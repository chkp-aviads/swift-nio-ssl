//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
//===----------------------------------------------------------------------===//

import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import NIOPosix
import XCTest

@testable import NIOSSL

/// Covers ``TLSConfiguration/clientCertificateRequestCallback``, which lets a client find out that
/// the server asked it for a certificate and stop the handshake before it completes.
final class ClientCertificateRequestCallbackTests: XCTestCase {
    private static let cert: NIOSSLCertificate = {
        try! NIOSSLCertificate(bytes: Array(samplePemCert.utf8), format: .pem)
    }()
    private static let key: NIOSSLPrivateKey = {
        try! NIOSSLPrivateKey(bytes: Array(samplePemKey.utf8), format: .pem)
    }()

    /// A server that asks for a client certificate but does not insist on getting one, so the
    /// outcome of the handshake is decided entirely by the client-side callback.
    private static func serverConfigurationRequestingClientCertificate() -> TLSConfiguration {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(Self.cert)],
            privateKey: .privateKey(Self.key)
        )
        // optionalVerification sends a CertificateRequest without requiring a reply.
        config.certificateVerification = .optionalVerification
        config.trustRoots = .certificates([Self.cert])
        return config
    }

    private static func serverConfigurationNotRequestingClientCertificate() -> TLSConfiguration {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(Self.cert)],
            privateKey: .privateKey(Self.key)
        )
        config.certificateVerification = .none
        return config
    }

    private static func clientConfiguration() -> TLSConfiguration {
        var config = TLSConfiguration.makeClientConfiguration()
        config.trustRoots = .certificates([Self.cert])
        config.certificateVerification = .noHostnameVerification
        return config
    }

    /// Runs one handshake and reports whether it succeeded.
    private func handshake(
        clientConfig: TLSConfiguration,
        serverConfig: TLSConfiguration,
        serverHostname: String? = "localhost"
    ) throws -> Bool {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { XCTAssertNoThrow(try group.syncShutdownGracefully()) }

        let serverContext = try NIOSSLContext(configuration: serverConfig)
        let clientContext = try NIOSSLContext(configuration: clientConfig)

        let serverChannel = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        NIOSSLServerHandler(context: serverContext)
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
        defer { try? serverChannel.close().wait() }

        do {
            let clientChannel = try ClientBootstrap(group: group)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(
                            try NIOSSLClientHandler(context: clientContext, serverHostname: serverHostname)
                        )
                    }
                }
                .connect(to: serverChannel.localAddress!).wait()
            // Force the handshake to complete (or fail) before reporting success: connect only
            // establishes TCP, and NIOSSL drives TLS afterwards.
            try clientChannel.writeAndFlush(ByteBuffer(string: "x")).wait()
            try? clientChannel.close().wait()
            return true
        } catch {
            return false
        }
    }

    // MARK: - Behaviour

    func testCallbackFiresAndAbortsHandshakeWhenServerRequestsCertificate() throws {
        let seenHostname = NIOLockedValueBox<String??>(.none)
        var clientConfig = Self.clientConfiguration()
        clientConfig.clientCertificateRequestCallback = { hostname in
            seenHostname.withLockedValue { $0 = .some(hostname) }
            return false  // refuse: fail the handshake
        }

        let succeeded = try self.handshake(
            clientConfig: clientConfig,
            serverConfig: Self.serverConfigurationRequestingClientCertificate()
        )

        XCTAssertFalse(succeeded, "returning false from the callback must fail the handshake")
        let observed = seenHostname.withLockedValue { $0 }
        XCTAssertNotNil(observed, "callback should have been invoked")
        XCTAssertEqual(observed ?? nil, "localhost", "callback should receive the SNI hostname")
    }

    func testCallbackReturningTrueLeavesHandshakeAlone() throws {
        let invoked = NIOLockedValueBox(false)
        var clientConfig = Self.clientConfiguration()
        clientConfig.clientCertificateRequestCallback = { _ in
            invoked.withLockedValue { $0 = true }
            return true  // allow: keep BoringSSL's default (empty certificate list)
        }

        let succeeded = try self.handshake(
            clientConfig: clientConfig,
            serverConfig: Self.serverConfigurationRequestingClientCertificate()
        )

        XCTAssertTrue(succeeded, "returning true must preserve the default behaviour")
        XCTAssertTrue(invoked.withLockedValue { $0 }, "callback should have been invoked")
    }

    func testCallbackNotInvokedWhenServerDoesNotRequestCertificate() throws {
        let invoked = NIOLockedValueBox(false)
        var clientConfig = Self.clientConfiguration()
        clientConfig.clientCertificateRequestCallback = { _ in
            invoked.withLockedValue { $0 = true }
            return false
        }

        let succeeded = try self.handshake(
            clientConfig: clientConfig,
            serverConfig: Self.serverConfigurationNotRequestingClientCertificate()
        )

        XCTAssertTrue(succeeded, "a server that asks for nothing must still complete the handshake")
        XCTAssertFalse(invoked.withLockedValue { $0 }, "callback must not fire without a CertificateRequest")
    }

    /// The backward-compatibility assertion: without a callback, nothing changes.
    func testNoCallbackLeavesExistingBehaviourUnchanged() throws {
        let succeeded = try self.handshake(
            clientConfig: Self.clientConfiguration(),
            serverConfig: Self.serverConfigurationRequestingClientCertificate()
        )
        XCTAssertTrue(succeeded, "with no callback the handshake must complete as it always has")
    }

    func testCallbackReceivesNilWhenNoSNISent() throws {
        let seenHostname = NIOLockedValueBox<String??>(.none)
        var clientConfig = Self.clientConfiguration()
        clientConfig.clientCertificateRequestCallback = { hostname in
            seenHostname.withLockedValue { $0 = .some(hostname) }
            return false
        }

        _ = try self.handshake(
            clientConfig: clientConfig,
            serverConfig: Self.serverConfigurationRequestingClientCertificate(),
            serverHostname: nil
        )

        let observed = seenHostname.withLockedValue { $0 }
        XCTAssertNotNil(observed, "callback should have been invoked")
        XCTAssertNil(observed ?? "not-nil", "no SNI sent means the callback receives nil")
    }

    // MARK: - Interaction with sslContextCallback
    //
    // Both callbacks share BoringSSL's single cert_cb slot, and sslContextCallback is used on the
    // client too (TLSConfigurationTest.testClientSideCertSelection) to select a client
    // certificate. These two tests pin the layering: the request callback is a veto in front of
    // that selection, not a replacement for it.

    func testVetoRefusesEvenWhenClientCertSelectionIsConfigured() throws {
        var clientConfig = Self.clientConfiguration()
        clientConfig.sslContextCallback = { _, promise in
            var override = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(Self.cert)]
            override.privateKey = .privateKey(Self.key)
            promise.succeed(override)
        }
        clientConfig.clientCertificateRequestCallback = { _ in false }

        let succeeded = try self.handshake(
            clientConfig: clientConfig,
            serverConfig: Self.serverConfigurationRequestingClientCertificate()
        )
        XCTAssertFalse(succeeded, "the veto must win over a configured certificate selection")
    }

    func testAllowingVetoStillRunsClientCertSelection() throws {
        let selectionRan = NIOLockedValueBox(false)
        var clientConfig = Self.clientConfiguration()
        clientConfig.sslContextCallback = { _, promise in
            selectionRan.withLockedValue { $0 = true }
            var override = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(Self.cert)]
            override.privateKey = .privateKey(Self.key)
            promise.succeed(override)
        }
        clientConfig.clientCertificateRequestCallback = { _ in true }

        let succeeded = try self.handshake(
            clientConfig: clientConfig,
            serverConfig: Self.serverConfigurationRequestingClientCertificate()
        )
        XCTAssertTrue(succeeded, "allowing the request must leave the handshake working")
        XCTAssertTrue(
            selectionRan.withLockedValue { $0 },
            "sslContextCallback must still run when the request callback allows it"
        )
    }

    // MARK: - Configuration equality and hashing
    //
    // TLSConfiguration carries this closure, and AsyncHTTPClient keys its NIOSSLContext cache on
    // bestEffortEquals/bestEffortHash. A configuration must therefore still compare equal to a
    // copy of itself, or every cache lookup misses and rebuilds the context.

    func testConfigWithCallbackEqualsItself() {
        var config = Self.clientConfiguration()
        config.clientCertificateRequestCallback = { _ in false }
        let sameConfig = config

        XCTAssertTrue(config.bestEffortEquals(sameConfig))
        XCTAssertTrue(config.bestEffortEquals(config))
    }

    func testConfigWithCallbackHashesEqualToItself() {
        var config = Self.clientConfiguration()
        config.clientCertificateRequestCallback = { _ in false }
        let sameConfig = config

        var hasher = Hasher()
        var hasher2 = Hasher()
        config.bestEffortHash(into: &hasher)
        sameConfig.bestEffortHash(into: &hasher2)
        XCTAssertEqual(hasher.finalize(), hasher2.finalize())
    }

    func testDifferentCallbacksNotEqual() {
        var config = Self.clientConfiguration()
        config.clientCertificateRequestCallback = { _ in false }
        var differentConfig = config
        differentConfig.clientCertificateRequestCallback = { _ in false }

        XCTAssertFalse(config.bestEffortEquals(differentConfig))
    }

    func testCallbackPresenceIsPartOfEquality() {
        var withCallback = Self.clientConfiguration()
        withCallback.clientCertificateRequestCallback = { _ in false }
        let withoutCallback = Self.clientConfiguration()

        XCTAssertFalse(withCallback.bestEffortEquals(withoutCallback))
        XCTAssertFalse(withoutCallback.bestEffortEquals(withCallback))
    }
}
