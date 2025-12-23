//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOPosix
import NIOTLS
import XCTest

@testable import NIOSSL

final class CustomErrorHandlingCallbackTests: XCTestCase {
    private enum TestError: Error {
        case callbackFailed
    }

    private static let certAndKey = generateSelfSignedCert()
    private static var cert: NIOSSLCertificate { Self.certAndKey.0 }
    private static var key: NIOSSLPrivateKey { Self.certAndKey.1 }

    private func configuredServerContext() throws -> NIOSSLContext {
        let config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(Self.cert)],
            privateKey: .privateKey(Self.key)
        )
        return try NIOSSLContext(configuration: config)
    }

    func testCustomErrorHandlingCallbackIsInvokedOnHandshakeFailure() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let callbackFired = XCTestExpectation(description: "customErrorHandlingCallback invoked")
        let childChannelPromise = group.next().makePromise(of: Channel.self)
        let errorCatcher = ErrorCatcher<any Error>()

        let context = try self.configuredServerContext()

        let serverChannel = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                childChannelPromise.succeed(channel)
                return channel.eventLoop.makeCompletedFuture {
                    let handler = NIOSSLServerHandler(
                        context: context,
                        customVerificationCallback: nil,
                        customErrorHandlingCallback: { _, context, _ in
                            callbackFired.fulfill()
                            context.close(promise: nil)
                            return context.eventLoop.makeSucceededFuture(())
                        },
                        configuration: .init()
                    )
                    try channel.pipeline.syncOperations.addHandler(handler)
                    try channel.pipeline.syncOperations.addHandler(errorCatcher)
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()

        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try ClientBootstrap(group: group)
            .connect(to: serverChannel.localAddress!)
            .wait()

        defer {
            _ = try? clientChannel.close().wait()
        }

        // Send non-TLS data to force a handshake error on the server.
        var buffer = clientChannel.allocator.buffer(capacity: 16)
        buffer.writeString("not tls")
        try clientChannel.writeAndFlush(buffer).wait()

        wait(for: [callbackFired], timeout: 5.0)

        let childChannel = try childChannelPromise.futureResult.wait()
        _ = try? childChannel.closeFuture.wait()

        try childChannel.eventLoop.submit {
            let nioErrors = errorCatcher.errors.compactMap { $0 as? NIOSSLError }
            XCTAssertFalse(nioErrors.contains { error in
                if case .handshakeFailed = error { return true }
                return false
            })
        }.wait()
    }

    func testCustomErrorHandlingCallbackFailureFallsBackToDefaultErrorHandling() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let callbackFired = XCTestExpectation(description: "customErrorHandlingCallback invoked")
        let childChannelPromise = group.next().makePromise(of: Channel.self)
        let errorCatcher = ErrorCatcher<any Error>()

        let context = try self.configuredServerContext()

        let serverChannel = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                childChannelPromise.succeed(channel)
                return channel.eventLoop.makeCompletedFuture {
                    let handler = NIOSSLServerHandler(
                        context: context,
                        customVerificationCallback: nil,
                        customErrorHandlingCallback: { _, context, _ in
                            callbackFired.fulfill()
                            return context.eventLoop.makeFailedFuture(TestError.callbackFailed)
                        },
                        configuration: .init()
                    )
                    try channel.pipeline.syncOperations.addHandler(handler)
                    try channel.pipeline.syncOperations.addHandler(errorCatcher)
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()

        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try ClientBootstrap(group: group)
            .connect(to: serverChannel.localAddress!)
            .wait()

        defer {
            _ = try? clientChannel.close().wait()
        }

        // Send non-TLS data to force a handshake error on the server.
        var buffer = clientChannel.allocator.buffer(capacity: 16)
        buffer.writeString("not tls")
        try clientChannel.writeAndFlush(buffer).wait()

        wait(for: [callbackFired], timeout: 5.0)

        let childChannel = try childChannelPromise.futureResult.wait()
        _ = try? childChannel.closeFuture.wait()

        try childChannel.eventLoop.submit {
            let nioErrors = errorCatcher.errors.compactMap { $0 as? NIOSSLError }
            XCTAssertTrue(nioErrors.contains { error in
                if case .handshakeFailed = error { return true }
                return false
            })
        }.wait()
    }
}
