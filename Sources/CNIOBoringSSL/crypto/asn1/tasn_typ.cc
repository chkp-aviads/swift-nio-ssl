/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <CNIOBoringSSL_asn1.h>

#include <CNIOBoringSSL_asn1t.h>

// Declarations for string types

#define IMPLEMENT_ASN1_STRING_FUNCTIONS(sname)                         \
  IMPLEMENT_ASN1_TYPE(sname)                                           \
  IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(sname, sname, sname)     \
  sname *sname##_new(void) { return ASN1_STRING_type_new(V_##sname); } \
  void sname##_free(sname *x) { ASN1_STRING_free(x); }

IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_OCTET_STRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_INTEGER)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_ENUMERATED)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_BIT_STRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_UTF8STRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_PRINTABLESTRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_T61STRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_IA5STRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_GENERALSTRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_UTCTIME)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_GENERALIZEDTIME)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_VISIBLESTRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_UNIVERSALSTRING)
IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_BMPSTRING)

IMPLEMENT_ASN1_TYPE(ASN1_NULL)
IMPLEMENT_ASN1_FUNCTIONS_const(ASN1_NULL)

IMPLEMENT_ASN1_TYPE(ASN1_OBJECT)

IMPLEMENT_ASN1_TYPE(ASN1_ANY)

// Just swallow an ASN1_SEQUENCE in an ASN1_STRING
IMPLEMENT_ASN1_TYPE(ASN1_SEQUENCE)

IMPLEMENT_ASN1_FUNCTIONS_const_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)

// Multistring types

IMPLEMENT_ASN1_MSTRING(ASN1_PRINTABLE, B_ASN1_PRINTABLE)
IMPLEMENT_ASN1_FUNCTIONS_const_fname(ASN1_STRING, ASN1_PRINTABLE,
                                     ASN1_PRINTABLE)

IMPLEMENT_ASN1_MSTRING(DISPLAYTEXT, B_ASN1_DISPLAYTEXT)
IMPLEMENT_ASN1_FUNCTIONS_const_fname(ASN1_STRING, DISPLAYTEXT, DISPLAYTEXT)

IMPLEMENT_ASN1_MSTRING(DIRECTORYSTRING, B_ASN1_DIRECTORYSTRING)
IMPLEMENT_ASN1_FUNCTIONS_const_fname(ASN1_STRING, DIRECTORYSTRING,
                                     DIRECTORYSTRING)

// Three separate BOOLEAN type: normal, DEFAULT TRUE and DEFAULT FALSE
IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, ASN1_BOOLEAN_NONE)
IMPLEMENT_ASN1_TYPE_ex(ASN1_TBOOLEAN, ASN1_BOOLEAN, ASN1_BOOLEAN_TRUE)
IMPLEMENT_ASN1_TYPE_ex(ASN1_FBOOLEAN, ASN1_BOOLEAN, ASN1_BOOLEAN_FALSE)

ASN1_ITEM_TEMPLATE(ASN1_SEQUENCE_ANY) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, ASN1_SEQUENCE_ANY, ASN1_ANY)
ASN1_ITEM_TEMPLATE_END(ASN1_SEQUENCE_ANY)

ASN1_ITEM_TEMPLATE(ASN1_SET_ANY) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0,
                                                         ASN1_SET_ANY, ASN1_ANY)
ASN1_ITEM_TEMPLATE_END(ASN1_SET_ANY)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ASN1_SEQUENCE_ANY,
                                            ASN1_SEQUENCE_ANY,
                                            ASN1_SEQUENCE_ANY)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ASN1_SEQUENCE_ANY, ASN1_SET_ANY,
                                            ASN1_SET_ANY)
