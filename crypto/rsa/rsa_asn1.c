/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include "rsa_locl.h"

/* Override the default free and new methods */
static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {   /* 分配RSA私钥结构体，并初始化 RSA->meth */
        *pval = (ASN1_VALUE *)RSA_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        RSA_free((RSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

#if 0
static const ASN1_AUX RSAPrivateKey_aux = {NULL, 0, 0, 0, rsa_cb, 0};
static const ASN1_TEMPLATE RSAPrivateKey_seq_tt[] = {
    {0, 0, offsetof(RSA, version), "version", &LONG_it},
    {0, 0, offsetof(RSA, n), "n", &BIGNUM_it},
    {0, 0, offsetof(RSA, e), "e", &BIGNUM_it},
    {0, 0, offsetof(RSA, d), "d", &CBIGNUM_it},
    {0, 0, offsetof(RSA, p), "p", &CBIGNUM_it},
    {0, 0, offsetof(RSA, q), "q", &CBIGNUM_it},
    {0, 0, offsetof(RSA, dmp1), "dmp1", &CBIGNUM_it},
    {0, 0, offsetof(RSA, dmq1), "dmq1", &CBIGNUM_it},
    {0, 0, offsetof(RSA, iqmp), "iqmp", &CBIGNUM_it},
};
const ASN1_ITEM * RSAPrivateKey_it(void) {
    static const ASN1_ITEM local_it = {
        ASN1_ITYPE_SEQUENCE,
        V_ASN1_SEQUENCE,
        RSAPrivateKey_seq_tt,
        sizeof(RSAPrivateKey_seq_tt) / sizeof(ASN1_TEMPLATE),
        &RSAPrivateKey_aux,
        sizeof(RSA),
        "RSAPrivateKey"
    };
    return &local_it;
}
#endif
ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
        ASN1_SIMPLE(RSA, version, LONG),
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
        ASN1_SIMPLE(RSA, d, CBIGNUM),
        ASN1_SIMPLE(RSA, p, CBIGNUM),
        ASN1_SIMPLE(RSA, q, CBIGNUM),
        ASN1_SIMPLE(RSA, dmp1, CBIGNUM),
        ASN1_SIMPLE(RSA, dmq1, CBIGNUM),
        ASN1_SIMPLE(RSA, iqmp, CBIGNUM)
} ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)

#if 0
static const ASN1_AUX RSAPublicKey_aux = {NULL, 0, 0, 0, rsa_cb, 0};
static const ASN1_TEMPLATE RSAPublicKey_seq_tt[] = {
    {0, 0, offsetof(RSA, version), "version", &LONG_it},
    {0, 0, offsetof(RSA, n), "n", &BIGNUM_it},
    {0, 0, offsetof(RSA, e), "e", &BIGNUM_it},
    {0, 0, offsetof(RSA, d), "d", &CBIGNUM_it},
    {0, 0, offsetof(RSA, p), "p", &CBIGNUM_it},
    {0, 0, offsetof(RSA, q), "q", &CBIGNUM_it},
    {0, 0, offsetof(RSA, dmp1), "dmp1", &CBIGNUM_it},
    {0, 0, offsetof(RSA, dmq1), "dmq1", &CBIGNUM_it},
    {0, 0, offsetof(RSA, iqmp), "iqmp", &CBIGNUM_it},
};
const ASN1_ITEM * RSAPublicKey_it(void) {
    static const ASN1_ITEM local_it = {
        ASN1_ITYPE_SEQUENCE,
        V_ASN1_SEQUENCE,
        RSAPublicKey_seq_tt,
        sizeof(RSAPublicKey_seq_tt) / sizeof(ASN1_TEMPLATE),
        &RSAPublicKey_aux,
        sizeof(RSA),
        "RSAPublicKey"
    };
    return &local_it;
}
#endif
ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
} ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)

/* Free up maskHash */
static int rsa_pss_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      void *exarg)
{
    if (operation == ASN1_OP_FREE_PRE) {
        RSA_PSS_PARAMS *pss = (RSA_PSS_PARAMS *)*pval;
        X509_ALGOR_free(pss->maskHash);
    }
    return 1;
}

ASN1_SEQUENCE_cb(RSA_PSS_PARAMS, rsa_pss_cb) = {
        ASN1_EXP_OPT(RSA_PSS_PARAMS, hashAlgorithm, X509_ALGOR,0),
        ASN1_EXP_OPT(RSA_PSS_PARAMS, maskGenAlgorithm, X509_ALGOR,1),
        ASN1_EXP_OPT(RSA_PSS_PARAMS, saltLength, ASN1_INTEGER,2),
        ASN1_EXP_OPT(RSA_PSS_PARAMS, trailerField, ASN1_INTEGER,3)
} ASN1_SEQUENCE_END_cb(RSA_PSS_PARAMS, RSA_PSS_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(RSA_PSS_PARAMS)

/* Free up maskHash */
static int rsa_oaep_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                       void *exarg)
{
    if (operation == ASN1_OP_FREE_PRE) {
        RSA_OAEP_PARAMS *oaep = (RSA_OAEP_PARAMS *)*pval;
        X509_ALGOR_free(oaep->maskHash);
    }
    return 1;
}

ASN1_SEQUENCE_cb(RSA_OAEP_PARAMS, rsa_oaep_cb) = {
        ASN1_EXP_OPT(RSA_OAEP_PARAMS, hashFunc, X509_ALGOR, 0),
        ASN1_EXP_OPT(RSA_OAEP_PARAMS, maskGenFunc, X509_ALGOR, 1),
        ASN1_EXP_OPT(RSA_OAEP_PARAMS, pSourceFunc, X509_ALGOR, 2),
} ASN1_SEQUENCE_END_cb(RSA_OAEP_PARAMS, RSA_OAEP_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

#if 0
RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len) {
    return (RSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, RSAPrivateKey_it());
}
int i2d_RSAPrivateKey(const RSA *a, unsigned char **out) {
    return ASN1_item_i2d((ASN1_VALUE *)a, out, RSAPrivateKey_it());
}
#endif
/* 展开如上"#if 0 ... #endif"注释 */
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPrivateKey, RSAPrivateKey)

#if 0
RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len) {
    return (RSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, RSAPublicKey_it());
}
int i2d_RSAPublicKey(const RSA *a, unsigned char **out) {
    return ASN1_item_i2d((ASN1_VALUE *)a, out, RSAPublicKey_it());
}
#endif
/* 展开如上"#if 0 ... #endif"注释 */
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPublicKey, RSAPublicKey)

RSA *RSAPublicKey_dup(RSA *rsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(RSAPublicKey), rsa);
}

RSA *RSAPrivateKey_dup(RSA *rsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(RSAPrivateKey), rsa);
}
