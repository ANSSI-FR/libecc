/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#ifndef __RSA_H__
#define __RSA_H__

/*
 * NOTE: although we only need libarith for RSA as we
 * manipulate a ring of integers, we include libsig for
 * the hash algorithms.
 */
#include "../lib_ecc_config.h"

/* The hash algorithms wrapper */
#include "rsa_hash.h"

/* We define hereafter the types and functions for RSA.
 * The notations are taken from RFC 8017 and should be compliant
 * with it.
 */

/* RSA public key, composed of:
 *       n        the RSA modulus, a positive integer
 *       e        the RSA public exponent, a positive integer
 */
typedef struct {
	nn n;
	nn e;
} rsa_pub_key;

/* RSA private key, composed of:
 *       n       the RSA modulus, a positive integer
 *       d       the RSA private exponent, a positive integer
 *
 * OR when using CRT:
 *       p      the first factor, a positive integer
 *       q      the second factor, a positive integer
 *       dP     the first factor's CRT exponent, a positive integer
 *       dQ     the second factor's CRT exponent, a positive integer
 *       qInv   the (first) CRT coefficient, a positive integer
 *       r_i    the i-th factor, a positive integer
 *       d_i    the i-th factor's CRT exponent, a positive integer
 *       t_i    the i-th factor's CRT coefficient, a positive integer
 * u is the number of (r_i, d_i, t_i) triplets.
 */
typedef enum {
        RSA_SIMPLE = 0,
        RSA_CRT    = 1,
} rsa_priv_key_type;

/*** RSA "simple" private key ***/
typedef struct {
	nn n;
	nn d;
} rsa_priv_key_simple;

/*** RSA CRT private key *******/
typedef struct {
	nn r;
	nn d;
	nn t;
} rsa_priv_key_crt_coeffs;

typedef struct {
	nn p;
	nn q;
	nn dP;
	nn dQ;
	nn qInv;
	/* A maximum of 255 triplets are allowed in our
	 * implementation.
	 */
	u8 u;
	rsa_priv_key_crt_coeffs coeffs[255];
} rsa_priv_key_crt;

typedef struct {
	rsa_priv_key_type type;
	union {
		rsa_priv_key_simple s;
		rsa_priv_key_crt crt;
	} key;
} rsa_priv_key;

ATTRIBUTE_WARN_UNUSED_RET int i2osp(nn_src_t x, u8 *buf, u16 buflen);
ATTRIBUTE_WARN_UNUSED_RET int os2ip(nn_t x, const u8 *buf, u16 buflen);

ATTRIBUTE_WARN_UNUSED_RET int rsa_import_pub_key(rsa_pub_key *pub, const u8 *n, u16 nlen, const u8 *e, u16 elen);
ATTRIBUTE_WARN_UNUSED_RET int rsa_import_simple_priv_key(rsa_priv_key *priv, const u8 *n, u16 nlen, const u8 *d, u16 dlen);
ATTRIBUTE_WARN_UNUSED_RET int rsa_import_crt_priv_key(rsa_priv_key *priv, const u8 *p, u16 plen, const u8 *q, u16 qlen, const u8 *dP, u16 dPlen, const u8 *dQ, u16 dQlen, const u8 *qInv, u16 qInvlen, const u8 **coeffs, u16 *coeffslens, u8 u);

ATTRIBUTE_WARN_UNUSED_RET int rsaep(const rsa_pub_key *pub, nn_src_t m, nn_t c);
ATTRIBUTE_WARN_UNUSED_RET int rsadp(const rsa_priv_key *priv, nn_src_t c, nn_t m);
ATTRIBUTE_WARN_UNUSED_RET int rsasp1(const rsa_priv_key *priv, nn_src_t m, nn_t s);
ATTRIBUTE_WARN_UNUSED_RET int rsavp1(const rsa_pub_key *pub, nn_src_t s, nn_t m);

ATTRIBUTE_WARN_UNUSED_RET int emsa_pkcs1_v1_5_encode(const u8 *m, u16 mlen, u8 *em, u16 emlen, rsa_hash_alg_type rsa_hash_type);
ATTRIBUTE_WARN_UNUSED_RET int emsa_pss_encode(const u8 *m, u16 mlen, u8 *em, u32 embits, u16 *eminlen, rsa_hash_alg_type rsa_hash_type, u16 slen, const u8 *forced_salt);
ATTRIBUTE_WARN_UNUSED_RET int emsa_pss_verify(const u8 *m, u16 mlen, const u8 *em, u32 embits, u16 emlen, rsa_hash_alg_type rsa_hash_type, u16 slen);

ATTRIBUTE_WARN_UNUSED_RET int rsaes_pkcs1_v1_5_encrypt(const rsa_pub_key *pub, const u8 *m, u16 mlen, u8 *c, u16 *clen, u32 modbits, const u8 *forced_seed, u16 seedlen);
ATTRIBUTE_WARN_UNUSED_RET int rsaes_pkcs1_v1_5_decrypt(const rsa_priv_key *priv, const u8 *c, u16 clen, u8 *m, u16 *mlen, u32 modbits);

ATTRIBUTE_WARN_UNUSED_RET int rsaes_oaep_encrypt(const rsa_pub_key *pub, const u8 *m, u16 mlen, u8 *c, u16 *clen, u32 modbits, const u8 *label, u16 label_len, rsa_hash_alg_type rsa_hash_type, const u8 *forced_seed, u16 seedlen);
ATTRIBUTE_WARN_UNUSED_RET int rsaes_oaep_decrypt(const rsa_priv_key *priv, const u8 *c, u16 clen, u8 *m, u16 *mlen, u32 modbits, const u8 *label, u16 label_len, rsa_hash_alg_type rsa_hash_type);

ATTRIBUTE_WARN_UNUSED_RET int rsassa_pkcs1_v1_5_sign(const rsa_priv_key *priv, const u8 *m, u16 mlen, u8 *s, u16 *slen, u32 modbits, rsa_hash_alg_type rsa_hash_type);
ATTRIBUTE_WARN_UNUSED_RET int rsassa_pkcs1_v1_5_verify(const rsa_pub_key *pub, const u8 *m, u16 mlen, const u8 *s, u16 slen, u32 modbits, rsa_hash_alg_type rsa_hash_type);

ATTRIBUTE_WARN_UNUSED_RET int rsassa_pss_sign(const rsa_priv_key *priv, const u8 *m, u16 mlen, u8 *s, u16 *slen, u32 modbits, rsa_hash_alg_type rsa_hash_type, u16 saltlen, const u8 *forced_salt);
ATTRIBUTE_WARN_UNUSED_RET int rsassa_pss_verify(const rsa_pub_key *pub, const u8 *m, u16 mlen, const u8 *s, u16 slen, u32 modbits, rsa_hash_alg_type rsa_hash_type, u16 saltlen);

#endif /* __RSA_H__ */
