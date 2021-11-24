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
#ifndef __RSA_HASH_H__
#define __RSA_HASH_H__


/*
 * NOTE: although we only need libarith for RSA as we
 * manipulate a ring of integers, we include libsig for
 * the hash algorithms.
 */
#include "libec.h"

/* MD-2 source code */
#include "md2.h"
/* MD-4 source code */
#include "md4.h"
/* MD-5 source code */
#include "md5.h"
/* SHA-1 source code */
#include "sha1.h"

/****************************************************/
/****************************************************/
/****************************************************/
typedef enum {
	/* libecc native hashes */
	RSA_SHA224 = 0,
	RSA_SHA256 = 1,
	RSA_SHA384 = 2,
	RSA_SHA512 = 3,
	RSA_SHA512_224 = 4,
	RSA_SHA512_256 = 5,
	RSA_SHA3_224 = 6,
	RSA_SHA3_256 = 7,
	RSA_SHA3_384 = 8,
	RSA_SHA3_512 = 9,
	RSA_SM3 = 10,
	RSA_STREEBOG256 = 11,
	RSA_STREEBOG512 = 12,
	RSA_SHAKE256 = 13,
	RSA_RIPEMD160 = 14,
	/* Deprecated hash algorithms not supported by libecc
	 * (for security reasons).
	 * XXX: NOTE: These algorithms are here as a playground e.g.
	 * to test some backward compatibility of cryptographic cipher suites,
	 * please DO NOT use them in production code!
	 */
	RSA_MD2 = 15,
	RSA_MD4 = 16,
	RSA_MD5 = 17,
	RSA_SHA1 = 18,
	RSA_NO_HASH = 19,
} rsa_hash_alg_type;

ATTRIBUTE_WARN_UNUSED_RET int rsa_get_hash_sizes(rsa_hash_alg_type rsa_hash_type, u8 *hlen, u8 *block_size);
ATTRIBUTE_WARN_UNUSED_RET int rsa_digestinfo_from_hash(rsa_hash_alg_type rsa_hash_type, u8 *digestinfo, u32 *digestinfo_len);
ATTRIBUTE_WARN_UNUSED_RET int rsa_hfunc_scattered(const u8 **input, const u32 *ilen, u8 *digest, rsa_hash_alg_type rsa_hash_type);

#endif /* __RSA_HASH_H__ */
