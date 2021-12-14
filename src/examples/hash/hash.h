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
#ifndef __HASH_HASH_H__
#define __HASH_HASH_H__


/*
 * NOTE: we include libsig for the libecc
 * hash algorithms.
 */
#include "libec.h"

/* MD-2 source code */
#include "md2.h"
/* MD-4 source code */
#include "md4.h"
/* MD-5 source code */
#include "md5.h"
/* SHA-0 source code */
#include "sha0.h"
/* SHA-1 source code */
#include "sha1.h"
/* MDC-2 source code */
#include "mdc2.h"

/****************************************************/
/****************************************************/
/****************************************************/
typedef enum {
	/* libecc native hashes */
	HASH_SHA224 = 0,
	HASH_SHA256 = 1,
	HASH_SHA384 = 2,
	HASH_SHA512 = 3,
	HASH_SHA512_224 = 4,
	HASH_SHA512_256 = 5,
	HASH_SHA3_224 = 6,
	HASH_SHA3_256 = 7,
	HASH_SHA3_384 = 8,
	HASH_SHA3_512 = 9,
	HASH_SM3 = 10,
	HASH_STREEBOG256 = 11,
	HASH_STREEBOG512 = 12,
	HASH_SHAKE256 = 13,
	HASH_RIPEMD160 = 14,
	/* Deprecated hash algorithms not supported by libecc
	 * (for security reasons).
	 * XXX: NOTE: These algorithms are here as a playground e.g.
	 * to test some backward compatibility of cryptographic cipher suites,
	 * please DO NOT use them in production code!
	 */
	HASH_MD2 = 15,
	HASH_MD4 = 16,
	HASH_MD5 = 17,
	HASH_SHA0 = 18,
	HASH_SHA1 = 19,
	HASH_MDC2_PADDING1 = 20,
	HASH_MDC2_PADDING2 = 21,
	HASH_NO_HASH = 22,
} gen_hash_alg_type;

/* Our generic hash context */
typedef union {
	/* libecc native hashes */
	hash_context hctx;
	/* MD2 */
	md2_context md2ctx;
	/* MD4 */
	md4_context md4ctx;
	/* MD5 */
	md5_context md5ctx;
	/* SHA-0 */
	sha0_context sha0ctx;
	/* SHA-1 */
	sha1_context sha1ctx;
	/* MDC2-1 */
	mdc2_context mdc2ctx;
} gen_hash_context;

ATTRIBUTE_WARN_UNUSED_RET int gen_hash_get_hash_sizes(gen_hash_alg_type gen_hash_type, u8 *hlen, u8 *block_size);
ATTRIBUTE_WARN_UNUSED_RET int gen_hash_init(gen_hash_context *ctx, gen_hash_alg_type gen_hash_type);
ATTRIBUTE_WARN_UNUSED_RET int gen_hash_update(gen_hash_context *ctx, const u8 *chunk, u32 chunklen, gen_hash_alg_type gen_hash_type);
ATTRIBUTE_WARN_UNUSED_RET int gen_hash_final(gen_hash_context *ctx, u8 *output, gen_hash_alg_type gen_hash_type);
ATTRIBUTE_WARN_UNUSED_RET int gen_hash_hfunc(const u8 *input, u32 ilen, u8 *digest, gen_hash_alg_type gen_hash_type);
ATTRIBUTE_WARN_UNUSED_RET int gen_hash_hfunc_scattered(const u8 **input, const u32 *ilen, u8 *digest, gen_hash_alg_type gen_hash_type);

#endif /* __HASH_HASH_H__ */
