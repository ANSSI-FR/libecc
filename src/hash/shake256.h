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
#include "../lib_ecc_config.h"
#ifdef WITH_HASH_SHAKE256

#ifndef __SHAKE256_H__
#define __SHAKE256_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "shake.h"

/* NOTE: this is an instantiation of SHAKE256 with
 * maximum size of 114 bytes, specifically suited for EdDSA Ed448
 * signature scheme.
 */
#define SHAKE256_BLOCK_SIZE   136
#define SHAKE256_DIGEST_SIZE  114

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < SHAKE256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHAKE256_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHAKE256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHAKE256_BLOCK_SIZE
#endif

#define SHAKE256_HASH_MAGIC ((word_t)(0x4326763238134567ULL))
#define SHAKE256_HASH_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHAKE256_HASH_MAGIC))

typedef shake_context shake256_context;

void shake256_init(shake256_context *ctx);
void shake256_update(shake256_context *ctx, const u8 *input, u32 ilen);
void shake256_final(shake256_context *ctx, u8 output[SHAKE256_DIGEST_SIZE]);
void shake256_scattered(const u8 **inputs, const u32 *ilens,
			u8 output[SHAKE256_DIGEST_SIZE]);
void shake256(const u8 *input, u32 ilen, u8 output[SHAKE256_DIGEST_SIZE]);

#endif /* __SHAKE256_H__ */
#endif /* WITH_HASH_SHAKE256 */
