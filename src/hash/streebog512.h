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
#ifdef WITH_HASH_STREEBOG512

#ifndef __STREEBOG512_H__
#define __STREEBOG512_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "streebog.h"

#define STREEBOG512_BLOCK_SIZE   STREEBOG_BLOCK_SIZE
#define STREEBOG512_DIGEST_SIZE  64

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < STREEBOG512_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE STREEBOG512_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < STREEBOG512_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE STREEBOG512_BLOCK_SIZE
#endif

#define STREEBOG512_HASH_MAGIC ((word_t)(0x3293187509128364ULL))
#define STREEBOG512_HASH_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == STREEBOG512_HASH_MAGIC))

typedef streebog_context streebog512_context;

void streebog512_init(streebog512_context *ctx);
void streebog512_update(streebog512_context *ctx, const u8 *input, u32 ilen);
void streebog512_final(streebog512_context *ctx, u8 output[STREEBOG512_DIGEST_SIZE]);
void streebog512_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[STREEBOG512_DIGEST_SIZE]);
void streebog512(const u8 *input, u32 ilen, u8 output[STREEBOG512_DIGEST_SIZE]);

#endif /* __STREEBOG512_H__ */
#endif /* WITH_HASH_STREEBOG512 */
