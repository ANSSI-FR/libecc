/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "../lib_ecc_config.h"
#ifdef WITH_HASH_SHA224

#ifndef __SHA224_H__
#define __SHA224_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "sha2.h"

#define SHA224_STATE_SIZE   8
#define SHA224_BLOCK_SIZE   64
#define SHA224_DIGEST_SIZE  28

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA224_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA224_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA224_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA224_BLOCK_SIZE
#endif

#define SHA224_HASH_MAGIC ((word_t)(0x1120323b32342910ULL))
#define SHA224_HASH_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA224_HASH_MAGIC))

typedef struct {
	/* Number of bytes processed */
	u64 sha224_total;
	/* Internal state */
	u32 sha224_state[SHA224_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	u8 sha224_buffer[SHA224_BLOCK_SIZE];
        /* Initialization magic value */
        word_t magic;
} sha224_context;

void sha224_init(sha224_context *ctx);
void sha224_update(sha224_context *ctx, const u8 *input, u32 ilen);
void sha224_final(sha224_context *ctx, u8 output[SHA224_DIGEST_SIZE]);
void sha224_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA224_DIGEST_SIZE]);
void sha224(const u8 *input, u32 ilen, u8 output[SHA224_DIGEST_SIZE]);

#endif /* __SHA224_H__ */
#endif /* WITH_HASH_SHA224 */
