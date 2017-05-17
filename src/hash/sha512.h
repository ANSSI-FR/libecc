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
#ifdef WITH_HASH_SHA512

#ifndef __SHA512_H__
#define __SHA512_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "sha2.h"

#define SHA512_STATE_SIZE   8
#define SHA512_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE  64

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA512_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA512_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE	0
#endif
#if (MAX_BLOCK_SIZE < SHA512_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA512_BLOCK_SIZE
#endif

typedef struct {
	/* Number of bytes processed on 128 bits */
	u64 sha512_total[2];
	/* Internal state */
	u64 sha512_state[SHA512_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	u8 sha512_buffer[SHA512_BLOCK_SIZE];
} sha512_context;

void sha512_init(sha512_context *ctx);
void sha512_update(sha512_context *ctx, const u8 *input, u32 ilen);
void sha512_final(sha512_context *ctx, u8 output[SHA512_DIGEST_SIZE]);
void sha512_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA512_DIGEST_SIZE]);
void sha512(const u8 *input, u32 ilen, u8 output[SHA512_DIGEST_SIZE]);

#endif /* __SHA512_H__ */
#endif /* WITH_HASH_SHA512 */
