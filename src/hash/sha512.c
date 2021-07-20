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

#include "sha512.h"

/* Init hash function */
void sha512_init(sha512_context *ctx)
{
	MUST_HAVE(ctx != NULL);

	ctx->sha512_total[0] = ctx->sha512_total[1] = 0;
	ctx->sha512_state[0] = (u64)(0x6A09E667F3BCC908);
	ctx->sha512_state[1] = (u64)(0xBB67AE8584CAA73B);
	ctx->sha512_state[2] = (u64)(0x3C6EF372FE94F82B);
	ctx->sha512_state[3] = (u64)(0xA54FF53A5F1D36F1);
	ctx->sha512_state[4] = (u64)(0x510E527FADE682D1);
	ctx->sha512_state[5] = (u64)(0x9B05688C2B3E6C1F);
	ctx->sha512_state[6] = (u64)(0x1F83D9ABFB41BD6B);
	ctx->sha512_state[7] = (u64)(0x5BE0CD19137E2179);

	/* Tell that we are initialized */
	ctx->magic = SHA512_HASH_MAGIC;
}

/* Update hash function */
void sha512_update(sha512_context *ctx, const u8 *input, u32 ilen)
{
	SHA512_HASH_CHECK_INITIALIZED(ctx);

	sha512_core_update(ctx, input, ilen);

	return;
}

/* Finalize */
void sha512_final(sha512_context *ctx, u8 output[SHA512_DIGEST_SIZE])
{
	SHA512_HASH_CHECK_INITIALIZED(ctx);

	sha512_core_final(ctx, output, SHA512_DIGEST_SIZE);

	/* Tell that we are uninitialized */
	ctx->magic = 0;

	return;
}

void sha512_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA512_DIGEST_SIZE])
{
	sha512_context ctx;
	int pos = 0;

	sha512_init(&ctx);

	while (inputs[pos] != NULL) {
		sha512_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	sha512_final(&ctx, output);
}

void sha512(const u8 *input, u32 ilen, u8 output[SHA512_DIGEST_SIZE])
{
	sha512_context ctx;

	sha512_init(&ctx);
	sha512_update(&ctx, input, ilen);
	sha512_final(&ctx, output);
}

#else /* WITH_HASH_SHA512 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHA512 */
