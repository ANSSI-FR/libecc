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

#include "shake256.h"

void shake256_init(shake256_context *ctx)
{
	_shake_init(ctx, SHAKE256_DIGEST_SIZE, SHAKE256_BLOCK_SIZE);

	/* Tell that we are initialized */
	ctx->magic = SHAKE256_HASH_MAGIC;
}

void shake256_update(shake256_context *ctx, const u8 *input, u32 ilen)
{
	SHAKE256_HASH_CHECK_INITIALIZED(ctx);

	_shake_update((shake_context *)ctx, input, ilen);
}

void shake256_final(shake256_context *ctx, u8 output[SHAKE256_DIGEST_SIZE])
{
	SHAKE256_HASH_CHECK_INITIALIZED(ctx);

	_shake_finalize((shake_context *)ctx, output);

	/* Tell that we are uninitialized */
	ctx->magic = 0;
}

void shake256_scattered(const u8 **inputs, const u32 *ilens,
			u8 output[SHAKE256_DIGEST_SIZE])
{
	shake256_context ctx;
	int pos = 0;

	shake256_init(&ctx);

	while (inputs[pos] != NULL) {
		shake256_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	shake256_final(&ctx, output);
}

void shake256(const u8 *input, u32 ilen, u8 output[SHAKE256_DIGEST_SIZE])
{
	shake256_context ctx;

	shake256_init(&ctx);
	shake256_update(&ctx, input, ilen);
	shake256_final(&ctx, output);
}

#else /* WITH_HASH_SHAKE256 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHAKE256 */
