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
#ifdef WITH_HASH_SHA3_256

#include "sha3-256.h"

void sha3_256_init(sha3_256_context *ctx)
{
	_sha3_init(ctx, SHA3_256_DIGEST_SIZE);

        /* Tell that we are initialized */
        ctx->magic = SHA3_256_HASH_MAGIC;
}

void sha3_256_update(sha3_256_context *ctx, const u8 *input, u32 ilen)
{
        SHA3_256_HASH_CHECK_INITIALIZED(ctx);

	_sha3_update((sha3_context *)ctx, input, ilen);
}

void sha3_256_final(sha3_256_context *ctx, u8 output[SHA3_256_DIGEST_SIZE])
{
        SHA3_256_HASH_CHECK_INITIALIZED(ctx);

	_sha3_finalize((sha3_context *)ctx, output);

        /* Tell that we are uninitialized */
        ctx->magic = 0;
}

void sha3_256_scattered(const u8 **inputs, const u32 *ilens,
			u8 output[SHA3_256_DIGEST_SIZE])
{
	sha3_256_context ctx;
	int pos = 0;

	sha3_256_init(&ctx);

	while (inputs[pos] != NULL) {
		sha3_256_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	sha3_256_final(&ctx, output);
}

void sha3_256(const u8 *input, u32 ilen, u8 output[SHA3_256_DIGEST_SIZE])
{
	sha3_256_context ctx;

	sha3_256_init(&ctx);
	sha3_256_update(&ctx, input, ilen);
	sha3_256_final(&ctx, output);
}

#else /* WITH_HASH_SHA3_256 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHA3_256 */
