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
#ifdef WITH_HASH_SHA512_256

#include "sha512-256.h"

/* Init hash function */
void sha512_256_init(sha512_256_context *ctx)
{
	MUST_HAVE(ctx != NULL);

	ctx->sha512_total[0] = ctx->sha512_total[1] = 0;
	ctx->sha512_state[0] = (u64)(0x22312194FC2BF72C);
	ctx->sha512_state[1] = (u64)(0x9F555FA3C84C64C2);
	ctx->sha512_state[2] = (u64)(0x2393B86B6F53B151);
	ctx->sha512_state[3] = (u64)(0x963877195940EABD);
	ctx->sha512_state[4] = (u64)(0x96283EE2A88EFFE3);
	ctx->sha512_state[5] = (u64)(0xBE5E1E2553863992);
	ctx->sha512_state[6] = (u64)(0x2B0199FC2C85B8AA);
	ctx->sha512_state[7] = (u64)(0x0EB72DDC81C52CA2);

	/* Tell that we are initialized */
	ctx->magic = SHA512_256_HASH_MAGIC;
}

/* Update hash function */
void sha512_256_update(sha512_256_context *ctx, const u8 *input, u32 ilen)
{
	SHA512_256_HASH_CHECK_INITIALIZED(ctx);

	sha512_core_update(ctx, input, ilen);

	return;
}

/* Finalize */
void sha512_256_final(sha512_256_context *ctx, u8 output[SHA512_256_DIGEST_SIZE])
{
	SHA512_256_HASH_CHECK_INITIALIZED(ctx);

	sha512_core_final(ctx, output, SHA512_256_DIGEST_SIZE);

	/* Tell that we are uninitialized */
	ctx->magic = 0;

	return;
}

void sha512_256_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA512_256_DIGEST_SIZE])
{
	sha512_256_context ctx;
	int pos = 0;

	sha512_256_init(&ctx);

	while (inputs[pos] != NULL) {
		sha512_256_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	sha512_256_final(&ctx, output);
}

void sha512_256(const u8 *input, u32 ilen, u8 output[SHA512_256_DIGEST_SIZE])
{
	sha512_256_context ctx;

	sha512_256_init(&ctx);
	sha512_256_update(&ctx, input, ilen);
	sha512_256_final(&ctx, output);
}

#else /* WITH_HASH_SHA512_256 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHA512_256 */
