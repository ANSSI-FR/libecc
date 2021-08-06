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
#ifdef WITH_HASH_SHA512_224

#include "sha512-224.h"

/* Init hash function */
void sha512_224_init(sha512_224_context *ctx)
{
	MUST_HAVE(ctx != NULL);

	ctx->sha512_total[0] = ctx->sha512_total[1] = 0;
	ctx->sha512_state[0] = (u64)(0x8C3D37C819544DA2);
	ctx->sha512_state[1] = (u64)(0x73E1996689DCD4D6);
	ctx->sha512_state[2] = (u64)(0x1DFAB7AE32FF9C82);
	ctx->sha512_state[3] = (u64)(0x679DD514582F9FCF);
	ctx->sha512_state[4] = (u64)(0x0F6D2B697BD44DA8);
	ctx->sha512_state[5] = (u64)(0x77E36F7304C48942);
	ctx->sha512_state[6] = (u64)(0x3F9D85A86A1D36C8);
	ctx->sha512_state[7] = (u64)(0x1112E6AD91D692A1);

	/* Tell that we are initialized */
	ctx->magic = SHA512_224_HASH_MAGIC;
}

/* Update hash function */
void sha512_224_update(sha512_224_context *ctx, const u8 *input, u32 ilen)
{
	SHA512_224_HASH_CHECK_INITIALIZED(ctx);

	sha512_core_update(ctx, input, ilen);

	return;
}

/* Finalize */
void sha512_224_final(sha512_224_context *ctx, u8 output[SHA512_224_DIGEST_SIZE])
{
	SHA512_224_HASH_CHECK_INITIALIZED(ctx);

	sha512_core_final(ctx, output, SHA512_224_DIGEST_SIZE);

	/* Tell that we are uninitialized */
	ctx->magic = 0;

	return;
}

void sha512_224_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA512_224_DIGEST_SIZE])
{
	sha512_224_context ctx;
	int pos = 0;

	sha512_224_init(&ctx);

	while (inputs[pos] != NULL) {
		sha512_224_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	sha512_224_final(&ctx, output);
}

void sha512_224(const u8 *input, u32 ilen, u8 output[SHA512_224_DIGEST_SIZE])
{
	sha512_224_context ctx;

	sha512_224_init(&ctx);
	sha512_224_update(&ctx, input, ilen);
	sha512_224_final(&ctx, output);
}

#else /* WITH_HASH_SHA512_224 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHA512_224 */
