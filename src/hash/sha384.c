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
#ifdef WITH_HASH_SHA384

#include "sha384.h"

/* SHA-2 core processing */
static void sha384_process(sha384_context *ctx,
			   const u8 data[SHA384_BLOCK_SIZE])
{
	u64 a, b, c, d, e, f, g, h;
	u64 W[80];
	unsigned int i;

	MUST_HAVE(data != NULL);
	SHA384_HASH_CHECK_INITIALIZED(ctx);

	/* Init our inner variables */
	a = ctx->sha384_state[0];
	b = ctx->sha384_state[1];
	c = ctx->sha384_state[2];
	d = ctx->sha384_state[3];
	e = ctx->sha384_state[4];
	f = ctx->sha384_state[5];
	g = ctx->sha384_state[6];
	h = ctx->sha384_state[7];

	for (i = 0; i < 16; i++) {
		GET_UINT64_BE(W[i], data, 8 * i);
		SHA2CORE_SHA512(a, b, c, d, e, f, g, h, W[i], K_SHA512[i]);
	}

	for (i = 16; i < 80; i++) {
		SHA2CORE_SHA512(a, b, c, d, e, f, g, h, UPDATEW_SHA512(W, i),
				K_SHA512[i]);
	}

	/* Update state */
	ctx->sha384_state[0] += a;
	ctx->sha384_state[1] += b;
	ctx->sha384_state[2] += c;
	ctx->sha384_state[3] += d;
	ctx->sha384_state[4] += e;
	ctx->sha384_state[5] += f;
	ctx->sha384_state[6] += g;
	ctx->sha384_state[7] += h;
}

/* Init hash function */
void sha384_init(sha384_context *ctx)
{
	MUST_HAVE(ctx != NULL);

	ctx->sha384_total[0] = ctx->sha384_total[1] = 0;
	ctx->sha384_state[0] = (u64)(0xCBBB9D5DC1059ED8);
	ctx->sha384_state[1] = (u64)(0x629A292A367CD507);
	ctx->sha384_state[2] = (u64)(0x9159015A3070DD17);
	ctx->sha384_state[3] = (u64)(0x152FECD8F70E5939);
	ctx->sha384_state[4] = (u64)(0x67332667FFC00B31);
	ctx->sha384_state[5] = (u64)(0x8EB44A8768581511);
	ctx->sha384_state[6] = (u64)(0xDB0C2E0D64F98FA7);
	ctx->sha384_state[7] = (u64)(0x47B5481DBEFA4FA4);

	/* Tell that we are initialized */
	ctx->magic = SHA384_HASH_MAGIC;
}

/* Update hash function */
void sha384_update(sha384_context *ctx, const u8 *input, u32 ilen)
{
	u32 left;
	u32 fill;
	const u8 *data_ptr = input;
	u32 remain_ilen = ilen;

	MUST_HAVE(input != NULL);
	SHA384_HASH_CHECK_INITIALIZED(ctx);

	/* Nothing to process, return */
	if (ilen == 0) {
		return;
	}

	/* Get what's left in our local buffer */
	left = ctx->sha384_total[0] & 0x7F;
	fill = SHA384_BLOCK_SIZE - left;

	ADD_UINT128_UINT64(ctx->sha384_total[0], ctx->sha384_total[1], ilen);

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		local_memcpy(ctx->sha384_buffer + left, data_ptr, fill);
		sha384_process(ctx, ctx->sha384_buffer);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= SHA384_BLOCK_SIZE) {
		sha384_process(ctx, data_ptr);
		data_ptr += SHA384_BLOCK_SIZE;
		remain_ilen -= SHA384_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		local_memcpy(ctx->sha384_buffer + left, data_ptr, remain_ilen);
	}
}

/* Finalize */
void sha384_final(sha384_context *ctx, u8 output[SHA384_DIGEST_SIZE])
{
	unsigned int block_present = 0;
	u8 last_padded_block[2 * SHA384_BLOCK_SIZE];

	MUST_HAVE(output != NULL);
	SHA384_HASH_CHECK_INITIALIZED(ctx);

	/* Fill in our last block with zeroes */
	local_memset(last_padded_block, 0, sizeof(last_padded_block));

	/* This is our final step, so we proceed with the padding */
	block_present = ctx->sha384_total[0] % SHA384_BLOCK_SIZE;
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		local_memcpy(last_padded_block, ctx->sha384_buffer,
			     block_present);
	}

	/* Put the 0x80 byte, beginning of padding  */
	last_padded_block[block_present] = 0x80;

	/* Handle possible additional block */
	if (block_present > (SHA384_BLOCK_SIZE - 1 - (2 * sizeof(u64)))) {
		/* We need an additional block */
		PUT_MUL8_UINT128_BE(ctx->sha384_total[0], ctx->sha384_total[1],
				    last_padded_block,
				    2 * (SHA384_BLOCK_SIZE - sizeof(u64)));
		sha384_process(ctx, last_padded_block);
		sha384_process(ctx, last_padded_block + SHA384_BLOCK_SIZE);
	} else {
		/* We do not need an additional block */
		PUT_MUL8_UINT128_BE(ctx->sha384_total[0], ctx->sha384_total[1],
				    last_padded_block,
				    SHA384_BLOCK_SIZE - (2 * sizeof(u64)));
		sha384_process(ctx, last_padded_block);
	}

	/* Output the hash result */
	PUT_UINT64_BE(ctx->sha384_state[0], output, 0);
	PUT_UINT64_BE(ctx->sha384_state[1], output, 8);
	PUT_UINT64_BE(ctx->sha384_state[2], output, 16);
	PUT_UINT64_BE(ctx->sha384_state[3], output, 24);
	PUT_UINT64_BE(ctx->sha384_state[4], output, 32);
	PUT_UINT64_BE(ctx->sha384_state[5], output, 40);

	/* Tell that we are uninitialized */
	ctx->magic = 0;
}

void sha384_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA384_DIGEST_SIZE])
{
	sha384_context ctx;
	int pos = 0;

	sha384_init(&ctx);

	while (inputs[pos] != NULL) {
		const u8 *buf = inputs[pos];
		u32 buflen = ilens[pos];

		sha384_update(&ctx, buf, buflen);

		pos += 1;
	}

	sha384_final(&ctx, output);
}

void sha384(const u8 *input, u32 ilen, u8 output[SHA384_DIGEST_SIZE])
{
	const u8 *inputs[2];
	u32 ilens[1];

	inputs[0] = input;
	inputs[1] = NULL;

	ilens[0] = ilen;

	sha384_scattered(inputs, ilens, output);
}

#else /* WITH_HASH_SHA384 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHA384 */
