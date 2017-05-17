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

/* SHA-2 core processing */
static void sha512_process(sha512_context *ctx,
			   const u8 data[SHA512_BLOCK_SIZE])
{
	u64 a, b, c, d, e, f, g, h;
	u64 W[80];
	unsigned int i;

	MUST_HAVE((ctx != NULL) && (data != NULL));

	/* Init our inner variables */
	a = ctx->sha512_state[0];
	b = ctx->sha512_state[1];
	c = ctx->sha512_state[2];
	d = ctx->sha512_state[3];
	e = ctx->sha512_state[4];
	f = ctx->sha512_state[5];
	g = ctx->sha512_state[6];
	h = ctx->sha512_state[7];

	for (i = 0; i < 16; i++) {
		GET_UINT64_BE(W[i], data, 8 * i);
		SHA2CORE_SHA512(a, b, c, d, e, f, g, h, W[i], K_SHA512[i]);
	}

	for (i = 16; i < 80; i++) {
		SHA2CORE_SHA512(a, b, c, d, e, f, g, h, UPDATEW_SHA512(W, i),
				K_SHA512[i]);
	}

	/* Update state */
	ctx->sha512_state[0] += a;
	ctx->sha512_state[1] += b;
	ctx->sha512_state[2] += c;
	ctx->sha512_state[3] += d;
	ctx->sha512_state[4] += e;
	ctx->sha512_state[5] += f;
	ctx->sha512_state[6] += g;
	ctx->sha512_state[7] += h;
}

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
}

/* Update hash function */
void sha512_update(sha512_context *ctx, const u8 *input, u32 ilen)
{
	const u8 *data_ptr = input;
	u32 remain_ilen = ilen;
	u16 fill;
	u8 left;

	MUST_HAVE((ctx != NULL) && (input != NULL));

	/* Nothing to process, return */
	if (ilen == 0) {
		return;
	}

	/* Get what's left in our local buffer */
	left = ctx->sha512_total[0] & 0x7F;
	fill = SHA512_BLOCK_SIZE - left;

	ADD_UINT128_UINT64(ctx->sha512_total[0], ctx->sha512_total[1], ilen);

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		local_memcpy(ctx->sha512_buffer + left, data_ptr, fill);
		sha512_process(ctx, ctx->sha512_buffer);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= SHA512_BLOCK_SIZE) {
		sha512_process(ctx, data_ptr);
		data_ptr += SHA512_BLOCK_SIZE;
		remain_ilen -= SHA512_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		local_memcpy(ctx->sha512_buffer + left, data_ptr, remain_ilen);
	}
}

/* Finalize */
void sha512_final(sha512_context *ctx, u8 output[SHA512_DIGEST_SIZE])
{
	unsigned int block_present = 0;
	u8 last_padded_block[2 * SHA512_BLOCK_SIZE];

	MUST_HAVE((ctx != NULL) && (output != NULL));

	/* Fill in our last block with zeroes */
	local_memset(last_padded_block, 0, sizeof(last_padded_block));

	/* This is our final step, so we proceed with the padding */
	block_present = ctx->sha512_total[0] % SHA512_BLOCK_SIZE;
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		local_memcpy(last_padded_block, ctx->sha512_buffer,
			     block_present);
	}

	/* Put the 0x80 byte, beginning of padding  */
	last_padded_block[block_present] = 0x80;

	/* Handle possible additional block */
	if (block_present > (SHA512_BLOCK_SIZE - 1 - (2 * sizeof(u64)))) {
		/* We need an additional block */
		PUT_MUL8_UINT128_BE(ctx->sha512_total[0], ctx->sha512_total[1],
				    last_padded_block,
				    2 * (SHA512_BLOCK_SIZE - sizeof(u64)));
		sha512_process(ctx, last_padded_block);
		sha512_process(ctx, last_padded_block + SHA512_BLOCK_SIZE);
	} else {
		/* We do not need an additional block */
		PUT_MUL8_UINT128_BE(ctx->sha512_total[0], ctx->sha512_total[1],
				    last_padded_block,
				    SHA512_BLOCK_SIZE - (2 * sizeof(u64)));
		sha512_process(ctx, last_padded_block);
	}

	/* Output the hash result */
	PUT_UINT64_BE(ctx->sha512_state[0], output, 0);
	PUT_UINT64_BE(ctx->sha512_state[1], output, 8);
	PUT_UINT64_BE(ctx->sha512_state[2], output, 16);
	PUT_UINT64_BE(ctx->sha512_state[3], output, 24);
	PUT_UINT64_BE(ctx->sha512_state[4], output, 32);
	PUT_UINT64_BE(ctx->sha512_state[5], output, 40);
	PUT_UINT64_BE(ctx->sha512_state[6], output, 48);
	PUT_UINT64_BE(ctx->sha512_state[7], output, 56);
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
