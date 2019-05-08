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
#ifdef WITH_HASH_SHA256

#include "sha256.h"

/* SHA-2 core processing */
static void sha256_process(sha256_context *ctx,
			   const u8 data[SHA256_BLOCK_SIZE])
{
	u32 a, b, c, d, e, f, g, h;
	u32 W[64];
	unsigned int i;

	MUST_HAVE((ctx != NULL) && (data != NULL));

	/* Init our inner variables */
	a = ctx->sha256_state[0];
	b = ctx->sha256_state[1];
	c = ctx->sha256_state[2];
	d = ctx->sha256_state[3];
	e = ctx->sha256_state[4];
	f = ctx->sha256_state[5];
	g = ctx->sha256_state[6];
	h = ctx->sha256_state[7];

	for (i = 0; i < 16; i++) {
		GET_UINT32_BE(W[i], data, 4 * i);
		SHA2CORE_SHA256(a, b, c, d, e, f, g, h, W[i], K_SHA256[i]);
	}

	for (i = 16; i < 64; i++) {
		SHA2CORE_SHA256(a, b, c, d, e, f, g, h, UPDATEW_SHA256(W, i),
				K_SHA256[i]);
	}

	/* Update state */
	ctx->sha256_state[0] += a;
	ctx->sha256_state[1] += b;
	ctx->sha256_state[2] += c;
	ctx->sha256_state[3] += d;
	ctx->sha256_state[4] += e;
	ctx->sha256_state[5] += f;
	ctx->sha256_state[6] += g;
	ctx->sha256_state[7] += h;
}

/* Init hash function */
void sha256_init(sha256_context *ctx)
{
	MUST_HAVE(ctx != NULL);

	ctx->sha256_total = 0;
	ctx->sha256_state[0] = 0x6A09E667;
	ctx->sha256_state[1] = 0xBB67AE85;
	ctx->sha256_state[2] = 0x3C6EF372;
	ctx->sha256_state[3] = 0xA54FF53A;
	ctx->sha256_state[4] = 0x510E527F;
	ctx->sha256_state[5] = 0x9B05688C;
	ctx->sha256_state[6] = 0x1F83D9AB;
	ctx->sha256_state[7] = 0x5BE0CD19;
}

/* Update hash function */
void sha256_update(sha256_context *ctx, const u8 *input, u32 ilen)
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
	left = ctx->sha256_total & 0x3F;
	fill = SHA256_BLOCK_SIZE - left;

	ctx->sha256_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		local_memcpy(ctx->sha256_buffer + left, data_ptr, fill);
		sha256_process(ctx, ctx->sha256_buffer);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= SHA256_BLOCK_SIZE) {
		sha256_process(ctx, data_ptr);
		data_ptr += SHA256_BLOCK_SIZE;
		remain_ilen -= SHA256_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		local_memcpy(ctx->sha256_buffer + left, data_ptr, remain_ilen);
	}
	return;
}

/* Finalize */
void sha256_final(sha256_context *ctx, u8 output[SHA256_DIGEST_SIZE])
{
	unsigned int block_present = 0;
	u8 last_padded_block[2 * SHA256_BLOCK_SIZE];

	MUST_HAVE((ctx != NULL) && (output != NULL));

	/* Fill in our last block with zeroes */
	local_memset(last_padded_block, 0, sizeof(last_padded_block));

	/* This is our final step, so we proceed with the padding */
	block_present = ctx->sha256_total % SHA256_BLOCK_SIZE;
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		local_memcpy(last_padded_block, ctx->sha256_buffer,
			     block_present);
	}

	/* Put the 0x80 byte, beginning of padding  */
	last_padded_block[block_present] = 0x80;

	/* Handle possible additional block */
	if (block_present > (SHA256_BLOCK_SIZE - 1 - sizeof(u64))) {
		/* We need an additional block */
		PUT_UINT64_BE(8 * ctx->sha256_total, last_padded_block,
			      (2 * SHA256_BLOCK_SIZE) - sizeof(u64));
		sha256_process(ctx, last_padded_block);
		sha256_process(ctx, last_padded_block + SHA256_BLOCK_SIZE);
	} else {
		/* We do not need an additional block */
		PUT_UINT64_BE(8 * ctx->sha256_total, last_padded_block,
			      SHA256_BLOCK_SIZE - sizeof(u64));
		sha256_process(ctx, last_padded_block);
	}

	/* Output the hash result */
	PUT_UINT32_BE(ctx->sha256_state[0], output, 0);
	PUT_UINT32_BE(ctx->sha256_state[1], output, 4);
	PUT_UINT32_BE(ctx->sha256_state[2], output, 8);
	PUT_UINT32_BE(ctx->sha256_state[3], output, 12);
	PUT_UINT32_BE(ctx->sha256_state[4], output, 16);
	PUT_UINT32_BE(ctx->sha256_state[5], output, 20);
	PUT_UINT32_BE(ctx->sha256_state[6], output, 24);
	PUT_UINT32_BE(ctx->sha256_state[7], output, 28);
}

void sha256_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[SHA256_DIGEST_SIZE])
{
	sha256_context ctx;
	int pos = 0;

	sha256_init(&ctx);

	while (inputs[pos] != NULL) {
		sha256_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	sha256_final(&ctx, output);
}

void sha256(const u8 *input, u32 ilen, u8 output[SHA256_DIGEST_SIZE])
{
	sha256_context ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, input, ilen);
	sha256_final(&ctx, output);
}

#else /* WITH_HASH_SHA256 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_SHA256 */
