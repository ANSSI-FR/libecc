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
#if defined(WITH_HASH_STREEBOG256) || defined(WITH_HASH_STREEBOG512)

/*
 * NOTE: we put STREEBOG256 and STREEBOG512 in the same compilation unit on
 * purpose, so that we avoid duplicating the rather big tables that are shared
 * between the two digest versions.
 */

#include "../utils/utils.h"
#if defined(WITH_HASH_STREEBOG256)
#include "streebog256.h"
#endif
#if defined(WITH_HASH_STREEBOG512)
#include "streebog512.h"
#endif

/*** Generic functions for both STREEBOG256 and STREEBOG512 ***/
/* Init */
static void streebog_init(streebog_context *ctx, u8 digest_size, u8 block_size)
{
	/* Sanity check */
	MUST_HAVE((digest_size == 32) || (digest_size == 64));

	MUST_HAVE(ctx != NULL);

	/* Zeroize the internal state */
	local_memset(ctx, 0, sizeof(streebog_context));

	if(digest_size == 32){
		local_memset(ctx->h, 1, sizeof(ctx->h));
	}

	/* Initialize our digest size and block size */
	ctx->streebog_digest_size = digest_size;
	ctx->streebog_block_size = block_size;
	/* Detect endianness */
	ctx->streebog_endian = arch_is_big_endian() ? STREEBOG_BIG : STREEBOG_LITTLE;
}

static void streebog_update(streebog_context *ctx, const u8 *input, u32 ilen)
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
	left = ctx->streebog_total & 0x3F;
	fill = STREEBOG_BLOCK_SIZE - left;

	ctx->streebog_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		local_memcpy(ctx->streebog_buffer + left, data_ptr, fill);
		streebog_process(ctx, ctx->streebog_buffer, (8 * STREEBOG_BLOCK_SIZE));
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= STREEBOG_BLOCK_SIZE) {
		streebog_process(ctx, data_ptr, (8 * STREEBOG_BLOCK_SIZE));
		data_ptr += STREEBOG_BLOCK_SIZE;
		remain_ilen -= STREEBOG_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		local_memcpy(ctx->streebog_buffer + left, data_ptr, remain_ilen);
	}

	return;
}

static void streebog_final(streebog_context *ctx, u8 *output)
{
	unsigned int block_present = 0;
	u8 last_padded_block[STREEBOG_BLOCK_SIZE];
	u64 Z[STREEBOG_BLOCK_U64_SIZE];
	unsigned int j;
	u8 digest_size;
	u8 idx;

	MUST_HAVE((ctx != NULL) && (output != NULL));

	digest_size = ctx->streebog_digest_size;
	/* Sanity check */
	MUST_HAVE((digest_size == 32) || (digest_size == 64));

	/* Zero init our Z */
	local_memset(Z, 0, sizeof(Z));

	/* Fill in our last block with zeroes */
	local_memset(last_padded_block, 0, sizeof(last_padded_block));

	/* This is our final step, so we proceed with the padding */
	block_present = ctx->streebog_total % STREEBOG_BLOCK_SIZE;
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		local_memcpy(last_padded_block, ctx->streebog_buffer,
			     block_present);
	}

	/* Put the 0x01 byte, beginning of padding  */
	last_padded_block[block_present] = 0x01;

	streebog_process(ctx, last_padded_block, (8 * (ctx->streebog_total % STREEBOG_BLOCK_SIZE)));

	gN(ctx->h, ctx->N, Z);
	gN(ctx->h, ctx->Sigma, Z);

	for(j = 0; j < STREEBOG_BLOCK_U64_SIZE; j++){
		ctx->h[j] = S64(ctx->h[j]);
	}

	idx = 0;

	if(digest_size == 64){
		/* 512-bit hash case */
		STREEBOG_PUT_UINT64(ctx->h[0], output, idx, ctx->streebog_endian); idx += 8;
		STREEBOG_PUT_UINT64(ctx->h[1], output, idx, ctx->streebog_endian); idx += 8;
		STREEBOG_PUT_UINT64(ctx->h[2], output, idx, ctx->streebog_endian); idx += 8;
		STREEBOG_PUT_UINT64(ctx->h[3], output, idx, ctx->streebog_endian); idx += 8;
	}
	/* 256 and 512-bit hash case */
	STREEBOG_PUT_UINT64(ctx->h[4], output, idx, ctx->streebog_endian); idx += 8;
	STREEBOG_PUT_UINT64(ctx->h[5], output, idx, ctx->streebog_endian); idx += 8;
	STREEBOG_PUT_UINT64(ctx->h[6], output, idx, ctx->streebog_endian); idx += 8;
	STREEBOG_PUT_UINT64(ctx->h[7], output, idx, ctx->streebog_endian); idx += 8;
}

#if defined(WITH_HASH_STREEBOG256)

/* Init */
void streebog256_init(streebog256_context *ctx)
{
	streebog_init(ctx, STREEBOG256_DIGEST_SIZE, STREEBOG256_BLOCK_SIZE);

	ctx->magic = STREEBOG256_HASH_MAGIC;
}

/* Update */
void streebog256_update(streebog256_context *ctx, const u8 *input, u32 ilen)
{
	STREEBOG256_HASH_CHECK_INITIALIZED(ctx);

	streebog_update(ctx, input, ilen);
}

/* Finalize */
void streebog256_final(streebog256_context *ctx,
		       u8 output[STREEBOG256_DIGEST_SIZE])
{
	STREEBOG256_HASH_CHECK_INITIALIZED(ctx);

	streebog_final(ctx, output);

	/* Uninit our context magic */
	ctx->magic = 0;
}

void streebog256_scattered(const u8 **inputs, const u32 *ilens,
			   u8 output[STREEBOG256_DIGEST_SIZE])
{
	streebog256_context ctx;
	int pos = 0;

	streebog256_init(&ctx);

	while (inputs[pos] != NULL) {
		streebog256_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	streebog256_final(&ctx, output);
}

void streebog256(const u8 *input, u32 ilen, u8 output[STREEBOG256_DIGEST_SIZE])
{
	streebog256_context ctx;

	streebog256_init(&ctx);
	streebog256_update(&ctx, input, ilen);
	streebog256_final(&ctx, output);
}

#endif /* defined(WITH_HASH_STREEBOG256) */


#if defined(WITH_HASH_STREEBOG512)

/* Init */
void streebog512_init(streebog512_context *ctx)
{
	streebog_init(ctx, STREEBOG512_DIGEST_SIZE, STREEBOG512_BLOCK_SIZE);

	ctx->magic = STREEBOG512_HASH_MAGIC;
}

/* Update */
void streebog512_update(streebog512_context *ctx, const u8 *input, u32 ilen)
{
	STREEBOG512_HASH_CHECK_INITIALIZED(ctx);

	streebog_update(ctx, input, ilen);
}

/* Finalize */
void streebog512_final(streebog512_context *ctx,
		       u8 output[STREEBOG512_DIGEST_SIZE])
{
	STREEBOG512_HASH_CHECK_INITIALIZED(ctx);

	streebog_final(ctx, output);

	/* Uninit our context magic */
	ctx->magic = 0;
}

void streebog512_scattered(const u8 **inputs, const u32 *ilens,
			   u8 output[STREEBOG512_DIGEST_SIZE])
{
	streebog512_context ctx;
	int pos = 0;

	streebog512_init(&ctx);

	while (inputs[pos] != NULL) {
		streebog512_update(&ctx, inputs[pos], ilens[pos]);
		pos += 1;
	}

	streebog512_final(&ctx, output);
}

void streebog512(const u8 *input, u32 ilen, u8 output[STREEBOG512_DIGEST_SIZE])
{
	streebog512_context ctx;

	streebog512_init(&ctx);
	streebog512_update(&ctx, input, ilen);
	streebog512_final(&ctx, output);
}

#endif /* defined(WITH_HASH_STREEBOG512) */

#else /* !(defined(WITH_HASH_STREEBOG256) || defined(WITH_HASH_STREEBOG512)) */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;

#endif /* defined(WITH_HASH_STREEBOG256) || defined(WITH_HASH_STREEBOG512) */

