#include "../lib_ecc_config.h"
#if defined(WITH_HASH_GOST256) || defined(WITH_HASH_GOST512)

/*
 * NOTE: we put GOST256 and GOST512 in the same compilation unit on purpose, so that
 * we avoid duplicating the rather big tables that are shared between the two digest
 * versions.
 */

#include "../utils/utils.h"
#if defined(WITH_HASH_GOST256)
#include "gost256.h"
#endif
#if defined(WITH_HASH_GOST512)
#include "gost512.h"
#endif

/*** Generic functions for both GOST256 and GOST512 ***/
/* Init */
static void gost_init(gost_context *ctx, u8 digest_size, u8 block_size)
{
	/* Sanity check */
	MUST_HAVE((digest_size == 32) || (digest_size == 64));

	MUST_HAVE(ctx != NULL);

	/* Zeroize the internal state */
	local_memset(ctx, 0, sizeof(gost_context));

	if(digest_size == 32){
		local_memset(ctx->h, 1, sizeof(ctx->h));
	}

	/* Initialize our digest size and block size */
	ctx->gost_digest_size = digest_size;
	ctx->gost_block_size = block_size;
        /* Detect endianness */
        ctx->gost_endian = arch_is_big_endian() ? GOST_BIG : GOST_LITTLE;
}

static void gost_update(gost_context *ctx, const u8 *input, u32 ilen)
{
	MUST_HAVE((ctx != NULL) && (input != NULL));
        const u8 *data_ptr = input;
        u32 remain_ilen = ilen;
        u16 fill;
        u8 left;

        /* Nothing to process, return */
        if (ilen == 0) {
                return;
        }

        /* Get what's left in our local buffer */
        left = ctx->gost_total & 0x3F;
        fill = GOST_BLOCK_SIZE - left;

        ctx->gost_total += ilen;

        if ((left > 0) && (remain_ilen >= fill)) {
                /* Copy data at the end of the buffer */
                local_memcpy(ctx->gost_buffer + left, data_ptr, fill);
                gost_process(ctx, ctx->gost_buffer, (8 * GOST_BLOCK_SIZE));
                data_ptr += fill;
                remain_ilen -= fill;
                left = 0;
        }

        while (remain_ilen >= GOST_BLOCK_SIZE) {
                gost_process(ctx, data_ptr, (8 * GOST_BLOCK_SIZE));
                data_ptr += GOST_BLOCK_SIZE;
                remain_ilen -= GOST_BLOCK_SIZE;
        }

        if (remain_ilen > 0) {
                local_memcpy(ctx->gost_buffer + left, data_ptr, remain_ilen);
        }

        return;
}

static void gost_final(gost_context *ctx, u8 *output)
{
        unsigned int block_present = 0;
        u8 last_padded_block[2 * GOST_BLOCK_SIZE];
	u64 Z[GOST_BLOCK_U64_SIZE];
	unsigned int j;
	u8 digest_size;

	MUST_HAVE((ctx != NULL) && (output != NULL));

	digest_size = ctx->gost_digest_size;
	/* Sanity check */
	MUST_HAVE((digest_size == 32) || (digest_size == 64));

	/* Zero init our Z */
	local_memset(Z, 0, sizeof(Z));

        /* Fill in our last block with zeroes */
        local_memset(last_padded_block, 0, sizeof(last_padded_block));

        /* This is our final step, so we proceed with the padding */
        block_present = ctx->gost_total % GOST_BLOCK_SIZE;
        if (block_present != 0) {
                /* Copy what's left in our temporary context buffer */
                local_memcpy(last_padded_block, ctx->gost_buffer,
                             block_present);
        }

        /* Put the 0x01 byte, beginning of padding  */
        last_padded_block[block_present] = 0x01;

        /* Handle possible additional block */
        if (block_present > (GOST_BLOCK_SIZE - 1)) {
                /* We need an additional block */
                gost_process(ctx, last_padded_block, (8 * GOST_BLOCK_SIZE));
                gost_process(ctx, last_padded_block + GOST_BLOCK_SIZE, (8 * (ctx->gost_total % GOST_BLOCK_SIZE)));
        } else {
                /* We do not need an additional block */
                gost_process(ctx, last_padded_block, (8 * (ctx->gost_total % GOST_BLOCK_SIZE)));
        }
	gN(ctx->h, ctx->N, Z);
	gN(ctx->h, ctx->Sigma, Z);

	for(j = 0; j < GOST_BLOCK_U64_SIZE; j++){
		ctx->h[j] = S64(ctx->h[j]);
	}
	if(digest_size == 32){
		/* 256-bit hash case */
		GOST_PUT_UINT64(ctx->h[4], output, 0,  ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[5], output, 8,  ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[6], output, 16, ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[7], output, 24, ctx->gost_endian);
	}
	else{
		/* 512-bit hash case */
		GOST_PUT_UINT64(ctx->h[0], output, 0,  ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[1], output, 8,  ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[2], output, 16, ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[3], output, 24, ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[4], output, 32, ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[5], output, 40, ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[6], output, 48, ctx->gost_endian);
		GOST_PUT_UINT64(ctx->h[7], output, 56, ctx->gost_endian);
	}
}

#if defined(WITH_HASH_GOST256)

/* Init */
void gost256_init(gost256_context *ctx)
{
	gost_init(ctx, GOST256_DIGEST_SIZE, GOST256_BLOCK_SIZE);

	ctx->magic = GOST256_HASH_MAGIC;
}

/* Update */
void gost256_update(gost256_context *ctx, const u8 *input, u32 ilen)
{
	GOST256_HASH_CHECK_INITIALIZED(ctx);

	gost_update(ctx, input, ilen);
}

/* Finalize */
void gost256_final(gost256_context *ctx, u8 output[GOST256_DIGEST_SIZE])
{
	GOST256_HASH_CHECK_INITIALIZED(ctx);

	gost_final(ctx, output);

	/* Uninit our context magic */
	ctx->magic = 0;
}

void gost256_scattered(const u8 **inputs, const u32 *ilens,
                      u8 output[GOST256_DIGEST_SIZE])
{
        gost256_context ctx;
        int pos = 0;

        gost256_init(&ctx);

        while (inputs[pos] != NULL) {
                gost256_update(&ctx, inputs[pos], ilens[pos]);
                pos += 1;
        }

        gost256_final(&ctx, output);
}

void gost256(const u8 *input, u32 ilen, u8 output[GOST256_DIGEST_SIZE])
{
        gost256_context ctx;

        gost256_init(&ctx);
        gost256_update(&ctx, input, ilen);
        gost256_final(&ctx, output);
}

#endif /* defined(WITH_HASH_GOST256) */


#if defined(WITH_HASH_GOST512)

/* Init */
void gost512_init(gost512_context *ctx)
{
	gost_init(ctx, GOST512_DIGEST_SIZE, GOST512_BLOCK_SIZE);

	ctx->magic = GOST512_HASH_MAGIC;
}

/* Update */
void gost512_update(gost512_context *ctx, const u8 *input, u32 ilen)
{
	GOST512_HASH_CHECK_INITIALIZED(ctx);

	gost_update(ctx, input, ilen);
}

/* Finalize */
void gost512_final(gost512_context *ctx, u8 output[GOST512_DIGEST_SIZE])
{
	GOST512_HASH_CHECK_INITIALIZED(ctx);

	gost_final(ctx, output);

	/* Uninit our context magic */
	ctx->magic = 0;
}

void gost512_scattered(const u8 **inputs, const u32 *ilens,
                      u8 output[GOST512_DIGEST_SIZE])
{
        gost512_context ctx;
        int pos = 0;

        gost512_init(&ctx);

        while (inputs[pos] != NULL) {
                gost512_update(&ctx, inputs[pos], ilens[pos]);
                pos += 1;
        }

        gost512_final(&ctx, output);
}

void gost512(const u8 *input, u32 ilen, u8 output[GOST512_DIGEST_SIZE])
{
        gost512_context ctx;

        gost512_init(&ctx);
        gost512_update(&ctx, input, ilen);
        gost512_final(&ctx, output);
}

#endif /* defined(WITH_HASH_GOST512) */

#else /* !(defined(WITH_HASH_GOST256) || defined(WITH_HASH_GOST512)) */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;

#endif /* defined(WITH_HASH_GOST256) || defined(WITH_HASH_GOST512) */

