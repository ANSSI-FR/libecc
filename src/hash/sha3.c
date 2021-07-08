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
#include "../utils/utils.h"
#include "sha3.h"

/* Init function depending on the digest size */
void _sha3_init(sha3_context *ctx, u8 digest_size)
{
	/* Check given inpur digest size: we only consider KECCAK versions 
	 * mapped on SHA-3 instances (224, 256, 384, 512).
	 */
        MUST_HAVE( (digest_size == (224/8)) || (digest_size == (256/8)) || \
                (digest_size == (384/8)) || (digest_size == (512/8)) );

	MUST_HAVE(ctx != NULL);

        /* Zeroize the internal state */
        local_memset(ctx->sha3_state, 0, sizeof(ctx->sha3_state));

        ctx->sha3_idx = 0;
        ctx->sha3_digest_size = digest_size;
        ctx->sha3_block_size = (KECCAK_SLICES * KECCAK_SLICES * sizeof(u64)) - (2 * digest_size);

	/* Detect endianness */
	ctx->sha3_endian = arch_is_big_endian() ? SHA3_BIG : SHA3_LITTLE;

        return;
}

/* Update hash function */
void _sha3_update(sha3_context *ctx, const u8 *input, u32 ilen)
{
        u32 i;
        u8 *state;

	MUST_HAVE((ctx != NULL) && (input != NULL));

        state = (u8*)(ctx->sha3_state);

        for(i = 0; i < ilen; i++){
                /* Compute the index depending on the endianness */
                u64 idx = (ctx->sha3_endian == SHA3_LITTLE) ? ctx->sha3_idx : SWAP64_Idx(ctx->sha3_idx);
                ctx->sha3_idx++;
                /* Update the state, and adapt endianness order */
                state[idx] ^= input[i];
                if(ctx->sha3_idx == ctx->sha3_block_size){
                        KECCAKF(ctx->sha3_state);
                        ctx->sha3_idx = 0;
                }
        }

        return;
}

/* Finalize hash function */
void _sha3_finalize(sha3_context *ctx, u8 *output)
{
        unsigned int i;
        u8 *state;

	MUST_HAVE((ctx != NULL) && (output != NULL));
	MUST_HAVE(ctx->sha3_digest_size <= sizeof(ctx->sha3_state));

        state = (u8*)(ctx->sha3_state);

        /* Proceed with the padding of the last block */
        /* Compute the index depending on the endianness */
        if(ctx->sha3_endian == SHA3_LITTLE){
                /* Little endian case */
                state[ctx->sha3_idx] ^= 0x06;
                state[ctx->sha3_block_size - 1] ^= 0x80;
        }
        else{
                /* Big endian case */
                state[SWAP64_Idx(ctx->sha3_idx)] ^= 0x06;
                state[SWAP64_Idx(ctx->sha3_block_size - 1)] ^= 0x80;
        }
        KECCAKF(ctx->sha3_state);
        for(i = 0; i < ctx->sha3_digest_size; i++){
                output[i] = (ctx->sha3_endian == SHA3_LITTLE) ? state[i] : state[SWAP64_Idx(i)];
        }

        return;
}
