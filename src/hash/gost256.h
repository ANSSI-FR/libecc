#include "../lib_ecc_config.h"
#ifdef WITH_HASH_GOST256

#ifndef __GOST256_H__
#define __GOST256_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "gost.h"

#define GOST256_BLOCK_SIZE   GOST_BLOCK_SIZE
#define GOST256_DIGEST_SIZE  32

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < GOST256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE GOST256_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < GOST256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE GOST256_BLOCK_SIZE
#endif

#define GOST256_HASH_MAGIC ((word_t)(0x11221a2122328332ULL))
#define GOST256_HASH_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == GOST256_HASH_MAGIC))

typedef gost_context gost256_context;

void gost256_init(gost256_context *ctx);
void gost256_update(gost256_context *ctx, const u8 *input, u32 ilen);
void gost256_final(gost256_context *ctx, u8 output[GOST256_DIGEST_SIZE]);
void gost256_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[GOST256_DIGEST_SIZE]);
void gost256(const u8 *input, u32 ilen, u8 output[GOST256_DIGEST_SIZE]);

#endif /* __GOST256_H__ */
#endif /* WITH_HASH_GOST256 */
