#include "../lib_ecc_config.h"
#ifdef WITH_HASH_GOST512

#ifndef __GOST512_H__
#define __GOST512_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "gost.h"

#define GOST512_BLOCK_SIZE   GOST_BLOCK_SIZE
#define GOST512_DIGEST_SIZE  64

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < GOST512_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE GOST512_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < GOST512_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE GOST512_BLOCK_SIZE
#endif

#define GOST512_HASH_MAGIC ((word_t)(0x3293187509128364ULL))
#define GOST512_HASH_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == GOST512_HASH_MAGIC))

typedef gost_context gost512_context;

void gost512_init(gost512_context *ctx);
void gost512_update(gost512_context *ctx, const u8 *input, u32 ilen);
void gost512_final(gost512_context *ctx, u8 output[GOST512_DIGEST_SIZE]);
void gost512_scattered(const u8 **inputs, const u32 *ilens,
		      u8 output[GOST512_DIGEST_SIZE]);
void gost512(const u8 *input, u32 ilen, u8 output[GOST512_DIGEST_SIZE]);

#endif /* __GOST512_H__ */
#endif /* WITH_HASH_GOST512 */
