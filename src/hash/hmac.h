#ifndef __HMAC_H__
#define __HMAC_H__

#include "../lib_ecc_config.h"
#ifdef WITH_HMAC

#include "../words/words.h"
#include "../utils/utils.h"
#include "hash_algs.h"

#define HMAC_MAGIC ((word_t)(0x9849020187612083ULL))
#define HMAC_CHECK_INITIALIZED(A) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == HMAC_MAGIC) && ((A)->hash != NULL))

/* The HMAC structure is made of two hash contexts */
typedef struct {
	/* The hash mapping associated with the hmac */
        const hash_mapping *hash;
	/* The two hash contexts (inner and outer) */
        hash_context in_ctx;
        hash_context out_ctx;
        /* Initialization magic value */
        word_t magic;
} hmac_context;

int hmac_init(hmac_context *ctx, const u8 *hmackey, u32 hmackey_len, hash_alg_type hash_type);

int hmac_update(hmac_context *ctx, const u8 *input, u32 ilen);

int hmac_finalize(hmac_context *ctx, u8 *output, u8 *outlen);

int hmac(const u8 *hmackey, u32 hmackey_len, hash_alg_type hash_type, const u8 *input, u32 ilen, u8 *output, u8 *outlen);

#endif /* WITH_HMAC */

#endif /* __HMAC_H__ */
