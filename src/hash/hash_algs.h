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
#ifndef __HASH_ALGS_H__
#define __HASH_ALGS_H__

#include "../lib_ecc_config.h"
#include "../lib_ecc_types.h"
#include "../words/words.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "sha512-224.h"
#include "sha512-256.h"
#include "sha3-224.h"
#include "sha3-256.h"
#include "sha3-384.h"
#include "sha3-512.h"
#include "sm3.h"
#include "shake256.h"
#include "streebog256.h"
#include "streebog512.h"
#include "../utils/utils.h"

#if (MAX_DIGEST_SIZE == 0)
#error "It seems you disabled all hash algorithms in lib_ecc_config.h"
#endif

#if (MAX_BLOCK_SIZE == 0)
#error "It seems you disabled all hash algorithms in lib_ecc_config.h"
#endif

typedef union {
#ifdef SHA224_BLOCK_SIZE
	sha224_context sha224;
#endif
#ifdef SHA256_BLOCK_SIZE
	sha256_context sha256;
#endif
#ifdef SHA384_BLOCK_SIZE
	sha384_context sha384;
#endif
#ifdef SHA512_BLOCK_SIZE
	sha512_context sha512;
#endif
#ifdef SHA512_224_BLOCK_SIZE
	sha512_224_context sha512_224;
#endif
#ifdef SHA512_256_BLOCK_SIZE
	sha512_256_context sha512_256;
#endif
#ifdef SHA3_224_BLOCK_SIZE
	sha3_224_context sha3_224;
#endif
#ifdef SHA3_256_BLOCK_SIZE
	sha3_256_context sha3_256;
#endif
#ifdef SHA3_384_BLOCK_SIZE
	sha3_384_context sha3_384;
#endif
#ifdef SHA3_512_BLOCK_SIZE
	sha3_512_context sha3_512;
#endif
#ifdef SHAKE256_BLOCK_SIZE
	shake256_context shake256;
#endif
#ifdef SM3_BLOCK_SIZE
	sm3_context sm3;
#endif
#ifdef STREEBOG256_BLOCK_SIZE
	streebog256_context streebog256;
#endif
#ifdef STREEBOG512_BLOCK_SIZE
	streebog512_context streebog512;
#endif
} hash_context;

typedef void (*_hfunc_init) (hash_context * hctx);
typedef void (*_hfunc_update) (hash_context * hctx,
			       const unsigned char *chunk, u32 chunklen);
typedef void (*_hfunc_finalize) (hash_context * hctx, unsigned char *output);
typedef void (*_hfunc_scattered) (const unsigned char **inputs,
				  const u32 *ilens, unsigned char *output);

#define HASH_MAPPING_SANITY_CHECK(A)			\
	MUST_HAVE(((A) != NULL) && 			\
		  ((A)->name != NULL) &&		\
		  ((A)->hfunc_init != NULL) &&		\
		  ((A)->hfunc_update != NULL) &&	\
		  ((A)->hfunc_finalize != NULL) &&	\
		  ((A)->hfunc_scattered != NULL))

/*
 * All the hash algorithms we support are abstracted using the following
 * structure (and following map) which provides for each hash alg its
 * digest size, its block size and the associated scattered function.
 */
typedef struct {
	hash_alg_type type;
	const char *name;
	u8 digest_size;
	u8 block_size;
	_hfunc_init hfunc_init;
	_hfunc_update hfunc_update;
	_hfunc_finalize hfunc_finalize;
	_hfunc_scattered hfunc_scattered;
} hash_mapping;

#define MAX_HASH_ALG_NAME_LEN	0
static const hash_mapping hash_maps[] = {
#ifdef WITH_HASH_SHA224
	{.type = SHA224,	/* SHA224 */
	 .name = "SHA224",
	 .digest_size = SHA224_DIGEST_SIZE,
	 .block_size = SHA224_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha224_init,
	 .hfunc_update = (_hfunc_update) sha224_update,
	 .hfunc_finalize = (_hfunc_finalize) sha224_final,
	 .hfunc_scattered = sha224_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA224 */
#ifdef WITH_HASH_SHA256
	{.type = SHA256,	/* SHA256 */
	 .name = "SHA256",
	 .digest_size = SHA256_DIGEST_SIZE,
	 .block_size = SHA256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha256_init,
	 .hfunc_update = (_hfunc_update) sha256_update,
	 .hfunc_finalize = (_hfunc_finalize) sha256_final,
	 .hfunc_scattered = sha256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA256 */
#ifdef WITH_HASH_SHA384
	{.type = SHA384,	/* SHA384 */
	 .name = "SHA384",
	 .digest_size = SHA384_DIGEST_SIZE,
	 .block_size = SHA384_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha384_init,
	 .hfunc_update = (_hfunc_update) sha384_update,
	 .hfunc_finalize = (_hfunc_finalize) sha384_final,
	 .hfunc_scattered = sha384_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA384 */
#ifdef WITH_HASH_SHA512
	{.type = SHA512,	/* SHA512 */
	 .name = "SHA512",
	 .digest_size = SHA512_DIGEST_SIZE,
	 .block_size = SHA512_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha512_init,
	 .hfunc_update = (_hfunc_update) sha512_update,
	 .hfunc_finalize = (_hfunc_finalize) sha512_final,
	 .hfunc_scattered = sha512_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA512 */
#ifdef WITH_HASH_SHA512_224
	{.type = SHA512_224,	/* SHA512_224 */
	 .name = "SHA512_224",
	 .digest_size = SHA512_224_DIGEST_SIZE,
	 .block_size = SHA512_224_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha512_224_init,
	 .hfunc_update = (_hfunc_update) sha512_224_update,
	 .hfunc_finalize = (_hfunc_finalize) sha512_224_final,
	 .hfunc_scattered = sha512_224_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA512_224 */
#ifdef WITH_HASH_SHA512_256
	{.type = SHA512_256,	/* SHA512_256 */
	 .name = "SHA512_256",
	 .digest_size = SHA512_256_DIGEST_SIZE,
	 .block_size = SHA512_256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha512_256_init,
	 .hfunc_update = (_hfunc_update) sha512_256_update,
	 .hfunc_finalize = (_hfunc_finalize) sha512_256_final,
	 .hfunc_scattered = sha512_256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA512_256 */
#ifdef WITH_HASH_SHA3_224
	{.type = SHA3_224,	/* SHA3_224 */
	 .name = "SHA3_224",
	 .digest_size = SHA3_224_DIGEST_SIZE,
	 .block_size = SHA3_224_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_224_init,
	 .hfunc_update = (_hfunc_update) sha3_224_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_224_final,
	 .hfunc_scattered = sha3_224_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA3_224 */
#ifdef WITH_HASH_SHA3_256
	{.type = SHA3_256,	/* SHA3_256 */
	 .name = "SHA3_256",
	 .digest_size = SHA3_256_DIGEST_SIZE,
	 .block_size = SHA3_256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_256_init,
	 .hfunc_update = (_hfunc_update) sha3_256_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_256_final,
	 .hfunc_scattered = sha3_256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA3_256 */
#ifdef WITH_HASH_SHA3_384
	{.type = SHA3_384,	/* SHA3_384 */
	 .name = "SHA3_384",
	 .digest_size = SHA3_384_DIGEST_SIZE,
	 .block_size = SHA3_384_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_384_init,
	 .hfunc_update = (_hfunc_update) sha3_384_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_384_final,
	 .hfunc_scattered = sha3_384_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA3_384 */
#ifdef WITH_HASH_SHA3_512
	{.type = SHA3_512,	/* SHA3_512 */
	 .name = "SHA3_512",
	 .digest_size = SHA3_512_DIGEST_SIZE,
	 .block_size = SHA3_512_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_512_init,
	 .hfunc_update = (_hfunc_update) sha3_512_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_512_final,
	 .hfunc_scattered = sha3_512_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA3_512 */
#ifdef WITH_HASH_SM3
        {.type = SM3,   /* SM3 */
         .name = "SM3",
         .digest_size = SM3_DIGEST_SIZE,
         .block_size = SM3_BLOCK_SIZE,
         .hfunc_init = (_hfunc_init) sm3_init,
         .hfunc_update = (_hfunc_update) sm3_update,
         .hfunc_finalize = (_hfunc_finalize) sm3_final,
         .hfunc_scattered = sm3_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 4)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 4
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SM3 */
#ifdef WITH_HASH_SHAKE256
	{.type = SHAKE256,	/* SHAKE256 */
	 .name = "SHAKE256",
	 .digest_size = SHAKE256_DIGEST_SIZE,
	 .block_size = SHAKE256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) shake256_init,
	 .hfunc_update = (_hfunc_update) shake256_update,
	 .hfunc_finalize = (_hfunc_finalize) shake256_final,
	 .hfunc_scattered = shake256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHAKE256 */
#ifdef WITH_HASH_STREEBOG256
	{.type = STREEBOG256,	/* STREEBOG256 */
	 .name = "STREEBOG256",
	 .digest_size = STREEBOG256_DIGEST_SIZE,
	 .block_size = STREEBOG256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) streebog256_init,
	 .hfunc_update = (_hfunc_update) streebog256_update,
	 .hfunc_finalize = (_hfunc_finalize) streebog256_final,
	 .hfunc_scattered = streebog256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 12)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 12
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_STREEBOG256 */
#ifdef WITH_HASH_STREEBOG512
	{.type = STREEBOG512,	/* STREEBOG512 */
	 .name = "STREEBOG512",
	 .digest_size = STREEBOG512_DIGEST_SIZE,
	 .block_size = STREEBOG512_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) streebog512_init,
	 .hfunc_update = (_hfunc_update) streebog512_update,
	 .hfunc_finalize = (_hfunc_finalize) streebog512_final,
	 .hfunc_scattered = streebog512_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 12)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 12
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_STREEBOG512 */
	{.type = UNKNOWN_HASH_ALG,	/* Needs to be kept last */
	 .name = "UNKNOWN",
	 .digest_size = 0,
	 .block_size = 0,
	 .hfunc_init = NULL,
	 .hfunc_update = NULL,
	 .hfunc_finalize = NULL,
	 .hfunc_scattered = NULL},
};

const hash_mapping *get_hash_by_name(const char *hash_name);
const hash_mapping *get_hash_by_type(hash_alg_type hash_type);
int get_hash_sizes(hash_alg_type hash_type, u8 *digest_size, u8 *block_size);
int hash_mapping_callbacks_sanity_check(const hash_mapping *h);

#endif /* __HASH_ALGS_H__ */
