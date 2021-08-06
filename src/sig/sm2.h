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
#include "../lib_ecc_types.h"
#ifdef WITH_SIG_SM2

#ifndef __SM2_H__
#define __SM2_H__

#include "../words/words.h"
#include "ec_key.h"
#include "../hash/hash_algs.h"
#include "../curves/curves.h"
#include "../utils/utils.h"

#define SM2_R_LEN(q_bit_len)  (BYTECEIL(q_bit_len))
#define SM2_S_LEN(q_bit_len)  (BYTECEIL(q_bit_len))
#define SM2_SIGLEN(q_bit_len) (SM2_R_LEN(q_bit_len) + \
				 SM2_S_LEN(q_bit_len))
#define SM2_MAX_SIGLEN SM2_SIGLEN(CURVES_MAX_Q_BIT_LEN)
#define SM2_MAX_ID_LEN 8191 /* SM2 user ID max byte length */

/*
 * Compute max signature length for all the mechanisms enabled
 * in the library (see lib_ecc_config.h). Having that done during
 * preprocessing sadly requires some verbosity.
 */
#ifndef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN 0
#endif
#if ((EC_MAX_SIGLEN) < (SM2_MAX_SIGLEN))
#undef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN SM2_MAX_SIGLEN
#endif

typedef struct {
	hash_context h_ctx;
	word_t magic;
} sm2_sign_data;

struct ec_sign_context;

int sm2_gen_priv_key(ec_priv_key *priv_key);

int sm2_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv);

u8 sm2_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

int _sm2_sign_init(struct ec_sign_context *ctx);

int _sm2_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen);

int _sm2_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

typedef struct {
	nn r;
	nn s;
	hash_context h_ctx;
	word_t magic;
} sm2_verify_data;

struct ec_verify_context;

int _sm2_verify_init(struct ec_verify_context *ctx,
		       const u8 *sig, u8 siglen);

int _sm2_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen);

int _sm2_verify_finalize(struct ec_verify_context *ctx);

#endif /* __SM2_H__ */
#endif /* WITH_SIG_SM2 */
