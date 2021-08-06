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
#include "../lib_ecc_types.h"
#ifdef WITH_SIG_ECSDSA

#ifndef __ECSDSA_H__
#define __ECSDSA_H__
#include "../words/words.h"
#include "ec_key.h"
#include "../utils/utils.h"
#include "../hash/hash_algs.h"
#include "../curves/curves.h"

#define ECSDSA_R_LEN(hsize) (hsize)
#define ECSDSA_S_LEN(q_bit_len) (BYTECEIL(q_bit_len))
#define ECSDSA_SIGLEN(hsize, q_bit_len) (ECSDSA_R_LEN(hsize) + \
					 ECSDSA_S_LEN(q_bit_len))
#define ECSDSA_MAX_SIGLEN ECSDSA_SIGLEN(MAX_DIGEST_SIZE, CURVES_MAX_Q_BIT_LEN)

/*
 * Compute max signature length for all the mechanisms enabled
 * in the library (see lib_ecc_config.h). Having that done during
 * preprocessing sadly requires some verbosity.
 */
#ifndef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN 0
#endif
#if ((EC_MAX_SIGLEN) < (ECSDSA_MAX_SIGLEN))
#undef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN ECSDSA_MAX_SIGLEN
#endif

int ecsdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv);

u8 ecsdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

typedef struct {
	hash_context h_ctx;
	nn k;
	word_t magic;
} ecsdsa_sign_data;

int _ecsdsa_sign_init(struct ec_sign_context *ctx);

int _ecsdsa_sign_update(struct ec_sign_context *ctx,
			const u8 *chunk, u32 chunklen);

int _ecsdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

typedef struct {
	hash_context h_ctx;
	u8 r[MAX_DIGEST_SIZE];
	nn s;
	word_t magic;
} ecsdsa_verify_data;

int _ecsdsa_verify_init(struct ec_verify_context *ctx,
			const u8 *sig, u8 siglen);

int _ecsdsa_verify_update(struct ec_verify_context *ctx,
			  const u8 *chunk, u32 chunklen);

int _ecsdsa_verify_finalize(struct ec_verify_context *ctx);

#endif /* __ECSDSA_H__ */
#endif /* WITH_SIG_ECSDSA */
