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
#if defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448)

#ifndef __EDDSA_H__
#define __EDDSA_H__

#include "../words/words.h"
#include "ec_key.h"
#include "../hash/hash_algs.h"
#include "../curves/curves.h"
#include "../utils/utils.h"

/*
 * NOTE: for EDDSA, the signature length is twice the encoding of integers,
 * which corresponds to half the hash size.
 */
#define EDDSA_R_LEN(hsize)  (hsize / 2)
#define EDDSA_S_LEN(hsize)  (hsize / 2)
#define EDDSA_SIGLEN(hsize) (EDDSA_R_LEN(hsize) + EDDSA_S_LEN(hsize))
#define EDDSA_MAX_SIGLEN EDDSA_SIGLEN(MAX_DIGEST_SIZE)

/*
 * Compute max signature length for all the mechanisms enabled
 * in the library (see lib_ecc_config.h). Having that done during
 * preprocessing sadly requires some verbosity.
 */
#ifndef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN 0
#endif
#if ((EC_MAX_SIGLEN) < (EDDSA_MAX_SIGLEN))
#undef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN EDDSA_MAX_SIGLEN
#endif

typedef struct {
	hash_context h_ctx;
	word_t magic;
} eddsa_sign_data;

struct ec_sign_context;

int eddsa_gen_priv_key(ec_priv_key *priv_key);
int eddsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv);

u8 eddsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

int _eddsa_sign_init_pre_hash(struct ec_sign_context *ctx);

int _eddsa_sign_update_pre_hash(struct ec_sign_context *ctx,
				const u8 *chunk, u32 chunklen);

int _eddsa_sign_finalize_pre_hash(struct ec_sign_context *ctx,
				  u8 *sig, u8 siglen);

int _eddsa_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
		const u8 *m, u32 mlen, int (*rand) (nn_t out, nn_src_t q),
		ec_sig_alg_type sig_type, hash_alg_type hash_type,
		const u8 *adata, u16 adata_len);

typedef struct {
	prj_pt _R;
	nn S;
	hash_context h_ctx;
	hash_context h_ctx_pre_hash;
	word_t magic;
} eddsa_verify_data;

struct ec_verify_context;

int _eddsa_verify_init(struct ec_verify_context *ctx,
		       const u8 *sig, u8 siglen);

int _eddsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen);

int _eddsa_verify_finalize(struct ec_verify_context *ctx);

/* Functions specific to EdDSA */
int eddsa_derive_priv_key(ec_priv_key *priv_key);
int eddsa_import_priv_key(ec_priv_key *priv_key, const u8 *buf, u16 buflen,
			  const ec_params *shortw_curve_params,
			  ec_sig_alg_type sig_type);
int eddsa_import_pub_key(ec_pub_key *out_pub, const u8 *buf, u16 buflen,
			 const ec_params *shortw_curve_params,
			 ec_sig_alg_type sig_type);
int eddsa_export_pub_key(const ec_pub_key *in_pub, u8 *buf, u16 buflen);
int eddsa_import_key_pair_from_priv_key_buf(ec_key_pair *kp,
					    const u8 *buf, u16 buflen,
					    const ec_params *shortw_curve_params,
					    ec_sig_alg_type sig_type);

#endif /* __EDDSA_H__ */
#endif /* defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448) */
