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
#ifndef __SIG_ALGS_H__
#define __SIG_ALGS_H__

#include "sig_algs_internal.h"

/* Generic private key generation function */
int generic_gen_priv_key(ec_priv_key *priv_key);

/* Private key generation function specific to each scheme */
int gen_priv_key(ec_priv_key *priv_key);

/*
 * Generic function to init a uninitialized public key from an initialized
 * private key. The function uses the expected logic to derive the key
 * (e.g. Y=xG, Y=(x^-1)G, etc). It returns -1 on error (i.e. if the signature
 * alg is unknown) in which case the public key has not been initialized.
 */
int init_pubkey_from_privkey(ec_pub_key *pub_key, ec_priv_key *priv_key);

const ec_sig_mapping *get_sig_by_name(const char *ec_sig_name);
const ec_sig_mapping *get_sig_by_type(ec_sig_alg_type sig_type);

/* Sanity checks for calbacks */
int ec_sig_mapping_callbacks_sanity_check(const ec_sig_mapping *sig);
int ec_sig_ctx_callbacks_sanity_check(const struct ec_sign_context *sig_ctx);
int ec_verify_ctx_callbacks_sanity_check(const struct ec_verify_context *verify_ctx);

/*
 * Compute generic effective signature length depending on the curve parameters,
 * the signature algorithm and the hash function
 */
int ec_get_sig_len(const ec_params *params, ec_sig_alg_type sig_type,
		   hash_alg_type hash_type, u8 *siglen);

/* Generic signature init/update/finalize */

int _ec_sign_init(struct ec_sign_context *ctx,
                         const ec_key_pair *key_pair,
                         int (*rand) (nn_t out, nn_src_t q),
                         ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len);

int ec_sign_init(struct ec_sign_context *ctx, const ec_key_pair *key_pair,
		 ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len);

int ec_sign_update(struct ec_sign_context *ctx, const u8 *chunk, u32 chunklen);

int ec_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

int _ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
             const u8 *m, u32 mlen,
             int (*rand) (nn_t out, nn_src_t q),
             ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len);

int ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
            const u8 *m, u32 mlen,
            ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len);

/* Generic signature verification init/update/finalize */

int ec_verify_init(struct ec_verify_context *ctx, const ec_pub_key *pub_key,
		   const u8 *sig, u8 siglen, ec_sig_alg_type sig_type,
		   hash_alg_type hash_type, const u8 *adata, u16 adata_len);

int ec_verify_update(struct ec_verify_context *ctx,
		     const u8 *chunk, u32 chunklen);

int ec_verify_finalize(struct ec_verify_context *ctx);

int ec_verify(const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
              const u8 *m, u32 mlen,
              ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len);

int ec_structured_sig_import_from_buf(u8 *sig, u32 siglen,
                                      const u8 *out_buf, u32 outlen,
                                      ec_sig_alg_type * sig_type,
                                      hash_alg_type * hash_type,
                                      u8 curve_name[MAX_CURVE_NAME_LEN]);

int ec_structured_sig_export_to_buf(const u8 *sig, u32 siglen,
                                    u8 *out_buf, u32 outlen,
                                    ec_sig_alg_type sig_type,
                                    hash_alg_type hash_type,
                                    const u8
                                    curve_name[MAX_CURVE_NAME_LEN]);

#endif /* __SIG_ALGS_H__ */
