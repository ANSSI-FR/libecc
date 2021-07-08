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
#if (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA))

#ifndef __ECSDSA_COMMON_H__
#define __ECSDSA_COMMON_H__

#include "../words/words.h"
#include "ec_key.h"
#include "../hash/hash_algs.h"
#include "../sig/sig_algs.h"
#include "../curves/curves.h"
#include "../utils/utils.h"

struct ec_sign_context;

int __ecsdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv,
			   ec_sig_alg_type key_type);
u8 __ecsdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

int __ecsdsa_sign_init(struct ec_sign_context *ctx,
		       ec_sig_alg_type key_type, int optimized);
int __ecsdsa_sign_update(struct ec_sign_context *ctx,
			 const u8 *chunk, u32 chunklen);
int __ecsdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

int __ecsdsa_verify_init(struct ec_verify_context *ctx,
			 const u8 *sig, u8 siglen,
			 ec_sig_alg_type key_type, int optimized);
int __ecsdsa_verify_update(struct ec_verify_context *ctx,
			   const u8 *chunk, u32 chunklen);
int __ecsdsa_verify_finalize(struct ec_verify_context *ctx);

#endif /* __ECSDSA_COMMON_H__ */
#endif /* (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA)) */
