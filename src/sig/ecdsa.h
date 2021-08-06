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
#ifdef WITH_SIG_ECDSA

#ifndef __ECDSA_H__
#define __ECDSA_H__

#include "ecdsa_common.h"

int ecdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv);

u8 ecdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

int _ecdsa_sign_init(struct ec_sign_context *ctx);

int _ecdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen);

int _ecdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

int _ecdsa_verify_init(struct ec_verify_context *ctx,
		       const u8 *sig, u8 siglen);

int _ecdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen);

int _ecdsa_verify_finalize(struct ec_verify_context *ctx);

#endif /* __ECDSA_H__ */
#endif /* WITH_SIG_ECDSA */
