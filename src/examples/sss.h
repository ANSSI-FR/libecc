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
#ifndef __SSS_H__
#define __SSS_H__

/* NOTE: we need the arithmetic library for SSS as all
 * operations will take place in Fp with p a public known
 * prime number.
 */
#include "../lib_ecc_config.h"
#include "libarith.h"
/* We use HMAC */
#include "../hash/hmac.h"
/* We generate random */
#include "../external_deps/rand.h"

typedef enum { false, true } bool;

/* The final secret size in bytes, corresponding to the
 * size of an element in Fp with ~256 bit prime.
 */
#define SSS_SECRET_SIZE	32

/* Secrets and shares typedefs for "raw" SSS */
typedef struct ATTRIBUTE_PACKED {
	u8 secret[SSS_SECRET_SIZE];
} sss_secret;
typedef struct ATTRIBUTE_PACKED {
	/* Index x of the share */
	u16 index;
	/* Value of the share */
	u8 share[SSS_SECRET_SIZE];
} _sss_raw_share;

/* Security wrapper for the secret for "secured" SSS */
typedef struct ATTRIBUTE_PACKED {
	_sss_raw_share raw_share;
	u8 raw_share_hmac[SHA256_DIGEST_SIZE];
} sss_share;

/* SSS shares and secret generation */
ATTRIBUTE_WARN_UNUSED_RET int sss_generate(sss_share *shares, u16 k, u16 n, sss_secret *secret, bool input_secret);

/* SSS shares and secret combination */
ATTRIBUTE_WARN_UNUSED_RET int sss_combine(const sss_share *shares, u16 k, sss_secret *secret);

/* SSS shares regeneration from existing shares */
ATTRIBUTE_WARN_UNUSED_RET int sss_regenerate(sss_share *shares, u16 k, u16 n, sss_secret *secret);

#endif /* __SSS_H__ */
