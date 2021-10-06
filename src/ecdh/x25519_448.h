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

#if defined(WITH_X25519) || defined(WITH_X448)

#ifndef __X25519_448_H__
#define __X25519_448_H__

#include "../words/words.h"


#if defined(WITH_X25519)
/* The X25519 function as specified in RFC7748.
 *
 */
ATTRIBUTE_WARN_UNUSED_RET int x25519(const u8 k[32], const u8 u[32], u8 res[32]);

ATTRIBUTE_WARN_UNUSED_RET int x25519_gen_priv_key(u8 priv_key[32]);

ATTRIBUTE_WARN_UNUSED_RET int x25519_init_pub_key(const u8 priv_key[32], u8 pub_key[32]);

ATTRIBUTE_WARN_UNUSED_RET int x25519_derive_secret(const u8 priv_key[32], const u8 peer_pub_key[32], u8 shared_secret[32]);
#endif

#if defined(WITH_X448)
/* The X448 function as specified in RFC7748.
 *
 */
ATTRIBUTE_WARN_UNUSED_RET int x448(const u8 k[56], const u8 u[56], u8 res[56]);

ATTRIBUTE_WARN_UNUSED_RET int x448_gen_priv_key(u8 priv_key[56]);

ATTRIBUTE_WARN_UNUSED_RET int x448_init_pub_key(const u8 priv_key[56], u8 pub_key[56]);

ATTRIBUTE_WARN_UNUSED_RET int x448_derive_secret(const u8 priv_key[56], const u8 peer_pub_key[56], u8 shared_secret[56]);
#endif

#endif /* __X25519_448_H__ */

#endif /* defined(WITH_X25519) || defined(WITH_X448) */
