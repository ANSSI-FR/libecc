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
#ifndef __CURVES_LIST_H__
#define __CURVES_LIST_H__

#include "../lib_ecc_config.h"
#include "../lib_ecc_types.h"
#include "../words/words.h"
#include "known/ec_params_brainpoolp192r1.h"
#include "known/ec_params_brainpoolp224r1.h"
#include "known/ec_params_brainpoolp256r1.h"
#include "known/ec_params_brainpoolp384r1.h"
#include "known/ec_params_brainpoolp512r1.h"
#include "known/ec_params_secp192r1.h"
#include "known/ec_params_secp224r1.h"
#include "known/ec_params_secp256r1.h"
#include "known/ec_params_secp384r1.h"
#include "known/ec_params_secp521r1.h"
#include "known/ec_params_frp256v1.h"
#include "known/ec_params_gost256.h"
#include "known/ec_params_gost512.h"
#include "known/ec_params_sm2p192test.h"
#include "known/ec_params_sm2p256test.h"
#include "known/ec_params_sm2p256v1.h"
#include "known/ec_params_wei25519.h"
#include "known/ec_params_wei448.h"
#include "known/ec_params_gost_R3410_2012_256_paramSetA.h"
#include "known/ec_params_secp256k1.h"

/* ADD curves header here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */

#ifndef CURVES_MAX_P_BIT_LEN
#error "Max p bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_P_BIT_LEN > 65535)
#error "Prime field length (in bytes) MUST fit on an u16!"
#endif

#ifndef CURVES_MAX_Q_BIT_LEN
#error "Max q bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_Q_BIT_LEN > 65535)
#error "Generator order length (in bytes) MUST fit on an u16!"
#endif

#ifndef CURVES_MAX_CURVE_ORDER_BIT_LEN
#error "Max curve order bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_CURVE_ORDER_BIT_LEN > 65535)
#error "Curve order length (in bytes) MUST fit on an u16!"
#endif

typedef struct {
	ec_curve_type type;
	const ec_str_params *params;
} ec_mapping;

static const ec_mapping ec_maps[] = {
#ifdef WITH_CURVE_FRP256V1
	{.type = FRP256V1,.params = &frp256v1_str_params},
#endif /* WITH_CURVE_FRP256V1 */
#ifdef WITH_CURVE_SECP192R1
	{.type = SECP192R1,.params = &secp192r1_str_params},
#endif /* WITH_CURVE_SECP192R1 */
#ifdef WITH_CURVE_SECP224R1
	{.type = SECP224R1,.params = &secp224r1_str_params},
#endif /* WITH_CURVE_SECP224R1 */
#ifdef WITH_CURVE_SECP256R1
	{.type = SECP256R1,.params = &secp256r1_str_params},
#endif /* WITH_CURVE_SECP256R1 */
#ifdef WITH_CURVE_SECP384R1
	{.type = SECP384R1,.params = &secp384r1_str_params},
#endif /* WITH_CURVE_SECP384R1 */
#ifdef WITH_CURVE_SECP521R1
	{.type = SECP521R1,.params = &secp521r1_str_params},
#endif /* WITH_CURVE_SECP521R1 */
#ifdef WITH_CURVE_BRAINPOOLP192R1
	{.type = BRAINPOOLP192R1,.params = &brainpoolp192r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP192R1 */
#ifdef WITH_CURVE_BRAINPOOLP224R1
	{.type = BRAINPOOLP224R1,.params = &brainpoolp224r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP224R1 */
#ifdef WITH_CURVE_BRAINPOOLP256R1
	{.type = BRAINPOOLP256R1,.params = &brainpoolp256r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP256R1 */
#ifdef WITH_CURVE_BRAINPOOLP384R1
	{.type = BRAINPOOLP384R1,.params = &brainpoolp384r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP384R1 */
#ifdef WITH_CURVE_BRAINPOOLP512R1
	{.type = BRAINPOOLP512R1,.params = &brainpoolp512r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP512R1 */
#ifdef WITH_CURVE_GOST256
	{.type = GOST256,.params = &GOST_256bits_curve_str_params},
#endif /* WITH_CURVE_GOST256 */
#ifdef WITH_CURVE_GOST512
	{.type = GOST512,.params = &GOST_512bits_curve_str_params},
#endif /* WITH_CURVE_GOST512 */
#ifdef WITH_CURVE_SM2P256TEST
	{.type = SM2P256TEST,.params = &sm2p256test_str_params},
#endif /* WITH_CURVE_SM2P256TEST */
#ifdef WITH_CURVE_SM2P256V1
	{.type = SM2P256V1,.params = &sm2p256v1_str_params},
#endif /* WITH_CURVE_SM2P256V1 */
#ifdef WITH_CURVE_WEI25519
	{.type = WEI25519,.params = &wei25519_str_params},
#endif /* WITH_CURVE_WEI25519 */
#ifdef WITH_CURVE_WEI448
	{.type = WEI448,.params = &wei448_str_params},
#endif /* WITH_CURVE_WEI448 */
#ifdef WITH_CURVE_GOST_R3410_2012_256_PARAMSETA
	{ .type = GOST_R3410_2012_256_PARAMSETA, .params = &gost_R3410_2012_256_paramSetA_str_params },
#endif /* WITH_CURVE_GOST_R3410_2012_256_PARAMSETA */
#ifdef WITH_CURVE_SECP256K1
	{.type = SECP256K1,.params = &secp256k1_str_params},
#endif /* WITH_CURVE_SECP256K1 */
/* ADD curves mapping here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */
};

/*
 * Number of cuvres supported by the lib, i.e. number of elements in
 * ec_maps array above.
 */
#define EC_CURVES_NUM (sizeof(ec_maps) / sizeof(ec_mapping))
#endif /* __CURVES_LIST_H__ */
