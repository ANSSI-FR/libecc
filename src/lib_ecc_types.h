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
#ifndef __LIB_ECC_TYPES_H__
#define __LIB_ECC_TYPES_H__

#include "lib_ecc_config.h"

/* Signature algorithm types */
typedef enum {
	UNKNOWN_SIG_ALG = 0,
#ifdef WITH_SIG_ECDSA
	ECDSA = 1,
#endif
#ifdef WITH_SIG_ECKCDSA
	ECKCDSA = 2,
#endif
#ifdef WITH_SIG_ECSDSA
	ECSDSA = 3,
#endif
#ifdef WITH_SIG_ECOSDSA
	ECOSDSA = 4,
#endif
#ifdef WITH_SIG_ECFSDSA
	ECFSDSA = 5,
#endif
#ifdef WITH_SIG_ECGDSA
	ECGDSA = 6,
#endif
#ifdef WITH_SIG_ECRDSA
	ECRDSA = 7,
#endif
} ec_sig_alg_type;

/* Hash algorithm types */
typedef enum {
	UNKNOWN_HASH_ALG = 0,
#ifdef WITH_HASH_SHA224
	SHA224 = 1,
#endif
#ifdef WITH_HASH_SHA256
	SHA256 = 2,
#endif
#ifdef WITH_HASH_SHA384
	SHA384 = 3,
#endif
#ifdef WITH_HASH_SHA512
	SHA512 = 4,
#endif
#ifdef WITH_HASH_SHA3_224
	SHA3_224 = 5,
#endif
#ifdef WITH_HASH_SHA3_256
	SHA3_256 = 6,
#endif
#ifdef WITH_HASH_SHA3_384
	SHA3_384 = 7,
#endif
#ifdef WITH_HASH_SHA3_512
	SHA3_512 = 8,
#endif
} hash_alg_type;

/* All curves we support */
typedef enum {
	UNKNOWN_CURVE = 0,
#ifdef WITH_CURVE_FRP256V1
	FRP256V1 = 1,
#endif
#ifdef WITH_CURVE_SECP192R1
	SECP192R1 = 2,
#endif
#ifdef WITH_CURVE_SECP224R1
	SECP224R1 = 3,
#endif
#ifdef WITH_CURVE_SECP256R1
	SECP256R1 = 4,
#endif
#ifdef WITH_CURVE_SECP384R1
	SECP384R1 = 5,
#endif
#ifdef WITH_CURVE_SECP521R1
	SECP521R1 = 6,
#endif
#ifdef WITH_CURVE_BRAINPOOLP224R1
	BRAINPOOLP224R1 = 7,
#endif
#ifdef WITH_CURVE_BRAINPOOLP256R1
	BRAINPOOLP256R1 = 8,
#endif
#ifdef WITH_CURVE_BRAINPOOLP512R1
	BRAINPOOLP512R1 = 9,
#endif
#ifdef WITH_CURVE_GOST256
	GOST256 = 10,
#endif
#ifdef WITH_CURVE_GOST512
	GOST512 = 11,
#endif
#ifdef WITH_CURVE_BRAINPOOLP384R1
	BRAINPOOLP384R1 = 12,
#endif
/* ADD curves type here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */
} ec_curve_type;

#endif /* __LIB_ECC_TYPES_H__ */
