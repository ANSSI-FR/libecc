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
#ifndef __SIG_ALGS_INTERNAL_H__
#define __SIG_ALGS_INTERNAL_H__

#include "../hash/hash_algs.h"
#include "../curves/curves.h"
#include "ec_key.h"
#include "ecdsa.h"
#include "eckcdsa.h"
#include "ecsdsa.h"
#include "ecosdsa.h"
#include "ecfsdsa.h"
#include "ecgdsa.h"
#include "ecrdsa.h"

#if (EC_MAX_SIGLEN == 0)
#error "It seems you disabled all signature schemes in lib_ecc_config.h"
#endif

/* Sanity check to ensure our sig mapping does not contain
 * NULL pointers
 */
#define SIG_MAPPING_SANITY_CHECK(A) 			\
	MUST_HAVE(((A) != NULL) && 			\
		  ((A)->name != NULL) && 		\
		  ((A)->siglen != NULL) && 		\
		  ((A)->init_pub_key != NULL) && 	\
		  ((A)->sign_init != NULL) && 		\
		  ((A)->sign_update != NULL) && 	\
		  ((A)->sign_finalize != NULL) && 	\
		  ((A)->verify_init != NULL) && 	\
		  ((A)->verify_update != NULL) && 	\
		  ((A)->verify_finalize != NULL)) 	\

/*
 * All the signature algorithms we support are abstracted using the following
 * structure (and following map) which provides for each hash alg its
 * digest size, its block size and the associated scattered function.
 */
typedef struct {
	ec_sig_alg_type type;
	const char *name;

	u8 (*siglen) (u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

	void (*init_pub_key) (ec_pub_key *pub_key, ec_priv_key *priv_key);

	int (*sign_init) (struct ec_sign_context * ctx);
	int (*sign_update) (struct ec_sign_context * ctx,
			    const u8 *chunk, u32 chunklen);
	int (*sign_finalize) (struct ec_sign_context * ctx,
			      u8 *sig, u8 siglen);

	int (*verify_init) (struct ec_verify_context * ctx,
			    const u8 *sig, u8 siglen);
	int (*verify_update) (struct ec_verify_context * ctx,
			      const u8 *chunk, u32 chunklen);
	int (*verify_finalize) (struct ec_verify_context * ctx);
} ec_sig_mapping;

/*
 * Each specific signature scheme need to maintain some specific
 * data between calls to init()/update()/finalize() functions.
 *
 * Each scheme provides a specific structure for that purpose
 * (in its .h file) which we include in the union below. A field
 * of that type (.sign_data) is then included in the generic
 * struct ec_sign_context below.
 *
 * The purpose of that work is to allow static declaration and
 * allocation of common struct ec_sign_context with enough room
 * available for all supported signature types.
 */

typedef union {
#ifdef WITH_SIG_ECDSA		/* ECDSA   */
	ecdsa_sign_data ecdsa;
#endif
#ifdef WITH_SIG_ECKCDSA		/* ECKCDSA */
	eckcdsa_sign_data eckcdsa;
#endif
#if (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA))	/* EC[O]SDSA  */
	ecsdsa_sign_data ecsdsa;
#endif
#ifdef WITH_SIG_ECFSDSA		/* ECFSDSA */
	ecfsdsa_sign_data ecfsdsa;
#endif
#ifdef WITH_SIG_ECGDSA		/* ECGDSA  */
	ecgdsa_sign_data ecgdsa;
#endif
#ifdef WITH_SIG_ECRDSA		/* ECRDSA  */
	ecrdsa_sign_data ecrdsa;
#endif
} sig_sign_data;

/*
 * The 'struct ec_sign_context' below provides a persistent state
 * between successive calls to ec_sign_{init,update,finalize}().
 */
struct ec_sign_context {
	word_t ctx_magic;
	const ec_key_pair *key_pair;
	int (*rand) (nn_t out, nn_src_t q);
	const hash_mapping *h;
	const ec_sig_mapping *sig;

	sig_sign_data sign_data;
};

#define SIG_SIGN_MAGIC ((word_t)(0x4ed73cfe4594dfd3ULL))
#define SIG_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE(((A) != NULL) && ((A)->ctx_magic == SIG_SIGN_MAGIC))

typedef union {
#ifdef WITH_SIG_ECDSA		/* ECDSA */
	ecdsa_verify_data ecdsa;
#endif
#ifdef WITH_SIG_ECKCDSA		/* ECKCDSA */
	eckcdsa_verify_data eckcdsa;
#endif
#if (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA))	/* EC[O]SDSA  */
	ecsdsa_verify_data ecsdsa;
#endif
#ifdef WITH_SIG_ECFSDSA		/* ECFSDSA */
	ecfsdsa_verify_data ecfsdsa;
#endif
#ifdef WITH_SIG_ECGDSA		/* ECGDSA */
	ecgdsa_verify_data ecgdsa;
#endif
#ifdef WITH_SIG_ECRDSA		/* ECRDSA */
	ecrdsa_verify_data ecrdsa;
#endif
} sig_verify_data;

/*
 * The 'struct ec_verify_context' below provides a persistent state
 * between successive calls to ec_verify_{init,update,finalize}().
 */
struct ec_verify_context {
	word_t ctx_magic;
	const ec_pub_key *pub_key;
	const hash_mapping *h;
	const ec_sig_mapping *sig;

	sig_verify_data verify_data;
};

#define SIG_VERIFY_MAGIC ((word_t)(0x7e0d42d13e3159baULL))
#define SIG_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE(((A) != NULL) &&	((A)->ctx_magic == SIG_VERIFY_MAGIC))

/*
 * Each signature algorithm supported by the library and implemented
 * in ec{,ck,s,fs,g,r}dsa.{c,h} is referenced below.
 */
#define MAX_SIG_ALG_NAME_LEN	0
static const ec_sig_mapping ec_sig_maps[] = {
#ifdef WITH_SIG_ECDSA
	{.type = ECDSA,
	 .name = "ECDSA",
	 .siglen = ecdsa_siglen,
	 .init_pub_key = ecdsa_init_pub_key,
	 .sign_init = _ecdsa_sign_init,
	 .sign_update = _ecdsa_sign_update,
	 .sign_finalize = _ecdsa_sign_finalize,
	 .verify_init = _ecdsa_verify_init,
	 .verify_update = _ecdsa_verify_update,
	 .verify_finalize = _ecdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 6)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 6
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECDSA */
#ifdef WITH_SIG_ECKCDSA
	{.type = ECKCDSA,
	 .name = "ECKCDSA",
	 .siglen = eckcdsa_siglen,
	 .init_pub_key = eckcdsa_init_pub_key,
	 .sign_init = _eckcdsa_sign_init,
	 .sign_update = _eckcdsa_sign_update,
	 .sign_finalize = _eckcdsa_sign_finalize,
	 .verify_init = _eckcdsa_verify_init,
	 .verify_update = _eckcdsa_verify_update,
	 .verify_finalize = _eckcdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 8)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 8
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECKCDSA */
#ifdef WITH_SIG_ECSDSA
	{.type = ECSDSA,
	 .name = "ECSDSA",
	 .siglen = ecsdsa_siglen,
	 .init_pub_key = ecsdsa_init_pub_key,
	 .sign_init = _ecsdsa_sign_init,
	 .sign_update = _ecsdsa_sign_update,
	 .sign_finalize = _ecsdsa_sign_finalize,
	 .verify_init = _ecsdsa_verify_init,
	 .verify_update = _ecsdsa_verify_update,
	 .verify_finalize = _ecsdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 7)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 7
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECSDSA */
#ifdef WITH_SIG_ECOSDSA
	{.type = ECOSDSA,
	 .name = "ECOSDSA",
	 .siglen = ecosdsa_siglen,
	 .init_pub_key = ecosdsa_init_pub_key,
	 .sign_init = _ecosdsa_sign_init,
	 .sign_update = _ecosdsa_sign_update,
	 .sign_finalize = _ecosdsa_sign_finalize,
	 .verify_init = _ecosdsa_verify_init,
	 .verify_update = _ecosdsa_verify_update,
	 .verify_finalize = _ecosdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 8)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 8
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECOSDSA */
#ifdef WITH_SIG_ECFSDSA
	{.type = ECFSDSA,
	 .name = "ECFSDSA",
	 .siglen = ecfsdsa_siglen,
	 .init_pub_key = ecfsdsa_init_pub_key,
	 .sign_init = _ecfsdsa_sign_init,
	 .sign_update = _ecfsdsa_sign_update,
	 .sign_finalize = _ecfsdsa_sign_finalize,
	 .verify_init = _ecfsdsa_verify_init,
	 .verify_update = _ecfsdsa_verify_update,
	 .verify_finalize = _ecfsdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 8)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 8
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECFSDSA */
#ifdef WITH_SIG_ECGDSA
	{.type = ECGDSA,
	 .name = "ECGDSA",
	 .siglen = ecgdsa_siglen,
	 .init_pub_key = ecgdsa_init_pub_key,
	 .sign_init = _ecgdsa_sign_init,
	 .sign_update = _ecgdsa_sign_update,
	 .sign_finalize = _ecgdsa_sign_finalize,
	 .verify_init = _ecgdsa_verify_init,
	 .verify_update = _ecgdsa_verify_update,
	 .verify_finalize = _ecgdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 7)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 7
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECGDSA */
#ifdef WITH_SIG_ECRDSA
	{.type = ECRDSA,
	 .name = "ECRDSA",
	 .siglen = ecrdsa_siglen,
	 .init_pub_key = ecrdsa_init_pub_key,
	 .sign_init = _ecrdsa_sign_init,
	 .sign_update = _ecrdsa_sign_update,
	 .sign_finalize = _ecrdsa_sign_finalize,
	 .verify_init = _ecrdsa_verify_init,
	 .verify_update = _ecrdsa_verify_update,
	 .verify_finalize = _ecrdsa_verify_finalize,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 7)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 7
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* WITH_SIG_ECRDSA */
	{.type = UNKNOWN_SIG_ALG,	/* Needs to be kept last */
	 .name = "UNKNOWN",
	 .siglen = 0,
	 .init_pub_key = NULL,
	 .sign_init = NULL,
	 .sign_update = NULL,
	 .sign_finalize = NULL,
	 .verify_init = NULL,
	 .verify_update = NULL,
	 .verify_finalize = NULL,
	 },
};

/*
 * For a given raw signature, the structured version is produced by prepending
 * three bytes providing specific sig alg, hash alg and curve.
 */
#define EC_STRUCTURED_SIG_EXPORT_SIZE(siglen)  ((siglen) + (3 * sizeof(u8)))

#endif /* __SIG_ALGS_INTERNAL_H__ */
