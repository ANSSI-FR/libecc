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
#include "ec_self_tests_core.h"
#include "../utils/utils.h"
#include "../external_deps/rand.h"
#include "../external_deps/time.h"
#include "../external_deps/print.h"


static int ec_gen_import_export_kp(ec_key_pair *kp, const ec_params *params,
				   const ec_test_case *c)
{
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	u8 priv_key_buf[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE];
	u8 pub_key_buf_len, priv_key_buf_len;
	ec_key_pair imported_kp;
	int ret;

	/* Generate key pair */
	ret = ec_key_pair_gen(kp, params, c->sig_type);
	if (ret) {
		ext_printf("Error generating key pair\n");
		goto err;
	}
	pub_key_buf_len = EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(&(kp->pub_key));
	priv_key_buf_len = EC_STRUCTURED_PRIV_KEY_EXPORT_SIZE(&(kp->priv_key));

	/* Export public and private keys in buffers */
	ret = ec_structured_pub_key_export_to_buf(&(kp->pub_key), pub_key_buf,
					  pub_key_buf_len);
	if (ret) {
		ext_printf("Error exporting public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_export_to_buf(&(kp->priv_key),
					   priv_key_buf,
					   priv_key_buf_len);
	if (ret) {
		ext_printf("Error exporting private key\n");
		goto err;
	}

	/* Import public and private key */
	ret = ec_structured_pub_key_import_from_buf(&(imported_kp.pub_key),
					    params,
					    pub_key_buf,
					    pub_key_buf_len,
					    c->sig_type);
	if (ret) {
		ext_printf("Error importing public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_import_from_buf(&(imported_kp.priv_key),
					     params, priv_key_buf,
					     priv_key_buf_len,
					     c->sig_type);
	if (ret) {
		ext_printf("Error importing private key\n");
		goto err;
	}
	ret = 0;

err:
	return ret;
}

/* This function randomly splits the message input in small chunks to
 * test the signature init / multiple updates / finalize mechanism for
 * algorithms that support them.
 */
static int random_split_ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
	     const u8 *m, u32 mlen,
	     int (*rand) (nn_t out, nn_src_t q),
	     ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len)
{
	struct ec_sign_context ctx;
	int ret;

	ret = _ec_sign_init(&ctx, key_pair, rand, sig_type, hash_type, adata, adata_len);
	if (ret) {
		goto err;
	}
	/* We randomly split the input message in chunks and proceed with updates */
	u32 consumed = 0;
	while(consumed < mlen){
		u32 toconsume = 0;
		ret = get_random((u8 *)&toconsume, sizeof(toconsume));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		toconsume = (toconsume % (mlen - consumed));
		if(((mlen - consumed) == 1) && (toconsume == 0)){
			toconsume = 1;
		}
		ret = ec_sign_update(&ctx, &m[consumed], toconsume);
		if (ret) {
			goto err;
		}
		consumed += toconsume;
	}

	ret = ec_sign_finalize(&ctx, sig, siglen);

 err:
	return ret;
}

/* This function randomly splits the message input in small chunks to
 * test the verification init / multiple updates / finalize mechanism for
 * algorithms that support them.
 */
static int random_split_ec_verify(const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
	      const u8 *m, u32 mlen,
	      ec_sig_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len)
{
	int ret;
	struct ec_verify_context ctx;

	ret = ec_verify_init(&ctx, pub_key, sig, siglen, sig_type, hash_type, adata, adata_len);
	if (ret) {
		goto err;
	}

	/* We randomly split the input message in chunks and proceed with updates */
	u32 consumed = 0;
	while(consumed < mlen){
		u32 toconsume = 0;
		ret = get_random((u8 *)&toconsume, sizeof(toconsume));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		toconsume = (toconsume % (mlen - consumed));
		if(((mlen - consumed) == 1) && (toconsume == 0)){
			toconsume = 1;
		}
		ret = ec_verify_update(&ctx, &m[consumed], toconsume);
		if (ret) {
			goto err;
		}
		consumed += toconsume;
	}

	ret = ec_verify_finalize(&ctx);

 err:
	return ret;
}


/* Reduce pressure on the stack for small targets
 * by letting the user override this value.
 */
#ifndef MAX_MSG_LEN
#define MAX_MSG_LEN 8192
#endif

/*
 * ECC generic self tests (sign/verify on random values
 * with import/export)
 */
static int ec_import_export_test(const ec_test_case *c)
{
	ec_key_pair kp;
	ec_params params;
	int ret;

	/* Import EC params from test case */
	import_params(&params, c->ec_str_p);

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u16 msglen;
		u8 siglen;
		u8 msg[MAX_MSG_LEN];
		u8 sig[EC_MAX_SIGLEN];

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
				     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/* Generate a random message to sign */
		ret = get_random((u8 *)&msglen, sizeof(msglen));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		msglen = msglen % MAX_MSG_LEN;
		ret = get_random(msg, msglen);
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}

		ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
		if (ret) {
			ext_printf("Error when signing\n");
			goto err;
		}
		u8 sig_tmp1[EC_MAX_SIGLEN];
		local_memset(sig_tmp1, 0, sizeof(sig_tmp1));
		u8 sig_tmp2[EC_MAX_SIGLEN];
		local_memset(sig_tmp2, 0, sizeof(sig_tmp2));
		/* If the algorithm supports streaming mode, test it against direct mode */
		if(is_sign_streaming_mode_supported(c->sig_type)){
			if(siglen > sizeof(sig_tmp1)){
				ret = -1;
				goto err;
			}
			if(siglen > sizeof(sig_tmp2)){
				ret = -1;
				goto err;
			}
			ret = generic_ec_sign(sig_tmp1, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if(ret){
				ext_printf("Error when signing\n");
				ret = -1;
				goto err;
			}
			ret = random_split_ec_sign(sig_tmp2, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if(ret){
				ext_printf("Error when signing\n");
				ret = -1;
				goto err;
			}
			/* Verify signature equality only in case of deterministic signatures */
			if(is_sign_deterministic(c->sig_type)){
				if(!are_equal(sig, sig_tmp1, siglen)){
					ext_printf("Error when signing: streaming and non streaming modes results differ "\
						   "for deterministic signature scheme!\n");
					ret = -1;
					goto err;
				}
				if(!are_equal(sig, sig_tmp2, siglen)){
					ext_printf("Error when signing: streaming and non streaming modes results differ "\
						   "for deterministic signature scheme!\n");
					ret = -1;
					goto err;
				}
			}
		}

		ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
				c->sig_type, c->hash_type, c->adata, c->adata_len);
		if (ret) {
			ext_printf("Error when verifying signature\n");
			goto err;
		}
		/* If the algorithm supports streaming mode, test it against direct mode */
		if(is_verify_streaming_mode_supported(c->sig_type)){
			if(is_sign_streaming_mode_supported(c->sig_type)){
				ret = generic_ec_verify(sig_tmp2, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			else{
				ret = generic_ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			if (ret) {
				ext_printf("Error when verifying signature generic_ec_verify\n");
				goto err;
			}
			if(is_sign_streaming_mode_supported(c->sig_type)){
				ret = random_split_ec_verify(sig_tmp1, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			else{
				ret = random_split_ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			if (ret) {
				ext_printf("Error when verifying signature random_split_ec_verify\n");
				goto err;
			}
		}
#ifdef USE_CRYPTOFUZZ
		u8 check = 0;
		/* Specific case where we have access to raw signature API */
#if defined(WITH_SIG_ECDSA)
		if(c->sig_type == ECDSA){
			check = 1;
		}
#endif
#if defined(WITH_SIG_ECGDSA)
		if(c->sig_type == ECGDSA){
			check = 1;
		}
#endif
#if defined(WITH_SIG_ECRDSA)
		if(c->sig_type == ECRDSA){
			check = 1;
		}
#endif
		if(check){
			struct ec_sign_context sig_ctx;
			struct ec_verify_context verif_ctx;
			u8 digest[MAX_DIGEST_SIZE] = { 0 };
			u8 digestlen;
			/* Initialize our signature context */
			if(ec_sign_init(&sig_ctx, &kp, c->sig_type, c->hash_type, c->adata, c->adata_len)){
				ret = -1;
				goto err;
			}
			/* Perform the hash of the data ourselves */
			if(hash_mapping_callbacks_sanity_check(sig_ctx.h)){
				ret = -1;
				goto err;
			}
			const u8 *input[2] = { (const u8*)msg , NULL};
			u32 ilens[2] = { msglen , 0 };
			sig_ctx.h->hfunc_scattered(input, ilens, digest);
			digestlen = sig_ctx.h->digest_size;
			MUST_HAVE(digestlen <= sizeof(digest));
			/* Raw signing of data */
#if defined(WITH_SIG_ECDSA)
			if(c->sig_type == ECDSA){
				if(ecdsa_sign_raw(&sig_ctx, digest, digestlen, sig, siglen, NULL, 0)){
					ret = -1;
					goto err;
				}
			}
#endif
#if defined(WITH_SIG_ECGDSA)
			if(c->sig_type ==  ECGDSA){
				if(ecgdsa_sign_raw(&sig_ctx, digest, digestlen, sig, siglen, NULL, 0)){
					ret = -1;
					goto err;
				}
			}
#endif
#if defined(WITH_SIG_ECRDSA)
			if(c->sig_type ==  ECRDSA){
				if(ecrdsa_sign_raw(&sig_ctx, digest, digestlen, sig, siglen, NULL, 0)){
					ret = -1;
					goto err;
				}
			}
#endif
			/* Now verify signature */
			if(ec_verify_init(&verif_ctx,  &(kp.pub_key), sig, siglen, c->sig_type, c->hash_type, c->adata, c->adata_len)){
				ret = -1;
				goto err;
			}
#if defined(WITH_SIG_ECDSA)
			if(c->sig_type == ECDSA){
				if(ecdsa_verify_raw(&verif_ctx, digest, digestlen)){
					ret = -1;
					goto err;
				}
			}
#endif
#if defined(WITH_SIG_ECGDSA)
			if(c->sig_type ==  ECGDSA){
				if(ecgdsa_verify_raw(&verif_ctx, digest, digestlen)){
					ret = -1;
					goto err;
				}
			}
#endif
#if defined(WITH_SIG_ECRDSA)
			if(c->sig_type ==  ECRDSA){
				if(ecrdsa_verify_raw(&verif_ctx, digest, digestlen)){
					ret = -1;
					goto err;
				}
			}
#endif
		}
#endif
	}

	ret = 0;

 err:
	return ret;
}

/*
 * Those functions respectively perform signature and verification tests
 * based the content of a given test case.
 */
static int ec_test_sign(u8 *sig, u8 siglen, ec_key_pair *kp,
			const ec_test_case *c)
{
	/* If the algorithm supports streaming, we check that both the streaming and
	 * non streaming modes produce the same result.
	 */
	int ret = -1;
	ret = _ec_sign(sig, siglen, kp, (const u8 *)(c->msg), c->msglen,
				c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
	if(ret){
		ret = -1;
		goto err;
	}
	if(is_sign_streaming_mode_supported(c->sig_type)){
		u8 sig_tmp[EC_MAX_SIGLEN];
		if(siglen > sizeof(sig_tmp)){
			ret = -1;
			goto err;
		}
		ret = generic_ec_sign(sig_tmp, siglen, kp, (const u8 *)(c->msg), c->msglen,
				c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
		if(ret){
			ret = -1;
			goto err;
		}
		if(!are_equal(sig, sig_tmp, siglen)){
			ret = -1;
			goto err;
		}
		/* Now test the random split version */
		ret = random_split_ec_sign(sig_tmp, siglen, kp, (const u8 *)(c->msg), c->msglen,
				c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
		if(ret){
			ret = -1;
			goto err;
		}
		if(!are_equal(sig, sig_tmp, siglen)){
			ret = -1;
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

static int ec_test_verify(u8 *sig, u8 siglen, const ec_pub_key *pub_key,
			  const ec_test_case *c)
{
	/* If the algorithm supports streaming, we check that both the streaming and
	 * non streaming modes produce the same result.
	 */
	int ret = -1;

	ret = ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
				 c->sig_type, c->hash_type, c->adata, c->adata_len);
	if(ret){
		ret = -1;
		goto err;
	}
	if(is_verify_streaming_mode_supported(c->sig_type)){
		ret = generic_ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
				 c->sig_type, c->hash_type, c->adata, c->adata_len);
		if(ret){
			ret = -1;
			goto err;
		}
		/* Now test the random split version */
		ret = random_split_ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
				 c->sig_type, c->hash_type, c->adata, c->adata_len);
		if(ret){
			ret = -1;
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

/*
 * ECC generic self tests (sign/verify on known test vectors). Returns
 * 0 if given test succeeded, or a non-zero value otherwise. In that
 * case, the value encodes the information on what went wrong as
 * described above.
 */
static int ec_sig_known_vector_tests_one(const ec_test_case *c)
{
	test_err_kind failed_test = TEST_KEY_IMPORT_ERROR;
	u8 sig[EC_MAX_SIGLEN];
	ec_params params;
	ec_key_pair kp;
	u8 siglen;
	int ret;

	MUST_HAVE(c != NULL);

	import_params(&params, c->ec_str_p);

#if defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448)
	/* In the specific case of EdDSA, we perform a specific key derivation */
#if defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_EDDSA448)
	if((c->sig_type == EDDSA25519) || (c->sig_type == EDDSA25519CTX) || (c->sig_type == EDDSA25519PH) || \
	  (c->sig_type == EDDSA448) || (c->sig_type == EDDSA448PH)){
#endif
#if defined(WITH_SIG_EDDSA25519) && !defined(WITH_SIG_EDDSA448)
	if((c->sig_type == EDDSA25519) || (c->sig_type == EDDSA25519CTX) || (c->sig_type == EDDSA25519PH)){
#endif
#if !defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_EDDSA448)
	if((c->sig_type == EDDSA448) || (c->sig_type == EDDSA448PH)){
#endif
		/* Import the key pair using the EdDSA dedicated function */
		if(eddsa_import_key_pair_from_priv_key_buf(&kp, c->priv_key, c->priv_key_len, &params, c->sig_type)){
			ret = -1;
			failed_test = TEST_KEY_IMPORT_ERROR;
			goto err;
		}
	}
	else
#endif /* !(defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448)) */
	{
		/* Regular import if not EdDSA */
		ret = ec_key_pair_import_from_priv_key_buf(&kp, &params, c->priv_key,
							   c->priv_key_len,
							   c->sig_type);
		if (ret) {
			failed_test = TEST_KEY_IMPORT_ERROR;
			goto err;
		}
	}

	siglen = c->exp_siglen;
	ret = ec_test_sign(sig, siglen, &kp, c);
	if (ret) {
		failed_test = TEST_SIG_ERROR;
		goto err;
	}

	ret = are_equal(sig, c->exp_sig, siglen);
	if (!ret) {
		ret = -1;
		failed_test = TEST_SIG_COMP_ERROR;
		goto err;
	}

	ret = ec_test_verify(sig, siglen, &(kp.pub_key), c);
	if (ret) {
		failed_test = TEST_VERIF_ERROR;
		goto err;
	}

#ifdef USE_CRYPTOFUZZ
	u8 check = 0;
	/* Specific case where we have access to raw signature API */
#if defined(WITH_SIG_ECDSA)
	if(c->sig_type == ECDSA){
		check = 1;
	}
#endif
#if defined(WITH_SIG_ECGDSA)
	if(c->sig_type == ECGDSA){
		check = 1;
	}
#endif
#if defined(WITH_SIG_ECRDSA)
	if(c->sig_type == ECRDSA){
		check = 1;
	}
#endif
	/* Specific case where we have access to raw signature API */
	if(check){
		struct ec_sign_context sig_ctx;
		struct ec_verify_context verif_ctx;
		u8 digest[MAX_DIGEST_SIZE] = { 0 };
		u8 digestlen;
		/* Initialize our signature context */
		if(ec_sign_init(&sig_ctx, &kp, c->sig_type, c->hash_type, c->adata, c->adata_len)){
			ret = -1;
			failed_test = TEST_SIG_ERROR;
			goto err;
		}
		/* Perform the hash of the data ourselves */
		if(hash_mapping_callbacks_sanity_check(sig_ctx.h)){
			ret = -1;
			failed_test = TEST_SIG_ERROR;
			goto err;
		}
		const u8 *input[2] = { (const u8*)(c->msg) , NULL};
		u32 ilens[2] = { c->msglen , 0 };
		sig_ctx.h->hfunc_scattered(input, ilens, digest);
		digestlen = sig_ctx.h->digest_size;
		MUST_HAVE(digestlen <= sizeof(digest));
		/* Import the fixed nonce */
		u8 nonce[BIT_LEN_WORDS(NN_MAX_BIT_LEN) * (WORDSIZE / 8)] = { 0 };
		nn n_nonce;
		bitcnt_t q_bit_len = kp.priv_key.params->ec_gen_order_bitlen;
		if(c->nn_random(&n_nonce, &(kp.priv_key.params->ec_gen_order))){
			ret = -1;
			failed_test = TEST_SIG_ERROR;
			goto err;
		}
		nn_export_to_buf(nonce, BYTECEIL(q_bit_len), &n_nonce);
		if((unsigned int)BYTECEIL(q_bit_len) > sizeof(nonce)){
			ret = -1;
			failed_test = TEST_SIG_ERROR;
			goto err;
		}
		u8 noncelen = (u8)(BYTECEIL(q_bit_len));
		MUST_HAVE(noncelen <= sizeof(nonce));
		/* Raw signing of data */
#if defined(WITH_SIG_ECDSA)
		if(c->sig_type == ECDSA){
			if(ecdsa_sign_raw(&sig_ctx, digest, digestlen, sig, siglen, nonce, noncelen)){
				ret = -1;
				failed_test = TEST_SIG_ERROR;
				goto err;
			}
		}
#endif
#if defined(WITH_SIG_ECGDSA)
		if(c->sig_type == ECGDSA){
			if(ecgdsa_sign_raw(&sig_ctx, digest, digestlen, sig, siglen, nonce, noncelen)){
				ret = -1;
				failed_test = TEST_SIG_ERROR;
				goto err;
			}
		}
#endif
#if defined(WITH_SIG_ECRDSA)
		if(c->sig_type == ECRDSA){
			if(ecrdsa_sign_raw(&sig_ctx, digest, digestlen, sig, siglen, nonce, noncelen)){
				ret = -1;
				failed_test = TEST_SIG_ERROR;
				goto err;
			}
		}
#endif
		/* Check computed signature against expected one */
		ret = are_equal(sig, c->exp_sig, siglen);
		if (!ret) {
			failed_test = TEST_SIG_COMP_ERROR;
			ret = -1;
			goto err;
		}
		/* Now verify signature */
		if(ec_verify_init(&verif_ctx,  &(kp.pub_key), sig, siglen, c->sig_type, c->hash_type, c->adata, c->adata_len)){
			ret = -1;
			failed_test = TEST_VERIF_ERROR;
			goto err;
		}
		/* Raw verification of data */
#if defined(WITH_SIG_ECDSA)
		if(c->sig_type == ECDSA){
			if(ecdsa_verify_raw(&verif_ctx, digest, digestlen)){
				ret = -1;
				failed_test = TEST_VERIF_ERROR;
				goto err;
			}
		}
#endif
#if defined(WITH_SIG_ECGDSA)
		if(c->sig_type == ECGDSA){
			if(ecgdsa_verify_raw(&verif_ctx, digest, digestlen)){
				ret = -1;
				failed_test = TEST_VERIF_ERROR;
				goto err;
			}
		}
#endif
#if defined(WITH_SIG_ECRDSA)
		if(c->sig_type == ECRDSA){
			if(ecrdsa_verify_raw(&verif_ctx, digest, digestlen)){
				ret = -1;
				failed_test = TEST_VERIF_ERROR;
				goto err;
			}
		}
#endif
	}
#endif
	ret = 0;

 err:
	if (ret) {
		ret = (int)encode_error_value(c, failed_test);
	}

	return ret;
}

int perform_known_test_vectors_test(const char *sig, const char *hash, const char *curve)
{
	const ec_test_case *cur_test;
	unsigned int i;
	int ret = 0;

	ext_printf("======= Known test vectors test =================\n");
	for (i = 0; i < EC_FIXED_VECTOR_NUM_TESTS; i++) {
		cur_test = ec_fixed_vector_tests[i];
		if(cur_test == NULL){
			continue;
		}
		/* If this is a dummy test case, skip it! */
		if(cur_test->sig_type == UNKNOWN_SIG_ALG){
			continue;
		}
		/* Filter out */
		if(sig != NULL){
			const ec_sig_mapping *sig_map = get_sig_by_type(cur_test->sig_type);
			if(sig_map == NULL){
				continue;
			}
			if(!are_str_equal(sig_map->name, sig)){
				continue;
			}
		}
		if(hash != NULL){
			const hash_mapping *hash_map = get_hash_by_type(cur_test->hash_type);
			if(hash_map == NULL){
				continue;
			}
			if(!are_str_equal(hash_map->name, hash)){
				continue;
			}
		}
		if(curve != NULL){
			if(cur_test->ec_str_p == NULL){
				continue;
			}
			if(!are_str_equal((const char*)cur_test->ec_str_p->name->buf, curve)){
				continue;
			}
		}
		ret = ec_sig_known_vector_tests_one(cur_test);
		ext_printf("[%s] %30s selftests: known test vectors "
			   "sig/verif %s\n", ret ? "-" : "+",
			   cur_test->name, ret ? "failed" : "ok");
#ifdef USE_CRYPTOFUZZ
#if defined(WITH_SIG_ECDSA)
		if(cur_test->sig_type == ECDSA){
			ext_printf("\t(RAW ECDSA for CRYPTOFUZZ also checked!)\n");
		}
#endif
#if defined(WITH_SIG_ECGDSA)
		if(cur_test->sig_type == ECGDSA){
			ext_printf("\t(RAW ECGDSA for CRYPTOFUZZ also checked!)\n");
		}
#endif
#if defined(WITH_SIG_ECRDSA)
		if(cur_test->sig_type == ECRDSA){
			ext_printf("\t(RAW ECRDSA for CRYPTOFUZZ also checked!)\n");
		}
#endif
#endif
		if (ret) {
			goto err;
		}
	}

 err:
	return ret;
}

static int rand_sig_verif_test_one(const ec_sig_mapping *sig,
				   const hash_mapping *hash,
				   const ec_mapping *ec)
{
	char test_name[MAX_CURVE_NAME_LEN + MAX_HASH_ALG_NAME_LEN +
		       MAX_SIG_ALG_NAME_LEN + 2];
	const unsigned int tn_size = sizeof(test_name) - 1; /* w/o trailing 0 */
	const char *crv_name = (const char *)PARAM_BUF_PTR((ec->params)->name);
	ec_test_case t;
	int ret;

	/* Generate the test name */
	local_memset(test_name, 0, tn_size + 1);
	local_strncpy(test_name, sig->name, tn_size);
	local_strncat(test_name, "-", tn_size -	local_strlen(test_name));
	local_strncat(test_name, hash->name, tn_size - local_strlen(test_name));
	local_strncat(test_name, "/", tn_size - local_strlen(test_name));
	local_strncat(test_name, crv_name, tn_size - local_strlen(test_name));

	/* Create a test */
	t.name = test_name;
	t.ec_str_p = ec->params;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;
#if defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_SM2)
	u8 rand_adata[255] = { 0 };
	/* The case of EDDSA25519CTX and SM2 needs a non NULL context (ancillary data).
	 * Create a random string of size <= 255 for this.
	 */
#if defined(WITH_SIG_EDDSA25519) && !defined(WITH_SIG_SM2)
	if(sig->type == EDDSA25519CTX)
#endif
#if !defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_SM2)
	if(sig->type == SM2)
#endif
#if defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_SM2)
	if((sig->type == EDDSA25519CTX) || (sig->type == SM2))
#endif
	{
		u8 rand_len = 0;
		if(get_random((u8 *)&rand_len, sizeof(rand_len))){
			ret = -1;
			return ret;
		}
		if(get_random((u8 *)rand_adata, rand_len)){
			ret = -1;
			return ret;
		}
		t.adata = rand_adata;
		t.adata_len = rand_len;
	}
	else
#endif
	{
		t.adata = NULL;
		t.adata_len = 0;
	}

	/* Execute the test */
	ret = ec_import_export_test(&t);
	ext_printf("[%s] %34s randtests: random import/export "
		   "with sig/verif %s\n", ret ? "-" : "+", t.name,
		   ret ? "failed" : "ok");
#ifdef USE_CRYPTOFUZZ
#if defined(WITH_SIG_ECDSA)
	if(t.sig_type == ECDSA){
		ext_printf("\t(RAW ECDSA for CRYPTOFUZZ also checked!)\n");
	}
#endif
#if defined(WITH_SIG_ECGDSA)
	if(t.sig_type == ECGDSA){
		ext_printf("\t(RAW ECGDSA for CRYPTOFUZZ also checked!)\n");
	}
#endif
#if defined(WITH_SIG_ECRDSA)
	if(t.sig_type == ECRDSA){
		ext_printf("\t(RAW ECRDSA for CRYPTOFUZZ also checked!)\n");
	}
#endif
#endif

	return ret;
}

int perform_random_sig_verif_test(const char *sig, const char *hash, const char *curve)
{
	unsigned int i, j, k;
	int ret;

	/*
	 * Perform basic sign/verify tests on all the cipher suites
	 * (combination of sign algo/hash function/curve)
	 */
	ext_printf("======= Random sig/verif test ===================\n");
	for (i = 0; ec_sig_maps[i].type != UNKNOWN_SIG_ALG; i++) {
		for (j = 0; hash_maps[j].type != UNKNOWN_HASH_ALG; j++) {
			for (k = 0; k < EC_CURVES_NUM; k++) {
				if(sig != NULL){
					if(!are_str_equal(ec_sig_maps[i].name, sig)){
						continue;
					}
				}
				if(hash != NULL){
					if(!are_str_equal(hash_maps[j].name, hash)){
						continue;
					}
				}
				if(curve != NULL){
					if(!are_str_equal((const char*)ec_maps[k].params->name->buf, curve)){
						continue;
					}
				}
				/* If we have EDDSA25519 or EDDSA448, we only accept specific hash functions.
				 * Skip the other tests.
				 */
#ifdef WITH_SIG_EDDSA25519
				if((ec_sig_maps[i].type == EDDSA25519) && ((hash_maps[j].type != SHA512) || (ec_maps[k].type != WEI25519))){
					continue;
				}
				if((ec_sig_maps[i].type == EDDSA25519CTX) && ((hash_maps[j].type != SHA512) || (ec_maps[k].type != WEI25519))){
					continue;
				}
				if((ec_sig_maps[i].type == EDDSA25519PH) && ((hash_maps[j].type != SHA512) || (ec_maps[k].type != WEI25519))){
					continue;
				}
#endif
#ifdef WITH_SIG_EDDSA448
				if((ec_sig_maps[i].type == EDDSA448) && ((hash_maps[j].type != SHAKE256) || (ec_maps[k].type != WEI448))){
					continue;
				}
				if((ec_sig_maps[i].type == EDDSA448PH) && ((hash_maps[j].type != SHAKE256) || (ec_maps[k].type != WEI448))){
					continue;
				}
#endif
				ret = rand_sig_verif_test_one(&ec_sig_maps[i],
							      &hash_maps[j],
							      &ec_maps[k]);
				if (ret) {
					goto err;
				}
			}
		}
	}

	return 0;

err:
	return -1;
}

#define PERF_NUM_OP	300

/*
 * ECC generic performance test: Returns the number of signatures
 * and verifications per second
 */
static int ec_performance_test(const ec_test_case *c,
			       unsigned int *n_perf_sign,
			       unsigned int *n_perf_verif)
{
	ec_key_pair kp;
	ec_params params;
	int ret;

	/* Import EC params from test case */
	import_params(&params, c->ec_str_p);

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u8 sig[EC_MAX_SIGLEN];
		u8 siglen;
		u8 msg[MAX_BLOCK_SIZE];
		u16 msglen;
		u8 hash_digest_size, hash_block_size;
		/* Time related variables */
		u64 time1, time2, cumulated_time_sign, cumulated_time_verify;
		int i;

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
			     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/*
		 * Random tests to measure performance: We do it on small
		 * messages to "absorb" the hash function cost
		 */
		ret = get_hash_sizes(c->hash_type, &hash_digest_size,
			     &hash_block_size);
		if (ret) {
			ext_printf("Error when getting hash size\n");
			goto err;
		}
		cumulated_time_sign = cumulated_time_verify = 0;
		for (i = 0; i < PERF_NUM_OP; i++) {
			/* Generate a random message to sign */
			ret = get_random((u8 *)&msglen, sizeof(msglen));
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}
			msglen = msglen % hash_block_size;
			ret = get_random(msg, msglen);
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}

			/***** Signature **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if (ret) {
				ext_printf("Error when signing\n");
				goto err;
			}
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (t2 < t1)\n");
				goto err;
			}
			cumulated_time_sign += (time2 - time1);

			/***** Verification **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			if (ret) {
				ext_printf("Error when verifying signature\n");
				goto err;
			}
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (time2 < time1)\n");
				goto err;
			}
			cumulated_time_verify += (time2 - time1);
		}
		if (n_perf_sign != NULL) {
			*n_perf_sign = ((PERF_NUM_OP * 1000ULL) / cumulated_time_sign);
		}
		if (n_perf_verif != NULL) {
			*n_perf_verif = ((PERF_NUM_OP * 1000ULL) / cumulated_time_verify);
		}
	}
	ret = 0;
 err:
	return ret;
}


static int perf_test_one(const ec_sig_mapping *sig, const hash_mapping *hash,
			 const ec_mapping *ec)
{
	char test_name[MAX_CURVE_NAME_LEN + MAX_HASH_ALG_NAME_LEN +
		       MAX_SIG_ALG_NAME_LEN + 2];
	const unsigned int tn_size = sizeof(test_name) - 1; /* w/o trailing 0 */
	unsigned int n_perf_sign = 0, n_perf_verif = 0;
	const char *crv_name = (const char *)PARAM_BUF_PTR((ec->params)->name);
	ec_test_case t;
	int ret;

	/* Generate the test name */
	local_memset(test_name, 0, tn_size + 1);
	local_strncpy(test_name, sig->name, tn_size);
	local_strncat(test_name, "-", tn_size -	local_strlen(test_name));
	local_strncat(test_name, hash->name, tn_size - local_strlen(test_name));
	local_strncat(test_name, "/", tn_size - local_strlen(test_name));
	local_strncat(test_name, crv_name, tn_size - local_strlen(test_name));

	/* Create a test */
	t.name = test_name;
	t.ec_str_p = ec->params;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;
#if defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_SM2)
	u8 rand_adata[255] = { 0 };
	/* The case of EDDSA25519CTX and SM2 needs a non NULL context (ancillary data).
	 * Create a random string of size <= 255 for this.
	 */
#if defined(WITH_SIG_EDDSA25519) && !defined(WITH_SIG_SM2)
	if(sig->type == EDDSA25519CTX)
#endif
#if !defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_SM2)
	if(sig->type == SM2)
#endif
#if defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_SM2)
	if((sig->type == EDDSA25519CTX) || (sig->type == SM2))
#endif
	{
		u8 rand_len = 0;
		if(get_random((u8 *)&rand_len, sizeof(rand_len))){
			ret = -1;
			return ret;
		}
		if(get_random((u8 *)rand_adata, rand_len)){
			ret = -1;
			return ret;
		}
		t.adata = rand_adata;
		t.adata_len = rand_len;
	}
	else
#endif
	{
		t.adata = NULL;
		t.adata_len = 0;
	}

	/* Sign and verify some random data during some time */
	ret = ec_performance_test(&t, &n_perf_sign, &n_perf_verif);
	ext_printf("[%s] %30s perf: %d sign/s and %d verif/s\n",
		   ret ? "-" : "+", t.name, n_perf_sign, n_perf_verif);
	if ((n_perf_sign == 0) || (n_perf_verif == 0)) {
		ext_printf("\t(0 is less than one sig/verif per sec)\n");
	}

	return ret;
}

int perform_performance_test(const char *sig, const char *hash, const char *curve)
{
	unsigned int i, j, k;
	int ret;

	/* Perform performance tests like "openssl speed" command */
	ext_printf("======= Performance test ========================\n");
	for (i = 0; ec_sig_maps[i].type != UNKNOWN_SIG_ALG; i++) {
		for (j = 0; hash_maps[j].type != UNKNOWN_HASH_ALG; j++) {
			for (k = 0; k < EC_CURVES_NUM; k++) {
				if(sig != NULL){
					if(!are_str_equal(ec_sig_maps[i].name, sig)){
						continue;
					}
				}
				if(hash != NULL){
					if(!are_str_equal(hash_maps[j].name, hash)){
						continue;
					}
				}
				if(curve != NULL){
					if(!are_str_equal((const char*)ec_maps[k].params->name->buf, curve)){
						continue;
					}
				}
				/* If we have EDDSA25519 or EDDSA448, we only accept specific hash functions.
				 * Skip the other tests.
				 */
#ifdef WITH_SIG_EDDSA25519
				if((ec_sig_maps[i].type == EDDSA25519) && ((hash_maps[j].type != SHA512) || (ec_maps[k].type != WEI25519))){
					continue;
				}
				if((ec_sig_maps[i].type == EDDSA25519CTX) && ((hash_maps[j].type != SHA512) || (ec_maps[k].type != WEI25519))){
					continue;
				}
				if((ec_sig_maps[i].type == EDDSA25519PH) && ((hash_maps[j].type != SHA512) || (ec_maps[k].type != WEI25519))){
					continue;
				}
#endif
#ifdef WITH_SIG_EDDSA448
				if((ec_sig_maps[i].type == EDDSA448) && ((hash_maps[j].type != SHAKE256) || (ec_maps[k].type != WEI448))){
					continue;
				}
				if((ec_sig_maps[i].type == EDDSA448PH) && ((hash_maps[j].type != SHAKE256) || (ec_maps[k].type != WEI448))){
					continue;
				}
#endif
				ret = perf_test_one(&ec_sig_maps[i],
						    &hash_maps[j],
						    &ec_maps[k]);
				if (ret) {
					goto err;
				}
			}
		}
	}

	return 0;

err:
	return -1;
}
