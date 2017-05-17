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
#include "sig_algs.h"

/*
 * Generic function to init a uninitialized public key from an initialized
 * private key. The function uses the expected logic to derive the key
 * (e.g. Y=xG, Y=(x^-1)G, etc). It returns -1 on error (i.e. if the signature
 * alg is unknown) in which case the public key has not been initialized.
 */
int init_pubkey_from_privkey(ec_pub_key *pub_key, ec_priv_key *priv_key)
{
	const ec_sig_mapping *sm;
	int ret = -1;
	u8 i;

	priv_key_check_initialized(priv_key);

	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if (sm->type == priv_key->key_type) {
			sm->init_pub_key(pub_key, priv_key);
			ret = 0;
			break;
		}
	}

	return ret;
}

const ec_sig_mapping *get_sig_by_name(const char *ec_sig_name)
{
	const ec_sig_mapping *sm, *ret = NULL;
	u8 i;

	MUST_HAVE(ec_sig_name != NULL);

	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if (are_str_equal(ec_sig_name, sm->name)) {
			ret = sm;
			break;
		}
	}

	return ret;
}

const ec_sig_mapping *get_sig_by_type(ec_sig_alg_type sig_type)
{
	const ec_sig_mapping *sm, *ret = NULL;
	u8 i;

	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if (sm->type == sig_type) {
			ret = sm;
			break;
		}
	}

	return ret;
}

/*
 * Compute generic effective signature length depending on the curve parameters,
 * the signature algorithm and the hash function
 */
int ec_get_sig_len(const ec_params *params, ec_sig_alg_type sig_type,
		   hash_alg_type hash_type, u8 *siglen)
{
	const ec_sig_mapping *sm;
	u8 digest_size = 0;
	u8 block_size = 0;
	int ret = -1;
	u8 i;

	MUST_HAVE(params != NULL);

	ret = get_hash_sizes(hash_type, &digest_size, &block_size);
	if (ret) {
		ret = -1;
		goto err;
	}

	ret = -1;
	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if (sm->type == sig_type) {
			*siglen = sm->siglen(params->ec_fp.p_bitlen,
					     params->ec_gen_order_bitlen,
					     digest_size, block_size);
			ret = 0;
			break;
		}
	}
 err:

	return ret;
}

/* Generic signature */

/*
 * Internal version of generic signature initialization function. Its purpose
 * is to initialize given sign context structure 'ctx' based on given key pair,
 * nn random function, signature and hash types. This version allows passing
 * a specific nn random function. It returns 0 on success, -1 on error.
 */
static int _ec_sign_init(struct ec_sign_context *ctx,
			 const ec_key_pair *key_pair,
			 int (*rand) (nn_t out, nn_src_t q),
			 ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
	const ec_sig_mapping *sm;
	const hash_mapping *hm;
	int ret = -1;
	u8 i;

	MUST_HAVE(ctx != NULL);
	key_pair_check_initialized(key_pair);
	if ((key_pair->priv_key.key_type != sig_type) ||
	    (key_pair->pub_key.key_type != sig_type)) {
		ret = -1;
		goto err;
	}

	/* We first need to get the specific hash structure */
	ret = -1;
	for (i = 0, hm = &hash_maps[i];
	     hm->type != UNKNOWN_HASH_ALG; hm = &hash_maps[++i]) {
		if (hm->type == hash_type) {
			ret = 0;
			break;
		}
	}
	if (ret) {
		goto err;
	}

	/* Now, let's try and get the specific key alg which was requested */
	ret = -1;
	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if ((sm->type == sig_type) && (sm->sign_init != NULL)) {
			ret = 0;
			break;
		}
	}
	if (ret) {
		goto err;
	}

	/* Use given random function if provided or fallback to ours */
	if (!rand) {
		rand = nn_get_random_mod;
	}

	/* Sanity checks on our mappings */
	HASH_MAPPING_SANITY_CHECK(hm);
	SIG_MAPPING_SANITY_CHECK(sm);
	/* Initialize context for specific signature function */
	local_memset(ctx, 0, sizeof(struct ec_sign_context));
	ctx->key_pair = key_pair;
	ctx->rand = rand;
	ctx->h = hm;
	ctx->sig = sm;
	ctx->ctx_magic = SIG_SIGN_MAGIC;

	ret = sm->sign_init(ctx);

 err:
	if (ret) {
		/* Clear the whole context to prevent future reuse */
		local_memset(ctx, 0, sizeof(struct ec_sign_context));
	}

	return ret;
}

/*
 * Same as previous but for public use; it forces our internal nn random
 * function
 */
int ec_sign_init(struct ec_sign_context *ctx, const ec_key_pair *key_pair,
		 ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
	return _ec_sign_init(ctx, key_pair, NULL, sig_type, hash_type);
}

/* Signature update function */
int ec_sign_update(struct ec_sign_context *ctx, const u8 *chunk, u32 chunklen)
{
	int ret;

	SIG_SIGN_CHECK_INITIALIZED(ctx);
	SIG_MAPPING_SANITY_CHECK(ctx->sig);
	HASH_MAPPING_SANITY_CHECK(ctx->h);

	ret = ctx->sig->sign_update(ctx, chunk, chunklen);

	if (ret) {
		/* Clear the whole context to prevent future reuse */
		local_memset(ctx, 0, sizeof(struct ec_sign_context));
	}

	return ret;
}

/* Signature finalization function */
int ec_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	int ret;

	SIG_SIGN_CHECK_INITIALIZED(ctx);
	SIG_MAPPING_SANITY_CHECK(ctx->sig);
	HASH_MAPPING_SANITY_CHECK(ctx->h);

	ret = ctx->sig->sign_finalize(ctx, sig, siglen);

	/* Clear the whole context to prevent future reuse */
	local_memset(ctx, 0, sizeof(struct ec_sign_context));

	return ret;
}

int _ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
	     const u8 *m, u32 mlen,
	     int (*rand) (nn_t out, nn_src_t q),
	     ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
	struct ec_sign_context ctx;
	int ret;

	ret = _ec_sign_init(&ctx, key_pair, rand, sig_type, hash_type);
	if (ret) {
		goto err;
	}

	ret = ec_sign_update(&ctx, m, mlen);
	if (ret) {
		goto err;
	}

	ret = ec_sign_finalize(&ctx, sig, siglen);

 err:

	return ret;
}

int ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
	    const u8 *m, u32 mlen,
	    ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
	return _ec_sign(sig, siglen, key_pair, m, mlen,
			NULL, sig_type, hash_type);
}

/* Generic signature verification */

int ec_verify_init(struct ec_verify_context *ctx, const ec_pub_key *pub_key,
		   const u8 *sig, u8 siglen,
		   ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
	const ec_sig_mapping *sm;
	const hash_mapping *hm;
	u8 i;
	int ret;

	pub_key_check_initialized(pub_key);
	if (pub_key->key_type != sig_type) {
		ret = -1;
		goto err;
	}

	/* We first need to get the specific hash structure */
	ret = -1;
	for (i = 0, hm = &hash_maps[i];
	     hm->type != UNKNOWN_HASH_ALG; hm = &hash_maps[++i]) {
		if (hm->type == hash_type) {
			ret = 0;
			break;
		}
	}
	if (ret) {
		goto err;
	}

	/* Now, let's try and get the specific key algorithm which was requested */
	ret = -1;
	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if (sm->type == sig_type && sm->verify_init != NULL) {
			ret = 0;
			break;
		}
	}
	if (ret) {
		goto err;
	}

	/* Sanity checks on our mappings */
	HASH_MAPPING_SANITY_CHECK(hm);
	SIG_MAPPING_SANITY_CHECK(sm);
	/* Initialize context for specific signature function */
	local_memset(ctx, 0, sizeof(struct ec_verify_context));
	ctx->pub_key = pub_key;
	ctx->h = hm;
	ctx->sig = sm;
	ctx->ctx_magic = SIG_VERIFY_MAGIC;

	ret = sm->verify_init(ctx, sig, siglen);

 err:

	if (ret) {
		/* Clear the whole context to prevent future reuse */
		local_memset(ctx, 0, sizeof(struct ec_verify_context));
	}

	return ret;
}

int ec_verify_update(struct ec_verify_context *ctx,
		     const u8 *chunk, u32 chunklen)
{
	int ret;

	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	SIG_MAPPING_SANITY_CHECK(ctx->sig);
	HASH_MAPPING_SANITY_CHECK(ctx->h);

	ret = ctx->sig->verify_update(ctx, chunk, chunklen);

	if (ret) {
		/* Clear the whole context to prevent future reuse */
		local_memset(ctx, 0, sizeof(struct ec_verify_context));
	}

	return ret;
}

int ec_verify_finalize(struct ec_verify_context *ctx)
{
	int ret;

	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	SIG_MAPPING_SANITY_CHECK(ctx->sig);
	HASH_MAPPING_SANITY_CHECK(ctx->h);

	ret = ctx->sig->verify_finalize(ctx);

	/* Clear the whole context to prevent future reuse */
	local_memset(ctx, 0, sizeof(struct ec_verify_context));

	return ret;
}

int ec_verify(const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
	      const u8 *m, u32 mlen,
	      ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
	int ret;
	struct ec_verify_context ctx;

	ret = ec_verify_init(&ctx, pub_key, sig, siglen, sig_type, hash_type);
	if (ret) {
		goto err;
	}

	ret = ec_verify_update(&ctx, m, mlen);
	if (ret) {
		goto err;
	}

	ret = ec_verify_finalize(&ctx);

 err:
	return ret;
}
