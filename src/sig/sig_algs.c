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
			/* NOTE: since sm is initalized with a structure
	 		 * coming from a const source, we can safely call the callback here.
	 		 */
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

/* Here, we provide a helper that sanity checks the provided signature 
 * mapping against the constant ones.
 */
int ec_sig_mapping_callbacks_sanity_check(const ec_sig_mapping *sig)
{
	const ec_sig_mapping *sm;
	u8 i;

	if(sig == NULL){
		goto err;
	}
	/* We just check is our mapping is indeed
	 * one of the registered mappings.
	 */
	for (i = 0, sm = &ec_sig_maps[i];
	     sm->type != UNKNOWN_SIG_ALG; sm = &ec_sig_maps[++i]) {
		if(sm->type == sig->type){
			if(!are_str_equal_nlen(sm->name, sig->name, MAX_SIG_ALG_NAME_LEN)){
				goto err;
			}
			else if(sm->siglen != sig->siglen){
				goto err;
			}
			else if(sm->init_pub_key != sig->init_pub_key){
				goto err;
			}
			else if(sm->sign_init != sig->sign_init){
				goto err;
			}
			else if(sm->sign_update != sig->sign_update){
				goto err;
			}
			else if(sm->sign_finalize != sig->sign_finalize){
				goto err;
			}
			else if(sm->verify_init != sig->verify_init){
				goto err;
			}
			else if(sm->verify_update != sig->verify_update){
				goto err;
			}
			else if(sm->verify_finalize != sig->verify_finalize){
				goto err;
			}
			else{
				return 0;
			}
		}
	}

err:
	return -1;
}

/* Sanity check of a signature context to see if everything seems
 * OK.
 */
int ec_sig_ctx_callbacks_sanity_check(const struct ec_sign_context *sig_ctx)
{
	if(sig_ctx == NULL){
		goto err;
	}
	if(sig_ctx->ctx_magic != SIG_SIGN_MAGIC){
		goto err;
	}
	if(hash_mapping_callbacks_sanity_check(sig_ctx->h)){
		goto err;
	}
	if(ec_sig_mapping_callbacks_sanity_check(sig_ctx->sig)){
		goto err;
	}
	
	return 0;
err:
	return -1;
}

/* Sanity check of a verification context to see if everything seems
 * OK.
 */
int ec_verify_ctx_callbacks_sanity_check(const struct ec_verify_context *verify_ctx)
{
	if(verify_ctx == NULL){
		goto err;
	}
	if(verify_ctx->ctx_magic != SIG_VERIFY_MAGIC){
		goto err;
	}
	if(hash_mapping_callbacks_sanity_check(verify_ctx->h)){
		goto err;
	}
	if(ec_sig_mapping_callbacks_sanity_check(verify_ctx->sig)){
		goto err;
	}
	
	return 0;
err:
	return -1;
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

	MUST_HAVE((params != NULL) && (siglen != NULL));

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

#ifdef NO_KNOWN_VECTORS
        /* NOTE: when we do not need self tests for known vectors,
         * we can be strict about random function handler!
	 * We only use our internal method to provide random integers
	 * (which avoids honest mistakes ...).
	 *
         * This also allows us to avoid the corruption of such a pointer in
	 * our signature contexts.
         */
	if(rand){
		if(rand != nn_get_random_mod){
			ret = -1;
			goto err;
		}
	}
	rand = nn_get_random_mod;
#else
	/* Use given random function if provided or fallback to ours */
	if (!rand) {
		rand = nn_get_random_mod;
	}
#endif
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

	/* NOTE: since sm has been previously initalized with a structure
	 * coming from a const source, we can safely call the callback here.
	 */
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

	/* Since we call a callback, sanity check our contexts */
	if(ec_sig_ctx_callbacks_sanity_check(ctx)){
		ret = -1;
		goto err;
	}
	ret = ctx->sig->sign_update(ctx, chunk, chunklen);

	if (ret) {
		/* Clear the whole context to prevent future reuse */
		local_memset(ctx, 0, sizeof(struct ec_sign_context));
	}

err:
	return ret;
}

/* Signature finalization function */
int ec_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	int ret;

	SIG_SIGN_CHECK_INITIALIZED(ctx);
	SIG_MAPPING_SANITY_CHECK(ctx->sig);
	HASH_MAPPING_SANITY_CHECK(ctx->h);

	/* Since we call a callback, sanity check our contexts */
	if(ec_sig_ctx_callbacks_sanity_check(ctx)){
		ret = -1;
		goto err;
	}
	ret = ctx->sig->sign_finalize(ctx, sig, siglen);

	/* Clear the whole context to prevent future reuse */
	local_memset(ctx, 0, sizeof(struct ec_sign_context));

err:
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

	MUST_HAVE(ctx != NULL);
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
		if ((sm->type == sig_type) && (sm->verify_init != NULL)) {
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

	/* NOTE: since sm has been previously initalized with a structure
	 * coming from a const source, we can safely call the callback here.
	 */
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

	/* Since we call a callback, sanity check our contexts */
	if(ec_verify_ctx_callbacks_sanity_check(ctx)){
		ret = -1;
		goto err;
	}
	ret = ctx->sig->verify_update(ctx, chunk, chunklen);

	if (ret) {
		/* Clear the whole context to prevent future reuse */
		local_memset(ctx, 0, sizeof(struct ec_verify_context));
	}

err:
	return ret;
}

int ec_verify_finalize(struct ec_verify_context *ctx)
{
	int ret;

	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	SIG_MAPPING_SANITY_CHECK(ctx->sig);
	HASH_MAPPING_SANITY_CHECK(ctx->h);

	/* Since we call a callback, sanity check our contexts */
	if(ec_verify_ctx_callbacks_sanity_check(ctx)){
		ret = -1;
		goto err;
	}
	ret = ctx->sig->verify_finalize(ctx);

	/* Clear the whole context to prevent future reuse */
	local_memset(ctx, 0, sizeof(struct ec_verify_context));

err:
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

/*
 * Import a signature with structured data containing information about the EC
 * algorithm type as well as the hash function used to produce it
 */
int ec_structured_sig_import_from_buf(u8 *sig, u32 siglen,
                                      const u8 *out_buf, u32 outlen,
                                      ec_sig_alg_type * sig_type,
                                      hash_alg_type * hash_type,
                                      u8 curve_name[MAX_CURVE_NAME_LEN])
{
        u32 metadata_len = (3 * sizeof(u8));

	MUST_HAVE((out_buf != NULL) && (sig_type != NULL) && (hash_type != NULL) && (curve_name != NULL));
        /* We only deal with signatures of length < 256 */
        MUST_HAVE(siglen <= EC_MAX_SIGLEN);
	if(siglen > 0){
		MUST_HAVE(sig != NULL);
	}

        /* We first import the metadata consisting of:
         *      - One byte = the EC algorithm type
         *      - One byte = the hash algorithm type
         *      - One byte = the curve type (FRP256V1, ...)
         */
        MUST_HAVE(outlen <= (siglen + metadata_len));
        if (outlen > (siglen + metadata_len))
                return -1;

        *sig_type = (ec_sig_alg_type)out_buf[0];
        *hash_type = (hash_alg_type)out_buf[1];
        if (ec_get_curve_name_by_type((ec_curve_type) out_buf[2],
                                      curve_name, MAX_CURVE_NAME_LEN)) {
                return -1;
        }

        /* Copy the raw signature */
        local_memcpy(sig, out_buf + metadata_len, siglen);

        return 0;
}

/*
 * Export a signature with structured data containing information about the EC
 * algorithm type as well as the hash function used to produce it.
 */
int ec_structured_sig_export_to_buf(const u8 *sig, u32 siglen,
                                    u8 *out_buf, u32 outlen,
                                    ec_sig_alg_type sig_type,
                                    hash_alg_type hash_type,
                                    const u8
                                    curve_name[MAX_CURVE_NAME_LEN])
{
        u32 metadata_len = (3 * sizeof(u8));
        u8 curve_name_len;
        ec_curve_type curve_type;

	MUST_HAVE((out_buf != NULL) && (curve_name != NULL));
        /* We only deal with signatures of length < 256 */
        MUST_HAVE(siglen <= EC_MAX_SIGLEN);
	if(siglen > 0){
		MUST_HAVE(sig != NULL);
	}

        /* We first export the metadata consisting of:
         *      - One byte = the EC algorithm type
         *      - One byte = the hash algorithm type
         *      - One byte = the curve type (FRP256V1, ...)
         *
         */
        MUST_HAVE(outlen >= (siglen + metadata_len));
        if (outlen < (siglen + metadata_len)) {
                return -1;
        }

        out_buf[0] = (u8)sig_type;
        out_buf[1] = (u8)hash_type;
        curve_name_len = (u8)local_strlen((const char *)curve_name) + 1;
        curve_type = ec_get_curve_type_by_name(curve_name, curve_name_len);
        out_buf[2] = (u8)curve_type;
        if (out_buf[2] == UNKNOWN_CURVE) {
                return -1;
        }

        /* Copy the raw signature */
        local_memcpy(out_buf + metadata_len, sig, siglen);

        return 0;
}
