/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *	Ryad BENADJILA <ryadbenadjila@gmail.com>
 *	Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *	Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *	Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *	Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "../lib_ecc_config.h"
#if (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA))

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "ecsdsa_common.h"
#include "sig_algs_internal.h"
#include "ec_key.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "EC[O]SDSA"
#endif
#include "../utils/dbg_sig.h"

int __ecsdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv,
			   ec_sig_alg_type key_type)
{
	prj_pt_src_t G;

	MUST_HAVE(out_pub != NULL);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	priv_key_check_initialized_and_type(in_priv, key_type);

	/* Y = xG */
	G = &(in_priv->params->ec_gen);
	/* Use blinding when computing point scalar multiplication */
	if(prj_pt_mul_monty_blind(&(out_pub->y), &(in_priv->x), G)){
		goto err;
	}

	out_pub->key_type = key_type;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	return 0;
err:
	return -1;
}

u8 __ecsdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)ECSDSA_SIGLEN(hsize, q_bit_len);
}

/*
 * Generic *internal* EC-SDSA signature functions. There purpose is to
 * allow passing specific hash functions and the random ephemeral
 * key k, so that compliance tests against test vector be made
 * without ugly hack in the code itself.
 *
 * The 'optimized' parameter tells the function if the r value of
 * the signature is computed using only the x ccordinate of the
 * the user's public key (normal version uses both coordinates).
 *
 * Normal:     r = h(Wx || Wy || m)
 * Optimized : r = h(Wx || m)
 *
 *| IUF - ECSDSA/ECOSDSA signature
 *|
 *| I	1. Get a random value k in ]0, q[
 *| I	2. Compute W = kG = (Wx, Wy)
 *| IUF 3. Compute r = H(Wx [|| Wy] || m)
 *|	   - In the normal version (ECSDSA), r = H(Wx || Wy || m).
 *|	   - In the optimized version (ECOSDSA), r = H(Wx || m).
 *|   F 4. Compute e = OS2I(r) mod q
 *|   F 5. if e == 0, restart at step 1.
 *|   F 6. Compute s = (k + ex) mod q.
 *|   F 7. if s == 0, restart at step 1.
 *|   F 8. Return (r, s)
 *
 * In the project, the normal mode is named ECSDSA, the optimized
 * one is ECOSDSA.
 *
 * Implementation note:
 *
 * In ISO-14888-3, the option is provided to the developer to check
 * whether r = 0 and restart the process in that case. Even if
 * unlikely to trigger, that check makes a lot of sense because the
 * verifier expects a non-zero value for r. In the  specification, r
 * is a string (r =  H(Wx [|| Wy] || m)). But r is used in practice
 * - both on the signer and the verifier - after conversion to an
 * integer and reduction mod q. The value resulting from that step
 * is named e (e = OS2I(r) mod q). The check for the case when r = 0
 * should be replaced by a check for e = 0. This is more conservative
 * and what is described above and done below in the implementation.
 */

#define ECSDSA_SIGN_MAGIC ((word_t)(0x743c03ae409d15c4ULL))
#define ECSDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECSDSA_SIGN_MAGIC))

int __ecsdsa_sign_init(struct ec_sign_context *ctx,
		       ec_sig_alg_type key_type, int optimized)
{
	u8 Wx[BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	u8 Wy[BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	const ec_priv_key *priv_key;
	prj_pt_src_t G;
	bitcnt_t p_bit_len;
	u8 p_len;
	prj_pt kG;
	aff_pt W_aff;
	nn_src_t q;
	int ret;
	nn k;

	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Zero init points */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, key_type);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	p_bit_len = priv_key->params->ec_fp.p_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", q);
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", G);
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));

	/* 1. Get a random value k in ]0, q[ */
#ifdef NO_KNOWN_VECTORS
	/* NOTE: when we do not need self tests for known vectors,
	 * we can be strict about random function handler!
	 * This allows us to avoid the corruption of such a pointer.
	 */
	/* Sanity check on the handler before calling it */
	if(ctx->rand != nn_get_random_mod){
		ret = -1;
		goto err;
	}
#endif
	if(ctx->rand == NULL){
		ret = -1;
		goto err;
	}
	ret = ctx->rand(&k, q);
	if (ret) {
		ret = -1;
		goto err;
	}
	dbg_nn_print("k", &k);

	/* 2. Compute W = kG = (Wx, Wy). */
#ifdef USE_SIG_BLINDING
	if(prj_pt_mul_monty_blind(&kG, &k, G)){
		ret = -1;
		goto err;
	}
#else
	prj_pt_mul_monty(&kG, &k, G);
#endif
	prj_pt_to_aff(&W_aff, &kG);
	prj_pt_uninit(&kG);
	dbg_nn_print("W_x", &(W_aff.x.fp_val));
	dbg_nn_print("W_y", &(W_aff.y.fp_val));

	/*
	 * 3. Compute r = H(Wx [|| Wy] || m)
	 *
	 *    - In the normal version (ECSDSA), r = h(Wx || Wy || m).
	 *    - In the optimized version (ECOSDSA), r = h(Wx || m).
	 */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->sign_data.ecsdsa.h_ctx));
	fp_export_to_buf(Wx, p_len, &(W_aff.x));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecsdsa.h_ctx), Wx, p_len);
	if (!optimized) {
		fp_export_to_buf(Wy, p_len, &(W_aff.y));
		/* Since we call a callback, sanity check our mapping */
		if(hash_mapping_callbacks_sanity_check(ctx->h)){
			ret = -1;
			goto err;
		}
		ctx->h->hfunc_update(&(ctx->sign_data.ecsdsa.h_ctx), Wy,
				     p_len);
	}
	aff_pt_uninit(&W_aff);
	local_memset(Wx, 0, p_len);
	local_memset(Wy, 0, p_len);

	/* Initialize the remaining of sign context. */
	nn_copy(&(ctx->sign_data.ecsdsa.k), &k);
	nn_zero(&k);
	ctx->sign_data.ecsdsa.magic = ECSDSA_SIGN_MAGIC;

	ret = 0;

 err:
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(p_bit_len);

	return ret;
}

int __ecsdsa_sign_update(struct ec_sign_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECSDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECSDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecsdsa));

	/* 3. Compute r = H(Wx [|| Wy] || m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecsdsa.h_ctx), chunk, chunklen);

	return 0;
}

int __ecsdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	nn_src_t q, x;
	nn tmp, s, e, ex;
	u8 r[MAX_DIGEST_SIZE];
	const ec_priv_key *priv_key;
	bitcnt_t q_bit_len;
	u8 r_len, s_len;
	u8 hsize;
	int ret;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif /* USE_SIG_BLINDING */

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECSDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECSDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecsdsa));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	q = &(priv_key->params->ec_gen_order);
	x = &(priv_key->x);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	hsize = ctx->h->digest_size;
	r_len = (u8)ECSDSA_R_LEN(hsize);
	s_len = (u8)ECSDSA_S_LEN(q_bit_len);

	if (siglen != ECSDSA_SIGLEN(hsize, q_bit_len)) {
		ret = -1;
		goto err;
	}

#ifdef USE_SIG_BLINDING
	ret = nn_get_random_mod(&b, q);
	if (ret) {
		ret = -1;
		goto err;
	}
	dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */

	/* 3. Compute r = H(Wx [|| Wy] || m) */
	local_memset(r, 0, hsize);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->sign_data.ecsdsa.h_ctx), r);
	dbg_buf_print("r", r, r_len);

	/* 4. Compute e = OS2I(r) mod q */
	nn_init_from_buf(&tmp, r, r_len);
	nn_mod(&e, &tmp, q);
	dbg_nn_print("e", &e);

	/*
	 * 5. if e == 0, restart at step 1.
	 *
	 * As we cannot restart at that point (step 1. is in init()),
	 * we just stop and return an error.
	 */
	if (nn_iszero(&e)) {
		ret = -1;
		goto err;
	}

#ifdef USE_SIG_BLINDING
	/* Blind e with b */
	nn_mul_mod(&e, &e, &b, q);
#endif /* USE_SIG_BLINDING */

	/* 6. Compute s = (k + ex) mod q. */
	nn_mul_mod(&ex, x, &e, q);
	nn_zero(&e);
#ifdef USE_SIG_BLINDING
	/* Blind k with b */
	nn_mul_mod(&s, &(ctx->sign_data.ecsdsa.k), &b, q);
	nn_mod_add(&s, &s, &ex, q);
#else
	nn_mod_add(&s, &(ctx->sign_data.ecsdsa.k), &ex, q);
#endif /* USE_SIG_BLINDING */
	nn_zero(&ex);
	nn_zero(&tmp);

#ifdef USE_SIG_BLINDING
	/* Unblind s */
	nn_modinv(&binv, &b, q);
	nn_mul_mod(&s, &s, &binv, q);
#endif /* USE_SIG_BLINDING */
	dbg_nn_print("s", &s);

	/*
	 * 7. if s == 0, restart at step 1.
	 *
	 * As we cannot restart at that point (step 1. is in init()),
	 * we just stop and return an error.
	 */
	if (nn_iszero(&s)) {
		ret = -1;
		goto err;
	}

	/* 8. Return (r, s) */
	local_memcpy(sig, r, r_len);
	local_memset(r, 0, r_len);
	nn_export_to_buf(sig + r_len, s_len, &s);
	nn_zero(&s);

	ret = 0;

 err:
	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecsdsa), 0, sizeof(ecsdsa_sign_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	PTR_NULLIFY(priv_key);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(hsize);

#ifdef USE_SIG_BLINDING
	if(nn_is_initialized(&b)){
		nn_uninit(&b);
	}
	if(nn_is_initialized(&binv)){
		nn_uninit(&binv);
	}
#endif /* USE_SIG_BLINDING */

	return ret;
}

#define ECSDSA_VERIFY_MAGIC ((word_t)(0x8eac1ff89995bb0aULL))
#define ECSDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECSDSA_VERIFY_MAGIC))

/*
 *| IUF - ECSDSA/ECOSDSA verification
 *|
 *| I	1. if s is not in ]0,q[, reject the signature.
 *| I	2. Compute e = -r mod q
 *| I	3. If e == 0, reject the signature.
 *| I	4. Compute W' = sG + eY
 *| IUF 5. Compute r' = H(W'x [|| W'y] || m)
 *|	   - In the normal version (ECSDSA), r' = H(W'x || W'y || m).
 *|	   - In the optimized version (ECOSDSA), r' = H(W'x || m).
 *|   F 6. Accept the signature if and only if r and r' are the same
 *
 */
int __ecsdsa_verify_init(struct ec_verify_context *ctx,
			 const u8 *sig, u8 siglen,
			 ec_sig_alg_type key_type, int optimized)
{
	prj_pt_src_t G, Y;
	const ec_pub_key *pub_key;
	nn_src_t q;
	nn rmodq, e, r, s;
	prj_pt sG, eY, Wprime;
	u8 Wprimex[BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	u8 Wprimey[BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	u8 p_len, r_len, s_len;
	bitcnt_t q_bit_len;
	aff_pt Wprime_aff;
	u8 hsize;
	int ret;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Zero init points */
	local_memset(&sG, 0, sizeof(prj_pt));
	local_memset(&eY, 0, sizeof(prj_pt));

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, key_type);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	pub_key = ctx->pub_key;
	G = &(pub_key->params->ec_gen);
	Y = &(pub_key->y);
	q = &(pub_key->params->ec_gen_order);
	p_len = (u8)BYTECEIL(pub_key->params->ec_fp.p_bitlen);
	q_bit_len = pub_key->params->ec_gen_order_bitlen;
	hsize = ctx->h->digest_size;
	r_len = (u8)ECSDSA_R_LEN(hsize);
	s_len = (u8)ECSDSA_S_LEN(q_bit_len);

	if (siglen != ECSDSA_SIGLEN(hsize, q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* 1. if s is not in ]0,q[, reject the signature. */
	nn_init_from_buf(&s, sig + r_len, s_len);
	if (nn_iszero(&s) || (nn_cmp(&s, q) >= 0)) {
		ret = -1;
		goto err;
	}

	/*
	 * 2. Compute e = -r mod q
	 *
	 * To avoid dealing w/ negative numbers, we simply compute
	 * e = -r mod q = q - (r mod q) (except when r is 0).
	 */
	nn_init_from_buf(&r, sig, r_len);
	nn_mod(&rmodq, &r, q);
	nn_zero(&r);
	if (nn_iszero(&rmodq)) {
		nn_zero(&e);
	} else {
		nn_sub(&e, q, &rmodq);
	}
	nn_zero(&rmodq);

	/* 3. If e == 0, reject the signature. */
	if (nn_iszero(&e)) {
		ret = -1;
		goto err;
	}

	/* 4. Compute W' = sG + eY */
	prj_pt_mul_monty(&sG, &s, G);
	prj_pt_mul_monty(&eY, &e, Y);
	nn_zero(&e);
	prj_pt_add_monty(&Wprime, &sG, &eY);
	prj_pt_to_aff(&Wprime_aff, &Wprime);
	prj_pt_uninit(&sG);
	prj_pt_uninit(&eY);
	prj_pt_uninit(&Wprime);

	/*
	 * 5. Compute r' = H(W'x [|| W'y] || m)
	 *
	 *    - In the normal version (ECSDSA), r = h(W'x || W'y || m).
	 *    - In the optimized version (ECOSDSA), r = h(W'x || m).
	 */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->verify_data.ecsdsa.h_ctx));
	fp_export_to_buf(Wprimex, p_len, &(Wprime_aff.x));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecsdsa.h_ctx), Wprimex, p_len);
	if (!optimized) {
		fp_export_to_buf(Wprimey, p_len, &(Wprime_aff.y));
		/* Since we call a callback, sanity check our mapping */
		if(hash_mapping_callbacks_sanity_check(ctx->h)){
			ret = -1;
			goto err;
		}
		ctx->h->hfunc_update(&(ctx->verify_data.ecsdsa.h_ctx),
				     Wprimey, p_len);
	}
	local_memset(Wprimex, 0, p_len);
	local_memset(Wprimey, 0, p_len);
	aff_pt_uninit(&Wprime_aff);

	/* Initialize the remaining of verify context. */
	local_memcpy(ctx->verify_data.ecsdsa.r, sig, r_len);
	nn_copy(&(ctx->verify_data.ecsdsa.s), &s);
	nn_zero(&s);
	ctx->verify_data.ecsdsa.magic = ECSDSA_VERIFY_MAGIC;

	ret = 0;

 err:
	/* Clean what remains on the stack */
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(pub_key);
	PTR_NULLIFY(q);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(hsize);

	return ret;
}

int __ecsdsa_verify_update(struct ec_verify_context *ctx,
			   const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECSDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECSDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecsdsa));

	/* 5. Compute r' = H(W'x [|| W'y] || m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecsdsa.h_ctx), chunk,
			     chunklen);

	return 0;
}

int __ecsdsa_verify_finalize(struct ec_verify_context *ctx)
{
	u8 r_prime[MAX_DIGEST_SIZE];
	u32 r_len;
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECSDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECSDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecsdsa));

	r_len = ECSDSA_R_LEN(ctx->h->digest_size);

	/* 5. Compute r' = H(W'x [|| W'y] || m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->verify_data.ecsdsa.h_ctx), r_prime);

	/* 6. Accept the signature if and only if r and r' are the same */
	ret = are_equal(ctx->verify_data.ecsdsa.r, r_prime, r_len) ? 0 : -1;
	local_memset(r_prime, 0, r_len);

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecsdsa), 0,
		     sizeof(ecsdsa_verify_data));

	/* Clean what remains on the stack */
	VAR_ZEROIFY(r_len);

err:
	return ret;
}

#else /* (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA)) */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* (defined(WITH_SIG_ECSDSA) || defined(WITH_SIG_ECOSDSA)) */
