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
#ifdef WITH_SIG_ECFSDSA

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECFSDSA"
#endif
#include "../utils/dbg_sig.h"

int ecfsdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	prj_pt_src_t G;

	MUST_HAVE(out_pub != NULL);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	priv_key_check_initialized_and_type(in_priv, ECFSDSA);

	/* Sanity check */
	if(nn_cmp(&(in_priv->x), &(in_priv->params->ec_gen_order)) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		goto err;
	}

	/* Y = xG */
	G = &(in_priv->params->ec_gen);
	/* Use blinding when computing point scalar multiplication */
	if(prj_pt_mul_monty_blind(&(out_pub->y), &(in_priv->x), G)){
		goto err;
	}

	out_pub->key_type = ECFSDSA;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	return 0;
err:
	return -1;
}

u8 ecfsdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)ECFSDSA_SIGLEN(p_bit_len, q_bit_len);
}

/*
 * Generic *internal* ECFSDSA signature functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * their output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-FSDSA signature process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - ECFSDSA signature
 *|
 *| I	1. Get a random value k in ]0,q[
 *| I	2. Compute W = (W_x,W_y) = kG
 *| I	3. Compute r = FE2OS(W_x)||FE2OS(W_y)
 *| I	4. If r is an all zero string, restart the process at step 1.
 *| IUF 5. Compute h = H(r||m)
 *|   F 6. Compute e = OS2I(h) mod q
 *|   F 7. Compute s = (k + ex) mod q
 *|   F 8. If s is 0, restart the process at step 1 (see c. below)
 *|   F 9. Return (r,s)
 *
 * Implementation notes:
 *
 * a) sig is built as the concatenation of r and s. r is encoded on
 *    2*ceil(bitlen(p)) bytes and s on ceil(bitlen(q)) bytes.
 * b) in EC-FSDSA, the public part of the key is not needed per se during
 *    the signature but - as it is needed in other signature algs implemented
 *    in the library - the whole key pair is passed instead of just the
 *    private key.
 * c) Implementation of EC-FSDSA in an init()/update()/finalize() logic
 *    cannot be made deterministic, in the sense that if s is 0 at step
 *    8 above, there is no way to restart the whole signature process
 *    w/o rehashing m. So, even if the event is extremely unlikely,
 *    signature process may fail to provide a signature of the data
 *    during finalize() call.
 */

#define ECFSDSA_SIGN_MAGIC ((word_t)(0x1ed9635924b48ddaULL))
#define ECFSDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECFSDSA_SIGN_MAGIC))

int _ecfsdsa_sign_init(struct ec_sign_context *ctx)
{
	prj_pt_src_t G;
	nn_src_t q;
	nn *k;
	u8 *r;
	prj_pt kG;
	aff_pt W;
	const ec_priv_key *priv_key;
	bitcnt_t p_bit_len;
	u8 i, p_len, r_len;
	u16 p_len_;
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Zero init points */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, ECFSDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	r = ctx->sign_data.ecfsdsa.r;
	k = &(ctx->sign_data.ecfsdsa.k);
	p_bit_len = priv_key->params->ec_fp.p_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECFSDSA_R_LEN(p_bit_len);

	p_len_ = p_len;
	if (p_len_ > NN_MAX_BYTE_LEN) {
		ret = -1;
		goto err;
	}

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", q);
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", G);
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));

 restart:

	/*  1. Get a random value k in ]0,q[ */
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
	ret = ctx->rand(k, q);
	if (ret) {
		ret = -1;
		goto err;
	}

	/*  2. Compute W = (W_x,W_y) = kG */
#ifdef USE_SIG_BLINDING
	/* We use blinding for the scalar multiplication */
	if(prj_pt_mul_monty_blind(&kG, k, G)){
		ret = -1;
		goto err;
	}
#else
	prj_pt_mul_monty(&kG, k, G);
#endif
	prj_pt_to_aff(&W, &kG);
	prj_pt_uninit(&kG);

	dbg_nn_print("Wx", &(W.x.fp_val));
	dbg_nn_print("Wy", &(W.y.fp_val));

	/*  3. Compute r = FE2OS(W_x)||FE2OS(W_y) */
	fp_export_to_buf(r, p_len, &(W.x));
	fp_export_to_buf(r + p_len, p_len, &(W.y));
	aff_pt_uninit(&W);
	dbg_buf_print("r: ", r, r_len);

	/*  4. If r is an all zero string, restart the process at step 1. */
	ret = 0;
	for (i = 0; i < r_len; i++) {
		ret |= r[i];
	}
	if (ret == 0) {
		goto restart;
	}

	/*  5. Compute h = H(r||m).
	 *
	 * Note that we only start the hash work here by initializing the hash
	 * context and processing r. Message m will be handled during following
	 * update() calls.
	 */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->sign_data.ecfsdsa.h_ctx));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecfsdsa.h_ctx), r, r_len);
	ctx->sign_data.ecfsdsa.magic = ECFSDSA_SIGN_MAGIC;

	ret = 0;

 err:

	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(k);
	PTR_NULLIFY(r);
	PTR_NULLIFY(priv_key);
	VAR_ZEROIFY(i);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);

	return ret;
}

int _ecfsdsa_sign_update(struct ec_sign_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECFSDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECFSDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecfsdsa));

	/*  5. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecfsdsa.h_ctx), chunk, chunklen);

	return 0;
}

int _ecfsdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	nn_src_t q, x;
	nn tmp, s, e, ex, *k;
	const ec_priv_key *priv_key;
	u8 e_buf[MAX_DIGEST_SIZE];
	bitcnt_t p_bit_len, q_bit_len;
	u8 hsize, s_len, r_len;
	int ret = -1;
	u8 *r;

#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif /* USE_SIG_BLINDING */

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECFSDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECFSDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecfsdsa));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	q = &(priv_key->params->ec_gen_order);
	x = &(priv_key->x);
	p_bit_len = ctx->key_pair->priv_key.params->ec_fp.p_bitlen;
	q_bit_len = ctx->key_pair->priv_key.params->ec_gen_order_bitlen;
	k = &(ctx->sign_data.ecfsdsa.k);
	r_len = (u8)ECFSDSA_R_LEN(p_bit_len);
	s_len = (u8)ECFSDSA_S_LEN(q_bit_len);
	hsize = ctx->h->digest_size;
	r = ctx->sign_data.ecfsdsa.r;

	/* Sanity check */
	if(nn_cmp(x, q) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		ret = -1;
		goto err;
	}

	if (siglen != ECFSDSA_SIGLEN(p_bit_len, q_bit_len)) {
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

	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	/*  5. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->sign_data.ecfsdsa.h_ctx), e_buf);
	dbg_buf_print("h(R||m)", e_buf, hsize);

	/*  6. Compute e by converting h to an integer and reducing it mod q */
	nn_init_from_buf(&tmp, e_buf, hsize);
	local_memset(e_buf, 0, hsize);
	nn_mod(&e, &tmp, q);

#ifdef USE_SIG_BLINDING
	/* Blind e with b */
	nn_mul_mod(&e, &e, &b, q);
#endif /* USE_SIG_BLINDING */
	/*  7. Compute s = (k + ex) mod q */
	nn_mul_mod(&ex, &e, x, q);
	nn_uninit(&e);
#ifdef USE_SIG_BLINDING
	/* Blind k with b */
	nn_mul_mod(&s, k, &b, q);
	nn_mod_add(&s, &s, &ex, q);
#else
	nn_mod_add(&s, k, &ex, q);
#endif /* USE_SIG_BLINDING */
	nn_uninit(&ex);
	nn_uninit(&tmp);
#ifdef USE_SIG_BLINDING
	/* Unblind s */
	nn_modinv(&binv, &b, q);
	nn_mul_mod(&s, &s, &binv, q);
#endif /* USE_SIG_BLINDING */
	dbg_nn_print("s: ", &s);

	/*
	 * 8. If s is 0, restart the process at step 1.
	 *
	 * In practice, as we cannot restart the whole process in
	 * finalize() we just report an error.
	 */
	if (nn_iszero(&s)) {
		nn_uninit(&s);
		ret = -1;
		goto err;
	}

	/*  9. Return (r,s) */
	local_memcpy(sig, r, r_len);
	nn_export_to_buf(sig + r_len, s_len, &s);
	nn_uninit(&s);

	ret = 0;

 err:

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecfsdsa), 0, sizeof(ecfsdsa_sign_data));

	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	PTR_NULLIFY(k);
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(r);
	VAR_ZEROIFY(hsize);
	VAR_ZEROIFY(p_bit_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);

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

/*
 * Generic *internal* ECFSDSA verification functions (init, update and
 * finalize). Their purpose is to allow passing a specific hash function
 * (along with their output size) and the random ephemeral key k, so
 * that compliance tests against test vectors can be made without ugly
 * hack in the code itself.
 *
 * Global EC-FSDSA verification process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - ECFSDSA verification
 *|
 *| I	1. Reject the signature if r is not a valid point on the curve.
 *| I	2. Reject the signature if s is not in ]0,q[
 *| IUF 3. Compute h = H(r||m)
 *|   F 4. Convert h to an integer and then compute e = -h mod q
 *|   F 5. compute W' = sG + eY, where Y is the public key
 *|   F 6. Compute r' = FE2OS(W'_x)||FE2OS(W'_y)
 *|   F 7. Accept the signature if and only if r equals r'
 *
 */

#define ECFSDSA_VERIFY_MAGIC ((word_t)(0x26afb13ccd96fa04ULL))
#define ECFSDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECFSDSA_VERIFY_MAGIC))

int _ecfsdsa_verify_init(struct ec_verify_context *ctx,
			 const u8 *sig, u8 siglen)
{
	bitcnt_t p_bit_len, q_bit_len;
	u8 p_len, r_len, s_len;
	int ret = -1;
	const u8 *r;
	nn_src_t q;
	fp rx, ry;
	nn *s;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, ECFSDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	q = &(ctx->pub_key->params->ec_gen_order);
	p_bit_len = ctx->pub_key->params->ec_fp.p_bitlen;
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECFSDSA_R_LEN(p_bit_len);
	s_len = (u8)ECFSDSA_S_LEN(q_bit_len);
	s = &(ctx->verify_data.ecfsdsa.s);

	if (siglen != ECFSDSA_SIGLEN(p_bit_len, q_bit_len)) {
		ret = -1;
		goto err;
	}

	/*  1. Reject the signature if r is not a valid point on the curve. */

	/* Let's first import r, i.e. x and y coordinates of the point */
	r = sig;
	fp_init(&rx, ctx->pub_key->params->ec_curve.a.ctx);
	fp_import_from_buf(&rx, r, p_len);
	fp_init(&ry, ctx->pub_key->params->ec_curve.a.ctx);
	fp_import_from_buf(&ry, r + p_len, p_len);

	/* Let's now check that r represents a point on the curve */
	if (!is_on_shortw_curve(&rx, &ry, &(ctx->pub_key->params->ec_curve))) {
		ret = -1;
		goto err;
	}
	fp_uninit(&rx);
	fp_uninit(&ry);

	/* 2. Reject the signature if s is not in ]0,q[ */

	/* Import s as a nn */
	nn_init_from_buf(s, sig + r_len, s_len);

	/* Check that s is in ]0,q[ */
	if (nn_iszero(s) || (nn_cmp(s, q) >= 0)) {
		ret = -1;
		goto err;
	}

	/* 3. Compute h = H(r||m) */

	/* Initialize the verify context */
	local_memcpy(&(ctx->verify_data.ecfsdsa.r), r, r_len);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->verify_data.ecfsdsa.h_ctx));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecfsdsa.h_ctx), r, r_len);
	ctx->verify_data.ecfsdsa.magic = ECFSDSA_VERIFY_MAGIC;

	ret = 0;

 err:
	if (ret) {
		/*
		 * Signature is invalid. Clear data part of the context.
		 * This will clear magic and avoid further reuse of the
		 * whole context.
		 */
		local_memset(&(ctx->verify_data.ecfsdsa), 0,
			     sizeof(ecfsdsa_verify_data));
	}

	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(p_bit_len);
	VAR_ZEROIFY(q_bit_len);
	PTR_NULLIFY(r);
	PTR_NULLIFY(q);
	PTR_NULLIFY(s);

	return ret;
}

int _ecfsdsa_verify_update(struct ec_verify_context *ctx,
			   const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECFSDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECFSDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecfsdsa));

	/* 3. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecfsdsa.h_ctx), chunk,
			     chunklen);

	return 0;
}

int _ecfsdsa_verify_finalize(struct ec_verify_context *ctx)
{
	prj_pt_src_t G, Y;
	nn_src_t q;
	nn tmp, tmp2, e, *s;
	prj_pt sG, eY, Wprime;
	bitcnt_t p_bit_len, r_len;
	aff_pt Wprime_aff;
	u8 r_prime[2 * NN_MAX_BYTE_LEN];
	u8 e_buf[MAX_DIGEST_SIZE];
	u8 hsize, p_len;
	const u8 *r;
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECFSDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECFSDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecfsdsa));

	/* Zero init points */
	local_memset(&sG, 0, sizeof(prj_pt));
	local_memset(&eY, 0, sizeof(prj_pt));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	Y = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	hsize = ctx->h->digest_size;
	s = &(ctx->verify_data.ecfsdsa.s);
	r = ctx->verify_data.ecfsdsa.r;
	p_bit_len = ctx->pub_key->params->ec_fp.p_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECFSDSA_R_LEN(p_bit_len);

	/* 3. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->verify_data.ecfsdsa.h_ctx), e_buf);

	/*
	 * 4. Convert h to an integer and then compute e = -h mod q
	 *
	 * Because we only support positive integers, we compute
	 * e = q - (h mod q) (except when h is 0).
	 */
	nn_init_from_buf(&tmp, e_buf, hsize);
	local_memset(e_buf, 0, hsize);
	nn_mod(&tmp2, &tmp, q);
	nn_uninit(&tmp);
	if (nn_iszero(&tmp2)) {
		nn_zero(&e);
	} else {
		nn_sub(&e, q, &tmp2);
	}
	nn_uninit(&tmp2);

	/* 5. compute W' = (W'_x,W'_y) = sG + tY, where Y is the public key */
	prj_pt_mul_monty(&sG, s, G);
	prj_pt_mul_monty(&eY, &e, Y);
	nn_uninit(&e);
	prj_pt_add_monty(&Wprime, &sG, &eY);
	prj_pt_uninit(&sG);
	prj_pt_uninit(&eY);
	prj_pt_to_aff(&Wprime_aff, &Wprime);
	prj_pt_uninit(&Wprime);

	/* 6. Compute r' = FE2OS(W'_x)||FE2OS(W'_y) */
	fp_export_to_buf(r_prime, p_len, &(Wprime_aff.x));
	fp_export_to_buf(r_prime + p_len, p_len, &(Wprime_aff.y));
	aff_pt_uninit(&Wprime_aff);

	dbg_buf_print("r_prime: ", r_prime, r_len);

	/* 7. Accept the signature if and only if r equals r' */
	ret = are_equal(r, r_prime, r_len) ? 0 : -1;
	local_memset(r_prime, 0, r_len);

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecfsdsa), 0,
		     sizeof(ecfsdsa_verify_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(q);
	PTR_NULLIFY(s);
	PTR_NULLIFY(r);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(hsize);

err:
	return ret;
}

#else /* WITH_SIG_ECFSDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECFSDSA */
