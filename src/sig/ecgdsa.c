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
#ifdef WITH_SIG_ECGDSA

#include "../nn/nn.h"
#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECGDSA"
#endif
#include "../utils/dbg_sig.h"

int ecgdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	prj_pt_src_t G;
	nn xinv;

	MUST_HAVE(out_pub != NULL);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	priv_key_check_initialized_and_type(in_priv, ECGDSA);

	/* Sanity check */
	if(nn_cmp(&(in_priv->x), &(in_priv->params->ec_gen_order)) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		goto err;
	}

	/* Y = (x^-1)G */
	G = &(in_priv->params->ec_gen);
	nn_modinv(&xinv, &(in_priv->x), &(in_priv->params->ec_gen_order));
	/* Use blinding with scalar_b when computing point scalar multiplication */
	if(prj_pt_mul_monty_blind(&(out_pub->y), &xinv, G)){
		goto err;
	}
	nn_uninit(&xinv);

	out_pub->key_type = ECGDSA;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	return 0;
err:
	return -1;
}

u8 ecgdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)ECGDSA_SIGLEN(q_bit_len);
}

/*
 * Generic *internal* EC-GDSA signature functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * its output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-GDSA signature process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - EC-GDSA signature
 *|
 *|  UF 1. Compute h = H(m). If |h| > bitlen(q), set h to bitlen(q)
 *|	   leftmost (most significant) bits of h
 *|   F 2. Compute e = - OS2I(h) mod q
 *|   F 3. Get a random value k in ]0,q[
 *|   F 4. Compute W = (W_x,W_y) = kG
 *|   F 5. Compute r = W_x mod q
 *|   F 6. If r is 0, restart the process at step 4.
 *|   F 7. Compute s = x(kr + e) mod q
 *|   F 8. If s is 0, restart the process at step 4.
 *|   F 9. Return (r,s)
 *
 * Implementation notes:
 *
 * a) Usually (this is for instance the case in ISO 14888-3 and X9.62), the
 *    process starts with steps 4 to 7 and is followed by steps 1 to 3.
 *    The order is modified here w/o impact on the result and the security
 *    in order to allow the algorithm to be compatible with an
 *    init/update/finish API. More explicitly, the generation of k, which
 *    may later result in a (unlikely) restart of the whole process is
 *    postponed until the hash of the message has been computed.
 * b) sig is built as the concatenation of r and s. Both r and s are
 *    encoded on ceil(bitlen(q)/8) bytes.
 * c) in EC-GDSA, the public part of the key is not needed per se during the
 *    signature but - as it is needed in other signature algs implemented
 *    in the library - the whole key pair is passed instead of just the
 *    private key.
 */

#define ECGDSA_SIGN_MAGIC ((word_t)(0xe2f60ea3353ecc9eULL))
#define ECGDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECGDSA_SIGN_MAGIC))

int _ecgdsa_sign_init(struct ec_sign_context *ctx)
{
	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, ECGDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		return -1;
	}

	/*
	 * Initialize hash context stored in our private part of context
	 * and record data init has been done
	 */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_init(&(ctx->sign_data.ecgdsa.h_ctx));
	ctx->sign_data.ecgdsa.magic = ECGDSA_SIGN_MAGIC;

	return 0;
}

int _ecgdsa_sign_update(struct ec_sign_context *ctx,
			const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-GDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECGDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecgdsa));

	/* 1. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecgdsa.h_ctx), chunk, chunklen);

	return 0;
}

int _ecgdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	nn_src_t q, x;
	nn tmp, tmp2, s, e, kr, k, r;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif
	u8 e_buf[MAX_DIGEST_SIZE];
	const ec_priv_key *priv_key;
	prj_pt_src_t G;
	u8 hsize, r_len, s_len, p_len;
	u16 p_len_;
	bitcnt_t q_bit_len, p_bit_len, rshift;
	prj_pt kG;
	aff_pt W;
	int ret;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-GDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECGDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecgdsa));

	/* Zero init points */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	x = &(priv_key->x);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	p_bit_len = priv_key->params->ec_fp.p_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECGDSA_R_LEN(q_bit_len);
	s_len = (u8)ECGDSA_S_LEN(q_bit_len);
	hsize = ctx->h->digest_size;

	/* Sanity check */
	if(nn_cmp(x, q) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		ret = -1;
		goto err;
	}

	if (siglen != ECGDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

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

	/* 1. Compute h = H(m) */
	local_memset(e_buf, 0, hsize);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->sign_data.ecgdsa.h_ctx), e_buf);
	dbg_buf_print("H(m)", e_buf, hsize);

	/*
	 * If |h| > bitlen(q), set h to bitlen(q)
	 * leftmost bits of h.
	 *
	 */
	rshift = 0;
	if ((hsize * 8) > q_bit_len) {
		rshift = (hsize * 8) - q_bit_len;
	}
	nn_init_from_buf(&tmp, e_buf, hsize);
	local_memset(e_buf, 0, hsize);
	if (rshift) {
		nn_rshift_fixedlen(&tmp, &tmp, rshift);
	}
	dbg_nn_print("H(m) truncated as nn", &tmp);

	/*
	 * 2. Convert h to an integer and then compute e = -h mod q,
	 *    i.e. compute e = - OS2I(h) mod q
	 *
	 * Because we only support positive integers, we compute
	 * e = q - (h mod q) (except when h is 0).
	 */
	nn_mod(&tmp2, &tmp, q);
	if (nn_iszero(&tmp2)) {
		nn_init(&e, 0);
		nn_zero(&e);
	} else {
		nn_sub(&e, q, &tmp2);
	}

 restart:
	/* 3. Get a random value k in ]0,q[ */
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
		nn_uninit(&tmp2);
		nn_uninit(&tmp);
		nn_uninit(&e);
		ret = -1;
		goto err;
	}

#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, e and e are multiplied by
	 * a random value b in ]0,q[ */
	ret = nn_get_random_mod(&b, q);
	if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&tmp);
		nn_uninit(&e);
		ret = -1;
		goto err;
	}
	dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */


	/* 4. Compute W = kG = (Wx, Wy) */
#ifdef USE_SIG_BLINDING
	/* We use blinding for the scalar multiplication */
	if(prj_pt_mul_monty_blind(&kG, &k, G)){
		ret = -1;
		goto err;
	}
#else
	prj_pt_mul_monty(&kG, &k, G);
#endif /* USE_SIG_BLINDING */
	prj_pt_to_aff(&W, &kG);
	prj_pt_uninit(&kG);

	dbg_nn_print("W_x", &(W.x.fp_val));
	dbg_nn_print("W_y", &(W.y.fp_val));

	/* 5. Compute r = Wx mod q */
	nn_mod(&r, &(W.x.fp_val), q);
	aff_pt_uninit(&W);
	dbg_nn_print("r", &r);

	/* 6. If r is 0, restart the process at step 4. */
	if (nn_iszero(&r)) {
		goto restart;
	}

	/* Export r */
	nn_export_to_buf(sig, r_len, &r);

#ifdef USE_SIG_BLINDING
	/* Blind e and r with b */
	nn_mul_mod(&e, &e, &b, q);
	nn_mul_mod(&r, &r, &b, q);
#endif /* USE_SIG_BLINDING */
	/* 7. Compute s = x(kr + e) mod q */
	nn_mul_mod(&kr, &k, &r, q);
	nn_uninit(&k);
	nn_mod_add(&tmp2, &kr, &e, q);
	nn_uninit(&kr);
	nn_uninit(&e);
	nn_uninit(&tmp);
	nn_mul_mod(&s, x, &tmp2, q);
	nn_uninit(&tmp2);
#ifdef USE_SIG_BLINDING
	/* Unblind s */
	nn_modinv(&binv, &b, q);
	nn_mul_mod(&s, &s, &binv, q);
#endif
	dbg_nn_print("s", &s);

	/* 8. If s is 0, restart the process at step 4. */
	if (nn_iszero(&s)) {
		goto restart;
	}

	/* 9. Return (r,s) */
	nn_export_to_buf(sig + r_len, s_len, &s);

	nn_uninit(&r);
	nn_uninit(&s);

	ret = 0;

 err:

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecgdsa), 0, sizeof(ecgdsa_sign_data));

	/* Clean what remains on the stack */
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(p_bit_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(hsize);
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(G);

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
 * Generic *internal* EC-GDSA verification functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * their output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-GDSA verification process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - EC-GDSA verification
 *|
 *| I	1. Reject the signature if r or s is 0.
 *|  UF 2. Compute h = H(m). If |h| > bitlen(q), set h to bitlen(q)
 *|	   leftmost (most significant) bits of h
 *|   F 3. Compute e = OS2I(h) mod q
 *|   F 4. Compute u = ((r^-1)e mod q)
 *|   F 5. Compute v = ((r^-1)s mod q)
 *|   F 6. Compute W' = uG + vY
 *|   F 7. Compute r' = W'_x mod q
 *|   F 8. Accept the signature if and only if r equals r'
 *
 */

#define ECGDSA_VERIFY_MAGIC ((word_t)(0xd4da37527288d1b6ULL))
#define ECGDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECGDSA_VERIFY_MAGIC))

int _ecgdsa_verify_init(struct ec_verify_context *ctx,
			const u8 *sig, u8 siglen)
{
	u8 r_len, s_len;
	bitcnt_t q_bit_len;
	nn_src_t q;
	nn *s, *r;
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, ECGDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	q = &(ctx->pub_key->params->ec_gen_order);
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	r = &(ctx->verify_data.ecgdsa.r);
	s = &(ctx->verify_data.ecgdsa.s);
	r_len = (u8)ECGDSA_R_LEN(q_bit_len);
	s_len = (u8)ECGDSA_S_LEN(q_bit_len);

	/* Check given signature length is the expected one */
	if (siglen != ECGDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* 1. Reject the signature if r or s is 0. */

	/* Let's first import r, the x coordinates of the point reduced mod q */
	nn_init_from_buf(r, sig, r_len);

	/* Import s as a nn */
	nn_init_from_buf(s, sig + r_len, s_len);

	/* Check that r and s are both in ]0,q[ */
	if (nn_iszero(s) || (nn_cmp(s, q) >= 0) ||
	    nn_iszero(r) || (nn_cmp(r, q) >= 0)) {
		nn_uninit(r);
		nn_uninit(s);
		ret = -1;
		goto err;
	}

	/* Initialize the remaining of verify context */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->verify_data.ecgdsa.h_ctx));
	ctx->verify_data.ecgdsa.magic = ECGDSA_VERIFY_MAGIC;

	ret = 0;

 err:
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	PTR_NULLIFY(q);
	PTR_NULLIFY(s);
	PTR_NULLIFY(r);

	return ret;
}

int _ecgdsa_verify_update(struct ec_verify_context *ctx,
			  const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-GDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECGDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecgdsa));

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecgdsa.h_ctx), chunk,
			     chunklen);

	return 0;
}

int _ecgdsa_verify_finalize(struct ec_verify_context *ctx)
{
	nn tmp, e, r_prime, rinv, u, v, *r, *s;
	prj_pt uG, vY, Wprime;
	aff_pt Wprime_aff;
	prj_pt_src_t G, Y;
	u8 e_buf[MAX_DIGEST_SIZE];
	nn_src_t q;
	u8 hsize;
	bitcnt_t q_bit_len, rshift;
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-GDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECGDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecgdsa));

	/* Zero init points */
	local_memset(&uG, 0, sizeof(prj_pt));
	local_memset(&vY, 0, sizeof(prj_pt));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	Y = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	r = &(ctx->verify_data.ecgdsa.r);
	s = &(ctx->verify_data.ecgdsa.s);
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	hsize = ctx->h->digest_size;

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->verify_data.ecgdsa.h_ctx), e_buf);
	dbg_buf_print("H(m)", e_buf, hsize);

	/*
	 * If |h| > bitlen(q), set h to bitlen(q)
	 * leftmost bits of h.
	 *
	 */
	rshift = 0;
	if ((hsize * 8) > q_bit_len) {
		rshift = (hsize * 8) - q_bit_len;
	}
	nn_init_from_buf(&tmp, e_buf, hsize);
	local_memset(e_buf, 0, hsize);
	if (rshift) {
		nn_rshift_fixedlen(&tmp, &tmp, rshift);
	}
	dbg_nn_print("H(m) truncated as nn", &tmp);

	/* 3. Compute e by converting h to an integer and reducing it mod q */
	nn_mod(&e, &tmp, q);

	/* 4. Compute u = (r^-1)e mod q */
	nn_modinv(&rinv, r, q);	/* r^-1 */
	nn_mul(&tmp, &rinv, &e);	/* r^-1 * e */
	nn_mod(&u, &tmp, q);	/* (r^-1 * e) mod q */
	nn_uninit(&e);

	/* 5. Compute v = (r^-1)s mod q */
	nn_mul(&tmp, &rinv, s);	/*  r^-1 * s */
	nn_mod(&v, &tmp, q);	/* (r^-1 * s) mod q */
	nn_uninit(&tmp);
	nn_uninit(&rinv);

	/* 6. Compute W' = uG + vY */
	prj_pt_mul_monty(&uG, &u, G);
	prj_pt_mul_monty(&vY, &v, Y);
	prj_pt_add_monty(&Wprime, &uG, &vY);
	nn_uninit(&u);
	nn_uninit(&v);
	prj_pt_uninit(&uG);
	prj_pt_uninit(&vY);

	/* 7. Compute r' = W'_x mod q */
	prj_pt_to_aff(&Wprime_aff, &Wprime);
	prj_pt_uninit(&Wprime);
	dbg_nn_print("W'_x", &(Wprime_aff.x.fp_val));
	dbg_nn_print("W'_y", &(Wprime_aff.y.fp_val));
	nn_mod(&r_prime, &(Wprime_aff.x.fp_val), q);
	aff_pt_uninit(&Wprime_aff);

	/* 8. Accept the signature if and only if r equals r' */
	ret = (nn_cmp(r, &r_prime) != 0) ? -1 : 0;
	nn_uninit(&r_prime);

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecgdsa), 0,
		     sizeof(ecgdsa_verify_data));

	PTR_NULLIFY(r);
	PTR_NULLIFY(s);
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(q);
	VAR_ZEROIFY(hsize);

err:
	return ret;
}

#else /* WITH_SIG_ECGDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECGDSA */
