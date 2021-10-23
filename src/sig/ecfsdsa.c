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
	int ret, cmp;
	prj_pt_src_t G;
	nn_src_t q;

	MUST_HAVE((out_pub != NULL), ret, err);

	/* Zero init public key to be generated */
	ret = local_memset(out_pub, 0, sizeof(ec_pub_key)); EG(ret, err);

	ret = priv_key_check_initialized_and_type(in_priv, ECFSDSA); EG(ret, err);
	q = &(in_priv->params->ec_gen_order);

	/* Sanity check on key compliance */
	MUST_HAVE(!nn_cmp(&(in_priv->x), q, &cmp) && (cmp < 0), ret, err);

	/* Y = xG */
	G = &(in_priv->params->ec_gen);
	/* Use blinding when computing point scalar multiplication */
	ret = prj_pt_mul_blind(&(out_pub->y), &(in_priv->x), G); EG(ret, err);

	out_pub->key_type = ECFSDSA;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

err:
	return ret;
}

int ecfsdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize, u8 *siglen)
{
	int ret;

	MUST_HAVE((siglen != NULL), ret, err);
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE), ret, err);
	(*siglen) = (u8)ECFSDSA_SIGLEN(p_bit_len, q_bit_len);
	ret = 0;

err:
	return ret;
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
#define ECFSDSA_SIGN_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && \
		  ((A)->magic == ECFSDSA_SIGN_MAGIC), ret, err)

int _ecfsdsa_sign_init(struct ec_sign_context *ctx)
{
	prj_pt_src_t G;
	nn_src_t q;
	nn *k;
	u8 *r;
	prj_pt kG;
	const ec_priv_key *priv_key;
	bitcnt_t p_bit_len;
	u8 i, p_len, r_len;
	int ret;
	kG.magic = WORD(0);

	/* First, verify context has been initialized */
	ret = sig_sign_check_initialized(ctx); EG(ret, err);

	/* Zero init points */
	ret = local_memset(&kG, 0, sizeof(prj_pt)); EG(ret, err);

	/* Additional sanity checks on input params from context */
	ret = key_pair_check_initialized_and_type(ctx->key_pair, ECFSDSA); EG(ret, err);
	MUST_HAVE((ctx->h != NULL) && (ctx->h->digest_size <= MAX_DIGEST_SIZE) &&
		  (ctx->h->block_size <= MAX_BLOCK_SIZE), ret, err);

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	r = ctx->sign_data.ecfsdsa.r;
	k = &(ctx->sign_data.ecfsdsa.k);
	p_bit_len = priv_key->params->ec_fp.p_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECFSDSA_R_LEN(p_bit_len);

	MUST_HAVE(((u32)p_len <= NN_MAX_BYTE_LEN), ret, err);

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
	MUST_HAVE((ctx->rand == nn_get_random_mod), ret, err);
#endif
	MUST_HAVE((ctx->rand != NULL), ret, err);
	ret = ctx->rand(k, q); EG(ret, err);

	/*  2. Compute W = (W_x,W_y) = kG */
#ifdef USE_SIG_BLINDING
	/* We use blinding for the scalar multiplication */
	ret = prj_pt_mul_blind(&kG, k, G); EG(ret, err);
#else
	ret = prj_pt_mul(&kG, k, G); EG(ret, err);
#endif
	ret = prj_pt_unique(&kG, &kG); EG(ret, err);

	dbg_nn_print("Wx", &(kG.X.fp_val));
	dbg_nn_print("Wy", &(kG.Y.fp_val));

	/*  3. Compute r = FE2OS(W_x)||FE2OS(W_y) */
	ret = fp_export_to_buf(r, p_len, &(kG.X)); EG(ret, err);
	ret = fp_export_to_buf(r + p_len, p_len, &(kG.Y)); EG(ret, err);
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
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_init(&(ctx->sign_data.ecfsdsa.h_ctx)); EG(ret, err);
	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_update(&(ctx->sign_data.ecfsdsa.h_ctx), r, r_len); EG(ret, err);

	ctx->sign_data.ecfsdsa.magic = ECFSDSA_SIGN_MAGIC;

 err:
	prj_pt_uninit(&kG);

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
	int ret;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECFSDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	ret = sig_sign_check_initialized(ctx); EG(ret, err);
	ECFSDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecfsdsa), ret, err);

	/*  5. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_update(&(ctx->sign_data.ecfsdsa.h_ctx), chunk, chunklen); EG(ret, err);

err:
	return ret;
}

int _ecfsdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	nn_src_t q, x;
	nn s, e, ex, *k;
	const ec_priv_key *priv_key;
	u8 e_buf[MAX_DIGEST_SIZE];
	bitcnt_t p_bit_len, q_bit_len;
	u8 hsize, s_len, r_len;
	int ret, iszero, cmp;
	u8 *r;

#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
	b.magic = binv.magic = WORD(0);
#endif /* USE_SIG_BLINDING */

	s.magic = e.magic = ex.magic = WORD(0);

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECFSDSA
	 * signature one and we do not finalize() before init().
	 */
	ret = sig_sign_check_initialized(ctx); EG(ret, err);
	ECFSDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecfsdsa), ret, err);
	MUST_HAVE((sig != NULL), ret, err);

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
	ret = nn_cmp(x, q, &cmp); EG(ret, err);
	/* This should not happen and means that our
	 * private key is not compliant!
	 */
	MUST_HAVE((cmp < 0), ret, err);

	MUST_HAVE((siglen == ECFSDSA_SIGLEN(p_bit_len, q_bit_len)), ret, err);

#ifdef USE_SIG_BLINDING
	ret = nn_get_random_mod(&b, q); EG(ret, err);
	dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */

	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	/*  5. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_finalize(&(ctx->sign_data.ecfsdsa.h_ctx), e_buf); EG(ret, err);
	dbg_buf_print("h(R||m)", e_buf, hsize);

	/*  6. Compute e by converting h to an integer and reducing it mod q */
	ret = nn_init_from_buf(&e, e_buf, hsize); EG(ret, err);
	ret = local_memset(e_buf, 0, hsize); EG(ret, err);
	ret = nn_mod(&e, &e, q); EG(ret, err);

#ifdef USE_SIG_BLINDING
	/* Blind e with b */
	ret = nn_mul_mod(&e, &e, &b, q); EG(ret, err);
#endif /* USE_SIG_BLINDING */
	/*  7. Compute s = (k + ex) mod q */
	ret = nn_mul_mod(&ex, &e, x, q); EG(ret, err);
#ifdef USE_SIG_BLINDING
	/* Blind k with b */
	ret = nn_mul_mod(&s, k, &b, q); EG(ret, err);
	ret = nn_mod_add(&s, &s, &ex, q); EG(ret, err);
#else
	ret = nn_mod_add(&s, k, &ex, q); EG(ret, err);
#endif /* USE_SIG_BLINDING */
#ifdef USE_SIG_BLINDING
	/* Unblind s */
        /* NOTE: we use Fermat little theorem inversion for
         * constant time here.
         */
	ret = nn_modinv_fermat(&binv, &b, q); EG(ret, err);
	ret = nn_mul_mod(&s, &s, &binv, q); EG(ret, err);
#endif /* USE_SIG_BLINDING */
	dbg_nn_print("s: ", &s);

	/*
	 * 8. If s is 0, restart the process at step 1.
	 *
	 * In practice, as we cannot restart the whole process in
	 * finalize() we just report an error.
	 */
	MUST_HAVE((!nn_iszero(&s, &iszero)) && (!iszero), ret, err);

	/*  9. Return (r,s) */
	ret = local_memcpy(sig, r, r_len); EG(ret, err);
	ret = local_memset(r, 0, r_len); EG(ret, err);
	ret = nn_export_to_buf(sig + r_len, s_len, &s);

 err:
	nn_uninit(&s);
	nn_uninit(&e);
	nn_uninit(&ex);
#ifdef USE_SIG_BLINDING
	nn_uninit(&b);
	nn_uninit(&binv);
#endif

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	if(ctx != NULL){
		IGNORE_RET_VAL(local_memset(&(ctx->sign_data.ecfsdsa), 0, sizeof(ecfsdsa_sign_data)));
	}

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
#define ECFSDSA_VERIFY_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && \
		  ((A)->magic == ECFSDSA_VERIFY_MAGIC), ret, err)

int _ecfsdsa_verify_init(struct ec_verify_context *ctx,
			 const u8 *sig, u8 siglen)
{
	bitcnt_t p_bit_len, q_bit_len;
	u8 p_len, r_len, s_len;
	int ret, iszero, on_curve, cmp;
	const u8 *r;
	nn_src_t q;
	fp rx, ry;
	nn *s;

	rx.magic = ry.magic = WORD(0);

	/* First, verify context has been initialized */
	ret = sig_verify_check_initialized(ctx); EG(ret, err);

	/* Do some sanity checks on input params */
	ret = pub_key_check_initialized_and_type(ctx->pub_key, ECFSDSA); EG(ret, err);
	MUST_HAVE((ctx->h != NULL) && (ctx->h->digest_size <= MAX_DIGEST_SIZE) &&
		(ctx->h->block_size <= MAX_BLOCK_SIZE), ret, err);
	MUST_HAVE((sig != NULL), ret, err);

	/* Make things more readable */
	q = &(ctx->pub_key->params->ec_gen_order);
	p_bit_len = ctx->pub_key->params->ec_fp.p_bitlen;
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECFSDSA_R_LEN(p_bit_len);
	s_len = (u8)ECFSDSA_S_LEN(q_bit_len);
	s = &(ctx->verify_data.ecfsdsa.s);

	MUST_HAVE((siglen == ECFSDSA_SIGLEN(p_bit_len, q_bit_len)), ret, err);

	/*  1. Reject the signature if r is not a valid point on the curve. */

	/* Let's first import r, i.e. x and y coordinates of the point */
	r = sig;
	ret = fp_init(&rx, ctx->pub_key->params->ec_curve.a.ctx); EG(ret, err);
	ret = fp_import_from_buf(&rx, r, p_len); EG(ret, err);
	ret = fp_init(&ry, ctx->pub_key->params->ec_curve.a.ctx); EG(ret, err);
	ret = fp_import_from_buf(&ry, r + p_len, p_len); EG(ret, err);

	/* Let's now check that r represents a point on the curve */
	ret = is_on_shortw_curve(&rx, &ry, &(ctx->pub_key->params->ec_curve), &on_curve); EG(ret, err);
	MUST_HAVE(on_curve, ret, err);

	/* 2. Reject the signature if s is not in ]0,q[ */

	/* Import s as a nn */
	ret = nn_init_from_buf(s, sig + r_len, s_len); EG(ret, err);

	/* Check that s is in ]0,q[ */
	ret = nn_iszero(s, &iszero); EG(ret, err);
	ret = nn_cmp(s, q, &cmp); EG(ret, err);
	MUST_HAVE((!iszero) && (cmp < 0), ret, err);

	/* 3. Compute h = H(r||m) */

	/* Initialize the verify context */
	ret = local_memcpy(&(ctx->verify_data.ecfsdsa.r), r, r_len); EG(ret, err);
	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_init(&(ctx->verify_data.ecfsdsa.h_ctx)); EG(ret, err);

	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_update(&(ctx->verify_data.ecfsdsa.h_ctx), r, r_len); EG(ret, err);

	ctx->verify_data.ecfsdsa.magic = ECFSDSA_VERIFY_MAGIC;

 err:
	fp_uninit(&rx);
	fp_uninit(&ry);

	if (ret && (ctx != NULL)) {
		/*
		 * Signature is invalid. Clear data part of the context.
		 * This will clear magic and avoid further reuse of the
		 * whole context.
		 */
		IGNORE_RET_VAL(local_memset(&(ctx->verify_data.ecfsdsa), 0,
			     sizeof(ecfsdsa_verify_data)));
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
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECFSDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	ret = sig_verify_check_initialized(ctx); EG(ret, err);
	ECFSDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecfsdsa), ret, err);

	/* 3. Compute h = H(r||m) */
	/* Since we call a callback, sanity check our mapping */
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_update(&(ctx->verify_data.ecfsdsa.h_ctx), chunk,
			     chunklen);

err:
	return ret;
}

int _ecfsdsa_verify_finalize(struct ec_verify_context *ctx)
{
	prj_pt_src_t G, Y;
	nn_src_t q;
	nn tmp, e, *s;
	prj_pt sG, eY;
	prj_pt_t Wprime;
	bitcnt_t p_bit_len, r_len;
	u8 r_prime[2 * NN_MAX_BYTE_LEN];
	u8 e_buf[MAX_DIGEST_SIZE];
	u8 hsize, p_len;
	const u8 *r;
	int ret, iszero, check;

	tmp.magic = e.magic = WORD(0);
	sG.magic = eY.magic = WORD(0);

	/* NOTE: we reuse sG for Wprime to optimize local variables */
	Wprime = &sG;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECFSDSA
	 * verification one and we do not finalize() before init().
	 */
	ret = sig_verify_check_initialized(ctx); EG(ret, err);
	ECFSDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecfsdsa), ret, err);

	/* Zero init points */
	ret = local_memset(&sG, 0, sizeof(prj_pt)); EG(ret, err);
	ret = local_memset(&eY, 0, sizeof(prj_pt)); EG(ret, err);

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
	ret = hash_mapping_callbacks_sanity_check(ctx->h); EG(ret, err);
	ret = ctx->h->hfunc_finalize(&(ctx->verify_data.ecfsdsa.h_ctx), e_buf); EG(ret, err);

	/*
	 * 4. Convert h to an integer and then compute e = -h mod q
	 *
	 * Because we only support positive integers, we compute
	 * e = q - (h mod q) (except when h is 0).
	 */
	ret = nn_init_from_buf(&tmp, e_buf, hsize); EG(ret, err);
	ret = local_memset(e_buf, 0, hsize); EG(ret, err);
	ret = nn_mod(&tmp, &tmp, q); EG(ret, err);

	ret = nn_iszero(&tmp, &iszero); EG(ret, err);
	if (iszero) {
		ret = nn_zero(&e); EG(ret, err);
	} else {
		ret = nn_sub(&e, q, &tmp); EG(ret, err);
	}

	/* 5. compute W' = (W'_x,W'_y) = sG + tY, where Y is the public key */
	ret = prj_pt_mul(&sG, s, G); EG(ret, err);
	ret = prj_pt_mul(&eY, &e, Y); EG(ret, err);
	ret = prj_pt_add(Wprime, &sG, &eY); EG(ret, err);
	ret = prj_pt_unique(Wprime, Wprime); EG(ret, err);

	/* 6. Compute r' = FE2OS(W'_x)||FE2OS(W'_y) */
	ret = fp_export_to_buf(r_prime, p_len, &(Wprime->X)); EG(ret, err);
	ret = fp_export_to_buf(r_prime + p_len, p_len, &(Wprime->Y)); EG(ret, err);

	dbg_buf_print("r_prime: ", r_prime, r_len);

	/* 7. Accept the signature if and only if r equals r' */
	ret = are_equal(r, r_prime, r_len, &check); EG(ret, err);
	ret = check ? 0 : -1;

err:
	IGNORE_RET_VAL(local_memset(r_prime, 0, sizeof(r_prime)));

	nn_uninit(&tmp);
	nn_uninit(&e);
	prj_pt_uninit(&sG);
	prj_pt_uninit(&eY);

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	if(ctx != NULL){
		IGNORE_RET_VAL(local_memset(&(ctx->verify_data.ecfsdsa), 0,
			     sizeof(ecfsdsa_verify_data)));
	}

	/* Clean what remains on the stack */
	PTR_NULLIFY(Wprime);
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(q);
	PTR_NULLIFY(s);
	PTR_NULLIFY(r);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(hsize);

	return ret;
}

#else /* WITH_SIG_ECFSDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECFSDSA */
