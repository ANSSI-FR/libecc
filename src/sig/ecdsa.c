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
#ifdef WITH_SIG_ECDSA

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#include "../utils/utils.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECDSA"
#endif
#include "../utils/dbg_sig.h"

void ecdsa_init_pub_key(ec_pub_key *out_pub, ec_priv_key *in_priv)
{
	prj_pt_src_t G;
        /* Blinding mask for scalar multiplication */
        nn scalar_b;
        int ret;

	MUST_HAVE(out_pub != NULL);

	priv_key_check_initialized_and_type(in_priv, ECDSA);
        /* We use blinding for the scalar multiplication */
        ret = nn_get_random_mod(&scalar_b, &(in_priv->params->ec_gen_order));
        if (ret) {
                goto err;
        }

	/* Y = xG */
	G = &(in_priv->params->ec_gen);
        /* Use blinding with scalar_b when computing point scalar multiplication */
        if(prj_pt_mul_monty_blind(&(out_pub->y), &(in_priv->x), G, &scalar_b, &(in_priv->params->ec_gen_order))){
		goto err;
	}
	nn_uninit(&scalar_b);

	out_pub->key_type = ECDSA;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

err:
	return;
}

u8 ecdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)ECDSA_SIGLEN(q_bit_len);
}

/*
 * Generic *internal* ECDSA signature functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * its output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-DSA signature process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF  - ECDSA signature
 *|
 *|  UF  1. Compute h = H(m)
 *|   F  2. If |h| > bitlen(q), set h to bitlen(q)
 *|         leftmost (most significant) bits of h
 *|   F  3. e = OS2I(h) mod q
 *|   F  4. Get a random value k in ]0,q[
 *|   F  5. Compute W = (W_x,W_y) = kG
 *|   F  6. Compute r = W_x mod q
 *|   F  7. If r is 0, restart the process at step 4.
 *|   F  8. If e == rx, restart the process at step 4.
 *|   F  9. Compute s = k^-1 * (xr + e) mod q
 *|   F 10. If s is 0, restart the process at step 4.
 *|   F 11. Return (r,s)
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
 * c) in EC-DSA, the public part of the key is not needed per se during the
 *    signature but - as it is needed in other signature algs implemented
 *    in the library - the whole key pair is passed instead of just the
 *    private key.
 */

#define ECDSA_SIGN_MAGIC ((word_t)(0x80299a2bf630945bULL))
#define ECDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == ECDSA_SIGN_MAGIC))

int _ecdsa_sign_init(struct ec_sign_context *ctx)
{
	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, ECDSA);
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
	ctx->h->hfunc_init(&(ctx->sign_data.ecdsa.h_ctx));
	ctx->sign_data.ecdsa.magic = ECDSA_SIGN_MAGIC;

	return 0;
}

int _ecdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecdsa));

	/* 1. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecdsa.h_ctx), chunk, chunklen);

	return 0;
}

int _ecdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	nn k, r, e, tmp, tmp2, s, kinv;
#ifdef USE_SIG_BLINDING
        /* b is the blinding mask */
        nn b;
	/* scalar_b is the scalar multiplication blinder */
	nn scalar_b;
#endif
	const ec_priv_key *priv_key;
	prj_pt_src_t G;
	u8 hash[MAX_DIGEST_SIZE];
	bitcnt_t rshift, q_bit_len;
	prj_pt kG;
	aff_pt W;
	nn_src_t q, x;
	u8 hsize, q_len;
	int ret;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecdsa));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	q = &(priv_key->params->ec_gen_order);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	G = &(priv_key->params->ec_gen);
	q_len = (u8)BYTECEIL(q_bit_len);
	x = &(priv_key->x);
	hsize = ctx->h->digest_size;

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", &(priv_key->params->ec_gen_order));
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", &(priv_key->params->ec_gen));
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));

	/* Check given signature buffer length has the expected size */
	if (siglen != ECDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* 1. Compute h = H(m) */
	local_memset(hash, 0, hsize);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->sign_data.ecdsa.h_ctx), hash);
	dbg_buf_print("h", hash, hsize);

	/*
	 * 2. If |h| > bitlen(q), set h to bitlen(q)
	 *    leftmost bits of h.
	 *
	 * Note that it's easier to check if the truncation has
	 * to be done here but only implement it using a logical
	 * shift at the beginning of step 3. below once the hash
	 * has been converted to an integer.
	 */
	rshift = 0;
	if ((hsize * 8) > q_bit_len) {
		rshift = (hsize * 8) - q_bit_len;
	}

	/*
	 * 3. Compute e = OS2I(h) mod q, i.e. by converting h to an
	 *    integer and reducing it mod q
	 */
	nn_init_from_buf(&tmp2, hash, hsize);
	local_memset(hash, 0, hsize);
	dbg_nn_print("h initial import as nn", &tmp2);
	if (rshift) {
		nn_rshift_fixedlen(&tmp2, &tmp2, rshift);
	}
	dbg_nn_print("h   final import as nn", &tmp2);
	nn_mod(&e, &tmp2, q);
	dbg_nn_print("e", &e);

 restart:
	/* 4. get a random value k in ]0,q[ */
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
	ret = ctx->rand(&k, q);
	if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&e);
		ret = -1;
		goto err;
	}
	dbg_nn_print("k", &k);

#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, r and e are multiplied by
	 * a random value b in ]0,q[ */
        ret = nn_get_random_mod(&b, q);
        if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&e);
		ret = -1;
                goto err;
        }
        dbg_nn_print("b", &b);
        /* We use blinding for the scalar multiplication */
        ret = nn_get_random_mod(&scalar_b, q);
        if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&e);
		ret = -1;
                goto err;
        }
        dbg_nn_print("scalar_b", &scalar_b);
#endif /* USE_SIG_BLINDING */


	/* 5. Compute W = (W_x,W_y) = kG */
#ifdef USE_SIG_BLINDING
	if(prj_pt_mul_monty_blind(&kG, &k, G, &scalar_b, q)){
		ret = -1;
		goto err;
	}
	nn_uninit(&scalar_b);
#else
        prj_pt_mul_monty(&kG, &k, G);
#endif /* USE_SIG_BLINDING */
	prj_pt_to_aff(&W, &kG);
	prj_pt_uninit(&kG);

	dbg_nn_print("W_x", &(W.x.fp_val));
	dbg_nn_print("W_y", &(W.y.fp_val));

	/* 6. Compute r = W_x mod q */
	nn_mod(&r, &(W.x.fp_val), q);
	aff_pt_uninit(&W);
	dbg_nn_print("r", &r);

	/* 7. If r is 0, restart the process at step 4. */
	if (nn_iszero(&r)) {
		goto restart;
	}

	/* Export r */
	nn_export_to_buf(sig, q_len, &r);

#ifdef USE_SIG_BLINDING
	/* Blind r with b */
	nn_mul_mod(&r, &r, &b, q);

	/* Blind the message e */
	nn_mul_mod(&e, &e, &b, q);
#endif /* USE_SIG_BLINDING */

	/* tmp = xr mod q */
	nn_mul_mod(&tmp, x, &r, q);
	dbg_nn_print("x*r mod q", &tmp);

	/* 8. If e == rx, restart the process at step 4. */
	if (!nn_cmp(&e, &tmp)) {
		goto restart;
	}

	/* 9. Compute s = k^-1 * (xr + e) mod q */

	/* tmp2 = (e + xr) mod q */
	nn_mod_add(&tmp2, &tmp, &e, q);
	nn_uninit(&e);
	nn_uninit(&tmp);
	dbg_nn_print("(xr + e) mod q", &tmp2);

#ifdef USE_SIG_BLINDING
	/* In case of blinding, we compute (b*k)^-1, and 
	 * b^-1 will automatically unblind (r*x) in the following
	 */
	nn_mul_mod(&k, &k, &b, q);
#endif
	/* Compute k^-1 mod q */
	nn_modinv(&kinv, &k, q);
	nn_uninit(&k);

	dbg_nn_print("k^-1 mod q", &kinv);

	/* s = k^-1 * tmp2 mod q */
	nn_mul_mod(&s, &tmp2, &kinv, q);
	nn_uninit(&kinv);
	nn_uninit(&tmp2);

	dbg_nn_print("s", &s);

	/* 10. If s is 0, restart the process at step 4. */
	if (nn_iszero(&s)) {
		goto restart;
	}

	/* 11. return (r,s) */
	nn_export_to_buf(sig + q_len, q_len, &s);

	nn_uninit(&r);
	nn_uninit(&s);

 err:

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecdsa), 0, sizeof(ecdsa_sign_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	VAR_ZEROIFY(q_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(rshift);
	VAR_ZEROIFY(hsize);

#ifdef USE_SIG_BLINDING
        nn_zero(&b);
#endif /* USE_SIG_BLINDING */

	return ret;
}

/*
 * Generic *internal* ECDSA verification functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * its output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global ECDSA verification process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF  - ECDSA verification
 *|
 *| I    1. Reject the signature if r or s is 0.
 *|  UF  2. Compute h = H(m)
 *|   F  3. If |h| > bitlen(q), set h to bitlen(q)
 *|         leftmost (most significant) bits of h
 *|   F  4. Compute e = OS2I(h) mod q
 *|   F  5. Compute u = (s^-1)e mod q
 *|   F  6. Compute v = (s^-1)r mod q
 *|   F  7. Compute W' = uG + vY
 *|   F  8. If W' is the point at infinity, reject the signature.
 *|   F  9. Compute r' = W'_x mod q
 *|   F 10. Accept the signature if and only if r equals r'
 *
 */

#define ECDSA_VERIFY_MAGIC ((word_t)(0x5155fe73e7fd51beULL))
#define ECDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == ECDSA_VERIFY_MAGIC))

int _ecdsa_verify_init(struct ec_verify_context *ctx, const u8 *sig, u8 siglen)
{
	bitcnt_t q_bit_len;
	u8 q_len;
	nn_src_t q;
	nn *r, *s;
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, ECDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	q = &(ctx->pub_key->params->ec_gen_order);
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	q_len = (u8)BYTECEIL(q_bit_len);
	r = &(ctx->verify_data.ecdsa.r);
	s = &(ctx->verify_data.ecdsa.s);

	/* Check given signature length is the expected one */
	if (siglen != ECDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* Import r and s values from signature buffer */
	nn_init_from_buf(r, sig, q_len);
	nn_init_from_buf(s, sig + q_len, q_len);
	dbg_nn_print("r", r);
	dbg_nn_print("s", s);

	/* 1. Reject the signature if r or s is 0. */
	if (nn_iszero(r) || (nn_cmp(r, q) >= 0) ||
	    nn_iszero(s) || (nn_cmp(s, q) >= 0)) {
		nn_uninit(r);
		nn_uninit(s);
		ret = -1;
		goto err;
	}

	/* Initialize the remaining of verify context. */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->verify_data.ecdsa.h_ctx));
	ctx->verify_data.ecdsa.magic = ECDSA_VERIFY_MAGIC;

	ret = 0;

 err:
	VAR_ZEROIFY(q_len);
	VAR_ZEROIFY(q_bit_len);
	PTR_NULLIFY(q);
	PTR_NULLIFY(r);
	PTR_NULLIFY(s);

	return ret;
}

int _ecdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecdsa));

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecdsa.h_ctx), chunk, chunklen);
	return 0;
}

int _ecdsa_verify_finalize(struct ec_verify_context *ctx)
{
	prj_pt uG, vY, W_prime;
	nn e, tmp, sinv, u, v, r_prime;
	aff_pt W_prime_aff;
	prj_pt_src_t G, Y;
	u8 hash[MAX_DIGEST_SIZE];
	bitcnt_t rshift, q_bit_len;
	nn_src_t q;
	nn *s, *r;
	u8 hsize;
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecdsa));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	Y = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	hsize = ctx->h->digest_size;
	r = &(ctx->verify_data.ecdsa.r);
	s = &(ctx->verify_data.ecdsa.s);

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->verify_data.ecdsa.h_ctx), hash);
	dbg_buf_print("h = H(m)", hash, hsize);

	/*
	 * 3. If |h| > bitlen(q), set h to bitlen(q)
	 *    leftmost bits of h.
	 *
	 * Note that it's easier to check here if the truncation
	 * needs to be done but implement it using a logical
	 * shift at the beginning of step 3. below once the hash
	 * has been converted to an integer.
	 */
	rshift = 0;
	if ((hsize * 8) > q_bit_len) {
		rshift = (hsize * 8) - q_bit_len;
	}

	/*
	 * 4. Compute e = OS2I(h) mod q, by converting h to an integer
	 * and reducing it mod q
	 */
	nn_init_from_buf(&tmp, hash, hsize);
	local_memset(hash, 0, hsize);
	dbg_nn_print("h initial import as nn", &tmp);
	if (rshift) {
		nn_rshift_fixedlen(&tmp, &tmp, rshift);
	}
	dbg_nn_print("h   final import as nn", &tmp);

	nn_mod(&e, &tmp, q);
	nn_uninit(&tmp);
	dbg_nn_print("e", &e);

	/* Compute s^-1 mod q */
	nn_modinv(&sinv, s, q);
	dbg_nn_print("s", s);
	dbg_nn_print("sinv", &sinv);
	nn_uninit(s);

	/* 5. Compute u = (s^-1)e mod q */
	nn_mul(&tmp, &e, &sinv);
	nn_uninit(&e);
	nn_mod(&u, &tmp, q);
	dbg_nn_print("u = (s^-1)e mod q", &u);

	/* 6. Compute v = (s^-1)r mod q */
	nn_mul_mod(&v, r, &sinv, q);
	dbg_nn_print("v = (s^-1)r mod q", &v);
	nn_uninit(&sinv);
	nn_uninit(&tmp);

	/* 7. Compute W' = uG + vY */
	prj_pt_mul_monty(&uG, &u, G);
	prj_pt_mul_monty(&vY, &v, Y);
	prj_pt_add_monty(&W_prime, &uG, &vY);
	prj_pt_uninit(&uG);
	prj_pt_uninit(&vY);
	nn_uninit(&u);
	nn_uninit(&v);

	/* 8. If W' is the point at infinity, reject the signature. */
	if (prj_pt_iszero(&W_prime)) {
		ret = -1;
		goto err;
	}

	/* 9. Compute r' = W'_x mod q */
	prj_pt_to_aff(&W_prime_aff, &W_prime);
	dbg_nn_print("W'_x", &(W_prime_aff.x.fp_val));
	dbg_nn_print("W'_y", &(W_prime_aff.y.fp_val));
	nn_mod(&r_prime, &(W_prime_aff.x.fp_val), q);
	prj_pt_uninit(&W_prime);
	aff_pt_uninit(&W_prime_aff);

	/* 10. Accept the signature if and only if r equals r' */
	ret = (nn_cmp(&r_prime, r) != 0) ? -1 : 0;
	nn_uninit(&r_prime);

 err:
	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecdsa), 0, sizeof(ecdsa_verify_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	VAR_ZEROIFY(rshift);
	VAR_ZEROIFY(q_bit_len);
	PTR_NULLIFY(q);
	PTR_NULLIFY(s);
	PTR_NULLIFY(r);
	VAR_ZEROIFY(hsize);

	return ret;
}

#else /* WITH_SIG_ECDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECDSA */
