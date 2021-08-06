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
#ifdef WITH_SIG_ECRDSA

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECRDSA"
#endif
#include "../utils/dbg_sig.h"


/*
 * NOTE: ISO/IEC 14888-3 standard seems to diverge from the existing implementations
 * of ECRDSA when treating the message hash, and from the examples of certificates provided
 * in RFC 7091 and draft-deremin-rfc4491-bis. While in ISO/IEC 14888-3 it is explicitely asked
 * to proceed with the hash of the message as big endian, the RFCs derived from the Russian
 * standard expect the hash value to be treated as little endian when importing it as an integer
 * (this discrepancy is exhibited and confirmed by test vectors present in ISO/IEC 14888-3, and
 * by X.509 certificates present in the RFCs). This seems (to be confirmed) to be a discrepancy of
 * ISO/IEC 14888-3 algorithm description that must be fixed there.
 *
 * In order to be conservative, libecc uses the Russian standard behavior as expected to be in line with
 * other implemetations, but keeps the ISO/IEC 14888-3 behavior if forced/asked by the user using
 * the USE_ISO14888_3_ECRDSA toggle. This allows to keep backward compatibility with previous versions of the
 * library if needed.
 *
 */
#ifndef USE_ISO14888_3_ECRDSA
/* Reverses the endiannes of a buffer in place */
static inline int _reverse_endianness(u8 *buf, u16 buf_size)
{
	u32 i;
	u8 tmp;
	int ret = -1;

	if(buf == NULL){
		ret = -1;
		goto err;
	}
	if(buf_size > 1){
		for(i = 0; i < (buf_size / 2); i++){
			tmp = buf[i];
			buf[i] = buf[buf_size - 1 - i];
			buf[buf_size - 1 - i] = tmp;
		}
	}

	ret = 0;
err:
	return ret;
}
#endif

int ecrdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	int ret = -1;
	prj_pt_src_t G;

	MUST_HAVE(out_pub != NULL);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	priv_key_check_initialized_and_type(in_priv, ECRDSA);

	/* Sanity check */
	if(nn_cmp(&(in_priv->x), &(in_priv->params->ec_gen_order)) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		ret = -1;
		goto err;
	}

	/* Y = xG */
	G = &(in_priv->params->ec_gen);
	/* Use blinding when computing point scalar multiplication */
	if(prj_pt_mul_monty_blind(&(out_pub->y), &(in_priv->x), G)){
		ret = -1;
		goto err;
	}

	out_pub->key_type = ECRDSA;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	ret = 0;
err:
	return ret;
}

u8 ecrdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)ECRDSA_SIGLEN(q_bit_len);
}

/*
 * Generic *internal* EC-RDSA signature functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * its output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-RDSA signature process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - EC-RDSA signature
 *|
 *|  UF	 1. Compute h = H(m)
 *|   F	 2. Get a random value k in ]0,q[
 *|   F	 3. Compute W = (W_x,W_y) = kG
 *|   F	 4. Compute r = W_x mod q
 *|   F	 5. If r is 0, restart the process at step 2.
 *|   F	 6. Compute e = OS2I(h) mod q. If e is 0, set e to 1.
 *|         NOTE: here, ISO/IEC 14888-3 and RFCs differ in the way e treated.
 *|         e = OS2I(h) for ISO/IEC 14888-3, or e = OS2I(reversed(h)) when endianness of h
 *|         is reversed for RFCs.
 *|   F	 7. Compute s = (rx + ke) mod q
 *|   F	 8. If s is 0, restart the process at step 2.
 *|   F 11. Return (r,s)
 *
 */

#define ECRDSA_SIGN_MAGIC ((word_t)(0xcc97bbc8ada8973cULL))
#define ECRDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECRDSA_SIGN_MAGIC))

int _ecrdsa_sign_init(struct ec_sign_context *ctx)
{
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, ECRDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/*
	 * Initialize hash context stored in our private part of context
	 * and record data init has been done
	 */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->sign_data.ecrdsa.h_ctx));
	ctx->sign_data.ecrdsa.magic = ECRDSA_SIGN_MAGIC;

	ret = 0;
err:
	return ret;
}

int _ecrdsa_sign_update(struct ec_sign_context *ctx,
			const u8 *chunk, u32 chunklen)
{
	int ret = -1;
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-RDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECRDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecrdsa));

	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecrdsa.h_ctx), chunk, chunklen);

	ret = 0;
err:
	return ret;
}

int _ecrdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	bitcnt_t q_bit_len, p_bit_len;
	const ec_priv_key *priv_key;
	nn tmp, s, rx, ke, k, r, e;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif /* USE_SIG_BLINDING */
	u8 h_buf[MAX_DIGEST_SIZE];
	prj_pt_src_t G;
	prj_pt kG;
	aff_pt W;
	nn_src_t q, x;
	u8 hsize, r_len, s_len;
	int ret = -1;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-RDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECRDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecrdsa));

	/* Zero init points */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	p_bit_len = priv_key->params->ec_fp.p_bitlen;
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	x = &(priv_key->x);
	r_len = (u8)ECRDSA_R_LEN(q_bit_len);
	s_len = (u8)ECRDSA_S_LEN(q_bit_len);
	hsize = ctx->h->digest_size;

	/* Sanity check */
	if(nn_cmp(x, q) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		ret = -1;
		goto err;
	}

	if (NN_MAX_BIT_LEN < p_bit_len) {
		ret = -1;
		goto err;
	}

	if (siglen != ECRDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", q);
	dbg_priv_key_print("x", priv_key);
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));
	dbg_ec_point_print("G", G);

 restart:
	/* 2. Get a random value k in ]0, q[ ... */
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
#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, k and e are multiplied by
	 * a random value b in ]0,q[ */
	ret = nn_get_random_mod(&b, q);
	if (ret) {
		ret = -1;
		goto err;
	}
	dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */

	/* 3. Compute W = kG = (Wx, Wy) */
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

	/* 4. Compute r = Wx mod q */
	nn_mod(&r, &(W.x.fp_val), q);
	aff_pt_uninit(&W);

	/* 5. If r is 0, restart the process at step 2. */
	if (nn_iszero(&r)) {
		goto restart;
	}
	dbg_nn_print("r", &r);

	/* Export r */
	nn_export_to_buf(sig, r_len, &r);

	/* 6. Compute e = OS2I(h) mod q. If e is 0, set e to 1. */
	local_memset(h_buf, 0, hsize);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->sign_data.ecrdsa.h_ctx), h_buf);
	dbg_buf_print("H(m)", h_buf, hsize);
	/* NOTE: this handles a discrepancy between ISO/IEC 14888-3 and
	 * Russian standard based RFCs.
	 */
#ifndef USE_ISO14888_3_ECRDSA
	if(_reverse_endianness(h_buf, hsize)){
		ret = -1;
		goto err;
	}
#endif
	nn_init_from_buf(&tmp, h_buf, hsize);
	local_memset(h_buf, 0, hsize);
	nn_mod(&e, &tmp, q);
	if (nn_iszero(&e)) {
		nn_inc(&e, &e);
	}
	dbg_nn_print("e", &e);

#ifdef USE_SIG_BLINDING
	/* In case of blinding, we blind r and e */
	nn_mul_mod(&r, &r, &b, q);
	nn_mul_mod(&e, &e, &b, q);
#endif /* USE_SIG_BLINDING */

	/* Compute s = (rx + ke) mod q */
	nn_mul_mod(&rx, &r, x, q);
	nn_mul_mod(&ke, &k, &e, q);
	nn_zero(&e);
	nn_zero(&k);
	nn_mod_add(&s, &rx, &ke, q);
	nn_zero(&rx);
	nn_zero(&ke);
	nn_zero(&tmp);
#ifdef USE_SIG_BLINDING
	/* Unblind s */
	nn_modinv(&binv, &b, q);
	nn_mul_mod(&s, &s, &binv, q);
#endif /* USE_SIG_BLINDING */

	/* If s is 0, restart the process at step 2. */
	if (nn_iszero(&s)) {
		goto restart;
	}

	dbg_nn_print("s", &s);

	/* Return (r,s) */
	nn_export_to_buf(sig + r_len, s_len, &s);
	nn_zero(&r);
	nn_zero(&s);

	ret = 0;

 err:
	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecrdsa), 0, sizeof(ecrdsa_sign_data));

	/* Clean what remains on the stack */
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(p_bit_len);
	VAR_ZEROIFY(hsize);
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);

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

#define ECRDSA_VERIFY_MAGIC ((word_t)(0xa8e16b7e8180cb9aULL))
#define ECRDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECRDSA_VERIFY_MAGIC))

/*
 * Generic *internal* EC-RDSA verification functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * their output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-RDSA verification process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - EC-RDSA verification
 *|
 *|  UF 1. Check that r and s are both in ]0,q[
 *|   F 2. Compute h = H(m)
 *|   F 3. Compute e = OS2I(h)^-1 mod q
 *|         NOTE: here, ISO/IEC 14888-3 and RFCs differ in the way e treated.
 *|         e = OS2I(h) for ISO/IEC 14888-3, or e = OS2I(reversed(h)) when endianness of h
 *|         is reversed for RFCs.
 *|   F 4. Compute u = es mod q
 *|   F 5. Compute v = -er mod q
 *|   F 6. Compute W' = uG + vY = (W'_x, W'_y)
 *|   F 7. Compute r' = W'_x mod q
 *|   F 8. Check r and r' are the same
 *
 */

int _ecrdsa_verify_init(struct ec_verify_context *ctx,
			const u8 *sig, u8 siglen)
{
	bitcnt_t q_bit_len;
	u8 r_len, s_len;
	nn_src_t q;
	nn s, r;
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, ECRDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	q = &(ctx->pub_key->params->ec_gen_order);
	q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	r_len = (u8)ECRDSA_R_LEN(q_bit_len);
	s_len = (u8)ECRDSA_S_LEN(q_bit_len);

	if (siglen != ECRDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* 1. Check that r and s are both in ]0,q[ */
	nn_init_from_buf(&r, sig, r_len);
	nn_init_from_buf(&s, sig + r_len, s_len);
	if (nn_iszero(&s) || (nn_cmp(&s, q) >= 0) ||
	    nn_iszero(&r) || (nn_cmp(&r, q) >= 0)) {
		ret = -1;
		goto err;
	}

	/* Initialize the remaining of verify context. */
	nn_copy(&(ctx->verify_data.ecrdsa.r), &r);
	nn_zero(&r);
	nn_copy(&(ctx->verify_data.ecrdsa.s), &s);
	nn_zero(&s);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->verify_data.ecrdsa.h_ctx));
	ctx->verify_data.ecrdsa.magic = ECRDSA_VERIFY_MAGIC;

	ret = 0;

 err:

	/* Clean what remains on the stack */
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	PTR_NULLIFY(q);

	return ret;
}

int _ecrdsa_verify_update(struct ec_verify_context *ctx,
			  const u8 *chunk, u32 chunklen)
{
	int ret = -1;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-RDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECRDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecrdsa));

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecrdsa.h_ctx), chunk,
			     chunklen);

	ret = 0;
err:
	return ret;
}

int _ecrdsa_verify_finalize(struct ec_verify_context *ctx)
{
	prj_pt_src_t G, Y;
	nn_src_t q;
	nn tmp, h, r_prime, e, v, u;
	prj_pt vY, uG, Wprime;
	aff_pt Wprime_aff;
	u8 h_buf[MAX_DIGEST_SIZE];
	nn *r, *s;
	u8 hsize;
	int ret = -1;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-RDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECRDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecrdsa));

	/* Zero init points */
	local_memset(&uG, 0, sizeof(prj_pt));
	local_memset(&vY, 0, sizeof(prj_pt));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	Y = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	r = &(ctx->verify_data.ecrdsa.r);
	s = &(ctx->verify_data.ecrdsa.s);
	hsize = ctx->h->digest_size;

	/* 2. Compute h = H(m) */
	local_memset(h_buf, 0, hsize);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->verify_data.ecrdsa.h_ctx), h_buf);
	dbg_buf_print("H(m)", h_buf, hsize);
	/* NOTE: this handles a discrepancy between ISO/IEC 14888-3 and
	 * Russian standard based RFCs.
	 */
#ifndef USE_ISO14888_3_ECRDSA
	if(_reverse_endianness(h_buf, hsize)){
		ret = -1;
		goto err;
	}
#endif

	/* 3. Compute e = OS2I(h)^-1 mod q */
	nn_init_from_buf(&tmp, h_buf, hsize);
	local_memset(h_buf, 0, hsize);
	nn_mod(&h, &tmp, q);	/* h = OS2I(h) mod q */
	if (nn_iszero(&h)) {	/* If h is equal to 0, set it to 1 */
		nn_inc(&h, &h);
	}
	nn_modinv(&e, &h, q);	/* e = h^-1 mod q */
	nn_zero(&h);

	/* 4. Compute u = es mod q */
	nn_mul(&tmp, &e, s);
	nn_mod(&u, &tmp, q);

	/* 5. Compute v = -er mod q
	 *
	 * Because we only support positive integers, we compute
	 * v = -er mod q = q - (er mod q) (except when er is 0).
	 */
	nn_mul(&tmp, &e, r);	/* tmp = er */
	nn_zero(&e);
	nn_mod(&tmp, &tmp, q);	/* tmp = er mod q */
	if (nn_iszero(&tmp)) {
		nn_zero(&v);
	} else {
		nn_sub(&v, q, &tmp);
	}
	nn_zero(&tmp);

	/* 6. Compute W' = uG + vY = (W'_x, W'_y) */
	prj_pt_mul_monty(&uG, &u, G);
	prj_pt_mul_monty(&vY, &v, Y);
	nn_zero(&u);
	nn_zero(&v);
	prj_pt_add_monty(&Wprime, &uG, &vY);
	prj_pt_uninit(&uG);
	prj_pt_uninit(&vY);
	prj_pt_to_aff(&Wprime_aff, &Wprime);
	prj_pt_uninit(&Wprime);
	dbg_nn_print("W'_x", &(Wprime_aff.x.fp_val));
	dbg_nn_print("W'_y", &(Wprime_aff.y.fp_val));

	/* 7. Compute r' = W'_x mod q */
	nn_mod(&r_prime, &(Wprime_aff.x.fp_val), q);
	aff_pt_uninit(&Wprime_aff);

	/* 8. Check r and r' are the same */
	ret = (nn_cmp(r, &r_prime) == 0) ? 0 : -1;
	nn_zero(&r_prime);

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecrdsa), 0,
		     sizeof(ecrdsa_verify_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(q);
	PTR_NULLIFY(r);
	PTR_NULLIFY(s);
	VAR_ZEROIFY(hsize);

err:
	return ret;
}

#else /* WITH_SIG_ECRDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECRDSA */
