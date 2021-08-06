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
#ifdef WITH_SIG_ECKCDSA

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECKCDSA"
#endif
#include "../utils/dbg_sig.h"

int eckcdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	prj_pt_src_t G;
	nn xinv;

	MUST_HAVE(out_pub != NULL);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	priv_key_check_initialized_and_type(in_priv, ECKCDSA);

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
	/* Use blinding when computing point scalar multiplication */
	prj_pt_mul_monty_blind(&(out_pub->y), &xinv, G);
	nn_uninit(&xinv);

	out_pub->key_type = ECKCDSA;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	return 0;
err:
	return -1;
}

u8 eckcdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)ECKCDSA_SIGLEN(hsize, q_bit_len);
}

/*
 * ISO 14888-3:2016 has some insane specific case when the digest size
 * (gamma) is larger than beta, the bit length of q (i.e. hsize >
 * bitlen(q), i.e. gamma > beta). In that case, both the values of h
 * (= H(z||m)) and r (= H(FE2OS(W_x))) must be post-processed/mangled
 * in the following way:
 *
 *  - h = I2BS(beta', (BS2I(gamma, h))) mod 2^beta'
 *  - r = I2BS(beta', (BS2I(gamma, r))) mod 2^beta'
 *
 * where beta' = 8 * ceil(beta / 8)
 *
 * There are two things to consider before implementing those steps
 * using various conversions to/from nn, shifting and masking:
 *
 *  - the expected post-processing work is simply clearing the first
 *    (gamma - beta') bits at the beginning of h and r to keep only
 *    last beta ones unmodified.
 *  - In the library, we do not work on bitstring but byte strings in
 *    all cases
 *  - In EC-KCDSA sig/verif, the result (h and then r) are then XORed
 *    together and then converted to an integer (the buffer being
 *    considered in big endian order)
 *
 * For that reason, this function simply takes a buffer 'buf' of
 * 'buflen' bytes and shifts it 'shift' bytes to the left, clearing
 * the trailing 'shift' bytes at the end of the buffer. The function
 * is expected to be used with 'shift' parameter set to
 * (gamma - beta') / 8.
 *
 * This is better presented on an example:
 *
 * shift = (gamma - beta') / 8 = 4
 * before: buf = { 0xff, 0xff, 0xff, 0x12, 0x34, 0x56, 0x78}
 * after : buf = { 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00}
 */
static void buf_lshift(u8 *buf, u8 buflen, u8 shift)
{
	u8 i;

	MUST_HAVE(buf != NULL);

	if (shift > buflen) {
		shift = buflen;
	}

	/* Start by shifting all trailing bytes to the left ... */
	for (i = shift; i < buflen; i++) {
		buf[i - shift] = buf[i];
	}

	/* Let's now zeroize the end of the buffer ... */
	for (i = 1; i <= shift; i++) {
		buf[buflen - i] = 0;
	}
}

/*
 * Generic *internal* EC-KCDSA signature functions (init, update and finalize).
 * Their purpose is to allow passing a specific hash function (along with
 * its output size) and the random ephemeral key k, so that compliance
 * tests against test vectors can be made without ugly hack in the code
 * itself.
 *
 * Global EC-KCDSA signature process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - EC-KCDSA signature
 *|
 *| IUF	 1. Compute h = H(z||m)
 *|   F	 2. If |H| > bitlen(q), set h to beta' rightmost bits of
 *|	    bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|	    set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
 *|   F	 3. Get a random value k in ]0,q[
 *|   F	 4. Compute W = (W_x,W_y) = kG
 *|   F	 5. Compute r = H(FE2OS(W_x)).
 *|   F	 6. If |H| > bitlen(q), set r to beta' rightmost bits of
 *|	    bitstring r (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|	    set r to I2BS(beta', BS2I(|H|, r) mod 2^beta')
 *|   F	 7. Compute e = OS2I(r XOR h) mod q
 *|   F	 8. Compute s = x(k - e) mod q
 *|   F	 9. if s == 0, restart at step 3.
 *|   F 10. return (r,s)
 *
 */

#define ECKCDSA_SIGN_MAGIC ((word_t)(0x45503fcf5114bf1eULL))
#define ECKCDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECKCDSA_SIGN_MAGIC))

int _eckcdsa_sign_init(struct ec_sign_context *ctx)
{
	u8 tmp_buf[LOCAL_MAX(2 * BYTECEIL(CURVES_MAX_P_BIT_LEN), MAX_BLOCK_SIZE)];
	const ec_pub_key *pub_key;
	aff_pt y_aff;
	u8 p_len;
	u16 z_len;
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, ECKCDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	pub_key = &(ctx->key_pair->pub_key);
	p_len = (u8)BYTECEIL(pub_key->params->ec_fp.p_bitlen);
	z_len = ctx->h->block_size;

	/*
	 * 1. Compute h = H(z||m)
	 *
	 * We first need to compute z, the certificate data that will be
	 * prepended to the message m prior to hashing. In ISO-14888-3:2016,
	 * z is basically the concatenation of Yx and Yy (the affine coordinates
	 * of the public key Y) up to the block size of the hash function.
	 * If the concatenation of those coordinates is smaller than blocksize,
	 * 0 are appended.
	 *
	 * So, we convert the public key point to its affine representation and
	 * concatenate the two coordinates in a temporary (zeroized) buffer, of
	 * which the first z_len (i.e. blocksize) bytes are exported to z.
	 *
	 * Message m will be handled during following update() calls.
	 */
	prj_pt_to_aff(&y_aff, &(pub_key->y));
	local_memset(tmp_buf, 0, sizeof(tmp_buf));
	fp_export_to_buf(tmp_buf, p_len, &(y_aff.x));
	fp_export_to_buf(tmp_buf + p_len, p_len, &(y_aff.y));
	aff_pt_uninit(&y_aff);

	dbg_pub_key_print("Y", pub_key);

	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->sign_data.eckcdsa.h_ctx));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.eckcdsa.h_ctx), tmp_buf, z_len);
	local_memset(tmp_buf, 0, sizeof(tmp_buf));

	/* Initialize data part of the context */
	ctx->sign_data.eckcdsa.magic = ECKCDSA_SIGN_MAGIC;

	ret = 0;

 err:
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(z_len);
	PTR_NULLIFY(pub_key);

	return ret;
}

int _eckcdsa_sign_update(struct ec_sign_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-KCDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECKCDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.eckcdsa));

	/* 1. Compute h = H(z||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.eckcdsa.h_ctx), chunk, chunklen);

	return 0;
}

int _eckcdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	prj_pt_src_t G;
	nn_src_t q, x;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif /* USE_SIG_BLINDING */
	prj_pt kG;
	aff_pt W;
	unsigned int i;
	nn e, tmp, tmp2, s, k;
	u8 hzm[MAX_DIGEST_SIZE];
	u8 r[MAX_DIGEST_SIZE];
	u8 tmp_buf[BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	hash_context r_ctx;
	const ec_priv_key *priv_key;
	u8 p_len, r_len, s_len, hsize, shift;
	bitcnt_t q_bit_len;
	int ret;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-KCDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECKCDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.eckcdsa));

	/* Zero init points */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	hsize = ctx->h->digest_size;
	p_len = (u8)BYTECEIL(priv_key->params->ec_fp.p_bitlen);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	r_len = (u8)ECKCDSA_R_LEN(hsize, q_bit_len);
	s_len = (u8)ECKCDSA_S_LEN(q_bit_len);
	x = &(priv_key->x);

	/* Sanity check */
	if(nn_cmp(x, q) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		ret = -1;
		goto err;
	}
	if (siglen != ECKCDSA_SIGLEN(hsize, q_bit_len)) {
		ret = -1;
		goto err;
	}

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", q);
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", G);

	/* 1. Compute h = H(z||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->sign_data.eckcdsa.h_ctx), hzm);
	dbg_buf_print("h = H(z||m)  pre-mask", hzm, hsize);

	/*
	 * 2. If |H| > bitlen(q), set h to beta' rightmost bits of
	 *    bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
	 *    set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
	 */
	shift = (hsize > r_len) ? (hsize - r_len) : 0;
	if(hsize > sizeof(hzm)){
		ret = -1;
		goto err;
	}
	buf_lshift(hzm, hsize, shift);
	dbg_buf_print("h = H(z||m) post-mask", hzm, r_len);

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
		goto err;
	}
	dbg_nn_print("k", &k);

#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, k and e are multiplied by
	 * a random value b in ]0,q[ */
	ret = nn_get_random_mod(&b, q);
	if (ret) {
		goto err;
	}
	dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */

	/* 4. Compute W = (W_x,W_y) = kG */
#ifdef USE_SIG_BLINDING
	/* We use blinding for the scalar multiplication */
	if(prj_pt_mul_monty_blind(&kG, &k, G)){
		goto err;
	}
#else
	prj_pt_mul_monty(&kG, &k, G);
#endif /* USE_SIG_BLINDING */
	prj_pt_to_aff(&W, &kG);
	prj_pt_uninit(&kG);
	dbg_nn_print("W_x", &(W.x.fp_val));
	dbg_nn_print("W_y", &(W.y.fp_val));

	/* 5 Compute r = h(FE2OS(W_x)). */
	local_memset(tmp_buf, 0, sizeof(tmp_buf));
	fp_export_to_buf(tmp_buf, p_len, &(W.x));
	aff_pt_uninit(&W);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&r_ctx);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&r_ctx, tmp_buf, p_len);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&r_ctx, r);
	local_memset(tmp_buf, 0, p_len);
	local_memset(&r_ctx, 0, sizeof(hash_context));

	/*
	 * 6. If |H| > bitlen(q), set r to beta' rightmost bits of
	 *    bitstring r (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
	 *    set r to I2BS(beta', BS2I(|H|, r) mod 2^beta')
	 */
	dbg_buf_print("r  pre-mask", r, hsize);
	if(hsize > sizeof(r)){
		ret = -1;
		goto err;
	}
	buf_lshift(r, hsize, shift);
	dbg_buf_print("r post-mask", r, r_len);

	/* 7. Compute e = OS2I(r XOR h) mod q */
	for (i = 0; i < r_len; i++) {
		hzm[i] ^= r[i];
	}
	nn_init_from_buf(&tmp, hzm, r_len);
	local_memset(hzm, 0, r_len);
	nn_mod(&e, &tmp, q);
	nn_zero(&tmp);
	dbg_nn_print("e", &e);

#ifdef USE_SIG_BLINDING
	/* In case of blinding, we compute (k*b - e*b) * x * b^-1 */
	nn_mul_mod(&k, &k, &b, q);
	nn_mul_mod(&e, &e, &b, q);
	nn_modinv(&binv, &b, q);
#endif /* USE_SIG_BLINDING */
	/*
	 * 8. Compute s = x(k - e) mod q
	 *
	 * This is equivalent to computing s = x(k + (q - e)) mod q.
	 * This second version avoids checking if k < e before the
	 * subtraction, because e has already been reduced mod q
	 * (i.e. is guaranteed to be lower than q) and we can then
	 * safely call nn_sub().
	 */
	nn_sub(&tmp, q, &e);
	nn_zero(&e);
	nn_mod_add(&tmp2, &k, &tmp, q);
	nn_zero(&k);
	nn_mul_mod(&s, x, &tmp2, q);
	nn_zero(&tmp2);
	nn_zero(&tmp);
#ifdef USE_SIG_BLINDING
	/* Unblind s with b^-1 */
	nn_mul_mod(&s, &s, &binv, q);
#endif /* USE_SIG_BLINDING */

	/* 9. if s == 0, restart at step 3. */
	if (nn_iszero(&s)) {
		goto restart;
	}

	dbg_nn_print("s", &s);

	/* 10. return (r,s) */
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
	local_memset(&(ctx->sign_data.eckcdsa), 0, sizeof(eckcdsa_sign_data));

	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	VAR_ZEROIFY(i);
	PTR_NULLIFY(priv_key);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(q_bit_len);
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

/*
 * Generic *internal* EC-KCDSA verification functions (init, update and
 * finalize). Their purpose is to allow passing a specific hash function
 * (along with its output size) and the random ephemeral key k, so that
 * compliance tests against test vectors can be made without ugly hack
 * in the code itself.
 *
 * Global EC-CKDSA verification process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 *| IUF - EC-KCDSA verification
 *|
 *| I	1. Check the length of r:
 *|	    - if |H| > bitlen(q), r must be of length
 *|	      beta' = 8 * ceil(bitlen(q) / 8)
 *|	    - if |H| <= bitlen(q), r must be of length hsize
 *| I	2. Check that s is in ]0,q[
 *| IUF 3. Compute h = H(z||m)
 *|   F 4. If |H| > bitlen(q), set h to beta' rightmost bits of
 *|	   bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|	   set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
 *|   F 5. Compute e = OS2I(r XOR h) mod q
 *|   F 6. Compute W' = sY + eG, where Y is the public key
 *|   F 7. Compute r' = h(W'x)
 *|   F 8. If |H| > bitlen(q), set r' to beta' rightmost bits of
 *|	   bitstring r' (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|	   set r' to I2BS(beta', BS2I(|H|, r') mod 2^beta')
 *|   F 9. Check if r == r'
 *
 */

#define ECKCDSA_VERIFY_MAGIC ((word_t)(0xa836a75de66643aaULL))
#define ECKCDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((const void *)(A)) != NULL) && \
		  ((A)->magic == ECKCDSA_VERIFY_MAGIC))

int _eckcdsa_verify_init(struct ec_verify_context *ctx,
			 const u8 *sig, u8 siglen)
{
	u8 tmp_buf[LOCAL_MAX(2 * BYTECEIL(CURVES_MAX_P_BIT_LEN), MAX_BLOCK_SIZE)];
	u8 p_len, r_len, s_len, z_len;
	bitcnt_t q_bit_len;
	const ec_pub_key *pub_key;
	aff_pt y_aff;
	nn_src_t q;
	u8 hsize;
	int ret;
	nn s;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, ECKCDSA);
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	pub_key = ctx->pub_key;
	p_len = (u8)BYTECEIL(pub_key->params->ec_fp.p_bitlen);
	q_bit_len = pub_key->params->ec_gen_order_bitlen;
	q = &(pub_key->params->ec_gen_order);
	hsize = ctx->h->digest_size;
	r_len = (u8)ECKCDSA_R_LEN(hsize, q_bit_len);
	s_len = (u8)ECKCDSA_S_LEN(q_bit_len);
	z_len = ctx->h->block_size;

	/*
	 * 1. Check the length of r:
	 *     - if |H| > bitlen(q), r must be of length
	 *	 beta' = 8 * ceil(bitlen(q) / 8)
	 *     - if |H| <= bitlen(q), r must be of length hsize
	 *
	 * As we expect the signature as the concatenation of r and s, the check
	 * is done by verifying the length of the signature is the expected one.
	 */
	if (siglen != ECKCDSA_SIGLEN(hsize, q_bit_len)) {
		ret = -1;
		goto err;
	}

	/* 2. Check that s is in ]0,q[ */
	nn_init_from_buf(&s, sig + r_len, s_len);
	if (nn_iszero(&s) || (nn_cmp(&s, q) >= 0)) {
		ret = -1;
		goto err;
	}
	dbg_nn_print("s", &s);

	/*
	 * 3. Compute h = H(z||m)
	 *
	 * We first need to compute z, the certificate data that will be
	 * prepended to the message m prior to hashing. In ISO-14888-3:2016,
	 * z is basically the concatenation of Yx and Yy (the affine coordinates
	 * of the public key Y) up to the block size of the hash function.
	 * If the concatenation of those coordinates is smaller than blocksize,
	 * 0 are appended.
	 *
	 * So, we convert the public key point to its affine representation and
	 * concatenate the two coordinates in a temporary (zeroized) buffer, of
	 * which the first z_len (i.e. blocksize) bytes are exported to z.
	 *
	 * Message m will be handled during following update() calls.
	 */
	prj_pt_to_aff(&y_aff, &(pub_key->y));
	local_memset(tmp_buf, 0, sizeof(tmp_buf));
	fp_export_to_buf(tmp_buf, p_len, &(y_aff.x));
	fp_export_to_buf(tmp_buf + p_len, p_len, &(y_aff.y));
	aff_pt_uninit(&y_aff);

	dbg_pub_key_print("Y", pub_key);

	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&(ctx->verify_data.eckcdsa.h_ctx));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.eckcdsa.h_ctx), tmp_buf,
			     z_len);
	local_memset(tmp_buf, 0, sizeof(tmp_buf));

	/*
	 * Initialize the verify context by storing r and s as imported
	 * from the signature
	 */
	local_memcpy(ctx->verify_data.eckcdsa.r, sig, r_len);
	nn_copy(&(ctx->verify_data.eckcdsa.s), &s);
	nn_zero(&s);
	ctx->verify_data.eckcdsa.magic = ECKCDSA_VERIFY_MAGIC;

	ret = 0;

 err:
	if (ret) {
		/*
		 * Signature is invalid. Clear data part of the context.
		 * This will clear magic and avoid further reuse of the
		 * whole context.
		 */
		local_memset(&(ctx->verify_data.eckcdsa), 0,
			     sizeof(eckcdsa_verify_data));
	}

	/* Let's also clear what remains on the stack */
	PTR_NULLIFY(q);
	PTR_NULLIFY(pub_key);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(z_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(hsize);

	return ret;
}

int _eckcdsa_verify_update(struct ec_verify_context *ctx,
			   const u8 *chunk, u32 chunklen)
{
	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-KCDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECKCDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.eckcdsa));

	/* 3. Compute h = H(z||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.eckcdsa.h_ctx),
			     chunk, chunklen);

	return 0;
}

int _eckcdsa_verify_finalize(struct ec_verify_context *ctx)
{
	u8 tmp_buf[BYTECEIL(CURVES_MAX_P_BIT_LEN)];
	bitcnt_t q_bit_len, p_bit_len;
	u8 p_len, r_len;
	prj_pt sY, eG, Wprime;
	aff_pt Wprime_aff;
	prj_pt_src_t G, Y;
	u8 r_prime[MAX_DIGEST_SIZE];
	const ec_pub_key *pub_key;
	hash_context r_prime_ctx;
	u8 hzm[MAX_DIGEST_SIZE];
	unsigned int i;
	nn_src_t q;
	nn e, tmp;
	u8 hsize, shift;
	int ret;
	u8 *r;
	nn *s;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-KCDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECKCDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.eckcdsa));

	/* Zero init points */
	local_memset(&sY, 0, sizeof(prj_pt));
	local_memset(&eG, 0, sizeof(prj_pt));

	/* Make things more readable */
	pub_key = ctx->pub_key;
	G = &(pub_key->params->ec_gen);
	Y = &(pub_key->y);
	q = &(pub_key->params->ec_gen_order);
	p_bit_len = pub_key->params->ec_fp.p_bitlen;
	q_bit_len = pub_key->params->ec_gen_order_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	hsize = ctx->h->digest_size;
	r_len = (u8)ECKCDSA_R_LEN(hsize, q_bit_len);
	r = ctx->verify_data.eckcdsa.r;
	s = &(ctx->verify_data.eckcdsa.s);

	/* 3. Compute h = H(z||m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&(ctx->verify_data.eckcdsa.h_ctx), hzm);
	dbg_buf_print("h = H(z||m)  pre-mask", hzm, hsize);

	/*
	 * 4. If |H| > bitlen(q), set h to beta' rightmost bits of
	 *    bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
	 *    set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
	 */
	shift = (hsize > r_len) ? (hsize - r_len) : 0;
	if(hsize > sizeof(hzm)){
		ret = -1;
		goto err;
	}
	buf_lshift(hzm, hsize, shift);
	dbg_buf_print("h = H(z||m) post-mask", hzm, r_len);

	/* 5. Compute e = OS2I(r XOR h) mod q */
	for (i = 0; i < r_len; i++) {
		hzm[i] ^= r[i];
	}
	nn_init_from_buf(&tmp, hzm, r_len);
	local_memset(hzm, 0, hsize);
	nn_mod(&e, &tmp, q);
	nn_zero(&tmp);

	dbg_nn_print("e", &e);

	/* 6. Compute W' = sY + eG, where Y is the public key */
	prj_pt_mul_monty(&sY, s, Y);
	prj_pt_mul_monty(&eG, &e, G);
	nn_zero(&e);
	prj_pt_add_monty(&Wprime, &sY, &eG);
	prj_pt_uninit(&sY);
	prj_pt_uninit(&eG);
	prj_pt_to_aff(&Wprime_aff, &Wprime);
	prj_pt_uninit(&Wprime);
	dbg_nn_print("W'_x", &(Wprime_aff.x.fp_val));
	dbg_nn_print("W'_y", &(Wprime_aff.y.fp_val));

	/* 7. Compute r' = h(W'x) */
	local_memset(tmp_buf, 0, sizeof(tmp_buf));
	fp_export_to_buf(tmp_buf, p_len, &(Wprime_aff.x));
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(&r_prime_ctx);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&r_prime_ctx, tmp_buf, p_len);
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_finalize(&r_prime_ctx, r_prime);
	local_memset(tmp_buf, 0, p_len);
	local_memset(&r_prime_ctx, 0, sizeof(hash_context));

	/*
	 * 8. If |H| > bitlen(q), set r' to beta' rightmost bits of
	 *    bitstring r' (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
	 *    set r' to I2BS(beta', BS2I(|H|, r') mod 2^beta')
	 */
	dbg_buf_print("r'  pre-mask", r_prime, hsize);
	buf_lshift(r_prime, hsize, shift);
	dbg_buf_print("r' post-mask", r_prime, r_len);
	dbg_buf_print("r", r, r_len);

	/* 9. Check if r == r' */
	ret = are_equal(r, r_prime, r_len) ? 0 : -1;

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.eckcdsa), 0,
		     sizeof(eckcdsa_verify_data));

	/* Let's also clear what remains on the stack */
	VAR_ZEROIFY(i);
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(q);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(p_bit_len);
	PTR_NULLIFY(pub_key);
	VAR_ZEROIFY(hsize);
	PTR_NULLIFY(r);
	PTR_NULLIFY(s);

err:
	return ret;
}

#else /* WITH_SIG_ECKCDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECKCDSA */
