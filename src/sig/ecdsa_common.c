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
#if defined(WITH_SIG_ECDSA) || defined(WITH_SIG_DECDSA)

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


#if defined(WITH_SIG_DECDSA)
#include "../hash/hmac.h"

/*
 * Deterministic nonce generation function for deterministic ECDSA, as
 * described in RFC6979.
 * NOTE: Deterministic nonce generation for ECDSA is useful against attackers
 * in contexts where only poor RNG/entropy are available, or when nonce bits
 * leaking can be possible through side-channel attacks.
 * However, in contexts where fault attacks are easy to mount, deterministic
 * ECDSA can bring more security risks than regular ECDSA.
 *
 * Depending on the context where you use the library, choose carefully if
 * you want to use the deterministic version or not.
 *
 */
static int __ecdsa_rfc6979_nonce(nn_t k, nn_src_t q, bitcnt_t q_bit_len,
				 nn_src_t x, const u8 *hash, u8 hsize,
				 hash_alg_type hash_type)
{
	int ret = -1;
	u8 V[MAX_DIGEST_SIZE];
	u8 K[MAX_DIGEST_SIZE];
	u8 T[BYTECEIL(CURVES_MAX_Q_BIT_LEN) + MAX_DIGEST_SIZE];
	u8 priv_key_buff[EC_PRIV_KEY_MAX_SIZE];
	hmac_context hmac_ctx;
	bitcnt_t t_bit_len;
	u8 q_len;
	u8 hmac_size;
	u8 tmp;

	/* Sanity checks */
	MUST_HAVE(k != NULL);
	nn_check_initialized(q);
	nn_check_initialized(x);
	MUST_HAVE(hash != NULL);

	q_len = (u8)BYTECEIL(q_bit_len);

	if((q_len > EC_PRIV_KEY_MAX_SIZE) || (hsize > MAX_BLOCK_SIZE)){
		ret = -1;
		goto err;
	}
	/* Steps b. and c.: set V = 0x01 ... 0x01 and K = 0x00 ... 0x00 */
	local_memset(V, 0x01, hsize);
	local_memset(K, 0x00, hsize);
	/* Export our private key in a buffer */
	nn_export_to_buf(priv_key_buff, q_len, x);
	/* Step d.: set K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	 * where x is the private key and h1 the message hash.
	 */
	if(hmac_init(&hmac_ctx, K, hsize, hash_type)){
		ret = -1;
		goto err;
	}
	if(hmac_update(&hmac_ctx, V, hsize)){
		ret = -1;
		goto err;
	}
	tmp = 0x00;
	if(hmac_update(&hmac_ctx, &tmp, 1)){
		ret = -1;
		goto err;
	}
	if(hmac_update(&hmac_ctx, priv_key_buff, q_len)){
		ret = -1;
		goto err;
	}
	/* We compute bits2octets(hash) here */
	nn_init_from_buf(k, hash, hsize);
	if((8 * hsize) > q_bit_len){
		nn_rshift(k, k, (8 * hsize) - q_bit_len);
	}
	nn_mod(k, k, q);
	nn_export_to_buf(T, q_len, k);
	if(hmac_update(&hmac_ctx, T, q_len)){
		ret = -1;
		goto err;
	}
	hmac_size = sizeof(K);
	if(hmac_finalize(&hmac_ctx, K, &hmac_size)){
		ret = -1;
		goto err;
	}
	/* Step e.: set V = HMAC_K(V) */
	hmac_size = sizeof(V);
	if(hmac(K, hsize, hash_type, V, hsize, V, &hmac_size)){
		ret = -1;
		goto err;
	}
	/*  Step f.: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
	if(hmac_init(&hmac_ctx, K, hsize, hash_type)){
		ret = -1;
		goto err;
	}
	if(hmac_update(&hmac_ctx, V, hsize)){
		ret = -1;
		goto err;
	}
	tmp = 0x01;
	if(hmac_update(&hmac_ctx, &tmp, 1)){
		ret = -1;
		goto err;
	}
	if(hmac_update(&hmac_ctx, priv_key_buff, q_len)){
		ret = -1;
		goto err;
	}
	/* We compute bits2octets(hash) here */
	if(hmac_update(&hmac_ctx, T, q_len)){
		ret = -1;
		goto err;
	}
	hmac_size = sizeof(K);
	if(hmac_finalize(&hmac_ctx, K, &hmac_size)){
		ret = -1;
		goto err;
	}
	/* Step g.: set V = HMAC_K(V)*/
	hmac_size = sizeof(V);
	if(hmac(K, hsize, hash_type, V, hsize, V, &hmac_size)){
		ret = -1;
		goto err;
	}
	/* Step h. now apply the generation algorithm until we get
	 * a proper nonce value:
	 * 1.  Set T to the empty sequence.  The length of T (in bits) is
	 * denoted tlen; thus, at that point, tlen = 0.
	 * 2.  While tlen < qlen, do the following:
	 *    V = HMAC_K(V)
	 *    T = T || V
	 * 3.  Compute:
	 *    k = bits2int(T)
	 * If that value of k is within the [1,q-1] range, and is
	 * suitable for DSA or ECDSA (i.e., it results in an r value
	 * that is not 0; see Section 3.4), then the generation of k is
	 * finished.  The obtained value of k is used in DSA or ECDSA.
	 * Otherwise, compute:
	 *    K = HMAC_K(V || 0x00)
	 *    V = HMAC_K(V)
	 * and loop (try to generate a new T, and so on).
	 */
restart:
	t_bit_len = 0;
	while(t_bit_len < q_bit_len){
		/* V = HMAC_K(V) */
		hmac_size = sizeof(V);
		if(hmac(K, hsize, hash_type, V, hsize, V, &hmac_size)){
			ret = -1;
			goto err;
		}
		local_memcpy(&T[BYTECEIL(t_bit_len)], V, hmac_size);
		t_bit_len += (8 * hmac_size);
	}
	nn_init_from_buf(k, T, q_len);
	if((8 * q_len) > q_bit_len){
		nn_rshift(k, k, (8 * q_len) - q_bit_len);
	}
	if(nn_cmp(k, q) >= 0){
		/* K = HMAC_K(V || 0x00) */
		if(hmac_init(&hmac_ctx, K, hsize, hash_type)){
			ret = -1;
			goto err;
		}
		if(hmac_update(&hmac_ctx, V, hsize)){
			ret = -1;
			goto err;
		}
		tmp = 0x00;
		if(hmac_update(&hmac_ctx, &tmp, 1)){
			ret = -1;
			goto err;
		}
		hmac_size = sizeof(K);
		if(hmac_finalize(&hmac_ctx, K, &hmac_size)){
			ret = -1;
			goto err;
		}
		/* V = HMAC_K(V) */
		hmac_size = sizeof(V);
		if(hmac(K, hsize, hash_type, V, hsize, V, &hmac_size)){
			ret = -1;
			goto err;
		}
		goto restart;
	}
	ret = 0;
err:
	return ret;
}
#endif

int __ecdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv,
			 ec_sig_alg_type key_type)
{
	prj_pt_src_t G;

	MUST_HAVE(out_pub != NULL);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	priv_key_check_initialized_and_type(in_priv, key_type);

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

	out_pub->key_type = key_type;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	return 0;
err:
	return -1;
}

u8 __ecdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
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
 *| IUF	 - ECDSA signature
 *|
 *|  UF	 1. Compute h = H(m)
 *|   F	 2. If |h| > bitlen(q), set h to bitlen(q)
 *|	    leftmost (most significant) bits of h
 *|   F	 3. e = OS2I(h) mod q
 *|   F	 4. Get a random value k in ]0,q[
 *|   F	 5. Compute W = (W_x,W_y) = kG
 *|   F	 6. Compute r = W_x mod q
 *|   F	 7. If r is 0, restart the process at step 4.
 *|   F	 8. If e == rx, restart the process at step 4.
 *|   F	 9. Compute s = k^-1 * (xr + e) mod q
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

int __ecdsa_sign_init(struct ec_sign_context *ctx, ec_sig_alg_type key_type)
{
	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, key_type);

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

int __ecdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen, ec_sig_alg_type key_type)
{
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an ECDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecdsa));

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, key_type);

	/* 1. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.ecdsa.h_ctx), chunk, chunklen);

	return 0;
}

int __ecdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen,
			  ec_sig_alg_type key_type)
{
	nn k, r, e, tmp, tmp2, s, kinv;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b;
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

	/* Additional sanity checks on input params from context */
	key_pair_check_initialized_and_type(ctx->key_pair, key_type);

	/* Zero init out point */
	local_memset(&kG, 0, sizeof(prj_pt));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	q = &(priv_key->params->ec_gen_order);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	G = &(priv_key->params->ec_gen);
	q_len = (u8)BYTECEIL(q_bit_len);
	x = &(priv_key->x);
	hsize = ctx->h->digest_size;

	MUST_HAVE(priv_key->key_type == key_type);

	/* Sanity check */
	if(nn_cmp(x, q) >= 0){
		/* This should not happen and means that our
		 * private key is not compliant!
		 */
		ret = -1;
		goto err;
	}

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
	dbg_nn_print("h initial import as nn", &tmp2);
	if (rshift) {
		nn_rshift_fixedlen(&tmp2, &tmp2, rshift);
	}
	dbg_nn_print("h	  final import as nn", &tmp2);
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
#ifdef WITH_SIG_DECDSA
		/* In deterministic ECDSA, nevermind! */
		if(key_type != DECDSA)
#endif
		{
			ret = -1;
			goto err;
		}
	}
#endif
	if(ctx->rand != NULL){
		/* Non-deterministic generation, or deterministic with
		 * test vectors.
		 */
		ret = ctx->rand(&k, q);
	}
	else
#if defined(WITH_SIG_DECDSA)
	{
		/* Only applies for DETERMINISTIC ECDSA */
		if(key_type != DECDSA){
			ret = -1;
			goto err;
		}
		/* Deterministically generate k as RFC6979 mandates */
		ret = __ecdsa_rfc6979_nonce(&k, q, q_bit_len, &(priv_key->x),
					    hash, hsize, ctx->h->type);
	}
#else
	{
		/* NULL rand function is not accepted for regular ECDSA */
		ret = -1;
		goto err;
	}
#endif
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
#endif /* USE_SIG_BLINDING */


	/* 5. Compute W = (W_x,W_y) = kG */
#ifdef USE_SIG_BLINDING
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

	/* 6. Compute r = W_x mod q */
	nn_mod(&r, &(W.x.fp_val), q);
	aff_pt_uninit(&W);
	dbg_nn_print("r", &r);

	/* 7. If r is 0, restart the process at step 4. */
	if (nn_iszero(&r)) {
		goto restart;
	}

	/* Clean hash buffer as we do not need it anymore */
	local_memset(hash, 0, hsize);

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
	/*
	 * In case of blinding, we compute (b*k)^-1, and b^-1 will
	 * automatically unblind (r*x) in the following.
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
	if(nn_is_initialized(&b)){
		nn_uninit(&b);
	}
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
 *| IUF	 - ECDSA verification
 *|
 *| I	 1. Reject the signature if r or s is 0.
 *|  UF	 2. Compute h = H(m)
 *|   F	 3. If |h| > bitlen(q), set h to bitlen(q)
 *|	    leftmost (most significant) bits of h
 *|   F	 4. Compute e = OS2I(h) mod q
 *|   F	 5. Compute u = (s^-1)e mod q
 *|   F	 6. Compute v = (s^-1)r mod q
 *|   F	 7. Compute W' = uG + vY
 *|   F	 8. If W' is the point at infinity, reject the signature.
 *|   F	 9. Compute r' = W'_x mod q
 *|   F 10. Accept the signature if and only if r equals r'
 *
 */

#define ECDSA_VERIFY_MAGIC ((word_t)(0x5155fe73e7fd51beULL))
#define ECDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == ECDSA_VERIFY_MAGIC))

int __ecdsa_verify_init(struct ec_verify_context *ctx, const u8 *sig, u8 siglen,
			ec_sig_alg_type key_type)
{
	bitcnt_t q_bit_len;
	u8 q_len;
	nn_src_t q;
	nn *r, *s;
	int ret = -1;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, key_type);
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

int __ecdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen, ec_sig_alg_type key_type)
{
	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an ECDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecdsa));
	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, key_type);

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		return -1;
	}
	ctx->h->hfunc_update(&(ctx->verify_data.ecdsa.h_ctx), chunk, chunklen);
	return 0;
}

int __ecdsa_verify_finalize(struct ec_verify_context *ctx,
			    ec_sig_alg_type key_type)
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
	/* Do some sanity checks on input params */
	pub_key_check_initialized_and_type(ctx->pub_key, key_type);

	/* Zero init points */
	local_memset(&uG, 0, sizeof(prj_pt));
	local_memset(&vY, 0, sizeof(prj_pt));

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
	dbg_nn_print("h	  final import as nn", &tmp);

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

#else /* defined(WITH_SIG_ECDSA) || defined(WITH_SIG_DECDSA) */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECDSA */
