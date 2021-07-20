/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "../lib_ecc_config.h"
#if defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448)

/*
 * Sanity checks on the hash functions and curves depending on the EdDSA variant.
 */
/* EDDSA25519 used SHA-512 as a fixed hash function and WEI25519 as a fixed
 * curve.
 */
#if defined(WITH_SIG_EDDSA25519)
#if !defined(WITH_HASH_SHA512) || !defined(WITH_CURVE_WEI25519)
#error "Error: EDDSA25519 needs SHA-512 and WEI25519 to be defined! Please define them in libecc config file"
#endif
#endif
/* EDDSA448 used SHAKE256 as a fixed hash function and WEI448 as a fixed
 * curve.
 */
#if defined(WITH_SIG_EDDSA448)
#if !defined(WITH_HASH_SHAKE256) || !defined(WITH_CURVE_WEI448)
#error "Error: EDDSA25519 needs SHAKE256 and WEI448 to be defined! Please define them in libecc config file"
#endif
#endif

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"
#include "../fp/fp.h"
#include "../fp/fp_sqrt.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#include "../utils/utils.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "EDDSA"
#endif
#include "../utils/dbg_sig.h"


static inline int dom(u16 x, const u8 *y, u16 olen_y, const hash_mapping *h,
		      hash_context *h_ctx, u8 dom_type){
	u8 tmp[2];
	int ret = -1;

	if((h == NULL) || (h_ctx == NULL)){
		ret = -1;
		goto err;
	}
	/* Sanity check on ancillary data len, its size must not exceed 255 bytes as per RFC8032 */
	if((x > 255) || (olen_y > 255)){
		ret = -1;
		goto err;
	}
	if(dom_type == 2){
		h->hfunc_update(h_ctx, (const u8*)"SigEd25519 no Ed25519 collisions", 32);
	}
	else if(dom_type == 4){
		h->hfunc_update(h_ctx, (const u8*)"SigEd448", 8);
	}
	else{
		ret = -1;
		goto err;
	}
	tmp[0] = (u8)x;
	tmp[1] = (u8)olen_y;
	h->hfunc_update(h_ctx, tmp, 2);
	if(y != NULL){
		h->hfunc_update(h_ctx, y, olen_y);
	}

	ret = 0;
err:
	return ret;
}

#if defined(WITH_SIG_EDDSA25519)
/* Helper for dom2(x, y).
 *
 * See RFC8032:
 *
 * dom2(x, y)     The blank octet string when signing or verifying
 *                Ed25519.  Otherwise, the octet string: "SigEd25519 no
 *                Ed25519 collisions" || octet(x) || octet(OLEN(y)) ||
 *                y, where x is in range 0-255 and y is an octet string
 *                of at most 255 octets.  "SigEd25519 no Ed25519
 *                collisions" is in ASCII (32 octets).
 */
static inline int dom2(u16 x, const u8 *y, u16 olen_y, const hash_mapping *h,
		       hash_context *h_ctx){
	return dom(x, y, olen_y, h, h_ctx, 2);
}
#endif /* defined(WITH_SIG_EDDSA25519) */

#if defined(WITH_SIG_EDDSA448)
/* Helper for dom4(x, y).
 *
 * See RFC8032:
 *
 * dom4(x, y)     The octet string "SigEd448" || octet(x) ||
 *                octet(OLEN(y)) || y, where x is in range 0-255 and y
 *                is an octet string of at most 255 octets.  "SigEd448"
 *                is in ASCII (8 octets).
 */
static inline int dom4(u16 x, const u8 *y, u16 olen_y, const hash_mapping *h,
		       hash_context *h_ctx){
	return dom(x, y, olen_y, h, h_ctx, 4);
}
#endif /* defined(WITH_SIG_EDDSA448) */

/* EdDSA sanity check on keys.
 * EDDSA25519 and variants only support WEI25519 as a curve, and SHA-512 as a hash function.
 * EDDSA448 and variants only support WEI448 as a curve, and SHAKE256 as a "hash function".
 */
static inline hash_alg_type get_eddsa_hash_type(ec_sig_alg_type sig_type){
	hash_alg_type hash_type = UNKNOWN_HASH_ALG;

	switch (sig_type) {
#if defined(WITH_SIG_EDDSA25519)
		case EDDSA25519:
		case EDDSA25519PH:
		case EDDSA25519CTX:{
			hash_type = SHA512;
			break;
		}
#endif
#if defined(WITH_SIG_EDDSA448)
		case EDDSA448:
		case EDDSA448PH:{
			hash_type = SHAKE256;
			break;
		}
#endif
		default:{
			hash_type = UNKNOWN_HASH_ALG;
			break;
		}
	}
	return hash_type;
}

/*
 * Check given EdDSA key type does match given curve type. Returns 0 on success,
 * and -1 on error.
 */
static int eddsa_key_type_check_curve(ec_sig_alg_type key_type,
				      ec_curve_type curve_type)
{
	int ret = -1;

	switch (key_type) {
#if defined(WITH_SIG_EDDSA25519)
		case EDDSA25519:
		case EDDSA25519PH:
		case EDDSA25519CTX:{
			/* Check curve */
			ret = (curve_type == WEI25519) ? 0 : -1;
			break;
		}
#endif
#if defined(WITH_SIG_EDDSA448)
		case EDDSA448:
		case EDDSA448PH:{
			/* Check curve */
			ret = (curve_type == WEI448) ? 0 : -1;
			break;
		}
#endif
		default:{
			ret = -1;
			break;
		}
	}

	return ret;
}

static int eddsa_priv_key_sanity_check(const ec_priv_key *in_priv)
{
	int ret = 0;

	if ((!priv_key_is_initialized(in_priv)) ||
	    eddsa_key_type_check_curve(in_priv->key_type,
				       in_priv->params->curve_type)) {
		ret = -1;
	}

	return ret;
}

static int eddsa_pub_key_sanity_check(const ec_pub_key *in_pub)
{
	int ret = 0;

	if ((!pub_key_is_initialized(in_pub)) ||
	    eddsa_key_type_check_curve(in_pub->key_type,
				       in_pub->params->curve_type)) {
		ret = -1;
	}

	return ret;
}

static int eddsa_key_pair_sanity_check(const ec_key_pair *key_pair)
{
	int ret = -1;

	if(eddsa_priv_key_sanity_check(&(key_pair->priv_key))){
		ret = -1;
		goto err;
	}
	if(eddsa_pub_key_sanity_check(&(key_pair->pub_key))){
		ret = -1;
		goto err;
	}
	if(key_pair->priv_key.key_type != key_pair->pub_key.key_type){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	return ret;
}

/*
 * EdDSA decode an integer from a buffer using little endian format.
 */
static int eddsa_decode_integer(nn_t nn_out, const u8 *buf, u16 buf_size)
{
	u32 i;
	u8 buf_little_endian[MAX_DIGEST_SIZE];
	int ret = -1;

	if(buf == NULL){
		ret = -1;
		goto err;
	}
	if(sizeof(buf_little_endian) < buf_size){
		ret = -1;
		goto err;
	}
	nn_init(nn_out, 0);

	local_memset(buf_little_endian, 0, sizeof(buf_little_endian));
	if(buf_size > 1){
		/* Inverse endianness of our input buffer */
		for(i = 0; i < buf_size; i++){
			buf_little_endian[i] = buf[buf_size - 1 - i];
		}
	}

	/* Compute an integer from the buffer */
	nn_init_from_buf(nn_out, buf_little_endian, buf_size);

	ret = 0;
err:
	return ret;
}

/*
 * EdDSA encode an integer to a buffer using little endian format.
 */
static int eddsa_encode_integer(nn_src_t nn_in, u8 *buf, u16 buf_size)
{
	u32 i;
	u8 tmp;
	int ret = -1;

	if(buf == NULL){
		ret = -1;
		goto err;
	}
	if(!nn_is_initialized(nn_in)){
		ret = -1;
		goto err;
	}
	/* Sanity check that we do not lose information */
	if(((u32)nn_bitlen(nn_in)) > (8 * (u32)buf_size)){
		ret = -1;
		goto err;
	}
	/* Export the number to our buffer */
	nn_export_to_buf(buf, buf_size, nn_in);
	/* Now reverse endianness in place */
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

/*
 * EdDSA encoding of scalar s.
 */
static int eddsa_compute_s(nn_t s, const u8 *digest, u16 digest_size)
{
	int ret = -1;

	if(digest == NULL){
		ret = -1;
		goto err;
	}
	if((digest_size % 2) != 0){
		ret = -1;
		goto err;
	}
	/* s is half of the digest size encoded in little endian format */
	if(eddsa_decode_integer(s, digest, (digest_size / 2))){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	return ret;
}

/* Extract the digest from the encoded private key */
static int eddsa_get_digest_from_priv_key(u8 *digest, u8 *digest_size, const ec_priv_key *in_priv)
{
	int ret = -1;
	hash_alg_type hash_type;
	const hash_mapping *hash;

	if(eddsa_priv_key_sanity_check(in_priv)){
		ret = -1;
		goto err;
	}

	if((hash_type = get_eddsa_hash_type(in_priv->key_type)) == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	if((hash = get_hash_by_type(hash_type)) == NULL){
		ret = -1;
		goto err;
	}

	/* Sanity check */
	if((digest == NULL) || (digest_size == NULL)){
		ret = -1;
		goto err;
	}
	/* Check real digest size */
	if(*digest_size < hash->digest_size){
		ret = -1;
		goto err;
	}
	*digest_size = hash->digest_size;
	nn_export_to_buf(digest, *digest_size, &(in_priv->x));

	ret = 0;
err:
	return ret;
}

/* Encode an Edwards curve affine point in canonical form */
static int eddsa_encode_point(aff_pt_edwards_src_t in, fp_src_t alpha_edwards,
			      u8 *buf, u16 buflen, ec_sig_alg_type sig_alg)
{
	nn out_reduced;
	u8 lsb;
	int ret = -1;

	nn_init(&out_reduced, 0);

	/* Sanity checks */
	if(buf == NULL){
		ret = -1;
		goto err;
	}
	if(!aff_pt_edwards_is_initialized(in)){
		ret = -1;
		goto err;
	}
	if(!fp_is_initialized(alpha_edwards)){
		ret = -1;
		goto err;
	}

	/* Zeroize the buffer */
	local_memset(buf, 0, buflen);

	/* Note: we should be reduced modulo Fp for canonical encoding here as
	 * coordinate elements are in Fp ...
	 */
#if defined(WITH_SIG_EDDSA448)
	if((sig_alg == EDDSA448) || (sig_alg == EDDSA448PH)){
		/*
		 * In case of EDDSA448, we apply the 4-isogeny to transfer from
		 * Ed448 to Edwards448.
		 * The isogeny maps (x, y) on Ed448 to (x1, y1) on Edwards448
		 * using:
		 *      x1 = (4*x*y/c) / (y^2-x^2)
		 *      y1 = (2-x^2-y^2) / (x^2+y^2) = (2 - (x^2+y^2)) / (x^2 + y^2)
		 * and (0, 1) as well as (0, -1) are mapped to (0, 1)
		 * We only need to encode our y1 here, but x1 computation is
		 * unfortunately needed to get its LSB that is necessary for
		 * the encoding.
		 */
		fp tmp_x, tmp_y, y1;
		/* Compute x1 to get our LSB */
		fp_init(&y1, in->y.ctx);
		fp_copy(&tmp_x, &(in->x));
		fp_sqr(&tmp_x, &tmp_x);
		fp_copy(&tmp_y, &(in->y));
		fp_sqr(&tmp_y, &tmp_y);
		fp_sub(&tmp_y, &tmp_y, &tmp_x);
		/* NOTE: inversion by zero should be caught by lower layers */
		fp_inv(&tmp_y, &tmp_y);
		fp_set_word_value(&tmp_x, WORD(4));
		fp_mul(&tmp_x, &tmp_x, &(in->x));
		fp_mul(&tmp_x, &tmp_x, &(in->y));
		fp_mul(&tmp_x, &tmp_x, &tmp_y);
		fp_inv(&tmp_y, alpha_edwards);
		fp_mul(&tmp_x, &tmp_x, &tmp_y);
		lsb = nn_getbit(&(tmp_x.fp_val), 0);
		/* Compute y1 */
		fp_copy(&tmp_x, &(in->x));
		fp_sqr(&tmp_x, &tmp_x);
		fp_copy(&tmp_y, &(in->y));
		fp_sqr(&tmp_y, &tmp_y);
		fp_set_word_value(&y1, WORD(2));
		fp_sub(&y1, &y1, &tmp_x);
		fp_sub(&y1, &y1, &tmp_y);
		fp_add(&tmp_x, &tmp_x, &tmp_y);
		/* NOTE: inversion by zero should be caught by lower layers */
		fp_inv(&tmp_x, &tmp_x);
		fp_mul(&y1, &y1, &tmp_x);
		if(eddsa_encode_integer(&(y1.fp_val), buf, buflen)){
			fp_uninit(&tmp_x);
			fp_uninit(&tmp_y);
			fp_uninit(&y1);
			ret = -1;
			goto err;
		}
		fp_uninit(&tmp_x);
		fp_uninit(&tmp_y);
		fp_uninit(&y1);
	}
	else
#endif /* !defined(WITH_SIG_EDDSA448) */
	{	/* EDDSA25519 and other cases */
		FORCE_USED_VAR(sig_alg); /* To avoid unused variable error */
		lsb = nn_getbit(&(in->x.fp_val), 0);
		if(eddsa_encode_integer(&(in->y.fp_val), buf, buflen)){
			ret = -1;
			goto err;
		}
	}
	/*
	 * Now deal with the sign for the last bit: copy the least significant
	 * bit of the x coordinate in the MSB of the last octet.
	 */
	if(buflen <= 1){
		ret = -1;
		goto err;
	}
	buf[buflen - 1] |= (u8)(lsb << 7);

	ret = 0;
err:
	nn_uninit(&out_reduced);
	return ret;
}

/* Decode an Edwards curve affine point from canonical form */
static int eddsa_decode_point(aff_pt_edwards_t out, ec_edwards_crv_src_t edwards_curve,
			      fp_src_t alpha_edwards, const u8 *buf, u16 buflen,
			      ec_sig_alg_type sig_type)
{
	fp x, y;
	fp sqrt1, sqrt2;
	u8 x_0;
	u8 buf_little_endian[MAX_DIGEST_SIZE];
	u32 i;
	int ret = -1;

#if defined(WITH_SIG_EDDSA448)
	const u8 d_edwards448_buff[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x67, 0x56
	};
	fp d_edwards448;
#endif

	if(buf == NULL){
		ret = -1;
		goto err;
	}
	if(!ec_edwards_crv_is_initialized(edwards_curve)){
		ret = -1;
		goto err;
	}
	if(!fp_is_initialized(alpha_edwards)){
		ret = -1;
		goto err;
	}
	/* Extract the sign */
	x_0 = (buf[buflen - 1] & 0x80) >> 7;
	/* Extract the value by reversing endianness */
	if(sizeof(buf_little_endian) < buflen){
		ret = -1;
		goto err;
	}
	/* Inverse endianness of our input buffer and mask the sign bit */
	if(buflen <= 1){
		ret = -1;
		goto err;
	}
	for(i = 0; i < buflen; i++){
		buf_little_endian[i] = buf[buflen - 1 - i];
		if(i == 0){
			/* Mask the sign bit */
			buf_little_endian[i] &= 0x7f;
		}
	}
	/* Try to decode the y coordinate */
	fp_init_from_buf(&y, edwards_curve->a.ctx, buf_little_endian, buflen);
	/*
	 * If we suceed, try to find our x coordinate that is the square root of
	 * (y^2 - 1) / (d y^2 + 1) or (y^2 - 1) / (d y^2 - 1) depending on the
	 * algorithm.
	 */
	fp_init(&sqrt1, edwards_curve->a.ctx);
	fp_init(&sqrt2, edwards_curve->a.ctx);
	fp_init(&x, edwards_curve->a.ctx);
	fp_sqr(&sqrt1, &y);
	fp_copy(&sqrt2, &sqrt1);
	fp_dec(&sqrt1, &sqrt1);
#if defined(WITH_SIG_EDDSA448)
	if((sig_type == EDDSA448) || (sig_type == EDDSA448PH)){
		/*
		 * If we deal with EDDSA448 we must handle the point on
		 * Edwards448 so we use the dedicated d.
		 */
		fp_init_from_buf(&d_edwards448, edwards_curve->a.ctx,
				 (const u8*)d_edwards448_buff,
				 sizeof(d_edwards448_buff));
		fp_mul(&sqrt2, &sqrt2, &d_edwards448);
		/* (d y^2 - 1) */
		fp_dec(&sqrt2, &sqrt2);
	}
	else
#endif /* !defined(WITH_SIG_EDDSA448) */
	{
		FORCE_USED_VAR(sig_type); /* To avoid unused variable error */
		fp_mul(&sqrt2, &sqrt2, &(edwards_curve->d));
		/* (d y^2 + 1) */
		fp_inc(&sqrt2, &sqrt2);
	}
	/* NOTE: inversion by zero should be caught by lower layers */
	fp_inv(&sqrt2, &sqrt2);
	fp_mul(&x, &sqrt1, &sqrt2);
	if(fp_sqrt(&sqrt1, &sqrt2, &x)){
		/* Error or no square root found, this should not happen! */
		ret = -1;
		goto err;
	}
	/* Now select the square root of the proper sign */
	if(nn_getbit(&(sqrt1.fp_val), 0) == x_0){
		fp_copy(&x, &sqrt1);
	}
	else{
		fp_copy(&x, &sqrt2);
	}
	/* If x = 0 and the sign bit is 1, this is an error */
	if(fp_iszero(&x) && (x_0 == 1)){
		ret = -1;
		goto err;
	}
	/*
	 * In case of EDDSA448, we apply the 4-isogeny to transfer from
	 * Edwards448 to Ed448.
	 * The isogeny maps (x1, y1) on Edwards448 to (x, y) on Ed448 using:
	 *	x = alpha_edwards * (x1*y1) / (2-x1^2-y1^2)
	 *      y = (x1^2+y1^2) / (y1^2-x1^2)
	 */
#if defined(WITH_SIG_EDDSA448)
	if((sig_type == EDDSA448) || (sig_type == EDDSA448PH)){
		/*
		 * Use sqrt1 and sqrt2 as temporary buffers for x and y, and
		 * d_edwards448 as scratch pad buffer
		 */
		fp_copy(&sqrt1, &x);
		fp_copy(&sqrt2, &y);

		fp_set_word_value(&x, WORD(2));
		fp_sqr(&d_edwards448, &sqrt1);
		fp_sub(&x, &x, &d_edwards448);
		fp_sqr(&d_edwards448, &sqrt2);
		fp_sub(&x, &x, &d_edwards448);
		/* NOTE: inversion by zero should be caught by lower layers */
		fp_inv(&x, &x);
		fp_mul(&x, &x, &sqrt1);
		fp_mul(&x, &x, &sqrt2);
		fp_mul(&x, &x, alpha_edwards);

		fp_sqr(&sqrt1, &sqrt1);
		fp_sqr(&sqrt2, &sqrt2);
		fp_sub(&y, &sqrt2, &sqrt1);
		/* NOTE: inversion by zero should be caught by lower layers */
		fp_inv(&y, &y);
		fp_add(&sqrt1, &sqrt1, &sqrt2);
		fp_mul(&y, &y, &sqrt1);
	}
#endif /* !defined(WITH_SIG_EDDSA448) */

	/* Initialize our point */
	aff_pt_edwards_init_from_coords(out, edwards_curve, &x, &y);

	ret = 0;

err:
	if(fp_is_initialized(&sqrt1)){
		fp_uninit(&sqrt1);
	}
	if(fp_is_initialized(&sqrt2)){
		fp_uninit(&sqrt2);
	}
	if(fp_is_initialized(&x)){
		fp_uninit(&x);
	}
	if(fp_is_initialized(&y)){
		fp_uninit(&y);
	}
#if defined(WITH_SIG_EDDSA448)
	if(fp_is_initialized(&d_edwards448)){
		fp_uninit(&d_edwards448);
	}
#endif
	return ret;
}


/*
 * Derive hash from private key.
 */
static int eddsa_derive_priv_key_hash(const ec_priv_key *in_priv,
				      u8 *buf, u16 buflen)
{
	hash_alg_type hash_type;
	const hash_mapping *hash;
	u8 x_buf[EC_PRIV_KEY_MAX_SIZE];
	int ret = -1;

	if(eddsa_priv_key_sanity_check(in_priv)){
		ret = -1;
		goto err;
	}

	if((hash_type = get_eddsa_hash_type(in_priv->key_type)) == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	if((hash = get_hash_by_type(hash_type)) == NULL){
		ret = -1;
		goto err;
	}
	/* Get the private key as a buffer and hash it */
	local_memset(x_buf, 0, sizeof(x_buf));
	if(sizeof(x_buf) < (hash->digest_size / 2)){
		ret = -1;
		goto err;
	}
	if(ec_priv_key_export_to_buf(in_priv, x_buf, (hash->digest_size / 2))){
		ret = -1;
		goto err;
	}
	if(hash_mapping_callbacks_sanity_check(hash)){
		ret = -1;
		goto err;
	}
	if(buflen < hash->digest_size){
		ret = -1;
		goto err;
	}
	const u8 *in[2] = { x_buf, NULL };
	u32 in_len[2] = { (hash->digest_size / 2), 0 };
	hash->hfunc_scattered(in, in_len, buf);

	ret = 0;
err:
	PTR_NULLIFY(hash);
	VAR_ZEROIFY(hash_type);

	return ret;
}

/*
 * Derive an EdDSA private key.
 *
 */
int eddsa_derive_priv_key(ec_priv_key *priv_key)
{
	int ret = -1;
	u8 digest_size;
	u8 digest[MAX_DIGEST_SIZE];
	hash_alg_type hash_type;

	/* Check if private key is initialized. */
	if(eddsa_priv_key_sanity_check(priv_key)){
		ret = -1;
		goto err;
	}

	/* Check hash function compatibility:
	 *   We must have 2**(b-1) > p with (2*b) the size of the hash function.
	 */
	if((hash_type = get_eddsa_hash_type(priv_key->key_type)) == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	digest_size = 0;
	if(get_hash_sizes(hash_type, &digest_size, NULL)){
		ret = -1;
		goto err;
	}
	if((2 * priv_key->params->ec_fp.p_bitlen) >= (8 * (bitcnt_t)digest_size)){
		ret = -1;
		goto err;
	}
	if((digest_size % 2) != 0){
		ret = -1;
		goto err;
	}
	if(digest_size > sizeof(digest)){
		ret = -1;
		goto err;
	}

	/*
	 * Now that we have our private scalar, derive the hash value of secret
	 * key
	 */
	/* Hash the private key */
	if(eddsa_derive_priv_key_hash(priv_key, digest, digest_size)){
		ret = -1;
		goto err;
	}
	/* Get the cofactor as an integer */
	word_t cofactor = priv_key->params->ec_gen_cofactor.val[0];
	if(nn_cmp_word(&(priv_key->params->ec_gen_cofactor), cofactor) != 0){
		ret = -1;
		goto err;
	}
	/* Cofactor must be 2**2 or 2**3 as per RFC8032 standard */
	if((cofactor != (0x1 << 2)) && (cofactor != (0x1 << 3))){
		ret = -1;
		goto err;
	}

	/* Now clear the low bits related to cofactor */
	digest[0] &= ~(cofactor - 1);
#if defined(WITH_SIG_EDDSA25519)
	if ((priv_key->key_type == EDDSA25519) ||
	    (priv_key->key_type == EDDSA25519CTX) ||
	    (priv_key->key_type == EDDSA25519PH)){
		/*
		 * MSB of highest octet of half must be cleared, second MSB must
		 * be set
		 */
		digest[(digest_size / 2) - 1] &= 0x7f;
		digest[(digest_size / 2) - 1] |= 0x40;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if ((priv_key->key_type == EDDSA448) || (priv_key->key_type == EDDSA448PH)) {
		if((digest_size / 2) < 2){
			ret = -1;
			goto err;
		}
		/*
		 * All eight bits of the last octet are cleared, highest bit
		 * of the second to last octet is set.
		 */
		digest[(digest_size / 2) - 1] = 0;
		digest[(digest_size / 2) - 2] |= 0x80;
	}
#endif
#if !defined(WITH_SIG_EDDSA25519) && !defined(WITH_SIG_EDDSA448)
	ret = -1;
	goto err;
#endif
	/*
	 * Now that we have derived our hash, store it in place of our secret
	 * value NOTE: we do not need the secret value anymore since only the
	 * hash is needed.
	 */
	nn_init_from_buf(&(priv_key->x), digest, digest_size);

	ret = 0;
err:
	VAR_ZEROIFY(hash_type);
	VAR_ZEROIFY(digest_size);

	return ret;
}

/*
 * Generate an EdDSA private key.
 *
 */
int eddsa_gen_priv_key(ec_priv_key *priv_key)
{
	int ret = -1;
	u8 digest_size;
	hash_alg_type hash_type;

	/* Check if private key is initialized. */
	if(eddsa_priv_key_sanity_check(priv_key)){
		ret = -1;
		goto err;
	}

	/* Check hash function compatibility:
	 *   We must have 2**(b-1) > p with (2*b) the size of the hash function.
	 */
	if((hash_type = get_eddsa_hash_type(priv_key->key_type)) == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	digest_size = 0;
	if(get_hash_sizes(hash_type, &digest_size, NULL)){
		ret = -1;
		goto err;
	}
	if((2 * priv_key->params->ec_fp.p_bitlen) >= (8 * (bitcnt_t)digest_size)){
		ret = -1;
		goto err;
	}
	if((digest_size % 2) != 0){
		ret = -1;
		goto err;
	}

	/* Generate a random private key
	 * An EdDSA secret scalar is a b bit string with (2*b) the size of the hash function
	 */
	ret = nn_get_random_len(&(priv_key->x), (digest_size / 2));
	if (ret) {
		ret = -1;
		goto err;
	}

	/* Derive the private key */
	if(eddsa_derive_priv_key(priv_key)){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	VAR_ZEROIFY(hash_type);
	VAR_ZEROIFY(digest_size);

	return ret;
}


/* Import an EdDSA private key from a raw buffer.
 * NOTE: the private key must be a big number associated to the curve that
 * depends on the flavor of EdDSA (Ed25519 or Ed448), and the result is a
 * derived private key that can be used by the internal EdDSA functions.
 * The derived key is a hash of the private key: we mainly perform this
 * derivation early to prevent side-channel attacks and other leaks on the
 * "root" private key.
 */
int eddsa_import_priv_key(ec_priv_key *priv_key, const u8 *buf, u16 buflen,
			  const ec_params *shortw_curve_params,
			  ec_sig_alg_type sig_type)
{
	int ret = -1;
	hash_alg_type hash_type;
	u8 digest_size;

	/* Some sanity checks */
	if((priv_key == NULL) || (buf == NULL) || (shortw_curve_params == NULL)){
		ret = -1;
		goto err;
	}
	/* Import the big number from our buffer */
	nn_init_from_buf(&(priv_key->x), buf, buflen);
	/* The bit length of our big number must be <= b, half the digest size */
	hash_type = get_eddsa_hash_type(sig_type);
	if(hash_type == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	digest_size = 0;
	if(get_hash_sizes(hash_type, &digest_size, NULL)){
		ret = -1;
		goto err;
	}
	if(nn_bitlen(&(priv_key->x)) > (8 * ((bitcnt_t)digest_size / 2))){
		ret = -1;
		goto err;
	}

	/* Initialize stuff */
	priv_key->key_type = sig_type;
	priv_key->params = shortw_curve_params;
	priv_key->magic = PRIV_KEY_MAGIC;

	/* Now derive the private key.
	 * NOTE: sanity check on the private key is performed during derivation.
	 */
	if(eddsa_derive_priv_key(priv_key)){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	if((priv_key != NULL) && (ret != 0)){
		local_memset(priv_key, 0, sizeof(ec_priv_key));
	}
	VAR_ZEROIFY(hash_type);
	VAR_ZEROIFY(digest_size);

	return ret;
}

/* NOTE: we perform EDDSA public key computation on the short Weierstrass
 * form of the curve thanks to the birational equivalence of curve
 * models (the isomorphism allows to perform the scalar multiplication
 * on the equivalent curve).
 */
int eddsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	prj_pt_src_t G;
	u8 digest_size;
	u8 digest[MAX_DIGEST_SIZE];
	/* Secret scalar used for public generation */
	nn s;
	hash_alg_type hash_type;
	int ret = -1;

	MUST_HAVE(out_pub != NULL);

	nn_init(&s, 0);

	/* Zero init public key to be generated */
	local_memset(out_pub, 0, sizeof(ec_pub_key));

	/* Check if private key is initialized and everything is OK with it */
	if(eddsa_priv_key_sanity_check(in_priv)){
		ret = -1;
		goto err;
	}

	/* Get the generator G */
	G = &(in_priv->params->ec_gen);

	/* Get the digest in proper format */
	if((hash_type = get_eddsa_hash_type(in_priv->key_type)) == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	u8 digest_size_;
	digest_size_ = 0;
	if(get_hash_sizes(hash_type, &digest_size_, NULL)){
		ret = -1;
		goto err;
	}
	/* Extract the digest */
	digest_size = sizeof(digest);
	if(eddsa_get_digest_from_priv_key(digest, &digest_size, in_priv)){
		ret = -1;
		goto err;
	}
	/* Sanity check */
	if(digest_size != digest_size_){
		ret = -1;
		goto err;
	}
	/* Encode the scalar s from the digest */
	if(eddsa_compute_s(&s, digest, digest_size)){
		ret = -1;
		goto err;
	}
	/* Compute s x G where G is the base point */
	/*
	 * Use blinding when computing point scalar multiplication as we
	 * manipulate a fixed secret.
	 */
#if defined(WITH_SIG_EDDSA448)
	if((in_priv->key_type == EDDSA448) || (in_priv->key_type == EDDSA448PH)){
		/*
		 * NOTE: because of the 4-isogeny between Ed448 and Edwards448,
		 * we actually multiply by (s/4) since the base point of
		 * Edwards448 is four times the one of Ed448.
		 * Here, s/4 can be simply computed by right shifting by 2 as
		 * we are ensured that our scalar is a multiple of 4 by
		 * construction.
		 */
		nn_rshift(&s, &s, 2);
	}
#endif
	if(prj_pt_mul_monty_blind(&(out_pub->y), &s, G)){
		ret = -1;
		goto err;
	}

	out_pub->key_type = in_priv->key_type;
	out_pub->params = in_priv->params;
	out_pub->magic = PUB_KEY_MAGIC;

	ret = 0;
err:
	PTR_NULLIFY(G);
	VAR_ZEROIFY(digest_size);
	nn_uninit(&s);
	return ret;
}

/*
 * Import a public key in canonical form.
 * (imports a public key from a buffer and checks its canonical form.)
 *
 */
int eddsa_import_pub_key(ec_pub_key *pub_key, const u8 *buf, u16 buflen,
			 const ec_params *shortw_curve_params,
			 ec_sig_alg_type sig_type)
{
	aff_pt_edwards _Tmp;
	ec_edwards_crv edwards_curve;
	int ret;
	ec_shortw_crv_src_t shortw_curve;
	fp_src_t alpha_montgomery;
	fp_src_t gamma_montgomery;
	fp_src_t alpha_edwards;
	prj_pt_t pub_key_y;

	ret = -1;

#if defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_EDDSA448)
	if((sig_type != EDDSA25519) && (sig_type != EDDSA25519CTX) && (sig_type != EDDSA25519PH) && \
	   (sig_type != EDDSA448) && (sig_type != EDDSA448PH)){
#endif
#if defined(WITH_SIG_EDDSA25519) && !defined(WITH_SIG_EDDSA448)
	if((sig_type != EDDSA25519) && (sig_type != EDDSA25519CTX) && (sig_type != EDDSA25519PH)){
#endif
#if !defined(WITH_SIG_EDDSA25519) && defined(WITH_SIG_EDDSA448)
	if((sig_type != EDDSA448) && (sig_type != EDDSA448PH)){
#endif
		ret = -1;
		goto err;
	}
	if(pub_key == NULL){
		ret = -1;
		goto err;
	}
	/* Handle our short Weierstrass curve */
	if(shortw_curve_params == NULL){
		ret = -1;
		goto err;
	}
	/* Make things more readable */
	shortw_curve = &(shortw_curve_params->ec_curve);
	alpha_montgomery = &(shortw_curve_params->ec_alpha_montgomery);
	gamma_montgomery = &(shortw_curve_params->ec_gamma_montgomery);
	alpha_edwards = &(shortw_curve_params->ec_alpha_edwards);
	pub_key_y = &(pub_key->y);

	/* Get the isogenic Edwards curve */
	curve_shortw_to_edwards(shortw_curve, &edwards_curve, alpha_montgomery,
				gamma_montgomery, alpha_edwards);

	/* Decode the point in Edwards */
	if(eddsa_decode_point(&_Tmp, &edwards_curve, alpha_edwards, buf, buflen,
			      sig_type)){
		ret = -1;
		goto err;
	}
	/* Then transfer to short Weierstrass in our public key */
	aff_pt_edwards_to_prj_pt_shortw(&_Tmp, shortw_curve, pub_key_y,
					alpha_edwards);
#if defined(WITH_SIG_EDDSA448)
	if((sig_type == EDDSA448) || (sig_type == EDDSA448PH)){
		nn_src_t gen_order = &(shortw_curve_params->ec_gen_order);
		nn tmp;
		/*
		 * NOTE: because of the 4-isogeny between Ed448 and Edwards448,
		 * we actually multiply by (s/4) since the base point of
		 * Edwards448 is four times the one of Ed448.
		 * Here, s/4 is computed by multiplying s by the modular
		 * inverse of 4.
		 */
		nn_init(&tmp, 0);
		nn_modinv_word(&tmp, WORD(4), gen_order);
		prj_pt_mul_monty(&(pub_key->y), &tmp, pub_key_y);
		nn_uninit(&tmp);
		PTR_NULLIFY(gen_order);
	}
#endif
	/* Mark the public key as initialized */
	pub_key->key_type = sig_type;
	pub_key->params = shortw_curve_params;
	pub_key->magic = PUB_KEY_MAGIC;

	/* Now sanity check our public key before validating the import */
	if(eddsa_pub_key_sanity_check(pub_key)){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	if((pub_key != NULL) && (ret != 0)){
		local_memset(pub_key, 0, sizeof(ec_pub_key));
	}
	PTR_NULLIFY(shortw_curve);
	PTR_NULLIFY(alpha_montgomery);
	PTR_NULLIFY(gamma_montgomery);
	PTR_NULLIFY(alpha_edwards);
	PTR_NULLIFY(pub_key_y);
	if(aff_pt_edwards_is_initialized(&_Tmp)){
		aff_pt_edwards_uninit(&_Tmp);
	}
	if(ec_edwards_crv_is_initialized(&edwards_curve)){
		ec_edwards_crv_uninit(&edwards_curve);
	}

	return ret;
}

/*
 * Export a public key in canonical form.
 * (exports a public key to a buffer in canonical form.)
 */
int eddsa_export_pub_key(const ec_pub_key *in_pub, u8 *buf, u16 buflen)
{
	aff_pt_edwards _Tmp;
	ec_edwards_crv edwards_curve;
	int ret;
	ec_shortw_crv_src_t shortw_curve;
	fp_src_t alpha_montgomery;
	fp_src_t gamma_montgomery;
	fp_src_t alpha_edwards;
	prj_pt_src_t pub_key_y;

	ret = -1;

	if(pub_key_is_initialized(in_pub)){
		ret = -1;
		goto err;
	}
	/* Make things more readable */
	shortw_curve = &(in_pub->params->ec_curve);
	alpha_montgomery = &(in_pub->params->ec_alpha_montgomery);
	gamma_montgomery = &(in_pub->params->ec_gamma_montgomery);
	alpha_edwards = &(in_pub->params->ec_alpha_edwards);
	pub_key_y = &(in_pub->y);

	/* Transfer our short Weierstrass to Edwards representation */
	curve_shortw_to_edwards(shortw_curve, &edwards_curve, alpha_montgomery,
				gamma_montgomery, alpha_edwards);
	prj_pt_shortw_to_aff_pt_edwards(pub_key_y, &edwards_curve, &_Tmp,
					alpha_edwards);
	/* Export to buffer canonical form */
	if(eddsa_encode_point(&_Tmp, alpha_edwards, buf,
			      buflen,in_pub->key_type)){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	PTR_NULLIFY(shortw_curve);
	PTR_NULLIFY(alpha_montgomery);
	PTR_NULLIFY(gamma_montgomery);
	PTR_NULLIFY(alpha_edwards);
	PTR_NULLIFY(pub_key_y);
	if(aff_pt_edwards_is_initialized(&_Tmp)){
		aff_pt_edwards_uninit(&_Tmp);
	}
	if(ec_edwards_crv_is_initialized(&edwards_curve)){
		ec_edwards_crv_uninit(&edwards_curve);
	}

	return ret;
}

/* Import an EdDSA key pair from a private key buffer */
int eddsa_import_key_pair_from_priv_key_buf(ec_key_pair *kp,
					    const u8 *buf, u16 buflen,
					    const ec_params *shortw_curve_params,
					    ec_sig_alg_type sig_type)
{
	int ret = -1;

	if(kp == NULL){
		ret = -1;
		goto err;
	}

	/* Try to import the private key */
	if(eddsa_import_priv_key(&(kp->priv_key), buf, buflen,
				 shortw_curve_params, sig_type)){
		ret = -1;
		goto err;
	}
	/* Now derive the public key */
	if(eddsa_init_pub_key(&(kp->pub_key), &(kp->priv_key))){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	return ret;
}

/* Compute PH(M) with PH being the hash depending on the key type */
static int eddsa_compute_pre_hash(const u8 *message, u32 message_size,
				  u8 *digest, u8 *digest_size,
				  ec_sig_alg_type sig_type)
{
	hash_alg_type hash_type;
	const hash_mapping *hash;
	hash_context hash_ctx;
	int ret = -1;

	if((message == NULL) || (digest == NULL) || (digest_size == NULL)){
		ret = -1;
		goto err;
	}

	if((hash_type = get_eddsa_hash_type(sig_type)) == UNKNOWN_HASH_ALG){
		ret = -1;
		goto err;
	}
	if((hash = get_hash_by_type(hash_type)) == NULL){
		ret = -1;
		goto err;
	}
	/* Sanity check on the size */
	if((*digest_size) < hash->digest_size){
		ret = -1;
		goto err;
	}
	*digest_size = hash->digest_size;
	/* Hash the message */
	if(hash_mapping_callbacks_sanity_check(hash)){
		ret = -1;
		goto err;
	}
	hash->hfunc_init(&hash_ctx);
	hash->hfunc_update(&hash_ctx, message, message_size);
	hash->hfunc_finalize(&hash_ctx, digest);

	ret = 0;
err:
	return ret;
}

/*****************/

/* EdDSA signature length */
u8 eddsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize)
{
	MUST_HAVE((p_bit_len <= CURVES_MAX_P_BIT_LEN) &&
		  (q_bit_len <= CURVES_MAX_Q_BIT_LEN) &&
		  (hsize <= MAX_DIGEST_SIZE) && (blocksize <= MAX_BLOCK_SIZE));

	return (u8)EDDSA_SIGLEN(hsize);
}

/*
 * Generic *internal* EdDSA signature functions (init, update and finalize).
 *
 * Global EdDSA signature process is as follows (I,U,F provides
 * information in which function(s) (init(), update() or finalize())
 * a specific step is performed):
 *
 */

#define EDDSA_SIGN_MAGIC ((word_t)(0x7632542bf630972bULL))
#define EDDSA_SIGN_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == EDDSA_SIGN_MAGIC))

int _eddsa_sign_init_pre_hash(struct ec_sign_context *ctx)
{
	int ret = -1;
	u8 use_message_pre_hash = 0;
	ec_sig_alg_type key_type;

	/* First, verify context has been initialized */
	SIG_SIGN_CHECK_INITIALIZED(ctx);

	/* Make things more readable */
	const ec_key_pair *key_pair = ctx->key_pair;
	const hash_mapping *h = ctx->h;
	key_type = ctx->key_pair->priv_key.key_type;

	/* Sanity check: this function is only supported in PH mode */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		use_message_pre_hash = 1;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		use_message_pre_hash = 1;
	}
#endif
	if(use_message_pre_hash != 1){
		ret = -1;
		goto err;
	}

	/* Sanity check on hash types */
	if((key_type != key_pair->pub_key.key_type) ||
	   (h->type != get_eddsa_hash_type(key_type))){
		ret = -1;
		goto err;
	}

	/* Additional sanity checks on input params from context */
	if(eddsa_key_pair_sanity_check(key_pair)){
		ret = -1;
		goto err;
	}
	if ((!h) || (h->digest_size > MAX_DIGEST_SIZE) ||
	    (h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/*
	 * Sanity check on hash size versus private key size
	 */
	if(nn_bitlen(&(key_pair->priv_key.x)) > (8 * h->digest_size)){
		ret = -1;
		goto err;
	}

	/*
	 * Initialize hash context stored in our private part of context
	 * and record data init has been done
	 */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(h)){
		ret = -1;
		goto err;
	}
	h->hfunc_init(&(ctx->sign_data.eddsa.h_ctx));

	/* Initialize other elements in the context */
	ctx->sign_data.eddsa.magic = EDDSA_SIGN_MAGIC;

	ret = 0;

err:
	PTR_NULLIFY(key_pair);
	PTR_NULLIFY(h);
	VAR_ZEROIFY(key_type);
	VAR_ZEROIFY(use_message_pre_hash);

	return ret;
}

int _eddsa_sign_update_pre_hash(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen)
{
	int ret = -1;
	ec_sig_alg_type key_type;
	u8 use_message_pre_hash = 0;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EDDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	EDDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.eddsa));

	key_type = ctx->key_pair->priv_key.key_type;

	/* Sanity check: this function is only supported in PH mode */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		use_message_pre_hash = 1;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		use_message_pre_hash = 1;
	}
#endif
	if(use_message_pre_hash != 1){
		ret = -1;
		goto err;
	}

	/* Sanity check on hash types */
	if(ctx->h->type != get_eddsa_hash_type(key_type)){
		ret = -1;
		goto err;
	}

	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_update(&(ctx->sign_data.eddsa.h_ctx), chunk, chunklen);

	ret = 0;
err:
	VAR_ZEROIFY(key_type);
	VAR_ZEROIFY(use_message_pre_hash);
	return ret;

}

int _eddsa_sign_finalize_pre_hash(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	nn r, s, S;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif
	const ec_priv_key *priv_key;
	const ec_pub_key *pub_key;
	prj_pt_src_t G;
	u8 hash[MAX_DIGEST_SIZE];
	u8 ph_hash[MAX_DIGEST_SIZE];
	prj_pt R;
	ec_edwards_crv crv_edwards;
	aff_pt_edwards Tmp_edwards;
	nn_src_t q;
	u8 hsize, hash_size;
	int ret;
	ec_shortw_crv_src_t shortw_curve;
	fp_src_t alpha_montgomery;
	fp_src_t gamma_montgomery;
	fp_src_t alpha_edwards;
	prj_pt_src_t pub_key_y;
	u8 use_message_pre_hash = 0;
	u16 use_message_pre_hash_hsize = 0;
	ec_sig_alg_type key_type;
	u8 r_len, s_len;

	ret = -1;
	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EDDSA
	 * signature one and we do not update() or finalize()
	 * before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	EDDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.eddsa));
	MUST_HAVE(sig != NULL);

	/* Zero init out points and data */
	local_memset(&R, 0, sizeof(prj_pt));
	local_memset(&Tmp_edwards, 0, sizeof(aff_pt_edwards));
	local_memset(&crv_edwards, 0, sizeof(ec_edwards_crv));
	local_memset(hash, 0, sizeof(hash));
	local_memset(ph_hash, 0, sizeof(ph_hash));

	/* Key type */
	key_type = ctx->key_pair->priv_key.key_type;
	/* Sanity check on hash types */
	if((key_type != ctx->key_pair->pub_key.key_type) || \
	   (ctx->h->type != get_eddsa_hash_type(key_type))){
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	pub_key = &(ctx->key_pair->pub_key);
	q = &(priv_key->params->ec_gen_order);
	G = &(priv_key->params->ec_gen);
	const hash_mapping *h = ctx->h;
	hsize = h->digest_size;
	r_len = EDDSA_R_LEN(hsize);
	s_len = EDDSA_S_LEN(hsize);

	shortw_curve = &(priv_key->params->ec_curve);
	alpha_montgomery = &(priv_key->params->ec_alpha_montgomery);
	gamma_montgomery = &(priv_key->params->ec_gamma_montgomery);
	alpha_edwards = &(priv_key->params->ec_alpha_edwards);
	pub_key_y = &(pub_key->y);

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", &(priv_key->params->ec_gen_order));
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", &(priv_key->params->ec_gen));
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));

	/* Check provided signature length */
	if((siglen != EDDSA_SIGLEN(hsize)) || (siglen != (r_len + s_len))){
		ret = -1;
		goto err;
	}
	/* Is it indeed a PH version of the algorithm? */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		use_message_pre_hash = 1;
		use_message_pre_hash_hsize = hsize;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		use_message_pre_hash = 1;
		/* NOTE: as per RFC8032, EDDSA448PH uses
		 * SHAKE256 with 64 bytes output.
		 */
		use_message_pre_hash_hsize = 64;
	}
#endif
	/* Sanity check: this function is only supported in PH mode */
	if(use_message_pre_hash != 1){
		ret = -1;
		goto err;
	}

	/* Finish the message hash session */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(h)){
		ret = -1;
		goto err;
	}
	h->hfunc_finalize(&(ctx->sign_data.eddsa.h_ctx), ph_hash);

	/* 1. Finish computing the nonce r = H(h256 || ... || h511 || m) */
	/* Update our hash context with half of the secret key */
	hash_size = sizeof(hash);
	if(eddsa_get_digest_from_priv_key(hash, &hash_size, priv_key)){
		ret = -1;
		goto err;
	}
	/* Sanity check */
	if(hash_size != hsize){
		ret = -1;
		goto err;
	}
	/* Hash half the digest */
	h->hfunc_init(&(ctx->sign_data.eddsa.h_ctx));
	/* At this point, we are ensured that we have PH versions of the algorithms */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		if(dom2(1, ctx->adata, ctx->adata_len, h,
			&(ctx->sign_data.eddsa.h_ctx))){
			ret = -1;
			goto err;
		}
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		if(dom4(1, ctx->adata, ctx->adata_len, h,
			&(ctx->sign_data.eddsa.h_ctx))){
			ret = -1;
			goto err;
		}
	}
#endif
	h->hfunc_update(&(ctx->sign_data.eddsa.h_ctx), &hash[hsize / 2], hsize / 2);

	/* Update hash h with message hash PH(m) */
	if(use_message_pre_hash_hsize > hsize){
		ret = -1;
		goto err;
	}
	h->hfunc_update(&(ctx->sign_data.eddsa.h_ctx), ph_hash,
			use_message_pre_hash_hsize);

	/* 1. Finish computing the nonce r = H(h256 || ... || h511 || PH(m)) */
	h->hfunc_finalize(&(ctx->sign_data.eddsa.h_ctx), hash);
	dbg_buf_print("h(h || m)", hash, hsize);

	/* Import r as the hash scalar */
	if(eddsa_decode_integer(&r, hash, hsize)){
		ret = -1;
		goto err;
	}
	/* Reduce r modulo q for the next computation */
	nn_mod(&r, &r, q);
	/* Now perform our scalar multiplication.
	 */
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		/*
		 * NOTE: in case of EDDSA448, because of the 4-isogeny we must
		 * divide our scalar by 4.
		 */
		nn r_tmp;
		nn_init(&r_tmp, 0);
		nn_modinv_word(&r_tmp, WORD(4), q);
		nn_mul_mod(&r_tmp, &r_tmp, &r, q);
#ifdef USE_SIG_BLINDING
		if(prj_pt_mul_monty_blind(&R, &r_tmp, G)){
			ret = -1;
			goto err;
		}
#else
		prj_pt_mul_monty(&R, &r_tmp, G);
#endif
		nn_uninit(&r_tmp);
	}
	else
#endif /* !defined(WITH_SIG_EDDSA448) */
	{
#ifdef USE_SIG_BLINDING
		if(prj_pt_mul_monty_blind(&R, &r, G)){
			ret = -1;
			goto err;
		}
#else
		prj_pt_mul_monty(&R, &r, G);
#endif
	}

	/* Now compute S = (r + H(R || PubKey || PH(m)) * secret) mod q */
	h->hfunc_init(&(ctx->sign_data.eddsa.h_ctx));
	/* Transfer R to Edwards */
	curve_shortw_to_edwards(shortw_curve, &crv_edwards, alpha_montgomery,
				gamma_montgomery, alpha_edwards);
	prj_pt_shortw_to_aff_pt_edwards(&R, &crv_edwards, &Tmp_edwards,
					alpha_edwards);
	dbg_ec_edwards_point_print("R", &Tmp_edwards);
	if(r_len > siglen){
		ret = -1;
		goto err;
	}
	/* Encode R and update */
	if(eddsa_encode_point(&Tmp_edwards, alpha_edwards, &sig[0],
			      r_len, key_type)){
		ret = -1;
		goto err;
	}
	/* At this point, we are ensured that we have PH versions of the algorithms */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		if(dom2(1, ctx->adata, ctx->adata_len, h,
			&(ctx->sign_data.eddsa.h_ctx))){
			ret = -1;
			goto err;
		}
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		if(dom4(1, ctx->adata, ctx->adata_len, h,
			&(ctx->sign_data.eddsa.h_ctx))){
			ret = -1;
			goto err;
		}
	}
#endif
	/* Update the hash with the encoded R point */
	h->hfunc_update(&(ctx->sign_data.eddsa.h_ctx), &sig[0], r_len);
	/* Encode the public key */
	/* Transfer the public key to Edwards */
	prj_pt_shortw_to_aff_pt_edwards(pub_key_y, &crv_edwards,
					&Tmp_edwards, alpha_edwards);
	dbg_ec_edwards_point_print("A", &Tmp_edwards);
	if(r_len > sizeof(hash)){
		ret = -1;
		goto err;
	}
	/* NOTE: we use the hash buffer as a temporary buffer */
	if(eddsa_encode_point(&Tmp_edwards, alpha_edwards, hash,
			      r_len, key_type)){
		ret = -1;
		goto err;
	}
	/* Update the hash with the encoded public key point */
	h->hfunc_update(&(ctx->sign_data.eddsa.h_ctx), hash, r_len);
	/* Update the hash with PH(m) */
	h->hfunc_update(&(ctx->sign_data.eddsa.h_ctx), ph_hash,
			use_message_pre_hash_hsize);
	/* Finalize the hash */
	h->hfunc_finalize(&(ctx->sign_data.eddsa.h_ctx), hash);
	dbg_buf_print("h(R || PubKey || PH(m))", hash, hsize);
	/* Import our resulting hash as an integer in S */
	if(eddsa_decode_integer(&S, hash, hsize)){
		ret = -1;
		goto err;
	}
	nn_mod(&S, &S, q);
	/* Extract the digest */
	hsize = sizeof(hash);
	if(eddsa_get_digest_from_priv_key(hash, &hsize, priv_key)){
		ret = -1;
		goto err;
	}
	/* Encode the scalar s from the digest */
	if(eddsa_compute_s(&s, hash, hsize)){
		goto err;
	}
	nn_mod(&s, &s, q);

#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, r and H(R || PubKey || m) are multiplied by
	 * a random value b in ]0,q[ */
	ret = nn_get_random_mod(&b, q);
	if (ret) {
		ret = -1;
		goto err;
	}
	dbg_nn_print("b", &b);
	nn_modinv(&binv, &b, q);
	/* If we use blinding, multiply by b */
	nn_mul_mod(&S, &S, &b, q);
	nn_mul_mod(&r, &r, &b, q);
#endif
	/* Multiply by the secret */
	nn_mul_mod(&S, &S, &s, q);
	/* The secret is not needed anymore */
	nn_uninit(&s);
	/* Add to r */
	nn_mod_add(&S, &S, &r, q);
#ifdef USE_SIG_BLINDING
	/* Unblind the result */
	nn_mul_mod(&S, &S, &binv, q);
#endif
	/* Store our S in the context as an encoded buffer */
	if(s_len > (siglen - r_len)){
		ret = -1;
		goto err;
	}
	if(eddsa_encode_integer(&S, &sig[r_len], s_len)){
		ret = -1;
		goto err;
	}

	ret = 0;
 err:
	/* Clean what remains on the stack */
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(pub_key);
	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(shortw_curve);
	PTR_NULLIFY(alpha_montgomery);
	PTR_NULLIFY(gamma_montgomery);
	PTR_NULLIFY(alpha_edwards);
	PTR_NULLIFY(pub_key_y);
	VAR_ZEROIFY(hsize);
	VAR_ZEROIFY(hash_size);
	VAR_ZEROIFY(key_type);
	VAR_ZEROIFY(use_message_pre_hash);
	VAR_ZEROIFY(use_message_pre_hash_hsize);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);

	if(prj_pt_is_initialized(&R)){
		prj_pt_uninit(&R);
	}
	if(ec_edwards_crv_is_initialized(&crv_edwards)){
		ec_edwards_crv_uninit(&crv_edwards);
	}
	if(aff_pt_edwards_is_initialized(&Tmp_edwards)){
		aff_pt_edwards_uninit(&Tmp_edwards);
	}
	if(nn_is_initialized(&s)){
		nn_uninit(&s);
	}
	if(nn_is_initialized(&r)){
		nn_uninit(&r);
	}
	if(nn_is_initialized(&S)){
		nn_uninit(&S);
	}

#ifdef USE_SIG_BLINDING
	if(nn_is_initialized(&b)){
		nn_uninit(&b);
	}
	if(nn_is_initialized(&binv)){
		nn_uninit(&binv);
	}
#endif /* USE_SIG_BLINDING */
	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.eddsa), 0, sizeof(eddsa_sign_data));
	local_memset(ph_hash, 0, sizeof(ph_hash));

	return ret;
}


/******** Signature function specific to pure EdDSA where the message
********* streaming mode via init/update/finalize is not supported.
 */
int _eddsa_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
		const u8 *m, u32 mlen, int (*rand) (nn_t out, nn_src_t q),
		ec_sig_alg_type sig_type, hash_alg_type hash_type,
		const u8 *adata, u16 adata_len)
{
	nn r, s, S;
#ifdef USE_SIG_BLINDING
	/* b is the blinding mask */
	nn b, binv;
#endif
	int ret = -1;
	ec_sig_alg_type key_type;
	ec_shortw_crv_src_t shortw_curve;
	fp_src_t alpha_montgomery;
	fp_src_t gamma_montgomery;
	fp_src_t alpha_edwards;
	prj_pt_src_t pub_key_y;
	u8 use_message_pre_hash = 0;
	u16 use_message_pre_hash_hsize = 0;
	prj_pt_src_t G;
	prj_pt R;
	aff_pt_edwards Tmp_edwards;
	ec_edwards_crv crv_edwards;
	u8 hash[MAX_DIGEST_SIZE];
	u8 ph_hash[MAX_DIGEST_SIZE];
	const ec_priv_key *priv_key;
	const ec_pub_key *pub_key;
	nn_src_t q;
	u8 hsize, hash_size;
	hash_context h_ctx;
	u8 r_len, s_len;

	/*
	 * NOTE: EdDSA does not use any notion of random Nonce, so no need
	 * to use 'rand' here: we strictly check that NULL is provided.
	 */
	if(rand != NULL){
		ret = -1;
		goto err;
	}

	/* Zero init out points and data */
	local_memset(&R, 0, sizeof(prj_pt));
	local_memset(&Tmp_edwards, 0, sizeof(aff_pt_edwards));
	local_memset(&crv_edwards, 0, sizeof(ec_edwards_crv));
	local_memset(hash, 0, sizeof(hash));
	local_memset(ph_hash, 0, sizeof(ph_hash));

	/* Sanity check on the key pair */
	if(eddsa_key_pair_sanity_check(key_pair)){
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	const hash_mapping *h = get_hash_by_type(hash_type);
	key_type = key_pair->priv_key.key_type;

	/* Sanity check on the hash type */
	if(h == NULL){
		ret = -1;
		goto err;
	}
	if(get_eddsa_hash_type(sig_type) != hash_type){
		ret = -1;
		goto err;
	}
	/* Sanity check on the key type */
	if(key_type != sig_type){
		ret = -1;
		goto err;
	}
	if ((!h) || (h->digest_size > MAX_DIGEST_SIZE) ||
	    (h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}
	/*
	 * Sanity check on hash size versus private key size
	 */
	if(nn_bitlen(&(key_pair->priv_key.x)) > (8 * h->digest_size)){
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	priv_key = &(key_pair->priv_key);
	pub_key = &(key_pair->pub_key);
	q = &(priv_key->params->ec_gen_order);
	G = &(priv_key->params->ec_gen);
	hsize = h->digest_size;
	r_len = EDDSA_R_LEN(hsize);
	s_len = EDDSA_S_LEN(hsize);

	shortw_curve = &(priv_key->params->ec_curve);
	alpha_montgomery = &(priv_key->params->ec_alpha_montgomery);
	gamma_montgomery = &(priv_key->params->ec_gamma_montgomery);
	alpha_edwards = &(priv_key->params->ec_alpha_edwards);
	pub_key_y = &(pub_key->y);

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", &(priv_key->params->ec_gen_order));
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", &(priv_key->params->ec_gen));
	dbg_pub_key_print("Y", &(pub_key));

	/* Check provided signature length */
	if((siglen != EDDSA_SIGLEN(hsize)) || (siglen != (r_len + s_len))){
		ret = -1;
		goto err;
	}
	/* Do we use the raw message or its PH(M) hashed version? */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		use_message_pre_hash = 1;
		use_message_pre_hash_hsize = hsize;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		use_message_pre_hash = 1;
		/* NOTE: as per RFC8032, EDDSA448PH uses
		 * SHAKE256 with 64 bytes output.
		 */
		use_message_pre_hash_hsize = 64;
	}
#endif
	/* First of all, compute the message hash if necessary */
	if(use_message_pre_hash){
		hash_size = sizeof(ph_hash);
		if(eddsa_compute_pre_hash(m, mlen, ph_hash, &hash_size, sig_type)){
			ret = -1;
			goto err;
		}
		if(use_message_pre_hash_hsize > hash_size){
			ret = -1;
			goto err;
		}
	}
	/* Initialize our hash context */
	/* Compute half of the secret key */
	hash_size = sizeof(hash);
	if(eddsa_get_digest_from_priv_key(hash, &hash_size, &(key_pair->priv_key))){
		ret = -1;
		goto err;
	}
	/* Sanity check */
	if(hash_size != hsize){
		ret = -1;
		goto err;
	}
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(h)){
		ret = -1;
		goto err;
	}
	h->hfunc_init(&h_ctx);
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519CTX){
		/* As per RFC8032, for EDDSA25519CTX the context SHOULD NOT be empty */
		if(adata == NULL){
			ret = -1;
			goto err;
		}
		if(dom2(0, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
	if(key_type == EDDSA25519PH){
		if(dom2(1, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448){
		if(dom4(0, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
	if(key_type == EDDSA448PH){
		if(dom4(1, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
#endif
	h->hfunc_update(&h_ctx, &hash[hsize / 2], hsize / 2);

	/* Now finish computing the scalar r */
	if(use_message_pre_hash){
		h->hfunc_update(&h_ctx, ph_hash, use_message_pre_hash_hsize);
	}
	else{
		h->hfunc_update(&h_ctx, m, mlen);
	}
	h->hfunc_finalize(&h_ctx, hash);
	dbg_buf_print("h(h || PH(m))", hash, hsize);

	/* Import r as the hash scalar */
	if(eddsa_decode_integer(&r, hash, hsize)){
		ret = -1;
		goto err;
	}
	/* Reduce r modulo q for the next computation */
	nn_mod(&r, &r, q);
	/* Now perform our scalar multiplication.
	 */
#if defined(WITH_SIG_EDDSA448)
	if((key_type == EDDSA448) || (key_type == EDDSA448PH)){
		/*
		 * NOTE: in case of EDDSA448, because of the 4-isogeny we must
		 * divide our scalar by 4.
		 */
		nn r_tmp;
		nn_init(&r_tmp, 0);
		nn_modinv_word(&r_tmp, WORD(4), q);
		nn_mul_mod(&r_tmp, &r_tmp, &r, q);
#ifdef USE_SIG_BLINDING
		if(prj_pt_mul_monty_blind(&R, &r_tmp, G)){
			ret = -1;
			goto err;
		}
#else
		prj_pt_mul_monty(&R, &r_tmp, G);
#endif
		nn_uninit(&r_tmp);
	}
	else
#endif /* !defined(WITH_SIG_EDDSA448) */
	{
#ifdef USE_SIG_BLINDING
		if(prj_pt_mul_monty_blind(&R, &r, G)){
			ret = -1;
			goto err;
		}
#else
		prj_pt_mul_monty(&R, &r, G);
#endif
	}
	/* Now compute S = (r + H(R || PubKey || PH(m)) * secret) mod q */
	if(hash_mapping_callbacks_sanity_check(h)){
		ret = -1;
		goto err;
	}
	h->hfunc_init(&h_ctx);
	/* Transfer R to Edwards */
	curve_shortw_to_edwards(shortw_curve, &crv_edwards, alpha_montgomery,
				gamma_montgomery, alpha_edwards);
	prj_pt_shortw_to_aff_pt_edwards(&R, &crv_edwards, &Tmp_edwards,
					alpha_edwards);
	dbg_ec_edwards_point_print("R", &Tmp_edwards);
	if(r_len > siglen){
		ret = -1;
		goto err;
	}
	/* Encode R and update */
	if(eddsa_encode_point(&Tmp_edwards, alpha_edwards, &sig[0],
			      r_len, key_type)){
		ret = -1;
		goto err;
	}
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519CTX){
		/*
		 * As per RFC8032, for EDDSA25519CTX the context
		 * SHOULD NOT be empty
		 */
		if(adata == NULL){
			ret = -1;
			goto err;
		}
		if(dom2(0, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
	if(key_type == EDDSA25519PH){
		if(dom2(1, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448){
		if(dom4(0, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
	if(key_type == EDDSA448PH){
		if(dom4(1, adata, adata_len, h, &h_ctx)){
			ret = -1;
			goto err;
		}
	}
#endif
	/* Update the hash with the encoded R point */
	h->hfunc_update(&h_ctx, &sig[0], r_len);
	/* Transfer the public key to Edwards */
	prj_pt_shortw_to_aff_pt_edwards(pub_key_y, &crv_edwards, &Tmp_edwards,
					alpha_edwards);
	dbg_ec_edwards_point_print("A", &Tmp_edwards);
	if(r_len > sizeof(hash)){
		ret = -1;
		goto err;
	}
	/* Encode the public key */
	/* NOTE: we use the hash buffer as a temporary buffer */
	if(eddsa_encode_point(&Tmp_edwards, alpha_edwards,
			      hash, r_len, key_type)){
		ret = -1;
		goto err;
	}
	/* Update the hash with the encoded public key point */
	h->hfunc_update(&h_ctx, hash, r_len);
	/* Update the hash with the message or its hash for the PH versions */
	if(use_message_pre_hash){
		h->hfunc_update(&h_ctx, ph_hash, use_message_pre_hash_hsize);
	}
	else{
		h->hfunc_update(&h_ctx, m, mlen);
	}
	/* Finalize the hash */
	h->hfunc_finalize(&h_ctx, hash);
	dbg_buf_print("h(R || PubKey || PH(m))", hash, hsize);
	/* Import our resulting hash as an integer in S */
	if(eddsa_decode_integer(&S, hash, hsize)){
		ret = -1;
		goto err;
	}
	nn_mod(&S, &S, q);
	/* Extract the digest */
	hsize = sizeof(hash);
	if(eddsa_get_digest_from_priv_key(hash, &hsize, priv_key)){
		ret = -1;
		goto err;
	}
	if(eddsa_compute_s(&s, hash, hsize)){
		goto err;
	}
	nn_mod(&s, &s, q);
#ifdef USE_SIG_BLINDING
	/* Note: if we use blinding, r and H(R || PubKey || m) are multiplied by
	 * a random value b in ]0,q[ */
	ret = nn_get_random_mod(&b, q);
	if (ret) {
		ret = -1;
		goto err;
	}
	dbg_nn_print("b", &b);
	nn_modinv(&binv, &b, q);
	/* If we use blinding, multiply by b */
	nn_mul_mod(&S, &S, &b, q);
	nn_mul_mod(&r, &r, &b, q);
#endif
	/* Multiply by the secret */
	nn_mul_mod(&S, &S, &s, q);
	/* The secret is not needed anymore */
	nn_uninit(&s);
	/* Add to r */
	nn_mod_add(&S, &S, &r, q);
#ifdef USE_SIG_BLINDING
	/* Unblind the result */
	nn_mul_mod(&S, &S, &binv, q);
#endif
	/* Store our S in the context as an encoded buffer */
	if(s_len > (siglen - r_len)){
		ret = -1;
		goto err;
	}
	/* Encode the scalar s from the digest */
	if(eddsa_encode_integer(&S, &sig[r_len], s_len)){
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	/* Clean what remains on the stack */
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(pub_key);
	PTR_NULLIFY(G);
	PTR_NULLIFY(q);
	PTR_NULLIFY(shortw_curve);
	PTR_NULLIFY(alpha_montgomery);
	PTR_NULLIFY(gamma_montgomery);
	PTR_NULLIFY(alpha_edwards);
	PTR_NULLIFY(pub_key_y);
	VAR_ZEROIFY(hsize);
	VAR_ZEROIFY(hash_size);
	VAR_ZEROIFY(key_type);
	VAR_ZEROIFY(use_message_pre_hash);
	VAR_ZEROIFY(use_message_pre_hash_hsize);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	local_memset(&h_ctx, 0, sizeof(h_ctx));
	local_memset(hash, 0, sizeof(hash));
	local_memset(ph_hash, 0, sizeof(ph_hash));

	if(prj_pt_is_initialized(&R)){
		prj_pt_uninit(&R);
	}
	if(ec_edwards_crv_is_initialized(&crv_edwards)){
		ec_edwards_crv_uninit(&crv_edwards);
	}
	if(aff_pt_edwards_is_initialized(&Tmp_edwards)){
		aff_pt_edwards_uninit(&Tmp_edwards);
	}
	if(nn_is_initialized(&s)){
		nn_uninit(&s);
	}
	if(nn_is_initialized(&r)){
		nn_uninit(&r);
	}
	if(nn_is_initialized(&S)){
		nn_uninit(&S);
	}

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

/******************************************************************************/
/*
 * Generic *internal* EDDSA verification functions (init, update and finalize).
 *
 */

/* Naive double and add cofactor scalar multiplication */
static int _eddsa_cofactor_scalar_mult(prj_pt_t out, prj_pt_src_t in, nn_src_t cofactor)
{
	u8 expbit;
	bitcnt_t explen;

	if(!prj_pt_is_initialized(in)){
		goto err;
	}
	if(!nn_is_initialized(cofactor)){
		goto err;
	}

	if(nn_iszero(cofactor)){
		/* This should not happen: cofactor cannot be zero! */
		goto err;
	}
	explen = nn_bitlen(cofactor) - 1;
	prj_pt_copy(out, in);
	while (explen > 0) {
		explen -= (bitcnt_t)1;
		expbit = nn_getbit(cofactor, explen);
		prj_pt_dbl_monty(out, out);
		if(expbit){
			prj_pt_add_monty(out, out, in);
		}
	}

	return 0;
err:
	return -1;
}

#define EDDSA_VERIFY_MAGIC ((word_t)(0x3298fe87e77151beULL))
#define EDDSA_VERIFY_CHECK_INITIALIZED(A) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == EDDSA_VERIFY_MAGIC))

int _eddsa_verify_init(struct ec_verify_context *ctx, const u8 *sig, u8 siglen)
{
	nn_src_t q;
	ec_edwards_crv crv_edwards;
	aff_pt_edwards R;
	prj_pt _Tmp;
	prj_pt_t _R;
	aff_pt_edwards A;
	nn *S;
	u8 buff[MAX_DIGEST_SIZE];
	int ret = -1;
	u16 hsize;
	const ec_pub_key *pub_key;
	ec_shortw_crv_src_t shortw_curve;
	fp_src_t alpha_montgomery;
	fp_src_t gamma_montgomery;
	fp_src_t alpha_edwards;
	nn_src_t gen_cofactor;
	prj_pt_src_t pub_key_y;
	hash_context *h_ctx;
	hash_context *h_ctx_pre_hash;

	/* First, verify context has been initialized */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);

	/* Zero init our local data */
	local_memset(&A, 0, sizeof(aff_pt_edwards));
	local_memset(&crv_edwards, 0, sizeof(ec_edwards_crv));
	local_memset(buff, 0, sizeof(buff));
	local_memset(&R, 0, sizeof(R));
	local_memset(&_Tmp, 0, sizeof(_Tmp));

	/* Do some sanity checks on input params */
	if(eddsa_pub_key_sanity_check(ctx->pub_key)){
		ret = -1;
		goto err;
	}
	if ((!(ctx->h)) || (ctx->h->digest_size > MAX_DIGEST_SIZE) ||
	    (ctx->h->block_size > MAX_BLOCK_SIZE)) {
		ret = -1;
		goto err;
	}

	/* Make things more readable */
	q = &(ctx->pub_key->params->ec_fp.p);
	_R = &(ctx->verify_data.eddsa._R);
	S = &(ctx->verify_data.eddsa.S);
	hsize = ctx->h->digest_size;

	pub_key = ctx->pub_key;
	shortw_curve = &(pub_key->params->ec_curve);
	alpha_montgomery = &(pub_key->params->ec_alpha_montgomery);
	gamma_montgomery = &(pub_key->params->ec_gamma_montgomery);
	alpha_edwards = &(pub_key->params->ec_alpha_edwards);
	gen_cofactor = &(pub_key->params->ec_gen_cofactor);
	pub_key_y = &(pub_key->y);
	ec_sig_alg_type key_type = pub_key->key_type;
	h_ctx = &(ctx->verify_data.eddsa.h_ctx);
	h_ctx_pre_hash = &(ctx->verify_data.eddsa.h_ctx_pre_hash);

	/* Sanity check on hash types */
	if(ctx->h->type != get_eddsa_hash_type(key_type)){
		ret = -1;
		goto err;
	}

	/* Check given signature length is the expected one */
	if (siglen != EDDSA_SIGLEN(hsize)) {
		ret = -1;
		goto err;
	}
	if (siglen != (EDDSA_R_LEN(hsize) + EDDSA_S_LEN(hsize))) {
		ret = -1;
		goto err;
	}

	/* Initialize the hash context */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	ctx->h->hfunc_init(h_ctx);
	ctx->h->hfunc_init(h_ctx_pre_hash);
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519CTX){
		/* As per RFC8032, for EDDSA25519CTX the context SHOULD NOT be empty */
		if(ctx->adata == NULL){
			ret = -1;
			goto err;
		}
		if(dom2(0, ctx->adata, ctx->adata_len, ctx->h, h_ctx)){
			ret = -1;
			goto err;
		}
	}
	if(key_type == EDDSA25519PH){
		if(dom2(1, ctx->adata, ctx->adata_len, ctx->h, h_ctx)){
			ret = -1;
			goto err;
		}
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448){
		if(dom4(0, ctx->adata, ctx->adata_len, ctx->h, h_ctx)){
			ret = -1;
			goto err;
		}
	}
	if(key_type == EDDSA448PH){
		if(dom4(1, ctx->adata, ctx->adata_len, ctx->h, h_ctx)){
			ret = -1;
			goto err;
		}
	}
#endif
	/* Import R and S values from signature buffer */
	/*******************************/
	/* Import R as an Edwards point */
	curve_shortw_to_edwards(shortw_curve, &crv_edwards, alpha_montgomery,
				gamma_montgomery, alpha_edwards);
	if(eddsa_decode_point(&R, &crv_edwards, alpha_edwards, &sig[0],
			      EDDSA_R_LEN(hsize), key_type)){
		/* NOTE: non canonical R are checked and rejected here */
		ret = -1;
		goto err;
	}
	dbg_ec_edwards_point_print("R", &R);
	/* Transfer our public point R to Weierstrass */
	aff_pt_edwards_to_prj_pt_shortw(&R, shortw_curve, _R, alpha_edwards);
	/* Update the hash with the encoded R */
	ctx->h->hfunc_update(h_ctx, &sig[0], EDDSA_R_LEN(hsize));

	/*******************************/
	/* Import S as an integer */
	if(eddsa_decode_integer(S, &sig[EDDSA_R_LEN(hsize)], EDDSA_S_LEN(hsize))){
		ret = -1;
		goto err;
	}
	/* Reject S if it is not reduced modulo q */
	if(nn_cmp(S, q) >= 0){
		ret = -1;
		goto err;
	}
	dbg_nn_print("S", S);

	/*******************************/
	/* Encode the public key
	 * NOTE: since we deal with a public key transfered to Weierstrass,
	 * encoding checking has been handled elsewhere.
	 */
	/* Reject the signature if the public key is one of small order points.
	 * We multiply by the cofactor: since this is a public verification,
	 * we use a basic double and add algorithm.
	 */
	if(_eddsa_cofactor_scalar_mult(&_Tmp, pub_key_y, gen_cofactor)){
		ret = -1;
		goto err;
	}
	/* Reject the signature if we have point at infinity here as this means
	 * that the public key is of small order.
	 */
	if(prj_pt_iszero(&_Tmp)){
		ret = -1;
		goto err;
	}
	/* Transfer the public key to Edwards */
	prj_pt_shortw_to_aff_pt_edwards(pub_key_y, &crv_edwards, &A, alpha_edwards);
	dbg_ec_edwards_point_print("A", &A);
	if(EDDSA_R_LEN(hsize) > sizeof(buff)){
		ret = -1;
		goto err;
	}
	/* NOTE: we use the hash buffer as a temporary buffer */
	if(eddsa_encode_point(&A, alpha_edwards, buff, EDDSA_R_LEN(hsize), key_type)){
		ret = -1;
		goto err;
	}

	/* Update the hash with the encoded public key */
	ctx->h->hfunc_update(h_ctx, buff, EDDSA_R_LEN(hsize));

	/* Context magic set */
	ctx->verify_data.eddsa.magic = EDDSA_VERIFY_MAGIC;

	ret = 0;

 err:
	PTR_NULLIFY(q);
	PTR_NULLIFY(_R);
	PTR_NULLIFY(S);
	PTR_NULLIFY(pub_key);
	PTR_NULLIFY(shortw_curve);
	PTR_NULLIFY(alpha_montgomery);
	PTR_NULLIFY(gamma_montgomery);
	PTR_NULLIFY(alpha_edwards);
	PTR_NULLIFY(gen_cofactor);
	PTR_NULLIFY(pub_key_y);
	VAR_ZEROIFY(key_type);
	if(aff_pt_edwards_is_initialized(&A)){
		aff_pt_edwards_uninit(&A);
	}
	if(aff_pt_edwards_is_initialized(&R)){
		aff_pt_edwards_uninit(&R);
	}
	if(prj_pt_is_initialized(&_Tmp)){
		prj_pt_uninit(&_Tmp);
	}

	return ret;
}

int _eddsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	int ret = -1;
	ec_sig_alg_type key_type;
	u8 use_message_pre_hash = 0;
	hash_context *h_ctx;
	hash_context *h_ctx_pre_hash;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EDDSA
	 * verification one and we do not update() or finalize()
	 * before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	EDDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.eddsa));

	key_type = ctx->pub_key->key_type;
	h_ctx = &(ctx->verify_data.eddsa.h_ctx);
	h_ctx_pre_hash = &(ctx->verify_data.eddsa.h_ctx_pre_hash);

	/* Sanity check on hash types */
	if(ctx->h->type != get_eddsa_hash_type(key_type)){
		ret = -1;
		goto err;
	}

	/* Do we use the raw message or its PH(M) hashed version? */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		use_message_pre_hash = 1;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		use_message_pre_hash = 1;
	}
#endif
	/* 2. Compute h = H(m) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	if(use_message_pre_hash == 1){
		/* In PH mode, update the dedicated hash context */
		ctx->h->hfunc_update(h_ctx_pre_hash,
				     chunk, chunklen);
	}
	else{
		/* In normal mode, update the nominal hash context */
		ctx->h->hfunc_update(h_ctx, chunk, chunklen);
	}

	ret = 0;
err:
	VAR_ZEROIFY(key_type);
	VAR_ZEROIFY(use_message_pre_hash);
	return ret;
}

int _eddsa_verify_finalize(struct ec_verify_context *ctx)
{
	prj_pt_src_t G, _R, A;
	prj_pt _Tmp1, _Tmp2;
	nn_src_t q, S;
	nn h;
	u16 hsize;
	u8 hash[MAX_DIGEST_SIZE];
	nn_src_t gen_cofactor;
	int ret = -1;
	ec_sig_alg_type key_type;
	u8 use_message_pre_hash = 0;
	u16 use_message_pre_hash_hsize = 0;
	hash_context *h_ctx;
	hash_context *h_ctx_pre_hash;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EDDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	EDDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.eddsa));

	/* Zero init points */
	local_memset(&_Tmp1, 0, sizeof(prj_pt));
	local_memset(&_Tmp2, 0, sizeof(prj_pt));
	local_memset(hash, 0, sizeof(hash));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	A = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	hsize = ctx->h->digest_size;
	S = &(ctx->verify_data.eddsa.S);
	_R = &(ctx->verify_data.eddsa._R);
	gen_cofactor = &(ctx->pub_key->params->ec_gen_cofactor);
	key_type = ctx->pub_key->key_type;
	h_ctx = &(ctx->verify_data.eddsa.h_ctx);
	h_ctx_pre_hash = &(ctx->verify_data.eddsa.h_ctx_pre_hash);

	/* Sanity check on hash types */
	if(ctx->h->type != get_eddsa_hash_type(key_type)){
		ret = -1;
		goto err;
	}


	/* Do we use the raw message or its PH(M) hashed version? */
#if defined(WITH_SIG_EDDSA25519)
	if(key_type == EDDSA25519PH){
		use_message_pre_hash = 1;
		use_message_pre_hash_hsize = hsize;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(key_type == EDDSA448PH){
		use_message_pre_hash = 1;
		/* NOTE: as per RFC8032, EDDSA448PH uses
		 * SHAKE256 with 64 bytes output.
		 */
		use_message_pre_hash_hsize = 64;
	}
#endif

	/* Reject S if it is not reduced modulo q */
	if(nn_cmp(S, q) >= 0){
		ret = -1;
		goto err;
	}

	if(hsize > sizeof(hash)){
		ret = -1;
		goto err;
	}
	/* 2. Finish our computation of h = H(R || A || M) */
	/* Since we call a callback, sanity check our mapping */
	if(hash_mapping_callbacks_sanity_check(ctx->h)){
		ret = -1;
		goto err;
	}
	/* Update the hash with the message or its hash for the PH versions */
	if(use_message_pre_hash == 1){
		ctx->h->hfunc_finalize(h_ctx_pre_hash, hash);
		if(use_message_pre_hash_hsize > hsize){
			ret = -1;
			goto err;
		}
		ctx->h->hfunc_update(h_ctx, hash, use_message_pre_hash_hsize);
	}
	ctx->h->hfunc_finalize(h_ctx, hash);
	dbg_buf_print("hash = H(R || A || PH(M))", hash, hsize);

	/* 3. Import our hash as a NN and reduce it modulo q */
	if(eddsa_decode_integer(&h, hash, hsize)){
		ret = -1;
		goto err;
	}
	nn_mod(&h, &h, q);
	dbg_nn_print("h = ", &h);

#if defined(WITH_SIG_EDDSA448)
	if((key_type == EDDSA448) || (key_type == EDDSA448PH)){
		/* When dealing with EDDSA448, because of our 4-isogeny between Edwars448 and Ed448
		 * mapping base point to four times base point, we actually multiply our public key by 4 here
		 * to be inline with the other computations (the public key stored in Weierstrass )
		 */
		nn_lshift(&h, &h, 2);
		nn_mod(&h, &h, q);
	}
#endif
	/* 4. Compute (S * G) - R - (h * A)  */
	prj_pt_mul_monty(&_Tmp1, S, G);
	prj_pt_neg(&_Tmp2, _R);
	prj_pt_add_monty(&_Tmp1, &_Tmp1, &_Tmp2);
	prj_pt_mul_monty(&_Tmp2, &h, A);
	prj_pt_neg(&_Tmp2, &_Tmp2);
	prj_pt_add_monty(&_Tmp1, &_Tmp1, &_Tmp2);

	/* 5. We use cofactored multiplication, so multiply by the cofactor:
	 *    since this is a public verification, we use a basic double and add
	 *    algorithm.
	 */
	if(_eddsa_cofactor_scalar_mult(&_Tmp2, &_Tmp1, gen_cofactor)){
		ret = -1;
		goto err;
	}

	/* Reject the signature if we do not have point at infinity here */
	if(!prj_pt_iszero(&_Tmp2)){
		ret = -1;
		goto err;
	}

	ret = 0;
 err:
	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.eddsa), 0, sizeof(eddsa_verify_data));

	/* Clean what remains on the stack */
	PTR_NULLIFY(G);
	PTR_NULLIFY(A);
	PTR_NULLIFY(q);
	PTR_NULLIFY(S);
	PTR_NULLIFY(_R);
	PTR_NULLIFY(gen_cofactor);
	VAR_ZEROIFY(hsize);
	VAR_ZEROIFY(key_type);
	VAR_ZEROIFY(use_message_pre_hash);
	VAR_ZEROIFY(use_message_pre_hash_hsize);
	if(nn_is_initialized(&h)){
		nn_uninit(&h);
	}
	if(prj_pt_is_initialized(&_Tmp1)){
		prj_pt_uninit(&_Tmp1);
	}
	if(prj_pt_is_initialized(&_Tmp2)){
		prj_pt_uninit(&_Tmp2);
	}

	return ret;
}

#else /* !(defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448)) */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* defined(WITH_SIG_EDDSA25519) || defined(WITH_SIG_EDDSA448) */
