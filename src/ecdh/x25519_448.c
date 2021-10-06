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
#if defined(WITH_X25519) || defined(WITH_X448)

/*
 * XXX: X25519 and X448 are incompatible with small stack devices for now ...
 */
#if defined(USE_SMALL_STACK)
#error "Error: X25519 and X448 are incompatible with USE_SMALL_STACK (devices low on memory)"
#endif

#if defined(WITH_X25519) && !defined(WITH_CURVE_WEI25519)
#error "Error: X25519 needs curve WEI25519 to be defined! Please define it in libecc config file"
#endif
#if defined(WITH_X448) && !defined(WITH_CURVE_WEI448)
#error "Error: X448 needs curve WEI448 to be defined! Please define it in libecc config file"
#endif

#include "x25519_448.h"

#include "../curves/curves.h"
#include "../sig/ec_key.h"
#include "../utils/utils.h"
#include "../fp/fp_sqrt.h"

/* For randomness source */
#include "../external_deps/rand.h"

/* This module mainly implements the X25519 and X448 functions stricly as defined in
 * RFC77448.
 */


/* Scalar clamping/decoding */
ATTRIBUTE_WARN_UNUSED_RET static int decodeScalar(const u8 *scalar, u8 *scalar_decoded, u8 len)
{
        int ret;
        unsigned int i;

        /* Aliasing is not supported */
        MUST_HAVE((scalar != scalar_decoded), ret, err);

        for(i = 0; i < len; i++){
                scalar_decoded[len - 1 - i] = scalar[i];
        }
	if(len == 32){
		/* Curve25519 */
	        scalar_decoded[len - 1] &= 248;
        	scalar_decoded[0]       &= 127;
	        scalar_decoded[0]       |= 64;
	}
	else if(len == 56){
		/* Curve448 */
		scalar_decoded[len - 1] &= 252;
		scalar_decoded[0]       |= 128;
	}
	else{
		/* Error, unknown type */
		ret = -1;
		goto err;
	}

        ret = 0;

err:
        return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int decodeUCoordinate(const u8 *u, u8 *u_decoded, u8 len)
{
        int ret;
        unsigned int i;

        /* Aliasing is not supported */
        MUST_HAVE((u != u_decoded), ret, err);

        for(i = 0; i < len; i++){
                u_decoded[len - 1 - i] = u[i];
        }

        ret = 0;

err:
        return ret;
}

/* U coordinate encoding */
ATTRIBUTE_WARN_UNUSED_RET static int encodeUCoordinate(const u8 *u, u8 *u_encoded, u8 len)
{
	return decodeUCoordinate(u, u_encoded, len);
}


/* Find V coordinate from U coordinate on Curve25519 or Curve448 */
ATTRIBUTE_WARN_UNUSED_RET static int computeVfromU(fp_src_t u, fp_t v, ec_montgomery_crv_src_t crv)
{
        int ret;
        fp tmp;

        tmp.magic = 0;

        /* Sanity checks */
        ret = fp_check_initialized(u); EG(ret, err);
        ret = ec_montgomery_crv_check_initialized(crv); EG(ret, err);
        MUST_HAVE((u->ctx == crv->A.ctx) && (u->ctx == crv->B.ctx), ret, err);

        /* Initialize v with context */
        ret = fp_init(v, u->ctx); EG(ret, err);
        ret = fp_init(&tmp, u->ctx); EG(ret, err);

        /* v must satisfy the equation B v^2 = u^3 + A u^2 + u,
         * so we compute square root for B^-1 * (u^3 + A u^2 + u)
         */
        ret = fp_sqr(&tmp, u); EG(ret, err);
        ret = fp_mul(v, &tmp, u); EG(ret, err);
        ret = fp_mul(&tmp, &tmp, &(crv->A)); EG(ret, err);
        ret = fp_add(v, v, &tmp); EG(ret, err);
        ret = fp_add(v, v, u); EG(ret, err);
        ret = fp_inv(&tmp, &(crv->B)); EG(ret, err);
        ret = fp_mul(v, v, &tmp); EG(ret, err);

        /* Choose any of the two square roots as the solution */
        ret = fp_sqrt(v, &tmp, v);

err:
        fp_uninit(&tmp);

        return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int x25519_448_core(const u8 *k, const u8 *u, u8 *res, u8 len)
{
	int ret, iszero, loaded;
	/* Note: our local variables holding scalar and coordinate have the maximum size */
#if defined(WITH_X448)
	u8 k_[56], u_[56];
#else
	u8 k_[32], u_[32];
#endif
	aff_pt_montgomery _Tmp;
	prj_pt Q;
	ec_montgomery_crv montgomery_curve;
	ec_params shortw_curve_params;
	ec_shortw_crv_src_t shortw_curve;
	fp_src_t alpha_montgomery;
	fp_src_t gamma_montgomery;
	nn scalar;
	nn_t v_coord_nn;
	fp_t u_coord, v_coord;

	_Tmp.magic = montgomery_curve.magic = Q.magic = WORD(0);
	scalar.magic = WORD(0);

	MUST_HAVE((k != NULL) && (u != NULL) && (res != NULL), ret, err);
	/* Sanity check on sizes */
	MUST_HAVE(((len == 32) || (len == 56)), ret, err);
	MUST_HAVE(((sizeof(k_) >= len) && (sizeof(u_) >= len)), ret, err);

	/* First of all, we clamp and decode the scalar and u */
	ret = decodeScalar(k, k_, len); EG(ret, err);
	ret = decodeUCoordinate(u, u_, len); EG(ret, err);

	/* Import curve parameters */
	loaded = 0;
#if defined(WITH_X25519)
	if(len == 32){
		ret = import_params(&shortw_curve_params, &wei25519_str_params); EG(ret, err);
		loaded = 1;
	}
#endif
#if defined(WITH_X448)
	if(len == 56){
		ret = import_params(&shortw_curve_params, &wei448_str_params); EG(ret, err);
		loaded = 1;
	}
#endif
	/* Sanity check that we have loaded our curve parameters */
	MUST_HAVE((loaded == 1), ret, err);

	/* Make things more readable */
	shortw_curve = &(shortw_curve_params.ec_curve);
	alpha_montgomery = &(shortw_curve_params.ec_alpha_montgomery);
	gamma_montgomery = &(shortw_curve_params.ec_gamma_montgomery);
	/* NOTE: we use the projective point Q Fp values as temporary
	 * space to save some stack here.
	 */
	u_coord = &(Q.X);
	v_coord = &(Q.Y);
	v_coord_nn = &(v_coord->fp_val);

	/* Get the isogenic Montgomery curve */
	ret = curve_shortw_to_montgomery(shortw_curve, &montgomery_curve, alpha_montgomery,
			gamma_montgomery); EG(ret, err);

	/* Import the scalar and u coordinate as a big integer and Fp element */
	ret = nn_init_from_buf(&scalar, k_, len); EG(ret, err);
	ret = nn_init_from_buf(v_coord_nn, u_, len); EG(ret, err);
	/* Reduce u modulo p as we MUST accept any u as per RFC7748.
	 * NOTE: we use v here as a temporary value.
	 */
	ret = nn_mod(v_coord_nn, v_coord_nn, &(montgomery_curve.A.ctx->p)); EG(ret, err);
	/* Now initialize u as Fp element with the reduced value */
	ret = fp_init(u_coord, montgomery_curve.A.ctx); EG(ret, err);
	ret = fp_set_nn(u_coord, v_coord_nn); EG(ret, err);

	/* Compute the v coordinate from u */
	ret = computeVfromU(u_coord, v_coord, &montgomery_curve); EG(ret, err);

	/* Get the affine point in Montgomery */
	ret = aff_pt_montgomery_init_from_coords(&_Tmp, &montgomery_curve, u_coord, v_coord); EG(ret, err);
	/* Transfer from Montgomery to short Weierstrass using the isogeny */
	ret = aff_pt_montgomery_to_prj_pt_shortw(&_Tmp, shortw_curve, &Q); EG(ret, err);

	/* Now proceed with the scalar multiplication */
#ifdef USE_SIG_BLINDING
	ret = prj_pt_mul_blind(&Q, &scalar, &Q); EG(ret, err);
#else
	ret = prj_pt_mul(&Q, &scalar, &Q); EG(ret, err);
#endif

	/* Transfer back from short Weierstrass to Montgomery using the isogeny */
	ret = prj_pt_shortw_to_aff_pt_montgomery(&Q, &montgomery_curve, &_Tmp); EG(ret, err);

	/* Reject the all zero output */
	ret = fp_iszero(&(_Tmp.u), &iszero); EG(ret, err);
	MUST_HAVE((!iszero), ret, err);

	/* Now export the resulting u coordinate ... */
	ret = fp_export_to_buf(u_, len, &(_Tmp.u)); EG(ret, err);
	/* ... and encode it in the output */
	ret = encodeUCoordinate(u_, res, len);

err:
	IGNORE_RET_VAL(local_memset(u_, 0, sizeof(u_)));
	IGNORE_RET_VAL(local_memset(k_, 0, sizeof(k_)));
	IGNORE_RET_VAL(local_memset(&shortw_curve_params, 0, sizeof(shortw_curve_params)));

	aff_pt_montgomery_uninit(&_Tmp);
	prj_pt_uninit(&Q);
	ec_montgomery_crv_uninit(&montgomery_curve);

	PTR_NULLIFY(shortw_curve);
	PTR_NULLIFY(alpha_montgomery);
	PTR_NULLIFY(gamma_montgomery);
	PTR_NULLIFY(u_coord);
	PTR_NULLIFY(v_coord);
	PTR_NULLIFY(v_coord_nn);

        return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int x25519_448_gen_priv_key(u8 *priv_key, u8 len)
{
	int ret;

	MUST_HAVE((priv_key != NULL), ret, err);
	MUST_HAVE(((len == 32) || (len == 56)), ret, err);

	/* Generating a private key consists in generating a random byte string */
	ret = get_random(priv_key, len);

err:
	return ret;
}


ATTRIBUTE_WARN_UNUSED_RET static int x25519_448_init_pub_key(const u8 *priv_key, u8 *pub_key, u8 len)
{
	int ret;

	MUST_HAVE((priv_key != NULL) && (pub_key != NULL), ret, err);
	MUST_HAVE(((len == 32) || (len == 56)), ret, err);

	/* Computing the public key is x25519(priv_key, 9) or x448(priv_key, 5) */
	if(len == 32){
		/* X25519 */
		u8 u[32] = { 0x09 };
		ret = x25519_448_core(priv_key, u, pub_key, len);
	}
	else if(len == 56){
		/* X448 */
		u8 u[56] = { 0x05 };
		ret = x25519_448_core(priv_key, u, pub_key, len);
	}
	else{
		ret = -1;
	}
err:
	return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int x25519_448_derive_secret(const u8 *priv_key, const u8 *peer_pub_key, u8 *shared_secret, u8 len)
{
	int ret;

	MUST_HAVE((priv_key != NULL) && (peer_pub_key != NULL) && (shared_secret != NULL), ret, err);
	MUST_HAVE(((len == 32) || (len == 56)), ret, err);

	/* Computing the shared secret is x25519(priv_key, peer_pub_key) or x448(priv_key, peer_pub_key) */
	ret = x25519_448_core(priv_key, peer_pub_key, shared_secret, len);

err:
	return ret;
}


#if defined(WITH_X25519)
/* The X25519 function as specified in RFC7748.
 *
 * NOTE: we use isogenies between Montgomery Curve25519 and short Weierstrass
 * WEI25519 to perform the Elliptic Curves computations.
 */
int x25519(const u8 k[32], const u8 u[32], u8 res[32])
{
	return x25519_448_core(k, u, res, 32);
}

int x25519_gen_priv_key(u8 priv_key[32])
{
	return x25519_448_gen_priv_key(priv_key, 32);
}

int x25519_init_pub_key(const u8 priv_key[32], u8 pub_key[32])
{
	return x25519_448_init_pub_key(priv_key, pub_key, 32);
}

int x25519_derive_secret(const u8 priv_key[32], const u8 peer_pub_key[32], u8 shared_secret[32])
{
	return x25519_448_derive_secret(priv_key, peer_pub_key, shared_secret, 32);
}
#endif

#if defined(WITH_X448)
/* The X448 function as specified in RFC7748.
 *
 * NOTE: we use isogenies between Montgomery Curve448 and short Weierstrass
 * WEI448 to perform the Elliptic Curves computations.
 */
int x448(const u8 k[56], const u8 u[56], u8 res[56])
{
	return x25519_448_core(k, u, res, 56);
}

int x448_gen_priv_key(u8 priv_key[56])
{
	return x25519_448_gen_priv_key(priv_key, 56);
}

int x448_init_pub_key(const u8 priv_key[56], u8 pub_key[56])
{
	return x25519_448_init_pub_key(priv_key, pub_key, 56);
}

int x448_derive_secret(const u8 priv_key[56], const u8 peer_pub_key[56], u8 shared_secret[56])
{
	return x25519_448_derive_secret(priv_key, peer_pub_key, shared_secret, 56);
}
#endif

#else /* !(defined(WITH_X25519) || defined(WITH_X448)) */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;

#endif /* defined(WITH_X25519) || defined(WITH_X448) */