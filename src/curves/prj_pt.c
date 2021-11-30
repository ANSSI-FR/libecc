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
#include "ec_shortw.h"
#include "prj_pt.h"
#include "../nn/nn_logical.h"
#include "../nn/nn_add.h"
#include "../nn/nn_rand.h"
#include "../fp/fp_add.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_montgomery.h"
#include "../fp/fp_rand.h"

/*
void prj_pt_check_initialized(prj_pt_src_t in)
{
	MUST_HAVE((in != NULL) && (in->magic == PRJ_PT_MAGIC)
		  && (in->crv != NULL));
}
*/
int prj_pt_is_initialized(prj_pt_src_t in)
{
	return !!((in != NULL) && (in->magic == PRJ_PT_MAGIC) &&
		   (in->crv != NULL));
}

void prj_pt_init(prj_pt_t in, ec_shortw_crv_src_t curve)
{
	ec_shortw_crv_check_initialized(curve);
	MUST_HAVE(in != NULL);

	fp_init(&(in->X), curve->a.ctx);
	fp_init(&(in->Y), curve->a.ctx);
	fp_init(&(in->Z), curve->a.ctx);
	in->crv = curve;
	in->magic = PRJ_PT_MAGIC;
}

void prj_pt_init_from_coords(prj_pt_t in,
			     ec_shortw_crv_src_t curve,
			     fp_src_t xcoord, fp_src_t ycoord, fp_src_t zcoord)
{
	prj_pt_init(in, curve);
	fp_copy(&(in->X), xcoord);
	fp_copy(&(in->Y), ycoord);
	fp_copy(&(in->Z), zcoord);
}

void prj_pt_uninit(prj_pt_t in)
{
	prj_pt_check_initialized(in);

	fp_uninit(&(in->X));
	fp_uninit(&(in->Y));
	fp_uninit(&(in->Z));
	in->crv = NULL;
	in->magic = WORD(0);
}

int prj_pt_iszero(prj_pt_src_t in)
{
	prj_pt_check_initialized(in);

	return fp_iszero(&(in->Z));
}

void prj_pt_zero(prj_pt_t out)
{
	prj_pt_check_initialized(out);

	fp_zero(&(out->X));
	fp_one(&(out->Y));
	fp_zero(&(out->Z));

	return;
}

/* Check if a projective point is indeed on its curve.
 * Returns 1 if the point is on the curve, 0 if not.
 */
int prj_pt_is_on_curve(prj_pt_src_t in)
{
	int ret = 0;
	prj_pt in1, in2;
	aff_pt in_aff;

	prj_pt_check_initialized(in);

	/* Point at infinity is trivially on the curve.
	 * However, we do not want to leak that we are testing it,
	 * and hence we test a dummy value if necessary.
	 * The dummy point is not on the curve, but computations
	 * are performed anyways!
	 */
	prj_pt_init(&in1, in->crv);
	prj_pt_copy(&in1, in);
	prj_pt_init(&in2, in->crv);
	nn_copy(&(in2.X.fp_val), &((in2.crv)->a.fp_val));
	nn_copy(&(in2.Y.fp_val), &((in2.crv)->b.fp_val));
	nn_copy(&(in2.Z.fp_val), &((in2.crv)->a_monty.fp_val));

	ret = prj_pt_iszero(in);
	nn_cnd_swap(ret, &(in1.X.fp_val), &(in2.X.fp_val));
	nn_cnd_swap(ret, &(in1.Y.fp_val), &(in2.Y.fp_val));
	nn_cnd_swap(ret, &(in1.Z.fp_val), &(in2.Z.fp_val));

	/* Move to the affine unique representation */
	prj_pt_to_aff(&in_aff, &in1);

	/* Check that the affine coordinates are on the curve */
	ret |= aff_pt_is_on_curve(&in_aff);

	prj_pt_uninit(&in1);
	prj_pt_uninit(&in2);
	aff_pt_uninit(&in_aff);

	return ret;
}

void prj_pt_copy(prj_pt_t out, prj_pt_src_t in)
{
	prj_pt_check_initialized(in);

	prj_pt_init(out, in->crv);

	fp_copy(&(out->X), &(in->X));
	fp_copy(&(out->Y), &(in->Y));
	fp_copy(&(out->Z), &(in->Z));
}

void prj_pt_to_aff(aff_pt_t out, prj_pt_src_t in)
{
	fp inv;

	prj_pt_check_initialized(in);
	MUST_HAVE(!prj_pt_iszero(in));

	aff_pt_init(out, in->crv);
	fp_init(&inv, (in->X).ctx);

	fp_inv(&inv, &(in->Z));
	fp_mul(&(out->x), &(in->X), &inv);
	fp_mul(&(out->y), &(in->Y), &inv);

	fp_uninit(&inv);
}

/* 
 * Get the unique Z = 1 projective point representation
 * ("equivalent" to affine point).
 */
void prj_pt_unique(prj_pt_t out, prj_pt_src_t in)
{
	fp inv;

	prj_pt_check_initialized(in);
	MUST_HAVE(!prj_pt_iszero(in));

	if(out != in){
		prj_pt_init(out, in->crv);
	}
	fp_init(&inv, (in->X).ctx);

	fp_inv(&inv, &(in->Z));
	fp_mul(&(out->X), &(in->X), &inv);
	fp_mul(&(out->Y), &(in->Y), &inv);
	fp_one(&(out->Z));

	fp_uninit(&inv);
}


void ec_shortw_aff_to_prj(prj_pt_t out, aff_pt_src_t in)
{
	aff_pt_check_initialized(in);
	
	/* The input affine point must be on the curve */
	MUST_HAVE(is_on_shortw_curve(&(in->x), &(in->y), in->crv) == 1);

	prj_pt_init(out, in->crv);

	fp_copy(&(out->X), &(in->x));
	fp_copy(&(out->Y), &(in->y));
	nn_inc(&(out->Z).fp_val, &(out->Z).fp_val);	/* Z = 1 */
}

int prj_pt_cmp(prj_pt_src_t in1, prj_pt_src_t in2)
{
	fp X1, X2, Y1, Y2;
	int ret;

	prj_pt_check_initialized(in1);
	prj_pt_check_initialized(in2);
	MUST_HAVE(in1->crv == in2->crv);

	fp_init(&X1, (in1->X).ctx);
	fp_init(&X2, (in2->X).ctx);
	fp_init(&Y1, (in1->Y).ctx);
	fp_init(&Y2, (in2->Y).ctx);

	/*
	 * Montgomery multiplication is used as it is faster than
	 * usual multiplication and the spurious multiplicative
	 * factor does not matter.
	 */
	fp_mul_redc1(&X1, &(in1->X), &(in2->Z));
	fp_mul_redc1(&X2, &(in2->X), &(in1->Z));
	fp_mul_redc1(&Y1, &(in1->Y), &(in2->Z));
	fp_mul_redc1(&Y2, &(in2->Y), &(in1->Z));

	ret = fp_cmp(&X1, &X2) | fp_cmp(&Y1, &Y2);

	fp_uninit(&X1);
	fp_uninit(&X2);
	fp_uninit(&Y1);
	fp_uninit(&Y2);

	return ret;
}

/*
 * Return 1 if if given projective points are equal or opposite.
 * Returns 0 otherwise.
 */
int prj_pt_eq_or_opp(prj_pt_src_t in1, prj_pt_src_t in2)
{
	fp X1, X2, Y1, Y2;
	int ret;

	prj_pt_check_initialized(in1);
	prj_pt_check_initialized(in2);
	MUST_HAVE(in1->crv == in2->crv);

	fp_init(&X1, (in1->X).ctx);
	fp_init(&X2, (in2->X).ctx);
	fp_init(&Y1, (in1->Y).ctx);
	fp_init(&Y2, (in2->Y).ctx);

	/*
	 * Montgomery multiplication is used as it is faster than
	 * usual multiplication and the spurious multiplicative
	 * factor does not matter.
	 */
	fp_mul_redc1(&X1, &(in1->X), &(in2->Z));
	fp_mul_redc1(&X2, &(in2->X), &(in1->Z));
	fp_mul_redc1(&Y1, &(in1->Y), &(in2->Z));
	fp_mul_redc1(&Y2, &(in2->Y), &(in1->Z));

	ret = (fp_cmp(&X1, &X2) == 0);
	ret &= fp_eq_or_opp(&Y1, &Y2);

	fp_uninit(&X1);
	fp_uninit(&X2);
	fp_uninit(&Y1);
	fp_uninit(&Y2);

	return ret;
}

/* Compute the opposite of a projective point. Supports aliasing. */
void prj_pt_neg(prj_pt_t out, prj_pt_src_t in)
{
	fp Y_opposite;

	prj_pt_check_initialized(in);

	fp_init(&Y_opposite, (in->Y).ctx);
	fp_neg(&Y_opposite, &(in->Y));

	/* Handle aliasing */
	if (out == in) {
		prj_pt _in;
		prj_pt_copy(&_in, in);
		prj_pt_init_from_coords(out, _in.crv, &(_in.X), &Y_opposite, &(_in.Z));
		prj_pt_uninit(&_in);
	} else {
		prj_pt_init_from_coords(out, in->crv, &(in->X), &Y_opposite, &(in->Z));
	}

	fp_uninit(&Y_opposite);
}

/*
 * Import a projective point from a buffer with the following layout; the 3
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 3 * p_len.
 */
int prj_pt_import_from_buf(prj_pt_t pt,
			   const u8 *pt_buf,
			   u16 pt_buf_len, ec_shortw_crv_src_t crv)
{
	fp_ctx_src_t ctx;
	u16 coord_len;

	ec_shortw_crv_check_initialized(crv);
	MUST_HAVE(pt_buf != NULL);

	ctx = crv->a.ctx;
	coord_len = BYTECEIL(ctx->p_bitlen);

	if (pt_buf_len != (3 * coord_len)) {
		return -1;
	}

	fp_init_from_buf(&(pt->X), ctx, pt_buf, coord_len);
	fp_init_from_buf(&(pt->Y), ctx, pt_buf + coord_len, coord_len);
	fp_init_from_buf(&(pt->Z), ctx, pt_buf + (2 * coord_len), coord_len);

	/* Set the curve */
	pt->crv = crv;

	/* Mark the point as initialized */
	pt->magic = PRJ_PT_MAGIC;

	/* Check that the point is indeed on the provided curve, uninitialize it
	 * if this is not the case.
	 */
	if(prj_pt_is_on_curve(pt) != 1){
		prj_pt_uninit(pt);
		return -1;
	}

	return 0;
}

/*
 * Import a projective point from an affine point buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int prj_pt_import_from_aff_buf(prj_pt_t pt,
			   const u8 *pt_buf,
			   u16 pt_buf_len, ec_shortw_crv_src_t crv)
{
	fp_ctx_src_t ctx;
	u16 coord_len;

	ec_shortw_crv_check_initialized(crv);
	MUST_HAVE(pt_buf != NULL);

	ctx = crv->a.ctx;
	coord_len = BYTECEIL(ctx->p_bitlen);

	if (pt_buf_len != (2 * coord_len)) {
		return -1;
	}

	fp_init_from_buf(&(pt->X), ctx, pt_buf, coord_len);
	fp_init_from_buf(&(pt->Y), ctx, pt_buf + coord_len, coord_len);
	/* Z coordinate is set to 1 */
	fp_init(&(pt->Z), ctx);
	fp_one(&(pt->Z));

	/* Set the curve */
	pt->crv = crv;

	/* Mark the point as initialized */
	pt->magic = PRJ_PT_MAGIC;

	/* Check that the point is indeed on the provided curve, uninitialize it
	 * if this is not the case.
	 */
	if(prj_pt_is_on_curve(pt) != 1){
		prj_pt_uninit(pt);
		return -1;
	}

	return 0;
}


/* Export a projective point to a buffer with the following layout; the 3
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 3 * p_len.
 */
int prj_pt_export_to_buf(prj_pt_src_t pt, u8 *pt_buf, u32 pt_buf_len)
{
	fp_ctx_src_t ctx;
	u16 coord_len;

	prj_pt_check_initialized(pt);
	MUST_HAVE(pt_buf != NULL);

	/* The point to be exported must be on the curve */
        MUST_HAVE(prj_pt_is_on_curve(pt) == 1);

	ctx = pt->crv->a.ctx;
	coord_len = BYTECEIL(ctx->p_bitlen);

	if (pt_buf_len != (3 * coord_len)) {
		return -1;
	}

	/* Export the three coordinates */
	fp_export_to_buf(pt_buf, coord_len, &(pt->X));
	fp_export_to_buf(pt_buf + coord_len, coord_len, &(pt->Y));
	fp_export_to_buf(pt_buf + (2 * coord_len), coord_len, &(pt->Z));

	return 0;
}

/* Export a projective point to an affine point buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int prj_pt_export_to_aff_buf(prj_pt_src_t pt, u8 *pt_buf, u32 pt_buf_len)
{
	aff_pt tmp_aff;

	prj_pt_check_initialized(pt);
	MUST_HAVE(pt_buf != NULL);

	/* The point to be exported must be on the curve */
        MUST_HAVE(prj_pt_is_on_curve(pt) == 1);

	/* Move to the affine unique representation */
	prj_pt_to_aff(&tmp_aff, pt);

	/* Export the affine point to the buffer */
	if(aff_pt_export_to_buf(&tmp_aff, pt_buf, pt_buf_len)){
		return -1;
	}

	return 0;
}


/*
 * If NO_USE_COMPLETE_FORMULAS flag is not defined addition formulas from Algorithm 1
 * of https://joostrenes.nl/publications/complete.pdf are used, otherwise
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
 */
static void __prj_pt_add(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
#ifndef NO_USE_COMPLETE_FORMULAS
	fp t0, t1, t2, t3, t4, t5;

	/* Info: initialization check of in1 and in2 done at upper level */
	MUST_HAVE(in1->crv == in2->crv);

	prj_pt_init(out, in1->crv);

	fp_init(&t0, out->crv->a.ctx);
	fp_init(&t1, out->crv->a.ctx);
	fp_init(&t2, out->crv->a.ctx);
	fp_init(&t3, out->crv->a.ctx);
	fp_init(&t4, out->crv->a.ctx);
	fp_init(&t5, out->crv->a.ctx);

	MUST_HAVE(out->crv == in1->crv);
	MUST_HAVE(out->crv == in2->crv);

	fp_mul(&t0, &in1->X, &in2->X);
	fp_mul(&t1, &in1->Y, &in2->Y);
	fp_mul(&t2, &in1->Z, &in2->Z);
	fp_add(&t3, &in1->X, &in1->Y);
	fp_add(&t4, &in2->X, &in2->Y);

	fp_mul(&t3, &t3, &t4);
	fp_add(&t4, &t0, &t1);
	fp_sub(&t3, &t3, &t4);
	fp_add(&t4, &in1->X, &in1->Z);
	fp_add(&t5, &in2->X, &in2->Z);

	fp_mul(&t4, &t4, &t5);
	fp_add(&t5, &t0, &t2);
	fp_sub(&t4, &t4, &t5);
	fp_add(&t5, &in1->Y, &in1->Z);
	fp_add(&out->X, &in2->Y, &in2->Z);

	fp_mul(&t5, &t5, &out->X);
	fp_add(&out->X, &t1, &t2);
	fp_sub(&t5, &t5, &out->X);
	fp_mul(&out->Z, &in1->crv->a, &t4);
	fp_mul(&out->X, &in1->crv->b3, &t2);

	fp_add(&out->Z, &out->X, &out->Z);
	fp_sub(&out->X, &t1, &out->Z);
	fp_add(&out->Z, &t1, &out->Z);
	fp_mul(&out->Y, &out->X, &out->Z);
	fp_add(&t1, &t0, &t0);

	fp_add(&t1, &t1, &t0);
	fp_mul(&t2, &in1->crv->a, &t2);
	fp_mul(&t4, &in1->crv->b3, &t4);
	fp_add(&t1, &t1, &t2);
	fp_sub(&t2, &t0, &t2);

	fp_mul(&t2, &in1->crv->a, &t2);
	fp_add(&t4, &t4, &t2);
	fp_mul(&t0, &t1, &t4);
	fp_add(&out->Y, &out->Y, &t0);
	fp_mul(&t0, &t5, &t4);

	fp_mul(&out->X, &t3, &out->X);
	fp_sub(&out->X, &out->X, &t0);
	fp_mul(&t0, &t3, &t1);
	fp_mul(&out->Z, &t5, &out->Z);
	fp_add(&out->Z, &out->Z, &t0);

	fp_uninit(&t0);
	fp_uninit(&t1);
	fp_uninit(&t2);
	fp_uninit(&t3);
	fp_uninit(&t4);
	fp_uninit(&t5);
#else
	fp Y1Z2, X1Z2, Z1Z2, u, uu, v, vv, vvv, R, A;

	/* Info: initialization check of in1 and in2 done at upper level */
	MUST_HAVE(in1->crv == in2->crv);

	prj_pt_init(out, in1->crv);

	fp_init(&Y1Z2, out->crv->a.ctx);
	fp_init(&X1Z2, out->crv->a.ctx);
	fp_init(&Z1Z2, out->crv->a.ctx);
	fp_init(&u, out->crv->a.ctx);
	fp_init(&uu, out->crv->a.ctx);
	fp_init(&v, out->crv->a.ctx);
	fp_init(&vv, out->crv->a.ctx);
	fp_init(&vvv, out->crv->a.ctx);
	fp_init(&R, out->crv->a.ctx);
	fp_init(&A, out->crv->a.ctx);

	MUST_HAVE(out->crv == in1->crv);
	MUST_HAVE(out->crv == in2->crv);
	MUST_HAVE(!prj_pt_iszero(in1));
	MUST_HAVE(!prj_pt_iszero(in2));
	MUST_HAVE(!prj_pt_eq_or_opp(in1, in2));

	/* Y1Z2 = Y1*Z2 */
	fp_mul(&Y1Z2, &(in1->Y), &(in2->Z));

	/* X1Z2 = X1*Z2 */
	fp_mul(&X1Z2, &(in1->X), &(in2->Z));

	/* Z1Z2 = Z1*Z2 */
	fp_mul(&Z1Z2, &(in1->Z), &(in2->Z));

	/* u = Y2*Z1-Y1Z2 */
	fp_mul(&u, &(in2->Y), &(in1->Z));
	fp_sub(&u, &u, &Y1Z2);

	/* uu = u² */
	fp_sqr(&uu, &u);

	/* v = X2*Z1-X1Z2 */
	fp_mul(&v, &(in2->X), &(in1->Z));
	fp_sub(&v, &v, &X1Z2);

	/* vv = v² */
	fp_sqr(&vv, &v);

	/* vvv = v*vv */
	fp_mul(&vvv, &v, &vv);

	/* R = vv*X1Z2 */
	fp_mul(&R, &vv, &X1Z2);

	/* A = uu*Z1Z2-vvv-2*R */
	fp_mul(&A, &uu, &Z1Z2);
	fp_sub(&A, &A, &vvv);
	fp_sub(&A, &A, &R);
	fp_sub(&A, &A, &R);

	/* X3 = v*A */
	fp_mul(&(out->X), &v, &A);

	/* Y3 = u*(R-A)-vvv*Y1Z2 */
	fp_sub(&R, &R, &A);
	fp_mul(&(out->Y), &u, &R);
	fp_mul(&R, &vvv, &Y1Z2);
	fp_sub(&(out->Y), &(out->Y), &R);

	/* Z3 = vvv*Z1Z2 */
	fp_mul(&(out->Z), &vvv, &Z1Z2);

	fp_uninit(&Y1Z2);
	fp_uninit(&X1Z2);
	fp_uninit(&Z1Z2);
	fp_uninit(&u);
	fp_uninit(&uu);
	fp_uninit(&v);
	fp_uninit(&vv);
	fp_uninit(&vvv);
	fp_uninit(&R);
	fp_uninit(&A);
#endif
}

/* Aliased version */
static void _prj_pt_add(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
	if ((out == in1) || (out == in2)) {
		prj_pt out_cpy;
		prj_pt_init(&out_cpy, out->crv);
		prj_pt_copy(&out_cpy, out);
		__prj_pt_add(&out_cpy, in1, in2);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		__prj_pt_add(out, in1, in2);
	}
}

/*
 * Public version of the addition to handle the case where the inputs are
 * zero or opposites
 */
void prj_pt_add(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
	prj_pt_check_initialized(in1);
	prj_pt_check_initialized(in2);

#ifdef NO_USE_COMPLETE_FORMULAS
	if (prj_pt_iszero(in1)) {
		prj_pt_init(out, in2->crv);
		prj_pt_copy(out, in2);
	} else if (prj_pt_iszero(in2)) {
		prj_pt_init(out, in1->crv);
		prj_pt_copy(out, in1);
	} else if (prj_pt_eq_or_opp(in1, in2)) {
		if (prj_pt_cmp(in1, in2) == 0) {
			prj_pt_dbl(out, in1);
		} else {
			prj_pt_init(out, in1->crv);
			prj_pt_zero(out);
		}
	} else {
		_prj_pt_add(out, in1, in2);
	}
#else
	_prj_pt_add(out, in1, in2);
#endif
}

/*
 * If NO_USE_COMPLETE_FORMULAS flag is not defined addition formulas from Algorithm 3
 * of https://joostrenes.nl/publications/complete.pdf are used, otherwise
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
 */
static void __prj_pt_dbl(prj_pt_t out, prj_pt_src_t in)
{
#ifndef NO_USE_COMPLETE_FORMULAS
	fp t0, t1, t2 ,t3;

	/* Info: initialization check of in done at upper level */
	prj_pt_init(out, in->crv);

	fp_init(&t0, out->crv->a.ctx);
	fp_init(&t1, out->crv->a.ctx);
	fp_init(&t2, out->crv->a.ctx);
	fp_init(&t3, out->crv->a.ctx);

	MUST_HAVE(out->crv == in->crv);

	fp_mul(&t0, &in->X, &in->X);
	fp_mul(&t1, &in->Y, &in->Y);
	fp_mul(&t2, &in->Z, &in->Z);
	fp_mul(&t3, &in->X, &in->Y);
	fp_add(&t3, &t3, &t3);

	fp_mul(&out->Z, &in->X, &in->Z);
	fp_add(&out->Z, &out->Z, &out->Z);
	fp_mul(&out->X, &in->crv->a, &out->Z);
	fp_mul(&out->Y, &in->crv->b3, &t2);
	fp_add(&out->Y, &out->X, &out->Y);

	fp_sub(&out->X, &t1, &out->Y);
	fp_add(&out->Y, &t1, &out->Y);
	fp_mul(&out->Y, &out->X, &out->Y);
	fp_mul(&out->X, &t3, &out->X);
	fp_mul(&out->Z, &in->crv->b3, &out->Z);

	fp_mul(&t2, &in->crv->a, &t2);
	fp_sub(&t3, &t0, &t2);
	fp_mul(&t3, &in->crv->a, &t3);
	fp_add(&t3, &t3, &out->Z);
	fp_add(&out->Z, &t0, &t0);

	fp_add(&t0, &out->Z, &t0);
	fp_add(&t0, &t0, &t2);
	fp_mul(&t0, &t0, &t3);
	fp_add(&out->Y, &out->Y, &t0);
	fp_mul(&t2, &in->Y, &in->Z);

	fp_add(&t2, &t2, &t2);
	fp_mul(&t0, &t2, &t3);
	fp_sub(&out->X, &out->X, &t0);
	fp_mul(&out->Z, &t2, &t1);
	fp_add(&out->Z, &out->Z, &out->Z);

	fp_add(&out->Z, &out->Z, &out->Z);

	fp_uninit(&t0);
	fp_uninit(&t1);
	fp_uninit(&t2);
	fp_uninit(&t3);
#else
	fp XX, ZZ, w, s, ss, sss, R, RR, B, h;

	/* Info: initialization check of in done at upper level */
	prj_pt_init(out, in->crv);

	fp_init(&XX, out->crv->a.ctx);
	fp_init(&ZZ, out->crv->a.ctx);
	fp_init(&w, out->crv->a.ctx);
	fp_init(&s, out->crv->a.ctx);
	fp_init(&ss, out->crv->a.ctx);
	fp_init(&sss, out->crv->a.ctx);
	fp_init(&R, out->crv->a.ctx);
	fp_init(&RR, out->crv->a.ctx);
	fp_init(&B, out->crv->a.ctx);
	fp_init(&h, out->crv->a.ctx);

	MUST_HAVE(out->crv == in->crv);
	MUST_HAVE(!prj_pt_iszero(in));

	/* XX = X1² */
	fp_sqr(&XX, &(in->X));

	/* ZZ = Z1² */
	fp_sqr(&ZZ, &(in->Z));

	/* w = a*ZZ+3*XX */
	fp_mul(&w, &(in->crv->a), &ZZ);
	fp_add(&w, &w, &XX);
	fp_add(&w, &w, &XX);
	fp_add(&w, &w, &XX);

	/* s = 2*Y1*Z1 */
	fp_mul(&s, &(in->Y), &(in->Z));
	fp_add(&s, &s, &s);

	/* ss = s² */
	fp_sqr(&ss, &s);

	/* sss = s*ss */
	fp_mul(&sss, &s, &ss);

	/* R = Y1*s */
	fp_mul(&R, &(in->Y), &s);

	/* RR = R² */
	fp_sqr(&RR, &R);

	/* B = (X1+R)²-XX-RR */
	fp_add(&R, &R, &(in->X));
	fp_sqr(&B, &R);
	fp_sub(&B, &B, &XX);
	fp_sub(&B, &B, &RR);

	/* h = w²-2*B */
	fp_sqr(&h, &w);
	fp_sub(&h, &h, &B);
	fp_sub(&h, &h, &B);

	/* X3 = h*s */
	fp_mul(&(out->X), &h, &s);

	/* Y3 = w*(B-h)-2*RR */
	fp_sub(&B, &B, &h);
	fp_mul(&(out->Y), &w, &B);
	fp_sub(&(out->Y), &(out->Y), &RR);
	fp_sub(&(out->Y), &(out->Y), &RR);

	/* Z3 = sss */
	fp_copy(&(out->Z), &sss);

	fp_uninit(&XX);
	fp_uninit(&ZZ);
	fp_uninit(&w);
	fp_uninit(&s);
	fp_uninit(&ss);
	fp_uninit(&sss);
	fp_uninit(&R);
	fp_uninit(&RR);
	fp_uninit(&B);
	fp_uninit(&h);
#endif
}

/* Aliased version */
static void _prj_pt_dbl(prj_pt_t out, prj_pt_src_t in)
{
	if (out == in) {
		prj_pt out_cpy;
		prj_pt_init(&out_cpy, out->crv);
		prj_pt_copy(&out_cpy, out);
		__prj_pt_dbl(&out_cpy, in);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		__prj_pt_dbl(out, in);
	}
}

/*
 * Public version of the doubling to handle the case where the inputs are
 * zero or opposite
 */
void prj_pt_dbl(prj_pt_t out, prj_pt_src_t in)
{
	prj_pt_check_initialized(in);

#ifdef NO_USE_COMPLETE_FORMULAS
	if (prj_pt_iszero(in)) {
		prj_pt_init(out, in->crv);
		prj_pt_zero(out);
	} else {
		_prj_pt_dbl(out, in);
	}
#else
	_prj_pt_dbl(out, in);
#endif
}

/****** Scalar multiplication algorithms *****/

/* If nothing is specified regarding the scalar multiplication algorithm, we use
 * the Montgomery Ladder
 */
#if !defined(USE_DOUBLE_ADD_ALWAYS) && !defined(USE_MONTY_LADDER)
#define USE_MONTY_LADDER
#endif

#if defined(USE_DOUBLE_ADD_ALWAYS) && defined(USE_MONTY_LADDER)
#error "You can either choose USE_DOUBLE_ADD_ALWAYS or USE_MONTY_LADDER, not both!"
#endif

#ifdef USE_DOUBLE_ADD_ALWAYS
/* Double-and-Add-Always masked using Itoh et al. anti-ADPA
 * (Address-bit DPA) countermeasure.
 * See "A Practical Countermeasure against Address-Bit Differential Power Analysis"
 * by Itoh, Izu and Takenaka for more information.
 *
 * NOTE: this masked variant of the Double-and-Add-Always algorithm is always
 * used as it has a very small impact on performance and is inherently more
 * robust againt DPA.
 *
 * NOTE: the Double-and-Add-Always algorithm inherently depends on the MSB of the
 * scalar. In order to avoid leaking this MSB and fall into HNP (Hidden Number
 * Problem) issues, we use the trick described in https://eprint.iacr.org/2011/232.pdf
 * to have the MSB always set. However, since the scalar m might be less or bigger than
 * the order q of the curve, we distinguish three situations:
 *     - The scalar m is < q (the order), in this case we compute:
 *         -
 *        | m' = m + (2 * q) if [log(k + q)] == [log(q)],
 *        | m' = m + q otherwise.
 *         -
 *     - The scalar m is >= q and < q**2, in this case we compute:
 *         -
 *        | m' = m + (2 * (q**2)) if [log(k + (q**2))] == [log(q**2)],
 *        | m' = m + (q**2) otherwise.
 *         -
 *     - The scalar m is >= (q**2), in this case m == m'
 *
 *   => We only deal with 0 <= m < (q**2) using the countermeasure. When m >= (q**2),
 *      we stick with m' = m, accepting MSB issues (not much can be done in this case
 *      anyways). In the two first cases, Double-and-Add-Always is performed in constant
 *      time wrt the size of the scalar m.
 */
static void _prj_pt_mul_ltr_dbl_add_always(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	/* We use Itoh et al. notations here for T and the random r */
	prj_pt T[3];
	bitcnt_t mlen;
	int mbit, rbit;
	/* Random for masking the Double and Add Always algorithm */
	nn r;
	/* Random for projective coordinates masking */
        fp l;
	/* The new scalar we will use with MSB fixed to 1 (noted m' above).
	 * This helps dealing with constant time.
	 */
	nn m_msb_fixed;
	nn_src_t curve_order;
	nn curve_order_square;

	/* Check that the input is on the curve */
	MUST_HAVE(prj_pt_is_on_curve(in) == 1);
	/* Compute m' from m depending on the rule described above */
	curve_order = &(in->crv->order);
	/* First compute q**2 */
	nn_sqr(&curve_order_square, curve_order);
	/* Then compute m' depending on m size */
	if(nn_cmp(m, curve_order) < 0){
		/* Case where m < q */
		nn_add(&m_msb_fixed, m, curve_order);
		bitcnt_t msb_bit_len = nn_bitlen(&m_msb_fixed);
		bitcnt_t order_bitlen = nn_bitlen(curve_order);
		nn_cnd_add((msb_bit_len == order_bitlen), &m_msb_fixed, &m_msb_fixed, curve_order);
	}
	else if(nn_cmp(m, &curve_order_square) < 0){
		/* Case where m >= q and m < (q**2) */
		nn_add(&m_msb_fixed, m, &curve_order_square);
		bitcnt_t msb_bit_len = nn_bitlen(&m_msb_fixed);
		bitcnt_t curve_order_square_bitlen = nn_bitlen(&curve_order_square);
		nn_cnd_add((msb_bit_len == curve_order_square_bitlen), &m_msb_fixed, &m_msb_fixed, &curve_order_square);

	}
	else{
		/* Case where m >= (q**2) */
		nn_copy(&m_msb_fixed, m);
	}
	mlen = nn_bitlen(&m_msb_fixed);
	if(mlen == 0){
		/* Should not happen thanks to our MSB fixing trick, but in case ...
		 * Return the infinite point.
		 */
		prj_pt_init(out, in->crv);
		prj_pt_zero(out);
		return;
	}
	mlen--;

	/* Get a random r with the same size of m_msb_fixed */
	MUST_HAVE(!nn_get_random_len(&r, m_msb_fixed.wlen * WORD_BYTES));
        /* Get a random value l in Fp */
	MUST_HAVE(!fp_get_random(&l, in->X.ctx));
	rbit = nn_getbit(&r, mlen);

	/* Initialize points */
	prj_pt_init(&T[0], in->crv);
	prj_pt_init(&T[1], in->crv);
        /* 
	 * T[2] = R(P)
	 * Blind the point with projective coordinates (X, Y, Z) => (l*X, l*Y, l*Z)
         */
	prj_pt_init(&T[2], in->crv);
        fp_mul(&(T[2].X), &(in->X), &l);
        fp_mul(&(T[2].Y), &(in->Y), &l);
        fp_mul(&(T[2].Z), &(in->Z), &l);

	/*  T[r[n-1]] = T[2] */
	prj_pt_copy(&T[rbit], &T[2]);

	/* Main loop of Double and Add Always */
	while (mlen > 0) {
		int rbit_next;
		--mlen;
		/* rbit is r[i+1], and rbit_next is r[i] */
		rbit_next = nn_getbit(&r, mlen);
		/* mbit is m[i] */
		mbit = nn_getbit(&m_msb_fixed, mlen);
		/* Double: T[r[i+1]] = ECDBL(T[r[i+1]]) */
#ifndef NO_USE_COMPLETE_FORMULAS
                /* NOTE: in case of complete formulas, we use the
                 * addition for doubling, incurring a small performance hit
                 * for better SCA resistance.
                 */
		prj_pt_add(&T[rbit], &T[rbit], &T[rbit]);
#else
		prj_pt_dbl(&T[rbit], &T[rbit]);
#endif
		/* Add:  T[1-r[i+1]] = ECADD(T[r[i+1]],T[2]) */
		prj_pt_add(&T[1-rbit], &T[rbit], &T[2]);
		/* T[r[i]] = T[d[i] ^ r[i+1]] 
		 * NOTE: we use the low level nn_copy function here to avoid
		 * any possible leakage on operands with prj_pt_copy
		 */
		nn_copy(&(T[rbit_next].X.fp_val), &(T[mbit ^ rbit].X.fp_val));
		nn_copy(&(T[rbit_next].Y.fp_val), &(T[mbit ^ rbit].Y.fp_val));
		nn_copy(&(T[rbit_next].Z.fp_val), &(T[mbit ^ rbit].Z.fp_val));
		/* Update rbit */
		rbit = rbit_next;
	}
	/* Output: T[r[0]] */
	prj_pt_copy(out, &T[rbit]);
	/* Check that the output is on the curve */
	MUST_HAVE(prj_pt_is_on_curve(out) == 1);

	prj_pt_uninit(&T[0]);
	prj_pt_uninit(&T[1]);
	prj_pt_uninit(&T[2]);
	nn_uninit(&r);
	fp_uninit(&l);
	nn_uninit(&m_msb_fixed);
	nn_uninit(&curve_order_square);
}
#endif

#ifdef USE_MONTY_LADDER
/* Montgomery Ladder masked using Itoh et al. anti-ADPA
 * (Address-bit DPA) countermeasure.
 * See "A Practical Countermeasure against Address-Bit Differential Power Analysis"
 * by Itoh, Izu and Takenaka for more information.
 *
 * NOTE: this masked variant of the Montgomery Ladder algorithm is always
 * used as it has a very small impact on performance and is inherently more
 * robust againt DPA.
 *
 * NOTE: the Montgomery Ladder algorithm inherently depends on the MSB of the
 * scalar. In order to avoid leaking this MSB and fall into HNP (Hidden Number
 * Problem) issues, we use the trick described in https://eprint.iacr.org/2011/232.pdf
 * to have the MSB always set. However, since the scalar m might be less or bigger than
 * the order q of the curve, we distinguish three situations:
 *     - The scalar m is < q (the order), in this case we compute:
 *         -
 *        | m' = m + (2 * q) if [log(k + q)] == [log(q)],
 *        | m' = m + q otherwise.
 *         -
 *     - The scalar m is >= q and < q**2, in this case we compute:
 *         -
 *        | m' = m + (2 * (q**2)) if [log(k + (q**2))] == [log(q**2)],
 *        | m' = m + (q**2) otherwise.
 *         -
 *     - The scalar m is >= (q**2), in this case m == m'
 *
 *   => We only deal with 0 <= m < (q**2) using the countermeasure. When m >= (q**2),
 *      we stick with m' = m, accepting MSB issues (not much can be done in this case
 *      anyways). In the two first cases, Montgomery Ladder is performed in constant
 *      time wrt the size of the scalar m.
 */
static void _prj_pt_mul_ltr_ladder(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	/* We use Itoh et al. notations here for T and the random r */
	prj_pt T[3];
	bitcnt_t mlen;
	int mbit, rbit;
	/* Random for masking the Montgomery Ladder algorithm */
	nn r;
	/* Random for projective coordinates masking */
        fp l;
	/* The new scalar we will use with MSB fixed to 1 (noted m' above).
	 * This helps dealing with constant time.
	 */
	nn m_msb_fixed;
	nn_src_t curve_order;
	nn curve_order_square;

	/* Check that the input is on the curve */
	MUST_HAVE(prj_pt_is_on_curve(in) == 1);

	/* Compute m' from m depending on the rule described above */
	curve_order = &(in->crv->order);
	/* First compute q**2 */
	nn_sqr(&curve_order_square, curve_order);
	/* Then compute m' depending on m size */
	if(nn_cmp(m, curve_order) < 0){
		/* Case where m < q */
		nn_add(&m_msb_fixed, m, curve_order);
		bitcnt_t msb_bit_len = nn_bitlen(&m_msb_fixed);
		bitcnt_t order_bitlen = nn_bitlen(curve_order);
		nn_cnd_add((msb_bit_len == order_bitlen), &m_msb_fixed, &m_msb_fixed, curve_order);
	}
	else if(nn_cmp(m, &curve_order_square) < 0){
		/* Case where m >= q and m < (q**2) */
		nn_add(&m_msb_fixed, m, &curve_order_square);
		bitcnt_t msb_bit_len = nn_bitlen(&m_msb_fixed);
		bitcnt_t curve_order_square_bitlen = nn_bitlen(&curve_order_square);
		nn_cnd_add((msb_bit_len == curve_order_square_bitlen), &m_msb_fixed, &m_msb_fixed, &curve_order_square);

	}
	else{
		/* Case where m >= (q**2) */
		nn_copy(&m_msb_fixed, m);
	}
	mlen = nn_bitlen(&m_msb_fixed);
	if(mlen == 0){
		/* Should not happen thanks to our MSB fixing trick, but in case ...
		 * Return the infinite point.
		 */
		prj_pt_init(out, in->crv);
		prj_pt_zero(out);
		return;
	}
	mlen--;

	/* Get a random r with the same size of m_msb_fixed */
	MUST_HAVE(!nn_get_random_len(&r, m_msb_fixed.wlen * WORD_BYTES));
        /* Get a random value l in Fp */
	MUST_HAVE(!fp_get_random(&l, in->X.ctx));
	rbit = nn_getbit(&r, mlen);

	/* Initialize points */
	prj_pt_init(&T[0], in->crv);
	prj_pt_init(&T[1], in->crv);
	prj_pt_init(&T[2], in->crv);

	/* Initialize T[r[n-1]] to input point */
	prj_pt_copy(&T[rbit], in);
        /* Blind the point with projective coordinates (X, Y, Z) => (l*X, l*Y, l*Z)
         */
        fp_mul(&(T[rbit].X), &(T[rbit].X), &l);
        fp_mul(&(T[rbit].Y), &(T[rbit].Y), &l);
        fp_mul(&(T[rbit].Z), &(T[rbit].Z), &l);
	/* Initialize T[1-r[n-1]] with ECDBL(T[r[n-1]])) */
#ifndef NO_USE_COMPLETE_FORMULAS
       /* NOTE: in case of complete formulas, we use the
        * addition for doubling, incurring a small performance hit
        * for better SCA resistance.
        */
	prj_pt_add(&T[1-rbit], &T[rbit], &T[rbit]);
#else
	prj_pt_dbl(&T[1-rbit], &T[rbit]);
#endif
	/* Main loop of the Montgomery Ladder */
	while (mlen > 0) {
		int rbit_next;
		--mlen;
		/* rbit is r[i+1], and rbit_next is r[i] */
		rbit_next = nn_getbit(&r, mlen);
		/* mbit is m[i] */
		mbit = nn_getbit(&m_msb_fixed, mlen);
		/* Double: T[2] = ECDBL(T[d[i] ^ r[i+1]]) */
#ifndef NO_USE_COMPLETE_FORMULAS
                /* NOTE: in case of complete formulas, we use the
                 * addition for doubling, incurring a small performance hit
		 * for better SCA resistance.
		 */
		prj_pt_add(&T[2], &T[mbit ^ rbit], &T[mbit ^ rbit]);
#else
		prj_pt_dbl(&T[2], &T[mbit ^ rbit]);
#endif
		/* Add: T[1] = ECADD(T[0],T[1]) */
		prj_pt_add(&T[1], &T[0], &T[1]);
		/* T[0] = T[2-(d[i] ^ r[i])] */
		/* NOTE: we use the low level nn_copy function here to avoid
		 * any possible leakage on operands with prj_pt_copy
		 */
		nn_copy(&(T[0].X.fp_val), &(T[2-(mbit ^ rbit_next)].X.fp_val));
		nn_copy(&(T[0].Y.fp_val), &(T[2-(mbit ^ rbit_next)].Y.fp_val));
		nn_copy(&(T[0].Z.fp_val), &(T[2-(mbit ^ rbit_next)].Z.fp_val));
		/* T[1] = T[1+(d[i] ^ r[i])] */
		/* NOTE: we use the low level nn_copy function here to avoid
		 * any possible leakage on operands with prj_pt_copy
		 */
		nn_copy(&(T[1].X.fp_val), &(T[1+(mbit ^ rbit_next)].X.fp_val));
		nn_copy(&(T[1].Y.fp_val), &(T[1+(mbit ^ rbit_next)].Y.fp_val));
		nn_copy(&(T[1].Z.fp_val), &(T[1+(mbit ^ rbit_next)].Z.fp_val));
		/* Update rbit */
		rbit = rbit_next;
	}
	/* Output: T[r[0]] */
	prj_pt_copy(out, &T[rbit]);
	/* Check that the output is on the curve */
	MUST_HAVE(prj_pt_is_on_curve(out) == 1);

	prj_pt_uninit(&T[0]);
	prj_pt_uninit(&T[1]);
	prj_pt_uninit(&T[2]);
	nn_uninit(&r);
	fp_uninit(&l);
	nn_uninit(&m_msb_fixed);
	nn_uninit(&curve_order_square);
}
#endif

/* Main projective scalar multiplication function.
 * Depending on the preprocessing options, we use either the
 * Double and Add Always algorithm, or the Montgomery Ladder one.
 */
static void _prj_pt_mul_ltr(prj_pt_t out, nn_src_t m, prj_pt_src_t in){
#if defined(USE_DOUBLE_ADD_ALWAYS)
	_prj_pt_mul_ltr_dbl_add_always(out, m, in);
#elif defined(USE_MONTY_LADDER)
	_prj_pt_mul_ltr_ladder(out, m, in);
#else
#error "Error: neither Double and Add Always nor Montgomery Ladder has been selected!"
#endif
	return;
}

/* Aliased version */
void prj_pt_mul(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt_check_initialized(in);
	nn_check_initialized(m);

	if (out == in) {
		prj_pt out_cpy;
		prj_pt_init(&out_cpy, out->crv);
		prj_pt_copy(&out_cpy, out);
		_prj_pt_mul_ltr(&out_cpy, m, in);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		_prj_pt_mul_ltr(out, m, in);
	}
}


int prj_pt_mul_blind(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	/* Blind the scalar m with (b*q) */
	/* First compute the order x cofactor */
	nn b;
	nn_src_t q;
	int ret = -1;

	prj_pt_check_initialized(in);

	q = &(in->crv->order);

	nn_init(&b, 0);

	ret = nn_get_random_mod(&b, q);
	if (ret) {
		ret = -1;
		goto err;
	}

	nn_mul(&b, &b, q);
	nn_add(&b, &b, m);

	/* NOTE: point blinding is performed in the lower
	 * functions
	 */

	/* Perform the scalar multiplication */
	prj_pt_mul(out, &b, in);

	ret = 0;
err:
	/* Zero the mask to avoid information leak */
	nn_zero(&b);
	nn_uninit(&b);

	return ret;
}

/*
 * Map points from Edwards to short Weierstrass projective points through Montgomery (composition mapping).
 *     Point at infinity (0, 1) -> (0, 1, 0) is treated as an exception, which is trivially not constant time.
 *     This is OK since our mapping functions should be used at the non sensitive input and output
 *     interfaces.
 * 
 */
void aff_pt_edwards_to_prj_pt_shortw(aff_pt_edwards_src_t in_edwards, ec_shortw_crv_src_t shortw_crv, prj_pt_t out_shortw, fp_src_t alpha_edwards)
{
	aff_pt out_shortw_aff;
	fp one;

	/* Check the curves compatibility */
	MUST_HAVE(curve_edwards_shortw_check(in_edwards->crv, shortw_crv, alpha_edwards) == 1);
	
	/* Initialize output point with curve */
	prj_pt_init(out_shortw, shortw_crv);

	fp_init(&one, in_edwards->x.ctx);
	fp_one(&one);
	/* Check if we are the point at infinity
	 * This check induces a non consant time exception, but the current function must be called on
	 * public data anyways.
	 */
	if(fp_iszero(&(in_edwards->x)) && (fp_cmp(&(in_edwards->y), &one) == 0)){
		prj_pt_zero(out_shortw);
		goto out;
	}
	
	/* Use the affine mapping */
	aff_pt_edwards_to_shortw(in_edwards, shortw_crv, &out_shortw_aff, alpha_edwards);
	/* And then map the short Weierstrass affine to projective coordinates */
	ec_shortw_aff_to_prj(out_shortw, &out_shortw_aff);
	aff_pt_uninit(&out_shortw_aff);

out:
	fp_uninit(&one);
	return;
}

/*
 * Map points from short Weierstrass projective points to Edwards through Montgomery (composition mapping).
 *     Point at infinity with Z=0 (in projective coordinates) -> (0, 1) is treated as an exception, which is trivially not constant time.
 *     This is OK since our mapping functions should be used at the non sensitive input and output
 *     interfaces.
 * 
 */
void prj_pt_shortw_to_aff_pt_edwards(prj_pt_src_t in_shortw, ec_edwards_crv_src_t edwards_crv, aff_pt_edwards_t out_edwards, fp_src_t alpha_edwards)
{
	aff_pt in_shortw_aff;

	/* Check the curves compatibility */
	MUST_HAVE(curve_edwards_shortw_check(edwards_crv, in_shortw->crv, alpha_edwards) == 1);
	
	/* Initialize output point with curve */
	aff_pt_init(&in_shortw_aff, in_shortw->crv);

	/* Check if we are the point at infinity
	 * This check induces a non consant time exception, but the current function must be called on
	 * public data anyways.
	 */
	if(prj_pt_iszero(in_shortw)){
		fp zero, one;
		fp_init(&zero, in_shortw->X.ctx);
		fp_init(&one, in_shortw->X.ctx);
		/**/
		fp_zero(&zero);
		fp_one(&one);
		/**/
		aff_pt_edwards_init_from_coords(out_edwards, edwards_crv, &zero, &one);
		/**/		
		fp_uninit(&zero);
		fp_uninit(&one);
		goto out;
	}

	/* Map projective to affine on the short Weierstrass */
	prj_pt_to_aff(&in_shortw_aff, in_shortw);
	/* Use the affine mapping */
	aff_pt_shortw_to_edwards(&in_shortw_aff, edwards_crv, out_edwards, alpha_edwards);

out:
	aff_pt_uninit(&in_shortw_aff);

	return;
}

/*
 * Map points from Montgomery to short Weierstrass projective points.
 */
void aff_pt_montgomery_to_prj_pt_shortw(aff_pt_montgomery_src_t in_montgomery, ec_shortw_crv_src_t shortw_crv, prj_pt_t out_shortw)
{
	aff_pt out_shortw_aff;

	/* Check the curves compatibility */
	MUST_HAVE(curve_montgomery_shortw_check(in_montgomery->crv, shortw_crv) == 1);
	
	/* Initialize output point with curve */
	prj_pt_init(out_shortw, shortw_crv);
	
	/* Use the affine mapping */
	aff_pt_montgomery_to_shortw(in_montgomery, shortw_crv, &out_shortw_aff);
	/* And then map the short Weierstrass affine to projective coordinates */
	ec_shortw_aff_to_prj(out_shortw, &out_shortw_aff);

	aff_pt_uninit(&out_shortw_aff);

	return;
}

/*
 * Map points from short Weierstrass projective points to Montgomery.
 * 
 */
void prj_pt_shortw_to_aff_pt_montgomery(prj_pt_src_t in_shortw, ec_montgomery_crv_src_t montgomery_crv, aff_pt_montgomery_t out_montgomery)
{
	aff_pt in_shortw_aff;

	/* Check the curves compatibility */
	MUST_HAVE(curve_montgomery_shortw_check(montgomery_crv, in_shortw->crv) == 1);
	
	/* Initialize output point with curve */
	aff_pt_init(&in_shortw_aff, in_shortw->crv);

	/* Map projective to affine on the short Weierstrass */
	prj_pt_to_aff(&in_shortw_aff, in_shortw);
	/* Use the affine mapping */
	aff_pt_shortw_to_montgomery(&in_shortw_aff, montgomery_crv, out_montgomery);

	aff_pt_uninit(&in_shortw_aff);

	return;
}

