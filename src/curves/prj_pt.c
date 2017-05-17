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
#include "../fp/fp_add.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_montgomery.h"

#define PRJ_PT_MAGIC ((word_t)(0xe1cd70babb1d5afeULL))

void prj_pt_check_initialized(prj_pt_src_t in)
{
	MUST_HAVE((in != NULL) && (in->magic == PRJ_PT_MAGIC)
		  && (in->crv != NULL));
}

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

void ec_shortw_aff_to_prj(prj_pt_t out, aff_pt_src_t in)
{
	aff_pt_check_initialized(in);

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
	fp_init_from_buf(&(pt->Z), ctx, pt_buf + 2 * coord_len, coord_len);

	/* Set the curve */
	pt->crv = crv;

	/* Mark the point as initialized */
	pt->magic = PRJ_PT_MAGIC;

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

	ctx = pt->crv->a.ctx;
	coord_len = BYTECEIL(ctx->p_bitlen);

	if (pt_buf_len != (3 * coord_len)) {
		return -1;
	}

	/* Export the three coordinates */
	fp_export_to_buf(pt_buf, coord_len, &(pt->X));
	fp_export_to_buf(pt_buf + coord_len, coord_len, &(pt->Y));
	fp_export_to_buf(pt_buf + 2 * coord_len, coord_len, &(pt->Z));

	return 0;
}

/*
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
 */
static void __prj_pt_add(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
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
}

/*
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
 */
static void __prj_pt_dbl(prj_pt_t out, prj_pt_src_t in)
{
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

	if (prj_pt_iszero(in)) {
		prj_pt_init(out, in->crv);
		prj_pt_zero(out);
	} else {
		_prj_pt_dbl(out, in);
	}
}

static void _prj_pt_mul(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt dbl;
	bitcnt_t mlen;
	int mbit;

	MUST_HAVE(!prj_pt_iszero(in));
	MUST_HAVE(!nn_iszero(m));

	prj_pt_copy(out, in);
	prj_pt_init(&dbl, in->crv);

	mlen = nn_bitlen(m) - 1;
	while (mlen > 0) {
		--mlen;
		mbit = nn_getbit(m, mlen);
		prj_pt_dbl(&dbl, out);
		prj_pt_add(out, &dbl, in);
		nn_cnd_swap(!mbit, &(out->X.fp_val), &(dbl.X.fp_val));
		nn_cnd_swap(!mbit, &(out->Y.fp_val), &(dbl.Y.fp_val));
		nn_cnd_swap(!mbit, &(out->Z.fp_val), &(dbl.Z.fp_val));
	}

	prj_pt_uninit(&dbl);
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
		_prj_pt_mul(&out_cpy, m, in);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		_prj_pt_mul(out, m, in);
	}
}
