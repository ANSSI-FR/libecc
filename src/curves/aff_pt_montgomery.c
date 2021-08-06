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
#include "aff_pt.h"

#define AFF_PT_MONTGOMERY_MAGIC ((word_t)(0x7390a9bc43d94598ULL))

/* Verify that an affine point has already been initialized */
void aff_pt_montgomery_check_initialized(aff_pt_montgomery_src_t in)
{
	MUST_HAVE((in != NULL) && (in->magic == AFF_PT_MONTGOMERY_MAGIC)
		  && (in->crv != NULL));
}

/* Verify that an affine point has already been initialized.
 * Return 0 or 1.
 */
int aff_pt_montgomery_is_initialized(aff_pt_montgomery_src_t in)
{
	return !!((in != NULL) && (in->magic == AFF_PT_MONTGOMERY_MAGIC) &&
		   (in->crv != NULL));
}

/*
 * Initialize pointed aff_pt_montgomery structure to make it usable by library
 * function on given curve.
 */
void aff_pt_montgomery_init(aff_pt_montgomery_t in, ec_montgomery_crv_src_t curve)
{
	MUST_HAVE(in != NULL);
	ec_montgomery_crv_check_initialized(curve);

	fp_init(&(in->u), curve->A.ctx);
	fp_init(&(in->v), curve->A.ctx);
	in->crv = curve;
	in->magic = AFF_PT_MONTGOMERY_MAGIC;
}

void aff_pt_montgomery_init_from_coords(aff_pt_montgomery_t in,
			     ec_montgomery_crv_src_t curve,
			     fp_src_t ucoord, fp_src_t vcoord)
{
	aff_pt_montgomery_init(in, curve);
	fp_copy(&(in->u), ucoord);
	fp_copy(&(in->v), vcoord);
}

/*
 * Uninitialize pointed affine point to prevent further use (magic field
 * in the structure is zeroized) and zeroize associated storage space.
 * Note that the curve context pointed to by the point element (passed
 * during init) is left untouched.
 */
void aff_pt_montgomery_uninit(aff_pt_montgomery_t in)
{
	fp_uninit(&(in->u));
	fp_uninit(&(in->v));
	in->crv = NULL;
	in->magic = WORD(0);
}

/*
 * Return 1 if the point of coordinates (u,v) is on the curve, i.e. if it
 * verifies curve equation B*v^2 = u^3 + A*u^2 + u. Returns 0 otherwise.
 */
int is_on_montgomery_curve(fp_src_t u, fp_src_t v, ec_montgomery_crv_src_t curve)
{
	fp Bv2, u3, Au2, tmp;
	int ret;

	ec_montgomery_crv_check_initialized(curve);
	fp_check_initialized(u);
	fp_check_initialized(v);
	MUST_HAVE(u->ctx == v->ctx);
	MUST_HAVE(u->ctx == curve->A.ctx);

	fp_init(&Bv2, v->ctx);
	fp_sqr(&Bv2, v);
	fp_mul(&Bv2, &(curve->B), &Bv2);

	fp_init(&Au2, u->ctx);
	fp_sqr(&Au2, u);
	fp_copy(&u3, &Au2);
	fp_mul(&Au2, &(curve->A), &Au2);

	fp_mul(&u3, &u3, u);

	fp_init(&tmp, u->ctx);
	fp_add(&tmp, &u3, &Au2);
	fp_add(&tmp, &tmp, u);

	ret = !fp_cmp(&tmp, &Bv2);

	fp_uninit(&Bv2);
	fp_uninit(&u3);
	fp_uninit(&Au2);
	fp_uninit(&tmp);

	return ret;
}

int aff_pt_montgomery_is_on_curve(aff_pt_montgomery_src_t pt)
{
	aff_pt_montgomery_check_initialized(pt);
	return is_on_montgomery_curve(&(pt->u), &(pt->v), pt->crv);
}

void ec_montgomery_aff_copy(aff_pt_montgomery_t out, aff_pt_montgomery_src_t in)
{
	aff_pt_montgomery_check_initialized(in);
	aff_pt_montgomery_init(out, in->crv);

	fp_copy(&(out->u), &(in->u));
	fp_copy(&(out->v), &(in->v));
}

int ec_montgomery_aff_cmp(aff_pt_montgomery_src_t in1, aff_pt_montgomery_src_t in2)
{
	aff_pt_montgomery_check_initialized(in1);
	aff_pt_montgomery_check_initialized(in2);
	MUST_HAVE(in1->crv == in2->crv);

	return fp_cmp(&(in1->u), &(in2->u)) | fp_cmp(&(in1->v), &(in2->v));
}

/*
 * Import an Edwards affine point from a buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int aff_pt_montgomery_import_from_buf(aff_pt_montgomery_t pt,
                           const u8 *pt_buf,
                           u16 pt_buf_len, ec_montgomery_crv_src_t crv)
{
        fp_ctx_src_t ctx;
        u16 coord_len;
	int ret = -1;

        ec_montgomery_crv_check_initialized(crv);
        MUST_HAVE(pt_buf != NULL);

        ctx = crv->A.ctx;
        coord_len = BYTECEIL(ctx->p_bitlen);

        if (pt_buf_len != (2 * coord_len)) {
		ret = -1;
		goto err;
        }

        fp_init_from_buf(&(pt->u), ctx, pt_buf, coord_len);
        fp_init_from_buf(&(pt->v), ctx, pt_buf + coord_len, coord_len);

        /* Set the curve */
        pt->crv = crv;

        /* Mark the point as initialized */
        pt->magic = AFF_PT_MONTGOMERY_MAGIC;

        /* Check that the point is indeed on the provided curve, uninitialize it
         * if this is not the case.
         */
        if(aff_pt_montgomery_is_on_curve(pt) != 1){
                aff_pt_montgomery_uninit(pt);
		ret = -1;
		goto err;
        }

	ret = 0;
err:
        return ret;
}


/* Export an Edwards affine point to a buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int aff_pt_montgomery_export_to_buf(aff_pt_montgomery_src_t pt, u8 *pt_buf, u32 pt_buf_len)
{
        fp_ctx_src_t ctx;
        u16 coord_len;
	int ret = -1;

        aff_pt_montgomery_check_initialized(pt);
        MUST_HAVE(pt_buf != NULL);

        /* The point to be exported must be on the curve */
        MUST_HAVE(aff_pt_montgomery_is_on_curve(pt) == 1);

        ctx = pt->crv->A.ctx;
        coord_len = BYTECEIL(ctx->p_bitlen);

        if (pt_buf_len != (2 * coord_len)) {
		ret = -1;
		goto err;
        }

        /* Export the three coordinates */
        fp_export_to_buf(pt_buf, coord_len, &(pt->u));
        fp_export_to_buf(pt_buf + coord_len, coord_len, &(pt->v));

	ret = 0;
err:
        return ret;
}

/**** Mappings between curves *************/
/*
 * Mapping curves from Montgomery to short Weiertstrass.
 *
 *  M{A, B} is mapped to W{a, b} using the formula:
 *    a = (3-A^2)/(3*B^2)
 *    b = (2*A^3-9*A)/(27*B^3)
 */
void curve_montgomery_to_shortw(ec_montgomery_crv_src_t montgomery_crv, ec_shortw_crv_t shortw_crv)
{
	fp tmp, tmp2, a, b;

	ec_montgomery_crv_check_initialized(montgomery_crv);

	fp_init(&tmp, montgomery_crv->A.ctx);
	fp_init(&tmp2, montgomery_crv->A.ctx);
	fp_init(&a, montgomery_crv->A.ctx);
	fp_init(&b, montgomery_crv->A.ctx);

	/* Compute a */
	fp_sqr(&tmp, &(montgomery_crv->B));
        fp_set_word_value(&tmp2, WORD(3));
	/* 3*B^2 */
        fp_mul(&tmp, &tmp, &tmp2);
	/* (3*B^2)^-1 */
	fp_inv(&tmp, &tmp);

	/* (3-A^2) */
	fp_sqr(&tmp2, &(montgomery_crv->A));
        fp_set_word_value(&a, WORD(3));
	fp_sub(&tmp2, &a, &tmp2);

	fp_mul(&a, &tmp2, &tmp);

	/* Compute b */
	fp_sqr(&tmp, &(montgomery_crv->B));
	fp_mul(&tmp, &tmp, &(montgomery_crv->B));
        fp_set_word_value(&tmp2, WORD(27));
	/* (27*B^3) */
	fp_mul(&tmp, &tmp, &tmp2);
	/* (27*B^3)^-1 */
	fp_inv(&tmp, &tmp);

	/* (2*A^3-9*A) */
	fp_set_word_value(&tmp2, WORD(2));
	fp_mul(&tmp2, &tmp2, &(montgomery_crv->A));
	fp_mul(&tmp2, &tmp2, &(montgomery_crv->A));
	fp_mul(&tmp2, &tmp2, &(montgomery_crv->A));

	fp_set_word_value(&b, WORD(9));
	fp_mul(&b, &b, &(montgomery_crv->A));
	fp_sub(&b, &tmp2, &b);

	fp_mul(&b, &b, &tmp);

	/* Initialize our short Weiertstrass curve */
	ec_shortw_crv_init(shortw_crv, &a, &b, &(montgomery_crv->order));

	fp_uninit(&a);
	fp_uninit(&b);
	fp_uninit(&tmp);
	fp_uninit(&tmp2);

	return;
}

int curve_montgomery_shortw_check(ec_montgomery_crv_src_t montgomery_crv, ec_shortw_crv_src_t shortw_crv)
{
	ec_shortw_crv shortw_crv_check;
	int ret = 0;

	curve_montgomery_to_shortw(montgomery_crv, &shortw_crv_check);

	/* Check elements */
	if(fp_cmp(&(shortw_crv_check.a), &(shortw_crv->a)) != 0){
		ret = 0;
		goto err;
	}
	if(fp_cmp(&(shortw_crv_check.b), &(shortw_crv->b)) != 0){
		ret = 0;
		goto err;
	}
	if(nn_cmp(&(shortw_crv_check.order), &(shortw_crv->order)) != 0){
		ret = 0;
		goto err;
	}

	ret = 1;
err:
	ec_shortw_crv_uninit(&shortw_crv_check);
	return ret;
}

/*
 * Mapping curves from short Weiertstrass to Montgomery
 *
 *  W{a, b} is mapped to M{A, B} using the formula:
 *    A = 3 * alpha / gamma
 *    B = 1 / gamma
 *  with gamma square root of c = a + 3 * alpha**2
 */
void curve_shortw_to_montgomery(ec_shortw_crv_src_t shortw_crv, ec_montgomery_crv_t montgomery_crv, fp_src_t alpha, fp_src_t gamma)
{
	fp c, gamma_inv, A, tmp;

	ec_shortw_crv_check_initialized(shortw_crv);
	fp_check_initialized(alpha);
	fp_check_initialized(gamma);
	MUST_HAVE((alpha->ctx == shortw_crv->a.ctx) && (gamma->ctx == shortw_crv->a.ctx));

	fp_init(&A, shortw_crv->a.ctx);
	fp_init(&gamma_inv, shortw_crv->a.ctx);
	fp_init(&c, shortw_crv->a.ctx);
	fp_init(&tmp, shortw_crv->a.ctx);

	/* Compute 1 / gamma */
	fp_inv(&gamma_inv, gamma);

	/* Compute A */
        fp_set_word_value(&A, WORD(3));
	fp_mul(&A, &A, alpha);
	fp_mul(&A, &A, &gamma_inv);

	/* Sanity check on c */
	fp_set_word_value(&c, WORD(3));
	fp_mul(&c, &c, alpha);
	fp_mul(&c, &c, alpha);
	fp_add(&c, &c, &(shortw_crv->a));
	fp_sqr(&tmp, gamma);
	/* gamma ** 2 must be equal to c */
	MUST_HAVE(fp_cmp(&c, &tmp) == 0);

	/* B is simply the inverse of gamma */
	ec_montgomery_crv_init(montgomery_crv, &A, &gamma_inv, &(shortw_crv->order));

	fp_uninit(&A);
	fp_uninit(&gamma_inv);
	fp_uninit(&c);
	fp_uninit(&tmp);

	return;
}

/*
 * Mapping points from Montgomery to short Weierstrass.
 *   Point M(u, v) is mapped to W(x, y) with the formula:
 *       - (x, y) = ((u/B)+(A/3B), v/B)
 *
 */
void aff_pt_montgomery_to_shortw(aff_pt_montgomery_src_t in_montgomery, ec_shortw_crv_src_t shortw_crv, aff_pt_t out_shortw)
{
	fp tmp, tmp2;

	ec_shortw_crv_check_initialized(shortw_crv);

	/* Check that our input point is on its curve */
	MUST_HAVE(aff_pt_montgomery_is_on_curve(in_montgomery) == 1);

	fp_init(&tmp, in_montgomery->crv->A.ctx);
	fp_init(&tmp2, in_montgomery->crv->A.ctx);

	aff_pt_montgomery_check_initialized(in_montgomery);
	MUST_HAVE(curve_montgomery_shortw_check(in_montgomery->crv, shortw_crv) == 1);

	aff_pt_init(out_shortw, shortw_crv);

	fp_inv(&tmp, &(in_montgomery->crv->B));
	fp_mul(&tmp, &tmp, &(in_montgomery->u));

	fp_set_word_value(&tmp2, WORD(3));
	fp_mul(&tmp2, &tmp2, &(in_montgomery->crv->B));
	fp_inv(&tmp2, &tmp2);
	fp_mul(&tmp2, &tmp2, &(in_montgomery->crv->A));

	fp_add(&(out_shortw->x), &tmp, &tmp2);

	fp_inv(&tmp, &(in_montgomery->crv->B));
	fp_mul(&(out_shortw->y), &tmp, &(in_montgomery->v));

	/* Final check that the point is on the curve */
	MUST_HAVE(aff_pt_is_on_curve(out_shortw) == 1);

	fp_uninit(&tmp);
	fp_uninit(&tmp2);

	return;
}

/*
 * Mapping from short Weierstrass to Montgomery.
 *   Point W(x, y) is mapped to M(u, v) with the formula:
 *       - (u, v) = (((Bx)−(A/3), By)
 */
void aff_pt_shortw_to_montgomery(aff_pt_src_t in_shortw, ec_montgomery_crv_src_t montgomery_crv, aff_pt_montgomery_t out_montgomery)
{
	fp tmp, tmp2;

	ec_montgomery_crv_check_initialized(montgomery_crv);

	/* Check that our input point is on its curve */
	MUST_HAVE(aff_pt_is_on_curve(in_shortw) == 1);

	fp_init(&tmp, in_shortw->crv->a.ctx);
	fp_init(&tmp2, in_shortw->crv->a.ctx);

	MUST_HAVE(curve_montgomery_shortw_check(montgomery_crv, in_shortw->crv) != 0);

	aff_pt_montgomery_init(out_montgomery, montgomery_crv);

	/* A/3 */
	fp_inv_word(&tmp, WORD(3));
	fp_mul(&tmp, &tmp, &(montgomery_crv->A));

	/* Bx */
	fp_mul(&tmp2, &(montgomery_crv->B), &(in_shortw->x));

	/* u = (Bx) - (A/3) */
	fp_sub(&(out_montgomery->u), &tmp2, &tmp);

	/* v = By */
	fp_mul(&(out_montgomery->v), &(montgomery_crv->B), &(in_shortw->y));

	/* Final check that the point is on the curve */
	MUST_HAVE(aff_pt_montgomery_is_on_curve(out_montgomery) == 1);

	fp_uninit(&tmp);
	fp_uninit(&tmp2);

	return;
}
