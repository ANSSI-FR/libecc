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

/* NOTE: Edwards here implies Twisted Edwards curves
 * (these in fact include/extend basic form Edwards curves).
 */

#define AFF_PT_EDWARDS_MAGIC ((word_t)(0x8390a9bc43d9ffabULL))

/* Verify that an affine point has already been initialized */
void aff_pt_edwards_check_initialized(aff_pt_edwards_src_t in)
{
	MUST_HAVE((in != NULL) && (in->magic == AFF_PT_EDWARDS_MAGIC)
		  && (in->crv != NULL));
}

/* Verify that an affine point has already been initialized.
 * Return 0 or 1.
 */
int aff_pt_edwards_is_initialized(aff_pt_edwards_src_t in)
{
	return !!((in != NULL) && (in->magic == AFF_PT_EDWARDS_MAGIC) &&
		   (in->crv != NULL));
}

/*
 * Initialize pointed aff_pt_edwards structure to make it usable by library
 * function on given curve.
 */
void aff_pt_edwards_init(aff_pt_edwards_t in, ec_edwards_crv_src_t curve)
{
	MUST_HAVE(in != NULL);
	ec_edwards_crv_check_initialized(curve);

	fp_init(&(in->x), curve->a.ctx);
	fp_init(&(in->y), curve->a.ctx);
	in->crv = curve;
	in->magic = AFF_PT_EDWARDS_MAGIC;
}

void aff_pt_edwards_init_from_coords(aff_pt_edwards_t in,
			     ec_edwards_crv_src_t curve,
			     fp_src_t xcoord, fp_src_t ycoord)
{
	aff_pt_edwards_init(in, curve);
	fp_copy(&(in->x), xcoord);
	fp_copy(&(in->y), ycoord);
}

/*
 * Uninitialize pointed affine point to prevent further use (magic field
 * in the structure is zeroized) and zeroize associated storage space.
 * Note that the curve context pointed to by the point element (passed
 * during init) is left untouched.
 */
void aff_pt_edwards_uninit(aff_pt_edwards_t in)
{
	fp_uninit(&(in->x));
	fp_uninit(&(in->y));
	in->crv = NULL;
	in->magic = WORD(0);
}

/*
 * Return 1 if the point of coordinates (u,v) is on the curve, i.e. if it
 * verifies curve equation a*x^2 + y^2 = 1 + d*x^2*y^2. Returns 0 otherwise.
 */
int is_on_edwards_curve(fp_src_t x, fp_src_t y, ec_edwards_crv_src_t curve)
{
	fp x2, y2, tmp1, tmp2;
	int ret;

	ec_edwards_crv_check_initialized(curve);
	fp_check_initialized(x);
	fp_check_initialized(y);
	MUST_HAVE(x->ctx == y->ctx);
	MUST_HAVE(x->ctx == curve->a.ctx);

	fp_init(&x2, x->ctx);
	fp_sqr(&x2, x);
	fp_init(&y2, x->ctx);
	fp_sqr(&y2, y);

	fp_init(&tmp1, x->ctx);
	fp_init(&tmp2, x->ctx);

	fp_mul(&tmp1, &x2, &y2);
	fp_mul(&tmp1, &tmp1, &(curve->d));
	fp_inc(&tmp1, &tmp1);

	fp_mul(&tmp2, &x2, &(curve->a));
	fp_add(&tmp2, &tmp2, &y2);

	ret = !fp_cmp(&tmp1, &tmp2);

	fp_uninit(&x2);
	fp_uninit(&y2);
	fp_uninit(&tmp1);
	fp_uninit(&tmp2);

	return ret;
}

int aff_pt_edwards_is_on_curve(aff_pt_edwards_src_t pt)
{
	aff_pt_edwards_check_initialized(pt);
	return is_on_edwards_curve(&(pt->x), &(pt->y), pt->crv);
}

void ec_edwards_aff_copy(aff_pt_edwards_t out, aff_pt_edwards_src_t in)
{
	aff_pt_edwards_check_initialized(in);
	aff_pt_edwards_init(out, in->crv);

	fp_copy(&(out->x), &(in->x));
	fp_copy(&(out->y), &(in->y));
}

int ec_edwards_aff_cmp(aff_pt_edwards_src_t in1, aff_pt_edwards_src_t in2)
{
	aff_pt_edwards_check_initialized(in1);
	aff_pt_edwards_check_initialized(in2);
	MUST_HAVE(in1->crv == in2->crv);

	return fp_cmp(&(in1->x), &(in2->x)) | fp_cmp(&(in1->y), &(in2->y));
}

/*
 * Import an Edwards affine point from a buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int aff_pt_edwards_import_from_buf(aff_pt_edwards_t pt,
                           const u8 *pt_buf,
                           u16 pt_buf_len, ec_edwards_crv_src_t crv)
{
        fp_ctx_src_t ctx;
        u16 coord_len;
	int ret = -1;

        ec_edwards_crv_check_initialized(crv);
        MUST_HAVE(pt_buf != NULL);

        ctx = crv->a.ctx;
        coord_len = BYTECEIL(ctx->p_bitlen);

        if (pt_buf_len != (2 * coord_len)) {
		ret = -1;
                goto err;
        }

        fp_init_from_buf(&(pt->x), ctx, pt_buf, coord_len);
        fp_init_from_buf(&(pt->y), ctx, pt_buf + coord_len, coord_len);

        /* Set the curve */
        pt->crv = crv;

        /* Mark the point as initialized */
        pt->magic = AFF_PT_EDWARDS_MAGIC;

        /* Check that the point is indeed on the provided curve, uninitialize it
         * if this is not the case.
         */
        if(aff_pt_edwards_is_on_curve(pt) != 1){
                aff_pt_edwards_uninit(pt);
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
int aff_pt_edwards_export_to_buf(aff_pt_edwards_src_t pt, u8 *pt_buf, u32 pt_buf_len)
{
        fp_ctx_src_t ctx;
        u16 coord_len;
	int ret = -1;

        aff_pt_edwards_check_initialized(pt);
        MUST_HAVE(pt_buf != NULL);

        /* The point to be exported must be on the curve */
        MUST_HAVE(aff_pt_edwards_is_on_curve(pt) == 1);

        ctx = pt->crv->a.ctx;
        coord_len = BYTECEIL(ctx->p_bitlen);

        if (pt_buf_len != (2 * coord_len)) {
		ret = -1;
		goto err;
        }

        /* Export the three coordinates */
        fp_export_to_buf(pt_buf, coord_len, &(pt->x));
        fp_export_to_buf(pt_buf + coord_len, coord_len, &(pt->y));

        ret = 0;
err:
	return ret;
}

/*
 * Mapping curves from twisted Edwards to Montgomery.
 *
 *  E{a, d} is mapped to M{A, B} using the formula:
 *    A = 2(a+d)/(a-d)
 *    B = 4/((a-d) * alpha^2)
 */
void curve_edwards_to_montgomery(ec_edwards_crv_src_t edwards_crv, ec_montgomery_crv_t montgomery_crv, fp_src_t alpha_edwards)
{
	fp tmp1, tmp2, A, B;

	ec_edwards_crv_check_initialized(edwards_crv);
	MUST_HAVE(fp_is_initialized(alpha_edwards) && (edwards_crv->a.ctx == alpha_edwards->ctx));

	fp_init(&tmp1, edwards_crv->a.ctx);
	fp_init(&tmp2, edwards_crv->a.ctx);
	fp_init(&A, edwards_crv->a.ctx);
	fp_init(&B, edwards_crv->a.ctx);


	/* Compute Z = (alpha ^ 2) et T = 2 / ((a-d) * Z)
	 * and then:
	 *   A = 2(a+d)/(a-d) = Z * (a + d) * T
	 *   B = 4/((a-d) * alpha^2) = 2 * T
	 */
	fp_sqr(&tmp1, alpha_edwards);
	fp_sub(&tmp2, &(edwards_crv->a), &(edwards_crv->d));
	fp_mul(&tmp2, &tmp2, &tmp1);
	fp_inv(&tmp2, &tmp2);
	fp_set_word_value(&B, WORD(2));
	fp_mul(&tmp2, &tmp2, &B);

	fp_add(&A, &(edwards_crv->a), &(edwards_crv->d));
	fp_mul(&A, &A, &tmp1);
	fp_mul(&A, &A, &tmp2);
	fp_mul(&B, &B, &tmp2);

	/* Initialize our Montgomery curve */
	ec_montgomery_crv_init(montgomery_crv, &A, &B, &(edwards_crv->order));

	fp_uninit(&tmp1);
	fp_uninit(&tmp2);
	fp_uninit(&A);
	fp_uninit(&B);
	return;
}

int curve_edwards_montgomery_check(ec_edwards_crv_src_t edwards_crv, ec_montgomery_crv_src_t montgomery_crv, fp_src_t alpha_edwards)
{
	int ret = 0;

        ec_montgomery_crv montgomery_crv_check;

        curve_edwards_to_montgomery(edwards_crv, &montgomery_crv_check, alpha_edwards);

        /* Check elements */
        if(fp_cmp(&(montgomery_crv_check.A), &(montgomery_crv->A)) != 0){
		ret = 0;
                goto err;
        }
        if(fp_cmp(&(montgomery_crv_check.B), &(montgomery_crv->B)) != 0){
		ret = 0;
                goto err;
        }
        if(nn_cmp(&(montgomery_crv_check.order), &(montgomery_crv->order)) != 0){
		ret = 0;
                goto err;
        }

        ret = 1;
err:
	ec_montgomery_crv_uninit(&montgomery_crv_check);
        return ret;
}

/*
 * Mapping curves from Montgomery to twisted Edwards.
 *
 *  M{A, B} is mapped to E{a, d} using the formula:
 *    a = (A+2)/(B * alpha^2)
 *    d = (A-2)/(B * alpha^2)
 *
 *  Or the inverse (switch a and d roles).
 */
void curve_montgomery_to_edwards(ec_montgomery_crv_src_t montgomery_crv, ec_edwards_crv_t edwards_crv, fp_src_t alpha_edwards)
{
        fp tmp, tmp2, a, d;

        ec_montgomery_crv_check_initialized(montgomery_crv);
	MUST_HAVE(fp_is_initialized(alpha_edwards) && (montgomery_crv->A.ctx == alpha_edwards->ctx));

        fp_init(&tmp, montgomery_crv->A.ctx);
        fp_init(&tmp2, montgomery_crv->A.ctx);
        fp_init(&a, montgomery_crv->A.ctx);
        fp_init(&d, montgomery_crv->A.ctx);

	fp_set_word_value(&tmp, WORD(2));
	fp_mul(&tmp2, &(montgomery_crv->B), alpha_edwards);
	fp_mul(&tmp2, &tmp2, alpha_edwards);
	fp_inv(&tmp2, &tmp2);

	/* a = (A+2)/(B * alpha^2) */
	fp_add(&a, &(montgomery_crv->A), &tmp);
	fp_mul(&a, &a, &tmp2);

	/* d = (A-2)/(B * alpha^2) */
	fp_sub(&d, &(montgomery_crv->A), &tmp);
	fp_mul(&d, &d, &tmp2);

        /* Initialize our Edwards curve */
	/* Check if we have to inverse a and d */
	fp_one(&tmp);
	if(fp_cmp(&d, &tmp) == 0){
	        ec_edwards_crv_init(edwards_crv, &d, &a, &(montgomery_crv->order));
	}
	else{
	        ec_edwards_crv_init(edwards_crv, &a, &d, &(montgomery_crv->order));
	}

	fp_uninit(&tmp);
	fp_uninit(&tmp2);
	fp_uninit(&a);
	fp_uninit(&d);
	return;
}

/*
 * Mapping curve from Edwards to short Weierstrass and vice-versa.
 *
 */
void curve_edwards_to_shortw(ec_edwards_crv_src_t edwards_crv, ec_shortw_crv_t shortw_crv, fp_src_t alpha_edwards)
{
	ec_montgomery_crv montgomery_crv;

	curve_edwards_to_montgomery(edwards_crv, &montgomery_crv, alpha_edwards);
	curve_montgomery_to_shortw(&montgomery_crv, shortw_crv);

	ec_montgomery_crv_uninit(&montgomery_crv);

	return;
}

int curve_edwards_shortw_check(ec_edwards_crv_src_t edwards_crv, ec_shortw_crv_src_t shortw_crv, fp_src_t alpha_edwards)
{
	ec_montgomery_crv montgomery_crv;
	int ret;

	curve_edwards_to_montgomery(edwards_crv, &montgomery_crv, alpha_edwards);

	ret = curve_montgomery_shortw_check(&montgomery_crv, shortw_crv);

	ec_montgomery_crv_uninit(&montgomery_crv);

	return ret;
}

void curve_shortw_to_edwards(ec_shortw_crv_src_t shortw_crv, ec_edwards_crv_t edwards_crv, fp_src_t alpha_montgomery, fp_src_t gamma_montgomery, fp_src_t alpha_edwards)
{
	ec_montgomery_crv montgomery_crv;

	curve_shortw_to_montgomery(shortw_crv, &montgomery_crv, alpha_montgomery, gamma_montgomery);

	curve_montgomery_to_edwards(&montgomery_crv, edwards_crv, alpha_edwards);

	ec_montgomery_crv_uninit(&montgomery_crv);

	return;
}

/*
 * Mapping points from twisted Edwards to Montgomery.
 *   Point E(x, y) is mapped to M(u, v) with the formula:
 *       - (0, 1) mapped to the point at infinity (not possible in our affine coordinates)
 *       - (0, -1) mapped to (0, 0)
 *       - (u, v) mapped to ((1+y)/(1-y), alpha * (1+y)/((1-y)x))
 */
void aff_pt_edwards_to_montgomery(aff_pt_edwards_src_t in_edwards, ec_montgomery_crv_src_t montgomery_crv, aff_pt_montgomery_t out_montgomery, fp_src_t alpha_edwards)
{
	/* NOTE: we attempt to perform the (0, -1) -> (0, 0) mapping in constant time.
	 * Hence the weird table selection.
	 */
        fp tmp, tmp2, x, y;
	fp tab_x[2];
	fp_src_t tab_x_t[2] = { &tab_x[0], &tab_x[1] };
	fp tab_y[2];
	fp_src_t tab_y_t[2] = { &tab_y[0], &tab_y[1] };

	ec_montgomery_crv_check_initialized(montgomery_crv);

	/* Check input point is on its curve */
	MUST_HAVE(aff_pt_edwards_is_on_curve(in_edwards));
	MUST_HAVE(curve_edwards_montgomery_check(in_edwards->crv, montgomery_crv, alpha_edwards) == 1);

	fp_init(&tmp, in_edwards->crv->a.ctx);
	fp_init(&tmp2, in_edwards->crv->a.ctx);
	fp_init(&x, in_edwards->crv->a.ctx);
	fp_init(&y, in_edwards->crv->a.ctx);
	fp_init(&tab_x[0], in_edwards->crv->a.ctx);
	fp_init(&tab_x[1], in_edwards->crv->a.ctx);
	fp_init(&tab_y[0], in_edwards->crv->a.ctx);
	fp_init(&tab_y[1], in_edwards->crv->a.ctx);

	fp_one(&tmp);
	/* We do not handle point at infinity in affine coordinates */
	MUST_HAVE(!(fp_iszero(&(in_edwards->x)) && (fp_cmp(&(in_edwards->y), &tmp) == 0)));
	/* Map (0, -1) to (0, 0) */
	fp_zero(&tmp2);
	fp_sub(&tmp2, &tmp2, &tmp);
	/* Copy 1 as x as dummy value */
	fp_one(&tab_x[0]);
	fp_copy(&tab_x[1], &(in_edwards->x));
	/* Copy -1 as y to produce (0, 0) */
	fp_copy(&tab_y[0], &tmp2);
	fp_copy(&tab_y[1], &(in_edwards->y));

	u8 idx = (fp_iszero(&(in_edwards->x)) && fp_cmp(&(in_edwards->y), &tmp2)) ? 0 : 1;
	fp_tabselect(&x, idx, tab_x_t, 2);
	fp_tabselect(&y, idx, tab_y_t, 2);

	aff_pt_montgomery_init(out_montgomery, montgomery_crv);
	/* Compute general case */
	fp_copy(&tmp2, &tmp);
	/* Put 1/(1-y) in tmp */
	fp_sub(&tmp, &tmp, &y);
	fp_inv(&tmp, &tmp);
	/* Put (1+y) in tmp2 */
	fp_add(&tmp2, &tmp2, &y);
	/* u = (1+y) / (1-y) */
	fp_mul(&(out_montgomery->u), &tmp, &tmp2);
	/* v = alpha_edwards * (1+y)/((1-y)x) */
	fp_inv(&(out_montgomery->v), &x);
	fp_mul(&(out_montgomery->v), &(out_montgomery->v), alpha_edwards);
	fp_mul(&(out_montgomery->v), &(out_montgomery->u), &(out_montgomery->v));

	/* Final check that the point is on the curve */
	MUST_HAVE(aff_pt_montgomery_is_on_curve(out_montgomery) == 1);

	fp_uninit(&tmp);
	fp_uninit(&tmp2);
	fp_uninit(&x);
	fp_uninit(&y);
	fp_uninit(&tab_x[0]);
	fp_uninit(&tab_x[1]);
	fp_uninit(&tab_y[0]);
	fp_uninit(&tab_y[1]);
	return;
}

/*
 * Mapping points from Montgomery to twisted Edwards.
 *   Point M(u, v) is mapped to E(x, y) with the formula:
 *       - Point at infinity mapped to (0, 1) (not possible in our affine coordinates)
 *       - (0, 0) mapped to (0, -1)
 *       - (x, y) mapped to (alpha * (u/v), (u-1)/(u+1))
 */
void aff_pt_montgomery_to_edwards(aff_pt_montgomery_src_t in_montgomery, ec_edwards_crv_src_t edwards_crv, aff_pt_edwards_t out_edwards, fp_src_t alpha)
{
	/* NOTE: we attempt to perform the (0, 0) -> (0, -1) mapping in constant time.
	 * Hence the weird table selection.
	 */
        fp tmp, u, v;
	fp tab_u[2];
	fp_src_t tab_u_t[2] = { &tab_u[0], &tab_u[1] };
	fp tab_v[2];
	fp_src_t tab_v_t[2] = { &tab_v[0], &tab_v[1] };

	ec_edwards_crv_check_initialized(edwards_crv);

	/* Check input point is on its curve */
	MUST_HAVE(aff_pt_montgomery_is_on_curve(in_montgomery));
	MUST_HAVE(curve_edwards_montgomery_check(edwards_crv, in_montgomery->crv, alpha) == 1);

	fp_init(&tmp, in_montgomery->crv->A.ctx);
	fp_init(&u, in_montgomery->crv->A.ctx);
	fp_init(&v, in_montgomery->crv->A.ctx);
	fp_init(&tab_u[0], in_montgomery->crv->A.ctx);
	fp_init(&tab_u[1], in_montgomery->crv->A.ctx);
	fp_init(&tab_v[0], in_montgomery->crv->A.ctx);
	fp_init(&tab_v[1], in_montgomery->crv->A.ctx);

	fp_one(&tmp);
	/* Map (0, 0) to (0, -1) */
	/* Copy 0 as u as dummy value */
	fp_zero(&tab_u[0]);
	fp_copy(&tab_u[1], &(in_montgomery->u));
	/* Copy 1 as v dummy value to produce (0, -1) */
	fp_copy(&tab_v[0], &tmp);
	fp_copy(&tab_v[1], &(in_montgomery->v));

	u8 idx = (fp_iszero(&(in_montgomery->u)) && fp_iszero(&(in_montgomery->v))) ? 0 : 1;
	fp_tabselect(&u, idx, tab_u_t, 2);
	fp_tabselect(&v, idx, tab_v_t, 2);

	aff_pt_edwards_init(out_edwards, edwards_crv);
	/* x = alpha * (u / v) */
	fp_inv(&(out_edwards->x), &v);
	fp_mul(&(out_edwards->x), &(out_edwards->x), alpha);
	fp_mul(&(out_edwards->x), &(out_edwards->x), &u);
	/* y = (u-1)/(u+1) */
	fp_add(&(out_edwards->y), &u, &tmp);
	fp_inv(&(out_edwards->y), &(out_edwards->y));
	fp_sub(&tmp, &u, &tmp);
	fp_mul(&(out_edwards->y), &(out_edwards->y), &tmp);

	/* Final check that the point is on the curve */
	MUST_HAVE(aff_pt_edwards_is_on_curve(out_edwards) == 1);

	fp_uninit(&tmp);
	fp_uninit(&u);
	fp_uninit(&v);
	fp_uninit(&tab_u[0]);
	fp_uninit(&tab_u[1]);
	fp_uninit(&tab_v[0]);
	fp_uninit(&tab_v[1]);
	return;
}


/*
 * Map points from Edwards to short Weierstrass through Montgomery (composition mapping).
 *
 */
void aff_pt_edwards_to_shortw(aff_pt_edwards_src_t in_edwards, ec_shortw_crv_src_t shortw_crv, aff_pt_t out_shortw, fp_src_t alpha_edwards)
{
	aff_pt_montgomery inter_montgomery;
	ec_montgomery_crv inter_montgomery_crv;

	/* First, map from Edwards to Montgomery */
	curve_edwards_to_montgomery(in_edwards->crv, &inter_montgomery_crv, alpha_edwards);
	aff_pt_edwards_to_montgomery(in_edwards, &inter_montgomery_crv, &inter_montgomery, alpha_edwards);

	/* Then map from Montgomery to short Weierstrass */
	aff_pt_montgomery_to_shortw(&inter_montgomery, shortw_crv, out_shortw);

	aff_pt_montgomery_uninit(&inter_montgomery);
	ec_montgomery_crv_uninit(&inter_montgomery_crv);

	return;
}

/*
 * Map points from projective short Weierstrass to Edwards through Montgomery (composition mapping).
 *
 */
void aff_pt_shortw_to_edwards(aff_pt_src_t in_shortw, ec_edwards_crv_src_t edwards_crv, aff_pt_edwards_t out_edwards, fp_src_t alpha_edwards)
{
	aff_pt_montgomery inter_montgomery;
	ec_montgomery_crv inter_montgomery_crv;

	/* First, map from short Weierstrass to Montgomery */
	curve_edwards_to_montgomery(edwards_crv, &inter_montgomery_crv, alpha_edwards);
	aff_pt_shortw_to_montgomery(in_shortw, &inter_montgomery_crv, &inter_montgomery);

	/* Then map from Montgomery to Edwards */
	aff_pt_montgomery_to_edwards(&inter_montgomery, edwards_crv, out_edwards, alpha_edwards);

	aff_pt_montgomery_uninit(&inter_montgomery);
	ec_montgomery_crv_uninit(&inter_montgomery_crv);

	return;
}
