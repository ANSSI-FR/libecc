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
#include "aff_pt.h"

#define AFF_PT_MAGIC ((word_t)(0x4c82a9bcd0d9ffabULL))

/* Verify that a prj point has already been initialized */
void aff_pt_check_initialized(aff_pt_src_t in)
{
	MUST_HAVE((in != NULL) && (in->magic == AFF_PT_MAGIC)
		  && (in->crv != NULL));
}

/* Verify that an affine point has already been initialized.
 * Return 0 or 1.
 */
int aff_pt_is_initialized(aff_pt_src_t in)
{
	return !!((in != NULL) && (in->magic == AFF_PT_MAGIC) &&
		   (in->crv != NULL));
}

/*
 * Initialize pointed aff_pt structure to make it usable by library
 * function on given curve.
 */
void aff_pt_init(aff_pt_t in, ec_shortw_crv_src_t curve)
{
	MUST_HAVE(in != NULL);
	ec_shortw_crv_check_initialized(curve);

	fp_init(&(in->x), curve->a.ctx);
	fp_init(&(in->y), curve->a.ctx);
	in->crv = curve;
	in->magic = AFF_PT_MAGIC;
}

void aff_pt_init_from_coords(aff_pt_t in,
			     ec_shortw_crv_src_t curve,
			     fp_src_t xcoord, fp_src_t ycoord)
{
	aff_pt_init(in, curve);
	fp_copy(&(in->x), xcoord);
	fp_copy(&(in->y), ycoord);
}

/*
 * Uninitialize pointed affine point to prevent further use (magic field
 * in the structure is zeroized) and zeroize associated storage space.
 * Note that the curve context pointed to by the point element (passed
 * during init) is left untouched.
 */
void aff_pt_uninit(aff_pt_t in)
{
	fp_uninit(&(in->x));
	fp_uninit(&(in->y));
	in->crv = NULL;
	in->magic = WORD(0);
}

/*
 * Return 1 if the point of coordinates (x,y) is on the curve, i.e. if it
 * verifies curve equation y^2 = x^3 + ax + b. Returns 0 otherwise.
 */
int is_on_shortw_curve(fp_src_t x, fp_src_t y, ec_shortw_crv_src_t curve)
{
	fp y2, ax, x3, x2, tmp, tmp2;
	int ret;

	ec_shortw_crv_check_initialized(curve);
	fp_check_initialized(x);
	fp_check_initialized(y);
	MUST_HAVE(x->ctx == y->ctx);
	MUST_HAVE(x->ctx == curve->a.ctx);

	fp_init(&y2, x->ctx);
	fp_sqr(&y2, y);

	fp_init(&ax, x->ctx);
	fp_mul(&ax, &(curve->a), x);

	fp_init(&x2, x->ctx);
	fp_sqr(&x2, x);

	fp_init(&x3, x->ctx);
	fp_mul(&x3, &x2, x);

	fp_init(&tmp, x->ctx);
	fp_add(&tmp, &ax, &curve->b);

	fp_init(&tmp2, x->ctx);
	fp_add(&tmp2, &x3, &tmp);

	ret = !fp_cmp(&y2, &tmp2);

	fp_uninit(&y2);
	fp_uninit(&ax);
	fp_uninit(&x3);
	fp_uninit(&x2);
	fp_uninit(&tmp);
	fp_uninit(&tmp2);

	return ret;
}

int aff_pt_is_on_curve(aff_pt_src_t pt)
{
	aff_pt_check_initialized(pt);
	return is_on_shortw_curve(&(pt->x), &(pt->y), pt->crv);
}

void ec_shortw_aff_copy(aff_pt_t out, aff_pt_src_t in)
{
	aff_pt_check_initialized(in);
	aff_pt_init(out, in->crv);

	fp_copy(&(out->x), &(in->x));
	fp_copy(&(out->y), &(in->y));
}

int ec_shortw_aff_cmp(aff_pt_src_t in1, aff_pt_src_t in2)
{
	aff_pt_check_initialized(in1);
	aff_pt_check_initialized(in2);
	MUST_HAVE(in1->crv == in2->crv);

	return fp_cmp(&(in1->x), &(in2->x)) | fp_cmp(&(in1->y), &(in2->y));
}

/*
 * Return 1 if given points (on the same curve) are equal or opposite.
 * Return 0 otherwise.
 */
int ec_shortw_aff_eq_or_opp(aff_pt_src_t in1, aff_pt_src_t in2)
{
	int ret;

	aff_pt_check_initialized(in1);
	aff_pt_check_initialized(in2);
	MUST_HAVE(in1->crv == in2->crv);

	ret = (fp_cmp(&(in1->x), &(in2->x)) == 0);
	ret &= fp_eq_or_opp(&(in1->y), &(in2->y));

	return ret;
}

/*
 * Import an affine point from a buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int aff_pt_import_from_buf(aff_pt_t pt,
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

        fp_init_from_buf(&(pt->x), ctx, pt_buf, coord_len);
        fp_init_from_buf(&(pt->y), ctx, pt_buf + coord_len, coord_len);

        /* Set the curve */
        pt->crv = crv;

        /* Mark the point as initialized */
        pt->magic = AFF_PT_MAGIC;

        /* Check that the point is indeed on the provided curve, uninitialize it
         * if this is not the case.
         */
        if(aff_pt_is_on_curve(pt) != 1){
                aff_pt_uninit(pt);
                return -1;
        }

        return 0;
}


/* Export an affine point to a buffer with the following layout; the 2
 * coordinates (elements of Fp) are each encoded on p_len bytes, where p_len
 * is the size of p in bytes (e.g. 66 for a prime p of 521 bits). Each
 * coordinate is encoded in big endian. Size of buffer must exactly match
 * 2 * p_len.
 */
int aff_pt_export_to_buf(aff_pt_src_t pt, u8 *pt_buf, u32 pt_buf_len)
{
        fp_ctx_src_t ctx;
        u16 coord_len;

        aff_pt_check_initialized(pt);
        MUST_HAVE(pt_buf != NULL);

        /* The point to be exported must be on the curve */
        MUST_HAVE(aff_pt_is_on_curve(pt) == 1);

        ctx = pt->crv->a.ctx;
        coord_len = BYTECEIL(ctx->p_bitlen);

        if (pt_buf_len != (2 * coord_len)) {
                return -1;
        }

        /* Export the three coordinates */
        fp_export_to_buf(pt_buf, coord_len, &(pt->x));
        fp_export_to_buf(pt_buf + coord_len, coord_len, &(pt->y));

        return 0;
}
