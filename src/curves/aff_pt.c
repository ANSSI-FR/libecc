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

/* Verify that a prj point has already been initialized.
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
int is_on_curve(fp_src_t x, fp_src_t y, ec_shortw_crv_src_t curve)
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
