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
#include "ec_params.h"

/*
 * Initialize (already allocated) curve parameters structure pointed by
 * ec_params using value provided in remaining parameters.
 */
void import_params(ec_params *out_params, const ec_str_params *in_str_params)
{
	nn tmp_p, tmp_p_bitlen, tmp_r, tmp_r_square, tmp_mpinv, tmp_p_shift;
	nn tmp_p_normalized, tmp_p_reciprocal, tmp_npoints, tmp_order;
	nn tmp_order_bitlen, tmp_cofactor;
	fp tmp_a, tmp_b, tmp_gx, tmp_gy, tmp_gz;

	local_memset(out_params, 0, sizeof(ec_params));

	/*
	 * We first need to import p, the prime defining Fp and associated
	 * Montgomery parameters (r, r^2 and mpinv)
	 */
	nn_init_from_buf(&tmp_p, PARAM_BUF_PTR(in_str_params->p),
			 PARAM_BUF_LEN(in_str_params->p));

	nn_init_from_buf(&tmp_p_bitlen,
			 PARAM_BUF_PTR(in_str_params->p_bitlen),
			 PARAM_BUF_LEN(in_str_params->p_bitlen));

	nn_init_from_buf(&tmp_r, PARAM_BUF_PTR(in_str_params->r),
			 PARAM_BUF_LEN(in_str_params->r));

	nn_init_from_buf(&tmp_r_square,
			 PARAM_BUF_PTR(in_str_params->r_square),
			 PARAM_BUF_LEN(in_str_params->r_square));

	nn_init_from_buf(&tmp_mpinv,
			 PARAM_BUF_PTR(in_str_params->mpinv),
			 PARAM_BUF_LEN(in_str_params->mpinv));

	nn_init_from_buf(&tmp_p_shift,
			 PARAM_BUF_PTR(in_str_params->p_shift),
			 PARAM_BUF_LEN(in_str_params->p_shift));

	nn_init_from_buf(&tmp_p_normalized,
			 PARAM_BUF_PTR(in_str_params->p_normalized),
			 PARAM_BUF_LEN(in_str_params->p_normalized));

	nn_init_from_buf(&tmp_p_reciprocal,
			 PARAM_BUF_PTR(in_str_params->p_reciprocal),
			 PARAM_BUF_LEN(in_str_params->p_reciprocal));

	/* From p, we can create global Fp context */
	fp_ctx_init(&(out_params->ec_fp), &tmp_p,
		    (bitcnt_t)(tmp_p_bitlen.val[0]),
		    &tmp_r, &tmp_r_square,
		    tmp_mpinv.val[0], (bitcnt_t)tmp_p_shift.val[0],
		    &tmp_p_normalized, tmp_p_reciprocal.val[0]);

	/*
	 * Having Fp context, we can import a and b, the coefficient of
	 * of Weierstrass equation.
	 */
	fp_init_from_buf(&tmp_a, &(out_params->ec_fp),
			 PARAM_BUF_PTR(in_str_params->a),
			 PARAM_BUF_LEN(in_str_params->a));
	fp_init_from_buf(&tmp_b, &(out_params->ec_fp),
			 PARAM_BUF_PTR(in_str_params->b),
			 PARAM_BUF_LEN(in_str_params->b));

	/* Now, we can create curve context from a and b. */
	ec_shortw_crv_init(&(out_params->ec_curve), &tmp_a, &tmp_b);

	/* Now we can store the number of points on the curve */
	nn_init_from_buf(&tmp_npoints,
			 PARAM_BUF_PTR(in_str_params->npoints),
			 PARAM_BUF_LEN(in_str_params->npoints));
	nn_init(&(out_params->ec_curve_points), tmp_npoints.wlen * WORD_BYTES);
	nn_copy(&(out_params->ec_curve_points), &tmp_npoints);

	/* Let's now import G from its affine coordinates (gx,gy) */
	fp_init_from_buf(&tmp_gx, &(out_params->ec_fp),
			 PARAM_BUF_PTR(in_str_params->gx),
			 PARAM_BUF_LEN(in_str_params->gx));
	fp_init_from_buf(&tmp_gy, &(out_params->ec_fp),
			 PARAM_BUF_PTR(in_str_params->gy),
			 PARAM_BUF_LEN(in_str_params->gy));
	fp_init_from_buf(&tmp_gz, &(out_params->ec_fp),
			 PARAM_BUF_PTR(in_str_params->gz),
			 PARAM_BUF_LEN(in_str_params->gz));
	prj_pt_init_from_coords(&(out_params->ec_gen),
				&(out_params->ec_curve),
				&tmp_gx, &tmp_gy, &tmp_gz);

	/*
	 * Now we can store the number of points in the group generated
	 * by g and the associated cofactor (i.e. npoints / order).
	 */
	nn_init_from_buf(&tmp_order,
			 PARAM_BUF_PTR(in_str_params->order),
			 PARAM_BUF_LEN(in_str_params->order));
	nn_init(&(out_params->ec_gen_order), tmp_order.wlen * WORD_BYTES);
	nn_copy(&(out_params->ec_gen_order), &tmp_order);

	nn_init_from_buf(&tmp_order_bitlen,
			 PARAM_BUF_PTR(in_str_params->order_bitlen),
			 PARAM_BUF_LEN(in_str_params->order_bitlen));
	out_params->ec_gen_order_bitlen = (bitcnt_t)(tmp_order_bitlen.val[0]);

	nn_init_from_buf(&tmp_cofactor,
			 PARAM_BUF_PTR(in_str_params->cofactor),
			 PARAM_BUF_LEN(in_str_params->cofactor));
	nn_init(&(out_params->ec_gen_cofactor),
		tmp_cofactor.wlen * WORD_BYTES);
	nn_copy(&(out_params->ec_gen_cofactor), &tmp_cofactor);

	/* Import a local copy of curve OID */
	local_memset(out_params->curve_oid, 0, MAX_CURVE_OID_LEN);
	local_strncpy((char *)out_params->curve_oid,
		      (const char *)in_str_params->oid->buf,
		      MAX_CURVE_OID_LEN - 1);

	/* Import a local copy of curve name */
	local_memset(out_params->curve_name, 0, MAX_CURVE_NAME_LEN);
	local_strncpy((char *)out_params->curve_name,
		      (const char *)in_str_params->name->buf,
		      MAX_CURVE_NAME_LEN - 1);

	/* Uninit temporary parameters */
	nn_uninit(&tmp_p);
	nn_uninit(&tmp_r);
	nn_uninit(&tmp_r_square);
	nn_uninit(&tmp_mpinv);
	nn_uninit(&tmp_p_shift);
	nn_uninit(&tmp_p_normalized);
	nn_uninit(&tmp_p_reciprocal);
	fp_uninit(&tmp_a);
	fp_uninit(&tmp_b);
	nn_uninit(&tmp_npoints);
	fp_uninit(&tmp_gx);
	fp_uninit(&tmp_gy);
	fp_uninit(&tmp_gz);
	nn_uninit(&tmp_order);
	nn_uninit(&tmp_cofactor);
}
