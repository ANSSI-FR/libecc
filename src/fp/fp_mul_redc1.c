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
#include "fp_mul_redc1.h"

/*
 * Perform Montgomery multiplication.
 */
static inline void _fp_mul_redc1(nn_t out, nn_src_t in1, nn_src_t in2,
				 fp_ctx_src_t ctx)
{
	nn_mul_redc1(out, in1, in2, &(ctx->p), ctx->mpinv);
}

void fp_mul_redc1(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp_check_initialized(in1);
	fp_check_initialized(in2);
	fp_check_initialized(out);

	MUST_HAVE(out->ctx == in1->ctx);
	MUST_HAVE(out->ctx == in2->ctx);

	_fp_mul_redc1(&(out->fp_val), &(in1->fp_val), &(in2->fp_val),
		      out->ctx);
}

void fp_sqr_redc1(fp_t out, fp_src_t in)
{
	fp_mul_redc1(out, in, in);
}

/*
 * redcify could be done by shifting and division by p.
 */
void fp_redcify(fp_t out, fp_src_t in)
{
	fp_check_initialized(in);
	fp_check_initialized(out);

	MUST_HAVE(out->ctx == in->ctx);
	_fp_mul_redc1(&(out->fp_val), &(in->fp_val), &(out->ctx->r_square),
		      out->ctx);
}

void fp_unredcify(fp_t out, fp_src_t in)
{
	nn one;

	fp_check_initialized(in);
	fp_check_initialized(out);

	nn_init(&one, 0);
	nn_one(&one);

	_fp_mul_redc1(&(out->fp_val), &(in->fp_val), &one, out->ctx);

	nn_uninit(&one);
}
