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
#include "fp_mul.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_div.h"
#include "../nn/nn_modinv.h"

void fp_mul(fp_t out, fp_src_t in1, fp_src_t in2)
{
	nn prod;

	fp_check_initialized(in1);
	fp_check_initialized(in2);
	fp_check_initialized(out);

	nn_init(&prod, 2 * (in1->ctx->p.wlen) * WORD_BYTES);

	MUST_HAVE(out->ctx == in1->ctx);
	MUST_HAVE(out->ctx == in2->ctx);

	nn_mul(&prod, &(in1->fp_val), &(in2->fp_val));
	nn_mod_unshifted(&(out->fp_val), &prod, &(in1->ctx->p_normalized),
			 in1->ctx->p_reciprocal, in1->ctx->p_shift);

	nn_uninit(&prod);
}

void fp_sqr(fp_t out, fp_src_t in)
{
	fp_mul(out, in, in);
}

void fp_inv(fp_t out, fp_src_t in)
{
	int ret;

	fp_check_initialized(in);
	fp_check_initialized(out);

	MUST_HAVE(out->ctx == in->ctx);
	ret = nn_modinv(&(out->fp_val), &(in->fp_val), &(in->ctx->p));
	MUST_HAVE(ret == 1);
}

void fp_div(fp_t out, fp_src_t num, fp_src_t den)
{
	fp inv;

	fp_check_initialized(num);
	fp_check_initialized(den);
	fp_check_initialized(out);

	fp_init(&inv, den->ctx);

	MUST_HAVE(out->ctx == num->ctx);
	MUST_HAVE(out->ctx == den->ctx);

	fp_inv(&inv, den);
	fp_mul(out, num, &inv);

	fp_uninit(&inv);
}
