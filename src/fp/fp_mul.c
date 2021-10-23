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
#include "fp_pow.h"
#include "../nn/nn_add.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_div.h"
#include "../nn/nn_modinv.h"

int fp_mul(fp_t out, fp_src_t in1, fp_src_t in2)
{
	int ret;

	ret = fp_check_initialized(in1); EG(ret, err);
	ret = fp_check_initialized(in2); EG(ret, err);
	ret = fp_check_initialized(out); EG(ret, err);

	MUST_HAVE(out->ctx == in1->ctx, ret, err);
	MUST_HAVE(out->ctx == in2->ctx, ret, err);

	ret = nn_mul(&(out->fp_val), &(in1->fp_val), &(in2->fp_val)); EG(ret, err);
	ret = nn_mod_unshifted(&(out->fp_val), &(out->fp_val), &(in1->ctx->p_normalized),
                         in1->ctx->p_reciprocal, in1->ctx->p_shift);

err:
	return ret;
}

int fp_sqr(fp_t out, fp_src_t in)
{
	return fp_mul(out, in, in);
}

/* We use Fermat's little theorem for our inversion in Fp:
 *    x^(p-1) = 1 mod (p) means that x^(p-2) mod(p) is the modular
 *    inverse of x mod (p)
 */
int fp_inv(fp_t out, fp_src_t in)
{
	int ret, cmp;
	nn p_minus_two, two;
	two.magic = p_minus_two.magic = 0;

	ret = fp_check_initialized(in); EG(ret, err);
	ret = fp_check_initialized(out); EG(ret, err);

	MUST_HAVE(out->ctx == in->ctx, ret, err);

	/* For p <= 2, we use our regular nn_modinv */
	ret = nn_cmp_word(&(in->ctx->p), WORD(2), &cmp); EG(ret, err);
	if(cmp <= 0){
		ret = nn_modinv(&(out->fp_val), &(in->fp_val), &(in->ctx->p));
		goto err;
	}

	/* Else we compute x^(p-2) mod (p) */
	ret = nn_init(&p_minus_two, 0); EG(ret, err);

	ret = nn_init(&two, 0); EG(ret, err);
	ret = nn_set_word_value(&two, WORD(2)); EG(ret, err);

	ret = nn_sub(&p_minus_two, &(in->ctx->p), &two); EG(ret, err);

	ret = fp_pow(out, in, &p_minus_two);

err:
	nn_uninit(&p_minus_two);
	nn_uninit(&two);

	return ret;
}

int fp_inv_word(fp_t out, word_t w)
{
	int ret;

	ret = fp_check_initialized(out); EG(ret, err);

	ret = nn_modinv_word(&(out->fp_val), w, &(out->ctx->p));

err:
	return ret;
}

int fp_div(fp_t out, fp_src_t num, fp_src_t den)
{
	int ret;

	ret = fp_check_initialized(num); EG(ret, err);
 	ret = fp_check_initialized(den); EG(ret, err);
	ret = fp_check_initialized(out); EG(ret, err);

	MUST_HAVE(out->ctx == num->ctx, ret, err);
	MUST_HAVE(out->ctx == den->ctx, ret, err);

	ret = fp_inv(out, den); EG(ret, err);
	ret = fp_mul(out, num, out);

err:
	return ret;
}
