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
#include "../nn/nn_logical.h"
#include "fp_mul_redc1.h"
#include "fp_pow.h"
#include "fp.h"

/*
 * NOT constant time with regard to the bitlength of exp.
 * Aliasing not supported.
 */
#define TAB_ENTRIES 2
static void _fp_pow(fp_t out, fp_src_t base, nn_src_t exp)
{
	fp base_monty, mul_monty, sqr_monty, out_monty, r;
	fp_src_t tab_monty[TAB_ENTRIES];
	bitcnt_t explen;
	u8 expbit;

	fp_check_initialized(base);
	nn_check_initialized(exp);
	fp_init(out, base->ctx);

	/* Exponentiating to zero provides 1 */
	if(nn_iszero(exp)){
		fp_one(out);
		return;
	}

	fp_init(&base_monty, out->ctx);
	fp_init(&mul_monty, out->ctx);
	fp_init(&sqr_monty, out->ctx);
	fp_init(&out_monty, out->ctx);
	fp_init(&r, out->ctx);
	fp_set_nn(&r, &(out->ctx->r));

	explen = nn_bitlen(exp) - 1;

	fp_redcify(&base_monty, base);
	nn_copy(&(out_monty.fp_val), &(base_monty.fp_val));

	tab_monty[0] = &r;
	tab_monty[1] = &base_monty;

	while (explen > 0) {
		explen -= (bitcnt_t)1;
		expbit = nn_getbit(exp, explen);
		fp_sqr_redc1(&sqr_monty, &out_monty);
		fp_tabselect(&mul_monty, expbit, tab_monty, TAB_ENTRIES);
		fp_mul_redc1(&out_monty, &sqr_monty, &mul_monty);
	}

	fp_unredcify(out, &out_monty);

	fp_uninit(&base_monty);
	fp_uninit(&mul_monty);
	fp_uninit(&sqr_monty);
	fp_uninit(&out_monty);
	fp_uninit(&r);
}

/* Aliased version */
void fp_pow(fp_t out, fp_src_t base, nn_src_t exp)
{
	/* Handle output aliasing */
	if (out == base) {
		fp out_cpy;

		_fp_pow(&out_cpy, base, exp);
		fp_init(out, out_cpy.ctx);
		fp_copy(out, &out_cpy);
		fp_uninit(&out_cpy);
	} else {
		_fp_pow(out, base, exp);
	}
}
