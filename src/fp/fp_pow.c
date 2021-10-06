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
 * Aliasing not supported. Expects caller to check parameters
 * have been initialized. This is an internal helper.
 *
 * Returns 0 on success, -1 on error.
 */
#define TAB_ENTRIES 2
ATTRIBUTE_WARN_UNUSED_RET static int _fp_pow(fp_t out, fp_src_t base, nn_src_t exp)
{
	fp base_monty, mul_monty, sqr_monty, out_monty, r;
	fp_src_t tab_monty[TAB_ENTRIES];
	bitcnt_t explen;
	u8 expbit;
	int ret, iszero;
	base_monty.magic = mul_monty.magic = sqr_monty.magic = out_monty.magic = r.magic = WORD(0);

	/* Exponentiating to zero provides 1 */
	ret = nn_iszero(exp, &iszero); EG(ret, err);
	if (iszero) {
		ret = fp_one(out);
		goto err;
	}

	ret = fp_init(&base_monty, out->ctx); EG(ret, err);
	ret = fp_init(&mul_monty, out->ctx); EG(ret, err);
	ret = fp_init(&sqr_monty, out->ctx); EG(ret, err);
	ret = fp_init(&out_monty, out->ctx); EG(ret, err);
	ret = fp_init(&r, out->ctx);  EG(ret, err);
	ret = fp_set_nn(&r, &(out->ctx->r)); EG(ret, err);

	ret = nn_bitlen(exp, &explen); EG(ret, err);

	/* Sanity check */
	MUST_HAVE((explen > 0), ret, err);

	explen -= (bitcnt_t)1;

	ret = fp_redcify(&base_monty, base); EG(ret, err);
	ret = nn_copy(&(out_monty.fp_val), &(base_monty.fp_val)); EG(ret, err);

	tab_monty[0] = &r;
	tab_monty[1] = &base_monty;

	while (explen > 0) {
		explen -= (bitcnt_t)1;

		ret = nn_getbit(exp, explen, &expbit); EG(ret, err);
		ret = fp_sqr_redc1(&sqr_monty, &out_monty); EG(ret, err);
		ret = fp_tabselect(&mul_monty, expbit, tab_monty, TAB_ENTRIES); EG(ret, err);
		ret = fp_mul_redc1(&out_monty, &sqr_monty, &mul_monty); EG(ret, err);
	}
	ret = fp_unredcify(out, &out_monty);

err:
	fp_uninit(&base_monty);
	fp_uninit(&mul_monty);
	fp_uninit(&sqr_monty);
	fp_uninit(&out_monty);
	fp_uninit(&r);

	return ret;
}

/*
 * Same purpose as above but handles aliasing of 'base' and 'out', i.e.
 * base is passed via 'out'.  Expects caller to check parameters
 * have been initialized. This is an internal helper.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _fp_pow_aliased(fp_t out, nn_src_t exp)
{
	fp base;
	int ret;
	base.magic = WORD(0);

	ret = fp_init(&base, out->ctx); EG(ret, err);
	ret = fp_copy(&base, out); EG(ret, err);
	ret = _fp_pow(out, &base, exp); EG(ret, err);

err:
	fp_uninit(&base);

	return ret;
}

/* Aliased version of previous one. */
int fp_pow(fp_t out, fp_src_t base, nn_src_t exp)
{
	int ret;

	ret = fp_check_initialized(base); EG(ret, err);
	ret = nn_check_initialized(exp); EG(ret, err);

	/* Handle output aliasing */
	if (out == base) {
		ret = _fp_pow_aliased(out, exp);
	} else {
		ret = fp_init(out, base->ctx);  EG(ret, err);
		ret = _fp_pow(out, base, exp);
	}

err:
	return ret;
}
