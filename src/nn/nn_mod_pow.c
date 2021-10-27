/*
 *  Copyright (C) 2021 - This file is part of libecc project
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
#include "nn_mul_redc1.h"
#include "nn_div.h"
#include "nn_logical.h"
#include "nn_mod_pow.h"
#include "nn.h"

/*
 * NOT constant time with regard to the bitlength of exp.
 * Aliasing not supported. Expects caller to check parameters
 * have been initialized. This is an internal helper.
 *
 * Compute (base ** exp) mod (mod) using a square and multiply algorithm
 * with Montgomery redcification, hence the Montgomery coefficients as input.
 *
 * Returns 0 on success, -1 on error.
 */
#define TAB_ENTRIES 2
ATTRIBUTE_WARN_UNUSED_RET static int _nn_mod_pow_redc(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod, nn_src_t r, nn_src_t r_square, word_t mpinv)
{
	nn base_monty, mul_monty, sqr_monty, out_monty, one;
	nn_src_t tab_monty[TAB_ENTRIES];
	bitcnt_t explen;
 	u8 expbit;
	int ret, iszero, cmp;
	base_monty.magic = mul_monty.magic = sqr_monty.magic = out_monty.magic = one.magic = WORD(0);

	MUST_HAVE((out != NULL), ret, err);

	/* Initialize out */
	ret = nn_init(out, 0); EG(ret, err);

	/* Exponentiating to zero provides 1 */
	ret = nn_iszero(exp, &iszero); EG(ret, err);
	if (iszero) {
		ret = nn_one(out);
		goto err;
	}

	ret = nn_init(&base_monty, 0); EG(ret, err);
	ret = nn_init(&mul_monty, 0); EG(ret, err);
	ret = nn_init(&sqr_monty, 0); EG(ret, err);
	ret = nn_init(&out_monty, 0); EG(ret, err);

	ret = nn_init(&one, 0); EG(ret, err);
	ret = nn_one(&one); EG(ret, err);

	ret = nn_bitlen(exp, &explen); EG(ret, err);

	/* Sanity check */
	MUST_HAVE((explen > 0), ret, err);

	explen -= (bitcnt_t)1;

	/* Reduce the base if necessary */
	ret = nn_cmp(base, mod, &cmp); EG(ret, err);
	if(cmp >= 0){
		ret = nn_mod(&base_monty, base, mod); EG(ret, err);
		/* Redcify the base */
		ret = nn_mul_redc1(&base_monty, &base_monty, r_square, mod, mpinv); EG(ret, err);
	}
	else{
		/* Redcify the base */
		ret = nn_mul_redc1(&base_monty, base, r_square, mod, mpinv); EG(ret, err);
	}

	/* Copy base in out */
	ret = nn_copy(&out_monty, &base_monty); EG(ret, err);

	tab_monty[0] = r;
	tab_monty[1] = &base_monty;

	/* Now proceed with the square and multiply always algorithm */
	while (explen > 0) {
		explen -= (bitcnt_t)1;

		ret = nn_getbit(exp, explen, &expbit); EG(ret, err);
		/* Square */
		ret = nn_mul_redc1(&sqr_monty, &out_monty, &out_monty, mod, mpinv); EG(ret, err);
		/* Optional swap */
		ret = nn_tabselect(&mul_monty, expbit, tab_monty, TAB_ENTRIES); EG(ret, err);
		/* Multiply */
		ret = nn_mul_redc1(&out_monty, &sqr_monty, &mul_monty, mod, mpinv); EG(ret, err);
	}
	/* Now unredcify */
	ret = nn_mul_redc1(out, &out_monty, &one, mod, mpinv);

err:
	nn_uninit(&base_monty);
	nn_uninit(&mul_monty);
	nn_uninit(&sqr_monty);
	nn_uninit(&out_monty);
	nn_uninit(&one);

	return ret;
}

/*
 * Same purpose as above but handles aliasing of 'base' and 'out', i.e.
 * base is passed via 'out'.  Expects caller to check parameters
 * have been initialized. This is an internal helper.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _nn_mod_pow_redc_aliased(nn_t out, nn_src_t exp, nn_src_t mod, nn_src_t r, nn_src_t r_square, word_t mpinv)
{
	nn base;
	int ret;
	base.magic = WORD(0);

	ret = nn_init(&base, 0); EG(ret, err);
	ret = nn_copy(&base, out); EG(ret, err);
	ret = _nn_mod_pow_redc(out, &base, exp, mod, r, r_square, mpinv);

err:
	nn_uninit(&base);

	return ret;
}

/* Aliased version of previous one. */
int nn_mod_pow_redc(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod, nn_src_t r, nn_src_t r_square, word_t mpinv)
{
	int ret;

	ret = nn_check_initialized(base); EG(ret, err);
	ret = nn_check_initialized(exp); EG(ret, err);
	ret = nn_check_initialized(mod); EG(ret, err);
	ret = nn_check_initialized(r); EG(ret, err);
	ret = nn_check_initialized(r_square); EG(ret, err);

	/* Handle output aliasing */
	if (out == base) {
		ret = _nn_mod_pow_redc_aliased(out, exp, mod, r, r_square, mpinv);
	} else {
		ret = nn_init(out, 0);  EG(ret, err);
		ret = _nn_mod_pow_redc(out, base, exp, mod, r, r_square, mpinv);
	}

err:
	return ret;
}


/*
 * NOT constant time with regard to the bitlength of exp.
 * Aliasing not supported. Expects caller to check parameters
 * have been initialized. This is an internal helper.
 *
 * Compute (base ** exp) mod (mod) using a square and multiply algorithm.
 * Internally, this computes Montgomery coefficients and uses the redc
 * function.
 *
 * Returns 0 on success, -1 on error.
 */
int nn_mod_pow(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod)
{
	nn r, r_square;
	word_t mpinv;
	int ret;
	r.magic = r_square.magic = WORD(0);

	/* Compute the Montgomery coefficients */
	ret = nn_compute_redc1_coefs(&r, &r_square, mod, &mpinv); EG(ret, err);

	/* Now use the redc version */
	ret = nn_mod_pow_redc(out, base, exp, mod, &r, &r_square, mpinv);

err:
	nn_uninit(&r);
	nn_uninit(&r_square);

	return ret;
}
