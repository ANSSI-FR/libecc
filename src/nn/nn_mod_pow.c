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
 *
 * Reduces the base modulo mod if it is not already reduced,
 * which is also a small divergence wrt constant time leaking
 * the information that base <= mod or not: please use with care
 * in the callers if this information is sensitive.
 *
 * Aliasing not supported. Expects caller to check parameters
 * have been initialized. This is an internal helper.
 *
 * Compute (base ** exp) mod (mod) using a Montgomery Ladder algorithm
 * with Montgomery redcification, hence the Montgomery coefficients as input.
 * The module "mod" is expected to be odd for redcification to be used.
 *
 * Returns 0 on success, -1 on error.
 */
#define TAB_ENTRIES 2
ATTRIBUTE_WARN_UNUSED_RET static int _nn_mod_pow_redc(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod, nn_src_t r, nn_src_t r_square, word_t mpinv)
{
	nn base_monty, one, r_monty;
	nn_t tab_monty[TAB_ENTRIES];
	bitcnt_t explen;
 	u8 expbit;
	int ret, cmp;
	base_monty.magic = one.magic = r_monty.magic = WORD(0);

	MUST_HAVE((out != NULL), ret, err);

	/* Initialize out */
	ret = nn_init(out, 0); EG(ret, err);

	ret = nn_init(&base_monty, 0); EG(ret, err);
	ret = nn_init(&r_monty, 0); EG(ret, err);

	ret = nn_init(&one, 0); EG(ret, err);
	ret = nn_one(&one); EG(ret, err);

	ret = nn_bitlen(exp, &explen); EG(ret, err);

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

	/* We implement the Montgomery ladder exponentiation with tegisters R0 and R1,
	 * tab_monty[0] is R0 and tab_monty[1] is R1.
	 */
	ret = nn_copy(&r_monty, r); EG(ret, err);
	tab_monty[0] = &r_monty; /* r is redcified one */
	tab_monty[1] = &base_monty;

	/* Now proceed with the Montgomery Ladder algorithm.
	 */
	while (explen > 0) {
		explen -= (bitcnt_t)1;
		/* Get the exponent bit */
		ret = nn_getbit(exp, explen, &expbit); EG(ret, err);
		/* Multiply */
		ret = nn_mul_redc1(tab_monty[(~expbit) & 0x1], tab_monty[0], tab_monty[1], mod, mpinv); EG(ret, err);
		/* Square */
		ret = nn_mul_redc1(tab_monty[expbit], tab_monty[expbit], tab_monty[expbit], mod, mpinv); EG(ret, err);
	}
	/* Now unredcify */
	ret = nn_mul_redc1(out, tab_monty[0], &one, mod, mpinv);

err:
	nn_uninit(&base_monty);
	nn_uninit(&r_monty);
	nn_uninit(&one);

	return ret;
}

/*
 * NOT constant time with regard to the bitlength of exp.
 *
 * Reduces the base modulo mod if it is not already reduced,
 * which is also a small divergence wrt constant time leaking
 * the information that base <= mod or not: please use with care
 * in the callers if this information is sensitive.
 *
 * Aliasing not supported. Expects caller to check parameters
 * have been initialized. This is an internal helper.
 *
 * Compute (base ** exp) mod (mod) using a Montgomery Ladder algorithm.
 * This function works for all values of "mod", but is slower that the one
 * using Montgomery multiplication (which only works for odd "mod"). Hence,
 * it is only used on even "mod" by upper layers.
 *
 * Returns 0 on success, -1 on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static int __nn_mod_pow(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod)
{
	nn _base, one;
	nn_t tab[TAB_ENTRIES];
	bitcnt_t explen;
 	u8 expbit;
	int ret, cmp;
	_base.magic = one.magic =  WORD(0);

	MUST_HAVE((out != NULL), ret, err);

	/* Initialize out */
	ret = nn_init(out, 0); EG(ret, err);

	ret = nn_init(&_base, 0); EG(ret, err);

	ret = nn_init(&one, 0); EG(ret, err);
	ret = nn_one(&one); EG(ret, err);

	ret = nn_bitlen(exp, &explen); EG(ret, err);

	/* Reduce the base if necessary */
	ret = nn_cmp(base, mod, &cmp); EG(ret, err);
	if(cmp >= 0){
		ret = nn_mod(&_base, base, mod); EG(ret, err);
	}
	else{
		ret = nn_copy(&_base, base); EG(ret, err);
	}

	/* We implement the Montgomery ladder exponentiation with tegisters R0 and R1,
	 * tab_monty[0] is R0 and tab[1] is R1.
	 */
	tab[0] = &one;
	tab[1] = &_base;

	/* Now proceed with the Montgomery Ladder algorithm.
	 */
	while (explen > 0) {
		explen -= (bitcnt_t)1;
		/* Get the exponent bit */
		ret = nn_getbit(exp, explen, &expbit); EG(ret, err);
		/* Multiply */
		ret = nn_mod_mul(tab[(~expbit) & 0x1], tab[0], tab[1], mod); EG(ret, err);
		/* Square */
		ret = nn_mod_mul(tab[expbit], tab[expbit], tab[expbit], mod); EG(ret, err);
	}
	/* Copy the result in out */
	ret = nn_copy(out, tab[0]);

err:
	nn_uninit(&_base);
	nn_uninit(&one);

	return ret;
}

/* Aliased version of generic nn_mod_pow */
ATTRIBUTE_WARN_UNUSED_RET static int _nn_mod_pow(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod)
{
	int ret;

	if ((out == base) || (out == base) || (out == exp) || (out == mod)) {
		nn _out;
		_out.magic = WORD(0);

		ret = nn_init(&_out, 0); EG(ret, err);
		ret = __nn_mod_pow(&_out, base, exp, mod); EG(ret, err);
		ret = nn_copy(out, &_out);
	}
	else{
		ret = __nn_mod_pow(out, base, exp, mod);
	}

err:
	return ret;
}

/*
 * Same purpose as above but handles aliasing.
 * Expects caller to check parameters
 * have been initialized. This is an internal helper.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _nn_mod_pow_redc_aliased(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod, nn_src_t r, nn_src_t r_square, word_t mpinv)
{
	nn _out;
	int ret;
	_out.magic = WORD(0);

	ret = nn_init(&_out, 0); EG(ret, err);
	ret = _nn_mod_pow_redc(&_out, base, exp, mod, r, r_square, mpinv); EG(ret, err);
	ret = nn_copy(out, &_out);

err:
	nn_uninit(&_out);

	return ret;
}

/* Aliased version of previous one.
 * NOTE: our nn_mod_pow_redc primitives suppose that the modulo is odd for Montgomery multiplication
 * primitives to provide consistent results.
 */
int nn_mod_pow_redc(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod, nn_src_t r, nn_src_t r_square, word_t mpinv)
{
	int ret, isodd;

	ret = nn_check_initialized(base); EG(ret, err);
	ret = nn_check_initialized(exp); EG(ret, err);
	ret = nn_check_initialized(mod); EG(ret, err);
	ret = nn_check_initialized(r); EG(ret, err);
	ret = nn_check_initialized(r_square); EG(ret, err);

	/* Check that we have an odd number for our modulo */
	ret = nn_isodd(mod, &isodd); EG(ret, err);
	MUST_HAVE(isodd, ret, err);

	/* Handle the case where our prime is less than two words size.
	 * We need it to be >= 2 words size for the Montgomery multiplication to be
	 * usable.
	 */
	if(mod->wlen < 2){
		/* Local copy our modulo */
		nn _mod;
		_mod.magic = WORD(0);

		/* And set its length accordingly */
		ret = nn_copy(&_mod, mod); EG(ret, err1);
		ret = nn_set_wlen(&_mod, 2); EG(ret, err1);
		/* Handle output aliasing */
		if ((out == base) || (out == base) || (out == exp) || (out == mod) || (out == r) || (out == r_square)) {
			ret = _nn_mod_pow_redc_aliased(out, base, exp, &_mod, r, r_square, mpinv); EG(ret, err1);
		} else {
			ret = _nn_mod_pow_redc(out, base, exp, &_mod, r, r_square, mpinv); EG(ret, err1);
		}
err1:
		nn_uninit(&_mod);
		EG(ret, err);
	}
	else{
		/* Handle output aliasing */
		if ((out == base) || (out == base) || (out == exp) || (out == mod) || (out == r) || (out == r_square)) {
			ret = _nn_mod_pow_redc_aliased(out, base, exp, mod, r, r_square, mpinv);
		} else {
			ret = _nn_mod_pow_redc(out, base, exp, mod, r, r_square, mpinv);
		}
	}

err:
	return ret;
}


/*
 * NOT constant time with regard to the bitlength of exp.
 * Aliasing not supported. Expects caller to check parameters
 * have been initialized. This is an internal helper.
 *
 * Compute (base ** exp) mod (mod) using a Montgomery Ladder algorithm.
 * Internally, this computes Montgomery coefficients and uses the redc
 * function.
 *
 * Returns 0 on success, -1 on error.
 */
int nn_mod_pow(nn_t out, nn_src_t base, nn_src_t exp, nn_src_t mod)
{
	nn r, r_square;
	word_t mpinv;
	int ret, isodd;
	r.magic = r_square.magic = WORD(0);

	/* Handle the case where our modulo is even: in this case, we cannot
	 * use our Montgomery multiplication primitives as they are only suitable
	 * for odd numbers. We fallback to less efficient regular modular exponentiation.
	 */
	ret = nn_isodd(mod, &isodd); EG(ret, err);
	if(!isodd){
		/* mod is even: use the regular unoptimized modular exponentiation */
		ret = _nn_mod_pow(out, base, exp, mod);
	}
	else{
		/* mod is odd */
		/* Compute the Montgomery coefficients */
		ret = nn_compute_redc1_coefs(&r, &r_square, mod, &mpinv); EG(ret, err);

		/* Now use the redc version */
		ret = nn_mod_pow_redc(out, base, exp, mod, &r, &r_square, mpinv);
	}

err:
	nn_uninit(&r);
	nn_uninit(&r_square);

	return ret;
}
