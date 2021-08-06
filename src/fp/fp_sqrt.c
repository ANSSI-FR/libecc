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
#include "fp_sqrt.h"
#include "../nn/nn_add.h"
#include "../nn/nn_logical.h"

/*
 * Compute the legendre symbol of an element of Fp:
 *
 *   Legendre(a) = a^((p-1)/2) (p) = { -1, 0, 1 }
 *
 */
static int legendre(fp_src_t a)
{
	int ret;
	/* The result if the exponentiation is in Fp */
	fp pow;
	/* The element 1 in the field */
	fp one;
	/* The power exponent is in NN */
	nn exp;

	/* Initialize elements */
	fp_init(&pow, a->ctx);
	fp_init(&one, a->ctx);
	nn_init(&exp, 0);

	/* Initialize our variables from the Fp context of the
	 * input a.
	 */
	fp_init(&pow, a->ctx);
	fp_init(&one, a->ctx);
	nn_init(&exp, 0);

	/* one = 1 in Fp */
	fp_one(&one);

	/* Compute the exponent (p-1)/2
	 * The computation is done in NN, and the division by 2
	 * is performed using a right shift by one
	 */
	nn_dec(&exp, &(a->ctx->p));
	nn_rshift(&exp, &exp, 1);

	/* Compute a^((p-1)/2) in Fp using our fp_pow
	 * API.
	 */
	fp_pow(&pow, a, &exp);

	if (fp_iszero(&pow)) {
		ret = 0;
	} else if (fp_cmp(&pow, &one) == 0) {
		ret = 1;
	} else {
		ret = -1;
	}

	/* Cleaning */
	fp_uninit(&pow);
	fp_uninit(&one);
	nn_uninit(&exp);

	return ret;
}

/*
 * We implement the Tonelli-Shanks algorithm for finding
 * square roots (quadratic residues) modulo a prime number,
 * i.e. solving the equation:
 *     x^2 = n (p)
 * where p is a prime number. This can be seen as an equation
 * over the finite field Fp where a and x are elements of
 * this finite field.
 *   Source: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
 *   All   ≡   are taken to mean   (mod p)   unless stated otherwise.
 *   Input : p an odd prime, and an integer n .
 *       Step 0. Check that n is indeed a square  : (n | p) must be ≡ 1
 *       Step 1. [Factors out powers of 2 from p-1] Define q -odd- and s such as p-1 = q * 2^s
 *           - if s = 1 , i.e p ≡ 3 (mod 4) , output the two solutions r ≡ +/- n^((p+1)/4) .
 *       Step 2. Select a non-square z such as (z | p) = -1 , and set c ≡ z^q .
 *       Step 3. Set r ≡ n ^((q+1)/2) , t ≡ n^q, m = s .
 *       Step 4. Loop.
 *           - if t ≡ 1 output r, p-r .
 *           - Otherwise find, by repeated squaring, the lowest i , 0 < i < m , such as t^(2^i) ≡ 1
 *           - Let b ≡ c^(2^(m-i-1)), and set r ≡ r*b, t ≡ t*b^2 , c ≡ b^2 and m = i.
 *
 * Input aliasing is supported.
 *
 * NOTE: the algorithm is NOT constant time.
 */
int fp_sqrt(fp_t sqrt1, fp_t sqrt2, fp_src_t n)
{
	int ret;
	nn q, s, one_nn, two_nn, m, i, tmp_nn;
	fp z, t, b, r, c, one_fp, tmp_fp, __n;
	fp_t _n = &__n;

	nn_init(&q, 0);
	nn_init(&s, 0);
	nn_init(&tmp_nn, 0);
	nn_init(&one_nn, 0);
	nn_init(&two_nn, 0);
	nn_init(&m, 0);
	nn_init(&i, 0);
	fp_init(&z, n->ctx);
	fp_init(&t, n->ctx);
	fp_init(&b, n->ctx);
	fp_init(&r, n->ctx);
	fp_init(&c, n->ctx);
	fp_init(&one_fp, n->ctx);
	fp_init(&tmp_fp, n->ctx);

	/* Handle input aliasing */
	fp_copy(_n, n);

	/* Initialize outputs */
	fp_init(sqrt1, _n->ctx);
	fp_init(sqrt2, _n->ctx);

	/* one_nn = 1 in NN */
	nn_one(&one_nn);
	/* two_nn = 2 in NN */
	nn_set_word_value(&two_nn, WORD(2));

	/* If our p prime of Fp is 2, then return the input as square roots */
	if (nn_cmp(&(_n->ctx->p), &two_nn) == 0) {
		fp_copy(sqrt1, _n);
		fp_copy(sqrt2, _n);
		ret = 0;
		goto out;
	}

	/* Square root of 0 is 0 */
	if (fp_iszero(_n)) {
		fp_zero(sqrt1);
		fp_zero(sqrt2);
		ret = 0;
		goto out;
	}
	/* Step 0. Check that n is indeed a square  : (n | p) must be ≡ 1 */
	if (legendre(_n) != 1) {
		/* a is not a square */
		ret = -1;
		goto out;
	}
	/* Step 1. [Factors out powers of 2 from p-1] Define q -odd- and s such as p-1 = q * 2^s */
	/* s = 0 */
	nn_zero(&s);
	/* q = p - 1 */
	nn_copy(&q, &(_n->ctx->p));
	nn_dec(&q, &q);
	while (1) {
		/* i is used as a temporary unused variable here */
		nn_divrem(&tmp_nn, &i, &q, &two_nn);
		nn_inc(&s, &s);
		nn_copy(&q, &tmp_nn);
		/* If r is odd, we have finished our division */
		if (nn_isodd(&q)) {
			break;
		}
	}
	/* - if s = 1 , i.e p ≡ 3 (mod 4) , output the two solutions r ≡ +/- n^((p+1)/4) . */
	if (nn_cmp(&s, &one_nn) == 0) {
		nn_inc(&tmp_nn, &(_n->ctx->p));
		nn_rshift(&tmp_nn, &tmp_nn, 2);
		fp_pow(sqrt1, _n, &tmp_nn);
		fp_neg(sqrt2, sqrt1);
		ret = 0;
		goto out;
	}
	/* Step 2. Select a non-square z such as (z | p) = -1 , and set c ≡ z^q . */
	fp_zero(&z);
	while (legendre(&z) != -1) {
		fp_inc(&z, &z);
	}
	fp_pow(&c, &z, &q);
	/* Step 3. Set r ≡ n ^((q+1)/2) , t ≡ n^q, m = s . */
	nn_inc(&tmp_nn, &q);
	nn_rshift(&tmp_nn, &tmp_nn, 1);
	fp_pow(&r, _n, &tmp_nn);
	fp_pow(&t, _n, &q);
	nn_copy(&m, &s);
	fp_one(&one_fp);

	/* Step 4. Loop. */
	while (1) {
		/* - if t ≡ 1 output r, p-r . */
		if (fp_cmp(&t, &one_fp) == 0) {
			fp_copy(sqrt1, &r);
			fp_neg(sqrt2, sqrt1);
			ret = 0;
			goto out;
		}
		/* - Otherwise find, by repeated squaring, the lowest i , 0 < i < m , such as t^(2^i) ≡ 1 */
		nn_one(&i);
		fp_copy(&tmp_fp, &t);
		while (1) {
			fp_sqr(&tmp_fp, &tmp_fp);
			if (fp_cmp(&tmp_fp, &one_fp) == 0) {
				break;
			}
			nn_inc(&i, &i);
			if (nn_cmp(&i, &m) == 0) {
				/* i has reached m, that should not happen ... */
				ret = -2;
				goto out;
			}
		}
		/* - Let b ≡ c^(2^(m-i-1)), and set r ≡ r*b, t ≡ t*b^2 , c ≡ b^2 and m = i. */
		nn_sub(&tmp_nn, &m, &i);
		nn_dec(&tmp_nn, &tmp_nn);
		fp_copy(&b, &c);
		while (!nn_iszero(&tmp_nn)) {
			fp_sqr(&b, &b);
			nn_dec(&tmp_nn, &tmp_nn);
		}
		/* r ≡ r*b */
		fp_mul(&r, &r, &b);
		/* c ≡ b^2 */
		fp_sqr(&c, &b);
		/* t ≡ t*b^2 */
		fp_mul(&t, &t, &c);
		/* m = i */
		nn_copy(&m, &i);
	}

 out:
	/* Uninitialize local variables */
	nn_uninit(&q);
	nn_uninit(&s);
	nn_uninit(&tmp_nn);
	nn_uninit(&one_nn);
	nn_uninit(&two_nn);
	nn_uninit(&m);
	nn_uninit(&i);
	fp_uninit(&z);
	fp_uninit(&t);
	fp_uninit(&b);
	fp_uninit(&r);
	fp_uninit(&c);
	fp_uninit(&one_fp);
	fp_uninit(&tmp_fp);
	fp_uninit(_n);

	return ret;
}
