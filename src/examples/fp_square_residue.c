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
#include "libarith.h"

/* Declare our Miller-Rabin test implemented
 * in another module.
 */
int miller_rabin(nn_src_t n, const unsigned int t);

int legendre(fp_src_t a);
/*
 * Compute the legendre symbol of an element of Fp:
 *
 *   Legendre(a) = a^((p-1)/2) (p) = { -1, 0, 1 }
 *
 */
int legendre(fp_src_t a)
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

int fp_square_root(fp_t sqrt1, fp_t sqrt2, fp_src_t n);
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
 */
int fp_square_root(fp_t sqrt1, fp_t sqrt2, fp_src_t n)
{
	int ret;
	nn q, s, one_nn, two_nn, m, i, tmp_nn;
	fp z, t, b, r, c, one_fp, tmp_fp;

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
	/* Initialize outputs */
	fp_init(sqrt1, n->ctx);
	fp_init(sqrt2, n->ctx);

	/* one_nn = 1 in NN */
	nn_one(&one_nn);
	/* two_nn = 2 in NN */
	nn_set_word_value(&two_nn, 2);

	/* If our p prime of Fp is 2, then return the input as square roots */
	if (nn_cmp(&(n->ctx->p), &two_nn) == 0) {
		fp_copy(sqrt1, n);
		fp_copy(sqrt2, n);
		ret = 0;
		goto out;
	}

	/* Square root of 0 is 0 */
	if (fp_iszero(n)) {
		fp_zero(sqrt1);
		fp_zero(sqrt2);
		ret = 0;
		goto out;
	}
	/* Step 0. Check that n is indeed a square  : (n | p) must be ≡ 1 */
	if (legendre(n) != 1) {
		/* a is not a square */
		ret = -1;
		goto out;
	}
	/* Step 1. [Factors out powers of 2 from p-1] Define q -odd- and s such as p-1 = q * 2^s */
	/* s = 0 */
	nn_zero(&s);
	/* q = p - 1 */
	nn_copy(&q, &(n->ctx->p));
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
		nn_inc(&tmp_nn, &(n->ctx->p));
		nn_rshift(&tmp_nn, &tmp_nn, 2);
		fp_pow(sqrt1, n, &tmp_nn);
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
	fp_pow(&r, n, &tmp_nn);
	fp_pow(&t, n, &q);
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

	return ret;
}

#ifdef FP_EXAMPLE
int main()
{
	nn p;
	fp x, x_sqrt1, x_sqrt2;
	fp_ctx ctx;
	int ret;

	while (1) {
		/* Get a random prime p of maximum 521 bits */
		nn_init(&p, 0);
		while (1) {
			/* x = random with max size ~= (NN_MAX_BIT_LEN / 3) bytes.
			 * This size limit is infered from the NN arithmetic primitives
			 * maximum working size. See nn.h for more information about this.
			 */
			if (nn_get_random_maxlen
			    (&p, (u16)((NN_MAX_BIT_LEN / 3) / 8))) {
				continue;
			}

			/* p = 1 is a marginal prime we don't want to deal with */
			if (nn_isone(&p)) {
				continue;
			}
			/* Check primality of p, and choose it if it is prime */
			if (miller_rabin(&p, 100) == 1) {
				break;
			}
		}
		nn_print("Prime p", &p);
		/* Initialize our Fp context from p */
		fp_ctx_init_from_p(&ctx, &p);
		/* Initialize x and its square roots */
		fp_init(&x, &ctx);
		fp_init(&x_sqrt1, &ctx);
		fp_init(&x_sqrt2, &ctx);

		/* Get a random value in Fp */
		fp_get_random(&x, &ctx);
		/* Compute its square in Fp */
		ext_printf("Random before squaring:\n");
		fp_print("x", &x);
		ext_printf("Random after squaring:\n");
		fp_sqr(&x, &x);
		nn_print("x^2", &(x.fp_val));

		ret = fp_square_root(&x_sqrt1, &x_sqrt2, &x);

		if (ret == 0) {
			/* Square roots found!, check them! */
			fp_print("sqrt1", &x_sqrt1);
			fp_sqr(&x_sqrt1, &x_sqrt1);
			if (fp_cmp(&x, &x_sqrt1) == 0) {
				ext_printf("First found square OK!\n");
			} else {
				ext_printf("First found square NOK: square "
					   "is not the expected value ...\n");
			}
			fp_print("sqrt2", &x_sqrt2);
			fp_sqr(&x_sqrt2, &x_sqrt2);
			if (fp_cmp(&x, &x_sqrt2) == 0) {
				ext_printf("Second found square OK!\n");
			} else {
				ext_printf("Second found square NOK: square "
					   "is not the expected value ...\n");
			}

		} else {
			if (ret == -1) {
				/* This should not happen since we have forged our square */
				ext_printf("Value n has no square over Fp\n");
				ext_printf("(Note: this error can be due to "
					   "Miller-Rabin providing a false "
					   "positive prime ...)\n");
				ext_printf("(though this should happen with "
					   "negligible probability))\n");
				nn_print("Check primality of p =", &p);
				/* Get out of the main loop */
				break;
			} else {
				/* This should not happen since we have forged our square */
				ext_printf("Tonelli-Shanks algorithm unkown "
					   "error ...\n");
				ext_printf("(Note: this error can be due to "
					   "Miller-Rabin providing a false "
					   "positive prime ...)\n");
				ext_printf("(though this should happen with "
					   "negligible probability))\n");
				nn_print("Check primality of p =", &p);
				/* Get out of the main loop */
				break;
			}
		}
	}

	return 0;
}
#endif
