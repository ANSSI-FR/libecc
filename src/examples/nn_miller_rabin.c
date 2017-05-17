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
/* We include the NN layer API header */
#include "libarith.h"

int miller_rabin(nn_src_t n, const unsigned int t);

/* Miller-Rabin primality test.
 * See "Handbook of Applied Cryptography", alorithm 4.24:
 *
 *   Algorithm: Miller-Rabin probabilistic primality test
 *   MILLER-RABIN(n,t)
 *   INPUT: an odd integer n ≥ 3 and security parameter t ≥ 1.
 *   OUTPUT: an answer “prime” or “composite” to the question: “Is n prime?”
 *     1. Write n − 1 = 2**s x r such that r is odd.
 *     2. For i from 1 to t do the following:
 *       2.1 Choose a random integer a, 2 ≤ a ≤ n − 2.
 *       2.2 Compute y = a**r mod n using Algorithm 2.143.
 *       2.3 If y != 1 and y != n − 1 then do the following:
 *         j←1.
 *         While j ≤ s − 1 and y != n − 1 do the following:
 *           Compute y←y2 mod n.
 *           If y = 1 then return(“composite”).
 *           j←j + 1.
 *           If y != n − 1 then return (“composite”).
 *     3. Return(“maybe prime”).
 *
 * The Miller-Rabin test can give false positives when
 * answering "maybe prime", but is always right when answering
 * "composite".
 */
int miller_rabin(nn_src_t n, const unsigned int t)
{
	int ret = 0;
	unsigned int i;
	bitcnt_t k;
	/* Temporary NN variables */
	nn s, q, r, d, a, y, j, one, two, tmp;

	/* Initialize our local NN variables */
	nn_init(&s, 0);
	nn_init(&q, 0);
	nn_init(&r, 0);
	nn_init(&d, 0);
	nn_init(&a, 0);
	nn_init(&y, 0);
	nn_init(&j, 0);
	nn_init(&one, 0);
	nn_init(&two, 0);
	nn_init(&tmp, 0);

	/* Security parameter t must be >= 1 */
	MUST_HAVE(t >= 1);

	/* one = 1 */
	nn_one(&one);
	/* two = 2 */
	nn_set_word_value(&two, 2);

	/* If n = 0, this is not a prime */
	if (nn_iszero(n)) {
		ret = 0;
		goto out;
	}
	/* If n = 1, this is not a prime */
	if (nn_cmp(n, &one) == 0) {
		ret = 0;
		goto out;
	}
	/* If n = 2, this is a prime number */
	if (nn_cmp(n, &two) == 0) {
		ret = 1;
		goto out;
	}
	/* If n = 3, this is a prime number */
	nn_copy(&tmp, n);
	nn_dec(&tmp, &tmp);
	if (nn_cmp(&tmp, &two) == 0) {
		ret = 1;
		goto out;
	}

	/* If n >= 4 is even, this is not a prime */
	if (!nn_isodd(n)) {
		ret = 0;
		goto out;
	}

	/* n − 1 = 2^s x r, repeatedly try to divide n-1 by 2 */
	/* s = 0 and r = n-1 */
	nn_zero(&s);
	nn_copy(&r, n);
	nn_dec(&r, &r);
	while (1) {
		nn_divrem(&q, &d, &r, &two);
		nn_inc(&s, &s);
		nn_copy(&r, &q);
		/* If r is odd, we have finished our division */
		if (nn_isodd(&r)) {
			break;
		}
	}
	/* 2. For i from 1 to t do the following: */
	for (i = 1; i <= t; i++) {
		/* 2.1 Choose a random integer a, 2 ≤ a ≤ n − 2 */
		nn_copy(&tmp, n);
		nn_dec(&tmp, &tmp);
		nn_zero(&a);
		while (nn_cmp(&a, &two) < 0) {
			nn_get_random_mod(&a, &tmp);
		}
		/* A very loose (and NOT robust) implementation of
		 * modular exponentiation with square and multiply
		 * to compute y = a**r (n)
		 * WARNING: NOT to be used in production code!
		 */
		nn_one(&y);
		for (k = 0; k < nn_bitlen(&r); k++) {
			if (nn_getbit(&r, k)) {
				/* Warning: the multiplication is not modular, we
				 * have to take care of our size here!
				 */
				MUST_HAVE(NN_MAX_BIT_LEN >=
					  (WORD_BITS * (y.wlen + a.wlen)));
				nn_mul(&y, &y, &a);
				nn_mod(&y, &y, n);
			}
			MUST_HAVE(NN_MAX_BIT_LEN >= (2 * WORD_BITS * a.wlen));
			nn_sqr(&a, &a);
			nn_mod(&a, &a, n);
		}
		/* 2.3 If y != 1 and y != n − 1 then do the following
		 * Note: tmp still contains n - 1 here.
		 */
		if ((nn_cmp(&y, &one) != 0) && (nn_cmp(&y, &tmp) != 0)) {
			/* j←1. */
			nn_one(&j);
			/*  While j ≤ s − 1 and y != n − 1 do the following: */
			while ((nn_cmp(&j, &s) < 0) && (nn_cmp(&y, &tmp) != 0)) {
				/* Compute y←y2 mod n. */
				MUST_HAVE(NN_MAX_BIT_LEN >=
					  (2 * WORD_BITS * y.wlen));
				nn_sqr(&y, &y);
				nn_mod(&y, &y, n);
				/* If y = 1 then return(“composite”). */
				if (nn_cmp(&y, &one) == 0) {
					ret = 0;
					goto out;
				}
				/* j←j + 1. */
				nn_inc(&j, &j);
			}
			/* If y != n − 1 then return (“composite”). */
			if (nn_cmp(&y, &tmp) != 0) {
				ret = 0;
				goto out;
			}
		}
		/* 3. Return(“maybe prime”). */
		ret = 1;
	}

 out:
	nn_uninit(&s);
	nn_uninit(&q);
	nn_uninit(&r);
	nn_uninit(&d);
	nn_uninit(&a);
	nn_uninit(&y);
	nn_uninit(&j);
	nn_uninit(&one);
	nn_uninit(&two);
	nn_uninit(&tmp);

	return ret;
}
