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
/*
 * The purpose of this example is to implement Pollard's rho
 * algorithm to find non-trivial factors of a composite natural
 * number.
 * The prime numbers decomposition of the natural number is
 * recovered through repeated Pollard's rho. Primality checking
 * is performed using a Miller-Rabin test.
 *
 * WARNING: the code in this example is only here to illustrate
 * how to use the NN layer API. This code has not been designed
 * for production purposes (e.g. no effort has been made to make
 * it constant time).
 *
 *
 */

/* We include the NN layer API header */
#include "libarith.h"

/* Declare our Miller-Rabin test implemented
 * in another module.
 */
int miller_rabin(nn_src_t n, const unsigned int t);

int pollar_rho(nn_t d, nn_src_t n, const word_t c);
/* Pollard's rho main function, as described in
 * "Handbook of Applied Cryptography".
 *
 * Pollard's rho:
 * ==============
 * See "Handbook of Applied Cryptography", alorithm 3.9:
 *
 *   Algorithm Pollard’s rho algorithm for factoring integers
 *   INPUT: a composite integer n that is not a prime power.
 *   OUTPUT: a non-trivial factor d of n.
 *      1. Set a←2, b←2.
 *      2. For i = 1, 2, ... do the following:
 *        2.1 Compute a←a^2 + 1 mod n, b←b^2 + 1 mod n, b←b^2 + 1 mod n.
 *        2.2 Compute d = gcd(a − b, n).
 *        2.3 If 1 < d < n then return(d) and terminate with success.
 *        2.4 If d = n then terminate the algorithm with failure (see Note 3.12).
 */
int pollar_rho(nn_t d, nn_src_t n, const word_t c)
{
	int ret;
	/* Temporary a and b variables */
	nn a, b, tmp, one, c_bignum;
	/* Initialize variables */
	nn_init(&a, 0);
	nn_init(&b, 0);
	nn_init(&tmp, 0);
	nn_init(&one, 0);
	nn_init(&c_bignum, 0);
	nn_init(d, 0);

	MUST_HAVE(c > 0);

	/* Zeroize the output */
	nn_zero(d);
	nn_one(&one);
	/* 1. Set a←2, b←2. */
	nn_set_word_value(&a, 2);
	nn_set_word_value(&b, 2);
	nn_set_word_value(&c_bignum, c);

	/* For i = 1, 2, . . . do the following: */
	while (1) {
		/* 2.1 Compute a←a^2 + c mod n */
		nn_sqr(&a, &a);
		nn_add(&a, &a, &c_bignum);
		nn_mod(&a, &a, n);
		/* 2.1 Compute b←b^2 + c mod n twice in a row */
		nn_sqr(&b, &b);
		nn_add(&b, &b, &c_bignum);
		nn_mod(&b, &b, n);
		nn_sqr(&b, &b);
		nn_add(&b, &b, &c_bignum);
		nn_mod(&b, &b, n);
		/* 2.2 Compute d = gcd(a − b, n) */
		if (nn_cmp(&a, &b) >= 0) {
			nn_sub(&tmp, &a, &b);
		} else {
			nn_sub(&tmp, &b, &a);
		}
		nn_gcd(d, &tmp, n);
		if ((nn_cmp(d, n) < 0) && (nn_cmp(d, &one) > 0)) {
			ret = 0;
			goto out;
		}
		if (nn_cmp(d, n) == 0) {
			ret = -1;
			goto out;
		}
	}
 out:
	/* Uninitialize local variables */
	nn_uninit(&a);
	nn_uninit(&b);
	nn_uninit(&tmp);
	nn_uninit(&one);
	nn_uninit(&c_bignum);

	return ret;
}

void find_divisors(nn_src_t in);
/* Maximum number of divisors we support */
#define MAX_DIVISORS 10
/* Function to find prime divisors of the NN input */
void find_divisors(nn_src_t in)
{
	int n_divisors_found, i, found, ret;
	nn n;
	nn divisors[MAX_DIVISORS];
	word_t c;

	ext_printf("=================\n");
	nn_print("Finding factors of:", in);

	/* First, check primality of the input */
	if (miller_rabin(in, 10)) {
		ext_printf("The number is probably prime, leaving ...\n");
		return;
	}
	ext_printf("The number is composite, performing Pollard's rho\n");

	nn_init(&n, 0);
	nn_copy(&n, in);
	for (i = 0; i < MAX_DIVISORS; i++) {
		nn_init(&(divisors[i]), 0);
	}

	n_divisors_found = 0;
	c = 0;
	while (1) {
		c++;
		ret = pollar_rho(&(divisors[n_divisors_found]), &n, c);
		if (ret) {
			continue;
		}
		found = 0;
		for (i = 0; i < n_divisors_found; i++) {
			if (nn_cmp
			    (&(divisors[n_divisors_found]),
			     &(divisors[i])) == 0) {
				found = 1;
			}
		}
		if (found == 0) {
			nn q, r;
			nn_init(&q, 0);
			nn_init(&r, 0);
			ext_printf("Pollard's rho succeded\n");
			nn_print("d:", &(divisors[n_divisors_found]));
			/*
			 * Now we can launch the algorithm again on n / d
			 * to find new divisors. If n / d is prime, we are done!
			 */
			nn_divrem(&q, &r, &n, &(divisors[n_divisors_found]));
			/*
			 * Check n / d primality with Miller-Rabin (security
			 * parameter of 10)
			 */
			if (miller_rabin(&q, 10) == 1) {
				nn_print("Last divisor is prime:", &q);
				nn_uninit(&q);
				nn_uninit(&r);
				break;
			}
			nn_print("Now performing Pollard's rho on:", &q);
			nn_copy(&n, &q);
			nn_uninit(&q);
			nn_uninit(&r);
			c = 0;
			n_divisors_found++;
			if (n_divisors_found == MAX_DIVISORS) {
				ext_printf
					("Max divisors reached, leaving ...\n");
				break;
			}
		}
	}

	ext_printf("=================\n");
	nn_uninit(&n);
	for (i = 0; i < MAX_DIVISORS; i++) {
		nn_uninit(&(divisors[i]));
	}
	return;
}

#ifdef NN_EXAMPLE
int main()
{
	nn n;

	/* Fermat F5 = 2^32 + 1 = 641 x 6700417 */
	const unsigned char fermat_F5[] = { 0x01, 0x00, 0x00, 0x00, 0x01 };
	/* Fermat F6 = 2^64 + 1 = 274177 x 67280421310721 */
	const unsigned char fermat_F6[] =
		{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

	nn_init(&n, 0);
	/* Execute factorization on F5 */
	nn_init_from_buf(&n, fermat_F5, sizeof(fermat_F5));
	find_divisors(&n);
	/* Execute factorization on F6 */
	nn_init_from_buf(&n, fermat_F6, sizeof(fermat_F6));
	find_divisors(&n);
	/* Execute factorization on a random 80 bits number */
	nn_one(&n);
	/* Compute 2**80 = 0x1 << 80 */
	nn_lshift(&n, &n, 80);
	nn_get_random_mod(&n, &n);
	find_divisors(&n);

	return 0;
}
#endif
