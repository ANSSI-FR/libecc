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
#include "nn_modinv.h"
#include "nn_div.h"
#include "nn_mul.h"
#include "nn_logical.h"
#include "nn_add.h"
#include "nn.h"

/*
 * Compute out = x^-1 mod m, i.e. out such that (out * x) = 1 mod m
 * out is initialized by the function, i.e. caller need
 * not initialize it; only provide the associated storage space.
 * Done in *constant time* if underlying routines are.
 *
 * Asserts that m is odd and that x is smaller than m.
 * This second condition is not strictly necessary,
 * but it allows to perform all operations on nn's of the same length,
 * namely the length of m.
 *
 * Uses a binary xgcd algorithm,
 * only keeps track of coefficient for inverting x,
 * and performs reduction modulo m at each step.
 *
 * This does not normalize out on return.
 */
static int nn_modinv_odd(nn_t out, nn_src_t x, nn_src_t m)
{
	int odd, swap, smaller, ret;
	nn a, b, u, tmp, mp1d2;
	nn_t uu = out;
	bitcnt_t cnt;
	nn_init(out, 0);
	nn_init(&a, m->wlen * WORD_BYTES);
	nn_init(&b, m->wlen * WORD_BYTES);
	nn_init(&u, m->wlen * WORD_BYTES);
	nn_init(&mp1d2, m->wlen * WORD_BYTES);
	/*
	 * Temporary space needed to only deal with positive stuff.
	 */
	nn_init(&tmp, m->wlen * WORD_BYTES);

	MUST_HAVE(nn_isodd(m));
	MUST_HAVE(nn_cmp(x, m) < 0); /* could be leveraged by using maxlen(x,m) when dealing with a and b */
	MUST_HAVE(!nn_iszero(x)); /* could rather return 0 */

	/*
	 * Maintain:
	 *
	 * a = u * x (mod m)
	 * b = uu * x (mod m)
	 *
	 * and b odd at all times. Initially,
	 *
	 * a = x, u = 1
	 * b = m, uu = 0
	 */
	nn_copy(&a, x);
	nn_set_wlen(&a, m->wlen);
	nn_copy(&b, m);
	nn_one(&u);
	nn_zero(uu);
	/*
	 * The lengths of u and uu should not affect constant timeness but it
	 * does not hurt to set them already.
	 * They will always be strictly smaller than m.
	 */
	nn_set_wlen(&u, m->wlen);
	nn_set_wlen(uu, m->wlen);

	/*
	 * Precompute inverse of 2 mod m:
	 * 	2^-1 = (m+1)/2
	 * computed as (m >> 1) + 1.
	 */
	nn_rshift_fixedlen(&mp1d2, m, 1);
	nn_inc(&mp1d2, &mp1d2); /* no carry can occur here because of previous shift */

	cnt = (a.wlen + b.wlen) * WORD_BITS;
	while (cnt-- > 0) {
		/*
		 * Always maintain b odd. The logic of the iteration is as
		 * follows.
		 */

		/*
		 * For a, b:
		 *
		 * odd = a & 1
		 * swap = odd & (a < b)
		 * if (swap)
		 *      swap(a, b)
		 * if (odd)
		 *      a -= b
		 * a /= 2
		 */

		MUST_HAVE(nn_isodd(&b));
		odd = nn_isodd(&a);
		swap = odd & (nn_cmp(&a, &b) == -1);
		nn_cnd_swap(swap, &a, &b);
		nn_cnd_sub(odd, &a, &a, &b);
		MUST_HAVE(!nn_isodd(&a)); /* a is now even */
		nn_rshift_fixedlen(&a, &a, 1); /* division by 2 */

		/*
		 * For u, uu:
		 *
		 * if (swap)
		 *      swap u, uu
		 * smaller = (u < uu)
		 * if (odd)
		 *      if (smaller)
		 *              u += m - uu
		 *      else
		 *              u -= uu
		 * u >>= 1
		 * if (u was odd)
		 *      u += (m+1)/2
		 */
		nn_cnd_swap(swap, &u, uu);
		/* This parameter is used to avoid handling negative numbers. */
		smaller = (nn_cmp(&u, uu) == -1);
		/* Computation of 'm - uu' can always be performed. */
		nn_sub(&tmp, m, uu);
		/* Selection btw 'm-uu' and '-uu' is made by the following function calls. */
		nn_cnd_add(odd & smaller, &u, &u, &tmp); /* no carry can occur as 'u+(m-uu) = m-(uu-u) < m' */
		nn_cnd_sub(odd & !smaller, &u, &u, uu);
		/* Divide u by 2 */
		odd = nn_isodd(&u);
		nn_rshift_fixedlen(&u, &u, 1);
		nn_cnd_add(odd, &u, &u, &mp1d2); /* no carry can occur as u=1+u' with u'<m-1 and u' even so u'/2+(m+1)/2<(m-1)/2+(m+1)/2=m */

		MUST_HAVE(nn_cmp(&u, m) < 0);
		MUST_HAVE(nn_cmp(uu, m) < 0);

		/*
		 * As long as a > 0, the quantity
		 * (bitsize of a) + (bitsize of b)
		 * is reduced by at least one bit per iteration,
		 * hence after (bitsize of x) + (bitsize of m) - 1
		 * iterations we surely have a = 0. Then b = gcd(x, m)
		 * and if b = 1 then also uu = x^{-1} (mod m).
		 */
	}
	MUST_HAVE(nn_iszero(&a));

	/* Check that gcd is one. */
	ret = (nn_cmp_word(&b, WORD(1)) == 0);
	/* If not, set "inverse" to zero. */
	nn_cnd_sub(ret != 1, uu, uu, uu);

	nn_uninit(&a);
	nn_uninit(&b);
	nn_uninit(&u);
	nn_uninit(&mp1d2);
	nn_uninit(&tmp);

	return ret;
}

/*
 * Same as above without restriction on m.
 * No attempt to make it constant time.
 * Uses the above constant-time binary xgcd when m is odd
 * and a not constant time plain Euclidean xgcd when m is even.
 *
 * Return 0 if x has no reciprocal modulo m, out is zeroed.
 * Return 1 if x has reciprocal modulo m.
 */
int nn_modinv(nn_t out, nn_src_t x, nn_src_t m)
{
	int sign, ret;
	nn u, v;

	nn_check_initialized(x);
	nn_check_initialized(m);
	
	/* Initialize out */
	nn_init(out, 0);

	if (nn_isodd(m)) {
	        if(nn_cmp(x, m) >= 0){
		        /* If x >= m, (x^-1) mod m = ((x mod m)^-1) mod m
        		 * Hence, compute x mod m
	       	  	 */
			nn x_mod_m;
			nn_init(&x_mod_m, 0);
        	        nn_mod(&x_mod_m, x, m);
			ret = nn_modinv_odd(out, &x_mod_m, m);
			nn_uninit(&x_mod_m);
			return ret;
        	}
		else{
			return nn_modinv_odd(out, x, m);
		}
	}
	/* Now m is even */
	if (!nn_isodd(x)) {
		nn_zero(out);
		return 0;
	}

	nn_init(&u, 0);
	nn_init(&v, 0);

	sign = nn_xgcd(out, &u, &v, x, m);
	if (!nn_isone(out)) {
		ret = 0;
		nn_zero(out);
	} else {
		ret = 1;
		nn_mod(out, &u, m);
		if (sign == -1) {
			nn_sub(out, m, out);
		}
	}
	nn_uninit(&u);
	nn_uninit(&v);

	return ret;
}

/*
 * Compute (A - B) % 2^(storagebitsizeof(B) + 1).
 * No assumption on A and B such as A >= B.
 * Done in *constant time*.
 */
static inline void nn_sub_mod_2exp(nn_t A, nn_src_t B)
{
	u8 Awlen = A->wlen;
	nn_set_wlen(A, Awlen + 1);
	/* Make sure A > B */
	A->val[A->wlen - 1] = WORD(1);
	nn_sub(A, A, B);
	/* The artificial word will be cleared in the following function call */
	nn_set_wlen(A, Awlen);
}

/*
 * Invert x modulo 2^exp using Hensel lifting.
 * Returns 0 if x is even, and 1 if x is odd.
 * Done in *constant time*.
 */
int nn_modinv_2exp(nn_t out, nn_src_t x, bitcnt_t exp)
{
	bitcnt_t cnt;
	u8 exp_wlen = (u8)BIT_LEN_WORDS(exp);
	bitcnt_t exp_cnt = exp % WORD_BITS;
	word_t mask = (exp_cnt == 0) ? WORD_MASK : (word_t)((WORD(1) << exp_cnt) - WORD(1));
	nn tmp_sqr, tmp_mul;

	nn_check_initialized(x);

	nn_init(out, 0);
	nn_init(&tmp_sqr, 0);
	nn_init(&tmp_mul, 0);

	if (!nn_isodd(x)) {
		nn_zero(out);
		return 0;
	}

	/*
	 * Inverse modulo 2.
	 */
	cnt = 1;
	nn_one(out);

	/*
	 * Inverse modulo 2^(2^i) <= 2^WORD_BITS.
	 * Assumes WORD_BITS is a power of two.
	 */
	for (; cnt < WORD_MIN(WORD_BITS, exp); cnt <<= 1) {
		nn_sqr_low(&tmp_sqr, out, out->wlen);
		nn_mul_low(&tmp_mul, &tmp_sqr, x, out->wlen);
		nn_lshift_fixedlen(out, out, 1);
		/*
		 * Allowing "negative" results for a subtraction modulo
		 * a power of two would allow to use directly:
		 * nn_sub(out, out, tmp_mul)
		 * which is always negative in ZZ except when x is one.
		 *
		 * Another solution is to add the opposite of tmp_mul.
		 * nn_modopp_2exp(tmp_mul, tmp_mul);
		 * nn_add(out, out, tmp_mul);
		 *
		 * The current solution is to add a sufficiently large power
		 * of two to out unconditionally to absorb the potential
		 * borrow. The result modulo 2^(2^i) is correct whether the
		 * borrow occurs or not.
		 */
		nn_sub_mod_2exp(out, &tmp_mul);
	}

	/*
	 * Inverse modulo 2^WORD_BITS < 2^(2^i) < 2^exp.
	 */
	for (; cnt < ((exp + 1) >> 1); cnt <<= 1) {
		nn_set_wlen(out, (2 * out->wlen));
		nn_sqr_low(&tmp_sqr, out, out->wlen);
		nn_mul_low(&tmp_mul, &tmp_sqr, x, out->wlen);
		nn_lshift_fixedlen(out, out, 1);
		nn_sub_mod_2exp(out, &tmp_mul);
	}

	/*
	 * Inverse modulo 2^(2^i + j) >= 2^exp.
	 */
	if (exp > WORD_BITS) {
		nn_set_wlen(out, exp_wlen);
		nn_sqr_low(&tmp_sqr, out, out->wlen);
		nn_mul_low(&tmp_mul, &tmp_sqr, x, out->wlen);
		nn_lshift_fixedlen(out, out, 1);
		nn_sub_mod_2exp(out, &tmp_mul);
	}

	/*
	 * Inverse modulo 2^exp.
	 */
	{
		out->val[exp_wlen - 1] &= mask;
	}

	nn_uninit(&tmp_sqr);
	nn_uninit(&tmp_mul);
	return 1;
}
