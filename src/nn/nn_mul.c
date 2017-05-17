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
#include "nn_mul.h"
#include "nn_add.h"
#include "nn.h"

/*
 * Compute out = (in1 * in2) & (2^(WORD_BYTES * wlimits) - 1).
 *
 * The function is constant time for all sets of parameters of given
 * lengths.
 *
 * Implementation: while most generic library implement some advanced
 * algorithm (Karatsuba, Toom-Cook, or FFT based algorithms)
 * which provide a performance advantage for large numbers, the code
 * below is mainly oriented towards simplicity and readibility. It is
 * a direct writing of the naive multiplication algorithm one has
 * learned in school.
 *
 * Portability: in order for the code to be portable, all word by
 * word multiplication are actually performed by an helper macro
 * on half words.
 *
 * Note: 'out' is initialized by the function (caller can omit it)
 */

static void _nn_mul_low(nn_t out, nn_src_t in1, nn_src_t in2,
			u8 wlimit)
{
	word_t carry, prod_high, prod_low;
	u8 i, j, pos;

	nn_check_initialized(in1);
	nn_check_initialized(in2);

	/* We have to check that wlimit does not exceed our NN_MAX_WORD_LEN */
	MUST_HAVE((wlimit * WORD_BYTES) <= NN_MAX_BYTE_LEN);
	nn_init(out, (u16)(wlimit * WORD_BYTES));

	for (i = 0; i < in1->wlen; i++) {
		carry = 0;
		pos = 0;

		for (j = 0; j < in2->wlen; j++) {
			pos = i + j;

			/*
			 * size of the result provided by the caller may not
			 * be large enough for what multiplication may
			 * generate.
			 */
			if (pos >= wlimit) {
				continue;
			}

			/*
			 * Compute the result of the multiplication of
			 * two words.
			 */
			WORD_MUL(prod_high, prod_low,
				 in1->val[i], in2->val[j]);
			/*
			 * And add previous carry.
			 */
			prod_low += carry;
			prod_high += prod_low < carry;

			/*
			 * Add computed word to what we can currently
			 * find at current position in result.
			 */
			out->val[pos] += prod_low;
			carry = prod_high + (out->val[pos] < prod_low);
		}

		/*
		 * What remains in acc_high at end of previous loop should
		 * be added to next word after pos in result.
		 */
		if ((pos + 1) < wlimit) {
			out->val[pos + 1] += carry;
		}
	}
}

/* Handle aliasing */
void nn_mul_low(nn_t out, nn_src_t in1, nn_src_t in2, u8 wlimit)
{
	/* Handle output aliasing */
	if ((out == in1) || (out == in2)) {
		nn out_cpy;
		_nn_mul_low(&out_cpy, in1, in2, wlimit);
		nn_init(out, out_cpy.wlen);
		nn_copy(out, &out_cpy);
		nn_uninit(&out_cpy);
	} else {
		_nn_mul_low(out, in1, in2, wlimit);
	}
}

/* Note: 'out' is initialized by the function (caller can omit it) */
void nn_mul(nn_t out, nn_src_t in1, nn_src_t in2)
{
	nn_mul_low(out, in1, in2, in1->wlen + in2->wlen);
}

void nn_sqr_low(nn_t out, nn_src_t in, u8 wlimit)
{
	nn_mul_low(out, in, in, wlimit);
}

/* Note: 'out' is initialized by the function (caller can omit it) */
void nn_sqr(nn_t out, nn_src_t in)
{
	nn_mul(out, in, in);
}

/* Multiply a multiprecision number by a word. */
void nn_mul_word(nn_t out, nn_src_t in, word_t w)
{
	nn w_nn;

	nn_check_initialized(in);

	nn_init(&w_nn, WORD_BYTES);

	w_nn.val[0] = w;
	nn_mul(out, in, &w_nn);

	nn_uninit(&w_nn);
}
