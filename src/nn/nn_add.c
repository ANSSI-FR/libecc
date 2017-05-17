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
#include "nn_add.h"
#include "nn.h"

/*
 * This module provides conditional addition and subtraction functions between
 * two nn's:
 *
 *  o out = in1 +/- in2 if cnd is not zero.
 *  o out = in1 if cnd is zero.
 *
 * The time taken by the operation does not depend on cnd value, i.e. it is
 * constant time for that specific factor, nor on the values of in1 and in2.
 * It still depends on the maximal length of in1 and in2.
 *
 * Common addition and subtraction functions are derived from those conditional
 * versions.
 */

/*
 * Conditionally adds 'in2' to 'in1' according to "cnd", storing the result
 * in "out" and returning the carry. This is the lowest level function for
 * conditional addition.
 *
 * Note that unlike "usual" addition, the function is *in general* not
 * commutative, i.e. "_nn_cnd_add(cnd, out, in1, in2)"  is not equivalent
 * to "_nn_cnd_add(cnd, out, in2, in1)". It is commutative though if "cnd"
 * is not zero or 'in1' == 'in2'.
 *
 * Aliasing of inputs and output is possible. "out" is initialized if needed,
 * that is if not aliased to 'in1' or 'in2'. The length of "out" is set to
 * the maximal length of 'in1' and 'in2'. Note that both 'in1' and 'in2' will
 * be read to this maximal length. As our memory managment model assumes that
 * storage arrays only contains zeros past the "wlen" index, correct results
 * will be produced. The length of 'out' is not normalized on return.
 *
 * The runtime of this function should not depend on:
 *  o the value of "cnd",
 *  o the data stored in 'in1' and 'in2'.
 * It depends on:
 *  o the maximal length of 'in1' and 'in2'.
 *
 * This function is for internal use only.
 */
static word_t _nn_cnd_add(int cnd, nn_t out, nn_src_t in1, nn_src_t in2)
{
	word_t tmp, carry1, carry2, carry = WORD(0);
	word_t mask = WORD_MASK_IFNOTZERO(cnd);
	u8 i, loop_wlen;

	nn_check_initialized(in1);
	nn_check_initialized(in2);

	/* Handle aliasing */
	loop_wlen = MAX(in1->wlen, in2->wlen);
	if ((out != in1) && (out != in2)) {
		nn_init(out, loop_wlen * WORD_BYTES);
	} else {
		nn_set_wlen(out, loop_wlen);
	}

	/* Perform addition one word at a time, propagating the carry. */
	for (i = 0; i < loop_wlen; i++) {
		tmp = in1->val[i] + (in2->val[i] & mask);
		carry1 = tmp < in1->val[i];
		out->val[i] = tmp + carry;
		carry2 = out->val[i] < tmp;
		/* There is at most one carry going out. */
		carry = carry1 | carry2;
	}

	return carry;
}

/*
 * Conditionally adds 'in2' to 'in1' according to "cnd", storing the result
 * in "out", including the potential carry overflowing past the maximal
 * length of 'in1' and 'in2'. It is user responsibility to ensure that the
 * resulting nn will not be higher than what can be supported. This is
 * for instance guaranteed if both in1->wlen and in2->wlen are less than
 * NN_MAX_WORD_LEN. Otherwise the function will error out which could leak
 * information.
 *
 * Note that the length of the output depends the lengths of the inputs,
 * but also on their values.
 * It is the user responsibility to use this function carefully when
 * constant time of an algorithm using this function is seeked.
 * This choice was preferred above unconditionally increasing
 * the length of the output by one, to ease the management of length
 * explosion when multiple additions are performed.
 * For finer carry propagation and length control the internal "_nn_cnd_add"
 * function can be used.
 *
 * See "_nn_cnd_add" documentation above for further details.
 */
void nn_cnd_add(int cnd, nn_t out, nn_src_t in1, nn_src_t in2)
{
	word_t carry = _nn_cnd_add(cnd, out, in1, in2);

	/* We cannot allow a non-zero carry if out->wlen is at its limit */
	MUST_HAVE((out->wlen != NN_MAX_WORD_LEN) || (!carry));
	if (out->wlen != NN_MAX_WORD_LEN) {
		/*
		 * To maintain constant time, we perform carry addition in all
		 * cases. If carry is 0, no change is performed in practice,
		 * neither to 'out' value, nor to its length.
		 * Note that the length of the output can vary and make
		 * the time taken by further operations on it will vary.
		 */
		out->val[out->wlen] = carry;
		out->wlen += carry;
	}
}

/*
 * Unconditionally adds 'in2' to 'in1', storing the result in "out",
 * including the potential carry overflowing past the maximal length of
 * 'in1' and 'in2'.
 *
 * Note that the length of the output depends the lengths of the inputs,
 * but also on their values.
 * It is the user responsibility to use this function carefully when
 * constant time of an algorithm using this function is seeked.
 *
 * See "_nn_cnd_add" documentation for further details.
 */
void nn_add(nn_t out, nn_src_t in1, nn_src_t in2)
{
	nn_cnd_add(1, out, in1, in2);
}

/*
 * Compute out = in1 + w where 'in1' is an initialized nn and 'w' a word. It is
 * caller responsibility to ensure that the result will fit in a nn (This is
 * for instance guaranteed if 'in1' wlen is less than NN_MAX_WORD_LEN).
 *
 * The result is stored in 'out' parameter. 'out' is initialized if needed (i.e.
 * in case aliasing is not used) and is not normalized on return.
 *
 * Note that the length of the output depends the lengths of the inputs,
 * but also on their values.
 * It is the user responsibility to use this function carefully when
 * constant time of an algorithm using this function is seeked.
 *
 * This function is for internal use only.
 */
static void nn_add_word(nn_t out, nn_src_t in1, word_t w)
{
	word_t carry, tmp;
	u8 i, n_wlen;

	nn_check_initialized(in1);

	/* Handle aliasing */
	n_wlen = in1->wlen;
	if ((out != in1)) {
		nn_init(out, n_wlen * WORD_BYTES);
	} else {
		nn_set_wlen(out, n_wlen);
	}

	/* No matter its value, propagate the carry. */
	carry = w;
	for (i = 0; i < n_wlen; i++) {
		tmp = in1->val[i] + carry;
		carry = tmp < in1->val[i];
		out->val[i] = tmp;
	}

	MUST_HAVE((out->wlen != NN_MAX_WORD_LEN) || (!carry));
	if (out->wlen != NN_MAX_WORD_LEN) {
		/*
		 * To maintain constant time, we perform carry addition in all
		 * cases. If carry is 0, no change is performed in practice,
		 * neither to 'out' value, nor to its length.
		 * Note that the length of the output can vary and make
		 * the time taken by further operations on it will vary.
		 */
		out->val[out->wlen] = carry;
		out->wlen += carry;
	}
}

/*
 * Compute out = in1 + 1. Aliasing is supported i.e. nn_inc(in1, in1) works as
 * expected and provides in1++. It is caller responsibility to ensure that the
 * result will fit in a nn (This is for instance guaranteed if 'in1' wlen is
 * less than NN_MAX_WORD_LEN).
 *
 * Note that the length of the output depends the lengths of the inputs,
 * but also on their values.
 * It is the user responsibility to use this function carefully when
 * constant time of an algorithm using this function is seeked.
 */
void nn_inc(nn_t out, nn_src_t in1)
{
	nn_add_word(out, in1, WORD(1));
}

/*
 * Conditionally subtracts 'in2' from 'in1' according to "cnd",
 * storing the result in "out":
 *  o out = in1 - in2 if cnd is not zero.
 *  o out = in1 if cnd is zero.
 *
 * 'in1' and 'in2' must point to initialized nn, such that the value of 'in1'
 * is larger than 'in2'. Aliasing is supported, i.e. 'out' can point to the
 * same nn as 'in1' or 'in2'. If aliasing is not used, 'out' is initialized by
 * the function. The length of 'out' is set to the length of 'in1'
 * and is not normalized on return.
 */
void nn_cnd_sub(int cnd, nn_t out, nn_src_t in1, nn_src_t in2)
{
	word_t tmp, borrow1, borrow2, borrow = WORD(0);
	word_t mask = WORD_MASK_IFNOTZERO(cnd);
	u8 loop_wlen, i;

	nn_check_initialized(in1);
	nn_check_initialized(in2);

	/* Handle aliasing */
	loop_wlen = MAX(in1->wlen, in2->wlen);
	if ((out != in1) && (out != in2)) {
		nn_init(out, loop_wlen * WORD_BYTES);
	} else {
		nn_set_wlen(out, in1->wlen);
	}

	/* Perform subtraction one word at a time, propagating the borrow. */
	for (i = 0; i < loop_wlen; i++) {
		tmp = in1->val[i] - (in2->val[i] & mask);
		borrow1 = tmp > in1->val[i];
		out->val[i] = tmp - borrow;
		borrow2 = out->val[i] > tmp;
		/* There is at most one borrow going out. */
		borrow = borrow1 | borrow2;
	}

	/* We only support the in1 >= in2 case */
	MUST_HAVE(borrow == 0);
}

/* Same as the one above, but the subtraction is performed unconditionally. */
void nn_sub(nn_t out, nn_src_t in1, nn_src_t in2)
{
	nn_cnd_sub(1, out, in1, in2);
}

/*
 * Compute out = in1 - 1 where in1 is a *positive* integer. Aliasing is
 * supported i.e. nn_dec(A, A) works as expected and provides A -= 1.
 */
void nn_dec(nn_t out, nn_src_t in1)
{
	const word_t w = WORD(1);
	word_t tmp, borrow;
	u8 n_wlen, i;

	nn_check_initialized(in1);

	n_wlen = in1->wlen;
	nn_set_wlen(out, n_wlen);

	/* Perform subtraction w/ provided word and propagate the borrow */
	borrow = w;
	for (i = 0; i < n_wlen; i++) {
		tmp = in1->val[i] - borrow;
		borrow = tmp > in1->val[i];
		out->val[i] = tmp;
	}
	MUST_HAVE(borrow == WORD(0));
}

/*
 * The following functions handle modular arithmetic. Our outputs sizes do not
 * need a "normalization" since everything will be bounded by the modular number
 * size.
 *
 * Warning: the following functions are only useful when the inputs are < p,
 * i.e. we suppose that the input are already reduced modulo p. These primitives
 * are mostly useful for the Fp layer. Even though they give results when
 * applied to inputs >= p, there is no guarantee that the result is indeed < p
 * or correct whatsoever.
 */

/* Compute out = in1 + in2 mod p. */
void nn_mod_add(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p)
{
	int larger;

	nn_check_initialized(in1);
	nn_check_initialized(in2);
	MUST_HAVE(p->wlen < NN_MAX_WORD_LEN);	/* otherwise carry could overflow */
	SHOULD_HAVE(nn_cmp(in1, p) < 0);	/* a SHOULD_HAVE as documented above */
	SHOULD_HAVE(nn_cmp(in2, p) < 0);	/* a SHOULD_HAVE as documented above */

	nn_add(out, in1, in2);
	/*
	 * If previous addition extends out->wlen, this may have an effect on
	 * computation time of functions below. For that reason, we always
	 * normalize out->wlen to p->wlen + 1. Its length is set to that of
	 * p after the computations.
	 *
	 * We could also use _nn_cnd_add to catch the carry and deal
	 * with p's of size NN_MAX_WORD_LEN.
	 * It is still painful because we have no constraint on the lengths
	 * of in1 and in2 so getting a carry out does not necessarily mean
	 * that the sum is larger than p...
	 */
	nn_set_wlen(out, p->wlen + 1);
	larger = (nn_cmp(out, p) >= 0);
	nn_cnd_sub(larger, out, out, p);
	nn_set_wlen(out, p->wlen);
}

/* Compute out = in1 + 1 mod p */
void nn_mod_inc(nn_t out, nn_src_t in1, nn_src_t p)
{
	int larger;

	nn_check_initialized(in1);
	nn_check_initialized(p);
	MUST_HAVE(p->wlen < NN_MAX_WORD_LEN);	/* otherwise carry could overflow */
	SHOULD_HAVE(nn_cmp(in1, p) < 0);	/* a SHOULD_HAVE as documented above */

	nn_inc(out, in1);
	nn_set_wlen(out, p->wlen + 1);	/* see comment in nn_mod_add() */
	larger = (nn_cmp(out, p) >= 0);
	nn_cnd_sub(larger, out, out, p);
	nn_set_wlen(out, p->wlen);
}

/* Compute out = in1 - in2 mod p */
void nn_mod_sub(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p)
{
	nn_src_t in2_;
	int smaller;
	nn in2_cpy;

	nn_check_initialized(in1);
	nn_check_initialized(in2);
	nn_check_initialized(p);
	MUST_HAVE(p->wlen < NN_MAX_WORD_LEN);	/* otherwise carry could overflow */
	SHOULD_HAVE(nn_cmp(in1, p) < 0);	/* a SHOULD_HAVE as documented above */
	SHOULD_HAVE(nn_cmp(in2, p) < 0);	/* a SHOULD_HAVE as documented above */

	/* Handle the case where in2 and out are aliased */
	if (in2 == out) {
		nn_copy(&in2_cpy, in2);
		in2_ = &in2_cpy;
	} else {
		nn_init(&in2_cpy, 0);
		in2_ = in2;
	}

	/* The below trick is used to avoid handling of "negative" numbers. */
	smaller = nn_cmp(in1, in2_) < 0;
	nn_cnd_add(smaller, out, in1, p);
	nn_set_wlen(out, p->wlen + 1);	/* See Comment in nn_mod_add() */
	nn_sub(out, out, in2_);
	nn_set_wlen(out, p->wlen);
	nn_uninit(&in2_cpy);
}

/* Compute out = in1 - 1 mod p */
void nn_mod_dec(nn_t out, nn_src_t in1, nn_src_t p)
{
	nn_check_initialized(in1);
	nn_check_initialized(p);
	MUST_HAVE(p->wlen < NN_MAX_WORD_LEN);	/* otherwise carry could overflow */
	SHOULD_HAVE(nn_cmp(in1, p) < 0);	/* a SHOULD_HAVE; Documented above */

	/* The below trick is used to avoid handling of "negative" numbers. */
	nn_cnd_add(nn_iszero(in1), out, in1, p);
	nn_set_wlen(out, p->wlen + 1);	/* See Comment in nn_mod_add() */
	nn_dec(out, out);
	nn_set_wlen(out, p->wlen);
}
