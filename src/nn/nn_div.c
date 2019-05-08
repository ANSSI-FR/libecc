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
#include "nn_div.h"
#include "nn_mul.h"
#include "nn_logical.h"
#include "nn_add.h"
#include "nn.h"

/*
 * Some helper functions to perform operations on an arbitrary part
 * of a multiprecision number.
 * This is exactly the same code as for operations on the least significant
 * part of a multiprecision number except for the starting point in the
 * array representing it.
 * Done in *constant time*.
 *
 * Operations producing an output are in place.
 */

/* Compare a shifted version of in2 with in1. */
static int nn_cmp_shift(nn_src_t in1, nn_src_t in2, u8 shift)
{
	u8 i;
	int ret, mask;

	MUST_HAVE(in1->wlen >= (in2->wlen + shift));

	ret = 0;
	for (i = in2->wlen; i > 0; i--) {
		mask = !(ret & 0x1);
		ret += (in1->val[shift + i - 1] > in2->val[i - 1]) & mask;
		ret -= (in1->val[shift + i - 1] < in2->val[i - 1]) & mask;
	}

	return ret;
}

/* Conditionally subtract a shifted version of in from out. */
static word_t nn_cnd_sub_shift(int cnd, nn_t out, nn_src_t in, u8 shift)
{
	word_t tmp, borrow1, borrow2, borrow = WORD(0);
	word_t mask = WORD_MASK_IFNOTZERO(cnd);
	u8 i;

	MUST_HAVE(out->wlen >= in->wlen + shift);

	/*
	 *  Perform subtraction one word at a time,
	 *  propagating the borrow.
	 */
	for (i = 0; i < in->wlen; i++) {
		tmp = out->val[shift + i] - (in->val[i] & mask);
		borrow1 = tmp > out->val[shift + i];
		out->val[shift + i] = tmp - borrow;
		borrow2 = out->val[shift + i] > tmp;
		/* There is at most one borrow going out. */
		borrow = borrow1 | borrow2;
	}

	return borrow;
}

/* Subtract a shifted version of in multiplied by w from out and return borrow. */
static word_t nn_submul_word_shift(nn_t out, nn_src_t in, word_t w, u8 shift)
{
	word_t borrow = WORD(0), prod_high, prod_low, tmp;
	u8 i;

	MUST_HAVE(out->wlen >= (in->wlen + shift));

	for (i = 0; i < in->wlen; i++) {
		/*
		 * Compute the result of the multiplication of
		 * two words.
		 */
		WORD_MUL(prod_high, prod_low, in->val[i], w);

		/*
		 * And add previous borrow.
		 */
		prod_low += borrow;
		prod_high += prod_low < borrow;

		/*
		 * Subtract computed word at current position in result.
		 */
		tmp = out->val[shift + i] - prod_low;
		borrow = prod_high + (tmp > out->val[shift + i]);
		out->val[shift + i] = tmp;
	}

	return borrow;
}

/*
 * Compute quotient and remainder of Euclidean division,
 * and do not normalize them.
 * Done in *constant time*,
 * only depending on the lengths of 'a' and 'b',
 * but not on the values of 'a' and 'b'.
 *
 * This uses the above function to perform arithmetic on arbitrary parts
 * of multiprecision numbers.
 *
 * The algorithm used is schoolbook division:
 * + the quotient is computed word by word,
 * + a small division of the MSW is performed to obtain an
 *   approximation of the MSW of the quotient,
 * + the approximation is corrected to obtain the correct
 *   multiprecision MSW of the quotient,
 * + the corresponding product is subtracted from the dividend,
 * + the same procedure is used for the following word of the quotient.
 *
 * It is assumed that:
 * + b is normalized: the MSB of its MSW is 1,
 * + the most significant part of a is smaller than b,
 * + a precomputed reciprocal
 *     v = floor(B^3/(d+1)) - B
 *   where d is the MSW of the (normalized) divisor
 *   is given to perform the small 3-by-2 division.
 * + using this reciprocal, the approximated quotient is always
 *   too small and at most one multiprecision correction is needed.
 *
 * All outputs should have been initialized.
 * Does not support aliasing of 'b' or 'q'.
 *
 */
static void _nn_divrem_normalized(nn_t q, nn_t r, nn_src_t a, nn_src_t b, word_t v)
{
	word_t qstar, qh, ql, rh, rl; /* will be used to perform 3-by-2 div. */
	word_t borrow;
	int small;
	u8 i;

	nn_check_initialized(a);
	nn_check_initialized(b);
	nn_check_initialized(q);
	nn_check_initialized(r);

	MUST_HAVE(b->wlen > 0);
	MUST_HAVE((b->val[b->wlen - 1] >> (WORD_BITS - 1)) == WORD(1));
	MUST_HAVE((a->wlen > b->wlen) && (nn_cmp_shift(a, b, a->wlen - b->wlen) < 0));

	/* Handle trivial aliasing for a and r */
	if (r != a) {
		nn_set_wlen(r, a->wlen);
		nn_copy(r, a);
	}

	nn_set_wlen(q, r->wlen - b->wlen);

	/*
	 * Compute subsequent words of the quotient one by one.
	 * Perform approximate 3-by-2 division using the precomputed
	 * reciprocal and correct afterward.
	 */
	for (i = r->wlen; i > b->wlen; i--) {
		u8 shift = i - b->wlen - 1;

		/*
		 * Perform 3-by-2 approximate division:
		 * <qstar, qh, ql> = <rh, rl> * (v + B)
		 * We are only interested in qstar.
		 */
		rh = r->val[i - 1];
		rl = r->val[i - 2];
		/* Perform 2-by-1 multiplication. */
		WORD_MUL(qh, ql, rl, v);
		WORD_MUL(qstar, ql, rh, v);
		/* And propagate carries. */
		qh += ql;
		qstar += qh < ql;
		qh += rl;
		rh += qh < rl;
		qstar += rh;

		/*
		 * Compute approximate quotient times divisor
		 * and subtract it from remainder:
		 * r = r - (b*qstar << B^shift)
		 */
		borrow = nn_submul_word_shift(r, b, qstar, shift);
		/* Check that the approximate quotient was indeed not too large. */
		MUST_HAVE(r->val[i - 1] >= borrow);
		r->val[i - 1] -= borrow;

		/*
		 * Check whether the approximate quotient was too small or not.
		 * At most one multiprecision correction is needed.
		 */
		small = (!!(r->val[i - 1])) | (nn_cmp_shift(r, b, shift) >= 0);
		/* Perform conditional multiprecision correction. */
		borrow = nn_cnd_sub_shift(small, r, b, shift);
		MUST_HAVE(r->val[i - 1] == borrow);
		r->val[i - 1] -= borrow;
		/* Adjust the quotient if it was too small and set it in the multiprecision array. */
		qstar += (word_t) small;
		q->val[shift] = qstar;
		/* Check that the MSW of remainder was cancelled out and that we could not increase the quotient anymore. */
		MUST_HAVE(r->val[r->wlen - 1] == WORD(0));
		MUST_HAVE(nn_cmp_shift(r, b, shift) < 0);

		nn_set_wlen(r, r->wlen - 1);
	}
}

/*
 * Compute quotient and remainder of Euclidean division,
 * and do not normalize them.
 * Done in *constant time*, see documentation of _nn_divrem_normalized.
 *
 * Assume that 'b' is normalized (the MSB of its MSW is set),
 * that 'v' is the reciprocal of the MSW of 'b'.
 * and that the high part of 'a' is smaller than 'b'.
 *
 * Aliased version of _nn_divrem_normalized for 'r' only.
 */
void nn_divrem_normalized(nn_t q, nn_t r, nn_src_t a, nn_src_t b, word_t v)
{
	nn_check_initialized(a);
	nn_check_initialized(b);
	nn_check_initialized(q);
	nn_check_initialized(r);

	/*
	 * Handle output aliasing for r and b.
	 * No special treatment needed when aliasing r and a.
	 */
	if(r == b){
		nn r_cpy;
		nn_init(&r_cpy, 0);
		_nn_divrem_normalized(q, &r_cpy, a, b, v);
		nn_copy(r, &r_cpy);
		nn_uninit(&r_cpy);
	}
	else{
		_nn_divrem_normalized(q, r, a, b, v);
	}
}

/*
 * Compute remainder only and do not normalize it.
 * Constant time, see documentation of _nn_divrem_normalized.
 *
 * Support aliasing of inputs and outputs.
 */
void nn_mod_normalized(nn_t r, nn_src_t a, nn_src_t b, word_t v)
{
	nn q;

	nn_init(&q, 0);
	nn_divrem_normalized(&q, r, a, b, v);
	nn_uninit(&q);
}


/* 
 * Compute quotient and remainder of Euclidean division,
 * and do not normalize them.
 * Done in *constant time*,
 * only depending on the lengths of 'a' and 'b' and the value of 'cnt',
 * but not on the values of 'a' and 'b'.
 *
 * Assume that b has been normalized by a 'cnt' bit shift,
 * that v is the reciprocal of the MSW of 'b',
 * but a is not shifted yet.
 * Useful when multiple multiplication by the same b are performed,
 * e.g. at the fp level.
 *
 * All outputs should have been initialized.
 * Does not support aliasing of 'b' or 'q'.
 */
static void _nn_divrem_unshifted(nn_t q, nn_t r, nn_src_t a, nn_src_t b_norm, word_t v, bitcnt_t cnt)
{
	nn a_shift;
	u8 new_wlen, b_wlen;
	int larger;

	nn_check_initialized(a);
	nn_check_initialized(b_norm);
	nn_check_initialized(q);
	nn_check_initialized(r);
	MUST_HAVE((a->wlen + BIT_LEN_WORDS(cnt)) < NN_MAX_WORD_LEN);

	/* We now know that new_wlen will fit in an u8 */
	new_wlen = (a->wlen + (u8)BIT_LEN_WORDS(cnt));

	b_wlen = b_norm->wlen;
	if (new_wlen < b_wlen) {
		nn_copy(r, a);
		nn_zero(q);
		return;
	}

	/* Shift a. */
	nn_init(&a_shift, new_wlen * WORD_BYTES);
	nn_set_wlen(&a_shift, new_wlen);
	nn_lshift_fixedlen(&a_shift, a, cnt);

	nn_set_wlen(r, new_wlen);

	if (new_wlen == b_wlen) {
        	/* Ensure that a is smaller than b. */
		larger = nn_cmp(&a_shift, b_norm) >= 0;
		nn_cnd_sub(larger, r, &a_shift, b_norm);
		MUST_HAVE(nn_cmp(r, b_norm) < 0);
        	/* Set MSW of quotient. */
		nn_set_wlen(q, new_wlen - b_wlen + 1);
		q->val[new_wlen - b_wlen] = (word_t) larger;
		/* And we are done as the quotient is 0 or 1. */
	} else if (new_wlen > b_wlen) {
        	/* Ensure that most significant part of a is smaller than b. */
		larger = nn_cmp_shift(&a_shift, b_norm, new_wlen - b_wlen) >= 0;
		nn_cnd_sub_shift(larger, &a_shift, b_norm, new_wlen - b_wlen);
		MUST_HAVE(nn_cmp_shift(&a_shift, b_norm, new_wlen - b_wlen) < 0);
		/*
		 * Perform division with MSP of a smaller than b.
		 * This ensures that the quotient is of length a_len-b_len.
		 */
		_nn_divrem_normalized(q, r, &a_shift, b_norm, v);
		/* Set MSW of quotient. */
		nn_set_wlen(q, new_wlen - b_wlen + 1);
		q->val[new_wlen - b_wlen] = (word_t) larger;
	} /* else a is smaller than b... treated above. */

	nn_rshift_fixedlen(r, r, cnt);
	nn_set_wlen(r, b_wlen);

	nn_uninit(&a_shift);
}

/*
 * Compute quotient and remainder and do not normalize them.
 * Constant time, see documentation of _nn_divrem_unshifted.
 *
 * Aliased version of _nn_divrem_unshifted for 'r' only.
 */
void nn_divrem_unshifted(nn_t q, nn_t r, nn_src_t a, nn_src_t b, word_t v, bitcnt_t cnt)
{
	nn_check_initialized(a);
	nn_check_initialized(b);
	nn_check_initialized(q);
	nn_check_initialized(r);

	/*
	 * Handle output aliasing for r and b.
	 * No special treatment needed when aliasing r and a.
	 */
	if(r == b){
		nn r_cpy;
		nn_init(&r_cpy, 0);
		_nn_divrem_unshifted(q, &r_cpy, a, b, v, cnt);
		nn_copy(r, &r_cpy);
		nn_uninit(&r_cpy);
	}
	else{
		_nn_divrem_unshifted(q, r, a, b, v, cnt);
	}
}

/*
 * Compute remainder only and do not normalize it.
 * Constant time, see documentation of _nn_divrem_unshifted.
 *
 * Aliasing of inputs and outputs is possible.
 */
void nn_mod_unshifted(nn_t r, nn_src_t a, nn_src_t b, word_t v, bitcnt_t cnt)
{
	nn q;
	nn_init(&q, 0);
	nn_divrem_unshifted(&q, r, a, b, v, cnt);
	nn_uninit(&q);
}

/*
 * Helper functions for arithmetic in 2-by-1 division
 * used in the reciprocal computation.
 *
 * These are variations of the nn multiprecision functions
 * acting on arrays of fixed length, in place,
 * and returning carry/borrow.
 *
 * Done in constant time.
 */

/* Comparison of two limbs numbers. */
static int wcmp_22(word_t a[2], word_t b[2])
{
	int mask, ret = 0;
	ret += a[1] > b[1];
	ret -= a[1] < b[1];
	mask = !(ret & 0x1);
	ret += (a[0] > b[0]) & mask;
	ret -= (a[0] < b[0]) & mask;
	return ret;
}

/* Addition of two limbs numbers with carry returned. */
static word_t wadd_22(word_t a[2], word_t b[2])
{
	word_t carry;
	a[0] += b[0];
	carry = a[0] < b[0];
	a[1] += carry;
	carry = a[1] < carry;
	a[1] += b[1];
	carry |= a[1] < b[1];
	return carry;
}

/* Subtraction of two limbs numbers with borrow returned. */
static word_t wsub_22(word_t a[2], word_t b[2])
{
	word_t borrow, tmp;
	tmp = a[0] - b[0];
	borrow = tmp > a[0];
	a[0] = tmp;
	tmp = a[1] - borrow;
	borrow = tmp > a[1];
	a[1] = tmp - b[1];
	borrow |= a[1] > tmp;
	return borrow;
}

/*
 * Helper macros for conditional subtraction in 2-by-1 division
 * used in the reciprocal computation.
 *
 * Done in constant time.
 */

/* Conditional subtraction of a one limb number from a two limbs number. */
#define WORD_CND_SUB_21(cnd, ah, al, b) do {				\
		word_t tmp, mask;					\
		mask = WORD_MASK_IFNOTZERO((cnd));			\
		tmp = (al) - ((b) & mask);				\
		(ah) -= tmp > (al);					\
		(al) = tmp;						\
	} while (0)
/* Conditional subtraction of a two limbs number from a two limbs number. */
#define WORD_CND_SUB_22(cnd, ah, al, bh, bl) do {			\
		word_t tmp, mask;					\
		mask = WORD_MASK_IFNOTZERO((cnd));			\
		tmp = (al) - ((bl) & mask);				\
		(ah) -= tmp > (al);					\
		(al) = tmp;						\
		(ah) -= (bh) & mask;					\
	} while (0)

/*
 * WORD_DIVREM: divide two words by a normalized word using schoolbook division
 * on half words.
 * This is only used below in the reciprocal computation.
 */
#define WORD_DIVREM(q, r, ah, al, b) do {				\
		int larger;						\
		u8 j;							\
		word_t bh, bl;						\
		word_t qh, ql;						\
		word_t rhl[2], rm;					\
		word_t phl[2];						\
		MUST_HAVE(WRSHIFT((b), (WORD_BITS - 1)) == WORD(1));	\
		bh = WRSHIFT((b), HWORD_BITS);				\
		bl = WLSHIFT((b), HWORD_BITS);				\
		rhl[1] = (ah);						\
		rhl[0] = (al);						\
		/*                                                      \
		 * Compute high part of the quotient. We know from      \
		 * MUST_HAVE() check above that bh (a word_t) is not 0  \
		 */							\
		KNOWN_FACT(bh != 0);					\
		qh = rhl[1] / bh;					\
		qh = WORD_MIN(qh, HWORD_MASK);				\
		WORD_MUL(phl[1], phl[0], qh, (b));			\
		phl[1] = (WLSHIFT(phl[1], HWORD_BITS) |			\
			  WRSHIFT(phl[0], HWORD_BITS));			\
		phl[0] = WLSHIFT(phl[0], HWORD_BITS);			\
		for (j = 0; j < 2; j++) {				\
			larger = wcmp_22(phl, rhl) > 0;			\
			qh -= (word_t) larger;				\
			WORD_CND_SUB_22(larger, phl[1], phl[0], bh, bl);\
		}							\
		MUST_HAVE(wcmp_22(phl, rhl) <= 0);			\
		wsub_22(rhl, phl);					\
		MUST_HAVE(WRSHIFT(rhl[1], HWORD_BITS) == 0);		\
		/* Compute low part of the quotient. */			\
		rm = (WLSHIFT(rhl[1], HWORD_BITS) |			\
		      WRSHIFT(rhl[0], HWORD_BITS));			\
		ql = rm / bh;						\
		ql = WORD_MIN(ql, HWORD_MASK);				\
		WORD_MUL(phl[1], phl[0], ql, (b));			\
		for (j = 0; j < 2; j++) {				\
			larger = wcmp_22(phl, rhl) > 0;			\
			ql -= (word_t) larger;				\
			WORD_CND_SUB_21(larger, phl[1], phl[0], (b));	\
		}							\
		MUST_HAVE(wcmp_22(phl, rhl) <= 0);			\
		wsub_22(rhl, phl);					\
		/* Set outputs. */					\
		MUST_HAVE(rhl[1] == WORD(0));				\
		MUST_HAVE(rhl[0] < (b));				\
		(q) = WLSHIFT(qh, HWORD_BITS) | ql;			\
		(r) = rhl[0];						\
		MUST_HAVE((word_t) ((q)*(b) + (r)) == (al));		\
	} while (0)

/*
 * Compute the reciprocal of d as
 * 	floor(B^3/(d+1)) - B
 * which is used to perform approximate small division using a multiplication.
 *
 * No attempt was made to make it constant time.
 * Indeed, such values are usually precomputed in contexts
 * where constant time is wanted, e.g. in the fp layer.
 */
word_t wreciprocal(word_t dh, word_t dl)
{
	word_t q;
	word_t carry;
	word_t r[2], t[2];

	if (((word_t)(dh + WORD(1)) == WORD(0))
	    && ((word_t)(dl + WORD(1)) == WORD(0)))
		return WORD(0);

	if ((word_t)(dh + WORD(1)) == WORD(0)) {
		q = ~dh;
		r[1] = ~dl;
	} else {
		t[1] = ~dh;
		t[0] = ~dl;
		WORD_DIVREM(q, r[1], t[1], t[0], (word_t)(dh + WORD(1)));
	}

	if ((word_t)(dl + WORD(1)) == WORD(0))
		return q;

	r[0] = WORD(0);

	WORD_MUL(t[1], t[0], q, (word_t)~dl);
	carry = wadd_22(r, t);

	t[0] = dl + WORD(1);
	t[1] = dh;
	while (carry || (wcmp_22(r, t) >= 0)) {
		q++;
		carry -= wsub_22(r, t);
	}

	return q;
}

/*
 * Given an odd number p, compute division coefficients p_normalized,
 * p_shift and p_reciprocal so that:
 *	- p_shift = p_rounded_bitlen - bitsizeof(p), where
 *          o p_rounded_bitlen = BIT_LEN_WORDS(p) (i.e. bit length of
 *            minimum number of words required to store p) and
 *          o p_bitlen is the real bit size of p
 *	- p_normalized = p << p_shift
 *	- p_reciprocal = B^3 / ((p_normalized >> (pbitlen - 2*WORDSIZE)) + 1) - B
 *	  with B = 2^WORDSIZE
 *
 * These coefficients are useful for the optimized shifted variants of NN
 * division and modular functions. Because we have two word_t outputs
 * (p_shift and p_reciprocal), these are passed through word_t pointers.
 * Aliasing of outputs with the input is possible since p_in is copied in
 * local p at the beginning of the function.
 */
void nn_compute_div_coefs(nn_t p_normalized, word_t *p_shift,
			  word_t *p_reciprocal, nn_src_t p_in)
{
	bitcnt_t p_rounded_bitlen;
	nn p, tmp_nn;

	nn_check_initialized(p_in);
	MUST_HAVE(p_shift != NULL);
	MUST_HAVE(p_reciprocal != NULL);

	nn_init(&p, 0);
	nn_copy(&p, p_in);

	/*
	 * In order for our reciprocal division routines to work, it is expected
	 * that the bit length (including leading zeroes) of input prime
	 * p is >= 2 * wlen where wlen is the number of bits of a word size.
	 */
	if (p.wlen < 2) {
		nn_set_wlen(&p, 2);
	}

	nn_init(p_normalized, 0);
	nn_init(&tmp_nn, 0);

	/* p_rounded_bitlen = bitlen of p rounded to word size */
	p_rounded_bitlen = WORD_BITS * p.wlen;

	/* p_shift */
	(*p_shift) = p_rounded_bitlen - nn_bitlen(&p);

	/* p_normalized = p << pshift */
	nn_lshift(p_normalized, &p, (bitcnt_t)(*p_shift));

	/* Sanity check to protect the p_reciprocal computation */
	MUST_HAVE(p_rounded_bitlen >= (2 * WORDSIZE));
	/*
	 * p_reciprocal = B^3 / ((p_normalized >> (p_rounded_bitlen - 2 * wlen)) + 1) - B
	 * where B = 2^wlen where wlen = word size in bits. We use our NN
	 * helper to compute it.
	 */
	nn_rshift(&tmp_nn, p_normalized, (p_rounded_bitlen - (2 * WORDSIZE)));
	(*p_reciprocal) = wreciprocal(tmp_nn.val[1], tmp_nn.val[0]);

	nn_uninit(&p);
	nn_uninit(&tmp_nn);
}

/*
 * Compute quotient remainder of Euclidean division.
 *
 * This function is a wrapper to normalize the divisor,
 * i.e. shift it so that the MSB of its MSW is set,
 * and precompute the reciprocal of this MSW to be used
 * to perform small divisions using multiplications
 * during the long schoolbook division.
 * It uses the helper functions/macros above.
 *
 * This is NOT constant time with regards to the word length of a and b,
 * but also the actual bitlength of b as we need to normalize b at the
 * bit level.
 * Moreover the precomputation of the reciprocal is not constant time at all.
 *
 * r need not be initialized, the function does it for the the caller.
 *
 * This function does not support aliasing.
 */
static void _nn_divrem(nn_t q, nn_t r, nn_src_t a, nn_src_t b)
{
	nn b_large, b_normalized;
	bitcnt_t cnt;
	word_t v;
	nn_src_t ptr = b;

	nn_init(r, 0);
	nn_init(q, 0);
	nn_init(&b_large, 0);

	MUST_HAVE(!nn_iszero(b));

	if(b->wlen == 1){
		nn_copy(&b_large, b);
		/* Expand our big number with zeroes */
		nn_set_wlen(&b_large, 2);
		/* This cast could seem inappropriate, but we are 
		 * sure here that we won't touch ptr since it is only 
		 * given as a const parameter to sub functions.
		 */
		ptr = (nn_src_t) &b_large;
	}
	/* After this, we only handle >= 2 words big numbers */
	MUST_HAVE(ptr->wlen >= 2);

	nn_init(&b_normalized, (ptr->wlen) * WORD_BYTES);

	cnt = nn_clz(ptr);
	nn_lshift_fixedlen(&b_normalized, ptr, cnt);

	v = wreciprocal(b_normalized.val[ptr->wlen - 1],
			b_normalized.val[ptr->wlen - 2]); /* Not constant time. */

	_nn_divrem_unshifted(q, r, a, &b_normalized, v, cnt);

	nn_uninit(&b_normalized);
	nn_uninit(&b_large);
}

/*
 * Compute quotient and remainder and normalize them.
 * Not constant time, see documentation of _nn_divrem.
 *
 * Aliased version of _nn_divrem.
 */
void nn_divrem_notrim(nn_t q, nn_t r, nn_src_t a, nn_src_t b)
{

	/* _nn_divrem initializes q and r */
	nn_check_initialized(a);
	nn_check_initialized(b);

	/* Handle aliasing whenever any of the inputs is 
	 * used as an output.
	 */
	if ((a == q) || (a == r) || (b == q) || (b == r)) {
		nn a_cpy, b_cpy;

		nn_init(&a_cpy, 0);
		nn_init(&b_cpy, 0);
		nn_copy(&a_cpy, a);
		nn_copy(&b_cpy, b);

		_nn_divrem(q, r, &a_cpy, &b_cpy);

		nn_uninit(&a_cpy);
		nn_uninit(&b_cpy);
	}
	else{
		_nn_divrem(q, r, a, b);
	}

	return;
}

/*
 * Compute quotient and remainder and normalize them.
 * Not constant time, see documentation of _nn_divrem.
 */
void nn_divrem(nn_t q, nn_t r, nn_src_t a, nn_src_t b)
{
	nn_divrem_notrim(q, r, a, b);
	/* Normalize (trim) the quotient and rest to avoid size overflow */
	nn_normalize(q);
	nn_normalize(r);
}

/*
 * Compute remainder only and do not normalize it.
 * Not constant time, see documentation of _nn_divrem.
 */
void nn_mod_notrim(nn_t r, nn_src_t a, nn_src_t b)
{
	nn q;
	/* nn_divrem will init q. */
	nn_divrem_notrim(&q, r, a, b);
	nn_uninit(&q);
}

/*
 * Compute remainder only and normalize it.
 * Not constant time, see documentation of _nn_divrem.
 */
void nn_mod(nn_t r, nn_src_t a, nn_src_t b)
{
	nn q;
	/* nn_divrem will init q. */
	nn_divrem(&q, r, a, b);
	nn_uninit(&q);
}

/*
 * Below follow gcd and xgcd non constant time functions for the user ease.
 */

/* 
 * Unaliased version of xgcd, and we suppose that a >= b.
 * Badly non-constant time per the algorithm used.
 */
static int _nn_xgcd(nn_t g, nn_t u, nn_t v, nn_src_t a, nn_src_t b)
{
	u8 i;
	int swap;
	nn_t c, d, q, r;
	nn_t u1, v1, u2, v2;
	nn scratch[8];

	/*
	 * Maintain:
	 * |u1 v1| |c| = |a|
	 * |u2 v2| |d|   |b|
	 * u1, v1, u2, v2 >= 0
	 * c >= d
	 *
	 * Initially:
	 * |1  0 | |a| = |a|
	 * |0  1 | |b|   |b|
	 *
	 * At each iteration:
	 * c >= d
	 * c = q*d + r
	 * |u1 v1| = |q*u1+v1 u1|
	 * |u2 v2|   |q*u2+v2 u2|
	 *
	 * Finally, after i steps:
	 * |u1 v1| |g| = |a|
	 * |u2 v2| |g| = |b|
	 *
	 * Inverting the matrix:
	 * |g| = (-1)^i | v2 -v1| |a|
	 * |g|          |-u2  u1| |b|
	 */

	/*
	 * Initialization.
	 */
	nn_init(g, 0);
	nn_init(u, 0);
	nn_init(v, 0);
	if (nn_iszero(b)) {
		/* gcd(0, a) = a, and 1*a + 0*b = a */
		nn_copy(g, a);
		nn_one(u);
		nn_zero(v);
		return 1;
    	}

	for (i = 0; i < 8; i++){
		nn_init(scratch + i, 0);
	}
	u1 = &(scratch[0]);
	v1 = &(scratch[1]);
	u2 = &(scratch[2]);
	v2 = &(scratch[3]);
	nn_one(u1);
	nn_zero(v1);
	nn_zero(u2);
	nn_one(v2);
	c = &(scratch[4]);
	d = &(scratch[5]);
	nn_copy(c, a); /* Copy could be skipped. */
	nn_copy(d, b); /* Copy could be skipped. */
	q = &(scratch[6]);
	r = &(scratch[7]);
	swap = 0;

	/*
	 * Loop.
	 */
	while (!nn_iszero(d)) {
		nn_divrem(q, r, c, d);
		nn_normalize(q);
		nn_normalize(r);
		nn_copy(c, r);
		nn_mul(r, q, u1);
		nn_normalize(r);
		nn_add(v1, v1, r);
		nn_mul(r, q, u2);
		nn_normalize(r);
		nn_add(v2, v2, r);
		nn_normalize(v1);
		nn_normalize(v2);
		swap = 1;
		if (nn_iszero(c)){
			break;
		}
		nn_divrem(q, r, d, c);
		nn_normalize(q);
		nn_normalize(r);
		nn_copy(d, r);
		nn_mul(r, q, v1);
		nn_normalize(r);
		nn_add(u1, u1, r);
		nn_mul(r, q, v2);
		nn_normalize(r);
		nn_add(u2, u2, r);
		nn_normalize(u1);
		nn_normalize(u2);
		swap = 0;
	}

	/* Copies could be skipped. */
	if (swap) {
		nn_copy(g, d);
		nn_copy(u, u2);
		nn_copy(v, u1);
	} else {
		nn_copy(g, c);
		nn_copy(u, v2);
		nn_copy(v, v1);
	}
	
	for (i = 0; i < 8; i++){
		nn_uninit(scratch + i);
	}

	/* swap = -1 means u <= 0; = 1 means v <= 0 */
	return swap ? -1 : 1;
}

/* 
 * Aliased version of xgcd, and no assumption on a and b.
 * Not constant time at all.
 */
int nn_xgcd(nn_t g, nn_t u, nn_t v, nn_src_t a, nn_src_t b)
{
	int ret;

	/* Handle aliasing 
	 * Note: in order to properly handle aliasing, we accept to lose 
	 * some "space" on the stack with copies.
	 */
	nn a_cpy, b_cpy;
	nn_src_t a_, b_;

	/* The internal _nn_xgcd function initializes g, u and v */
	nn_check_initialized(a);
	nn_check_initialized(b);

	nn_init(&a_cpy, 0);
	nn_init(&b_cpy, 0);

	/* Aliasing of a */
	if((g == a) || (u == a) || (v == a)){
		nn_copy(&a_cpy, a);
		a_ = &a_cpy;
	}
	else{
		a_ = a;
	}
	/* Aliasing of b */
	if((g == b) || (u == b) || (v == b)){
		nn_copy(&b_cpy, b);
		b_ = &b_cpy;
	}
	else{
		b_ = b;
	}

	if (nn_cmp(a_, b_) < 0) {
		/* If a < b, swap the inputs */
		ret = -(_nn_xgcd(g, v, u, b_, a_));

	}
	else{
		ret = _nn_xgcd(g, u, v, a_, b_);
	}
	
	nn_uninit(&a_cpy);
	nn_uninit(&b_cpy);

	return ret;
}

/*
 * Compute g = gcd(a, b).
 * Internally use the xgcd and drop u and v.
 * Not constant time at all.
 */
void nn_gcd(nn_t g, nn_src_t a, nn_src_t b)
{
	nn u, v;

	/* nn_xgcd will initialize g, u and v and 
	 * check if a and b are indeed initialized.
	 */
	nn_xgcd(g, &u, &v, a, b);

	return; 
}
