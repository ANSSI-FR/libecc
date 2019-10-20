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
#define NN_CONSISTENCY_CHECK
#include "nn.h"

/*
 * Except otherwise specified, all functions accept *initialized* nn.
 * The WORD(NN_MAX_WORD_LEN + WORDSIZE) magic is here to detect modules
 * compiled with different WORDSIZE or NN_MAX_WORD_LEN and are binary incompatible.
 */

#define NN_MAGIC ((word_t)((0xb4cf5d56e2023316ULL ^ (WORD(NN_MAX_WORD_LEN + WORDSIZE)))))

/*
 * Local helper internally used to check that the storage space
 * above wlen is made of zero words.
 * Due to its performance cost, this consistency check is used
 * in SHOULD_HAVE macros, meaning that it will only be present
 * in DEBUG mode. Hence the ATTRIBUTE_UNUSED so that no warning
 * (error in -Werror) is triggered at compilation time.
 *
 */
static int ATTRIBUTE_UNUSED __nn_is_wlen_consistent(nn_src_t A)
{
	word_t val = 0;
	u8 i;

	for (i = A->wlen; i < NN_MAX_WORD_LEN; i++) {
		val |= (A)->val[i];
	}
	return (val == 0);
}

/*
 * Verify that pointed nn has already been initialized. This function
 * should be used as a safety net in all function before using a nn
 * received as parameter.
 */
void nn_check_initialized(nn_src_t A)
{
	MUST_HAVE((A != NULL) && (A->magic == NN_MAGIC) &&
		  (A->wlen <= NN_MAX_WORD_LEN));
	SHOULD_HAVE(__nn_is_wlen_consistent(A));
}

/*
 * Verify that pointed nn has already been initialized and return 0 or 1.
 *
 */
int nn_is_initialized(nn_src_t A)
{
	return !!((A != NULL) && (A->magic == NN_MAGIC) &&
		   (A->wlen <= NN_MAX_WORD_LEN));
}

/*
 * Initialize nn from expected initial byte length 'len', setting its wlen
 * to associated (ceil) value and clearing whole storage space.
 */
void nn_init(nn_t A, u16 len)
{
	u8 i;

	MUST_HAVE((A != NULL) && (len <= NN_MAX_BYTE_LEN));

	A->wlen = (u8)BYTE_LEN_WORDS(len);
	A->magic = NN_MAGIC;

	for (i = 0; i < NN_MAX_WORD_LEN; i++) {
		A->val[i] = WORD(0);
	}
}

/* Set current value of pointed initialized nn to 0. */
void nn_zero(nn_t A)
{
	nn_check_initialized(A);
	nn_init(A, 0);
}

/* Set current value of pointed initialized nn to given word value. */
void nn_set_word_value(nn_t A, word_t val)
{
	nn_zero(A);
	A->val[0] = val;
	A->wlen = 1;
}

/* Set current value of pointed initialized nn to 1. */
void nn_one(nn_t A)
{
	nn_set_word_value(A, WORD(1));
}

/*
 * Uninitialize pointed nn to prevent further use (magic field in
 * the structure is zeroized) and zeroize associated storage space.
 */
void nn_uninit(nn_t A)
{
	nn_zero(A);
	A->wlen = 0;
	A->magic = 0;
}

/*
 * Conditionally swap two nn's content *in constant time*
 * Swapping is done if 'cnd' is not zero. Nothing is done otherwise.
 */
void nn_cnd_swap(int cnd, nn_t in1, nn_t in2)
{
	word_t mask = WORD_MASK_IFNOTZERO(cnd);
	u8 len, i;
	word_t t;

	nn_check_initialized(in1);
	nn_check_initialized(in2);
	MUST_HAVE(in1->wlen <= NN_MAX_WORD_LEN);
	MUST_HAVE(in2->wlen <= NN_MAX_WORD_LEN);

	len = (in1->wlen >= in2->wlen) ? in1->wlen : in2->wlen;

	for (i = 0; i < NN_MAX_WORD_LEN; i++) {
		word_t local_mask = WORD_MASK_IFNOTZERO((i < len));
		t = (in1->val[i] ^ in2->val[i]) & mask;
		in1->val[i] ^= (t & local_mask);
		in2->val[i] ^= (t & local_mask);
	}

	t = (in1->wlen ^ in2->wlen) & mask;
	in1->wlen ^= (u8)t;
	in2->wlen ^= (u8)t;
}

/*
 * Adjust internal wlen attribute of given nn to new_wlen. If internal wlen
 * attribute value is reduced, words above that limit in A are zeroized.
 * new_wlen must be in [0, NN_MAX_WORD_LEN].
 * The trimming is performed in constant time wrt to the length of the
 * input to avoid leaking it.
 */
void nn_set_wlen(nn_t A, u8 new_wlen)
{
	u8 i;

	nn_check_initialized(A);
	MUST_HAVE(new_wlen <= NN_MAX_WORD_LEN);
	MUST_HAVE(A->wlen <= NN_MAX_WORD_LEN);

        /* Trimming performed in constant time */
        for (i = 0; i < NN_MAX_WORD_LEN; i++) {
                A->val[i] &= WORD_MASK_IFZERO((i >= new_wlen));
        }

	A->wlen = new_wlen;
}

/*
 * Return 1 if given nn is zero. Return 0 otherwise.
 * Done *in constant time*
 */
int nn_iszero(nn_src_t A)
{
	int ret = 0;
	u8 i;

	nn_check_initialized(A);
	MUST_HAVE(A->wlen <= NN_MAX_WORD_LEN);

	for (i = 0; i < NN_MAX_WORD_LEN; i++) {
		int mask = ((i < A->wlen) ? 1 : 0);
		ret |= ((A->val[i] != 0) & mask);
	}

	return !ret;
}

/* 
 * Return 1 if given nn is one. Return 0 otherwise.
 * Done *in constant time*
 */
int nn_isone(nn_src_t A)
{
	int ret;
	u8 i;

	nn_check_initialized(A);
	MUST_HAVE(A->wlen <= NN_MAX_WORD_LEN);

	/* val[0] access is ok no matter wlen value */
	ret = (A->val[0] != 1);	
	for (i = 1; i < NN_MAX_WORD_LEN; i++) {
		int mask = ((i < A->wlen) ? 1 : 0);
		ret |= ((A->val[i] != 0) & mask);
	}

	return !ret;
}

/* Return 1 if given nn is odd, Return 0 otherwise. */
int nn_isodd(nn_src_t A)
{
	nn_check_initialized(A);

	return (A->wlen != 0) && (A->val[0] & 1);
}

/*
 * Compare given nn and word.
 * Done *in constant time*
 * (only depending on the input length, not on its value
 * or on the word value).
 */
int nn_cmp_word(nn_src_t in, word_t w)
{
	u8 i;
	word_t mask;
	int ret = 0;

	nn_check_initialized(in);

	/* No need to read, we can conclude */
	if (in->wlen == 0) {
		ret = -(w != 0);
		return ret;
	}

	/*
	 * Let's loop on all nn above first one to see if one
	 * of those is non-zero.
	 */
	for (i = in->wlen - 1; i > 0; i--) {
		ret |= (in->val[i] != 0);
	}

	/*
	 * Compare first word of nn w/ w if needed. This
	 * is done w/ masking to avoid doing or not doing
	 * it based on 'ret' (i.e. fact that a high word
	 * of nn is not zero).
	 */
	mask = WORD_MASK_IFZERO(ret);
	ret += (int)(((word_t)(in->val[i] > w)) & (mask));
	ret -= (int)(((word_t)(in->val[i] < w)) & (mask));

	return ret;
}

/*
 * Compare given two nn.
 * Done *in constant time*
 * (only depending on the largest length of the inputs,
 * not on their values).
 */
int nn_cmp(nn_src_t A, nn_src_t B)
{
	u8 cmp_len;
	int mask, ret, i;

	nn_check_initialized(A);
	nn_check_initialized(B);

	cmp_len = (A->wlen >= B->wlen) ? A->wlen : B->wlen;

	ret = 0;
	for (i = cmp_len - 1; i >= 0; i--) {	/* ok even if cmp_len is 0 */
		mask = !(ret & 0x1);
		ret += (A->val[i] > B->val[i]) & mask;
		ret -= (A->val[i] < B->val[i]) & mask;
	}

	return ret;
}

/*
 * Copy given nn 'src_nn' into 'dst_nn'.
 * Done *in constant time*.
 * 'dst_nn' must point to a declared nn, but *need not be initialized*;
 * it will be (manually) initialized by the function.
 * 'src_nn' must have been initialized prior to the call.
 */
void nn_copy(nn_t dst_nn, nn_src_t src_nn)
{
	u8 i;

	MUST_HAVE((const void *)dst_nn != NULL);
	nn_check_initialized(src_nn);

	for (i = 0; i < NN_MAX_WORD_LEN; i++) {
		dst_nn->val[i] = src_nn->val[i];
	}

	dst_nn->wlen = src_nn->wlen;
	dst_nn->magic = NN_MAGIC;
}

/*
 * Update wlen value of given nn if a set of words below wlen value
 * are zero.
 * *Not constant time*, this depends on the input value.
 */
void nn_normalize(nn_t in1)
{
	nn_check_initialized(in1);

	while ((in1->wlen > 0) && (in1->val[in1->wlen - 1] == 0)) {
		in1->wlen--;
	}
}

/*
 * Convert given consecutive WORD_BYTES bytes pointed by val from network (big
 * endian) order to host order.
 * 'val' need not point to a word-aligned region.
 */
static word_t ntohw(const u8 *val)
{
	word_t res = 0;
	u8 *res_buf = (u8 *)(&res);
	int i;

	MUST_HAVE(val != NULL);

	if (arch_is_big_endian()) {
		/* copy bytes, one by one to avoid alignement issues */
		for (i = 0; i < WORD_BYTES; i++) {
			res_buf[i] = val[i];
		}
	} else {
		u8 tmp;

		for (i = 0; i < (WORD_BYTES / 2); i++) {
			tmp = val[i];
			res_buf[i] = val[WORD_BYTES - i - 1];
			res_buf[WORD_BYTES - i - 1] = tmp;
		}

		VAR_ZEROIFY(tmp);
	}

	return res;
}

/*
 * Convert given consecutive 'WORD_BYTES' bytes pointed by 'val'
 * from host order to network (big endian) order.
 * 'val' need not point to a word-aligned region.
 */
static inline word_t htonw(const u8 *val)
{
	return ntohw(val);
}

/*
 * 'out_nn' is expected to point to the storage location of a declared nn,
 * which will be initialized by the function (i.e. given nn need not be
 * initialized). The function then import value (expected to be in big
 * endian) from given buffer 'buf' of length 'buflen' into it. To guarantee
 * import will always succeed, the function expects (and enforces) that buflen
 * is less than or equal to NN_MAX_BYTE_LEN.
 */
void nn_init_from_buf(nn_t out_nn, const u8 *buf, u16 buflen)
{
	u8 tmp[NN_MAX_BYTE_LEN];
	u16 wpos;

	MUST_HAVE((out_nn != NULL) && (buf != NULL) &&
		  (buflen <= NN_MAX_BYTE_LEN));

	local_memset(tmp, 0, NN_MAX_BYTE_LEN - buflen);
	local_memcpy(tmp + NN_MAX_BYTE_LEN - buflen, buf, buflen);

	nn_init(out_nn, buflen);

	for (wpos = 0; wpos < NN_MAX_WORD_LEN; wpos++) {
		u16 buf_pos = (NN_MAX_WORD_LEN - wpos - 1) * WORD_BYTES;
		out_nn->val[wpos] = ntohw(tmp + buf_pos);
	}

	local_memset(tmp, 0, NN_MAX_BYTE_LEN);
}

/*
 * Export 'buflen' LSB bytes of given nn as a big endian buffer. If buffer
 * length is larger than effective size of input nn, padding w/ zero is
 * performed. If buffer size is smaller than input nn effective size,
 * MSB bytes are simply lost in exported buffer.
 */
void nn_export_to_buf(u8 *buf, u16 buflen, nn_src_t in_nn)
{
	u8 *src_word_ptr, *dst_word_ptr;
	const u8 wb = WORD_BYTES;
	u16 remain = buflen;
	u8 i;

	MUST_HAVE(buf != NULL);
	nn_check_initialized(in_nn);

	local_memset(buf, 0, buflen);

	/*
	 * We consider each word in input nn one at a time and convert
	 * it to big endian in a temporary word. Based on remaining
	 * length of output buffer, we copy the LSB bytes of temporary
	 * word into it at current position. That way, filling of the
	 * buffer is performed from its end to its beginning, word by
	 * word, except for the last one, which may be shorten if
	 * given buffer length is not a multiple of word length.
	 */
	for (i = 0; remain && (i < in_nn->wlen); i++) {
		word_t val = htonw((const u8 *)&in_nn->val[i]);
		u32 copylen = (remain > wb) ? wb : remain;

		dst_word_ptr = buf + buflen - (i * wb) - copylen;
		src_word_ptr = (u8 *)(&val) + wb - copylen;

		local_memcpy(dst_word_ptr, src_word_ptr, copylen);
		src_word_ptr = NULL;

		remain -= copylen;
	}
}
