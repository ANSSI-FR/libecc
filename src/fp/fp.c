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
#include "fp.h"
#include "fp_add.h"
#include "../nn/nn_add.h"
#include "../nn/nn_logical.h"
#include "../nn/nn_mul_redc1.h"

#define FP_CTX_MAGIC ((word_t)(0x114366fc34955125ULL))

/*
 * Verify given Fp context has been correctly initialized, by checking
 * given pointer is valid and structure magic has expected value.
 */
void fp_ctx_check_initialized(fp_ctx_src_t ctx)
{
	MUST_HAVE((ctx != NULL) && (ctx->magic == FP_CTX_MAGIC));
}

/*
 * Verify given Fp context has been correctly initialized, by checking
 * given pointer is valid and structure magic has expected value.
 * Returns 0 or 1.
 */
int fp_ctx_is_initialized(fp_ctx_src_t ctx)
{
	return !!((ctx != NULL) && (ctx->magic == FP_CTX_MAGIC));
}

/*
 * Initialize pointed Fp context structure from given parameters:
 *  - p: pointer to the prime defining Fp
 *  - p_bitlen: the bit length of p
 *  - r, r_square, mpinv: pointers to the Montgomery parameters r,
 *    (2^|p|) mod p), r^2 mod p and -p^-1 mod B (where B is the
 *    size in bits of words, as defined for the project, 16, 32
 *    or 64).
 *  - p_shift, p_normalized and p_reciprocal are precomputed
 *    division parameters (see ec_params_external.h for details).
 */
void fp_ctx_init(fp_ctx_t ctx, nn_src_t p, bitcnt_t p_bitlen,
		 nn_src_t r, nn_src_t r_square,
		 word_t mpinv,
		 bitcnt_t p_shift, nn_src_t p_normalized, word_t p_reciprocal)
{
	nn_check_initialized(p);
	nn_check_initialized(r);
	nn_check_initialized(r_square);
	nn_check_initialized(p_normalized);

	MUST_HAVE(ctx != NULL);
	nn_copy(&(ctx->p), p);
	ctx->p_bitlen = p_bitlen;
	nn_copy(&(ctx->r), r);
	nn_copy(&(ctx->r_square), r_square);
	ctx->mpinv = mpinv;
	ctx->p_shift = p_shift;
	nn_copy(&(ctx->p_normalized), p_normalized);
	ctx->p_reciprocal = p_reciprocal;
	ctx->magic = FP_CTX_MAGIC;
}

/*
 * Initialize pointed Fp context structure only from the prime p.
 * The Montgomery related parameters are dynamically computed
 * using our redc1 helpers from the NN layer.
 */
void fp_ctx_init_from_p(fp_ctx_t ctx, nn_src_t p_in)
{
	nn p, r, r_square, p_normalized;
	word_t mpinv, p_shift, p_reciprocal;
	bitcnt_t p_bitlen;

	nn_check_initialized(p_in);
	MUST_HAVE(ctx != NULL);

	nn_init(&p, 0);
	nn_copy(&p, p_in);

	nn_init(&r, 0);
	nn_init(&r_square, 0);
	nn_init(&p_normalized, 0);

	/*
	 * In order for our reciprocal division routines to work, it is
	 * expected that the bit length (including leading zeroes) of
	 * input prime p is >= 2 * wlen where wlen is the number of bits
	 * of a word size. Thus, in order
	 */
	if (p.wlen < 2) {
		nn_set_wlen(&p, 2);
	}

	mpinv = nn_compute_redc1_coefs(&r, &r_square, &p);
	nn_compute_div_coefs(&p_normalized, &p_shift, &p_reciprocal, &p);

	p_bitlen = nn_bitlen(p_in);
	fp_ctx_init(ctx, &p, p_bitlen, &r, &r_square,
		    mpinv, (bitcnt_t)p_shift, &p_normalized, p_reciprocal);

	nn_uninit(&p);
	nn_uninit(&r);
	nn_uninit(&r_square);
	nn_uninit(&p_normalized);
}

#define FP_MAGIC ((word_t)(0x14e96c8ab28221efULL))

/*
 * Verify given Fp element has been correctly intialized, by checking
 * given pointer is valid and structure magic has expected value.
 */
void fp_check_initialized(fp_src_t in)
{
	MUST_HAVE((in != NULL) && (in->magic == FP_MAGIC)
		  && (in->ctx != NULL));
}

/*
 * Verify given Fp element has been correctly intialized, by checking
 * given pointer is valid and structure magic has expected value.
 * Return 0 or 1.
 */
int fp_is_initialized(fp_src_t in)
{
	return !!((in != NULL) && (in->magic == FP_MAGIC) &&
		   (in->ctx != NULL));
}

/*
 * Initialilize pointed Fp element structure with given Fp context. Initial
 * value of Fp element is set to 0.
 */
void fp_init(fp_t in, fp_ctx_src_t fpctx)
{
	fp_ctx_check_initialized(fpctx);
	nn_init(&in->fp_val, fpctx->p.wlen * WORD_BYTES);
	in->ctx = fpctx;
	in->magic = FP_MAGIC;
}

/*
 * Same as above but providing the element an initial value given by 'buf'
 * content (in big endian order) of size 'buflen'. Content of 'buf' must
 * be less than p.
 */
void fp_init_from_buf(fp_t in, fp_ctx_src_t fpctx, const u8 *buf, u16 buflen)
{
	fp_ctx_check_initialized(fpctx);
	fp_init(in, fpctx);
	fp_import_from_buf(in, buf, buflen);
}

/*
 * Uninitialize pointed Fp element to prevent further use (magic field
 * in the structure is zeroized) and zeroize associated storage space.
 * Note that the Fp context pointed to by Fp element (passed during
 * init) is left untouched.
 */
void fp_uninit(fp_t in)
{
	fp_check_initialized(in);
	nn_uninit(&in->fp_val);
	in->ctx = NULL;
	in->magic = WORD(0);
}

/*
 * Set value of given Fp element to that of given nn. The value of
 * given nn must be less than that of p, i.e. no reduction modulo
 * p is performed by the function.
 */
void fp_set_nn(fp_t out, nn_src_t in)
{
	nn_check_initialized(in);

	nn_copy(&(out->fp_val), in);

	MUST_HAVE(nn_cmp(&(out->fp_val), &(out->ctx->p)) < 0);

	/* Set the wlen to the length of p */
	nn_set_wlen(&(out->fp_val), out->ctx->p.wlen);
}

/* Set 'out' to the element 0 of Fp (neutral element for addition) */
void fp_zero(fp_t out)
{
	fp_check_initialized(out);

	nn_set_word_value(&(out->fp_val), 0);
	/* Set the wlen to the length of p */
	nn_set_wlen(&(out->fp_val), out->ctx->p.wlen);
}

/* Set out to the element 1 of Fp (neutral element for multiplication) */
void fp_one(fp_t out)
{
	fp_check_initialized(out);

	nn_set_word_value(&(out->fp_val), 1);
	/* Set the wlen to the length of p */
	nn_set_wlen(&(out->fp_val), out->ctx->p.wlen);
}

/*
 * Compare given Fp elements. The function returns -1 if the value of in1 is
 * less than that of in2, 0 if they are equal and 1 if the value of in2 is
 * more than that of in1. Obviously, both parameters must be initialized and
 * belong to the same field (i.e. must have been initialized from the same
 * context).
 */
int fp_cmp(fp_src_t in1, fp_src_t in2)
{
	fp_check_initialized(in1);
	fp_check_initialized(in2);

	MUST_HAVE(in1->ctx == in2->ctx);

	return nn_cmp(&(in1->fp_val), &(in2->fp_val));
}

/* Check if given Fp element has value 0 */
int fp_iszero(fp_src_t in)
{
	fp_check_initialized(in);

	return nn_iszero(&(in->fp_val));
}

/*
 * Copy value of pointed Fp element (in) into pointed Fp element (out). Both Fp
 * elements must have been initialized w/ the same context (i.e. belong to the
 * field) prior to the call.
 */
void fp_copy(fp_t out, fp_src_t in)
{
	fp_check_initialized(in);
	fp_check_initialized(out);

	MUST_HAVE(out->ctx == in->ctx);

	nn_copy(&(out->fp_val), &(in->fp_val));
}

/*
 * Given a table 'tab' pointing to a set of 'tabsize' Fp elements, the
 * function copies the value of element at position idx (idx < tabsize)
 * in 'out' parameters. Masking is used to avoid leaking which element
 * was copied.
 *
 * Note that the main copying loop is done on the |p| bits for all
 * Fp elements and not based on the specific effective size of each
 * Fp elements in 'tab'
 */
void fp_tabselect(fp_t out, u8 idx, fp_src_t *tab, u8 tabsize)
{
	u8 i, k, p_wlen;
	word_t mask;
	nn_src_t p;

	/* Basic sanity checks */
	MUST_HAVE((((void *)(tab)) != NULL) && (idx < tabsize));
	fp_check_initialized(out);

	/* Make things more readable */
	p = &(out->ctx->p);
	MUST_HAVE(p != NULL);
	p_wlen = p->wlen;

	/* Zeroize out and enforce its size. */
	nn_zero(&(out->fp_val));
	out->fp_val.wlen = p_wlen;

	for (k = 0; k < tabsize; k++) {
		/* Check current element is initialized and from Fp */
		fp_check_initialized(tab[k]);
		MUST_HAVE((&(tab[k]->ctx->p)) == p);

		mask = WORD_MASK_IFNOTZERO(idx == k);

		for (i = 0; i < p_wlen; i++) {
			out->fp_val.val[i] |= (tab[k]->fp_val.val[i] & mask);
		}
	}
}

/*
 * Return 1 if in1 and in2 parameters are equal or opposite (in Fp).
 * Return 0 otherwise.
 */
int fp_eq_or_opp(fp_src_t in1, fp_src_t in2)
{
	int ret;
	fp opp;

	fp_check_initialized(in1);
	fp_check_initialized(in2);
	MUST_HAVE(in1->ctx == in2->ctx);

	fp_init(&opp, in1->ctx);

	fp_neg(&opp, in2);
	ret = (nn_cmp(&(in1->fp_val), &(in2->fp_val)) == 0);
	ret |= (nn_cmp(&(in1->fp_val), &(opp.fp_val)) == 0);

	fp_uninit(&opp);

	return ret;
}

/*
 * Import given buffer of length buflen as a value for out_fp. Buffer is
 * expected to be in big endian format. out_fp is expected to be already
 * initialized w/ a proper Fp context, providing a value for p. The value
 * in buf is also expected to be less than the one of p.
 */
void fp_import_from_buf(fp_t out_fp, const u8 *buf, u16 buflen)
{
	fp_check_initialized(out_fp);

	nn_init_from_buf(&(out_fp->fp_val), buf, buflen);

	MUST_HAVE(nn_cmp(&(out_fp->fp_val), &(out_fp->ctx->p)) < 0);
}

/*
 * Export an element from Fp to a buffer using the underlying
 * NN export primitive.
 */
void fp_export_to_buf(u8 *buf, u16 buflen, fp_src_t in_fp)
{
	nn_export_to_buf(buf, buflen, &(in_fp->fp_val));
}
