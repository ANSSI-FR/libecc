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
#include "fp_add.h"
#include "../nn/nn_add.h"

/* Compute out = in1 + in2 mod p */
void fp_add(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp_check_initialized(out);
	fp_check_initialized(in1);
	fp_check_initialized(in2);
	MUST_HAVE((&(in1->ctx->p)) == (&(in2->ctx->p)));
	MUST_HAVE((&(in1->ctx->p)) == (&(out->ctx->p)));
	SHOULD_HAVE(nn_cmp(&in1->fp_val, &(in1->ctx->p)) < 0);
	SHOULD_HAVE(nn_cmp(&in2->fp_val, &(in2->ctx->p)) < 0);
	nn_mod_add(&(out->fp_val), &(in1->fp_val),
		   &(in2->fp_val), &(in1->ctx->p));
}

/* Compute out = in + 1 mod p */
void fp_inc(fp_t out, fp_src_t in)
{
	fp_check_initialized(in);
	fp_check_initialized(out);
	MUST_HAVE((&(in->ctx->p)) == (&(out->ctx->p)));
	SHOULD_HAVE(nn_cmp(&in->fp_val, &(in->ctx->p)) < 0);
	nn_mod_inc(&(out->fp_val), &(in->fp_val), &(in->ctx->p));
}

/* Compute out = in1 - in2 mod p */
void fp_sub(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp_check_initialized(out);
	fp_check_initialized(in1);
	fp_check_initialized(in2);
	MUST_HAVE((&(in1->ctx->p)) == (&(in2->ctx->p)));
	MUST_HAVE((&(in1->ctx->p)) == (&(out->ctx->p)));
	SHOULD_HAVE(nn_cmp(&in1->fp_val, &(in1->ctx->p)) < 0);
	SHOULD_HAVE(nn_cmp(&in2->fp_val, &(in2->ctx->p)) < 0);
	nn_mod_sub(&(out->fp_val), &(in1->fp_val),
		   &(in2->fp_val), &(in1->ctx->p));
}

/* Compute out = in - 1 mod p */
void fp_dec(fp_t out, fp_src_t in)
{
	fp_check_initialized(out);
	fp_check_initialized(in);
	MUST_HAVE((&(in->ctx->p)) == (&(out->ctx->p)));
	SHOULD_HAVE(nn_cmp(&in->fp_val, &(in->ctx->p)) < 0);
	nn_mod_dec(&(out->fp_val), &(in->fp_val), &(in->ctx->p));
}

/* Compute out = -in mod p = (p - in) mod p */
void fp_neg(fp_t out, fp_src_t in)
{
	fp_check_initialized(in);
	fp_check_initialized(out);
	MUST_HAVE((&(in->ctx->p)) == (&(out->ctx->p)));
	SHOULD_HAVE(nn_cmp(&in->fp_val, &(in->ctx->p)) < 0);
	nn_sub(&(out->fp_val), &(in->ctx->p), &(in->fp_val));
}
