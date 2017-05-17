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
#include "fp_mul.h"
#include "fp_mul_redc1.h"
#include "fp_montgomery.h"

void fp_add_monty(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp_add(out, in1, in2);
}

void fp_sub_monty(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp_sub(out, in1, in2);
}

void fp_mul_monty(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp_mul_redc1(out, in1, in2);
}

void fp_sqr_monty(fp_t out, fp_src_t in)
{
	fp_sqr_redc1(out, in);
}

void fp_div_monty(fp_t out, fp_src_t in1, fp_src_t in2)
{
	fp tmp;

	fp_check_initialized(in1);
	fp_check_initialized(in2);
	fp_check_initialized(out);

	fp_init(&tmp, out->ctx);

	MUST_HAVE(out->ctx == in1->ctx);
	MUST_HAVE(out->ctx == in2->ctx);
	MUST_HAVE(!fp_iszero(in2));

	fp_div(&tmp, in1, in2);
	fp_redcify(out, &tmp);

	fp_uninit(&tmp);
}
