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
#include "print_fp.h"

/* Print the context of a prime field Fp */
void fp_ctx_print(const char *msg, fp_ctx_src_t ctx)
{
	fp_ctx_check_initialized(ctx);

	ext_printf("%s:\n", msg);
	nn_print("\t fp_ctx->p", &(ctx->p));
	ext_printf("\t fp_ctx->mpinv 0x%016lx\n",
		   (long unsigned int)ctx->mpinv);
	nn_print("\t fp_ctx->r", &(ctx->r));
	nn_print("\t fp_ctx->r_square", &(ctx->r_square));
}

/* Print the value of an Fp element */
void fp_print(const char *msg, fp_src_t a)
{
	fp_check_initialized(a);

	nn_print(msg, &(a->fp_val));
}

/* Print the value and Fp context of an Fp element */
void fp_print_all(const char *msg, fp_src_t a)
{
	fp_check_initialized(a);

	ext_printf("%s:\n", msg);
	nn_print("\t fp_val", &(a->fp_val));
	fp_ctx_print("", a->ctx);
}
