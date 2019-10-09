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
#include "ec_shortw.h"

#define EC_SHORTW_CRV_MAGIC ((word_t)(0x9c7c46a1a04c6720ULL))

/*
 * Check pointed short Weierstrass curve structure as already been
 * initialized.
 */
void ec_shortw_crv_check_initialized(ec_shortw_crv_src_t crv)
{
	MUST_HAVE((crv != NULL) && (crv->magic == EC_SHORTW_CRV_MAGIC));
}

/*
 * Initialize pointed short Weierstrass curve structure using given a and b
 * Fp elements representing curve equation (y^2 = x^3 + ax + b) parameters.
 */
void ec_shortw_crv_init(ec_shortw_crv_t crv, fp_src_t a, fp_src_t b)
{
	fp_check_initialized(a);
	fp_check_initialized(b);
	MUST_HAVE(a->ctx == b->ctx);

	fp_init(&(crv->a), a->ctx);
	fp_init(&(crv->b), b->ctx);
	fp_init(&(crv->a_monty), a->ctx);

	fp_copy(&(crv->a), a);
	fp_copy(&(crv->b), b);
	fp_redcify(&(crv->a_monty), a);

#ifndef NO_USE_COMPLETE_FORMULAS
	fp_init(&(crv->b3), b->ctx);
	fp_init(&(crv->b_monty), b->ctx);
	fp_init(&(crv->b3_monty), b->ctx);

	fp_add(&(crv->b3), b, b);
	fp_add(&(crv->b3), &(crv->b3), b);
	fp_redcify(&(crv->b_monty), b);
	fp_redcify(&(crv->b3_monty), &(crv->b3));
#endif

	crv->magic = EC_SHORTW_CRV_MAGIC;
}
