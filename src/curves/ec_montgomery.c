/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "ec_montgomery.h"

#define EC_MONTGOMERY_CRV_MAGIC ((word_t)(0x83734673a0443720ULL))

/*
 * Check pointed Montgomery curve structure has already been
 * initialized.
 */
int ec_montgomery_crv_is_initialized(ec_montgomery_crv_src_t crv)
{
	return !!((crv != NULL) && (crv->magic == EC_MONTGOMERY_CRV_MAGIC));
}

void ec_montgomery_crv_check_initialized(ec_montgomery_crv_src_t crv)
{
	MUST_HAVE((crv != NULL) && (crv->magic == EC_MONTGOMERY_CRV_MAGIC));
}

/*
 * Initialize pointed Montgomery curve structure using given A and B
 * Fp elements representing curve equation (B v^2 = u^3 + A u^2 + u) parameters.
 */
void ec_montgomery_crv_init(ec_montgomery_crv_t crv, fp_src_t A, fp_src_t B, nn_src_t order)
{
        fp tmp;

	MUST_HAVE(crv != NULL);

	fp_check_initialized(A);
	fp_check_initialized(B);
	MUST_HAVE(A->ctx == B->ctx);

	fp_init(&tmp, A->ctx);
	/* A and B elements of Fp, A unequal to (+/-)2 and B non zero */
	fp_set_word_value(&tmp, 2);
	fp_add(&tmp, A, &tmp);
	MUST_HAVE(!fp_iszero(&tmp));
	/**/
	fp_set_word_value(&tmp, 2);
	fp_sub(&tmp, A, &tmp);
	MUST_HAVE(!fp_iszero(&tmp));
	/**/
	MUST_HAVE(!fp_iszero(B));

	nn_check_initialized(order);

	fp_init(&(crv->A), A->ctx);
	fp_init(&(crv->B), B->ctx);

	fp_copy(&(crv->A), A);
	fp_copy(&(crv->B), B);

	nn_copy(&(crv->order), order);

	crv->magic = EC_MONTGOMERY_CRV_MAGIC;

	fp_uninit(&tmp);
}

/* Uninitialize curve */
void ec_montgomery_crv_uninit(ec_montgomery_crv_t crv)
{
        ec_montgomery_crv_check_initialized(crv);

        crv->magic = WORD(0);
}
