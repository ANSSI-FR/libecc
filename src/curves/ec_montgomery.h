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
#ifndef __EC_MONTGOMERY_H__
#define __EC_MONTGOMERY_H__

#include "../nn/nn.h"
#include "../fp/fp.h"
#include "../fp/fp_add.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_mul_redc1.h"

typedef struct {
	fp A;
	fp B;
	nn order;
	word_t magic;
} ec_montgomery_crv;

typedef ec_montgomery_crv *ec_montgomery_crv_t;
typedef const ec_montgomery_crv *ec_montgomery_crv_src_t;

int ec_montgomery_crv_is_initialized(ec_montgomery_crv_src_t crv);
void ec_montgomery_crv_check_initialized(ec_montgomery_crv_src_t crv);
void ec_montgomery_crv_init(ec_montgomery_crv_t crv, fp_src_t a, fp_src_t b, nn_src_t order);
void ec_montgomery_crv_uninit(ec_montgomery_crv_t crv);

#endif /* __EC_MONTGOMERY_H__ */
