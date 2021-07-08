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
#ifndef __FP_SQRT_H__
#define __FP_SQRT_H__
#include "fp.h"
#include "fp_add.h"
#include "fp_mul.h"
#include "fp_pow.h"

int fp_sqrt(fp_t sqrt1, fp_t sqrt2, fp_src_t n);

#endif /* __FP_SQRT_H__ */
