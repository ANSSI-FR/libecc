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
#ifndef __FP_MUL_H__
#define __FP_MUL_H__
#include "fp.h"

void fp_mul(fp_t out, fp_src_t in1, fp_src_t in2);
void fp_sqr(fp_t out, fp_src_t in);
void fp_inv(fp_t out, fp_src_t in);
void fp_div(fp_t out, fp_src_t num, fp_src_t den);

#endif /* __FP_MUL_H__ */
