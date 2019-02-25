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
#ifndef __PRJ_PT_MONTY_H__
#define __PRJ_PT_MONTY_H__

#include "prj_pt.h"

void prj_pt_add_monty(prj_pt_t sum, prj_pt_src_t in1, prj_pt_src_t in2);

void prj_pt_dbl_monty(prj_pt_t dbl, prj_pt_src_t in);

void prj_pt_mul_ltr_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in);

void prj_pt_mul_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in);

int prj_pt_mul_monty_blind(prj_pt_t out, nn_src_t m, prj_pt_src_t in, nn_t b, nn_src_t q);

#endif /* __PRJ_PT_MONTY_H__ */
