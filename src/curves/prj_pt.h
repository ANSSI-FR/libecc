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
#ifndef __PRJ_PT_H__
#define __PRJ_PT_H__

#include "../nn/nn_mul.h"
#include "../fp/fp.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_mul_redc1.h"
#include "ec_shortw.h"
#include "aff_pt.h"

typedef struct {
	fp X;
	fp Y;
	fp Z;
	ec_shortw_crv_src_t crv;
	word_t magic;
} prj_pt;

typedef prj_pt *prj_pt_t;
typedef const prj_pt *prj_pt_src_t;

void prj_pt_check_initialized(prj_pt_src_t in);

int prj_pt_is_initialized(prj_pt_src_t in);

void prj_pt_init(prj_pt_t in, ec_shortw_crv_src_t curve);

void prj_pt_init_from_coords(prj_pt_t in,
			     ec_shortw_crv_src_t curve,
			     fp_src_t xcoord,
			     fp_src_t ycoord, fp_src_t zcoord);

void prj_pt_uninit(prj_pt_t in);

void prj_pt_zero(prj_pt_t out);

int prj_pt_iszero(prj_pt_src_t in);

int prj_pt_is_on_curve(prj_pt_src_t in);

void prj_pt_copy(prj_pt_t out, prj_pt_src_t in);

void prj_pt_to_aff(aff_pt_t out, prj_pt_src_t in);

void ec_shortw_aff_to_prj(prj_pt_t out, aff_pt_src_t in);

int prj_pt_cmp(prj_pt_src_t in1, prj_pt_src_t in2);

int prj_pt_eq_or_opp(prj_pt_src_t in1, prj_pt_src_t in2);

int prj_pt_import_from_buf(prj_pt_t pt,
			   const u8 *pt_buf,
			   u16 pt_buf_len, ec_shortw_crv_src_t crv);

int prj_pt_export_to_buf(prj_pt_src_t pt, u8 *pt_buf, u32 pt_buf_len);

void prj_pt_add(prj_pt_t sum, prj_pt_src_t in1, prj_pt_src_t in2);

void prj_pt_dbl(prj_pt_t dbl, prj_pt_src_t in);

void prj_pt_mul(prj_pt_t out, nn_src_t m, prj_pt_src_t in);

int prj_pt_mul_blind(prj_pt_t out, nn_src_t m, prj_pt_src_t in, nn_t b, nn_src_t q);

#endif /* __PRJ_PT_H__ */
