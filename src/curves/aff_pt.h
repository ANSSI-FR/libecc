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
#ifndef __AFF_PT_H__
#define __AFF_PT_H__

#include "../fp/fp.h"
#include "ec_shortw.h"

typedef struct {
	fp x;
	fp y;
	ec_shortw_crv_src_t crv;
	word_t magic;
} aff_pt;

typedef aff_pt *aff_pt_t;
typedef const aff_pt_t aff_pt_src_t;

void aff_pt_check_initialized(aff_pt_src_t in);
int aff_pt_is_initialized(aff_pt_src_t in);
void aff_pt_init(aff_pt_t in, ec_shortw_crv_src_t curve);
void aff_pt_init_from_coords(aff_pt_t in,
			     ec_shortw_crv_src_t curve,
			     fp_src_t xcoord, fp_src_t ycoord);
void aff_pt_uninit(aff_pt_t in);
int is_on_curve(fp_src_t x, fp_src_t y, ec_shortw_crv_src_t curve);
void ec_shortw_aff_copy(aff_pt_t out, aff_pt_src_t in);
int ec_shortw_aff_cmp(aff_pt_src_t in1, aff_pt_src_t in2);
int ec_shortw_aff_eq_or_opp(aff_pt_src_t in1, aff_pt_src_t in2);

#endif /* __EC_SHORTW_AFF_PT_H__ */
