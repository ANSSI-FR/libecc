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
#ifndef __LOGICAL_H__
#define __LOGICAL_H__
#include "nn.h"

int nn_rshift_fixedlen(nn_t out, nn_src_t in, bitcnt_t cnt);
int nn_rshift(nn_t out, nn_src_t in, bitcnt_t cnt);
int nn_lshift_fixedlen(nn_t out, nn_src_t in, bitcnt_t cnt);
int nn_lshift(nn_t out, nn_src_t in, bitcnt_t cnt);
int nn_rrot(nn_t out, nn_src_t in, bitcnt_t cnt, bitcnt_t bitlen);
int nn_lrot(nn_t out, nn_src_t in, bitcnt_t cnt, bitcnt_t bitlen);
int nn_xor(nn_t B, nn_src_t C, nn_src_t A);
int nn_or(nn_t B, nn_src_t C, nn_src_t A);
int nn_and(nn_t B, nn_src_t C, nn_src_t A);
int nn_not(nn_t B, nn_src_t A);
int nn_clz(nn_src_t A, bitcnt_t *lz);
int nn_bitlen(nn_src_t A, bitcnt_t *blen);
int nn_getbit(nn_src_t in, bitcnt_t bit, u8 *bitval);

#endif /* __LOGICAL_H__ */
