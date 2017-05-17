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
#include "print_curves.h"

/*
 * Locally convert given projective point to affine representation and
 * print x and y coordinates.
 */
void ec_point_print(const char *msg, prj_pt_src_t prj_pt)
{
	aff_pt y_aff;

	prj_pt_to_aff(&y_aff, prj_pt);
	ext_printf("%s", msg);
	nn_print("x", &(y_aff.x.fp_val));
	ext_printf("%s", msg);
	nn_print("y", &(y_aff.y.fp_val));
}
