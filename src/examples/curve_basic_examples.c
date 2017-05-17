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
#include "libec.h"
/* We include the printf external dependency for printf output */
#include "print.h"
/* We include the time external dependency for performance measurement */
#include "time.h"

/* Declare our Tonelli-Shanks algorithm to find square roots
 * in Fp, implemented in another module.
 */
int fp_square_root(fp_t sqrt1, fp_t sqrt2, fp_src_t n);

/* The followin function picks a random Fp element x, where Fp is the
 * curve underlying prime field, and computes y in Fp such that:
 *   y^2 = x^3 + ax + b, where a and b are the input elliptic
 * curve parameters.
 *
 * This means that (x, y) are the affine coordinates of a "random"
 * point on our curve. The function then outputs the projective
 * coordinates of (x, y), i.e. the triplet (x, y, 1).
 * PS: all our operations on points are done with projective coordinates.
 *
 * Computing y means computing a quadratic residue in Fp, for which we
 * use the Tonelli-Shanks algorithm implemented in the Fp source example
 * (fp_square_residue.c).
 */
void get_random_point_on_curve(ec_params *curve_params, prj_pt *out_point);
void get_random_point_on_curve(ec_params *curve_params, prj_pt *out_point)
{
	nn nn_tmp;
	/* Inside our internal representation, curve_params->ec_curve
	 * contains the curve coefficients a and b.
	 * curve_params->ec_fp is the Fp context of the curve.
	 */
	fp x, y, fp_tmp1, fp_tmp2;
	fp_ctx_src_t ctx;
	/* Initialize our x value with the curve Fp context */
	ctx = &(curve_params->ec_fp);
	fp_init(&x, ctx);
	fp_init(&y, ctx);
	fp_init(&fp_tmp1, ctx);
	fp_init(&fp_tmp2, ctx);

	nn_init(&nn_tmp, 0);
	nn_set_word_value(&nn_tmp, WORD(3));
	while (1) {
		/* Get a random Fp */
		fp_get_random(&x, ctx);
		fp_copy(&fp_tmp1, &x);
		fp_copy(&fp_tmp2, &x);
		/* Compute x^3 + ax + b */
		fp_pow(&fp_tmp1, &fp_tmp1, &nn_tmp);
		fp_mul(&fp_tmp2, &fp_tmp2, &(curve_params->ec_curve.a));
		fp_add(&fp_tmp1, &fp_tmp1, &fp_tmp2);
		fp_add(&fp_tmp1, &fp_tmp1, &(curve_params->ec_curve.b));
		/*
		 * Get any of the two square roots, corresponding to (x, y)
		 * and (x, -y) both on the curve. If no square root exist,
		 * go to next random Fp.
		 */
		if (fp_square_root(&y, &fp_tmp2, &fp_tmp1) == 0) {
			/* Check that we indeed satisfy the curve equation */
			if (!is_on_curve(&x, &y, &(curve_params->ec_curve))) {
				/* This should not happen ... */
				ext_printf("Error: Tonelli-Shanks found a bad "
					   "solution to curve equation ...\n");
				continue;
			}
			break;
		}
	}
	/* Now initialize our point with the coordinates (x, y, 1) */
	fp_one(&fp_tmp1);
	prj_pt_init_from_coords(out_point, &(curve_params->ec_curve), &x, &y,
				&fp_tmp1);

	fp_uninit(&x);
	fp_uninit(&y);
	fp_uninit(&fp_tmp1);
	fp_uninit(&fp_tmp2);
	nn_uninit(&nn_tmp);
}

#define PERF_SCALAR_MUL 40
int check_curve(const u8 *curve_name);
int check_curve(const u8 *curve_name)
{
	unsigned int i;
	u64 t1, t2;
	int ret = 0;

	nn nn_k;
	/* libecc internal structure holding the curve parameters */
	ec_params curve_params;
	/* libecc internal structure holding projective points on curves */
	prj_pt A, B, C, D;
	prj_pt TMP;
	aff_pt T;

	/* Importing a specific curve parameters from the constant static
	 * buffers describing it:
	 * It is possible to import a curves parameters by its name.
	 */
	const ec_str_params *the_curve_const_parameters =
		ec_get_curve_params_by_name(curve_name,
					    (u8)local_strnlen((const char *)
							      curve_name,
							      MAX_CURVE_NAME_LEN)
					    + 1);
	/* Get out if getting the parameters went wrong */
	if (the_curve_const_parameters == NULL) {
		ext_printf("Error: error when importing curve %s "
			   "parameters ...\n", curve_name);
		ret = -1;
		goto out;
	}
	/* Now map the curve parameters to our libecc internal representation */
	import_params(&curve_params, the_curve_const_parameters);
	/* Get two random points on the curve */
	get_random_point_on_curve(&curve_params, &A);
	get_random_point_on_curve(&curve_params, &B);

	/*
	 * Let's add the two points with our Montgomery and non Montgomery
	 * (regular) variants to check that both results represent the same
	 * point.
	 * C = A + B with regular point addition
	 * D = A + B with Montgomery point addition
	 */
	prj_pt_add(&C, &A, &B);
	prj_pt_add_monty(&D, &A, &B);
	if (prj_pt_cmp(&C, &D) != 0) {
		ext_printf("Error: A+B differs with Montgomery and "
			   "non Montgomery add methods ...\n");
		ret = -1;
		goto out;
	}
	/*
	 * Check that the resulting additive point C = A+B is indeed on the
	 * curve. In order to check this, we have to go back to affine
	 * representation
	 */
	prj_pt_to_aff(&T, &C);
	if (!is_on_curve(&(T.x), &(T.y), &(curve_params.ec_curve))) {
		ext_printf("Error: C = A+B is not on the %s curve!\n",
			   curve_params.curve_name);
		ret = -1;
		goto out;
	}
	/* Same check with doubling
	 * C = 2A = A+A with regular point doubling
	 * D = 2A = A+A  with Montgomery point doubling
	 */
	prj_pt_dbl(&C, &A);
	prj_pt_dbl_monty(&D, &A);
	if (prj_pt_cmp(&C, &D) != 0) {
		ext_printf("Error: 2A differs with Montgomery and "
			   "non Montgomery add methods ...\n");
		ret = -1;
		goto out;
	}
	/* Check that the resulting point C = 2A is indeed on the curve.
	 * In order to check this, we have to go back to affine representation
	 *
	 */
	prj_pt_to_aff(&T, &C);
	if (!is_on_curve(&(T.x), &(T.y), &(curve_params.ec_curve))) {
		ext_printf("Error: C = A+B is not on the %s curve!\n",
			   curve_params.curve_name);
		ret = -1;
		goto out;
	}
	/*
	 * If the cofactor of the curve is 1, this means that the order of the
	 * generator is the cardinal of the curve (and hence the order of the
	 * curve points group). This means that for any point P on the curve,
	 * we should have qP = 0 (the inifinity point, i.e. the zero neutral
	 * element of the curve additive group). We test both Montgomery and
	 * non Montgomery methods to check this on our point A, B, C = A + B
	 * and D = 2A.
	 */
	prj_pt_add_monty(&C, &A, &B);
	prj_pt_dbl_monty(&D, &A);
	if (nn_isone(&(curve_params.ec_gen_cofactor))) {
		prj_pt_mul(&TMP, &(curve_params.ec_gen_order), &A);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qA is not 0! (regular mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul_monty(&TMP, &(curve_params.ec_gen_order), &A);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qA is not 0! (Montgomery mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul(&TMP, &(curve_params.ec_gen_order), &B);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qB is not 0! (regular mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul_monty(&TMP, &(curve_params.ec_gen_order), &B);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qB is not 0! (Montgomery mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul(&TMP, &(curve_params.ec_gen_order), &C);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qC is not 0! (regular mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul_monty(&TMP, &(curve_params.ec_gen_order), &C);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qC is not 0! (Montgomery mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul(&TMP, &(curve_params.ec_gen_order), &D);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qD is not 0! (regular mul)\n");
			ret = -1;
			goto out;
		}
		prj_pt_mul_monty(&TMP, &(curve_params.ec_gen_order), &D);
		if (!prj_pt_iszero(&TMP)) {
			ext_printf("Error: qD is not 0! (Montgomery mul)\n");
			ret = -1;
			goto out;
		}
	}
	/* Now let's show that even though they give the same results, our
	 * Montgomery variant for point addition and doubling are faster!
	 * We compute kA many times to have a decent performance measurement,
	 * where k is chose random at each iteration. We also check that kA
	 * is indeed on the curve.
	 */
	nn_init(&nn_k, 0);
	if (get_ms_time(&t1)) {
		ext_printf("Error: cannot get time with get_ms_time\n");
		ret = -1;
		goto out;
	}
	for (i = 0; i < PERF_SCALAR_MUL; i++) {
		/* k = random mod (q) */
		nn_get_random_mod(&nn_k, &(curve_params.ec_gen_order));
		/* Compute kA with regular add/double formulas */
		prj_pt_mul(&TMP, &nn_k, &A);
		prj_pt_to_aff(&T, &TMP);
		if (!is_on_curve(&(T.x), &(T.y), &(curve_params.ec_curve))) {
			ext_printf("Error: kA is not on the %s curve!\n",
				   curve_params.curve_name);
			nn_print("k=", &nn_k);
			ret = -1;
			goto out;
		}
	}
	if (get_ms_time(&t2)) {
		ext_printf("Error: cannot get time with get_ms_time\n");
		ret = -1;
		goto out;
	}
	ext_printf("  [*] Regular EC scalar multiplication took %f seconds "
		   "on average\n",
		   (double)(t2 - t1) / (double)(PERF_SCALAR_MUL * 1000ULL));
	if (get_ms_time(&t1)) {
		ext_printf("Error: cannot get time with get_ms_time\n");
		ret = -1;
		goto out;
	}
	for (i = 0; i < PERF_SCALAR_MUL; i++) {
		/* k = random mod (q) */
		nn_get_random_mod(&nn_k, &(curve_params.ec_gen_order));
		/* Compute kA with Montgomery add/double formulas */
		prj_pt_mul_monty(&TMP, &nn_k, &A);
		prj_pt_to_aff(&T, &TMP);
		if (!is_on_curve(&(T.x), &(T.y), &(curve_params.ec_curve))) {
			ext_printf("Error: kA is not on the %s curve!\n",
				   curve_params.curve_name);
			nn_print("k=", &nn_k);
			ret = -1;
			goto out;
		}
	}
	if (get_ms_time(&t2)) {
		ext_printf("Error: cannot get time with get_ms_time\n");
		ret = -1;
		goto out;
	}
	ext_printf("  [*] Montgomery EC scalar multiplication took %f seconds "
		   "on average\n",
		   (double)(t2 - t1) / (double)(PERF_SCALAR_MUL * 1000ULL));

	prj_pt_uninit(&A);
	prj_pt_uninit(&B);
	prj_pt_uninit(&C);
	prj_pt_uninit(&D);
	prj_pt_uninit(&TMP);
	aff_pt_uninit(&T);
	nn_uninit(&nn_k);
 out:
	return ret;
}

#ifdef CURVE_BASIC_EXAMPLES
int main()
{
	unsigned int i;
	u8 curve_name[MAX_CURVE_NAME_LEN] = { 0 };

	/* Traverse all the possible curves we have at our disposal (known curves and
	 * user defined curves).
	 */
	for (i = 0; i < EC_CURVES_NUM; i++) {
		/* All our possible curves are in ../curves/curves_list.h
		 * We can get the curve name from its internal type.
		 */
		ec_get_curve_name_by_type(ec_maps[i].type, curve_name,
					  sizeof(curve_name));
		/* Check our curve! */
		ext_printf("[+] Checking curve %s\n", curve_name);
		if (check_curve(curve_name)) {
			ext_printf("Error: error performing check on "
				   "curve %s\n", curve_name);
			return -1;
		}
	}
	return 0;
}
#endif
