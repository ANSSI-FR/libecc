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
#include "ec_shortw.h"
#include "prj_pt.h"
#include "prj_pt_monty.h"
#include "../nn/nn_logical.h"
#include "../fp/fp_add.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_montgomery.h"

/*
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
 */
static void __prj_pt_add_monty(prj_pt_t out, prj_pt_src_t in1,
			       prj_pt_src_t in2)
{
	fp Y1Z2, X1Z2, Z1Z2, u, uu, v, vv, vvv, R, A;

	/* Info: in1 and in2 init check done in upper levels */
	MUST_HAVE(in1->crv == in2->crv);
	MUST_HAVE(!prj_pt_iszero(in1));
	MUST_HAVE(!prj_pt_iszero(in2));
	/*
	 * The following test which guarantees in1 and in2 are not
	 * equal or opposite needs to be rewritten because it
	 * has a *HUGE* impact on perf (ec_self_tests run on
	 * all test vectors takes 24 times as long with this
	 * enabled). The same exists in non monty version.
	 */
	SHOULD_HAVE(!prj_pt_eq_or_opp(in1, in2));

	prj_pt_init(out, in1->crv);

	fp_init(&Y1Z2, out->crv->a.ctx);
	fp_init(&X1Z2, out->crv->a.ctx);
	fp_init(&Z1Z2, out->crv->a.ctx);
	fp_init(&u, out->crv->a.ctx);
	fp_init(&uu, out->crv->a.ctx);
	fp_init(&v, out->crv->a.ctx);
	fp_init(&vv, out->crv->a.ctx);
	fp_init(&vvv, out->crv->a.ctx);
	fp_init(&R, out->crv->a.ctx);
	fp_init(&A, out->crv->a.ctx);

	/* Y1Z2 = Y1*Z2 */
	fp_mul_monty(&Y1Z2, &(in1->Y), &(in2->Z));

	/* X1Z2 = X1*Z2 */
	fp_mul_monty(&X1Z2, &(in1->X), &(in2->Z));

	/* Z1Z2 = Z1*Z2 */
	fp_mul_monty(&Z1Z2, &(in1->Z), &(in2->Z));

	/* u = Y2*Z1-Y1Z2 */
	fp_mul_monty(&u, &(in2->Y), &(in1->Z));
	fp_sub_monty(&u, &u, &Y1Z2);

	/* uu = u² */
	fp_sqr_monty(&uu, &u);

	/* v = X2*Z1-X1Z2 */
	fp_mul_monty(&v, &(in2->X), &(in1->Z));
	fp_sub_monty(&v, &v, &X1Z2);

	/* vv = v² */
	fp_sqr_monty(&vv, &v);

	/* vvv = v*vv */
	fp_mul_monty(&vvv, &v, &vv);

	/* R = vv*X1Z2 */
	fp_mul_monty(&R, &vv, &X1Z2);

	/* A = uu*Z1Z2-vvv-2*R */
	fp_mul_monty(&A, &uu, &Z1Z2);
	fp_sub_monty(&A, &A, &vvv);
	fp_sub_monty(&A, &A, &R);
	fp_sub_monty(&A, &A, &R);

	/* X3 = v*A */
	fp_mul_monty(&(out->X), &v, &A);

	/* Y3 = u*(R-A)-vvv*Y1Z2 */
	fp_sub_monty(&R, &R, &A);
	fp_mul_monty(&(out->Y), &u, &R);
	fp_mul_monty(&R, &vvv, &Y1Z2);
	fp_sub_monty(&(out->Y), &(out->Y), &R);

	/* Z3 = vvv*Z1Z2 */
	fp_mul_monty(&(out->Z), &vvv, &Z1Z2);

	fp_uninit(&Y1Z2);
	fp_uninit(&X1Z2);
	fp_uninit(&Z1Z2);
	fp_uninit(&u);
	fp_uninit(&uu);
	fp_uninit(&v);
	fp_uninit(&vv);
	fp_uninit(&vvv);
	fp_uninit(&R);
	fp_uninit(&A);
}

/* Aliased version */
static void _prj_pt_add_monty(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
	if ((out == in1) || (out == in2)) {
		prj_pt out_cpy;
		prj_pt_init(&out_cpy, out->crv);
		prj_pt_copy(&out_cpy, out);
		__prj_pt_add_monty(&out_cpy, in1, in2);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		__prj_pt_add_monty(out, in1, in2);
	}
}

/* Public version of the addition to handle the case where the inputs are
 * zero or opposites
 */
void prj_pt_add_monty(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
	prj_pt_check_initialized(in1);
	prj_pt_check_initialized(in2);

	if (prj_pt_iszero(in1)) {
		prj_pt_init(out, in2->crv);
		prj_pt_copy(out, in2);
	} else if (prj_pt_iszero(in2)) {
		prj_pt_init(out, in1->crv);
		prj_pt_copy(out, in1);
	}
	/*
	 * The following test which guarantees in1 and in2 are not
	 * equal or opposite needs to be rewritten because it
	 * has a *HUGE* impact on perf (ec_self_tests run on
	 * all test vectors takes 24 times as long with this
	 * enabled). The same exists in non monty version.
	 */
	else if (prj_pt_eq_or_opp(in1, in2)) {
		if (prj_pt_cmp(in1, in2) == 0) {
			prj_pt_dbl_monty(out, in1);
		} else {
			prj_pt_init(out, in1->crv);
			prj_pt_zero(out);
		}
	} else {
		_prj_pt_add_monty(out, in1, in2);
	}
}

/*
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
 */
static void __prj_pt_dbl_monty(prj_pt_t out, prj_pt_src_t in)
{
	fp XX, ZZ, w, s, ss, sss, R, RR, B, h;

	/* Info: in init check done in upper levels */
	MUST_HAVE(!prj_pt_iszero(in));

	prj_pt_init(out, in->crv);

	fp_init(&XX, out->crv->a.ctx);
	fp_init(&ZZ, out->crv->a.ctx);
	fp_init(&w, out->crv->a.ctx);
	fp_init(&s, out->crv->a.ctx);
	fp_init(&ss, out->crv->a.ctx);
	fp_init(&sss, out->crv->a.ctx);
	fp_init(&R, out->crv->a.ctx);
	fp_init(&RR, out->crv->a.ctx);
	fp_init(&B, out->crv->a.ctx);
	fp_init(&h, out->crv->a.ctx);

	/* XX = X1² */
	fp_sqr_monty(&XX, &(in->X));

	/* ZZ = Z1² */
	fp_sqr_monty(&ZZ, &(in->Z));

	/* w = a*ZZ+3*XX */
	fp_mul_monty(&w, &(in->crv->a_monty), &ZZ);
	fp_add_monty(&w, &w, &XX);
	fp_add_monty(&w, &w, &XX);
	fp_add_monty(&w, &w, &XX);

	/* s = 2*Y1*Z1 */
	fp_mul_monty(&s, &(in->Y), &(in->Z));
	fp_add_monty(&s, &s, &s);

	/* ss = s² */
	fp_sqr_monty(&ss, &s);

	/* sss = s*ss */
	fp_mul_monty(&sss, &s, &ss);

	/* R = Y1*s */
	fp_mul_monty(&R, &(in->Y), &s);

	/* RR = R² */
	fp_sqr_monty(&RR, &R);

	/* B = (X1+R)²-XX-RR */
	fp_add_monty(&R, &R, &(in->X));
	fp_sqr_monty(&B, &R);
	fp_sub_monty(&B, &B, &XX);
	fp_sub_monty(&B, &B, &RR);

	/* h = w²-2*B */
	fp_sqr_monty(&h, &w);
	fp_sub_monty(&h, &h, &B);
	fp_sub_monty(&h, &h, &B);

	/* X3 = h*s */
	fp_mul_monty(&(out->X), &h, &s);

	/* Y3 = w*(B-h)-2*RR */
	fp_sub_monty(&B, &B, &h);
	fp_mul_monty(&(out->Y), &w, &B);
	fp_sub_monty(&(out->Y), &(out->Y), &RR);
	fp_sub_monty(&(out->Y), &(out->Y), &RR);

	/* Z3 = sss */
	fp_copy(&(out->Z), &sss);

	fp_uninit(&XX);
	fp_uninit(&ZZ);
	fp_uninit(&w);
	fp_uninit(&s);
	fp_uninit(&ss);
	fp_uninit(&sss);
	fp_uninit(&R);
	fp_uninit(&RR);
	fp_uninit(&B);
	fp_uninit(&h);
}

/* Aliased version */
static void _prj_pt_dbl_monty(prj_pt_t out, prj_pt_src_t in)
{
	if (out == in) {
		prj_pt out_cpy;
		prj_pt_init(&out_cpy, out->crv);
		prj_pt_copy(&out_cpy, out);
		__prj_pt_dbl_monty(&out_cpy, in);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		__prj_pt_dbl_monty(out, in);
	}
}

/* Public version of the doubling to handle the case where the inputs are
 * zero or opposites
 */
void prj_pt_dbl_monty(prj_pt_t out, prj_pt_src_t in)
{
	prj_pt_check_initialized(in);

	if (prj_pt_iszero(in)) {
		prj_pt_init(out, in->crv);
		prj_pt_zero(out);
	} else {
		_prj_pt_dbl_monty(out, in);
	}
}

static void _prj_pt_mul_ltr_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt dbl;
	bitcnt_t mlen;
	int mbit;

	MUST_HAVE(!prj_pt_iszero(in));
	MUST_HAVE(!nn_iszero(m));

	prj_pt_copy(out, in);
	prj_pt_init(&dbl, in->crv);

	mlen = nn_bitlen(m) - 1;
	while (mlen > 0) {
		--mlen;
		mbit = nn_getbit(m, mlen);
		prj_pt_dbl_monty(&dbl, out);
		prj_pt_add_monty(out, &dbl, in);
		nn_cnd_swap(!mbit, &(out->X.fp_val), &(dbl.X.fp_val));
		nn_cnd_swap(!mbit, &(out->Y.fp_val), &(dbl.Y.fp_val));
		nn_cnd_swap(!mbit, &(out->Z.fp_val), &(dbl.Z.fp_val));
	}

	prj_pt_uninit(&dbl);
}

/* Aliased version */
void prj_pt_mul_ltr_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt_check_initialized(in);
	nn_check_initialized(m);

	if (out == in) {
		prj_pt out_cpy;
		prj_pt_init(&out_cpy, out->crv);
		prj_pt_copy(&out_cpy, out);
		_prj_pt_mul_ltr_monty(&out_cpy, m, in);
		prj_pt_copy(out, &out_cpy);
		prj_pt_uninit(&out_cpy);
	} else {
		_prj_pt_mul_ltr_monty(out, m, in);
	}
}

void prj_pt_mul_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt_mul_ltr_monty(out, m, in);
}
