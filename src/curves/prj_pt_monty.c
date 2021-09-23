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
#include "../nn/nn_add.h"
#include "../nn/nn_rand.h"
#include "../fp/fp_add.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_montgomery.h"
#include "../fp/fp_rand.h"

#ifdef NO_USE_COMPLETE_FORMULAS

/*
 * The function is an internal one: no check is performed on parameters,
 * this MUST be done by the caller:
 *
 *  - in is initialized
 *  - in and out must not be aliased
 *
 * The function will initialize 'out'. The function returns 0 on success, -1
 * on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static int __prj_pt_dbl_monty_no_cf(prj_pt_t out, prj_pt_src_t in)
{
	fp XX, ZZ, w, s, ss, sss, R, RR, B, h;
	int ret;
	XX.magic = ZZ.magic = w.magic = s.magic = 0;
	ss.magic = sss.magic = R.magic = 0;
	RR.magic = B.magic = h.magic = 0;

	ret = prj_pt_init(out, in->crv); EG(ret, err);

	ret = fp_init(&XX, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&ZZ, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&w, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&s, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&ss, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&sss, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&R, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&RR, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&B, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&h, out->crv->a.ctx); EG(ret, err);

	/* XX = X1² */
	ret = fp_sqr_monty(&XX, &(in->X)); EG(ret, err);

	/* ZZ = Z1² */
	ret = fp_sqr_monty(&ZZ, &(in->Z)); EG(ret, err);

	/* w = a*ZZ+3*XX */
	ret = fp_mul_monty(&w, &(in->crv->a_monty), &ZZ); EG(ret, err);
	ret = fp_add_monty(&w, &w, &XX); EG(ret, err);
	ret = fp_add_monty(&w, &w, &XX); EG(ret, err);
	ret = fp_add_monty(&w, &w, &XX); EG(ret, err);

	/* s = 2*Y1*Z1 */
	ret = fp_mul_monty(&s, &(in->Y), &(in->Z)); EG(ret, err);
	ret = fp_add_monty(&s, &s, &s); EG(ret, err);

	/* ss = s² */
	ret = fp_sqr_monty(&ss, &s); EG(ret, err);

	/* sss = s*ss */
	ret = fp_mul_monty(&sss, &s, &ss); EG(ret, err);

	/* R = Y1*s */
	ret = fp_mul_monty(&R, &(in->Y), &s); EG(ret, err);

	/* RR = R² */
	ret = fp_sqr_monty(&RR, &R); EG(ret, err);

	/* B = (X1+R)²-XX-RR */
	ret = fp_add_monty(&R, &R, &(in->X)); EG(ret, err);
	ret = fp_sqr_monty(&B, &R); EG(ret, err);
	ret = fp_sub_monty(&B, &B, &XX); EG(ret, err);
	ret = fp_sub_monty(&B, &B, &RR); EG(ret, err);

	/* h = w²-2*B */
	ret = fp_sqr_monty(&h, &w); EG(ret, err);
	ret = fp_sub_monty(&h, &h, &B); EG(ret, err);
	ret = fp_sub_monty(&h, &h, &B); EG(ret, err);

	/* X3 = h*s */
	ret = fp_mul_monty(&(out->X), &h, &s); EG(ret, err);

	/* Y3 = w*(B-h)-2*RR */
	ret = fp_sub_monty(&B, &B, &h); EG(ret, err);
	ret = fp_mul_monty(&(out->Y), &w, &B); EG(ret, err);
	ret = fp_sub_monty(&(out->Y), &(out->Y), &RR); EG(ret, err);
	ret = fp_sub_monty(&(out->Y), &(out->Y), &RR); EG(ret, err);

	/* Z3 = sss */
	ret = fp_copy(&(out->Z), &sss);

err:
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

	return ret;
}

/*
 * The function is an internal one: no check is performed on parameters,
 * this MUST be done by the caller:
 *
 *  - in1 and in2 are initialized
 *  - in1 and in2 are on the same curve
 *  - in1/in2 and out must not be aliased
 *  - in1 and in2 must not be equal, opposite or have identical value
 *
 * The function will initialize 'out'. The function returns 0 on success, -1
 * on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static int ___prj_pt_add_monty_no_cf(prj_pt_t out,
							       prj_pt_src_t in1,
							       prj_pt_src_t in2)
{
	fp Y1Z2, X1Z2, Z1Z2, u, uu, v, vv, vvv, R, A;
	int ret;
	Y1Z2.magic = X1Z2.magic = Z1Z2.magic = u.magic = uu.magic = v.magic = 0;
	vv.magic = vvv.magic = R.magic = A.magic = 0;

	ret = prj_pt_init(out, in1->crv); EG(ret, err);

	ret = fp_init(&Y1Z2, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&X1Z2, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&Z1Z2, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&u, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&uu, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&v, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&vv, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&vvv, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&R, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&A, out->crv->a.ctx); EG(ret, err);

	/* Y1Z2 = Y1*Z2 */
	ret = fp_mul_monty(&Y1Z2, &(in1->Y), &(in2->Z)); EG(ret, err);

	/* X1Z2 = X1*Z2 */
	ret = fp_mul_monty(&X1Z2, &(in1->X), &(in2->Z)); EG(ret, err);

	/* Z1Z2 = Z1*Z2 */
	ret = fp_mul_monty(&Z1Z2, &(in1->Z), &(in2->Z)); EG(ret, err);

	/* u = Y2*Z1-Y1Z2 */
	ret = fp_mul_monty(&u, &(in2->Y), &(in1->Z)); EG(ret, err);
	ret = fp_sub_monty(&u, &u, &Y1Z2); EG(ret, err);

	/* uu = u² */
	ret = fp_sqr_monty(&uu, &u); EG(ret, err);

	/* v = X2*Z1-X1Z2 */
	ret = fp_mul_monty(&v, &(in2->X), &(in1->Z)); EG(ret, err);
	ret = fp_sub_monty(&v, &v, &X1Z2); EG(ret, err);

	/* vv = v² */
	ret = fp_sqr_monty(&vv, &v); EG(ret, err);

	/* vvv = v*vv */
	ret = fp_mul_monty(&vvv, &v, &vv); EG(ret, err);

	/* R = vv*X1Z2 */
	ret = fp_mul_monty(&R, &vv, &X1Z2); EG(ret, err);

	/* A = uu*Z1Z2-vvv-2*R */
	ret = fp_mul_monty(&A, &uu, &Z1Z2); EG(ret, err);
	ret = fp_sub_monty(&A, &A, &vvv); EG(ret, err);
	ret = fp_sub_monty(&A, &A, &R); EG(ret, err);
	ret = fp_sub_monty(&A, &A, &R); EG(ret, err);

	/* X3 = v*A */
	ret = fp_mul_monty(&(out->X), &v, &A); EG(ret, err);

	/* Y3 = u*(R-A)-vvv*Y1Z2 */
	ret = fp_sub_monty(&R, &R, &A); EG(ret, err);
	ret = fp_mul_monty(&(out->Y), &u, &R); EG(ret, err);
	ret = fp_mul_monty(&R, &vvv, &Y1Z2); EG(ret, err);
	ret = fp_sub_monty(&(out->Y), &(out->Y), &R); EG(ret, err);

	/* Z3 = vvv*Z1Z2 */
	ret = fp_mul_monty(&(out->Z), &vvv, &Z1Z2);

err:
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

	return ret;
}

/*
 * Public version of the addition w/o complete formulas to handle the case
 * where the inputs are zero or opposite. Returns 0 on success, -1 on error.
 */
int __prj_pt_add_monty_no_cf(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
	int ret, iszero, eq_or_opp, cmp;

	ret = prj_pt_check_initialized(in1); EG(ret, err);
	ret = prj_pt_check_initialized(in2); EG(ret, err);
	MUST_HAVE(in1->crv == in2->crv, ret, err);

	ret = prj_pt_iszero(in1, &iszero); EG(ret, err);
	if (iszero) {
		/* in1 at infinity, output in2 in all cases */
		ret = prj_pt_init(out, in2->crv); EG(ret, err);
		ret = prj_pt_copy(out, in2); EG(ret, err);
	} else {
		/* in1 not at infinity, output in2 */
		ret = prj_pt_iszero(in2, &iszero); EG(ret, err);
		if (iszero) {
			/* in2 at infinity, output in1 */
			ret = prj_pt_init(out, in1->crv); EG(ret, err);
			ret = prj_pt_copy(out, in1); EG(ret, err);
		} else {
			/* enither in1, nor in2 at infinity */

			/*
			 * The following test which guarantees in1 and in2 are not
			 * equal or opposite needs to be rewritten because it
			 * has a *HUGE* impact on perf (ec_self_tests run on
			 * all test vectors takes 24 times as long with this
			 * enabled). The same exists in non monty version.
			 */
			ret = prj_pt_eq_or_opp(in1, in2, &eq_or_opp); EG(ret, err);
			if (eq_or_opp) {
				/* in1 and in2 are either equal or opposite */
				ret = prj_pt_cmp(in1, in2, &cmp); EG(ret, err);
				if (cmp == 0) {
					/* in1 == in2 => doubling w/o cf */
					ret = __prj_pt_dbl_monty_no_cf(out, in1); EG(ret, err);
				} else {
					/* in1 == -in2 => output zero (point at infinity) */
					ret = prj_pt_init(out, in1->crv); EG(ret, err);
					ret = prj_pt_zero(out); EG(ret, err);
				}
			} else {
				/*
				 * in1 and in2 are neither 0, nor equal or
				 * opposite. Use the basic monty addition
				 * implementation w/o complete formulas.
				 */
				ret = ___prj_pt_add_monty_no_cf(out, in1, in2); EG(ret, err);
			}
		}
	}

err:
	return ret;
}


#else /* NO_USE_COMPLETE_FORMULAS */


/*
 * If NO_USE_COMPLETE_FORMULAS flag is not defined addition formulas from Algorithm 3
 * of https://joostrenes.nl/publications/complete.pdf are used, otherwise
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
 */
ATTRIBUTE_WARN_UNUSED_RET static int __prj_pt_dbl_monty_cf(prj_pt_t out, prj_pt_src_t in)
{
	fp t0, t1, t2, t3;
	int ret;
	t0.magic = t1.magic = t2.magic = t3.magic = 0;

	ret = prj_pt_init(out, in->crv); EG(ret, err);

	ret = fp_init(&t0, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t1, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t2, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t3, out->crv->a.ctx); EG(ret, err);

	ret = fp_mul_monty(&t0, &in->X, &in->X); EG(ret, err);
	ret = fp_mul_monty(&t1, &in->Y, &in->Y); EG(ret, err);
	ret = fp_mul_monty(&t2, &in->Z, &in->Z); EG(ret, err);
	ret = fp_mul_monty(&t3, &in->X, &in->Y); EG(ret, err);
	ret = fp_add_monty(&t3, &t3, &t3); EG(ret, err);

	ret = fp_mul_monty(&out->Z, &in->X, &in->Z); EG(ret, err);
	ret = fp_add_monty(&out->Z, &out->Z, &out->Z); EG(ret, err);
	ret = fp_mul_monty(&out->X, &in->crv->a_monty, &out->Z); EG(ret, err);
	ret = fp_mul_monty(&out->Y, &in->crv->b3_monty, &t2); EG(ret, err);
	ret = fp_add_monty(&out->Y, &out->X, &out->Y); EG(ret, err);

	ret = fp_sub_monty(&out->X, &t1, &out->Y); EG(ret, err);
	ret = fp_add_monty(&out->Y, &t1, &out->Y); EG(ret, err);
	ret = fp_mul_monty(&out->Y, &out->X, &out->Y); EG(ret, err);
	ret = fp_mul_monty(&out->X, &t3, &out->X); EG(ret, err);
	ret = fp_mul_monty(&out->Z, &in->crv->b3_monty, &out->Z); EG(ret, err);

	ret = fp_mul_monty(&t2, &in->crv->a_monty, &t2); EG(ret, err);
	ret = fp_sub_monty(&t3, &t0, &t2); EG(ret, err);
	ret = fp_mul_monty(&t3, &in->crv->a_monty, &t3); EG(ret, err);
	ret = fp_add_monty(&t3, &t3, &out->Z); EG(ret, err);
	ret = fp_add_monty(&out->Z, &t0, &t0); EG(ret, err);

	ret = fp_add_monty(&t0, &out->Z, &t0); EG(ret, err);
	ret = fp_add_monty(&t0, &t0, &t2); EG(ret, err);
	ret = fp_mul_monty(&t0, &t0, &t3); EG(ret, err);
	ret = fp_add_monty(&out->Y, &out->Y, &t0); EG(ret, err);
	ret = fp_mul_monty(&t2, &in->Y, &in->Z); EG(ret, err);

	ret = fp_add_monty(&t2, &t2, &t2); EG(ret, err);
	ret = fp_mul_monty(&t0, &t2, &t3); EG(ret, err);
	ret = fp_sub_monty(&out->X, &out->X, &t0); EG(ret, err);
	ret = fp_mul_monty(&out->Z, &t2, &t1); EG(ret, err);
	ret = fp_add_monty(&out->Z, &out->Z, &out->Z); EG(ret, err);

	ret = fp_add_monty(&out->Z, &out->Z, &out->Z);

err:
	fp_uninit(&t0);
	fp_uninit(&t1);
	fp_uninit(&t2);
	fp_uninit(&t3);

	return ret;
}

/*
 * If NO_USE_COMPLETE_FORMULAS flag is not defined addition formulas from Algorithm 1
 * of https://joostrenes.nl/publications/complete.pdf are used, otherwise
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
 */

/*
 * The function is an internal one: no check is performed on parameters,
 * this MUST be done by the caller:
 *
 *  - in1 and in2 are initialized
 *  - in1 and in2 are on the same curve
 *  - in1/in2 and out must not be aliased
 *  - in1 and in2 must not be equal, opposite or have identical value
 *
 * The function will initialize 'out'. The function returns 0 on success, -1
 * on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static int __prj_pt_add_monty_cf(prj_pt_t out,
							   prj_pt_src_t in1,
							   prj_pt_src_t in2)
{
	fp t0, t1, t2, t3, t4, t5;
	int ret;
	t0.magic = t1.magic = t2.magic = 0;
	t3.magic = t4.magic = t5.magic = 0;

	ret = prj_pt_init(out, in1->crv); EG(ret, err);

	ret = fp_init(&t0, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t1, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t2, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t3, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t4, out->crv->a.ctx); EG(ret, err);
	ret = fp_init(&t5, out->crv->a.ctx); EG(ret, err);

	ret = fp_mul_monty(&t0, &in1->X, &in2->X); EG(ret, err);
	ret = fp_mul_monty(&t1, &in1->Y, &in2->Y); EG(ret, err);
	ret = fp_mul_monty(&t2, &in1->Z, &in2->Z); EG(ret, err);
	ret = fp_add_monty(&t3, &in1->X, &in1->Y); EG(ret, err);
	ret = fp_add_monty(&t4, &in2->X, &in2->Y); EG(ret, err);

	ret = fp_mul_monty(&t3, &t3, &t4); EG(ret, err);
	ret = fp_add_monty(&t4, &t0, &t1); EG(ret, err);
	ret = fp_sub_monty(&t3, &t3, &t4); EG(ret, err);
	ret = fp_add_monty(&t4, &in1->X, &in1->Z); EG(ret, err);
	ret = fp_add_monty(&t5, &in2->X, &in2->Z); EG(ret, err);

	ret = fp_mul_monty(&t4, &t4, &t5); EG(ret, err);
	ret = fp_add_monty(&t5, &t0, &t2); EG(ret, err);
	ret = fp_sub_monty(&t4, &t4, &t5); EG(ret, err);
	ret = fp_add_monty(&t5, &in1->Y, &in1->Z); EG(ret, err);
	ret = fp_add_monty(&out->X, &in2->Y, &in2->Z); EG(ret, err);

	ret = fp_mul_monty(&t5, &t5, &out->X); EG(ret, err);
	ret = fp_add_monty(&out->X, &t1, &t2); EG(ret, err);
	ret = fp_sub_monty(&t5, &t5, &out->X); EG(ret, err);
	ret = fp_mul_monty(&out->Z, &in1->crv->a_monty, &t4); EG(ret, err);
	ret = fp_mul_monty(&out->X, &in1->crv->b3_monty, &t2); EG(ret, err);

	ret = fp_add_monty(&out->Z, &out->X, &out->Z); EG(ret, err);
	ret = fp_sub_monty(&out->X, &t1, &out->Z); EG(ret, err);
	ret = fp_add_monty(&out->Z, &t1, &out->Z); EG(ret, err);
	ret = fp_mul_monty(&out->Y, &out->X, &out->Z); EG(ret, err);
	ret = fp_add_monty(&t1, &t0, &t0); EG(ret, err);

	ret = fp_add_monty(&t1, &t1, &t0); EG(ret, err);
	ret = fp_mul_monty(&t2, &in1->crv->a_monty, &t2); EG(ret, err);
	ret = fp_mul_monty(&t4, &in1->crv->b3_monty, &t4); EG(ret, err);
	ret = fp_add_monty(&t1, &t1, &t2); EG(ret, err);
	ret = fp_sub_monty(&t2, &t0, &t2); EG(ret, err);

	ret = fp_mul_monty(&t2, &in1->crv->a_monty, &t2); EG(ret, err);
	ret = fp_add_monty(&t4, &t4, &t2); EG(ret, err);
	ret = fp_mul_monty(&t0, &t1, &t4); EG(ret, err);
	ret = fp_add_monty(&out->Y, &out->Y, &t0); EG(ret, err);
	ret = fp_mul_monty(&t0, &t5, &t4); EG(ret, err);

	ret = fp_mul_monty(&out->X, &t3, &out->X); EG(ret, err);
	ret = fp_sub_monty(&out->X, &out->X, &t0); EG(ret, err);
	ret = fp_mul_monty(&t0, &t3, &t1); EG(ret, err);
	ret = fp_mul_monty(&out->Z, &t5, &out->Z); EG(ret, err);
	ret = fp_add_monty(&out->Z, &out->Z, &t0);

err:
	fp_uninit(&t0);
	fp_uninit(&t1);
	fp_uninit(&t2);
	fp_uninit(&t3);
	fp_uninit(&t4);
	fp_uninit(&t5);

	return ret;
}
#endif  /* NO_USE_COMPLETE_FORMULAS */

/*
 * Internal function:
 *
 *  - not supporting aliasing,
 *  - requiring caller to check in parameter is initialized
 *
 * Based on library configuration, the function either use complete formulas
 * or not.
 */
static int _prj_pt_dbl_monty(prj_pt_t out, prj_pt_src_t in)
{
	int ret;

#ifdef NO_USE_COMPLETE_FORMULAS
	int iszero;
	ret = prj_pt_iszero(in, &iszero); EG(ret, err);
	if (iszero) {
		ret = prj_pt_init(out, in->crv); EG(ret, err);
		ret = prj_pt_zero(out);
	} else {
		ret = __prj_pt_dbl_monty_no_cf(out, in);
	}
#else
	ret = __prj_pt_dbl_monty_cf(out, in); EG(ret, err);
#endif

err:
	return ret;
}

/*
 * Internal version that peform in place doubling of given val,
 * by using a temporary copy. Sanity checks on parameters must
 * be done by caller.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _prj_pt_dbl_monty_aliased(prj_pt_t val)
{
	prj_pt out_cpy;
	int ret;
	out_cpy.magic = 0;

	ret = _prj_pt_dbl_monty(&out_cpy, val); EG(ret, err);
	ret = prj_pt_copy(val, &out_cpy);

err:
	prj_pt_uninit(&out_cpy);
	return ret;
}

/*
 * Public function for projective point doubling. The function handles the init
 * check of 'in' parameter which must be guaranteed for internal functions.
 * 'out' parameter need not be initialized and can be aliased with 'in'
 * parameter.
 *
 * The function returns 0 on success, -1 on error.
 */
ATTRIBUTE_WARN_UNUSED_RET int prj_pt_dbl_monty(prj_pt_t out, prj_pt_src_t in)
{
	int ret;

	ret = prj_pt_check_initialized(in); EG(ret, err);

	if (out == in) {
		ret = _prj_pt_dbl_monty_aliased(out);
	} else {
		ret = _prj_pt_dbl_monty(out, in);
	}

err:
	return ret;
}

/*
 * Internal function:
 *
 *  - not supporting aliasing,
 *  - requiring caller to check in1 and in2 parameter
 *
 * Based on library configuration, the function either use complete formulas
 * or not.
 */
ATTRIBUTE_WARN_UNUSED_RET static inline int _prj_pt_add_monty(prj_pt_t out,
							      prj_pt_src_t in1,
							      prj_pt_src_t in2)
{
#ifndef NO_USE_COMPLETE_FORMULAS
	return __prj_pt_add_monty_cf(out, in1, in2);
#else
	return __prj_pt_add_monty_no_cf(out, in1, in2);
#endif
}

/*
 * The function is an internal one that specifically handles aliasing. No check
 * is performed on parameters, this MUST be done by the caller:
 *
 *  - in1 and in2 are initialized
 *  - in1 and in2 are on the same curve
 *
 * The function will initialize 'out'. The function returns 0 on success, -1
 * on error.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _prj_pt_add_monty_aliased(prj_pt_t out,
								prj_pt_src_t in1,
								prj_pt_src_t in2)
{
	prj_pt out_cpy;
	int ret;
	out_cpy.magic = 0;

	ret = _prj_pt_add_monty(&out_cpy, in1, in2); EG(ret, err);
	ret = prj_pt_copy(out, &out_cpy); EG(ret, err);

err:
	prj_pt_uninit(&out_cpy);
	return ret;
}

/*
 * Public function for projective point addition. The function handles the
 * init checks of 'in1' and 'in2' parameters, along with the check they
 * use the same curve. This must be guaranteed for internal functions.
 * 'out' parameter need not be initialized and can be aliased with either
 * 'in1' or 'in2' parameter.
 *
 * The function returns 0 on success, -1 on error.
 */
int prj_pt_add_monty(prj_pt_t out, prj_pt_src_t in1, prj_pt_src_t in2)
{
	int ret;

	ret = prj_pt_check_initialized(in1); EG(ret, err);
	ret = prj_pt_check_initialized(in2); EG(ret, err);
	MUST_HAVE(in1->crv == in2->crv, ret, err);

	if ((out == in1) || (out == in2)) {
		ret = _prj_pt_add_monty_aliased(out, in1, in2);
	} else {
		ret = _prj_pt_add_monty(out, in1, in2);
	}

err:
	return ret;
}

/****** Scalar multiplication algorithms *****/

/* If nothing is specified regarding the scalar multiplication algorithm, we use
 * the Montgomery Ladder
 */
#if !defined(USE_DOUBLE_ADD_ALWAYS) && !defined(USE_MONTY_LADDER)
#define USE_MONTY_LADDER
#endif

#if defined(USE_DOUBLE_ADD_ALWAYS) && defined(USE_MONTY_LADDER)
#error "You can either choose USE_DOUBLE_ADD_ALWAYS or USE_MONTY_LADDER, not both!"
#endif

#ifdef USE_DOUBLE_ADD_ALWAYS
/* Double-and-Add-Always masked using Itoh et al. anti-ADPA
 * (Address-bit DPA) countermeasure.
 * See "A Practical Countermeasure against Address-Bit Differential Power Analysis"
 * by Itoh, Izu and Takenaka for more information.
 *
 * NOTE: this masked variant of the Double-and-Add-Always algorithm is always
 * used as it has a very small impact on performance and is inherently more
 * robust againt DPA.
 *
 * NOTE: the Double-and-Add-Always algorithm inherently depends on the MSB of the
 * scalar. In order to avoid leaking this MSB and fall into HNP (Hidden Number
 * Problem) issues, we use the trick described in https://eprint.iacr.org/2011/232.pdf
 * to have the MSB always set. However, since the scalar m might be less or bigger than
 * the order q of the curve, we distinguish three situations:
 *     - The scalar m is < q (the order), in this case we compute:
 *         -
 *        | m' = m + (2 * q) if [log(k + q)] == [log(q)],
 *        | m' = m + q otherwise.
 *         -
 *     - The scalar m is >= q and < q**2, in this case we compute:
 *         -
 *        | m' = m + (2 * (q**2)) if [log(k + (q**2))] == [log(q**2)],
 *        | m' = m + (q**2) otherwise.
 *         -
 *     - The scalar m is >= (q**2), in this case m == m'
 *
 *   => We only deal with 0 <= m < (q**2) using the countermeasure. When m >= (q**2),
 *      we stick with m' = m, accepting MSB issues (not much can be done in this case
 *      anyways). In the two first cases, Double-and-Add-Always is performed in constant
 *      time wrt the size of the scalar m.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _prj_pt_mul_ltr_monty_dbl_add_always(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	/* We use Itoh et al. notations here for T and the random r */
	prj_pt T[3];
	bitcnt_t mlen;
	u8 mbit, rbit;
	/* Random for masking the Double and Add Always algorithm */
	nn r;
	/* Random for projective coordinates masking */
	fp l;
	/* The new scalar we will use with MSB fixed to 1 (noted m' above).
	 * This helps dealing with constant time.
	 */
	nn m_msb_fixed;
	nn_src_t curve_order;
	nn curve_order_square;
	int ret, on_curve, cmp;
	r.magic = l.magic = m_msb_fixed.magic = curve_order_square.magic = 0;
	T[0].magic = T[1].magic = T[2].magic = 0;

	/* Check that the input is on the curve */
	MUST_HAVE(!prj_pt_is_on_curve(in, &on_curve) && on_curve, ret, err);
	/* Compute m' from m depending on the rule described above */
	curve_order = &(in->crv->order);
	/* First compute q**2 */
	ret = nn_sqr(&curve_order_square, curve_order); EG(ret, err);
	/* Then compute m' depending on m size */
	ret = nn_cmp(m, curve_order, &cmp); EG(ret, err);
	if (cmp < 0){
		bitcnt_t msb_bit_len, order_bitlen;

		/* Case where m < q */
		ret = nn_add(&m_msb_fixed, m, curve_order); EG(ret, err);
		ret = nn_bitlen(&m_msb_fixed, &msb_bit_len); EG(ret, err);
		ret = nn_bitlen(curve_order, &order_bitlen); EG(ret, err);
		ret = nn_cnd_add((msb_bit_len == order_bitlen), &m_msb_fixed,
				  &m_msb_fixed, curve_order); EG(ret, err);
	} else {
		ret = nn_cmp(m, &curve_order_square, &cmp); EG(ret, err);
		if (cmp < 0) {
			bitcnt_t msb_bit_len, curve_order_square_bitlen;

			/* Case where m >= q and m < (q**2) */
			ret = nn_add(&m_msb_fixed, m, &curve_order_square); EG(ret, err);
			ret = nn_bitlen(&m_msb_fixed, &msb_bit_len); EG(ret, err);
			ret = nn_bitlen(&curve_order_square, &curve_order_square_bitlen); EG(ret, err);
			ret = nn_cnd_add((msb_bit_len == curve_order_square_bitlen),
					&m_msb_fixed, &m_msb_fixed, &curve_order_square); EG(ret, err);
		} else {
			/* Case where m >= (q**2) */
			ret = nn_copy(&m_msb_fixed, m); EG(ret, err);
		}
	}
	ret = nn_bitlen(&m_msb_fixed, &mlen); EG(ret, err);
	if (mlen == 0){
		ret = -1;
		goto err;
	}
	mlen--;

	/* Get a random r with the same size of m_msb_fixed */
	ret = nn_get_random_len(&r, m_msb_fixed.wlen * WORD_BYTES); EG(ret, err);

	/* Get a random value l in Fp */
	ret = fp_get_random(&l, in->X.ctx); EG(ret, err);

	ret = nn_getbit(&r, mlen, &rbit); EG(ret, err);

	/* Initialize points */
	ret = prj_pt_init(&T[0], in->crv); EG(ret, err);
	ret = prj_pt_init(&T[1], in->crv); EG(ret, err);

	/*
	 * T[2] = R(P)
	 * Blind the point with projective coordinates
	 * (X, Y, Z) => (l*X, l*Y, l*Z)
	 */
	ret = prj_pt_init(&T[2], in->crv); EG(ret, err);
	ret = fp_mul_monty(&(T[2].X), &(in->X), &l); EG(ret, err);
	ret = fp_mul_monty(&(T[2].Y), &(in->Y), &l); EG(ret, err);
	ret = fp_mul_monty(&(T[2].Z), &(in->Z), &l); EG(ret, err);

	/*  T[r[n-1]] = T[2] */
	ret = prj_pt_copy(&T[rbit], &T[2]); EG(ret, err);

	/* Main loop of Double and Add Always */
	while (mlen > 0) {
		u8 rbit_next;
		--mlen;
		/* rbit is r[i+1], and rbit_next is r[i] */
		ret = nn_getbit(&r, mlen, &rbit_next); EG(ret, err);

		/* mbit is m[i] */
		ret = nn_getbit(&m_msb_fixed, mlen, &mbit); EG(ret, err);

		/* Double: T[r[i+1]] = ECDBL(T[r[i+1]]) */
#ifndef NO_USE_COMPLETE_FORMULAS
		/*
		 * NOTE: in case of complete formulas, we use the
		 * addition for doubling, incurring a small performance hit
		 * for better SCA resistance.
		 */
		ret = prj_pt_add_monty(&T[rbit], &T[rbit], &T[rbit]); EG(ret, err);
#else
		ret = prj_pt_dbl_monty(&T[rbit], &T[rbit]); EG(ret, err);
#endif
		/* Add:  T[1-r[i+1]] = ECADD(T[r[i+1]],T[2]) */
		ret = prj_pt_add_monty(&T[1-rbit], &T[rbit], &T[2]); EG(ret, err);

		/*
		 * T[r[i]] = T[d[i] ^ r[i+1]]
		 * NOTE: we use the low level nn_copy function here to avoid
		 * any possible leakage on operands with prj_pt_copy
		 */
		ret = nn_copy(&(T[rbit_next].X.fp_val), &(T[mbit ^ rbit].X.fp_val)); EG(ret, err);
		ret = nn_copy(&(T[rbit_next].Y.fp_val), &(T[mbit ^ rbit].Y.fp_val)); EG(ret, err);
		ret = nn_copy(&(T[rbit_next].Z.fp_val), &(T[mbit ^ rbit].Z.fp_val)); EG(ret, err);

		/* Update rbit */
		rbit = rbit_next;
	}
	/* Output: T[r[0]] */
	ret = prj_pt_copy(out, &T[rbit]); EG(ret, err);

	/* Check that the output is on the curve */
	ret = prj_pt_is_on_curve(out, &on_curve); EG(ret, err);
	if(!on_curve){
		ret = -1;
	}

err:
	prj_pt_uninit(&T[0]);
	prj_pt_uninit(&T[1]);
	prj_pt_uninit(&T[2]);
	nn_uninit(&r);
	fp_uninit(&l);
	nn_uninit(&m_msb_fixed);
	nn_uninit(&curve_order_square);

	return ret;
}
#endif

#ifdef USE_MONTY_LADDER
/* Montgomery Ladder masked using Itoh et al. anti-ADPA
 * (Address-bit DPA) countermeasure.
 * See "A Practical Countermeasure against Address-Bit Differential Power Analysis"
 * by Itoh, Izu and Takenaka for more information.
 *
 * NOTE: this masked variant of the Montgomery Ladder algorithm is always
 * used as it has a very small impact on performance and is inherently more
 * robust againt DPA.
 *
 * NOTE: the Montgomery Ladder algorithm inherently depends on the MSB of the
 * scalar. In order to avoid leaking this MSB and fall into HNP (Hidden Number
 * Problem) issues, we use the trick described in https://eprint.iacr.org/2011/232.pdf
 * to have the MSB always set. However, since the scalar m might be less or bigger than
 * the order q of the curve, we distinguish three situations:
 *     - The scalar m is < q (the order), in this case we compute:
 *         -
 *        | m' = m + (2 * q) if [log(k + q)] == [log(q)],
 *        | m' = m + q otherwise.
 *         -
 *     - The scalar m is >= q and < q**2, in this case we compute:
 *         -
 *        | m' = m + (2 * (q**2)) if [log(k + (q**2))] == [log(q**2)],
 *        | m' = m + (q**2) otherwise.
 *         -
 *     - The scalar m is >= (q**2), in this case m == m'
 *
 *   => We only deal with 0 <= m < (q**2) using the countermeasure. When m >= (q**2),
 *      we stick with m' = m, accepting MSB issues (not much can be done in this case
 *      anyways). In the two first cases, Montgomery Ladder is performed in constant
 *      time wrt the size of the scalar m.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _prj_pt_mul_ltr_monty_ladder(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	/* We use Itoh et al. notations here for T and the random r */
	prj_pt T[3];
	bitcnt_t mlen;
	u8 mbit, rbit;
	/* Random for masking the Montgomery Ladder algorithm */
	nn r;
	/* Random for projective coordinates masking */
	fp l;
	/* The new scalar we will use with MSB fixed to 1 (noted m' above).
	 * This helps dealing with constant time.
	 */
	nn m_msb_fixed;
	nn_src_t curve_order;
	nn curve_order_square;
	int ret, cmp, on_curve;
	r.magic = l.magic = m_msb_fixed.magic = curve_order_square.magic = 0;
	T[0].magic = T[1].magic = T[2].magic = 0;

	/* Check that the input is on the curve */
	ret = prj_pt_is_on_curve(in, &on_curve); EG(ret, err);
	MUST_HAVE((on_curve), ret, err);

	/* Compute m' from m depending on the rule described above */
	curve_order = &(in->crv->order);

	/* First compute q**2 */
	ret = nn_sqr(&curve_order_square, curve_order); EG(ret, err);

	/* Then compute m' depending on m size */
	ret = nn_cmp(m, curve_order, &cmp); EG(ret, err);
	if (cmp < 0) {
		bitcnt_t msb_bit_len, order_bitlen;

		/* Case where m < q */
		ret = nn_add(&m_msb_fixed, m, curve_order); EG(ret, err);
		ret = nn_bitlen(&m_msb_fixed, &msb_bit_len); EG(ret, err);
		ret = nn_bitlen(curve_order, &order_bitlen); EG(ret, err);
		ret = nn_cnd_add((msb_bit_len == order_bitlen), &m_msb_fixed,
				&m_msb_fixed, curve_order); EG(ret, err);
	} else {
		ret = nn_cmp(m, &curve_order_square, &cmp); EG(ret, err);
		if (cmp < 0) {
			bitcnt_t msb_bit_len, curve_order_square_bitlen;

			/* Case where m >= q and m < (q**2) */
			ret = nn_add(&m_msb_fixed, m, &curve_order_square); EG(ret, err);
			ret = nn_bitlen(&m_msb_fixed, &msb_bit_len); EG(ret, err);
			ret = nn_bitlen(&curve_order_square, &curve_order_square_bitlen); EG(ret, err);
			ret = nn_cnd_add((msb_bit_len == curve_order_square_bitlen),
					 &m_msb_fixed, &m_msb_fixed, &curve_order_square); EG(ret, err);
		} else {
			/* Case where m >= (q**2) */
			ret = nn_copy(&m_msb_fixed, m); EG(ret, err);
		}
	}

	ret = nn_bitlen(&m_msb_fixed, &mlen); EG(ret, err);
	if (mlen == 0) {
		ret = -1;
		goto err;
	}
	mlen--;

	/* Get a random r with the same size of m_msb_fixed */
	ret = nn_get_random_len(&r, m_msb_fixed.wlen * WORD_BYTES); EG(ret, err);

	/* Get a random value l in Fp */
	ret = fp_get_random(&l, in->X.ctx); EG(ret, err);

	ret = nn_getbit(&r, mlen, &rbit); EG(ret, err);

	/* Initialize points */
	ret = prj_pt_init(&T[0], in->crv); EG(ret, err);
	ret = prj_pt_init(&T[1], in->crv); EG(ret, err);
	ret = prj_pt_init(&T[2], in->crv); EG(ret, err);

	/* Initialize T[r[n-1]] to input point */
	ret = prj_pt_copy(&T[rbit], in); EG(ret, err);

	/*
	 * Blind the point with projective coordinates
	 * (X, Y, Z) => (l*X, l*Y, l*Z)
	 */
	ret = fp_mul_monty(&(T[rbit].X), &(T[rbit].X), &l); EG(ret, err);
	ret = fp_mul_monty(&(T[rbit].Y), &(T[rbit].Y), &l); EG(ret, err);
	ret = fp_mul_monty(&(T[rbit].Z), &(T[rbit].Z), &l); EG(ret, err);

	/* Initialize T[1-r[n-1]] with ECDBL(T[r[n-1]])) */
#ifndef NO_USE_COMPLETE_FORMULAS
	/*
	 * NOTE: in case of complete formulas, we use the
	 * addition for doubling, incurring a small performance hit
	 * for better SCA resistance.
	 */
	ret = prj_pt_add_monty(&T[1-rbit], &T[rbit], &T[rbit]); EG(ret, err);
#else
	ret = prj_pt_dbl_monty(&T[1-rbit], &T[rbit]); EG(ret, err);
#endif

	/* Main loop of the Montgomery Ladder */
	while (mlen > 0) {
		u8 rbit_next;
		--mlen;
		/* rbit is r[i+1], and rbit_next is r[i] */
		ret = nn_getbit(&r, mlen, &rbit_next); EG(ret, err);

		/* mbit is m[i] */
		ret = nn_getbit(&m_msb_fixed, mlen, &mbit); EG(ret, err);
		/* Double: T[2] = ECDBL(T[d[i] ^ r[i+1]]) */

#ifndef NO_USE_COMPLETE_FORMULAS
		/* NOTE: in case of complete formulas, we use the
		 * addition for doubling, incurring a small performance hit
		 * for better SCA resistance.
		 */
		ret = prj_pt_add_monty(&T[2], &T[mbit ^ rbit], &T[mbit ^ rbit]); EG(ret, err);
#else
		ret = prj_pt_dbl_monty(&T[2], &T[mbit ^ rbit]); EG(ret, err);
#endif

		/* Add: T[1] = ECADD(T[0],T[1]) */
		ret = prj_pt_add_monty(&T[1], &T[0], &T[1]); EG(ret, err);

		/* T[0] = T[2-(d[i] ^ r[i])] */
		/*
		 * NOTE: we use the low level nn_copy function here to avoid
		 * any possible leakage on operands with prj_pt_copy
		 */
		ret = nn_copy(&(T[0].X.fp_val), &(T[2-(mbit ^ rbit_next)].X.fp_val)); EG(ret, err);
		ret = nn_copy(&(T[0].Y.fp_val), &(T[2-(mbit ^ rbit_next)].Y.fp_val)); EG(ret, err);
		ret = nn_copy(&(T[0].Z.fp_val), &(T[2-(mbit ^ rbit_next)].Z.fp_val)); EG(ret, err);

		/* T[1] = T[1+(d[i] ^ r[i])] */
		/* NOTE: we use the low level nn_copy function here to avoid
		 * any possible leakage on operands with prj_pt_copy
		 */
		ret = nn_copy(&(T[1].X.fp_val), &(T[1+(mbit ^ rbit_next)].X.fp_val)); EG(ret, err);
		ret = nn_copy(&(T[1].Y.fp_val), &(T[1+(mbit ^ rbit_next)].Y.fp_val)); EG(ret, err);
		ret = nn_copy(&(T[1].Z.fp_val), &(T[1+(mbit ^ rbit_next)].Z.fp_val)); EG(ret, err);

		/* Update rbit */
		rbit = rbit_next;
	}
	/* Output: T[r[0]] */
	ret = prj_pt_copy(out, &T[rbit]); EG(ret, err);
	/* Check that the output is on the curve */
	ret = prj_pt_is_on_curve(out, &on_curve); EG(ret, err);
	if(!on_curve){
		ret = -1;
	}

err:
	prj_pt_uninit(&T[0]);
	prj_pt_uninit(&T[1]);
	prj_pt_uninit(&T[2]);
	nn_uninit(&r);
	fp_uninit(&l);
	nn_uninit(&m_msb_fixed);
	nn_uninit(&curve_order_square);

	return ret;
}
#endif

/* Main projective scalar multiplication function.
 * Depending on the preprocessing options, we use either the
 * Double and Add Always algorithm, or the Montgomery Ladder one.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _prj_pt_mul_ltr_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in){
#if defined(USE_DOUBLE_ADD_ALWAYS)
	return _prj_pt_mul_ltr_monty_dbl_add_always(out, m, in);
#elif defined(USE_MONTY_LADDER)
	return _prj_pt_mul_ltr_monty_ladder(out, m, in);
#else
#error "Error: neither Double and Add Always nor Montgomery Ladder has been selected!"
#endif
}

/* version with 'm' passed via 'out'. */
ATTRIBUTE_WARN_UNUSED_RET static int _prj_pt_mul_ltr_monty_aliased(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt out_cpy;
	int ret;
	out_cpy.magic = 0;

	ret = prj_pt_init(&out_cpy, in->crv); EG(ret, err);
	ret = _prj_pt_mul_ltr_monty(&out_cpy, m, in); EG(ret, err);
	ret = prj_pt_copy(out, &out_cpy);

err:
	prj_pt_uninit(&out_cpy);
	return ret;
}

/* Aliased version */
int prj_pt_mul_ltr_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	int ret;

	ret = prj_pt_check_initialized(in); EG(ret, err);
	ret = nn_check_initialized(m); EG(ret, err);

	if (out == in) {
		ret = _prj_pt_mul_ltr_monty_aliased(out, m, in);
	} else {
		ret = _prj_pt_mul_ltr_monty(out, m, in);
	}

err:
	return ret;
}


int prj_pt_mul_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	return prj_pt_mul_ltr_monty(out, m, in);
}

int prj_pt_mul_monty_blind(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	/* Blind the scalar m with (b*q) */
	/* First compute the order x cofactor */
	nn b;
	nn_src_t q;
	int ret;
	b.magic = 0;

	ret = prj_pt_check_initialized(in); EG(ret, err);

	q = &(in->crv->order);

	ret = nn_init(&b, 0); EG(ret, err);

	ret = nn_get_random_mod(&b, q); EG(ret, err);

	ret = nn_mul(&b, &b, q); EG(ret, err);
	ret = nn_add(&b, &b, m); EG(ret, err);

	/* NOTE: point blinding is performed in the lower functions */

	/* Perform the scalar multiplication */
	ret = prj_pt_mul_ltr_monty(out, &b, in);

err:
	nn_uninit(&b);

	return ret;
}

/*
 * Check if an integer is (a multiple of) a projective point order.
 */
int check_prj_pt_order(prj_pt_src_t in_shortw, nn_src_t in_isorder)
{
	int ret, iszero;
	prj_pt res;
	res.magic = 0;

	/* First sanity checks */
	ret = prj_pt_check_initialized(in_shortw); EG(ret, err);
	ret = nn_check_initialized(in_isorder); EG(ret, err);

	/* Then, perform the scalar multiplication */
	ret = prj_pt_mul_monty(&res, in_isorder, in_shortw); EG(ret, err);

	/* Check if we have the point at infinity */
	ret = prj_pt_iszero(&res, &iszero); EG(ret, err);
	if(!iszero){
		ret = -1;
	}

err:
	prj_pt_uninit(&res);

	return ret;
}
