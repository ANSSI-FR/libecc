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
#include "../fp/fp_add.h"
#include "../fp/fp_mul.h"
#include "../fp/fp_montgomery.h"
#include "../fp/fp_rand.h"

/*
 * If USE_COMPLETE_FORMULAS flag is defined addition formulas from Algorithm 1
 * of https://joostrenes.nl/publications/complete.pdf are used, otherwise
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
 */
static void __prj_pt_add_monty(prj_pt_t out, prj_pt_src_t in1,
			       prj_pt_src_t in2)
{
#ifdef USE_COMPLETE_FORMULAS
	fp t0, t1, t2, t3, t4, t5;

	/* Info: initialization check of in1 and in2 done at upper level */
	MUST_HAVE(in1->crv == in2->crv);

	prj_pt_init(out, in1->crv);

	fp_init(&t0, out->crv->a.ctx);
	fp_init(&t1, out->crv->a.ctx);
	fp_init(&t2, out->crv->a.ctx);
	fp_init(&t3, out->crv->a.ctx);
	fp_init(&t4, out->crv->a.ctx);
	fp_init(&t5, out->crv->a.ctx);

	MUST_HAVE(out->crv == in1->crv);
	MUST_HAVE(out->crv == in2->crv);

	fp_mul_monty(&t0, &in1->X, &in2->X);
	fp_mul_monty(&t1, &in1->Y, &in2->Y);
	fp_mul_monty(&t2, &in1->Z, &in2->Z);
	fp_add_monty(&t3, &in1->X, &in1->Y);
	fp_add_monty(&t4, &in2->X, &in2->Y);

	fp_mul_monty(&t3, &t3, &t4);
	fp_add_monty(&t4, &t0, &t1);
	fp_sub_monty(&t3, &t3, &t4);
	fp_add_monty(&t4, &in1->X, &in1->Z);
	fp_add_monty(&t5, &in2->X, &in2->Z);

	fp_mul_monty(&t4, &t4, &t5);
	fp_add_monty(&t5, &t0, &t2);
	fp_sub_monty(&t4, &t4, &t5);
	fp_add_monty(&t5, &in1->Y, &in1->Z);
	fp_add_monty(&out->X, &in2->Y, &in2->Z);

	fp_mul_monty(&t5, &t5, &out->X);
	fp_add_monty(&out->X, &t1, &t2);
	fp_sub_monty(&t5, &t5, &out->X);
	fp_mul_monty(&out->Z, &in1->crv->a_monty, &t4);
	fp_mul_monty(&out->X, &in1->crv->b3_monty, &t2);

	fp_add_monty(&out->Z, &out->X, &out->Z);
	fp_sub_monty(&out->X, &t1, &out->Z);
	fp_add_monty(&out->Z, &t1, &out->Z);
	fp_mul_monty(&out->Y, &out->X, &out->Z);
	fp_add_monty(&t1, &t0, &t0);

	fp_add_monty(&t1, &t1, &t0);
	fp_mul_monty(&t2, &in1->crv->a_monty, &t2);
	fp_mul_monty(&t4, &in1->crv->b3_monty, &t4);
	fp_add_monty(&t1, &t1, &t2);
	fp_sub_monty(&t2, &t0, &t2);

	fp_mul_monty(&t2, &in1->crv->a_monty, &t2);
	fp_add_monty(&t4, &t4, &t2);
	fp_mul_monty(&t0, &t1, &t4);
	fp_add_monty(&out->Y, &out->Y, &t0);
	fp_mul_monty(&t0, &t5, &t4);

	fp_mul_monty(&out->X, &t3, &out->X);
	fp_sub_monty(&out->X, &out->X, &t0);
	fp_mul_monty(&t0, &t3, &t1);
	fp_mul_monty(&out->Z, &t5, &out->Z);
	fp_add_monty(&out->Z, &out->Z, &t0);

	fp_uninit(&t0);
	fp_uninit(&t1);
	fp_uninit(&t2);
	fp_uninit(&t3);
	fp_uninit(&t4);
	fp_uninit(&t5);
#else
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
#endif
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

#ifndef USE_COMPLETE_FORMULAS
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
#else
	_prj_pt_add_monty(out, in1, in2);
#endif
}

/*
 * If USE_COMPLETE_FORMULAS flag is defined addition formulas from Algorithm 3
 * of https://joostrenes.nl/publications/complete.pdf are used, otherwise
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
 */
static void __prj_pt_dbl_monty(prj_pt_t out, prj_pt_src_t in)
{
#ifdef USE_COMPLETE_FORMULAS
	fp t0, t1, t2 ,t3;

	/* Info: initialization check of in done at upper level */
	prj_pt_init(out, in->crv);

	fp_init(&t0, out->crv->a.ctx);
	fp_init(&t1, out->crv->a.ctx);
	fp_init(&t2, out->crv->a.ctx);
	fp_init(&t3, out->crv->a.ctx);

	MUST_HAVE(out->crv == in->crv);

	fp_mul_monty(&t0, &in->X, &in->X);
	fp_mul_monty(&t1, &in->Y, &in->Y);
	fp_mul_monty(&t2, &in->Z, &in->Z);
	fp_mul_monty(&t3, &in->X, &in->Y);
	fp_add_monty(&t3, &t3, &t3);

	fp_mul_monty(&out->Z, &in->X, &in->Z);
	fp_add_monty(&out->Z, &out->Z, &out->Z);
	fp_mul_monty(&out->X, &in->crv->a_monty, &out->Z);
	fp_mul_monty(&out->Y, &in->crv->b3_monty, &t2);
	fp_add_monty(&out->Y, &out->X, &out->Y);

	fp_sub_monty(&out->X, &t1, &out->Y);
	fp_add_monty(&out->Y, &t1, &out->Y);
	fp_mul_monty(&out->Y, &out->X, &out->Y);
	fp_mul_monty(&out->X, &t3, &out->X);
	fp_mul_monty(&out->Z, &in->crv->b3_monty, &out->Z);

	fp_mul_monty(&t2, &in->crv->a_monty, &t2);
	fp_sub_monty(&t3, &t0, &t2);
	fp_mul_monty(&t3, &in->crv->a_monty, &t3);
	fp_add_monty(&t3, &t3, &out->Z);
	fp_add_monty(&out->Z, &t0, &t0);

	fp_add_monty(&t0, &out->Z, &t0);
	fp_add_monty(&t0, &t0, &t2);
	fp_mul_monty(&t0, &t0, &t3);
	fp_add_monty(&out->Y, &out->Y, &t0);
	fp_mul_monty(&t2, &in->Y, &in->Z);

	fp_add_monty(&t2, &t2, &t2);
	fp_mul_monty(&t0, &t2, &t3);
	fp_sub_monty(&out->X, &out->X, &t0);
	fp_mul_monty(&out->Z, &t2, &t1);
	fp_add_monty(&out->Z, &out->Z, &out->Z);

	fp_add_monty(&out->Z, &out->Z, &out->Z);

	fp_uninit(&t0);
	fp_uninit(&t1);
	fp_uninit(&t2);
	fp_uninit(&t3);
#else
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
#endif
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

#ifndef USE_COMPLETE_FORMULAS
	if (prj_pt_iszero(in)) {
		prj_pt_init(out, in->crv);
		prj_pt_zero(out);
	} else {
		_prj_pt_dbl_monty(out, in);
	}
#else
	_prj_pt_dbl_monty(out, in);
#endif
}

static void _prj_pt_mul_ltr_monty(prj_pt_t out, nn_src_t m, prj_pt_src_t in)
{
	prj_pt dbl;
	bitcnt_t mlen;
	int mbit;

	MUST_HAVE(!nn_iszero(m));

#ifndef USE_COMPLETE_FORMULAS
	/* Case where we do not use the complete formulas.
	 * WARNING: in this case, the MSB of the scalar m is searched, which
	 * can be leaked through a side channel (such as timing). If you are in
	 * a context where side channel attacks matter, do not use incomplete
	 * formulas!
	 */
	MUST_HAVE(!prj_pt_iszero(in));

	prj_pt_copy(out, in);
	prj_pt_init(&dbl, in->crv);

	mlen = nn_bitlen(m) - 1;
#else
	/* When we use complete formulas, perform the double and add always loop in
	 * constant time.
	 */
	prj_pt_copy(out, in);
	/* Initialize dbl to the infinity point */
	prj_pt_init(&dbl, in->crv);
	prj_pt_zero(&dbl);

	mlen = m->wlen * WORD_BITS;

	/* Initialize out to either input point or inifity point
	 * depending on the first bit value
	 */
	mbit = nn_getbit(m, mlen);
	nn_cnd_swap(!mbit, &(out->X.fp_val), &(dbl.X.fp_val));
	nn_cnd_swap(!mbit, &(out->Y.fp_val), &(dbl.Y.fp_val));
	nn_cnd_swap(!mbit, &(out->Z.fp_val), &(dbl.Z.fp_val));
#endif

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

int prj_pt_mul_monty_blind(prj_pt_t out, nn_src_t m, prj_pt_src_t in, nn_t b, nn_src_t q)
{
        /* The projective coordinates blinding mask */
        fp l;
        int ret;
	prj_pt tmp_pt;

        /* Get a random value l in Fp */
        ret = fp_get_random(&l, in->X.ctx);
        if(ret){
		ret = -1;
                goto err;
        }
        /* Blind the point with projective coordinates (X, Y, Z) => (l*X, l*Y, l*Z) 
         */
	prj_pt_init(&tmp_pt, in->crv);
        fp_mul(&(tmp_pt.X), &(in->X), &l);
        fp_mul(&(tmp_pt.Y), &(in->Y), &l);
        fp_mul(&(tmp_pt.Z), &(in->Z), &l);

	/* Blind the scalar m with (b*q) */
	nn_mul(b, b, q);
	nn_add(b, b, m);

        /* Perform the scalar multiplication */
	prj_pt_mul_ltr_monty(out, b, &tmp_pt);

	ret = 0;
err:
	/* Zero the mask to avoid information leak */
	nn_zero(b);
	fp_zero(&l);
	return ret;
}
