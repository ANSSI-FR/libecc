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
#include "../lib_ecc_config.h"
#if defined(WITH_SIG_ECGDSA) && defined(USE_CRYPTOFUZZ)

#include "../nn/nn_rand.h"
#include "../nn/nn_mul.h"
#include "../nn/nn_logical.h"

#include "sig_algs_internal.h"
#include "ec_key.h"
#include "../utils/utils.h"
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECGDSA"
#endif
#include "../utils/dbg_sig.h"

/* NOTE: the following versions of ECGDSA are "raw" with
 * no hash functions and nonce override. They are DANGEROUS and
 * should NOT be used in production mode! They are however useful
 * for corner cases tests and fuzzing.
 */
#define ECGDSA_SIGN_MAGIC ((word_t)(0xe2f60ea3353ecc9eULL))
#define ECGDSA_SIGN_CHECK_INITIALIZED(A) \
        MUST_HAVE((((const void *)(A)) != NULL) && \
                  ((A)->magic == ECGDSA_SIGN_MAGIC))

int ecgdsa_sign_raw(struct ec_sign_context *ctx, const u8 *input, u8 inputlen, u8 *sig, u8 siglen, const u8 *nonce, u8 noncelen)
{
        nn_src_t q, x;
        nn tmp, tmp2, s, e, kr, k, r;
#ifdef USE_SIG_BLINDING
        /* b is the blinding mask */
        nn b, binv;
#endif
	/* NOTE: hash here is not really a hash ... */
	u8 e_buf[BIT_LEN_WORDS(NN_MAX_BIT_LEN) * (WORDSIZE / 8)];
        const ec_priv_key *priv_key;
        prj_pt_src_t G;
        u8 hsize, r_len, s_len, p_len;
        u16 p_len_;
        bitcnt_t q_bit_len, p_bit_len, rshift;
        prj_pt kG;
        aff_pt W;
        int ret;

	/*
	 * First, verify context has been initialized and private
	 * part too. This guarantees the context is an EC-GDSA
	 * signature one and we do not finalize() before init().
	 */
	SIG_SIGN_CHECK_INITIALIZED(ctx);
	ECGDSA_SIGN_CHECK_INITIALIZED(&(ctx->sign_data.ecgdsa));

        /* Zero init points */
        local_memset(&kG, 0, sizeof(prj_pt));

	/* Make things more readable */
	priv_key = &(ctx->key_pair->priv_key);
	G = &(priv_key->params->ec_gen);
	q = &(priv_key->params->ec_gen_order);
	x = &(priv_key->x);
	q_bit_len = priv_key->params->ec_gen_order_bitlen;
	p_bit_len = priv_key->params->ec_fp.p_bitlen;
	p_len = (u8)BYTECEIL(p_bit_len);
	r_len = (u8)ECGDSA_R_LEN(q_bit_len);
	s_len = (u8)ECGDSA_S_LEN(q_bit_len);
	hsize = inputlen;

	if (siglen != ECGDSA_SIGLEN(q_bit_len)) {
		ret = -1;
		goto err;
	}

	p_len_ = p_len;
	if (p_len_ > NN_MAX_BYTE_LEN) {
		ret = -1;
		goto err;
	}

	dbg_nn_print("p", &(priv_key->params->ec_fp.p));
	dbg_nn_print("q", q);
	dbg_priv_key_print("x", priv_key);
	dbg_ec_point_print("G", G);
	dbg_pub_key_print("Y", &(ctx->key_pair->pub_key));

	/* 1. Compute h = H(m) */
        /* NOTE: here we have raw ECGDSA, this is the raw input */
        if((input == NULL) || (inputlen > sizeof(e_buf))){
                ret = -1;
                goto err;
        }
        local_memset(e_buf, 0, sizeof(e_buf));
        local_memcpy(e_buf, input, hsize);
	dbg_buf_print("H(m)", e_buf, hsize);

        /*
         * If |h| > bitlen(q), set h to bitlen(q)
         * leftmost bits of h.
         *
         */
        rshift = 0;
        if ((hsize * 8) > q_bit_len) {
                rshift = (hsize * 8) - q_bit_len;
        }
        nn_init_from_buf(&tmp, e_buf, hsize);
        local_memset(e_buf, 0, hsize);
        if (rshift) {
                nn_rshift_fixedlen(&tmp, &tmp, rshift);
        }
        dbg_nn_print("H(m) truncated as nn", &tmp);

	/*
	 * 2. Convert h to an integer and then compute e = -h mod q,
	 *    i.e. compute e = - OS2I(h) mod q
	 *
	 * Because we only support positive integers, we compute
	 * e = q - (h mod q) (except when h is 0).
	 */
	nn_mod(&tmp2, &tmp, q);
	if (nn_iszero(&tmp2)) {
		nn_init(&e, 0);
		nn_zero(&e);
	} else {
		nn_sub(&e, q, &tmp2);
	}

/*
     NOTE: the restart label is removed in CRYPTOFUZZ mode as
     we trigger MUST_HAVE instead of restarting in this mode.
 restart:
*/
	/* 3. Get a random value k in ]0,q[ */
        /* NOTE: copy our input nonce if not NULL */
        if(nonce != NULL){
                if(noncelen > (u8)(BYTECEIL(q_bit_len))){
                        ret = -1;
                }
                else{
                        nn_init_from_buf(&k, nonce, noncelen);
                        ret = 0;
                }
        }
        else{
                ret = ctx->rand(&k, q);
        }
	if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&tmp);
		nn_uninit(&e);
		ret = -1;
		goto err;
	}

#ifdef USE_SIG_BLINDING
        /* Note: if we use blinding, e and e are multiplied by
         * a random value b in ]0,q[ */
        ret = nn_get_random_mod(&b, q);
        if (ret) {
		nn_uninit(&tmp2);
		nn_uninit(&tmp);
		nn_uninit(&e);
		ret = -1;
                goto err;
        }
        dbg_nn_print("b", &b);
#endif /* USE_SIG_BLINDING */


	/* 4. Compute W = kG = (Wx, Wy) */
#ifdef USE_SIG_BLINDING
        /* We use blinding for the scalar multiplication */
        if(prj_pt_mul_monty_blind(&kG, &k, G)){
		ret = -1;
		goto err;
	}
#else
        prj_pt_mul_monty(&kG, &k, G);
#endif /* USE_SIG_BLINDING */
	prj_pt_to_aff(&W, &kG);
	prj_pt_uninit(&kG);

	dbg_nn_print("W_x", &(W.x.fp_val));
	dbg_nn_print("W_y", &(W.y.fp_val));

	/* 5. Compute r = Wx mod q */
	nn_mod(&r, &(W.x.fp_val), q);
	aff_pt_uninit(&W);
	dbg_nn_print("r", &r);

	/* 6. If r is 0, restart the process at step 4. */
        /* NOTE: for the CRYPTOFUZZ mode, we do not restart
         * the procedure but throw an assert exception instead.
         */
        MUST_HAVE(!nn_iszero(&r));

	/* Export r */
	nn_export_to_buf(sig, r_len, &r);

#ifdef USE_SIG_BLINDING
	/* Blind e and r with b */
	nn_mul_mod(&e, &e, &b, q);
	nn_mul_mod(&r, &r, &b, q);
#endif /* USE_SIG_BLINDING */
	/* 7. Compute s = x(kr + e) mod q */
	nn_mul_mod(&kr, &k, &r, q);
	nn_uninit(&k);
	nn_mod_add(&tmp2, &kr, &e, q);
	nn_uninit(&kr);
	nn_uninit(&e);
	nn_uninit(&tmp);
	nn_mul_mod(&s, x, &tmp2, q);
	nn_uninit(&tmp2);
#ifdef USE_SIG_BLINDING
	/* Unblind s */
	nn_modinv(&binv, &b, q);
	nn_mul_mod(&s, &s, &binv, q);
#endif
	dbg_nn_print("s", &s);

	/* 8. If s is 0, restart the process at step 4. */
        /* NOTE: for the CRYPTOFUZZ mode, we do not restart
         * the procedure but throw an assert exception instead.
         */
        MUST_HAVE(!nn_iszero(&s));

	/* 9. Return (r,s) */
	nn_export_to_buf(sig + r_len, s_len, &s);

	nn_uninit(&r);
	nn_uninit(&s);

	ret = 0;

 err:

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->sign_data.ecgdsa), 0, sizeof(ecgdsa_sign_data));

	/* Clean what remains on the stack */
	VAR_ZEROIFY(q_bit_len);
	VAR_ZEROIFY(p_bit_len);
	VAR_ZEROIFY(r_len);
	VAR_ZEROIFY(s_len);
	VAR_ZEROIFY(p_len);
	VAR_ZEROIFY(hsize);
	PTR_NULLIFY(q);
	PTR_NULLIFY(x);
	PTR_NULLIFY(priv_key);
	PTR_NULLIFY(G);

#ifdef USE_SIG_BLINDING
        if(nn_is_initialized(&b)){
                nn_uninit(&b);
        }
        if(nn_is_initialized(&binv)){
                nn_uninit(&binv);
        }
#endif /* USE_SIG_BLINDING */

	return ret;
}

/******************************/
#define ECGDSA_VERIFY_MAGIC ((word_t)(0xd4da37527288d1b6ULL))
#define ECGDSA_VERIFY_CHECK_INITIALIZED(A) \
        MUST_HAVE((((const void *)(A)) != NULL) && \
                  ((A)->magic == ECGDSA_VERIFY_MAGIC))

int ecgdsa_verify_raw(struct ec_verify_context *ctx, const u8 *input, u8 inputlen)
{
	nn tmp, e, r_prime, rinv, u, v, *r, *s;
	prj_pt uG, vY, Wprime;
	aff_pt Wprime_aff;
	prj_pt_src_t G, Y;
        /* NOTE: hash here is not really a hash ... */
        u8 e_buf[BIT_LEN_WORDS(NN_MAX_BIT_LEN) * (WORDSIZE / 8)];
	nn_src_t q;
	u8 hsize;
        bitcnt_t q_bit_len, rshift;
	int ret;

	/*
	 * First, verify context has been initialized and public
	 * part too. This guarantees the context is an EC-GDSA
	 * verification one and we do not finalize() before init().
	 */
	SIG_VERIFY_CHECK_INITIALIZED(ctx);
	ECGDSA_VERIFY_CHECK_INITIALIZED(&(ctx->verify_data.ecgdsa));

        /* Zero init points */
        local_memset(&uG, 0, sizeof(prj_pt));
        local_memset(&vY, 0, sizeof(prj_pt));

	/* Make things more readable */
	G = &(ctx->pub_key->params->ec_gen);
	Y = &(ctx->pub_key->y);
	q = &(ctx->pub_key->params->ec_gen_order);
	r = &(ctx->verify_data.ecgdsa.r);
	s = &(ctx->verify_data.ecgdsa.s);
        q_bit_len = ctx->pub_key->params->ec_gen_order_bitlen;
	hsize = inputlen;

	/* 2. Compute h = H(m) */
        /* NOTE: here we have raw ECGDSA, this is the raw input */
        if((input == NULL) || (inputlen > sizeof(e_buf))){
                ret = -1;
                goto err;
        }
        local_memset(e_buf, 0, sizeof(e_buf));
        local_memcpy(e_buf, input, hsize);
	dbg_buf_print("H(m)", e_buf, hsize);

        /*
         * If |h| > bitlen(q), set h to bitlen(q)
         * leftmost bits of h.
         *
         */
        rshift = 0;
        if ((hsize * 8) > q_bit_len) {
                rshift = (hsize * 8) - q_bit_len;
        }
        nn_init_from_buf(&tmp, e_buf, hsize);
        local_memset(e_buf, 0, hsize);
        if (rshift) {
                nn_rshift_fixedlen(&tmp, &tmp, rshift);
        }
        dbg_nn_print("H(m) truncated as nn", &tmp);

	/* 3. Compute e by converting h to an integer and reducing it mod q */
	nn_mod(&e, &tmp, q);

	/* 4. Compute u = (r^-1)e mod q */
	nn_modinv(&rinv, r, q);	/* r^-1 */
	nn_mul(&tmp, &rinv, &e);	/* r^-1 * e */
	nn_mod(&u, &tmp, q);	/* (r^-1 * e) mod q */
	nn_uninit(&e);

	/* 5. Compute v = (r^-1)s mod q */
	nn_mul(&tmp, &rinv, s);	/*  r^-1 * s */
	nn_mod(&v, &tmp, q);	/* (r^-1 * s) mod q */
	nn_uninit(&tmp);
	nn_uninit(&rinv);

	/* 6. Compute W' = uG + vY */
	prj_pt_mul_monty(&uG, &u, G);
	prj_pt_mul_monty(&vY, &v, Y);
	prj_pt_add_monty(&Wprime, &uG, &vY);
	nn_uninit(&u);
	nn_uninit(&v);
	prj_pt_uninit(&uG);
	prj_pt_uninit(&vY);

	/* 7. Compute r' = W'_x mod q */
	prj_pt_to_aff(&Wprime_aff, &Wprime);
	prj_pt_uninit(&Wprime);
	dbg_nn_print("W'_x", &(Wprime_aff.x.fp_val));
	dbg_nn_print("W'_y", &(Wprime_aff.y.fp_val));
	nn_mod(&r_prime, &(Wprime_aff.x.fp_val), q);
	aff_pt_uninit(&Wprime_aff);

	/* 8. Accept the signature if and only if r equals r' */
	ret = (nn_cmp(r, &r_prime) != 0) ? -1 : 0;
	nn_uninit(&r_prime);

	/*
	 * We can now clear data part of the context. This will clear
	 * magic and avoid further reuse of the whole context.
	 */
	local_memset(&(ctx->verify_data.ecgdsa), 0,
		     sizeof(ecgdsa_verify_data));

	PTR_NULLIFY(r);
	PTR_NULLIFY(s);
	PTR_NULLIFY(G);
	PTR_NULLIFY(Y);
	PTR_NULLIFY(q);
	VAR_ZEROIFY(hsize);

err:
	return ret;
}


#else /* WITH_SIG_ECGDSA && USE_CRYPTOFUZZ */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECGDSA */
