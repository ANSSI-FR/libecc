/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "rsa.h"
#include "rsa_tests.h"


/* We include the rand external dependency because we have to generate
 * some random data for the padding.
 */
#include "rand.h"
/* We include the printf external dependency for printf output */
#include "print.h"
/* We include our common helpers */
#include "../common/common.h"


/*
 * The purpose of this example is to implement the RSA
 * related algorithms as per RFC 8017 based on libecc arithmetic
 * primitives.
 *
 * XXX: Please be aware that libecc has been designed for Elliptic
 * Curve cryptography, and as so the arithmetic primitives are
 * not optimized for big numbers >= 1024 bits usually used for RSA.
 * Additionnaly, a hard limit of our NN values makes it impossible
 * to exceed ~5300 bits in the best case (words of size 64 bits).
 *
 * All in all, please see this as a proof of concept of implementing
 * RFC 8017 rather than a production code. Use it at your own risk!
 *
 * !! DISCLAIMER !!
 * ================
 * Although some efforts have been put on providing a clean code and although many of
 * the underlying arithmetic primitives are constant time, no particular effort has
 * been deployed to prevent advanced side channels (e.g. to protect the private keys
 * against cache based side-channels and so on). Padding oracles (Bleichenbacher,
 * Manger) in RSA PKCS#1 v1.5 and RSA-OAEP decryption primitives are taken into
 * account, although no guarantee can be made on this (and mostly: these oracles
 * also heavily depend on what the upper layer callers do). Fault injection
 * (e.g. Bellcore attack and so on) are not taken into account.
 *
 * Also, as for all other libecc primitives, beware of randomness sources. By default,
 * the library uses the OS random sources (e.g. "/dev/urandom"), but the user
 * is encouraged to adapt the ../external_deps/rand.c source file to combine
 * multiple sources and add entropy there depending on the context where this
 * code is integrated. The security level of all the cryptographic primitives
 * heavily relies on random sources quality.
 *
 * All-in-all, this piece of code can be useful in some contexts, or risky to
 * use in other sensitive ones where advanced side-channels or fault attacks
 * have to be considered. Use this RSA code knowingly and at your own risk!
 *
 */

int rsa_import_pub_key(rsa_pub_key *pub, const u8 *n,
                       u16 nlen, const u8 *e, u16 elen)
{
	int ret;

	MUST_HAVE((pub != NULL), ret, err);

	/* Import our big numbers */
	ret = nn_init_from_buf(&(pub->n), n, nlen); EG(ret, err);
	ret = nn_init_from_buf(&(pub->e), e, elen);

err:
	if(ret && (pub != NULL)){
		IGNORE_RET_VAL(local_memset(pub, 0, sizeof(rsa_pub_key)));
	}

	return ret;
}

int rsa_import_simple_priv_key(rsa_priv_key *priv,
                               const u8 *n, u16 nlen, const u8 *d, u16 dlen)
{
	int ret;

	MUST_HAVE((priv != NULL), ret, err);

	priv->type = RSA_SIMPLE;
	/* Import our big numbers */
	ret = nn_init_from_buf(&(priv->key.s.n), n, nlen); EG(ret, err);
	ret = nn_init_from_buf(&(priv->key.s.d), d, dlen);

err:
	if(ret && (priv != NULL)){
		IGNORE_RET_VAL(local_memset(priv, 0, sizeof(rsa_priv_key)));
	}

	return ret;
}

int rsa_import_crt_priv_key(rsa_priv_key *priv,
                            const u8 *p, u16 plen,
                            const u8 *q, u16 qlen,
                            const u8 *dP, u16 dPlen,
                            const u8 *dQ, u16 dQlen,
                            const u8 *qInv, u16 qInvlen,
                            const u8 **coeffs, u16 *coeffslens, u8 u)
{
	int ret;

	MUST_HAVE((priv != NULL), ret, err);

	priv->type = RSA_CRT;
	/* Import our big numbers */
	ret = nn_init_from_buf(&(priv->key.crt.p), p, plen); EG(ret, err);
	ret = nn_init_from_buf(&(priv->key.crt.q), q, qlen); EG(ret, err);
	ret = nn_init_from_buf(&(priv->key.crt.dP), dP, dPlen); EG(ret, err);
	ret = nn_init_from_buf(&(priv->key.crt.dQ), dQ, dQlen); EG(ret, err);
	ret = nn_init_from_buf(&(priv->key.crt.qInv), qInv, qInvlen); EG(ret, err);

	priv->key.crt.u = 0;

	/* Import the optional coefficients if necessary */
	if(coeffs != NULL){
		unsigned int i;

		MUST_HAVE((coeffslens != NULL), ret, err);
		MUST_HAVE((u > 0) && (u < MAX_CRT_COEFFS), ret, err);

		priv->key.crt.u = u;

		for(i = 0; i < (3*u); i += 3){
			rsa_priv_key_crt_coeffs *cur = &(priv->key.crt.coeffs[(i / 3)]);

			ret = nn_init_from_buf(&(cur->r), coeffs[i],     coeffslens[i]);     EG(ret, err);
			ret = nn_init_from_buf(&(cur->d), coeffs[i + 1], coeffslens[i + 1]); EG(ret, err);
			ret = nn_init_from_buf(&(cur->t), coeffs[i + 2], coeffslens[i + 2]); EG(ret, err);
		}
	}

err:
	if(ret && (priv != NULL)){
		IGNORE_RET_VAL(local_memset(priv, 0, sizeof(rsa_priv_key)));
	}
	return ret;
}

/* I2OSP - Integer-to-Octet-String primitive
 * (as decribed in section 4.1 of RFC 8017)
 */
int rsa_i2osp(nn_src_t x, u8 *buf, u16 buflen)
{
	return _i2osp(x, buf, buflen);
}

/* OS2IP - Octet-String-to-Integer primitive
 * (as decribed in section 4.2 of RFC 8017)
 */
int rsa_os2ip(nn_t x, const u8 *buf, u16 buflen)
{
	return _os2ip(x, buf, buflen);
}

/* The raw RSAEP function as defined in RFC 8017 section 5.1.1
 *     Input: an RSA public key and a big int message
 *     Output: a big int ciphertext
 *     Assumption:  RSA public key K is valid
 */
int rsaep(const rsa_pub_key *pub, nn_src_t m, nn_t c)
{
	int ret, cmp;
	nn_src_t n, e;

	/* Sanity checks */
	MUST_HAVE((pub != NULL), ret, err);

	/* Make things more readable */
	n = &(pub->n);
	e = &(pub->e);

	/* Sanity checks */
	ret = nn_check_initialized(n); EG(ret, err);
	ret = nn_check_initialized(e); EG(ret, err);

	/* Check that m is indeed in [0, n-1], trigger an error if not */
	MUST_HAVE((!nn_cmp(m, n, &cmp)) && (cmp < 0), ret, err);

	/* Compute c = m^e mod n
	 * NOTE: we use our internal *insecure* modular exponentation as we
	 * are handling public key and data.
	 */
	ret = _nn_mod_pow_insecure(c, m, e, n);

err:
	PTR_NULLIFY(n);
	PTR_NULLIFY(e);

	return ret;
}

/* The raw RSADP function as defined in RFC 8017 section 5.1.2
 *     Input: an RSA private key 'priv' and a big int ciphertext 'c'
 *     Output: a big int clear message 'm'
 *     Assumption:  RSA private key 'priv' is valid
 */
ATTRIBUTE_WARN_UNUSED_RET static int rsadp_crt_coeffs(const rsa_priv_key *priv, nn_src_t c, nn_t m, u8 u)
{
	int ret;
	unsigned int i;
	nn_src_t r_i, d_i, t_i, r_i_1;
	nn m_i, h, R;
	m_i.magic = h.magic = R.magic = WORD(0);

	/* Sanity check on u */
	MUST_HAVE((u < MAX_CRT_COEFFS), ret, err);

	ret = nn_init(&m_i, 0); EG(ret, err);
	ret = nn_init(&h, 0); EG(ret, err);
	ret = nn_init(&R, 0); EG(ret, err);

	/* NOTE: this is an internal function, sanity checks on priv and u have
	 * been performed by the callers.
	 */
	/* R = r_1 */
	ret = nn_copy(&R, &(priv->key.crt.coeffs[0].r)); EG(ret, err);
	/* Loop  */
	for(i = 1; i < u; i++){
		r_i_1 = &(priv->key.crt.coeffs[i-1].r);
		r_i = &(priv->key.crt.coeffs[i].r);
		d_i = &(priv->key.crt.coeffs[i].d);
		t_i = &(priv->key.crt.coeffs[i].t);

		/* Sanity checks */
		ret = nn_check_initialized(r_i_1); EG(ret, err);
		ret = nn_check_initialized(r_i); EG(ret, err);
		ret = nn_check_initialized(d_i); EG(ret, err);
		ret = nn_check_initialized(t_i); EG(ret, err);

		/* m_i = c^(d_i) mod r_i */
		ret = nn_mod_pow(&m_i, c, d_i, r_i); EG(ret, err);
		/* R = R * r_(i-1) */
		ret = nn_mul(&R, &R, r_i_1); EG(ret, err);
		/*  h = (m_i - m) * t_i mod r_i */
		ret = nn_mod(&h, m, r_i); EG(ret, err);
		ret = nn_mod_sub(&h, &m_i, &h, r_i); EG(ret, err);
		ret = nn_mod_mul(&h, &h, t_i, r_i); EG(ret, err);
		/* m = m + R * h */
		ret = nn_mul(&h, &R, &h); EG(ret, err);
		ret = nn_add(m, m, &h); EG(ret, err);
	}

err:
	nn_uninit(&m_i);
	nn_uninit(&h);
	nn_uninit(&R);

	PTR_NULLIFY(r_i);
	PTR_NULLIFY(d_i);
	PTR_NULLIFY(t_i);
	PTR_NULLIFY(r_i_1);

	return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int rsadp_crt(const rsa_priv_key *priv, nn_src_t c, nn_t m)
{
	int ret;
	nn_src_t p, q, dP, dQ, qInv;
	nn m_1, m_2, h;
	u8 u;
	m_1.magic = m_2.magic = h.magic = WORD(0);

	ret = nn_init(&m_1, 0); EG(ret, err);
	ret = nn_init(&m_2, 0); EG(ret, err);
	ret = nn_init(&h, 0); EG(ret, err);

	/* Make things more readable */
	p    = &(priv->key.crt.p);
	q    = &(priv->key.crt.q);
	dP   = &(priv->key.crt.dP);
	dQ   = &(priv->key.crt.dQ);
	qInv = &(priv->key.crt.qInv);
	u    = priv->key.crt.u;

	/* Sanity checks */
	ret = nn_check_initialized(p); EG(ret, err);
	ret = nn_check_initialized(q); EG(ret, err);
	ret = nn_check_initialized(dP); EG(ret, err);
	ret = nn_check_initialized(dQ); EG(ret, err);
	ret = nn_check_initialized(qInv); EG(ret, err);

	/* m_1 = c^dP mod p */
	ret = nn_mod_pow(&m_1, c, dP, p); EG(ret, err);
	/* m_2 = c^dQ mod q */
	ret = nn_mod_pow(&m_2, c, dQ, q); EG(ret, err);
	/* h = (m_1 - m_2) * qInv mod p */
	ret = nn_mod(&h, &m_2, p); EG(ret, err);
	ret = nn_mod_sub(&h, &m_1, &h, p); EG(ret, err);
	ret = nn_mod_mul(&h, &h, qInv, p); EG(ret, err);
	/* m = m_2 + q * h */
	ret = nn_mul(m, &h, q); EG(ret, err);
	ret = nn_add(m, &m_2, m); EG(ret, err);

	if(u > 1){
		ret = rsadp_crt_coeffs(priv, c, m, u);
	}

err:
	nn_uninit(&m_1);
	nn_uninit(&m_2);
	nn_uninit(&h);

	PTR_NULLIFY(p);
	PTR_NULLIFY(q);
	PTR_NULLIFY(dP);
	PTR_NULLIFY(dQ);
	PTR_NULLIFY(qInv);

	return ret;
}

int rsadp(const rsa_priv_key *priv, nn_src_t c, nn_t m)
{
	int ret, cmp;

	/* Sanity checks */
	MUST_HAVE((priv != NULL), ret, err);

	/* Do we have a simple or a CRT key? */
	if(priv->type == RSA_SIMPLE){
		nn_src_t n, d;
		/* Make things more readable */
		n = &(priv->key.s.n);
		d = &(priv->key.s.d);
		/* Sanity checks */
		ret = nn_check_initialized(n); EG(ret, err);
		ret = nn_check_initialized(d); EG(ret, err);
		/* Check that c is indeed in [0, n-1], trigger an error if not */
		MUST_HAVE((!nn_cmp(c, n, &cmp)) && (cmp < 0), ret, err1);
		/* Compute m = c^d mod n */
		ret = nn_mod_pow(m, c, d, n); EG(ret, err1);
err1:
		PTR_NULLIFY(n);
		PTR_NULLIFY(d);
	}
	else if(priv->type == RSA_CRT){
		ret = rsadp_crt(priv, c, m); EG(ret, err);
	}
	else{
		ret = -1;
		goto err;
	}

err:
	return ret;
}

/* The raw RSASP1 function as defined in RFC 8017 section 5.2.1
 *     Input: an RSA private key 'priv' and a big int message 'm'
 *     Output: a big int signature 's'
 *     Assumption:  RSA private key 'priv' is valid
 */
int rsasp1(const rsa_priv_key *priv, nn_src_t m, nn_t s)
{
	return rsadp(priv, m, s);
}



/* The raw RSAVP1 function as defined in RFC 8017 section 5.2.2
 *     Input: an RSA public key 'pub' and a big int signature 's'
 *     Output: a big int ciphertext 'm'
 *     Assumption:  RSA public key 'pub' is valid
 */
int rsavp1(const rsa_pub_key *pub, nn_src_t s, nn_t m)
{
	return rsaep(pub, s, m);
}

ATTRIBUTE_WARN_UNUSED_RET static int rsa_digestinfo_from_hash(gen_hash_alg_type gen_hash_type, u8 *digestinfo, u32 *digestinfo_len)
{
	int ret;

	/* Sanity check */
	MUST_HAVE((digestinfo_len != NULL), ret, err);

	switch(gen_hash_type){
		case HASH_MD2:{
			const u8 _digestinfo[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a,
						   0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02,
						   0x05, 0x00, 0x04, 0x10 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_MD4:{
			const u8 _digestinfo[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a,
						   0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04,
						   0x05, 0x00, 0x04, 0x10 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_MD5:{
			const u8 _digestinfo[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a,
						   0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
						   0x05, 0x00, 0x04, 0x10 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA1:{
			const u8 _digestinfo[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
						   0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
						   0x14 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA224:{
			const u8 _digestinfo[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x04, 0x05, 0x00, 0x04, 0x1c };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA256:{
			const u8 _digestinfo[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x01, 0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA384:{
			const u8 _digestinfo[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x02, 0x05, 0x00, 0x04, 0x30 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA512:{
			const u8 _digestinfo[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x03, 0x05, 0x00, 0x04, 0x40 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA512_224:{
			const u8 _digestinfo[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x05, 0x05, 0x00, 0x04, 0x1c };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA512_256:{
			const u8 _digestinfo[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x06, 0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_RIPEMD160:{
			const u8 _digestinfo[] = { 0x30, 0x21, 0x30, 0x0d, 0x06, 0x09, 0x2b,
						   0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04,
						   0x14 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		/* The following SHA-3 oids have been taken from
		 *     https://www.ietf.org/archive/id/draft-jivsov-openpgp-sha3-01.txt
		 *
		 * The specific case of SHA3-224 is infered from the OID of SHA3-224 although
		 * not standardized.
		 */
		case HASH_SHA3_224:{
			const u8 _digestinfo[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x07, 0x05, 0x00, 0x04, 0x1c };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA3_256:{
			const u8 _digestinfo[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x08, 0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA3_384:{
			const u8 _digestinfo[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x09, 0x05, 0x00, 0x04, 0x30 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case HASH_SHA3_512:{
			const u8 _digestinfo[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x0a ,0x05, 0x00, 0x04, 0x40 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		/* For SM3, the "RSA Signing with SM3" OID is taken from:
		 *     http://gmssl.org/docs/oid.html
		 */
		case HASH_SM3:{
			const u8 _digestinfo[] = { 0x30, 0x30, 0x30, 0x0d, 0x06, 0x08, 0x2A,
						   0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78,
						   0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		default:{
			ret = -1;
			goto err;
		}
	}

err:
	return ret;
}

/* GF1 as a mask generation function as described in RFC 8017 Appendix B.2.1
 *     z is the 'seed', and zlen its length
 */
ATTRIBUTE_WARN_UNUSED_RET static int _mgf1(const u8 *z, u16 zlen,
					   u8 *mask, u64 masklen,
					   gen_hash_alg_type mgf_hash_type)
{
	int ret;
	u8 hlen, block_size;
	u32 c, ceil;
	u8 C[4];
	const u8 *input[3] = { z, C, NULL };
	u32 ilens[3] = { zlen, 4, 0 };
	u8 digest[MAX_DIGEST_SIZE];

	/* Zeroize local variables */
	ret = local_memset(C, 0, sizeof(C)); EG(ret, err);
	ret = local_memset(digest, 0, sizeof(digest)); EG(ret, err);

	/* Sanity checks */
	MUST_HAVE((z != NULL) && (mask != NULL), ret, err);

	ret = gen_hash_get_hash_sizes(mgf_hash_type, &hlen, &block_size); EG(ret, err);
	MUST_HAVE((hlen <= MAX_DIGEST_SIZE), ret, err);

	/* masklen must be < 2**32 * hlen */
	MUST_HAVE((masklen < ((u64)hlen * ((u64)0x1 << 32))), ret, err);
	ceil = (u32)(masklen / hlen) + !!(masklen % hlen);

	for(c = 0; c < ceil; c++){
		/* 3.A: C = I2OSP (counter, 4) */
		C[0] = ((c >> 24) & 0xff);
		C[1] = ((c >> 16) & 0xff);
		C[2] = ((c >>  8) & 0xff);
		C[3] = ((c >>  0) & 0xff);

		/* 3.B + 4. */
		if ((masklen % hlen) && (c == (ceil - 1))) { /* need last chunk smaller than hlen */
			ret = gen_hash_hfunc_scattered(input, ilens, digest, mgf_hash_type); EG(ret, err);
			ret = local_memcpy(&mask[c * hlen], digest, masklen % hlen); EG(ret, err);
		} else {                                     /* common case, i.e. complete chunk */
			ret = gen_hash_hfunc_scattered(input, ilens, &mask[c * hlen], mgf_hash_type); EG(ret, err);
		}
	}
err:
	return ret;
}

/* EMSA-PSS-ENCODE encoding as described in RFC 8017 section 9.1.1
 * NOTE: we enforce MGF1 as a mask generation function
 */
int emsa_pss_encode(const u8 *m, u16 mlen, u8 *em, u32 embits,
                    u16 *eminlen, gen_hash_alg_type gen_hash_type, gen_hash_alg_type mgf_hash_type,
                    u16 slen, const u8 *forced_salt)
{
	int ret;
	u8 hlen, block_size;
	u8 mhash[MAX_DIGEST_SIZE];
	u8 h[MAX_DIGEST_SIZE];
	u8 zeroes[8];
	/* Reasonable sizes:
	 * NOTE: for the cases where the salt exceeds this size, we return an error
	 * alhough this should not happen if our underlying libecc supports the current
	 * modulus size.
	 */
	u8 salt[NN_USABLE_MAX_BYTE_LEN];
	u8 *dbmask = em;
	const u8 *input[2] = { m, NULL };
	u32 ilens[2] = { mlen, 0 };
	u32 emlen, dblen, pslen;
	unsigned int i;
	u8 mask;
	const u8 *input_[4] = { zeroes, mhash, salt, NULL };
	u32 ilens_[4];

	/* Zeroize local variables */
	ret = local_memset(mhash, 0, sizeof(mhash)); EG(ret, err);
	ret = local_memset(h, 0, sizeof(h)); EG(ret, err);
	ret = local_memset(salt, 0, sizeof(salt)); EG(ret, err);
	ret = local_memset(zeroes, 0, sizeof(zeroes)); EG(ret, err);
	ret = local_memset(ilens_, 0, sizeof(ilens_)); EG(ret, err);

	/* Sanity checks */
	MUST_HAVE((m != NULL) && (em != NULL) && (eminlen != NULL), ret, err);

	/* We only allow salt up to a certain size */
	MUST_HAVE((slen <= sizeof(salt)), ret, err);
	emlen = BYTECEIL(embits);
	MUST_HAVE((emlen < (u32)(0x1 << 16)), ret, err);

	/* Check that we have enough room for the output */
	MUST_HAVE(((*eminlen) >= emlen), ret, err);

	/* Get the used hash information */
	ret = gen_hash_get_hash_sizes(gen_hash_type, &hlen, &block_size); EG(ret, err);
	MUST_HAVE((hlen <= MAX_DIGEST_SIZE), ret, err);

	/* emBits at least 8hLen + 8sLen + 9 */
	MUST_HAVE((embits >= ((8*(u32)hlen) + (8*(u32)slen) + 9)), ret, err);

	/*  If emLen < hLen + sLen + 2, output "encoding error" and stop. */
	MUST_HAVE((emlen >= ((u32)hlen + (u32)slen + 2)), ret, err);

	/* mHash = Hash(M) */
	ret = gen_hash_hfunc_scattered(input, ilens, mhash, gen_hash_type); EG(ret, err);

	/*  Generate a random octet string salt of length sLen; if sLen = 0
	 *  then salt is the empty string.
	 *  M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	 *  H = Hash(M'),
	 */
	if(forced_salt != NULL){
		/* We are given a forced salt, use it */
		ret = local_memcpy(salt, forced_salt, slen); EG(ret, err);
	}
	else{
		/* Get random salt */
		ret = get_random(salt, slen); EG(ret, err);
	}
	ilens_[0] = sizeof(zeroes);
	ilens_[1] = hlen;
	ilens_[2] = slen;
	ilens_[3] = 0;
	ret = gen_hash_hfunc_scattered(input_, ilens_, h, gen_hash_type); EG(ret, err);

	/* dbMask = MGF(H, emLen - hLen - 1)
	 * NOTE: dbmask points to &em[0]
	 */
	dblen = (emlen - hlen - 1);
	pslen = (dblen - slen - 1); /* padding string PS len */
	ret = _mgf1(h, hlen, dbmask, dblen, mgf_hash_type); EG(ret, err);

        /*
         * maskedb = (PS || 0x01 || salt) xor dbmask. We compute maskeddb directly
         * in dbmask.
         */

        /* 1) PS is made of 0 so xoring it with first pslen bytes of dbmask is a NOP */

        /*
         * 2) the byte after padding string is 0x01. Do the xor with the associated
         *    byte in dbmask
         */
        dbmask[pslen] ^= 0x01;

        /* 3) xor the salt with the end of dbmask */
        for (i = 0; i < slen; i++){
                dbmask[dblen - slen + i] ^= salt[i];
        }

	/* Set the leftmost 8emLen - emBits bits of the leftmost octet
	 * in maskedDB to zero.
	 */
	mask = 0;
	for(i = 0; i < (8 - ((8*emlen) - embits)); i++){
		mask |= (0x1 << i);
	}
	dbmask[0] &= mask;
	/* EM = maskedDB || H || 0xbc */
	ret = local_memcpy(&em[dblen], h, hlen); EG(ret, err);
	em[emlen - 1] = 0xbc;
	(*eminlen) = (u16)emlen;

err:
	return ret;
}

/* EMSA-PSS-VERIFY verification as described in RFC 8017 section 9.1.2
 * NOTE: we enforce MGF1 as a mask generation function
 */
int emsa_pss_verify(const u8 *m, u16 mlen, const u8 *em,
                    u32 embits, u16 emlen,
		    gen_hash_alg_type gen_hash_type, gen_hash_alg_type mgf_hash_type,
                    u16 slen)
{
	int ret, cmp;
	u8 hlen, block_size;
	u8 mhash[MAX_DIGEST_SIZE];
	u8 h_[MAX_DIGEST_SIZE];
	u8 zeroes[8];
	const u8 *input[2] = { m, NULL };
	u32 ilens[2] = { mlen, 0 };
	unsigned int i;
	u8 mask;
	u16 _emlen;
	/*
	 * NOTE: the NN_USABLE_MAX_BYTE_LEN should be a reasonable size here.
	 */
	u8 dbmask[NN_USABLE_MAX_BYTE_LEN];
	u8 *db;
	const u8 *h, *salt, *maskeddb = em;
	u32 dblen;
	const u8 *input_[4];
	u32 ilens_[4];

	/* Zeroize local variables */
	ret = local_memset(mhash, 0, sizeof(mhash)); EG(ret, err);
	ret = local_memset(h_, 0, sizeof(h_)); EG(ret, err);
	ret = local_memset(dbmask, 0, sizeof(dbmask)); EG(ret, err);
	ret = local_memset(zeroes, 0, sizeof(zeroes)); EG(ret, err);
	ret = local_memset(input_, 0, sizeof(input_)); EG(ret, err);
	ret = local_memset(ilens_, 0, sizeof(ilens_)); EG(ret, err);

	/* Sanity checks */
	MUST_HAVE((m != NULL) && (em != NULL), ret, err);

	/* Get the used hash information */
	ret = gen_hash_get_hash_sizes(gen_hash_type, &hlen, &block_size); EG(ret, err);
	MUST_HAVE((hlen <= MAX_DIGEST_SIZE), ret, err);

	/* Let mHash = Hash(M), an octet string of length hLen */
	ret = gen_hash_hfunc_scattered(input, ilens, mhash, gen_hash_type); EG(ret, err);

	/* emBits at least 8hLen + 8sLen + 9 */
	MUST_HAVE((embits >= ((8*(u32)hlen) + (8*(u32)slen) + 9)), ret, err);

	/* Check that emLen == \ceil(emBits/8) */
	MUST_HAVE((((embits / 8) + 1) < (u32)(0x1 << 16)), ret, err);
	_emlen = ((embits % 8) == 0) ? (u16)(embits / 8) : (u16)((embits / 8) + 1);
	MUST_HAVE((_emlen == emlen), ret, err);

	/* If emLen < hLen + sLen + 2, output "inconsistent" and stop */
	MUST_HAVE((emlen >= ((u32)hlen + (u32)slen + 2)), ret, err);

	/* If the rightmost octet of EM does not have hexadecimal value 0xbc, output "inconsistent" and stop */
	MUST_HAVE((em[emlen - 1] == 0xbc), ret, err);

	/* If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are not all equal to zero,
	 * output "inconsistent" and stop
	 * NOTE: maskeddb points to &em[0]
	 */
	mask = 0;
	for(i = 0; i < (8 - ((8*emlen) - embits)); i++){
		mask |= (0x1 << i);
	}
	MUST_HAVE(((maskeddb[0] & (~mask)) == 0), ret, err);

	/* dbMask = MGF(H, emLen - hLen - 1) */
	dblen = (emlen - hlen - 1);
	h = &em[dblen];
	MUST_HAVE(((u16)dblen <= sizeof(dbmask)), ret, err); /* sanity check for overflow */
	ret = _mgf1(h, hlen, dbmask, dblen, mgf_hash_type); EG(ret, err);
	/* DB = maskedDB \xor dbMask */
	db = &dbmask[0];
	for(i = 0; i < (u16)dblen; i++){
		db[i] = (dbmask[i] ^ maskeddb[i]);
	}
	/* Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero */
	db[0] &= mask;

	/*
	 * If the emLen - hLen - sLen - 2 leftmost octets of DB are not
         * zero or if the octet at position emLen - hLen - sLen - 1 (the
         * leftmost position is "position 1") does not have hexadecimal
         * value 0x01, output "inconsistent" and stop.
	 */
	for(i = 0; i < (u16)(dblen - slen - 1); i++){
		MUST_HAVE((db[i] == 0x00), ret, err);
	}
	MUST_HAVE((db[dblen - slen - 1] == 0x01), ret, err);

	/* Let salt be the last sLen octets of DB */
	salt = &db[dblen - slen];
	/*
	 * Let H' = Hash(M'), an octet string of length hLen with
	 *     M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 */
	/* Fill input_ */
	input_[0] = zeroes;
	input_[1] = mhash;
	input_[2] = salt;
	input_[3] = NULL;
	/* Fill ilens_ */
	ilens_[0] = sizeof(zeroes);
	ilens_[1] = hlen;
	ilens_[2] = slen;
	ilens_[3] = 0;
	/* Hash */
	ret = gen_hash_hfunc_scattered(input_, ilens_, h_, gen_hash_type); EG(ret, err);

	/* If H = H', output "consistent".  Otherwise, output "inconsistent" */
	ret = are_equal(h, h_, hlen, &cmp); EG(ret, err);
	if(!cmp){
		ret = -1;
	}

err:
	return ret;
}

/* EMSA-PKCS1-v1_5 encoding as described in RFC 8017 section 9.2
 */
int emsa_pkcs1_v1_5_encode(const u8 *m, u16 mlen, u8 *em, u16 emlen,
                           gen_hash_alg_type gen_hash_type)
{
	int ret;
	const u8 *input[2] = { m, NULL };
	u32 ilens[2] = { mlen, 0 };
	u8 digest_size, block_size;
	u8 digest[MAX_DIGEST_SIZE];
	u32 digestinfo_len = 0;
	u32 tlen = 0;

	/* Zeroize local variables */
	ret = local_memset(digest, 0, sizeof(digest)); EG(ret, err);

	/* Compute H = Hash(M) */
	ret = local_memset(digest, 0, sizeof(digest)); EG(ret, err);
	ret = gen_hash_get_hash_sizes(gen_hash_type, &digest_size, &block_size); EG(ret, err);
	MUST_HAVE((digest_size <= MAX_DIGEST_SIZE), ret, err);
	ret = gen_hash_hfunc_scattered(input, ilens, digest, gen_hash_type); EG(ret, err);

	/* Now encode:
	 *
         *     DigestInfo ::= SEQUENCE {
         *         digestAlgorithm AlgorithmIdentifier,
         *         digest OCTET STRING
         *     }
	 */
	digestinfo_len = emlen;
	/* NOTE: the rsa_digestinfo_from_hash returns the size of DigestInfo *WITHOUT* the
	 * appended raw hash, tlen is the real size of the complete encoded DigestInfo.
	 */
	ret = rsa_digestinfo_from_hash(gen_hash_type, em, &digestinfo_len); EG(ret, err);
	tlen = (digestinfo_len + digest_size);

	/* If emLen < tLen + 11, output "intended encoded message length too short" and stop */
	MUST_HAVE((emlen >= (tlen + 11)), ret, err);

	/* Copy T at the end of em */
	digestinfo_len = emlen;
	ret = rsa_digestinfo_from_hash(gen_hash_type, &em[emlen - tlen], &digestinfo_len); EG(ret, err);
	ret = local_memcpy(&em[emlen - tlen + digestinfo_len], digest, digest_size);

	/*
	 * Format 0x00 || 0x01 || PS || 0x00 before
	 */
	em[0] = 0x00;
	em[1] = 0x01;
	em[emlen - tlen - 1] = 0x00;
	ret = local_memset(&em[2], 0xff, emlen - tlen - 3);

err:
	return ret;
}

/****************************************************************/
/******** Encryption schemes *************************************/
/* The RSAES-PKCS1-V1_5-ENCRYPT algorithm as described in RFC 8017 section 7.2.1
 *
 */
int rsaes_pkcs1_v1_5_encrypt(const rsa_pub_key *pub, const u8 *m, u16 mlen,
                             u8 *c, u16 *clen, u32 modbits,
                             const u8 *forced_seed, u16 seedlen)
{
	int ret;
	u32 k;
	u8 *em = c;
	unsigned int i;
	nn m_, c_;
	m_.magic = c_.magic = WORD(0);

	MUST_HAVE((clen != NULL) && (c != NULL) && (m != NULL), ret, err);

	k = BYTECEIL(modbits);

	/* Check on lengths */
	MUST_HAVE((k >= 11), ret, err);
	MUST_HAVE((mlen <= (k - 11)), ret, err);
	MUST_HAVE(((*clen) >= k), ret, err);

	/* EME-PKCS1-v1_5 encoding EM = 0x00 || 0x02 || PS || 0x00 || M */
	em[0] = 0x00;
	em[1] = 0x02;
	if(forced_seed == NULL){
		for(i = 0; i < (k - mlen - 3); i++){
			u8 rand_byte = 0;
			while (!rand_byte) {
				ret = get_random(&rand_byte, 1); EG(ret, err);
			}
			em[2 + i] = rand_byte;
		}
	}
	else{
		MUST_HAVE((seedlen == (k - mlen - 3)), ret, err);
		/* Check that the forced seed does not contain 0x00 */
		for(i = 0; i < seedlen; i++){
			MUST_HAVE((forced_seed[i] != 0), ret, err);
		}
		ret = local_memcpy(&em[2], forced_seed, seedlen);
	}
	em[k - mlen - 1] = 0x00;
	ret = local_memcpy(&em[k - mlen], m, mlen);

	/* RSA encryption */
	/*   m = OS2IP (EM) */
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);
	ret = rsa_os2ip(&m_, em, (u16)k); EG(ret, err);
	/*   c = RSAEP ((n, e), m) */
	ret = rsaep(pub, &m_, &c_); EG(ret, err);
	/*   C = I2OSP (c, k) */
	ret = rsa_i2osp(&c_, c, (u16)k); EG(ret, err);
	(*clen) = (u16)k;

err:
	nn_uninit(&m_);
	nn_uninit(&c_);
	/* Zeroify in case of error */
	if(ret && (clen != NULL)){
		IGNORE_RET_VAL(local_memset(c, 0, (*clen)));
	}

	return ret;
}

/* The RSAES-PKCS1-V1_5-DECRYPT algorithm as described in RFC 8017 section 7.2.2
 *
 */
int rsaes_pkcs1_v1_5_decrypt(const rsa_priv_key *priv, const u8 *c, u16 clen,
                             u8 *m, u16 *mlen, u32 modbits)
{
	int ret;
	unsigned int i, pos;
	u32 k;
	u8 r;
	u8 *em = m;
	nn m_, c_;
	m_.magic = c_.magic = WORD(0);

	MUST_HAVE((mlen != NULL) && (c != NULL) && (m != NULL), ret, err);

	k = BYTECEIL(modbits);

	/* Check on lengths */
	MUST_HAVE((clen == k) && (k >= 11), ret, err);
	MUST_HAVE(((*mlen) >= k), ret, err);

	/* RSA decryption */
	/*   c = OS2IP (C) */
	ret = rsa_os2ip(&c_, c, clen); EG(ret, err);
	/*   m = RSADP ((n, d), c) */
	ret = rsadp(priv, &c_, &m_); EG(ret, err);
	/*   EM = I2OSP (m, k) */
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);
	ret = rsa_i2osp(&m_, em, (u16)k); EG(ret, err);

	/* EME-PKCS1-v1_5 decoding: EM = 0x00 || 0x02 || PS || 0x00 || M */
	/* NOTE: we try our best to do the following in constant time to
	 * limit padding oracles here (see Bleichenbacher attacks).
	 */
	ret = !((em[0] == 0x00) && (em[1] == 0x02));
	pos = 0;
	/* Handle the first zero octet after PS in constant time */
	for(i = 2; i < k; i++){
		pos = ((em[i] == 0x00) && (pos == 0)) ? i : pos;
	}
	ret |= !(pos >= (2 + 8)); /* PS length is at least 8 (also implying we found a 0x00) */
	pos = (pos == 0) ? pos : (pos + 1);
	/* We get a random value between 2 and k if we have an error so that
	 * we put a random value in pos.
	 */
        ret |= get_random((u8*)&i, 4);
	/* Get a random value r for later loop dummy operations */
	ret |= get_random(&r, 1);
	/* Update pos with random value in case of error to progress
	 * nominally with the algorithm
	 */
	pos = (ret) ? ((i % (k - 2)) + 2) : pos;
	for(i = 2; i < k; i++){
		u8 r_;
		unsigned int idx;
		/* Replace m by a random value in case of error */
		idx = ((i < pos) ? 0x00 : (i - pos));
		r ^= (u8)i;
		r_ = ((u8)(!!ret) * r);
		m[idx] = (em[i] ^ r_);
	}
	(*mlen) = (u16)(k - pos);
	/* Hide return value details to avoid information leak */
	ret = -(!!ret);

err:
	nn_uninit(&m_);
	nn_uninit(&c_);

	return ret;
}

/* The RSAES-OAEP-ENCRYPT algorithm as described in RFC 8017 section 7.1.1
 *
 */
int rsaes_oaep_encrypt(const rsa_pub_key *pub, const u8 *m, u16 mlen,
                       u8 *c, u16 *clen, u32 modbits, const u8 *label, u16 label_len,
                       gen_hash_alg_type gen_hash_type, gen_hash_alg_type mgf_hash_type,
		       const u8 *forced_seed, u16 seedlen)
{
	int ret;
	u32 k, pslen, khlen;
	unsigned int i;
	u8 hlen, block_size;
	u8 *em = c;
	/* Reasonable sizes */
	u8 seed[MAX_DIGEST_SIZE];
        /*
         * NOTE: the NN_USABLE_MAX_BYTE_LEN should be a reasonable size here.
         */
	u8 dbmask[NN_USABLE_MAX_BYTE_LEN];
	u8 db[NN_USABLE_MAX_BYTE_LEN];
	u8 *seedmask = dbmask, *maskedseed = NULL, *maskeddb = NULL;
	const u8 *input[2] = { c, NULL };
	u32 ilens[2] = { 0, 0 };
	nn m_, c_;
	m_.magic = c_.magic = WORD(0);

	/* Zeroize local variables */
	ret = local_memset(seed, 0, sizeof(seed)); EG(ret, err);
	ret = local_memset(db, 0, sizeof(db)); EG(ret, err);
	ret = local_memset(dbmask, 0, sizeof(dbmask)); EG(ret, err);

	MUST_HAVE((clen != NULL) && (c != NULL) && (m != NULL), ret, err);

	k = BYTECEIL(modbits);

	ret = gen_hash_get_hash_sizes(gen_hash_type, &hlen, &block_size); EG(ret, err);
	MUST_HAVE((hlen <= MAX_DIGEST_SIZE), ret, err);

	/* Check on lengths */
	MUST_HAVE(((u32)k >= ((2 * (u32)hlen) + 2)), ret, err);
	MUST_HAVE(((mlen ) <= ((u32)k - (2 * (u32)hlen) - 2)), ret, err);
	MUST_HAVE(((*clen) >= k), ret, err);

	/* EME-OAEP encoding: DB = lHash || PS || 0x01 || M */
	/* and then EM = 0x00 || maskedSeed || maskedDB */
	maskedseed = &em[1];
	maskeddb   = &em[hlen + 1];
	MUST_HAVE(((k - hlen - 1) <= sizeof(db)), ret, err);
	if(label == NULL){
		MUST_HAVE((label_len == 0), ret, err);
	}
	else{
		input[0] = label;
		ilens[0] = label_len;
	}
	ret = gen_hash_hfunc_scattered(input, ilens, &db[0], gen_hash_type); EG(ret, err);
	/*
	 * 2.b. Generate a padding string PS consisting of k - mLen - 2hLen -
	 * 2 zero octets. The length of PS may be zero.
	 *
	 * DB = lHash || PS || 0x01 || M. Hence, PS starts at octet hlen in DB
	 */
	pslen = (k - mlen - (2 * hlen) - 2);
	for(i = 0; i < pslen; i++){
		db[hlen + i] = 0x00;
	}
	/* 0x01 || M */
	db[hlen + pslen] = 0x01;
	for(i = 0 ; i < mlen; i++){
		db[hlen + pslen + 1 + i] = m[i];
	}
	/* Generate a random octet string seed of length hLen */
	MUST_HAVE((hlen <= sizeof(seed)), ret, err);
	if(forced_seed != NULL){
		MUST_HAVE((seedlen == hlen), ret, err);
		ret = local_memcpy(seed, forced_seed, seedlen); EG(ret, err);
	}
	else{
		ret = get_random(seed, hlen); EG(ret, err);
	}
	/* Let dbMask = MGF(seed, k - hLen - 1)*/
	khlen = (k - hlen - 1);
	MUST_HAVE((khlen <= sizeof(dbmask)), ret, err);
	ret = _mgf1(seed, hlen, dbmask, khlen, mgf_hash_type); EG(ret, err);
	/* Let maskedDB = DB \xor dbMask */
	for(i = 0; i < khlen; i++){
		maskeddb[i] = (db[i] ^ dbmask[i]);
	}
	/* Let seedMask = MGF(maskedDB, hLen) */
	MUST_HAVE((khlen < (u32)(0x1 << 16)), ret, err);
	ret = _mgf1(maskeddb, (u16)khlen, seedmask, hlen, mgf_hash_type); EG(ret, err);
	/* Let maskedSeed = seed \xor seedMask */
	for(i = 0; i < hlen; i++){
		maskedseed[i] = (seed[i] ^ seedmask[i]);
	}
	/* EM = 0x00 || maskedSeed || maskedDB should be filled */
	em[0] = 0x00;

	/* RSA encryption */
	/*   m = OS2IP (EM) */
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);
	ret = rsa_os2ip(&m_, em, (u16)k); EG(ret, err);
	/*   c = RSAEP ((n, e), m) */
	ret = rsaep(pub, &m_, &c_); EG(ret, err);
	/*   C = I2OSP (c, k) */
	ret = rsa_i2osp(&c_, c, (u16)k); EG(ret, err);
	(*clen) = (u16)k;

err:
	nn_uninit(&m_);
	nn_uninit(&c_);
	/* Zeroify in case of error */
	if(ret && (clen != NULL)){
		IGNORE_RET_VAL(local_memset(c, 0, (*clen)));
	}

	return ret;
}

/* The RSAES-OAEP-DECRYPT algorithm as described in RFC 8017 section 7.1.2
 *
 */
int rsaes_oaep_decrypt(const rsa_priv_key *priv, const u8 *c, u16 clen,
                       u8 *m, u16 *mlen, u32 modbits,
                       const u8 *label, u16 label_len, gen_hash_alg_type gen_hash_type,
		       gen_hash_alg_type mgf_hash_type)
{
	int ret, cmp;
	u32 k, khlen;
	unsigned int i, pos;
	u8 hlen, block_size;
	u8 *em = m;
	u8 r;
	/* Reasonable sizes */
	u8 lhash[MAX_DIGEST_SIZE];
	u8 seedmask[MAX_DIGEST_SIZE];
        /*
         * NOTE: the NN_USABLE_MAX_BYTE_LEN should be a reasonable size here.
         */
	u8 dbmask[NN_USABLE_MAX_BYTE_LEN];
	u8 *seed = seedmask, *maskedseed = NULL, *maskeddb = NULL, *db = NULL;
	const u8 *input[2] = { c, NULL };
	u32 ilens[2] = { 0, 0 };
	nn m_, c_;
	m_.magic = c_.magic = WORD(0);

	/* Zeroize local variables */
	ret = local_memset(lhash, 0, sizeof(lhash)); EG(ret, err);
	ret = local_memset(seedmask, 0, sizeof(seedmask)); EG(ret, err);
	ret = local_memset(dbmask, 0, sizeof(dbmask)); EG(ret, err);

	MUST_HAVE((c != NULL) && (m != NULL), ret, err);

	k = BYTECEIL(modbits);

	ret = gen_hash_get_hash_sizes(gen_hash_type, &hlen, &block_size); EG(ret, err);
	MUST_HAVE((hlen <= MAX_DIGEST_SIZE), ret, err);

	/* Check on lengths */
	MUST_HAVE((clen == k), ret, err);
	MUST_HAVE(((u32)k >= ((2 * (u32)hlen) + 2)), ret, err);

	/* RSA decryption */
	/*   c = OS2IP (C) */
	ret = rsa_os2ip(&c_, c, clen); EG(ret, err);
	/*   m = RSADP ((n, d), c) */
	ret = rsadp(priv, &c_, &m_); EG(ret, err);
	/*   EM = I2OSP (m, k) */
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);
	ret = rsa_i2osp(&m_, em, (u16)k); EG(ret, err);

	/* EME-OAEP decoding */
	/* lHash = Hash(L) */
	if(label == NULL){
		MUST_HAVE((label_len == 0), ret, err);
	}
	else{
		input[0] = label;
		ilens[0] = label_len;
	}
	ret = gen_hash_hfunc_scattered(input, ilens, lhash, gen_hash_type); EG(ret, err);
	/*  EM = Y || maskedSeed || maskedDB */
	maskedseed = &em[1];
	maskeddb   = &em[hlen + 1];
	/* seedMask = MGF(maskedDB, hLen) */
	khlen = (k - hlen - 1);
	MUST_HAVE((khlen < (u32)(0x1 << 16)), ret, err);
	ret = _mgf1(maskeddb, (u16)khlen, seedmask, hlen, mgf_hash_type); EG(ret, err);
	/* Let maskedSeed = seed \xor seedMask */
	for(i = 0; i < hlen; i++){
		seed[i] = (maskedseed[i] ^ seedmask[i]);
	}
	/* dbMask = MGF(seed, k - hLen - 1) */
	MUST_HAVE((khlen <= sizeof(dbmask)), ret, err);
	ret = _mgf1(seed, hlen, dbmask, khlen, mgf_hash_type); EG(ret, err);
	/* Let DB = maskedDB \xor dbMask */
	db = dbmask;
	for(i = 0; i < khlen; i++){
		db[i] = (maskeddb[i] ^ dbmask[i]);
	}
	/* DB = lHash' || PS || 0x01 || M */
	/* NOTE: we try our best to do the following in constant time to
	 * limit padding oracles here (see Manger attacks).
	 */
	/* Y must be != 0 */
	ret = !(em[0] == 0x00);
	/* Isolate and compare lHash' to lHash */
	ret |= are_equal(&db[0], lhash, hlen, &cmp);
	ret |= ((~cmp) & 0x1);
	/* Find 0x01 separator in constant time */
	pos = 0;
	for(i = hlen; i < khlen; i++){
		u8 r_;
		pos = ((db[i] == 0x01) && (pos == 0)) ? i : pos;
		r_ = (pos == 0) ? db[i] : 0;
		ret |= r_; /* Capture non zero PS */
	}
	pos = (pos == 0) ? pos : (pos + 1);
	/* We get a random value between 2 and k if we have an error so that
	 * we put a random value in pos.
	 */
        ret |= get_random((u8*)&i, 4);
	/* Get a random value r for later loop dummy operations */
	ret |= get_random(&r, 1);
	/* Update pos with random value in case of error to progress
	 * nominally with the algorithm
	 */
	pos = (ret) ? ((i % (khlen - hlen)) + hlen) : pos;
	/* Copy the result */
	for(i = hlen; i < khlen; i++){
		u8 r_;
		unsigned int idx;
		/* Replace m by a random value in case of error */
		idx = (i < pos) ? 0x00 : (i - pos);
		r ^= (u8)i;
		r_ = ((u8)(!!ret) * r);
		m[idx] = (db[i] ^ r_);
	}
	(*mlen) = (u16)(k - hlen - 1 - pos);
	/* Hide return value details to avoid information leak */
	ret = -(!!ret);

err:
	nn_uninit(&m_);
	nn_uninit(&c_);

	return ret;
}



/****************************************************************/
/******** Signature schemes *************************************/
/* The RSASSA-PKCS1-V1_5-SIGN signature algorithm as described in RFC 8017 section 8.2.1
 *
 */
int rsassa_pkcs1_v1_5_sign(const rsa_priv_key *priv, const u8 *m, u16 mlen,
                           u8 *s, u16 *slen, u32 modbits, gen_hash_alg_type gen_hash_type)
{
	int ret;
	u8 *em = s;
	u32 k;
	nn m_, s_;
	m_.magic = s_.magic = WORD(0);

	/* Checks on sizes */
	MUST_HAVE((slen != NULL), ret, err);

	k = BYTECEIL(modbits);

	/* Only accept reasonable sizes */
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);
	/* Sanity check on size */
	MUST_HAVE(((*slen) >= k), ret, err);

	/* EM = EMSA-PKCS1-V1_5-ENCODE (M, k) */
	ret = emsa_pkcs1_v1_5_encode(m, mlen, em, (u16)k, gen_hash_type); EG(ret, err);

	/* m = OS2IP (EM) */
	ret = rsa_os2ip(&m_, em, (u16)k); EG(ret, err);
	/* s = RSASP1 (K, m) */
	ret = rsasp1(priv, &m_, &s_); EG(ret, err);
	/* S = I2OSP (s, k) */
	ret = rsa_i2osp(&s_, s, (u16)k);
	(*slen) = (u16)k;

err:
	nn_uninit(&m_);
	nn_uninit(&s_);
	/* Zeroify in case of error */
	if(ret && (slen != NULL)){
		IGNORE_RET_VAL(local_memset(s, 0, (*slen)));
	}

	return ret;
}

/* The RSASSA-PKCS1-V1_5-VERIFY verification algorithm as described in RFC 8017 section 8.2.2
 *
 */
int rsassa_pkcs1_v1_5_verify(const rsa_pub_key *pub, const u8 *m, u16 mlen,
                             const u8 *s, u16 slen, u32 modbits, gen_hash_alg_type gen_hash_type)
{
	int ret, cmp;
	/* Get a large enough buffer to hold the result */
        /*
         * NOTE: the NN_USABLE_MAX_BYTE_LEN should be a reasonable size here.
         */
	u8 em[NN_USABLE_MAX_BYTE_LEN];
	u8 em_[NN_USABLE_MAX_BYTE_LEN];
	u32 k;
	nn m_, s_;
	m_.magic = s_.magic = WORD(0);

	/* Zeroize local variables */
	ret = local_memset(em, 0, sizeof(em)); EG(ret, err);
	ret = local_memset(em_, 0, sizeof(em_)); EG(ret, err);

	k = BYTECEIL(modbits);
	/* Only accept reasonable sizes */
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);

	/* Length checking: If the length of the signature S is not k
         * octets, output "invalid signature" and stop.
	 */
	MUST_HAVE(((u16)k == slen), ret, err);

	/* s = OS2IP (S) */
	ret = rsa_os2ip(&s_, s, slen); EG(ret, err);
	/* m = RSAVP1 ((n, e), s) */
	ret = rsavp1(pub, &s_, &m_); EG(ret, err);
	/* EM = I2OSP (m, k) */
	MUST_HAVE((slen <= sizeof(em)), ret, err);
	ret = rsa_i2osp(&m_, em, slen); EG(ret, err);
	/* EM' = EMSA-PKCS1-V1_5-ENCODE (M, k) */
	MUST_HAVE((k <= sizeof(em_)), ret, err);
	ret = emsa_pkcs1_v1_5_encode(m, mlen, em_, (u16)k, gen_hash_type); EG(ret, err);

	/* Compare */
	ret = are_equal(em, em_, (u16)k, &cmp); EG(ret, err);
	if(!cmp){
		ret = -1;
	}
err:
	nn_uninit(&m_);
	nn_uninit(&s_);

	return ret;
}

/* The RSASSA-PSS-SIGN signature algorithm as described in RFC 8017 section 8.1.1
 *
 */
int rsassa_pss_sign(const rsa_priv_key *priv, const u8 *m, u16 mlen,
                    u8 *s, u16 *slen, u32 modbits,
		    gen_hash_alg_type gen_hash_type, gen_hash_alg_type mgf_hash_type,
                    u16 saltlen, const u8 *forced_salt)
{
	int ret;
	u8 *em = s;
	u16 emsize;
	u32 k;
	nn m_, s_;
	m_.magic = s_.magic = WORD(0);

	MUST_HAVE((slen != NULL), ret, err);

	MUST_HAVE((modbits > 1), ret, err);

	k = BYTECEIL(modbits);
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);

	/* Sanity check on size */
	MUST_HAVE(((*slen) >= k), ret, err);

	/* EM = EMSA-PSS-ENCODE (M, modBits - 1) */
	emsize = (*slen);
	ret = emsa_pss_encode(m, mlen, em, (modbits - 1), &emsize, gen_hash_type, mgf_hash_type, saltlen, forced_salt); EG(ret, err);

	/* Note that the octet length of EM will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise */
	MUST_HAVE(emsize == BYTECEIL(modbits - 1), ret, err);

	/* m = OS2IP (EM) */
	ret = rsa_os2ip(&m_, em, (u16)emsize); EG(ret, err);
	/* s = RSASP1 (K, m) */
	ret = rsasp1(priv, &m_, &s_); EG(ret, err);
	/* S = I2OSP (s, k) */
	MUST_HAVE((k < (0x1 << 16)), ret, err);
	ret = rsa_i2osp(&s_, s, (u16)k);
	(*slen) = (u16)k;

err:
	nn_uninit(&m_);
	nn_uninit(&s_);
	/* Zeroify in case of error */
	if(ret && (slen != NULL)){
		IGNORE_RET_VAL(local_memset(s, 0, (*slen)));
	}

	return ret;
}

/* The RSASSA-PSS-VERIFY verification algorithm as described in RFC 8017 section 8.1.2
 *
 */
int rsassa_pss_verify(const rsa_pub_key *pub, const u8 *m, u16 mlen,
                      const u8 *s, u16 slen, u32 modbits,
                      gen_hash_alg_type gen_hash_type, gen_hash_alg_type mgf_hash_type,
		      u16 saltlen)
{
	int ret;
	/* Get a large enough buffer to hold the result */
        /*
         * NOTE: the NN_USABLE_MAX_BYTE_LEN should be a reasonable size here.
         */
	u8 em[NN_USABLE_MAX_BYTE_LEN];
	u16 emlen;
	u32 k;
	nn m_, s_;
	m_.magic = s_.magic = WORD(0);

	/* Zeroize local variables */
	ret = local_memset(em, 0, sizeof(em)); EG(ret, err);

	MUST_HAVE((modbits > 1), ret, err);
	k = BYTECEIL(modbits);
	MUST_HAVE((k < (u32)(0x1 << 16)), ret, err);

	/* s = OS2IP (S) */
	ret = rsa_os2ip(&s_, s, slen); EG(ret, err);
	/* m = RSAVP1 ((n, e), s) */
	ret = rsavp1(pub, &s_, &m_); EG(ret, err);
	/* emLen = \ceil ((modBits - 1)/8) */
	MUST_HAVE((((modbits - 1) / 8) + 1) < (u32)(0x1 << 16), ret, err);
	emlen = (((modbits - 1) % 8) == 0) ? (u16)((modbits - 1) / 8) : (u16)(((modbits - 1) / 8) + 1);

	/* Note that emLen will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise */
	MUST_HAVE(emlen == BYTECEIL(modbits - 1), ret, err);

	/* EM = I2OSP (m, emLen) */
	MUST_HAVE((emlen <= sizeof(em)), ret, err);
	ret = rsa_i2osp(&m_, em, (u16)emlen); EG(ret, err);
	/*  Result = EMSA-PSS-VERIFY (M, EM, modBits - 1) */
	ret = emsa_pss_verify(m, mlen, em, (modbits - 1), emlen, gen_hash_type, mgf_hash_type, saltlen);

err:
	nn_uninit(&m_);
	nn_uninit(&s_);

	return ret;
}

#ifdef RSA
/* RSA PKCS#1 test vectors taken from:
 *     https://github.com/bdauvergne/python-pkcs1/tree/master/tests/data
 */
#include "rsa_pkcs1_tests.h"

int main(int argc, char *argv[])
{
	int ret = 0;
	FORCE_USED_VAR(argc);
	FORCE_USED_VAR(argv);

	/* Sanity check on size for RSA.
	 * NOTE: the double parentheses are here to handle -Wunreachable-code
	 */
	if((NN_USABLE_MAX_BIT_LEN) < (4096)){
		ext_printf("Error: you seem to have compiled libecc with usable NN size < 4096, not suitable for RSA.\n");
		ext_printf("  => Please recompile libecc with EXTRA_CFLAGS=\"-DUSER_NN_BIT_LEN=4096\"\n");
		ext_printf("     This will increase usable NN for proper RSA up to 4096 bits.\n");
		ext_printf("     Then recompile the current examples with the same EXTRA_CFLAGS=\"-DUSER_NN_BIT_LEN=4096\" flag and execute again!\n");
		ret = -1;
		goto err;
	}
	ret = perform_rsa_tests(all_rsa_tests, sizeof(all_rsa_tests) / sizeof(rsa_test*));

err:
	return ret;
}
#endif
