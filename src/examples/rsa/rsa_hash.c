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
#include "rsa_hash.h"

/* Get a libecc hash type and mapping from an RSA hash type */
ATTRIBUTE_WARN_UNUSED_RET static int get_libecc_hash(rsa_hash_alg_type rsa_hash_type, hash_alg_type *hash_type, const hash_mapping **hm, u8 *hlen, u8 *block_size)
{
	int ret;
	hash_alg_type htype = UNKNOWN_HASH_ALG;

	MUST_HAVE((hash_type != NULL) && (hm != NULL), ret, err);

	switch(rsa_hash_type){
		case RSA_SHA224:{
#ifdef WITH_HASH_SHA224
			htype = SHA224;
#endif
			break;
		}
		case RSA_SHA256:{
#ifdef WITH_HASH_SHA256
			htype = SHA256;
#endif
			break;
		}
		case RSA_SHA384:{
#ifdef WITH_HASH_SHA384
			htype = SHA384;
#endif
			break;
		}
		case RSA_SHA512:{
#ifdef WITH_HASH_SHA512
			htype = SHA512;
#endif
			break;
		}
		case RSA_SHA512_224:{
#ifdef WITH_HASH_SHA512_224
			htype = SHA512_224;
#endif
			break;
		}
		case RSA_SHA512_256:{
#ifdef WITH_HASH_SHA512_256
			htype = SHA512_256;
#endif
			break;
		}
		case RSA_SHA3_224:{
#ifdef WITH_HASH_SHA3_224
			htype = SHA3_224;
#endif
			break;
		}
		case RSA_SHA3_256:{
#ifdef WITH_HASH_SHA3_256
			htype = SHA3_256;
#endif
			break;
		}
		case RSA_SHA3_384:{
#ifdef WITH_HASH_SHA3_384
			htype = SHA3_384;
#endif
			break;
		}
		case RSA_SHA3_512:{
#ifdef WITH_HASH_SHA3_512
			htype = SHA3_512;
#endif
			break;
		}
		case RSA_SM3:{
#ifdef WITH_HASH_SM3
			htype = SM3;
#endif
			break;
		}
		case RSA_STREEBOG256:{
#ifdef WITH_HASH_STREEBOG256
			htype = STREEBOG256;
#endif
			break;
		}
		case RSA_STREEBOG512:{
#ifdef WITH_HASH_STREEBOG512
			htype = STREEBOG512;
#endif
			break;
		}
		case RSA_SHAKE256:{
#ifdef WITH_HASH_SHAKE256
			htype = SHAKE256;
#endif
			break;
		}
		case RSA_RIPEMD160:{
#ifdef WITH_HASH_RIPEMD160
			htype = RIPEMD160;
#endif
			break;
		}

		default:{
			ret = -1;
			htype = UNKNOWN_HASH_ALG;
			break;
		}
	}
	if(htype != UNKNOWN_HASH_ALG){
		(*hash_type) = htype;
		ret = get_hash_by_type(htype, hm); EG(ret, err);
		ret = get_hash_sizes(htype, hlen, block_size); EG(ret, err);
		MUST_HAVE(((*hlen) <= MAX_DIGEST_SIZE), ret, err);
	}
	else{
		ret = -1;
	}

err:
	if(ret && (hm != NULL)){
		(*hm) = NULL;
	}
	if(ret && (hash_type != NULL)){
		(*hash_type) = UNKNOWN_HASH_ALG;
	}
	return ret;
}


int rsa_digestinfo_from_hash(rsa_hash_alg_type rsa_hash_type, u8 *digestinfo, u32 *digestinfo_len)
{
	int ret;

	/* Sanity check */
	MUST_HAVE((digestinfo_len != NULL), ret, err);

	switch(rsa_hash_type){
		case RSA_MD2:{
			const u8 _digestinfo[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a,
						   0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02,
						   0x05, 0x00, 0x04, 0x10 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_MD4:{
			const u8 _digestinfo[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a,
						   0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04,
						   0x05, 0x00, 0x04, 0x10 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_MD5:{
			const u8 _digestinfo[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a,
						   0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
						   0x05, 0x00, 0x04, 0x10 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA1:{
			const u8 _digestinfo[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
						   0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
						   0x14 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA224:{
			const u8 _digestinfo[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x04, 0x05, 0x00, 0x04, 0x1c };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA256:{
			const u8 _digestinfo[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x01, 0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA384:{
			const u8 _digestinfo[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x02, 0x05, 0x00, 0x04, 0x30 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA512:{
			const u8 _digestinfo[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x03, 0x05, 0x00, 0x04, 0x40 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA512_224:{
			const u8 _digestinfo[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x05, 0x05, 0x00, 0x04, 0x1c };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA512_256:{
			const u8 _digestinfo[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x06, 0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_RIPEMD160:{
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
		case RSA_SHA3_224:{
			const u8 _digestinfo[] = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x07, 0x05, 0x00, 0x04, 0x1c };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA3_256:{
			const u8 _digestinfo[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x08, 0x05, 0x00, 0x04, 0x20 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA3_384:{
			const u8 _digestinfo[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
						   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
						   0x09, 0x05, 0x00, 0x04, 0x30 };
			MUST_HAVE(((*digestinfo_len) >= sizeof(_digestinfo)), ret, err);
			ret = local_memcpy(digestinfo, _digestinfo, sizeof(_digestinfo)); EG(ret, err);
			(*digestinfo_len) = sizeof(_digestinfo);
			break;
		}
		case RSA_SHA3_512:{
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
		case RSA_SM3:{
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

int rsa_get_hash_sizes(rsa_hash_alg_type rsa_hash_type, u8 *hlen, u8 *block_size)
{
	int ret;

	MUST_HAVE((hlen != NULL) && (block_size != NULL), ret, err);

	switch(rsa_hash_type){
		case RSA_MD2:{
			(*hlen) = MD2_DIGEST_SIZE;
			(*block_size) = MD2_BLOCK_SIZE;
			ret = 0;
			break;
		}
		case RSA_MD4:{
			(*hlen) = MD4_DIGEST_SIZE;
			(*block_size) = MD4_BLOCK_SIZE;
			ret = 0;
			break;
		}
		case RSA_MD5:{
			(*hlen) = MD5_DIGEST_SIZE;
			(*block_size) = MD5_BLOCK_SIZE;
			ret = 0;
			break;
		}
		case RSA_SHA0:{
			(*hlen) = SHA0_DIGEST_SIZE;
			(*block_size) = SHA0_BLOCK_SIZE;
			ret = 0;
			break;
		}
		case RSA_SHA1:{
			(*hlen) = SHA1_DIGEST_SIZE;
			(*block_size) = SHA1_BLOCK_SIZE;
			ret = 0;
			break;
		}
		/* The default case falls back to a genuine libecc hash function */
		default:{
			const hash_mapping *hm;
			hash_alg_type hash_type;
			ret = get_libecc_hash(rsa_hash_type, &hash_type, &hm, hlen, block_size); EG(ret, err);
			break;
		}
	}

err:
	return ret;
}

int rsa_hfunc_scattered(const u8 **input, const u32 *ilen, u8 *digest, rsa_hash_alg_type rsa_hash_type)
{
	int ret;

	switch(rsa_hash_type){
		case RSA_MD2:{
			ret = md2_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case RSA_MD4:{
			ret = md4_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case RSA_MD5:{
			ret = md5_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case RSA_SHA0:{
			ret = sha0_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case RSA_SHA1:{
			ret = sha1_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		/* The fallback should be libecc type */
		default:{
			const hash_mapping *hm;
			hash_alg_type hash_type;
			u8 hlen, block_size;
			ret = get_libecc_hash(rsa_hash_type, &hash_type, &hm, &hlen, &block_size); EG(ret, err);
			MUST_HAVE((hm != NULL), ret, err);
			ret = hm->hfunc_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
	}

err:
	return ret;
}
