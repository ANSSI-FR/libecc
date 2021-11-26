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
#include "hash.h"

/* Get a libecc hash type and mapping from a generic hash type */
ATTRIBUTE_WARN_UNUSED_RET static int get_libecc_hash(gen_hash_alg_type gen_hash_type, hash_alg_type *hash_type, const hash_mapping **hm, u8 *hlen, u8 *block_size)
{
	int ret;
	hash_alg_type htype = UNKNOWN_HASH_ALG;

	MUST_HAVE((hash_type != NULL) && (hm != NULL), ret, err);

	switch(gen_hash_type){
		case HASH_SHA224:{
#ifdef WITH_HASH_SHA224
			htype = SHA224;
#endif
			break;
		}
		case HASH_SHA256:{
#ifdef WITH_HASH_SHA256
			htype = SHA256;
#endif
			break;
		}
		case HASH_SHA384:{
#ifdef WITH_HASH_SHA384
			htype = SHA384;
#endif
			break;
		}
		case HASH_SHA512:{
#ifdef WITH_HASH_SHA512
			htype = SHA512;
#endif
			break;
		}
		case HASH_SHA512_224:{
#ifdef WITH_HASH_SHA512_224
			htype = SHA512_224;
#endif
			break;
		}
		case HASH_SHA512_256:{
#ifdef WITH_HASH_SHA512_256
			htype = SHA512_256;
#endif
			break;
		}
		case HASH_SHA3_224:{
#ifdef WITH_HASH_SHA3_224
			htype = SHA3_224;
#endif
			break;
		}
		case HASH_SHA3_256:{
#ifdef WITH_HASH_SHA3_256
			htype = SHA3_256;
#endif
			break;
		}
		case HASH_SHA3_384:{
#ifdef WITH_HASH_SHA3_384
			htype = SHA3_384;
#endif
			break;
		}
		case HASH_SHA3_512:{
#ifdef WITH_HASH_SHA3_512
			htype = SHA3_512;
#endif
			break;
		}
		case HASH_SM3:{
#ifdef WITH_HASH_SM3
			htype = SM3;
#endif
			break;
		}
		case HASH_STREEBOG256:{
#ifdef WITH_HASH_STREEBOG256
			htype = STREEBOG256;
#endif
			break;
		}
		case HASH_STREEBOG512:{
#ifdef WITH_HASH_STREEBOG512
			htype = STREEBOG512;
#endif
			break;
		}
		case HASH_SHAKE256:{
#ifdef WITH_HASH_SHAKE256
			htype = SHAKE256;
#endif
			break;
		}
		case HASH_RIPEMD160:{
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

int gen_hash_get_hash_sizes(gen_hash_alg_type gen_hash_type, u8 *hlen, u8 *block_size)
{
        int ret;

        MUST_HAVE((hlen != NULL) && (block_size != NULL), ret, err);

        switch(gen_hash_type){
                case HASH_MD2:{
                        (*hlen) = MD2_DIGEST_SIZE;
                        (*block_size) = MD2_BLOCK_SIZE;
                        ret = 0;
                        break;
                }
                case HASH_MD4:{
                        (*hlen) = MD4_DIGEST_SIZE;
                        (*block_size) = MD4_BLOCK_SIZE;
                        ret = 0;
                        break;
                }
                case HASH_MD5:{
                        (*hlen) = MD5_DIGEST_SIZE;
                        (*block_size) = MD5_BLOCK_SIZE;
                        ret = 0;
                        break;
                }
                case HASH_SHA0:{
                        (*hlen) = SHA0_DIGEST_SIZE;
                        (*block_size) = SHA0_BLOCK_SIZE;
                        ret = 0;
                        break;
                }
                case HASH_SHA1:{
                        (*hlen) = SHA1_DIGEST_SIZE;
                        (*block_size) = SHA1_BLOCK_SIZE;
                        ret = 0;
                        break;
                }
                /* The default case falls back to a genuine libecc hash function */
                default:{
                        const hash_mapping *hm;
                        hash_alg_type hash_type;
                        ret = get_libecc_hash(gen_hash_type, &hash_type, &hm, hlen, block_size); EG(ret, err);
                        break;
                }
        }

err:
        return ret;
}

int gen_hash_hfunc_scattered(const u8 **input, const u32 *ilen, u8 *digest, gen_hash_alg_type gen_hash_type)
{
	int ret;

	switch(gen_hash_type){
		case HASH_MD2:{
			ret = md2_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case HASH_MD4:{
			ret = md4_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case HASH_MD5:{
			ret = md5_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case HASH_SHA0:{
			ret = sha0_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		case HASH_SHA1:{
			ret = sha1_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
		/* The fallback should be libecc type */
		default:{
			const hash_mapping *hm;
			hash_alg_type hash_type;
			u8 hlen, block_size;
			ret = get_libecc_hash(gen_hash_type, &hash_type, &hm, &hlen, &block_size); EG(ret, err);
			MUST_HAVE((hm != NULL), ret, err);
			ret = hm->hfunc_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
	}

err:
	return ret;
}
