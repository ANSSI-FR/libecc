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
#include "hash_algs.h"

const hash_mapping *get_hash_by_name(const char *hash_name)
{
	const hash_mapping *m = NULL, *ret = NULL;
	u8 i;

	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		const char *exp_name = (const char *)m->name;

		if (are_str_equal(hash_name, exp_name)) {
			ret = m;
			break;
		}
	}

	return ret;
}

const hash_mapping *get_hash_by_type(hash_alg_type hash_type)
{
	const hash_mapping *m = NULL, *ret = NULL;
	u8 i;

	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		if (m->type == hash_type) {
			ret = m;
			break;
		}
	}

	return ret;
}

/*
 * Returns respectively in digest_size and block_size param the digest size
 * and block size for given hash function, if return value of the function is 0.
 * If return value is -1, then the hash algorithm is not known and output
 * parameters are not modified.
 */
int get_hash_sizes(hash_alg_type hash_type, u8 *digest_size, u8 *block_size)
{
	const hash_mapping *m;
	int ret = -1;
	u8 i;

	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		if (m->type == hash_type) {
			if (digest_size != NULL) {
				*digest_size = m->digest_size;
			}
			if (block_size != NULL) {
				*block_size = m->block_size;
			}
			ret = 0;
			break;
		}
	}

	return ret;
}

/* Here, we provide a helper that sanity checks the provided hash
 * mapping against our constant ones.
 */
int hash_mapping_callbacks_sanity_check(const hash_mapping *h)
{
	const hash_mapping *m;
        u8 i;

        if(h == NULL){
                goto err;
        }
        /* We just check is our mapping is indeed
         * one of the registered mappings.
         */
	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
                if(m->type == h->type){
			if(!are_str_equal_nlen(m->name, h->name, MAX_HASH_ALG_NAME_LEN)){
				goto err;
			}
			else if(m->digest_size != h->digest_size){
				goto err;
			}
			else if(m->block_size != h->block_size){
				goto err;
			}
			else if(m->hfunc_init != h->hfunc_init){
				goto err;
			}
			else if(m->hfunc_update != h->hfunc_update){
				goto err;
			}
			else if(m->hfunc_finalize != h->hfunc_finalize){
				goto err;
			}
			else if(m->hfunc_scattered != h->hfunc_scattered){
				goto err;
			}
                        else{
                                return 0;
                        }
                }
        }

err:
        return -1;
}

