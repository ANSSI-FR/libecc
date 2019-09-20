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
#include "nn_rand.h"
#include "nn_div.h"
#include "nn_add.h"
#include "nn_logical.h"

#include "../external_deps/rand.h"

/*
 * The function initializes nn structure pointed by 'out' to a random value of
 * byte length 'len'. The resulting nn will have a uniformly random value in
 * [0, 2^(8 * len)[. Provided length 'len' parameter must be less than or equal
 * to NN_MAX_BYTE_LEN. The function returns -1 on error and 0 on success.
 */
int nn_get_random_len(nn_t out, u16 len)
{
	MUST_HAVE(len <= NN_MAX_BYTE_LEN);

	nn_init(out, len);

	return get_random((u8*) out->val, len);
}

/*
 * The function initializes nn structure pointed by 'out' to a random value of
 * *random* byte length less than or equal to 'max_len'. Unlike the function
 * above (nn_get_random_len()), the resulting nn will have a uniformly random
 * value in in [0, 2^(8 * len)[ *with* length selected at random in
 * [0, max_len]. The function returns -1 on error and 0 on success.
 *
 * !! NOTE !!: think twice before using this function for anything other than
 * testing purposes. Its main goal is to generate nn with random length, not
 * random numbers. For instance, for a given value of max_len, the function
 * returns a nn with a value of 0 w/ probability 1/max_len.
 */
int nn_get_random_maxlen(nn_t out, u16 max_len)
{
	u16 len;

	MUST_HAVE(max_len <= NN_MAX_BYTE_LEN);

	if(get_random((u8 *)&len, 2)){
		/* Failure of get_random */
		return -1;
	}
	len %= max_len + 1;

	return nn_get_random_len(out, len);
}

/*
 * On success, the return value of the function is 0 and 'out' parameter
 * is initialized to an unbiased random value in ]0,q[. On error, the
 * function returns -1. Due to the generation process described below,
 * the size of q is limited by NN_MAX_BYTE_LEN / 2. Aliasing is supported.
 *
 * Generating a random value in ]0,q[ is done by reducing a large random
 * value modulo q. The random value is taken with a length twice the one
 * of q to ensure the reduction does not produce a biased value.
 *
 * Even if this is unlikely to happen, the reduction can produce a null
 * result; this specific case would require to repeat the whole process.
 * For that reason, the algorithm we implement works in the following
 * way:
 *
 *  1) compute q' = q - 1                   (note: q is neither 0 nor 1)
 *  2) generate a random value tmp_rand twice the size of q
 *  3) compute out = tmp_rand mod q'        (note: out is in [0, q-2])
 *  4) compute out += 1                     (note: out is in [1, q-1])
 *
 */
int nn_get_random_mod(nn_t out, nn_src_t q)
{
	nn tmp_rand, qprime;
	bitcnt_t q_bit_len, q_len;
	int ret;

	/* Check q is initialized and get its bit length */
	nn_check_initialized(q);
	q_bit_len = nn_bitlen(q);
	q_len = BYTECEIL(q_bit_len);

	/* Check q is neither 0, nor 1 and its size is ok */
	if ((!q_len) || nn_isone(q) || (q_len > (NN_MAX_BYTE_LEN / 2))) {
		ret = -1;
		goto err;
	}

	/* 1) compute q' = q - 1  */
	nn_copy(&qprime, q);
	nn_dec(&qprime, &qprime);

	/* 2) generate a random value tmp_rand twice the size of q */
	nn_init(&tmp_rand, (u16)(2 * q_len));
	ret = get_random((u8 *)tmp_rand.val, (u16)(2 * q_len));
	if (ret == -1) {
		goto err;
	}

	/* 3) compute out = tmp_rand mod q' */
	nn_init(out, (u16)q_len);
	/* Use nn_mod_notrim to avoid exposing the generated random length */
	nn_mod_notrim(out, &tmp_rand, &qprime);

	/* 4) compute out += 1 */
	nn_inc(out, out);

	ret = 0;

 err:
	if(nn_is_initialized(&qprime)){
		nn_uninit(&qprime);
	}
	if(nn_is_initialized(&tmp_rand)){
		nn_uninit(&tmp_rand);
	}
	return ret;
}
