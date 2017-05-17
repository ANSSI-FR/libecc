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
#include "ec_self_tests_core.h"
#include "../utils/utils.h"
#include "../external_deps/rand.h"
#include "../external_deps/time.h"
#include "../external_deps/print.h"


static int ec_gen_import_export_kp(ec_key_pair *kp, const ec_params *params,
				   const ec_test_case *c)
{
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	u8 priv_key_buf[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE];
	u8 pub_key_buf_len, priv_key_buf_len;
	ec_key_pair imported_kp;
	int ret;

	/* Generate key pair */
	ret = ec_key_pair_gen(kp, params, c->sig_type);
	if (ret) {
		ext_printf("Error generating key pair\n");
		goto err;
	}
	pub_key_buf_len = EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(&(kp->pub_key));
	priv_key_buf_len = EC_STRUCTURED_PRIV_KEY_EXPORT_SIZE(&(kp->priv_key));

	/* Export public and private keys in buffers */
	ret = ec_structured_pub_key_export_to_buf(&(kp->pub_key), pub_key_buf,
					  pub_key_buf_len);
	if (ret) {
		ext_printf("Error exporting public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_export_to_buf(&(kp->priv_key),
					   priv_key_buf,
					   priv_key_buf_len);
	if (ret) {
		ext_printf("Error exporting private key\n");
	goto err;
	}

	/* Import public and private key */
	ret = ec_structured_pub_key_import_from_buf(&(imported_kp.pub_key),
					    params,
					    pub_key_buf,
					    pub_key_buf_len,
					    c->sig_type);
	if (ret) {
		ext_printf("Error importing public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_import_from_buf(&(imported_kp.priv_key),
					     params, priv_key_buf,
					     priv_key_buf_len,
					     c->sig_type);
	if (ret) {
		ext_printf("Error importing private key\n");
		goto err;
	}
	ret = 0;

err:
	return ret;
}

/* Reduce pressure on the stack for small targets
 * by letting the user override this value.
 */
#ifndef MAX_MSG_LEN
#define MAX_MSG_LEN 8192
#endif

/*
 * ECC generic self tests (sign/verify on random values
 * with import/export)
 */
static int ec_import_export_test(const ec_test_case *c)
{
	ec_key_pair kp;
	ec_params params;
	int ret;

	/* Import EC params from test case */
	import_params(&params, c->ec_str_p);

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u16 msglen;
		u8 siglen;
		u8 msg[MAX_MSG_LEN];
		u8 sig[EC_MAX_SIGLEN];

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
				     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/* Generate a random message to sign */
		ret = get_random((u8 *)&msglen, sizeof(msglen));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		msglen = msglen % MAX_MSG_LEN;
		ret = get_random(msg, msglen);
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}

		ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type);
		if (ret) {
			ext_printf("Error when signing\n");
			goto err;
		}

		ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
				c->sig_type, c->hash_type);
		if (ret) {
			ext_printf("Error when verifying signature\n");
			goto err;
		}
	}
	ret = 0;

 err:
	return ret;
}

/*
 * Those functions respectively perform signature and verification tests
 * based the content of a given test case.
 */
static int ec_test_sign(u8 *sig, u8 siglen, ec_key_pair *kp,
			const ec_test_case *c)
{
	return _ec_sign(sig, siglen, kp, (const u8 *)(c->msg), c->msglen,
			c->nn_random, c->sig_type, c->hash_type);
}

static int ec_test_verify(u8 *sig, u8 siglen, const ec_pub_key *pub_key,
			  const ec_test_case *c)
{
	return ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
			 c->sig_type, c->hash_type);
}

/*
 * ECC generic self tests (sign/verify on known test vectors). Returns
 * 0 if given test succeeded, or a non-zero value otherwise. In that
 * case, the value encodes the information on what went wrong as
 * described above.
 */
static int ec_sig_known_vector_tests_one(const ec_test_case *c)
{
	test_err_kind failed_test = TEST_KEY_IMPORT_ERROR;
	u8 sig[EC_MAX_SIGLEN];
	ec_params params;
	ec_key_pair kp;
	u8 siglen;
	int ret;

	MUST_HAVE(c != NULL);

	import_params(&params, c->ec_str_p);

	ret = ec_key_pair_import_from_priv_key_buf(&kp, &params, c->priv_key,
						   c->priv_key_len,
						   c->sig_type);
	if (ret) {
		failed_test = TEST_KEY_IMPORT_ERROR;
		goto err;
	}
	siglen = c->exp_siglen;
	ret = ec_test_sign(sig, siglen, &kp, c);
	if (ret) {
		failed_test = TEST_SIG_ERROR;
		goto err;
	}

	ret = are_equal(sig, c->exp_sig, siglen);
	if (!ret) {
		failed_test = TEST_SIG_COMP_ERROR;
		goto err;
	}

	ret = ec_test_verify(sig, siglen, &(kp.pub_key), c);
	if (ret) {
		failed_test = TEST_VERIF_ERROR;
	}

	ret = 0;

 err:
	if (ret) {
		ret = (int)encode_error_value(c, failed_test);
	}

	return ret;
}

int perform_known_test_vectors_test(void)
{
	const ec_test_case *cur_test;
	unsigned int i;
	int ret = 0;

	ext_printf("======= Known test vectors test =================\n");
	for (i = 0; i < EC_FIXED_VECTOR_NUM_TESTS; i++) {
		cur_test = ec_fixed_vector_tests[i];
		/* If this is a dummy test case, skip it! */
		if(cur_test->sig_type == UNKNOWN_SIG_ALG){
			continue;
		}

		ret = ec_sig_known_vector_tests_one(cur_test);
		ext_printf("[%s] %30s selftests: known test vectors "
			   "sig/verif %s\n", ret ? "-" : "+",
			   cur_test->name, ret ? "failed" : "ok");
		if (ret) {
			goto err;
		}
	}

 err:
	return ret;
}

static int rand_sig_verif_test_one(const ec_sig_mapping *sig,
				   const hash_mapping *hash,
				   const ec_mapping *ec)
{
	char test_name[MAX_CURVE_NAME_LEN + MAX_HASH_ALG_NAME_LEN +
		       MAX_SIG_ALG_NAME_LEN + 2];
	const unsigned int tn_size = sizeof(test_name) - 1; /* w/o trailing 0 */
	const char *crv_name = (const char *)PARAM_BUF_PTR((ec->params)->name);
	ec_test_case t;
	int ret;

	/* Generate the test name */
	local_memset(test_name, 0, tn_size + 1);
	local_strncpy(test_name, sig->name, tn_size);
	local_strncat(test_name, "-", tn_size -	local_strlen(test_name));
	local_strncat(test_name, hash->name, tn_size - local_strlen(test_name));
	local_strncat(test_name, "/", tn_size - local_strlen(test_name));
	local_strncat(test_name, crv_name, tn_size - local_strlen(test_name));

	/* Create a test */
	t.name = test_name;
	t.ec_str_p = ec->params;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;

	/* Execute the test */
	ret = ec_import_export_test(&t);
	ext_printf("[%s] %34s randtests: random import/export "
		   "with sig/verif %s\n", ret ? "-" : "+", t.name,
		   ret ? "failed" : "ok");

	return ret;
}

int perform_random_sig_verif_test(void)
{
	unsigned int i, j, k;
	int ret;

	/*
	 * Perform basic sign/verify tests on all the cipher suites
	 * (combination of sign algo/hash function/curve)
	 */
	ext_printf("======= Random sig/verif test ===================\n");
	for (i = 0; ec_sig_maps[i].type != UNKNOWN_SIG_ALG; i++) {
		for (j = 0; hash_maps[j].type != UNKNOWN_HASH_ALG; j++) {
			for (k = 0; k < EC_CURVES_NUM; k++) {
				ret = rand_sig_verif_test_one(&ec_sig_maps[i],
							      &hash_maps[j],
							      &ec_maps[k]);
				if (ret) {
					goto err;
				}
			}
		}
	}

	return 0;

err:
	return -1;
}

#define PERF_NUM_OP	300

/*
 * ECC generic performance test: Returns the number of signatures
 * and verifications per second
 */
static int ec_performance_test(const ec_test_case *c,
			       unsigned int *n_perf_sign,
			       unsigned int *n_perf_verif)
{
	ec_key_pair kp;
	ec_params params;
	int ret;

	/* Import EC params from test case */
	import_params(&params, c->ec_str_p);

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u8 sig[EC_MAX_SIGLEN];
		u8 siglen;
		u8 msg[MAX_BLOCK_SIZE];
		u16 msglen;
		u8 hash_digest_size, hash_block_size;
		/* Time related variables */
		u64 time1, time2, cumulated_time_sign, cumulated_time_verify;
		int i;

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
			     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/*
		 * Random tests to measure performance: We do it on small
		 * messages to "absorb" the hash function cost
		 */
		ret = get_hash_sizes(c->hash_type, &hash_digest_size,
			     &hash_block_size);
		if (ret) {
			ext_printf("Error when getting hash size\n");
			goto err;
		}
		cumulated_time_sign = cumulated_time_verify = 0;
		for (i = 0; i < PERF_NUM_OP; i++) {
			/* Generate a random message to sign */
			ret = get_random((u8 *)&msglen, sizeof(msglen));
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}
			msglen = msglen % hash_block_size;
			ret = get_random(msg, msglen);
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}

			/***** Signature **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type);
			if (ret) {
				ext_printf("Error when signing\n");
				goto err;
			}
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (t2 < t1)\n");
				goto err;
			}
			cumulated_time_sign += (time2 - time1);

			/***** Verification **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type);
			if (ret) {
				ext_printf("Error when verifying signature\n");
				goto err;
			}
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (time2 < time1)\n");
				goto err;
			}
			cumulated_time_verify += (time2 - time1);
		}
		if (n_perf_sign != NULL) {
			*n_perf_sign = ((PERF_NUM_OP * 1000ULL) / cumulated_time_sign);
		}
		if (n_perf_verif != NULL) {
			*n_perf_verif = ((PERF_NUM_OP * 1000ULL) / cumulated_time_verify);
		}
	}
	ret = 0;
 err:
	return ret;
}


static int perf_test_one(const ec_sig_mapping *sig, const hash_mapping *hash,
			 const ec_mapping *ec)
{
	char test_name[MAX_CURVE_NAME_LEN + MAX_HASH_ALG_NAME_LEN +
		       MAX_SIG_ALG_NAME_LEN + 2];
	const unsigned int tn_size = sizeof(test_name) - 1; /* w/o trailing 0 */
	unsigned int n_perf_sign = 0, n_perf_verif = 0;
	const char *crv_name = (const char *)PARAM_BUF_PTR((ec->params)->name);
	ec_test_case t;
	int ret;

	/* Generate the test name */
	local_memset(test_name, 0, tn_size + 1);
	local_strncpy(test_name, sig->name, tn_size);
	local_strncat(test_name, "-", tn_size -	local_strlen(test_name));
	local_strncat(test_name, hash->name, tn_size - local_strlen(test_name));
	local_strncat(test_name, "/", tn_size - local_strlen(test_name));
	local_strncat(test_name, crv_name, tn_size - local_strlen(test_name));

	/* Create a test */
	t.name = test_name;
	t.ec_str_p = ec->params;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;

	/* Sign and verify some random data during some time */
	ret = ec_performance_test(&t, &n_perf_sign, &n_perf_verif);
	ext_printf("[%s] %30s perf: %d sign/s and %d verif/s\n",
		   ret ? "-" : "+", t.name, n_perf_sign, n_perf_verif);
	if ((n_perf_sign == 0) || (n_perf_verif == 0)) {
		ext_printf("\t(0 is less than one sig/verif per sec)\n");
	}

	return ret;
}

int perform_performance_test(void)
{
	unsigned int i, j, k;
	int ret;

	/* Perform performance tests like "openssl speed" command */
	ext_printf("======= Performance test ========================\n");
	for (i = 0; ec_sig_maps[i].type != UNKNOWN_SIG_ALG; i++) {
		for (j = 0; hash_maps[j].type != UNKNOWN_HASH_ALG; j++) {
			for (k = 0; k < EC_CURVES_NUM; k++) {
				ret = perf_test_one(&ec_sig_maps[i],
						    &hash_maps[j],
						    &ec_maps[k]);
				if (ret) {
					goto err;
				}
			}
		}
	}

	return 0;

err:
	return -1;
}
