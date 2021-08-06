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
#include "../external_deps/print.h"
#include "../utils/utils.h"
#include "../libsig.h"

/* Some mockup code to be able to compile in CRYPTOFUZZ mode although
 * setjmp/longjmp are used.
 */
#if defined(USE_CRYPTOFUZZ) /* CRYPTOFUZZ mode */
sigjmp_buf cryptofuzz_jmpbuf;
unsigned char cryptofuzz_longjmp_triggered;
#define cryptofuzz_save() do {                                                                  \
        if(sigsetjmp(cryptofuzz_jmpbuf, 1) && (cryptofuzz_longjmp_triggered == 0)){             \
                exit(-1);                                                                       \
        }                                                                                       \
        if(cryptofuzz_longjmp_triggered == 1){                                                  \
                ext_printf("ASSERT error caught through cryptofuzz_jmpbuf\n");                  \
                exit(-1);                                                                       \
        }                                                                                       \
} while(0);
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#endif

/*
 * Use extern declarations to avoid including
 * ec_self_tests_core.h, which has all fixed
 * test vectors definitions. We only need the
 * three functions below.
 */
extern int perform_known_test_vectors_test(const char *sig, const char *hash, const char *curve);
extern int perform_random_sig_verif_test(const char *sig, const char *hash, const char *curve);
extern int perform_performance_test(const char *sig, const char *hash, const char *curve);

/* Tests kinds */
#define KNOWN_TEST_VECTORS	(1)
#define RANDOM_SIG_VERIF	(1 << 2)
#define PERFORMANCE		(1 << 3)

typedef struct {
	const char *type_name;
	const char *type_help;
	unsigned int type_mask;
} test_type;

static const test_type test_types[] = {
	{
	 .type_name = "vectors",
	 .type_help = "Perform known test vectors",
	 .type_mask = KNOWN_TEST_VECTORS,
	 },
	{
	 .type_name = "rand",
	 .type_help = "Perform random sign/verify tests",
	 .type_mask = RANDOM_SIG_VERIF,
	 },
	{
	 .type_name = "perf",
	 .type_help = "Performance tests",
	 .type_mask = PERFORMANCE,
	 },
};

static int perform_tests(unsigned int tests, const char *sig, const char *hash, const char *curve)
{
	/* KNOWN_TEST_VECTORS tests */
	if (tests & KNOWN_TEST_VECTORS) {
		if (perform_known_test_vectors_test(sig, hash, curve)) {
			goto err;
		}
	}
	/* RANDOM_SIG_VERIF tests */
	if (tests & RANDOM_SIG_VERIF) {
		if (perform_random_sig_verif_test(sig, hash, curve)) {
			goto err;
		}
	}
	/* PERFORMANCE tests */
	if (tests & PERFORMANCE) {
		if (perform_performance_test(sig, hash, curve)) {
			goto err;
		}
	}

	return 0;

 err:
	return -1;
}

static void print_curves(void)
{
       u8 i;

       /* Print all the available curves */
       for (i = 0; i < EC_CURVES_NUM; i++) {
               ext_printf("%s ", (const char *)(ec_maps[i].params->name->buf));
       }

       return;
}

static void print_hash_algs(void)
{
       int i;

       /* Print all the available hash functions */
       for (i = 0; hash_maps[i].type != UNKNOWN_HASH_ALG; i++) {
               ext_printf("%s ", hash_maps[i].name);
       }

       return;
}

static void print_sig_algs(void)
{
        int i;

        /* Print all the available signature schemes */
        for (i = 0; ec_sig_maps[i].type != UNKNOWN_SIG_ALG; i++) {
                ext_printf("%s ", ec_sig_maps[i].name);
        }

        return;
}

static void print_help(const char *bad_arg)
{
	int j;
	if(bad_arg != NULL){
		ext_printf("Argument %s is unknown. Possible args are:\n", bad_arg);
	}
	for (j = 0; j < (int)(sizeof(test_types) / sizeof(test_type)); j++) {
		ext_printf("\t%20s:\t%s\n", test_types[j].type_name,
			   test_types[j].type_help);
	}
	ext_printf("-------------------\n");
	ext_printf("NOTE: you can filter signatures with 'sign=', hash algorithms with 'hash=', curves with 'curve='\n");
	ext_printf("\tExample: sign=ECDSA hash=SHA256 hash=SHA512 curve=FRP256V1\n");
	ext_printf("\tPossible signatures: ");
	print_sig_algs();
	ext_printf("\n\tPossible hash algorithms: ");
	print_hash_algs();
	ext_printf("\n\tPossible curves: ");
	print_curves();
	ext_printf("\n");
}

#define MAX_FILTERS 100

int main(int argc, char *argv[])
{
        /* Some mockup code to be able to compile in CRYPTOFUZZ mode although
         * setjmp/longjmp are used.
         */
#if defined(USE_CRYPTOFUZZ) /* CRYPTOFUZZ mode */
        /* Save our context */
        cryptofuzz_save()
#endif

	int ret;
	unsigned int tests_to_do;
	const char *sign_filters[MAX_FILTERS]  = { NULL };
	const char *hash_filters[MAX_FILTERS]  = { NULL };
	const char *curve_filters[MAX_FILTERS] = { NULL };
	int sign_filters_num = 0, hash_filters_num = 0, curve_filters_num = 0;
	int i, j, k;

	/* By default, perform all tests */
	tests_to_do = KNOWN_TEST_VECTORS | RANDOM_SIG_VERIF | PERFORMANCE;

	/* Sanity check */
	if(MAX_FILTERS < 1){
		ext_printf("Error: MAX_FILTERS too small\n");
		return -1;
	}

	/* If we have one or more arguments, only perform specific test */
	if (argc > 1) {
		unsigned char found = 0, found_filter = 0;
		unsigned int found_ops = 0;
		/* Check of the args */
		for (i = 1; i < argc; i++) {
			found = found_filter = 0;
			for (j = 0;
			     j < (int)(sizeof(test_types) / sizeof(test_type));
			     j++) {
				if (are_equal
				    (argv[i], test_types[j].type_name,
				     local_strlen(test_types[j].type_name) +
				     1)) {
					found_ops++;
					found = 1;
					break;
				}
				if(are_equal(argv[i], "sign=", sizeof("sign=")-1)){
					if(sign_filters_num >= MAX_FILTERS){
						ext_printf("Maximum number of sign filters %d exceeded!\n", sign_filters_num);
						return -1;
					}
					sign_filters[sign_filters_num++] = argv[i]+sizeof("sign=")-1;
					found_filter = 1;
					break;
				}
				if(are_equal(argv[i], "hash=", sizeof("hash=")-1)){
					if(hash_filters_num >= MAX_FILTERS){
						ext_printf("Maximum number of hash filters %d exceeded!\n", hash_filters_num);
						return -1;
					}
					hash_filters[hash_filters_num++] = argv[i]+sizeof("hash=")-1;
					found_filter = 1;
					break;
				}
				if(are_equal(argv[i], "curve=", sizeof("curve=")-1)){
					if(curve_filters_num >= MAX_FILTERS){
						ext_printf("Maximum number of curve filters %d exceeded!\n", curve_filters_num);
						return -1;
					}
					curve_filters[curve_filters_num++] = argv[i]+sizeof("curve=")-1;
					found_filter = 1;
					break;
				}
			}
			if ((found == 0) && (found_filter == 0)) {
				print_help(argv[i]);
				return -1;
			}
		}
		if (found_ops == 0) {
			if(found_filter == 0){
				ext_printf("Error: no operation asked ...\n");
				print_help(NULL);
				return -1;
			}
		}
		else{
			tests_to_do = 0;
			for (i = 1; i < argc; i++) {
				for (j = 0;
				     j < (int)(sizeof(test_types) / sizeof(test_type));
				     j++) {
					if (are_equal
					    (argv[i], test_types[j].type_name,
					     local_strlen(test_types[j].type_name) +
					     1)) {
						tests_to_do |= test_types[j].type_mask;
					}
				}
			}
		}
	}
	/* If we do not have filters, we put NULL to tell that we do not filter */
	if(sign_filters_num == 0){
		sign_filters_num = 1;
		sign_filters[0] = NULL;
	}
	if(hash_filters_num == 0){
		hash_filters_num = 1;
		hash_filters[0] = NULL;
	}
	if(curve_filters_num == 0){
		curve_filters_num = 1;
		curve_filters[0] = NULL;
	}
	for(i = 0; i < sign_filters_num; i++){
		for(j = 0; j < hash_filters_num; j++){
			for(k = 0; k < curve_filters_num; k++){
				if((ret = perform_tests(tests_to_do, sign_filters[i], hash_filters[j], curve_filters[k]))){
					const char *curr_sign_filters = sign_filters[i];
					const char *curr_hash_filters = hash_filters[j];
					const char *curr_curve_filters = curve_filters[k];
					const char *all = "all";
					if(curr_sign_filters == NULL){
						curr_sign_filters = all;
					}
					if(curr_hash_filters == NULL){
						curr_hash_filters = all;
					}
					if(curr_curve_filters == NULL){
						curr_curve_filters = all;
					}
					ext_printf("Test for sign=%s/hash=%s/curve=%s failed!\n", curr_sign_filters, curr_hash_filters, curr_curve_filters);
					return ret;
				}
			}
		}
	}
	return 0;
}
