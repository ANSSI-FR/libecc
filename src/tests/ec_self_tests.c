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

/*
 * Use extern declarations to avoid including
 * ec_self_tests_core.h, which has all fixed
 * test vectors definitions. We only need the
 * three functions below.
 */
extern int perform_known_test_vectors_test(void);
extern int perform_random_sig_verif_test(void);
extern int perform_performance_test(void);

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

static int perform_tests(unsigned int tests)
{
	/* KNOWN_TEST_VECTORS tests */
	if (tests & KNOWN_TEST_VECTORS) {
		if (perform_known_test_vectors_test()) {
			goto err;
		}
	}
	/* RANDOM_SIG_VERIF tests */
	if (tests & RANDOM_SIG_VERIF) {
		if (perform_random_sig_verif_test()) {
			goto err;
		}
	}
	/* PERFORMANCE tests */
	if (tests & PERFORMANCE) {
		if (perform_performance_test()) {
			goto err;
		}
	}

	return 0;

 err:
	return -1;
}

static void print_help(const char *bad_arg)
{
	int j;
	ext_printf("Argument %s is unknown. Possible args are:\n", bad_arg);
	for (j = 0; j < (int)(sizeof(test_types) / sizeof(test_type)); j++) {
		ext_printf("\t%20s:\t%s\n", test_types[j].type_name,
			   test_types[j].type_help);
	}
}

int main(int argc, char *argv[])
{
	unsigned int tests_to_do;

	/* By default, perform all tests */
	tests_to_do = KNOWN_TEST_VECTORS | RANDOM_SIG_VERIF | PERFORMANCE;

	/* If we have one or more arguments, only perform specific test */
	if (argc > 1) {
		int i, j;
		/* Check of the args */
		for (i = 1; i < argc; i++) {
			char found = 0;
			for (j = 0;
			     j < (int)(sizeof(test_types) / sizeof(test_type));
			     j++) {
				if (are_equal
				    (argv[i], test_types[j].type_name,
				     local_strlen(test_types[j].type_name) +
				     1)) {
					found = 1;
					break;
				}
			}
			if (found == 0) {
				print_help(argv[i]);
				return -1;
			}
		}
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

	return perform_tests(tests_to_do);
}
