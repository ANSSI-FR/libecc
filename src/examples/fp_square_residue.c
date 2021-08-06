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
#include "libarith.h"

/* Declare our Miller-Rabin test implemented
 * in another module.
 */
int miller_rabin(nn_src_t n, const unsigned int t);

#ifdef FP_EXAMPLE
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

int main()
{
        /* Some mockup code to be able to compile in CRYPTOFUZZ mode although
         * setjmp/longjmp are used.
         */
#if defined(USE_CRYPTOFUZZ) /* CRYPTOFUZZ mode */
        /* Save our context */
        cryptofuzz_save()
#endif

	nn p;
	fp x, x_sqrt1, x_sqrt2;
	fp_ctx ctx;
	int ret;

	while (1) {
		/* Get a random prime p of maximum 521 bits */
		nn_init(&p, 0);
		while (1) {
			/* x = random with max size ~= (NN_MAX_BIT_LEN / 3) bytes.
			 * This size limit is infered from the NN arithmetic primitives
			 * maximum working size. See nn.h for more information about this.
			 */
			if (nn_get_random_maxlen
			    (&p, (u16)((NN_MAX_BIT_LEN / 3) / 8))) {
				continue;
			}

			/* p = 1 is a marginal prime we don't want to deal with */
			if (nn_isone(&p)) {
				continue;
			}
			/* Check primality of p, and choose it if it is prime */
			if (miller_rabin(&p, 100) == 1) {
				break;
			}
		}
		nn_print("Prime p", &p);
		/* Initialize our Fp context from p */
		fp_ctx_init_from_p(&ctx, &p);
		/* Initialize x and its square roots */
		fp_init(&x, &ctx);
		fp_init(&x_sqrt1, &ctx);
		fp_init(&x_sqrt2, &ctx);

		/* Get a random value in Fp */
		fp_get_random(&x, &ctx);
		/* Compute its square in Fp */
		ext_printf("Random before squaring:\n");
		fp_print("x", &x);
		ext_printf("Random after squaring:\n");
		fp_sqr(&x, &x);
		nn_print("x^2", &(x.fp_val));

		ret = fp_sqrt(&x_sqrt1, &x_sqrt2, &x);

		if (ret == 0) {
			/* Square roots found!, check them! */
			fp_print("sqrt1", &x_sqrt1);
			fp_sqr(&x_sqrt1, &x_sqrt1);
			if (fp_cmp(&x, &x_sqrt1) == 0) {
				ext_printf("First found square OK!\n");
			} else {
				ext_printf("First found square NOK: square "
					   "is not the expected value ...\n");
			}
			fp_print("sqrt2", &x_sqrt2);
			fp_sqr(&x_sqrt2, &x_sqrt2);
			if (fp_cmp(&x, &x_sqrt2) == 0) {
				ext_printf("Second found square OK!\n");
			} else {
				ext_printf("Second found square NOK: square "
					   "is not the expected value ...\n");
			}

		} else {
			if (ret == -1) {
				/* This should not happen since we have forged our square */
				ext_printf("Value n has no square over Fp\n");
				ext_printf("(Note: this error can be due to "
					   "Miller-Rabin providing a false "
					   "positive prime ...)\n");
				ext_printf("(though this should happen with "
					   "negligible probability))\n");
				nn_print("Check primality of p =", &p);
				/* Get out of the main loop */
				break;
			} else {
				/* This should not happen since we have forged our square */
				ext_printf("Tonelli-Shanks algorithm unkown "
					   "error ...\n");
				ext_printf("(Note: this error can be due to "
					   "Miller-Rabin providing a false "
					   "positive prime ...)\n");
				ext_printf("(though this should happen with "
					   "negligible probability))\n");
				nn_print("Check primality of p =", &p);
				/* Get out of the main loop */
				break;
			}
		}
	}

	return 0;
}
#endif
