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
#ifndef __NN_CONFIG_H__
#define __NN_CONFIG_H__
#include "../words/words.h"
/*
 * We include the curves list to adapt the maximum NN size to P and Q
 * (prime and order of the curve).
 */
#include "../curves/curves_list.h"

/*
 * All the big num used in the lib are statically allocated. This constant
 * must be defined (here or during build) to provide an upper limit on the
 * size in bits of the numbers the instance of the lib you will build will
 * handle. Note that this value does not prevent the declaration and use
 * of smaller numbers.
 *
 * Rationale for the default value: the main purpose of the lirary is to
 * support for an ECC implementation. ATM, a forseeable upper limit for the
 * numbers that will be dealt with is 521 bits.
 * 
 * However, the user is allowed to overload the maximum bit length of the
 * numbers through the USER_NN_BIT_LEN macro definition (see below). A
 * hard limit 'nn_max' for this size depends on the word size and verifies
 * the following equation (with w being the word size):
 *
 *             floor((nn_max + w - 1) / w) * 3 = 255
 *
 * This equation is explained by elements given below, and by the fact that
 * the length in words of our big numbers are encoded on an u8. This yields 
 * in max sizes of around 5300 bits for 64-bit words, around 2650 bits for 
 * 32-bit words, and around 1300 bits for 16-bit words.
 *
 * Among all the functions we have, some need to handle something which
 * can be seen as a double, so we need twice the amount of bit above.
 * This is typically the case when two numbers are multiplied.
 * But then you usually want to divide this product by another number
 * of the initial size which generically requires shifting by the
 * original sized, whence the factor 3 below.
 *
 * Additionally, all numbers we handled are expected to have a length which
 * is a multiple of the word size we support, i.e. 64/32/16 bits. Hence the
 * rounding.
 */

/*
 * Macro to round a bit length size of a NN value to a word size, and
 * to a size compatible with the arithmetic operations of the library
 * (usually 3 times the size of the input numbers, see explanations above).
 */
#define MAX_BIT_LEN_ROUNDING(x, w) (((((x) + (w) - 1) / (w)) * (w)) * 3)

#ifndef USER_NN_BIT_LEN
/*
 * The user has not defined a specific bit length: we can infer our maximum
 * NN bit size from our curves.
 */
#ifndef NN_MAX_BIT_LEN
#if CURVES_MAX_P_BIT_LEN >= CURVES_MAX_Q_BIT_LEN
#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(CURVES_MAX_P_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE CURVES_MAX_P_BIT_LEN
#else
#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(CURVES_MAX_Q_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE CURVES_MAX_Q_BIT_LEN
#endif
#endif
/****************/
#else
/*
 * If the USER_NN_BIT_LEN flag is defined by the user, we want to be sure that
 * we can also handle our curves, and we also want to round the size to the
 * words we have.
 */
#if CURVES_MAX_P_BIT_LEN >= CURVES_MAX_Q_BIT_LEN
#if USER_NN_BIT_LEN >= CURVES_MAX_P_BIT_LEN
#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(USER_NN_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE USER_NN_BIT_LEN
#else
#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(CURVES_MAX_P_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE CURVES_MAX_P_BIT_LEN
#endif
#else
#if USER_NN_BIT_LEN >= CURVES_MAX_Q_BIT_LEN
#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(USER_NN_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE USER_NN_BIT_LEN
#else
#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(CURVES_MAX_Q_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE CURVES_MAX_Q_BIT_LEN
#endif
#endif
#endif

#define NN_MAX_BYTE_LEN (NN_MAX_BIT_LEN / 8)
#define NN_MAX_WORD_LEN (NN_MAX_BYTE_LEN / WORD_BYTES)

#if (NN_MAX_WORD_LEN > 255)
#error "nn.wlen is encoded on an u8. NN_MAX_WORD_LEN cannot be larger than 255!"
#endif

/* Add a (somehow 'dirty' but working and useful!) way to detect when our .a
 * library has been compiled with options (WORDSIZE and NN_MAX_BIT_LEN)
 * inconsistent with the 'final' binary we want to compile linking to the .a
 * archive. The 'magic' lies in the definition in nn.c of a function (symbol)
 * in our .a archive, consisting in a concatenation of WORDSIZE and
 * NN_MAX_BIT_LEN preprocessed values. On the other side, we force the use
 * of this symbol in other NN .c modules, yielding in a compile time error
 * if WORDSIZE or NN_MAX_BIT_LEN differ.
 * Update: we also check here the consistency of using complete formulas
 * or not.
 */
#ifdef NO_USE_COMPLETE_FORMULAS
#define _CONCATENATE(a, b, c, d) a##b##c##d
#define CONCATENATE(a, b, c, d) _CONCATENATE(a, b, c, d)
void CONCATENATE(nn_consistency_check_maxbitlen, NN_MAX_BASE, wordsize,
		 WORDSIZE) (void);
#ifdef NN_CONSISTENCY_CHECK
ATTRIBUTE_USED void CONCATENATE(nn_consistency_check_maxbitlen, NN_MAX_BASE,
				wordsize, WORDSIZE) (void) {
	return;
}
#else
ATTRIBUTE_USED static inline void nn_check_libconsistency(void)
{
	CONCATENATE(nn_consistency_check_maxbitlen, NN_MAX_BASE, wordsize,
		    WORDSIZE) ();
	return;
}
#endif
#else /* NO_USE_COMPLETE_FORMULAS */
#define _CONCATENATE(a, b, c, d, e) a##b##c##d##e
#define CONCATENATE(a, b, c, d, e) _CONCATENATE(a, b, c, d, e)
void CONCATENATE(nn_consistency_check_maxbitlen, NN_MAX_BASE, wordsize,
		 WORDSIZE, complete_formulas) (void);
#ifdef NN_CONSISTENCY_CHECK
ATTRIBUTE_USED void CONCATENATE(nn_consistency_check_maxbitlen, NN_MAX_BASE,
				wordsize, WORDSIZE, complete_formulas) (void) {
	return;
}
#else
ATTRIBUTE_USED static inline void nn_check_libconsistency(void)
{
	CONCATENATE(nn_consistency_check_maxbitlen, NN_MAX_BASE, wordsize,
		    WORDSIZE, complete_formulas) ();
	return;
}
#endif
#endif /* NO_USE_COMPLETE_FORMULAS */

#endif /* __NN_CONFIG_H__ */
