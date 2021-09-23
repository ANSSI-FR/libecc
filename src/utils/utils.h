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
#ifndef __UTILS_H__
#define __UTILS_H__

#include "../words/words.h"

/*
 * At various locations in the code, we expect expect some specific
 * conditions to be true for correct operation of the code after
 * those locations. This is commonly the case on input parameters
 * at the beginning of functions. Other conditions may be expected
 * but are not necessarily impacting for correct operation of the
 * code.
 *
 * We use the three following macros for that purpose:
 *
 * MUST_HAVE(): The condition is always tested, i.e. both in debug
 * and non debug build. This macros is used when it's better not to
 * continue if the condition does not hold. In production code,
 * if the condition does not hold, a while (1) loop is currently
 * executed (but this may be changed for some specific code the
 * system provide (e.g. abort())). In debug mode, an assert() is
 * used when the condition is false.
 *
 * SHOULD_HAVE(): the condition is only executed in debug mode and
 * the whole macros is a nop in production code. This can be used
 * to add more checks in the code to detect specific conditions
 * or changes. Those checks may have performance impact which are
 * acceptable in debug mode but are not in production mode.
 *
 * KNOWN_FACT(): the condition is only executed in debug mode and
 * the whole macro is a nop in production code. This macro is used
 * to add conditions that are known to be true which may help analysis
 * tools to work on the code. The macro can be used in order to make
 * those conditions explicit.
 */

/*
 * We known it is BAD BAD BAD to define macro with goto inside them
 * but this is the best way we found to avoid making the code
 * unreadable with tests of error conditions when implementing
 * error handling in the project.
 *
 * EG stands for Error Goto, which represents the purpose of the
 * macro, i.e. test a condition cond, and if false goto label
 * lbl.
 */
#define EG(cond,lbl) do { if (cond) { goto lbl ; } } while (0)

/****** AFL and other general purpose fuzzers case *******************/
#if (defined(__AFL_COMPILER) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)) && !defined(USE_CRYPTOFUZZ)
/*
 * When we use AFL (American Fuzzy Lop) style fuzzing, we do not want asserts
 * resulting in SIGABRT interpreted as a 'crash', or while(1) interpreted as a
 * 'hang'. Hence we force an exit(-1) to remove all this false positive
 * 'pollution'.
 */
#ifndef WITH_STDLIB
#error "AFL Fuzzing needs the STDLIB!"
#endif
#include <stdlib.h>
#define MUST_HAVE(x)
#define SHOULD_HAVE(x)
#define KNOWN_FACT(x)

/****** Regular DEBUG and production modes cases  ****************/
#else /* DEBUG and production modes */
#if defined(DEBUG)

/*
 * In DEBUG mode, we enforce a regular assert() in MUST_HAVE,
 * SHOULD_HAVE and KNOWN_FACT, i.e. they are all the same.
 */

#define MUST_HAVE(cond, ret, lbl) do {	\
	assert((cond));			\
	if (0) { /* silence unused	\
		    label warning  */	\
		ret = -1;		\
		goto lbl;		\
	}				\
}  while (0)

#define SHOULD_HAVE(cond, ret, lbl) MUST_HAVE(cond, ret, lbl)

#define KNOWN_FACT(cond, ret, lbl) MUST_HAVE(cond, ret, lbl)

#else /* defined(DEBUG) */

#if defined(USE_ASSERT_PRINT)
#define MUST_HAVE_EXT_PRINT do {					\
	ext_printf("MUST_HAVE error: %s at %d\n", __FILE__,__LINE__);	\
} while (0)
#else
#define MUST_HAVE_EXT_PRINT
#endif

/*
 * In regular production mode, SHOULD_HAVE and KNOWN_FACT are void for
 * performance reasons. MUST_HAVE includes an ext_printf call for
 * tracing the origin of the error when necessary (if USE_ASSERT_PRINT
 * is specified by the user).
 */
/* Print some information and exit if we are asked to */
#define MUST_HAVE(cond, ret, lbl) do {		\
	if (!(cond)) {				\
		MUST_HAVE_EXT_PRINT;		\
		ret = -1;			\
		goto lbl;			\
	}					\
}  while (0)

#define SHOULD_HAVE(cond, ret, lbl) do { \
	if (0) { /* silence unused	 \
		    label warning  */	 \
		ret = -1;		 \
		goto lbl;		 \
	}				 \
}  while (0)

#define KNOWN_FACT(cond, ret, lbl) SHOULD_HAVE(cond, ret, lbl);

#endif  /* defined(DEBUG) */
#endif

#define LOCAL_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define LOCAL_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define BYTECEIL(numbits) (((numbits) + 7) / 8)

u8 are_equal(const void *a, const void *b, u32 len);
void local_memcpy(void *dst, const void *src, u32 n);
void local_memset(void *v, u8 c, u32 n);
u8 are_str_equal(const char *s1, const char *s2);
u8 are_str_equal_nlen(const char *s1, const char *s2, u32 maxlen);
u32 local_strlen(const char *s);
u32 local_strnlen(const char *s, u32 maxlen);
char *local_strncpy(char *dst, const char *src, u32 n);
char *local_strncat(char *dest, const char *src, u32 n);

/* Return 1 if architecture is big endian, 0 otherwise. */
static inline int arch_is_big_endian(void)
{
	const u16 val = 0x0102;
	const u8 *buf = (const u8 *)(&val);

	return buf[0] == 0x01;
}

#define VAR_ZEROIFY(x) do { \
		x = 0;      \
	} while (0)

#define PTR_NULLIFY(x) do { \
		x = NULL;   \
	} while (0)

#endif /* __UTILS_H__ */
