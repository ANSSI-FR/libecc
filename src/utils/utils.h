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
#if defined(__AFL_COMPILER) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
/* When we use AFL (American Fuzzy Lop) style fuzzing, we do not 
 * want asserts resulting in SIGABRT interpreted as a 'crash', 
 * or while(1) interpreted as a 'hang'. Hence we force an exit(-1) 
 * to remove all this false positive 'pollution'.
 */
#ifndef WITH_STDLIB
#error "AFL Fuzzing needs the STDLIB!"
#endif
#include <stdlib.h>
#define MUST_HAVE(x) do { if (!(x)) { exit(-1); } } while(0)
#define SHOULD_HAVE(x)
#define KNOWN_FACT(x)

#else
#if defined(DEBUG)
#include <assert.h>
#define MUST_HAVE(x) assert(x)
#define SHOULD_HAVE(x) assert(x)
#define KNOWN_FACT(x) assert(x)
#else
#define MUST_HAVE(x) do { if (!(x)) { while (1); } } while (0)
#define SHOULD_HAVE(x)
#define KNOWN_FACT(x)
#endif
#endif /* AFL_FUZZ or FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define BYTECEIL(numbits) (((numbits) + 7) / 8)

u8 are_equal(const void *a, const void *b, u32 len);
void local_memcpy(void *dst, const void *src, u32 n);
void local_memset(void *v, u8 c, u32 n);
u8 are_str_equal(const char *s1, const char *s2);
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
