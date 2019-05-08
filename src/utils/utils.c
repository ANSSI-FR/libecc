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
#include "utils.h"

/*
 * Return 1 if first 'len' bytes of both buffers a and b are equal. It
 * returns 0 otherwise. The test is done in constant time.
 */
u8 are_equal(const void *a, const void *b, u32 len)
{
	const u8 *la = (const u8*)a, *lb = (const u8*)b;
	u8 ret = 1;
	u32 i;

	for (i = 0; i < len; i++) {
		ret &= (*la == *lb);
		la++;
		lb++;
	}

	return ret;
}

/* This function is a simple (non-optimized) reimplementation of memcpy() */
void local_memcpy(void *dst, const void *src, u32 n)
{
	const u8 *lsrc = (const u8*)src;
	u8 *ldst = (u8*)dst;
	u32 i;

	for (i = 0; i < n; i++) {
		*ldst = *lsrc;
		ldst++;
		lsrc++;
	}
}

/* This function is a simple (non-optimized) reimplementation of memset() */
void local_memset(void *v, u8 c, u32 n)
{
	volatile u8 *p = (volatile u8*)v;
	u32 i;

	for (i = 0; i < n; i++) {
		*p = c;
		p++;
	}
}

/* This function returns 1 if strings are equal and 0 otherise */
u8 are_str_equal(const char *s1, const char *s2)
{
	const char *ls1 = s1, *ls2 = s2;

	while (*ls1 && (*ls1 == *ls2)) {
		ls1++;
		ls2++;
	}

	return *ls1 == *ls2;
}

/* This function is a simple (non-optimized) reimplementation of strlen() */
u32 local_strlen(const char *s)
{
	u32 i = 0;

	while (s[i]) {
		i++;
	}

	return i;
}

/* This function is a simple (non-optimized) reimplementation of strnlen() */
u32 local_strnlen(const char *s, u32 maxlen)
{
	u32 i = 0;

	while ((i < maxlen) && s[i]) {
		i++;
	}

	return i;
}

/* This functin is a simple (non-optimized) reimplementation of strncpy() */
char *local_strncpy(char *dst, const char *src, u32 n)
{
	u32 i;

	for (i = 0; (i < n) && src[i]; i++) {
		dst[i] = src[i];
	}
	for (; i < n; i++) {
		dst[i] = 0;
	}

	return dst;
}

/* This functin is a simple (non-optimized) reimplementation of strncat() */
char *local_strncat(char *dst, const char *src, u32 n)
{
	u32 dst_len, i;

	dst_len = local_strlen(dst);
	for (i = 0; (i < n) && src[i]; i++) {
		dst[dst_len + i] = src[i];
	}
	dst[dst_len + i] = 0;

	return dst;
}
