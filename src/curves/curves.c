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
#include "curves.h"

/*
 * From a null-terminated string 'ec_name' of exact length 'ec_name_len'
 * (including final null character), the function returns a pointer
 * to the parameters for that curve if it is known, or NULL if the
 * curve is not known.
 */
const ec_str_params *ec_get_curve_params_by_name(const u8 *ec_name,
						 u8 ec_name_len)
{
	const ec_str_params *ret = NULL, *params;
	u8 comp_len, name_len;
	const ec_mapping *map;
	const u8 *name;
	unsigned int i;

	MUST_HAVE(ec_name != NULL);

	/* No need to bother w/ obvious crap */
	if ((ec_name_len <= 2) || (ec_name_len > MAX_CURVE_NAME_LEN)) {
		goto err;
	}

	/*
	 * User has been warned ec_name_len is expected to include final
	 * null character.
	 */
	comp_len = (u8)local_strnlen((const char *)ec_name, ec_name_len);
	if ((comp_len + 1) != ec_name_len) {
		goto err;
	}

	/* Iterate on our list of curves */
	for (i = 0; i < EC_CURVES_NUM; i++) {
		map = &ec_maps[i];
		params = map->params;

		MUST_HAVE(params != NULL);
		MUST_HAVE(params->name != NULL);
		MUST_HAVE(params->name->buf != NULL);
		name = params->name->buf;
		name_len = params->name->buflen;

		if (name_len != ec_name_len) {
			continue;
		}

		if (are_str_equal((const char *)ec_name, (const char *)name)) {
			ret = params;
			break;
		}
	}

 err:
	return ret;
}

/*
 * From a given curve type, the function returns a pointer to the
 * parameters for that curve if it is known, or NULL if the curve
 * is not known.
 */
const ec_str_params *ec_get_curve_params_by_type(ec_curve_type ec_type)
{
	const ec_str_params *ret = NULL, *params;
	const ec_mapping *map;
	const u8 *name;
	u8 name_len;
	unsigned int i;

	for (i = 0; i < EC_CURVES_NUM; i++) {
		map = &ec_maps[i];
		params = map->params;

		MUST_HAVE(params != NULL);

		if (ec_type == map->type) {
			/* Do some sanity check before returning */
			MUST_HAVE(params->name != NULL);
			MUST_HAVE(params->name->buf != NULL);
			name = params->name->buf;
			name_len = (u8)local_strlen((const char *)name);
			MUST_HAVE(params->name->buflen == (name_len + 1));

			ret = params;
			break;
		}
	}

	return ret;
}

/*
 * From a null-terminated string 'ec_name' of exact length 'ec_name_len'
 * (including final null character), the function returns the curve type
 * if it is known. If the name does not match any known curve,
 * UNKNOWN_CURVE is returned.
 */
ec_curve_type ec_get_curve_type_by_name(const u8 *ec_name, u8 ec_name_len)
{
	ec_curve_type ret = UNKNOWN_CURVE;
	const ec_str_params *params;
	u8 name_len, comp_len;
	const ec_mapping *map;
	const u8 *name;
	unsigned int i;

	/* No need to bother w/ obvious crap */
	if ((ec_name_len <= 2) || (ec_name_len > MAX_CURVE_NAME_LEN)) {
		goto err;
	}

	/*
	 * User has been warned ec_name_len is expected to include final
	 * null character.
	 */
	comp_len = (u8)local_strnlen((const char *)ec_name, ec_name_len);
	if ((comp_len + 1) != ec_name_len) {
		goto err;
	}

	/* Iterate on our list of curves */
	for (i = 0; i < EC_CURVES_NUM; i++) {
		map = &ec_maps[i];
		params = map->params;

		MUST_HAVE(params != NULL);
		MUST_HAVE(params->name != NULL);
		MUST_HAVE(params->name->buf != NULL);
		name = params->name->buf;
		name_len = params->name->buflen;

		if (name_len != ec_name_len) {
			continue;
		}

		if (are_str_equal((const char *)ec_name, (const char *)name)) {
			ret = map->type;
			break;
		}
	}

 err:
	return ret;
}

/*
 * Given a curve type, the function finds the curve described by given type
 * and write its name (null terminated string) to given output buffer 'out'
 * of length 'outlen'. 0 is returned on success, -1 otherwise.
 */
int ec_get_curve_name_by_type(const ec_curve_type ec_type, u8 *out, u8 outlen)
{
	const ec_str_params *by_type;
	const u8 *name;
	u8 name_len;
	int ret = -1;

	/* Let's first do the lookup by type */
	by_type = ec_get_curve_params_by_type(ec_type);
	if (!by_type) {
		goto err;
	}

	/* Found a curve for that type. Let's check name matches. */
	MUST_HAVE(by_type->name != NULL);
	MUST_HAVE(by_type->name->buf != NULL);
	name_len = by_type->name->buflen;
	name = by_type->name->buf;

	/* Not enough room to copy curve name */
	if (name_len > outlen) {
		goto err;
	}

	local_memcpy(out, name, name_len);

	ret = 0;

 err:
	return ret;
}

/*
 * The function verifies the coherency between given curve type value and
 * associated name 'ec_name' of length 'ec_name_len' (including final
 * null character). The function returns 0 if the curve type is known
 * and provided name matches expected one. The function returns -1
 * otherwise.
 */
int ec_check_curve_type_and_name(const ec_curve_type ec_type,
				 const u8 *ec_name, u8 ec_name_len)
{
	const ec_str_params *by_type;
	const u8 *name;
	u8 name_len;
	int ret = -1;

	/* No need to bother w/ obvious crap */
	if ((ec_name_len <= 2) || (ec_name_len > MAX_CURVE_NAME_LEN)) {
		goto err;
	}

	/* Let's first do the lookup by type */
	by_type = ec_get_curve_params_by_type(ec_type);
	if (!by_type) {
		goto err;
	}

	/* Found a curve for that type. Let's check name matches. */
	MUST_HAVE(by_type->name != NULL);
	MUST_HAVE(by_type->name->buf != NULL);
	name = by_type->name->buf;
	name_len = by_type->name->buflen;

	if (name_len != ec_name_len) {
		goto err;
	}

	if (!are_str_equal((const char *)ec_name, (const char *)name)) {
		goto err;
	}

	ret = 0;
 err:
	return ret;
}
