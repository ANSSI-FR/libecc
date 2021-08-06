/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *	Ryad BENADJILA <ryadbenadjila@gmail.com>
 *	Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *	Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *	Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *	Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "../libsig.h"

/* Some mockup code to be able to compile in CRYPTOFUZZ mode although
 * setjmp/longjmp are used.
 */
#if defined(USE_CRYPTOFUZZ) /* CRYPTOFUZZ mode */

sigjmp_buf cryptofuzz_jmpbuf;
unsigned char cryptofuzz_longjmp_triggered = 0;
#define cryptofuzz_save() do {									\
	if(sigsetjmp(cryptofuzz_jmpbuf, 1) && (cryptofuzz_longjmp_triggered == 0)){		\
		exit(-1);									\
	}											\
	if(cryptofuzz_longjmp_triggered == 1){							\
		ext_printf("ASSERT error caught through cryptofuzz_jmpbuf\n");			\
		exit(-1);									\
	}											\
} while(0);
#endif


#ifdef WITH_STDLIB
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#define HDR_MAGIC	 0x34215609

typedef enum {
	IMAGE_TYPE0 = 0,
	IMAGE_TYPE1 = 1,
	IMAGE_TYPE2 = 2,
	IMAGE_TYPE3 = 3,
	/* Info: You can add more image header types */
} image_type;

/* Generic header to prepend data */
typedef struct {
	u32 magic;		/* header header */
	u32 type;		/* Type of the signed image */
	u32 version;		/* Version */
	u32 len;		/* length of data after header */
	u32 siglen;		/* length of sig (on header + data) */
} ATTRIBUTE_PACKED metadata_hdr;

/* Max stack working buffer size */
#define MAX_BUF_LEN		8192

typedef enum {
	RAWBIN,
	DOTH,
} export_file_type;

static int export_private_key(FILE * file, const char *name,
			      const ec_priv_key *priv_key,
			      export_file_type file_type)
{
	u8 export_buf_size = EC_STRUCTURED_PRIV_KEY_EXPORT_SIZE(priv_key);
	u8 priv_key_buf[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE];
	int ret;
	u32 i;
	size_t written;

	priv_key_check_initialized(priv_key);
	MUST_HAVE(file != NULL);

	/* Serialize the private key to a buffer */
	ret = ec_structured_priv_key_export_to_buf(priv_key, priv_key_buf,
						   export_buf_size);
	if (ret) {
		printf("Error exporting private key to buffer\n");
		ret = -1;
		goto err;
	}

	/* Export the private key to the file */
	switch (file_type) {
	case DOTH:
		MUST_HAVE(name != NULL);
		fprintf(file, "const char %s[] = { ", name);
		for (i = 0; i < export_buf_size; i++) {
			fprintf(file, "0x%02x", priv_key_buf[i]);
			if (i != export_buf_size) {
				fprintf(file, ", ");
			}
		}
		fprintf(file, "};\n");
		ret = 0;
		break;
	case RAWBIN:
		written = fwrite(priv_key_buf, 1, export_buf_size, file);
		if(written != export_buf_size){
			ret = -1;
			goto err;
		}
		ret = 0;
		break;
	default:
		ret = -1;
	}

 err:
	return ret;
}

static int export_public_key(FILE * file, const char *name,
			     const ec_pub_key *pub_key,
			     export_file_type file_type)
{
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	u8 export_buf_size;
	int ret;
	u32 i;
	size_t written;

	pub_key_check_initialized(pub_key);
	MUST_HAVE(file != NULL);

	/* Serialize the public key to a buffer */
	export_buf_size = EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(pub_key);
	ret = ec_structured_pub_key_export_to_buf(pub_key, pub_key_buf,
						  export_buf_size);
	if (ret) {
		printf("Error exporting public key to buffer\n");
		ret = -1;
		goto err;
	}

	/* Export the public key to the file */
	switch (file_type) {
	case DOTH:
		MUST_HAVE(name != NULL);
		fprintf(file, "const char %s[] = { ", name);
		for (i = 0; i < export_buf_size; i++) {
			fprintf(file, "0x%02x", pub_key_buf[i]);
			if (i != export_buf_size) {
				fprintf(file, ", ");
			}
		}
		fprintf(file, "};\n");
		ret = 0;
		break;
	case RAWBIN:
		written = fwrite(pub_key_buf, 1, export_buf_size, file);
		if(written != export_buf_size){
			ret = -1;
			goto err;
		}
		ret = 0;
		break;
	default:
		ret = -1;
	}

 err:
	return ret;
}

static int string_to_params(const char *ec_name, const char *ec_sig_name,
			    ec_sig_alg_type * sig_type,
			    const ec_str_params ** ec_str_p,
			    const char *hash_name, hash_alg_type * hash_type)
{
	const ec_str_params *curve_params;
	const ec_sig_mapping *sm;
	const hash_mapping *hm;
	u32 curve_name_len;

	if (sig_type != NULL) {
		/* Get sig type from signature alg name */
		sm = get_sig_by_name(ec_sig_name);
		if (!sm) {
			printf("Error: signature type %s is unknown!\n",
			       ec_sig_name);
			goto err;
		}
		*sig_type = sm->type;
	}

	if (ec_str_p != NULL) {
		/* Get curve params from curve name */
		curve_name_len = local_strlen((const char *)ec_name) + 1;
		if(curve_name_len > 255){
			/* Sanity check */
			goto err;
		}
		curve_params = ec_get_curve_params_by_name((const u8 *)ec_name,
							   (u8)curve_name_len);
		if (!curve_params) {
			printf("Error: EC curve %s is unknown!\n", ec_name);
			goto err;
		}
		*ec_str_p = curve_params;
	}

	if (hash_type != NULL) {
		/* Get hash type from hash alg name */
		hm = get_hash_by_name(hash_name);
		if (!hm) {
			printf("Error: hash function %s is unknown!\n",
			       hash_name);
			goto err;
		}
		*hash_type = hm->type;
	}

	return 0;

 err:
	return -1;
}

static int generate_and_export_key_pair(const char *ec_name,
					const char *ec_sig_name,
					const char *fname_prefix)
{
	const ec_str_params *ec_str_p;
	char fname[MAX_BUF_LEN];
	char kname[MAX_BUF_LEN];
	const u16 fname_len = sizeof(fname);
	const u16 kname_len = sizeof(kname);
	u16 prefix_len;
	ec_sig_alg_type sig_type;
	ec_params params;
	ec_key_pair kp;
	FILE *file;
	int ret;

	MUST_HAVE(ec_name != NULL);
	MUST_HAVE(fname_prefix != NULL);
	MUST_HAVE(ec_sig_name != NULL);

	/* Get parameters from pretty names */
	ret = string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
			       NULL, NULL);
	if (ret) {
		goto err;
	}

	/* Import the parameters */
	import_params(&params, ec_str_p);

	/* Generate the key pair */
	ec_key_pair_gen(&kp, &params, sig_type);

	/* Get the unique affine equivalent representation of the projective point for the public key.
	 * This avoids ambiguity when exporting the point, and is mostly here
	 * for compatibility with external libraries.
	 */
	prj_pt_unique(&(kp.pub_key.y), &(kp.pub_key.y));

	/*************************/

	/* Export the private key to the raw binary file */
	prefix_len = (u16)local_strnlen(fname_prefix, fname_len);
	local_memset(fname, 0, fname_len);
	local_memcpy(fname, fname_prefix, prefix_len);
	local_strncat(fname, "_private_key.bin", fname_len - prefix_len);
	file = fopen(fname, "w");
	if (file == NULL) {
		printf("Error: file %s cannot be opened\n", fname);
		goto err;
	}

	ret = export_private_key(file, NULL, &(kp.priv_key), RAWBIN);
	fclose(file);
	if (ret) {
		printf("Error exporting the private key\n");
		goto err;
	}

	/* Export the private key to the .h file */
	local_memset(fname, 0, fname_len);
	local_memcpy(fname, fname_prefix, prefix_len);
	local_strncat(fname, "_private_key.h", fname_len - prefix_len);
	file = fopen(fname, "w");
	if (file == NULL) {
		printf("Error: file %s cannot be opened\n", fname);
		goto err;
	}

	snprintf(kname, kname_len, "%s_%s_private_key", ec_name, ec_sig_name);
	ret = export_private_key(file, kname, &(kp.priv_key), DOTH);
	fclose(file);
	if (ret) {
		printf("Error: error exporting the private key\n");
		goto err;
	}

	/*************************/

	/* Export the public key to the raw binary file */
	local_memset(fname, 0, fname_len);
	local_memcpy(fname, fname_prefix, prefix_len);
	local_strncat(fname, "_public_key.bin", fname_len - prefix_len);
	file = fopen(fname, "w");
	if (file == NULL) {
		printf("Error: file %s cannot be opened\n", fname);
		goto err;
	}

	ret = export_public_key(file, NULL, &(kp.pub_key), RAWBIN);
	fclose(file);
	if (ret) {
		printf("Error exporting the public key\n");
		goto err;
	}

	/* Export the public key to the .h file */
	local_memset(fname, 0, fname_len);
	local_memcpy(fname, fname_prefix, prefix_len);
	local_strncat(fname, "_public_key.h", fname_len - prefix_len);
	file = fopen(fname, "w");
	if (file == NULL) {
		printf("Error: file %s cannot be opened\n", fname);
		goto err;
	}

	snprintf(kname, kname_len, "%s_%s_public_key", ec_name, ec_sig_name);
	ret = export_public_key(file, kname, &(kp.pub_key), DOTH);
	fclose(file);
	if (ret) {
		printf("Error exporting the public key\n");
		goto err;
	}

	return 0;

err:
	return -1;
}


static int store_sig(const char *in_fname, const char *out_fname,
		     const u8 *sig, u32 siglen,
		     ec_sig_alg_type sig_type, hash_alg_type hash_type,
		     const u8 curve_name[MAX_CURVE_NAME_LEN],
		     metadata_hdr * hdr)
{
	FILE *in_file = NULL, *out_file = NULL;
	u8 buf[MAX_BUF_LEN];
	size_t read, written;
	int ret;

	MUST_HAVE(EC_STRUCTURED_SIG_EXPORT_SIZE(siglen) <= sizeof(buf));

	/* Import the data from the input file */
	in_file = fopen(in_fname, "r");
	if (in_file == NULL) {
		printf("Error: file %s cannot be opened\n", in_fname);
		goto err;
	}
	out_file = fopen(out_fname, "w");
	if (out_file == NULL) {
		printf("Error: file %s cannot be opened\n", out_fname);
		goto err;
	}
	if (hdr != NULL) {
		/* Write the metadata header as a prepending information */
		written = fwrite(hdr, 1, sizeof(metadata_hdr), out_file);
		if (written != sizeof(metadata_hdr)) {
			fclose(in_file);
			fclose(out_file);
			in_file = out_file = NULL;
			goto err;
		}
	}

	while (1) {
		read = fread(buf, 1, sizeof(buf), in_file);
		written = fwrite(buf, 1, read, out_file);
		if (written != read) {
			printf("Error: error when writing to %s\n",
			       out_fname);
			fclose(in_file);
			fclose(out_file);
			in_file = out_file = NULL;
			goto err;
		}
		if (read != sizeof(buf)) {
			if (feof(in_file)) {
				/* EOF */
				break;
			} else {
				printf("Error: error when reading from %s\n",
				       in_fname);
				fclose(in_file);
				fclose(out_file);
				in_file = out_file = NULL;
				goto err;
			}
		}

	}

	/* Compute the structured signature */
	ret = ec_structured_sig_export_to_buf(sig, siglen, buf, sizeof(buf),
					      sig_type, hash_type, curve_name);
	if (ret) {
		printf("Error: error when exporting signature to structured buffer\n");
		goto err;
	}
	/* Store the signature buffer */
	written =
		fwrite(buf, 1, EC_STRUCTURED_SIG_EXPORT_SIZE(siglen),
		       out_file);
	if (written != EC_STRUCTURED_SIG_EXPORT_SIZE(siglen)) {
		printf("Error: error when writing to %s\n", out_fname);
		fclose(in_file);
		fclose(out_file);
		in_file = out_file = NULL;
		goto err;
	}

	fclose(in_file);
	fclose(out_file);
	return 0;
 err:
	if(in_file != NULL){
		fclose(in_file);
	}
	if(out_file != NULL){
		fclose(out_file);
	}
	return -1;
}

/* Get the raw size of a file */
static int get_file_size(const char *in_fname, size_t *outsz)
{
	FILE *in_file;
	long size;

	*outsz = 0;

	in_file = fopen(in_fname, "r");
	if (in_file == NULL) {
		printf("Error: file %s cannot be opened\n", in_fname);
		goto err;
	}
	/* Compute the size of the file */
	if (fseek(in_file, 0L, SEEK_END)) {
		printf("Error: file %s cannot be seeked\n", in_fname);
		goto err_close;
	}
	size = ftell(in_file);
	if (size < 0) {
		printf("Error: cannot compute file %s size\n", in_fname);
		goto err_close;
	}
	/* Check overflow */
	if ((unsigned long)size > ((u32)~0)) {
		printf("Error: file %s size %ld overflow (>= 2^32)\n",
		       in_fname, size);
		goto err_close;
	}

	*outsz = (u32)size;
	fclose(in_file);
	return 0;

 err_close:
	fclose(in_file);
 err:
	return -1;
}

/* Generate a proper handler from a given type and other information */
static int generate_metadata_hdr(metadata_hdr * hdr, const char *hdr_type,
				 const char *version, size_t len, u8 siglen)
{
	unsigned long ver;
	char *endptr; /* for strtoul() */

	/* The magic value */
	hdr->magic = HDR_MAGIC;

	/* The given version */
	ver = strtoul(version, &endptr, 0);
	if (*endptr != '\0') {
		printf("Error: error getting provided version %s\n", version);
		goto err;
	}
	if ((ver & 0xffffffff) != ver) {
		printf("Error: provided version %s is too long!\n", version);
		goto err;
	}
	hdr->version = (u32)ver;

	/* The image type */
	if (are_str_equal(hdr_type, "IMAGE_TYPE0")) {
		hdr->type = IMAGE_TYPE0;
	} else if (are_str_equal(hdr_type, "IMAGE_TYPE1")) {
		hdr->type = IMAGE_TYPE0;
	} else if (are_str_equal(hdr_type, "IMAGE_TYPE2")) {
		hdr->type = IMAGE_TYPE0;
	} else if (are_str_equal(hdr_type, "IMAGE_TYPE3")) {
		hdr->type = IMAGE_TYPE3;
	} else {
		printf("Error: unknown header type %s\n", hdr_type);
		goto err;
	}

	/* The length without the signature */
	if ((len & 0xffffffff) != len) {
		printf("Error: provided length value %lu is too long!\n", (unsigned long)len);
		goto err;
	}
	hdr->len = (u32)len;

	/* The signature length */
	hdr->siglen = siglen;

	return 0;

 err:
	return -1;
}

/* Warn the user that the provided ancillary data won't be used
 * if the algorithm does not need them.
 */
static void check_ancillary_data(const char *adata, ec_sig_alg_type sig_type, const char *sig_name)
{
	u8 check = 0;

	if(adata == NULL){
		return;
	}

	MUST_HAVE(sig_type != UNKNOWN_SIG_ALG);

#if defined(WITH_SIG_EDDSA25519)
	if(sig_type == EDDSA25519CTX){
		check = 1;
	}
#endif
#if defined(WITH_SIG_EDDSA448)
	if(sig_type == EDDSA448){
		check = 1;
	}
#endif
#if defined(WITH_SIG_SM2)
	if(sig_type == SM2){
		check = 1;
	}
#endif
	if(check == 0){
		printf("Warning: you have provided optional ancillary data "\
		       "with a signature algorithm %s that does not need it! "\
		       "This data is ignored.\n", sig_name);
	}
	return;
}

/*
 * Sign data from file and append signature
 */
static int sign_bin_file(const char *ec_name, const char *ec_sig_name,
			 const char *hash_algorithm, const char *in_fname,
			 const char *in_key_fname,
			 const char *out_fname, const char *hdr_type,
			 const char *version, const char *adata, u16 adata_len)
{
	u8 sig[EC_MAX_SIGLEN];
	u8 buf[MAX_BUF_LEN];
	u8 siglen;
	FILE *in_file;
	ec_key_pair key_pair;
	FILE *in_key_file;
	const ec_str_params *ec_str_p;
	ec_params params;
	int ret;
	ec_sig_alg_type sig_type;
	hash_alg_type hash_type;
	u8 priv_key_buf[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE];
	u8 priv_key_buf_len;
	size_t raw_data_len;
	metadata_hdr hdr;
	size_t read, to_read;
	int eof;

	struct ec_sign_context sig_ctx;

	MUST_HAVE(ec_name != NULL);

	/************************************/
	/* Get parameters from pretty names */
	if (string_to_params
	    (ec_name, ec_sig_name, &sig_type, &ec_str_p, hash_algorithm,
	     &hash_type)) {
		goto err;
	}
	/* Check if ancillary data will be used */
	check_ancillary_data(adata, sig_type, ec_sig_name);
	/* Import the parameters */
	import_params(&params, ec_str_p);

	/************************************/
	/* Import the private key from the file */
	in_key_file = fopen(in_key_fname, "r");
	if (in_key_file == NULL) {
		printf("Error: file %s cannot be opened\n", in_key_fname);
		goto err;
	}
	priv_key_buf_len = (u8)fread(priv_key_buf, 1, sizeof(priv_key_buf),
				     in_key_file);
	fclose(in_key_file);
	ret = ec_structured_key_pair_import_from_priv_key_buf(&key_pair,
							      &params,
							      priv_key_buf,
							      priv_key_buf_len,
							      sig_type);
	if (ret) {
		printf("Error: error when importing key pair from %s\n",
		       in_key_fname);
		goto err;
	}

	ret = get_file_size(in_fname, &raw_data_len);
	if (ret) {
		printf("Error: cannot retrieve file %s size\n", in_fname);
		goto err;
	}
	ret = ec_get_sig_len(&params, sig_type, hash_type, &siglen);
	if (ret) {
		printf("Error getting effective signature length from %s\n",
		       (const char *)(ec_str_p->name->buf));
		goto err;
	}

	/* Structured export case, we forge a header */
	if((hdr_type != NULL) && (version != NULL)){
		/************************************/
		/* Forge the header */
		ret = generate_metadata_hdr(&hdr, hdr_type, version, raw_data_len,
					    EC_STRUCTURED_SIG_EXPORT_SIZE(siglen));

		if (ret) {
			printf("Error: error when generating metadata\n");
			goto err;
		}
	}

	/*
	 * Initialize signature context and start signature computation
	 * with generated metadata header.
	 */
	ret = ec_sign_init(&sig_ctx, &key_pair, sig_type, hash_type, (const u8*)adata, adata_len);
	if (ret) {
		printf("Error: error when signing\n");
		goto err;
	}

	/* Structured export case, we prepend the header in the signature */
	if((hdr_type != NULL) && (version != NULL)){
		ret = ec_sign_update(&sig_ctx, (const u8 *)&hdr, sizeof(metadata_hdr));
		if (ret) {
			printf("Error: error when signing\n");
			goto err;
		}
	}

	/*
	 * Read file content chunk by chunk up to file length, passing each
	 * chunk to signature update function
	 */
	in_file = fopen(in_fname, "r");
	if (in_file == NULL) {
		printf("Error: file %s cannot be opened\n", in_fname);
		goto err;
	}

	eof = 0;
	clearerr(in_file);
	while (raw_data_len && !eof) {
		to_read =
			(raw_data_len <
			sizeof(buf)) ? raw_data_len : sizeof(buf);
		read = fread(buf, 1, to_read, in_file);
		if (read != to_read) {
			/* Check if this was EOF */
			ret = feof(in_file);
			clearerr(in_file);
			if (ret) {
				eof = 1;
			}
		}

		if (read > raw_data_len) {
			/* we read more than expected: leave! */
			break;
		}

		raw_data_len -= read;

		ret = ec_sign_update(&sig_ctx, buf, (u32)read);
		if (ret) {
			break;
		}
	}

	fclose(in_file);

	if (raw_data_len) {
		printf("Error: unable to read full file content\n");
		goto err;
	}

	/* We can now complete signature generation */
	ret = ec_sign_finalize(&sig_ctx, sig, siglen);
	if (ret) {
		printf("Error: error when signing\n");
		goto err;
	}

	/* Structured export case, forge the full structured file
	 * with HEADER || raw_binary || signature
	 */
	if((hdr_type != NULL) && (version != NULL)){
		/***********************************/
		/* Store the header, the raw data of the file as well as the signature */
		ret = store_sig(in_fname, out_fname, sig, siglen, sig_type,
				hash_type, params.curve_name, &hdr);
		if (ret) {
			printf("Error: error when storing signature to %s\n",
			       out_fname);
			goto err;
		}
	}
	else{
		/* Store the raw binary signature in the output file */
		FILE *out_file;
		size_t written;

		out_file = fopen(out_fname, "w");
		if (out_file == NULL) {
			printf("Error: file %s cannot be opened\n", out_fname);
			goto err;
		}
		written = fwrite(sig, 1, siglen, out_file);
		fclose(out_file);
		if (written != siglen) {
			printf("Error: error when writing to %s\n",
			       out_fname);
			goto err;
		}
	}

	return 0;

 err:
	return -1;
}

/* Dump metadata header */
static int dump_hdr_info(const metadata_hdr * hdr)
{
	/* Dump the header */
	printf("Metadata header info:\n");
	printf("    magic   = 0x%08lx\n", hdr->magic);
	switch (hdr->type) {
	case IMAGE_TYPE0:
		printf("    type    = IMAGE_TYPE0\n");
		break;
	case IMAGE_TYPE1:
		printf("    type    = IMAGE_TYPE1\n");
		break;
	case IMAGE_TYPE2:
		printf("    type    = IMAGE_TYPE2\n");
		break;
	case IMAGE_TYPE3:
		printf("    type    = IMAGE_TYPE3\n");
		break;
	default:
		printf("    type %lu unknown!\n", hdr->type);
		break;
	}
	printf("    version = 0x%08lx\n", hdr->version);
	printf("    len	    = 0x%08lx\n", hdr->len);
	printf("    siglen  = 0x%08lx\n", hdr->siglen);

	return 0;
}

/*
 * Verify signature data from file with appended signature
 */
static int verify_bin_file(const char *ec_name, const char *ec_sig_name,
			   const char *hash_algorithm,
			   const char *in_fname,
			   const char *in_key_fname, const char *in_sig_fname, const char *adata, u16 adata_len)
{
	u8 st_sig[EC_STRUCTURED_SIG_EXPORT_SIZE(EC_MAX_SIGLEN)];
	u8 stored_curve_name[MAX_CURVE_NAME_LEN];
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	struct ec_verify_context verif_ctx;
	ec_sig_alg_type stored_sig_type;
	hash_alg_type stored_hash_type;
	const ec_str_params *ec_str_p;
	ec_sig_alg_type sig_type;
	hash_alg_type hash_type;
	u8 sig[EC_MAX_SIGLEN];
	u8 siglen, st_siglen;
	size_t read, to_read;
	u8 buf[MAX_BUF_LEN];
	u8 pub_key_buf_len;
	size_t raw_data_len;
	ec_pub_key pub_key;
	FILE *in_key_file;
	FILE *in_sig_file;
	ec_params params;
	metadata_hdr hdr;
	size_t exp_len;
	FILE *in_file;
	int ret, eof;

	MUST_HAVE(ec_name != NULL);

	/************************************/
	/* Get parameters from pretty names */
	if (string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
			     hash_algorithm, &hash_type)) {
		goto err;
	}
	/* Check if ancillary data will be used */
	check_ancillary_data(adata, sig_type, ec_sig_name);
	/* Import the parameters */
	import_params(&params, ec_str_p);

	ret = ec_get_sig_len(&params, sig_type, hash_type, &siglen);
	if (ret) {
		printf("Error getting effective signature length from %s\n",
		       (const char *)(ec_str_p->name->buf));
		goto err;
	}

	/************************************/
	/* Import the public key from the file */
	in_key_file = fopen(in_key_fname, "r");
	if (in_key_file == NULL) {
		printf("Error: file %s cannot be opened\n", in_key_fname);
		goto err;
	}
	pub_key_buf_len =(u8)fread(pub_key_buf, 1, sizeof(pub_key_buf),
				   in_key_file);
	fclose(in_key_file);
	ret = ec_structured_pub_key_import_from_buf(&pub_key, &params,
						    pub_key_buf,
						    pub_key_buf_len, sig_type);
	if (ret) {
		printf("Error: error when importing public key from %s\n",
		       in_key_fname);
		goto err;
	}

	/* Let's first get file size */
	ret = get_file_size(in_fname, &raw_data_len);
	if (ret) {
		printf("Error: cannot retrieve file %s size\n", in_fname);
		goto err;
	}

	/* Open main file to verify ... */
	in_file = fopen(in_fname, "r");
	if (in_file == NULL) {
		printf("Error: file %s cannot be opened\n", in_fname);
		goto err;
	}

	/*
	 * We are in 'structured' mode, read the header and get the information
	 * from it
	 */
	if (in_sig_fname == NULL) {
		/* ... and first read metadata header */
		read = fread(&hdr, 1, sizeof(hdr), in_file);
		if (read != sizeof(hdr)) {
			printf("Error: unable to read metadata header "
			       "from file\n");
			fclose(in_file);
			goto err;
		}

		/* Sanity checks on the header we get */
		if (hdr.magic != HDR_MAGIC) {
			printf("Error: got magic 0x%08lx instead of 0x%08x "
			       "from metadata header\n", hdr.magic, HDR_MAGIC);
			goto err;
		}

		st_siglen = EC_STRUCTURED_SIG_EXPORT_SIZE(siglen);
		MUST_HAVE(raw_data_len > (sizeof(hdr) + st_siglen));
		exp_len = raw_data_len - sizeof(hdr) - st_siglen;
		if (hdr.len != exp_len) {
			printf("Error: got raw size of %lu instead of %lu from "
			       "metadata header\n", hdr.len,
			       (unsigned long)exp_len);
			goto err;
		}

		if (hdr.siglen != st_siglen) {
			printf("Error: got siglen %lu instead of %d from "
			       "metadata header\n", hdr.siglen, siglen);
			goto err;
		}

		/* Dump the header */
		dump_hdr_info(&hdr);

		/*
		 * We now need to seek in file to get structured signature.
		 * Before doing that, let's first check size is large enough.
		 */
		if (raw_data_len < (sizeof(hdr) + st_siglen)) {
			goto err;
		}

		ret = fseek(in_file, (long)(raw_data_len - st_siglen),
			    SEEK_SET);
		if (ret) {
			printf("Error: file %s cannot be seeked\n", in_fname);
			goto err;
		}
		read = fread(st_sig, 1, st_siglen, in_file);
		if (read != st_siglen) {
			printf("Error: unable to read structure sig from "
			       "file\n");
			fclose(in_file);
			goto err;
		}
		/* Import the signature from the structured signature buffer */
		ret = ec_structured_sig_import_from_buf(sig, siglen,
							st_sig, st_siglen,
							&stored_sig_type,
							&stored_hash_type,
							stored_curve_name);
		if (ret) {
			printf("Error: error when importing signature "
			       "from %s\n", in_fname);
			goto err;
		}
		if (stored_sig_type != sig_type) {
			printf("Error: signature type imported from signature "
			       "mismatches with %s\n", ec_sig_name);
			goto err;
		}
		if (stored_hash_type != hash_type) {
			printf("Error: hash algorithm type imported from "
			       "signature mismatches with %s\n",
			       hash_algorithm);
			goto err;
		}
		if (!are_str_equal((char *)stored_curve_name,
				   (char *)params.curve_name)) {
			printf("Error: curve type '%s' imported from signature "
			       "mismatches with '%s'\n", stored_curve_name,
			       params.curve_name);
			goto err;
		}

		/*
		 * Get back to the beginning of file, at the beginning of header
		 */
		if (fseek(in_file, 0, SEEK_SET)) {
			printf("Error: file %s cannot be seeked\n", in_fname);
			goto err;
		}
		exp_len += sizeof(hdr);
	} else {
		/* Get the signature size */
		ret = get_file_size(in_sig_fname, &to_read);
		if (ret) {
			printf("Error: cannot retrieve file %s size\n",
			       in_sig_fname);
			goto err;
		}
		if((to_read > EC_MAX_SIGLEN) || (to_read > 255)){
			/* This is not an expected size, get out */
			printf("Error: size %d of signature in %s is > max "
			       "signature size %d or > 255",
			       (int)to_read, in_sig_fname, EC_MAX_SIGLEN);
			goto err;
		}
		siglen = (u8)to_read;
		/* Read the raw signature from the signature file */
		in_sig_file = fopen(in_sig_fname, "r");
		if (in_sig_file == NULL) {
			printf("Error: file %s cannot be opened\n",
			       in_sig_fname);
			goto err;
		}
		read = fread(&sig, 1, siglen, in_sig_file);
		fclose(in_sig_file);
		if (read != siglen) {
			printf("Error: unable to read signature from %s\n",
			       in_sig_fname);
			goto err;
		}
		exp_len = raw_data_len;
	}

	/*
	 * ... and read file content chunk by chunk to compute signature
	 */
	ret = ec_verify_init(&verif_ctx, &pub_key, sig, siglen,
			     sig_type, hash_type, (const u8*)adata, adata_len);
	if (ret) {
		goto err;
	}

	eof = 0;
	clearerr(in_file);
	while (exp_len && !eof) {
		to_read = (exp_len < sizeof(buf)) ? exp_len : sizeof(buf);
		read = fread(buf, 1, to_read, in_file);
		if (read != to_read) {
			/* Check if this was EOF */
			ret = feof(in_file);
			clearerr(in_file);
			if (ret) {
				eof = 1;
			}
		}

		if (read > exp_len) {
			/* we read more than expected: leave! */
			break;
		}

		exp_len -= read;

		ret = ec_verify_update(&verif_ctx, buf, (u32)read);
		if (ret) {
			break;
		}
	}

	fclose(in_file);

	if (exp_len) {
		printf("Error: unable to read full file content\n");
		goto err;
	}

	ret = ec_verify_finalize(&verif_ctx);
	if (ret) {
		goto err;
	}

	return ret;

 err:
	return -1;
}

/* Compute 'scalar * Point' on the provided curve and prints
 * the result.
 */
static int ec_scalar_mult(const char *ec_name,
			  const char *scalar_file,
			  const char *point_file,
			  const char *outfile_name)
{
	const ec_str_params *ec_str_p;
	ec_params curve_params;
	int ret;
	u8 buf[MAX_BUF_LEN];
	size_t buf_len;
	FILE *in_file;
	FILE *out_file;
	u16 coord_len;

	/* Scalar (natural number) to import */
	nn d;
	/* Point to import */
	prj_pt Q;

	MUST_HAVE(ec_name != NULL);
	MUST_HAVE(scalar_file != NULL);
	MUST_HAVE(point_file != NULL);
	MUST_HAVE(outfile_name != NULL);

	/* Get parameters from pretty names */
	ret = string_to_params(ec_name, NULL, NULL, &ec_str_p,
			       NULL, NULL);
	if (ret) {
		goto err;
	}

	/* Import the parameters */
	import_params(&curve_params, ec_str_p);

	/* Import the scalar in the local buffer from the file */
	/* Let's first get file size */
	ret = get_file_size(scalar_file, &buf_len);
	if (ret) {
		printf("Error: cannot retrieve file %s size\n", scalar_file);
		goto err;
	}
	if(buf_len > sizeof(buf)){
		printf("Error: file %s content too large for our local buffers\n", scalar_file);
		goto err;
	}
	/* Open main file to verify ... */
	in_file = fopen(scalar_file, "r");
	if (in_file == NULL) {
		printf("Error: file %s cannot be opened\n", scalar_file);
		goto err;
	}
	/* Read the content of the file */
	if(fread(buf, 1, buf_len, in_file) != buf_len){
		printf("Error: error when reading in %s\n", scalar_file);
		goto err;
	}
	fclose(in_file);
	/* Import the scalar */
	nn_init_from_buf(&d, buf, (u16)buf_len);

	/* Import the point in the local buffer from the file */
	/* Let's first get file size */
	ret = get_file_size(point_file, &buf_len);
	if (ret) {
		printf("Error: cannot retrieve file %s size\n", point_file);
		goto err;
	}
	if(buf_len > sizeof(buf)){
		printf("Error: file %s content too large for our local buffers\n", point_file);
		goto err;
	}
	/* Open main file to verify ... */
	in_file = fopen(point_file, "r");
	if (in_file == NULL) {
		printf("Error: file %s cannot be opened\n", point_file);
		goto err;
	}
	/* Read the content of the file */
	if(fread(buf, 1, buf_len, in_file) != buf_len){
		fclose(in_file);
		printf("Error: error when reading in %s\n", point_file);
		goto err;
	}
	fclose(in_file);
	/* Import the point */
	if(prj_pt_import_from_buf(&Q, buf, (u16)buf_len, &(curve_params.ec_curve))){
		printf("Error: error when importing the projective point from %s\n", point_file);
		goto err;
	}

#ifdef USE_SIG_BLINDING
	/* NB: we use a blind scalar multiplication here since we do not want our
	 * private d to leak ...
	 */
	prj_pt_mul_monty_blind(&Q, &d, &Q);
#else
	prj_pt_mul_monty(&Q, &d, &Q);
#endif
	/* Get the unique representation of the point */
	prj_pt_unique(&Q, &Q);

	/* Export the projective point in the local buffer */
	coord_len = 3 * BYTECEIL((Q.crv)->a.ctx->p_bitlen);
	if(coord_len > sizeof(buf)){
		nn_uninit(&d);
		prj_pt_uninit(&Q);
		printf("Error: error when exporting the point\n");
		goto err;
	}
	if(prj_pt_export_to_buf(&Q, buf, coord_len)){
		nn_uninit(&d);
		prj_pt_uninit(&Q);
		printf("Error: error when exporting the point\n");
		goto err;
	}
	/* Now save the coordinates in the output file */
	out_file = fopen(outfile_name, "w");
	if (out_file == NULL) {
		nn_uninit(&d);
		prj_pt_uninit(&Q);
		printf("Error: file %s cannot be opened\n", outfile_name);
		goto err;
	}

	/* Write in the file */
	if(fwrite(buf, 1, coord_len, out_file) != coord_len){
		fclose(out_file);
		nn_uninit(&d);
		prj_pt_uninit(&Q);
		printf("Error: error when writing to %s\n", outfile_name);
		goto err;
	}

	fclose(out_file);
	/* Uninit local variables */
	nn_uninit(&d);
	prj_pt_uninit(&Q);

	return 0;

err:
	return -1;
}


static void print_curves(void)
{
       u8 i;

       /* Print all the available curves */
       for (i = 0; i < EC_CURVES_NUM; i++) {
	       printf("%s ", (const char *)(ec_maps[i].params->name->buf));
       }

       return;
}

static void print_hash_algs(void)
{
       int i;

       /* Print all the available hash functions */
       for (i = 0; hash_maps[i].type != UNKNOWN_HASH_ALG; i++) {
	       printf("%s ", hash_maps[i].name);
       }

       return;
}

static void print_sig_algs(void)
{
	int i;

	/* Print all the available signature schemes */
	for (i = 0; ec_sig_maps[i].type != UNKNOWN_SIG_ALG; i++) {
		printf("%s ", ec_sig_maps[i].name);
	}

	return;
}

static void print_help(const char *prog_name)
{
	printf("%s expects at least one argument\n", prog_name);
	printf("\targ1 = 'gen_keys', 'sign', 'verify', 'struct_sign', 'struct_verify' or 'scalar_mult'\n");
	return;
}

int main(int argc, char *argv[])
{
	/* Some mockup code to be able to compile in CRYPTOFUZZ mode although
	 * setjmp/longjmp are used.
	 */
#if defined(USE_CRYPTOFUZZ) /* CRYPTOFUZZ mode */
	/* Save our context */
	cryptofuzz_save()
#endif

	if (argc < 2) {
		print_help(argv[0]);
		return -1;
	}

	if (are_str_equal(argv[1], "gen_keys")) {
		/* Generate keys ---------------------------------
		 *
		 * arg1 = curve name ("frp256v1", ...)
		 * arg2 = algorithm type ("ECDSA", "ECKCDSA", ...)
		 * arg3 = file name prefix
		 */
		if (argc != 5){
			printf("Bad args number for %s %s:\n", argv[0],
			       argv[1]);
			printf("\targ1 = curve name: ");
			print_curves();
			printf("\n");

			printf("\targ2 = signature algorithm type: ");
			print_sig_algs();
			printf("\n");

			printf("\targ3 = file name prefix\n");
			printf("\n");

			return -1;
		}
		if(generate_and_export_key_pair(argv[2], argv[3], argv[4])){
			return -1;
		}
	}
	else if (are_str_equal(argv[1], "sign")) {
		/* Sign something --------------------------------
		 * Signature is structured, i.e. the output is a self contained
		 * data image
		 * arg1 = curve name ("frp256v1", ...)
		 * arg2 = signature algorithm type ("ECDSA", "ECKCDSA", ...)
		 * arg3 = hash algorithm type ("SHA256", "SHA512", ...)
		 * arg4 = input file to sign
		 * arg5 = input file containing the private key
		 * arg6 = output file containing the signature
		 * arg7 (optional) = ancillary data to be used
		 */
		if ((argc != 8) && (argc != 9)) {
			printf("Bad args number for %s %s:\n", argv[0],
			       argv[1]);
			printf("\targ1 = curve name: ");
			print_curves();
			printf("\n");

			printf("\targ2 = signature algorithm type: ");
			print_sig_algs();
			printf("\n");

			printf("\targ3 = hash algorithm type: ");
			print_hash_algs();
			printf("\n");

			printf("\targ4 = input file to sign\n");
			printf("\targ5 = input file containing the private key (in raw binary format)\n");
			printf("\targ6 = output file containing the signature\n");
			printf("\t<arg7 (optional) = ancillary data to be used>\n");
			return -1;
		}
		const char *adata = NULL;
		u16 adata_len = 0;
		if(argc == 9){
			adata = argv[8];
			adata_len = (u16)local_strlen(adata);
		}
		if(sign_bin_file(argv[2], argv[3], argv[4], argv[5], argv[6],
			      argv[7], NULL, NULL, adata, adata_len)){
			return -1;
		}
	}
	else if (are_str_equal(argv[1], "verify")) {
		/* Verify something ------------------------------
		 *
		 * arg1 = curve name ("frp256v1", ...)
		 * arg2 = signature algorithm type ("ECDSA", "ECKCDSA", ...)
		 * arg3 = hash algorithm type ("SHA256", "SHA512", ...)
		 * arg = input file to verify
		 * arg5 = input file with the public key
		 * arg6 = input file containing the signature
		 * arg7 (optional) = ancillary data to be used
		 */
		if ((argc != 8) && (argc != 9)) {
			printf("Bad args number for %s %s:\n", argv[0],
			       argv[1]);
			printf("\targ1 = curve name: ");
			print_curves();
			printf("\n");

			printf("\targ2 = signature algorithm type: ");
			print_sig_algs();
			printf("\n");

			printf("\targ3 = hash algorithm type: ");
			print_hash_algs();
			printf("\n");

			printf("\targ4 = input file to verify\n");
			printf("\targ5 = input file containing the public key (in raw binary format)\n");
			printf("\t<arg7 (optional) = ancillary data to be used>\n");
			return -1;
		}
		const char *adata = NULL;
		u16 adata_len = 0;
		if(argc == 9){
			adata = argv[8];
			adata_len = (u16)local_strlen(adata);
		}
		if (verify_bin_file(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], adata, adata_len)) {
			printf("Signature check of %s failed\n", argv[5]);
			return -1;
		} else {
			printf("Signature check of %s OK\n", argv[5]);
		}
	}
	else if (are_str_equal(argv[1], "struct_sign")) {
		/* Sign something --------------------------------
		 * Signature is structured, i.e. the output is a self contained
		 * data image
		 * arg1 = curve name ("frp256v1", ...)
		 * arg2 = signature algorithm type ("ECDSA", "ECKCDSA", ...)
		 * arg3 = hash algorithm type ("SHA256", "SHA512", ...)
		 * arg4 = input file to sign
		 * arg5 = input file with the private key
		 * arg6 = output file containing the appended signature
		 * arg7 = metadata header type
		 * arg8 = version of the metadata header
		 * arg9 (optional) = ancillary data to be used
		 */
		if ((argc != 10) && (argc != 11)) {
			printf("Bad args number for %s %s:\n", argv[0],
			       argv[1]);
			printf("\targ1 = curve name: ");
			print_curves();
			printf("\n");

			printf("\targ2 = signature algorithm type: ");
			print_sig_algs();
			printf("\n");

			printf("\targ3 = hash algorithm type: ");
			print_hash_algs();
			printf("\n");

			printf("\targ4 = input file to sign\n");
			printf("\targ5 = input file containing the private key (in raw binary format)\n");
			printf("\targ6 = output file containing the appended signature\n");
			printf("\targ7 = metadata header type (IMAGE_TYPE0, IMAGE_TYPE1, ...)\n");
			printf("\targ8 = version of the metadata header\n");
			printf("\t<arg9 (optional) = ancillary data to be used>\n");
			return -1;
		}
		const char *adata = NULL;
		u16 adata_len = 0;
		if(argc == 11){
			adata = argv[10];
			adata_len = (u16)local_strlen(adata);
		}
		if(sign_bin_file(argv[2], argv[3], argv[4], argv[5], argv[6],
			      argv[7], argv[8], argv[9], adata, adata_len)){
			return -1;
		}
	}
	else if (are_str_equal(argv[1], "struct_verify")) {
		/* Verify something ------------------------------
		 *
		 * arg1 = curve name ("frp256v1", ...)
		 * arg2 = signature algorithm type ("ECDSA", "ECKCDSA", ...)
		 * arg3 = hash algorithm type ("SHA256", "SHA512", ...)
		 * arg4 = input file to verify
		 * arg5 = input file containing the public key (in raw binary format)
		 * arg6 (optional) = ancillary data to be used
		 */
		if ((argc != 7) && (argc != 8)) {
			printf("Bad args number for %s %s:\n", argv[0],
			       argv[1]);
			printf("\targ1 = curve name: ");
			print_curves();
			printf("\n");

			printf("\targ2 = signature algorithm type: ");
			print_sig_algs();
			printf("\n");

			printf("\targ3 = hash algorithm type: ");
			print_hash_algs();
			printf("\n");

			printf("\targ4 = input file to verify\n");
			printf("\targ5 = input file containing the public key (in raw binary format)\n");
			printf("\t<arg6 (optional) = ancillary data to be used>\n");
			return -1;
		}
		const char *adata = NULL;
		u16 adata_len = 0;
		if(argc == 8){
			adata = argv[7];
			adata_len = (u16)local_strlen(adata);
		}
		if (verify_bin_file(argv[2], argv[3], argv[4], argv[5], argv[6], NULL, adata, adata_len)) {
			printf("Signature check of %s failed\n", argv[5]);
			return -1;
		} else {
			printf("Signature check of %s OK\n", argv[5]);
		}
	}
	else if (are_str_equal(argv[1], "scalar_mult")) {
		/* Point scalar multiplication --------------------
		 *
		 * arg1 = curve name ("frp256v1", ...)
		 * arg2 = scalar
		 * arg3 = point to multiply
		 * arg4 = file name where to save the result
		 */
		if (argc != 6) {
			printf("Bad args number for %s %s:\n", argv[0],
			       argv[1]);
			printf("\targ1 = curve name: ");
			print_curves();
			printf("\n");

			printf("\targ2 = scalar bin file\n");
			printf("\targ3 = point to multiply bin file (projective coordinates)\n");
			printf("\targ4 = file name where to save the result\n");
			return -1;
		}
		if(ec_scalar_mult(argv[2], argv[3], argv[4], argv[5])){
			printf("Scalar multiplication failed\n");
			return -1;
		}
	}

	else{
		/* Bad first argument, print help */
		printf("Bad first argument '%s'\n", argv[1]);
		print_help(argv[0]);
		return -1;
	}

	return 0;
}
