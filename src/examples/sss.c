/*
 *  Copyright (C) 2021 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "sss.h"


/*
 * The purpose of this example is to implement the SSS
 * (Shamir's Secret Sharing) scheme based on libecc arithmetic
 * primitives. The scheme is implemented over a ~256 bit prime
 * field.
 *
 * Secret sharing allows to combine some shares (at least k among n >= k)
 * to regenerate a secret. The current code also ensures the integrity
 * of the shares using HMAC. A maximum of (2**16 - 1) shares can be
 * generated, and beware that the time complexity of generation heavily
 * increases with k and n, and the time complexity of shares combination
 * increases with k.
 *
 * Shares regeneration from exisiting ones is also offered although it
 * is expensive in CPU cycles (as the Lagrange interpolation polynomials
 * have to be evaluated for each existing share before computing new ones).
 *
 * !! DISCLAIMER !!
 * ================
 * Some efforts have been put on providing a clean code and constant time
 * as well as some SCA (side-channel attacks) resistance (e.g. blinding some
 * operations manipulating secrets). However, no absolute guarantee can be made:
 * use this code knowingly and at your own risk!
 *
 * Also, as for all other libecc primitives, beware of randomness sources. By default,
 * the library uses the OS random sources (e.g. "/dev/urandom"), but the user
 * is encouraged to adapt the ../external_deps/rand.c source file to combine
 * multiple sources and add entropy there depending on the context where this
 * code is integrated. The security level of all the cryptographic primitives
 * heavily relies on random sources quality.
 *
 */


/* The prime number we use: it is close to (2**256-1) but still stricly less
 * than this value, hence a theoretical security of more than 255 bits but less than
 * 256 bits.
 *
 * This can be modified with another prime, beware however of the size
 * of the prime to be in line with the shared secrets sizes, and also
 * that all our shares and secret lie in Fp, and hence are < p,
 *
 * Although bigger primes could be used, beware that SSS shares recombination
 * complexity is quadratic in the number of shares, yielding impractical
 * computation time when the prime is too big. Also, some elements related to
 * the share generation (_sss_derive_seed) must be adapated to keep proper entropy
 * if the prime (size) is modified.
 */
static const u8 prime[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
};

ATTRIBUTE_WARN_UNUSED_RET static int _sss_derive_seed(fp_t out, const u8 seed[SSS_SECRET_SIZE], u16 idx)
{
	int ret;
	u8 hmac_val[SHA512_DIGEST_SIZE];
	u8 C[2];
	u8 len;
	nn nn_val;

	/* Sanity check on sizes to avoid entropy loss through reduction biases */
	MUST_HAVE((SHA512_DIGEST_SIZE >= (2 * SSS_SECRET_SIZE)), ret, err);

	/* out must be initialized with a context */
	ret = fp_check_initialized(out);

	ret = local_memset(hmac_val, 0, sizeof(hmac_val)); EG(ret, err);
	ret = local_memset(C, 0, sizeof(C)); EG(ret, err);

	/* Export our idx in big endian representation on two bytes */
	C[0] = ((idx >> 8) & 0xff);
	C[1] = (idx & 0xff);

	len = sizeof(hmac_val);
	ret = hmac(seed, SSS_SECRET_SIZE, SHA512, C, sizeof(C), hmac_val, &len); EG(ret, err);

	ret = nn_init_from_buf(&nn_val, hmac_val, len); EG(ret, err);
	/* Since we will put this in Fp, take the modulo */
	ret = nn_mod(&nn_val, &nn_val, &(out->ctx->p)); EG(ret, err);
	/* Now import our reduced value in Fp as the result of the derivation */
	ret = fp_set_nn(out, &nn_val);

err:
	/* Cleanup secret data */
	IGNORE_RET_VAL(local_memset(hmac_val, 0, sizeof(hmac_val)));
	IGNORE_RET_VAL(local_memset(C, 0, sizeof(C)));
	nn_uninit(&nn_val);

	return ret;
}

/***** Raw versions ***********************/
/* SSS shares and secret generation */
ATTRIBUTE_WARN_UNUSED_RET static int _sss_raw_generate(sss_share *shares, u16 k, u16 n, sss_secret *secret, bool input_secret)
{
	fp_ctx ctx;
	nn p;
	fp a0, a, s;
	fp exp, base, tmp;
	fp blind, blind_inv;
	u8 secret_seed[SSS_SECRET_SIZE];
	u16 idx;
	int ret;
	unsigned int i, j;
	p.magic = WORD(0);
	exp.magic = base.magic = tmp.magic = s.magic = a.magic = a0.magic = WORD(0);
	blind.magic = blind_inv.magic = WORD(0);

	ret = local_memset(secret_seed, 0, sizeof(secret_seed)); EG(ret, err);

	MUST_HAVE((shares != NULL) && (secret != NULL), ret, err);
	/* Sanity checks */
	MUST_HAVE((k <= n), ret, err);
	MUST_HAVE((k >= 1), ret, err);
	MUST_HAVE((SSS_SECRET_SIZE == sizeof(prime)), ret, err);

	/* Import our prime number and create the Fp context */
	ret = nn_init_from_buf(&p, prime, sizeof(prime)); EG(ret, err);
	ret = fp_ctx_init_from_p(&ctx, &p); EG(ret, err);

	/* Generate a secret seed of the size of the secret that will be our base to
	 * generate the plolynomial coefficients.
	 */
	ret = get_random(secret_seed, sizeof(secret_seed)); EG(ret, err);
	/* NOTE: although we could generate all our a[i] coefficients using our randomness
	 * source, we prefer to derive them from a single secret seed in order to optimize
	 * the storage space as our share generation algorithm needs to parse these a[i] multiple
	 * times. This time / memory tradeoff saves a lot of memory space for embedded contexts and
	 * avoids "malloc" usage (preserving the "no dynamic allocation" philosophy of libecc).
	 *
	 * Our secret seed is SSS_SECRET_SIZE long, so on the security side there should be no
	 * no loss of strength/entropy. For each inded i, a[i] is computed as follows:
	 *
	 * a[i] = HMAC(secret_seed, i) where the HMAC is interpreted as a value in Fp (i.e. modulo
	 * p), and i is represented as a string of 2 elements. The HMAC uses a hash function of at
	 * least twice the size of the secret to avoid biases in modular reduction.
	 */

	/* a0 is either derived from the secret seed or taken from input if
	 * provided.
	 */
	ret = fp_init(&a0, &ctx); EG(ret, err);
	if(input_secret == true){
		/* Import the secret the user provides
		 * XXX: NOTE: the user shared secret MUST be in Fp! Since our prime is < (2**256 - 1),
		 * some 256 bit strings can be rejected here.
		 */
		ret = fp_import_from_buf(&a0, secret->secret, SSS_SECRET_SIZE); EG(ret, err);
	}
	else{
		/* Generate the secret from our seed */
		ret = _sss_derive_seed(&a0, secret_seed, 0);
	}

	/* Compute the shares P(x) for x in [1, ..., n] */
	ret = fp_init(&base, &ctx); EG(ret, err);
	ret = fp_init(&exp, &ctx); EG(ret, err);
	ret = fp_init(&tmp, &ctx); EG(ret, err);
	ret = fp_init(&s, &ctx); EG(ret, err);
	ret = fp_init(&a, &ctx); EG(ret, err);
	/* Get a random blind mask and inverse it */
	ret = fp_get_random(&blind, &ctx); EG(ret, err);
	ret = fp_init(&blind_inv, &ctx); EG(ret, err);
	ret = fp_inv(&blind_inv, &blind); EG(ret, err);
	/* Generate a random index base for x to avoid leaking
	 * the number of shares.
	 */
	ret = get_random((u8*)&idx, sizeof(idx)); EG(ret, err);
	for(i = 0; i < n; i++){
		u16 curr_idx = (u16)(idx + i);
		/* Set s[i] to the a[0] as blinded initial value */
		ret = fp_mul(&s, &blind, &a0); EG(ret, err);
		/* Get a random base x as u16 for share index */
		ret = fp_set_word_value(&base, (word_t)(curr_idx)); EG(ret, err);
		/* Set the exp to 1 */
		ret = fp_one(&exp);
		for(j = 1; j < k; j++){
			/* Compute x**j by iterative multiplications */
			ret = fp_mul(&exp, &exp, &base); EG(ret, err);
			/* Compute our a[j] coefficient */
			ret = _sss_derive_seed(&a, secret_seed, (u16)j); EG(ret, err);
			/* Blind a[j] */
			ret = fp_mul(&a, &a, &blind); EG(ret, err);
			/* Accumulate */
			ret = fp_mul(&tmp, &exp, &a); EG(ret, err);
			ret = fp_add(&s, &s, &tmp); EG(ret, err);
		}
		/* Export the computed share */
		shares[i].raw_share.index = curr_idx;
		/* Unblind */
		ret = fp_mul(&s, &s, &blind_inv); EG(ret, err);
		ret = fp_export_to_buf(shares[i].raw_share.share, SSS_SECRET_SIZE, &s); EG(ret, err);
	}
	/* The secret is a[0] */
	ret = fp_export_to_buf(secret->secret, SSS_SECRET_SIZE, &a0);

err:
	/* We can throw away our secret seed now that the shares have
	 * been generated.
	 */
	IGNORE_RET_VAL(local_memset(secret_seed, 0, sizeof(secret_seed)));
	IGNORE_RET_VAL(local_memset(&ctx, 0, sizeof(ctx)));
	nn_uninit(&p);
	fp_uninit(&a0);
	fp_uninit(&a);
	fp_uninit(&s);
	fp_uninit(&base);
	fp_uninit(&exp);
	fp_uninit(&tmp);
	fp_uninit(&blind);
	fp_uninit(&blind_inv);

	return ret;
}

/* SSS helper to compute lagrange interpolation on an input value.
 */
ATTRIBUTE_WARN_UNUSED_RET static int _sss_raw_lagrange(const sss_share *shares, u16 k, sss_secret *secret, u16 val)
{
	fp_ctx ctx;
	nn p;
	fp s, x, y;
	fp x_i, x_j, tmp, tmp2;
	fp blind, blind_inv;
	int ret;
	unsigned int i, j;
	p.magic = WORD(0);
	x_i.magic = x_j.magic = tmp.magic = tmp2.magic = s.magic = y.magic = x.magic = WORD(0);
	blind.magic = blind_inv.magic = WORD(0);

	MUST_HAVE((shares != NULL) && (secret != NULL), ret, err);
	/* Sanity checks */
	MUST_HAVE((k >= 1), ret, err);
	MUST_HAVE((SSS_SECRET_SIZE == sizeof(prime)), ret, err);

	/* Import our prime number and create the Fp context */
	ret = nn_init_from_buf(&p, prime, sizeof(prime)); EG(ret, err);
	ret = fp_ctx_init_from_p(&ctx, &p); EG(ret, err);

	/* Recombine our shared secrets */
	ret = fp_init(&s, &ctx); EG(ret, err);
	ret = fp_init(&y, &ctx); EG(ret, err);
	ret = fp_init(&x_i, &ctx); EG(ret, err);
	ret = fp_init(&x_j, &ctx); EG(ret, err);
	ret = fp_init(&tmp, &ctx); EG(ret, err);
	ret = fp_init(&tmp2, &ctx); EG(ret, err);
	if(val != 0){
		ret = fp_init(&x, &ctx); EG(ret, err);
		ret = fp_set_word_value(&x, (word_t)val); EG(ret, err);
	}
	/* Get a random blind mask and inverse it */
	ret = fp_get_random(&blind, &ctx); EG(ret, err);
	ret = fp_init(&blind_inv, &ctx); EG(ret, err);
	ret = fp_inv(&blind_inv, &blind); EG(ret, err);
	/* Proceed with the interpolation */
	for(i = 0; i < k; i++){
		/* Import s[i] */
		ret = fp_import_from_buf(&s, shares[i].raw_share.share, SSS_SECRET_SIZE); EG(ret, err);
		/* Blind s[i] */
		ret = fp_mul(&s, &s, &blind); EG(ret, err);
		/* Get the index */
		ret = fp_set_word_value(&x_i, (word_t)(shares[i].raw_share.index)); EG(ret, err);
		/* Initialize multiplication with one */
		ret = fp_one(&tmp2); EG(ret, err);
		/* Compute the product for all k other than i */
		for(j = 0; j < k; j++){
			ret = fp_set_word_value(&x_j, (word_t)(shares[j].raw_share.index)); EG(ret, err);
			if(j != i){
				if(val != 0){
					ret = fp_sub(&tmp, &x_j, &x); EG(ret, err);
					ret = fp_mul(&s, &s, &tmp); EG(ret, err);
				}
				else{
					ret = fp_mul(&s, &s, &x_j); EG(ret, err);
				}
				ret = fp_sub(&tmp, &x_j, &x_i); EG(ret, err);
				ret = fp_mul(&tmp2, &tmp2, &tmp); EG(ret, err);
			}
		}
		/* Inverse all the (x_j - x_i) poducts */
		ret = fp_inv(&tmp, &tmp2); EG(ret, err);
		ret = fp_mul(&s, &s, &tmp); EG(ret, err);
		/* Accumulate in secret */
		ret = fp_add(&y, &y, &s); EG(ret, err);
	}
	/* Unblind y */
	ret = fp_mul(&y, &y, &blind_inv); EG(ret, err);
	/* We should have our secret in y */
	ret = fp_export_to_buf(secret->secret, SSS_SECRET_SIZE, &y);

err:
	IGNORE_RET_VAL(local_memset(&ctx, 0, sizeof(ctx)));
	nn_uninit(&p);
	fp_uninit(&s);
	fp_uninit(&y);
	fp_uninit(&x_i);
	fp_uninit(&x_j);
	fp_uninit(&tmp);
	fp_uninit(&tmp2);
	fp_uninit(&blind);
	fp_uninit(&blind_inv);
	if(val != 0){
		fp_uninit(&x);
	}

	return ret;
}


/* SSS shares and secret combination */
ATTRIBUTE_WARN_UNUSED_RET static int _sss_raw_combine(const sss_share *shares, u16 k, sss_secret *secret)
{
	return _sss_raw_lagrange(shares, k, secret, 0);
}

/***** Secure versions ***********************/
/* SSS shares and secret generation */
int sss_generate(sss_share *shares, u16 k, u16 n, sss_secret *secret, bool input_secret)
{
	int ret;
	unsigned int i;
	u8 len;

	/* Generate raw shares */
	ret = _sss_raw_generate(shares, k, n, secret, input_secret); EG(ret, err);

	/* Sanity check */
	MUST_HAVE((SHA512_DIGEST_SIZE >= sizeof(shares[0].raw_share_hmac)), ret, err);

	/* Compute the authenticity seal for each HMAC */
	for(i = 0; i < n; i++){
		len = sizeof(shares[i].raw_share_hmac);
		/* NOTE: we 'abuse' casts here for shares[i].raw_share to u8*, but this should be OK since
		 * our structures are packed.
		 */
		ret = hmac((const u8*)secret, SSS_SECRET_SIZE, SHA256, (const u8*)&(shares[i].raw_share), sizeof(shares[i].raw_share), shares[i].raw_share_hmac, &len); EG(ret, err);
	}

err:
	return ret;
}


/* SSS shares and secret combination */
int sss_combine(const sss_share *shares, u16 k, sss_secret *secret)
{
	int ret, cmp;
	unsigned int i;
	u8 hmac_val[SHA256_DIGEST_SIZE];
	u8 len;


	ret = local_memset(hmac_val, 0, sizeof(hmac_val)); EG(ret, err);

	/* Recombine raw shares */
	ret = _sss_raw_combine(shares, k, secret); EG(ret, err);

	/* Compute and check the authenticity seal for each HMAC */
	for(i = 0; i < k; i++){
		len = sizeof(shares[i].raw_share_hmac);
		ret = hmac((const u8*)secret, SSS_SECRET_SIZE, SHA256, (const u8*)&(shares[i].raw_share), sizeof(shares[i].raw_share), hmac_val, &len); EG(ret, err);
		ret = are_equal(hmac_val, shares[i].raw_share_hmac, len, &cmp); EG(ret, err);
		if(!cmp){
#ifdef VERBOSE
			ext_printf("[-] sss_combine error for share %d / %d: HMAC is not OK!\n", i, k);
#endif
			ret = -1;
			goto err;
		}
	}

err:
	IGNORE_RET_VAL(local_memset(hmac_val, 0, sizeof(hmac_val)));

	return ret;
}

/* SSS shares regeneration */
int sss_regenerate(sss_share *shares, u16 k, u16 n, sss_secret *secret)
{
	int ret, cmp;
	unsigned int i;
	u16 max_idx;
	u8 hmac_val[SHA256_DIGEST_SIZE];
	u8 len;

	/* Sanity check */
	MUST_HAVE((n >= k), ret, err);

	ret = local_memset(hmac_val, 0, sizeof(hmac_val)); EG(ret, err);

	/* Compute the secret */
	ret = _sss_raw_lagrange(shares, k, secret, 0);
	/* Check the authenticity of our shares */
	for(i = 0; i < k; i++){
		len = sizeof(shares[i].raw_share_hmac);
		/* NOTE: we 'abuse' casts here for shares[i].raw_share to u8*, but this should be OK since
		 * our structures are packed.
		 */
		ret = hmac((const u8*)secret, SSS_SECRET_SIZE, SHA256, (const u8*)&(shares[i].raw_share), sizeof(shares[i].raw_share), hmac_val, &len); EG(ret, err);
		ret = are_equal(hmac_val, shares[i].raw_share_hmac, len, &cmp); EG(ret, err);
		if(!cmp){
#ifdef VERBOSE
			ext_printf("[-] sss_combine error for share %d / %d: HMAC is not OK!\n", i, k);
#endif
			ret = -1;
			goto err;
		}
	}

	/* Our secret regeneration consists of determining the maximum index, and
	 * proceed with Lagrange interpolation on new values.
	 */
	max_idx = 0;
	for(i = 0; i < k; i++){
		if(shares[i].raw_share.index > max_idx){
			max_idx = shares[i].raw_share.index;
		}
	}
	/* Now regenerate as many shares as we need */
	for(i = k; i < n; i++){
		/* NOTE: we 'abuse' casts here for shares[i].raw_share.share to sss_secret*, but this should be OK since
		 * our shares[i].raw_share.share is a SSS_SECRET_SIZE as the sss_secret.secret type encapsulates and our
		 * structures are packed.
		 */
		ret = _sss_raw_lagrange(shares, k, (sss_secret*)shares[i].raw_share.share, (max_idx + (u16)(i - k + 1))); EG(ret, err);
		shares[i].raw_share.index = (max_idx + (u16)(i - k + 1));
		/* Compute the HMAC */
		len = sizeof(shares[i].raw_share_hmac);
		/* NOTE: we 'abuse' casts here for shares[i].raw_share to u8*, but this should be OK since
		 * our structures are packed.
		 */
		ret = hmac((const u8*)secret, SSS_SECRET_SIZE, SHA256, (const u8*)&(shares[i].raw_share), sizeof(shares[i].raw_share), (u8*)&(shares[i].raw_share_hmac), &len); EG(ret, err);
	}

err:
	IGNORE_RET_VAL(local_memset(hmac_val, 0, sizeof(hmac_val)));

	return ret;
}

#ifdef SSS
#include "../utils/print_buf.h"

#define K 50
#define N 150
#define MAX_N 200

int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned int i;
	sss_share shares[MAX_N];
	sss_share shares_[MAX_N];
	sss_secret secret;

	FORCE_USED_VAR(argc);
	FORCE_USED_VAR(argv);

	/* Generate n = 400 shares for SSS with at least K shares OK among N */
	ext_printf("[+] Generating the secrets %d / %d, call should be OK\n", K, N);
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	/* NOTE: 'false' here means that we let the library generate the secret randomly */
	ret = sss_generate(shares, K, N, &secret, false);
	if(ret){
		ext_printf("  [X] Error: sss_generate error\n");
	}
	else{
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE); EG(ret, err);
	}
	/* Shuffle shares */
	for(i = 0; i < N; i++){
		shares_[i] = shares[N - 1 - i];
	}

	/* Combine (k-1) shares: this call should trigger an ERROR */
	ext_printf("[+] Combining the secrets with less shares: call should trigger an error\n");
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	ret = sss_combine(shares_, K - 1, &secret);
	if (ret) {
		ext_printf("  [X] Error: sss_combine error\n");
	} else{
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE);
	}

	/* Combine k shares: this call should be OK and recombine the initial
	 * secret
	 */
	ext_printf("[+] Combining the secrets with minimum shares: call should be OK\n");
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	ret = sss_combine(shares_, K, &secret);
	if (ret) {
		ext_printf("  [X] Error: sss_combine error\n");
	} else {
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE);
	}

	/* Combine k shares: this call should be OK and recombine the initial
	 * secret
	 */
	ext_printf("[+] Combining the secrets with more shares: call should be OK\n");
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	ret = sss_combine(shares_, K + 1, &secret);
	if (ret) {
		ext_printf("  [X] Error: sss_combine error\n");
	} else {
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE);
	}

	/* Combine with a corrupted share: call should trigger an error */
	ext_printf("[+] Combining the secrets with more shares but one corrupted: call should trigger an error\n");
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	shares_[K].raw_share.share[0] = 0x00;
	ret = sss_combine(shares_, K + 1, &secret);
	if (ret) {
		ext_printf("  [X] Error: sss_combine error\n");
	} else {
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE);
	}

	/* Regenerate more shares! call should be OK */
	ext_printf("[+] Regenerating more shares: call should be OK\n");
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	ret = sss_regenerate(shares, K, MAX_N, &secret); EG(ret, err);
	if (ret) {
		ext_printf("  [X] Error: sss_regenerate error\n");
	} else {
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE);
	}
	/* Shuffle shares */
	for(i = 0; i < MAX_N; i++){
		shares_[i] = shares[MAX_N - 1 - i];
	}

	/* Combine newly generated shares: call should be OK */
	ext_printf("[+] Combining the secrets with newly generated shares: call should be OK\n");
	ret = local_memset(&secret, 0x00, sizeof(secret)); EG(ret, err);
	ret = sss_combine(shares_, K, &secret);
	if (ret) {
		ext_printf("  [X] Error: sss_combine error\n");
	} else {
		buf_print("  secret", (u8*)&secret, SSS_SECRET_SIZE);
	}

err:
	return ret;
}
#endif
