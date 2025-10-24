// SPDX-License-Identifier: GPL-2.0-or-later
/* Signature verification with an asymmetric key
 *
 * See Documentation/crypto/asymmetric-keys.rst
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "SIG: "fmt
#include <keys/asymmetric-subtype.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/keyctl.h>
#include <crypto/public_key.h>
#include <keys/user-type.h>
#include "asymmetric_keys.h"
#include <crypto/api.h>

/*
 * Destroy a public key signature.
 */
void CRYPTO_API(public_key_signature_free)(struct public_key_signature *sig)
{
	int i;

	if (sig) {
		for (i = 0; i < ARRAY_SIZE(sig->auth_ids); i++)
			kfree(sig->auth_ids[i]);
		kfree(sig->s);
		kfree(sig->digest);
		kfree(sig);
	}
}
DEFINE_CRYPTO_API(public_key_signature_free);

/**
 * query_asymmetric_key - Get information about an asymmetric key.
 * @params: Various parameters.
 * @info: Where to put the information.
 */
int CRYPTO_API(query_asymmetric_key)(const struct kernel_pkey_params *params,
			 struct kernel_pkey_query *info)
{
	const struct asymmetric_key_subtype *subtype;
	struct key *key = params->key;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (key->type != &key_type_asymmetric)
		return -EINVAL;
	subtype = asymmetric_key_subtype(key);
	if (!subtype ||
	    !key->payload.data[0])
		return -EINVAL;
	if (!subtype->query)
		return -ENOTSUPP;

	ret = subtype->query(params, info);

	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}
DEFINE_CRYPTO_API(query_asymmetric_key);

/**
 * encrypt_blob - Encrypt data using an asymmetric key
 * @params: Various parameters
 * @data: Data blob to be encrypted, length params->data_len
 * @enc: Encrypted data buffer, length params->enc_len
 *
 * Encrypt the specified data blob using the private key specified by
 * params->key.  The encrypted data is wrapped in an encoding if
 * params->encoding is specified (eg. "pkcs1").
 *
 * Returns the length of the data placed in the encrypted data buffer or an
 * error.
 */
int CRYPTO_API(encrypt_blob)(struct kernel_pkey_params *params,
		 const void *data, void *enc)
{
	params->op = kernel_pkey_encrypt;
	return asymmetric_key_eds_op(params, data, enc);
}
DEFINE_CRYPTO_API(encrypt_blob);

/**
 * decrypt_blob - Decrypt data using an asymmetric key
 * @params: Various parameters
 * @enc: Encrypted data to be decrypted, length params->enc_len
 * @data: Decrypted data buffer, length params->data_len
 *
 * Decrypt the specified data blob using the private key specified by
 * params->key.  The decrypted data is wrapped in an encoding if
 * params->encoding is specified (eg. "pkcs1").
 *
 * Returns the length of the data placed in the decrypted data buffer or an
 * error.
 */
int CRYPTO_API(decrypt_blob)(struct kernel_pkey_params *params,
		 const void *enc, void *data)
{
	params->op = kernel_pkey_decrypt;
	return asymmetric_key_eds_op(params, enc, data);
}
DEFINE_CRYPTO_API(decrypt_blob);

/**
 * create_signature - Sign some data using an asymmetric key
 * @params: Various parameters
 * @data: Data blob to be signed, length params->data_len
 * @enc: Signature buffer, length params->enc_len
 *
 * Sign the specified data blob using the private key specified by params->key.
 * The signature is wrapped in an encoding if params->encoding is specified
 * (eg. "pkcs1").  If the encoding needs to know the digest type, this can be
 * passed through params->hash_algo (eg. "sha1").
 *
 * Returns the length of the data placed in the signature buffer or an error.
 */
int CRYPTO_API(create_signature)(struct kernel_pkey_params *params,
		     const void *data, void *enc)
{
	params->op = kernel_pkey_sign;
	return asymmetric_key_eds_op(params, data, enc);
}
DEFINE_CRYPTO_API(create_signature);

/**
 * verify_signature - Initiate the use of an asymmetric key to verify a signature
 * @key: The asymmetric key to verify against
 * @sig: The signature to check
 *
 * Returns 0 if successful or else an error.
 */
int CRYPTO_API(verify_signature)(const struct key *key,
		     const struct public_key_signature *sig)
{
	const struct asymmetric_key_subtype *subtype;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (key->type != &key_type_asymmetric)
		return -EINVAL;
	subtype = asymmetric_key_subtype(key);
	if (!subtype ||
	    !key->payload.data[0])
		return -EINVAL;
	if (!subtype->verify_signature)
		return -ENOTSUPP;

	ret = subtype->verify_signature(key, sig);

	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}
DEFINE_CRYPTO_API(verify_signature);
