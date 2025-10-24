/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Asymmetric public-key algorithm definitions
 *
 * See Documentation/crypto/asymmetric-keys.rst
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_PUBLIC_KEY_H
#define _LINUX_PUBLIC_KEY_H

#include <linux/errno.h>
#include <linux/keyctl.h>
#include <linux/oid_registry.h>
#include <crypto/api.h>

/*
 * Cryptographic data for the public-key subtype of the asymmetric key type.
 *
 * Note that this may include private part of the key as well as the public
 * part.
 */
struct public_key {
	void *key;
	u32 keylen;
	enum OID algo;
	void *params;
	u32 paramlen;
	bool key_is_private;
	const char *id_type;
	const char *pkey_algo;
	unsigned long key_eflags;	/* key extension flags */
#define KEY_EFLAG_CA		0	/* set if the CA basic constraints is set */
#define KEY_EFLAG_DIGITALSIG	1	/* set if the digitalSignature usage is set */
#define KEY_EFLAG_KEYCERTSIGN	2	/* set if the keyCertSign usage is set */
};

DECLARE_CRYPTO_API(public_key_free, void, (struct public_key *key), (key));

/*
 * Public key cryptography signature data
 */
struct public_key_signature {
	struct asymmetric_key_id *auth_ids[3];
	u8 *s;			/* Signature */
	u8 *digest;
	u32 s_size;		/* Number of bytes in signature */
	u32 digest_size;	/* Number of bytes in digest */
	const char *pkey_algo;
	const char *hash_algo;
	const char *encoding;
};

DECLARE_CRYPTO_API(public_key_signature_free, void, (struct public_key_signature *sig), (sig));

#ifndef FIPS_MODULE
#define public_key_subtype nonfips_public_key_subtype
#else
#define public_key_subtype fips_public_key_subtype
#endif
extern struct asymmetric_key_subtype public_key_subtype;

struct key;
struct key_type;
union key_payload;

extern int restrict_link_by_signature(struct key *dest_keyring,
				      const struct key_type *type,
				      const union key_payload *payload,
				      struct key *trust_keyring);

extern int restrict_link_by_key_or_keyring(struct key *dest_keyring,
					   const struct key_type *type,
					   const union key_payload *payload,
					   struct key *trusted);

extern int restrict_link_by_key_or_keyring_chain(struct key *trust_keyring,
						 const struct key_type *type,
						 const union key_payload *payload,
						 struct key *trusted);

#if IS_REACHABLE(CONFIG_ASYMMETRIC_KEY_TYPE)
extern int restrict_link_by_ca(struct key *dest_keyring,
			       const struct key_type *type,
			       const union key_payload *payload,
			       struct key *trust_keyring);
int restrict_link_by_digsig(struct key *dest_keyring,
			    const struct key_type *type,
			    const union key_payload *payload,
			    struct key *trust_keyring);
#else
static inline int restrict_link_by_ca(struct key *dest_keyring,
				      const struct key_type *type,
				      const union key_payload *payload,
				      struct key *trust_keyring)
{
	return 0;
}

static inline int restrict_link_by_digsig(struct key *dest_keyring,
					  const struct key_type *type,
					  const union key_payload *payload,
					  struct key *trust_keyring)
{
	return 0;
}
#endif

DECLARE_CRYPTO_API(query_asymmetric_key, int, (const struct kernel_pkey_params *i, struct kernel_pkey_query *j), (i, j));
DECLARE_CRYPTO_API(encrypt_blob, int, (struct kernel_pkey_params *i, const void *j, void *k), (i, j, k));
DECLARE_CRYPTO_API(decrypt_blob, int, (struct kernel_pkey_params *i, const void *j, void *k), (i, j, k));
DECLARE_CRYPTO_API(create_signature, int, (struct kernel_pkey_params *i, const void *j, void *k), (i, j, k));
DECLARE_CRYPTO_API(verify_signature, int, (const struct key *i, const struct public_key_signature *j), (i, j));

#if IS_REACHABLE(CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE)
DECLARE_CRYPTO_API(public_key_verify_signature, int, (const struct public_key *pkey, const struct public_key_signature *sig), (pkey, sig));
#else
static inline
int public_key_verify_signature(const struct public_key *pkey,
				const struct public_key_signature *sig)
{
	return -EINVAL;
}
#endif

#endif /* _LINUX_PUBLIC_KEY_H */
