/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PKCS#7 crypto data parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _CRYPTO_PKCS7_H
#define _CRYPTO_PKCS7_H

#include <linux/verification.h>
#include <linux/hash_info.h>
#include <crypto/public_key.h>

struct key;
struct pkcs7_message;

/*
 * pkcs7_parser.c
 */
DECLARE_CRYPTO_API(pkcs7_parse_message, struct pkcs7_message *, (const void *data, size_t datalen), (data, datalen));
DECLARE_CRYPTO_API(pkcs7_free_message, void, (struct pkcs7_message *pkcs7), (pkcs7));

DECLARE_CRYPTO_API(pkcs7_get_content_data, int, (const struct pkcs7_message *pkcs7, const void **_data, size_t *_datalen, size_t *_headerlen), (pkcs7, _data, _datalen, _headerlen));
/*
 * pkcs7_trust.c
 */
DECLARE_CRYPTO_API(pkcs7_validate_trust, int, (struct pkcs7_message *pkcs7, struct key *trust_keyring), (pkcs7, trust_keyring));

/*
 * pkcs7_verify.c
 */
DECLARE_CRYPTO_API(pkcs7_verify, int, (struct pkcs7_message *pkcs7, enum key_being_used_for usage), (pkcs7, usage));
DECLARE_CRYPTO_API(pkcs7_supply_detached_data, int, (struct pkcs7_message *pkcs7, const void *data, size_t datalen), (pkcs7, data, datalen));

extern int pkcs7_get_digest(struct pkcs7_message *pkcs7, const u8 **buf,
			    u32 *len, enum hash_algo *hash_algo);

#endif /* _CRYPTO_PKCS7_H */
