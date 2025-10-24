/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Software async crypto daemon
 *
 * Added AEAD support to cryptd.
 *    Authors: Tadeusz Struk (tadeusz.struk@intel.com)
 *             Adrian Hoban <adrian.hoban@intel.com>
 *             Gabriele Paoloni <gabriele.paoloni@intel.com>
 *             Aidan O'Mahony (aidan.o.mahony@intel.com)
 *    Copyright (c) 2010, Intel Corporation.
 */

#ifndef _CRYPTO_CRYPT_H
#define _CRYPTO_CRYPT_H

#include <linux/types.h>

#include <crypto/api.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>

struct cryptd_skcipher {
	struct crypto_skcipher base;
};

/* alg_name should be algorithm to be cryptd-ed */
DECLARE_CRYPTO_API3(cryptd_alloc_skcipher, struct cryptd_skcipher *, const char *, alg_name, u32, type, u32, mask);
DECLARE_CRYPTO_API1(cryptd_skcipher_child, struct crypto_skcipher *, struct cryptd_skcipher *, tfm);
/* Must be called without moving CPUs. */
DECLARE_CRYPTO_API1(cryptd_skcipher_queued, bool, struct cryptd_skcipher *, tfm);
DECLARE_CRYPTO_API1(cryptd_free_skcipher, void, struct cryptd_skcipher *, tfm);

struct cryptd_ahash {
	struct crypto_ahash base;
};

static inline struct cryptd_ahash *__cryptd_ahash_cast(
	struct crypto_ahash *tfm)
{
	return (struct cryptd_ahash *)tfm;
}

/* alg_name should be algorithm to be cryptd-ed */
DECLARE_CRYPTO_API3(cryptd_alloc_ahash, struct cryptd_ahash *, const char *, alg_name, u32, type, u32, mask);
DECLARE_CRYPTO_API1(cryptd_ahash_child, struct crypto_shash *, struct cryptd_ahash *, tfm);
DECLARE_CRYPTO_API1(cryptd_shash_desc, struct shash_desc *, struct ahash_request *, req);
/* Must be called without moving CPUs. */
DECLARE_CRYPTO_API1(cryptd_ahash_queued, bool, struct cryptd_ahash *, tfm);
DECLARE_CRYPTO_API1(cryptd_free_ahash, void, struct cryptd_ahash *, tfm);

struct cryptd_aead {
	struct crypto_aead base;
};

static inline struct cryptd_aead *__cryptd_aead_cast(
	struct crypto_aead *tfm)
{
	return (struct cryptd_aead *)tfm;
}

DECLARE_CRYPTO_API3(cryptd_alloc_aead, struct cryptd_aead *, const char *, alg_name, u32, type, u32, mask);

DECLARE_CRYPTO_API1(cryptd_aead_child, struct crypto_aead *, struct cryptd_aead *, tfm);
/* Must be called without moving CPUs. */
DECLARE_CRYPTO_API1(cryptd_aead_queued, bool, struct cryptd_aead *, tfm);

DECLARE_CRYPTO_API1(cryptd_free_aead, void, struct cryptd_aead *, tfm);

#endif
