/* SPDX-License-Identifier: GPL-2.0 */
/* Values for NULL algorithms */

#ifndef _CRYPTO_NULL_H
#define _CRYPTO_NULL_H

#include <crypto/api.h>

#define NULL_KEY_SIZE		0
#define NULL_BLOCK_SIZE		1
#define NULL_DIGEST_SIZE	0
#define NULL_IV_SIZE		0

DECLARE_CRYPTO_API0(crypto_get_default_null_skcipher, struct crypto_sync_skcipher *);
DECLARE_CRYPTO_API0(crypto_put_default_null_skcipher, void);

#endif
