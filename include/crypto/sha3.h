/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for SHA-3 algorithms
 */
#ifndef __CRYPTO_SHA3_H__
#define __CRYPTO_SHA3_H__

#include <crypto/api.h>

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)

#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)

#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)

#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3_state {
	u64		st[25];
	unsigned int	rsiz;
	unsigned int	rsizw;

	unsigned int	partial;
	u8		buf[SHA3_224_BLOCK_SIZE];
};

DECLARE_CRYPTO_API1(crypto_sha3_init, int, struct shash_desc *, desc);
DECLARE_CRYPTO_API3(crypto_sha3_update, int, struct shash_desc *, desc, const u8 *, data, unsigned int, len);
DECLARE_CRYPTO_API2(crypto_sha3_final, int, struct shash_desc *, desc, u8 *, out);

#endif
