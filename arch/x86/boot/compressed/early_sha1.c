// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Apertus Solutions, LLC.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <asm/boot.h>
#include <asm/unaligned.h>

#include "early_sha1.h"

#define SHA1_DISABLE_EXPORT
#include "../../../../lib/sha1.c"

/* The SHA1 implementation in lib/sha1.c was written to get the workspace
 * buffer as a parameter. This wrapper function provides a container
 * around a temporary workspace that is cleared after the transform completes.
 */
static void __sha_transform(u32 *digest, const char *data)
{
	u32 ws[SHA1_WORKSPACE_WORDS];

	sha1_transform(digest, data, ws);

	memset(ws, 0, sizeof(ws));
	/*
	 * As this is cryptographic code, prevent the memset 0 from being
	 * optimized out potentially leaving secrets in memory.
	 */
	wmb();

}

void early_sha1_init(struct sha1_state *sctx)
{
	sha1_init(sctx->state);
	sctx->count = 0;
}

void early_sha1_update(struct sha1_state *sctx,
		       const u8 *data,
		       unsigned int len)
{
	unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;

	sctx->count += len;

	if (likely((partial + len) >= SHA1_BLOCK_SIZE)) {
		int blocks;

		if (partial) {
			int p = SHA1_BLOCK_SIZE - partial;

			memcpy(sctx->buffer + partial, data, p);
			data += p;
			len -= p;

			__sha_transform(sctx->state, sctx->buffer);
		}

		blocks = len / SHA1_BLOCK_SIZE;
		len %= SHA1_BLOCK_SIZE;

		if (blocks) {
			while (blocks--) {
				__sha_transform(sctx->state, data);
				data += SHA1_BLOCK_SIZE;
			}
		}
		partial = 0;
	}

	if (len)
		memcpy(sctx->buffer + partial, data, len);
}

void early_sha1_final(struct sha1_state *sctx, u8 *out)
{
	const int bit_offset = SHA1_BLOCK_SIZE - sizeof(__be64);
	__be64 *bits = (__be64 *)(sctx->buffer + bit_offset);
	__be32 *digest = (__be32 *)out;
	unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;
	int i;

	sctx->buffer[partial++] = 0x80;
	if (partial > bit_offset) {
		memset(sctx->buffer + partial, 0x0, SHA1_BLOCK_SIZE - partial);
		partial = 0;

		__sha_transform(sctx->state, sctx->buffer);
	}

	memset(sctx->buffer + partial, 0x0, bit_offset - partial);
	*bits = cpu_to_be64(sctx->count << 3);
	__sha_transform(sctx->state, sctx->buffer);

	for (i = 0; i < SHA1_DIGEST_SIZE / sizeof(__be32); i++)
		put_unaligned_be32(sctx->state[i], digest++);

	*sctx = (struct sha1_state){};
}
