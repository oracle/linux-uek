/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Apertus Solutions, LLC
 */

#ifndef BOOT_COMPRESSED_EARLY_SHA1_H
#define BOOT_COMPRESSED_EARLY_SHA1_H

#include <crypto/sha1.h>

void early_sha1_init(struct sha1_state *sctx);
void early_sha1_update(struct sha1_state *sctx,
		       const u8 *data,
		       unsigned int len);
void early_sha1_final(struct sha1_state *sctx, u8 *out);

#endif /* BOOT_COMPRESSED_EARLY_SHA1_H */
