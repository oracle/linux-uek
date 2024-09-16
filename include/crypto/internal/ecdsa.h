/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * ECDSA internal helpers
 *
 * Copyright (c) 2023 Marvell
 */
#ifndef _ECDSA_HELPER_
#define _ECDSA_HELPER_
#include <linux/types.h>

struct ecdsa_signature_ctx {
	const struct ecc_curve *curve;
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];
};

/**
 * ecdsa_parse_signature() - decodes the BER encoded buffer and stores
 * in the provided struct ecdsa_signature_ctx.
 *
 * @sig_ctx:	struct ecdsa_signature_ctx
 * @sig:	signature in BER format
 * @sig_len:	length of signature
 *
 * Return:	0 on success or error code in case of error
 */
int ecdsa_parse_signature(struct ecdsa_signature_ctx *sig_ctx, void *sig,
			  unsigned int sig_len);

#endif
