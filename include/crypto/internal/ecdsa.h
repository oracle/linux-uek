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

struct ecc_ctx {
	unsigned int curve_id;
	const struct ecc_curve *curve;
	bool key_set;
	bool is_private;

	u64 d[ECC_MAX_DIGITS]; /* priv key big integer */
	u64 x[ECC_MAX_DIGITS]; /* pub key x and y coordinates */
	u64 y[ECC_MAX_DIGITS];
	struct ecc_point pub_key;
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

/**
 * ecdsa_parse_privkey() - decodes the BER encoded buffer and stores
 * in the provided struct ecc_ctx.
 *
 * @ecc_ctx:	struct ecc_ctx
 * @key:	key in BER format
 * @key_len:	length of privkey
 *
 * Return:	0 on success or error code in case of error
 */
int ecdsa_parse_privkey(struct ecc_ctx *ctx, const void *key, unsigned int key_len);
int ecdsa_asn1_encode_signature_sg(struct akcipher_request *req,
				   struct ecdsa_signature_ctx *sig_ctx);

#endif
