/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPT_ALGS_H
#define __CN10K_CPT_ALGS_H

#include <crypto/hash.h>
#include "cn10k_cpt_common.h"

#define CN10K_CPT_MAX_ENC_KEY_SIZE    32
#define CN10K_CPT_MAX_HASH_KEY_SIZE   64
#define CN10K_CPT_MAX_KEY_SIZE (CN10K_CPT_MAX_ENC_KEY_SIZE + \
			       CN10K_CPT_MAX_HASH_KEY_SIZE)
enum cn10k_cpt_request_type {
	CN10K_CPT_ENC_DEC_REQ            = 0x1,
	CN10K_CPT_AEAD_ENC_DEC_REQ       = 0x2,
	CN10K_CPT_AEAD_ENC_DEC_NULL_REQ  = 0x3,
	CN10K_CPT_PASSTHROUGH_REQ	= 0x4
};

enum cn10k_cpt_major_opcodes {
	CN10K_CPT_MAJOR_OP_MISC = 0x01,
	CN10K_CPT_MAJOR_OP_FC   = 0x33,
	CN10K_CPT_MAJOR_OP_HMAC = 0x35,
};

enum cn10k_cpt_cipher_type {
	CN10K_CPT_CIPHER_NULL = 0x0,
	CN10K_CPT_DES3_CBC = 0x1,
	CN10K_CPT_DES3_ECB = 0x2,
	CN10K_CPT_AES_CBC  = 0x3,
	CN10K_CPT_AES_ECB  = 0x4,
	CN10K_CPT_AES_CFB  = 0x5,
	CN10K_CPT_AES_CTR  = 0x6,
	CN10K_CPT_AES_GCM  = 0x7,
	CN10K_CPT_AES_XTS  = 0x8
};

enum cn10k_cpt_mac_type {
	CN10K_CPT_MAC_NULL = 0x0,
	CN10K_CPT_MD5      = 0x1,
	CN10K_CPT_SHA1     = 0x2,
	CN10K_CPT_SHA224   = 0x3,
	CN10K_CPT_SHA256   = 0x4,
	CN10K_CPT_SHA384   = 0x5,
	CN10K_CPT_SHA512   = 0x6,
	CN10K_CPT_GMAC     = 0x7
};

enum cn10k_cpt_aes_key_len {
	CN10K_CPT_AES_128_BIT = 0x1,
	CN10K_CPT_AES_192_BIT = 0x2,
	CN10K_CPT_AES_256_BIT = 0x3
};

union cn10k_cpt_encr_ctrl {
	u64 u;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 enc_cipher:4;
		u64 reserved_59:1;
		u64 aes_key:2;
		u64 iv_source:1;
		u64 mac_type:4;
		u64 reserved_49_51:3;
		u64 auth_input_type:1;
		u64 mac_len:8;
		u64 reserved_32_39:8;
		u64 encr_offset:16;
		u64 iv_offset:8;
		u64 auth_offset:8;
#else
		u64 auth_offset:8;
		u64 iv_offset:8;
		u64 encr_offset:16;
		u64 reserved_32_39:8;
		u64 mac_len:8;
		u64 auth_input_type:1;
		u64 reserved_49_51:3;
		u64 mac_type:4;
		u64 iv_source:1;
		u64 aes_key:2;
		u64 reserved_59:1;
		u64 enc_cipher:4;
#endif
	} e;
};

struct cn10k_cpt_cipher {
	const char *name;
	u8 value;
};

struct cn10k_cpt_fc_enc_ctx {
	union cn10k_cpt_encr_ctrl enc_ctrl;
	u8 encr_key[32];
	u8 encr_iv[16];
};

union cn10k_cpt_fc_hmac_ctx {
	struct {
		u8 ipad[64];
		u8 opad[64];
	} e;
	struct {
		u8 hmac_calc[64]; /* HMAC calculated */
		u8 hmac_recv[64]; /* HMAC received */
	} s;
};

struct cn10k_cpt_fc_ctx {
	struct cn10k_cpt_fc_enc_ctx enc;
	union cn10k_cpt_fc_hmac_ctx hmac;
};

struct cn10k_cpt_enc_ctx {
	u32 key_len;
	u8 enc_key[CN10K_CPT_MAX_KEY_SIZE];
	u8 cipher_type;
	u8 key_type;
	u8 enc_align_len;
};

union cn10k_cpt_offset_ctrl {
	u64 flags;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 reserved:32;
		u64 enc_data_offset:16;
		u64 iv_offset:8;
		u64 auth_offset:8;
#else
		u64 auth_offset:8;
		u64 iv_offset:8;
		u64 enc_data_offset:16;
		u64 reserved:32;
#endif
	} e;
};

struct cn10k_cpt_req_ctx {
	struct cn10k_cpt_req_info cpt_req;
	union cn10k_cpt_offset_ctrl ctrl_word;
	struct cn10k_cpt_fc_ctx fctx;
};

struct cn10k_cpt_sdesc {
	struct shash_desc shash;
};

struct cn10k_cpt_aead_ctx {
	u8 key[CN10K_CPT_MAX_KEY_SIZE];
	struct crypto_shash *hashalg;
	struct cn10k_cpt_sdesc *sdesc;
	u8 *ipad;
	u8 *opad;
	u32 enc_key_len;
	u32 auth_key_len;
	u8 cipher_type;
	u8 mac_type;
	u8 key_type;
	u8 is_trunc_hmac;
	u8 enc_align_len;
};
int cn10k_cpt_crypto_init(struct pci_dev *pdev, struct module *mod,
			  enum cn10k_cpt_eng_type engine_type,
			  int num_queues, int num_devices);
void cn10k_cpt_crypto_exit(struct pci_dev *pdev, struct module *mod,
			   enum cn10k_cpt_eng_type engine_type);

#endif /* __CN10K_CPT_ALGS_H */
