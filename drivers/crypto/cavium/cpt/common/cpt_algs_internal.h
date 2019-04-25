/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_ALGS_INTERNAL_H_
#define __CPT_ALGS_INTERNAL_H_

#define MAX_ENC_KEY_SIZE 32
#define MAX_HASH_KEY_SIZE 64
#define MAX_KEY_SIZE (MAX_ENC_KEY_SIZE + MAX_HASH_KEY_SIZE)
#define CONTROL_WORD_LEN 8
#define KEY2_OFFSET 48

#define DMA_MODE_FLAG(dma_mode) \
	(((dma_mode) == DMA_GATHER_SCATTER) ? (1 << 7) : 0)

/* Size of salt in AES GCM mode */
#define AES_GCM_SALT_SIZE	4
/* Size of IV in AES GCM mode */
#define AES_GCM_IV_SIZE		8
/* Size of ICV (Integrity Check Value) in AES GCM mode */
#define AES_GCM_ICV_SIZE	16
/* Offset of IV in AES GCM mode */
#define AES_GCM_IV_OFFSET	8

/* Truncated SHA digest size */
#define SHA1_TRUNC_DIGEST_SIZE		12
#define SHA256_TRUNC_DIGEST_SIZE	16
#define SHA384_TRUNC_DIGEST_SIZE	24
#define SHA512_TRUNC_DIGEST_SIZE	32

#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)

enum request_type {
	ENC_DEC_REQ		= 0x1,
	AEAD_ENC_DEC_REQ	= 0x2,
	AEAD_ENC_DEC_NULL_REQ	= 0x3,
	PASSTHROUGH_REQ		= 0x4
};

enum major_opcodes {
	MAJOR_OP_MISC	= 0x01,
	MAJOR_OP_FC	= 0x33,
	MAJOR_OP_HMAC	= 0x35,
};

enum req_type {
	AE_CORE_REQ,
	SE_CORE_REQ,
};

enum cipher_type {
	CIPHER_NULL	= 0x0,
	DES3_CBC	= 0x1,
	DES3_ECB	= 0x2,
	AES_CBC		= 0x3,
	AES_ECB		= 0x4,
	AES_CFB		= 0x5,
	AES_CTR		= 0x6,
	AES_GCM		= 0x7,
	AES_XTS		= 0x8
};

enum mac_type {
	MAC_NULL	= 0x0,
	MD5		= 0x1,
	SHA1		= 0x2,
	SHA224		= 0x3,
	SHA256		= 0x4,
	SHA384		= 0x5,
	SHA512		= 0x6,
	GMAC		= 0x7
};

enum aes_key_len {
	AES_128_BIT = 0x1,
	AES_192_BIT = 0x2,
	AES_256_BIT = 0x3
};

union encr_ctrl {
	u64 flags;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 enc_cipher:4;
		u64 reserved1:1;
		u64 aes_key:2;
		u64 iv_source:1;
		u64 mac_type:4;
		u64 reserved2:3;
		u64 auth_input_type:1;
		u64 mac_len:8;
		u64 reserved3:8;
		u64 encr_offset:16;
		u64 iv_offset:8;
		u64 auth_offset:8;
#else
		u64 auth_offset:8;
		u64 iv_offset:8;
		u64 encr_offset:16;
		u64 reserved3:8;
		u64 mac_len:8;
		u64 auth_input_type:1;
		u64 reserved2:3;
		u64 mac_type:4;
		u64 iv_source:1;
		u64 aes_key:2;
		u64 reserved1:1;
		u64 enc_cipher:4;
#endif
	} e;
};

struct cvm_cipher {
	const char *name;
	u8 value;
};

struct enc_context {
	union encr_ctrl enc_ctrl;
	u8 encr_key[32];
	u8 encr_iv[16];
};

union fchmac_context {
	struct {
		u8 ipad[64];
		u8 opad[64]; /* or OPAD */
	} e;
	struct {
		u8 hmac_calc[64]; /* HMAC received */
		u8 hmac_recv[64]; /* HMAC calculated */
	} s;
};

struct fc_context {
	struct enc_context enc;
	union fchmac_context hmac;
};

struct cvm_enc_ctx {
	u32 key_len;
	u8 enc_key[MAX_KEY_SIZE];
	u8 cipher_type;
	u8 key_type;
};

struct cvm_des3_ctx {
	u32 key_len;
	u8 des3_key[MAX_KEY_SIZE];
};

union offset_ctrl_word {
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

struct cvm_req_ctx {
	struct cpt_request_info cpt_req;
	union offset_ctrl_word ctrl_word;
	struct fc_context fctx;
};

struct sdesc {
	struct shash_desc shash;
};

struct cvm_aead_ctx {
	u8 key[MAX_KEY_SIZE];
	struct crypto_shash *hashalg;
	struct sdesc *sdesc;
	u8 *ipad;
	u8 *opad;
	u32 enc_key_len;
	u32 auth_key_len;
	u8 cipher_type;
	u8 mac_type;
	u8 key_type;
	u8 is_trunc_hmac;
};

#endif /*__CPT_ALGS_INTERNAL_H_*/
