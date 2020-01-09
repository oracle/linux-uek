// SPDX-License-Identifier: GPL-2.0
/* Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/cryptd.h>
#include <crypto/des.h>
#include <crypto/internal/aead.h>
#include <crypto/sha.h>
#include <crypto/xts.h>
#include <linux/rtnetlink.h>
#include <linux/sort.h>
#include "cpt_common.h"
#include "cpt_algs.h"
#include "cpt_algs_internal.h"


static DEFINE_MUTEX(mutex);
static int is_crypto_registered;

/* 8X platform supports 64 VFs for CPT and 9X platform supports 128 VFs
 * for CPT therefore we take maximum number of supported VFs for CPT
 */
#define CPT_MAX_VF_NUM	128

struct cpt_device_desc {
	enum cpt_pf_type pf_type;
	struct algs_ops ops;
	struct pci_dev *dev;
	int num_queues;
};

struct cpt_device_table {
	atomic_t count;
	struct cpt_device_desc desc[CPT_MAX_VF_NUM];
};

static struct cpt_device_table se_devices = {
	.count = ATOMIC_INIT(0)
};

static struct cpt_device_table ae_devices = {
	.count = ATOMIC_INIT(0)
};

static inline int get_se_device(struct pci_dev **pdev, struct algs_ops **ops,
				int *cpu_num)
{
	int count, err = 0;

	count = atomic_read(&se_devices.count);
	if (count < 1)
		return -ENODEV;

	*cpu_num = get_cpu();

	switch (se_devices.desc[0].pf_type) {
	case CPT_81XX:
	case CPT_SE_83XX:
		/* On 8X platform there is one CPT instruction queue bound
		 * to each VF. We get maximum performance if one CPT queue
		 * is available for each cpu otherwise CPT queues need to be
		 * shared between cpus.
		 */
		if (*cpu_num >= count)
			*cpu_num %= count;
		*pdev = se_devices.desc[*cpu_num].dev;
		*ops = &se_devices.desc[*cpu_num].ops;
	break;

	case CPT_96XX:
		/* On 9X platform CPT instruction queue is bound to each
		 * local function LF, in turn LFs can be attached to PF
		 * or VF therefore we always use first device. We get maximum
		 * performance if one CPT queue is available for each cpu
		 * otherwise CPT queues need to be shared between cpus.
		 */
		if (*cpu_num >= se_devices.desc[0].num_queues)
			*cpu_num %= se_devices.desc[0].num_queues;
		*pdev = se_devices.desc[0].dev;
		*ops = &se_devices.desc[0].ops;
	break;

	default:
		pr_err("Unknown PF type %d\n", se_devices.desc[0].pf_type);
		err = -EINVAL;
	}

	put_cpu();
	return err;
}

static inline int validate_hmac_cipher_null(struct cpt_request_info *cpt_req)
{
	struct aead_request *req;
	struct cvm_req_ctx *rctx;
	struct crypto_aead *tfm;

	req = container_of(cpt_req->areq, struct aead_request, base);
	tfm = crypto_aead_reqtfm(req);
	rctx = aead_request_ctx(req);
	if (memcmp(rctx->fctx.hmac.s.hmac_calc,
		   rctx->fctx.hmac.s.hmac_recv,
		   crypto_aead_authsize(tfm)) != 0)
		return -EBADMSG;

	return 0;
}

void cvm_callback(int status, void *arg, void *req)
{
	struct crypto_async_request *areq = (struct crypto_async_request *)arg;
	struct cpt_request_info *cpt_req = (struct cpt_request_info *)req;

	if (!status) {
		/* When selected cipher is NULL we need to manually
		 * verify whether calculated hmac value matches
		 * received hmac value
		 */
		if (cpt_req->req_type == AEAD_ENC_DEC_NULL_REQ &&
		    !cpt_req->is_enc)
			status = validate_hmac_cipher_null(cpt_req);
	}

	areq->complete(areq, status);
}
EXPORT_SYMBOL_GPL(cvm_callback);

static inline void update_input_data(struct cpt_request_info *req_info,
				     struct scatterlist *inp_sg,
				     u32 nbytes, u32 *argcnt)
{
	req_info->req.dlen += nbytes;

	while (nbytes) {
		u32 len = min(nbytes, inp_sg->length);
		u8 *ptr = sg_virt(inp_sg);

		req_info->in[*argcnt].vptr = (void *)ptr;
		req_info->in[*argcnt].size = len;
		nbytes -= len;
		++(*argcnt);
		inp_sg = sg_next(inp_sg);
	}
}

static inline void update_output_data(struct cpt_request_info *req_info,
				      struct scatterlist *outp_sg,
				      u32 offset, u32 nbytes, u32 *argcnt)
{
	req_info->rlen += nbytes;

	while (nbytes) {
		u32 len = min(nbytes, outp_sg->length - offset);
		u8 *ptr = sg_virt(outp_sg);

		req_info->out[*argcnt].vptr = (void *) (ptr + offset);
		req_info->out[*argcnt].size = len;
		nbytes -= len;
		++(*argcnt);
		offset = 0;
		outp_sg = sg_next(outp_sg);
	}
}

static inline u32 create_ctx_hdr(struct ablkcipher_request *req, u32 enc,
				 u32 *argcnt)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cvm_enc_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	struct fc_context *fctx = &rctx->fctx;
	u64 *ctrl_flags = NULL;

	req_info->ctrl.s.dma_mode = DMA_GATHER_SCATTER;
	req_info->ctrl.s.se_req = SE_CORE_REQ;

	req_info->req.opcode.s.major = MAJOR_OP_FC |
					DMA_MODE_FLAG(DMA_GATHER_SCATTER);
	if (enc)
		req_info->req.opcode.s.minor = 2;
	else
		req_info->req.opcode.s.minor = 3;

	req_info->req.param1 = req->nbytes; /* Encryption Data length */
	req_info->req.param2 = 0; /*Auth data length */

	fctx->enc.enc_ctrl.e.enc_cipher = ctx->cipher_type;
	fctx->enc.enc_ctrl.e.aes_key = ctx->key_type;
	fctx->enc.enc_ctrl.e.iv_source = FROM_CPTR;

	if (ctx->cipher_type == AES_XTS)
		memcpy(fctx->enc.encr_key, ctx->enc_key, ctx->key_len * 2);
	else
		memcpy(fctx->enc.encr_key, ctx->enc_key, ctx->key_len);

	memcpy(fctx->enc.encr_iv, req->info, crypto_ablkcipher_ivsize(tfm));

	ctrl_flags = (u64 *)&fctx->enc.enc_ctrl.flags;
	*ctrl_flags = cpu_to_be64(*ctrl_flags);

	/* Storing  Packet Data Information in offset
	 * Control Word First 8 bytes
	 */
	req_info->in[*argcnt].vptr = (u8 *)&rctx->ctrl_word;
	req_info->in[*argcnt].size = CONTROL_WORD_LEN;
	req_info->req.dlen += CONTROL_WORD_LEN;
	++(*argcnt);

	req_info->in[*argcnt].vptr = (u8 *)fctx;
	req_info->in[*argcnt].size = sizeof(struct fc_context);
	req_info->req.dlen += sizeof(struct fc_context);

	++(*argcnt);

	return 0;
}

static inline u32 create_input_list(struct ablkcipher_request  *req, u32 enc,
				    u32 enc_iv_len)
{
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 argcnt =  0;

	create_ctx_hdr(req, enc, &argcnt);
	update_input_data(req_info, req->src, req->nbytes, &argcnt);
	req_info->incnt = argcnt;

	return 0;
}

static inline void create_output_list(struct ablkcipher_request *req,
				      u32 enc_iv_len)
{
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 argcnt = 0;

	/* OUTPUT Buffer Processing
	 * AES encryption/decryption output would be
	 * received in the following format
	 *
	 * ------IV--------|------ENCRYPTED/DECRYPTED DATA-----|
	 * [ 16 Bytes/     [   Request Enc/Dec/ DATA Len AES CBC ]
	 */
	/* Reading IV information */
	update_output_data(req_info, req->dst, 0, req->nbytes, &argcnt);
	req_info->outcnt = argcnt;
}

static inline int cvm_enc_dec(struct ablkcipher_request *req, u32 enc)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 enc_iv_len = crypto_ablkcipher_ivsize(tfm);
	struct pci_dev *pdev;
	struct algs_ops *ops;
	int status, cpu_num;

	/* Validate that request doesn't exceed maximum CPT supported size */
	if (req->nbytes > CPT_MAX_REQ_SIZE)
		return -E2BIG;

	/* Clear control words */
	rctx->ctrl_word.flags = 0;
	rctx->fctx.enc.enc_ctrl.flags = 0;

	create_input_list(req, enc, enc_iv_len);
	create_output_list(req, enc_iv_len);

	status = get_se_device(&pdev, &ops, &cpu_num);
	if (status)
		return status;

	req_info->callback = (void *)cvm_callback;
	req_info->areq = &req->base;
	req_info->req_type = ENC_DEC_REQ;
	req_info->is_trunc_hmac = false;
	if (!ops->cpt_get_kcrypto_eng_grp_num)
		return -EFAULT;
	req_info->ctrl.s.grp = ops->cpt_get_kcrypto_eng_grp_num(pdev);

	if (!ops->cpt_do_request)
		return -EFAULT;
	status = ops->cpt_do_request(pdev, req_info, cpu_num);
	/* We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return status;
}

static int cvm_encrypt(struct ablkcipher_request *req)
{
	return cvm_enc_dec(req, true);
}

static int cvm_decrypt(struct ablkcipher_request *req)
{
	return cvm_enc_dec(req, false);
}

static int cvm_xts_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
		   u32 keylen)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(cipher);
	struct cvm_enc_ctx *ctx = crypto_tfm_ctx(tfm);
	int err;
	const u8 *key1 = key;
	const u8 *key2 = key + (keylen / 2);

	err = xts_check_key(tfm, key, keylen);
	if (err)
		return err;
	ctx->key_len = keylen;
	memcpy(ctx->enc_key, key1, keylen / 2);
	memcpy(ctx->enc_key + KEY2_OFFSET, key2, keylen / 2);
	ctx->cipher_type = AES_XTS;
	switch (ctx->key_len) {
	case 32:
		ctx->key_type = AES_128_BIT;
		break;
	case 64:
		ctx->key_type = AES_256_BIT;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int cvm_validate_keylen(struct cvm_enc_ctx *ctx, u32 keylen)
{
	if ((keylen == 16) || (keylen == 24) || (keylen == 32)) {
		ctx->key_len = keylen;
		switch (ctx->key_len) {
		case 16:
			ctx->key_type = AES_128_BIT;
			break;
		case 24:
			ctx->key_type = AES_192_BIT;
			break;
		case 32:
			ctx->key_type = AES_256_BIT;
			break;
		default:
			return -EINVAL;
		}

		if (ctx->cipher_type == DES3_CBC)
			ctx->key_type = 0;

		return 0;
	}

	return -EINVAL;
}

static int cvm_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
		      u32 keylen, u8 cipher_type)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(cipher);
	struct cvm_enc_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->cipher_type = cipher_type;
	if (!cvm_validate_keylen(ctx, keylen)) {
		memcpy(ctx->enc_key, key, keylen);
		return 0;
	}

	crypto_ablkcipher_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static int cvm_cbc_aes_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			      u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, AES_CBC);
}

static int cvm_ecb_aes_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			      u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, AES_ECB);
}

static int cvm_cfb_aes_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			      u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, AES_CFB);
}

static int cvm_cbc_des3_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			       u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, DES3_CBC);
}

static int cvm_ecb_des3_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			       u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, DES3_ECB);
}

static int cvm_enc_dec_init(struct crypto_tfm *tfm)
{
	struct cvm_enc_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	tfm->crt_ablkcipher.reqsize = sizeof(struct cvm_req_ctx) +
					sizeof(struct ablkcipher_request);
	/* Additional memory for ablkcipher_request is
	 * allocated since the cryptd daemon uses
	 * this memory for request_ctx information
	 */

	return 0;
}

static int cvm_aead_init(struct crypto_aead *tfm, u8 cipher_type, u8 mac_type)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->cipher_type = cipher_type;
	ctx->mac_type = mac_type;

	/* When selected cipher is NULL we use HMAC opcode instead of
	 * FLEXICRYPTO opcode therefore we don't need to use HASH algorithms
	 * for calculating ipad and opad
	 */
	if (ctx->cipher_type != CIPHER_NULL) {
		switch (ctx->mac_type) {
		case SHA1:
			ctx->hashalg = crypto_alloc_shash("sha1", 0,
							  CRYPTO_ALG_ASYNC);
			if (IS_ERR(ctx->hashalg))
				return PTR_ERR(ctx->hashalg);
			break;

		case SHA256:
			ctx->hashalg = crypto_alloc_shash("sha256", 0,
							  CRYPTO_ALG_ASYNC);
			if (IS_ERR(ctx->hashalg))
				return PTR_ERR(ctx->hashalg);
			break;

		case SHA384:
			ctx->hashalg = crypto_alloc_shash("sha384", 0,
							  CRYPTO_ALG_ASYNC);
			if (IS_ERR(ctx->hashalg))
				return PTR_ERR(ctx->hashalg);
			break;

		case SHA512:
			ctx->hashalg = crypto_alloc_shash("sha512", 0,
							  CRYPTO_ALG_ASYNC);
			if (IS_ERR(ctx->hashalg))
				return PTR_ERR(ctx->hashalg);
			break;
		}
	}

	crypto_aead_set_reqsize(tfm, sizeof(struct cvm_req_ctx));

	return 0;
}

static int cvm_aead_cbc_aes_sha1_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, AES_CBC, SHA1);
}

static int cvm_aead_cbc_aes_sha256_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, AES_CBC, SHA256);
}

static int cvm_aead_cbc_aes_sha384_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, AES_CBC, SHA384);
}

static int cvm_aead_cbc_aes_sha512_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, AES_CBC, SHA512);
}

static int cvm_aead_ecb_null_sha1_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, CIPHER_NULL, SHA1);
}

static int cvm_aead_ecb_null_sha256_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, CIPHER_NULL, SHA256);
}

static int cvm_aead_ecb_null_sha384_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, CIPHER_NULL, SHA384);
}

static int cvm_aead_ecb_null_sha512_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, CIPHER_NULL, SHA512);
}

static int cvm_aead_gcm_aes_init(struct crypto_aead *tfm)
{
	return cvm_aead_init(tfm, AES_GCM, MAC_NULL);
}

static void cvm_aead_exit(struct crypto_aead *tfm)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);

	kfree(ctx->ipad);
	kfree(ctx->opad);
	if (ctx->hashalg)
		crypto_free_shash(ctx->hashalg);
	kfree(ctx->sdesc);
}

/* This is the Integrity Check Value validation (aka the authentication tag
 * length)
 */
static int cvm_aead_set_authsize(struct crypto_aead *tfm,
				 unsigned int authsize)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);

	switch (ctx->mac_type) {
	case SHA1:
		if (authsize != SHA1_DIGEST_SIZE &&
		    authsize != SHA1_TRUNC_DIGEST_SIZE)
			return -EINVAL;

		if (authsize == SHA1_TRUNC_DIGEST_SIZE)
			ctx->is_trunc_hmac = true;
		break;

	case SHA256:
		if (authsize != SHA256_DIGEST_SIZE &&
		    authsize != SHA256_TRUNC_DIGEST_SIZE)
			return -EINVAL;

		if (authsize == SHA256_TRUNC_DIGEST_SIZE)
			ctx->is_trunc_hmac = true;
		break;

	case SHA384:
		if (authsize != SHA384_DIGEST_SIZE &&
		    authsize != SHA384_TRUNC_DIGEST_SIZE)
			return -EINVAL;

		if (authsize == SHA384_TRUNC_DIGEST_SIZE)
			ctx->is_trunc_hmac = true;
		break;

	case SHA512:
		if (authsize != SHA512_DIGEST_SIZE &&
		    authsize != SHA512_TRUNC_DIGEST_SIZE)
			return -EINVAL;

		if (authsize == SHA512_TRUNC_DIGEST_SIZE)
			ctx->is_trunc_hmac = true;
		break;

	case MAC_NULL:
		if (ctx->cipher_type == AES_GCM) {
			if (authsize != AES_GCM_ICV_SIZE)
				return -EINVAL;
		} else
			return -EINVAL;
		break;

	default:
		return -EINVAL;
	}

	tfm->authsize = authsize;
	return 0;
}

static struct sdesc *alloc_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return NULL;

	sdesc->shash.tfm = alg;
	sdesc->shash.flags = 0x0;

	return sdesc;
}

static inline void swap_data32(void *buf, u32 len)
{
	u32 *store = (u32 *) buf;
	int i = 0;

	for (i = 0 ; i < len/sizeof(u32); i++, store++)
		*store = cpu_to_be32(*store);
}

static inline void swap_data64(void *buf, u32 len)
{
	u64 *store = (u64 *) buf;
	int i = 0;

	for (i = 0 ; i < len/sizeof(u64); i++, store++)
		*store = cpu_to_be64(*store);
}

static int copy_pad(u8 mac_type, u8 *out_pad, u8 *in_pad)
{
	struct sha512_state *sha512;
	struct sha256_state *sha256;
	struct sha1_state *sha1;

	switch (mac_type) {
	case SHA1:
		sha1 = (struct sha1_state *) in_pad;
		swap_data32(sha1->state, SHA1_DIGEST_SIZE);
		memcpy(out_pad, &sha1->state, SHA1_DIGEST_SIZE);
		break;

	case SHA256:
		sha256 = (struct sha256_state *) in_pad;
		swap_data32(sha256->state, SHA256_DIGEST_SIZE);
		memcpy(out_pad, &sha256->state, SHA256_DIGEST_SIZE);
		break;

	case SHA384:
	case SHA512:
		sha512 = (struct sha512_state *) in_pad;
		swap_data64(sha512->state, SHA512_DIGEST_SIZE);
		memcpy(out_pad, &sha512->state, SHA512_DIGEST_SIZE);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int calculateipadopad(struct crypto_aead *cipher)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(cipher);
	u8 *ipad = NULL, *opad = NULL;
	int bs = crypto_shash_blocksize(ctx->hashalg);
	int ds = crypto_shash_digestsize(ctx->hashalg);
	int state_size = crypto_shash_statesize(ctx->hashalg);
	int authkeylen = ctx->auth_key_len;
	int err = 0, icount = 0;

	ctx->sdesc = alloc_sdesc(ctx->hashalg);
	if (!ctx->sdesc)
		return -ENOMEM;

	ctx->ipad = kzalloc(bs, GFP_KERNEL);
	if (!ctx->ipad)
		goto calc_fail;

	ctx->opad = kzalloc(bs, GFP_KERNEL);
	if (!ctx->opad)
		goto calc_fail;

	ipad = kzalloc(state_size, GFP_KERNEL);
	if (!ipad)
		goto calc_fail;

	opad = kzalloc(state_size, GFP_KERNEL);
	if (!opad)
		goto calc_fail;

	if (authkeylen > bs) {
		err = crypto_shash_digest(&ctx->sdesc->shash, ctx->key,
					  authkeylen, ipad);
		if (err)
			goto calc_fail;

		authkeylen = ds;
	} else {
		memcpy(ipad, ctx->key, authkeylen);
	}

	memset(ipad + authkeylen, 0, bs - authkeylen);
	memcpy(opad, ipad, bs);

	for (icount = 0; icount < bs; icount++) {
		ipad[icount] ^= 0x36;
		opad[icount] ^= 0x5c;
	}

	/* Partial Hash calculated from the software
	 * algorithm is retrieved for IPAD & OPAD
	 */

	/* IPAD Calculation */
	crypto_shash_init(&ctx->sdesc->shash);
	crypto_shash_update(&ctx->sdesc->shash, ipad, bs);
	crypto_shash_export(&ctx->sdesc->shash, ipad);
	if (copy_pad(ctx->mac_type, ctx->ipad, ipad) != 0)
		goto calc_fail;

	/* OPAD Calculation */
	crypto_shash_init(&ctx->sdesc->shash);
	crypto_shash_update(&ctx->sdesc->shash, opad, bs);
	crypto_shash_export(&ctx->sdesc->shash, opad);
	if (copy_pad(ctx->mac_type, ctx->opad, opad) != 0)
		goto calc_fail;

	kfree(ipad);
	kfree(opad);
	return 0;

calc_fail:
	kfree(ctx->ipad);
	kfree(ctx->opad);
	kfree(ipad);
	kfree(opad);
	kfree(ctx->sdesc);

	return -ENOMEM;
}

static int cvm_aead_cbc_aes_sha_setkey(struct crypto_aead *cipher,
				const unsigned char *key,
				unsigned int keylen)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(cipher);
	struct crypto_authenc_key_param *param;
	struct rtattr *rta = (void *)key;
	int enckeylen = 0, authkeylen = 0;
	int status = -EINVAL;

	if (!RTA_OK(rta, keylen))
		goto badkey;

	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
		goto badkey;

	if (RTA_PAYLOAD(rta) < sizeof(*param))
		goto badkey;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);
	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);
	if (keylen < enckeylen)
		goto badkey;

	if (keylen > MAX_KEY_SIZE)
		goto badkey;

	authkeylen = keylen - enckeylen;
	memcpy(ctx->key, key, keylen);

	switch (enckeylen) {
	case AES_KEYSIZE_128:
		ctx->key_type = AES_128_BIT;
		break;
	case AES_KEYSIZE_192:
		ctx->key_type = AES_192_BIT;
		break;
	case AES_KEYSIZE_256:
		ctx->key_type = AES_256_BIT;
		break;
	default:
		/* Invalid key length */
		crypto_aead_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	ctx->enc_key_len = enckeylen;
	ctx->auth_key_len = authkeylen;

	status = calculateipadopad(cipher);
	if (status)
		goto badkey;

	return 0;
badkey:
	crypto_aead_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return status;
}

static int cvm_aead_ecb_null_sha_setkey(struct crypto_aead *cipher,
				 const unsigned char *key,
				 unsigned int keylen)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(cipher);
	struct crypto_authenc_key_param *param;
	struct rtattr *rta = (void *)key;
	int enckeylen = 0, authkeylen = 0;

	if (!RTA_OK(rta, keylen))
		goto badkey;

	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
		goto badkey;

	if (RTA_PAYLOAD(rta) < sizeof(*param))
		goto badkey;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);
	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);
	if (enckeylen != 0)
		goto badkey;

	if (keylen > MAX_KEY_SIZE)
		goto badkey;

	authkeylen = keylen - enckeylen;
	memcpy(ctx->key, key, keylen);
	ctx->enc_key_len = enckeylen;
	ctx->auth_key_len = authkeylen;
	return 0;
badkey:
	crypto_aead_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static int cvm_aead_gcm_aes_setkey(struct crypto_aead *cipher,
			    const unsigned char *key,
			    unsigned int keylen)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(cipher);

	/* For aes gcm we expect to get encryption key (16, 24, 32 bytes)
	 * and salt (4 bytes)
	 */
	switch (keylen) {
	case AES_KEYSIZE_128 + AES_GCM_SALT_SIZE:
		ctx->key_type = AES_128_BIT;
		ctx->enc_key_len = AES_KEYSIZE_128;
		break;
	case AES_KEYSIZE_192 + AES_GCM_SALT_SIZE:
		ctx->key_type = AES_192_BIT;
		ctx->enc_key_len = AES_KEYSIZE_192;
		break;
	case AES_KEYSIZE_256 + AES_GCM_SALT_SIZE:
		ctx->key_type = AES_256_BIT;
		ctx->enc_key_len = AES_KEYSIZE_256;
		break;
	default:
		/* Invalid key and salt length */
		crypto_aead_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	/* Store encryption key and salt */
	memcpy(ctx->key, key, keylen);

	return 0;
}

static inline u32 create_aead_ctx_hdr(struct aead_request *req, u32 enc,
				      u32 *argcnt)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	struct fc_context *fctx = &rctx->fctx;
	int mac_len = crypto_aead_authsize(tfm);
	int ds;

	rctx->ctrl_word.e.enc_data_offset = req->assoclen;

	switch (ctx->cipher_type) {
	case AES_CBC:
		fctx->enc.enc_ctrl.e.iv_source = FROM_CPTR;
		/* Copy encryption key to context */
		memcpy(fctx->enc.encr_key, ctx->key + ctx->auth_key_len,
		       ctx->enc_key_len);
		/* Copy IV to context */
		memcpy(fctx->enc.encr_iv, req->iv, crypto_aead_ivsize(tfm));

		ds = crypto_shash_digestsize(ctx->hashalg);
		if (ctx->mac_type == SHA384)
			ds = SHA512_DIGEST_SIZE;
		if (ctx->ipad)
			memcpy(fctx->hmac.e.ipad, ctx->ipad, ds);
		if (ctx->opad)
			memcpy(fctx->hmac.e.opad, ctx->opad, ds);
		break;

	case AES_GCM:
		fctx->enc.enc_ctrl.e.iv_source = FROM_DPTR;
		/* Copy encryption key to context */
		memcpy(fctx->enc.encr_key, ctx->key, ctx->enc_key_len);
		/* Copy salt to context */
		memcpy(fctx->enc.encr_iv, ctx->key + ctx->enc_key_len,
		       AES_GCM_SALT_SIZE);

		rctx->ctrl_word.e.iv_offset = req->assoclen - AES_GCM_IV_OFFSET;
		break;

	default:
		/* Unknown cipher type */
		return -EINVAL;
	}
	rctx->ctrl_word.flags = cpu_to_be64(rctx->ctrl_word.flags);

	req_info->ctrl.s.dma_mode = DMA_GATHER_SCATTER;
	req_info->ctrl.s.se_req = SE_CORE_REQ;
	req_info->req.opcode.s.major = MAJOR_OP_FC |
				 DMA_MODE_FLAG(DMA_GATHER_SCATTER);
	if (enc) {
		req_info->req.opcode.s.minor = 2;
		req_info->req.param1 = req->cryptlen;
		req_info->req.param2 = req->cryptlen + req->assoclen;
	} else {
		req_info->req.opcode.s.minor = 3;
		req_info->req.param1 = req->cryptlen - mac_len;
		req_info->req.param2 = req->cryptlen + req->assoclen - mac_len;
	}

	fctx->enc.enc_ctrl.e.enc_cipher = ctx->cipher_type;
	fctx->enc.enc_ctrl.e.aes_key = ctx->key_type;
	fctx->enc.enc_ctrl.e.mac_type = ctx->mac_type;
	fctx->enc.enc_ctrl.e.mac_len = mac_len;
	fctx->enc.enc_ctrl.flags = cpu_to_be64(fctx->enc.enc_ctrl.flags);

	/* Storing Packet Data Information in offset
	 * Control Word First 8 bytes
	 */
	req_info->in[*argcnt].vptr = (u8 *)&rctx->ctrl_word;
	req_info->in[*argcnt].size = CONTROL_WORD_LEN;
	req_info->req.dlen += CONTROL_WORD_LEN;
	++(*argcnt);

	req_info->in[*argcnt].vptr = (u8 *)fctx;
	req_info->in[*argcnt].size = sizeof(struct fc_context);
	req_info->req.dlen += sizeof(struct fc_context);
	++(*argcnt);

	return 0;
}

static inline u32 create_hmac_ctx_hdr(struct aead_request *req, u32 *argcnt,
				      u32 enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;

	req_info->ctrl.s.dma_mode = DMA_GATHER_SCATTER;
	req_info->ctrl.s.se_req = SE_CORE_REQ;
	req_info->req.opcode.s.major = MAJOR_OP_HMAC |
				 DMA_MODE_FLAG(DMA_GATHER_SCATTER);
	req_info->is_trunc_hmac = ctx->is_trunc_hmac;

	req_info->req.opcode.s.minor = 0;
	req_info->req.param1 = ctx->auth_key_len;
	req_info->req.param2 = ctx->mac_type << 8;

	/* Add authentication key */
	req_info->in[*argcnt].vptr = ctx->key;
	req_info->in[*argcnt].size = ROUNDUP8(ctx->auth_key_len);
	req_info->req.dlen += ROUNDUP8(ctx->auth_key_len);
	++(*argcnt);

	return 0;
}

static inline u32 create_aead_input_list(struct aead_request *req, u32 enc)
{
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 inputlen =  req->cryptlen + req->assoclen;
	u32 status, argcnt = 0;

	status = create_aead_ctx_hdr(req, enc, &argcnt);
	if (status)
		return status;
	update_input_data(req_info, req->src, inputlen, &argcnt);
	req_info->incnt = argcnt;

	return 0;
}

static inline u32 create_aead_output_list(struct aead_request *req, u32 enc,
					  u32 mac_len)
{
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info =  &rctx->cpt_req;
	u32 argcnt = 0, outputlen = 0;

	if (enc)
		outputlen = req->cryptlen +  req->assoclen + mac_len;
	else
		outputlen = req->cryptlen + req->assoclen - mac_len;

	update_output_data(req_info, req->dst, 0, outputlen, &argcnt);
	req_info->outcnt = argcnt;

	return 0;
}

static inline u32 create_aead_null_input_list(struct aead_request *req,
					      u32 enc, u32 mac_len)
{
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 inputlen, argcnt = 0;

	if (enc)
		inputlen =  req->cryptlen + req->assoclen;
	else
		inputlen =  req->cryptlen + req->assoclen - mac_len;

	create_hmac_ctx_hdr(req, &argcnt, enc);
	update_input_data(req_info, req->src, inputlen, &argcnt);
	req_info->incnt = argcnt;

	return 0;
}

static inline u32 create_aead_null_output_list(struct aead_request *req,
					       u32 enc, u32 mac_len)
{
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info =  &rctx->cpt_req;
	struct scatterlist *dst;
	u8 *ptr = NULL;
	int argcnt = 0, status, offset;
	u32 inputlen;

	if (enc)
		inputlen =  req->cryptlen + req->assoclen;
	else
		inputlen =  req->cryptlen + req->assoclen - mac_len;

	if (req->src != req->dst) {
		/*
		 * If source and destination are different
		 * then copy payload to destination
		 */

		ptr = kmalloc(inputlen, (req_info->areq->flags &
					 CRYPTO_TFM_REQ_MAY_SLEEP) ?
					 GFP_KERNEL : GFP_ATOMIC);
		if (!ptr) {
			status = -ENOMEM;
			goto error;
		}

		status = sg_copy_to_buffer(req->src, sg_nents(req->src), ptr,
					   inputlen);
		if (status != inputlen) {
			status = -EINVAL;
			goto error;
		}
		status = sg_copy_from_buffer(req->dst, sg_nents(req->dst), ptr,
					     inputlen);
		if (status != inputlen) {
			status = -EINVAL;
			goto error;
		}
		kfree(ptr);
	}

	if (enc) {
		/*
		 * In an encryption scenario hmac needs
		 * to be appended after payload
		 */
		dst = req->dst;
		offset = inputlen;
		while (offset >= dst->length) {
			offset -= dst->length;
			dst = sg_next(dst);
			if (!dst) {
				status = -ENOENT;
				goto error;
			}
		}

		update_output_data(req_info, dst, offset, mac_len, &argcnt);
	} else {
		/*
		 * In a decryption scenario calculated hmac for received
		 * payload needs to be compare with hmac received
		 */
		status = sg_copy_buffer(req->src, sg_nents(req->src),
					rctx->fctx.hmac.s.hmac_recv, mac_len,
					inputlen, true);
		if (status != mac_len) {
			status = -EINVAL;
			goto error;
		}

		req_info->out[argcnt].vptr = rctx->fctx.hmac.s.hmac_calc;
		req_info->out[argcnt].size = mac_len;
		argcnt++;
	}

	req_info->outcnt = argcnt;
	return 0;
error:
	kfree(ptr);
	return status;
}

static u32 cvm_aead_enc_dec(struct aead_request *req, u8 reg_type, u8 enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	struct pci_dev *pdev;
	struct algs_ops *ops;
	u32 status, cpu_num;

	/* Clear control words */
	rctx->ctrl_word.flags = 0;
	rctx->fctx.enc.enc_ctrl.flags = 0;

	req_info->callback = cvm_callback;
	req_info->areq = &req->base;
	req_info->req_type = reg_type;
	req_info->is_enc = enc;
	req_info->is_trunc_hmac = false;

	switch (reg_type) {
	case AEAD_ENC_DEC_REQ:
		status = create_aead_input_list(req, enc);
		if (status)
			return status;
		status = create_aead_output_list(req, enc,
						 crypto_aead_authsize(tfm));
		if (status)
			return status;
		break;

	case AEAD_ENC_DEC_NULL_REQ:
		status = create_aead_null_input_list(req, enc,
						     crypto_aead_authsize(tfm));
		if (status)
			return status;
		status = create_aead_null_output_list(req, enc,
						crypto_aead_authsize(tfm));
		if (status)
			return status;
		break;

	default:
		return -EINVAL;
	}

	/* Validate that request doesn't exceed maximum CPT supported size */
	if (req_info->req.param1 > CPT_MAX_REQ_SIZE ||
	    req_info->req.param2 > CPT_MAX_REQ_SIZE)
		return -E2BIG;

	status = get_se_device(&pdev, &ops, &cpu_num);
	if (status)
		return status;

	if (!ops->cpt_get_kcrypto_eng_grp_num)
		return -EFAULT;
	req_info->ctrl.s.grp = ops->cpt_get_kcrypto_eng_grp_num(pdev);

	if (!ops->cpt_do_request)
		return -EFAULT;
	status = ops->cpt_do_request(pdev, req_info, cpu_num);
	/* We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return status;
}

static int cvm_aead_encrypt(struct aead_request *req)
{
	return cvm_aead_enc_dec(req, AEAD_ENC_DEC_REQ, true);
}

static int cvm_aead_decrypt(struct aead_request *req)
{
	return cvm_aead_enc_dec(req, AEAD_ENC_DEC_REQ, false);
}

static int cvm_aead_null_encrypt(struct aead_request *req)
{
	return cvm_aead_enc_dec(req, AEAD_ENC_DEC_NULL_REQ, true);
}

static int cvm_aead_null_decrypt(struct aead_request *req)
{
	return cvm_aead_enc_dec(req, AEAD_ENC_DEC_NULL_REQ, false);
}

struct crypto_alg algs[] = { {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "xts(aes)",
	.cra_driver_name = "cavium-xts-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = 2 * AES_MIN_KEY_SIZE,
			.max_keysize = 2 * AES_MAX_KEY_SIZE,
			.setkey = cvm_xts_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "cbc(aes)",
	.cra_driver_name = "cavium-cbc-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.setkey = cvm_cbc_aes_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "ecb(aes)",
	.cra_driver_name = "cavium-ecb-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = 0,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.setkey = cvm_ecb_aes_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "cfb(aes)",
	.cra_driver_name = "cavium-cfb-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.setkey = cvm_cfb_aes_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_des3_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "cbc(des3_ede)",
	.cra_driver_name = "cavium-cbc-des3_ede",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = DES_BLOCK_SIZE,
			.setkey = cvm_cbc_des3_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_des3_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "ecb(des3_ede)",
	.cra_driver_name = "cavium-ecb-des3_ede",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = 0,
			.setkey = cvm_ecb_des3_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
} };

struct aead_alg cvm_aeads[] = { {
	.base = {
		.cra_name = "authenc(hmac(sha1),cbc(aes))",
		.cra_driver_name = "authenc-hmac-sha1-cbc-aes-cavm",
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_cbc_aes_sha1_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_cbc_aes_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_encrypt,
	.decrypt = cvm_aead_decrypt,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA1_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha256),cbc(aes))",
		.cra_driver_name = "authenc-hmac-sha256-cbc-aes-cavm",
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_cbc_aes_sha256_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_cbc_aes_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_encrypt,
	.decrypt = cvm_aead_decrypt,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA256_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha384),cbc(aes))",
		.cra_driver_name = "authenc-hmac-sha384-cbc-aes-cavm",
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_cbc_aes_sha384_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_cbc_aes_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_encrypt,
	.decrypt = cvm_aead_decrypt,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA384_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha512),cbc(aes))",
		.cra_driver_name = "authenc-hmac-sha512-cbc-aes-cavm",
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_cbc_aes_sha512_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_cbc_aes_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_encrypt,
	.decrypt = cvm_aead_decrypt,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA512_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha1),ecb(cipher_null))",
		.cra_driver_name = "authenc-hmac-sha1-ecb-null-cavm",
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_ecb_null_sha1_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_ecb_null_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_null_encrypt,
	.decrypt = cvm_aead_null_decrypt,
	.ivsize = 0,
	.maxauthsize = SHA1_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha256),ecb(cipher_null))",
		.cra_driver_name = "authenc-hmac-sha256-ecb-null-cavm",
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_ecb_null_sha256_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_ecb_null_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_null_encrypt,
	.decrypt = cvm_aead_null_decrypt,
	.ivsize = 0,
	.maxauthsize = SHA256_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha384),ecb(cipher_null))",
		.cra_driver_name = "authenc-hmac-sha384-ecb-null-cavm",
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_ecb_null_sha384_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_ecb_null_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_null_encrypt,
	.decrypt = cvm_aead_null_decrypt,
	.ivsize = 0,
	.maxauthsize = SHA384_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha512),ecb(cipher_null))",
		.cra_driver_name = "authenc-hmac-sha512-ecb-null-cavm",
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_ecb_null_sha512_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_ecb_null_sha_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_null_encrypt,
	.decrypt = cvm_aead_null_decrypt,
	.ivsize = 0,
	.maxauthsize = SHA512_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "rfc4106(gcm(aes))",
		.cra_driver_name = "rfc4106-gcm-aes-cavm",
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_gcm_aes_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_gcm_aes_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_encrypt,
	.decrypt = cvm_aead_decrypt,
	.ivsize = AES_GCM_IV_SIZE,
	.maxauthsize = AES_GCM_ICV_SIZE,
} };

static inline int is_any_alg_used(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(algs); i++)
		if (atomic_read(&algs[i].cra_refcnt) != 1)
			return true;
	for (i = 0; i < ARRAY_SIZE(cvm_aeads); i++)
		if (atomic_read(&cvm_aeads[i].base.cra_refcnt) != 1)
			return true;
	return false;
}

static inline int cav_register_algs(void)
{
	int i, err = 0;

	for (i = 0; i < ARRAY_SIZE(algs); i++)
		algs[i].cra_flags &= ~CRYPTO_ALG_DEAD;
	err = crypto_register_algs(algs, ARRAY_SIZE(algs));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(cvm_aeads); i++)
		cvm_aeads[i].base.cra_flags &= ~CRYPTO_ALG_DEAD;
	err = crypto_register_aeads(cvm_aeads, ARRAY_SIZE(cvm_aeads));
	if (err) {
		crypto_unregister_algs(algs, ARRAY_SIZE(algs));
		return err;
	}

	return 0;
}

static inline void cav_unregister_algs(void)
{
	crypto_unregister_algs(algs, ARRAY_SIZE(algs));
	crypto_unregister_aeads(cvm_aeads, ARRAY_SIZE(cvm_aeads));
}

static int compare_func(const void *lptr, const void *rptr)
{
	struct cpt_device_desc *ldesc = (struct cpt_device_desc *) lptr;
	struct cpt_device_desc *rdesc = (struct cpt_device_desc *) rptr;

	if (ldesc->dev->devfn < rdesc->dev->devfn)
		return -1;
	if (ldesc->dev->devfn > rdesc->dev->devfn)
		return 1;
	return 0;
}

static void swap_func(void *lptr, void *rptr, int size)
{
	struct cpt_device_desc *ldesc = (struct cpt_device_desc *) lptr;
	struct cpt_device_desc *rdesc = (struct cpt_device_desc *) rptr;
	struct cpt_device_desc desc;

	desc = *ldesc;
	*ldesc = *rdesc;
	*rdesc = desc;
}

int cvm_crypto_init(struct pci_dev *pdev, struct module *mod,
		    struct algs_ops ops, enum cpt_pf_type pf_type,
		    enum cpt_eng_type engine_type, int num_queues,
		    int num_devices)
{
	int ret = 0;
	int count;

	mutex_lock(&mutex);
	switch (engine_type) {
	case SE_TYPES:
		count = atomic_read(&se_devices.count);
		if (count >= CPT_MAX_VF_NUM) {
			dev_err(&pdev->dev, "No space to add a new device");
			ret = -ENOSPC;
			goto err;
		}
		se_devices.desc[count].pf_type = pf_type;
		se_devices.desc[count].num_queues = num_queues;
		se_devices.desc[count].ops = ops;
		se_devices.desc[count++].dev = pdev;
		atomic_inc(&se_devices.count);

		if (atomic_read(&se_devices.count) == num_devices &&
		    is_crypto_registered == false) {
			if (cav_register_algs()) {
				dev_err(&pdev->dev,
				   "Error in registering crypto algorithms\n");
				ret =  -EINVAL;
				goto err;
			}
			try_module_get(mod);
			is_crypto_registered = true;
		}
		sort(se_devices.desc, count, sizeof(struct cpt_device_desc),
		     compare_func, swap_func);
		break;

	case AE_TYPES:
		count = atomic_read(&ae_devices.count);
		if (count >= CPT_MAX_VF_NUM) {
			dev_err(&pdev->dev, "No space to a add new device");
			ret = -ENOSPC;
			goto err;
		}
		ae_devices.desc[count].pf_type = pf_type;
		ae_devices.desc[count].num_queues = num_queues;
		ae_devices.desc[count].ops = ops;
		ae_devices.desc[count++].dev = pdev;
		atomic_inc(&ae_devices.count);
		sort(ae_devices.desc, count, sizeof(struct cpt_device_desc),
		     compare_func, swap_func);
		break;

	default:
		dev_err(&pdev->dev, "Unknown VF type %d\n", engine_type);
	}
err:
	mutex_unlock(&mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(cvm_crypto_init);

void cvm_crypto_exit(struct pci_dev *pdev, struct module *mod,
		     enum cpt_eng_type engine_type)
{
	struct cpt_device_table *dev_tbl;
	bool dev_found = false;
	int i, j, count;

	mutex_lock(&mutex);

	dev_tbl = (engine_type == AE_TYPES) ? &ae_devices : &se_devices;
	count = atomic_read(&dev_tbl->count);
	for (i = 0; i < count; i++)
		if (pdev == dev_tbl->desc[i].dev) {
			for (j = i; j < count-1; j++)
				dev_tbl->desc[j] = dev_tbl->desc[j+1];
			dev_found = true;
			break;
		}

	if (!dev_found) {
		dev_err(&pdev->dev, "%s device not found", __func__);
		goto exit;
	}

	if (!(engine_type == AE_TYPES)) {
		if (atomic_dec_and_test(&se_devices.count) &&
		    !is_any_alg_used()) {
			cav_unregister_algs();
			module_put(mod);
			is_crypto_registered = false;
		}
	} else
		atomic_dec(&ae_devices.count);
exit:
	mutex_unlock(&mutex);
}
EXPORT_SYMBOL_GPL(cvm_crypto_exit);

