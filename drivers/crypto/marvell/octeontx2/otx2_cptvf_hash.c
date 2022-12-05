// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Marvell. */

#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/hash.h>
#include <linux/rtnetlink.h>
#include <linux/sort.h>
#include <linux/module.h>
#include "otx2_cptvf.h"
#include "otx2_cptvf_algs.h"
#include "otx2_cpt_reqmgr.h"

#define CPT_HMAC_KEY_SIZE_MAX  1024
#define CPT_HMAC_CTX_SIZE      (34 * 8)

enum hmac_minor_op {
	HMAC_FULL = 0,
	HMAC_START,
	HMAC_UPDATE,
	HMAC_FINISH
};

struct cpt_hmac_ctx {
	u8 key[CPT_HMAC_KEY_SIZE_MAX];
	u32 key_len;
	void *cptr;
	dma_addr_t cptr_dma;
	u32 digest_size;
	u8 hash_type;
};

struct cpt_hmac_req_ctx {
	u8 digest[HASH_MAX_DIGESTSIZE];
	struct cpt_hmac_ctx *ctx;
};

static void cpt_hash_callback(int status, void *arg1, void *arg2)
{
	struct otx2_cpt_inst_info *inst_info = arg2;
	struct crypto_async_request *areq = arg1;
	struct pci_dev *pdev = inst_info->pdev;
	struct otx2_cpt_req_info *req_info;
	struct ahash_request *ahash_req;
	struct otx2_cptvf_request *req;
	struct cpt_hmac_req_ctx *rctx;
	struct cpt_hmac_ctx *ctx;

	if (inst_info) {
		req_info = inst_info->req;
		req = &req_info->req;
		ahash_req = container_of(areq, struct ahash_request, base);
		rctx = ahash_request_ctx(ahash_req);
		ctx = rctx->ctx;
		if (req->opcode.s.minor == HMAC_FINISH) {
			dma_unmap_single(&pdev->dev, req->cptr_dma, CPT_HMAC_CTX_SIZE,
					 DMA_BIDIRECTIONAL);
			dma_unmap_single(&pdev->dev, req->dptr_dma, ctx->digest_size,
					 DMA_BIDIRECTIONAL);
			kfree(req->cptr);
		}
		if (req->opcode.s.minor == HMAC_FINISH || req->opcode.s.minor == HMAC_FULL) {
			if (!status)
				memcpy(ahash_req->result, rctx->digest, ctx->digest_size);
		}
		kfree(req_info);
		otx2_cpt_info_destroy(pdev, inst_info);
	}

	if (areq)
		areq->complete(areq, status);
}

static inline void create_hmac_ctx_hdr(struct otx2_cpt_req_info *req_info, struct cpt_hmac_ctx *ctx,
				       int minor_op, u32 *argcnt)
{
	req_info->ctrl.s.dma_mode = OTX2_CPT_DMA_MODE_SG;
	req_info->ctrl.s.se_req = 1;
	req_info->req.opcode.s.major = OTX2_CPT_MAJOR_OP_HMAC |
				 DMA_MODE_FLAG(OTX2_CPT_DMA_MODE_SG);
	req_info->is_trunc_hmac = 0;

	switch (minor_op) {
	case HMAC_FULL:
	case HMAC_START:
		req_info->req.param1 = ctx->key_len;
		req_info->in[*argcnt].vptr = ctx->key;
		req_info->in[*argcnt].size = round_up(ctx->key_len, 8);
		++(*argcnt);
		break;
	case HMAC_UPDATE:
	case HMAC_FINISH:
		req_info->req.param1 = 0;
		break;
	}
	req_info->req.param2 = ctx->hash_type << 8;
	req_info->req.opcode.s.minor = minor_op;
}

static inline void update_input_data(struct ahash_request *req, struct otx2_cpt_req_info *req_info,
				     u32 *argcnt)
{
	struct scatterlist *inp_sg = req->src;
	u32 nbytes = req->nbytes;

	if (inp_sg == NULL)
		return;

	while (nbytes) {
		u32 len = (nbytes < inp_sg->length) ? nbytes : inp_sg->length;
		u8 *ptr = sg_virt(inp_sg);

		req_info->in[*argcnt].vptr = (void *)ptr;
		req_info->in[*argcnt].size = len;
		nbytes -= len;
		++(*argcnt);
		inp_sg = sg_next(inp_sg);
	}
}

static inline void update_output_data(struct ahash_request *req, struct otx2_cpt_req_info *req_info)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct cpt_hmac_req_ctx *rctx = ahash_request_ctx(req);

	req_info->out[0].vptr = rctx->digest;
	req_info->out[0].size = ctx->digest_size;
	req_info->out_cnt = 1;
}

static inline int cpt_hmac_enqueue(struct ahash_request *req, struct otx2_cpt_req_info *req_info,
				   struct pci_dev *pdev, int cpu_num)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	req_info->ctrl.s.grp = otx2_cpt_get_kcrypto_eng_grp_num(pdev);
	req_info->callback = cpt_hash_callback;
	req_info->areq = &req->base;
	req_info->req.cptr = ctx->cptr;
	req_info->req.cptr_dma = ctx->cptr_dma;
	/*
	 * We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return otx2_cpt_do_request(pdev, req_info, cpu_num);
}

static int cpt_hmac_sha_init(struct ahash_request *req)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct cpt_hmac_req_ctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct otx2_cpt_req_info *req_info;
	struct pci_dev *pdev;
	int ret, cpu_num;
	u32 argcnt = 0;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	switch (crypto_ahash_digestsize(tfm)) {
	case SHA1_DIGEST_SIZE:
		ctx->hash_type = OTX2_CPT_SHA1;
		ctx->digest_size = SHA1_DIGEST_SIZE;
		break;
	case SHA256_DIGEST_SIZE:
		ctx->hash_type = OTX2_CPT_SHA256;
		ctx->digest_size = SHA256_DIGEST_SIZE;
		break;
	default:
		return -EINVAL;
	}
	ctx->cptr = kmalloc(CPT_HMAC_CTX_SIZE, GFP_ATOMIC);
	if (ctx->cptr == NULL)
		return -ENOMEM;

	req_info = kzalloc(sizeof(*req_info), GFP_KERNEL);
	if (req_info == NULL) {
		ret = -ENOMEM;
		goto cptr_free;
	}
	ctx->cptr_dma = dma_map_single(&pdev->dev, ctx->cptr, CPT_HMAC_CTX_SIZE,
				       DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(&pdev->dev, ctx->cptr_dma))) {
		dev_err(&pdev->dev, "DMA mapping failed for cptr\n");
		ret = -EIO;
		goto req_info_free;
	}
	rctx->ctx = ctx;

	create_hmac_ctx_hdr(req_info, ctx, HMAC_START, &argcnt);
	update_input_data(req, req_info, &argcnt);
	req_info->in_cnt = argcnt;
	update_output_data(req, req_info);

	ret = cpt_hmac_enqueue(req, req_info, pdev, cpu_num);
	if (ret != -EINPROGRESS && ret != -EBUSY)
		goto req_info_free;

	return ret;

req_info_free:
	kfree(req_info);
cptr_free:
	kfree(ctx->cptr);
	return ret;
}

static int cpt_hmac_sha_update(struct ahash_request *req)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct cpt_hmac_req_ctx *rctx = ahash_request_ctx(req);
	struct otx2_cpt_req_info *req_info;
	struct pci_dev *pdev;
	int ret, cpu_num;
	u32 argcnt = 0;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	if (ctx->cptr == NULL) {
		dev_err(&pdev->dev, "Unknown HMAC context\n");
		return -EINVAL;
	}
	if (req->nbytes > OTX2_CPT_MAX_REQ_SIZE)
		return -EINVAL;

	req_info = kzalloc(sizeof(*req_info), GFP_KERNEL);
	if (req_info == NULL)
		return -ENOMEM;

	rctx->ctx = ctx;
	create_hmac_ctx_hdr(req_info, ctx, HMAC_UPDATE, &argcnt);
	update_input_data(req, req_info, &argcnt);
	req_info->in_cnt = argcnt;
	update_output_data(req, req_info);

	ret = cpt_hmac_enqueue(req, req_info, pdev, cpu_num);
	if (ret != -EINPROGRESS && ret != -EBUSY)
		goto req_info_free;

	return ret;

req_info_free:
	kfree(req_info);
	return ret;
}

static int cpt_hmac_sha_final(struct ahash_request *req)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct cpt_hmac_req_ctx *rctx = ahash_request_ctx(req);
	struct otx2_cpt_req_info *req_info;
	struct pci_dev *pdev;
	dma_addr_t dptr_dma;
	int ret, cpu_num;
	u32 argcnt = 0;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	if (ctx->cptr == NULL) {
		dev_err(&pdev->dev, "Unknown HMAC context\n");
		return -EINVAL;
	}
	req_info = kzalloc(sizeof(*req_info), GFP_KERNEL);
	if (req_info == NULL)
		return -ENOMEM;

	rctx->ctx = ctx;
	create_hmac_ctx_hdr(req_info, ctx, HMAC_FINISH, &argcnt);

	req_info->ctrl.s.dma_mode = OTX2_CPT_DMA_MODE_DIRECT;
	req_info->req.opcode.s.major = OTX2_CPT_MAJOR_OP_HMAC | (1 << 6);
	req_info->req.dlen = 0;
	dptr_dma = dma_map_single(&pdev->dev, rctx->digest, ctx->digest_size,
				  DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(&pdev->dev, dptr_dma))) {
		dev_err(&pdev->dev, "DMA mapping failed for dptr\n");
		ret = -EIO;
		goto req_info_free;
	}
	req_info->req.dptr_dma = dptr_dma;

	ret = cpt_hmac_enqueue(req, req_info, pdev, cpu_num);
	if (ret != -EINPROGRESS && ret != -EBUSY)
		goto dptr_unmap;

	return ret;

dptr_unmap:
	dma_unmap_single(&pdev->dev, dptr_dma, ctx->digest_size,
			 DMA_BIDIRECTIONAL);
req_info_free:
	kfree(req_info);
	return ret;
}

static int cpt_hmac_sha_digest(struct ahash_request *req)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct cpt_hmac_req_ctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct otx2_cpt_req_info *req_info;
	struct pci_dev *pdev;
	int ret, cpu_num;
	u32 argcnt = 0;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	switch (crypto_ahash_digestsize(tfm)) {
	case SHA1_DIGEST_SIZE:
		ctx->hash_type = OTX2_CPT_SHA1;
		ctx->digest_size = SHA1_DIGEST_SIZE;
		break;
	case SHA256_DIGEST_SIZE:
		ctx->hash_type = OTX2_CPT_SHA256;
		ctx->digest_size = SHA256_DIGEST_SIZE;
		break;
	default:
		return -EINVAL;
	}
	if (req->nbytes > OTX2_CPT_MAX_REQ_SIZE)
		return -EINVAL;

	req_info = kzalloc(sizeof(*req_info), GFP_KERNEL);
	if (req_info == NULL)
		return -ENOMEM;

	rctx->ctx = ctx;
	create_hmac_ctx_hdr(req_info, ctx, HMAC_FULL, &argcnt);
	update_input_data(req, req_info, &argcnt);
	req_info->in_cnt = argcnt;
	update_output_data(req, req_info);

	ret = cpt_hmac_enqueue(req, req_info, pdev, cpu_num);
	if (ret != -EINPROGRESS && ret != -EBUSY)
		goto req_info_free;

	return ret;

req_info_free:
	kfree(req_info);
	return ret;
}

static int cpt_hmac_sha_setkey(struct crypto_ahash *tfm, const u8 *key,
				unsigned int keylen)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(crypto_ahash_tfm(tfm));

	memcpy(ctx->key, key, keylen);
	ctx->key_len = keylen;

	return 0;
}

static int cpt_hmac_sha_export(struct ahash_request *req, void *out)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	if (ctx->cptr)
		memcpy(out, ctx->cptr, CPT_HMAC_CTX_SIZE);
	return 0;
}

static int cpt_hmac_sha_import(struct ahash_request *req, const void *in)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	if (ctx->cptr)
		memcpy(ctx->cptr, in, CPT_HMAC_CTX_SIZE);

	return 0;
}

static int cpt_hmac_sha_cra_init(struct crypto_tfm *tfm)
{
	struct cpt_hmac_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct cpt_hmac_req_ctx));
	return 0;
}

static struct ahash_alg cpt_hmac_algs[] = {
{
	.init		= cpt_hmac_sha_init,
	.update		= cpt_hmac_sha_update,
	.final		= cpt_hmac_sha_final,
	.digest		= cpt_hmac_sha_digest,
	.setkey		= cpt_hmac_sha_setkey,
	.export		= cpt_hmac_sha_export,
	.import		= cpt_hmac_sha_import,
	.halg = {
		.digestsize	= SHA1_DIGEST_SIZE,
		.statesize	= CPT_HMAC_CTX_SIZE,
		.base	= {
			.cra_name		= "hmac(sha1)",
			.cra_driver_name	= "cpt-hmac-sha1",
			.cra_priority		= 4001,
			.cra_flags		= CRYPTO_ALG_ASYNC,
			.cra_blocksize		= SHA1_BLOCK_SIZE,
			.cra_ctxsize		= sizeof(struct cpt_hmac_ctx),
			.cra_alignmask		= 0,
			.cra_module		= THIS_MODULE,
			.cra_init		= cpt_hmac_sha_cra_init,
		}
	}
},
{
	.init		= cpt_hmac_sha_init,
	.update		= cpt_hmac_sha_update,
	.final		= cpt_hmac_sha_final,
	.digest		= cpt_hmac_sha_digest,
	.setkey		= cpt_hmac_sha_setkey,
	.export		= cpt_hmac_sha_export,
	.import		= cpt_hmac_sha_import,
	.halg = {
		.digestsize	= SHA256_DIGEST_SIZE,
		.statesize	= CPT_HMAC_CTX_SIZE,
		.base	= {
			.cra_name		= "hmac(sha256)",
			.cra_driver_name	= "cpt-hmac-sha256",
			.cra_priority		= 4001,
			.cra_flags		= CRYPTO_ALG_ASYNC,
			.cra_blocksize		= SHA256_BLOCK_SIZE,
			.cra_ctxsize		= sizeof(struct cpt_hmac_ctx),
			.cra_alignmask		= 0,
			.cra_module		= THIS_MODULE,
			.cra_init		= cpt_hmac_sha_cra_init,
		}
	}
},
};

int otx2_cpt_register_hmac_hash_algs(void)
{
	return crypto_register_ahashes(cpt_hmac_algs, ARRAY_SIZE(cpt_hmac_algs));
}

void otx2_cpt_unregister_hmac_hash_algs(void)
{
	crypto_unregister_ahashes(cpt_hmac_algs,
				    ARRAY_SIZE(cpt_hmac_algs));
}
