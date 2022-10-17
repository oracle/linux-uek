// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Marvell. */

#include <crypto/akcipher.h>
#include <crypto/ecdh.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/kpp.h>
#include <crypto/internal/rsa.h>
#include <crypto/kpp.h>
#include <crypto/scatterwalk.h>
#include <linux/module.h>
#include "otx2_cptvf.h"
#include "otx2_cptvf_algs.h"
#include "otx2_cpt_reqmgr.h"

#define CPT_CRT_PRMS  5
#define CPT_EGRP_AE   2

struct cpt_rsa_ctx {
	char *pubkey;
	char *prikey;
	/* low address: dq->dp->q->p->qinv */
	char *crt_prikey;
	u32 e_sz;
	u32 d_sz;
	bool crt_mode;
	bool pkcs1;
};

struct cpt_asym_ctx {
	unsigned int key_sz;
	struct device *dev;
	struct cpt_rsa_ctx rsa;
};

struct cpt_asym_req_ctx {
	struct otx2_cpt_req_info cpt_req;
	struct cpt_asym_ctx *ctx;
};

static void cpt_rsa_callback(int status, void *arg1, void *arg2)
{
	struct otx2_cpt_inst_info *inst_info = arg2;
	struct crypto_async_request *areq = arg1;
	struct otx2_cpt_req_info *req_info;
	struct akcipher_request *ak_req;
	struct otx2_cptvf_request *req;
	struct cpt_asym_req_ctx *rctx;
	struct pci_dev *pdev;

	if (inst_info) {
		req_info = inst_info->req;
		req = &req_info->req;
		ak_req = container_of(areq, struct akcipher_request, base);
		rctx = akcipher_request_ctx(ak_req);
		pdev = inst_info->pdev;

		ak_req->dst_len = rctx->ctx->key_sz;
		if (!status) {
			if (rctx->ctx->rsa.pkcs1 && (req->opcode.s.minor == 0x5 ||
			    req->opcode.s.minor == 4))
				scatterwalk_map_and_copy(req->dptr + 2, ak_req->dst, 0,
							 ak_req->dst_len, 1);
			else
				scatterwalk_map_and_copy(req->dptr, ak_req->dst, 0,
							 ak_req->dst_len, 1);
		}

		dma_unmap_single(&pdev->dev, req->dptr_dma, req->dlen,
				 DMA_BIDIRECTIONAL);
		kfree(req->dptr);
		otx2_cpt_info_destroy(pdev, inst_info);
	}
	if (areq)
		areq->complete(areq, status);
}

static int cpt_asym_enqueue(struct akcipher_request *req)
{
	struct cpt_asym_req_ctx *rctx = akcipher_request_ctx(req);
	struct otx2_cpt_req_info *req_info = &rctx->cpt_req;
	struct pci_dev *pdev;
	int cpu_num, ret;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	req_info->ctrl.s.grp = CPT_EGRP_AE;
	req_info->callback = cpt_rsa_callback;
	req_info->areq = &req->base;
	/*
	 * We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return otx2_cpt_do_request(pdev, req_info, cpu_num);
}

static void cpt_rsa_drop_leading_zeros(const char **ptr, size_t *len)
{
	while (!**ptr && *len) {
		(*ptr)++;
		(*len)--;
	}
}

static int cpt_rsa_enc(struct akcipher_request *req)
{
	struct cpt_asym_req_ctx *rctx = akcipher_request_ctx(req);
	struct cpt_asym_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct otx2_cpt_req_info *req_info = &rctx->cpt_req;
	u32 pubkey_len, dlen;
	char *dptr;

	if (unlikely(!ctx->rsa.pubkey))
		return -EINVAL;

	/* HW expects src length to be less than modulus length - 11. */
	if (req->src_len > (ctx->key_sz - 11))
		return -EINVAL;

	if (req->dst_len < ctx->key_sz) {
		req->dst_len = ctx->key_sz;
		return -EOVERFLOW;
	}
	rctx->ctx = ctx;
	req_info->ctrl.s.dma_mode = OTX2_CPT_DMA_MODE_DIRECT;
	req_info->ctrl.s.se_req = 0;
	req_info->req.opcode.s.major = OTX2_CPT_MAJOR_OP_PKCS_ENC | (1 << 6);
	req_info->is_trunc_hmac = 0;

	req_info->req.param1 = ctx->key_sz;
	if (ctx->rsa.pkcs1) {
		req_info->req.param2 |= ctx->rsa.e_sz << 1;
		req_info->req.opcode.s.minor = 0x02;
	} else {
		req_info->req.param2 = ctx->rsa.e_sz;
		req_info->req.opcode.s.minor = 0x01;
	}

	pubkey_len = ctx->key_sz + ctx->rsa.e_sz;
	dlen = pubkey_len + req->src_len;
	/*
	 * HW expects total input to be in contigeous buffer, so allocate new
	 * buf and copy src data.
	 */
	dptr = kmalloc(dlen, GFP_KERNEL);
	if (dptr == NULL)
		return -ENOMEM;
	req_info->req.dptr_dma = dma_map_single(ctx->dev, dptr, dlen,
						DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(ctx->dev, req_info->req.dptr_dma))) {
		dev_err(ctx->dev, "DMA mapping failed for dptr\n");
		kfree(dptr);
		return -EIO;
	}
	memcpy(dptr, ctx->rsa.pubkey, pubkey_len);
	scatterwalk_map_and_copy(dptr + pubkey_len, req->src, 0, req->src_len, 0);
	req_info->req.dlen = dlen;
	req_info->req.dptr = dptr;

	return cpt_asym_enqueue(req);
}

static int cpt_rsa_dec(struct akcipher_request *req)
{
	struct cpt_asym_req_ctx *rctx = akcipher_request_ctx(req);
	struct cpt_asym_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct otx2_cpt_req_info *req_info = &rctx->cpt_req;
	u32 prikey_len, dlen;
	void *prikey;
	char *dptr;

	if (unlikely(!ctx->rsa.prikey))
		return -EINVAL;

	if (req->dst_len < ctx->key_sz) {
		req->dst_len = ctx->key_sz;
		return -EOVERFLOW;
	}
	rctx->ctx = ctx;
	req_info->ctrl.s.dma_mode = OTX2_CPT_DMA_MODE_DIRECT;
	req_info->ctrl.s.se_req = 0;
	req_info->req.opcode.s.major = OTX2_CPT_MAJOR_OP_PKCS_ENC | (1 << 6);
	req_info->is_trunc_hmac = 0;

	req_info->req.param1 = ctx->key_sz;
	if (ctx->rsa.crt_mode) {
		if (ctx->rsa.pkcs1)
			req_info->req.opcode.s.minor = 0x05;
		else
			req_info->req.opcode.s.minor = 0x06;
		prikey = ctx->rsa.crt_prikey;
		prikey_len = CPT_CRT_PRMS * (ctx->key_sz >> 1);
	} else {
		if (ctx->rsa.pkcs1)
			req_info->req.opcode.s.minor = 0x04;
		else
			req_info->req.opcode.s.minor = 0x01;
		prikey = (void *)ctx->rsa.prikey;
		prikey_len = ctx->key_sz + ctx->rsa.d_sz;
		req_info->req.param2 = ctx->rsa.d_sz;
	}
	dlen = prikey_len + req->src_len;

	/*
	 * HW expects total input to be in contigeous buffer, so allocate new
	 * buf and copy src data.
	 */
	dptr = kmalloc(dlen, GFP_KERNEL);
	if (dptr == NULL)
		return -ENOMEM;
	req_info->req.dptr_dma = dma_map_single(ctx->dev, dptr, dlen,
						DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(ctx->dev, req_info->req.dptr_dma))) {
		dev_err(ctx->dev, "DMA mapping failed for dptr\n");
		kfree(dptr);
		return -EIO;
	}
	memcpy(dptr, prikey, prikey_len);
	scatterwalk_map_and_copy(dptr + prikey_len, req->src, 0, req->src_len, 0);
	req_info->req.dlen = dlen;
	req_info->req.dptr = dptr;

	return cpt_asym_enqueue(req);
}

static void cpt_rsa_ctx_clear(struct cpt_asym_ctx *ctx)
{
	unsigned int hlf_ksz = ctx->key_sz >> 1;

	kfree(ctx->rsa.pubkey);
	if (ctx->rsa.crt_prikey) {
		memzero_explicit(ctx->rsa.crt_prikey,
				 hlf_ksz * CPT_CRT_PRMS);
		kfree(ctx->rsa.crt_prikey);
		ctx->rsa.crt_prikey = NULL;
	}
	if (ctx->rsa.prikey) {
		memzero_explicit(ctx->rsa.prikey, ctx->key_sz);
		kfree(ctx->rsa.prikey);
		ctx->rsa.prikey = NULL;
	}
	ctx->key_sz = 0;
}

static int cpt_rsa_set_n(struct cpt_asym_ctx *ctx, const char *value,
			 size_t vlen, bool private)
{
	const char *ptr = value;

	cpt_rsa_drop_leading_zeros(&ptr, &vlen);
	if (vlen < 17 || vlen > 1024)
		return -EINVAL;

	ctx->rsa.pubkey = kmalloc(vlen << 1, GFP_KERNEL);
	if (!ctx->rsa.pubkey)
		return -ENOMEM;

	ctx->key_sz = vlen;
	if (private) {
		if (vlen < 34 || vlen > 1024 || !(vlen % 2 == 0))
			return -EINVAL;
		ctx->rsa.prikey = kmalloc(vlen << 1, GFP_KERNEL);
		if (!ctx->rsa.prikey) {
			kfree(ctx->rsa.pubkey);
			ctx->rsa.pubkey = NULL;
			return -ENOMEM;
		}
		memcpy(ctx->rsa.prikey, ptr, vlen);
	}
	memcpy(ctx->rsa.pubkey, ptr, vlen);

	return 0;
}

static int cpt_rsa_set_e(struct cpt_asym_ctx *ctx, const char *value,
			 size_t vlen)
{
	const char *ptr = value;

	cpt_rsa_drop_leading_zeros(&ptr, &vlen);
	if (!ctx->key_sz || !vlen || vlen > ctx->key_sz)
		return -EINVAL;

	ctx->rsa.e_sz = vlen;
	memcpy(ctx->rsa.pubkey + ctx->key_sz, ptr, vlen);

	return 0;
}

static int cpt_rsa_set_d(struct cpt_asym_ctx *ctx, const char *value,
			 size_t vlen)
{
	const char *ptr = value;

	cpt_rsa_drop_leading_zeros(&ptr, &vlen);
	if (!ctx->key_sz || !vlen || vlen > ctx->key_sz)
		return -EINVAL;

	ctx->rsa.d_sz = vlen;
	memcpy(ctx->rsa.prikey + ctx->key_sz, ptr, vlen);

	return 0;
}

static int cpt_crt_para_get(char *para, size_t para_sz,
			    const char *raw, size_t raw_sz)
{
	const char *ptr = raw;
	size_t len = raw_sz;

	cpt_rsa_drop_leading_zeros(&ptr, &len);
	if (!len || len > para_sz)
		return -EINVAL;

	memcpy(para + para_sz - len, ptr, len);

	return 0;
}

static int cpt_rsa_setkey_crt(struct cpt_asym_ctx *ctx, struct rsa_key *rsa_key)
{
	unsigned int hlf_ksz = ctx->key_sz >> 1;
	u64 offset;
	int ret;

	ctx->rsa.crt_prikey = kmalloc(hlf_ksz * CPT_CRT_PRMS, GFP_KERNEL);
	if (!ctx->rsa.crt_prikey)
		return -ENOMEM;

	ret = cpt_crt_para_get(ctx->rsa.crt_prikey, hlf_ksz,
			       rsa_key->q, rsa_key->q_sz);
	if (ret)
		goto free_key;

	offset = hlf_ksz;
	ret = cpt_crt_para_get(ctx->rsa.crt_prikey + offset, hlf_ksz,
			       rsa_key->dq, rsa_key->dq_sz);
	if (ret)
		goto free_key;

	offset += hlf_ksz;
	ret = cpt_crt_para_get(ctx->rsa.crt_prikey + offset, hlf_ksz,
			       rsa_key->p, rsa_key->p_sz);
	if (ret)
		goto free_key;

	offset += hlf_ksz;
	ret = cpt_crt_para_get(ctx->rsa.crt_prikey + offset, hlf_ksz,
			       rsa_key->dp, rsa_key->dp_sz);
	if (ret)
		goto free_key;

	offset += hlf_ksz;
	ret = cpt_crt_para_get(ctx->rsa.crt_prikey + offset, hlf_ksz,
			       rsa_key->qinv, rsa_key->qinv_sz);
	if (ret)
		goto free_key;

	ctx->rsa.crt_mode = true;
	return 0;

free_key:
	offset = hlf_ksz * CPT_CRT_PRMS;
	memzero_explicit(ctx->rsa.crt_prikey, offset);
	kfree(ctx->rsa.crt_prikey);
	ctx->rsa.crt_prikey = NULL;
	ctx->rsa.crt_mode = false;

	return ret;
}

static bool cpt_is_crt_key(struct rsa_key *key)
{
	u16 len = key->p_sz + key->q_sz + key->dp_sz + key->dq_sz +
		  key->qinv_sz;

#define LEN_OF_NCRT_PARA	5

	/* N-CRT less than 5 parameters */
	return len > LEN_OF_NCRT_PARA;
}

static int cpt_rsa_setkey(struct cpt_asym_ctx *ctx, const void *key,
			  unsigned int keylen, bool private)
{
	struct rsa_key rsa_key;
	int ret;

	if (private)
		ret = rsa_parse_priv_key(&rsa_key, key, keylen);
	else
		ret = rsa_parse_pub_key(&rsa_key, key, keylen);
	if (ret < 0)
		return ret;

	ret = cpt_rsa_set_n(ctx, rsa_key.n, rsa_key.n_sz, private);
	if (ret < 0)
		return ret;

	if (private) {
		ret = cpt_rsa_set_d(ctx, rsa_key.d, rsa_key.d_sz);
		if (ret < 0)
			goto free;

		if (cpt_is_crt_key(&rsa_key)) {
			ret = cpt_rsa_setkey_crt(ctx, &rsa_key);
			if (ret < 0)
				goto free;
		}
	}
	ret = cpt_rsa_set_e(ctx, rsa_key.e, rsa_key.e_sz);
	if (ret < 0)
		goto free;

	return 0;

free:
	cpt_rsa_ctx_clear(ctx);
	return ret;
}

static int cpt_rsa_setpubkey(struct crypto_akcipher *tfm, const void *key,
			     unsigned int keylen)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);

	return cpt_rsa_setkey(ctx, key, keylen, false);
}

static int cpt_rsa_setprivkey(struct crypto_akcipher *tfm, const void *key,
			      unsigned int keylen)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);

	return cpt_rsa_setkey(ctx, key, keylen, true);
}

static unsigned int cpt_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ctx->key_sz;
}

static unsigned int cpt_rsa_pkcs1_max_size(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ctx->key_sz + 2;
}

static int cpt_rsa_init_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct pci_dev *pdev;
	int ret, cpu_num;

	ctx->key_sz = 0;
	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	ctx->dev = &pdev->dev;

	return 0;
}

static int cpt_rsa_pkcs1_init_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct pci_dev *pdev;
	int ret, cpu_num;

	ctx->key_sz = 0;
	ctx->rsa.pkcs1 = true;
	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	ctx->dev = &pdev->dev;

	return 0;
}

static void cpt_rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);

	cpt_rsa_ctx_clear(ctx);
}

static struct akcipher_alg cpt_rsa_algs[] = {
{
	.encrypt = cpt_rsa_enc,
	.decrypt = cpt_rsa_dec,
	.set_pub_key = cpt_rsa_setpubkey,
	.set_priv_key = cpt_rsa_setprivkey,
	.max_size = cpt_rsa_max_size,
	.init = cpt_rsa_init_tfm,
	.exit = cpt_rsa_exit_tfm,
	.reqsize = sizeof(struct cpt_asym_req_ctx),
	.base = {
		.cra_ctxsize = sizeof(struct cpt_asym_ctx),
		.cra_priority = 4001,
		.cra_name = "rsa",
		.cra_driver_name = "cpt-rsa",
		.cra_module = THIS_MODULE,
	},
},
{
	.encrypt = cpt_rsa_enc,
	.decrypt = cpt_rsa_dec,
	.set_pub_key = cpt_rsa_setpubkey,
	.set_priv_key = cpt_rsa_setprivkey,
	.max_size = cpt_rsa_pkcs1_max_size,
	.init = cpt_rsa_pkcs1_init_tfm,
	.exit = cpt_rsa_exit_tfm,
	.reqsize = sizeof(struct cpt_asym_req_ctx),
	.base = {
		.cra_ctxsize = sizeof(struct cpt_asym_ctx),
		.cra_priority = 4001,
		.cra_name = "pkcs1pad(rsa)",
		.cra_driver_name = "cpt-pkcs1-rsa",
		.cra_module = THIS_MODULE,
	},
},
};

int otx2_cpt_register_asym_algs(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(cpt_rsa_algs); i++) {
		cpt_rsa_algs[i].base.cra_flags = 0;
		ret = crypto_register_akcipher(&cpt_rsa_algs[i]);
		if (ret)
			return ret;
	}

	return 0;
}

void otx2_cpt_unregister_asym_algs(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cpt_rsa_algs); i++)
		crypto_unregister_akcipher(&cpt_rsa_algs[i]);
}
