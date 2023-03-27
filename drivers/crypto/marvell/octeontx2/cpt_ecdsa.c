// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Marvell. */

#include <crypto/drbg.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include "otx2_cpt_common.h"
#include "cpt_asym.h"

static void cpt_ecdsa_callback(int status, void *arg1, void *arg2)
{
	struct otx2_cpt_inst_info *inst_info = arg2;
	struct crypto_async_request *areq = arg1;
	struct ecdsa_signature_ctx sig_ctx;
	struct otx2_cpt_req_info *req_info;
	struct akcipher_request *ak_req;
	struct otx2_cptvf_request *req;
	struct cpt_asym_req_ctx *rctx;
	struct cpt_asym_ctx *ctx;
	struct pci_dev *pdev;
	const u64 *digits;
	u32 ndigits;

	if (inst_info) {
		req_info = inst_info->req;
		req = &req_info->req;
		ak_req = container_of(areq, struct akcipher_request, base);
		rctx = akcipher_request_ctx(ak_req);
		pdev = inst_info->pdev;
		ctx = rctx->ctx;
		if (req->opcode.s.minor == 1 && !status) {
			ndigits = ctx->ecdsa.curve->g.ndigits;
			sig_ctx.curve = ctx->ecdsa.curve;
			digits = (u64 *)req->dptr;
			ecc_swap_digits(digits, sig_ctx.r, ndigits);
			ecc_swap_digits(&digits[ndigits], sig_ctx.s, ndigits);
			status = ecdsa_asn1_encode_signature_sg(ak_req, &sig_ctx);
		}

		dma_unmap_single(&pdev->dev, req->dptr_dma, req->dlen,
				 DMA_BIDIRECTIONAL);
		kfree(req->dptr);
		otx2_cpt_info_destroy(pdev, inst_info);
	}
	if (areq)
		areq->complete(areq, status);
}

static struct crypto_rng *cpt_rfc6979_alloc_rng(struct ecc_ctx *ctx,
						size_t hash_sz, u8 *hash)
{
	u32 ndigits = ctx->curve->g.ndigits;
	u32 keylen = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	struct drbg_string entropy, pers = {0};
	struct drbg_test_data seed_data;
	u64 seed[2 * ECC_MAX_DIGITS];
	u8 hash_k[ECC_MAX_BYTES];
	struct crypto_rng *rng;
	const char *alg;
	int diff;
	int err;

	switch (hash_sz) {
	case SHA1_DIGEST_SIZE:
		alg = "drbg_nopr_hmac_sha1";
		break;
	case SHA256_DIGEST_SIZE:
		alg = "drbg_nopr_hmac_sha256";
		break;
	case SHA384_DIGEST_SIZE:
		alg = "drbg_nopr_hmac_sha384";
		break;
	default:
		alg = "drbg_nopr_hmac_sha512";
	}

	rng = crypto_alloc_rng(alg, CRYPTO_ALG_TYPE_RNG, 0);
	if (IS_ERR(rng))
		return rng;

	/* if the hash is shorter then we will add leading zeros to fit to ndigits */
	diff = keylen - hash_sz;
	if (diff >= 0) {
		if (diff)
			memset(hash_k, 0, diff);
		memcpy(&hash_k[diff], hash, hash_sz);
	} else
		memcpy(hash_k, hash, hash_sz);

	memcpy(seed, ctx->d, keylen);
	memcpy(seed + ndigits, hash_k, keylen);
	drbg_string_fill(&entropy, (u8 *)seed, keylen * 2);
	seed_data.testentropy = &entropy;
	err = crypto_drbg_reset_test(rng, &pers, &seed_data);
	if (err) {
		crypto_free_rng(rng);
		return ERR_PTR(err);
	}

	return rng;
}

static int cpt_ecdsa_k_gen(struct cpt_asym_ctx *ctx, ssize_t hash_sz, u8 *hash, u8 *k)
{
	u32 ndigits = ctx->ecdsa.curve->g.ndigits;
	struct device *dev = ctx->dev;
	struct crypto_rng *rng;
	u8 K[ECC_MAX_BYTES];
	int ret;

	rng = cpt_rfc6979_alloc_rng(&ctx->ecdsa, hash_sz, hash);
	if (IS_ERR(rng)) {
		dev_err(dev, "failed to get default rng, ret = %d!\n", ret);
		return PTR_ERR(rng);
	}
	do {
		ret = crypto_rng_get_bytes(rng, k, ndigits << ECC_DIGITS_TO_BYTES_SHIFT);
		if (ret)
			return ret;

		ecc_swap_digits((u64 *)k, (u64 *)K, ndigits);
	} while (vli_cmp((u64 *)K, ctx->ecdsa.curve->n, ndigits) >= 0);

	ecc_swap_digits((u64 *)K, (u64 *)k, ndigits);
	crypto_free_rng(rng);

	return 0;
}

static int cpt_ecdsa_sign(struct akcipher_request *req)
{
	struct cpt_asym_req_ctx *rctx = akcipher_request_ctx(req);
	struct cpt_asym_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct otx2_cpt_req_info *req_info = &rctx->cpt_req;
	const struct ecc_curve *curve = ctx->ecdsa.curve;
	size_t key_len = curve->g.ndigits * sizeof(u64);
	struct device *dev = ctx->dev;
	struct otx2_cptvf_dev *cptvf;
	u8 hash[ECC_MAX_BYTES];
	u16 m_align, p_align;
	u8 k[ECC_MAX_BYTES];
	unsigned char *dptr;
	dma_addr_t dptr_dma;
	u64 fpm_table_iova;
	u32 dlen, ec_id;
	ssize_t msg_len;
	gfp_t gfp;
	int ret;

	gfp = (req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP) ? GFP_KERNEL :
							     GFP_ATOMIC;

	if (unlikely(!ctx->ecdsa.key_set))
		return -EINVAL;

	if (unlikely(req->dst_len < ctx->max_dst_len)) {
		dev_err(dev, "ECDSA: req->dst_len is less than required length: %d",
			ctx->max_dst_len);
		return -EOVERFLOW;
	}

	memset(req_info, 0, sizeof(*req_info));
	rctx->ctx = ctx;

	cptvf = pci_get_drvdata(ctx->pdev);
	ec_id = cpt_uc_ecc_id_get(ctx->ecdsa.curve_id);
	fpm_table_iova = cptvf->fpm_tbl.fpm_iova[ec_id];
	/* Truncate input length to curve prime length */
	if (req->src_len > key_len)
		msg_len = key_len;
	else
		msg_len = req->src_len;

	m_align = ALIGN(msg_len, 8);
	p_align = ALIGN(key_len, 8);

	dlen = sizeof(fpm_table_iova) + m_align + (6 * p_align);
	dptr = kzalloc(dlen, gfp);
	if (dptr == NULL)
		return -ENOMEM;

	dptr_dma = dma_map_single(dev, dptr, dlen, DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(dev, dptr_dma))) {
		dev_err(dev, "DMA mapping failed for ECDSA dptr\n");
		ret = -EIO;
		goto dptr_free;
	}
	req_info->req.dptr_dma = dptr_dma;
	req_info->req.dptr = dptr;
	req_info->req.dlen = dlen;
	req_info->ctrl.s.dma_mode = OTX2_CPT_DMA_MODE_DIRECT;
	req_info->ctrl.s.se_req = 0;
	req_info->req.opcode.s.major = OTX2_CPT_MAJOR_OP_ECDSA | 1 << 6;
	req_info->req.opcode.s.minor = 1;
	req_info->is_trunc_hmac = 0;
	req_info->callback = cpt_ecdsa_callback;

	req_info->req.param1 = ec_id | msg_len << 8;
	req_info->req.param2 = key_len << 8 | key_len;

	req_info->req.cptr = ctx->er_ctx.hw_ctx;
	req_info->req.cptr_dma = ctx->er_ctx.cptr_dma;

	sg_copy_to_buffer(req->src, sg_nents_for_len(req->src, req->src_len),
			  hash, req->src_len);

	ret = cpt_ecdsa_k_gen(ctx, req->src_len, hash, k);
	if (ret)
		goto dma_unmap;

	*(uint64_t *)dptr = fpm_table_iova;
	dptr += sizeof(fpm_table_iova);

	memcpy(dptr, k, key_len);
	dptr += p_align;

	fill_curve_param(dptr, curve->p, key_len, curve->g.ndigits);
	dptr += p_align;

	fill_curve_param(dptr, curve->n, key_len, curve->g.ndigits);
	dptr += p_align;

	memcpy(dptr, ctx->ecdsa.d, key_len);
	dptr += p_align;

	memcpy(dptr, hash, msg_len);
	dptr += m_align;

	fill_curve_param(dptr, curve->a, key_len, curve->g.ndigits);
	dptr += p_align;

	fill_curve_param(dptr, curve->b, key_len, curve->g.ndigits);

	return cpt_asym_enqueue(&req->base, req_info);

dma_unmap:
	dma_unmap_single(dev, dptr_dma, dlen, DMA_BIDIRECTIONAL);
dptr_free:
	kfree(dptr);

	return ret;
}

static int cpt_ecdsa_verify(struct akcipher_request *req)
{
	struct cpt_asym_req_ctx *rctx = akcipher_request_ctx(req);
	struct cpt_asym_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct otx2_cpt_req_info *req_info = &rctx->cpt_req;
	const struct ecc_curve *curve = ctx->ecdsa.curve;
	size_t key_len = curve->g.ndigits * sizeof(u64);
	struct ecdsa_signature_ctx sig_ctx = {
		.curve = curve,
	};
	struct device *dev = ctx->dev;
	struct otx2_cptvf_dev *cptvf;
	u16 m_align, p_align;
	unsigned char *dptr;
	dma_addr_t dptr_dma;
	u64 fpm_table_iova;
	u32 dlen, ec_id;
	ssize_t msg_len;
	u8 *buffer;
	gfp_t gfp;
	int ret;

	gfp = (req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP) ? GFP_KERNEL :
							     GFP_ATOMIC;

	if (unlikely(!ctx->ecdsa.key_set))
		return -EINVAL;

	memset(rctx, 0, sizeof(*rctx));
	rctx->ctx = ctx;

	cptvf = pci_get_drvdata(ctx->pdev);
	ec_id = cpt_uc_ecc_id_get(ctx->ecdsa.curve_id);
	fpm_table_iova = cptvf->fpm_tbl.fpm_iova[ec_id];
	/* Truncate input length to curve prime length */
	if (req->dst_len > key_len)
		msg_len = key_len;
	else
		msg_len = req->dst_len;

	m_align = ALIGN(msg_len, 8);
	p_align = ALIGN(key_len, 8);

	dlen = sizeof(fpm_table_iova) + m_align + (8 * p_align);
	dptr = kzalloc(dlen, gfp);
	if (dptr == NULL)
		return -ENOMEM;

	dptr_dma = dma_map_single(dev, dptr, dlen, DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(dev, dptr_dma))) {
		dev_err(dev, "DMA mapping failed for ECDSA dptr\n");
		ret = -EIO;
		goto dptr_free;
	}
	req_info->req.dptr_dma = dptr_dma;
	req_info->req.dptr = dptr;
	req_info->req.dlen = dlen;
	req_info->ctrl.s.dma_mode = OTX2_CPT_DMA_MODE_DIRECT;
	req_info->ctrl.s.se_req = 0;
	req_info->req.opcode.s.major = OTX2_CPT_MAJOR_OP_ECDSA;
	req_info->req.opcode.s.minor = 2;
	req_info->is_trunc_hmac = 0;
	req_info->callback = cpt_ecdsa_callback;

	req_info->req.param1 = ec_id | msg_len << 8;
	req_info->req.param2 = 0;

	req_info->req.cptr = ctx->er_ctx.hw_ctx;
	req_info->req.cptr_dma = ctx->er_ctx.cptr_dma;

	buffer = kzalloc(req->src_len + req->dst_len, gfp);
	if (buffer == NULL) {
		ret = -ENOMEM;
		goto dma_unmap;
	}
	sg_pcopy_to_buffer(req->src,
		sg_nents_for_len(req->src, req->src_len + req->dst_len),
		buffer, req->src_len + req->dst_len, 0);

	ret = ecdsa_parse_signature(&sig_ctx, buffer, req->src_len);
	if (ret < 0)
		goto buffer_free;

	*(uint64_t *)dptr = fpm_table_iova;
	dptr += sizeof(fpm_table_iova);

	memcpy(dptr, sig_ctx.r, key_len);
	dptr += p_align;

	memcpy(dptr, sig_ctx.s, key_len);
	dptr += p_align;

	memcpy(dptr, buffer + req->src_len, msg_len);
	dptr += m_align;

	fill_curve_param(dptr, curve->n, key_len, curve->g.ndigits);
	dptr += p_align;

	fill_curve_param(dptr, curve->p, key_len, curve->g.ndigits);
	dptr += p_align;

	memcpy(dptr, ctx->ecdsa.pub_key.x, key_len);
	dptr += p_align;

	memcpy(dptr, ctx->ecdsa.pub_key.y, key_len);
	dptr += p_align;

	fill_curve_param(dptr, curve->a, key_len, curve->g.ndigits);
	dptr += p_align;

	fill_curve_param(dptr, curve->b, key_len, curve->g.ndigits);

	kfree(buffer);
	return cpt_asym_enqueue(&req->base, req_info);

buffer_free:
	kfree(buffer);
dma_unmap:
	dma_unmap_single(dev, dptr_dma, dlen, DMA_BIDIRECTIONAL);
dptr_free:
	kfree(dptr);

	return ret;
}

static int ecdsa_ecc_ctx_init(struct cpt_asym_ctx *ctx, unsigned int curve_id)
{
	struct ecc_ctx *dctx = &ctx->ecdsa;

	dctx->curve_id = curve_id;
	dctx->curve = ecc_get_curve(curve_id);
	if (!dctx->curve)
		return -EINVAL;

	return 0;
}

static void ecdsa_ctx_deinit(struct ecc_ctx *ctx)
{
	ctx->key_set = false;
	if (ctx->is_private)
		memzero_explicit(ctx->d, sizeof(ctx->d));
}

static int ecdsa_ecc_ctx_reset(struct cpt_asym_ctx *ctx)
{
	struct ecc_ctx *dctx = &ctx->ecdsa;
	unsigned int curve_id = dctx->curve_id;
	int ret;

	ecdsa_ctx_deinit(dctx);
	ret = ecdsa_ecc_ctx_init(ctx, curve_id);
	if (ret == 0)
		dctx->pub_key = ECC_POINT_INIT(dctx->x, dctx->y,
					      dctx->curve->g.ndigits);
	return ret;
}

/*
 * Set the public key given the raw uncompressed key data from an X509
 * certificate. The key data contain the concatenated X and Y coordinates of
 * the public key.
 */
static int cpt_ecdsa_set_pub_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ecc_ctx *dctx = &ctx->ecdsa;
	const unsigned char *d = key;
	const u64 *digits = (const u64 *)&d[1];
	unsigned int ndigits;
	int ret;

	ret = ecdsa_ecc_ctx_reset(ctx);
	if (ret < 0)
		return ret;

	if (keylen < 1 || (((keylen - 1) >> 1) % sizeof(u64)) != 0)
		return -EINVAL;
	/* we only accept uncompressed format indicated by '4' */
	if (d[0] != 4)
		return -EINVAL;

	keylen--;
	ndigits = (keylen >> 1) / sizeof(u64);
	if (ndigits != dctx->curve->g.ndigits)
		return -EINVAL;

	memcpy(dctx->pub_key.x, digits, ndigits * 8);
	memcpy(dctx->pub_key.y, &digits[ndigits], ndigits * 8);

	dctx->key_set = ret == 0;

	return ret;
}

static int cpt_ecdsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
				  unsigned int keylen)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ecc_ctx *dctx = &ctx->ecdsa;
	u32 ndigits = dctx->curve->g.ndigits;
	u8 priv[ECC_MAX_BYTES];
	ssize_t dlen;
	int ret;

	ret = ecdsa_ecc_ctx_reset(ctx);
	if (ret < 0)
		return ret;

	ret = ecdsa_parse_privkey(dctx, key, keylen);
	if (ret)
		return ret;

	dlen = ndigits * sizeof(u64);
	ecc_swap_digits(dctx->d, (u64 *)priv, ndigits);
	ret = ecc_is_key_valid(dctx->curve_id, ndigits, (u64 *)priv, dlen);
	if (ret)
		return ret;

	dctx->key_set = ret == 0;
	dctx->is_private = true;

	return ret;
}

static void cpt_ecdsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);

	ecdsa_ctx_deinit(&ctx->ecdsa);
	cn10k_cpt_hw_ctx_clear(ctx->pdev, &ctx->er_ctx);
}

static u32 cpt_ecdsa_max_size(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ecc_ctx *dctx = &ctx->ecdsa;

	if (!dctx->key_set)
		return 0;

	if (dctx->is_private) {
		/* see crypto/ecdsasignature.asn1
		 * for a max 384 bit curve we would only need 1 byte length
		 * ASN1 encoding for the top level sequence and r,s integers
		 * 1 byte sequence tag + 1 byte sequence length (max 102 for 384
		 * bit curve) + 2 (for r and s) * (1 byte integer tag + 1 byte
		 * integer length (max 49 for 384 bit curve) + 1 zero byte (if r
		 * or s has leftmost bit set) + sizeof(r or s)
		 */
		ctx->max_dst_len = 2 + 2 * (3 + (dctx->curve->g.ndigits <<
						 ECC_DIGITS_TO_BYTES_SHIFT));

		return ctx->max_dst_len;
	}
	return dctx->pub_key.ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
}

static int cpt_ecdsa_nist_p384_init_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct pci_dev *pdev;
	int ret, cpu_num;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	ctx->dev = &pdev->dev;
	ctx->pdev = pdev;

	ret = ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P384);
	if (ret)
		return ret;

	return cn10k_cpt_hw_ctx_init(ctx->pdev, &ctx->er_ctx);
}

static int cpt_ecdsa_nist_p256_init_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct pci_dev *pdev;
	int ret, cpu_num;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	ctx->dev = &pdev->dev;
	ctx->pdev = pdev;

	ret = ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P256);
	if (ret)
		return ret;

	return cn10k_cpt_hw_ctx_init(ctx->pdev, &ctx->er_ctx);
}

static int cpt_ecdsa_nist_p192_init_tfm(struct crypto_akcipher *tfm)
{
	struct cpt_asym_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct pci_dev *pdev;
	int ret, cpu_num;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	ctx->dev = &pdev->dev;
	ctx->pdev = pdev;

	ret = ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P192);
	if (ret)
		return ret;

	return cn10k_cpt_hw_ctx_init(ctx->pdev, &ctx->er_ctx);
}

static struct akcipher_alg cpt_ecdsa_nist_p384 = {
	.sign = cpt_ecdsa_sign,
	.verify = cpt_ecdsa_verify,
	.set_priv_key = cpt_ecdsa_set_priv_key,
	.set_pub_key = cpt_ecdsa_set_pub_key,
	.max_size = cpt_ecdsa_max_size,
	.init = cpt_ecdsa_nist_p384_init_tfm,
	.exit = cpt_ecdsa_exit_tfm,
	.reqsize = sizeof(struct cpt_asym_req_ctx),
	.base = {
		.cra_name = "ecdsa-nist-p384",
		.cra_driver_name = "cpt-ecdsa-nist-p384",
		.cra_priority = 4001,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct cpt_asym_ctx),
	},
};

static struct akcipher_alg cpt_ecdsa_nist_p256 = {
	.sign = cpt_ecdsa_sign,
	.verify = cpt_ecdsa_verify,
	.set_priv_key = cpt_ecdsa_set_priv_key,
	.set_pub_key = cpt_ecdsa_set_pub_key,
	.max_size = cpt_ecdsa_max_size,
	.init = cpt_ecdsa_nist_p256_init_tfm,
	.exit = cpt_ecdsa_exit_tfm,
	.reqsize = sizeof(struct cpt_asym_req_ctx),
	.base = {
		.cra_name = "ecdsa-nist-p256",
		.cra_driver_name = "cpt-ecdsa-nist-p256",
		.cra_priority = 4001,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct cpt_asym_ctx),
	},
};

static struct akcipher_alg cpt_ecdsa_nist_p192 = {
	.sign = cpt_ecdsa_sign,
	.verify = cpt_ecdsa_verify,
	.set_priv_key = cpt_ecdsa_set_priv_key,
	.set_pub_key = cpt_ecdsa_set_pub_key,
	.max_size = cpt_ecdsa_max_size,
	.init = cpt_ecdsa_nist_p192_init_tfm,
	.exit = cpt_ecdsa_exit_tfm,
	.reqsize = sizeof(struct cpt_asym_req_ctx),
	.base = {
		.cra_name = "ecdsa-nist-p192",
		.cra_driver_name = "cpt-ecdsa-nist-p192",
		.cra_priority = 4001,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct cpt_asym_ctx),
	},
};
static bool ecdsa_nist_p192_registered;

int cpt_register_ecdsa(void)
{
	int ret;

	/* NIST p192 may not be available in FIPS mode */
	ret = crypto_register_akcipher(&cpt_ecdsa_nist_p192);
	ecdsa_nist_p192_registered = ret == 0;

	ret = crypto_register_akcipher(&cpt_ecdsa_nist_p256);
	if (ret)
		goto nist_p192_free;

	ret = crypto_register_akcipher(&cpt_ecdsa_nist_p384);
	if (ret)
		goto nist_p256_free;

	return 0;

nist_p256_free:
	crypto_unregister_akcipher(&cpt_ecdsa_nist_p256);
nist_p192_free:
	if (ecdsa_nist_p192_registered)
		crypto_unregister_akcipher(&cpt_ecdsa_nist_p192);
	return ret;
}

void cpt_unregister_ecdsa(void)
{
	if (ecdsa_nist_p192_registered)
		crypto_unregister_akcipher(&cpt_ecdsa_nist_p192);
	crypto_unregister_akcipher(&cpt_ecdsa_nist_p256);
	crypto_unregister_akcipher(&cpt_ecdsa_nist_p384);
}
