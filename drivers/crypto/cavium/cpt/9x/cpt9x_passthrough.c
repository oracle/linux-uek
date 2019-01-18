// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include "cpt9x_mbox_common.h"

#include "cpt_algs.h"
#include "cpt_algs_internal.h"
#include "cpt9x_passthrough.h"
#include "cpt9x_reqmgr.h"

static void passthrough_callback(struct crypto_async_request *req, int err)
{
	struct ablkcipher_request *areq;
	void *ptr;

	pr_info("Passthrough test callback, req = %p, err = %d\n", req, err);

	areq = container_of(req, struct ablkcipher_request, base);
	ptr = sg_virt(areq->src);
	kfree(ptr);
	kfree(areq->src);

	ptr = sg_virt(areq->dst);
	if (!err)
		pr_info("Passthrough result data %s\n", (char *) ptr);
	kfree(ptr);
	kfree(areq->dst);

	kfree(areq);

	if (!err)
		pr_info("Passthrough test succeed\n");
	else
		pr_info("Passthrough test failed\n");
}

static int cvm_passthrough(struct pci_dev *pdev, struct ablkcipher_request *req)
{
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	int cpu;

	memset(rctx, 0, sizeof(struct cvm_req_ctx));

	req_info->ctrl.s.dma_mode = DMA_GATHER_SCATTER;
	req_info->ctrl.s.se_req = SE_CORE_REQ;

	req_info->req.opcode.s.major = MAJOR_OP_MISC |
					DMA_MODE_FLAG(DMA_GATHER_SCATTER);
	req_info->req.opcode.s.minor = 3;
	req_info->req.param1 = req->nbytes; /* Data length */
	req_info->req.param2 = 0x0;

	req_info->callback = (void *) cvm_callback;
	req_info->areq = &req->base;
	req_info->req_type = PASSTHROUGH_REQ;

	req_info->in[0].vptr = sg_virt(req->src);
	req_info->in[0].size = req->src->length;
	req_info->incnt = 1;

	req_info->out[0].vptr = sg_virt(req->dst);
	req_info->out[0].size = req->dst->length;
	req_info->outcnt = 1;

	cpu = get_cpu();
	put_cpu();

	return cpt9x_do_request(pdev, req_info, cpu);
}

int run_passthrough_test(struct pci_dev *pdev, const char *buf, int size)
{
	struct ablkcipher_request *areq;
	struct scatterlist *src, *dst;
	void *ptr;
	int ret = 0;

	/* Allocate buffer for a request */
	areq = kzalloc(sizeof(*areq) + sizeof(struct cvm_req_ctx), GFP_KERNEL);
	if (!areq)
		return -ENOMEM;

	/* Allocate src buffer */
	ptr = kzalloc(size, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	src = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (!src)
		return -ENOMEM;
	memcpy(ptr, buf, size);
	sg_init_one(src, ptr, size);

	/* Allocate dst buffer */
	ptr = kzalloc(size, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	dst = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (!dst)
		return -ENOMEM;
	sg_init_one(dst, ptr, size);

	ablkcipher_request_set_callback(areq, 0, passthrough_callback, NULL);
	ablkcipher_request_set_crypt(areq, src, dst, size, NULL);

	dev_info(&pdev->dev,
		 "Run passthrough test size %d, data - %s\n", size, buf);

	ret = cvm_passthrough(pdev, areq);
	if (ret)
		goto error;
error:
	return ret;
}
