// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_common.h"
#include "cpt_reqmgr.h"

void dump_sg_list(struct pci_dev *pdev, struct cpt_request_info *req)
{
	int i;

	dev_info(&pdev->dev, "Gather list size %d\n", req->incnt);
	for (i = 0; i < req->incnt; i++) {
		dev_info(&pdev->dev,
			 "Buffer %d size %d, vptr 0x%p, dmaptr 0x%p\n", i,
			 req->in[i].size, req->in[i].vptr,
			 (void *) req->in[i].dma_addr);
		dev_info(&pdev->dev, "Buffer hexdump (%d bytes)\n",
			 req->in[i].size);
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
			       req->in[i].vptr, req->in[i].size, false);
	}

	dev_info(&pdev->dev, "Scatter list size %d\n", req->outcnt);
	for (i = 0; i < req->outcnt; i++) {
		dev_info(&pdev->dev,
			 "Buffer %d size %d, vptr 0x%p, dmaptr 0x%p\n", i,
			 req->out[i].size, req->out[i].vptr,
			 (void *) req->out[i].dma_addr);
		dev_info(&pdev->dev, "Buffer hexdump (%d bytes)\n",
			 req->out[i].size);
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
			       req->out[i].vptr, req->out[i].size, false);
	}
}
