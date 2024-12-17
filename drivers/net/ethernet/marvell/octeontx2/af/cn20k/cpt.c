// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "struct.h"
#include "../rvu.h"

int rvu_mbox_handler_cpt_rx_inline_qalloc(struct rvu *rvu,
					  struct msg_req *req,
					  struct cpt_rx_inline_qalloc_rsp *rsp)
{
	struct rvu_cpt *cpt = &rvu->cpt;

	int index = find_first_zero_bit(cpt->cpt_rx_queue_bitmap,
					CPT_AF_MAX_RXC_QUEUES);
	if (index >= CPT_AF_MAX_RXC_QUEUES)
		return CPT_AF_ERR_RXC_QUEUE_INVALID;

	/* Flag the queue ID as allocated */
	set_bit(index, cpt->cpt_rx_queue_bitmap);

	cpt->cptpfvf_map[index] = req->hdr.pcifunc;
	rsp->rx_queue_id = index;

	return 0;
}

static void cpt_rx_qid_init(struct rvu *rvu)
{
	struct rvu_cpt *cpt = &rvu->cpt;

	bitmap_zero(cpt->cpt_rx_queue_bitmap, CPT_AF_MAX_RXC_QUEUES);

	/* Queue 0 is reserved for Global LF, that is allocated via CPT
	 * PF, and can be used by RVU netdev.
	 */
	set_bit(0, cpt->cpt_rx_queue_bitmap);
}

void rvu_cn20k_cpt_init(struct rvu *rvu)
{
	cpt_rx_qid_init(rvu);
}
