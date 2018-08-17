// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/etherdevice.h>
#include <net/ip.h>

#include "otx2_reg.h"
#include "otx2_common.h"
#include "otx2_struct.h"
#include "otx2_txrx.h"

static inline u64 otx2_nix_cq_op_status(struct otx2_nic *pfvf, int cq_idx)
{
	u64 incr = (u64)cq_idx << 32;
	atomic64_t *ptr;
	u64 status;

	ptr = (__force atomic64_t *)(pfvf->reg_base + NIX_LF_CQ_OP_STATUS);

	status = atomic64_fetch_add_relaxed(incr, ptr);

	/* Barrier to prevent speculative reads of CQEs and their
	 * processing before above load of CQ_STATUS returns.
	 */
	dma_rmb();

	return status;
}

#define CQE_ADDR(CQ, idx) ((CQ)->cqe_base + ((CQ)->cqe_size * (idx)))

static int otx2_napi_handler(struct otx2_cq_queue *cq, struct otx2_nic *pfvf,
			     int budget)
{
	int processed_cqe = 0, cq_head, cq_tail;
	struct nix_cqe_hdr_s *cqe_hdr;
	int workdone = 0;
	u64 cq_status;

	cq_status = otx2_nix_cq_op_status(pfvf, cq->cq_idx);
	cq_head = (cq_status >> 20) & 0xFFFFF;
	cq_tail = cq_status & 0xFFFFF;
	/* Since multiple CQs may be mapped to same CINT,
	 * check if there are valid CQEs in this CQ.
	 */
	if (cq_head == cq_tail)
		return 0;

	while (cq_head != cq_tail) {
		if (workdone >= budget)
			break;

		cqe_hdr = (struct nix_cqe_hdr_s *)CQE_ADDR(cq, cq_head);
		cq_head++;
		cq_head &= (cq->cqe_cnt - 1);
		prefetch(CQE_ADDR(cq, cq_head));

		switch (cqe_hdr->cqe_type) {
		case NIX_XQE_TYPE_RX:
			/* Receive packet handler*/
			workdone++;
			break;
		}
		processed_cqe++;
	}

	otx2_write64(pfvf, NIX_LF_CQ_OP_DOOR,
		     ((u64)cq->cq_idx << 32) | processed_cqe);

	return workdone;
}

int otx2_poll(struct napi_struct *napi, int budget)
{
	struct otx2_cq_poll *cq_poll;
	int workdone = 0, cq_idx, i;
	struct otx2_cq_queue *cq;
	struct otx2_qset *qset;
	struct otx2_nic *pfvf;

	cq_poll = container_of(napi, struct otx2_cq_poll, napi);
	pfvf = (struct otx2_nic *)cq_poll->dev;
	qset = &pfvf->qset;

	for (i = 0; i < MAX_CQS_PER_CNT; i++) {
		cq_idx = cq_poll->cq_ids[i];
		if (cq_idx == CINT_INVALID_CQ)
			continue;
		cq = &qset->cq[cq_idx];
		workdone = otx2_napi_handler(cq, pfvf, budget);
	}

	/* Clear the IRQ */
	otx2_write64(pfvf, NIX_LF_CINTX_INT(cq_poll->cint_idx), BIT_ULL(0));

	if (workdone < budget) {
		/* Exit polling */
		napi_complete(napi);

		/* Re-enable interrupts */
		otx2_write64(pfvf, NIX_LF_CINTX_ENA_W1S(cq_poll->cint_idx),
			     BIT_ULL(0));
	}
	return workdone;
}
