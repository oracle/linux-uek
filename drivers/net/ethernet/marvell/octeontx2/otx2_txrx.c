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

static inline unsigned int frag_num(unsigned int i)
{
#ifdef __BIG_ENDIAN
	return (i & ~3) + 3 - (i & 3);
#else
	return i;
#endif
}

static void otx2_skb_add_frag(struct otx2_nic *pfvf,
			      struct sk_buff *skb, u64 iova, int len)
{
	struct page *page;
	void *va;

	dma_unmap_page_attrs(pfvf->dev, iova, RCV_FRAG_LEN,
			     DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);

	va = phys_to_virt(otx2_iova_to_phys(pfvf->iommu_domain, iova));
	page = virt_to_page(va);
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			va - page_address(page), len, RCV_FRAG_LEN);
}

static inline struct sk_buff *
otx2_get_rcv_skb(struct otx2_nic *pfvf, u64 iova, int len, int apad)
{
	struct sk_buff *skb;
	void *va;

	va = phys_to_virt(otx2_iova_to_phys(pfvf->iommu_domain, iova));
	skb = build_skb(va, RCV_FRAG_LEN);
	if (!skb) {
		put_page(virt_to_page(va));
		return NULL;
	}

	skb_reserve(skb, apad);
	skb_put(skb, len);

	dma_unmap_page_attrs(pfvf->dev, iova - apad, RCV_FRAG_LEN,
			     DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
	prefetch(skb->data);
	return skb;
}

static void otx2_rcv_pkt_handler(struct otx2_nic *pfvf,
				 struct otx2_cq_queue *cq, void *cqe,
				 int *pool_ptrs)
{
	struct nix_cqe_hdr_s *cqe_hdr = (struct nix_cqe_hdr_s *)cqe;
	struct otx2_qset *qset = &pfvf->qset;
	struct nix_rx_parse_s *parse;
	struct sk_buff *skb = NULL;
	struct nix_rx_sg_s *sg;
	void *start, *end;
	int seg, len;
	u16 *sg_lens;
	u64 *iova;

	/* CQE_HDR_S for a Rx pkt is always followed by RX_PARSE_S */
	parse = (struct nix_rx_parse_s *)(cqe + sizeof(*cqe_hdr));
	/* Check for errors */
	if (parse->errlev || parse->errcode) {
		dev_info(pfvf->dev,
			 "RQ%d: Error pkt received errlev %x errcode %x\n",
			 cq->cint_idx, parse->errlev, parse->errcode);
		return;
	}

	start = cqe + sizeof(*cqe_hdr) + sizeof(*parse);
	end = start + ((parse->desc_sizem1 + 1) * 16);

	/* Run through the each NIX_RX_SG_S subdc and frame the skb */
	while ((start + sizeof(*sg)) < end) {
		sg = (struct nix_rx_sg_s *)start;
		/* For a 128byte size CQE, NIX_RX_IMM_S is never expected */
		if (sg->subdc != NIX_SUBDC_SG) {
			dev_err(pfvf->dev, "RQ%d: Unexpected SUBDC %d\n",
				cq->cq_idx, sg->subdc);
			break;
		}

		if (!sg->segs) {
			dev_err(pfvf->dev, "RQ%d: Zero segments in NIX_RX_SG_S\n",
				cq->cq_idx);
			break;
		}

		sg_lens = (void *)sg;
		iova = (void *)sg + sizeof(*sg);

		for (seg = 0; seg < sg->segs; seg++) {
			len = sg_lens[frag_num(seg)];
			/* Starting IOVA's 2:0 bits give alignment
			 * bytes after which packet data starts.
			 */
			if (!skb)
				skb = otx2_get_rcv_skb(pfvf, *iova,
						       len, *iova & 0x07);
			else
				otx2_skb_add_frag(pfvf, skb, *iova, len);
			iova++;
			(*pool_ptrs)++;
		}

		/* When SEGS = 1, only one IOVA is followed by NIX_RX_SG_S.
		 * When SEGS >= 2, three IOVAs will follow NIX_RX_SG_S,
		 * irrespective of whether 2 SEGS are valid or all 3.
		 */
		if (sg->segs == 1)
			start += sizeof(*sg) + sizeof(u64);
		else
			start += sizeof(*sg) + (3 * sizeof(u64));
	}

	if (!skb)
		return;

	skb_record_rx_queue(skb, cq->cq_idx);
	skb->protocol = eth_type_trans(skb, pfvf->netdev);

	if (pfvf->netdev->features & NETIF_F_GRO)
		napi_gro_receive(&qset->napi[cq->cint_idx].napi, skb);
	else
		netif_receive_skb(skb);
}

#define CQE_ADDR(CQ, idx) ((CQ)->cqe_base + ((CQ)->cqe_size * (idx)))

static int otx2_napi_handler(struct otx2_cq_queue *cq, struct otx2_nic *pfvf,
			     int budget)
{
	struct otx2_pool *rbpool = cq->rbpool;
	int processed_cqe = 0, workdone = 0;
	int cq_head, cq_tail, pool_ptrs = 0;
	struct nix_cqe_hdr_s *cqe_hdr;
	u64 cq_status;
	s64 bufptr;

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
			otx2_rcv_pkt_handler(pfvf, cq, cqe_hdr, &pool_ptrs);
			workdone++;
			break;
		}
		processed_cqe++;
	}

	otx2_write64(pfvf, NIX_LF_CQ_OP_DOOR,
		     ((u64)cq->cq_idx << 32) | processed_cqe);

	if (!pool_ptrs)
		return 0;

	/* Refill pool with new buffers */
	while (pool_ptrs) {
		bufptr = otx2_alloc_rbuf(pfvf, rbpool);
		if (bufptr <= 0)
			break;
		otx2_aura_freeptr(pfvf, cq->cq_idx, bufptr);
		pool_ptrs--;
	}
	otx2_get_page(rbpool);

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
