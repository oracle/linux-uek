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

/* Flush SQE written to LMT to SQB */
static inline u64 otx2_lmt_flush(uint64_t addr)
{
	return atomic64_fetch_xor_relaxed(0, (atomic64_t *)addr);
}

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

static dma_addr_t otx2_dma_map_skb_frag(struct otx2_nic *pfvf,
					struct sk_buff *skb, int seg, int *len)
{
	const struct skb_frag_struct *frag;
	struct page *page;
	int offset;

	/* First segment is always skb->data */
	if (!seg) {
		page = virt_to_page(skb->data);
		offset = offset_in_page(skb->data);
		*len = skb_headlen(skb);
	} else {
		frag = &skb_shinfo(skb)->frags[seg - 1];
		page = skb_frag_page(frag);
		offset = frag->page_offset;
		*len = skb_frag_size(frag);
	}
	return dma_map_page_attrs(pfvf->dev, page, offset, *len,
				  DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
}

static void otx2_dma_unmap_skb_frags(struct otx2_nic *pfvf, struct sg_list *sg)
{
	int seg;

	for (seg = 0; seg < sg->num_segs; seg++) {
		dma_unmap_page_attrs(pfvf->dev, sg->dma_addr[seg],
				     sg->size[seg], DMA_TO_DEVICE,
				     DMA_ATTR_SKIP_CPU_SYNC);
	}
}

static void otx2_snd_pkt_handler(struct otx2_nic *pfvf,
				 struct otx2_cq_queue *cq, void *cqe,
				 int budget, int *tx_pkts, int *tx_bytes)
{
	struct nix_cqe_hdr_s *cqe_hdr = (struct nix_cqe_hdr_s *)cqe;
	struct nix_send_comp_s *snd_comp;
	struct sk_buff *skb = NULL;
	struct otx2_snd_queue *sq;
	struct sg_list *sg;

	snd_comp = (struct nix_send_comp_s *)(cqe + sizeof(*cqe_hdr));
	if (snd_comp->status) {
		/* tx packet error handling*/
		dev_info(pfvf->dev, "TX%d: Error in send CQ entry\n",
			 cq->cint_idx);
	}

	/* Barrier, so that update to sq by other cpus is visible */
	smp_mb();
	sq = &pfvf->qset.sq[cq->cint_idx];
	sg = &sq->sg[snd_comp->sqe_id];

	skb = (struct sk_buff *)sg->skb;
	if (skb) {
		*tx_bytes += skb->len;
		(*tx_pkts)++;
		otx2_dma_unmap_skb_frags(pfvf, sg);
		napi_consume_skb(skb, budget);
		sg->skb = (u64)NULL;
	}
}

static inline void otx2_set_rxhash(struct otx2_nic *pfvf,
				   struct nix_cqe_hdr_s *cqe_hdr,
				   struct sk_buff *skb)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	struct otx2_rss_info *rss;
	u32 hash = 0;

	if (!(pfvf->netdev->features & NETIF_F_RXHASH))
		return;

	rss = &pfvf->hw.rss_info;
	if (rss->flowkey_cfg) {
		if (rss->flowkey_cfg &
		    ~(FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6))
			hash_type = PKT_HASH_TYPE_L4;
		else
			hash_type = PKT_HASH_TYPE_L3;
		hash = cqe_hdr->flow_tag;
	}
	skb_set_hash(skb, hash, hash_type);
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

	otx2_set_rxhash(pfvf, cqe_hdr, skb);

	skb_record_rx_queue(skb, cq->cq_idx);
	skb->protocol = eth_type_trans(skb, pfvf->netdev);
	if (pfvf->netdev->features & NETIF_F_RXCSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	napi_gro_receive(&qset->napi[cq->cint_idx].napi, skb);
}

#define CQE_ADDR(CQ, idx) ((CQ)->cqe_base + ((CQ)->cqe_size * (idx)))

int otx2_napi_handler(struct otx2_cq_queue *cq,
		      struct otx2_nic *pfvf, int budget)
{
	struct otx2_pool *rbpool = cq->rbpool;
	int processed_cqe = 0, workdone = 0;
	int cq_head, cq_tail, pool_ptrs = 0;
	struct nix_cqe_hdr_s *cqe_hdr;
	int tx_pkts = 0, tx_bytes = 0;
	struct netdev_queue *txq;
	u64 cq_status;
	s64 bufptr;

	cq_status = otx2_nix_cq_op_status(pfvf, cq->cq_idx);
	if (cq_status & BIT_ULL(63)) {
		dev_err(pfvf->dev, "CQ operation error");
		schedule_work(&pfvf->reset_task);
		return 0;
	}
	if (cq_status & BIT_ULL(46)) {
		dev_err(pfvf->dev, "CQ stopped due to error");
		schedule_work(&pfvf->reset_task);
		return 0;
	}

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
		case NIX_XQE_TYPE_SEND:
			otx2_snd_pkt_handler(pfvf, cq, cqe_hdr, budget,
					     &tx_pkts, &tx_bytes);
		}
		processed_cqe++;
	}

	otx2_write64(pfvf, NIX_LF_CQ_OP_DOOR,
		     ((u64)cq->cq_idx << 32) | processed_cqe);

	if (tx_pkts) {
		txq = netdev_get_tx_queue(pfvf->netdev, cq->cint_idx);
		netdev_tx_completed_queue(txq, tx_pkts, tx_bytes);
	}

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

		/* If interface is going down, don't re-enable IRQ */
		if (pfvf->intf_down)
			return workdone;

		/* Re-enable interrupts */
		otx2_write64(pfvf, NIX_LF_CINTX_ENA_W1S(cq_poll->cint_idx),
			     BIT_ULL(0));
	}
	return workdone;
}

#define MAX_SEGS_PER_SG	3
/* Add SQE scatter/gather subdescriptor structure */
static bool otx2_sqe_add_sg(struct otx2_nic *pfvf, struct otx2_snd_queue *sq,
			    struct sk_buff *skb, int num_segs, int *offset)
{
	struct nix_sqe_sg_s *sg = NULL;
	u64 dma_addr, *iova = NULL;
	u16 *sg_lens = NULL;
	int seg, len;

	sq->sg[sq->head].num_segs = 0;

	for (seg = 0; seg < num_segs; seg++) {
		if ((seg % MAX_SEGS_PER_SG) == 0) {
			sg = (struct nix_sqe_sg_s *)(sq->sqe_base + *offset);
			sg->ld_type = NIX_SEND_LDTYPE_LDD;
			sg->subdc = NIX_SUBDC_SG;
			sg->segs = 0;
			sg_lens = (void *)sg;
			iova = (void *)sg + sizeof(*sg);
			/* Next subdc always starts at a 16byte boundary.
			 * So if sg->segs is whether 2 or 3, offset += 16bytes.
			 */
			if ((num_segs - seg) >= (MAX_SEGS_PER_SG - 1))
				*offset += sizeof(*sg) + (2 * sizeof(u64));
			else
				*offset += sizeof(*sg) + sizeof(u64);
		}
		dma_addr = otx2_dma_map_skb_frag(pfvf, skb, seg, &len);
		if (dma_mapping_error(pfvf->dev, dma_addr))
			return false;

		sg_lens[frag_num(seg % MAX_SEGS_PER_SG)] = len;
		sg->segs++;
		*iova++ = dma_addr;

		/* Save DMA mapping info for later unmapping */
		sq->sg[sq->head].dma_addr[seg] = dma_addr;
		sq->sg[sq->head].size[seg] = len;
		sq->sg[sq->head].num_segs++;
	}

	sq->sg[sq->head].skb = (u64)skb;
	return true;
}

/* Add SQE extended header subdescriptor */
static void otx2_sqe_add_ext(struct otx2_nic *pfvf, struct otx2_snd_queue *sq,
			     struct sk_buff *skb, int *offset)
{
	struct nix_sqe_ext_s *ext;

	if (!skb_shinfo(skb)->gso_size)
		return;

	ext = (struct nix_sqe_ext_s *)(sq->sqe_base + *offset);
	ext->subdc = NIX_SUBDC_EXT;
	if (skb_shinfo(skb)->gso_size) {
		ext->lso = 1;
		/* Is this TSOv4 or TSOv6, other GSO offloads not supported */
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)
			ext->lso_format = pfvf->hw.lso_tsov4_idx;
		else
			ext->lso_format = pfvf->hw.lso_tsov6_idx;
		ext->lso_sb = skb_transport_offset(skb) + tcp_hdrlen(skb);
		ext->lso_mps = skb_shinfo(skb)->gso_size;
	}

	*offset += sizeof(*ext);
}

/* Add SQE header subdescriptor structure */
static void otx2_sqe_add_hdr(struct otx2_nic *pfvf, struct otx2_snd_queue *sq,
			     struct nix_sqe_hdr_s *sqe_hdr,
			     struct sk_buff *skb, u16 qidx)
{
	int proto = 0;

	sqe_hdr->total = skb->len;
	/* Don't free Tx buffers to Aura */
	sqe_hdr->df = 1;
	sqe_hdr->aura = sq->aura_id;
	/* Post a CQE Tx after pkt transmission */
	sqe_hdr->pnc = 1;
	sqe_hdr->sq = qidx;
	/* Set SQE identifier which will be used later for freeing SKB */
	sqe_hdr->sqe_id = sq->head;

	/* Offload TCP/UDP checksum to HW */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		sqe_hdr->ol3ptr = skb_network_offset(skb);
		sqe_hdr->ol4ptr = skb_transport_offset(skb);

		if (skb->protocol == htons(ETH_P_IP)) {
			proto = ip_hdr(skb)->protocol;
			/* In case of TSO, HW needs this to be explicitly set.
			 * So set this always, instead of adding a check.
			 */
			sqe_hdr->ol3type = NIX_SENDL3TYPE_IP4_CKSUM;
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			proto = ipv6_hdr(skb)->nexthdr;
		}

		if (proto == IPPROTO_TCP)
			sqe_hdr->ol4type = NIX_SENDL4TYPE_TCP_CKSUM;
		else if (proto == IPPROTO_UDP)
			sqe_hdr->ol4type = NIX_SENDL4TYPE_UDP_CKSUM;
	}
}

bool otx2_sq_append_skb(struct net_device *netdev, struct otx2_snd_queue *sq,
			struct sk_buff *skb, u16 qidx)
{
	struct netdev_queue *txq = netdev_get_tx_queue(netdev, qidx);
	struct otx2_nic *pfvf = netdev_priv(netdev);
	struct nix_sqe_hdr_s *sqe_hdr;
	int offset, num_segs;
	u64 status;

	/* Check if there is room for new SQE.
	 * 'Num of SQBs freed to SQ's pool - SQ's Aura count'
	 * will give free SQE count.
	 */
	if (!(sq->num_sqbs - *sq->aura_fc_addr))
		goto fail;

	/* Set SQE's SEND_HDR */
	memset(sq->sqe_base, 0, sq->sqe_size);
	sqe_hdr = (struct nix_sqe_hdr_s *)(sq->sqe_base);
	otx2_sqe_add_hdr(pfvf, sq, sqe_hdr, skb, qidx);
	offset = sizeof(*sqe_hdr);

	num_segs = skb_shinfo(skb)->nr_frags + 1;

	/* If SKB doesn't fit in a single SQE, linearize it.
	 * TODO: Consider adding JUMP descriptor instead.
	 */
	if (num_segs > OTX2_MAX_FRAGS_IN_SQE) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return true;
		}
		num_segs = skb_shinfo(skb)->nr_frags + 1;
	}

	/* Add extended header if needed */
	otx2_sqe_add_ext(pfvf, sq, skb, &offset);

	/* Add SG subdesc with data frags */
	if (!otx2_sqe_add_sg(pfvf, sq, skb, num_segs, &offset)) {
		otx2_dma_unmap_skb_frags(pfvf, &sq->sg[sq->head]);
		return false;
	}

	sqe_hdr->sizem1 = (offset / 16) - 1;

	netdev_tx_sent_queue(txq, skb->len);

	/* Packet data stores should finish before SQE is flushed to HW */
	dma_wmb();

	do {
		memcpy(sq->lmt_addr, sqe_hdr, offset);
		status = otx2_lmt_flush(sq->io_addr);
	} while (status == 0);

	sq->head++;
	sq->head &= (SQ_QLEN - 1);

	return true;
fail:
	netdev_warn(pfvf->netdev, "SQ%d full, SQB count %d Aura count %lld\n",
		    qidx, sq->num_sqbs, *sq->aura_fc_addr);
	return false;
}
EXPORT_SYMBOL(otx2_sq_append_skb);

int otx2_rxtx_enable(struct otx2_nic *pfvf, bool enable)
{
	struct msg_req *msg;

	if (pfvf->tx_chan_base < CGX_CHAN_BASE)
		return 0;

	if (enable)
		msg = otx2_mbox_alloc_msg_CGX_START_RXTX(&pfvf->mbox);
	else
		msg = otx2_mbox_alloc_msg_CGX_STOP_RXTX(&pfvf->mbox);

	if (!msg)
		return -ENOMEM;

	return otx2_sync_mbox_msg(&pfvf->mbox);
}
