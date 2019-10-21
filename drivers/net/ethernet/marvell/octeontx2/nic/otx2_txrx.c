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
#include <net/tso.h>

#include "otx2_reg.h"
#include "otx2_common.h"
#include "otx2_struct.h"
#include "otx2_txrx.h"
#include "otx2_ptp.h"

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

	ptr = (__force atomic64_t *)otx2_get_regaddr(pfvf, NIX_LF_CQ_OP_STATUS);

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
	sg->num_segs = 0;
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
	int sqe_id;

	snd_comp = (struct nix_send_comp_s *)(cqe + sizeof(*cqe_hdr));
	if (snd_comp->status) {
		/* tx packet error handling*/
		if (netif_msg_tx_err(pfvf)) {
			netdev_info(pfvf->netdev,
				    "TX%d: Error in send CQ status:%x\n",
				    cq->cint_idx, snd_comp->status);
		}
	}

	/* Barrier, so that update to sq by other cpus is visible */
	smp_mb();
	sq = &pfvf->qset.sq[cq->cint_idx];
	sqe_id = snd_comp->sqe_id;
	sg = &sq->sg[sqe_id];

	skb = (struct sk_buff *)sg->skb;
	if (!skb)
		return;

	if (skb_shinfo(skb)->tx_flags & SKBTX_IN_PROGRESS) {
		u64 timestamp = ((u64 *)sq->timestamps->base)[sqe_id];

		if (timestamp != 1) {
			u64 tsns;
			int err;

			err = otx2_ptp_tstamp2time(pfvf, timestamp, &tsns);
			if (!err) {
				struct skb_shared_hwtstamps ts;

				memset(&ts, 0, sizeof(ts));
				ts.hwtstamp = ns_to_ktime(tsns);
				skb_tstamp_tx(skb, &ts);
			}
		}
	}

	*tx_bytes += skb->len;
	(*tx_pkts)++;
	otx2_dma_unmap_skb_frags(pfvf, sg);
	napi_consume_skb(skb, budget);
	sg->skb = (u64)NULL;
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
		    ~(NIX_FLOW_KEY_TYPE_IPV4 | NIX_FLOW_KEY_TYPE_IPV6))
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

	va = phys_to_virt(otx2_iova_to_phys(pfvf->iommu_domain, iova));
	page = virt_to_page(va);
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			va - page_address(page), len, RCV_FRAG_LEN);

	dma_unmap_page_attrs(pfvf->dev, iova - OTX2_HEAD_ROOM, RCV_FRAG_LEN,
			     DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
}

static inline struct sk_buff *
otx2_get_rcv_skb(struct otx2_nic *pfvf, u64 iova, int len)
{
	struct sk_buff *skb;
	void *va;

	iova -= OTX2_HEAD_ROOM;
	va = phys_to_virt(otx2_iova_to_phys(pfvf->iommu_domain, iova));
	skb = build_skb(va, RCV_FRAG_LEN);
	if (!skb) {
		put_page(virt_to_page(va));
		return NULL;
	}

	skb_reserve(skb, OTX2_HEAD_ROOM);
	skb_put(skb, len);

	dma_unmap_page_attrs(pfvf->dev, iova, RCV_FRAG_LEN,
			     DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
	prefetch(skb->data);
	return skb;
}

static inline void otx2_set_rxtstamp(struct otx2_nic *pfvf, struct sk_buff *skb)
{
	u64 tsns;
	int err;

	if (!pfvf->hw_rx_tstamp)
		return;

	/* The first 8 bytes is the timestamp */
	err = otx2_ptp_tstamp2time(pfvf, be64_to_cpu(*(u64 *)skb->data), &tsns);
	if (err)
		goto done;

	skb_hwtstamps(skb)->hwtstamp = ns_to_ktime(tsns);

done:
	__skb_pull(skb, 8);
}

static inline bool otx2_check_rcv_errors(struct otx2_nic *pfvf,
					 struct otx2_cq_queue *cq, void *cqe)
{
	struct otx2_drv_stats *stats = &pfvf->hw.drv_stats;
	struct nix_rx_parse_s *parse;
	struct nix_rx_sg_s *sg;
	void *start, *end;
	u64 *iova;
	int seg;

	parse = (struct nix_rx_parse_s *)(cqe + sizeof(struct nix_cqe_hdr_s));
	if (netif_msg_rx_err(pfvf))
		netdev_err(pfvf->netdev,
			   "RQ%d: Error pkt with errlev:0x%x errcode:0x%x\n",
			   cq->cq_idx, parse->errlev, parse->errcode);

	if (parse->errlev == NPC_ERRLVL_RE) {
		switch (parse->errcode) {
		case ERRCODE_FCS:
		case ERRCODE_FCS_RCV:
			atomic_inc(&stats->rx_fcs_errs);
			break;
		case ERRCODE_UNDERSIZE:
			atomic_inc(&stats->rx_undersize_errs);
			break;
		case ERRCODE_OVERSIZE:
			atomic_inc(&stats->rx_oversize_errs);
			break;
		case ERRCODE_OL2_LEN_MISMATCH:
			atomic_inc(&stats->rx_len_errs);
			break;
		default:
			atomic_inc(&stats->rx_other_errs);
			break;
		}
	} else if (parse->errlev == NPC_ERRLVL_NIX) {
		switch (parse->errcode) {
		case ERRCODE_OL3_LEN:
		case ERRCODE_OL4_LEN:
		case ERRCODE_IL3_LEN:
		case ERRCODE_IL4_LEN:
			atomic_inc(&stats->rx_len_errs);
			break;
		case ERRCODE_OL4_CSUM:
		case ERRCODE_IL4_CSUM:
			atomic_inc(&stats->rx_csum_errs);
			break;
		default:
			atomic_inc(&stats->rx_other_errs);
			break;
		}
	} else {
		atomic_inc(&stats->rx_other_errs);
		/* For now ignore all the NPC parser errors and
		 * pass the packets to stack.
		 */
		return false;
	}

	start = cqe + sizeof(struct nix_cqe_hdr_s) + sizeof(*parse);
	end = start + ((parse->desc_sizem1 + 1) * 16);
	while ((start + sizeof(*sg)) < end) {
		sg = (struct nix_rx_sg_s *)start;
		iova = (void *)sg + sizeof(*sg);

		/* If RXALL is enabled pass on packets to stack */
		if (sg->segs && pfvf->netdev->features & NETIF_F_RXALL)
			return false;

		for (seg = 0; seg < sg->segs; seg++) {
			otx2_aura_freeptr(pfvf, cq->cq_idx, *iova & ~0x07ULL);
			iova++;
		}
		if (sg->segs == 1)
			start += sizeof(*sg) + sizeof(u64);
		else
			start += sizeof(*sg) + (3 * sizeof(u64));
	}
	return true;
}

static void otx2_rcv_pkt_handler(struct otx2_nic *pfvf,
				 struct otx2_cq_queue *cq, void *cqe)
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
	if (parse->errlev || parse->errcode) {
		if (otx2_check_rcv_errors(pfvf, cq, cqe))
			return;
	}

	start = cqe + sizeof(*cqe_hdr) + sizeof(*parse);
	end = start + ((parse->desc_sizem1 + 1) * 16);

	/* Run through the each NIX_RX_SG_S subdc and frame the skb */
	while ((start + sizeof(*sg)) < end) {
		sg = (struct nix_rx_sg_s *)start;
		sg_lens = (void *)sg;
		iova = (void *)sg + sizeof(*sg);

		for (seg = 0; seg < sg->segs; seg++) {
			len = sg_lens[frag_num(seg)];
			/* Starting IOVA's 2:0 bits give alignment
			 * bytes after which packet data starts.
			 */
			if (!skb) {
				skb = otx2_get_rcv_skb(pfvf, *iova, len);
				/* check if data starts at some nonzero offset
				 * from the start of the buffer.  For now the
				 * only possible offset is 8 bytes in the case
				 * the packet data are prepended by a timestamp.
				 */
				if (parse->laptr)
					otx2_set_rxtstamp(pfvf, skb);
			} else {
				otx2_skb_add_frag(pfvf, skb, *iova, len);
			}
			iova++;
			cq->pool_ptrs++;
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

	if (netif_msg_pktdata(pfvf) && !skb_is_nonlinear(skb)) {
		netdev_info(pfvf->netdev, "skb 0x%p, len=%d\n", skb, skb->len);
		print_hex_dump(KERN_DEBUG, "RX:", DUMP_PREFIX_OFFSET, 16, 1,
			       skb->data, skb->len, true);
	}

	otx2_set_rxhash(pfvf, cqe_hdr, skb);

	skb_record_rx_queue(skb, cq->cq_idx);
	skb->protocol = eth_type_trans(skb, pfvf->netdev);
	if (pfvf->netdev->features & NETIF_F_RXCSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* This holds true on condition RX VLAN offloads are enabled and
	 * 802.1AD or 802.1Q VLANs were found in frame.
	 */
	if (parse->vtag0_gone) {
		if (skb->protocol == htons(ETH_P_8021Q))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       parse->vtag0_tci);
		else
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       parse->vtag0_tci);
	}

	napi_gro_receive(&qset->napi[cq->cint_idx].napi, skb);
}

#define CQE_ADDR(CQ, idx) ((CQ)->cqe_base + ((CQ)->cqe_size * (idx)))

int otx2_napi_handler(struct otx2_cq_queue *cq,
		      struct otx2_nic *pfvf, int budget)
{
	struct otx2_pool *rbpool = cq->rbpool;
	int processed_cqe = 0, workdone = 0;
	int tx_pkts = 0, tx_bytes = 0;
	struct nix_cqe_hdr_s *cqe_hdr;
	struct netdev_queue *txq;
	u64 cq_status;
	s64 bufptr;

	/* If the pending CQE > 64 skip CQ status read */
	if (cq->pend_cqe >= budget)
		goto process_cqe;

	cq_status = otx2_nix_cq_op_status(pfvf, cq->cq_idx);
	if (cq_status & BIT_ULL(63)) {
		dev_err(pfvf->dev, "CQ operation error");
		pfvf->intf_down = true;
		schedule_work(&pfvf->reset_task);
		return 0;
	}
	if (cq_status & BIT_ULL(46)) {
		dev_err(pfvf->dev, "CQ stopped due to error");
		pfvf->intf_down = true;
		schedule_work(&pfvf->reset_task);
		return 0;
	}

	cq->cq_head = (cq_status >> 20) & 0xFFFFF;
	cq->cq_tail = cq_status & 0xFFFFF;

	/* Since multiple CQs may be mapped to same CINT,
	 * check if there are valid CQEs in this CQ.
	 */
	if (cq->cq_head == cq->cq_tail)
		return 0;
process_cqe:
	cq->pend_cqe = 0;
	while (cq->cq_head != cq->cq_tail) {
		if (workdone >= budget) {
			/* Calculate number of pending CQEs */
			if (cq->cq_tail < cq->cq_head)
				cq->pend_cqe = (cq->cqe_cnt - cq->cq_head)
						+ cq->cq_tail;
			else
				cq->pend_cqe = cq->cq_tail - cq->cq_head;
			break;
		}

		cqe_hdr = (struct nix_cqe_hdr_s *)CQE_ADDR(cq, cq->cq_head);
		cq->cq_head++;
		cq->cq_head &= (cq->cqe_cnt - 1);

		switch (cqe_hdr->cqe_type) {
		case NIX_XQE_TYPE_RX:
			/* Receive packet handler*/
			otx2_rcv_pkt_handler(pfvf, cq, cqe_hdr);
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
		/* Check if queue was stopped earlier due to ring full */
		smp_mb();
		if (netif_carrier_ok(pfvf->netdev) &&
		    netif_tx_queue_stopped(txq))
			netif_tx_wake_queue(txq);
	}

	if (!cq->pool_ptrs)
		return 0;

	/* Refill pool with new buffers */
	while (cq->pool_ptrs) {
		bufptr = otx2_alloc_rbuf(pfvf, rbpool, GFP_ATOMIC);
		if (bufptr <= 0) {
			struct refill_work *work;
			struct delayed_work *dwork;

			work = &pfvf->refill_wrk[cq->cq_idx];
			dwork = &work->pool_refill_work;
			/* Schedule a task if no other task is running */
			if (!cq->refill_task_sched) {
				cq->refill_task_sched = true;
				schedule_delayed_work(dwork,
						      msecs_to_jiffies(100));
			}
			break;
		}
		otx2_aura_freeptr(pfvf, cq->cq_idx, bufptr + OTX2_HEAD_ROOM);
		cq->pool_ptrs--;
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
	u64 qcount;

	cq_poll = container_of(napi, struct otx2_cq_poll, napi);
	pfvf = (struct otx2_nic *)cq_poll->dev;
	qset = &pfvf->qset;

	for (i = 0; i < MAX_CQS_PER_CNT; i++) {
		cq_idx = cq_poll->cq_ids[i];
		if (cq_idx == CINT_INVALID_CQ)
			continue;
		cq = &qset->cq[cq_idx];
		qcount = otx2_read64(pfvf, NIX_LF_CINTX_CNT(cq_poll->cint_idx));
		qcount = (qcount >> 32) & 0xFFFF;
		/* If the RQ refill WQ task is running, skip napi
		 * scheduler for this queue.
		 */
		if (cq->refill_task_sched)
			continue;
		workdone += otx2_napi_handler(cq, pfvf, budget);
		if (workdone && qcount == 1)
			break;
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

static inline void otx2_sqe_flush(struct otx2_snd_queue *sq, int size)
{
	u64 status;

	/* Packet data stores should finish before SQE is flushed to HW */
	dma_wmb();

	do {
		memcpy(sq->lmt_addr, sq->sqe_base, size);
		status = otx2_lmt_flush(sq->io_addr);
	} while (status == 0);

	sq->head++;
	sq->head &= (sq->sqe_cnt - 1);
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
				*offset += sizeof(*sg) + (3 * sizeof(u64));
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

	ext = (struct nix_sqe_ext_s *)(sq->sqe_base + *offset);
	ext->subdc = NIX_SUBDC_EXT;
	if (skb_shinfo(skb)->gso_size) {
		ext->lso = 1;
		ext->lso_sb = skb_transport_offset(skb) + tcp_hdrlen(skb);
		ext->lso_mps = skb_shinfo(skb)->gso_size;

		/* Only TSOv4 and TSOv6 GSO offloads are supported */
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
			ext->lso_format = pfvf->hw.lso_tsov4_idx;

			/* HW adds payload size to 'ip_hdr->tot_len' while
			 * sending TSO segment, hence set payload length
			 * in IP header of the packet to just header length.
			 */
			ip_hdr(skb)->tot_len =
				htons(ext->lso_sb - skb_network_offset(skb));
		} else {
			ext->lso_format = pfvf->hw.lso_tsov6_idx;
			ipv6_hdr(skb)->payload_len =
				htons(ext->lso_sb - skb_network_offset(skb));
		}
	} else if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) {
		ext->tstmp = 1;
	}

#define OTX2_VLAN_PTR_OFFSET     (ETH_HLEN - ETH_TLEN)
	if (skb_vlan_tag_present(skb)) {
		if (skb->vlan_proto == htons(ETH_P_8021Q)) {
			ext->vlan1_ins_ena = 1;
			ext->vlan1_ins_ptr = OTX2_VLAN_PTR_OFFSET;
			ext->vlan1_ins_tci = skb_vlan_tag_get(skb);
		} else if (skb->vlan_proto == htons(ETH_P_8021AD)) {
			ext->vlan0_ins_ena = 1;
			ext->vlan0_ins_ptr = OTX2_VLAN_PTR_OFFSET;
			ext->vlan0_ins_tci = skb_vlan_tag_get(skb);
		}
	}

	*offset += sizeof(*ext);
}

static void otx2_sqe_add_mem(struct otx2_snd_queue *sq, int *offset,
			     int alg, u64 iova)
{
	struct nix_sqe_mem_s *mem;

	mem = (struct nix_sqe_mem_s *)(sq->sqe_base + *offset);
	mem->subdc = NIX_SUBDC_MEM;
	mem->alg = alg;
	mem->wmem = 1; /* wait for the memory operation */
	mem->addr = iova;

	*offset += sizeof(*mem);
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
		/* get vlan protocol Ethertype */
		if (eth_type_vlan(skb->protocol))
			skb->protocol = vlan_get_protocol(skb);

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

static int otx2_dma_map_tso_skb(struct otx2_nic *pfvf,
				struct otx2_snd_queue *sq,
				struct sk_buff *skb, int sqe, int hdr_len)
{
	int num_segs = skb_shinfo(skb)->nr_frags + 1;
	struct sg_list *sg = &sq->sg[sqe];
	u64 dma_addr;
	int seg, len;

	sg->num_segs = 0;

	/* Get payload length at skb->data */
	len = skb_headlen(skb) - hdr_len;

	for (seg = 0; seg < num_segs; seg++) {
		/* Skip skb->data, if there is no payload */
		if (!seg && !len)
			continue;
		dma_addr = otx2_dma_map_skb_frag(pfvf, skb, seg, &len);
		if (dma_mapping_error(pfvf->dev, dma_addr))
			goto unmap;

		/* Save DMA mapping info for later unmapping */
		sg->dma_addr[sg->num_segs] = dma_addr;
		sg->size[sg->num_segs] = len;
		sg->num_segs++;
	}
	return 0;
unmap:
	otx2_dma_unmap_skb_frags(pfvf, sg);
	return -EINVAL;
}

static u64 otx2_tso_frag_dma_addr(struct otx2_snd_queue *sq,
				  struct sk_buff *skb, int seg,
				  u64 seg_addr, int hdr_len, int sqe)
{
	const struct skb_frag_struct *frag;
	struct sg_list *sg = &sq->sg[sqe];
	int offset;

	if (seg < 0)
		return sg->dma_addr[0] + (seg_addr - (u64)skb->data);

	frag = &skb_shinfo(skb)->frags[seg];
	offset = (u64)(page_address(frag->page.p) + frag->page_offset);
	offset = seg_addr - offset;
	if (skb_headlen(skb) - hdr_len)
		seg++;
	return sg->dma_addr[seg] + offset;
}

static void otx2_sqe_tso_add_sg(struct otx2_snd_queue *sq,
				struct sg_list *list, int *offset)
{
	struct nix_sqe_sg_s *sg = NULL;
	u16 *sg_lens = NULL;
	u64 *iova = NULL;
	int seg;

	/* Add SG descriptors with buffer addresses */
	for (seg = 0; seg < list->num_segs; seg++) {
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
			if ((list->num_segs - seg) >= (MAX_SEGS_PER_SG - 1))
				*offset += sizeof(*sg) + (3 * sizeof(u64));
			else
				*offset += sizeof(*sg) + sizeof(u64);
		}
		sg_lens[frag_num(seg % MAX_SEGS_PER_SG)] = list->size[seg];
		*iova++ = list->dma_addr[seg];
		sg->segs++;
	}
}

static void otx2_sq_append_tso(struct otx2_nic *pfvf, struct otx2_snd_queue *sq,
			       struct sk_buff *skb, u16 qidx)
{
	struct netdev_queue *txq = netdev_get_tx_queue(pfvf->netdev, qidx);
	int hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
	int tcp_data, seg_len, pkt_len, offset;
	struct nix_sqe_hdr_s *sqe_hdr;
	int first_sqe = sq->head;
	struct sg_list list;
	struct tso_t tso;

	/* Map SKB's fragments to DMA.
	 * It's done here to avoid mapping for every TSO segment's packet.
	 */
	if (otx2_dma_map_tso_skb(pfvf, sq, skb, first_sqe, hdr_len)) {
		dev_kfree_skb_any(skb);
		return;
	}

	netdev_tx_sent_queue(txq, skb->len);

	tso_start(skb, &tso);
	tcp_data = skb->len - hdr_len;
	while (tcp_data > 0) {
		char *hdr;

		seg_len = min_t(int, skb_shinfo(skb)->gso_size, tcp_data);
		tcp_data -= seg_len;

		/* Set SQE's SEND_HDR */
		memset(sq->sqe_base, 0, sq->sqe_size);
		sqe_hdr = (struct nix_sqe_hdr_s *)(sq->sqe_base);
		otx2_sqe_add_hdr(pfvf, sq, sqe_hdr, skb, qidx);
		offset = sizeof(*sqe_hdr);

		/* Add TSO segment's pkt header */
		hdr = sq->tso_hdrs->base + (sq->head * TSO_HEADER_SIZE);
		tso_build_hdr(skb, hdr, &tso, seg_len, tcp_data == 0);
		list.dma_addr[0] =
			sq->tso_hdrs->iova + (sq->head * TSO_HEADER_SIZE);
		list.size[0] = hdr_len;
		list.num_segs = 1;

		/* Add TSO segment's payload data fragments */
		pkt_len = hdr_len;
		while (seg_len > 0) {
			int size;

			size = min_t(int, tso.size, seg_len);

			list.size[list.num_segs] = size;
			list.dma_addr[list.num_segs] =
				otx2_tso_frag_dma_addr(sq, skb,
						       tso.next_frag_idx - 1,
						       (u64)tso.data, hdr_len,
						       first_sqe);
			list.num_segs++;
			pkt_len += size;
			seg_len -= size;
			tso_build_data(skb, &tso, size);
		}
		sqe_hdr->total = pkt_len;
		otx2_sqe_tso_add_sg(sq, &list, &offset);

		/* DMA mappings and skb needs to be freed only after last
		 * TSO segment is transmitted out. So set 'PNC' only for
		 * last segment. Also point last segment's sqe_id to first
		 * segment's SQE index where skb address and DMA mappings
		 * are saved.
		 */
		if (!tcp_data) {
			sqe_hdr->pnc = 1;
			sqe_hdr->sqe_id = first_sqe;
			sq->sg[first_sqe].skb = (u64)skb;
		} else {
			sqe_hdr->pnc = 0;
		}

		sqe_hdr->sizem1 = (offset / 16) - 1;

		/* Flush SQE to HW */
		otx2_sqe_flush(sq, offset);
	}
}

static inline bool is_hw_tso_supported(struct otx2_nic *pfvf,
				       struct sk_buff *skb)
{
	int payload_len, last_seg_size;

	if (!pfvf->hw.hw_tso)
		return false;

	/* HW has an issue due to which when the payload of the last LSO
	 * segment is shorter than 16 bytes, some header fields may not
	 * be correctly modified, hence don't offload such TSO segments.
	 */
	payload_len = skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));
	last_seg_size = payload_len % skb_shinfo(skb)->gso_size;
	if (last_seg_size && last_seg_size < 16)
		return false;
	return true;
}

static int otx2_get_sqe_count(struct otx2_nic *pfvf, struct sk_buff *skb)
{
	if (!skb_shinfo(skb)->gso_size)
		return 1;

	/* HW TSO */
	if (is_hw_tso_supported(pfvf, skb))
		return 1;

	/* SW TSO */
	return skb_shinfo(skb)->gso_segs;
}

static inline void otx2_set_txtstamp(struct otx2_nic *pfvf, struct sk_buff *skb,
				     struct otx2_snd_queue *sq, int *offset)
{
	u64 iova;

	if (!skb_shinfo(skb)->gso_size &&
	    skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) {
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		iova = sq->timestamps->iova + (sq->head * sizeof(u64));
		otx2_sqe_add_mem(sq, offset, NIX_SENDMEMALG_E_SETTSTMP, iova);
	} else {
		skb_tx_timestamp(skb);
	}
}

bool otx2_sq_append_skb(struct net_device *netdev, struct otx2_snd_queue *sq,
			struct sk_buff *skb, u16 qidx)
{
	struct netdev_queue *txq = netdev_get_tx_queue(netdev, qidx);
	struct otx2_nic *pfvf = netdev_priv(netdev);
	int offset, num_segs, free_sqe;
	struct nix_sqe_hdr_s *sqe_hdr;

	/* Check if there is room for new SQE.
	 * 'Num of SQBs freed to SQ's pool - SQ's Aura count'
	 * will give free SQE count.
	 */
	free_sqe = (sq->num_sqbs - *sq->aura_fc_addr) * sq->sqe_per_sqb;

	if (free_sqe < sq->sqe_thresh ||
	    free_sqe < otx2_get_sqe_count(pfvf, skb))
		goto fail;

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

	if (skb_shinfo(skb)->gso_size && !is_hw_tso_supported(pfvf, skb)) {
		/* Insert vlan tag before giving pkt to tso */
		if (skb_vlan_tag_present(skb))
			skb = __vlan_hwaccel_push_inside(skb);
		otx2_sq_append_tso(pfvf, sq, skb, qidx);
		return true;
	}

	/* Set SQE's SEND_HDR */
	memset(sq->sqe_base, 0, sq->sqe_size);
	sqe_hdr = (struct nix_sqe_hdr_s *)(sq->sqe_base);
	otx2_sqe_add_hdr(pfvf, sq, sqe_hdr, skb, qidx);
	offset = sizeof(*sqe_hdr);

	/* Add extended header if needed */
	otx2_sqe_add_ext(pfvf, sq, skb, &offset);

	/* Add SG subdesc with data frags */
	if (!otx2_sqe_add_sg(pfvf, sq, skb, num_segs, &offset)) {
		otx2_dma_unmap_skb_frags(pfvf, &sq->sg[sq->head]);
		return false;
	}

	otx2_set_txtstamp(pfvf, skb, sq, &offset);

	sqe_hdr->sizem1 = (offset / 16) - 1;

	netdev_tx_sent_queue(txq, skb->len);

	/* Flush SQE to HW */
	otx2_sqe_flush(sq, offset);

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
	int err;

	otx2_mbox_lock(&pfvf->mbox);
	if (enable)
		msg = otx2_mbox_alloc_msg_nix_lf_start_rx(&pfvf->mbox);
	else
		msg = otx2_mbox_alloc_msg_nix_lf_stop_rx(&pfvf->mbox);

	if (!msg) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	otx2_mbox_unlock(&pfvf->mbox);
	return err;
}
