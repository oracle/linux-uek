/* bnx2x_cmn.c: Broadcom Everest network driver.
 *
 * Copyright (c) 2007-2013 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Maintained by: Ariel Elior <ariele@broadcom.com>
 * Written by: Eliezer Tamir
 * Based on code from Michael Chan's bnx2 driver
 * UDP CSUM errata workaround by Arik Gendelman
 * Slowpath and fastpath rework by Vladislav Zolotarov
 * Statistics and Link management by Yitchak Gertner
 *
 */
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
#include <linux/version.h>
#include <linux/netdevice.h>
#endif
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <net/tcp.h>
#if !defined(__VMKLNX__) /* BNX2X_UPSTREAM */
#include <net/ipv6.h>
#else
#include <linux/ipv6.h>
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 7)) /* BNX2X_UPSTREAM */
#include <net/ip6_checksum.h>
#endif
#include <linux/prefetch.h>
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
#include <linux/pkt_sched.h>
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)) /* ! BNX2X_UPSTREAM */
#define __NO_TPA__		1
#endif
#include "bnx2x_cmn.h"
#include "bnx2x_init.h"
#include "bnx2x_sp.h"
#if defined(__VMKLNX__) /* ! BNX2X_UPSTREAM */
#include "bnx2x_esx.h"
#endif

static void bnx2x_free_fp_mem_cnic(struct bnx2x *bp);
static int bnx2x_alloc_fp_mem_cnic(struct bnx2x *bp);
static int bnx2x_alloc_fp_mem(struct bnx2x *bp);
#if defined(BNX2X_NEW_NAPI) /* BNX2X_UPSTREAM */
_STAEU int bnx2x_poll(struct napi_struct *napi, int budget);
#else
int bnx2x_poll(struct net_device *dev, int *budget);
#endif

_UP_STATIC void bnx2x_add_all_napi_cnic(struct bnx2x *bp)
{
	int i;

	/* Add NAPI objects */
	for_each_rx_queue_cnic(bp, i)
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
#if (VMWARE_ESX_DDK_VERSION >= 50000)
		if (!bnx2x_fp(bp, i, napi).net_poll)
#else
		if (!bnx2x_fp(bp, i, napi).worldlet)
#endif
#ifdef BNX2X_ESX_CNA
		if (!IS_FCOE_IDX(i))
#endif
#endif /* __VMKLNX__ */
		netif_napi_add(bp->dev, &bnx2x_fp(bp, i, napi),
			       bnx2x_poll, NAPI_POLL_WEIGHT);
#else /* non BNX2X_UPSTREAM */
	{
		/* initialize net_device for each rx queue */
		struct net_device *dummy_netdev = &bnx2x_fp(bp, i, dummy_netdev);
#if defined(USE_NAPI_GRO)
		struct napi_struct *napi = &bnx2x_fp(bp, i, napi);
		napi->dev = bp->dev;
#endif
		dummy_netdev->priv = &bp->fp[i];
		dummy_netdev->poll = bnx2x_poll;
		dummy_netdev->weight = NAPI_POLL_WEIGHT;
		set_bit(__LINK_STATE_START, &dummy_netdev->state);
	}
#endif
}

_UP_STATIC void bnx2x_add_all_napi(struct bnx2x *bp)
{
	int i;

	/* Add NAPI objects */
	for_each_eth_queue(bp, i)
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
#if (VMWARE_ESX_DDK_VERSION >= 50000)
		if (!bnx2x_fp(bp, i, napi).net_poll)
#else
		if (!bnx2x_fp(bp, i, napi).worldlet)
#endif
#ifdef BNX2X_ESX_CNA
		if (!IS_FCOE_IDX(i))
#endif
#endif /* __VMKLNX__ */
		netif_napi_add(bp->dev, &bnx2x_fp(bp, i, napi),
			       bnx2x_poll, NAPI_POLL_WEIGHT);
#else /* non BNX2X_UPSTREAM */
	{
		/* initialize net_device for each rx queue */
		struct net_device *dummy_netdev = &bnx2x_fp(bp, i, dummy_netdev);
#if defined(USE_NAPI_GRO)
		struct napi_struct *napi = &bnx2x_fp(bp, i, napi);
		napi->dev = bp->dev;
#endif
		dummy_netdev->priv = &bp->fp[i];
		dummy_netdev->poll = bnx2x_poll;
		dummy_netdev->weight = NAPI_POLL_WEIGHT;
		set_bit(__LINK_STATE_START, &dummy_netdev->state);
	}
#endif
}

static _UP_UINT2INT bnx2x_calc_num_queues(struct bnx2x *bp)
{
	return bnx2x_num_queues ?
		min_t(_UP_UINT2INT, bnx2x_num_queues, BNX2X_MAX_QUEUES(bp)) :
		min_t(_UP_UINT2INT, netif_get_num_default_rss_queues(),
		      BNX2X_MAX_QUEUES(bp));
}

/**
 * bnx2x_move_fp - move content of the fastpath structure.
 *
 * @bp:		driver handle
 * @from:	source FP index
 * @to:		destination FP index
 *
 * Makes sure the contents of the bp->fp[to].napi is kept
 * intact. This is done by first copying the napi struct from
 * the target to the source, and then mem copying the entire
 * source onto the target. Update txdata pointers and related
 * content.
 */
static inline void bnx2x_move_fp(struct bnx2x *bp, int from, int to)
{
	struct bnx2x_fastpath *from_fp = &bp->fp[from];
	struct bnx2x_fastpath *to_fp = &bp->fp[to];
	struct bnx2x_sp_objs *from_sp_objs = &bp->sp_objs[from];
	struct bnx2x_sp_objs *to_sp_objs = &bp->sp_objs[to];
	struct bnx2x_fp_stats *from_fp_stats = &bp->fp_stats[from];
	struct bnx2x_fp_stats *to_fp_stats = &bp->fp_stats[to];
	int old_max_eth_txqs, new_max_eth_txqs;
	int old_txdata_index = 0, new_txdata_index = 0;
	struct bnx2x_agg_info *old_tpa_info = to_fp->tpa_info;

#if defined(BNX2X_NEW_NAPI) || defined(USE_NAPI_GRO) /* BNX2X_UPSTREAM */
	/* Copy the NAPI object as it has been already initialized */
	from_fp->napi = to_fp->napi;
#endif
#if !defined(BNX2X_NEW_NAPI) /* ! BNX2X_UPSTREAM */
	/* Copy the "dummy" netdev object as it has been already
	 * initialized.
	 */
	from_fp->dummy_netdev = to_fp->dummy_netdev;
#endif

	/* Move bnx2x_fastpath contents */
	memcpy(to_fp, from_fp, sizeof(*to_fp));
	to_fp->index = to;

	/* Retain the tpa_info of the original `to' version as we don't want
	 * 2 FPs to contain the same tpa_info pointer.
	 */
	to_fp->tpa_info = old_tpa_info;

	/* move sp_objs contents as well, as their indices match fp ones */
	memcpy(to_sp_objs, from_sp_objs, sizeof(*to_sp_objs));

	/* move fp_stats contents as well, as their indices match fp ones */
	memcpy(to_fp_stats, from_fp_stats, sizeof(*to_fp_stats));

	/* Update txdata pointers in fp and move txdata content accordingly:
	 * Each fp consumes 'max_cos' txdata structures, so the index should be
	 * decremented by max_cos x delta.
	 */

	old_max_eth_txqs = BNX2X_NUM_ETH_QUEUES(bp) * (bp)->max_cos;
	new_max_eth_txqs = (BNX2X_NUM_ETH_QUEUES(bp) - from + to) *
				(bp)->max_cos;
	if (from == FCOE_IDX(bp)) {
		old_txdata_index = old_max_eth_txqs + FCOE_TXQ_IDX_OFFSET;
		new_txdata_index = new_max_eth_txqs + FCOE_TXQ_IDX_OFFSET;
	}
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	 else if (from == FWD_IDX(bp)) {
		old_txdata_index = old_max_eth_txqs + FWD_TXQ_IDX_OFFSET;
		new_txdata_index = new_max_eth_txqs + FWD_TXQ_IDX_OFFSET;
	} else { /* OOO_IDX */
		old_txdata_index = old_max_eth_txqs + OOO_TXQ_IDX_OFFSET;
		new_txdata_index = new_max_eth_txqs + OOO_TXQ_IDX_OFFSET;
	}
#endif

	memcpy(&bp->bnx2x_txq[new_txdata_index],
	       &bp->bnx2x_txq[old_txdata_index],
	       sizeof(struct bnx2x_fp_txdata));
	to_fp->txdata_ptr[0] = &bp->bnx2x_txq[new_txdata_index];
}

/**
 * bnx2x_fill_fw_str - Fill buffer with FW version string.
 *
 * @bp:        driver handle
 * @buf:       character buffer to fill with the fw name
 * @buf_len:   length of the above buffer
 *
 */
void bnx2x_fill_fw_str(struct bnx2x *bp, char *buf, size_t buf_len)
{
	if (IS_PF(bp)) {
		u8 phy_fw_ver[PHY_FW_VER_LEN];

		phy_fw_ver[0] = '\0';
		bnx2x_get_ext_phy_fw_version(&bp->link_params,
					     phy_fw_ver, PHY_FW_VER_LEN);
		strlcpy(buf, bp->fw_ver, buf_len);
		snprintf(buf + strlen(bp->fw_ver), 32 - strlen(bp->fw_ver),
			 "bc %d.%d.%d%s%s",
			 (bp->common.bc_ver & 0xff0000) >> 16,
			 (bp->common.bc_ver & 0xff00) >> 8,
			 (bp->common.bc_ver & 0xff),
			 ((phy_fw_ver[0] != '\0') ? " phy " : ""), phy_fw_ver);
	} else {
		bnx2x_vf_fill_fw_str(bp, buf, buf_len);
	}
}

/**
 * bnx2x_shrink_eth_fp - guarantees fastpath structures stay intact
 *
 * @bp:	driver handle
 * @delta:	number of eth queues which were not allocated
 */
static void bnx2x_shrink_eth_fp(struct bnx2x *bp, int delta)
{
	int i, cos, old_eth_num = BNX2X_NUM_ETH_QUEUES(bp);

	/* Queue pointer cannot be re-set on an fp-basis, as moving pointer
	 * backward along the array could cause memory to be overridden
	 */
	for (cos = 1; cos < bp->max_cos; cos++) {
		for (i = 0; i < old_eth_num - delta; i++) {
			struct bnx2x_fastpath *fp = &bp->fp[i];
			int new_idx = cos * (old_eth_num - delta) + i;

			memcpy(&bp->bnx2x_txq[new_idx], fp->txdata_ptr[cos],
			       sizeof(struct bnx2x_fp_txdata));
			fp->txdata_ptr[cos] = &bp->bnx2x_txq[new_idx];
		}
	}
}

int bnx2x_load_count[2][3] = { {0} }; /* per-path: 0-common, 1-port0, 2-port1 */

/* free skb in the packet ring at pos idx
 * return idx of last bd freed
 */
static u16 bnx2x_free_tx_pkt(struct bnx2x *bp, struct bnx2x_fp_txdata *txdata,
			     u16 idx, unsigned int *pkts_compl,
			     unsigned int *bytes_compl)
{
	struct sw_tx_bd *tx_buf = &txdata->tx_buf_ring[idx];
	struct eth_tx_start_bd *tx_start_bd;
	struct eth_tx_bd *tx_data_bd;
	struct sk_buff *skb = tx_buf->skb;
	u16 bd_idx = TX_BD(tx_buf->first_bd), new_cons;
	u16 split_bd_len = 0;
	int nbd;

	/* prefetch skb end pointer to speedup dev_kfree_skb() */
	prefetch(&skb->end);

	DP(NETIF_MSG_TX_DONE, "fp[%d]: pkt_idx %d  buff @(%p)->skb %p\n",
	   txdata->txq_index, idx, tx_buf, skb);

	tx_start_bd = &txdata->tx_desc_ring[bd_idx].start_bd;

	nbd = le16_to_cpu(tx_start_bd->nbd) - 1;
#ifdef BNX2X_STOP_ON_ERROR
	if ((nbd - 1) > (MAX_SKB_FRAGS + 2)) {
		BNX2X_ERR("BAD nbd!\n");
		bnx2x_panic();
	}
#endif
	new_cons = nbd + tx_buf->first_bd;

	/* Get the next bd */
	bd_idx = TX_BD(NEXT_TX_IDX(bd_idx));

	/* Skip a parse bd... */
	--nbd;
	bd_idx = TX_BD(NEXT_TX_IDX(bd_idx));

	/* TSO header+data bds share a common mapping. see bnx2x_tx_split() */
	if (tx_buf->flags & BNX2X_TSO_SPLIT_BD) {
		tx_data_bd = &txdata->tx_desc_ring[bd_idx].reg_bd;
		split_bd_len = BD_UNMAP_LEN(tx_data_bd);
		--nbd;
		bd_idx = TX_BD(NEXT_TX_IDX(bd_idx));
	}

	/* unmap first bd */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	dma_unmap_single(&bp->pdev->dev, BD_UNMAP_ADDR(tx_start_bd),
			 BD_UNMAP_LEN(tx_start_bd) + split_bd_len,
			 DMA_TO_DEVICE);
#else
	pci_unmap_single(bp->pdev, BD_UNMAP_ADDR(tx_start_bd),
			 BD_UNMAP_LEN(tx_start_bd) + split_bd_len,
			 PCI_DMA_TODEVICE);
#endif

	/* now free frags */
	while (nbd > 0) {

		tx_data_bd = &txdata->tx_desc_ring[bd_idx].reg_bd;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
		dma_unmap_page(&bp->pdev->dev, BD_UNMAP_ADDR(tx_data_bd),
			       BD_UNMAP_LEN(tx_data_bd), DMA_TO_DEVICE);
#else
		pci_unmap_page(bp->pdev, BD_UNMAP_ADDR(tx_data_bd),
			       BD_UNMAP_LEN(tx_data_bd), PCI_DMA_TODEVICE);
#endif
		if (--nbd)
			bd_idx = TX_BD(NEXT_TX_IDX(bd_idx));
	}

	/* release skb */
	WARN_ON(!skb);
	if (likely(skb)) {
		(*pkts_compl)++;
		(*bytes_compl) += skb->len;
	}

	dev_kfree_skb_any(skb);
	tx_buf->first_bd = 0;
	tx_buf->skb = NULL;

	return new_cons;
}

int bnx2x_tx_int(struct bnx2x *bp, struct bnx2x_fp_txdata *txdata)
{
	struct netdev_queue *txq;
	u16 hw_cons, sw_cons, bd_cons = txdata->tx_bd_cons;
	unsigned int pkts_compl = 0, bytes_compl = 0;

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic))
		return -1;
#endif

	txq = netdev_get_tx_queue(bp->dev, txdata->txq_index);
	hw_cons = le16_to_cpu(*txdata->tx_cons_sb);
	sw_cons = txdata->tx_pkt_cons;

	while (sw_cons != hw_cons) {
		u16 pkt_cons;

		pkt_cons = TX_BD(sw_cons);

		DP(NETIF_MSG_TX_DONE,
		   "queue[%d]: hw_cons %u  sw_cons %u  pkt_cons %u\n",
		   txdata->txq_index, hw_cons, sw_cons, pkt_cons);

		bd_cons = bnx2x_free_tx_pkt(bp, txdata, pkt_cons,
					    &pkts_compl, &bytes_compl);

		sw_cons++;
	}

	netdev_tx_completed_queue(txq, pkts_compl, bytes_compl);

	txdata->tx_pkt_cons = sw_cons;
	txdata->tx_bd_cons = bd_cons;

	/* Need to make the tx_bd_cons update visible to start_xmit()
	 * before checking for netif_tx_queue_stopped().  Without the
	 * memory barrier, there is a small possibility that
	 * start_xmit() will miss it and cause the queue to be stopped
	 * forever.
	 * On the other hand we need an rmb() here to ensure the proper
	 * ordering of bit testing in the following
	 * netif_tx_queue_stopped(txq) call.
	 */
	smp_mb();

#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
	if (likely(!txdata->parent_fp->esx.dynamic_netq_stop))
#endif
#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
	if (unlikely(netif_tx_queue_stopped(txq))) {
		/* Taking tx_lock() is needed to prevent re-enabling the queue
		 * while it's empty. This could have happen if rx_action() gets
		 * suspended in bnx2x_tx_int() after the condition before
		 * netif_tx_wake_queue(), while tx_action (bnx2x_start_xmit()):
		 *
		 * stops the queue->sees fresh tx_bd_cons->releases the queue->
		 * sends some packets consuming the whole queue again->
		 * stops the queue
		 */

		__netif_tx_lock(txq, smp_processor_id());

		if ((netif_tx_queue_stopped(txq)) &&
		    (bp->state == BNX2X_STATE_OPEN) &&
		    (bnx2x_tx_avail(bp, txdata) >= MAX_DESC_PER_TX_PKT))
			netif_tx_wake_queue(txq);

		__netif_tx_unlock(txq);
	}
#else
	if (unlikely(netif_queue_stopped(bp->dev))) {

		netif_tx_lock(bp->dev);

		if (netif_queue_stopped(bp->dev) &&
		    (bp->state == BNX2X_STATE_OPEN) &&
		    (bnx2x_tx_avail(bp, txdata) >= MAX_DESC_PER_TX_PKT))
			netif_wake_queue(bp->dev);

		netif_tx_unlock(bp->dev);
	}
#endif
	return 0;
}

#if !defined(__NO_TPA__) /* BNX2X_UPSTREAM */
static inline void bnx2x_update_last_max_sge(struct bnx2x_fastpath *fp,
					     u16 idx)
{
	u16 last_max = fp->last_max_sge;

	if (SUB_S16(idx, last_max) > 0)
		fp->last_max_sge = idx;
}

static inline void bnx2x_update_sge_prod(struct bnx2x_fastpath *fp,
					 u16 sge_len,
					 struct eth_end_agg_rx_cqe *cqe)
{
	struct bnx2x *bp = fp->bp;
	u16 last_max, last_elem, first_elem;
	u16 delta = 0;
	u16 i;

	if (!sge_len)
		return;

	/* First mark all used pages */
	for (i = 0; i < sge_len; i++)
		BIT_VEC64_CLEAR_BIT(fp->sge_mask,
			RX_SGE(le16_to_cpu(cqe->sgl_or_raw_data.sgl[i])));

	DP(NETIF_MSG_RX_STATUS, "fp_cqe->sgl[%d] = %d\n",
	   sge_len - 1, le16_to_cpu(cqe->sgl_or_raw_data.sgl[sge_len - 1]));

	/* Here we assume that the last SGE index is the biggest */
	prefetch((void *)(fp->sge_mask));
	bnx2x_update_last_max_sge(fp,
		le16_to_cpu(cqe->sgl_or_raw_data.sgl[sge_len - 1]));

	last_max = RX_SGE(fp->last_max_sge);
	last_elem = last_max >> BIT_VEC64_ELEM_SHIFT;
	first_elem = RX_SGE(fp->rx_sge_prod) >> BIT_VEC64_ELEM_SHIFT;

	/* If ring is not full */
	if (last_elem + 1 != first_elem)
		last_elem++;

	/* Now update the prod */
	for (i = first_elem; i != last_elem; i = NEXT_SGE_MASK_ELEM(i)) {
		if (likely(fp->sge_mask[i]))
			break;

		fp->sge_mask[i] = BIT_VEC64_ELEM_ONE_MASK;
		delta += BIT_VEC64_ELEM_SZ;
	}

	if (delta > 0) {
		fp->rx_sge_prod += delta;
		/* clear page-end entries */
		bnx2x_clear_sge_mask_next_elems(fp);
	}

	DP(NETIF_MSG_RX_STATUS,
	   "fp->last_max_sge = %d  fp->rx_sge_prod = %d\n",
	   fp->last_max_sge, fp->rx_sge_prod);
}

/* Get Toeplitz hash value in the skb using the value from the
 * CQE (calculated by HW).
 */
static u32 bnx2x_get_rxhash(const struct bnx2x *bp,
			    const struct eth_fast_path_rx_cqe *cqe,
			    bool *l4_rxhash)
{
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	/* Get Toeplitz hash from CQE */
	if ((bp->dev->features & NETIF_F_RXHASH) &&
	    (cqe->status_flags & ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG)) {
		enum eth_rss_hash_type htype;

		htype = cqe->status_flags & ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE;
		*l4_rxhash = (htype == TCP_IPV4_HASH_TYPE) ||
			     (htype == TCP_IPV6_HASH_TYPE);
		return le32_to_cpu(cqe->rss_hash_result);
	}
	*l4_rxhash = false;
#endif
	return 0;
}

static void bnx2x_tpa_start(struct bnx2x_fastpath *fp, u16 queue,
			    u16 cons, u16 prod,
			    struct eth_fast_path_rx_cqe *cqe)
{
	struct bnx2x *bp = fp->bp;
	struct sw_rx_bd *cons_rx_buf = &fp->rx_buf_ring[cons];
	struct sw_rx_bd *prod_rx_buf = &fp->rx_buf_ring[prod];
	struct eth_rx_bd *prod_bd = &fp->rx_desc_ring[prod];
	dma_addr_t mapping;
	struct bnx2x_agg_info *tpa_info = &fp->tpa_info[queue];
	struct sw_rx_bd *first_buf = &tpa_info->first_buf;

	/* print error if current state != stop */
	if (tpa_info->tpa_state != BNX2X_TPA_STOP)
		BNX2X_ERR("start of bin not in stop [%d]\n", queue);

	/* Try to map an empty data buffer from the aggregation info  */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	mapping = dma_map_single(&bp->pdev->dev,
				 first_buf->data + NET_SKB_PAD,
				 fp->rx_buf_size, DMA_FROM_DEVICE);
#else
	mapping = dma_map_single(&bp->pdev->dev,
				 first_buf->data->data,
				 fp->rx_buf_size, DMA_FROM_DEVICE);
#endif
#else
	mapping = pci_map_single(bp->pdev,
				 first_buf->data->data,
				 fp->rx_buf_size, PCI_DMA_FROMDEVICE);
#endif
	/*
	 *  ...if it fails - move the skb from the consumer to the producer
	 *  and set the current aggregation state as ERROR to drop it
	 *  when TPA_STOP arrives.
	 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) /* BNX2X_UPSTREAM */
	if (unlikely(dma_mapping_error(&bp->pdev->dev, mapping))) {
#else
	if (unlikely(dma_mapping_error(mapping))) {
#endif
		/* Move the BD from the consumer to the producer */
		bnx2x_reuse_rx_data(fp, cons, prod);
		tpa_info->tpa_state = BNX2X_TPA_ERROR;
		return;
	}

	/* move empty data from pool to prod */
	prod_rx_buf->data = first_buf->data;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	dma_unmap_addr_set(prod_rx_buf, mapping, mapping);
#else
	pci_unmap_addr_set(prod_rx_buf, mapping, mapping);
#endif
	/* point prod_bd to new data */
	prod_bd->addr_hi = cpu_to_le32(U64_HI(mapping));
	prod_bd->addr_lo = cpu_to_le32(U64_LO(mapping));

	/* move partial skb from cons to pool (don't unmap yet) */
	*first_buf = *cons_rx_buf;

	/* mark bin state as START */
	tpa_info->parsing_flags =
		le16_to_cpu(cqe->pars_flags.flags);
	tpa_info->vlan_tag = le16_to_cpu(cqe->vlan_tag);
	tpa_info->tpa_state = BNX2X_TPA_START;
	tpa_info->len_on_bd = le16_to_cpu(cqe->len_on_bd);
	tpa_info->placement_offset = cqe->placement_offset;
	tpa_info->rxhash = bnx2x_get_rxhash(bp, cqe, &tpa_info->l4_rxhash);
	if (fp->mode == TPA_MODE_GRO) {
		u16 gro_size = le16_to_cpu(cqe->pkt_len_or_gro_seg_len);
		tpa_info->full_page = SGE_PAGES / gro_size * gro_size;
		tpa_info->gro_size = gro_size;
	}

#ifdef BNX2X_STOP_ON_ERROR
	fp->tpa_queue_used |= (1 << queue);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)) /* BNX2X_UPSTREAM */
#ifdef _ASM_GENERIC_INT_L64_H
	DP(NETIF_MSG_RX_STATUS, "fp->tpa_queue_used = 0x%lx\n",
#else
	DP(NETIF_MSG_RX_STATUS, "fp->tpa_queue_used = 0x%llx\n",
#endif
#else
#if defined(__powerpc64__) || defined(_ASM_IA64_TYPES_H)
	DP(NETIF_MSG_RX_STATUS, "fp->tpa_queue_used = 0x%lx\n",
#else
	DP(NETIF_MSG_RX_STATUS, "fp->tpa_queue_used = 0x%llx\n",
#endif
#endif
	   fp->tpa_queue_used);
#endif
}

/* Timestamp option length allowed for TPA aggregation:
 *
 *		nop nop kind length echo val
 */
#define TPA_TSTAMP_OPT_LEN	12
/**
 * bnx2x_set_gro_params - compute GRO values
 *
 * @skb:		packet skb
 * @parsing_flags:	parsing flags from the START CQE
 * @len_on_bd:		total length of the first packet for the
 *			aggregation.
 * @pkt_len:		length of all segments
 *
 * Approximate value of the MSS for this aggregation calculated using
 * the first packet of it.
 * Compute number of aggregated segments, and gso_type.
 */
#ifndef BCM_VLAN /* BNX2X_UPSTREAM */
static void bnx2x_set_gro_params(struct sk_buff *skb, u16 parsing_flags,
				 u16 len_on_bd, unsigned int pkt_len,
				 u16 num_of_coalesced_segs)
#else
static void bnx2x_set_gro_params(struct sk_buff *skb, u16 parsing_flags,
				 u16 len_on_bd, unsigned int pkt_len,
				 u16 num_of_coalesced_segs, struct bnx2x *bp)
#endif
{
	/* TPA aggregation won't have either IP options or TCP options
	 * other than timestamp or IPv6 extension headers.
	 */
	u16 hdrs_len = ETH_HLEN + sizeof(struct tcphdr);

	if (GET_FLAG(parsing_flags, PARSING_FLAGS_OVER_ETHERNET_PROTOCOL) ==
	    PRS_FLAG_OVERETH_IPV6) {
		hdrs_len += sizeof(struct ipv6hdr);
#if !defined(NO_GRO_SUPPORT) || defined(__VMKLNX__)  /* BNX2X_UPSTREAM */
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
#endif
	} else {
		hdrs_len += sizeof(struct iphdr);
#if !defined(NO_GRO_SUPPORT) || defined(__VMKLNX__) /* BNX2X_UPSTREAM */
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
#endif
	}

#if defined(OLD_VLAN) /* ! BNX2X_UPSTREAM */
#ifdef BCM_VLAN
	/* There is VLAN on data, take into an account */
	if ((bp->vlgrp == NULL) && (parsing_flags & PARSING_FLAGS_VLAN))
#else
	if (parsing_flags & PARSING_FLAGS_VLAN)
#endif
		hdrs_len += VLAN_HLEN;
#endif
	/* Check if there was a TCP timestamp, if there is it's will
	 * always be 12 bytes length: nop nop kind length echo val.
	 *
	 * Otherwise FW would close the aggregation.
	 */
	if (parsing_flags & PARSING_FLAGS_TIME_STAMP_EXIST_FLAG)
		hdrs_len += TPA_TSTAMP_OPT_LEN;

	skb_shinfo(skb)->gso_size = len_on_bd - hdrs_len;

#if !defined(__VMKLNX__) && defined(NAPI_GRO_CB) /* BNX2X_UPSTREAM */
	/* tcp_gro_complete() will copy NAPI_GRO_CB(skb)->count
	 * to skb_shinfo(skb)->gso_segs
	 */
	NAPI_GRO_CB(skb)->count = num_of_coalesced_segs;
#endif
}

static int bnx2x_alloc_rx_sge(struct bnx2x *bp, struct bnx2x_fastpath *fp,
			      u16 index, gfp_t gfp_mask)
{
	struct page *page = alloc_pages(gfp_mask, PAGES_PER_SGE_SHIFT);
	struct sw_rx_page *sw_buf = &fp->rx_page_ring[index];
	struct eth_rx_sge *sge = &fp->rx_sge_ring[index];
	dma_addr_t mapping;

	if (unlikely(page == NULL)) {
		BNX2X_ERR("Can't alloc sge\n");
		return -ENOMEM;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	mapping = dma_map_page(&bp->pdev->dev, page, 0,
			       SGE_PAGES, DMA_FROM_DEVICE);
#else
	mapping = pci_map_page(bp->pdev, page, 0,
			       SGE_PAGES, PCI_DMA_FROMDEVICE);
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) /* BNX2X_UPSTREAM */
	if (unlikely(dma_mapping_error(&bp->pdev->dev, mapping))) {
#else
	if (unlikely(dma_mapping_error(mapping))) {
#endif
		__free_pages(page, PAGES_PER_SGE_SHIFT);
		BNX2X_ERR("Can't map sge\n");
		return -ENOMEM;
	}

	sw_buf->page = page;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	dma_unmap_addr_set(sw_buf, mapping, mapping);
#else
	pci_unmap_addr_set(sw_buf, mapping, mapping);
#endif

	sge->addr_hi = cpu_to_le32(U64_HI(mapping));
	sge->addr_lo = cpu_to_le32(U64_LO(mapping));

	return 0;
}

static int bnx2x_fill_frag_skb(struct bnx2x *bp, struct bnx2x_fastpath *fp,
			       struct bnx2x_agg_info *tpa_info,
			       u16 pages,
			       struct sk_buff *skb,
			       struct eth_end_agg_rx_cqe *cqe,
			       u16 cqe_idx)
{
	struct sw_rx_page *rx_pg, old_rx_pg;
	u32 i, frag_len, frag_size;
	int err, j, frag_id = 0;
	u16 len_on_bd = tpa_info->len_on_bd;
	u16 full_page = 0, gro_size = 0;

	frag_size = le16_to_cpu(cqe->pkt_len) - len_on_bd;

	if (fp->mode == TPA_MODE_GRO) {
		gro_size = tpa_info->gro_size;
		full_page = tpa_info->full_page;
	}

	/* This is needed in order to enable forwarding support */
	if (frag_size)
#ifndef BCM_VLAN /* BNX2X_UPSTREAM */
		bnx2x_set_gro_params(skb, tpa_info->parsing_flags, len_on_bd,
				     le16_to_cpu(cqe->pkt_len),
				     le16_to_cpu(cqe->num_of_coalesced_segs));
#else
		bnx2x_set_gro_params(skb, tpa_info->parsing_flags, len_on_bd,
				     le16_to_cpu(cqe->pkt_len),
				     le16_to_cpu(cqe->num_of_coalesced_segs),
				     bp);
#endif

#ifdef BNX2X_STOP_ON_ERROR
	if (pages > min_t(u32, 8, MAX_SKB_FRAGS) * SGE_PAGES) {
		BNX2X_ERR("SGL length is too long: %d. CQE index is %d\n",
			  pages, cqe_idx);
		BNX2X_ERR("cqe->pkt_len = %d\n", cqe->pkt_len);
		bnx2x_panic();
		return -EINVAL;
	}
#endif
	/* Run through the SGL and compose the fragmented skb */
	for (i = 0, j = 0; i < pages; i += PAGES_PER_SGE, j++) {
		u16 sge_idx = RX_SGE(le16_to_cpu(cqe->sgl_or_raw_data.sgl[j]));

		/* FW gives the indices of the SGE as if the ring is an array
		   (meaning that "next" element will consume 2 indices) */
		if (fp->mode == TPA_MODE_GRO)
			frag_len = min_t(u32, frag_size, (u32)full_page);
		else /* LRO */
			frag_len = min_t(u32, frag_size, (u32)SGE_PAGES);

		rx_pg = &fp->rx_page_ring[sge_idx];
		old_rx_pg = *rx_pg;

		/* If we fail to allocate a substitute page, we simply stop
		   where we are and drop the whole packet */
		err = bnx2x_alloc_rx_sge(bp, fp, sge_idx, GFP_ATOMIC);
		if (unlikely(err)) {
			bnx2x_fp_qstats(bp, fp)->rx_skb_alloc_failed++;
			return err;
		}

		/* Unmap the page as we're going to pass it to the stack */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
		dma_unmap_page(&bp->pdev->dev,
			       dma_unmap_addr(&old_rx_pg, mapping),
			       SGE_PAGES, DMA_FROM_DEVICE);
#else
		pci_unmap_page(bp->pdev, pci_unmap_addr(&old_rx_pg, mapping),
			       SGE_PAGES, PCI_DMA_FROMDEVICE);
#endif
		/* Add one frag and update the appropriate fields in the skb */
		if (fp->mode == TPA_MODE_LRO)
			skb_fill_page_desc(skb, j, old_rx_pg.page, 0, frag_len);
		else { /* GRO */
			int rem;
			int offset = 0;
			for (rem = frag_len; rem > 0; rem -= gro_size) {
				int len = rem > gro_size ? gro_size : rem;
				skb_fill_page_desc(skb, frag_id++,
						   old_rx_pg.page, offset, len);
#if !defined(__VMKLNX__) /* BNX2X_UPSTREAM */
				if (offset)
					get_page(old_rx_pg.page);
#endif
				offset += len;
			}
		}

		skb->data_len += frag_len;
		skb->truesize += SGE_PAGES;
		skb->len += frag_len;

		frag_size -= frag_len;
	}

	return 0;
}

#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
static void bnx2x_frag_free(const struct bnx2x_fastpath *fp, void *data)
{
#ifdef BCM_HAS_BUILD_SKB_V2 /* BNX2X_UPSTREAM */
	if (fp->rx_frag_size)
		put_page(virt_to_head_page(data));
	else
#endif
		kfree(data);
}
#endif

#ifndef NO_GRO_SUPPORT /* BNX2X_UPSTREAM */
#ifdef CONFIG_INET
static void bnx2x_gro_ip_csum(struct bnx2x *bp, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th;

	skb_set_transport_header(skb, sizeof(struct iphdr));
	th = tcp_hdr(skb);

#ifdef TCP_V4_CHECK_NEW /* BNX2X_UPSTREAM */
	th->check = ~tcp_v4_check(skb->len - skb_transport_offset(skb),
				  iph->saddr, iph->daddr, 0);
#else
	th->check = ~tcp_v4_check(th, skb->len - skb_transport_offset(skb),
				  iph->saddr, iph->daddr, 0);
#endif
}

static void bnx2x_gro_ipv6_csum(struct bnx2x *bp, struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr *th;

	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	th = tcp_hdr(skb);

	th->check = ~tcp_v6_check(skb->len - skb_transport_offset(skb),
				  &iph->saddr, &iph->daddr, 0);
}

static void bnx2x_gro_csum(struct bnx2x *bp, struct sk_buff *skb,
			    void (*gro_func)(struct bnx2x*, struct sk_buff*))
{
	skb_set_network_header(skb, 0);
	gro_func(bp, skb);
	tcp_gro_complete(skb);
}
#endif
#endif

#ifdef BCM_VLAN /* ! BNX2X_UPSTREAM */
static void bnx2x_vlan_gro_receive(struct bnx2x *bp, struct bnx2x_fastpath *fp,
				   u16 vlan_tag, struct sk_buff *skb)
{
#ifndef NO_GRO_SUPPORT /* BNX2X_UPSTREAM */
#ifdef CONFIG_INET
	if (skb_shinfo(skb)->gso_size) {
		switch (be16_to_cpu(skb->protocol)) {
		case ETH_P_IP:
			bnx2x_gro_csum(bp, skb, bnx2x_gro_ip_csum);
			break;
		case ETH_P_IPV6:
			bnx2x_gro_csum(bp, skb, bnx2x_gro_ipv6_csum);
			break;
		}
	}
#endif
#endif
	vlan_gro_receive(&fp->napi, bp->vlgrp, vlan_tag, skb);
}
#endif

static void bnx2x_gro_receive(struct bnx2x *bp, struct bnx2x_fastpath *fp,
			       struct sk_buff *skb)
{
#ifndef NO_GRO_SUPPORT /* BNX2X_UPSTREAM */
#ifdef CONFIG_INET
	if (skb_shinfo(skb)->gso_size) {
		switch (be16_to_cpu(skb->protocol)) {
		case ETH_P_IP:
			bnx2x_gro_csum(bp, skb, bnx2x_gro_ip_csum);
			break;
		case ETH_P_IPV6:
			bnx2x_gro_csum(bp, skb, bnx2x_gro_ipv6_csum);
			break;
		}
	}
#endif
#endif
	napi_gro_receive(&fp->napi, skb);
}

static void bnx2x_tpa_stop(struct bnx2x *bp, struct bnx2x_fastpath *fp,
			   struct bnx2x_agg_info *tpa_info,
			   u16 pages,
			   struct eth_end_agg_rx_cqe *cqe,
			   u16 cqe_idx)
{
	struct sw_rx_bd *rx_buf = &tpa_info->first_buf;
	u8 pad = tpa_info->placement_offset;
	u16 len = tpa_info->len_on_bd;
	struct sk_buff *skb = NULL;
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	u8 *new_data, *data = rx_buf->data;
#else
	struct sk_buff *new_data, *data = rx_buf->data;
#endif
	u8 old_tpa_state = tpa_info->tpa_state;

	tpa_info->tpa_state = BNX2X_TPA_STOP;

	/* If we there was an error during the handling of the TPA_START -
	 * drop this aggregation.
	 */
	if (old_tpa_state == BNX2X_TPA_ERROR)
		goto drop;

	/* Try to allocate the new data */
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	new_data = bnx2x_frag_alloc(fp, GFP_ATOMIC);
#else
	new_data = netdev_alloc_skb(bp->dev, fp->rx_buf_size);
#endif
	/* Unmap skb in the pool anyway, as we are going to change
	   pool entry status to BNX2X_TPA_STOP even if new skb allocation
	   fails. */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	dma_unmap_single(&bp->pdev->dev, dma_unmap_addr(rx_buf, mapping),
			 fp->rx_buf_size, DMA_FROM_DEVICE);
#else
	pci_unmap_single(bp->pdev, pci_unmap_addr(rx_buf, mapping),
			 fp->rx_buf_size, PCI_DMA_FROMDEVICE);
#endif
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	if (likely(new_data))
#ifdef BCM_HAS_BUILD_SKB_V2 /* BNX2X_UPSTREAM */
		skb = build_skb(data, fp->rx_frag_size);
#else
		skb = build_skb(data);
#endif

	if (likely(skb)) {
#else
	skb = data;

	if (likely(new_data)) {
		prefetch(skb);
		prefetch(((char *)(skb)) + L1_CACHE_BYTES);
#endif
#ifdef BNX2X_STOP_ON_ERROR
		if (pad + len > fp->rx_buf_size) {
			BNX2X_ERR("skb_put is about to fail...  pad %d  len %d  rx_buf_size %d\n",
				  pad, len, fp->rx_buf_size);
			bnx2x_panic();
			return;
		}
#endif

#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		skb_reserve(skb, pad + NET_SKB_PAD);
#else
		skb_reserve(skb, pad);
#endif
		skb_put(skb, len);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
		skb->rxhash = tpa_info->rxhash;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)) /* BNX2X_UPSTREAM */
		skb->l4_rxhash = tpa_info->l4_rxhash;
#endif
#endif

		skb->protocol = eth_type_trans(skb, bp->dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		if (!bnx2x_fill_frag_skb(bp, fp, tpa_info, pages,
					 skb, cqe, cqe_idx)) {
#ifdef BCM_VLAN
			if ((bp->vlgrp != NULL) &&
				(tpa_info->parsing_flags
							& PARSING_FLAGS_VLAN))
				bnx2x_vlan_gro_receive(bp, fp,
						       tpa_info->vlan_tag, skb);
			else
#elif !defined(OLD_VLAN) /* BNX2X_UPSTREAM */
			if (tpa_info->parsing_flags & PARSING_FLAGS_VLAN)
#ifdef VLAN_8021AD_ADDED /* BNX2X_UPSTREAM */
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), tpa_info->vlan_tag);
#else
				__vlan_hwaccel_put_tag(skb, tpa_info->vlan_tag);
#endif
#endif
			bnx2x_gro_receive(bp, fp, skb);
		} else {
			DP(NETIF_MSG_RX_STATUS,
			   "Failed to allocate new pages - dropping packet!\n");
			dev_kfree_skb_any(skb);
		}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)) /* ! BNX2X_UPSTREAM */
		bp->dev->last_rx = jiffies;
#endif

		/* put new data in bin */
		rx_buf->data = new_data;

		return;
	}
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	bnx2x_frag_free(fp, new_data);
#endif
drop:
	/* drop the packet and keep the buffer in the bin */
	DP(NETIF_MSG_RX_STATUS,
	   "Failed to allocate or map a new skb - dropping packet!\n");
	bnx2x_fp_stats(bp, fp)->eth_q_stats.rx_skb_alloc_failed++;
}
#endif

static int bnx2x_alloc_rx_data(struct bnx2x *bp, struct bnx2x_fastpath *fp,
			       u16 index, gfp_t gfp_mask)
{
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	u8 *data;
#else
	struct sk_buff *data;
#endif
	struct sw_rx_bd *rx_buf = &fp->rx_buf_ring[index];
	struct eth_rx_bd *rx_bd = &fp->rx_desc_ring[index];
	dma_addr_t mapping;

#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	data = bnx2x_frag_alloc(fp, gfp_mask);
#else
	data = netdev_alloc_skb(bp->dev, fp->rx_buf_size);
#endif
	if (unlikely(data == NULL))
		return -ENOMEM;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
	mapping = dma_map_single(&bp->pdev->dev, data + NET_SKB_PAD,
				 fp->rx_buf_size,
				 DMA_FROM_DEVICE);
#else
	mapping = dma_map_single(&bp->pdev->dev, data->data, fp->rx_buf_size,
				 DMA_FROM_DEVICE);
#endif
#else /* < 0x020622*/
	mapping = pci_map_single(bp->pdev, data->data, fp->rx_buf_size,
				 PCI_DMA_FROMDEVICE);
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) /* BNX2X_UPSTREAM */
	if (unlikely(dma_mapping_error(&bp->pdev->dev, mapping))) {
#else
	if (unlikely(dma_mapping_error(mapping))) {
#endif
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		bnx2x_frag_free(fp, data);
#else
		dev_kfree_skb_any(data);
#endif
		BNX2X_ERR("Can't map rx data\n");
		return -ENOMEM;
	}

	rx_buf->data = data;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	dma_unmap_addr_set(rx_buf, mapping, mapping);
#else
	pci_unmap_addr_set(rx_buf, mapping, mapping);
#endif

	rx_bd->addr_hi = cpu_to_le32(U64_HI(mapping));
	rx_bd->addr_lo = cpu_to_le32(U64_LO(mapping));

	return 0;
}

#ifdef BNX2X_UPSTREAM /* BNX2X_UPSTREAM */
static
#endif
void bnx2x_csum_validate(struct sk_buff *skb, union eth_rx_cqe *cqe,
				 struct bnx2x_fastpath *fp,
				 struct bnx2x_eth_q_stats *qstats)
{
	/* Do nothing if no L4 csum validation was done.
	 * We do not check whether IP csum was validated. For IPv4 we assume
	 * that if the card got as far as validating the L4 csum, it also
	 * validated the IP csum. IPv6 has no IP csum.
	 */
	if (cqe->fast_path_cqe.status_flags &
	    ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG)
		return;

	/* If L4 validation was done, check if an error was found. */

	if (cqe->fast_path_cqe.type_error_flags &
	    (ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG |
	     ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG))
		qstats->hw_csum_err++;
	else
		skb->ip_summed = CHECKSUM_UNNECESSARY;
}

_UP_STATIC int bnx2x_rx_int(struct bnx2x_fastpath *fp, int budget)
{
	struct bnx2x *bp = fp->bp;
	u16 bd_cons, bd_prod, bd_prod_fw, comp_ring_cons;
	u16 hw_comp_cons, sw_comp_cons, sw_comp_prod;
	int rx_pkt = 0;

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic))
		return 0;
#endif

	/* CQ "next element" is of the size of the regular element,
	   that's why it's ok here */
	hw_comp_cons = le16_to_cpu(*fp->rx_cons_sb);
	if ((hw_comp_cons & MAX_RCQ_DESC_CNT) == MAX_RCQ_DESC_CNT)
		hw_comp_cons++;

	bd_cons = fp->rx_bd_cons;
	bd_prod = fp->rx_bd_prod;
	bd_prod_fw = bd_prod;
	sw_comp_cons = fp->rx_comp_cons;
	sw_comp_prod = fp->rx_comp_prod;

	/* Memory barrier necessary as speculative reads of the rx
	 * buffer can be ahead of the index in the status block
	 */
	rmb();

	DP(NETIF_MSG_RX_STATUS,
	   "queue[%d]:  hw_comp_cons %u  sw_comp_cons %u\n",
	   fp->index, hw_comp_cons, sw_comp_cons);

	while (sw_comp_cons != hw_comp_cons) {
		struct sw_rx_bd *rx_buf = NULL;
		struct sk_buff *skb;
		union eth_rx_cqe *cqe;
		struct eth_fast_path_rx_cqe *cqe_fp;
		u8 cqe_fp_flags;
		enum eth_rx_cqe_type cqe_fp_type;
		u16 len, pad, queue;
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		u8 *data;
#else
		struct sk_buff *data;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)) /* BNX2X_UPSTREAM */
		bool l4_rxhash;
#endif

#ifdef BNX2X_STOP_ON_ERROR
		if (unlikely(bp->panic))
			return 0;
#endif

		comp_ring_cons = RCQ_BD(sw_comp_cons);
		bd_prod = RX_BD(bd_prod);
		bd_cons = RX_BD(bd_cons);

		cqe = &fp->rx_comp_ring[comp_ring_cons];
		cqe_fp = &cqe->fast_path_cqe;
		cqe_fp_flags = cqe_fp->type_error_flags;
		cqe_fp_type = cqe_fp_flags & ETH_FAST_PATH_RX_CQE_TYPE;
#ifdef BNX2X_CHAR_DEV /* ! BNX2X_UPSTREAM */
		cqe_fp->reserved1[7] = 0xFFFFFFFF;
#endif

		DP(NETIF_MSG_RX_STATUS,
		   "CQE type %x  err %x  status %x  queue %x  vlan %x  len %u\n",
		   CQE_TYPE(cqe_fp_flags),
		   cqe_fp_flags, cqe_fp->status_flags,
		   le32_to_cpu(cqe_fp->rss_hash_result),
		   le16_to_cpu(cqe_fp->vlan_tag),
		   le16_to_cpu(cqe_fp->pkt_len_or_gro_seg_len));

		/* is this a slowpath msg? */
		if (unlikely(CQE_TYPE_SLOW(cqe_fp_type))) {
			bnx2x_sp_event(fp, cqe);
			goto next_cqe;
		}

		rx_buf = &fp->rx_buf_ring[bd_cons];
		data = rx_buf->data;
#ifndef BCM_HAS_BUILD_SKB /* ! BNX2X_UPSTREAM */
		prefetch(data);
#endif

#if !defined(__NO_TPA__) /* BNX2X_UPSTREAM */
		if (!CQE_TYPE_FAST(cqe_fp_type)) {
			struct bnx2x_agg_info *tpa_info;
			u16 frag_size, pages;
#ifdef BNX2X_STOP_ON_ERROR
			/* sanity check */
			if (fp->disable_tpa &&
			    (CQE_TYPE_START(cqe_fp_type) ||
			     CQE_TYPE_STOP(cqe_fp_type)))
				BNX2X_ERR("START/STOP packet while disable_tpa type %x\n",
					  CQE_TYPE(cqe_fp_type));
#endif

			if (CQE_TYPE_START(cqe_fp_type)) {
				u16 queue = cqe_fp->queue_index;
				DP(NETIF_MSG_RX_STATUS,
				   "calling tpa_start on queue %d\n",
				   queue);

				bnx2x_tpa_start(fp, queue,
						bd_cons, bd_prod,
						cqe_fp);

				goto next_rx;
			}
			queue = cqe->end_agg_cqe.queue_index;
			tpa_info = &fp->tpa_info[queue];
			DP(NETIF_MSG_RX_STATUS,
			   "calling tpa_stop on queue %d\n",
			   queue);

			frag_size = le16_to_cpu(cqe->end_agg_cqe.pkt_len) -
				    tpa_info->len_on_bd;

			if (fp->mode == TPA_MODE_GRO)
				pages = (frag_size + tpa_info->full_page - 1) /
					 tpa_info->full_page;
			else
				pages = SGE_PAGE_ALIGN(frag_size) >>
					SGE_PAGE_SHIFT;

			bnx2x_tpa_stop(bp, fp, tpa_info, pages,
				       &cqe->end_agg_cqe, comp_ring_cons);
#ifdef BNX2X_STOP_ON_ERROR
			if (bp->panic)
				return 0;
#endif

			bnx2x_update_sge_prod(fp, pages, &cqe->end_agg_cqe);
			goto next_cqe;
		}
#endif
		/* non TPA */
		len = le16_to_cpu(cqe_fp->pkt_len_or_gro_seg_len);
		pad = cqe_fp->placement_offset;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
		dma_sync_single_for_cpu(&bp->pdev->dev,
					dma_unmap_addr(rx_buf, mapping),
					pad + RX_COPY_THRESH,
					DMA_FROM_DEVICE);
#else
		pci_dma_sync_single_for_cpu(bp->pdev,
				pci_unmap_addr(rx_buf, mapping),
					       pad + RX_COPY_THRESH,
					       PCI_DMA_FROMDEVICE);
#endif
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		pad += NET_SKB_PAD;
		prefetch(data + pad); /* speedup eth_type_trans() */
#else
		prefetch(((char *)(data)) + L1_CACHE_BYTES);
#endif
		/* is this an error packet? */
		if (unlikely(cqe_fp_flags & ETH_RX_ERROR_FALGS)) {
			DP(NETIF_MSG_RX_ERR | NETIF_MSG_RX_STATUS,
			   "ERROR  flags %x  rx packet %u\n",
			   cqe_fp_flags, sw_comp_cons);
			bnx2x_fp_qstats(bp, fp)->rx_err_discard_pkt++;
			goto reuse_rx;
		}

		/* Since we don't have a jumbo ring
		 * copy small packets if mtu > 1500
		 */
		if ((bp->dev->mtu > ETH_MAX_PACKET_SIZE) &&
		    (len <= RX_COPY_THRESH)) {
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
			skb = netdev_alloc_skb_ip_align(bp->dev, len);
#else
			skb = netdev_alloc_skb(bp->dev, len + pad);
#endif
			if (skb == NULL) {
				DP(NETIF_MSG_RX_ERR | NETIF_MSG_RX_STATUS,
				   "ERROR  packet dropped because of alloc failure\n");
				bnx2x_fp_qstats(bp, fp)->rx_skb_alloc_failed++;
				goto reuse_rx;
			}
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
			memcpy(skb->data, data + pad, len);
#else
			/* aligned copy */
			skb_copy_from_linear_data_offset(data, pad,
					    skb->data + pad, len);
			skb_reserve(skb, pad);
			data = skb;
#endif
			bnx2x_reuse_rx_data(fp, bd_cons, bd_prod);
		} else {
			if (likely(bnx2x_alloc_rx_data(bp, fp, bd_prod,
						       GFP_ATOMIC) == 0)) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
				dma_unmap_single(&bp->pdev->dev,
						 dma_unmap_addr(rx_buf, mapping),
						 fp->rx_buf_size,
						 DMA_FROM_DEVICE);
#else
				pci_unmap_single(bp->pdev,
					pci_unmap_addr(rx_buf, mapping),
						 fp->rx_buf_size,
						 PCI_DMA_FROMDEVICE);
#endif
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
#ifdef BCM_HAS_BUILD_SKB_V2 /* BNX2X_UPSTREAM */
				skb = build_skb(data, fp->rx_frag_size);
#else
				skb = build_skb(data);
#endif
				if (unlikely(!skb)) {
					bnx2x_frag_free(fp, data);
					bnx2x_fp_qstats(bp, fp)->
							rx_skb_alloc_failed++;
					goto next_rx;
				}
#else
				skb = data;
#endif
				skb_reserve(skb, pad);
			} else {
				DP(NETIF_MSG_RX_ERR | NETIF_MSG_RX_STATUS,
				   "ERROR  packet dropped because of alloc failure\n");
				bnx2x_fp_qstats(bp, fp)->rx_skb_alloc_failed++;
reuse_rx:
				bnx2x_reuse_rx_data(fp, bd_cons, bd_prod);
				goto next_rx;
			}
		}

		skb_put(skb, len);
#if defined(BNX2X_ESX_CNA) /* non BNX2X_UPSTREAM */
		if (IS_FCOE_FP(fp) && bp->cnadev)
			skb->protocol = eth_type_trans(skb, bp->cnadev);
		else
			skb->protocol = eth_type_trans(skb, bp->dev);
#else /* BNX2X_UPSTREAM */
		skb->protocol = eth_type_trans(skb, bp->dev);
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)) /* BNX2X_UPSTREAM */
		/* Set Toeplitz hash for a none-LRO skb */
		skb->rxhash = bnx2x_get_rxhash(bp, cqe_fp, &l4_rxhash);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)) /* BNX2X_UPSTREAM */
		skb->l4_rxhash = l4_rxhash;
#endif
#endif
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 55000) /* ! BNX2X_UPSTREAM */
		BNX2X_ESX_PUT_RSS_INFO(fp, cqe_fp, skb);
#endif
		skb_checksum_none_assert(skb);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)) /* non BNX2X_UPSTREAM */
		if (bp->rx_csum)
#else /* BNX2X_UPSTREAM */
		if (bp->dev->features & NETIF_F_RXCSUM)
#endif
			bnx2x_csum_validate(skb, cqe, fp,
					    bnx2x_fp_qstats(bp, fp));

		skb_record_rx_queue(skb, fp->rx_queue);

#ifdef BCM_PTP /* BNX2X_UPSTREAM */
		/* Check if this packet was timestamped */
		if (unlikely(le16_to_cpu(cqe->fast_path_cqe.type_error_flags) &
			     (1 << ETH_FAST_PATH_RX_CQE_PTP_PKT_SHIFT)))
			bnx2x_set_rx_ts(bp, skb);
#endif

#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
#if defined(BNX2X_ESX_CNA)
		if (IS_FCOE_FP(fp) && bp->cnadev)
			vmknetddi_queueops_set_skb_queueid(skb,
				VMKNETDDI_QUEUEOPS_MK_RX_QUEUEID(1));
		else
#endif
		vmknetddi_queueops_set_skb_queueid(skb,
				VMKNETDDI_QUEUEOPS_MK_RX_QUEUEID(fp->index));
#endif
#ifdef BCM_VLAN
		if ((bp->vlgrp != NULL) &&
		    (le16_to_cpu(cqe_fp->pars_flags.flags) &
		     PARSING_FLAGS_VLAN))
			vlan_gro_receive(&fp->napi, bp->vlgrp,
					 le16_to_cpu(cqe_fp->vlan_tag), skb);
		else
#elif !defined(OLD_VLAN) /* BNX2X_UPSTREAM */
		if (le16_to_cpu(cqe_fp->pars_flags.flags) &
		    PARSING_FLAGS_VLAN)
#ifdef VLAN_8021AD_ADDED /* BNX2X_UPSTREAM */
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       le16_to_cpu(cqe_fp->vlan_tag));
#else
			__vlan_hwaccel_put_tag(skb,
					       le16_to_cpu(cqe_fp->vlan_tag));
#endif
#endif
		napi_gro_receive(&fp->napi, skb);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)) /* ! BNX2X_UPSTREAM */
		bp->dev->last_rx = jiffies;
#endif

next_rx:
		rx_buf->data = NULL;

		bd_cons = NEXT_RX_IDX(bd_cons);
		bd_prod = NEXT_RX_IDX(bd_prod);
		bd_prod_fw = NEXT_RX_IDX(bd_prod_fw);
		rx_pkt++;
next_cqe:
		sw_comp_prod = NEXT_RCQ_IDX(sw_comp_prod);
		sw_comp_cons = NEXT_RCQ_IDX(sw_comp_cons);

		if (rx_pkt == budget)
			break;
	} /* while */

	fp->rx_bd_cons = bd_cons;
	fp->rx_bd_prod = bd_prod_fw;
	fp->rx_comp_cons = sw_comp_cons;
	fp->rx_comp_prod = sw_comp_prod;

	/* Update producers */
	bnx2x_update_rx_prod(bp, fp, bd_prod_fw, sw_comp_prod,
			     fp->rx_sge_prod);

	fp->rx_pkt += rx_pkt;
	fp->rx_calls++;

	return rx_pkt;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)) && (VMWARE_ESX_DDK_VERSION < 40000)
irqreturn_t bnx2x_msix_fp_int(int irq, void *fp_cookie,
				     struct pt_regs *regs)
#else /* BNX2X_UPSTREAM */
_UP_STATIC irqreturn_t bnx2x_msix_fp_int(int irq, void *fp_cookie)
#endif
{
	struct bnx2x_fastpath *fp = fp_cookie;
	struct bnx2x *bp = fp->bp;
	u8 cos;

	DP(NETIF_MSG_INTR,
	   "got an MSI-X interrupt on IDX:SB [fp %d fw_sd %d igusb %d]\n",
	   fp->index, fp->fw_sb_id, fp->igu_sb_id);
	bnx2x_ack_sb(bp, fp->igu_sb_id, USTORM_ID, 0, IGU_INT_DISABLE, 0);

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic))
		return IRQ_HANDLED;
#endif

	/* Handle Rx and Tx according to MSI-X vector */
	prefetch(fp->rx_cons_sb);

	for_each_cos_in_tx_queue(fp, cos)
		prefetch(fp->txdata_ptr[cos]->tx_cons_sb);

	prefetch(&fp->sb_running_index[SM_RX_ID]);
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
	napi_schedule(&bnx2x_fp(bp, fp->index, napi));
#else
	napi_schedule(&bnx2x_fp(bp, fp->index, dummy_netdev));
#endif

	return IRQ_HANDLED;
}

/* HW Lock for shared dual port PHYs */
void bnx2x_acquire_phy_lock(struct bnx2x *bp)
{
	mutex_lock(&bp->port.phy_mutex);

	bnx2x_acquire_hw_lock(bp, HW_LOCK_RESOURCE_MDIO);
}

void bnx2x_release_phy_lock(struct bnx2x *bp)
{
	bnx2x_release_hw_lock(bp, HW_LOCK_RESOURCE_MDIO);

	mutex_unlock(&bp->port.phy_mutex);
}

/* calculates MF speed according to current linespeed and MF configuration */
u16 bnx2x_get_mf_speed(struct bnx2x *bp)
{
	u16 line_speed = bp->link_vars.line_speed;
	if (IS_MF(bp)) {
		u16 maxCfg = bnx2x_extract_max_cfg(bp,
						   bp->mf_config[BP_VN(bp)]);

		/* Calculate the current MAX line speed limit for the MF
		 * devices
		 */
		if (IS_MF_SI(bp))
			line_speed = (line_speed * maxCfg) / 100;
		else { /* SD mode */
			u16 vn_max_rate = maxCfg * 100;

			if (vn_max_rate < line_speed)
				line_speed = vn_max_rate;
		}
	}

	return line_speed;
}

/**
 * bnx2x_fill_report_data - fill link report data to report
 *
 * @bp:		driver handle
 * @data:	link state to update
 *
 * It uses a none-atomic bit operations because is called under the mutex.
 */
static void bnx2x_fill_report_data(struct bnx2x *bp,
				   struct bnx2x_link_report_data *data)
{
	u16 line_speed = bnx2x_get_mf_speed(bp);

	memset(data, 0, sizeof(*data));

	/* Fill the report data: effective line speed */
	data->line_speed = line_speed;

	/* Link is down */
	if (!bp->link_vars.link_up || (bp->flags & MF_FUNC_DIS))
		__set_bit(BNX2X_LINK_REPORT_LINK_DOWN,
			  &data->link_report_flags);

#ifdef BNX2X_CHAR_DEV /* ! BNX2X_UPSTREAM */
	if (!BNX2X_NUM_ETH_QUEUES(bp))
		__set_bit(BNX2X_LINK_REPORT_LINK_DOWN,
			  &data->link_report_flags);
#endif
	/* Full DUPLEX */
	if (bp->link_vars.duplex == DUPLEX_FULL)
		__set_bit(BNX2X_LINK_REPORT_FD, &data->link_report_flags);

	/* Rx Flow Control is ON */
	if (bp->link_vars.flow_ctrl & BNX2X_FLOW_CTRL_RX)
		__set_bit(BNX2X_LINK_REPORT_RX_FC_ON, &data->link_report_flags);

	/* Tx Flow Control is ON */
	if (bp->link_vars.flow_ctrl & BNX2X_FLOW_CTRL_TX)
		__set_bit(BNX2X_LINK_REPORT_TX_FC_ON, &data->link_report_flags);
}

/**
 * bnx2x_link_report - report link status to OS.
 *
 * @bp:		driver handle
 *
 * Calls the __bnx2x_link_report() under the same locking scheme
 * as a link/PHY state managing code to ensure a consistent link
 * reporting.
 */

void bnx2x_link_report(struct bnx2x *bp)
{
	bnx2x_acquire_phy_lock(bp);
	__bnx2x_link_report(bp);
	bnx2x_release_phy_lock(bp);
}

/**
 * __bnx2x_link_report - report link status to OS.
 *
 * @bp:		driver handle
 *
 * None atomic implementation.
 * Should be called under the phy_lock.
 */
void __bnx2x_link_report(struct bnx2x *bp)
{
	struct bnx2x_link_report_data cur_data;

	/* reread mf_cfg */
	if (IS_PF(bp) && !CHIP_IS_E1(bp))
		bnx2x_read_mf_cfg(bp);

	/* Read the current link report info */
	bnx2x_fill_report_data(bp, &cur_data);

	/* Don't report link down or exactly the same link status twice */
	if (!memcmp(&cur_data, &bp->last_reported_link, sizeof(cur_data)) ||
	    (test_bit(BNX2X_LINK_REPORT_LINK_DOWN,
		      &bp->last_reported_link.link_report_flags) &&
	     test_bit(BNX2X_LINK_REPORT_LINK_DOWN,
		      &cur_data.link_report_flags)))
		return;

	bp->link_cnt++;

	/* We are going to report a new link parameters now -
	 * remember the current data for the next time.
	 */
	memcpy(&bp->last_reported_link, &cur_data, sizeof(cur_data));

	if (test_bit(BNX2X_LINK_REPORT_LINK_DOWN,
		     &cur_data.link_report_flags)) {
		netif_carrier_off(bp->dev);
#if defined(BNX2X_ESX_CNA) /* ! BNX2X_UPSTREAM */
		if (bp->flags & CNA_ENABLED)
			netif_carrier_off(bp->cnadev);
#endif
		netdev_err(bp->dev, "NIC Link is Down\n");
		return;
	} else {
		const char *duplex;
		const char *flow;

		netif_carrier_on(bp->dev);
#if defined(BNX2X_ESX_CNA) /* ! BNX2X_UPSTREAM */
		if (bp->flags & CNA_ENABLED)
			netif_carrier_on(bp->cnadev);
#endif

		if (test_and_clear_bit(BNX2X_LINK_REPORT_FD,
				       &cur_data.link_report_flags))
			duplex = "full";
		else
			duplex = "half";

		/* Handle the FC at the end so that only these flags would be
		 * possibly set. This way we may easily check if there is no FC
		 * enabled.
		 */
		if (cur_data.link_report_flags) {
			if (test_bit(BNX2X_LINK_REPORT_RX_FC_ON,
				     &cur_data.link_report_flags)) {
				if (test_bit(BNX2X_LINK_REPORT_TX_FC_ON,
				     &cur_data.link_report_flags))
					flow = "ON - receive & transmit";
				else
					flow = "ON - receive";
			} else {
				flow = "ON - transmit";
			}
		} else {
			flow = "none";
		}
		netdev_info(bp->dev, "NIC Link is Up, %d Mbps %s duplex, Flow control: %s\n",
			    cur_data.line_speed, duplex, flow);
	}
}

static void bnx2x_set_next_page_sgl(struct bnx2x_fastpath *fp)
{
	int i;

	for (i = 1; i <= NUM_RX_SGE_PAGES; i++) {
		struct eth_rx_sge *sge;

		sge = &fp->rx_sge_ring[RX_SGE_CNT * i - 2];
		sge->addr_hi =
			cpu_to_le32(U64_HI(fp->rx_sge_mapping +
			BCM_PAGE_SIZE*(i % NUM_RX_SGE_PAGES)));

		sge->addr_lo =
			cpu_to_le32(U64_LO(fp->rx_sge_mapping +
			BCM_PAGE_SIZE*(i % NUM_RX_SGE_PAGES)));
	}
}

static void bnx2x_free_tpa_pool(struct bnx2x *bp,
				struct bnx2x_fastpath *fp, int last)
{
	int i;

	for (i = 0; i < last; i++) {
		struct bnx2x_agg_info *tpa_info = &fp->tpa_info[i];
		struct sw_rx_bd *first_buf = &tpa_info->first_buf;
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		u8 *data = first_buf->data;
#else
		struct sk_buff *data = first_buf->data;
#endif

		if (data == NULL) {
			DP(NETIF_MSG_IFDOWN, "tpa bin %d empty on free\n", i);
			continue;
		}
		if (tpa_info->tpa_state == BNX2X_TPA_START)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
			dma_unmap_single(&bp->pdev->dev,
					 dma_unmap_addr(first_buf, mapping),
					 fp->rx_buf_size, DMA_FROM_DEVICE);
#else
			pci_unmap_single(bp->pdev,
					 pci_unmap_addr(first_buf, mapping),
					 fp->rx_buf_size, PCI_DMA_FROMDEVICE);
#endif
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		bnx2x_frag_free(fp, data);
#else
		dev_kfree_skb(data);
#endif
		first_buf->data = NULL;
	}
}

void bnx2x_init_rx_rings_cnic(struct bnx2x *bp)
{
	int j;

	for_each_rx_queue_cnic(bp, j) {
		struct bnx2x_fastpath *fp = &bp->fp[j];

		fp->rx_bd_cons = 0;

		/* Activate BD ring */
		/* Warning!
		 * this will generate an interrupt (to the TSTORM)
		 * must only be done after chip is initialized
		 */
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		if (IS_OOO_FP(fp))
			bnx2x_update_ooo_prod(bp, fp, fp->rx_bd_prod,
					      fp->rx_comp_prod,
					      fp->rx_sge_prod);
		else
#endif
		bnx2x_update_rx_prod(bp, fp, fp->rx_bd_prod, fp->rx_comp_prod,
				     fp->rx_sge_prod);
	}
}

#if (!defined(__VMKLNX__) || !DYNAMIC_NETQ_ALLOC) /* BNX2X_UPSTREAM */
int bnx2x_init_rx_rings(struct bnx2x *bp)
#else
int bnx2x_esx_init_rx_ring(struct bnx2x *bp, int esx_netq_index)
#endif
{
	int func = BP_FUNC(bp);
	u16 ring_prod;
	int i, j, rc = 0;

	/* Allocate TPA resources */
	for_each_eth_queue_(bp, j) {
		struct bnx2x_fastpath *fp = &bp->fp[j];

		DP(NETIF_MSG_IFUP,
		   "mtu %d  rx_buf_size %d\n", bp->dev->mtu, fp->rx_buf_size);

		if (!fp->disable_tpa) {
			/* Fill the per-aggregation pool */
			for (i = 0; i < MAX_AGG_QS(bp); i++) {
				struct bnx2x_agg_info *tpa_info =
					&fp->tpa_info[i];
				struct sw_rx_bd *first_buf =
					&tpa_info->first_buf;

#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
				first_buf->data =
					bnx2x_frag_alloc(fp, GFP_KERNEL);
#else
				first_buf->data = netdev_alloc_skb(bp->dev,
						       fp->rx_buf_size);
#endif
				if (!first_buf->data) {
					BNX2X_ERR("Failed to allocate TPA skb pool for queue[%d] - disabling TPA on this queue!\n",
						  j);
					bnx2x_free_tpa_pool(bp, fp, i);
					fp->disable_tpa = 1;
					rc = -EIO;
					break;
				}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
				dma_unmap_addr_set(first_buf, mapping, 0);
#else
				pci_unmap_addr_set(first_buf, mapping, 0);
#endif
				tpa_info->tpa_state = BNX2X_TPA_STOP;
			}

			/* "next page" elements initialization */
			bnx2x_set_next_page_sgl(fp);

			/* set SGEs bit mask */
			bnx2x_init_sge_ring_bit_mask(fp);

			/* Allocate SGEs and initialize the ring elements */
			for (i = 0, ring_prod = 0;
			     i < MAX_RX_SGE_CNT*NUM_RX_SGE_PAGES; i++) {

				if (bnx2x_alloc_rx_sge(bp, fp, ring_prod,
						       GFP_KERNEL) < 0) {
					BNX2X_ERR("was only able to allocate %d rx sges\n",
						  i);
					BNX2X_ERR("disabling TPA for queue[%d]\n",
						  j);
					/* Cleanup already allocated elements */
					bnx2x_free_rx_sge_range(bp, fp,
								ring_prod);
					bnx2x_free_tpa_pool(bp, fp,
							    MAX_AGG_QS(bp));
					fp->disable_tpa = 1;
					ring_prod = 0;
					rc = -EIO;
					break;
				}
				ring_prod = NEXT_SGE_IDX(ring_prod);
			}

			fp->rx_sge_prod = ring_prod;
		}
	}

	for_each_eth_queue_(bp, j) {
		struct bnx2x_fastpath *fp = &bp->fp[j];

		fp->rx_bd_cons = 0;

		/* Activate BD ring */
		/* Warning!
		 * this will generate an interrupt (to the TSTORM)
		 * must only be done after chip is initialized
		 */
		bnx2x_update_rx_prod(bp, fp, fp->rx_bd_prod, fp->rx_comp_prod,
				     fp->rx_sge_prod);

		if (j != 0)
			continue;

		if (CHIP_IS_E1(bp)) {
			REG_WR(bp, BAR_USTRORM_INTMEM +
			       USTORM_MEM_WORKAROUND_ADDRESS_OFFSET(func),
			       U64_LO(fp->rx_comp_mapping));
			REG_WR(bp, BAR_USTRORM_INTMEM +
			       USTORM_MEM_WORKAROUND_ADDRESS_OFFSET(func) + 4,
			       U64_HI(fp->rx_comp_mapping));
		}
	}
	return rc;
}

_STAEU void bnx2x_free_tx_skbs_queue(struct bnx2x_fastpath *fp)
{
	u8 cos;
	struct bnx2x *bp = fp->bp;

	for_each_cos_in_tx_queue(fp, cos) {
		struct bnx2x_fp_txdata *txdata = fp->txdata_ptr[cos];
		unsigned pkts_compl = 0, bytes_compl = 0;

		u16 sw_prod = txdata->tx_pkt_prod;
		u16 sw_cons = txdata->tx_pkt_cons;

		while (sw_cons != sw_prod) {
			bnx2x_free_tx_pkt(bp, txdata, TX_BD(sw_cons),
					  &pkts_compl, &bytes_compl);
			sw_cons++;
		}
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		if (txdata_has_netdev_queue(txdata))
#endif

		netdev_tx_reset_queue(
			netdev_get_tx_queue(bp->dev,
					    txdata->txq_index));
	}
}

static void bnx2x_free_tx_skbs_cnic(struct bnx2x *bp)
{
	int i;

	for_each_tx_queue_cnic(bp, i) {
		bnx2x_free_tx_skbs_queue(&bp->fp[i]);
	}
}

static void bnx2x_free_tx_skbs(struct bnx2x *bp)
{
	int i;

	for_each_eth_queue(bp, i) {
		bnx2x_free_tx_skbs_queue(&bp->fp[i]);
	}
}

_STAEU void bnx2x_free_rx_bds(struct bnx2x_fastpath *fp)
{
	struct bnx2x *bp = fp->bp;
	int i;

	/* ring wasn't allocated */
	if (fp->rx_buf_ring == NULL)
		return;

	for (i = 0; i < NUM_RX_BD; i++) {
		struct sw_rx_bd *rx_buf = &fp->rx_buf_ring[i];
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		u8 *data = rx_buf->data;
#elif defined(__VMKLNX__) /* !BNX2X_UPSTREAM */
		struct sk_buff *data = NULL;

		/* by swapping out rx_buf->data in an atomic operation,
		 * we can accomodate multiple threads calling
		 * bnx2x_free_rx_bds (in case of dynamic netq alloc)
		 */
		data = __sync_val_compare_and_swap(&rx_buf->data,
			rx_buf->data, data);
#else
		struct sk_buff *data = rx_buf->data;
#endif

		if (data == NULL)
			continue;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
		dma_unmap_single(&bp->pdev->dev,
				 dma_unmap_addr(rx_buf, mapping),
				 fp->rx_buf_size, DMA_FROM_DEVICE);
#else
		pci_unmap_single(bp->pdev,
				 pci_unmap_addr(rx_buf, mapping),
				 fp->rx_buf_size, PCI_DMA_FROMDEVICE);
#endif

		rx_buf->data = NULL;
#ifdef BCM_HAS_BUILD_SKB /* BNX2X_UPSTREAM */
		bnx2x_frag_free(fp, data);
#else
		dev_kfree_skb(data);
#endif
	}
}

static void bnx2x_free_rx_skbs_cnic(struct bnx2x *bp)
{
	int j;

	for_each_rx_queue_cnic(bp, j) {
		bnx2x_free_rx_bds(&bp->fp[j]);
	}
}

#if (!defined(__VMKLNX__) || !DYNAMIC_NETQ_ALLOC) /* BNX2X_UPSTREAM */
static void bnx2x_free_rx_skbs(struct bnx2x *bp)
#else
void bnx2x_esx_free_rx_skbs_queue(struct bnx2x *bp, int esx_netq_index)
#endif
{
	int j;

	for_each_eth_queue_(bp, j) {
		struct bnx2x_fastpath *fp = &bp->fp[j];

		bnx2x_free_rx_bds(fp);

		if (!fp->disable_tpa)
			bnx2x_free_tpa_pool(bp, fp, MAX_AGG_QS(bp));
	}
}

static void bnx2x_free_skbs_cnic(struct bnx2x *bp)
{
	bnx2x_free_tx_skbs_cnic(bp);
	bnx2x_free_rx_skbs_cnic(bp);
}

void bnx2x_free_skbs(struct bnx2x *bp)
{
	bnx2x_free_tx_skbs(bp);
	bnx2x_free_rx_skbs(bp);
}

void bnx2x_update_max_mf_config(struct bnx2x *bp, u32 value)
{
	/* load old values */
	u32 mf_cfg = bp->mf_config[BP_VN(bp)];

	if (value != bnx2x_extract_max_cfg(bp, mf_cfg)) {
		/* leave all but MAX value */
		mf_cfg &= ~FUNC_MF_CFG_MAX_BW_MASK;

		/* set new MAX value */
		mf_cfg |= (value << FUNC_MF_CFG_MAX_BW_SHIFT)
				& FUNC_MF_CFG_MAX_BW_MASK;

		bnx2x_fw_command(bp, DRV_MSG_CODE_SET_MF_BW, mf_cfg);
	}
}

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
static void bnx2x_free_msix_irqs_cnic(struct bnx2x *bp)
{
	int offset = 0;

	/* VFs don't have a default SB */
	if (IS_PF(bp))
		offset++;

	if (bp->flags & OWN_CNIC_IRQ) {
		DP(NETIF_MSG_IFDOWN, "about to release CNIC irq\n");
		free_irq(bp->msix_table[offset].vector, bnx2x_ooo_fp(bp));
		bp->flags &= ~OWN_CNIC_IRQ;
	}
}
#endif
/**
 * bnx2x_free_msix_irqs - free previously requested MSI-X IRQ vectors
 *
 * @bp:		driver handle
 * @nvecs:	number of vectors to be released
 */
static void bnx2x_free_msix_irqs(struct bnx2x *bp, int nvecs)
{
	int i, offset = 0;

	if (nvecs == offset)
		return;

	/* VFs don't have a default SB */
	if (IS_PF(bp)) {
		free_irq(bp->msix_table[offset].vector, bp->dev);
		DP(NETIF_MSG_IFDOWN, "released sp irq (%d)\n",
		   bp->msix_table[offset].vector);
		offset++;
	}

	if (CNIC_SUPPORT(bp)) {
		if (nvecs == offset)
			return;
		offset++;
	}

	for_each_eth_queue(bp, i) {
		if (nvecs == offset)
			return;
		DP(NETIF_MSG_IFDOWN, "about to release fp #%d->%d irq\n",
		   i, bp->msix_table[offset].vector);

		free_irq(bp->msix_table[offset++].vector, &bp->fp[i]);
	}
}

void bnx2x_free_irq(struct bnx2x *bp)
{
	if (bp->flags & USING_MSIX_FLAG &&
	    !(bp->flags & USING_SINGLE_MSIX_FLAG)) {
		int nvecs = BNX2X_NUM_ETH_QUEUES(bp) + CNIC_SUPPORT(bp);

		/* vfs don't have a default status block */
		if (IS_PF(bp))
			nvecs++;

		bnx2x_free_msix_irqs(bp, nvecs);
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		if (CNIC_LOADED(bp) && !NO_ISCSI_OOO(bp))
			bnx2x_free_msix_irqs_cnic(bp);
#endif
	} else {
		free_irq(bp->dev->irq, bp->dev);
	}
}

int bnx2x_enable_msix(struct bnx2x *bp)
{
	int msix_vec = 0, i, rc;

	/* VFs don't have a default status block */
	if (IS_PF(bp)) {
		bp->msix_table[msix_vec].entry = msix_vec;
		BNX2X_DEV_INFO("msix_table[0].entry = %d (slowpath)\n",
			       bp->msix_table[0].entry);
		msix_vec++;
	}

	/* Cnic requires an msix vector for itself */
	if (CNIC_SUPPORT(bp)) {
		bp->msix_table[msix_vec].entry = msix_vec;
		BNX2X_DEV_INFO("msix_table[%d].entry = %d (CNIC)\n",
			       msix_vec, bp->msix_table[msix_vec].entry);
		msix_vec++;
	}

	/* We need separate vectors for ETH queues only (not FCoE) */
	for_each_eth_queue(bp, i) {
		bp->msix_table[msix_vec].entry = msix_vec;
		BNX2X_DEV_INFO("msix_table[%d].entry = %d (fastpath #%u)\n",
			       msix_vec, msix_vec, i);
		msix_vec++;
	}

	DP(BNX2X_MSG_SP, "about to request enable msix with %d vectors\n",
	   msix_vec);

	rc = pci_enable_msix(bp->pdev, &bp->msix_table[0], msix_vec);

	/*
	 * reconfigure number of tx/rx queues according to available
	 * MSI-X vectors
	 */
	if (rc >= BNX2X_MIN_MSIX_VEC_CNT(bp)) {
		/* how less vectors we will have? */
		int diff = msix_vec - rc;

		BNX2X_DEV_INFO("Trying to use less MSI-X vectors: %d\n", rc);

		rc = pci_enable_msix(bp->pdev, &bp->msix_table[0], rc);

		if (rc) {
			BNX2X_DEV_INFO("MSI-X is not attainable rc %d\n", rc);
			goto no_msix;
		}
		/*
		 * decrease number of queues by number of unallocated entries
		 */
		bp->num_ethernet_queues -= diff;
		bp->num_queues = bp->num_ethernet_queues + bp->num_cnic_queues;

		BNX2X_DEV_INFO("New queue configuration set: %d\n",
			       bp->num_queues);
	} else if (rc > 0) {
		/* Get by with single vector */
		rc = pci_enable_msix(bp->pdev, &bp->msix_table[0], 1);
		if (rc) {
			BNX2X_DEV_INFO("Single MSI-X is not attainable rc %d\n",
				       rc);
			goto no_msix;
		}

		BNX2X_DEV_INFO("Using single MSI-X vector\n");
		bp->flags |= USING_SINGLE_MSIX_FLAG;

		BNX2X_DEV_INFO("set number of queues to 1\n");
		bp->num_ethernet_queues = 1;
		bp->num_queues = bp->num_ethernet_queues + bp->num_cnic_queues;
	} else if (rc < 0) {
		BNX2X_DEV_INFO("MSI-X is not attainable  rc %d\n", rc);
		goto no_msix;
	}

	bp->flags |= USING_MSIX_FLAG;

	return 0;

no_msix:
#if defined(CONFIG_XEN) /* ! BNX2X_UPSTREAM */
	/*
	 * XEN kernel is enabling the MSIX capability in any case during call
	 * to pci_enable_msix() - but there is no way to disable it back in
	 * case of failure.
	 */
	bnx2x_msix_set_enable(bp->pdev, false);
#endif
	/* fall to INTx if not enough memory */
	if (rc == -ENOMEM)
		bp->flags |= DISABLE_MSI_FLAG;

	return rc;
}

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
static int bnx2x_req_msix_irqs_cnic(struct bnx2x *bp)
{
	int rc, offset = 0;

	/* no default status block for vf */
	if (IS_PF(bp))
		offset++;

	if (!NO_ISCSI_OOO(bp)) {
		snprintf(bnx2x_ooo(bp, name),
			 sizeof(bnx2x_ooo(bp, name)),
			 "%s-fp-ooo", bp->dev->name);
		rc = request_irq(bp->msix_table[offset].vector,
					 bnx2x_msix_fp_int, 0,
				 bnx2x_ooo(bp, name), bnx2x_ooo_fp(bp));
		if (rc) {
			BNX2X_ERR("request for cnic irq (%d) failed  rc %d\n",
				  bp->msix_table[offset].vector, rc);
			bnx2x_free_msix_irqs(bp, offset);
			return -EBUSY;
		}
		bp->flags |= OWN_CNIC_IRQ;
	}

	return 0;
}
#endif

static int bnx2x_req_msix_irqs(struct bnx2x *bp)
{
	int i, rc, offset = 0;

	/* no default status block for vf */
	if (IS_PF(bp)) {
		rc = request_irq(bp->msix_table[offset++].vector,
				 bnx2x_msix_sp_int, 0,
				 bp->dev->name, bp->dev);
		if (rc) {
			BNX2X_ERR("request sp irq failed\n");
			return -EBUSY;
		}
	}

	if (CNIC_SUPPORT(bp))
		offset++;

	for_each_eth_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];
		snprintf(fp->name, sizeof(fp->name), "%s-fp-%d",
			 bp->dev->name, i);

		rc = request_irq(bp->msix_table[offset].vector,
				 bnx2x_msix_fp_int, 0, fp->name, fp);
		if (rc) {
			BNX2X_ERR("request fp #%d irq (%d) failed  rc %d\n", i,
			      bp->msix_table[offset].vector, rc);
			bnx2x_free_msix_irqs(bp, offset);
			return -EBUSY;
		}

		offset++;
	}

	i = BNX2X_NUM_ETH_QUEUES(bp);
	if (IS_PF(bp)) {
		offset = 1 + CNIC_SUPPORT(bp);
		netdev_info(bp->dev,
			    "using MSI-X  IRQs: sp %d  fp[%d] %d ... fp[%d] %d\n",
			    bp->msix_table[0].vector,
			    0, bp->msix_table[offset].vector,
			    i - 1, bp->msix_table[offset + i - 1].vector);
	} else {
		offset = CNIC_SUPPORT(bp);
		netdev_info(bp->dev,
			    "using MSI-X  IRQs: fp[%d] %d ... fp[%d] %d\n",
			    0, bp->msix_table[offset].vector,
			    i - 1, bp->msix_table[offset + i - 1].vector);
	}
	return 0;
}

int bnx2x_enable_msi(struct bnx2x *bp)
{
	int rc;

	rc = pci_enable_msi(bp->pdev);
	if (rc) {
		BNX2X_DEV_INFO("MSI is not attainable\n");
		return -1;
	}
	bp->flags |= USING_MSI_FLAG;

	return 0;
}

_UP_STATIC int bnx2x_req_irq(struct bnx2x *bp)
{
	unsigned long flags;
	unsigned int irq;

	if (bp->flags & (USING_MSI_FLAG | USING_MSIX_FLAG))
		flags = 0;
	else
		flags = IRQF_SHARED;

	if (bp->flags & USING_MSIX_FLAG)
		irq = bp->msix_table[0].vector;
	else
		irq = bp->pdev->irq;

	return request_irq(irq, bnx2x_interrupt, flags, bp->dev->name, bp->dev);
}

static int bnx2x_setup_irqs(struct bnx2x *bp)
{
	int rc = 0;
	if (bp->flags & USING_MSIX_FLAG &&
	    !(bp->flags & USING_SINGLE_MSIX_FLAG)) {
		rc = bnx2x_req_msix_irqs(bp);
		if (rc)
			return rc;
	} else {
		rc = bnx2x_req_irq(bp);
		if (rc) {
			BNX2X_ERR("IRQ request failed  rc %d, aborting\n", rc);
			return rc;
		}
		if (bp->flags & USING_MSI_FLAG) {
			bp->dev->irq = bp->pdev->irq;
			netdev_info(bp->dev, "using MSI IRQ %d\n",
				    bp->dev->irq);
		}
		if (bp->flags & USING_MSIX_FLAG) {
			bp->dev->irq = bp->msix_table[0].vector;
			netdev_info(bp->dev, "using MSIX IRQ %d\n",
				    bp->dev->irq);
		}
	}

	return 0;
}

static void bnx2x_napi_enable_cnic(struct bnx2x *bp)
{
	int i;

	for_each_rx_queue_cnic(bp, i)
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
		napi_enable(&bnx2x_fp(bp, i, napi));
#else
		netif_poll_enable(&bnx2x_fp(bp, i, dummy_netdev));
#endif
}

static void bnx2x_napi_enable(struct bnx2x *bp)
{
	int i;

	for_each_eth_queue(bp, i)
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
		napi_enable(&bnx2x_fp(bp, i, napi));
#else
		netif_poll_enable(&bnx2x_fp(bp, i, dummy_netdev));
#endif
}

static void bnx2x_napi_disable_cnic(struct bnx2x *bp)
{
	int i;

	for_each_rx_queue_cnic(bp, i)
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
		napi_disable(&bnx2x_fp(bp, i, napi));
#else
		netif_poll_disable(&bnx2x_fp(bp, i, dummy_netdev));
#endif
}

static void bnx2x_napi_disable(struct bnx2x *bp)
{
	int i;

	for_each_eth_queue(bp, i)
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
		napi_disable(&bnx2x_fp(bp, i, napi));
#else
		netif_poll_disable(&bnx2x_fp(bp, i, dummy_netdev));
#endif
}

void bnx2x_netif_start(struct bnx2x *bp)
{
	if (netif_running(bp->dev)) {
		bnx2x_napi_enable(bp);
		if (CNIC_LOADED(bp))
			bnx2x_napi_enable_cnic(bp);
		bnx2x_int_enable(bp);
		if (bp->state == BNX2X_STATE_OPEN) {
			netif_tx_wake_all_queues(bp->dev);
#if defined(BNX2X_ESX_CNA) /* ! BNX2X_UPSTREAM */
			if ((bp->flags & CNA_ENABLED) &&
			    BNX2X_IS_NETQ_TX_QUEUE_ALLOCATED(
				    bnx2x_fcoe_fp(bp)))
				netif_tx_wake_all_queues(bp->cnadev);
#endif
		}
	}
}

void bnx2x_netif_stop(struct bnx2x *bp, int disable_hw)
{
	bnx2x_int_disable_sync(bp, disable_hw);
#if defined(BNX2X_NEW_NAPI) || defined(USE_NAPI_GRO) /* BNX2X_UPSTREAM */
	bnx2x_napi_disable(bp);
	if (CNIC_LOADED(bp))
		bnx2x_napi_disable_cnic(bp);
#else
	if (netif_running(bp->dev)) {
		bnx2x_napi_disable(bp);
		if (CNIC_LOADED(bp))
			bnx2x_napi_disable_cnic(bp);
	}
#endif
}

#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
#if (LINUX_STARTING_AT_VERSION(3, 13, 0)) /* BNX2X_UPSTREAM */
u16 bnx2x_select_queue(struct net_device *dev, struct sk_buff *skb,
			void *accel_priv)
#else
u16 bnx2x_select_queue(struct net_device *dev, struct sk_buff *skb)
#endif
{
	struct bnx2x *bp = netdev_priv(dev);

	if (CNIC_LOADED(bp) && !NO_FCOE(bp)) {
		struct ethhdr *hdr = (struct ethhdr *)skb->data;
		u16 ether_type = ntohs(hdr->h_proto);

		/* Skip VLAN tag if present */
		if (ether_type == ETH_P_8021Q) {
			struct vlan_ethhdr *vhdr =
				(struct vlan_ethhdr *)skb->data;

			ether_type = ntohs(vhdr->h_vlan_encapsulated_proto);
		}

		/* If ethertype is FCoE or FIP - use FCoE ring */
		if ((ether_type == ETH_P_FCOE) || (ether_type == ETH_P_FIP))
			return bnx2x_fcoe_tx(bp, txq_index);
	}

	/* select a non-FCoE queue */
#ifdef BNX2X_COMPAT_NETDEV_PICK_TX /* BNX2X_UPSTREAM */
	return __netdev_pick_tx(dev, skb) % BNX2X_NUM_ETH_QUEUES(bp);
#else
	return __skb_tx_hash(dev, skb, BNX2X_NUM_ETH_QUEUES(bp));
#endif
}
#endif

void bnx2x_set_num_queues(struct bnx2x *bp)
{
	/* RSS queues */
	bp->num_ethernet_queues = bnx2x_calc_num_queues(bp);

	/* override in STORAGE SD modes */
	if (IS_MF_STORAGE_ONLY(bp))
		bp->num_ethernet_queues = 1;

	/* Add special queues */
	bp->num_cnic_queues = CNIC_SUPPORT(bp); /* For FCOE */
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	bp->num_cnic_queues += 2 * CNIC_SUPPORT(bp); /* For iSCSI OOO & FWD */
		DP(BNX2X_MSG_SP, "num_queues set to %d:\n", bp->num_queues);
#endif
	bp->num_queues = bp->num_ethernet_queues + bp->num_cnic_queues;

	BNX2X_DEV_INFO("set number of queues to %d\n", bp->num_queues);
}

/**
 * bnx2x_set_real_num_queues - configure netdev->real_num_[tx,rx]_queues
 *
 * @bp:		Driver handle
 *
 * We currently support for at most 16 Tx queues for each CoS thus we will
 * allocate a multiple of 16 for ETH L2 rings according to the value of the
 * bp->max_cos.
 *
 * If there is an FCoE L2 queue the appropriate Tx queue will have the next
 * index after all ETH L2 indices.
 *
 * If the actual number of Tx queues (for each CoS) is less than 16 then there
 * will be the holes at the end of each group of 16 ETh L2 indices (0..15,
 * 16..31,...) with indices that are not coupled with any real Tx queue.
 *
 * The proper configuration of skb->queue_mapping is handled by
 * bnx2x_select_queue() and __skb_tx_hash().
 *
 * bnx2x_setup_tc() takes care of the proper TC mappings so that __skb_tx_hash()
 * will return a proper Tx index if TC is enabled (netdev->num_tc > 0).
 */
static int bnx2x_set_real_num_queues(struct bnx2x *bp, int include_cnic)
{
	int rc, tx, rx;

	tx = BNX2X_NUM_ETH_QUEUES(bp) * bp->max_cos;
	rx = BNX2X_NUM_ETH_QUEUES(bp);

/* account for fcoe queue */
	if (include_cnic && !NO_FCOE(bp)) {
		rx++;
		tx++;
	}

#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)) /* BNX2X_UPSTREAM */
	rc = netif_set_real_num_tx_queues(bp->dev, tx);
	if (rc) {
		BNX2X_ERR("Failed to set real number of Tx queues: %d\n", rc);
		return rc;
	}
#else
	netif_set_real_num_tx_queues(bp->dev, tx);
#endif
#endif
	rc = netif_set_real_num_rx_queues(bp->dev, rx);
	if (rc) {
		BNX2X_ERR("Failed to set real number of Rx queues: %d\n", rc);
		return rc;
	}

	DP(NETIF_MSG_IFUP, "Setting real num queues to (tx, rx) (%d, %d)\n",
			  tx, rx);

	return rc;
}

static void bnx2x_set_rx_buf_size(struct bnx2x *bp)
{
	int i;

	for_each_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];
		u32 mtu;

		/* Always use a mini-jumbo MTU for the FCoE L2 ring */
		if (IS_FCOE_IDX(i))
			/*
			 * Although there are no IP frames expected to arrive to
			 * this ring we still want to add an
			 * IP_HEADER_ALIGNMENT_PADDING to prevent a buffer
			 * overrun attack.
			 */
			mtu = BNX2X_FCOE_MINI_JUMBO_MTU;
		else
			mtu = bp->dev->mtu;
		fp->rx_buf_size = BNX2X_FW_RX_ALIGN_START +
				  IP_HEADER_ALIGNMENT_PADDING +
				  ETH_OVREHEAD +
				  mtu +
				  BNX2X_FW_RX_ALIGN_END;
#ifdef BCM_HAS_BUILD_SKB_V2 /* BNX2X_UPSTREAM */
		/* Note : rx_buf_size doesn't take into account NET_SKB_PAD */
		if (fp->rx_buf_size + NET_SKB_PAD <= PAGE_SIZE)
			fp->rx_frag_size = fp->rx_buf_size + NET_SKB_PAD;
		else
			fp->rx_frag_size = 0;
#endif
	}
}

#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
static int bnx2x_init_rss(struct bnx2x *bp)
{
	int i;
	u8 num_eth_queues = BNX2X_NUM_ETH_QUEUES(bp);

	/* Prepare the initial contents for the indirection table if RSS is
	 * enabled
	 */
	for (i = 0; i < sizeof(bp->rss_conf_obj.ind_table); i++)
		bp->rss_conf_obj.ind_table[i] =
			bp->fp->cl_id +
			ethtool_rxfh_indir_default(i, num_eth_queues);

	/*
	 * For 57710 and 57711 SEARCHER configuration (rss_keys) is
	 * per-port, so if explicit configuration is needed , do it only
	 * for a PMF.
	 *
	 * For 57712 and newer on the other hand it's a per-function
	 * configuration.
	 */
	return bnx2x_config_rss_eth(bp, bp->port.pmf || !CHIP_IS_E1x(bp));
}

int bnx2x_rss(struct bnx2x *bp, struct bnx2x_rss_config_obj *rss_obj,
	      bool config_hash, bool enable)
{
	struct bnx2x_config_rss_params params = {NULL};

	/* Although RSS is meaningless when there is a single HW queue we
	 * still need it enabled in order to have HW Rx hash generated.
	 *
	 * if (!is_eth_multi(bp))
	 *      bp->multi_mode = ETH_RSS_MODE_DISABLED;
	 */

	params.rss_obj = rss_obj;

	__set_bit(RAMROD_COMP_WAIT, &params.ramrod_flags);

	if (enable) {
		__set_bit(BNX2X_RSS_MODE_REGULAR, &params.rss_flags);

		/* RSS configuration */
		__set_bit(BNX2X_RSS_IPV4, &params.rss_flags);
		__set_bit(BNX2X_RSS_IPV4_TCP, &params.rss_flags);
		__set_bit(BNX2X_RSS_IPV6, &params.rss_flags);
		__set_bit(BNX2X_RSS_IPV6_TCP, &params.rss_flags);
		if (rss_obj->udp_rss_v4)
			__set_bit(BNX2X_RSS_IPV4_UDP, &params.rss_flags);
		if (rss_obj->udp_rss_v6)
			__set_bit(BNX2X_RSS_IPV6_UDP, &params.rss_flags);

		if (!CHIP_IS_E1x(bp)) {
			/* valid only for TUNN_MODE_VXLAN tunnel mode */
			__set_bit(BNX2X_RSS_IPV4_VXLAN, &params.rss_flags);
			__set_bit(BNX2X_RSS_IPV6_VXLAN, &params.rss_flags);

			/* valid only for TUNN_MODE_GRE tunnel mode */
			__set_bit(BNX2X_RSS_GRE_INNER_HDRS, &params.rss_flags);
		}
	} else {
		__set_bit(BNX2X_RSS_MODE_DISABLED, &params.rss_flags);
	}

	/* Hash bits */
	params.rss_result_mask = MULTI_MASK;

	memcpy(params.ind_table, rss_obj->ind_table, sizeof(params.ind_table));

	if (config_hash) {
		/* RSS keys */
		prandom_bytes(params.rss_key, T_ETH_RSS_KEY * 4);
		__set_bit(BNX2X_RSS_SET_SRCH, &params.rss_flags);
	}

	if (IS_PF(bp))
		return bnx2x_config_rss(bp, &params);
	else
		return bnx2x_vfpf_config_rss(bp, &params);
}
#endif

static int bnx2x_init_hw(struct bnx2x *bp, u32 load_code)
{
	struct bnx2x_func_state_params func_params = {NULL};

	/* Prepare parameters for function state transitions */
	__set_bit(RAMROD_COMP_WAIT, &func_params.ramrod_flags);

	func_params.f_obj = &bp->func_obj;
	func_params.cmd = BNX2X_F_CMD_HW_INIT;

	func_params.params.hw_init.load_phase = load_code;

	return bnx2x_func_state_change(bp, &func_params);
}

/*
 * Cleans the object that have internal lists without sending
 * ramrods. Should be run when interrupts are disabled.
 */
void bnx2x_squeeze_objects(struct bnx2x *bp)
{
	int rc;
	unsigned long ramrod_flags = 0, vlan_mac_flags = 0;
	struct bnx2x_mcast_ramrod_params rparam = {NULL};
	struct bnx2x_vlan_mac_obj *mac_obj = &bp->sp_objs->mac_obj;

	/***************** Cleanup MACs' object first *************************/

	/* Wait for completion of requested */
	__set_bit(RAMROD_COMP_WAIT, &ramrod_flags);
	/* Perform a dry cleanup */
	__set_bit(RAMROD_DRV_CLR_ONLY, &ramrod_flags);

	/* Clean ETH primary MAC */
	__set_bit(BNX2X_ETH_MAC, &vlan_mac_flags);
	rc = mac_obj->delete_all(bp, &bp->sp_objs->mac_obj, &vlan_mac_flags,
				 &ramrod_flags);
	if (rc != 0)
		BNX2X_ERR("Failed to clean ETH MACs: %d\n", rc);

	/* Cleanup UC list */
	vlan_mac_flags = 0;
	__set_bit(BNX2X_UC_LIST_MAC, &vlan_mac_flags);
	rc = mac_obj->delete_all(bp, mac_obj, &vlan_mac_flags,
				 &ramrod_flags);
	if (rc != 0)
		BNX2X_ERR("Failed to clean UC list MACs: %d\n", rc);

	/***************** Now clean mcast object *****************************/
	rparam.mcast_obj = &bp->mcast_obj;
	__set_bit(RAMROD_DRV_CLR_ONLY, &rparam.ramrod_flags);

	/** Add a DEL command... - Since we're doing a driver cleanup only,
	 *  we take a lock surrounding both the initial send and the CONTs,
	 *  as we don't want a true completion to disrupt us in the middle.
	 */
	netif_addr_lock_bh(bp->dev);
	rc = bnx2x_config_mcast(bp, &rparam, BNX2X_MCAST_CMD_DEL);
	if (rc < 0)
		BNX2X_ERR("Failed to add a new DEL command to a multi-cast object: %d\n",
			  rc);

	/* ...and wait until all pending commands are cleared */
	rc = bnx2x_config_mcast(bp, &rparam, BNX2X_MCAST_CMD_CONT);
	while (rc != 0) {
		if (rc < 0) {
			BNX2X_ERR("Failed to clean multi-cast object: %d\n",
				  rc);
			netif_addr_unlock_bh(bp->dev);
			return;
		}

		rc = bnx2x_config_mcast(bp, &rparam, BNX2X_MCAST_CMD_CONT);
	}
	netif_addr_unlock_bh(bp->dev);
}

#ifndef BNX2X_STOP_ON_ERROR
#define LOAD_ERROR_EXIT(bp, label) \
	do { \
		(bp)->state = BNX2X_STATE_ERROR; \
		goto label; \
	} while (0)

#define LOAD_ERROR_EXIT_CNIC(bp, label) \
	do { \
		bp->cnic_loaded = false; \
		goto label; \
	} while (0)
#else /*BNX2X_STOP_ON_ERROR*/
#define LOAD_ERROR_EXIT(bp, label) \
	do { \
		(bp)->state = BNX2X_STATE_ERROR; \
		(bp)->panic = 1; \
		return -EBUSY; \
	} while (0)
#define LOAD_ERROR_EXIT_CNIC(bp, label) \
	do { \
		bp->cnic_loaded = false; \
		(bp)->panic = 1; \
		return -EBUSY; \
	} while (0)
#endif /*BNX2X_STOP_ON_ERROR*/

static void bnx2x_free_fw_stats_mem(struct bnx2x *bp)
{
	BNX2X_PCI_FREE(bp->fw_stats, bp->fw_stats_mapping,
		       bp->fw_stats_data_sz + bp->fw_stats_req_sz);
	return;
}

static int bnx2x_alloc_fw_stats_mem(struct bnx2x *bp)
{
	int num_groups, vf_headroom = 0;
	int is_fcoe_stats = NO_FCOE(bp) ? 0 : 1;

	/* number of queues for statistics is number of eth queues + FCoE */
	u8 num_queue_stats = BNX2X_NUM_ETH_QUEUES(bp) + is_fcoe_stats;

	/* Total number of FW statistics requests =
	 * 1 for port stats + 1 for PF stats + potential 2 for FCoE (fcoe proper
	 * and fcoe l2 queue) stats + num of queues (which includes another 1
	 * for fcoe l2 queue if applicable)
	 */
	bp->fw_stats_num = 2 + is_fcoe_stats + num_queue_stats;

	/* vf stats appear in the request list, but their data is allocated by
	 * the VFs themselves. We don't include them in the bp->fw_stats_num as
	 * it is used to determine where to place the vf stats queries in the
	 * request struct
	 */
	if (IS_SRIOV(bp))
#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
		vf_headroom = bnx2x_vf_headroom(bp);
#else
		vf_headroom = bnx2x_esx_vf_headroom(bp);
#endif

	/* Request is built from stats_query_header and an array of
	 * stats_query_cmd_group each of which contains
	 * STATS_QUERY_CMD_COUNT rules. The real number or requests is
	 * configured in the stats_query_header.
	 */
	num_groups =
		(((bp->fw_stats_num + vf_headroom) / STATS_QUERY_CMD_COUNT) +
		 (((bp->fw_stats_num + vf_headroom) % STATS_QUERY_CMD_COUNT) ?
		 1 : 0));

	DP(BNX2X_MSG_SP, "stats fw_stats_num %d, vf headroom %d, num_groups %d\n",
	   bp->fw_stats_num, vf_headroom, num_groups);
	bp->fw_stats_req_sz = sizeof(struct stats_query_header) +
		num_groups * sizeof(struct stats_query_cmd_group);

	/* Data for statistics requests + stats_counter
	 * stats_counter holds per-STORM counters that are incremented
	 * when STORM has finished with the current request.
	 * memory for FCoE offloaded statistics are counted anyway,
	 * even if they will not be sent.
	 * VF stats are not accounted for here as the data of VF stats is stored
	 * in memory allocated by the VF, not here.
	 */
	bp->fw_stats_data_sz = sizeof(struct per_port_stats) +
		sizeof(struct per_pf_stats) +
		sizeof(struct fcoe_statistics_params) +
		sizeof(struct per_queue_stats) * num_queue_stats +
		sizeof(struct stats_counter);

	BNX2X_PCI_ALLOC(bp->fw_stats, &bp->fw_stats_mapping,
			bp->fw_stats_data_sz + bp->fw_stats_req_sz);

	/* Set shortcuts */
	bp->fw_stats_req = (struct bnx2x_fw_stats_req *)bp->fw_stats;
	bp->fw_stats_req_mapping = bp->fw_stats_mapping;
	bp->fw_stats_data = (struct bnx2x_fw_stats_data *)
		((u8 *)bp->fw_stats + bp->fw_stats_req_sz);
	bp->fw_stats_data_mapping = bp->fw_stats_mapping +
		bp->fw_stats_req_sz;

	DP(BNX2X_MSG_SP, "statistics request base address set to %x %x\n",
	   U64_HI(bp->fw_stats_req_mapping),
	   U64_LO(bp->fw_stats_req_mapping));
	DP(BNX2X_MSG_SP, "statistics data base address set to %x %x\n",
	   U64_HI(bp->fw_stats_data_mapping),
	   U64_LO(bp->fw_stats_data_mapping));
	return 0;

alloc_mem_err:
	bnx2x_free_fw_stats_mem(bp);
	BNX2X_ERR("Can't allocate FW stats memory\n");
	return -ENOMEM;
}

/* send load request to mcp and analyze response */
static int bnx2x_nic_load_request(struct bnx2x *bp, u32 *load_code)
{
	u32 param;

	/* init fw_seq */
	bp->fw_seq =
		(SHMEM_RD(bp, func_mb[BP_FW_MB_IDX(bp)].drv_mb_header) &
		 DRV_MSG_SEQ_NUMBER_MASK);
	BNX2X_DEV_INFO("fw_seq 0x%08x\n", bp->fw_seq);

#ifndef __VMKLNX__ /* Remove FW pulse timer update */ /* BNX2X_UPSTREAM */
	/* Get current FW pulse sequence */
	bp->fw_drv_pulse_wr_seq =
		(SHMEM_RD(bp, func_mb[BP_FW_MB_IDX(bp)].drv_pulse_mb) &
		 DRV_PULSE_SEQ_MASK);
	BNX2X_DEV_INFO("drv_pulse 0x%x\n", bp->fw_drv_pulse_wr_seq);
#endif

	param = DRV_MSG_CODE_LOAD_REQ_WITH_LFA;

	if (IS_MF_SD(bp) && bnx2x_port_after_undi(bp))
		param |= DRV_MSG_CODE_LOAD_REQ_FORCE_LFA;

	/* load request */
	(*load_code) = bnx2x_fw_command(bp, DRV_MSG_CODE_LOAD_REQ, param);

	/* if mcp fails to respond we must abort */
	if (!(*load_code)) {
		BNX2X_ERR("MCP response failure, aborting\n");
		return -EBUSY;
	}

	/* If mcp refused (e.g. other port is in diagnostic mode) we
	 * must abort
	 */
	if ((*load_code) == FW_MSG_CODE_DRV_LOAD_REFUSED) {
		BNX2X_ERR("MCP refused load request, aborting\n");
		return -EBUSY;
	}
	return 0;
}

/* check whether another PF has already loaded FW to chip. In
 * virtualized environments a pf from another VM may have already
 * initialized the device including loading FW
 */
int bnx2x_nic_load_analyze_req(struct bnx2x *bp, u32 load_code, bool print_err)
{
	/* is another pf loaded on this engine? */
	if (load_code != FW_MSG_CODE_DRV_LOAD_COMMON_CHIP &&
	    load_code != FW_MSG_CODE_DRV_LOAD_COMMON) {
		/* build my FW version dword */
		u32 my_fw = (BCM_5710_FW_MAJOR_VERSION) +
			(BCM_5710_FW_MINOR_VERSION << 8) +
			(BCM_5710_FW_REVISION_VERSION << 16) +
			(BCM_5710_FW_ENGINEERING_VERSION << 24);

		/* read loaded FW from chip */
		u32 loaded_fw = REG_RD(bp, XSEM_REG_PRAM);

		DP(BNX2X_MSG_SP, "loaded fw %x, my fw %x\n",
		   loaded_fw, my_fw);

		/* abort nic load if version mismatch */
		if (my_fw != loaded_fw) {
			if (print_err)
				BNX2X_ERR("bnx2x with FW %x was already loaded which mismatches my %x FW. Aborting\n",
					  loaded_fw, my_fw);
			else
				BNX2X_DEV_INFO("bnx2x with FW %x was already loaded which mismatches my %x FW, possibly due to MF UNDI\n",
					       loaded_fw, my_fw);
			return -EBUSY;
		}
	}
	return 0;
}

/* returns the "mcp load_code" according to global bnx2x_load_count array */
static int bnx2x_nic_load_no_mcp(struct bnx2x *bp, int port)
{
	int path = BP_PATH(bp);

	DP(NETIF_MSG_IFUP, "NO MCP - load counts[%d]      %d, %d, %d\n",
	   path, bnx2x_load_count[path][0], bnx2x_load_count[path][1],
	   bnx2x_load_count[path][2]);
	bnx2x_load_count[path][0]++;
	bnx2x_load_count[path][1 + port]++;
	DP(NETIF_MSG_IFUP, "NO MCP - new load counts[%d]  %d, %d, %d\n",
	   path, bnx2x_load_count[path][0], bnx2x_load_count[path][1],
	   bnx2x_load_count[path][2]);
	if (bnx2x_load_count[path][0] == 1)
		return FW_MSG_CODE_DRV_LOAD_COMMON;
	else if (bnx2x_load_count[path][1 + port] == 1)
		return FW_MSG_CODE_DRV_LOAD_PORT;
	else
		return FW_MSG_CODE_DRV_LOAD_FUNCTION;
}

#ifndef BNX2X_UPSTREAM  /* ! BNX2X_UPSTREAM */
/* write 0 to driver version of ncsi OEM specific data, as it should
 * not be supported in Linux */
static void bnx2x_zero_drv_ver_ncsi_oem(struct bnx2x *bp, u32 load_code)
{
	u32 ncsi_oem_data_addr;
	if (load_code == FW_MSG_CODE_DRV_LOAD_COMMON_CHIP) {
		if (SHMEM2_HAS(bp, ncsi_oem_data_addr)) {
			ncsi_oem_data_addr = SHMEM2_RD(bp, ncsi_oem_data_addr);
			if (ncsi_oem_data_addr) {
				REG_WR(bp,
				       ncsi_oem_data_addr +
				       offsetof(struct glob_ncsi_oem_data,
						driver_version),
				       0);
			}
		}
	}
}
#endif
/* mark PMF if applicable */
static void bnx2x_nic_load_pmf(struct bnx2x *bp, u32 load_code)
{
	if ((load_code == FW_MSG_CODE_DRV_LOAD_COMMON) ||
	    (load_code == FW_MSG_CODE_DRV_LOAD_COMMON_CHIP) ||
	    (load_code == FW_MSG_CODE_DRV_LOAD_PORT)) {
		bp->port.pmf = 1;
		/* We need the barrier to ensure the ordering between the
		 * writing to bp->port.pmf here and reading it from the
		 * bnx2x_periodic_task().
		 */
		smp_mb();
	} else {
		bp->port.pmf = 0;
	}

	DP(NETIF_MSG_LINK, "pmf %d\n", bp->port.pmf);
#ifndef BNX2X_UPSTREAM  /* ! BNX2X_UPSTREAM */
	bnx2x_zero_drv_ver_ncsi_oem(bp, load_code);
#endif
}

static void bnx2x_nic_load_afex_dcc(struct bnx2x *bp, int load_code)
{
	if (((load_code == FW_MSG_CODE_DRV_LOAD_COMMON) ||
	     (load_code == FW_MSG_CODE_DRV_LOAD_COMMON_CHIP)) &&
	    (bp->common.shmem2_base)) {
		if (SHMEM2_HAS(bp, dcc_support))
			SHMEM2_WR(bp, dcc_support,
				  (SHMEM_DCC_SUPPORT_DISABLE_ENABLE_PF_TLV |
				   SHMEM_DCC_SUPPORT_BANDWIDTH_ALLOCATION_TLV));
		if (SHMEM2_HAS(bp, afex_driver_support))
			SHMEM2_WR(bp, afex_driver_support,
				  SHMEM_AFEX_SUPPORTED_VERSION_ONE);
	}

	/* Set AFEX default VLAN tag to an invalid value */
	bp->afex_def_vlan_tag = -1;
}

/**
 * bnx2x_bz_fp - zero content of the fastpath structure.
 *
 * @bp:		driver handle
 * @index:	fastpath index to be zeroed
 *
 * Makes sure the contents of the bp->fp[index].napi is kept
 * intact.
 */
static void bnx2x_bz_fp(struct bnx2x *bp, int index)
{
	struct bnx2x_fastpath *fp = &bp->fp[index];
	int cos;
#if defined(BNX2X_NEW_NAPI) || defined(USE_NAPI_GRO) /* BNX2X_UPSTREAM */
	struct napi_struct orig_napi = fp->napi;
#endif
#if !defined(BNX2X_NEW_NAPI) /* ! BNX2X_UPSTREAM */
	struct net_device orig_netdev = fp->dummy_netdev;
#endif
	struct bnx2x_agg_info *orig_tpa_info = fp->tpa_info;

	/* bzero bnx2x_fastpath contents */
	if (fp->tpa_info)
		memset(fp->tpa_info, 0, ETH_MAX_AGGREGATION_QUEUES_E1H_E2 *
		       sizeof(struct bnx2x_agg_info));
	memset(fp, 0, sizeof(*fp));

#if defined(BNX2X_NEW_NAPI) || defined(USE_NAPI_GRO) /* BNX2X_UPSTREAM */
	/* Restore the NAPI object as it has been already initialized */
	fp->napi = orig_napi;
#endif
#if !defined(BNX2X_NEW_NAPI) /* ! BNX2X_UPSTREAM */
	/* Restore the "dummy" netdev object as it has been already
	 * initialized.
	 */
	fp->dummy_netdev = orig_netdev;
#endif
	fp->tpa_info = orig_tpa_info;
	fp->bp = bp;
	fp->index = index;
	if (IS_ETH_FP(fp))
		fp->max_cos = bp->max_cos;
	else
		/* Special queues support only one CoS */
		fp->max_cos = 1;

	/* Init txdata pointers */
	if (IS_FCOE_FP(fp))
		fp->txdata_ptr[0] = &bp->bnx2x_txq[FCOE_TXQ_IDX(bp)];
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	if (IS_FWD_FP(fp))
		fp->txdata_ptr[0] = &bp->bnx2x_txq[FWD_TXQ_IDX(bp)];
	if (IS_OOO_FP(fp))
		fp->txdata_ptr[0] = &bp->bnx2x_txq[OOO_TXQ_IDX(bp)];
#endif
	if (IS_ETH_FP(fp))
		for_each_cos_in_tx_queue(fp, cos)
			fp->txdata_ptr[cos] = &bp->bnx2x_txq[cos *
				BNX2X_NUM_ETH_QUEUES(bp) + index];

	/* set the tpa flag for each queue. The tpa flag determines the queue
	 * minimal size so it must be set prior to queue memory allocation
	 */
#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
#ifdef NO_GRO_SUPPORT
	fp->disable_tpa = (bp->flags & TPA_ENABLE_FLAG) == 0;
#else /* BNX2X_UPSTREAM */
	fp->disable_tpa = !(bp->flags & TPA_ENABLE_FLAG ||
				  (bp->flags & GRO_ENABLE_FLAG &&
				   bnx2x_mtu_allows_gro(bp->dev->mtu)));
	if (bp->flags & TPA_ENABLE_FLAG)
		fp->mode = TPA_MODE_LRO;
	else if (bp->flags & GRO_ENABLE_FLAG)
		fp->mode = TPA_MODE_GRO;
#endif
#endif

#ifndef BCM_OOO /* BNX2X_UPSTREAM */
	/* We don't want TPA on an FCoE L2 ring */
	if (IS_FCOE_FP(fp))
#else  /* ! BNX2X_UPSTREAM */
	/* We don't want TPA on FCoE, FWD and OOO L2 rings */
	if (IS_FCOE_FP(fp) || IS_OOO_FP(fp) || IS_FWD_FP(fp))
#endif
		fp->disable_tpa = 1;
}

int bnx2x_load_cnic(struct bnx2x *bp)
{
	int i, rc, port = BP_PORT(bp);

	DP(NETIF_MSG_IFUP, "Starting CNIC-related load\n");

	mutex_init(&bp->cnic_mutex);

	if (IS_PF(bp)) {
		rc = bnx2x_alloc_mem_cnic(bp);
		if (rc) {
			BNX2X_ERR("Unable to allocate bp memory for cnic\n");
			LOAD_ERROR_EXIT_CNIC(bp, load_error_cnic0);
		}
	}

	rc = bnx2x_alloc_fp_mem_cnic(bp);
	if (rc) {
		BNX2X_ERR("Unable to allocate memory for cnic fps\n");
		LOAD_ERROR_EXIT_CNIC(bp, load_error_cnic0);
	}

	/* Update the number of queues with the cnic queues */
	rc = bnx2x_set_real_num_queues(bp, 1);
	if (rc) {
		BNX2X_ERR("Unable to set real_num_queues including cnic\n");
		LOAD_ERROR_EXIT_CNIC(bp, load_error_cnic0);
	}

#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
	/* Add all CNIC NAPI objects */
	bnx2x_add_all_napi_cnic(bp);
	DP(NETIF_MSG_IFUP, "cnic napi added\n");
#endif
	bnx2x_napi_enable_cnic(bp);

	rc = bnx2x_init_hw_func_cnic(bp);
	if (rc)
		LOAD_ERROR_EXIT_CNIC(bp, load_error_cnic1);

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	if (bp->flags & USING_MSIX_FLAG &&
	    !(bp->flags & USING_SINGLE_MSIX_FLAG)) {
		rc = bnx2x_req_msix_irqs_cnic(bp);
		if (rc)
			LOAD_ERROR_EXIT_CNIC(bp, load_error_cnic1);
	}
#endif
	bnx2x_nic_init_cnic(bp);

	if (IS_PF(bp)) {
		/* Enable Timer scan */
		REG_WR(bp, TM_REG_EN_LINEAR0_TIMER + port*4, 1);

		/* setup cnic queues */
		for_each_cnic_queue(bp, i) {
			rc = bnx2x_setup_queue(bp, &bp->fp[i], 0);
			if (rc) {
				BNX2X_ERR("Queue setup failed\n");
				LOAD_ERROR_EXIT(bp, load_error_cnic2);
			}
		}
	}

	/* Initialize Rx filter. */
	bnx2x_set_rx_mode_inner(bp);

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	/* Release CNIC's IRQ now, CNIC will connect to it */
	if (bp->flags & OWN_CNIC_IRQ) {
		int cnic_idx = 1;
		synchronize_irq(bp->msix_table[cnic_idx].vector);
		free_irq(bp->msix_table[cnic_idx].vector,
			 bnx2x_ooo_fp(bp));
		bp->flags &= ~OWN_CNIC_IRQ;
	}
#endif
	/* re-read iscsi info */
	bnx2x_get_iscsi_info(bp);
	bnx2x_setup_cnic_irq_info(bp);
	bnx2x_setup_cnic_info(bp);
	bp->cnic_loaded = true;
	if (bp->state == BNX2X_STATE_OPEN)
		bnx2x_cnic_notify(bp, CNIC_CTL_START_CMD);

	DP(NETIF_MSG_IFUP, "Ending successfully CNIC-related load\n");

	return 0;

#ifndef BNX2X_STOP_ON_ERROR
load_error_cnic2:
	/* Disable Timer scan */
	REG_WR(bp, TM_REG_EN_LINEAR0_TIMER + port*4, 0);
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	if (bp->flags & USING_MSIX_FLAG &&
	    !(bp->flags & USING_SINGLE_MSIX_FLAG))
		bnx2x_free_msix_irqs_cnic(bp);
#endif

load_error_cnic1:
	bnx2x_napi_disable_cnic(bp);
	/* Update the number of queues without the cnic queues */
	if (bnx2x_set_real_num_queues(bp, 0))
		BNX2X_ERR("Unable to set real_num_queues not including cnic\n");
load_error_cnic0:
	BNX2X_ERR("CNIC-related load failed\n");
	bnx2x_free_fp_mem_cnic(bp);
	bnx2x_free_mem_cnic(bp);
	return rc;
#endif /* ! BNX2X_STOP_ON_ERROR */
}

/* must be called with rtnl_lock */
int bnx2x_nic_load(struct bnx2x *bp, int load_mode)
{
	int port = BP_PORT(bp);
	int i, rc = 0, load_code = 0;

	DP(NETIF_MSG_IFUP, "Starting NIC load\n");
	DP(NETIF_MSG_IFUP,
	   "CNIC is %s\n", CNIC_ENABLED(bp) ? "enabled" : "disabled");

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic)) {
		BNX2X_ERR("Can't load NIC when there is panic\n");
		return -EPERM;
	}
#endif

	bp->state = BNX2X_STATE_OPENING_WAIT4_LOAD;

	/* zero the structure w/o any lock, before SP handler is initialized */
	memset(&bp->last_reported_link, 0, sizeof(bp->last_reported_link));
	__set_bit(BNX2X_LINK_REPORT_LINK_DOWN,
		&bp->last_reported_link.link_report_flags);

	if (IS_PF(bp))
		/* must be called before memory allocation and HW init */
		bnx2x_ilt_set_info(bp);

	/*
	 * Zero fastpath structures preserving invariants like napi, which are
	 * allocated only once, fp index, max_cos, bp pointer.
	 * Also set fp->disable_tpa and txdata_ptr.
	 */
	DP(NETIF_MSG_IFUP, "num queues: %d", bp->num_queues);
	for_each_queue(bp, i)
		bnx2x_bz_fp(bp, i);
	memset(bp->bnx2x_txq, 0, (BNX2X_MAX_RSS_COUNT(bp) * BNX2X_MULTI_TX_COS +
				  bp->num_cnic_queues) *
				  sizeof(struct bnx2x_fp_txdata));

	bp->fcoe_init = false;
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	bp->ooo_init = false;
#endif
	/* Set the receive queues buffer size */
	bnx2x_set_rx_buf_size(bp);

	if (IS_PF(bp)) {
		rc = bnx2x_alloc_mem(bp);
		if (rc) {
			BNX2X_ERR("Unable to allocate bp memory\n");
			return rc;
		}
	}

	/* need to be done after alloc mem, since it's self adjusting to amount
	 * of memory available for RSS queues
	 */
	rc = bnx2x_alloc_fp_mem(bp);
	if (rc) {
		BNX2X_ERR("Unable to allocate memory for fps\n");
		LOAD_ERROR_EXIT(bp, load_error0);
	}

	/* Allocated memory for FW statistics  */
	if (bnx2x_alloc_fw_stats_mem(bp))
		LOAD_ERROR_EXIT(bp, load_error0);

	/* request pf to initialize status blocks */
	if (IS_VF(bp)) {
		rc = bnx2x_vfpf_init(bp);
		if (rc)
			LOAD_ERROR_EXIT(bp, load_error0);
	}

	/* As long as bnx2x_alloc_mem() may possibly update
	 * bp->num_queues, bnx2x_set_real_num_queues() should always
	 * come after it. At this stage cnic queues are not counted.
	 */
	rc = bnx2x_set_real_num_queues(bp, 0);
	if (rc) {
		BNX2X_ERR("Unable to set real_num_queues\n");
		LOAD_ERROR_EXIT(bp, load_error0);
	}

#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
	rc =  bnx2x_esx_init_bp(bp);
	if (rc) {
		BNX2X_ERR("Unable to initialize ESX-related settings\n");
		LOAD_ERROR_EXIT(bp, load_error0);
	}
#endif
#ifdef BCM_MULTI_COS /* BNX2X_UPSTREAM */
	/* configure multi cos mappings in kernel.
	 * this configuration may be overridden by a multi class queue
	 * discipline or by a dcbx negotiation result.
	 */
	bnx2x_setup_tc(bp->dev, bp->max_cos);
#endif

#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
	/* Add all NAPI objects */
	bnx2x_add_all_napi(bp);
	DP(NETIF_MSG_IFUP, "napi added\n");
#endif
	bnx2x_napi_enable(bp);

	if (IS_PF(bp)) {
		/* set pf load just before approaching the MCP */
		bnx2x_set_pf_load(bp);

		/* if mcp exists send load request and analyze response */
		if (!BP_NOMCP(bp)) {
			/* attempt to load pf */
			rc = bnx2x_nic_load_request(bp, &load_code);
			if (rc)
				LOAD_ERROR_EXIT(bp, load_error1);

			/* what did mcp say? */
			rc = bnx2x_nic_load_analyze_req(bp, load_code, true);
			if (rc) {
				bnx2x_fw_command(bp, DRV_MSG_CODE_LOAD_DONE, 0);
				LOAD_ERROR_EXIT(bp, load_error2);
			}
		} else {
			load_code = bnx2x_nic_load_no_mcp(bp, port);
		}

		/* mark pmf if applicable */
		bnx2x_nic_load_pmf(bp, load_code);

		/* Init Function state controlling object */
		bnx2x__init_func_obj(bp);

		/* Initialize HW */
		rc = bnx2x_init_hw(bp, load_code);
		if (rc) {
			BNX2X_ERR("HW init failed, aborting\n");
			bnx2x_fw_command(bp, DRV_MSG_CODE_LOAD_DONE, 0);
			LOAD_ERROR_EXIT(bp, load_error2);
		}
	}

	bnx2x_pre_irq_nic_init(bp);

	/* Connect to IRQs */
	rc = bnx2x_setup_irqs(bp);
	if (rc) {
		BNX2X_ERR("setup irqs failed\n");
		if (IS_PF(bp))
			bnx2x_fw_command(bp, DRV_MSG_CODE_LOAD_DONE, 0);
		LOAD_ERROR_EXIT(bp, load_error2);
	}

	/* Init per-function objects */
	if (IS_PF(bp)) {
		/* Setup NIC internals and enable interrupts */
		bnx2x_post_irq_nic_init(bp, load_code);

		bnx2x_init_bp_objs(bp);
		bnx2x_iov_nic_init(bp);

		/* Set AFEX default VLAN tag to an invalid value */
		bp->afex_def_vlan_tag = -1;
		bnx2x_nic_load_afex_dcc(bp, load_code);
		bp->state = BNX2X_STATE_OPENING_WAIT4_PORT;
		rc = bnx2x_func_start(bp);
		if (rc) {
			BNX2X_ERR("Function start failed!\n");
			bnx2x_fw_command(bp, DRV_MSG_CODE_LOAD_DONE, 0);

			LOAD_ERROR_EXIT(bp, load_error3);
		}

		/* Send LOAD_DONE command to MCP */
		if (!BP_NOMCP(bp)) {
			load_code = bnx2x_fw_command(bp,
						     DRV_MSG_CODE_LOAD_DONE, 0);
			if (!load_code) {
				BNX2X_ERR("MCP response failure, aborting\n");
				rc = -EBUSY;
				LOAD_ERROR_EXIT(bp, load_error3);
			}
		}

		/* initialize FW coalescing state machines in RAM */
		bnx2x_update_coalesce(bp);
	}

	/* setup the leading queue */
	rc = bnx2x_setup_leading(bp);
	if (rc) {
		BNX2X_ERR("Setup leading failed!\n");
		LOAD_ERROR_EXIT(bp, load_error3);
	}

	/* set up the rest of the queues */
	for_each_nondefault_eth_queue(bp, i) {
		if (IS_PF(bp))
			rc = bnx2x_setup_queue(bp, &bp->fp[i], false);
		else /* VF */
			rc = bnx2x_vfpf_setup_q(bp, &bp->fp[i], false);
		if (rc) {
			BNX2X_ERR("Queue %d setup failed\n", i);
			LOAD_ERROR_EXIT(bp, load_error3);
		}
	}


#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
	/* setup rss */
	rc = bnx2x_init_rss(bp);
	if (rc) {
		BNX2X_ERR("PF RSS init failed\n");
		LOAD_ERROR_EXIT(bp, load_error3);
	}
#elif (VMWARE_ESX_DDK_VERSION >= 50000 && \
	   !DYNAMIC_NETQ_ALLOC) /* ! BNX2X_UPSTREAM */
	rc = bnx2x_netq_init_rss(bp);
	if (rc == VMKNETDDI_QUEUEOPS_ERR) {
		BNX2X_ERR("NetQ RSS init failed\n");
		LOAD_ERROR_EXIT(bp, load_error3);
	}
#endif

	/* Now when Clients are configured we are ready to work */
	bp->state = BNX2X_STATE_OPEN;

	/* Configure a ucast MAC */
	if (IS_PF(bp))
		rc = bnx2x_set_eth_mac(bp, true);
	else /* vf */
		rc = bnx2x_vfpf_config_mac(bp, bp->dev->dev_addr, bp->fp->index,
					   true);
	if (rc) {
		BNX2X_ERR("Setting Ethernet MAC failed\n");
		LOAD_ERROR_EXIT(bp, load_error3);
	}

	if (IS_PF(bp) && bp->pending_max) {
		bnx2x_update_max_mf_config(bp, bp->pending_max);
		bp->pending_max = 0;
	}

	if (bp->port.pmf) {
		rc = bnx2x_initial_phy_init(bp, load_mode);
		if (rc)
			LOAD_ERROR_EXIT(bp, load_error3);
	}
	bp->link_params.feature_config_flags &= ~FEATURE_CONFIG_BOOT_FROM_SAN;

	/* Start fast path */

	/* Initialize Rx filter. */
	bnx2x_set_rx_mode_inner(bp);

#ifdef BCM_PTP /* BNX2X_UPSTREAM */
	if (bp->flags & PTP_SUPPORTED) {
		bnx2x_init_ptp(bp);
		bnx2x_configure_ptp_filters(bp);
	}
#endif
	/* Start Tx */
	switch (load_mode) {
	case LOAD_NORMAL:
		/* Tx queue should be only re-enabled */
		netif_tx_wake_all_queues(bp->dev);
		break;

	case LOAD_OPEN:
		netif_tx_start_all_queues(bp->dev);
		smp_mb__after_clear_bit();
		break;

	case LOAD_DIAG:
	case LOAD_LOOPBACK_EXT:
		bp->state = BNX2X_STATE_DIAG;
		break;

	default:
		break;
	}

	if (bp->port.pmf)
		bnx2x_update_drv_flags(bp, 1 << DRV_FLAGS_PORT_MASK, 0);
	else
		bnx2x__link_status_update(bp);

	/* start the timer */
	mod_timer(&bp->timer, jiffies + bp->current_interval);
#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
	vmknetddi_queueops_invalidate_state(bp->dev);
#if (DYNAMIC_NETQ_ALLOC)
	/* setup netqs for esx for dynamic netq allocation */
	bnx2x_esx_init_netqs(bp);
#endif
#endif

	if (CNIC_ENABLED(bp))
		bnx2x_load_cnic(bp);

	if (IS_PF(bp))
		bnx2x_schedule_sp_rtnl(bp, BNX2X_SP_RTNL_GET_DRV_VERSION, 0);

	if (IS_PF(bp) && SHMEM2_HAS(bp, drv_capabilities_flag)) {
		/* mark driver is loaded in shmem2 */
		u32 val;
		val = SHMEM2_RD(bp, drv_capabilities_flag[BP_FW_MB_IDX(bp)]);
		val &= ~DRV_FLAGS_MTU_MASK;
		val |= (bp->dev->mtu << DRV_FLAGS_MTU_SHIFT);
		SHMEM2_WR(bp, drv_capabilities_flag[BP_FW_MB_IDX(bp)],
			  val | DRV_FLAGS_CAPABILITIES_LOADED_SUPPORTED |
			  DRV_FLAGS_CAPABILITIES_LOADED_L2);
	}

	/* Wait for all pending SP commands to complete */
	if (IS_PF(bp) && !bnx2x_wait_sp_comp(bp, ~0x0UL)) {
		BNX2X_ERR("Timeout waiting for SP elements to complete\n");
		bnx2x_nic_unload(bp, UNLOAD_CLOSE, false);
		return -EBUSY;
	}

#if !defined(__VMKLNX__) || \
	(((VMWARE_ESX_DDK_VERSION == 50000) && !defined(BNX2X_INBOX)) || \
	 (VMWARE_ESX_DDK_VERSION > 50000)) /* BNX2X_UPSTREAM */
	/* If PMF - send ADMIN DCBX msg to MFW to initiate DCBX FSM */
	if (bp->port.pmf && (bp->state != BNX2X_STATE_DIAG))
		bnx2x_dcbx_init(bp, false);
#endif

	DP(NETIF_MSG_IFUP, "Ending successfully NIC load\n");

	return 0;

#ifndef BNX2X_STOP_ON_ERROR
load_error3:
	if (IS_PF(bp)) {
		bnx2x_int_disable_sync(bp, 1);

		/* Clean queueable objects */
		bnx2x_squeeze_objects(bp);
	}

	/* Free SKBs, SGEs, TPA pool and driver internals */
	bnx2x_free_skbs(bp);
	for_each_rx_queue(bp, i)
		bnx2x_free_rx_sge_range(bp, bp->fp + i, NUM_RX_SGE);

	/* Release IRQs */
	bnx2x_free_irq(bp);
load_error2:
	if (IS_PF(bp) && !BP_NOMCP(bp)) {
		bnx2x_fw_command(bp, DRV_MSG_CODE_UNLOAD_REQ_WOL_MCP, 0);
		bnx2x_fw_command(bp, DRV_MSG_CODE_UNLOAD_DONE, 0);
	}

	bp->port.pmf = 0;
load_error1:
	bnx2x_napi_disable(bp);
	bnx2x_del_all_napi(bp);

	/* clear pf_load status, as it was already set */
	if (IS_PF(bp))
		bnx2x_clear_pf_load(bp);
load_error0:
	bnx2x_free_fw_stats_mem(bp);
	bnx2x_free_fp_mem(bp);
	bnx2x_free_mem(bp);

	return rc;
#endif /* ! BNX2X_STOP_ON_ERROR */
}

int bnx2x_drain_tx_queues(struct bnx2x *bp)
{
	u8 cos, i;
#ifdef BNX2X_STOP_ON_ERROR
	u8 rc = 0;
#endif

	/* Wait until tx fastpath tasks complete */
	for_each_tx_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];

		for_each_cos_in_tx_queue(fp, cos)
#ifndef BNX2X_STOP_ON_ERROR
			bnx2x_clean_tx_queue(bp, fp->txdata_ptr[cos]);
#else
		{
			rc = bnx2x_clean_tx_queue(bp, fp->txdata_ptr[cos]);
			if (rc)
				return rc;
		}
#endif
	}

	/* Give HW time to discard old tx messages */
	usleep_range(1000, 2000);
	return 0;
}

/* must be called with rtnl_lock */
int bnx2x_nic_unload(struct bnx2x *bp, int unload_mode, bool keep_link)
{
	int i;
	bool global = false;

	DP(NETIF_MSG_IFUP, "Starting NIC unload\n");

	/* mark driver is unloaded in shmem2 */
	if (IS_PF(bp) && SHMEM2_HAS(bp, drv_capabilities_flag)) {
		u32 val;
		val = SHMEM2_RD(bp, drv_capabilities_flag[BP_FW_MB_IDX(bp)]);
		SHMEM2_WR(bp, drv_capabilities_flag[BP_FW_MB_IDX(bp)],
			  val & ~DRV_FLAGS_CAPABILITIES_LOADED_L2);
	}

	if (IS_PF(bp) && bp->recovery_state != BNX2X_RECOVERY_DONE &&
	    (bp->state == BNX2X_STATE_CLOSED ||
	     bp->state == BNX2X_STATE_ERROR)) {
		/* We can get here if the driver has been unloaded
		 * during parity error recovery and is either waiting for a
		 * leader to complete or for other functions to unload and
		 * then ifdown has been issued. In this case we want to
		 * unload and let other functions to complete a recovery
		 * process.
		 */
		bp->recovery_state = BNX2X_RECOVERY_DONE;
		bp->is_leader = 0;
		bnx2x_release_leader_lock(bp);
		smp_mb();

		DP(NETIF_MSG_IFDOWN, "Releasing a leadership...\n");
		BNX2X_ERR("Can't unload in closed or error state\n");
		return -EINVAL;
	}
#if defined(__VMKLNX__)	/* ! BNX2X_UPSTREAM */
	/*
	 * On older version of ESX 'device close' could be called with no
	 * prior successful call to 'device open'. The valid states at this
	 * point are either 'open' (device open) or 'diag' (self-test)
	 */
	if(bp->state != BNX2X_STATE_OPEN && bp->state != BNX2X_STATE_DIAG) {
		BNX2X_ERR("called dev_close() with no prior successful call to dev_open()\n");
		return -EBUSY;
	}
#endif

	/* Nothing to do during unload if previous bnx2x_nic_load()
	 * have not completed successfully - all resources are released.
	 *
	 * we can get here only after unsuccessful ndo_* callback, during which
	 * dev->IFF_UP flag is still on.
	 */
	if (bp->state == BNX2X_STATE_CLOSED || bp->state == BNX2X_STATE_ERROR)
		return 0;

	/* It's important to set the bp->state to the value different from
	 * BNX2X_STATE_OPEN and only then stop the Tx. Otherwise bnx2x_tx_int()
	 * may restart the Tx from the NAPI context (see bnx2x_tx_int()).
	 */
	bp->state = BNX2X_STATE_CLOSING_WAIT4_HALT;
	smp_mb();

	/* indicate to VFs that the PF is going down */
	bnx2x_iov_channel_down(bp);

	if (CNIC_LOADED(bp))
		bnx2x_cnic_notify(bp, CNIC_CTL_STOP_CMD);

	/* Stop Tx */
	bnx2x_tx_disable(bp);
#ifdef BCM_MULTI_COS /* BNX2X_UPSTREAM */
	netdev_reset_tc(bp->dev);
#endif

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	/* Reaquire the CNIC's IRQ */
	if (CNIC_LOADED(bp) && !NO_ISCSI_OOO(bp) &&
	    (bp->flags & USING_MSIX_FLAG) &&
	    (!(bp->flags & USING_SINGLE_MSIX_FLAG)) &&
	    (!(bp->flags & OWN_CNIC_IRQ))) {
		int cnic_idx = 1;
		if (request_irq(bp->msix_table[cnic_idx].vector,
				bnx2x_msix_fp_int, 0,
				bnx2x_ooo(bp, name), bnx2x_ooo_fp(bp)))
			BNX2X_ERR("Failed to connect to CNIC IRQ\n");
		else
			bp->flags |= OWN_CNIC_IRQ;
	}
#endif
	bp->rx_mode = BNX2X_RX_MODE_NONE;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)) /* ! BNX2X_UPSTREAM */
	/* In kernels starting from 2.6.31 netdev layer does this */
	bp->dev->trans_start = jiffies;	/* prevent tx timeout */
#endif
	del_timer_sync(&bp->timer);

	if (IS_PF(bp)) {
		/* Set ALWAYS_ALIVE bit in shmem */
		bp->fw_drv_pulse_wr_seq |= DRV_PULSE_ALWAYS_ALIVE;
#ifndef __VMKLNX__ /* Remove FW pulse timer update */ /* BNX2X_UPSTREAM */
		bnx2x_drv_pulse(bp);
#endif /* !__VMKLNX__ */
		bnx2x_stats_handle(bp, STATS_EVENT_STOP);
		bnx2x_save_statistics(bp);
	}

	/* wait till consumers catch up with producers in all queues */
	bnx2x_drain_tx_queues(bp);

	/* if VF indicate to PF this function is going down (PF will delete sp
	 * elements and clear initializations
	 */
	if (IS_VF(bp))
		bnx2x_vfpf_close_vf(bp);
	else if (unload_mode != UNLOAD_RECOVERY)
		/* if this is a normal/close unload need to clean up chip*/
		bnx2x_chip_cleanup(bp, unload_mode, keep_link);
	else {
		/* Send the UNLOAD_REQUEST to the MCP */
		bnx2x_send_unload_req(bp, unload_mode);

		/* Prevent transactions to host from the functions on the
		 * engine that doesn't reset global blocks in case of global
		 * attention once global blocks are reset and gates are opened
		 * (the engine which leader will perform the recovery
		 * last).
		 */
		if (!CHIP_IS_E1x(bp))
			bnx2x_pf_disable(bp);

		/* Disable HW interrupts, NAPI */
		bnx2x_netif_stop(bp, 1);
#ifndef __VMKLNX__ /* BNX2X_UPSTREAM */
		/* Delete all NAPI objects */
		bnx2x_del_all_napi(bp);
		if (CNIC_LOADED(bp))
			bnx2x_del_all_napi_cnic(bp);
#endif
		/* Release IRQs */
		bnx2x_free_irq(bp);

		/* Report UNLOAD_DONE to MCP */
		bnx2x_send_unload_done(bp, false);
	}

	/*
	 * At this stage no more interrupts will arrive so we may safely clean
	 * the queueable objects here in case they failed to get cleaned so far.
	 */
	if (IS_PF(bp))
		bnx2x_squeeze_objects(bp);

	/* There should be no more pending SP commands at this stage */
	bp->sp_state = 0;

	bp->port.pmf = 0;

	/* clear pending work in rtnl task */
	bp->sp_rtnl_state = 0;
	smp_mb();

	/* Free SKBs, SGEs, TPA pool and driver internals */
	bnx2x_free_skbs(bp);
	if (CNIC_LOADED(bp))
		bnx2x_free_skbs_cnic(bp);
	for_each_rx_queue(bp, i)
		bnx2x_free_rx_sge_range(bp, bp->fp + i, NUM_RX_SGE);

	bnx2x_free_fp_mem(bp);
	if (CNIC_LOADED(bp))
		bnx2x_free_fp_mem_cnic(bp);

#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
	 bnx2x_esx_cleanup_bp(bp);
#endif
	if (IS_PF(bp)) {
		if (CNIC_LOADED(bp))
			bnx2x_free_mem_cnic(bp);
	}
	bnx2x_free_mem(bp);

	bp->state = BNX2X_STATE_CLOSED;
	bp->cnic_loaded = false;

	/* Clear driver version indication in shmem */
	if (IS_PF(bp))
		bnx2x_update_mng_version(bp);

	/* Check if there are pending parity attentions. If there are - set
	 * RECOVERY_IN_PROGRESS.
	 */
	if (IS_PF(bp) && bnx2x_chk_parity_attn(bp, &global, false)) {
		bnx2x_set_reset_in_progress(bp);

		/* Set RESET_IS_GLOBAL if needed */
		if (global)
			bnx2x_set_reset_global(bp);
	}

	/* The last driver must disable a "close the gate" if there is no
	 * parity attention or "process kill" pending.
	 */
	if (IS_PF(bp) &&
	    !bnx2x_clear_pf_load(bp) &&
	    bnx2x_reset_is_done(bp, BP_PATH(bp)))
		bnx2x_disable_close_the_gate(bp);

	DP(NETIF_MSG_IFUP, "Ending NIC unload\n");

	return 0;
}

int bnx2x_set_power_state(struct bnx2x *bp, pci_power_t state)
{
	u16 pmcsr;

	/* If there is no power capability, silently succeed */
	if (!BNX2X_PM_CAP(bp)) {
		BNX2X_DEV_INFO("No power capability. Breaking.\n");
		return 0;
	}

	pci_read_config_word(bp->pdev, BNX2X_PM_CAP(bp) + PCI_PM_CTRL, &pmcsr);

	switch (state) {
	case PCI_D0:
		pci_write_config_word(bp->pdev, BNX2X_PM_CAP(bp) + PCI_PM_CTRL,
				      ((pmcsr & ~PCI_PM_CTRL_STATE_MASK) |
				       PCI_PM_CTRL_PME_STATUS));

		if (pmcsr & PCI_PM_CTRL_STATE_MASK)
			/* delay required during transition out of D3hot */
			msleep(20);
		break;

	case PCI_D3hot:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)) /* BNX2X_UPSTREAM */
		/* If there are other clients above don't
		   shut down the power */
		if (atomic_read(&bp->pdev->enable_cnt) != 1)
			return 0;
#endif
		/* Don't shut down the power for emulation and FPGA */
		if (CHIP_REV_IS_SLOW(bp))
			return 0;

		pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
		pmcsr |= 3;

		if (bp->wol)
			pmcsr |= PCI_PM_CTRL_PME_ENABLE;

		pci_write_config_word(bp->pdev, BNX2X_PM_CAP(bp) + PCI_PM_CTRL,
				      pmcsr);

		/* No more memory access after this point until
		* device is brought back to D0.
		*/
		break;

	default:
		dev_err(&bp->pdev->dev, "Can't support state = %d\n", state);
		return -EINVAL;
	}
	return 0;
}

/*
 * net_device service functions
 */
#if defined(BNX2X_NEW_NAPI) /* BNX2X_UPSTREAM */
_STAEU int bnx2x_poll(struct napi_struct *napi, int budget)
#else
int bnx2x_poll(struct net_device *dev, int *budget)
#endif
{
	int work_done = 0;
	u8 cos;
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
	struct bnx2x_fastpath *fp = container_of(napi, struct bnx2x_fastpath,
						 napi);
	struct bnx2x *bp = fp->bp;
#else /* non BNX2X_UPSTREAM */
	struct bnx2x_fastpath *fp = dev->priv;
	struct bnx2x *bp = fp->bp;
	int orig_budget = min(*budget, dev->quota);
#endif

	while (1) {
#ifdef BNX2X_STOP_ON_ERROR
		if (unlikely(bp->panic)) {
			napi_complete(napi);
			return 0;
		}
#endif

#ifndef BNX2X_MULTI_QUEUE /* ! BNX2X_UPSTREAM */
		/* There is only one Tx queue on kernels 2.6.26 and below */
		if (fp->index == 0)
#endif
		for_each_cos_in_tx_queue(fp, cos)
			if (bnx2x_tx_queue_has_work(fp->txdata_ptr[cos]))
				bnx2x_tx_int(bp, fp->txdata_ptr[cos]);

		if (bnx2x_has_rx_work(fp)) {
#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
			work_done += bnx2x_rx_int(fp, budget - work_done);

			/* must not complete if we consumed full budget */
			if (work_done >= budget)
				break;
#else
			work_done = bnx2x_rx_int(fp, orig_budget);

			*budget -= work_done;
			dev->quota -= work_done;
			orig_budget = min(*budget, dev->quota);
			if (orig_budget <= 0)
				break;
#endif
		}

		/* Fall out from the NAPI loop if needed */
		if (!(bnx2x_has_rx_work(fp) || bnx2x_has_tx_work(fp))) {

			/* No need to update SB for FCoE L2 ring as long as
			 * it's connected to the default SB and the SB
			 * has been updated when NAPI was scheduled.
			 */
			if (IS_FCOE_FP(fp)) {
				napi_complete(napi);
#ifndef BNX2X_NEW_NAPI
				return 0;
#else	/* BNX2X_UPSTREAM */
				break;
#endif
			}
			bnx2x_update_fpsb_idx(fp);
			/* bnx2x_has_rx_work() reads the status block,
			 * thus we need to ensure that status block indices
			 * have been actually read (bnx2x_update_fpsb_idx)
			 * prior to this check (bnx2x_has_rx_work) so that
			 * we won't write the "newer" value of the status block
			 * to IGU (if there was a DMA right after
			 * bnx2x_has_rx_work and if there is no rmb, the memory
			 * reading (bnx2x_update_fpsb_idx) may be postponed
			 * to right before bnx2x_ack_sb). In this case there
			 * will never be another interrupt until there is
			 * another update of the status block, while there
			 * is still unhandled work.
			 */
			rmb();

			if (!(bnx2x_has_rx_work(fp) || bnx2x_has_tx_work(fp))) {
				napi_complete(napi);
				/* Re-enable interrupts */
				DP(NETIF_MSG_RX_STATUS,
				   "Update index to %d\n", fp->fp_hc_idx);
				bnx2x_ack_sb(bp, fp->igu_sb_id, USTORM_ID,
					     le16_to_cpu(fp->fp_hc_idx),
					     IGU_INT_ENABLE, 1);
#ifndef BNX2X_NEW_NAPI
				return 0;
#else	/* BNX2X_UPSTREAM */
				break;
#endif
			}
		}
	}

#ifdef BNX2X_NEW_NAPI /* BNX2X_UPSTREAM */
	return work_done;
#else
	return 1;
#endif
}

#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
/* we split the first BD into headers and data BDs
 * to ease the pain of our fellow microcode engineers
 * we use one mapping for both BDs
 */
static u16 bnx2x_tx_split(struct bnx2x *bp,
			  struct bnx2x_fp_txdata *txdata,
			  struct sw_tx_bd *tx_buf,
			  struct eth_tx_start_bd **tx_bd, u16 hlen,
			  u16 bd_prod)
{
	struct eth_tx_start_bd *h_tx_bd = *tx_bd;
	struct eth_tx_bd *d_tx_bd;
	dma_addr_t mapping;
	int old_len = le16_to_cpu(h_tx_bd->nbytes);

	/* first fix first BD */
	h_tx_bd->nbytes = cpu_to_le16(hlen);

	DP(NETIF_MSG_TX_QUEUED,	"TSO split header size is %d (%x:%x)\n",
	   h_tx_bd->nbytes, h_tx_bd->addr_hi, h_tx_bd->addr_lo);

	/* now get a new data BD
	 * (after the pbd) and fill it */
	bd_prod = TX_BD(NEXT_TX_IDX(bd_prod));
	d_tx_bd = &txdata->tx_desc_ring[bd_prod].reg_bd;

	mapping = HILO_U64(le32_to_cpu(h_tx_bd->addr_hi),
			   le32_to_cpu(h_tx_bd->addr_lo)) + hlen;

	d_tx_bd->addr_hi = cpu_to_le32(U64_HI(mapping));
	d_tx_bd->addr_lo = cpu_to_le32(U64_LO(mapping));
	d_tx_bd->nbytes = cpu_to_le16(old_len - hlen);

	/* this marks the BD as one that has no individual mapping */
	tx_buf->flags |= BNX2X_TSO_SPLIT_BD;

	DP(NETIF_MSG_TX_QUEUED,
	   "TSO split data size is %d (%x:%x)\n",
	   d_tx_bd->nbytes, d_tx_bd->addr_hi, d_tx_bd->addr_lo);

	/* update tx_bd */
	*tx_bd = (struct eth_tx_start_bd *)d_tx_bd;

	return bd_prod;
}
#endif

#define bswab32(b32) ((__force __le32) swab32((__force __u32) (b32)))
#define bswab16(b16) ((__force __le16) swab16((__force __u16) (b16)))
static __le16 bnx2x_csum_fix(unsigned char *t_header, u16 csum, s8 fix)
{
	__sum16 tsum = (__force __sum16) csum;

	if (fix > 0)
		tsum = ~csum_fold(csum_sub((__force __wsum) csum,
				  csum_partial(t_header - fix, fix, 0)));

	else if (fix < 0)
		tsum = ~csum_fold(csum_add((__force __wsum) csum,
				  csum_partial(t_header, -fix, 0)));

	return bswab16(tsum);
}

static u32 bnx2x_xmit_type(struct bnx2x *bp, struct sk_buff *skb)
{
	u32 rc;
	__u8 prot = 0;
	__be16 protocol;

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 55000) /* non BNX2X_UPSTREAM */
	if (skb->ip_summed != CHECKSUM_PARTIAL &&
	    skb->ip_summed != CHECKSUM_HW_ENCAP)
#else /* BNX2X_UPSTREAM */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
#endif
		return XMIT_PLAIN;

	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IPV6)) {
		rc = XMIT_CSUM_V6;
		prot = ipv6_hdr(skb)->nexthdr;
	} else {
		rc = XMIT_CSUM_V4;
		prot = ip_hdr(skb)->protocol;
	}

#ifdef ENC_SUPPORTED /* BNX2X_UPSTREAM */
#if defined(__VMKLNX__) /* non BNX2X_UPSTREAM */
	if (!CHIP_IS_E1x(bp) && IS_ENCAP(skb)) {
#else /* BNX2X_UPSTREAM */
	if (!CHIP_IS_E1x(bp) && skb->encapsulation) {
#endif
		if (inner_ip_hdr(skb)->version == 6) {
			rc |= XMIT_CSUM_ENC_V6;
			if (inner_ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
				rc |= XMIT_CSUM_TCP;
		} else {
			rc |= XMIT_CSUM_ENC_V4;
			if (inner_ip_hdr(skb)->protocol == IPPROTO_TCP)
				rc |= XMIT_CSUM_TCP;
		}
	}
#endif
	if (prot == IPPROTO_TCP)
		rc |= XMIT_CSUM_TCP;

#ifdef NETIF_F_GSO /* BNX2X_UPSTREAM */
	/*
	 * Don't try to align it to the upstream because NETIF_F_GSO is
	 * introduced in 2.6.18 together with the skb_is_gso(skb) which checks
	 * gso_size. At the same time gso_type could be SKB_GSO_TCPV4 or
	 * SKB_GSO_UDP, thus we can't use skb_is_gso(skb) from that kerel here.
	 */
	if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
		rc |= (XMIT_GSO_V4 | XMIT_CSUM_TCP);
		if (rc & XMIT_CSUM_ENC)
			rc |= XMIT_GSO_ENC_V4;
	}

#ifdef NETIF_F_TSO6 /* BNX2X_UPSTREAM */
	else if (skb_is_gso_v6(skb)) {
		rc |= (XMIT_GSO_V6 | XMIT_CSUM_TCP);
		if (rc & XMIT_CSUM_ENC)
			rc |= XMIT_GSO_ENC_V6;
	}
#endif
#elif defined(NETIF_F_TSO) /* none BNX2X_UPSTREAM */
	if (skb_is_gso(skb))
		rc |= (XMIT_GSO_V4 | XMIT_CSUM_TCP);
#endif

	return rc;
}

#if (MAX_SKB_FRAGS >= MAX_FETCH_BD - 3)
/* check if packet requires linearization (packet is too fragmented)
   no need to check fragmentation if page size > 8K (there will be no
   violation to FW restrictions) */
static int bnx2x_pkt_req_lin(struct bnx2x *bp, struct sk_buff *skb,
			     u32 xmit_type)
{
	int to_copy = 0;
	int hlen = 0;
	int first_bd_sz = 0;

	/* 3 = 1 (for linear data BD) + 2 (for PBD and last BD) */
	if (skb_shinfo(skb)->nr_frags >= (MAX_FETCH_BD - 3)) {

		if (xmit_type & XMIT_GSO) {
#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
			unsigned short lso_mss = skb_shinfo(skb)->gso_size;
			/* Check if LSO packet needs to be copied:
			   3 = 1 (for headers BD) + 2 (for PBD and last BD) */
			int wnd_size = MAX_FETCH_BD - 3;
			/* Number of windows to check */
			int num_wnds = skb_shinfo(skb)->nr_frags - wnd_size;
			int wnd_idx = 0;
			int frag_idx = 0;
			u32 wnd_sum = 0;

			/* Headers length */
			hlen = (int)(skb_transport_header(skb) - skb->data) +
				tcp_hdrlen(skb);

			/* Amount of data (w/o headers) on linear part of SKB*/
			first_bd_sz = skb_headlen(skb) - hlen;

			wnd_sum  = first_bd_sz;

			/* Calculate the first sum - it's special */
			for (frag_idx = 0; frag_idx < wnd_size - 1; frag_idx++)
				wnd_sum +=
					skb_frag_size(&skb_shinfo(skb)->frags[frag_idx]);

			/* If there was data on linear skb data - check it */
			if (first_bd_sz > 0) {
				if (unlikely(wnd_sum < lso_mss)) {
					to_copy = 1;
					goto exit_lbl;
				}

				wnd_sum -= first_bd_sz;
			}

			/* Others are easier: run through the frag list and
			   check all windows */
			for (wnd_idx = 0; wnd_idx <= num_wnds; wnd_idx++) {
				wnd_sum +=
				  skb_frag_size(&skb_shinfo(skb)->frags[wnd_idx + wnd_size - 1]);

				if (unlikely(wnd_sum < lso_mss)) {
					to_copy = 1;
					break;
				}
				wnd_sum -=
					skb_frag_size(&skb_shinfo(skb)->frags[wnd_idx]);
			}
#endif
		} else {
			/* in non-LSO too fragmented packet should always
			   be linearized */
			to_copy = 1;
		}
	}

#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
exit_lbl:
#endif
	if (unlikely(to_copy))
		DP(NETIF_MSG_TX_QUEUED,
		   "Linearization IS REQUIRED for %s packet. num_frags %d  hlen %d  first_bd_sz %d\n",
		   (xmit_type & XMIT_GSO) ? "LSO" : "non-LSO",
		   skb_shinfo(skb)->nr_frags, hlen, first_bd_sz);

	return to_copy;
}
#endif

#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
/**
 * bnx2x_set_pbd_gso - update PBD in GSO case.
 *
 * @skb:	packet skb
 * @pbd:	parse BD
 * @xmit_type:	xmit flags
 */
static void bnx2x_set_pbd_gso(struct sk_buff *skb,
			      struct eth_tx_parse_bd_e1x *pbd,
			      u32 xmit_type)
{
	pbd->lso_mss = cpu_to_le16(skb_shinfo(skb)->gso_size);
	pbd->tcp_send_seq = bswab32(tcp_hdr(skb)->seq);
	pbd->tcp_flags = pbd_tcp_flags(tcp_hdr(skb));

	if (xmit_type & XMIT_GSO_V4) {
		pbd->ip_id = bswab16(ip_hdr(skb)->id);
		pbd->tcp_pseudo_csum =
			bswab16(~csum_tcpudp_magic(ip_hdr(skb)->saddr,
						   ip_hdr(skb)->daddr,
						   0, IPPROTO_TCP, 0));
	} else {
		pbd->tcp_pseudo_csum =
			bswab16(~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						 &ipv6_hdr(skb)->daddr,
						 0, IPPROTO_TCP, 0));
	}

	pbd->global_data |=
		cpu_to_le16(ETH_TX_PARSE_BD_E1X_PSEUDO_CS_WITHOUT_LEN);
}
#endif /* NETIF_F_TSO */

/**
 * bnx2x_set_pbd_csum_enc - update PBD with checksum and return header length
 *
 * @bp:			driver handle
 * @skb:		packet skb
 * @parsing_data:	data to be updated
 * @xmit_type:		xmit flags
 *
 * 57712/578xx related, when skb has encapsulation
 */
static u8 bnx2x_set_pbd_csum_enc(struct bnx2x *bp, struct sk_buff *skb,
				 u32 *parsing_data, u32 xmit_type)
{
	*parsing_data |=
		((((u8 *)skb_inner_transport_header(skb) - skb->data) >> 1) <<
		ETH_TX_PARSE_BD_E2_L4_HDR_START_OFFSET_W_SHIFT) &
		ETH_TX_PARSE_BD_E2_L4_HDR_START_OFFSET_W;

	if (xmit_type & XMIT_CSUM_TCP) {
		*parsing_data |= ((inner_tcp_hdrlen(skb) / 4) <<
			ETH_TX_PARSE_BD_E2_TCP_HDR_LENGTH_DW_SHIFT) &
			ETH_TX_PARSE_BD_E2_TCP_HDR_LENGTH_DW;

		return skb_inner_transport_header(skb) +
			inner_tcp_hdrlen(skb) - skb->data;
	}

	/* We support checksum offload for TCP and UDP only.
	 * No need to pass the UDP header length - it's a constant.
	 */
	return skb_inner_transport_header(skb) +
		sizeof(struct udphdr) - skb->data;
}

/**
 * bnx2x_set_pbd_csum_e2 - update PBD with checksum and return header length
 *
 * @bp:			driver handle
 * @skb:		packet skb
 * @parsing_data:	data to be updated
 * @xmit_type:		xmit flags
 *
 * 57712/578xx related
 */
static u8 bnx2x_set_pbd_csum_e2(struct bnx2x *bp, struct sk_buff *skb,
				u32 *parsing_data, u32 xmit_type)
{
	*parsing_data |=
		((((u8 *)skb_transport_header(skb) - skb->data) >> 1) <<
		ETH_TX_PARSE_BD_E2_L4_HDR_START_OFFSET_W_SHIFT) &
		ETH_TX_PARSE_BD_E2_L4_HDR_START_OFFSET_W;

	if (xmit_type & XMIT_CSUM_TCP) {
		*parsing_data |= ((tcp_hdrlen(skb) / 4) <<
			ETH_TX_PARSE_BD_E2_TCP_HDR_LENGTH_DW_SHIFT) &
			ETH_TX_PARSE_BD_E2_TCP_HDR_LENGTH_DW;

		return skb_transport_header(skb) + tcp_hdrlen(skb) - skb->data;
	}
	/* We support checksum offload for TCP and UDP only.
	 * No need to pass the UDP header length - it's a constant.
	 */
	return skb_transport_header(skb) + sizeof(struct udphdr) - skb->data;
}

/* set FW indication according to inner or outer protocols if tunneled */
static void bnx2x_set_sbd_csum(struct bnx2x *bp, struct sk_buff *skb,
			       struct eth_tx_start_bd *tx_start_bd,
			       u32 xmit_type)
{
	tx_start_bd->bd_flags.as_bitfield |= ETH_TX_BD_FLAGS_L4_CSUM;

	if (xmit_type & (XMIT_CSUM_ENC_V6 | XMIT_CSUM_V6))
		tx_start_bd->bd_flags.as_bitfield |= ETH_TX_BD_FLAGS_IPV6;

	if (!(xmit_type & XMIT_CSUM_TCP))
		tx_start_bd->bd_flags.as_bitfield |= ETH_TX_BD_FLAGS_IS_UDP;
}

/**
 * bnx2x_set_pbd_csum - update PBD with checksum and return header length
 *
 * @bp:		driver handle
 * @skb:	packet skb
 * @pbd:	parse BD to be updated
 * @xmit_type:	xmit flags
 */
static u8 bnx2x_set_pbd_csum(struct bnx2x *bp, struct sk_buff *skb,
			     struct eth_tx_parse_bd_e1x *pbd,
			     u32 xmit_type)
{
	u8 hlen = (skb_network_header(skb) - skb->data) >> 1;

	/* for now NS flag is not used in Linux */
	pbd->global_data =
		cpu_to_le16(hlen |
			    ((skb->protocol == cpu_to_be16(ETH_P_8021Q)) <<
			     ETH_TX_PARSE_BD_E1X_LLC_SNAP_EN_SHIFT));

	pbd->ip_hlen_w = (skb_transport_header(skb) -
			skb_network_header(skb)) >> 1;

	hlen += pbd->ip_hlen_w;

	/* We support checksum offload for TCP and UDP only */
	if (xmit_type & XMIT_CSUM_TCP)
		hlen += tcp_hdrlen(skb) / 2;
	else
		hlen += sizeof(struct udphdr) / 2;

	pbd->total_hlen_w = cpu_to_le16(hlen);
	hlen = hlen*2;

	if (xmit_type & XMIT_CSUM_TCP) {
		pbd->tcp_pseudo_csum = bswab16(tcp_hdr(skb)->check);

	} else {
		s8 fix = SKB_CS_OFF(skb); /* signed! */

		DP(NETIF_MSG_TX_QUEUED,
		   "hlen %d  fix %d  csum before fix %x\n",
		   le16_to_cpu(pbd->total_hlen_w), fix, SKB_CS(skb));

		/* HW bug: fixup the CSUM */
		pbd->tcp_pseudo_csum =
			bnx2x_csum_fix(skb_transport_header(skb),
				       SKB_CS(skb), fix);

		DP(NETIF_MSG_TX_QUEUED, "csum after fix %x\n",
		   pbd->tcp_pseudo_csum);
	}

	return hlen;
}

static void bnx2x_update_pbds_gso_enc(struct sk_buff *skb,
				      struct eth_tx_parse_bd_e2 *pbd_e2,
				      struct eth_tx_parse_2nd_bd *pbd2,
				      u16 *global_data,
				      u32 xmit_type)
{
	u16 hlen_w = 0;
	u8 outerip_off, outerip_len = 0;

	/* from outer IP to transport */
	hlen_w = (skb_inner_transport_header(skb) -
		  skb_network_header(skb)) >> 1;

	/* transport len */
	hlen_w += inner_tcp_hdrlen(skb) >> 1;

	pbd2->fw_ip_hdr_to_payload_w = hlen_w;

	/* outer IP header info */
	if (xmit_type & XMIT_CSUM_V4) {
		struct iphdr *iph = ip_hdr(skb);

		u32 csum = (__force u32)(~iph->check) -
			   (__force u32)iph->tot_len -
			   (__force u32)iph->frag_off;

		outerip_len = iph->ihl << 1;

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 55000) /* ! BNX2X_UPSTREAM */
		if (!iph->check)
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
#endif
		pbd2->fw_ip_csum_wo_len_flags_frag =
			bswab16(csum_fold((__force __wsum)csum));
	} else {
		pbd2->fw_ip_hdr_to_payload_w =
			hlen_w - ((sizeof(struct ipv6hdr)) >> 1);
		pbd_e2->data.tunnel_data.flags |=
			1 /*IPv6*/ << ETH_TUNNEL_DATA_IP_HDR_TYPE_OUTER;
	}

	pbd2->tcp_send_seq = bswab32(inner_tcp_hdr(skb)->seq);

	pbd2->tcp_flags = pbd_tcp_flags(inner_tcp_hdr(skb));

	/* inner IP header info */
	if (xmit_type & XMIT_CSUM_ENC_V4) {
		pbd2->hw_ip_id = bswab16(inner_ip_hdr(skb)->id);

		pbd_e2->data.tunnel_data.pseudo_csum =
			bswab16(~csum_tcpudp_magic(
					inner_ip_hdr(skb)->saddr,
					inner_ip_hdr(skb)->daddr,
					0, IPPROTO_TCP, 0));
	} else {
		pbd_e2->data.tunnel_data.pseudo_csum =
			bswab16(~csum_ipv6_magic(
					&inner_ipv6_hdr(skb)->saddr,
					&inner_ipv6_hdr(skb)->daddr,
					0, IPPROTO_TCP, 0));
	}

	outerip_off = (skb_network_header(skb) - skb->data) >> 1;

	*global_data |=
		outerip_off |
		(outerip_len <<
			ETH_TX_PARSE_2ND_BD_IP_HDR_LEN_OUTER_W_SHIFT) |
		((skb->protocol == cpu_to_be16(ETH_P_8021Q)) <<
			ETH_TX_PARSE_2ND_BD_LLC_SNAP_EN_SHIFT);

	if (ip_hdr(skb)->protocol == IPPROTO_UDP) {
		SET_FLAG(*global_data, ETH_TX_PARSE_2ND_BD_TUNNEL_UDP_EXIST, 1);
		pbd2->tunnel_udp_hdr_start_w = skb_transport_offset(skb) >> 1;
	}
}

static inline void bnx2x_set_ipv6_ext_e2(struct sk_buff *skb, u32 *parsing_data,
					 u32 xmit_type)
{
	struct ipv6hdr *ipv6;

	if (!(xmit_type & (XMIT_GSO_ENC_V6 | XMIT_GSO_V6)))
		return;

	if (xmit_type & XMIT_GSO_ENC_V6)
		ipv6 = inner_ipv6_hdr(skb);
	else /* XMIT_GSO_V6 */
		ipv6 = ipv6_hdr(skb);

	if (ipv6->nexthdr == NEXTHDR_IPV6)
		*parsing_data |= ETH_TX_PARSE_BD_E2_IPV6_WITH_EXT_HDR;
}

/* called with netif_tx_lock
 * bnx2x_tx_int() runs without netif_tx_lock unless it needs to call
 * netif_wake_queue()
 */
netdev_tx_t bnx2x_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
#ifdef BNX2X_ESX_CNA /* non BNX2X_UPSTREAM */
	struct bnx2x *bp;

	if (dev->features & NETIF_F_CNA)
		bp = dev->priv;
	else
		bp = netdev_priv(dev);
#else /* BNX2X_UPSTREAM */
	struct bnx2x *bp = netdev_priv(dev);
#endif

#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
	struct netdev_queue *txq;
#endif
	struct bnx2x_fp_txdata *txdata;
	struct sw_tx_bd *tx_buf;
	struct eth_tx_start_bd *tx_start_bd, *first_bd;
	struct eth_tx_bd *tx_data_bd, *total_pkt_bd = NULL;
	struct eth_tx_parse_bd_e1x *pbd_e1x = NULL;
	struct eth_tx_parse_bd_e2 *pbd_e2 = NULL;
	struct eth_tx_parse_2nd_bd *pbd2 = NULL;
	u32 pbd_e2_parsing_data = 0;
	u16 pkt_prod, bd_prod;
	int nbd, txq_index;
	dma_addr_t mapping;
	u32 xmit_type = bnx2x_xmit_type(bp, skb);
	int i;
	u8 hlen = 0;
	__le16 pkt_size = 0;
	struct ethhdr *eth;
	u8 mac_type = UNICAST_ADDRESS;

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic))
		return NETDEV_TX_BUSY;
#endif

#ifdef __VMKLNX__ /* non BNX2X_UPSTREAM */
#if !defined(BNX2X_ESX_CNA)
	VMK_ASSERT(skb->queue_mapping <= BNX2X_NUM_TX_NETQUEUES(bp));
#endif
#if defined(BNX2X_ESX_CNA)
	if (dev->features & NETIF_F_CNA)
		txq_index = bnx2x_fcoe_tx(bp, txq_index);
	else
#endif
	txq_index = skb->queue_mapping;
	txq = netdev_get_tx_queue(dev, txq_index);

#elif defined(BNX2X_MULTI_QUEUE) /* BNX2X_UPSTREAM */
	txq_index = skb_get_queue_mapping(skb);
	txq = netdev_get_tx_queue(dev, txq_index);

#else
	txq_index = 0;
#endif
	BUG_ON(txq_index >= MAX_ETH_TXQ_IDX(bp) + (CNIC_LOADED(bp) ? 1 : 0));

	txdata = &bp->bnx2x_txq[txq_index];

	/* enable this debug print to view the transmission queue being used
	DP(NETIF_MSG_TX_QUEUED, "indices: txq %d, fp %d, txdata %d\n",
	   txq_index, fp_index, txdata_index); */

	/* enable this debug print to view the tranmission details
	DP(NETIF_MSG_TX_QUEUED,
	   "transmitting packet cid %d fp index %d txdata_index %d tx_data ptr %p fp pointer %p\n",
	   txdata->cid, fp_index, txdata_index, txdata, fp); */

	if (unlikely(bnx2x_tx_avail(bp, txdata) <
			skb_shinfo(skb)->nr_frags +
			BDS_PER_TX_PKT +
			NEXT_CNT_PER_TX_PKT(MAX_BDS_PER_TX_PKT))) {
		/* Handle special storage cases separately */
		if (txdata->tx_ring_size == 0) {
			struct bnx2x_eth_q_stats *q_stats =
				bnx2x_fp_qstats(bp, txdata->parent_fp);
			q_stats->driver_filtered_tx_pkt++;
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
		bnx2x_fp_qstats(bp, txdata->parent_fp)->driver_xoff++;
#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
		netif_tx_stop_queue(txq);
#else
		netif_stop_queue(dev);
#endif
		BNX2X_ERR("BUG! Tx ring full when queue awake!\n");

		return NETDEV_TX_BUSY;
	}

#ifdef NETIF_F_GSO /* BNX2X_UPSTREAM */
	DP(NETIF_MSG_TX_QUEUED,
	   "queue[%d]: SKB: summed %x  protocol %x protocol(%x,%x) gso type %x  xmit_type %x len %d\n",
	   txq_index, skb->ip_summed, skb->protocol, ipv6_hdr(skb)->nexthdr,
	   ip_hdr(skb)->protocol, skb_shinfo(skb)->gso_type, xmit_type,
	   skb->len);
#endif

	eth = (struct ethhdr *)skb->data;

	/* set flag according to packet type (UNICAST_ADDRESS is default)*/
	if (unlikely(is_multicast_ether_addr(eth->h_dest))) {
		if (is_broadcast_ether_addr(eth->h_dest))
			mac_type = BROADCAST_ADDRESS;
		else
			mac_type = MULTICAST_ADDRESS;
	}

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION <= 40000) /* ! BNX2X_UPSTREAM */
	if (xmit_type & XMIT_CSUM){
		/*
		 * The first sg element might not contain all the headers.
		 * Look at PR379952/PR405074.
		 * Do a simple check and if this holds pull tail on the skb.
		 * This should happen only when the VMs are using 3.0.x tools
		 * so it is a corner case.
		 */
		unsigned int hdr_len =
			(unsigned int)(skb_transport_header(skb) +
				       sizeof(struct tcphdr) - skb->data);
		if (!pskb_may_pull(skb, hdr_len)) {
			DP(NETIF_MSG_TX_QUEUED,
			   "pskb_may_pull() failed. Silently dropping...\n");
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}
#endif
#if (MAX_SKB_FRAGS >= MAX_FETCH_BD - BDS_PER_TX_PKT)
	/* First, check if we need to linearize the skb (due to FW
	   restrictions). No need to check fragmentation if page size > 8K
	   (there will be no violation to FW restrictions) */
	if (bnx2x_pkt_req_lin(bp, skb, xmit_type)) {
		/* Statistics of linearization */
		bp->lin_cnt++;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 17)) || defined(SLE_VERSION_CODE) /* BNX2X_UPSTREAM */
		if (skb_linearize(skb) != 0) {
#else
		if (skb_linearize(skb, GFP_ATOMIC) != 0) {
#endif
			DP(NETIF_MSG_TX_QUEUED,
			   "SKB linearization failed - silently dropping this SKB\n");
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}
#endif
	/* Map skb linear data for DMA */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
	mapping = dma_map_single(&bp->pdev->dev, skb->data,
				 skb_headlen(skb), DMA_TO_DEVICE);
#else
	mapping = pci_map_single(bp->pdev, skb->data,
				 skb_headlen(skb), PCI_DMA_TODEVICE);
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) /* BNX2X_UPSTREAM */
	if (unlikely(dma_mapping_error(&bp->pdev->dev, mapping))) {
#else
	if (unlikely(dma_mapping_error(mapping))) {
#endif
		DP(NETIF_MSG_TX_QUEUED,
		   "SKB mapping failed - silently dropping this SKB\n");
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	/*
	Please read carefully. First we use one BD which we mark as start,
	then we have a parsing info BD (used for TSO or xsum),
	and only then we have the rest of the TSO BDs.
	(don't forget to mark the last one as last,
	and to unmap only AFTER you write to the BD ...)
	And above all, all pdb sizes are in words - NOT DWORDS!
	*/

	/* get current pkt produced now - advance it just before sending packet
	 * since mapping of pages may fail and cause packet to be dropped
	 */
	pkt_prod = txdata->tx_pkt_prod;
	bd_prod = TX_BD(txdata->tx_bd_prod);

	/* get a tx_buf and first BD
	 * tx_start_bd may be changed during SPLIT,
	 * but first_bd will always stay first
	 */
	tx_buf = &txdata->tx_buf_ring[TX_BD(pkt_prod)];
	tx_start_bd = &txdata->tx_desc_ring[bd_prod].start_bd;
	first_bd = tx_start_bd;

	tx_start_bd->bd_flags.as_bitfield = ETH_TX_BD_FLAGS_START_BD;

#ifdef BCM_PTP /* BNX2X_UPSTREAM */
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
		if (!(bp->flags & TX_TIMESTAMPING_EN)) {
			BNX2X_ERR("Tx timestamping was not enabled, this packet will not be timestamped\n");
		} else if (bp->ptp_tx_skb) {
			BNX2X_ERR("The device supports only a single outstanding packet to timestamp, this packet will not be timestamped\n");
		} else {
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
			/* schedule check for Tx timestamp */
			bp->ptp_tx_skb = skb_get(skb);
			bp->ptp_tx_start = jiffies;
			schedule_work(&bp->ptp_task);
		}
	}
#endif

	/* header nbd: indirectly zero other flags! */
	tx_start_bd->general_data = 1 << ETH_TX_START_BD_HDR_NBDS_SHIFT;

	/* remember the first BD of the packet */
	tx_buf->first_bd = txdata->tx_bd_prod;
	tx_buf->skb = skb;
	tx_buf->flags = 0;

	DP(NETIF_MSG_TX_QUEUED,
	   "sending pkt %u @%p  next_idx %u  bd %u @%p\n",
	   pkt_prod, tx_buf, txdata->tx_pkt_prod, bd_prod, tx_start_bd);

#if defined(OLD_VLAN)
#if !defined(BNX2X_ESX_CNA)
/* in OLD_VLAN vf vlgrp is always null */
	if ((IS_VF(bp) || (bp->vlgrp != NULL)) && vlan_tx_tag_present(skb)) {
#else
	if (((IS_FCOE_FP(txdata->parent_fp) && (bp->cna_vlgrp != NULL)) ||
	     (!IS_FCOE_FP(txdata->parent_fp) && (bp->vlgrp != NULL))) &&
	    vlan_tx_tag_present(skb)) {
#endif
#else /* BNX2X_UPSTREAM */
	if (vlan_tx_tag_present(skb)) {
#endif
		tx_start_bd->vlan_or_ethertype =
		    cpu_to_le16(vlan_tx_tag_get(skb));
		tx_start_bd->bd_flags.as_bitfield |=
		    (X_ETH_OUTBAND_VLAN << ETH_TX_BD_FLAGS_VLAN_MODE_SHIFT);
	} else {
		/* when transmitting in a vf, start bd must hold the ethertype
		 * for fw to enforce it
		 */
#ifndef BNX2X_STOP_ON_ERROR
		if (IS_VF(bp)) {
#endif
			tx_start_bd->vlan_or_ethertype =
				cpu_to_le16(ntohs(eth->h_proto));
#ifndef BNX2X_STOP_ON_ERROR
		} else {
			/* used by FW for packet accounting */
			tx_start_bd->vlan_or_ethertype = cpu_to_le16(pkt_prod);

			/* if NPAR-SD is active then FW should do the tagging
			 * regardless of value of priority. Otherwise, if
			 * priority indicates this is a control packet we need
			 * to indicate to FW to avoid tagging.
			 */
			if (!IS_MF_AFEX(bp) &&
			    (skb->priority == TC_PRIO_CONTROL))
				SET_FLAG(tx_start_bd->general_data,
					 ETH_TX_START_BD_FORCE_VLAN_MODE, 1);
		}
#endif
	}

	nbd = 2; /* start_bd + pbd + frags (updated when pages are mapped) */

	/* turn on parsing and get a BD */
	bd_prod = TX_BD(NEXT_TX_IDX(bd_prod));

	if (xmit_type & XMIT_CSUM)
		bnx2x_set_sbd_csum(bp, skb, tx_start_bd, xmit_type);

	if (!CHIP_IS_E1x(bp)) {
		pbd_e2 = &txdata->tx_desc_ring[bd_prod].parse_bd_e2;
		memset(pbd_e2, 0, sizeof(struct eth_tx_parse_bd_e2));

		if (xmit_type & XMIT_CSUM_ENC) {
			u16 global_data = 0;

			/* Set PBD in enc checksum offload case */
			hlen = bnx2x_set_pbd_csum_enc(bp, skb,
						      &pbd_e2_parsing_data,
						      xmit_type);

			/* turn on 2nd parsing and get a BD */
			bd_prod = TX_BD(NEXT_TX_IDX(bd_prod));

			pbd2 = &txdata->tx_desc_ring[bd_prod].parse_2nd_bd;

			memset(pbd2, 0, sizeof(*pbd2));

			pbd_e2->data.tunnel_data.ip_hdr_start_inner_w =
				(skb_inner_network_header(skb) -
				 skb->data) >> 1;

			if (xmit_type & XMIT_GSO_ENC)
				bnx2x_update_pbds_gso_enc(skb, pbd_e2, pbd2,
							  &global_data,
							  xmit_type);

			pbd2->global_data = cpu_to_le16(global_data);

			/* add addition parse BD indication to start BD */
			SET_FLAG(tx_start_bd->general_data,
				 ETH_TX_START_BD_PARSE_NBDS, 1);
			/* set encapsulation flag in start BD */
			SET_FLAG(tx_start_bd->general_data,
				 ETH_TX_START_BD_TUNNEL_EXIST, 1);

			/* we omit setting type 0 - this is done implicitly
			 * during zeroing whole bd
			 * pbd2->bd_type = ETH_2ND_PARSE_BD_TYPE_LSO_TUNNEL;
			 */

			nbd++;
		} else if (xmit_type & XMIT_CSUM) {
			/* Set PBD in checksum offload case w/o encapsulation */
			hlen = bnx2x_set_pbd_csum_e2(bp, skb,
						     &pbd_e2_parsing_data,
						     xmit_type);
		}

		bnx2x_set_ipv6_ext_e2(skb, &pbd_e2_parsing_data, xmit_type);

		/* Add the macs to the parsing BD if the module param was
		 * explicitly set or if this is a vf
		 */
		if (IS_VF(bp)) {
			/* override GRE parameters in BD */
			bnx2x_set_fw_mac_addr(&pbd_e2->data.mac_addr.src_hi,
					      &pbd_e2->data.mac_addr.src_mid,
					      &pbd_e2->data.mac_addr.src_lo,
					      eth->h_source);

			bnx2x_set_fw_mac_addr(&pbd_e2->data.mac_addr.dst_hi,
					      &pbd_e2->data.mac_addr.dst_mid,
					      &pbd_e2->data.mac_addr.dst_lo,
					      eth->h_dest);
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
		} else if (bp->flags & TX_SWITCHING) {
			bnx2x_set_fw_mac_addr(&pbd_e2->data.mac_addr.dst_hi,
					      &pbd_e2->data.mac_addr.dst_mid,
					      &pbd_e2->data.mac_addr.dst_lo,
					      eth->h_dest);
#endif
#ifdef BNX2X_STOP_ON_ERROR
#ifdef BNX2X_UPSTREAM /* BNX2X_UPSTREAM */
		} else
#endif
			/* Enforce security is always set in Stop on Error -
			 * source mac should be present in the parsing BD
			 */
			bnx2x_set_fw_mac_addr(&pbd_e2->data.mac_addr.src_hi,
					      &pbd_e2->data.mac_addr.src_mid,
					      &pbd_e2->data.mac_addr.src_lo,
					      eth->h_source);
#endif
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
		}
#endif


		SET_FLAG(pbd_e2_parsing_data,
			 ETH_TX_PARSE_BD_E2_ETH_ADDR_TYPE, mac_type);
	} else {
		u16 global_data = 0;
		pbd_e1x = &txdata->tx_desc_ring[bd_prod].parse_bd_e1x;
		memset(pbd_e1x, 0, sizeof(struct eth_tx_parse_bd_e1x));
		/* Set PBD in checksum offload case */
		if (xmit_type & XMIT_CSUM)
			hlen = bnx2x_set_pbd_csum(bp, skb, pbd_e1x, xmit_type);

		SET_FLAG(global_data,
			 ETH_TX_PARSE_BD_E1X_ETH_ADDR_TYPE, mac_type);
		pbd_e1x->global_data |= cpu_to_le16(global_data);
	}

	/* Setup the data pointer of the first BD of the packet */
	tx_start_bd->addr_hi = cpu_to_le32(U64_HI(mapping));
	tx_start_bd->addr_lo = cpu_to_le32(U64_LO(mapping));
	tx_start_bd->nbytes = cpu_to_le16(skb_headlen(skb));
	pkt_size = tx_start_bd->nbytes;

	DP(NETIF_MSG_TX_QUEUED,
	   "first bd @%p  addr (%x:%x)  nbytes %d  flags %x  vlan %x\n",
	   tx_start_bd, tx_start_bd->addr_hi, tx_start_bd->addr_lo,
	   le16_to_cpu(tx_start_bd->nbytes),
	   tx_start_bd->bd_flags.as_bitfield,
	   le16_to_cpu(tx_start_bd->vlan_or_ethertype));

#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
	if (xmit_type & XMIT_GSO) {

		DP(NETIF_MSG_TX_QUEUED,
		   "TSO packet len %d  hlen %d  total len %d  tso size %d\n",
		   skb->len, hlen, skb_headlen(skb),
		   skb_shinfo(skb)->gso_size);

		tx_start_bd->bd_flags.as_bitfield |= ETH_TX_BD_FLAGS_SW_LSO;

		if (unlikely(skb_headlen(skb) > hlen)) {
			nbd++;
			bd_prod = bnx2x_tx_split(bp, txdata, tx_buf,
						 &tx_start_bd, hlen,
						 bd_prod);
		}
		if (!CHIP_IS_E1x(bp))
			pbd_e2_parsing_data |=
				(skb_shinfo(skb)->gso_size <<
				 ETH_TX_PARSE_BD_E2_LSO_MSS_SHIFT) &
				 ETH_TX_PARSE_BD_E2_LSO_MSS;
		else
			bnx2x_set_pbd_gso(skb, pbd_e1x, xmit_type);
	}
#endif

	/* Set the PBD's parsing_data field if not zero
	 * (for the chips newer than 57711).
	 */
	if (pbd_e2_parsing_data)
		pbd_e2->parsing_data = cpu_to_le32(pbd_e2_parsing_data);

	tx_data_bd = (struct eth_tx_bd *)tx_start_bd;

	/* Handle fragmented skb */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)) /* BNX2X_UPSTREAM */
		mapping = skb_frag_dma_map(&bp->pdev->dev, frag, 0,
					   skb_frag_size(frag), DMA_TO_DEVICE);
#else
		mapping = pci_map_page(bp->pdev, frag->page, frag->page_offset,
				       frag->size, PCI_DMA_TODEVICE);
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) /* BNX2X_UPSTREAM */
		if (unlikely(dma_mapping_error(&bp->pdev->dev, mapping))) {
#else
		if (unlikely(dma_mapping_error(mapping))) {
#endif
			unsigned int pkts_compl = 0, bytes_compl = 0;

			DP(NETIF_MSG_TX_QUEUED,
			   "Unable to map page - dropping packet...\n");

			/* we need unmap all buffers already mapped
			 * for this SKB;
			 * first_bd->nbd need to be properly updated
			 * before call to bnx2x_free_tx_pkt
			 */
			first_bd->nbd = cpu_to_le16(nbd);
			bnx2x_free_tx_pkt(bp, txdata,
					  TX_BD(txdata->tx_pkt_prod),
					  &pkts_compl, &bytes_compl);
			return NETDEV_TX_OK;
		}

		bd_prod = TX_BD(NEXT_TX_IDX(bd_prod));
		tx_data_bd = &txdata->tx_desc_ring[bd_prod].reg_bd;
		if (total_pkt_bd == NULL)
			total_pkt_bd = &txdata->tx_desc_ring[bd_prod].reg_bd;

		tx_data_bd->addr_hi = cpu_to_le32(U64_HI(mapping));
		tx_data_bd->addr_lo = cpu_to_le32(U64_LO(mapping));
		tx_data_bd->nbytes = cpu_to_le16(skb_frag_size(frag));
		le16_add_cpu(&pkt_size, skb_frag_size(frag));
		nbd++;

		DP(NETIF_MSG_TX_QUEUED,
		   "frag %d  bd @%p  addr (%x:%x)  nbytes %d\n",
		   i, tx_data_bd, tx_data_bd->addr_hi, tx_data_bd->addr_lo,
		   le16_to_cpu(tx_data_bd->nbytes));
	}

	DP(NETIF_MSG_TX_QUEUED, "last bd @%p\n", tx_data_bd);

	/* update with actual num BDs */
	first_bd->nbd = cpu_to_le16(nbd);

	bd_prod = TX_BD(NEXT_TX_IDX(bd_prod));

	/* now send a tx doorbell, counting the next BD
	 * if the packet contains or ends with it
	 */
	if (TX_BD_POFF(bd_prod) < nbd)
		nbd++;

	/* total_pkt_bytes should be set on the first data BD if
	 * it's not an LSO packet and there is more than one
	 * data BD. In this case pkt_size is limited by an MTU value.
	 * However we prefer to set it for an LSO packet (while we don't
	 * have to) in order to save some CPU cycles in a none-LSO
	 * case, when we much more care about them.
	 */
	if (total_pkt_bd != NULL)
		total_pkt_bd->total_pkt_bytes = pkt_size;

	if (pbd_e1x)
		DP(NETIF_MSG_TX_QUEUED,
		   "PBD (E1X) @%p  ip_data %x  ip_hlen %u  ip_id %u  lso_mss %u  tcp_flags %x  xsum %x  seq %u  hlen %u\n",
		   pbd_e1x, pbd_e1x->global_data, pbd_e1x->ip_hlen_w,
		   pbd_e1x->ip_id, pbd_e1x->lso_mss, pbd_e1x->tcp_flags,
		   pbd_e1x->tcp_pseudo_csum, pbd_e1x->tcp_send_seq,
		    le16_to_cpu(pbd_e1x->total_hlen_w));
	if (pbd_e2)
		DP(NETIF_MSG_TX_QUEUED,
		   "PBD (E2) @%p  dst %x %x %x src %x %x %x parsing_data %x\n",
		   pbd_e2,
		   pbd_e2->data.mac_addr.dst_hi,
		   pbd_e2->data.mac_addr.dst_mid,
		   pbd_e2->data.mac_addr.dst_lo,
		   pbd_e2->data.mac_addr.src_hi,
		   pbd_e2->data.mac_addr.src_mid,
		   pbd_e2->data.mac_addr.src_lo,
		   pbd_e2->parsing_data);
	DP(NETIF_MSG_TX_QUEUED, "doorbell: nbd %d  bd %u\n", nbd, bd_prod);

#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
	netdev_tx_sent_queue(txq, skb->len);
#endif

	skb_tx_timestamp(skb);

	txdata->tx_pkt_prod++;
	/*
	 * Make sure that the BD data is updated before updating the producer
	 * since FW might read the BD right after the producer is updated.
	 * This is only applicable for weak-ordered memory model archs such
	 * as IA-64. The following barrier is also mandatory since FW will
	 * assumes packets must have BDs.
	 */
	wmb();

	txdata->tx_db.data.prod += nbd;
	barrier();

	DOORBELL(bp, txdata->cid, txdata->tx_db.raw);

	mmiowb();

	txdata->tx_bd_prod += nbd;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)) /* ! BNX2X_UPSTREAM */
	/* In kernels starting from 2.6.31 netdev layer does this */
	dev->trans_start = jiffies;
#endif
#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
	if (likely(!txdata->parent_fp->esx.dynamic_netq_stop))
#endif
	if (unlikely(bnx2x_tx_avail(bp, txdata) < MAX_DESC_PER_TX_PKT)) {
#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
		netif_tx_stop_queue(txq);
#else
		netif_stop_queue(dev);
#endif

		/* paired memory barrier is in bnx2x_tx_int(), we have to keep
		 * ordering of set_bit() in netif_tx_stop_queue() and read of
		 * fp->bd_tx_cons */
		smp_mb();

		bnx2x_fp_qstats(bp, txdata->parent_fp)->driver_xoff++;
		if (bnx2x_tx_avail(bp, txdata) >= MAX_DESC_PER_TX_PKT)
#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
			netif_tx_wake_queue(txq);
#else
			netif_wake_queue(dev);
#endif
	}
	txdata->tx_pkt++;

	return NETDEV_TX_OK;
}

#ifdef BCM_MULTI_COS /* BNX2X_UPSTREAM */
/**
 * bnx2x_setup_tc - routine to configure net_device for multi tc
 *
 * @netdev: net device to configure
 * @tc: number of traffic classes to enable
 *
 * callback connected to the ndo_setup_tc function pointer
 */
int bnx2x_setup_tc(struct net_device *dev, u8 num_tc)
{
	int cos, prio, count, offset;
	struct bnx2x *bp = netdev_priv(dev);

	/* setup tc must be called under rtnl lock */
	ASSERT_RTNL();

	/* no traffic classes requested. Aborting */
	if (!num_tc) {
		netdev_reset_tc(dev);
		return 0;
	}

	/* requested to support too many traffic classes */
	if (num_tc > bp->max_cos) {
		BNX2X_ERR("support for too many traffic classes requested: %d. Max supported is %d\n",
			  num_tc, bp->max_cos);
		return -EINVAL;
	}

	/* declare amount of supported traffic classes */
	if (netdev_set_num_tc(dev, num_tc)) {
		BNX2X_ERR("failed to declare %d traffic classes\n", num_tc);
		return -EINVAL;
	}

	/* configure priority to traffic class mapping */
	for (prio = 0; prio < BNX2X_MAX_PRIORITY; prio++) {
		netdev_set_prio_tc_map(dev, prio, bp->prio_to_cos[prio]);
		DP(BNX2X_MSG_SP | NETIF_MSG_IFUP,
		   "mapping priority %d to tc %d\n",
		   prio, bp->prio_to_cos[prio]);
	}

	/* Use this configuration to differentiate tc0 from other COSes
	   This can be used for ets or pfc, and save the effort of setting
	   up a multio class queue disc or negotiating DCBX with a switch
	netdev_set_prio_tc_map(dev, 0, 0);
	DP(BNX2X_MSG_SP, "mapping priority %d to tc %d\n", 0, 0);
	for (prio = 1; prio < 16; prio++) {
		netdev_set_prio_tc_map(dev, prio, 1);
		DP(BNX2X_MSG_SP, "mapping priority %d to tc %d\n", prio, 1);
	} */

	/* configure traffic class to transmission queue mapping */
	for (cos = 0; cos < bp->max_cos; cos++) {
		count = BNX2X_NUM_ETH_QUEUES(bp);
		offset = cos * BNX2X_NUM_NON_CNIC_QUEUES(bp);
		netdev_set_tc_queue(dev, cos, count, offset);
		DP(BNX2X_MSG_SP | NETIF_MSG_IFUP,
		   "mapping tc %d to offset %d count %d\n",
		   cos, offset, count);
	}

	return 0;
}
#endif

/* called with rtnl_lock */
int bnx2x_change_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	struct bnx2x *bp = netdev_priv(dev);
	int rc = 0;

	if (!bnx2x_is_valid_ether_addr(bp, addr->sa_data)) {
		BNX2X_ERR("Requested MAC address is not valid\n");
		return -EINVAL;
	}

	if (IS_MF_STORAGE_ONLY(bp) && !is_zero_ether_addr(addr->sa_data)) {
		BNX2X_ERR("Can't configure non-zero address on iSCSI or FCoE functions in MF-SD mode\n");
		return -EINVAL;
	}

	if (netif_running(dev))  {
		rc = bnx2x_set_eth_mac(bp, false);
		if (rc)
			return rc;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)) /* ! BNX2X_UPSTREAM */
	dev->addr_assign_type &= ~NET_ADDR_RANDOM;
#endif
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	if (netif_running(dev))
		rc = bnx2x_set_eth_mac(bp, true);

	return rc;
}

static void bnx2x_free_fp_mem_at(struct bnx2x *bp, int fp_index)
{
	union host_hc_status_block *sb = &bnx2x_fp(bp, fp_index, status_blk);
	struct bnx2x_fastpath *fp = &bp->fp[fp_index];
	u8 cos;

	/* Common */

#ifdef BCM_OOO /* not BNX2X_UPSTREAM */
	/* OOO and Forwarding clients use CNIC status block
	 * FCoE client uses default status block
	 */
	if (IS_OOO_IDX(fp_index) || IS_FWD_IDX(fp_index) ||
		IS_FCOE_IDX(fp_index)) {
#else /* BNX2X_UPSTREAM */
	if (IS_FCOE_IDX(fp_index)) {
#endif
		memset(sb, 0, sizeof(union host_hc_status_block));
		fp->status_blk_mapping = 0;
	} else {
		/* status blocks */
		if (!CHIP_IS_E1x(bp))
			BNX2X_PCI_FREE(sb->e2_sb,
				       bnx2x_fp(bp, fp_index,
						status_blk_mapping),
				       sizeof(struct host_hc_status_block_e2));
		else
			BNX2X_PCI_FREE(sb->e1x_sb,
				       bnx2x_fp(bp, fp_index,
						status_blk_mapping),
				       sizeof(struct host_hc_status_block_e1x));
	}

	/* Rx */
	if (!skip_rx_queue(bp, fp_index)) {
		bnx2x_free_rx_bds(fp);

		/* fastpath rx rings: rx_buf rx_desc rx_comp */
		BNX2X_FREE(bnx2x_fp(bp, fp_index, rx_buf_ring));
		BNX2X_PCI_FREE(bnx2x_fp(bp, fp_index, rx_desc_ring),
			       bnx2x_fp(bp, fp_index, rx_desc_mapping),
			       sizeof(struct eth_rx_bd) * NUM_RX_BD);

		BNX2X_PCI_FREE(bnx2x_fp(bp, fp_index, rx_comp_ring),
			       bnx2x_fp(bp, fp_index, rx_comp_mapping),
			       sizeof(struct eth_fast_path_rx_cqe) *
			       NUM_RCQ_BD);

		/* SGE ring */
		BNX2X_FREE(bnx2x_fp(bp, fp_index, rx_page_ring));
		BNX2X_PCI_FREE(bnx2x_fp(bp, fp_index, rx_sge_ring),
			       bnx2x_fp(bp, fp_index, rx_sge_mapping),
			       BCM_PAGE_SIZE * NUM_RX_SGE_PAGES);
	}

	/* Tx */
	if (!skip_tx_queue(bp, fp_index)) {
		/* fastpath tx rings: tx_buf tx_desc */
		for_each_cos_in_tx_queue(fp, cos) {
			struct bnx2x_fp_txdata *txdata = fp->txdata_ptr[cos];

			DP(NETIF_MSG_IFDOWN,
			   "freeing tx memory of fp %d cos %d cid %d\n",
			   fp_index, cos, txdata->cid);

			BNX2X_FREE(txdata->tx_buf_ring);
			BNX2X_PCI_FREE(txdata->tx_desc_ring,
				txdata->tx_desc_mapping,
				sizeof(union eth_tx_bd_types) * NUM_TX_BD);
		}
	}
	/* end of fastpath */
}

static void bnx2x_free_fp_mem_cnic(struct bnx2x *bp)
{
	int i;
	for_each_cnic_queue(bp, i)
		bnx2x_free_fp_mem_at(bp, i);
}

void bnx2x_free_fp_mem(struct bnx2x *bp)
{
	int i;
	for_each_eth_queue(bp, i)
		bnx2x_free_fp_mem_at(bp, i);
}

static void set_sb_shortcuts(struct bnx2x *bp, int index)
{
	union host_hc_status_block status_blk = bnx2x_fp(bp, index, status_blk);
	if (!CHIP_IS_E1x(bp)) {
		bnx2x_fp(bp, index, sb_index_values) =
			(__le16 *)status_blk.e2_sb->sb.index_values;
		bnx2x_fp(bp, index, sb_running_index) =
			(__le16 *)status_blk.e2_sb->sb.running_index;
	} else {
		bnx2x_fp(bp, index, sb_index_values) =
			(__le16 *)status_blk.e1x_sb->sb.index_values;
		bnx2x_fp(bp, index, sb_running_index) =
			(__le16 *)status_blk.e1x_sb->sb.running_index;
	}
}

/* Returns the number of actually allocated BDs */
_UP_STATIC
int bnx2x_alloc_rx_bds(struct bnx2x_fastpath *fp,
			      int rx_ring_size)
{
	struct bnx2x *bp = fp->bp;
	u16 ring_prod, cqe_ring_prod;
	int i, failure_cnt = 0;

	fp->rx_comp_cons = 0;
	cqe_ring_prod = ring_prod = 0;

	/* This routine is called only during fo init so
	 * fp->eth_q_stats.rx_skb_alloc_failed = 0
	 */
	for (i = 0; i < rx_ring_size; i++) {
		if (bnx2x_alloc_rx_data(bp, fp, ring_prod, GFP_KERNEL) < 0) {
			failure_cnt++;
			continue;
		}
		ring_prod = NEXT_RX_IDX(ring_prod);
		cqe_ring_prod = NEXT_RCQ_IDX(cqe_ring_prod);
		WARN_ON(ring_prod <= (i - failure_cnt));
	}

	if (failure_cnt)
		BNX2X_ERR("was only able to allocate %d rx skbs on queue[%d]\n",
			  i - failure_cnt, fp->index);

	fp->rx_bd_prod = ring_prod;
	/* Limit the CQE producer by the CQE ring size */
	fp->rx_comp_prod = min_t(u16, NUM_RCQ_RINGS*RCQ_DESC_CNT,
			       cqe_ring_prod);
	fp->rx_pkt = fp->rx_calls = 0;

	bnx2x_fp_stats(bp, fp)->eth_q_stats.rx_skb_alloc_failed += failure_cnt;

	return i - failure_cnt;
}

static void bnx2x_set_next_page_rx_cq(struct bnx2x_fastpath *fp)
{
	int i;

	for (i = 1; i <= NUM_RCQ_RINGS; i++) {
		struct eth_rx_cqe_next_page *nextpg;

		nextpg = (struct eth_rx_cqe_next_page *)
			&fp->rx_comp_ring[RCQ_DESC_CNT * i - 1];
		nextpg->addr_hi =
			cpu_to_le32(U64_HI(fp->rx_comp_mapping +
				   BCM_PAGE_SIZE*(i % NUM_RCQ_RINGS)));
		nextpg->addr_lo =
			cpu_to_le32(U64_LO(fp->rx_comp_mapping +
				   BCM_PAGE_SIZE*(i % NUM_RCQ_RINGS)));
	}
}

#if (!defined(__VMKLNX__) || !DYNAMIC_NETQ_ALLOC) /* BNX2X_UPSTREAM */
static int bnx2x_alloc_fp_mem_at(struct bnx2x *bp, int index)
#else
int bnx2x_esx_alloc_fp_mem_at(struct bnx2x *bp, int index, int alloc_skb)
#endif
{
	union host_hc_status_block *sb;
	struct bnx2x_fastpath *fp = &bp->fp[index];
	int ring_size = 0;
	u8 cos;
	int rx_ring_size = 0;

	if (!bp->rx_ring_size && IS_MF_STORAGE_ONLY(bp)) {
		rx_ring_size = MIN_RX_SIZE_NONTPA;
		bp->rx_ring_size = rx_ring_size;
	} else if (!bp->rx_ring_size) {
		rx_ring_size = MAX_RX_AVAIL/BNX2X_NUM_RX_QUEUES(bp);

		if (CHIP_IS_E3(bp)) {
			u32 cfg = SHMEM_RD(bp,
					   dev_info.port_hw_config[BP_PORT(bp)].
					   default_cfg);

			/* Decrease ring size for 1G functions */
			if ((cfg & PORT_HW_CFG_NET_SERDES_IF_MASK) ==
			    PORT_HW_CFG_NET_SERDES_IF_SGMII)
				rx_ring_size /= 10;
		}

		/* allocate at least number of buffers required by FW */
		rx_ring_size = max_t(int, bp->disable_tpa ? MIN_RX_SIZE_NONTPA :
				     MIN_RX_SIZE_TPA, rx_ring_size);

		bp->rx_ring_size = rx_ring_size;
	} else /* if rx_ring_size specified - use it */
		rx_ring_size = bp->rx_ring_size;

	DP(BNX2X_MSG_SP, "calculated rx_ring_size %d\n", rx_ring_size);

	/* Common */
	sb = &bnx2x_fp(bp, index, status_blk);

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	if (IS_OOO_IDX(index) || IS_FWD_IDX(index)) {
		if (!CHIP_IS_E1x(bp))
			sb->e2_sb = bp->cnic_sb.e2_sb;
		else
			sb->e1x_sb = bp->cnic_sb.e1x_sb;

		bnx2x_fp(bp, index, status_blk_mapping) =
			bp->cnic_sb_mapping;
	} else
#endif
	if (!IS_FCOE_IDX(index)) {
		/* status blocks */
		if (!CHIP_IS_E1x(bp))
			BNX2X_PCI_ALLOC(sb->e2_sb,
				&bnx2x_fp(bp, index, status_blk_mapping),
				sizeof(struct host_hc_status_block_e2));
		else
			BNX2X_PCI_ALLOC(sb->e1x_sb,
				&bnx2x_fp(bp, index, status_blk_mapping),
			    sizeof(struct host_hc_status_block_e1x));
	}

	/* FCoE Queue uses Default SB and doesn't ACK the SB, thus no need to
	 * set shortcuts for it.
	 */
	if (!IS_FCOE_IDX(index))
		set_sb_shortcuts(bp, index);

	/* Tx */
	if (!skip_tx_queue(bp, index)) {
		/* fastpath tx rings: tx_buf tx_desc */
		for_each_cos_in_tx_queue(fp, cos) {
			struct bnx2x_fp_txdata *txdata = fp->txdata_ptr[cos];

			DP(NETIF_MSG_IFUP,
			   "allocating tx memory of fp %d cos %d\n",
			   index, cos);

			BNX2X_ALLOC(txdata->tx_buf_ring,
				sizeof(struct sw_tx_bd) * NUM_TX_BD);
			BNX2X_PCI_ALLOC(txdata->tx_desc_ring,
				&txdata->tx_desc_mapping,
				sizeof(union eth_tx_bd_types) * NUM_TX_BD);
		}
	}

	/* Rx */
	if (!skip_rx_queue(bp, index)) {
		/* fastpath rx rings: rx_buf rx_desc rx_comp */
		BNX2X_ALLOC(bnx2x_fp(bp, index, rx_buf_ring),
				sizeof(struct sw_rx_bd) * NUM_RX_BD);
		BNX2X_PCI_ALLOC(bnx2x_fp(bp, index, rx_desc_ring),
				&bnx2x_fp(bp, index, rx_desc_mapping),
				sizeof(struct eth_rx_bd) * NUM_RX_BD);

#ifndef BNX2X_CHAR_DEV /* BNX2X_UPSTREAM */
		BNX2X_PCI_ALLOC(bnx2x_fp(bp, index, rx_comp_ring),
				&bnx2x_fp(bp, index, rx_comp_mapping),
				sizeof(struct eth_fast_path_rx_cqe) *
				NUM_RCQ_BD);
#else
		BNX2X_PCI_FALLOC(bnx2x_fp(bp, index, rx_comp_ring),
				 &bnx2x_fp(bp, index, rx_comp_mapping),
				 sizeof(struct eth_fast_path_rx_cqe) *
				 NUM_RCQ_BD);
#endif

		/* SGE ring */
		BNX2X_ALLOC(bnx2x_fp(bp, index, rx_page_ring),
				sizeof(struct sw_rx_page) * NUM_RX_SGE);
		BNX2X_PCI_ALLOC(bnx2x_fp(bp, index, rx_sge_ring),
				&bnx2x_fp(bp, index, rx_sge_mapping),
				BCM_PAGE_SIZE * NUM_RX_SGE_PAGES);
		/* RX BD ring */
		bnx2x_set_next_page_rx_bd(fp);

		/* CQ ring */
		bnx2x_set_next_page_rx_cq(fp);

		/* BDs */
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		if (IS_OOO_FP(fp)) {
			ring_size = bnx2x_alloc_ooo_rx_bd_ring(fp);
			if (ring_size <	 min_t(int,
			/* Delete me! For integration only! */
					       min_t(int,
						     bp->tx_ring_size / 2,
						     500),
/*					       min_t(int,
						     bp->tx_ring_size / 2,
						     bp->rx_ring_size),
 */
					       INIT_OOO_RING_SIZE))
				goto alloc_mem_err;
		} else {
#endif
#if defined(__VMKLNX__) && (DYNAMIC_NETQ_ALLOC) /* ! BNX2X_UPSTREAM */
	/* initialize ring_size in case alloc_skb is not set */
	ring_size = rx_ring_size;
	if (alloc_skb)
#endif
		ring_size = bnx2x_alloc_rx_bds(fp, rx_ring_size);
		if (ring_size < rx_ring_size)
			goto alloc_mem_err;
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		}
#endif
	}

	return 0;

/* handles low memory cases */
alloc_mem_err:
	BNX2X_ERR("Unable to allocate full memory for queue %d (size %d)\n",
						index, ring_size);
	/* FW will drop all packets if queue is not big enough,
	 * In these cases we disable the queue
	 * Min size is different for OOO, TPA and non-TPA queues
	 */
#ifdef BCM_OOO /* not BNX2X_UPSTREAM */
	if ((IS_OOO_IDX(index) && ring_size < MIN_RX_AVAIL_OOO) ||
	    (!IS_OOO_IDX(index) &&
		ring_size < (fp->disable_tpa ?
				MIN_RX_SIZE_NONTPA : MIN_RX_SIZE_TPA))) {
#else /* BNX2X_UPSTREAM */
	if (ring_size < (fp->disable_tpa ?
				MIN_RX_SIZE_NONTPA : MIN_RX_SIZE_TPA)) {
#endif
			/* release memory allocated for this queue */
			bnx2x_free_fp_mem_at(bp, index);
			return -ENOMEM;
	}
	return 0;
}

static int bnx2x_alloc_fp_mem_cnic(struct bnx2x *bp)
{
	if (!NO_FCOE(bp))
		/* FCoE */
		if (bnx2x_alloc_fp_mem_at(bp, FCOE_IDX(bp)))
			/* we will fail load process instead of mark
			 * NO_FCOE_FLAG
			 */
			return -ENOMEM;
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	if (!NO_ISCSI_OOO(bp)) {
		/* OOO + FWD - if allocation fails we disabled iSCSI OOO */
		if (bnx2x_alloc_fp_mem_at(bp, OOO_IDX(bp))) {
			bp->flags |= NO_ISCSI_OOO_FLAG;
		} else if (bnx2x_alloc_fp_mem_at(bp, FWD_IDX(bp))) {
			bnx2x_free_fp_mem_at(bp, OOO_IDX(bp));
			bp->flags |= NO_ISCSI_OOO_FLAG;
		}
	}
#endif

	return 0;
}

static int bnx2x_alloc_fp_mem(struct bnx2x *bp)
{
	int i;

	/* 1. Allocate FP for leading - fatal if error
	 * 2. Allocate RSS - fix number of queues if error
	 */

	/* leading */
	if (bnx2x_alloc_fp_mem_at(bp, 0))
		return -ENOMEM;

	/* RSS */
	for_each_nondefault_eth_queue(bp, i)
#if ((!defined(__VMKLNX__)) || !DYNAMIC_NETQ_ALLOC) /* BNX2X_UPSTREAM */
		if (bnx2x_alloc_fp_mem_at(bp, i))
#else
		if (bnx2x_esx_alloc_fp_mem_at(bp, i, 0))
#endif
			break;

	/* handle memory failures */
	if (i != BNX2X_NUM_ETH_QUEUES(bp)) {
		int delta = BNX2X_NUM_ETH_QUEUES(bp) - i;

		WARN_ON(delta < 0);
		bnx2x_shrink_eth_fp(bp, delta);
		if (CNIC_SUPPORT(bp))
			/* move non eth FPs next to last eth FP
			 * must be done in that order of IDX_OFFSET enum
			 */
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
			bnx2x_move_fp(bp, OOO_IDX(bp), OOO_IDX(bp) - delta);
		if (CNIC_SUPPORT(bp))
#endif
			/* move FCoE fp even NO_FCOE_FLAG is on */
			bnx2x_move_fp(bp, FCOE_IDX(bp), FCOE_IDX(bp) - delta);
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		if (CNIC_SUPPORT(bp))
			bnx2x_move_fp(bp, FWD_IDX(bp), FWD_IDX(bp) - delta);
#endif
		bp->num_ethernet_queues -= delta;
		bp->num_queues = bp->num_ethernet_queues +
				 bp->num_cnic_queues;
		BNX2X_ERR("Adjusted num of queues from %d to %d\n",
			  bp->num_queues + delta, bp->num_queues);
	}

	return 0;
}

void bnx2x_free_mem_bp(struct bnx2x *bp)
{
	int i;

	for (i = 0; i < bp->fp_array_size; i++)
		kfree(bp->fp[i].tpa_info);
	kfree(bp->fp);
	kfree(bp->sp_objs);
	kfree(bp->fp_stats);
	kfree(bp->bnx2x_txq);
	kfree(bp->msix_table);
	kfree(bp->ilt);
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	if (IS_PF(bp))
		vfree(bp->dump_buff);
#endif
}

int __devinit bnx2x_alloc_mem_bp(struct bnx2x *bp)
{
	struct bnx2x_fastpath *fp;
	struct msix_entry *tbl;
	struct bnx2x_ilt *ilt;
	int msix_table_size = 0;
	int fp_array_size, txq_array_size;
	int i;

	/*
	 * The biggest MSI-X table we might need is as a maximum number of fast
	 * path IGU SBs plus default SB (for PF only).
	 */
	msix_table_size = bp->igu_sb_cnt;
	if (IS_PF(bp))
		msix_table_size++;
	BNX2X_DEV_INFO("msix_table_size %d\n", msix_table_size);

	/* fp array: RSS plus CNIC related L2 queues */
	fp_array_size = BNX2X_MAX_RSS_COUNT(bp) + CNIC_SUPPORT(bp);
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	fp_array_size += 2 * CNIC_SUPPORT(bp);
#endif
	bp->fp_array_size = fp_array_size;
	BNX2X_DEV_INFO("fp_array_size %d\n", bp->fp_array_size);

	fp = kcalloc(bp->fp_array_size, sizeof(*fp), GFP_KERNEL);
	if (!fp)
		goto alloc_err;
	for (i = 0; i < bp->fp_array_size; i++) {
		fp[i].tpa_info =
			kcalloc(ETH_MAX_AGGREGATION_QUEUES_E1H_E2,
				sizeof(struct bnx2x_agg_info), GFP_KERNEL);
		if (!(fp[i].tpa_info))
			goto alloc_err;
	}

	bp->fp = fp;

	/* allocate sp objs */
	bp->sp_objs = kcalloc(bp->fp_array_size, sizeof(struct bnx2x_sp_objs),
			      GFP_KERNEL);
	if (!bp->sp_objs)
		goto alloc_err;

	/* allocate fp_stats */
	bp->fp_stats = kcalloc(bp->fp_array_size, sizeof(struct bnx2x_fp_stats),
			       GFP_KERNEL);
	if (!bp->fp_stats)
		goto alloc_err;

	/* Allocate memory for the transmission queues array */
	txq_array_size =
		BNX2X_MAX_RSS_COUNT(bp) * BNX2X_MULTI_TX_COS + CNIC_SUPPORT(bp);
#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
	txq_array_size += 2 * CNIC_SUPPORT(bp);
#endif
	BNX2X_DEV_INFO("txq_array_size %d", txq_array_size);

	bp->bnx2x_txq = kcalloc(txq_array_size, sizeof(struct bnx2x_fp_txdata),
				GFP_KERNEL);
	if (!bp->bnx2x_txq)
		goto alloc_err;

	/* msix table */
	tbl = kcalloc(msix_table_size, sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		goto alloc_err;
	bp->msix_table = tbl;

	/* ilt */
	ilt = kzalloc(sizeof(*ilt), GFP_KERNEL);
	if (!ilt)
		goto alloc_err;
	bp->ilt = ilt;

#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	if (IS_PF(bp))
		bp->dump_buff = vzalloc(bnx2x_get_regs_len(bp->dev));
	/* do not consider as an error if null! */
#endif
	return 0;
alloc_err:
	bnx2x_free_mem_bp(bp);
	return -ENOMEM;
}

int bnx2x_reload_if_running(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	ESX_CHK_VF_COUNT(bp, "reload");

	if (unlikely(!netif_running(dev)))
		return 0;

	bnx2x_nic_unload(bp, UNLOAD_NORMAL, true);
	return bnx2x_nic_load(bp, LOAD_NORMAL);
}

int bnx2x_get_cur_phy_idx(struct bnx2x *bp)
{
	u32 sel_phy_idx = 0;
	if (bp->link_params.num_phys <= 1)
		return INT_PHY;

	if (bp->link_vars.link_up) {
		sel_phy_idx = EXT_PHY1;
		/* In case link is SERDES, check if the EXT_PHY2 is the one */
		if ((bp->link_vars.link_status & LINK_STATUS_SERDES_LINK) &&
		    (bp->link_params.phy[EXT_PHY2].supported & SUPPORTED_FIBRE))
			sel_phy_idx = EXT_PHY2;
	} else {

		switch (bnx2x_phy_selection(&bp->link_params)) {
		case PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT:
		case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY:
		case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY:
		       sel_phy_idx = EXT_PHY1;
		       break;
		case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY:
		case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY:
		       sel_phy_idx = EXT_PHY2;
		       break;
		}
	}

	return sel_phy_idx;
}
int bnx2x_get_link_cfg_idx(struct bnx2x *bp)
{
	u32 sel_phy_idx = bnx2x_get_cur_phy_idx(bp);
	/*
	 * The selected activated PHY is always after swapping (in case PHY
	 * swapping is enabled). So when swapping is enabled, we need to reverse
	 * the configuration
	 */

	if (bp->link_params.multi_phy_config &
	    PORT_HW_CFG_PHY_SWAPPED_ENABLED) {
		if (sel_phy_idx == EXT_PHY1)
			sel_phy_idx = EXT_PHY2;
		else if (sel_phy_idx == EXT_PHY2)
			sel_phy_idx = EXT_PHY1;
	}
	return LINK_CONFIG_IDX(sel_phy_idx);
}

#ifdef NETDEV_FCOE_WWNN
int bnx2x_fcoe_get_wwn(struct net_device *dev, u64 *wwn, int type)
{
	struct bnx2x *bp = netdev_priv(dev);
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	switch (type) {
	case NETDEV_FCOE_WWNN:
		*wwn = HILO_U64(cp->fcoe_wwn_node_name_hi,
				cp->fcoe_wwn_node_name_lo);
		break;
	case NETDEV_FCOE_WWPN:
		*wwn = HILO_U64(cp->fcoe_wwn_port_name_hi,
				cp->fcoe_wwn_port_name_lo);
		break;
	default:
		BNX2X_ERR("Wrong WWN type requested - %d\n", type);
		return -EINVAL;
	}

	return 0;
}
#endif

/* called with rtnl_lock */
int bnx2x_change_mtu(struct net_device *dev, int new_mtu)
{
	struct bnx2x *bp = netdev_priv(dev);
#ifdef __VMKLNX__ /* ! BNX2X_UPSTREAM */
	int rc = 0;
#endif

	if (bp->recovery_state != BNX2X_RECOVERY_DONE) {
		BNX2X_ERR("Can't perform change MTU during parity recovery\n");
		return -EAGAIN;
	}

	if ((new_mtu > ETH_MAX_JUMBO_PACKET_SIZE) ||
	    ((new_mtu + ETH_HLEN) < ETH_MIN_PACKET_SIZE)) {
		BNX2X_ERR("Can't support requested MTU size\n");
		return -EINVAL;
	}

#ifdef __VMKLNX__ /* non BNX2X_UPSTREAM */
	if (dev->mtu == new_mtu)
		return rc;

	ESX_CHK_VF_COUNT(bp, "MTU change");

	if (netif_running(dev)) {

#if (VMWARE_ESX_DDK_VERSION < 50000)
		/* There is no need to hold rtnl_lock
		 * when calling change MTU into driver
		 * from VMkernel ESX 5.0 onwards.
		 */
		rtnl_lock();
#endif
		bnx2x_nic_unload(bp, UNLOAD_NORMAL, true);
		dev->mtu = new_mtu;

		if (bp->dev->mtu > ETH_MAX_PACKET_SIZE)
			bp->rx_ring_size = BNX2X_ESX_INIT_JUMBO_RX_RING_SIZE;
		else
			bp->rx_ring_size = BNX2X_ESX_INIT_RX_RING_SIZE;

		rc = bnx2x_nic_load(bp, LOAD_NORMAL);

#if (VMWARE_ESX_DDK_VERSION < 50000)
		rtnl_unlock();
#endif
	} else
		dev->mtu = new_mtu;

	return rc;
#else /* BNX2X_UPSTREAM */
	/* This does not race with packet allocation
	 * because the actual alloc size is
	 * only updated as part of load
	 */
	dev->mtu = new_mtu;

	return bnx2x_reload_if_running(dev);
#endif
}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)) /* BNX2X_UPSTREAM */

netdev_features_t bnx2x_fix_features(struct net_device *dev,
				     netdev_features_t features)
{
	struct bnx2x *bp = netdev_priv(dev);

	/* TPA requires Rx CSUM offloading */
	if (!(features & NETIF_F_RXCSUM) || bp->disable_tpa) {
		features &= ~NETIF_F_LRO;
		features &= ~NETIF_F_GRO;
	}

	return features;
}

int bnx2x_set_features(struct net_device *dev, netdev_features_t features)
{
	struct bnx2x *bp = netdev_priv(dev);
	u32 flags = bp->flags;
	u32 changes;
	bool bnx2x_reload = false;

	if (features & NETIF_F_LRO)
		flags |= TPA_ENABLE_FLAG;
	else
		flags &= ~TPA_ENABLE_FLAG;

	if (features & NETIF_F_GRO)
		flags |= GRO_ENABLE_FLAG;
	else
		flags &= ~GRO_ENABLE_FLAG;

	if (features & NETIF_F_LOOPBACK) {
		if (bp->link_params.loopback_mode != LOOPBACK_BMAC) {
			bp->link_params.loopback_mode = LOOPBACK_BMAC;
			bnx2x_reload = true;
		}
	} else {
		if (bp->link_params.loopback_mode != LOOPBACK_NONE) {
			bp->link_params.loopback_mode = LOOPBACK_NONE;
			bnx2x_reload = true;
		}
	}

	changes = flags ^ bp->flags;

	/* if GRO is changed while LRO is enabled, don't force a reload */
	if ((changes & GRO_ENABLE_FLAG) && (flags & TPA_ENABLE_FLAG))
		changes &= ~GRO_ENABLE_FLAG;

	if (changes)
		bnx2x_reload = true;

	bp->flags = flags;

	if (bnx2x_reload) {
		if (bp->recovery_state == BNX2X_RECOVERY_DONE)
			return bnx2x_reload_if_running(dev);
		/* else: bnx2x_nic_load() will be called at end of recovery */
	}

	return 0;
}
#endif /*0x020627*/

void bnx2x_tx_timeout(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

#ifdef BNX2X_STOP_ON_ERROR
	if (!bp->panic)
		bnx2x_panic();
#endif

	/* This allows the netif to be shutdown gracefully before resetting */
	bnx2x_schedule_sp_rtnl(bp, BNX2X_SP_RTNL_TX_TIMEOUT, 0);
}

int bnx2x_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2x *bp;

	if (!dev) {
		dev_err(&pdev->dev, "BAD net device from bnx2x_init_one\n");
		return -ENODEV;
	}
	bp = netdev_priv(dev);

	rtnl_lock();

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)) /* BNX2X_UPSTREAM */
	pci_save_state(pdev);
#else
	pci_save_state(pdev, bp->pci_state);
#endif

	if (!netif_running(dev)) {
		rtnl_unlock();
		return 0;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)) /* ! BNX2X_UPSTREAM */
	flush_scheduled_work();
#endif
	netif_device_detach(dev);

	bnx2x_nic_unload(bp, UNLOAD_CLOSE, false);

	bnx2x_set_power_state(bp, pci_choose_state(pdev, state));

	rtnl_unlock();

	return 0;
}

int bnx2x_resume(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2x *bp;
	int rc;

	if (!dev) {
		dev_err(&pdev->dev, "BAD net device from bnx2x_init_one\n");
		return -ENODEV;
	}
	bp = netdev_priv(dev);

	if (bp->recovery_state != BNX2X_RECOVERY_DONE) {
		BNX2X_ERR("Handling parity error recovery. Try again later\n");
		return -EAGAIN;
	}

	rtnl_lock();

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)) /* BNX2X_UPSTREAM */
	pci_restore_state(pdev);
#else
	pci_restore_state(pdev, bp->pci_state);
#endif

	if (!netif_running(dev)) {
		rtnl_unlock();
		return 0;
	}

	bnx2x_set_power_state(bp, PCI_D0);
	netif_device_attach(dev);

	rc = bnx2x_nic_load(bp, LOAD_OPEN);

	rtnl_unlock();

	return rc;
}

#ifdef BCM_VLAN /* ! BNX2X_UPSTREAM */
#if defined(__VMKLNX__) && (DYNAMIC_NETQ_ALLOC) /* ! BNX2X_UPSTREAM */
int bnx2x_esx_set_vlan_stripping(struct bnx2x *bp, bool set, int esx_netq_index)
#else /* BNX2X_UPSTREAM */
static int bnx2x_set_vlan_stripping(struct bnx2x *bp, bool set)
#endif
{
	struct bnx2x_queue_state_params q_params = {NULL};
	struct bnx2x_queue_update_params *update_params =
		&q_params.params.update;
	int i, rc;

	/* We want to wait for completion in this context */
	__set_bit(RAMROD_COMP_WAIT, &q_params.ramrod_flags);

	/* Set the command */
	q_params.cmd = BNX2X_Q_CMD_UPDATE;

	/* Enable VLAN stripping if requested */
	if (set)
		__set_bit(BNX2X_Q_UPDATE_IN_VLAN_REM,
			&update_params->update_flags);

	/* Indicate that VLAN stripping configuration has changed */
	__set_bit(BNX2X_Q_UPDATE_IN_VLAN_REM_CHNG,
		  &update_params->update_flags);

	for_each_rx_queue_(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];
		if (IS_FCOE_IDX(i) && !CNIC_LOADED(bp))
			continue;

#ifdef BCM_OOO /* ! BNX2X_UPSTREAM */
		/* Don't configure VLAN stripping for iSCSI OOO ring */
		if (IS_OOO_IDX(i))
			continue;
#endif
#ifdef BNX2X_ESX_CNA /* ! BNX2X_UPSTREAM */
		if (IS_FCOE_IDX(i))
			continue;
#endif
		/* Set the appropriate Queue object */
		q_params.q_obj = &bnx2x_sp_obj(bp, fp).q_obj;

		/* Update the Queue state */
		rc = bnx2x_queue_state_change(bp, &q_params);
		if (rc) {
			BNX2X_ERR("Failed to configure VLAN stripping for Queue %d\n",
				  i);
			return rc;
		}
	}

	return 0;
}

/* called with rtnl_lock */
void bnx2x_vlan_rx_register(struct net_device *dev, struct vlan_group *vlgrp)
{
	struct bnx2x *bp = netdev_priv(dev);
	int rc = 0;

	if (IS_VF(bp))
		return;

	/* Configure VLAN stripping if NIC is up.
	 * Otherwise just set the bp->vlgrp and stripping will be
	 * configured in bnx2x_nic_load().
	 */
	if (bp->state == BNX2X_STATE_OPEN) {
		bool set = (vlgrp != NULL);
		rc = bnx2x_set_vlan_stripping(bp, set);
		if (rc) {
			netdev_err(dev, "Failed to %s HW VLAN stripping\n",
				   set ? "set" : "clear");
			if (set)
				bnx2x_set_vlan_stripping(bp, false);
		}
	}

	/*
	 * If we failed to configure VLAN stripping we don't
	 * want to use HW accelerated flow in bnx2x_rx_int().
	 * Thus we will leave bp->vlgrp to be equal to NULL to
	 * disable it.
	 */
	bp->vlgrp = rc ? NULL : vlgrp;
}

/* called with rtnl_lock */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)) /* ! BNX2X_UPSTREAM */
void bnx2x_vlan_rx_kill_vid(struct net_device *dev, uint16_t vid)
{
	struct bnx2x *bp = netdev_priv(dev);

	if (bp->vlgrp)
		vlan_group_set_device(bp->vlgrp, vid, NULL);
}
#endif
#endif /* BCM_VLAN */

void bnx2x_set_ctx_validation(struct bnx2x *bp, struct eth_context *cxt,
			      u32 cid)
{
	if (!cxt) {
		BNX2X_ERR("bad context pointer %p\n", cxt);
		return;
	}

	/* ustorm cxt validation */
	cxt->ustorm_ag_context.cdu_usage =
		CDU_RSRVD_VALUE_TYPE_A(HW_CID(bp, cid),
			CDU_REGION_NUMBER_UCM_AG, ETH_CONNECTION_TYPE);
	/* xcontext validation */
	cxt->xstorm_ag_context.cdu_reserved =
		CDU_RSRVD_VALUE_TYPE_A(HW_CID(bp, cid),
			CDU_REGION_NUMBER_XCM_AG, ETH_CONNECTION_TYPE);
}

static void storm_memset_hc_timeout(struct bnx2x *bp, u8 port,
				    u8 fw_sb_id, u8 sb_index,
				    u8 ticks)
{
	u32 addr = BAR_CSTRORM_INTMEM +
		   CSTORM_STATUS_BLOCK_DATA_TIMEOUT_OFFSET(fw_sb_id, sb_index);
	REG_WR8(bp, addr, ticks);
	DP(NETIF_MSG_IFUP,
	   "port %x fw_sb_id %d sb_index %d ticks %d\n",
	   port, fw_sb_id, sb_index, ticks);
}

static void storm_memset_hc_disable(struct bnx2x *bp, u8 port,
				    u16 fw_sb_id, u8 sb_index,
				    u8 disable)
{
	u32 enable_flag = disable ? 0 : (1 << HC_INDEX_DATA_HC_ENABLED_SHIFT);
	u32 addr = BAR_CSTRORM_INTMEM +
		   CSTORM_STATUS_BLOCK_DATA_FLAGS_OFFSET(fw_sb_id, sb_index);
	u8 flags = REG_RD8(bp, addr);
	/* clear and set */
	flags &= ~HC_INDEX_DATA_HC_ENABLED;
	flags |= enable_flag;
	REG_WR8(bp, addr, flags);
	DP(NETIF_MSG_IFUP,
	   "port %x fw_sb_id %d sb_index %d disable %d\n",
	   port, fw_sb_id, sb_index, disable);
}

void bnx2x_update_coalesce_sb_index(struct bnx2x *bp, u8 fw_sb_id,
				    u8 sb_index, u8 disable, u16 usec)
{
	int port = BP_PORT(bp);
	u8 ticks = usec / BNX2X_BTR;

	storm_memset_hc_timeout(bp, port, fw_sb_id, sb_index, ticks);

	disable = disable ? 1 : (usec ? 0 : 1);
	storm_memset_hc_disable(bp, port, fw_sb_id, sb_index, disable);
}

void bnx2x_schedule_sp_rtnl(struct bnx2x *bp, enum sp_rtnl_flag flag,
			    u32 verbose)
{
	smp_mb__before_clear_bit();
	set_bit(flag, &bp->sp_rtnl_state);
	smp_mb__after_clear_bit();
	DP((BNX2X_MSG_SP | verbose), "Scheduling sp_rtnl task [Flag: %d]\n",
	   flag);
	schedule_delayed_work(&bp->sp_rtnl_task, 0);
}
EXPORT_SYMBOL(bnx2x_schedule_sp_rtnl);
