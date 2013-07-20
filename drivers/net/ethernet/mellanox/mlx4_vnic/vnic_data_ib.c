/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/mlx4/qp.h>
#include <linux/mlx4/srq.h>
#include <rdma/ib_cache.h>
#include <net/ip6_checksum.h>

#include "vnic.h"
#include "vnic_data.h"

int vnic_post_recv(struct vnic_rx_ring *ring, u64 wr_id)
{
	struct ib_recv_wr *bad_wr;
	int i, rc;

	ring->wr.wr_id = wr_id;

	for (i = 0; i < ring->num_frags; i++)
		ring->sge[i].addr = ring->rx_info[wr_id].dma_addr[i];

	rc = ib_post_srq_recv(ring->srq, &ring->wr, &bad_wr);
	if (unlikely(rc)) {
		/* we will not use a lock here. In the worst case we will have
		 * an incorrect value of need_refill. Not a biggie
		 */

		/*ring->rx_info[wr_id].info = VNIC_FRAG_NOT_POSTED;
		   ring->need_refill = 1;
		 */
		vnic_dbg_data(ring->port->name, "receive failed for buf %llu (%d)\n",
			      wr_id, rc);
	}

	return rc;
}

static void vnic_dealloc_tx_skb(struct vnic_login *login, unsigned cq_index,
				u64 wr_id)
{
	struct vnic_tx_res *tx_res = &login->tx_res[cq_index];
	int is_inline = !!(wr_id & VNIC_SEND_INLINE_FLAG);
	struct sk_buff *skb;
	u64 *mapping;
	int i, off = 0;

	wr_id &= ~VNIC_SEND_INLINE_FLAG;
	skb = tx_res->tx_ring[wr_id].skb;
	ASSERT(skb);
	mapping = tx_res->tx_ring[wr_id].mapping;

	if (!is_inline) {
		if (!vnic_encap_headroom && !skb_is_gso(skb)) {
			ib_dma_unmap_single(login->port->dev->ca, mapping[off],
					    VNIC_ENCAP_LEN, DMA_TO_DEVICE);
			off++;
		}
		if (skb_headlen(skb)) {
			ib_dma_unmap_single(login->port->dev->ca, mapping[off],
					    skb_headlen(skb), DMA_TO_DEVICE);
			off++;
		}
		for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			ib_dma_unmap_page(login->port->dev->ca,
					  mapping[i + off], frag->size,
					  DMA_TO_DEVICE);
		}
	}

	/* dealloc skb */
	dev_kfree_skb_any(skb);
	tx_res->tx_ring[wr_id].skb = NULL;
}

static void vnic_ib_handle_tx_wc(struct vnic_login *login,
				 int tx_res_index, struct ib_wc *wc)
{
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];
	u64 wr_id = wc->wr_id & ~VNIC_SEND_INLINE_FLAG;

	vnic_dbg_data(login->name, "send completion: wr_id %llu, status: %d "
		      "[head %d - tail %d]\n", wr_id, wc->status,
		      tx_res->tx_head, tx_res->tx_tail);

	ASSERT(wr_id < vnic_tx_rings_len);
	vnic_dealloc_tx_skb(login, tx_res_index, wc->wr_id);

	++tx_res->tx_tail;
	--tx_res->tx_outstanding;

	if (unlikely(wc->status != IB_WC_SUCCESS && wc->status != IB_WC_WR_FLUSH_ERR)) {
		vnic_warn(login->name, "failed send event "
			  "(status %d, wr_id %llu, vend_err 0x%x)\n",
			  wc->status, wr_id, wc->vendor_err);
		vnic_warn(login->name, "TX CQE error, queueing rings restart\n");
		if (!login->queue_stopped)
			queue_delayed_work(login_wq, &login->restart_task, HZ / 100);
	}
}

int vnic_post_recvs(struct vnic_rx_ring *ring)
{
	int i, rc;

	for (i = 0; i < ring->size; i++) {
		rc = vnic_post_recv(ring, i);
		if (rc) {
			vnic_err(ring->port->name, "Failed post receive %d\n", rc);
			return rc;
		}
	}

	return 0;
}

static int vnic_vlan_is_valid(struct vnic_login *login,
			      struct vlan_ethhdr *veth)
{
	ASSERT(veth->h_vlan_proto == htons(ETH_P_8021Q));
	if ((be16_to_cpu(veth->h_vlan_TCI) & 0xfff) !=
	    be16_to_cpu(login->vid)) {
		vnic_dbg_data(login->name, "invalid vlan, ingress vid "
			      "0x%x, login: vid 0x%x vlan_used %d\n",
			      be16_to_cpu(veth->h_vlan_TCI),
			      be16_to_cpu(login->vid),
			      login->vlan_used);
		return 0;
	}

	return 1;
}

/* If a vlan tag should exist in the eth_hdr - validate it.
   is_vlan_proto is set if vlan protocol is present in the eth header
   return values 0 - on success, 1 - on error :
   for all vlans gateway (promisc vlan):
	0 - there is no vlan or there is a vlan and it is valid
	1 - vlan is present and not valid.
   for all other vlans:
	0 - there shouldn't be a vlan, or vlan should be present and is valid.
	1 - vlan should be present and it is not, ot it is not valid. */
static int validate_vnic_vlan(struct vnic_login *login,
			      struct vlan_ethhdr *veth,
			      int *is_vlan_proto)
{
	int is_vlan = !!(veth->h_vlan_proto == htons(ETH_P_8021Q));

	*is_vlan_proto = is_vlan;

	if (login->all_vlan_gw)
		return 0;

	if (VNIC_VLAN_ENABLED(login) && login->vid && !is_vlan) {
		vnic_dbg_data(login->name, "missing vlan tag\n");
		VNIC_STATS_INC(login->port_stats.vlan_err);
		return 1;
	}

	if (is_vlan && unlikely(!vnic_vlan_is_valid(login, veth))) {
		vnic_dbg_data(login->name, "invalid vlan tag\n");
		VNIC_STATS_INC(login->port_stats.vlan_err);
		return 1;
	}

	return 0;
}

static void vnic_ib_handle_rx_wc_linear(struct vnic_login *login,
					struct ib_wc *wc, int rx_ring_index)
{
	struct vnic_rx_ring *ring = login->port->rx_ring[rx_ring_index];
	struct eoibhdr *eoib_hdr;
	struct sk_buff *skb;
	struct vlan_ethhdr *veth;
	int rc, wr_id = wc->wr_id, checksum_ok, ip_summed,
	    buf_size = VNIC_BUF_SIZE(ring->port);
	int is_vlan_proto;
	u64 mapping;
	u16 eth_type;
	u8 *va, *eth_hdr;

	spin_lock_bh(&ring->lock);
	ASSERT(wr_id < ring->size);

	skb = ring->rx_info[wr_id].skb;
	mapping = ring->rx_info[wr_id].dma_addr[0];

	/* termination with error */
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if(wc->status != IB_WC_REM_ABORT_ERR &&
		   wc->status != IB_WC_LOC_LEN_ERR) {
			vnic_dbg_data(login->name, "RX CQE error "
				      "(status %d, vend_err 0x%x), "
				      "queueing rings restart\n",
				      wc->status, wc->vendor_err);
			if (!login->queue_stopped)
				queue_delayed_work(login_wq,
						   &login->restart_task,
						   HZ / 10);
		}
		goto repost;
	}

	ASSERT(skb);
	ASSERT(mapping);

	/* If we can't allocate a new RX buffer, dump
	 * this packet and reuse the old buffer.
	 */
	if (unlikely(!vnic_alloc_rx_skb(ring, wr_id, GFP_ATOMIC))) {
		VNIC_STATS_DO_INC(login->stats.rx_dropped);
		goto repost;
	}

	ib_dma_unmap_single(login->port->dev->ca, mapping,
			    buf_size, DMA_FROM_DEVICE);
	skb_put(skb, wc->byte_len);
	skb_pull(skb, IB_GRH_BYTES);

	/* check EoIB header signature and version */
	va = skb->data;
	eoib_hdr = (struct eoibhdr *)va;
	if (unlikely(VNIC_EOIB_HDR_GET_SIG(eoib_hdr) != VNIC_EOIB_HDR_SIG ||
		     VNIC_EOIB_HDR_GET_VER(eoib_hdr) != VNIC_EOIB_HDR_VER)) {
		vnic_dbg_data(login->name, "bad sig (0x%x) or ver (0x%x)\n",
			      VNIC_EOIB_HDR_GET_SIG(eoib_hdr),
			      VNIC_EOIB_HDR_GET_VER(eoib_hdr));
		VNIC_STATS_INC(login->port_stats.sig_ver_err);
		goto repost;
	}

	/* check EoIB CSUM */
	checksum_ok = login->rx_csum && VNIC_CSUM_OK(eoib_hdr);
	ip_summed = checksum_ok ? CHECKSUM_UNNECESSARY : CHECKSUM_NONE;
	if (likely((checksum_ok)))
		VNIC_STATS_INC(login->port_stats.rx_chksum_good);
	else
		VNIC_STATS_INC(login->port_stats.rx_chksum_none);

	/* Ethernet header */
	skb_pull(skb, VNIC_ENCAP_LEN);
	va += VNIC_ENCAP_LEN;
	veth = (struct vlan_ethhdr *)(va);

	eth_hdr = va;
	eth_type = be16_to_cpu(((struct ethhdr *)(va))->h_proto);

	/* validate VLAN tag, strip it if valid */
	if (validate_vnic_vlan(login, veth, &is_vlan_proto))
		goto repost;

	/* for all_vlan_gw - we don't strip the packet but send it as is*/
	if (!login->all_vlan_gw && is_vlan_proto) {
		eth_type = be16_to_cpu(veth->h_vlan_encapsulated_proto);
		eth_hdr += VLAN_HLEN;
		skb_pull(skb, VLAN_HLEN);
		memmove(eth_hdr, va, ETH_ALEN * 2);
	}

	/* update skb fields, keep this before LRO/GRO funcs */
	skb->dev = login->dev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb->ip_summed = ip_summed;

#if defined(NETIF_F_GRO) && !defined(_BP_NO_GRO)
	if ((login->dev->features & NETIF_F_GRO) && checksum_ok) {
		struct vnic_rx_res *rx_res = &login->rx_res[rx_ring_index];
		int ret;

		ret = napi_gro_receive(&rx_res->napi, skb);
		if (ret == GRO_HELD)
			VNIC_STATS_INC(login->port_stats.gro_held);
		else if (ret == GRO_NORMAL)
			VNIC_STATS_INC(login->port_stats.gro_normal);
		else if (ret == GRO_MERGED || ret == GRO_MERGED_FREE)
			VNIC_STATS_INC(login->port_stats.gro_merged);
		else
			VNIC_STATS_INC(login->port_stats.gro_drop);

		goto rx_repost;
	}
#elif defined(NETIF_F_LRO)
	if (login->dev->features & NETIF_F_LRO && checksum_ok) {
		struct vnic_rx_res *rx_res = &login->rx_res[rx_ring_index];

		/* processed for LRO */
                lro_receive_skb(&rx_res->lro, skb, NULL);
		VNIC_STATS_INC(login->port_stats.lro_aggregated);

		goto rx_repost;
	}
#endif

	rc = vnic_rx(login, skb, wc);
	if (unlikely(rc)) {
		vnic_dbg_data(login->name, "vnic_rx failed, rc %d\n", rc);
		goto repost;
	}

rx_repost:
	VNIC_STATS_INC(ring->stats.rx_packets);
	VNIC_STATS_ADD(ring->stats.rx_bytes, wc->byte_len);

	VNIC_STATS_DO_INC(login->stats.rx_packets);
	VNIC_STATS_DO_ADD(login->stats.rx_bytes, wc->byte_len);

	if (unlikely(vnic_post_recv(ring, wr_id)))
		vnic_dbg_data(login->name, "failed to post RX WQE id %d\n",
			      (int)wr_id);
	spin_unlock_bh(&ring->lock);

	return;

repost:
	login->dev->last_rx = jiffies;
	if (unlikely(vnic_post_recv(ring, wr_id)))
		vnic_dbg_data(login->name, "failed to post RX WQE id %d\n",
			      (int)wr_id);

	VNIC_STATS_INC(ring->stats.rx_dropped);
	VNIC_STATS_DO_INC(login->stats.rx_dropped);
	spin_unlock_bh(&ring->lock);

	return;
}

static void vnic_ib_handle_rx_wc(struct vnic_login *login,
				 struct ib_wc *wc, int rx_ring_index)
{
	struct vnic_rx_ring *ring = login->port->rx_ring[rx_ring_index];
	struct ib_device *ib_device = login->port->dev->ca;
	struct vnic_frag_data *frags_entry;
	struct skb_frag_struct frags[VNIC_MAX_RX_FRAGS] = {};
	struct eoibhdr *eoib_hdr;
	struct vlan_ethhdr *veth;
	struct iphdr *ip_hdr;
	u64 wr_id = wc->wr_id;
	u16 eth_type;
	u8 *va, *eth_hdr, ip_type;
	int rc, checksum_ok, ip_offset = ETH_HLEN,
		packet_length = wc->byte_len - VNIC_EOIB_HDR_SIZE,
		page_offset = VNIC_EOIB_HDR_SIZE, ip_summed;
	int is_vlan_proto;

	spin_lock_bh(&ring->lock);
	ASSERT(wr_id < ring->size);

	/* termination with error */
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if(wc->status != IB_WC_REM_ABORT_ERR &&
		   wc->status != IB_WC_LOC_LEN_ERR) {
			vnic_dbg_data(login->name, "RX CQE error "
				      "(status %d, vend_err 0x%x), "
				      "queueing rings restart\n",
				      wc->status, wc->vendor_err);
			if (!login->queue_stopped)
				queue_delayed_work(login_wq, &login->restart_task, HZ / 10);
			goto out;
		}
		goto drop_repost;
	}

	frags_entry = &ring->rx_info[wr_id];

	/* ensure cache coherency for packet headers and get vq */
	ib_dma_sync_single_for_cpu(ib_device,
				   ring->rx_info[wr_id].dma_addr[0] + IB_GRH_BYTES,
				   MAX_HEADER_SIZE, DMA_FROM_DEVICE);

	va = page_address(ring->rx_info[wr_id].frags[0].page.p) +
		ring->rx_info[wr_id].frags[0].page_offset + IB_GRH_BYTES;

	/* check EoIB header signature and version */
	eoib_hdr = (struct eoibhdr *)va;
	if (unlikely(VNIC_EOIB_HDR_GET_SIG(eoib_hdr) != VNIC_EOIB_HDR_SIG ||
		     VNIC_EOIB_HDR_GET_VER(eoib_hdr) != VNIC_EOIB_HDR_VER)) {
		vnic_dbg_data(login->name, "bad sig (0x%x) or ver (0x%x)\n",
			      VNIC_EOIB_HDR_GET_SIG(eoib_hdr),
			      VNIC_EOIB_HDR_GET_VER(eoib_hdr));
		VNIC_STATS_INC(login->port_stats.sig_ver_err);
		goto unmap_repost;
	}

	/* check EoIB CSUM */
	checksum_ok = login->rx_csum && VNIC_CSUM_OK(eoib_hdr);
	ip_summed = checksum_ok ? CHECKSUM_UNNECESSARY : CHECKSUM_NONE;
	if (likely((checksum_ok)))
		VNIC_STATS_INC(login->port_stats.rx_chksum_good);
	else
		VNIC_STATS_INC(login->port_stats.rx_chksum_none);

	/* Ethernet header */
	va += VNIC_ENCAP_LEN;
	veth = (struct vlan_ethhdr *)(va);

	eth_hdr = va;
	eth_type = be16_to_cpu(((struct ethhdr *)(va))->h_proto);

	/* validate VLAN tag, strip it if valid
	 * - if VID is set and !0, then VLAN tag must exist
	 *   note: VID zero can accept untagged packets
	 * - if ingress VID exists: validate it, and update the packet
	 *   note: rx user prio is ignored
	 * - else; it's valid untagged packet
	 */
	if (validate_vnic_vlan(login, veth, &is_vlan_proto))
		goto unmap_repost;

	/* for all_vlan_gw - we don't strip the packet but send it as is*/
	if (!login->all_vlan_gw && is_vlan_proto) {
		ip_offset += VLAN_HLEN;
		page_offset += VLAN_HLEN;
		packet_length -= VLAN_HLEN;
		eth_hdr += VLAN_HLEN;
		eth_type = be16_to_cpu(veth->h_vlan_encapsulated_proto);
		memmove(eth_hdr, va, ETH_ALEN * 2);
	}

	/* IP header */
	va += ip_offset;
	ip_hdr = (struct iphdr *)va;
	ip_type = ip_hdr->protocol;

	ib_dma_sync_single_for_device(ib_device,
				      frags_entry->dma_addr[0] + IB_GRH_BYTES,
				      MAX_HEADER_SIZE, DMA_FROM_DEVICE);

#if defined(NETIF_F_GRO) && !defined(_BP_NO_GRO)
	if ((login->dev->features & NETIF_F_GRO) && checksum_ok) {
		struct vnic_rx_res *rx_res = &login->rx_res[rx_ring_index];
		struct sk_buff *gro_skb;
		struct skb_frag_struct *gro_frags;
		int nr_frags, ret;

		gro_skb = napi_get_frags(&rx_res->napi);
		if (!gro_skb)
			goto drop_repost;

		gro_frags = skb_shinfo(gro_skb)->frags;
		nr_frags = vnic_unmap_and_replace_rx(ring, ib_device,
						     gro_frags, wr_id,
						     wc->byte_len);
		if (unlikely(!nr_frags))
			goto drop_repost;

		/* disregard GRH and eoib headers */
		gro_frags[0].page_offset += page_offset;
		gro_frags[0].size -= page_offset;

		skb_shinfo(gro_skb)->nr_frags = nr_frags;
		gro_skb->len = packet_length;
		gro_skb->data_len = packet_length;
		gro_skb->truesize += packet_length;
		gro_skb->ip_summed = CHECKSUM_UNNECESSARY;

		/* processed for GRO */
		skb_record_rx_queue(gro_skb, rx_res->index);
		ret = napi_gro_frags(&rx_res->napi);
		if (ret == GRO_HELD)
			VNIC_STATS_INC(login->port_stats.gro_held);
		else if (ret == GRO_NORMAL)
			VNIC_STATS_INC(login->port_stats.gro_normal);
		else if (ret == GRO_MERGED || ret == GRO_MERGED_FREE)
			VNIC_STATS_INC(login->port_stats.gro_merged);
		else
			VNIC_STATS_INC(login->port_stats.gro_drop);

		goto rx_repost;
	}
#elif defined(NETIF_F_LRO)
	if (login->dev->features & NETIF_F_LRO && checksum_ok &&
	    eth_type == ETH_P_IP && ip_type == IPPROTO_TCP) {
		struct vnic_rx_res *rx_res = &login->rx_res[rx_ring_index];
		int nr_frags;

		/* unmap the needed fragment and reallocate them.
		 * Fragments that were not used will be reused as is.*/
		nr_frags = vnic_unmap_and_replace_rx(ring, ib_device, frags,
						     wr_id, wc->byte_len);
		if (unlikely(!nr_frags))
			goto drop_repost;

		/* disregard GRH and eoib headers */
		frags[0].page_offset += page_offset;
		frags[0].size -= page_offset;

		/* processed for LRO */
		lro_receive_frags(&rx_res->lro, frags, packet_length,
				  packet_length, NULL, 0);
		VNIC_STATS_INC(login->port_stats.lro_aggregated);

		goto rx_repost;
	}
#endif

	rc = vnic_rx_skb(login, ring, wc, ip_summed, eth_hdr);
	if (unlikely(rc)) {
		vnic_dbg_data(login->name, "vnic_rx_skb failed, rc %d\n", rc);
		goto drop_repost;
	}

rx_repost:
	/* must hold lock when touching login->stats so the stats
	 * task won't read invalid values
	 */
	spin_lock(&login->stats_lock);
	VNIC_STATS_INC(ring->stats.rx_packets);
	VNIC_STATS_ADD(ring->stats.rx_bytes, packet_length);

	VNIC_STATS_DO_INC(login->stats.rx_packets);
	VNIC_STATS_DO_ADD(login->stats.rx_bytes, packet_length);
	spin_unlock(&login->stats_lock);

	login->dev->last_rx = jiffies;
	if (vnic_post_recv(ring, wr_id))
		vnic_dbg_data(login->name, "vnic_post_recv failed, "
			      "wr_id %llu\n", wr_id);
	spin_unlock_bh(&ring->lock);

	return;

unmap_repost:
	/* ignore rc of vnic_unmap_and_replace_rx() */
	vnic_unmap_and_replace_rx(ring, ib_device, frags,
				  wr_id, wc->byte_len);
drop_repost:
	VNIC_STATS_INC(ring->stats.rx_dropped);

	spin_lock(&login->stats_lock);
	VNIC_STATS_DO_INC(login->stats.rx_dropped);
	spin_unlock(&login->stats_lock);

	if (vnic_post_recv(ring, wr_id))
		vnic_dbg_data(login->name, "vnic_post_recv failed, "
			      "wr_id %llu\n", wr_id);
out:
	spin_unlock_bh(&ring->lock);
	return;
}

static inline void vnic_drain_tx_cq(struct vnic_login *login,
				    int tx_res_index)
{
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];
	int n, i;

	do {
		n = ib_poll_cq(tx_res->cq, VNIC_MAX_TX_CQE, tx_res->send_wc);
		for (i = 0; i < n; ++i)
			vnic_ib_handle_tx_wc(login, tx_res_index,
					     tx_res->send_wc + i);
	} while (n == VNIC_MAX_TX_CQE);
}

static void vnic_drain_arm_tx_cq(struct vnic_login *login, int tx_res_index)
{
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];

	ASSERT(login);
	ASSERT(login->dev);

	/* darin CQ then [arm] it */
	vnic_drain_tx_cq(login, tx_res_index);

	/* in tx interrupt mode, arm TX CQ after every interrupt */
	if (!vnic_tx_polling && ib_req_notify_cq(tx_res->cq, IB_CQ_NEXT_COMP))
		vnic_dbg(login->name, "ib_req_notify_cq failed\n");
	else if (unlikely(VNIC_TXQ_STOPPED(tx_res) &&
		     test_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state))) {
		if ((tx_res->tx_outstanding <= vnic_tx_rings_len >> 1)) {
			if (!test_bit(VNIC_STATE_NETDEV_NO_TX_ENABLE, &login->netdev_state)) {
				VNIC_STATS_DO_INC(login->port_stats.wake_queue);
				VNIC_TXQ_WAKE(tx_res);
			}
		/* make sure that after arming the cq, there is no access to
		 * login fields to avoid conflict with cq event handler.
		 * i.e., ib_req_notify_cq() must come at the end of this func
		 */
		} else if (ib_req_notify_cq(tx_res->cq, IB_CQ_NEXT_COMP)) {
			vnic_dbg(login->name, "ib_req_notify_cq failed\n");
			/* TODO: have to reset the device here */
		}
	}
}

static inline void vnic_comp_handler_tx(struct ib_cq *cq, void *ctx)
{
	struct vnic_tx_res *tx_res = ctx;

	if (!vnic_tx_polling) {
		spin_lock(&tx_res->lock);
		vnic_drain_arm_tx_cq(tx_res->login, tx_res->index);
		spin_unlock(&tx_res->lock);
	} else
		vnic_drain_arm_tx_cq(tx_res->login, tx_res->index);

}

static int vnic_drain_rx_cq(struct vnic_login *login, int max_poll,
			    int rx_res_index)
{
	struct vnic_rx_res *rx_res = &login->rx_res[rx_res_index];
	int polled, i;

	ASSERT(max_poll <= vnic_napi_weight);
	polled = ib_poll_cq(rx_res->cq, max_poll, rx_res->recv_wc);

	for (i = 0; vnic_rx_linear && i < polled; ++i)
		vnic_ib_handle_rx_wc_linear(login, &rx_res->recv_wc[i],
					    rx_res_index);

	for (i = 0; !vnic_rx_linear && i < polled; ++i)
		vnic_ib_handle_rx_wc(login, &rx_res->recv_wc[i],
				     rx_res_index);

#ifdef NETIF_F_LRO
	/* Done CQ handling: flush all LRO sessions unconditionally */
	if (login->dev->features & NETIF_F_LRO) {
		VNIC_STATS_INC(login->port_stats.lro_flushed);
		lro_flush_all(&rx_res->lro);
	}
#endif

	return polled;
}

/* RX CQ polling - called by NAPI */
#ifndef _BP_NAPI_POLL
int vnic_poll_cq_rx(struct napi_struct *napi, int budget)
{
	struct vnic_rx_res *rx_res = container_of(napi, struct vnic_rx_res, napi);
	struct vnic_login *login = rx_res->login;
	struct ib_cq *cq_rx = rx_res->cq;
	int rx_res_index = rx_res->index, polled;

	/* shouldn't happen, since when stopped=1 NAPI is disabled */
	if (unlikely(rx_res->stopped)) {
#ifndef _BP_NAPI_NETIFRX
		napi_complete(napi);
#else
		netif_rx_complete(login->dev, napi);
#endif
		return 0;
	}

	polled = vnic_drain_rx_cq(login, min(budget, VNIC_MAX_RX_CQE), rx_res_index);
	vnic_dbg_data(login->name, "after vnic_drain_rx_cq budget %d,"
		      " done %d, index %d\n", budget, polled, rx_res_index);

	/* If we used up all the quota - we're probably not done yet... */
	ASSERT(polled <= budget);
	if (polled < budget) {
		/* ATTENTION: ARM CQ must come after napi_complete() */
#ifndef _BP_NAPI_NETIFRX
		napi_complete(napi);
#else
		netif_rx_complete(login->dev, napi);
#endif
		/* Eventually calls vnic_comp_handler_rx() */
		if (ib_req_notify_cq(cq_rx, IB_CQ_NEXT_COMP))
			vnic_err(login->name, "ib_req_notify_cq failed\n");
	}

	return polled;
}
#else
int vnic_poll_cq_rx(struct net_device *poll_dev, int *budget)
{
	struct vnic_rx_res *rx_res = poll_dev->priv;
	struct vnic_login *login = rx_res->login;
	struct ib_cq *cq_rx = rx_res->cq;
	int rx_res_index = rx_res->index, polled, max_poll = min(*budget, poll_dev->quota);

	/* shouldn't happen, since when stopped=1 NAPI is disabled */
	if (unlikely(rx_res->stopped)) {
		netif_rx_complete(poll_dev);
		return 0;
	}

	while (max_poll >= 0) {
		polled = vnic_drain_rx_cq(login, min(max_poll, VNIC_MAX_RX_CQE), rx_res_index);
		if (polled <= 0)
			break;
		else {
			poll_dev->quota -= polled;
			*budget -= polled;
		}
		max_poll -= polled;
	}

	if (!max_poll)
		return 1;

	netif_rx_complete(poll_dev);
	ib_req_notify_cq(cq_rx, IB_CQ_NEXT_COMP);

	return 0;
}
#endif

static void vnic_comp_handler_rx(struct ib_cq *cq, void *rx_res_ptr)
{
	struct vnic_rx_res *rx_res = rx_res_ptr;
	struct vnic_login *login = rx_res->login;

	ASSERT(rx_res->cq == cq);
	ASSERT(login->dev);

	/* is this happens, will re-arm later in vnic_open */
	if (unlikely(rx_res->stopped))
		return;

#ifndef _BP_NAPI_POLL
	/* calls vnic_poll_cq_rx() */
#ifndef _BP_NAPI_NETIFRX
	napi_schedule(&rx_res->napi);
#else
	netif_rx_schedule(login->dev, &rx_res->napi);
#endif
#else
	netif_rx_schedule(rx_res->poll_dev);
#endif /* _BP_NAPI_POLL*/

}

static void vnic_stop_qp(struct vnic_login *login, int qp_index)
{
	struct ib_qp_attr qp_attr = { .qp_state = IB_QPS_ERR };
	struct vnic_qp_res *qp_res = &login->qp_res[qp_index];
	struct vnic_rx_res *rx_res = &login->rx_res[qp_res->rx_index];
	struct vnic_tx_res *tx_res = &login->tx_res[qp_res->tx_index];
	struct vnic_rx_ring *ring = login->port->rx_ring[rx_res->index];
	unsigned long flags;
	int polled, attr_mask, rc, i;

	/* move QP to ERR, wait for last WQE async event to drain the SRQ */
	rc = ib_modify_qp(qp_res->qp, &qp_attr, IB_QP_STATE);
	if (rc) {
		/* calls vnic_qp_event_handler() */
		vnic_warn(login->name, "failed to modify QP 0x%x to ERR state"
			  " (err = %d)\n", qp_res->qp->qp_num, rc);
		/* continue anyway, but don't wait for completion */
	} else {
		wait_for_completion(&qp_res->last_wqe_complete);
	}

	/* === at this point, no NAPI/RX comps === */

	/* drain TX CQ before moving to RESET, must hold tx_res->lock to
	 * protect from vnic_comp_handler_tx() after this call, all CQEs
	 * are polled (either by this direct call, or by CQ handlers)
	 */
	spin_lock_irqsave(&tx_res->lock, flags);
	vnic_drain_tx_cq(login, tx_res->index);
	spin_unlock_irqrestore(&tx_res->lock, flags);

	/* drain RX CQ before moving to RESET drop and re-post all comps */
	spin_lock_bh(&ring->lock);
	do {
		polled = ib_poll_cq(rx_res->cq, VNIC_MAX_RX_CQE, rx_res->recv_wc);
		for (i = 0; i < polled; ++i)
			if (vnic_post_recv(ring, rx_res->recv_wc[i].wr_id))
				vnic_dbg_data(login->name, "vnic_post_recv failed, "
					      "wr_id %llu\n", rx_res->recv_wc[i].wr_id);
	} while (polled == VNIC_MAX_RX_CQE);
	spin_unlock_bh(&ring->lock);

	/* move QP to RESET */
	qp_attr.qp_state = IB_QPS_RESET;
	rc = ib_modify_qp(qp_res->qp, &qp_attr, IB_QP_STATE);
	if (rc)
		vnic_warn(login->name, "failed to modify QP 0x%x to RESET"
			  " state (err = %d)\n", qp_res->qp->qp_num, rc);

	/* move QP to INIT to avoid multicast qp cache misses */
	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qkey = login->qkey;
	qp_attr.port_num = login->port->num;
	qp_attr.pkey_index = login->pkey_index;
	attr_mask = IB_QP_QKEY | IB_QP_PORT | IB_QP_PKEY_INDEX | IB_QP_STATE;

	rc = ib_modify_qp(qp_res->qp, &qp_attr, attr_mask);
	if (rc)
		vnic_warn(login->name, "failed to modify QP 0x%x to INIT state"
			  " (err = %d)\n", qp_res->qp->qp_num, rc);
}

int vnic_ib_stop(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	struct vnic_tx_res *tx_res;
	unsigned long begin = jiffies;
	int wr_id, i;

	/* flush tx and rx comps */
	for (i = 0; i < login->qps_num; ++i)
		vnic_stop_qp(login, i);

	/* check any pending tx comps */
	for (i = 0; i < login->tx_rings_num; i++) {
		tx_res = &login->tx_res[i];
		/* if tx_outstanding is non-zero, give it a chance to complete */
		if (!tx_res->tx_outstanding)
			continue;
		msleep(10);

		/* else, drain tx cq. This is indicates that something is
		 * wrong, thus we won't protect vnic_comp_handler_tx() here
		 */
		while (tx_res->tx_outstanding &&
		       time_before(jiffies, begin + 5 * HZ)) {
			vnic_drain_tx_cq(login, i);
			msleep(1);
		}

		/* if they're still not complete, force skb deallocation */
		if (!tx_res->tx_outstanding)
			continue;
		vnic_warn(login->name, "timing out: %d sends not completed\n",
			  tx_res->tx_outstanding);
		while (tx_res->tx_outstanding) {
			wr_id = tx_res->tx_tail & (vnic_tx_rings_len - 1);
			vnic_dealloc_tx_skb(login, i, wr_id);
			++tx_res->tx_tail;
			--tx_res->tx_outstanding;
		}
	}

	return 0;
}

int vnic_ib_open(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int i;

	/* move QP to RTS and attach to bcast group */
	for (i = 0; i < login->qps_num; ++i) {
		if (vnic_init_qp(login, i)) {
			vnic_err(login->name, "vnic_init_qp failed\n");
			goto stop_qps;
		}
	}

	return 0;

stop_qps:
	for (--i ; i >= 0; --i)
		vnic_stop_qp(login, i);

	return -EINVAL;
}

void vnic_destroy_qp(struct vnic_login *login, int qp_index)
{
	struct ib_qp *qp = login->qp_res[qp_index].qp;

	if (!qp)
		return;
	if (ib_destroy_qp(qp))
		vnic_warn(login->name, "ib_destroy_qp failed\n");
	return;
}

void vnic_qp_to_reset(struct vnic_login *login, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int rc;

	qp_attr.qp_state = IB_QPS_RESET;
	rc = ib_modify_qp(qp, &qp_attr, IB_QP_STATE);
	if (rc)
		vnic_err(login->name, "ib_modify_qp 0x%06x to RESET err %d\n",
			 qp->qp_num, rc);
}

int vnic_qp_to_init(struct vnic_login *login, struct ib_qp *qp, u32 qkey)
{
	struct ib_qp_attr qp_attr;
	int attr_mask, rc;

	/* move QP to INIT */
	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qkey = qkey;
	qp_attr.port_num = login->port->num;
	/* pkey will be overwritten later by login->pkey_index */
	qp_attr.pkey_index = login->port->pkey_index;
	attr_mask = IB_QP_QKEY | IB_QP_PORT | IB_QP_PKEY_INDEX | IB_QP_STATE;

	rc = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (rc) {
		vnic_err(login->name, "ib_modify_qp 0x%06x to INIT err %d\n",
			 qp->qp_num, rc);
		goto out_qp_reset;
	}

	return 0;

out_qp_reset:
	vnic_qp_to_reset(login, qp);
	return rc;
}

int vnic_init_qp(struct vnic_login *login, int qp_index)
{
	struct ib_qp_attr qp_attr;
	int attr_mask, rc, rc1;
	struct ib_qp *qp = login->qp_res[qp_index].qp;

	init_completion(&login->qp_res[qp_index].last_wqe_complete);
	/* move QP to INIT */
	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qkey = login->qkey;
	qp_attr.port_num = login->port->num;
	qp_attr.pkey_index = login->pkey_index;
	attr_mask = IB_QP_QKEY | IB_QP_PORT | IB_QP_PKEY_INDEX | IB_QP_STATE;

	rc = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (rc) {
		vnic_err(login->name, "ib_modify_qp to INIT err %d\n", rc);
		goto out_qp_reset;
	}

	/* move QP to RTR */
	qp_attr.qp_state = IB_QPS_RTR;
	attr_mask &= ~IB_QP_PORT;
	rc = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (rc) {
		vnic_err(login->name, "ib_modify_qp to RTR err %d\n", rc);
		goto out_qp_reset;
	}

	/* move QP to RTS */
	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	attr_mask |= IB_QP_SQ_PSN;
	attr_mask &= ~IB_QP_PKEY_INDEX;
	rc = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (rc) {
		vnic_err(login->name, "ib_modify_qp to RTS err, rc %d\n", rc);
		goto out_qp_reset;
	}

	/* What a Good QP! */
	vnic_dbg_data(login->name, "qpn 0x%06x moved to RTS\n",
		      qp->qp_num);

	return 0;

out_qp_reset:
	qp_attr.qp_state = IB_QPS_RESET;
	rc1 = ib_modify_qp(qp, &qp_attr, IB_QP_STATE);
	if (rc1)
		vnic_err(login->name, "ib_modify_qp to RESET err %d\n", rc1);

	return rc;
}

static void vnic_qp_event_handler(struct ib_event *event, void *ctx)
{
	struct vnic_qp_res *qp_res = ctx;
	struct vnic_login *login = qp_res->login;

	ASSERT(login);
	vnic_dbg_data(login->name, "[%s] qpn %d got event %d\n",
		      event->device->name, event->element.qp->qp_num,
		      event->event);
	if (event->event == IB_EVENT_QP_LAST_WQE_REACHED)
		complete(&qp_res->last_wqe_complete);
}

void vnic_destroy_rx_res(struct vnic_login *login, int rx_res_index)
{
	struct ib_cq *cq = login->rx_res[rx_res_index].cq;
	int rc = 0;

	if (cq)
		rc = ib_destroy_cq(cq);
	if (rc)
		vnic_warn(login->name, "ib_destroy_cq() index %d failed\n",
			  rx_res_index);
}

void vnic_destroy_tx_res(struct vnic_login *login, int tx_res_index)
{
	struct ib_cq *cq = login->tx_res[tx_res_index].cq;
	struct vnic_tx_buf *tx_ring = login->tx_res[tx_res_index].tx_ring;
	int rc = 0;

	if (tx_ring)
		vfree(tx_ring);
	if (cq)
		rc = ib_destroy_cq(cq);
	if (rc)
		vnic_warn(login->name, "ib_destroy_cq() index %d failed\n",
			  tx_res_index);
}

#if 0
static inline int get_comp_vector(int index, struct vnic_port *port)
{
	int vector;
	int num_cpus = roundup_pow_of_two(num_online_cpus());
	int port_for_eq;

	port_for_eq = (((index / port->dev->mdev->eq_per_port) %
			port->dev->mdev->dev->caps.num_ports) + 1);
	vector = (index % port->dev->mdev->eq_per_port) +
		 (port_for_eq * num_cpus);

	return vector;
}
#endif

int vnic_create_rx_res(struct vnic_login *login, int rx_res_index)
{
	struct vnic_rx_res *rx_res = &login->rx_res[rx_res_index];
	int comp_vector = rx_res_index % login->port->dev->ca->num_comp_vectors;
	struct ib_cq *cq =
		ib_create_cq(login->port->dev->ca,
			     vnic_comp_handler_rx,
			     NULL, &login->rx_res[rx_res_index],
			     vnic_rx_rings_len, comp_vector);
	if (IS_ERR(cq)) {
		vnic_err(login->name, "ib_create_cq failed, index %d, "
			 "comp_vector %d, rc %d\n",
			 rx_res_index, comp_vector, (int)PTR_ERR(cq));
		return -EINVAL;
	}

	rx_res->cq = cq;
	rx_res->index = rx_res_index;
	rx_res->login = login;

	return 0;
}

int vnic_create_tx_res(struct vnic_login *login, int tx_res_index)
{
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];
	struct ib_cq *cq;
	struct vnic_tx_buf *tx_ring;
	int i, comp_vector;

	tx_ring = vmalloc(vnic_tx_rings_len * sizeof *tx_res->tx_ring);
	if (!tx_ring) {
		vnic_err(login->name, "vmalloc failed to allocate %u * %lu\n",
			 vnic_tx_rings_len,
			 (long unsigned int) (sizeof *tx_res->tx_ring));
		return -ENOMEM;
	}
	memset(tx_ring, 0, vnic_tx_rings_len * sizeof *tx_res->tx_ring);

	/* create TX CQ and set WQE drafts */
	tx_res->tx_wr.sg_list = tx_res->tx_sge;
	tx_res->tx_wr.send_flags = IB_SEND_SIGNALED;
	tx_res->tx_wr.wr.ud.remote_qkey = login->qkey;

	for (i = 0; i < VNIC_MAX_TX_FRAGS; ++i)
		tx_res->tx_sge[i].lkey = login->port->mr->lkey;

	/* set mcast av draft*/
	memset(&tx_res->mcast_av, 0, sizeof(struct ib_ah_attr));
	tx_res->mcast_av.port_num = login->port->num;
	tx_res->mcast_av.ah_flags = IB_AH_GRH;

	/* create tx cq */
	comp_vector = tx_res_index % login->port->dev->ca->num_comp_vectors;
	cq = ib_create_cq(login->port->dev->ca,
			  vnic_comp_handler_tx,
			  NULL, &login->tx_res[tx_res_index],
			  vnic_tx_rings_len, comp_vector);
	if (IS_ERR(cq)) {
		vnic_err(login->name, "ib_create_cq failed, index %d, "
			 "comp_vector %d, rc %d\n",
			 tx_res_index, comp_vector, (int)PTR_ERR(cq));
		vfree(tx_ring);
		return -EINVAL;
	}

	tx_res->tx_ring = tx_ring;
	tx_res->cq = cq;
	tx_res->index = tx_res_index;
	tx_res->login = login;

	return 0;
}

int vnic_create_qp_range(struct vnic_login *login)
{
	int qp_index, create_flags = 0, rc;
	struct ib_qp_init_attr *attr;
	struct ib_qp *qps[VNIC_MAX_NUM_CPUS];
	struct vnic_qp_res *qp_res;

	attr = kzalloc(VNIC_MAX_NUM_CPUS * sizeof *attr, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	create_flags |= login->port->dev->attr.device_cap_flags &
		IB_DEVICE_BLOCK_MULTICAST_LOOPBACK ?
		IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK : 0;

	/* TODO: rename IB_QP_CREATE_IPOIB_UD_LSO */
	create_flags |= login->port->dev->attr.device_cap_flags &
		IB_DEVICE_UD_TSO ?
		IB_QP_CREATE_IPOIB_UD_LSO : 0;

	for (qp_index = 0; qp_index < login->qps_num; ++qp_index) {
		qp_res = &login->qp_res[qp_index];
		qp_res->tx_index = qp_index % login->tx_rings_num;
		qp_res->rx_index = qp_index % login->rx_rings_num;
		memset(&attr[qp_index], 0, sizeof(struct ib_qp_init_attr));
		attr[qp_index].cap.max_send_wr = vnic_tx_rings_len;
		attr[qp_index].cap.max_send_sge = VNIC_MAX_TX_FRAGS;
		attr[qp_index].cap.max_recv_wr = 0; /* we use SRQ */
		attr[qp_index].cap.max_recv_sge = 0;
		attr[qp_index].sq_sig_type = IB_SIGNAL_ALL_WR;
		attr[qp_index].qp_type = IB_QPT_UD;
		attr[qp_index].send_cq = login->tx_res[qp_res->tx_index].cq;
		attr[qp_index].recv_cq = login->rx_res[qp_res->rx_index].cq;
		attr[qp_index].srq = login->port->rx_ring[qp_res->rx_index]->srq;
		attr[qp_index].event_handler = vnic_qp_event_handler;
		attr[qp_index].qp_context = &login->qp_res[qp_index];
		attr[qp_index].create_flags = create_flags;
		attr[qp_index].cap.max_inline_data = vnic_inline_tshold;
	}


	rc = vnic_ib_create_qp_range(login->port->pd, attr, NULL,
				     login->qps_num, login->qps_num, qps);
	if (rc) {
		vnic_err(login->name, "vnic_ib_create_qp_range failed, rc %d\n", rc);
		goto err;
	}

	for (qp_index = 0; qp_index < login->qps_num; ++qp_index) {
		qp_res = &login->qp_res[qp_index];
		qp_res->qp = qps[qp_index];
		qp_res->login = login;
	}

	for (qp_index = 0; qp_index < login->qps_num; ++qp_index) {
		rc = vnic_qp_to_init(login, qps[qp_index], login->qkey);
		if (rc) {
			vnic_err(login->name, "vnic_qp_to_init failed, rc %d\n", rc);
			goto destroy_qps;
		}
	}

	kfree(attr);
	return 0;

destroy_qps:
	for (qp_index--; qp_index>=0; qp_index--)
		vnic_qp_to_reset(login, qps[qp_index]);

	for (qp_index = 0; qp_index < login->qps_num; ++qp_index)
		vnic_destroy_qp(login, qp_index);

err:
	kfree(attr);
	return rc;
}

static inline int use_inline(struct sk_buff *skb)
{
	return skb->len <= vnic_inline_tshold && !skb_shinfo(skb)->nr_frags;
}

int vnic_post_send(struct vnic_login *login, int tx_res_index,
		   u64 wr_id, struct ib_ah *ah, u32 dqpn)
{
	struct ib_send_wr *bad_wr;
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];
	struct vnic_qp_res *qp_res = &login->qp_res[tx_res_index % login->qps_num];
	struct vnic_tx_buf *tx_req = &tx_res->tx_ring[wr_id];
	skb_frag_t *frags = skb_shinfo(tx_req->skb)->frags;
	int nr_frags = skb_shinfo(tx_req->skb)->nr_frags, i, off = 0;

	ASSERT(qp_res);
	ASSERT(tx_res);
	ASSERT(qp_res->tx_index == tx_res->index);
	ASSERT(qp_res->qp->send_cq == tx_res->cq);

	if (!vnic_encap_headroom && !skb_is_gso(tx_req->skb)) {
		tx_res->tx_sge[off].addr = tx_req->mapping[off];
		tx_res->tx_sge[off].length = VNIC_ENCAP_LEN;
		off++;	
	}

	if (likely(skb_headlen(tx_req->skb))) {
		if (vnic_encap_headroom && use_inline(tx_req->skb)) {
			tx_res->tx_wr.send_flags |= IB_SEND_INLINE;
			wr_id |= VNIC_SEND_INLINE_FLAG;
			tx_res->tx_sge[off].addr = (unsigned long)tx_req->skb->data;
		} else {
			tx_res->tx_wr.send_flags &= ~IB_SEND_INLINE;
			tx_res->tx_sge[off].addr = tx_req->mapping[off];
		}
		tx_res->tx_sge[off].length = skb_headlen(tx_req->skb);
		off++;
	}

	for (i = 0; i < nr_frags; ++i) {
		tx_res->tx_sge[i + off].addr = tx_req->mapping[i + off];
		tx_res->tx_sge[i + off].length = frags[i].size;
	}

	/* handle runt packets using additional SG */
	if (unlikely(tx_req->skb->len < login->zlen)) {
		/* Note: always extend runt packets (for both
		 * internal & external) for virtualization, some emulators
		 * drop runt packets, so we need to avoid runt packets even
		 * if the traffic is not passing the bridge
		 */
		vnic_dbg_data(login->name, "runt packet, skb %p len %d => %d\n",
			      tx_req->skb, tx_req->skb->len, login->zlen);
		/* If there are frags, then packets is longer than 60B */
		if (use_inline(tx_req->skb))
			tx_res->tx_sge[i + off].addr = (u64)(unsigned long)login->pad_va;
		else
			tx_res->tx_sge[i + off].addr = login->pad_dma;

		tx_res->tx_sge[i + off].length = login->zlen - tx_req->skb->len;
		++nr_frags;
		VNIC_STATS_INC(login->port_stats.runt_packets);
	}

	tx_res->tx_wr.num_sge = nr_frags + off;
	tx_res->tx_wr.wr_id = wr_id;
	tx_res->tx_wr.wr.ud.remote_qpn = dqpn;
	tx_res->tx_wr.wr.ud.ah = ah;

	/* check if we need to calc csum */
	if (tx_req->skb->ip_summed == CHECKSUM_PARTIAL) {
		u16 csum_pseudo;

		/* calc pseudo header csum without the length
		 * and put in the transport's header checksum field.
		 * The HW will calculate the rest of it (SWP)
		 */
		if (tx_req->ip_off)
			csum_pseudo = ~csum_tcpudp_magic(ip_hdr(tx_req->skb)->saddr,
							  ip_hdr(tx_req->skb)->daddr,
							  0, /* length */
							  ip_hdr(tx_req->skb)->protocol,
							  0);
		else
			csum_pseudo = ~csum_ipv6_magic(&ipv6_hdr(tx_req->skb)->saddr,
							&ipv6_hdr(tx_req->skb)->daddr,
							0, /* length */
							ipv6_hdr(tx_req->skb)->nexthdr,
							0);

		/* place the calculated csum in the checksum field in
		 * tcp/udp header
		 */
		if (tx_req->tcp_off)
			tcp_hdr(tx_req->skb)->check = csum_pseudo;
		else
			udp_hdr(tx_req->skb)->check = csum_pseudo;

		/* set CSUM flag in ib_send_wr */
		tx_res->tx_wr.send_flags |= IB_SEND_IP_CSUM;
	} else {
		/* csum already calculated in SW */
		tx_res->tx_wr.send_flags &= ~IB_SEND_IP_CSUM;
	}

	/* prepare TSO header */
	if (skb_is_gso(tx_req->skb)) {
		tx_res->tx_wr.wr.ud.mss = skb_shinfo(tx_req->skb)->gso_size + tx_req->hlen;
		tx_res->tx_wr.wr.ud.header = tx_req->phead;
		tx_res->tx_wr.wr.ud.hlen = tx_req->hlen;
		tx_res->tx_wr.opcode = IB_WR_LSO;
	} else {
		tx_res->tx_wr.opcode = IB_WR_SEND;
	}

	vnic_dbg_data(login->name,
		      "skb %p wr_id %llu sqpn 0x%06x dqpn 0x%06x num_sge "
		      "%d phead %p was sent\n", tx_req->skb, wr_id, qp_res->qp->qp_num,
		      dqpn, tx_res->tx_wr.num_sge, tx_req->phead);

	/* if EoIB encap is OOB, copy LRO header to linear part */
	if (!vnic_encap_headroom && skb_is_gso(tx_req->skb)) {
		memcpy(tx_res->lso_hdr, VNIC_SKB_GET_ENCAP(tx_req->skb),
		       VNIC_ENCAP_LEN);
		memcpy((u8 *)(tx_res->lso_hdr) + VNIC_ENCAP_LEN,
		       tx_res->tx_wr.wr.ud.header,
		       tx_res->tx_wr.wr.ud.hlen);
		tx_res->tx_wr.wr.ud.header = tx_res->lso_hdr;
		tx_res->tx_wr.wr.ud.mss += VNIC_ENCAP_LEN;
		tx_res->tx_wr.wr.ud.hlen += VNIC_ENCAP_LEN;
	}

	return vnic_ib_post_send(qp_res->qp, &tx_res->tx_wr, &bad_wr,
				 tx_req->ip_off,
				 tx_req->ip6_off,
				 tx_req->tcp_off,
				 tx_req->udp_off);
}

static int vnic_dma_map_tx(struct ib_device *ca, struct vnic_tx_buf *tx_req)
{
	struct sk_buff *skb = tx_req->skb;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	u64 *mapping = tx_req->mapping;
	int i = 0, off = 0, headlen = skb_headlen(skb);

	if (vnic_encap_headroom && use_inline(skb))
		return 0;

	if (!vnic_encap_headroom && !skb_is_gso(tx_req->skb)) {
		mapping[off] = ib_dma_map_single(ca, VNIC_SKB_GET_ENCAP(skb),
						 VNIC_ENCAP_LEN, DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[off])))
			return -EIO;
		off++;
	}

	if (likely(headlen)) {
		mapping[off] = ib_dma_map_single(ca, skb->data,
						 headlen, DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[off])))
			goto partial_error;
		off++;
	}

	for (i = 0; i < shinfo->nr_frags; ++i) {
		skb_frag_t *frag = &shinfo->frags[i];
		mapping[i + off] = ib_dma_map_page(ca, frag->page.p,
						   frag->page_offset,
						   frag->size, DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[i + off])))
			goto partial_error;
	}

	return 0;

partial_error:
	for (--i; i >= 0; i--) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		ib_dma_unmap_page(ca, mapping[i + off], frag->size,
				  DMA_TO_DEVICE);
	}

	if (headlen)
		ib_dma_unmap_single(ca, mapping[--off], skb_headlen(skb),
				    DMA_TO_DEVICE);

	if (!vnic_encap_headroom && !skb_is_gso(tx_req->skb))
		ib_dma_unmap_single(ca, mapping[--off], VNIC_ENCAP_LEN,
				    DMA_TO_DEVICE);

	return -EIO;
}

void vnic_send(struct vnic_login *login, struct sk_buff *skb,
	       struct ib_ah *ah, u32 dqpn, int tx_res_index)
{
	struct eoibhdr *_eoib_hdr = VNIC_SKB_GET_ENCAP(skb);
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];
	struct vnic_tx_buf *tx_req;
	unsigned long flags = 0;
	u64 wr_id;
	int tx_pkt_num = 1;
	u8 ip_off;

	if (!vnic_tx_polling)
		spin_lock_irqsave(&tx_res->lock, flags);

	ASSERT(tx_res_index < login->tx_rings_num);
	wr_id = tx_res->tx_head & (vnic_tx_rings_len - 1);
	tx_req = &tx_res->tx_ring[wr_id];
	tx_req->skb = skb;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tx_req->ip_off = tx_req->ip6_off = tx_req->tcp_off = tx_req->udp_off = 0;
		if (VNIC_IP_CSUM_OK(_eoib_hdr)) {
			ip_off = vnic_encap_headroom ?
				((skb_network_header(skb) - skb->data) >> 1) :
				/* skb_network_header doesn't count the encap since it's OOB */
				((skb_network_header(skb) - skb->data + VNIC_ENCAP_LEN) >> 1);
			switch (ntohs(skb->protocol)) {
			case ETH_P_IP:
				tx_req->ip_off = ip_off;
				break;
			case ETH_P_IPV6:
				tx_req->ip6_off = ip_off;
			}
		}
		if (VNIC_TCP_CSUM_OK(_eoib_hdr))
			tx_req->tcp_off =
			    (skb_transport_header(skb) - skb_network_header(skb)) >> 2;
		else if (VNIC_UDP_CSUM_OK(_eoib_hdr))
			tx_req->udp_off =
			    (skb_transport_header(skb) - skb_network_header(skb)) >> 2;
		ASSERT(!tx_req->udp_off || !tx_req->tcp_off);
		vnic_dbg_data(login->name, "ip_off = %d, tcp_off = %d, udp_off = %d\n",
			      tx_req->ip_off, tx_req->tcp_off, tx_req->udp_off);
		VNIC_STATS_INC(login->port_stats.tx_chksum_offload);
	}

	/* TSO skb */
	if (skb_is_gso(skb)) {
		tx_req->hlen = skb_transport_offset(skb) + tcp_hdrlen(skb);
		tx_req->phead = skb->data;
		ASSERT(skb_pull(skb, tx_req->hlen));
		VNIC_STATS_INC(login->port_stats.tso_packets);
		tx_pkt_num = skb_shinfo(tx_req->skb)->gso_segs;
	}

	/* map tx skb */
	if (unlikely(vnic_dma_map_tx(login->port->dev->ca, tx_req)))
		goto err;

	/* send.. unmap.. free skb.. drain tx cq.. [pray] */
	if (unlikely(++tx_res->tx_outstanding == vnic_tx_rings_len)) {
		if (++tx_res->tx_stopped_cnt % 100 == 0)
			vnic_dbg(login->name, "tx queue %d stopped cnt %d, outs %d\n",
				 tx_res->index,
				 tx_res->tx_stopped_cnt,
				 tx_res->tx_outstanding);
		ASSERT(!VNIC_TXQ_STOPPED(tx_res));
		VNIC_TXQ_STOP(tx_res);
		/* vnic_drain_arm_tx_cq() will arm the cq OR resume the ring */
		VNIC_STATS_DO_INC(login->port_stats.queue_stopped);
	}

	ASSERT(tx_res->tx_outstanding <= vnic_tx_rings_len);

	if (unlikely(vnic_post_send(login, tx_res_index, wr_id, ah, dqpn))) {
		vnic_warn(login->name, "vnic_post_send failed\n");
		VNIC_STATS_DO_INC(tx_res->stats.tx_errors);
		VNIC_STATS_DO_INC(tx_res->stats.tx_dropped);
		--tx_res->tx_outstanding;
		vnic_dealloc_tx_skb(login, tx_res->index, wr_id);
		/* no need to netif_wake_queue() here, because
		 * vnic_comp_handler_tx() will eventually be called 
		 * for armed cq, and it will wake-up the queue when it's ready
		 */
	} else {
		VNIC_STATS_DO_ADD(tx_res->stats.tx_packets, tx_pkt_num);
		VNIC_STATS_DO_ADD(tx_res->stats.tx_bytes, skb->len);
		login->dev->trans_start = jiffies;
		++tx_res->tx_head;


		if (vnic_tx_polling) {
			if (likely(!skb_shared(skb)))
				skb_orphan(skb);
			else
				VNIC_STATS_DO_INC(login->port_stats.shared_packets);
		}
	}

	/* poll every vnic_max_tx_outs packets */
	if (vnic_tx_polling) {
		if (tx_res->tx_outstanding > vnic_max_tx_outs ||
		    VNIC_TXQ_STOPPED(tx_res))
			vnic_drain_arm_tx_cq(login, tx_res_index);
	} else
		spin_unlock_irqrestore(&tx_res->lock, flags);

	return;

err:
	VNIC_STATS_DO_INC(tx_res->stats.tx_dropped);
	VNIC_STATS_DO_INC(tx_res->stats.tx_errors);
	dev_kfree_skb_any(skb);

	if (!vnic_tx_polling)
		spin_unlock_irqrestore(&tx_res->lock, flags);

	return;
}

void vnic_ib_free_ring(struct vnic_rx_ring *ring)
{
	ASSERT(ring->srq);
	ib_destroy_srq(ring->srq);
}

int vnic_ib_init_ring(struct vnic_rx_ring *ring)
{
	struct ib_srq_init_attr srq_attr;
	struct vnic_port *port = ring->port;
	int rc = 0, headroom = 10;

	/* alloc SRQ */
	memset(&srq_attr, 0, sizeof(struct ib_srq_init_attr));
	srq_attr.attr.max_sge = VNIC_MAX_RX_FRAGS;
	srq_attr.attr.max_wr = vnic_rx_rings_len + headroom;
	srq_attr.attr.srq_limit = vnic_rx_rings_len + headroom;
	ring->srq = ib_create_srq(port->pd, &srq_attr);
	if (IS_ERR(ring->srq)) {
		vnic_err(ring->port->name, "ib_create_srq failed, index %d, rc %d\n",
			 ring->index, (int)PTR_ERR(ring->srq));
		rc = (int)PTR_ERR(ring->srq);
	}

	return rc;
}

int vnic_port_ib_init(struct vnic_port *port)
{
	int i;

	/* alloc PD */
	port->pd = ib_alloc_pd(port->dev->ca);
	if (IS_ERR(port->pd)) {
		vnic_err(port->name, "failed to allocate PD\n");
		goto err;
	}
	vnic_dbg_data(port->name, "port->pd %p\n", port);

	/* alloc MR */
	port->mr = ib_get_dma_mr(port->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(port->mr)) {
		vnic_err(port->name, "failed to allocate MR\n");
		goto free_pd;
	}
	vnic_dbg_data(port->name, "port->mr %p\n", port->mr);

	/* alloc RX RING */
	for (i = 0; i < port->rx_rings_num; ++i) {
		port->rx_ring[i] = vnic_create_rx_ring(port, i);
		if (IS_ERR(port->rx_ring[i])) {
			vnic_err(port->name, "failed to allocate rx_ring %d\n", i);
			port->rx_ring[i] = NULL;
			goto free_rx_ring;
		}
	}
	vnic_dbg_data(port->name, "allocated %d RX ring\n", port->rx_rings_num);

	return 0;

free_rx_ring:
	for (i = 0; i < port->rx_rings_num; ++i)
		vnic_destroy_rx_ring(port->rx_ring[i]);
/* free_mr: */
	ib_dereg_mr(port->mr);
free_pd:
	ib_dealloc_pd(port->pd);
err:
	return -EINVAL;

}

void vnic_port_ib_cleanup(struct vnic_port *port)
{
	int i;

	for (i = 0; i < port->rx_rings_num; ++i)
		vnic_destroy_rx_ring(port->rx_ring[i]);

	ib_dereg_mr(port->mr);
	ib_dealloc_pd(port->pd);

	return;
}

void vnic_ib_dispatch_event(struct ib_event *event)
{
	return;
}

int vnic_ib_set_moder(struct vnic_login *login, u16 rx_usecs, u16 rx_frames,
		      u16 tx_usecs, u16 tx_frames)
{
	int rc, i;

	vnic_dbg_moder(login->name, "set coalescing params for mtu:%d to "
		       "rx_frames:%d rx_usecs:%d, "
		       "tx_frames:%d tx_usecs:%d, "
		       "adaptive_rx_coal:%d, "
		       "adaptive_tx_coal:%d, "
		       "sample_interval:%d, "
		       "port.state: %d\n",
		       login->dev->mtu,
		       rx_frames, rx_usecs,
		       tx_frames, tx_usecs,
		       login->adaptive_rx_coal, 0,
		       login->sample_interval, login->port->attr.state);

	for (i = 0; i < login->tx_rings_num; ++i) {
		struct ib_cq_attr  attr;
		attr.moderation.cq_count = tx_frames;
		attr.moderation.cq_period = tx_usecs;
		rc = ib_modify_cq(login->tx_res[i].cq, &attr, IB_CQ_MODERATION);
		if (rc && rc != -ENOSYS) {
			vnic_warn(login->name, "failed modifying tx_res,"
				  " rc %d, tx ring index %d\n", rc, i);
			return rc;
		}
	}

	for (i = 0; i < login->rx_rings_num; ++i) {
		struct ib_cq_attr  attr;
		attr.moderation.cq_count = rx_frames;
		attr.moderation.cq_period = rx_usecs;
		rc = ib_modify_cq(login->rx_res[i].cq, &attr, IB_CQ_MODERATION);
		if (rc && rc != -ENOSYS) {
			vnic_warn(login->name, "failed modifying rx_res,"
				  " rc %d, rx ring index %d\n", rc, i);
			return rc;
		}
	}

	return 0;
}

int vnic_ib_down(struct net_device *dev)
{
	return 0;
}

int vnic_ib_up(struct net_device *dev)
{
	return 0;
}
