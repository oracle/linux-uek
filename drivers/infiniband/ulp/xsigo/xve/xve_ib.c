/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
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

#include "xve.h"
#include "xve_compat.h"

static DEFINE_MUTEX(pkey_mutex);

struct xve_ah *xve_create_ah(struct net_device *dev,
			     struct ib_pd *pd, struct ib_ah_attr *attr)
{
	struct xve_ah *ah;

	ah = kmalloc(sizeof(*ah), GFP_KERNEL);
	if (!ah)
		return NULL;

	ah->dev = dev;
	kref_init(&ah->ref);

	ah->ah = ib_create_ah(pd, attr);
	if (IS_ERR(ah->ah)) {
		kfree(ah);
		ah = NULL;
	} else {
		atomic_set(&ah->refcnt, 0);
		xve_debug(DEBUG_MCAST_INFO, netdev_priv(dev),
			  "%s Created ah %p\n", __func__, ah->ah);
	}

	return ah;
}

void xve_free_ah(struct kref *kref)
{
	struct xve_ah *ah = container_of(kref, struct xve_ah, ref);
	struct xve_dev_priv *priv = netdev_priv(ah->dev);

	list_add_tail(&ah->list, &priv->dead_ahs);
}

static void xve_ud_dma_unmap_rx(struct xve_dev_priv *priv,
				u64 mapping[XVE_UD_RX_EDR_SG])
{
	int i = 0;

	if (xve_ud_need_sg(priv->admin_mtu)) {
		ib_dma_unmap_single(priv->ca, mapping[0], XVE_UD_HEAD_SIZE,
				    DMA_FROM_DEVICE);
		for (i = 1; i < xve_ud_rx_sg(priv); i++) {
			ib_dma_unmap_page(priv->ca, mapping[i], PAGE_SIZE,
					DMA_FROM_DEVICE);
			xve_counters[XVE_NUM_PAGES_ALLOCED]--;
		}
	} else {
		ib_dma_unmap_single(priv->ca, mapping[0],
				    XVE_UD_BUF_SIZE(priv->max_ib_mtu),
				    DMA_FROM_DEVICE);
	}
}


static void xve_ud_skb_put_frags(struct xve_dev_priv *priv,
		struct sk_buff *skb,
		unsigned int length)
{
	int i, num_frags;
	unsigned int size, hdr_space = XVE_UD_HEAD_SIZE;

	/* put header into skb */
	if (xve_ud_need_sg(priv->admin_mtu))
		size = min(length, hdr_space);
	else
		size = length;

		skb->tail += size;
	skb->len += size;
	length -= size;

	num_frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < num_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		if (length == 0) {
			__free_page(skb_shinfo(skb)->frags[i].page.p);
			--skb_shinfo(skb)->nr_frags;
		} else {
			size = min_t(unsigned, length, PAGE_SIZE);

			frag->size = size;
			skb->data_len += size;
			skb->truesize += size;
			skb->len += size;
			length -= size;
		}
	}
}

static int xve_ib_post_receive(struct net_device *dev, int id)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_recv_wr *bad_wr;
	int ret, i;

	priv->rx_wr.wr_id = id | XVE_OP_RECV;
	for (i = 0; i < xve_ud_rx_sg(priv); i++)
		priv->rx_sge[i].addr = priv->rx_ring[id].mapping[i];

	ret = ib_post_recv(priv->qp, &priv->rx_wr, &bad_wr);
	if (unlikely(ret)) {
		xve_warn(priv, "receive failed for buf %d (%d)\n", id, ret);
		xve_ud_dma_unmap_rx(priv, priv->rx_ring[id].mapping);
		dev_kfree_skb_any(priv->rx_ring[id].skb);
		priv->rx_ring[id].skb = NULL;
	}

	return ret;
}

static struct sk_buff *xve_alloc_rx_skb(struct net_device *dev, int id)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;
	int buf_size, align;
	u64 *mapping;
	int tailroom, i;

	if (xve_ud_need_sg(priv->admin_mtu)) {
		/* reserve some tailroom for IP/TCP headers */
		buf_size = XVE_UD_HEAD_SIZE;
		tailroom = 128;
	} else {
		buf_size = XVE_UD_BUF_SIZE(priv->max_ib_mtu);
		tailroom = 0;
	}

	/*
	 * Eth header is 14 bytes, IB will leave a 40 byte gap for a GRH
	 * so we need 10 more bytes to get to 64 and align the
	 * IP header to a multiple of 16. EDR vNICs will have an additional
	 * 4-byte EoIB header.
	 */
	align = xve_is_ovn(priv) ? 10 : 6;
	skb = xve_dev_alloc_skb(priv, buf_size + tailroom + align);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, align);

	mapping = priv->rx_ring[id].mapping;
	mapping[0] = ib_dma_map_single(priv->ca, skb->data, buf_size,
				       DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(priv->ca, mapping[0])))
		goto error;

	for (i = 1; xve_ud_need_sg(priv->admin_mtu) &&
			i < xve_ud_rx_sg(priv); i++) {
		struct page *page = xve_alloc_page(GFP_ATOMIC);

		if (!page)
			goto partial_error;
		skb_fill_page_desc(skb, i-1, page, 0, PAGE_SIZE);
		mapping[i] =
			ib_dma_map_page(priv->ca,
					skb_shinfo(skb)->frags[i-1].page.p,
					0, PAGE_SIZE, DMA_FROM_DEVICE);
		if (unlikely(ib_dma_mapping_error(priv->ca, mapping[i])))
			goto partial_error;

	}

	priv->rx_ring[id].skb = skb;
	return skb;

partial_error:
	ib_dma_unmap_single(priv->ca, mapping[0], buf_size, DMA_FROM_DEVICE);
error:
	dev_kfree_skb_any(skb);
	return NULL;
}

static int xve_ib_post_receives(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < priv->xve_recvq_size; ++i) {
		if (!xve_alloc_rx_skb(dev, i)) {
			xve_warn(priv,
				 "%s failed to allocate ib receive buffer %d\n",
				 __func__, i);
			return -ENOMEM;
		}
		if (xve_ib_post_receive(dev, i)) {
			xve_warn(priv,
				 "%s xve_ib_post_receive failed for buf %d\n",
				 __func__, i);
			return -EIO;
		}
	}

	return 0;
}

static void xve_link_up(struct xve_dev_priv *priv)
{
	if (test_bit(XVE_FLAG_ADMIN_UP, &priv->flags) &&
			test_bit(XVE_CHASSIS_ADMIN_UP, &priv->flags)) {
		if (test_and_clear_bit(XVE_HBEAT_LOST, &priv->state)) {
			xve_set_oper_up_state(priv);
			xve_xsmp_send_oper_state(priv, priv->resource_id,
				XSMP_XVE_OPER_UP);
		}
		handle_carrier_state(priv, 1);
	}
}

void xve_process_link_state(struct xve_dev_priv *priv,
		struct xve_keep_alive *ka)
{
	uint32_t state = ntohl(ka->uplink_status);

	if (state) {
		set_bit(XVE_GW_STATE_UP, &priv->state);
		priv->hb_interval = 30*HZ;

		if ((!netif_carrier_ok(priv->netdev)) ||
			(!test_bit(XVE_OPER_UP, &priv->flags)))
			xve_link_up(priv);
	} else {
		clear_bit(XVE_GW_STATE_UP, &priv->state);
		priv->hb_interval = 15*HZ;
		if (netif_carrier_ok(priv->netdev))
			handle_carrier_state(priv, 0);
	}
}

void xve_update_hbeat(struct xve_dev_priv *priv)
{
	priv->last_hbeat = jiffies;
}

void xve_process_hbeat(struct xve_dev_priv *priv, struct xve_keep_alive *ka)
{
	xve_process_link_state(priv, ka);
	xve_update_hbeat(priv);
}

void xve_handle_ctrl_msg(struct xve_dev_priv *priv,
		struct sk_buff *skb, struct ethhdr *eh)
{
	struct xve_keep_alive *ka;

	skb_pull(skb, ETH_HLEN);

	if (!pskb_may_pull(skb, sizeof(*ka)))
		goto skb_free;

	ka = (struct xve_keep_alive *) skb->data;
	xve_dbg_ctrl(priv, "RX CTRL_MSG: ethtype: 0x%x, type:%d, state: 0x%x\n",
		ntohs(eh->h_proto), ntohl(ka->type),
		ntohl(ka->uplink_status));

	switch (ntohl(ka->type)) {
	case XVE_VNIC_HBEAT:
		xve_process_hbeat(priv, ka);
		priv->counters[XVE_HBEAT_COUNTER]++;
		break;

	case XVE_VNIC_LINK_STATE:
		xve_process_link_state(priv, ka);
		priv->counters[XVE_LINK_STATUS_COUNTER]++;
		break;

	default:
		xve_dbg_ctrl(priv, "Unknown control message type: %hu\n",
			ka->type);
	}

skb_free:
	dev_kfree_skb_any(skb);
}

static void
xve_ib_handle_rx_wc(struct net_device *dev, struct ib_wc *wc)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	unsigned int wr_id = wc->wr_id & ~XVE_OP_RECV;
	struct ethhdr	*eh;
	struct sk_buff *skb;
	u64 mapping[XVE_UD_RX_EDR_SG];
	struct ib_packed_grh *grhhdr;
	u16 vlan;

	xve_dbg_data(priv, "recv completion: id %d, QP%x, status: %d\n",
		     wr_id, wc->src_qp, wc->status);


	if (unlikely(wr_id >= priv->xve_recvq_size)) {
		xve_warn(priv, "recv completion event with wrid %d (> %d)\n",
			 wr_id, priv->xve_recvq_size);
		return;
	}

	skb = priv->rx_ring[wr_id].skb;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			xve_warn(priv, "failed recv event ");
			xve_warn(priv, "(status=%d, wrid=%d vend_err %x)\n",
				 wc->status, wr_id, wc->vendor_err);
		}
		xve_ud_dma_unmap_rx(priv, priv->rx_ring[wr_id].mapping);
		dev_kfree_skb_any(skb);
		priv->rx_ring[wr_id].skb = NULL;
		return;
	}

	/*
	 * Drop packets that this interface sent, ie multicast packets
	 * that the HCA has replicated.
	 */
	if (wc->slid == priv->local_lid &&
			(wc->src_qp & ~(0x3UL)) == priv->qp->qp_num)
		goto repost;

	memcpy(mapping, priv->rx_ring[wr_id].mapping,
	       XVE_UD_RX_EDR_SG * sizeof(*mapping));

	/*
	 * If we can't allocate a new RX buffer, dump
	 * this packet and reuse the old buffer.
	 */
	if (unlikely(!xve_alloc_rx_skb(dev, wr_id))) {
		INC_RX_DROP_STATS(priv, dev);
		goto repost;
	}


	xve_dbg_data(priv, "received %d bytes, SLID 0x%04x\n",
		     wc->byte_len, wc->slid);

	xve_ud_dma_unmap_rx(priv, mapping);
	xve_ud_skb_put_frags(priv, skb,  wc->byte_len);
	grhhdr = (struct ib_packed_grh *)(skb->data);
	skb_pull(skb, IB_GRH_BYTES);

	if (xve_is_edr(priv)) {
		struct xve_eoib_hdr *eoibp;

		eoibp = (struct xve_eoib_hdr *)skb_pull(skb, sizeof(*eoibp));
	}

	if (!pskb_may_pull(skb, ETH_HLEN)) {
		dev_kfree_skb_any(skb);
		INC_RX_DROP_STATS(priv, dev);
		goto repost;
	}

	skb_reset_mac_header(skb);
	eh = eth_hdr(skb);
	if (ntohs(eh->h_proto) == ETH_P_XVE_CTRL) { /* heart beat/link status */
		xve_handle_ctrl_msg(priv, skb, eh);
		goto repost;
	}


	vlan = xg_vlan_get_rxtag(skb);
	if (wc->wc_flags & IB_WC_GRH) {
		xve_fwt_insert(priv, NULL, &grhhdr->source_gid, wc->src_qp,
				eh->h_source, vlan);
	} else {
		xve_dbg_data(priv,
			"No GRH, not used for fwt learning smac %pM, vlan:%u\n",
			 &eh->h_source, vlan);
		priv->counters[XVE_RX_NOGRH]++;
	}
	xve_prepare_skb(priv, skb);
	if (((skb->dev->features & NETIF_F_RXCSUM) &&
			likely(wc->wc_flags & IB_WC_IP_CSUM_OK)) ||
			test_bit(XVE_FLAG_CSUM, &priv->flags))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* This will print packet when driver is in Debug Mode */
	dumppkt(skb->data, skb->len, "UD Packet Dump");
	xve_test("%s RX UD pkt %02x %02x %02x %02x %02x %02x %02x %02x %02x",
		 __func__, skb->data[0], skb->data[1], skb->data[2],
		 skb->data[3], skb->data[4], skb->data[5], skb->data[6],
		 skb->data[7], skb->data[8]);
	xve_test("%02x %02x %02x proto %x for %s\n",
		 skb->data[9], skb->data[10], skb->data[11],
		 skb->protocol, priv->xve_name);
	xve_send_skb(priv, skb);
repost:
	if (unlikely(xve_ib_post_receive(dev, wr_id))) {
		xve_warn(priv, "xve_ib_post_receive failed ");
		xve_warn(priv, "for buf %d\n", wr_id);
	}
}

static int xve_dma_map_tx(struct ib_device *ca, struct xve_tx_buf *tx_req)
{
	struct sk_buff *skb = tx_req->skb;
	u64 *mapping = tx_req->mapping;
	int i;
	int off;

	if (skb_headlen(skb)) {
		mapping[0] = ib_dma_map_single(ca, skb->data, skb_headlen(skb),
					       DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[0])))
			return -EIO;

		off = 1;
	} else
		off = 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		mapping[i + off] = ib_dma_map_page(ca, skb_frag_page(frag),
						   frag->page_offset,
						   frag->size, DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[i + off])))
			goto partial_error;
	}
	return 0;

partial_error:
	for (; i > 0; --i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i - 1];

		ib_dma_unmap_page(ca, mapping[i - !off], frag->size,
				  DMA_TO_DEVICE);
	}

	if (off)
		ib_dma_unmap_single(ca, mapping[0], skb_headlen(skb),
				    DMA_TO_DEVICE);

	return -EIO;
}

static void xve_dma_unmap_tx(struct ib_device *ca, struct xve_tx_buf *tx_req)
{
	struct sk_buff *skb = tx_req->skb;
	u64 *mapping = tx_req->mapping;
	int i;
	int off;

	if (skb_headlen(skb)) {
		ib_dma_unmap_single(ca, mapping[0], skb_headlen(skb),
				    DMA_TO_DEVICE);
		off = 1;
	} else
		off = 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		ib_dma_unmap_page(ca, mapping[i + off], frag->size,
				  DMA_TO_DEVICE);
	}
}

static void xve_free_txbuf_memory(struct xve_dev_priv *priv,
				  struct xve_tx_buf *tx_req)
{
	if ((tx_req->skb == NULL) || (!tx_req->mapping[0]))
		xve_debug(DEBUG_DATA_INFO, priv,
			  "%s [ca %p] tx_req skb %p mapping %lld\n",
			  __func__, priv->ca, tx_req->skb, tx_req->mapping[0]);
	else
		xve_dma_unmap_tx(priv->ca, tx_req);

	xve_dev_kfree_skb_any(priv, tx_req->skb, 1);
	memset(tx_req, 0, sizeof(struct xve_tx_buf));
}

static void xve_ib_handle_tx_wc(struct net_device *dev, struct ib_wc *wc)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	unsigned int wr_id = wc->wr_id;
	struct xve_tx_buf *tx_req;

	xve_dbg_data(priv, "send completion: id %d, status: %d\n",
		     wr_id, wc->status);

	if (unlikely(wr_id >= priv->xve_sendq_size)) {
		xve_warn(priv, "send completion event with wrid %d (> %d)\n",
			 wr_id, priv->xve_sendq_size);
		return;
	}

	tx_req = &priv->tx_ring[wr_id];

	BUG_ON(tx_req == NULL || tx_req->ah == NULL);

	xve_put_ah_refcnt(tx_req->ah);
	xve_free_txbuf_memory(priv, tx_req);

	++priv->tx_tail;

	if (unlikely(--priv->tx_outstanding == priv->xve_sendq_size >> 1) &&
	    netif_queue_stopped(dev) &&
	    test_bit(XVE_FLAG_ADMIN_UP, &priv->flags)) {
		priv->counters[XVE_TX_WAKE_UP_COUNTER]++;
		netif_wake_queue(dev);
	}

	if (wc->status != IB_WC_SUCCESS && wc->status != IB_WC_WR_FLUSH_ERR) {
		xve_warn(priv, "failed send event ");
		xve_warn(priv, "(status=%d, wrid=%d vend_err %x)\n",
			 wc->status, wr_id, wc->vendor_err);
	}
}

int poll_tx(struct xve_dev_priv *priv)
{
	int n, i;

	n = ib_poll_cq(priv->send_cq, MAX_SEND_CQE, priv->send_wc);
	/* handle multiple WC's in one call */
	for (i = 0; i < n; ++i)
		xve_ib_handle_tx_wc(priv->netdev,
				priv->send_wc + i);
	if (n < 0) {
		xve_warn(priv, "%s ib_poll_cq() failed, rc %d\n",
				__func__, n);
	}

	return n == MAX_SEND_CQE;
}

static int poll_rx(struct xve_dev_priv *priv, int num_polls, int *done,
		   int flush)
{
	int n, i;

	n = ib_poll_cq(priv->recv_cq, num_polls, priv->ibwc);
	if (n < 0)
		xve_warn(priv, "%s ib_poll_cq() failed, rc %d",
				 __func__, n);
	for (i = 0; i < n; ++i) {
		/*
		 * Convert any successful completions to flush
		 * errors to avoid passing packets up the
		 * stack after bringing the device down.
		 */
		if (flush && (priv->ibwc[i].status == IB_WC_SUCCESS))
			priv->ibwc[i].status = IB_WC_WR_FLUSH_ERR;

		if (priv->ibwc[i].wr_id & XVE_OP_RECV) {
			++(*done);
			if (priv->ibwc[i].wr_id & XVE_OP_CM)
				xve_cm_handle_rx_wc(priv->netdev,
						    priv->ibwc + i);
			else
				xve_ib_handle_rx_wc(priv->netdev,
						    priv->ibwc + i);
		} else
			xve_cm_handle_tx_wc(priv->netdev, priv->ibwc + i);
	}
	return n;
}

int xve_poll(struct napi_struct *napi, int budget)
{
	struct xve_dev_priv *priv =
	    container_of(napi, struct xve_dev_priv, napi);
	struct net_device *dev = priv->netdev;
	int done, n, t;

	done = 0;

	/*
	 * If not connected complete it
	 */
	if (!(test_bit(XVE_OPER_UP, &priv->state) ||
		test_bit(XVE_HBEAT_LOST, &priv->state))) {
		priv->counters[XVE_NAPI_DROP_COUNTER]++;
		napi_complete(&priv->napi);
		clear_bit(XVE_INTR_ENABLED, &priv->state);
		return 0;
	}

	priv->counters[XVE_NAPI_POLL_COUNTER]++;

poll_more:
	while (done < budget) {
		int max = (budget - done);
		int i;

		t = min(XVE_NUM_WC, max);

		n = ib_poll_cq(priv->recv_cq, t, priv->ibwc);
		if (n < 0)
			xve_warn(priv, "%s ib_poll_cq() failed, rc %d",
				 __func__, n);
		for (i = 0; i < n; i++) {
			struct ib_wc *wc = priv->ibwc + i;

			if (wc->wr_id & XVE_OP_RECV) {
				++done;
				if (wc->wr_id & XVE_OP_CM)
					xve_cm_handle_rx_wc(priv->netdev,
							wc);
				else
					xve_ib_handle_rx_wc(priv->netdev,
							wc);
			} else
				xve_cm_handle_tx_wc(priv->netdev, wc);
		}
		if (n != t)
			break;
	}

	if (done < budget) {
		if (dev->features & NETIF_F_LRO)
			lro_flush_all(&priv->lro.lro_mgr);

		napi_complete(napi);
		clear_bit(XVE_OVER_QUOTA, &priv->state);
		if (test_bit(XVE_OS_ADMIN_UP, &priv->state) &&
				test_bit(XVE_CHASSIS_ADMIN_UP, &priv->state) &&
				(test_bit(XVE_OPER_UP, &priv->state) ||
				 test_bit(XVE_HBEAT_LOST, &priv->state)) &&
				!test_bit(XVE_DELETING, &priv->state)) {
			set_bit(XVE_INTR_ENABLED, &priv->state);
			if (unlikely(ib_req_notify_cq(priv->recv_cq,
				IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS))
				&& napi_reschedule(napi)) {
				priv->counters[XVE_NAPI_RESCHEDULE_COUNTER]++;
				goto poll_more;
			}
		}
	}
	return done;
}

void xve_ib_completion(struct ib_cq *cq, void *dev_ptr)
{
	struct net_device *dev = dev_ptr;
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_data_recv_handler(priv);

}

/*
 * Data is pending, in interrupt context
 */
void xve_data_recv_handler(struct xve_dev_priv *priv)
{

	if (test_bit(XVE_OS_ADMIN_UP, &priv->state) &&
			test_bit(XVE_CHASSIS_ADMIN_UP, &priv->state) &&
			(test_bit(XVE_OPER_UP, &priv->state) ||
				 test_bit(XVE_HBEAT_LOST, &priv->state)) &&
			!test_bit(XVE_DELETING, &priv->state)) {
		priv->counters[XVE_NAPI_SCHED_COUNTER]++;
		clear_bit(XVE_INTR_ENABLED, &priv->state);
		napi_schedule(&priv->napi);
	} else {
		priv->counters[XVE_NAPI_NOTSCHED_COUNTER]++;
	}
}

static void xve_ib_tx_timer_func(unsigned long ctx)
{
	struct net_device *dev = (struct net_device *)ctx;
	struct xve_dev_priv *priv = netdev_priv(dev);
	unsigned long flags = 0;

	netif_tx_lock(dev);
	spin_lock_irqsave(&priv->lock, flags);
	if (test_bit(XVE_OPER_UP, &priv->state) &&
			!test_bit(XVE_DELETING, &priv->state)) {
		while (poll_tx(priv))
			; /* nothing */
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(dev))
		mod_timer(&priv->poll_timer, jiffies + 1);

	netif_tx_unlock(dev);
}


void xve_send_comp_handler(struct ib_cq *cq, void *dev_ptr)
{
	struct xve_dev_priv *priv = netdev_priv((struct net_device *)dev_ptr);

	mod_timer(&priv->poll_timer, jiffies);
}

static inline int post_send(struct xve_dev_priv *priv,
			    unsigned int wr_id,
			    struct ib_ah *address, u32 qpn,
			    struct xve_tx_buf *tx_req, void *head, int hlen)
{
	struct ib_send_wr *bad_wr;
	struct ib_send_wr *wr = &priv->tx_wr;
	int i, off;
	struct sk_buff *skb = tx_req->skb;
	skb_frag_t *frags = skb_shinfo(skb)->frags;
	int nr_frags = skb_shinfo(skb)->nr_frags;
	u64 *mapping = tx_req->mapping;
	int total_size = 0;

	if (skb_headlen(skb)) {
		priv->tx_sge[0].addr = mapping[0];
		priv->tx_sge[0].length = skb_headlen(skb);
		off = 1;
		total_size += skb_headlen(skb);
	} else
		off = 0;

	for (i = 0; i < nr_frags; ++i) {
		priv->tx_sge[i + off].addr = mapping[i + off];
		priv->tx_sge[i + off].length = frags[i].size;
		total_size += frags[i].size;
	}
	wr->num_sge = nr_frags + off;
	wr->wr_id = wr_id;
	wr->wr.ud.remote_qpn = qpn;
	if (priv->is_eoib) {
		wr->wr.ud.remote_qkey =  priv->port_qkey;
		xve_debug(DEBUG_TX_INFO, priv, "%s qkey to use %x",
				__func__, wr->wr.ud.remote_qkey);
	}
	wr->wr.ud.ah = address;
	if (head) {
		wr->wr.ud.mss = skb_shinfo(skb)->gso_size;
		wr->wr.ud.header = head;
		wr->wr.ud.hlen = hlen;
		wr->opcode = IB_WR_LSO;
	} else {
		wr->opcode = IB_WR_SEND;
	}

	xve_debug(DEBUG_TXDATA_INFO, priv, "wr_id %d Frags %d size %d\n",
			wr_id, wr->num_sge, total_size);
	dumppkt(skb->data + sizeof(struct xve_eoib_hdr), total_size,
			"Post Send Dump");
	return ib_post_send(priv->qp, &priv->tx_wr, &bad_wr);
}
/* Always called with priv->lock held
 * type argument is used to differentiate between the GATEWAY
 * and UVNIC packet.
 * 0 -> normal UVNIC PACKET
 * 1 -> GATEWAY Broadcast PACKET
 * 2 -> Sending Queued PACKET
 * 3 -> Path Not found PACKET
 */
int xve_send(struct net_device *dev, struct sk_buff *skb,
	      struct xve_ah *address, u32 qpn, int type)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_tx_buf *tx_req;
	int hlen;
	void *phead;
	int ret = NETDEV_TX_OK;
	u8 packet_sent = 0;
	int id;

	id = priv->tx_head & (priv->xve_sendq_size - 1);

	/*
	 * Gateway broadcast packet's can come as that packets are not
	 * controlled by network layer
	 */
	if (priv->tx_outstanding >= priv->xve_sendq_size) {
		xve_warn(priv, "TX QUEUE FULL %d head%d tail%d out%d type%d",
				id, priv->tx_head, priv->tx_tail,
				priv->tx_outstanding, type);
		goto drop_pkt;
	}

	if (skb_is_gso(skb)) {
		hlen = skb_transport_offset(skb) + tcp_hdrlen(skb);
		phead = skb->data;
		if (unlikely(!skb_pull(skb, hlen))) {
			xve_warn(priv,
				 "%s linear data too small dropping %ld packets %s\n",
				 __func__, dev->stats.tx_dropped,
				 dev->name);
		goto drop_pkt;
		}
	} else {
		int max_packet_len;

		if (priv->is_jumbo)
			max_packet_len = priv->admin_mtu + VLAN_ETH_HLEN
				+ sizeof(struct xve_eoib_hdr);
		else
			max_packet_len = priv->mcast_mtu + VLAN_ETH_HLEN;

		if (unlikely(skb->len > max_packet_len)) {
			xve_info(priv,
				"packet len %d (>%d) too long dropping",
				skb->len, max_packet_len);
			goto drop_pkt;
		}
		phead = NULL;
		hlen = 0;
	}

	/* Linearize if there are more than allowed SGE's */
	if (xve_linearize_skb(dev, skb, priv, priv->max_send_sge) < 0)
		return ret;

	xve_dbg_data(priv,
		     "%s sending packet, length=%d address=%p qpn=0x%06x\n",
		     __func__, skb->len, address, qpn);
	/*
	 * We put the skb into the tx_ring _before_ we call post_send()
	 * because it's entirely possible that the completion handler will
	 * run before we execute anything after the post_send().  That
	 * means we have to make sure everything is properly recorded and
	 * our state is consistent before we call post_send().
	 */
	tx_req = &priv->tx_ring[id];
	tx_req->skb = skb;
	tx_req->ah = address;
	if (unlikely(xve_dma_map_tx(priv->ca, tx_req))) {
		INC_TX_ERROR_STATS(priv, dev);
		xve_put_ah_refcnt(address);
		dev_kfree_skb_any(tx_req->skb);
		memset(tx_req, 0, sizeof(struct xve_tx_buf));
		return ret;
	}

	/* Queue almost full */
	if (++priv->tx_outstanding == priv->xve_sendq_size) {
		xve_dbg_data(priv,
				"%s stop queue id%d head%d tail%d out%d type%d",
				__func__, id, priv->tx_head, priv->tx_tail,
				priv->tx_outstanding, type);
		if (ib_req_notify_cq(priv->send_cq, IB_CQ_NEXT_COMP))
			xve_warn(priv, "%s Req notify on send CQ failed\n",
					__func__);
		priv->counters[XVE_TX_QUEUE_STOP_COUNTER]++;
		netif_stop_queue(dev);
	}

	skb_orphan(skb);
	skb_dst_drop(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		priv->tx_wr.send_flags |= IB_SEND_IP_CSUM;
	else
		priv->tx_wr.send_flags &= ~IB_SEND_IP_CSUM;

	xve_debug(DEBUG_TX_INFO, priv,
			"%s sending packet, length=%d csum=%x address=%p qpn=0x%06x flags%x\n",
			__func__, skb->len, skb->ip_summed,
			address, qpn, priv->tx_wr.send_flags);

	if (unlikely(post_send(priv, priv->tx_head & (priv->xve_sendq_size - 1),
			       address->ah, qpn, tx_req, phead, hlen))) {
		--priv->tx_outstanding;
		xve_warn(priv, "%s post_send failed id%d head%d tail%d out%d type%d",
				__func__, id, priv->tx_head, priv->tx_tail,
				priv->tx_outstanding, type);
		priv->counters[XVE_TX_RING_FULL_COUNTER]++;
		xve_put_ah_refcnt(address);
		xve_free_txbuf_memory(priv, tx_req);
		if (netif_queue_stopped(dev)) {
			priv->counters[XVE_TX_WAKE_UP_COUNTER]++;
			netif_wake_queue(dev);
		}
	} else {
		packet_sent = 1;
		++priv->tx_head;
	}

	priv->send_hbeat_flag = 0;

	if (packet_sent)
		priv->counters[XVE_TX_COUNTER]++;
	return ret;

drop_pkt:
	INC_TX_DROP_STATS(priv, dev);
	xve_put_ah_refcnt(address);
	dev_kfree_skb_any(skb);
	return ret;
}

static void __xve_reap_ah(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_ah *ah, *tah;
	LIST_HEAD(remove_list);
	unsigned long flags = 0;

	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	list_for_each_entry_safe(ah, tah, &priv->dead_ahs, list) {
		if (atomic_read(&ah->refcnt) == 0) {
			list_del(&ah->list);
			ib_destroy_ah(ah->ah);
			kfree(ah);
		}
	}

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);
}

void xve_reap_ah(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_AHREAP, 1);
	struct net_device *dev = priv->netdev;

	__xve_reap_ah(dev);

	/* STOP_REAPER is set in xve_stop */
	if (!test_bit(XVE_STOP_REAPER, &priv->flags))
		xve_queue_dwork(priv, XVE_WQ_START_AHREAP,
				round_jiffies_relative(HZ));
	xve_put_ctx(priv);
}

static void xve_ah_dev_cleanup(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	unsigned long begin;

	begin = jiffies;

	while (!list_empty(&priv->dead_ahs)) {
		__xve_reap_ah(dev);

		if (time_after(jiffies, begin + HZ)) {
			xve_warn(priv,
				 "timing out; will leak address handles\n");
			break;
		}

		msleep(20);
	}
}

static void xve_pkey_dev_check_presence(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	u16 pkey_index = 0;

	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &pkey_index))
		clear_bit(XVE_PKEY_ASSIGNED, &priv->flags);
	else
		set_bit(XVE_PKEY_ASSIGNED, &priv->flags);
}

int xve_ib_dev_up(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_debug(DEBUG_IBDEV_INFO, priv, "%s Bring up ib_dev\n", __func__);
	xve_pkey_dev_check_presence(dev);
	if (!test_bit(XVE_PKEY_ASSIGNED, &priv->flags)) {
		xve_debug(DEBUG_IBDEV_INFO, priv, "%s PKEY is not assigned\n",
			  __func__);
		return 0;
	}

	set_bit(XVE_FLAG_OPER_UP, &priv->flags);
	priv->hb_interval = 30*HZ;
	xve_update_hbeat(priv);

	return xve_mcast_start_thread(dev);
}

int xve_ib_dev_down(struct net_device *dev, int flush)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_path *path, *tp;

	xve_debug(DEBUG_IBDEV_INFO, priv, "%s downing ib_dev\n", __func__);
	if (!test_and_clear_bit(XVE_FLAG_OPER_UP, &priv->flags)) {
		xve_debug(DEBUG_IBDEV_INFO, priv,
			  "%s Down IB without being up\n", __func__);
		return 0;
	}

	netif_carrier_off(priv->netdev);

	/* Shutdown the P_Key thread if still active */
	if (!test_bit(XVE_PKEY_ASSIGNED, &priv->flags)) {
		mutex_lock(&pkey_mutex);
		set_bit(XVE_PKEY_STOP, &priv->flags);
		mutex_unlock(&pkey_mutex);
	}

	xve_mcast_stop_thread(dev, flush);
	xve_mcast_dev_flush(dev);

	/* Flush all Paths */
	list_for_each_entry_safe(path, tp, &priv->path_list, list)
		xve_flush_single_path_by_gid(dev, &path->pathrec.dgid, NULL);


	return 0;
}

static int recvs_pending(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int pending = 0;
	int i;

	for (i = 0; i < priv->xve_recvq_size; ++i)
		if (priv->rx_ring[i].skb)
			++pending;

	return pending;
}

void xve_drain_cq(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int n, done = 0;
	unsigned long flags = 0;

	if (test_and_set_bit(XVE_DRAIN_IN_PROGRESS, &priv->flags)) {
		xve_info(priv, "Drain in progress[%d:%d:%d] state[%lx:%lx]",
				priv->tx_outstanding, priv->tx_head,
				priv->tx_tail, priv->flags, priv->state);
		return;
	}
	/*
	 * We call completion handling routines that expect to be
	 * called from the BH-disabled NAPI poll context, so disable
	 * BHs here too.
	 */
	local_bh_disable();

	do {
		n = poll_rx(priv, XVE_NUM_WC, &done, 1);
	} while (n == XVE_NUM_WC);

	local_bh_enable();

	/* Poll UD completions */
	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	if (priv->tx_outstanding)
		while (poll_tx(priv))
			; /* nothing */

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);

	clear_bit(XVE_DRAIN_IN_PROGRESS, &priv->flags);
}

int xve_ib_dev_open(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret;

	xve_debug(DEBUG_IBDEV_INFO, priv, "%s Open  ib_dev\n", __func__);
	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &priv->pkey_index)) {
		xve_warn(priv, "%s P_Key 0x%04x not found\n", __func__,
			 priv->pkey);
		clear_bit(XVE_PKEY_ASSIGNED, &priv->flags);
		return -1;
	}
	set_bit(XVE_PKEY_ASSIGNED, &priv->flags);

	ret = xve_init_qp(dev);
	if (ret != 0) {
		xve_warn(priv, "%s xve_init_qp returned %d\n", __func__, ret);
		return -1;
	}

	ret = xve_ib_post_receives(dev);
	if (ret != 0) {
		xve_warn(priv, "%s xve_ib_post_receives returned %d\n",
			 __func__, ret);
		xve_ib_dev_stop(dev, 1);
		return -1;
	}

	ret = xve_cm_dev_open(dev);
	if (ret != 0) {
		xve_warn(priv, "%s xve_cm_dev_open returned %d\n", __func__,
			 ret);
		xve_ib_dev_stop(dev, 1);
		return -1;
	}

	clear_bit(XVE_STOP_REAPER, &priv->flags);
	xve_queue_dwork(priv, XVE_WQ_START_AHREAP,
			3 * round_jiffies_relative(HZ));

	if (!test_and_set_bit(XVE_FLAG_INITIALIZED, &priv->flags))
		napi_enable(&priv->napi);

	/* Set IB Dev to open */
	set_bit(XVE_IB_DEV_OPEN, &priv->flags);

	return 0;
}

int xve_ib_dev_stop(struct net_device *dev, int flush)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_attr qp_attr;
	unsigned long begin;
	struct xve_tx_buf *tx_req;
	int i;

	xve_debug(DEBUG_IBDEV_INFO, priv, "%s Stop  ib_dev\n", __func__);
	/* IB Dev stop */
	if (!test_and_clear_bit(XVE_IB_DEV_OPEN, &priv->flags)) {
		xve_debug(DEBUG_IBDEV_INFO, priv,
			  "%s Stop IB without being up\n", __func__);
		return 0;
	}

	if (test_and_clear_bit(XVE_FLAG_INITIALIZED, &priv->flags))
		napi_disable(&priv->napi);

	xve_cm_dev_stop(dev);

	/*
	 * Move our QP to the error state and then reinitialize in
	 * when all work requests have completed or have been flushed.
	 */
	qp_attr.qp_state = IB_QPS_ERR;
	if (ib_modify_qp(priv->qp, &qp_attr, IB_QP_STATE))
		xve_warn(priv, "Failed to modify QP to ERROR state\n");

	/* Wait for all sends and receives to complete */
	begin = jiffies;

	while (priv->tx_head != priv->tx_tail || recvs_pending(dev)) {
		/* Wait for xve_wait_txcompl seconds */
		if (time_after(jiffies, begin + xve_wait_txcompl * HZ)) {
			xve_warn(priv,
				 "%s timing out; %d sends %d receives not completed\n",
				 __func__, priv->tx_head - priv->tx_tail,
				 recvs_pending(dev));

			/*
			 * assume the HW is wedged and just free up
			 * all our pending work requests.
			 */
			while ((int)priv->tx_tail - (int)priv->tx_head < 0) {
				tx_req = &priv->tx_ring[priv->tx_tail &
					(priv->xve_sendq_size - 1)];
				xve_free_txbuf_memory(priv, tx_req);
				++priv->tx_tail;
				--priv->tx_outstanding;
			}

			for (i = 0; i < priv->xve_recvq_size; ++i) {
				struct xve_rx_buf *rx_req;

				rx_req = &priv->rx_ring[i];
				if (!rx_req->skb)
					continue;
				xve_ud_dma_unmap_rx(priv,
						    priv->rx_ring[i].mapping);
				xve_dev_kfree_skb_any(priv, rx_req->skb, 0);
				rx_req->skb = NULL;
			}

			goto timeout;
		}
		xve_drain_cq(dev);
		msleep(20);
	}

	xve_debug(DEBUG_IBDEV_INFO, priv, "%s All sends and receives done\n",
		  __func__);
timeout:
	xve_debug(DEBUG_IBDEV_INFO, priv, "Deleting TX timer\n");
	del_timer_sync(&priv->poll_timer);
	qp_attr.qp_state = IB_QPS_RESET;
	if (ib_modify_qp(priv->qp, &qp_attr, IB_QP_STATE))
		xve_warn(priv, "Failed to modify QP to RESET state\n");

	/* Wait for all AHs to be reaped */
	set_bit(XVE_STOP_REAPER, &priv->flags);
	xve_ah_dev_cleanup(dev);

	ib_req_notify_cq(priv->recv_cq, IB_CQ_NEXT_COMP);

	return 0;
}

int xve_ib_dev_init(struct net_device *dev, struct ib_device *ca, int port)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	priv->ca = ca;
	priv->port = port;
	priv->qp = NULL;

	if (xve_transport_dev_init(dev, ca) != 0) {
		pr_warn("%s: xve_transport_dev_init failed for %s\n",
			ca->name, priv->xve_name);
		return -ENODEV;
	}

	setup_timer(&priv->poll_timer, xve_ib_tx_timer_func,
			(unsigned long)dev);

	if (dev->flags & IFF_UP) {
		if (xve_ib_dev_open(dev) != 0) {
			xve_transport_dev_cleanup(dev);
			return -ENODEV;
		}
	}

	return 0;
}

static void __xve_ib_dev_flush(struct xve_dev_priv *priv,
			       enum xve_flush_level level)
{
	struct net_device *dev = priv->netdev;
	u16 new_index;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	if (!test_bit(XVE_FLAG_INITIALIZED, &priv->flags) ||
	    !test_bit(XVE_FLAG_ADMIN_UP, &priv->flags)) {
		xve_debug(DEBUG_IBDEV_INFO, priv,
			"%s Not flushing XVE_FLAG_ADMIN_UP/", __func__);
		xve_debug(DEBUG_IBDEV_INFO, priv,
			  "XVE_FLAG_INITIALIZED not set flags %lx\n",
			priv->flags);
		goto out;
	}
	spin_unlock_irqrestore(&priv->lock, flags);

	if (level == XVE_FLUSH_HEAVY) {
		if (ib_find_pkey(priv->ca, priv->port, priv->pkey,
			&new_index)) {
			clear_bit(XVE_PKEY_ASSIGNED, &priv->flags);
			xve_ib_dev_down(dev, 0);
			xve_ib_dev_stop(dev, 0);
			if (xve_pkey_dev_delay_open(dev))
				return;
		}

		/* restart QP only if P_Key index is changed */
		if (test_and_set_bit(XVE_PKEY_ASSIGNED, &priv->flags) &&
		    new_index == priv->pkey_index) {
			xve_debug(DEBUG_IBDEV_INFO, priv,
				  "%s PKey index not changed\n", __func__);
			return;
		}
		priv->pkey_index = new_index;
	}

	if (level == XVE_FLUSH_LIGHT) {
		xve_mark_paths_invalid(dev);
		xve_mcast_dev_flush(dev);
		clear_bit(XVE_FLAG_DONT_DETACH_MCAST, &priv->flags);
	}

	if (level >= XVE_FLUSH_NORMAL)
		xve_ib_dev_down(dev, 0);

	if (level == XVE_FLUSH_HEAVY) {
		xve_ib_dev_stop(dev, 0);
		xve_ib_dev_open(dev);
	}
	spin_lock_irqsave(&priv->lock, flags);
	set_bit(XVE_FLAG_IB_EVENT, &priv->flags);
out:
	spin_unlock_irqrestore(&priv->lock, flags);
}

void xve_ib_dev_flush_light(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_FLUSHLIGHT, 0);

	__xve_ib_dev_flush(priv, XVE_FLUSH_LIGHT);
	xve_put_ctx(priv);
}

void xve_ib_dev_flush_normal(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_FLUSHNORMAL, 0);

	__xve_ib_dev_flush(priv, XVE_FLUSH_NORMAL);
	xve_put_ctx(priv);
}

void xve_ib_dev_flush_heavy(struct work_struct *work)
{

	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_FLUSHHEAVY, 0);

	__xve_ib_dev_flush(priv, XVE_FLUSH_HEAVY);
	xve_put_ctx(priv);
}

void xve_ib_dev_cleanup(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_debug(DEBUG_IBDEV_INFO, priv, "%s Cleaning up ib_dev\n", __func__);

	xve_mcast_stop_thread(dev, 1);
	xve_mcast_dev_flush(dev);
	xve_ah_dev_cleanup(dev);
	xve_transport_dev_cleanup(dev);

}

/*
 * Delayed P_Key Assigment Interim Support
 *
 * The following is initial implementation of delayed P_Key assignment
 * mechanism. It is using the same approach implemented for the multicast
 * group join. The single goal of this implementation is to quickly address
 * Bug #2507. This implementation will probably be removed when the P_Key
 * change async notification is available.
 */

void xve_pkey_poll(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_PKEYPOLL, 1);
	struct net_device *dev = priv->netdev;

	xve_pkey_dev_check_presence(dev);

	if (test_bit(XVE_PKEY_ASSIGNED, &priv->flags))
		xve_open(dev);
	else {
		mutex_lock(&pkey_mutex);
		if (!test_bit(XVE_PKEY_STOP, &priv->flags))
			xve_queue_dwork(priv, XVE_WQ_START_PKEYPOLL, HZ);
		mutex_unlock(&pkey_mutex);
	}
	xve_put_ctx(priv);
}

int xve_pkey_dev_delay_open(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	/* Look for the interface pkey value in the IB Port P_Key table and */
	/* set the interface pkey assignment flag                            */
	xve_pkey_dev_check_presence(dev);

	/* P_Key value not assigned yet - start polling */
	if (!test_bit(XVE_PKEY_ASSIGNED, &priv->flags)) {
		mutex_lock(&pkey_mutex);
		clear_bit(XVE_PKEY_STOP, &priv->flags);
		xve_queue_dwork(priv, XVE_WQ_START_PKEYPOLL, HZ);
		mutex_unlock(&pkey_mutex);
		return 1;
	}

	return 0;
}
