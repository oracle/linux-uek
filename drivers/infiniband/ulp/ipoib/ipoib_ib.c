/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2004, 2005 Voltaire, Inc. All rights reserved.
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

#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#include "ipoib.h"

#include <linux/if_arp.h>	/* For ARPHRD_xxx */

#ifdef CONFIG_INFINIBAND_IPOIB_DEBUG_DATA
static int data_debug_level;

module_param(data_debug_level, int, 0644);
MODULE_PARM_DESC(data_debug_level,
		 "Enable data path debug tracing if > 0");
#endif

static DEFINE_MUTEX(pkey_mutex);

struct ipoib_ah *ipoib_create_ah(struct net_device *dev,
				 struct ib_pd *pd, struct ib_ah_attr *attr)
{
	struct ipoib_ah *ah;
	struct ib_ah *vah;

	ah = kmalloc(sizeof *ah, GFP_KERNEL);
	if (!ah)
		return ERR_PTR(-ENOMEM);

	ah->dev       = dev;
	kref_init(&ah->ref);

	vah = ib_create_ah(pd, attr);
	if (IS_ERR(vah)) {
		kfree(ah);
		ah = (struct ipoib_ah *)vah;
	} else {
		atomic_set(&ah->refcnt, 0);
		ah->ah = vah;
		ipoib_dbg(netdev_priv(dev), "Created ah %p\n", ah->ah);
	}

	return ah;
}

void ipoib_free_ah(struct kref *kref)
{
	struct ipoib_ah *ah = container_of(kref, struct ipoib_ah, ref);
	struct ipoib_dev_priv *priv = netdev_priv(ah->dev);

	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	list_add_tail(&ah->list, &priv->dead_ahs);
	spin_unlock_irqrestore(&priv->lock, flags);
}

static void ipoib_ud_dma_unmap_rx(struct ipoib_dev_priv *priv,
				  u64 mapping[IPOIB_UD_RX_SG])
{
	if (ipoib_ud_need_sg(priv->max_ib_mtu)) {
		ib_dma_unmap_single(priv->ca, mapping[0],
				    IPOIB_UD_HEAD_BUFF_SIZE,
				    DMA_FROM_DEVICE);
		ib_dma_unmap_page(priv->ca, mapping[1], PAGE_SIZE,
				  DMA_FROM_DEVICE);
	} else
		ib_dma_unmap_single(priv->ca, mapping[0],
				    IPOIB_UD_BUF_SIZE(priv->max_ib_mtu),
				    DMA_FROM_DEVICE);
}

static void ipoib_ud_skb_put_frags(struct ipoib_dev_priv *priv,
				   struct sk_buff *skb,
				   unsigned int length)
{
	if (ipoib_ud_need_sg(priv->max_ib_mtu)) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
		unsigned int size;
		if (length > IPOIB_UD_HEAD_BUFF_SIZE) {
			/*
			 * There is only two buffers needed for max_payload = 4K
			 * first buf size is IPOIB_UD_HEAD_BUFF_SIZE
			 */
			skb->tail += IPOIB_UD_HEAD_BUFF_SIZE;
			skb->len  += length;

			size = length - IPOIB_UD_HEAD_BUFF_SIZE;
		} else {
			skb_put(skb, length);
			size = 0;
		}

		skb_frag_size_set(frag, size);
		skb->data_len += size;
		skb->truesize += PAGE_SIZE;
	} else
		skb_put(skb, length);

}

static int ipoib_ib_post_receive(struct net_device *dev,
			struct ipoib_recv_ring *recv_ring, int id)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ib_recv_wr *bad_wr;
	int ret;

	recv_ring->rx_wr.wr_id   = id | IPOIB_OP_RECV;
	recv_ring->rx_sge[0].addr = recv_ring->rx_ring[id].mapping[0];
	recv_ring->rx_sge[1].addr = recv_ring->rx_ring[id].mapping[1];


	ret = ib_post_recv(recv_ring->recv_qp, &recv_ring->rx_wr, &bad_wr);
	if (unlikely(ret)) {
		ipoib_warn(priv, "receive failed for buf %d (%d)\n", id, ret);
		ipoib_ud_dma_unmap_rx(priv, recv_ring->rx_ring[id].mapping);
		dev_kfree_skb_any(recv_ring->rx_ring[id].skb);
		recv_ring->rx_ring[id].skb = NULL;
	}

	return ret;
}

static struct sk_buff *ipoib_alloc_rx_skb(struct net_device *dev,
					  struct ipoib_recv_ring *recv_ring,
					  int id)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;
	int buf_size;
	u64 *mapping;

	if (ipoib_ud_need_sg(priv->max_ib_mtu)) {
		buf_size = IPOIB_UD_HEAD_BUFF_SIZE;
	} else {
		buf_size = IPOIB_UD_BUF_SIZE(priv->max_ib_mtu);
	}

	skb = dev_alloc_skb(buf_size + 4);
	if (unlikely(!skb))
		return NULL;

	/*
	 * IB will leave a 40 byte gap for a GRH and IPoIB adds a 4 byte
	 * header.  So we need 4 more bytes to get to 48 and align the
	 * IP header to a multiple of 16.
	 */
	skb_reserve(skb, 4);

	mapping = recv_ring->rx_ring[id].mapping;
	mapping[0] = ib_dma_map_single(priv->ca, skb->data, buf_size,
				       DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(priv->ca, mapping[0])))
		goto error;

	if (ipoib_ud_need_sg(priv->max_ib_mtu)) {
		struct page *page = alloc_page(GFP_ATOMIC);
		if (!page)
			goto partial_error;
		skb_fill_page_desc(skb, 0, page, 0, PAGE_SIZE);
		mapping[1] =
			ib_dma_map_page(priv->ca, page,
					0, PAGE_SIZE, DMA_FROM_DEVICE);
		if (unlikely(ib_dma_mapping_error(priv->ca, mapping[1])))
			goto partial_error;
	}

	recv_ring->rx_ring[id].skb = skb;
	return skb;

partial_error:
	ib_dma_unmap_single(priv->ca, mapping[0], buf_size, DMA_FROM_DEVICE);
error:
	dev_kfree_skb_any(skb);
	return NULL;
}

static int ipoib_ib_post_ring_receives(struct net_device *dev,
				      struct ipoib_recv_ring *recv_ring)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < ipoib_recvq_size; ++i) {
		if (!ipoib_alloc_rx_skb(dev, recv_ring, i)) {
			ipoib_warn(priv,
				"failed to allocate receive buffer (%d,%d)\n",
				recv_ring->index, i);
			return -ENOMEM;
		}
		if (ipoib_ib_post_receive(dev, recv_ring, i)) {
			ipoib_warn(priv,
				"ipoib_ib_post_receive failed for buf (%d,%d)\n",
				recv_ring->index, i);
			return -EIO;
		}
	}

	return 0;
}

static int ipoib_ib_post_receives(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int err;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; ++i) {
		err = ipoib_ib_post_ring_receives(dev, recv_ring);
		if (err)
			return err;
		recv_ring++;
	}

	return 0;
}

static inline void ipoib_create_repath_ent(struct net_device *dev,
						struct sk_buff *skb,
						u16 lid)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_arp_repath *arp_repath;
	struct arphdr *parphdr;

	parphdr = (struct arphdr *)(skb->data);
	if ((ARPOP_REPLY != be16_to_cpu(parphdr->ar_op)) &&
		(ARPOP_REQUEST != be16_to_cpu(parphdr->ar_op))) {
		return;
	}

	arp_repath = kzalloc(sizeof *arp_repath, GFP_ATOMIC);
	if (!arp_repath) {
		ipoib_warn(priv, "Failed alloc ipoib_arp_repath.\n");
		return;
	}

	INIT_WORK(&arp_repath->work, ipoib_repath_ah);

	arp_repath->lid = lid;
	memcpy(&arp_repath->sgid, skb->data + sizeof(struct arphdr) + 4,
		sizeof(union ib_gid));
		arp_repath->dev = dev;

	if (!test_bit(IPOIB_STOP_REAPER, &priv->flags))
		queue_work(ipoib_workqueue, &arp_repath->work);
	else
		kfree(arp_repath);
}



static void ipoib_ib_handle_rx_wc(struct net_device *dev,
				  struct ipoib_recv_ring *recv_ring,
				  struct ib_wc *wc)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	unsigned int wr_id = wc->wr_id & ~IPOIB_OP_RECV;
	struct sk_buff *skb;
	u64 mapping[IPOIB_UD_RX_SG];
	union ib_gid *dgid;

	ipoib_dbg_data(priv, "recv completion: id %d, status: %d\n",
		       wr_id, wc->status);

	if (unlikely(wr_id >= ipoib_recvq_size)) {
		ipoib_warn(priv, "recv completion event with wrid %d (> %d)\n",
			   wr_id, ipoib_recvq_size);
		return;
	}

	skb  = recv_ring->rx_ring[wr_id].skb;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			ipoib_warn(priv, "failed recv event "
				   "(status=%d, wrid=%d vend_err %x)\n",
				   wc->status, wr_id, wc->vendor_err);
		ipoib_ud_dma_unmap_rx(priv, recv_ring->rx_ring[wr_id].mapping);
		dev_kfree_skb_any(skb);
		recv_ring->rx_ring[wr_id].skb = NULL;
		return;
	}

	/*
	 * Drop packets that this interface sent, ie multicast packets
	 * that the HCA has replicated.
	 * Note with SW TSS MC were sent using priv->qp so no need to mask
	 */
	if (wc->slid == priv->local_lid && wc->src_qp == priv->qp->qp_num)
		goto repost;

	memcpy(mapping, recv_ring->rx_ring[wr_id].mapping,
	       IPOIB_UD_RX_SG * sizeof *mapping);

	/*
	 * If we can't allocate a new RX buffer, dump
	 * this packet and reuse the old buffer.
	 */
	if (unlikely(!ipoib_alloc_rx_skb(dev, recv_ring, wr_id))) {
		++recv_ring->stats.rx_dropped;
		goto repost;
	}

	skb_record_rx_queue(skb, recv_ring->index);

	ipoib_dbg_data(priv, "received %d bytes, SLID 0x%04x\n",
		       wc->byte_len, wc->slid);

	ipoib_ud_dma_unmap_rx(priv, mapping);
	ipoib_ud_skb_put_frags(priv, skb, wc->byte_len);

	/* First byte of dgid signals multicast when 0xff */
	dgid = &((struct ib_grh *)skb->data)->dgid;

	if (!(wc->wc_flags & IB_WC_GRH) || dgid->raw[0] != 0xff)
		skb->pkt_type = PACKET_HOST;
	else if (memcmp(dgid, dev->broadcast + 4, sizeof(union ib_gid)) == 0)
		skb->pkt_type = PACKET_BROADCAST;
	else
		skb->pkt_type = PACKET_MULTICAST;

	skb_pull(skb, IB_GRH_BYTES);

	skb->protocol = ((struct ipoib_header *) skb->data)->proto;
	skb_reset_mac_header(skb);
	skb_pull(skb, IPOIB_ENCAP_LEN);

	++recv_ring->stats.rx_packets;
	recv_ring->stats.rx_bytes += skb->len;

	if (unlikely(be16_to_cpu(skb->protocol) == ETH_P_ARP))
		ipoib_create_repath_ent(dev, skb, wc->slid);

	skb->dev = dev;
	if ((dev->features & NETIF_F_RXCSUM) &&
			likely(wc->wc_flags & IB_WC_IP_CSUM_OK))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* if handler is registered on top of ipoib, set skb oob data. */
	if (dev->priv_flags & IFF_EIPOIB_VIF) {
		set_skb_oob_cb_data(skb, wc, &recv_ring->napi);
		/*the registered handler will take care of the skb.*/
		netif_receive_skb(skb);
	} else
		napi_gro_receive(&recv_ring->napi, skb);

repost:
	if (unlikely(ipoib_ib_post_receive(dev, recv_ring, wr_id)))
		ipoib_warn(priv, "ipoib_ib_post_receive failed "
			   "for buf %d\n", wr_id);
}

static int ipoib_dma_map_tx(struct ib_device *ca,
			    struct ipoib_tx_buf *tx_req)
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
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		mapping[i + off] = ib_dma_map_page(ca,
						 skb_frag_page(frag),
						 frag->page_offset, skb_frag_size(frag),
						 DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[i + off])))
			goto partial_error;
	}
	return 0;

partial_error:
	for (; i > 0; --i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i - 1];

		ib_dma_unmap_page(ca, mapping[i - !off], skb_frag_size(frag), DMA_TO_DEVICE);
	}

	if (off)
		ib_dma_unmap_single(ca, mapping[0], skb_headlen(skb), DMA_TO_DEVICE);

	return -EIO;
}

static void ipoib_dma_unmap_tx(struct ib_device *ca,
			       struct ipoib_tx_buf *tx_req)
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
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		ib_dma_unmap_page(ca, mapping[i + off],
					skb_frag_size(frag), DMA_TO_DEVICE);
	}
}

static void ipoib_ib_handle_tx_wc(struct ipoib_send_ring *send_ring,
				struct ib_wc *wc)
{
	struct net_device *dev = send_ring->dev;
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	unsigned int wr_id = wc->wr_id;
	struct ipoib_tx_buf *tx_req;
	struct ipoib_ah *ah;

	ipoib_dbg_data(priv, "send completion: id %d, status: %d\n",
		       wr_id, wc->status);

	if (unlikely(wr_id >= ipoib_sendq_size)) {
		ipoib_warn(priv, "send completion event with wrid %d (> %d)\n",
			   wr_id, ipoib_sendq_size);
		return;
	}

	tx_req = &send_ring->tx_ring[wr_id];

	ah = tx_req->ah;
	atomic_dec(&ah->refcnt);
	if (!tx_req->is_inline)
		ipoib_dma_unmap_tx(priv->ca, tx_req);

	++send_ring->stats.tx_packets;
	send_ring->stats.tx_bytes += tx_req->skb->len;

	dev_kfree_skb_any(tx_req->skb);

	++send_ring->tx_tail;
	if (unlikely(--send_ring->tx_outstanding <= ipoib_sendq_size >> 1) &&
			__netif_subqueue_stopped(dev, send_ring->index) &&
			test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags))
		netif_wake_subqueue(dev, send_ring->index);

	if (wc->status != IB_WC_SUCCESS &&
	    wc->status != IB_WC_WR_FLUSH_ERR)
		ipoib_warn(priv, "failed send event "
			   "(status=%d, wrid=%d vend_err %x)\n",
			   wc->status, wr_id, wc->vendor_err);
}

static int poll_tx_ring(struct ipoib_send_ring *send_ring)
{
	int n, i;

	n = ib_poll_cq(send_ring->send_cq, MAX_SEND_CQE, send_ring->tx_wc);
	for (i = 0; i < n; ++i)
		ipoib_ib_handle_tx_wc(send_ring, send_ring->tx_wc + i);

	return n == MAX_SEND_CQE;
}

int ipoib_poll(struct napi_struct *napi, int budget)
{
	struct ipoib_recv_ring *rx_ring;
	struct net_device *dev;
	int n, i;
	struct ib_wc *wc;

	rx_ring = container_of(napi, struct ipoib_recv_ring, napi);
	dev = rx_ring->dev;

poll_more:

	n = ib_poll_cq(rx_ring->recv_cq, IPOIB_NUM_WC, rx_ring->ibwc);

	for (i = 0; i < n; i++) {
		wc = rx_ring->ibwc + i;

		if (wc->wr_id & IPOIB_OP_RECV) {
			if (wc->wr_id & IPOIB_OP_CM)
				ipoib_cm_handle_rx_wc(dev, rx_ring, wc);
			else
				ipoib_ib_handle_rx_wc(dev, rx_ring, wc);
		} else
			ipoib_cm_handle_tx_wc(dev, wc);
	}

	if (n < budget) {
		napi_complete(napi);
		if (unlikely(ib_req_notify_cq(rx_ring->recv_cq,
					      IB_CQ_NEXT_COMP |
					      IB_CQ_REPORT_MISSED_EVENTS)) &&
					    napi_reschedule(napi))
			goto poll_more;
	}

	return (n < 0 ? 0 : n);
}

void ipoib_ib_completion(struct ib_cq *cq, void *ctx_ptr)
{
	struct ipoib_recv_ring *recv_ring = (struct ipoib_recv_ring *) ctx_ptr;

	napi_schedule(&recv_ring->napi);
}

static void drain_tx_cq(struct ipoib_send_ring *send_ring)
{
	netif_tx_lock_bh(send_ring->dev);

	while (poll_tx_ring(send_ring))
		; /* nothing */

	if (__netif_subqueue_stopped(send_ring->dev, send_ring->index))
		mod_timer(&send_ring->poll_timer, jiffies + 1);

	netif_tx_unlock_bh(send_ring->dev);
}

void ipoib_send_comp_handler(struct ib_cq *cq, void *ctx_ptr)
{
	struct ipoib_send_ring *send_ring = (struct ipoib_send_ring *) ctx_ptr;

	mod_timer(&send_ring->poll_timer, jiffies);
}

static inline int post_send(struct ipoib_send_ring *send_ring,
			    unsigned int wr_id,
			    struct ib_ah *address, u32 qpn,
			    struct ipoib_tx_buf *tx_req,
			    void *head, int hlen, int use_inline)
{
	struct ib_send_wr *bad_wr;
	int i, off;
	struct sk_buff *skb = tx_req->skb;
	skb_frag_t *frags = skb_shinfo(skb)->frags;
	int nr_frags = skb_shinfo(skb)->nr_frags;
	u64 *mapping = tx_req->mapping;

	if (use_inline) {
		send_ring->tx_sge[0].addr         =  (u64)skb->data;
		send_ring->tx_sge[0].length       = skb->len;
		send_ring->tx_wr.num_sge	 = 1;
	} else {
		if (skb_headlen(skb)) {
			send_ring->tx_sge[0].addr         = mapping[0];
			send_ring->tx_sge[0].length       = skb_headlen(skb);
			off = 1;
		} else
			off = 0;

		for (i = 0; i < nr_frags; ++i) {
			send_ring->tx_sge[i + off].addr = mapping[i + off];
			send_ring->tx_sge[i + off].length =
					skb_frag_size(&frags[i]);
		}

		send_ring->tx_wr.num_sge	 = nr_frags + off;
	}

	send_ring->tx_wr.wr_id		 = wr_id;
	send_ring->tx_wr.wr.ud.remote_qpn = qpn;
	send_ring->tx_wr.wr.ud.ah	 = address;

	if (head) {
		send_ring->tx_wr.wr.ud.mss	 = skb_shinfo(skb)->gso_size;
		send_ring->tx_wr.wr.ud.header = head;
		send_ring->tx_wr.wr.ud.hlen	 = hlen;
		send_ring->tx_wr.opcode	 = IB_WR_LSO;
	} else
		send_ring->tx_wr.opcode	 = IB_WR_SEND;

	return ib_post_send(send_ring->send_qp, &send_ring->tx_wr, &bad_wr);
}

void ipoib_send(struct net_device *dev, struct sk_buff *skb,
		struct ipoib_ah *address, u32 qpn)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_tx_buf *tx_req;
	struct ipoib_send_ring *send_ring;
	u16 queue_index;
	int hlen, rc;
	void *phead;
	int req_index;

	/* Find the correct QP to submit the IO to */
	queue_index = skb_get_queue_mapping(skb);
	send_ring = priv->send_ring + queue_index;

	if (skb_is_gso(skb)) {
		hlen = skb_transport_offset(skb) + tcp_hdrlen(skb);
		phead = skb->data;
		if (unlikely(!skb_pull(skb, hlen))) {
			ipoib_warn(priv, "linear data too small\n");
			++send_ring->stats.tx_dropped;
			++send_ring->stats.tx_errors;
			dev_kfree_skb_any(skb);
			return;
		}
	} else {
		if (unlikely(skb->len > priv->mcast_mtu + IPOIB_ENCAP_LEN)) {
			ipoib_warn(priv, "%s: packet len %d (> %d) too long to send, dropping\n",
				   __func__, skb->len, priv->mcast_mtu + IPOIB_ENCAP_LEN);
			++send_ring->stats.tx_dropped;
			++send_ring->stats.tx_errors;
			ipoib_cm_skb_too_long(dev, skb, priv->mcast_mtu);

			dev_kfree_skb_any(skb);
			return;
		}
		phead = NULL;
		hlen  = 0;
	}

	ipoib_dbg_data(priv, "sending packet, length=%d address=%p qpn=0x%06x\n",
		       skb->len, address, qpn);

	/*
	 * We put the skb into the tx_ring _before_ we call post_send()
	 * because it's entirely possible that the completion handler will
	 * run before we execute anything after the post_send().  That
	 * means we have to make sure everything is properly recorded and
	 * our state is consistent before we call post_send().
	 */
	req_index = send_ring->tx_head & (ipoib_sendq_size - 1);
	tx_req = &send_ring->tx_ring[req_index];
	tx_req->skb = skb;
	tx_req->ah = address;

	if (skb->len < ipoib_inline_thold &&
			!skb_shinfo(skb)->nr_frags) {
		tx_req->is_inline = 1;
		send_ring->tx_wr.send_flags |= IB_SEND_INLINE;
	} else {
		if (unlikely(ipoib_dma_map_tx(priv->ca, tx_req))) {
			++send_ring->stats.tx_errors;
			dev_kfree_skb_any(skb);
			return;
		}
		tx_req->is_inline = 0;
		send_ring->tx_wr.send_flags &= ~IB_SEND_INLINE;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		send_ring->tx_wr.send_flags |= IB_SEND_IP_CSUM;
	else
		send_ring->tx_wr.send_flags &= ~IB_SEND_IP_CSUM;

	if (++send_ring->tx_outstanding == ipoib_sendq_size) {
		ipoib_dbg(priv, "TX ring full, stopping kernel net queue\n");
		if (ib_req_notify_cq(send_ring->send_cq, IB_CQ_NEXT_COMP))
			ipoib_warn(priv, "request notify on send CQ failed\n");
		netif_stop_subqueue(dev, queue_index);
	}

	/*
	 * Incrementing the reference count after submitting
	 * may create race condition
	 * It is better to increment before and decrement in case of error
	 */
	atomic_inc(&address->refcnt);
	rc = post_send(send_ring, req_index,
		       address->ah, qpn, tx_req, phead, hlen,
		       tx_req->is_inline);
	if (unlikely(rc)) {
		ipoib_warn(priv, "%s: post_send failed, error %d, queue_index:%d skb->len: %d\n",
			   __func__, rc, queue_index, skb->len);
		++send_ring->stats.tx_errors;
		--send_ring->tx_outstanding;
		if (!tx_req->is_inline)
			ipoib_dma_unmap_tx(priv->ca, tx_req);
		dev_kfree_skb_any(skb);
		atomic_dec(&address->refcnt);
		if (__netif_subqueue_stopped(dev, queue_index))
			netif_wake_subqueue(dev, queue_index);
	} else {
		netdev_get_tx_queue(dev, queue_index)->trans_start = jiffies;

		++send_ring->tx_head;
		skb_orphan(skb);
	}

	if (unlikely(send_ring->tx_outstanding > MAX_SEND_CQE))
		while (poll_tx_ring(send_ring))
			; /* nothing */
}

static void __ipoib_reap_ah(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_ah *ah, *tah;
	LIST_HEAD(remove_list);
	unsigned long flags;

	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	list_for_each_entry_safe(ah, tah, &priv->dead_ahs, list)
		if (atomic_read(&ah->refcnt) == 0) {
			list_del(&ah->list);
			ib_destroy_ah(ah->ah);
			kfree(ah);
		}

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);
}

void ipoib_reap_ah(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, ah_reap_task.work);
	struct net_device *dev = priv->dev;

	__ipoib_reap_ah(dev);

	if (!test_bit(IPOIB_STOP_REAPER, &priv->flags))
		queue_delayed_work(ipoib_workqueue, &priv->ah_reap_task,
				   round_jiffies_relative(HZ));
}

static void ipoib_ib_tx_timer_func(unsigned long ctx)
{
	drain_tx_cq((struct ipoib_send_ring *)ctx);
}

static void ipoib_napi_enable(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		netif_napi_add(dev, &recv_ring->napi,
						ipoib_poll, IPOIB_NUM_WC);
		napi_enable(&recv_ring->napi);
		recv_ring++;
	}
}

static void ipoib_napi_disable(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < priv->num_rx_queues; i++) {
		napi_disable(&priv->recv_ring[i].napi);
		netif_napi_del(&priv->recv_ring[i].napi);
	}
}

int ipoib_ib_dev_open(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int ret;

	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &priv->pkey_index)) {
		ipoib_warn(priv, "P_Key 0x%04x not found\n", priv->pkey);
		clear_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
		return -1;
	}
	set_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);

	ret = ipoib_init_qp(dev);
	if (ret) {
		ipoib_warn(priv, "ipoib_init_qp returned %d\n", ret);
		return -1;
	}

	ret = ipoib_ib_post_receives(dev);
	if (ret) {
		ipoib_warn(priv, "ipoib_ib_post_receives returned %d\n", ret);
		ipoib_ib_dev_stop(dev, 1);
		return -1;
	}

	ret = ipoib_cm_dev_open(dev);
	if (ret) {
		ipoib_warn(priv, "ipoib_cm_dev_open returned %d\n", ret);
		ipoib_ib_dev_stop(dev, 1);
		return -1;
	}

	clear_bit(IPOIB_STOP_REAPER, &priv->flags);
	queue_delayed_work(ipoib_workqueue, &priv->ah_reap_task,
			   round_jiffies_relative(HZ));

	if (!test_and_set_bit(IPOIB_FLAG_INITIALIZED, &priv->flags))
		ipoib_napi_enable(dev);

	return 0;
}

static void ipoib_pkey_dev_check_presence(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	u16 pkey_index = 0;

	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &pkey_index))
		clear_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
	else
		set_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
}

int ipoib_ib_dev_up(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_pkey_dev_check_presence(dev);

	if (!test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags)) {
		ipoib_dbg(priv, "PKEY is not assigned.\n");
		return 0;
	}

	set_bit(IPOIB_FLAG_OPER_UP, &priv->flags);
	set_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);
	return ipoib_mcast_start_thread(dev);
}

int ipoib_ib_dev_down(struct net_device *dev, int flush)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_dbg(priv, "downing ib_dev\n");

	clear_bit(IPOIB_FLAG_OPER_UP, &priv->flags);
	netif_carrier_off(dev);

	/* Shutdown the P_Key thread if still active */
	if (!test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags)) {
		mutex_lock(&pkey_mutex);
		set_bit(IPOIB_PKEY_STOP, &priv->flags);
		mutex_unlock(&pkey_mutex);
		cancel_delayed_work_sync(&priv->pkey_poll_task);
	}

	/* cancell the adaptive moderation task. */
	if (test_and_clear_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags))
		cancel_delayed_work(&priv->adaptive_moder_task);

	flush_workqueue(ipoib_auto_moder_workqueue);

	ipoib_mcast_stop_thread(dev, flush);
	ipoib_mcast_dev_flush(dev);

	ipoib_flush_paths(dev);

	return 0;
}

static int recvs_pending(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int pending = 0;
	int i, j;

	recv_ring = priv->recv_ring;
	for (j = 0; j < priv->num_rx_queues; j++) {
		for (i = 0; i < ipoib_recvq_size; ++i) {
			if (recv_ring->rx_ring[i].skb)
				++pending;
		}
		recv_ring++;
	}

	return pending;
}

static int sends_pending(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_send_ring *send_ring;
	int pending = 0;
	int i;

	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		/*
		* Note that since head and tails are unsigned then
		* the result of the substruction is correct even when
		* the counters wrap around
		*/
		pending += send_ring->tx_head - send_ring->tx_tail;
		send_ring++;
	}

	return pending;
}

static void ipoib_drain_rx_ring(struct ipoib_dev_priv *priv,
				struct ipoib_recv_ring *rx_ring)
{
	struct net_device *dev = priv->dev;
	int i, n;

	/*
	 * We call completion handling routines that expect to be
	 * called from the BH-disabled NAPI poll context, so disable
	 * BHs here too.
	 */
	local_bh_disable();

	do {
		n = ib_poll_cq(rx_ring->recv_cq, IPOIB_NUM_WC, rx_ring->ibwc);
		for (i = 0; i < n; ++i) {
			/*
			 * Convert any successful completions to flush
			 * errors to avoid passing packets up the
			 * stack after bringing the device down.
			 */
			if (rx_ring->ibwc[i].status == IB_WC_SUCCESS)
				rx_ring->ibwc[i].status = IB_WC_WR_FLUSH_ERR;

			if (rx_ring->ibwc[i].wr_id & IPOIB_OP_RECV) {
				if (rx_ring->ibwc[i].wr_id & IPOIB_OP_CM)
					ipoib_cm_handle_rx_wc(dev, rx_ring,
							rx_ring->ibwc + i);
				else
					ipoib_ib_handle_rx_wc(dev, rx_ring,
							rx_ring->ibwc + i);
			} else
				ipoib_cm_handle_tx_wc(dev, rx_ring->ibwc + i);
		}
	} while (n == IPOIB_NUM_WC);

	local_bh_enable();
}

static void drain_rx_rings(struct ipoib_dev_priv *priv)
{
	struct ipoib_recv_ring *recv_ring;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		ipoib_drain_rx_ring(priv, recv_ring);
		recv_ring++;
	}
}


static void drain_tx_rings(struct ipoib_dev_priv *priv)
{
	struct ipoib_send_ring *send_ring;
	int bool_value = 0;
	int i;

	do {
		bool_value = 0;
		send_ring = priv->send_ring;
		for (i = 0; i < priv->num_tx_queues; i++) {
			local_bh_disable();
			bool_value |= poll_tx_ring(send_ring);
			local_bh_enable();
			send_ring++;
		}
	} while (bool_value);
}

void ipoib_drain_cq(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	drain_rx_rings(priv);

	drain_tx_rings(priv);
}

static void ipoib_ib_send_ring_stop(struct ipoib_dev_priv *priv)
{
	struct ipoib_send_ring *tx_ring;
	struct ipoib_tx_buf *tx_req;
	int i;

	tx_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		while ((int) tx_ring->tx_tail - (int) tx_ring->tx_head < 0) {
			tx_req = &tx_ring->tx_ring[tx_ring->tx_tail &
				  (ipoib_sendq_size - 1)];
			if (!tx_req->is_inline)
				ipoib_dma_unmap_tx(priv->ca, tx_req);
			dev_kfree_skb_any(tx_req->skb);
			++tx_ring->tx_tail;
			--tx_ring->tx_outstanding;
		}
		tx_ring++;
	}
}

static void ipoib_ib_recv_ring_stop(struct ipoib_dev_priv *priv)
{
	struct ipoib_recv_ring *recv_ring;
	int i, j;

	recv_ring = priv->recv_ring;
	for (j = 0; j < priv->num_rx_queues; ++j) {
		for (i = 0; i < ipoib_recvq_size; ++i) {
			struct ipoib_rx_buf *rx_req;

			rx_req = &recv_ring->rx_ring[i];
			if (!rx_req->skb)
				continue;
			ipoib_ud_dma_unmap_rx(priv,
					      recv_ring->rx_ring[i].mapping);
			dev_kfree_skb_any(rx_req->skb);
			rx_req->skb = NULL;
		}
		recv_ring++;
	}
}

static void set_tx_poll_timers(struct ipoib_dev_priv *priv)
{
	struct ipoib_send_ring *send_ring;
	int i;
	/* Init a timer per queue */
	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		setup_timer(&send_ring->poll_timer, ipoib_ib_tx_timer_func,
					(unsigned long) send_ring);
		send_ring++;
	}
}

static void del_tx_poll_timers(struct ipoib_dev_priv *priv)
{
	struct ipoib_send_ring *send_ring;
	int i;

	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		del_timer_sync(&send_ring->poll_timer);
		send_ring++;
	}
}

static void check_qp_movment_and_print(struct ipoib_dev_priv *priv, struct ib_qp *qp,
				       enum ib_qp_state new_state)
{
	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr query_init_attr;
	int ret;

	ret = ib_query_qp(qp, &qp_attr, IB_QP_STATE, &query_init_attr);
	if (ret) {
		ipoib_warn(priv, "%s: Failed to query QP \n", __func__);
		return;
	}
	/* print according to the new-state and the previous state.*/
	if (IB_QPS_ERR == new_state && qp_attr.qp_state == IB_QPS_RESET)
		ipoib_dbg(priv, "Failed to modify QP from"
				" IB_QPS_RESET to IB_QPS_ERR - acceptable.\n");
	else
		ipoib_warn(priv, "Failed to modify QP to state: %d from state: %d\n",
			   new_state, qp_attr.qp_state);
}

static void set_tx_rings_qp_state(struct ipoib_dev_priv *priv,
					enum ib_qp_state new_state)
{
	struct ipoib_send_ring *send_ring;
	struct ib_qp_attr qp_attr;
	int i;

	send_ring = priv->send_ring;
	for (i = 0; i <  priv->num_tx_queues; i++) {
		qp_attr.qp_state = new_state;
		if (ib_modify_qp(send_ring->send_qp, &qp_attr, IB_QP_STATE))
			check_qp_movment_and_print(priv, send_ring->send_qp, new_state);

		send_ring++;
	}
}

static void set_rx_rings_qp_state(struct ipoib_dev_priv *priv,
					enum ib_qp_state new_state)
{
	struct ipoib_recv_ring *recv_ring;
	struct ib_qp_attr qp_attr;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		qp_attr.qp_state = new_state;
		if (ib_modify_qp(recv_ring->recv_qp, &qp_attr, IB_QP_STATE))
			check_qp_movment_and_print(priv, recv_ring->recv_qp, new_state);

		recv_ring++;
	}
}

static void set_rings_qp_state(struct ipoib_dev_priv *priv,
				enum ib_qp_state new_state)
{
	if (priv->hca_caps & IB_DEVICE_UD_TSS) {
		/* TSS HW is supported, parent QP has no ring (send_ring) */
		struct ib_qp_attr qp_attr;
		qp_attr.qp_state = new_state;
		if (ib_modify_qp(priv->qp, &qp_attr, IB_QP_STATE))
			check_qp_movment_and_print(priv, priv->qp, new_state);
	}

	set_tx_rings_qp_state(priv, new_state);

	if (priv->num_rx_queues > 1)
		set_rx_rings_qp_state(priv, new_state);
}
/*
 * The function tries to clean the list of ah's that waiting for deleting.
 * it tries for one HZ if it wasn't clear till then it print message
 *  and out.
 */
static void ipoib_force_reap_ah_clean(struct ipoib_dev_priv *priv)
{
	unsigned long begin;

	begin = jiffies;

	while (!list_empty(&priv->dead_ahs)) {
		__ipoib_reap_ah(priv->dev);

		if (time_after(jiffies, begin + HZ)) {
			ipoib_warn(priv, "timing out; will leak address handles\n");
			break;
		}

		msleep(1);
	}

}

int ipoib_ib_dev_stop(struct net_device *dev, int flush)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int i;
	unsigned long begin;

	if (test_and_clear_bit(IPOIB_FLAG_INITIALIZED, &priv->flags))
		ipoib_napi_disable(dev);

	ipoib_cm_dev_stop(dev);

	/*
	 * Move our QP to the error state and then reinitialize in
	 * when all work requests have completed or have been flushed.
	 */
	set_rings_qp_state(priv, IB_QPS_ERR);


	/* Wait for all sends and receives to complete */
	begin = jiffies;

	while (sends_pending(dev) || recvs_pending(dev)) {
		if (time_after(jiffies, begin + 5 * HZ)) {
			ipoib_warn(priv, "timing out; %d sends %d receives not completed\n",
				   sends_pending(dev), recvs_pending(dev));

			/*
			 * assume the HW is wedged and just free up
			 * all our pending work requests.
			 */
			ipoib_ib_send_ring_stop(priv);

			ipoib_ib_recv_ring_stop(priv);

			goto timeout;
		}

		ipoib_drain_cq(dev);

		msleep(1);
	}

	ipoib_dbg(priv, "All sends and receives done.\n");

timeout:
	del_tx_poll_timers(priv);

	set_rings_qp_state(priv, IB_QPS_RESET);

	/* Wait for all AHs to be reaped */
	set_bit(IPOIB_STOP_REAPER, &priv->flags);
	cancel_delayed_work(&priv->ah_reap_task);
	if (flush)
		flush_workqueue(ipoib_workqueue);

	ipoib_force_reap_ah_clean(priv);

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; ++i) {
		ib_req_notify_cq(recv_ring->recv_cq, IB_CQ_NEXT_COMP);
		recv_ring++;
	}

	return 0;
}

int ipoib_ib_dev_init(struct net_device *dev, struct ib_device *ca, int port)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	priv->ca = ca;
	priv->port = port;
	priv->qp = NULL;

	if (ipoib_transport_dev_init(dev, ca)) {
		printk(KERN_WARNING "%s: ipoib_transport_dev_init failed\n", ca->name);
		return -ENODEV;
	}

	set_tx_poll_timers(priv);

	if (dev->flags & IFF_UP) {
		if (ipoib_ib_dev_open(dev)) {
			ipoib_transport_dev_cleanup(dev);
			return -ENODEV;
		}
	}

	return 0;
}

static void __ipoib_ib_dev_flush(struct ipoib_dev_priv *priv,
				enum ipoib_flush_level level)
{
	struct ipoib_dev_priv *cpriv;
	struct net_device *dev = priv->dev;
	u16 new_index;

	mutex_lock(&priv->vlan_mutex);

	/*
	 * Flush any child interfaces too -- they might be up even if
	 * the parent is down.
	 */
	list_for_each_entry(cpriv, &priv->child_intfs, list)
		__ipoib_ib_dev_flush(cpriv, level);

	mutex_unlock(&priv->vlan_mutex);

	if (!test_bit(IPOIB_FLAG_INITIALIZED, &priv->flags)) {
		ipoib_dbg(priv, "Not flushing - IPOIB_FLAG_INITIALIZED not set.\n");
		return;
	}

	if (!test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags)) {
		ipoib_dbg(priv, "Not flushing - IPOIB_FLAG_ADMIN_UP not set.\n");
		return;
	}

	if (level == IPOIB_FLUSH_HEAVY) {
		if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &new_index)) {
			clear_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
			ipoib_ib_dev_down(dev, 0);
			ipoib_ib_dev_stop(dev, 0);
			if (ipoib_pkey_dev_delay_open(dev))
				return;
		}

		/* restart QP only if P_Key index is changed */
		if (test_and_set_bit(IPOIB_PKEY_ASSIGNED, &priv->flags) &&
		    new_index == priv->pkey_index) {
			ipoib_dbg(priv, "Not flushing - P_Key index not changed.\n");
			return;
		}
		priv->pkey_index = new_index;
	}

	if (level == IPOIB_FLUSH_LIGHT) {
		ipoib_mark_paths_invalid(dev);
		ipoib_mcast_dev_flush(dev);
	}

	if (level >= IPOIB_FLUSH_NORMAL)
		ipoib_ib_dev_down(dev, 0);

	if (level == IPOIB_FLUSH_HEAVY) {
		ipoib_ib_dev_stop(dev, 0);
		ipoib_ib_dev_open(dev);
	}

	/*
	 * The device could have been brought down between the start and when
	 * we get here, don't bring it back up if it's not configured up
	 */
	if (test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags)) {
		if (level >= IPOIB_FLUSH_NORMAL)
			ipoib_ib_dev_up(dev);
		ipoib_mcast_restart_task(&priv->restart_task);
	}
}

void ipoib_ib_dev_flush_light(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, flush_light);

	__ipoib_ib_dev_flush(priv, IPOIB_FLUSH_LIGHT);
}

void ipoib_ib_dev_flush_normal(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, flush_normal);

	__ipoib_ib_dev_flush(priv, IPOIB_FLUSH_NORMAL);
}

void ipoib_ib_dev_flush_heavy(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, flush_heavy);

	__ipoib_ib_dev_flush(priv, IPOIB_FLUSH_HEAVY);
}

void ipoib_ib_dev_cleanup(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_dbg(priv, "cleaning up ib_dev\n");
	/*
	 * We must make sure there are no more (path)completions
	 * that may wish to touch priv fields that may no longe r be valid.
	 */
	ipoib_flush_paths(dev);

	ipoib_mcast_stop_thread(dev, 1);
	ipoib_mcast_dev_flush(dev);

	ipoib_force_reap_ah_clean(priv);

	ipoib_transport_dev_cleanup(dev);
}

/*
 * Delayed P_Key Assigment Interim Support
 *
 * The following is initial implementation of delayed P_Key assigment
 * mechanism. It is using the same approach implemented for the multicast
 * group join. The single goal of this implementation is to quickly address
 * Bug #2507. This implementation will probably be removed when the P_Key
 * change async notification is available.
 */

void ipoib_pkey_poll(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, pkey_poll_task.work);
	struct net_device *dev = priv->dev;

	ipoib_pkey_dev_check_presence(dev);

	if (test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags))
		ipoib_open(dev);
	else {
		mutex_lock(&pkey_mutex);
		if (!test_bit(IPOIB_PKEY_STOP, &priv->flags))
			queue_delayed_work(ipoib_workqueue,
					   &priv->pkey_poll_task,
					   HZ);
		mutex_unlock(&pkey_mutex);
	}
}

int ipoib_pkey_dev_delay_open(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	/* Look for the interface pkey value in the IB Port P_Key table and */
	/* set the interface pkey assigment flag                            */
	ipoib_pkey_dev_check_presence(dev);

	/* P_Key value not assigned yet - start polling */
	if (!test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags)) {
		mutex_lock(&pkey_mutex);
		clear_bit(IPOIB_PKEY_STOP, &priv->flags);
		queue_delayed_work(ipoib_workqueue,
				   &priv->pkey_poll_task,
				   HZ);
		mutex_unlock(&pkey_mutex);
		return 1;
	}

	return 0;
}
