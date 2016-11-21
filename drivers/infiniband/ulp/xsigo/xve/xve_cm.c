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

static int retry_count = 1;
module_param_named(retry_count, retry_count, int, 0644);
MODULE_PARM_DESC(retry_count, "Max number IB retries");

static int rnr_retry_count = 4;
module_param_named(rnr_retry_count, rnr_retry_count, int, 0644);
MODULE_PARM_DESC(rnr_retry_count, "Max number rnr retries");

int xve_wait_txcompl = 10;
module_param_named(xve_wait_txcompl, xve_wait_txcompl, int, 0644);

static int xve_modify_qp = 1;
module_param_named(xve_modify_qp, xve_modify_qp, int, 0644);

#define XVE_CM_IETF_ID 0x1000000000000000ULL

#define XVE_CM_RX_UPDATE_TIME (256 * HZ)
#define XVE_CM_RX_TIMEOUT     (2 * 256 * HZ)
#define XVE_CM_RX_DELAY       (3 * 256 * HZ)
#define XVE_CM_RX_UPDATE_MASK (0x3)

static struct ib_qp_attr xve_cm_err_attr = {
	.qp_state = IB_QPS_ERR
};

#define XVE_CM_RX_DRAIN_WRID 0xffffffff

static struct ib_send_wr xve_cm_rx_drain_wr = {
	.wr_id = XVE_CM_RX_DRAIN_WRID,
	.opcode = IB_WR_SEND,
};

static int xve_cm_tx_handler(struct ib_cm_id *cm_id,
		struct ib_cm_event *event);
static void __xve_cm_tx_reap(struct xve_dev_priv *priv);

static void xve_cm_dma_unmap_rx(struct xve_dev_priv *priv, int frags,
				u64 mapping[XVE_CM_RX_SG])
{
	int i;

	ib_dma_unmap_single(priv->ca, mapping[0], XVE_CM_HEAD_SIZE,
			    DMA_FROM_DEVICE);

	for (i = 0; i < frags; ++i) {
		xve_counters[XVE_NUM_PAGES_ALLOCED]--;
		ib_dma_unmap_single(priv->ca, mapping[i + 1], PAGE_SIZE,
				    DMA_FROM_DEVICE);
	}
}

static int xve_cm_post_receive_srq(struct net_device *netdev, int id)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);
	struct ib_recv_wr *bad_wr;
	struct ib_recv_wr *wr = &priv->cm.rx_wr;
	int i, ret;

	wr->wr_id = id | XVE_OP_CM | XVE_OP_RECV;

	for (i = 0; i < priv->cm.num_frags; ++i)
		priv->cm.rx_sge[i].addr = priv->cm.srq_ring[id].mapping[i];

	ret = ib_post_srq_recv(priv->cm.srq, wr, &bad_wr);
	if (unlikely(ret)) {
		xve_warn(priv, "post srq failed for buf %d (%d)", id, ret);
		xve_cm_dma_unmap_rx(priv, priv->cm.num_frags - 1,
				    priv->cm.srq_ring[id].mapping);
		dev_kfree_skb_any(priv->cm.srq_ring[id].skb);
		priv->cm.srq_ring[id].skb = NULL;
	}

	return ret;
}

static struct sk_buff *xve_cm_alloc_rx_skb(struct net_device *dev,
					   struct xve_cm_buf *rx_ring,
					   int id, int frags,
					   u64 mapping[XVE_CM_RX_SG])
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;
	int i;

	skb = xve_dev_alloc_skb(priv, XVE_CM_HEAD_SIZE + NET_IP_ALIGN);
	if (unlikely(!skb)) {
		xve_warn(priv, "%s Failed to allocate skb", __func__);
		return NULL;
	}

	skb_reserve(skb, NET_IP_ALIGN);

	mapping[0] = ib_dma_map_single(priv->ca, skb->data, XVE_CM_HEAD_SIZE,
				       DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(priv->ca, mapping[0]))) {
		xve_warn(priv, "%s Failed to Map skb\n", __func__);
		dev_kfree_skb_any(skb);
		return NULL;
	}

	for (i = 0; i < frags; i++) {
		gfp_t alloc_flags = GFP_ATOMIC;
		struct page *page = xve_alloc_page(alloc_flags);

		if (!page) {
			xve_warn(priv,
				 "%s Failed to allocate flags %x page state %d\n",
				 __func__, alloc_flags,
				 test_bit(XVE_OPER_UP, &priv->state));
			goto partial_error;
		}
		skb_fill_page_desc(skb, i, page, 0, PAGE_SIZE);

		mapping[i + 1] =
		    ib_dma_map_page(priv->ca, skb_shinfo(skb)->frags[i].page.p,
				    0, PAGE_SIZE, DMA_FROM_DEVICE);
		if (unlikely(ib_dma_mapping_error(priv->ca, mapping[i + 1]))) {
			xve_warn(priv, "%s Failed to Map page", __func__);
			goto partial_error;
		}
	}

	rx_ring[id].skb = skb;
	return skb;

partial_error:

	ib_dma_unmap_single(priv->ca, mapping[0], XVE_CM_HEAD_SIZE,
			    DMA_FROM_DEVICE);

	for (; i > 0; --i) {
		xve_counters[XVE_NUM_PAGES_ALLOCED]--;
		ib_dma_unmap_single(priv->ca, mapping[i], PAGE_SIZE,
				    DMA_FROM_DEVICE);
	}

	dev_kfree_skb_any(skb);
	return NULL;
}

static void xve_cm_free_rx_ring(struct net_device *dev,
				struct xve_cm_buf *rx_ring)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < priv->xve_recvq_size; ++i) {
		if (rx_ring[i].skb) {
			xve_cm_dma_unmap_rx(priv, XVE_CM_RX_SG - 1,
					    rx_ring[i].mapping);
			xve_dev_kfree_skb_any(priv, rx_ring[i].skb, 0);
		}
	}
	vfree(rx_ring);
}

static void xve_cm_start_rx_drain(struct xve_dev_priv *priv)
{
	struct ib_send_wr *bad_wr;
	struct xve_cm_ctx *p;

	/* We only reserved 1 extra slot in CQ for drain WRs, so
	 * make sure we have at most 1 outstanding WR. */
	if (list_empty(&priv->cm.rx_flush_list) ||
	    !list_empty(&priv->cm.rx_drain_list))
		return;

	/*
	 * QPs on flush list are error state.  This way, a "flush
	 * error" WC will be immediately generated for each WR we post.
	 */
	p = list_entry(priv->cm.rx_flush_list.next, typeof(*p), list);
	if (ib_post_send(p->qp, &xve_cm_rx_drain_wr, &bad_wr))
		xve_warn(priv, "failed to post drain wr");

	list_splice_init(&priv->cm.rx_flush_list, &priv->cm.rx_drain_list);
}

static void xve_cm_rx_event_handler(struct ib_event *event, void *ctx)
{
	struct xve_cm_ctx *p = ctx;
	struct xve_dev_priv *priv = netdev_priv(p->netdev);
	unsigned long flags;

	if (event->event != IB_EVENT_QP_LAST_WQE_REACHED)
		return;

	spin_lock_irqsave(&priv->lock, flags);
	list_move(&p->list, &priv->cm.rx_flush_list);
	p->state = XVE_CM_RX_FLUSH;
	xve_cm_start_rx_drain(priv);
	spin_unlock_irqrestore(&priv->lock, flags);
}

static struct ib_qp *xve_cm_create_rx_qp(struct net_device *dev,
					 struct xve_cm_ctx *p)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_init_attr attr = {
		.event_handler = xve_cm_rx_event_handler,
		.send_cq = priv->recv_cq,	/* For drain WR */
		.recv_cq = priv->recv_cq,
		.srq = priv->cm.srq,
		.cap.max_send_wr = 1,	/* For drain WR */
		.cap.max_send_sge = 1,	/* 0 Seems not to work */
		.sq_sig_type = IB_SIGNAL_ALL_WR,
		.qp_type = IB_QPT_RC,
		.qp_context = p,
	};

	return ib_create_qp(priv->pd, &attr);
}

static int xve_cm_modify_rx_qp(struct net_device *dev,
			       struct ib_cm_id *cm_id, struct ib_qp *qp,
			       unsigned psn)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to init QP attr for INIT: %d", ret);
		return ret;
	}
	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to INIT: %d", ret);
		return ret;
	}
	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to init QP attr for RTR: %d", ret);
		return ret;
	}
	qp_attr.rq_psn = psn;
	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to RTR: %d", ret);
		return ret;
	}

	/*
	 * Current Mellanox HCA firmware won't generate completions
	 * with error for drain WRs unless the QP has been moved to
	 * RTS first. This work-around leaves a window where a QP has
	 * moved to error asynchronously, but this will eventually get
	 * fixed in firmware, so let's not error out if modify QP
	 * fails.
	 */
	qp_attr.qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to init QP attr for RTS: %d", ret);
		return 0;
	}
	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to RTS: %d", ret);
		return 0;
	}

	return 0;
}

static void xve_cm_init_rx_wr(struct net_device *dev,
			      struct ib_recv_wr *wr, struct ib_sge *sge)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < priv->cm.num_frags; ++i)
		sge[i].lkey = priv->mr->lkey;

	sge[0].length = XVE_CM_HEAD_SIZE;
	for (i = 1; i < priv->cm.num_frags; ++i)
		sge[i].length = PAGE_SIZE;

	wr->next = NULL;
	wr->sg_list = sge;
	wr->num_sge = priv->cm.num_frags;
}

static int xve_cm_send_rep(struct net_device *dev, struct ib_cm_id *cm_id,
			   struct ib_qp *qp, struct ib_cm_req_event_param *req,
			   unsigned psn)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_data data = { };
	struct ib_cm_rep_param rep = { };

	data.qpn = cpu_to_be32(priv->qp->qp_num);
	data.mtu = cpu_to_be32(XVE_CM_BUF_SIZE);

	rep.private_data = &data;
	rep.private_data_len = sizeof(data);
	rep.flow_control = 0;
	rep.rnr_retry_count = req->rnr_retry_count;
	rep.srq = xve_cm_has_srq(dev);
	rep.qp_num = qp->qp_num;
	rep.starting_psn = psn;
	return ib_send_cm_rep(cm_id, &rep);
}

static int xve_cm_req_handler(struct ib_cm_id *cm_id,
		struct ib_cm_event *event)
{
	struct net_device *dev = cm_id->context;
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_ctx *p;
	unsigned psn;
	int ret;
	union ib_gid *dgid = &event->param.req_rcvd.primary_path->dgid;
	struct xve_path *path;

	xve_debug(DEBUG_CM_INFO, priv, "%s REQ arrived\n", __func__);
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->netdev = dev;
	strncpy(p->version, XSIGO_LOCAL_VERSION, 60);
	p->direction = XVE_CM_ESTD_RX;
	p->id = cm_id;
	cm_id->context = p;
	p->state = XVE_CM_RX_LIVE;
	p->jiffies = jiffies;
	INIT_LIST_HEAD(&p->list);
	/*
	 * Save the remote GID
	 */
	memcpy(&p->dgid, dgid, sizeof(union ib_gid));

	p->qp = xve_cm_create_rx_qp(dev, p);
	if (IS_ERR(p->qp)) {
		ret = PTR_ERR(p->qp);
		goto err_qp;
	}

	psn = xve_random32(priv);
	ret = xve_cm_modify_rx_qp(dev, cm_id, p->qp, psn);
	if (ret)
		goto err_modify;

	spin_lock_irq(&priv->lock);
	/* Find path and insert rx_qp */
	path = __path_find(dev, dgid->raw);
	if (path) {
		char print[512];

		print_mgid_buf(print, (char *)dgid->raw);
		pr_info("XVE: %s  Adding Rx QP%x to the path %s ctx:%p\n",
			priv->xve_name, p->qp->qp_num, print, p);
		path->cm_ctx_rx = p;
	} else {
		priv->counters[XVE_PATH_NOT_SETUP]++;
	}

	xve_queue_complete_work(priv, XVE_WQ_START_CMSTALE, XVE_CM_RX_DELAY);
	/* Add this entry to passive ids list head, but do not re-add it
	 * if IB_EVENT_QP_LAST_WQE_REACHED has moved it to flush list. */
	p->jiffies = jiffies;
	if (p->state == XVE_CM_RX_LIVE)
		list_move(&p->list, &priv->cm.passive_ids);
	spin_unlock_irq(&priv->lock);

	ret = xve_cm_send_rep(dev, cm_id, p->qp, &event->param.req_rcvd, psn);
	if (ret) {
		xve_warn(priv, "failed to send REP: %d", ret);
		if (ib_modify_qp(p->qp, &xve_cm_err_attr, IB_QP_STATE))
			xve_warn(priv, "unable to move qp to error state");
	}
	return 0;

err_modify:
	ib_destroy_qp(p->qp);
err_qp:
	kfree(p);
	return ret;
}

static int xve_cm_rx_handler(struct ib_cm_id *cm_id,
		struct ib_cm_event *event)
{
	struct xve_cm_ctx *p;
	struct xve_dev_priv *priv;

	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		return xve_cm_req_handler(cm_id, event);
	case IB_CM_DREQ_RECEIVED:
		p = cm_id->context;
		ib_send_cm_drep(cm_id, NULL, 0);
		/* Fall through */
	case IB_CM_REJ_RECEIVED:
		p = cm_id->context;
		priv = netdev_priv(p->netdev);
		if (ib_modify_qp(p->qp, &xve_cm_err_attr, IB_QP_STATE))
			xve_warn(priv, "unable to move qp to error state");
		/* Fall through */
	default:
		return 0;
	}
}

static void xve_cm_free_rx_reap_list(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_ctx *rx, *n;
	LIST_HEAD(list);

	spin_lock_irq(&priv->lock);
	list_splice_init(&priv->cm.rx_reap_list, &list);
	spin_unlock_irq(&priv->lock);

	list_for_each_entry_safe(rx, n, &list, list) {
		ib_destroy_cm_id(rx->id);
		ib_destroy_qp(rx->qp);
		kfree(rx);
	}
}


/* Adjust length of skb with fragments to match received data */
static inline void skb_put_frags(struct sk_buff *skb,
		 unsigned int hdr_space,
		 unsigned int length, struct sk_buff *toskb)
{
	int i, num_frags;
	unsigned int size;

	/* put header into skb */
	size = min(length, hdr_space);
	skb->tail += size;
	skb->len += size;
	length -= size;

	num_frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < num_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		if (length == 0) {
			/* don't need this page */
			if (toskb)
				skb_fill_page_desc(toskb, i, skb_frag_page(frag)
						, 0, PAGE_SIZE);
			else
				__free_page(skb_shinfo(skb)->frags[i].page.p);
			--skb_shinfo(skb)->nr_frags;
		} else {
			size = min_t(unsigned, length, (unsigned)PAGE_SIZE);

			frag->size = size;
			skb->data_len += size;
			skb->truesize += size;
			skb->len += size;
			length -= size;
		}
	}
}

void xve_cm_handle_rx_wc(struct net_device *dev, struct ib_wc *wc)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_buf *rx_ring;
	unsigned int wr_id = wc->wr_id & ~(XVE_OP_CM | XVE_OP_RECV);
	struct sk_buff *skb, *newskb = NULL;
	struct xve_cm_ctx *p;
	unsigned long flags;
	u64 mapping[XVE_CM_RX_SG];
	int frags;
	struct sk_buff *small_skb;
	u16 vlan;

	xve_dbg_data(priv, "cm recv completion: id %d, status: %d",
		     wr_id, wc->status);

	if (unlikely(wr_id >= priv->xve_recvq_size)) {
		if (wr_id ==
		    (XVE_CM_RX_DRAIN_WRID & ~(XVE_OP_CM | XVE_OP_RECV))) {
			spin_lock_irqsave(&priv->lock, flags);
			list_splice_init(&priv->cm.rx_drain_list,
					 &priv->cm.rx_reap_list);
			xve_cm_start_rx_drain(priv);
			xve_queue_work(priv, XVE_WQ_START_CMRXREAP);
			spin_unlock_irqrestore(&priv->lock, flags);
		} else
			xve_warn(priv,
				 "cm recv completion event with wrid %d (> %d)",
				 wr_id, priv->xve_recvq_size);
		return;
	}

	p = wc->qp->qp_context;
	if (p == NULL) {
		pr_err("%s ERROR In CM Connection[RX] context Null  [xve %s]",
		       __func__, priv->xve_name);
		return;

	}

	if (p->direction != XVE_CM_ESTD_RX) {
		pr_err("%s ERROR CM Connection[RX] is not yet", __func__);
		pr_err(" established [xve %s]", priv->xve_name);
		pr_err("p->direction %d\n", p->direction);
		return;

	}

	rx_ring = priv->cm.srq_ring;
	skb = rx_ring[wr_id].skb;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (!test_bit(XVE_DELETING, &priv->state))
			xve_dbg_data(priv,
				"cm recv err QP%x status:%d wr:%d vendor_err%x",
				 wc->qp->qp_num, wc->status, wr_id,
				 wc->vendor_err);
		INC_RX_DROP_STATS(priv, dev);
		priv->counters[XVE_RC_RXCOMPL_ERR_COUNTER]++;
		goto repost;
	}

	if (unlikely(!(wr_id & XVE_CM_RX_UPDATE_MASK))) {
		if (p && time_after_eq(jiffies,
				       p->jiffies + XVE_CM_RX_UPDATE_TIME)) {
			spin_lock_irqsave(&priv->lock, flags);
			p->jiffies = jiffies;
			/* Move this entry to list head, but do not re-add it
			 * if it has been moved out of list. */
			if (p->state == XVE_CM_RX_LIVE)
				list_move(&p->list, &priv->cm.passive_ids);
			spin_unlock_irqrestore(&priv->lock, flags);
		}
	}

	if (wc->byte_len < XVE_CM_COPYBREAK) {
		int dlen = wc->byte_len;

		small_skb = dev_alloc_skb(dlen + NET_IP_ALIGN);
		if (small_skb) {
			skb_reserve(small_skb, NET_IP_ALIGN);
			ib_dma_sync_single_for_cpu(priv->ca,
						   rx_ring[wr_id].mapping[0],
						   dlen, DMA_FROM_DEVICE);
			skb_copy_from_linear_data(skb, small_skb->data, dlen);
			ib_dma_sync_single_for_device(priv->ca,
						      rx_ring[wr_id].mapping[0],
						      dlen, DMA_FROM_DEVICE);
			skb_put(small_skb, dlen);
			skb = small_skb;
			priv->counters[XVE_RX_SMALLSKB_ALLOC_COUNTER]++;
			goto copied;
		}
	}

	frags = PAGE_ALIGN(wc->byte_len - min(wc->byte_len,
					      (unsigned)XVE_CM_HEAD_SIZE)) /
	    PAGE_SIZE;

	newskb = xve_cm_alloc_rx_skb(dev, rx_ring, wr_id, frags, mapping);
	if (unlikely(!newskb)) {
		/*
		 * If we can't allocate a new RX buffer, dump
		 * this packet and reuse the old buffer.
		 */
		xve_dbg_data(priv,
			     "%s failed to allocate rc receive buffer %d\n",
			     __func__, wr_id);
		INC_RX_DROP_STATS(priv, dev);
		goto repost;
	}

	xve_cm_dma_unmap_rx(priv, frags, rx_ring[wr_id].mapping);
	memcpy(rx_ring[wr_id].mapping, mapping, (frags + 1) * sizeof(*mapping));

	xve_dbg_data(priv, "%s received %d bytes, SLID 0x%04x\n", __func__,
		     wc->byte_len, wc->slid);

	skb_put_frags(skb, XVE_CM_HEAD_SIZE, wc->byte_len, newskb);
copied:

	vlan = xg_vlan_get_rxtag(skb);
	xve_fwt_insert(priv, p, &p->dgid, 0, skb->data + ETH_ALEN, vlan);
	xve_prepare_skb(priv, skb);

	xve_dbg_data(priv,
			"%s Received RC packet %02x %02x %02x %02x %02x %02x",
			__func__, skb->data[0], skb->data[1], skb->data[2],
			skb->data[3], skb->data[4], skb->data[5]);
	xve_dbg_data(priv,
			"%02x %02x %02x %02x %02x %02x proto %x\n",
			skb->data[6], skb->data[7], skb->data[8], skb->data[9],
			skb->data[10], skb->data[11],
			skb->protocol);
	update_cm_rx_rate(p, skb->len);
	priv->counters[XVE_RC_RXCOMPL_COUNTER]++;
	xve_send_skb(priv, skb);
repost:
	if (unlikely(xve_cm_post_receive_srq(dev, wr_id)))
		xve_warn(priv, "cm post srq failed for buf %d", wr_id);
}

static inline int post_send(struct xve_dev_priv *priv,
			    struct xve_cm_ctx *tx,
			    unsigned int wr_id, u64 addr, int len)
{
	struct ib_send_wr *bad_wr;

	priv->tx_sge[0].addr = addr;
	priv->tx_sge[0].length = len;

	priv->tx_wr.num_sge = 1;
	priv->tx_wr.wr_id = wr_id | XVE_OP_CM;

	return ib_post_send(tx->qp, &priv->tx_wr, &bad_wr);
}

static void xve_cm_tx_buf_free(struct xve_dev_priv *priv,
			       struct xve_cm_buf *tx_req,
			       struct xve_cm_ctx *tx,
			       uint32_t wr_id, uint32_t qp_num)
{
	BUG_ON(tx_req == NULL || tx_req->skb == NULL);

	ib_dma_unmap_single(priv->ca, tx_req->mapping[0],
			tx_req->skb->len, DMA_TO_DEVICE);
	xve_dev_kfree_skb_any(priv, tx_req->skb, 1);
	memset(tx_req, 0, sizeof(struct xve_cm_buf));
}

int xve_cm_send(struct net_device *dev, struct sk_buff *skb,
		 struct xve_cm_ctx *tx)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_buf *tx_req;
	u64 addr;
	int ret = NETDEV_TX_OK;
	uint32_t wr_id;

	if (unlikely(skb->len > tx->mtu + VLAN_ETH_HLEN)) {
		xve_warn(priv,
			 "packet len %d (> %d) too long to send, dropping",
			 skb->len, tx->mtu);
		INC_TX_DROP_STATS(priv, dev);
		INC_TX_ERROR_STATS(priv, dev);
		dev_kfree_skb_any(skb);
		return ret;
	}

	xve_dbg_data(priv,
		     "sending packet: head 0x%x length %d connection 0x%x",
		     tx->tx_head, skb->len, tx->qp->qp_num);

	/*
	 * We put the skb into the tx_ring _before_ we call post_send()
	 * because it's entirely possible that the completion handler will
	 * run before we execute anything after the post_send().  That
	 * means we have to make sure everything is properly recorded and
	 * our state is consistent before we call post_send().
	 */
	wr_id = tx->tx_head & (priv->xve_sendq_size - 1);
	tx_req = &tx->tx_ring[wr_id];
	tx_req->skb = skb;
	addr = ib_dma_map_single(priv->ca, skb->data, skb->len, DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(priv->ca, addr))) {
		INC_TX_ERROR_STATS(priv, dev);
		dev_kfree_skb_any(skb);
		memset(tx_req, 0, sizeof(struct xve_cm_buf));
		return ret;
	}
	tx_req->mapping[0] = addr;

	if (unlikely(post_send(priv, tx, wr_id,
			       addr, skb->len))) {
		xve_warn(priv, "QP[%d] post_send failed wr_id:%d ctx:%p",
				tx->qp->qp_num, wr_id, tx);
		INC_TX_ERROR_STATS(priv, dev);
		xve_cm_tx_buf_free(priv, tx_req, tx, 0, tx->qp->qp_num);
	} else {
		dev->trans_start = jiffies;
		++tx->tx_head;
		if (++priv->tx_outstanding == priv->xve_sendq_size) {
			xve_dbg_data(priv,
				     "TX ring 0x%x full, stopping kernel net queue\n",
				     tx->qp->qp_num);
			if (ib_req_notify_cq(priv->send_cq, IB_CQ_NEXT_COMP))
				xve_warn(priv,
					 "request notify on send CQ failed");
			priv->counters[XVE_TX_RING_FULL_COUNTER]++;
			priv->counters[XVE_TX_QUEUE_STOP_COUNTER]++;
			netif_stop_queue(dev);
		}
	}
	priv->send_hbeat_flag = 0;
	return ret;
}

void xve_cm_handle_tx_wc(struct net_device *dev,
		struct ib_wc *wc)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_ctx *tx = wc->qp->qp_context;
	unsigned int wr_id = wc->wr_id & ~XVE_OP_CM;
	struct xve_cm_buf *tx_req;

	xve_dbg_data(priv, "cm send completion: id %d, status: %d\n",
		     wr_id, wc->status);

	if (unlikely(wr_id >= priv->xve_sendq_size)) {
		xve_warn(priv, "cm send completion event with wrid %d (> %d)",
			 wr_id, priv->xve_sendq_size);
		return;
	}

	tx_req = &tx->tx_ring[wr_id];
	xve_cm_tx_buf_free(priv, tx_req, tx, wr_id, wc->qp->qp_num);

	netif_tx_lock(dev);
	++tx->tx_tail;
	priv->counters[XVE_RC_TXCOMPL_COUNTER]++;
	if (unlikely(--priv->tx_outstanding == priv->xve_sendq_size >> 1) &&
	    netif_queue_stopped(dev) &&
	    test_bit(XVE_FLAG_ADMIN_UP, &priv->flags)) {
		priv->counters[XVE_TX_WAKE_UP_COUNTER]++;
		netif_wake_queue(dev);
	}

	if (wc->status != IB_WC_SUCCESS && wc->status != IB_WC_WR_FLUSH_ERR) {
		priv->counters[XVE_RC_TXCOMPL_ERR_COUNTER]++;
		tx->stats.tx_compl_err++;
		if (wc->status != IB_WC_RNR_RETRY_EXC_ERR)
			xve_warn(priv, "QP[%x] failed cm send event status:%d wrid:%d vend_err:%x",
					wc->qp->qp_num, wc->status, wr_id,
					wc->vendor_err);
		else
			xve_debug(DEBUG_CM_INFO, priv, "QP[%x] status:%d wrid:%d vend_err:%x",
					wc->qp->qp_num, wc->status, wr_id,
					wc->vendor_err);
		xve_cm_destroy_tx_deferred(tx);
	}
	netif_tx_unlock(dev);
}

int xve_cm_dev_open(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret;
	u64 sid;

	if (!priv->cm_supported)
		return 0;

	priv->cm.id = ib_create_cm_id(priv->ca, xve_cm_rx_handler, dev);
	if (IS_ERR(priv->cm.id)) {
		pr_warn("%s: failed to create CM ID\n", priv->ca->name);
		ret = PTR_ERR(priv->cm.id);
		goto err_cm;
	}

	sid = priv->local_gid.raw[14] << 8 | priv->local_gid.raw[15];
	sid = XVE_CM_IETF_ID | sid << 32 | priv->net_id;

	ret = ib_cm_listen(priv->cm.id, cpu_to_be64(sid), 0, NULL);
	if (ret) {
		pr_warn("%s: failed to listen on ID 0x%llx\n",
			priv->ca->name, sid);
		goto err_listen;
	}

	return 0;

err_listen:
	ib_destroy_cm_id(priv->cm.id);
err_cm:
	priv->cm.id = NULL;
	return ret;
}

void xve_cm_dev_stop(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_ctx *p;
	unsigned long begin;
	int ret;

	if (!priv->cm_supported || !priv->cm.id)
		return;

	ib_destroy_cm_id(priv->cm.id);
	priv->cm.id = NULL;

	spin_lock_irq(&priv->lock);
	while (!list_empty(&priv->cm.passive_ids)) {
		p = list_entry(priv->cm.passive_ids.next, typeof(*p), list);
		list_move(&p->list, &priv->cm.rx_error_list);
		p->state = XVE_CM_RX_ERROR;
		spin_unlock_irq(&priv->lock);
		ret = ib_modify_qp(p->qp, &xve_cm_err_attr, IB_QP_STATE);
		if (ret)
			xve_warn(priv, "QP[%x] unable to move error state[%d]",
				 p->qp ? p->qp->qp_num : 0, ret);
		spin_lock_irq(&priv->lock);
	}

	/* Wait for all RX to be drained */
	begin = jiffies;

	while (!list_empty(&priv->cm.rx_error_list) ||
	       !list_empty(&priv->cm.rx_flush_list) ||
	       !list_empty(&priv->cm.rx_drain_list)) {
		if (time_after(jiffies, begin + 5 * HZ)) {
			xve_warn(priv, "RX drain timing out");

			/*
			 * assume the HW is wedged and just free up everything.
			 */
			list_splice_init(&priv->cm.rx_flush_list,
					 &priv->cm.rx_reap_list);
			list_splice_init(&priv->cm.rx_error_list,
					 &priv->cm.rx_reap_list);
			list_splice_init(&priv->cm.rx_drain_list,
					 &priv->cm.rx_reap_list);
			break;
		}
		spin_unlock_irq(&priv->lock);
		msleep(20);
		xve_drain_cq(dev);
		spin_lock_irq(&priv->lock);
	}

	spin_unlock_irq(&priv->lock);

	cancel_delayed_work_sync(&priv->stale_task);
	xve_cm_free_rx_reap_list(dev);
	__xve_cm_tx_reap(priv);

}

static int xve_cm_rep_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	struct xve_cm_ctx *p = cm_id->context;
	struct xve_dev_priv *priv = netdev_priv(p->netdev);
	struct xve_cm_data *data = event->private_data;
	struct sk_buff_head skqueue;
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;
	struct sk_buff *skb;

	p->mtu = be32_to_cpu(data->mtu);

	if (p->mtu <= ETH_HLEN) {
		xve_warn(priv, "Rejecting connection: mtu %d <= %d",
			 p->mtu, ETH_HLEN);
		return -EINVAL;
	}

	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to init QP attr for RTR: %d", ret);
		return ret;
	}

	qp_attr.rq_psn = 0; /* FIXME */
	ret = ib_modify_qp(p->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to RTR: %d", ret);
		return ret;
	}

	qp_attr.qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to init QP attr for RTS: %d", ret);
		return ret;
	}
	ret = ib_modify_qp(p->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to RTS: %d", ret);
		return ret;
	}

	skb_queue_head_init(&skqueue);

	spin_lock_irq(&priv->lock);
	set_bit(XVE_FLAG_OPER_UP, &p->flags);
	while ((skb = __skb_dequeue(&p->path->queue)))
		__skb_queue_tail(&skqueue, skb);
	spin_unlock_irq(&priv->lock);

	while ((skb = __skb_dequeue(&skqueue))) {
		skb->dev = p->netdev;
		if (dev_queue_xmit(skb)) {
			xve_warn(priv, "dev_queue_xmit failed ");
			xve_warn(priv, "to requeue packet");
		} else {
			xve_dbg_data(priv, "%s Succefully sent skb\n",
				     __func__);
		}

	}

	ret = ib_send_cm_rtu(cm_id, NULL, 0);
	if (ret) {
		xve_warn(priv, "failed to send RTU: %d", ret);
		return ret;
	}
	return 0;
}

static struct ib_qp *xve_cm_create_tx_qp(struct net_device *dev,
					 struct xve_cm_ctx *tx)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_init_attr attr = {
		.send_cq = priv->recv_cq,
		.recv_cq = priv->recv_cq,
		.srq = priv->cm.srq,
		.cap.max_send_wr = priv->xve_sendq_size,
		.cap.max_send_sge = 1,
		.sq_sig_type = IB_SIGNAL_ALL_WR,
		.qp_type = IB_QPT_RC,
		.qp_context = tx
	};

	return ib_create_qp(priv->pd, &attr);
}

static int xve_cm_send_req(struct net_device *dev,
			   struct ib_cm_id *id, struct ib_qp *qp,
			   struct ib_sa_path_rec *pathrec)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_data data = { };
	struct ib_cm_req_param req = { };
	u64 sid;

	sid = pathrec->dgid.raw[14] << 8 | pathrec->dgid.raw[15];
	sid = XVE_CM_IETF_ID | sid << 32 | priv->net_id;

	data.qpn = cpu_to_be32(priv->qp->qp_num);
	data.mtu = cpu_to_be32(XVE_CM_BUF_SIZE);

	req.primary_path = pathrec;
	req.alternate_path = NULL;
	req.service_id = cpu_to_be64(sid);
	req.qp_num = qp->qp_num;
	req.qp_type = qp->qp_type;
	req.private_data = &data;
	req.private_data_len = sizeof(data);
	req.flow_control = 0;

	req.starting_psn = 0;	/* FIXME */

	/*
	 * Pick some arbitrary defaults here; we could make these
	 * module parameters if anyone cared about setting them.
	 */
	req.responder_resources = 4;
	req.remote_cm_response_timeout = 20;
	req.local_cm_response_timeout = 20;
	req.retry_count = retry_count;
	req.rnr_retry_count = rnr_retry_count;
	req.max_cm_retries = 15;
	req.srq = xve_cm_has_srq(dev);
	return ib_send_cm_req(id, &req);
}

static int xve_cm_modify_tx_init(struct net_device *dev,
				 struct ib_cm_id *cm_id, struct ib_qp *qp)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	ret =
	    ib_find_pkey(priv->ca, priv->port, priv->pkey, &qp_attr.pkey_index);
	if (ret) {
		xve_warn(priv, "pkey 0x%x not found: %d", priv->pkey, ret);
		return ret;
	}

	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE;
	qp_attr.port_num = priv->port;
	qp_attr_mask =
	    IB_QP_STATE | IB_QP_ACCESS_FLAGS | IB_QP_PKEY_INDEX | IB_QP_PORT;

	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify tx QP to INIT: %d", ret);
		return ret;
	}
	return 0;
}

static int xve_cm_tx_init(struct xve_cm_ctx *p, struct ib_sa_path_rec *pathrec)
{
	struct xve_dev_priv *priv = netdev_priv(p->netdev);
	int ret;

	p->tx_ring = vmalloc(priv->xve_sendq_size * sizeof(*p->tx_ring));
	if (IS_ERR(p->tx_ring)) {
		xve_warn(priv, "failed to allocate tx ring");
		ret = -ENOMEM;
		goto err_tx;
	}
	memset(p->tx_ring, 0, priv->xve_sendq_size * sizeof(*p->tx_ring));

	p->qp = xve_cm_create_tx_qp(p->netdev, p);
	if (IS_ERR(p->qp)) {
		ret = PTR_ERR(p->qp);
		xve_warn(priv, "failed to allocate tx qp: %d", ret);
		goto err_qp;
	}

	p->id = ib_create_cm_id(priv->ca, xve_cm_tx_handler, p);
	if (IS_ERR(p->id)) {
		ret = PTR_ERR(p->id);
		xve_warn(priv, "failed to create tx cm id: %d", ret);
		goto err_id;
	}

	ret = xve_cm_modify_tx_init(p->netdev, p->id, p->qp);
	if (ret) {
		xve_warn(priv, "failed to modify tx qp to rtr: %d", ret);
		goto err_modify;
	}

	ret = xve_cm_send_req(p->netdev, p->id, p->qp, pathrec);
	if (ret) {
		xve_warn(priv, "failed to send cm req: %d", ret);
		goto err_send_cm;
	}

	pr_info("%s QP[%x] Tx Created path %pI6 ctx:%p\n", priv->xve_name,
			p->qp->qp_num, pathrec->dgid.raw, p);
	return 0;

err_send_cm:
err_modify:
	ib_destroy_cm_id(p->id);
err_id:
	p->id = NULL;
	ib_destroy_qp(p->qp);
err_qp:
	p->qp = NULL;
	vfree(p->tx_ring);
err_tx:
	return ret;
}

static int wait_for_txcmcompletions(struct xve_cm_ctx *p, u8 modify)
{
	struct xve_dev_priv *priv = netdev_priv(p->netdev);
	unsigned long begin;
	uint32_t qpnum = p->qp ? p->qp->qp_num : 0;


	if (p->tx_ring) {
		int num_loops = 0;

		begin = jiffies;

		while ((int)p->tx_tail - (int)p->tx_head < 0) {
			if (!num_loops && xve_modify_qp && modify) {
				ib_modify_qp(p->qp, &xve_cm_err_attr,
						IB_QP_STATE);
				xve_debug(DEBUG_CM_INFO, priv,
					"M%d QP[%x] TX Completions pending[%d]",
					modify, qpnum, p->tx_head - p->tx_tail);
			}

			/* If Oper State is down poll for completions */
			if (!test_bit(XVE_OPER_UP, &priv->state))
				xve_drain_cq(priv->netdev);

			if (time_after(jiffies,
				begin + xve_wait_txcompl * HZ)) {
				xve_warn(priv,
					"M%d QP[%x] Tx Completions Pending[%d], Waited[%d:%d] state%d",
					modify, qpnum, p->tx_head - p->tx_tail,
					num_loops, xve_wait_txcompl,
					test_bit(XVE_OPER_UP, &priv->state));
				return -EINVAL;
			}
			num_loops++;
			msleep(20);
		}
		if (num_loops != 0)
			xve_debug(DEBUG_CM_INFO, priv, "M%d QP%x Overall Wait[%d:%d]",
					modify, qpnum, num_loops,
					jiffies_to_msecs(jiffies - begin));
	}

	return 0;
}

static void xve_cm_tx_destroy(struct xve_cm_ctx *p)
{
	struct xve_dev_priv *priv = netdev_priv(p->netdev);
	struct xve_cm_buf *tx_req;
	unsigned long flags = 0;
	uint32_t qp_num = p->qp ? p->qp->qp_num : 0;

	xve_debug(DEBUG_CM_INFO, priv,
			"QP[%x] ctx:%p Destroy active conn head[0x%x] tail[0x%x]",
			qp_num, p, p->tx_head, p->tx_tail);

	if (p->id)
		ib_destroy_cm_id(p->id);

	wait_for_txcmcompletions(p, 1);

	/* Destroy QP and Wait for any pending completions */
	if (p->qp)
		ib_destroy_qp(p->qp);

	pr_info("%s QP[%x] ctx:%p Destroyed head[0x%x] tail[0x%x]\n",
			priv->xve_name, qp_num, p, p->tx_head, p->tx_tail);

	wait_for_txcmcompletions(p, 0);

	spin_lock_irqsave(&priv->lock, flags);
	while ((int)p->tx_tail - (int)p->tx_head < 0) {
		uint32_t wr_id = p->tx_tail & (priv->xve_sendq_size - 1);

		tx_req = &p->tx_ring[wr_id];

		++p->tx_tail;
		spin_unlock_irqrestore(&priv->lock, flags);

		xve_cm_tx_buf_free(priv, tx_req, p, 0, 0);
		netif_tx_lock_bh(p->netdev);
		if (unlikely(--priv->tx_outstanding ==
					(priv->xve_sendq_size >> 1))
		    && netif_queue_stopped(p->netdev) &&
		    test_bit(XVE_FLAG_ADMIN_UP, &priv->flags)) {
			priv->counters[XVE_TX_WAKE_UP_COUNTER]++;
			netif_wake_queue(p->netdev);
		}
		netif_tx_unlock_bh(p->netdev);

		spin_lock_irqsave(&priv->lock, flags);
	}
	spin_unlock_irqrestore(&priv->lock, flags);

	if (p->tx_ring)
		vfree(p->tx_ring);
	if (p != NULL)
		kfree(p);
}

static int xve_cm_tx_handler(struct ib_cm_id *cm_id,
		struct ib_cm_event *event)
{
	struct xve_cm_ctx *tx = cm_id->context;
	struct xve_dev_priv *priv;
	struct net_device *dev;
	int ret;

	if (tx == NULL) {
		pr_info("XVE: %s qpn %d Event %d\n", __func__,
			cm_id->remote_cm_qpn, event->event);
		return 0;
	}

	priv = netdev_priv(tx->netdev);
	dev = priv->netdev;
	switch (event->event) {
	case IB_CM_DREQ_RECEIVED:
		xve_debug(DEBUG_CM_INFO, priv, "%s DREQ received QP %x",
			  __func__, tx->qp ? tx->qp->qp_num : 0);

		ib_send_cm_drep(cm_id, NULL, 0);
		break;
	case IB_CM_REP_RECEIVED:
		xve_debug(DEBUG_CM_INFO, priv, "%s REP received QP %x",
			  __func__, tx->qp ? tx->qp->qp_num : 0);
		ret = xve_cm_rep_handler(cm_id, event);
		if (ret)
			ib_send_cm_rej(cm_id, IB_CM_REJ_CONSUMER_DEFINED,
				       NULL, 0, NULL, 0);
		break;
	case IB_CM_REQ_ERROR:
	case IB_CM_REJ_RECEIVED:
	case IB_CM_TIMEWAIT_EXIT:
		pr_info("%s CM event %d [dev %s] QP %x", __func__,
			event->event, dev->name, tx->qp ? tx->qp->qp_num : 0);
		netif_tx_lock_bh(dev);
		/*
		 * Should we delete all L2 entries XXX
		 */
		xve_cm_destroy_tx_deferred(tx);
		netif_tx_unlock_bh(dev);
		break;
	default:
		break;
	}

	return 0;
}

struct xve_cm_ctx *xve_cm_create_tx(struct net_device *dev,
				    struct xve_path *path)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_cm_ctx *tx;

	tx = kzalloc(sizeof(*tx), GFP_ATOMIC);
	if (!tx)
		return NULL;

	xve_cm_set(path, tx);
	strncpy(tx->version, XSIGO_LOCAL_VERSION, 60);
	tx->direction = XVE_CM_ESTD_TX;
	tx->path = path;
	tx->netdev = dev;
	list_add(&tx->list, &priv->cm.start_list);
	set_bit(XVE_FLAG_INITIALIZED, &tx->flags);
	xve_queue_work(priv, XVE_WQ_START_CMTXSTART);
	return tx;
}

void xve_cm_destroy_tx_deferred(struct xve_cm_ctx *tx)
{
	struct xve_dev_priv *priv = netdev_priv(tx->netdev);
	unsigned long flags = 0;

	spin_lock_irqsave(&priv->lock, flags);
	clear_bit(XVE_FLAG_OPER_UP, &tx->flags);
	if (test_and_clear_bit(XVE_FLAG_INITIALIZED, &tx->flags)) {
		list_move(&tx->list, &priv->cm.reap_list);
		xve_queue_work(priv, XVE_WQ_START_CMTXREAP);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
}

void xve_cm_tx_start(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_CMTXSTART, 0);
	struct net_device *dev = priv->netdev;
	struct xve_cm_ctx *p;
	unsigned long flags;
	int ret;
	struct ib_sa_path_rec pathrec;

	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	while (!list_empty(&priv->cm.start_list)) {
		p = list_entry(priv->cm.start_list.next, typeof(*p), list);
		list_del_init(&p->list);
		memcpy(&pathrec, &p->path->pathrec, sizeof(pathrec));

		spin_unlock_irqrestore(&priv->lock, flags);
		netif_tx_unlock_bh(dev);

		ret = xve_cm_tx_init(p, &pathrec);

		netif_tx_lock_bh(dev);
		spin_lock_irqsave(&priv->lock, flags);
	}

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);
	xve_put_ctx(priv);
}

static void __xve_cm_tx_reap(struct xve_dev_priv *priv)
{
	struct net_device *dev = priv->netdev;
	struct xve_cm_ctx *p;
	unsigned long flags;

	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	while (!list_empty(&priv->cm.reap_list)) {
		p = list_entry(priv->cm.reap_list.next, typeof(*p), list);
		list_del(&p->list);
		spin_unlock_irqrestore(&priv->lock, flags);
		netif_tx_unlock_bh(dev);
		/*
		 * Destroy path
		 */
		if (p->path)
			xve_flush_single_path_by_gid(dev,
					&p->path->pathrec.dgid, NULL);
		xve_cm_set(p->path, NULL);
		xve_cm_tx_destroy(p);
		netif_tx_lock_bh(dev);
		spin_lock_irqsave(&priv->lock, flags);
	}

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);
}

void xve_cm_tx_reap(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_CMTXREAP, 0);
	__xve_cm_tx_reap(priv);
	xve_put_ctx(priv);
}

void xve_cm_rx_reap(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_CMRXREAP, 0);

	xve_cm_free_rx_reap_list(priv->netdev);
	xve_put_ctx(priv);
}

void xve_cm_stale_task(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_CMSTALE, 2);
	struct xve_cm_ctx *p;
	int ret;

	spin_lock_irq(&priv->lock);
	while (!list_empty(&priv->cm.passive_ids)) {
		/* List is sorted by LRU, start from tail,
		 * stop when we see a recently used entry */
		p = list_entry(priv->cm.passive_ids.prev, typeof(*p), list);
		if (time_before_eq(jiffies, p->jiffies + XVE_CM_RX_TIMEOUT))
			break;
		list_move(&p->list, &priv->cm.rx_error_list);
		p->state = XVE_CM_RX_ERROR;
		spin_unlock_irq(&priv->lock);
		ret = ib_modify_qp(p->qp, &xve_cm_err_attr, IB_QP_STATE);
		if (ret)
			xve_warn(priv, "unable to move qp to error state: %d",
				 ret);
		spin_lock_irq(&priv->lock);
	}

	if (!list_empty(&priv->cm.passive_ids))
		xve_queue_complete_work(priv, XVE_WQ_START_CMSTALE,
					XVE_CM_RX_DELAY);

	spin_unlock_irq(&priv->lock);
}

static void xve_cm_create_srq(struct net_device *dev, int max_sge)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_srq_init_attr srq_init_attr = {
		.attr = {
			 .max_wr = priv->xve_recvq_size,
			 .max_sge = max_sge}
	};

	priv->cm.srq = ib_create_srq(priv->pd, &srq_init_attr);
	if (IS_ERR(priv->cm.srq)) {
		pr_warn("%s: failed to allocate SRQ, error %ld\n",
				priv->ca->name, PTR_ERR(priv->cm.srq));
		priv->cm.srq = NULL;
		return;
	}

	priv->cm.srq_ring =
	    vmalloc(priv->xve_recvq_size * sizeof(*priv->cm.srq_ring));
	if (!priv->cm.srq_ring) {
		pr_warn("%s: failed to allocate CM SRQ ring (%d entries)\n",
			priv->ca->name, priv->xve_recvq_size);
		ib_destroy_srq(priv->cm.srq);
		priv->cm.srq = NULL;
		return;
	}

	memset(priv->cm.srq_ring, 0,
	       priv->xve_recvq_size * sizeof(*priv->cm.srq_ring));
}

int xve_cm_dev_init(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int i, ret;
	struct ib_device_attr attr;

	if (!priv->cm_supported)
		return 0;

	INIT_LIST_HEAD(&priv->cm.passive_ids);
	INIT_LIST_HEAD(&priv->cm.reap_list);
	INIT_LIST_HEAD(&priv->cm.start_list);
	INIT_LIST_HEAD(&priv->cm.rx_error_list);
	INIT_LIST_HEAD(&priv->cm.rx_flush_list);
	INIT_LIST_HEAD(&priv->cm.rx_drain_list);
	INIT_LIST_HEAD(&priv->cm.rx_reap_list);

	ret = ib_query_device(priv->ca, &attr);
	if (ret) {
		pr_warn("ib_query_device() failed with %d\n", ret);
		return ret;
	}

	/* PSIF determines SGE value based on stack unwind */
	priv->dev_attr = attr;

	/* Based on the admin mtu from the chassis */
	attr.max_srq_sge =
	    min_t(int,
		  ALIGN((priv->admin_mtu + VLAN_ETH_HLEN),
			PAGE_SIZE) / PAGE_SIZE, attr.max_srq_sge);
	xve_debug(DEBUG_CM_INFO, priv, "%s max_srq_sge=%d", __func__,
		  attr.max_srq_sge);

	xve_cm_create_srq(dev, attr.max_srq_sge);
	if (xve_cm_has_srq(dev)) {
		priv->cm.max_cm_mtu = attr.max_srq_sge * PAGE_SIZE - 0x20;
		priv->cm.num_frags = attr.max_srq_sge;
		xve_debug(DEBUG_CM_INFO, priv,
			  "%s max_cm_mtu = 0x%x, num_frags=%d", __func__,
			  priv->cm.max_cm_mtu, priv->cm.num_frags);
	} else {
		pr_notice("XVE: Non-SRQ mode not supported\n");
		return -ENOTSUPP;
	}

	xve_cm_init_rx_wr(dev, &priv->cm.rx_wr, priv->cm.rx_sge);

	if (xve_cm_has_srq(dev)) {
		for (i = 0; i < priv->xve_recvq_size; ++i) {
			if (!xve_cm_alloc_rx_skb(dev, priv->cm.srq_ring, i,
						 priv->cm.num_frags - 1,
						 priv->cm.
						 srq_ring[i].mapping)) {
				xve_warn(priv,
					"%s failed to allocate rbuf rc%d",
					__func__, i);
				xve_cm_dev_cleanup(dev);
				return -ENOMEM;
			}

			if (xve_cm_post_receive_srq(dev, i)) {
				xve_warn(priv, "SRQ post failed buf:%d", i);
				xve_cm_dev_cleanup(dev);
				return -EIO;
			}
		}
	}

	return 0;
}

void xve_cm_dev_cleanup(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret;

	if (!priv->cm_supported || !priv->cm.srq)
		return;

	xve_debug(DEBUG_CM_INFO, priv, "%s Cleanup xve CM", __func__);

	ret = ib_destroy_srq(priv->cm.srq);
	if (ret)
		xve_warn(priv, "ib_destroy_srq failed: %d", ret);

	priv->cm.srq = NULL;
	if (!priv->cm.srq_ring)
		return;

	xve_cm_free_rx_ring(dev, priv->cm.srq_ring);
	priv->cm.srq_ring = NULL;
}
