/*
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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
 *
 * $Id$
 */
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include "sdp.h"

#define sdp_cnt(var) do { (var)++; } while (0)
static unsigned sdp_keepalive_probes_sent = 0;

module_param_named(sdp_keepalive_probes_sent, sdp_keepalive_probes_sent, uint, 0644);
MODULE_PARM_DESC(sdp_keepalive_probes_sent, "Total number of keepalive probes sent.");

static int sdp_process_tx_cq(struct sdp_sock *ssk);

int sdp_xmit_poll(struct sdp_sock *ssk, int force)
{
	int wc_processed = 0;

	/* If we don't have a pending timer, set one up to catch our recent
	   post in case the interface becomes idle */
	if (!timer_pending(&ssk->tx_ring.timer))
		mod_timer(&ssk->tx_ring.timer, jiffies + SDP_TX_POLL_TIMEOUT);

	/* Poll the CQ every SDP_TX_POLL_MODER packets */
	if (force || (++ssk->tx_ring.poll_cnt & (SDP_TX_POLL_MODER - 1)) == 0) {
		wc_processed = sdp_process_tx_cq(ssk);
		sdp_prf(&ssk->isk.sk, NULL, "processed %d wc's. inflight=%d", wc_processed,
				ring_posted(ssk->tx_ring));
	}

	return wc_processed;	
}

void sdp_post_send(struct sdp_sock *ssk, struct sk_buff *skb, u8 mid)
{
	struct sdp_buf *tx_req;
	struct sdp_bsdh *h = (struct sdp_bsdh *)skb_push(skb, sizeof *h);
	unsigned long mseq = ring_head(ssk->tx_ring);
	int i, rc, frags;
	u64 addr;
	struct ib_device *dev;
	struct ib_send_wr *bad_wr;

	struct ib_sge ibsge[SDP_MAX_SEND_SKB_FRAGS + 1];
	struct ib_sge *sge = ibsge;
	struct ib_send_wr tx_wr = { 0 };

	SDPSTATS_COUNTER_MID_INC(post_send, mid);
	SDPSTATS_HIST(send_size, skb->len);

	h->mid = mid;
	if (unlikely(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_URG))
		h->flags = SDP_OOB_PRES | SDP_OOB_PEND;
	else
		h->flags = 0;

	h->bufs = htons(ring_posted(ssk->rx_ring));
	h->len = htonl(skb->len);
	h->mseq = htonl(mseq);
	h->mseq_ack = htonl(mseq_ack(ssk));

	sdp_prf1(&ssk->isk.sk, skb, "TX: %s bufs: %d mseq:%ld ack:%d",
			mid2str(mid), ring_posted(ssk->rx_ring), mseq, ntohl(h->mseq_ack));

	SDP_DUMP_PACKET(&ssk->isk.sk, "TX", skb, h);

	tx_req = &ssk->tx_ring.buffer[mseq & (SDP_TX_SIZE - 1)];
	tx_req->skb = skb;
	dev = ssk->ib_device;
	addr = ib_dma_map_single(dev, skb->data, skb->len - skb->data_len,
				 DMA_TO_DEVICE);
	tx_req->mapping[0] = addr;

	/* TODO: proper error handling */
	BUG_ON(ib_dma_mapping_error(dev, addr));

	sge->addr = addr;
	sge->length = skb->len - skb->data_len;
	sge->lkey = ssk->mr->lkey;
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		++sge;
		addr = ib_dma_map_page(dev, skb_shinfo(skb)->frags[i].page,
				       skb_shinfo(skb)->frags[i].page_offset,
				       skb_shinfo(skb)->frags[i].size,
				       DMA_TO_DEVICE);
		BUG_ON(ib_dma_mapping_error(dev, addr));
		tx_req->mapping[i + 1] = addr;
		sge->addr = addr;
		sge->length = skb_shinfo(skb)->frags[i].size;
		sge->lkey = ssk->mr->lkey;
	}

	tx_wr.next = NULL;
	tx_wr.wr_id = ring_head(ssk->tx_ring) | SDP_OP_SEND;
	tx_wr.sg_list = ibsge;
	tx_wr.num_sge = frags + 1;
	tx_wr.opcode = IB_WR_SEND;
	tx_wr.send_flags = IB_SEND_SIGNALED;
	if (unlikely(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_URG))
		tx_wr.send_flags |= IB_SEND_SOLICITED;
	
	{
		static unsigned long last_send = 0;
		int delta = jiffies - last_send;
		
		if (likely(last_send)) 
			SDPSTATS_HIST(send_interval, delta);

		last_send = jiffies;
	}
	rc = ib_post_send(ssk->qp, &tx_wr, &bad_wr);
	atomic_inc(&ssk->tx_ring.head);
	atomic_dec(&ssk->tx_ring.credits);
	atomic_set(&ssk->remote_credits, ring_posted(ssk->rx_ring));
	if (unlikely(rc)) {
		sdp_dbg(&ssk->isk.sk, "ib_post_send failed with status %d.\n", rc);
		sdp_set_error(&ssk->isk.sk, -ECONNRESET);
		wake_up(&ssk->wq);
	}
}

static struct sk_buff *sdp_send_completion(struct sdp_sock *ssk, int mseq)
{
	struct ib_device *dev;
	struct sdp_buf *tx_req;
	struct sk_buff *skb = NULL;
	struct bzcopy_state *bz;
	int i, frags;
	struct sdp_tx_ring *tx_ring = &ssk->tx_ring;
	if (unlikely(mseq != ring_tail(*tx_ring))) {
		printk(KERN_WARNING "Bogus send completion id %d tail %d\n",
			mseq, ring_tail(*tx_ring));
		goto out;
	}

	dev = ssk->ib_device;
        tx_req = &tx_ring->buffer[mseq & (SDP_TX_SIZE - 1)];
	skb = tx_req->skb;
	ib_dma_unmap_single(dev, tx_req->mapping[0], skb->len - skb->data_len,
			    DMA_TO_DEVICE);
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		ib_dma_unmap_page(dev, tx_req->mapping[i + 1],
				  skb_shinfo(skb)->frags[i].size,
				  DMA_TO_DEVICE);
	}

	tx_ring->una_seq += TCP_SKB_CB(skb)->end_seq;

	/* TODO: AIO and real zcopy code; add their context support here */
	bz = BZCOPY_STATE(skb);
	if (bz)
		bz->busy--;

	atomic_inc(&tx_ring->tail);

out:
	return skb;
}

static int sdp_handle_send_comp(struct sdp_sock *ssk, struct ib_wc *wc)
{
	struct sk_buff *skb = NULL;

	skb = sdp_send_completion(ssk, wc->wr_id);
	if (unlikely(!skb))
		return -1;

	if (unlikely(wc->status)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			struct sock *sk = &ssk->isk.sk;
			sdp_warn(sk, "Send completion with error. "
				"Status %d\n", wc->status);
			sdp_set_error(sk, -ECONNRESET);
			wake_up(&ssk->wq);

			queue_work(sdp_wq, &ssk->destroy_work);
		}
	}

	{
		struct sdp_bsdh *h = (struct sdp_bsdh *)skb->data;
		sdp_prf1(&ssk->isk.sk, skb, "tx completion. mseq:%d", ntohl(h->mseq));
	}

	sk_wmem_free_skb(&ssk->isk.sk, skb);

	return 0;
}

static inline void sdp_process_tx_wc(struct sdp_sock *ssk, struct ib_wc *wc)
{
	if (likely(wc->wr_id & SDP_OP_SEND)) {
		sdp_handle_send_comp(ssk, wc);
		return;
	}

	/* Keepalive probe sent cleanup */
	sdp_cnt(sdp_keepalive_probes_sent);

	if (likely(!wc->status))
		return;

	sdp_dbg(&ssk->isk.sk, " %s consumes KEEPALIVE status %d\n",
			__func__, wc->status);

	if (wc->status == IB_WC_WR_FLUSH_ERR)
		return;

	sdp_set_error(&ssk->isk.sk, -ECONNRESET);
	wake_up(&ssk->wq);
}

static int sdp_process_tx_cq(struct sdp_sock *ssk)
{
	struct ib_wc ibwc[SDP_NUM_WC];
	int n, i;
	int wc_processed = 0;

	if (!ssk->tx_ring.cq) {
		sdp_warn(&ssk->isk.sk, "WARNING: tx irq when tx_cq is destroyed\n");
		return 0;
	}
	
	do {
		n = ib_poll_cq(ssk->tx_ring.cq, SDP_NUM_WC, ibwc);
		for (i = 0; i < n; ++i) {
			sdp_process_tx_wc(ssk, ibwc + i);
			wc_processed++;
		}
	} while (n == SDP_NUM_WC);

	sdp_dbg_data(&ssk->isk.sk, "processed %d wc's\n", wc_processed);

	if (wc_processed) {
		struct sock *sk = &ssk->isk.sk;
		sdp_post_sends(ssk, 0);

		if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
			sk_stream_write_space(&ssk->isk.sk);
	}

	return wc_processed;	
}

static void sdp_poll_tx_timeout(unsigned long data)
{
	struct sdp_sock *ssk = (struct sdp_sock *)data;
	struct sock *sk = &ssk->isk.sk;
	u32 inflight, wc_processed;

	sdp_dbg_data(&ssk->isk.sk, "Polling tx cq. inflight=%d\n",
		(u32) ring_posted(ssk->tx_ring));

	sdp_prf(&ssk->isk.sk, NULL, "%s. inflight=%d", __func__,
		(u32) ring_posted(ssk->tx_ring));

	/* Only process if the socket is not in use */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		mod_timer(&ssk->tx_ring.timer, jiffies + SDP_TX_POLL_TIMEOUT);
		sdp_dbg_data(&ssk->isk.sk, "socket is busy - trying later\n");
		SDPSTATS_COUNTER_INC(tx_poll_busy);
		goto out;
	}

	if (unlikely(sk->sk_state == TCP_CLOSE))
		goto out;

	wc_processed = sdp_process_tx_cq(ssk);
	sdp_prf(&ssk->isk.sk, NULL, "processed %d wc's. inflight=%d", wc_processed,
		ring_posted(ssk->tx_ring));
	if (!wc_processed)
		SDPSTATS_COUNTER_INC(tx_poll_miss);
	else
		SDPSTATS_COUNTER_INC(tx_poll_hit);

	inflight = (u32) ring_posted(ssk->tx_ring);

	/* If there are still packets in flight and the timer has not already
	 * been scheduled by the Tx routine then schedule it here to guarantee
	 * completion processing of these packets */
	if (inflight) { /* TODO: make sure socket is not closed */
		sdp_dbg_data(sk, "arming timer for more polling\n");
		mod_timer(&ssk->tx_ring.timer, jiffies + SDP_TX_POLL_TIMEOUT);
	}

out:
	bh_unlock_sock(sk);
}

static void sdp_tx_irq(struct ib_cq *cq, void *cq_context)
{
	struct sock *sk = cq_context;
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_warn(sk, "Got tx comp interrupt\n");

	mod_timer(&ssk->tx_ring.timer, jiffies + 1);
}

void sdp_tx_ring_purge(struct sdp_sock *ssk)
{
	while (ring_posted(ssk->tx_ring)) {
		struct sk_buff *skb;
		skb = sdp_send_completion(ssk, ring_tail(ssk->tx_ring));
		if (!skb)
			break;
		__kfree_skb(skb);
	}
}

void sdp_post_keepalive(struct sdp_sock *ssk)
{
	int rc;
	struct ib_send_wr wr, *bad_wr;

	sdp_dbg(&ssk->isk.sk, "%s\n", __func__);

	memset(&wr, 0, sizeof(wr));

	wr.next    = NULL;
	wr.wr_id   = 0;
	wr.sg_list = NULL;
	wr.num_sge = 0;
	wr.opcode  = IB_WR_RDMA_WRITE;

	rc = ib_post_send(ssk->qp, &wr, &bad_wr);
	if (rc) {
		sdp_dbg(&ssk->isk.sk, "ib_post_keepalive failed with status %d.\n", rc);
		sdp_set_error(&ssk->isk.sk, -ECONNRESET);
		wake_up(&ssk->wq);
	}

	sdp_cnt(sdp_keepalive_probes_sent);
}

static void sdp_tx_cq_event_handler(struct ib_event *event, void *data)
{
}

int sdp_tx_ring_create(struct sdp_sock *ssk, struct ib_device *device)
{
	struct ib_cq *tx_cq;
	int rc = 0;

	atomic_set(&ssk->tx_ring.head, 1);
	atomic_set(&ssk->tx_ring.tail, 1);

	ssk->tx_ring.buffer = kmalloc(sizeof *ssk->tx_ring.buffer * SDP_TX_SIZE,
				      GFP_KERNEL);
	if (!ssk->tx_ring.buffer) {
		rc = -ENOMEM;
		sdp_warn(&ssk->isk.sk, "Unable to allocate TX Ring size %zd.\n",
			 sizeof(*ssk->tx_ring.buffer) * SDP_TX_SIZE);

		goto out;
	}

	tx_cq = ib_create_cq(device, sdp_tx_irq, sdp_tx_cq_event_handler,
			  &ssk->isk.sk, SDP_TX_SIZE, 0);

	if (IS_ERR(tx_cq)) {
		rc = PTR_ERR(tx_cq);
		sdp_warn(&ssk->isk.sk, "Unable to allocate TX CQ: %d.\n", rc);
		goto err_cq;
	}

	sdp_sk(&ssk->isk.sk)->tx_ring.cq = tx_cq;

	init_timer(&ssk->tx_ring.timer);
	ssk->tx_ring.timer.function = sdp_poll_tx_timeout;
	ssk->tx_ring.timer.data = (unsigned long) ssk;
	ssk->tx_ring.poll_cnt = 0;

	init_timer(&ssk->nagle_timer);
	ssk->nagle_timer.function = sdp_nagle_timeout;
	ssk->nagle_timer.data = (unsigned long) ssk;

	return 0;

err_cq:
	kfree(ssk->tx_ring.buffer);
	ssk->tx_ring.buffer = NULL;
out:
	return rc;
}

void sdp_tx_ring_destroy(struct sdp_sock *ssk)
{
	del_timer(&ssk->nagle_timer);

	if (ssk->tx_ring.buffer) {
		sdp_tx_ring_purge(ssk);

		kfree(ssk->tx_ring.buffer);
		ssk->tx_ring.buffer = NULL;
	}

	if (ssk->tx_ring.cq) {
		ib_destroy_cq(ssk->tx_ring.cq);
		ssk->tx_ring.cq = NULL;
	}

	WARN_ON(ring_head(ssk->tx_ring) != ring_tail(ssk->tx_ring));
}
