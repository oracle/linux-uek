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

/* Like tcp_fin */
static void sdp_fin(struct sock *sk)
{
	sdp_dbg(sk, "%s\n", __func__);

	sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(sk, SOCK_DONE);


	sk_stream_mem_reclaim(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if (sk->sk_shutdown == SHUTDOWN_MASK ||
		    sk->sk_state == TCP_CLOSE)
			sk_wake_async(sk, 1, POLL_HUP);
		else
			sk_wake_async(sk, 1, POLL_IN);
	}
}

void sdp_post_send(struct sdp_sock *ssk, struct sk_buff *skb, u8 mid)
{
	struct sdp_buf *tx_req;
	struct sdp_bsdh *h = (struct sdp_bsdh *)skb_push(skb, sizeof *h);
	unsigned mseq = ssk->tx_head;
	int i, rc, frags;
	dma_addr_t addr;
	struct device *hwdev;
	struct ib_sge *sge;
	struct ib_send_wr *bad_wr;

	h->mid = mid;
	h->flags = 0; /* TODO: OOB */
	h->bufs = htons(ssk->rx_head - ssk->rx_tail);
	h->len = htonl(skb->len);
	h->mseq = htonl(mseq);
	h->mseq_ack = htonl(ssk->mseq_ack);

	tx_req = &ssk->tx_ring[mseq & (SDP_TX_SIZE - 1)];
	tx_req->skb = skb;
	hwdev = ssk->dma_device;
	sge = ssk->ibsge;
	addr = dma_map_single(hwdev,
			      skb->data, skb->len - skb->data_len,
			      DMA_TO_DEVICE);
	tx_req->mapping[0] = addr;
	
	/* TODO: proper error handling */
	BUG_ON(dma_mapping_error(addr));

	sge->addr = (u64)addr;
	sge->length = skb->len - skb->data_len;
	sge->lkey = ssk->mr->lkey;
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		++sge;
		addr = dma_map_page(hwdev, skb_shinfo(skb)->frags[i].page,
				    skb_shinfo(skb)->frags[i].page_offset,
				    skb_shinfo(skb)->frags[i].size,
				    DMA_TO_DEVICE);
		BUG_ON(dma_mapping_error(addr));
		tx_req->mapping[i + 1] = addr;
		sge->addr = addr;
		sge->length = skb_shinfo(skb)->frags[i].size;
		sge->lkey = ssk->mr->lkey;
	}

	ssk->tx_wr.next = NULL;
	ssk->tx_wr.wr_id = ssk->tx_head;
	ssk->tx_wr.sg_list = ssk->ibsge;
	ssk->tx_wr.num_sge = frags + 1;
	ssk->tx_wr.opcode = IB_WR_SEND;
	ssk->tx_wr.send_flags = IB_SEND_SIGNALED;
	if (unlikely(mid != SDP_MID_DATA))
		ssk->tx_wr.send_flags |= IB_SEND_SOLICITED;
	rc = ib_post_send(ssk->qp, &ssk->tx_wr, &bad_wr);
	BUG_ON(rc);
	++ssk->tx_head;
	--ssk->bufs;
	ssk->remote_credits = ssk->rx_head - ssk->rx_tail;
}

struct sk_buff *sdp_send_completion(struct sdp_sock *ssk, int mseq)
{
	struct device *hwdev;
	struct sdp_buf *tx_req;
	struct sk_buff *skb;
	int i, frags;

	if (unlikely(mseq != ssk->tx_tail)) {
		printk(KERN_WARNING "Bogus send completion id %d tail %d\n",
			mseq, ssk->tx_tail);
		return NULL;
	}

	hwdev = ssk->dma_device;
        tx_req = &ssk->tx_ring[mseq & (SDP_TX_SIZE - 1)];
	skb = tx_req->skb;
	dma_unmap_single(hwdev, tx_req->mapping[0], skb->len - skb->data_len,
			 DMA_TO_DEVICE);
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		dma_unmap_page(hwdev, tx_req->mapping[i + 1],
			       skb_shinfo(skb)->frags[i].size,
			       DMA_TO_DEVICE);
	}

	++ssk->tx_tail;
	return skb;
}


static void sdp_post_recv(struct sdp_sock *ssk)
{
	struct sdp_buf *rx_req;
	int i, rc, frags;
	dma_addr_t addr;
	struct device *hwdev;
	struct ib_sge *sge;
	struct ib_recv_wr *bad_wr;
	struct sk_buff *skb;
	struct page *page;
	skb_frag_t *frag;
	struct sdp_bsdh *h;
	int id = ssk->rx_head;

	/* Now, allocate and repost recv */
	/* TODO: allocate from cache */
	skb = sk_stream_alloc_skb(&ssk->isk.sk, sizeof(struct sdp_bsdh),
				  GFP_KERNEL);
	/* FIXME */
	BUG_ON(!skb);
	h = (struct sdp_bsdh *)skb_push(skb, sizeof *h);
	for (i = 0; i < SDP_MAX_SEND_SKB_FRAGS; ++i) {
		page = alloc_pages(GFP_KERNEL, 0);
		BUG_ON(!page);
		frag = &skb_shinfo(skb)->frags[i];
		frag->page                = page;
		frag->page_offset         = 0;
		frag->size                = PAGE_SIZE;
		++skb_shinfo(skb)->nr_frags;
		skb->len += PAGE_SIZE;
		skb->data_len += PAGE_SIZE;
		skb->truesize += PAGE_SIZE;
	}

        rx_req = ssk->rx_ring + (id & (SDP_RX_SIZE - 1));
	rx_req->skb = skb;
	hwdev = ssk->dma_device;
	sge = ssk->ibsge;
	addr = dma_map_single(hwdev, h, skb_headlen(skb),
			      DMA_FROM_DEVICE);
	BUG_ON(dma_mapping_error(addr));

	rx_req->mapping[0] = addr;
	
	/* TODO: proper error handling */
	sge->addr = (u64)addr;
	sge->length = skb_headlen(skb);
	sge->lkey = ssk->mr->lkey;
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		++sge;
		addr = dma_map_page(hwdev, skb_shinfo(skb)->frags[i].page,
				    skb_shinfo(skb)->frags[i].page_offset,
				    skb_shinfo(skb)->frags[i].size,
				    DMA_FROM_DEVICE);
		BUG_ON(dma_mapping_error(addr));
		rx_req->mapping[i + 1] = addr;
		sge->addr = addr;
		sge->length = skb_shinfo(skb)->frags[i].size;
		sge->lkey = ssk->mr->lkey;
	}

	ssk->rx_wr.next = NULL;
	ssk->rx_wr.wr_id = id | SDP_OP_RECV;
	ssk->rx_wr.sg_list = ssk->ibsge;
	ssk->rx_wr.num_sge = frags + 1;
	rc = ib_post_recv(ssk->qp, &ssk->rx_wr, &bad_wr);
	/* TODO */
	BUG_ON(rc);
	++ssk->rx_head;
}

void sdp_post_recvs(struct sdp_sock *ssk)
{
	int rmem = atomic_read(&ssk->isk.sk.sk_rmem_alloc);

	if (unlikely(!ssk->id))
		return;

	while ((likely(ssk->rx_head - ssk->rx_tail < SDP_RX_SIZE) &&
		(ssk->rx_head - ssk->rx_tail - SDP_MIN_BUFS) *
		SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE + rmem <
		ssk->isk.sk.sk_rcvbuf * 0x10) ||
	       unlikely(ssk->rx_head - ssk->rx_tail < SDP_MIN_BUFS))
		sdp_post_recv(ssk);
}

struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id)
{
	struct sdp_buf *rx_req;
	struct device *hwdev;
	struct sk_buff *skb;
	int i, frags;

	if (unlikely(id != ssk->rx_tail)) {
		printk(KERN_WARNING "Bogus recv completion id %d tail %d\n",
			id, ssk->rx_tail);
		return NULL;
	}

	hwdev = ssk->dma_device;
        rx_req = &ssk->rx_ring[id & (SDP_RX_SIZE - 1)];
	skb = rx_req->skb;
	dma_unmap_single(hwdev, rx_req->mapping[0], skb_headlen(skb),
			 DMA_FROM_DEVICE);
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i)
		dma_unmap_page(hwdev, rx_req->mapping[i + 1],
			       skb_shinfo(skb)->frags[i].size,
			       DMA_TO_DEVICE);
	++ssk->rx_tail;
	--ssk->remote_credits;
	return skb;
}

/* Here because I do not want queue to fail. */
static inline int sdp_sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int skb_len;

	skb_set_owner_r(skb, sk);

	skb_len = skb->len;

	skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb_len);
	return 0;
}

static inline void update_send_head(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_send_head = skb->next;
	if (sk->sk_send_head == (struct sk_buff *)&sk->sk_write_queue)
		sk->sk_send_head = NULL;
}

void sdp_post_sends(struct sdp_sock *ssk, int nonagle)
{
	/* TODO: nonagle */
	struct sk_buff *skb;
	int c;

	if (unlikely(!ssk->id))
		return;

	while (ssk->bufs > SDP_MIN_BUFS &&
	       ssk->tx_head - ssk->tx_tail < SDP_TX_SIZE &&
	       (skb = ssk->isk.sk.sk_send_head)) {
		update_send_head(&ssk->isk.sk, skb);
		__skb_dequeue(&ssk->isk.sk.sk_write_queue);
		sdp_post_send(ssk, skb, SDP_MID_DATA);
	}
	c = ssk->remote_credits;
	if (likely(c > SDP_MIN_BUFS))
		c *= 2;

	if (unlikely(c < ssk->rx_head - ssk->rx_tail) &&
	    likely(ssk->bufs > 1) &&
	    likely(ssk->tx_head - ssk->tx_tail < SDP_TX_SIZE)) {
		skb = sk_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh),
					  GFP_KERNEL);
		/* FIXME */
		BUG_ON(!skb);
		sdp_post_send(ssk, skb, SDP_MID_DATA);
	}

	if (unlikely((1 << ssk->isk.sk.sk_state) &
			(TCPF_FIN_WAIT1 | TCPF_LAST_ACK)) &&
		!ssk->isk.sk.sk_send_head &&
		ssk->bufs) {
		skb = sk_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh),
					  GFP_KERNEL);
		/* FIXME */
		BUG_ON(!skb);
		sdp_post_send(ssk, skb, SDP_MID_DISCONN);
		if (ssk->isk.sk.sk_state == TCP_FIN_WAIT1)
			ssk->isk.sk.sk_state = TCP_FIN_WAIT2;
		else
			ssk->isk.sk.sk_state = TCP_CLOSING;
	}
}

static void sdp_handle_wc(struct sdp_sock *ssk, struct ib_wc *wc)
{
	struct sk_buff *skb;
	struct sdp_bsdh *h;

	if (wc->wr_id & SDP_OP_RECV) {
		skb = sdp_recv_completion(ssk, wc->wr_id);
		if (unlikely(!skb))
			return;

		if (unlikely(wc->status)) {
			if (wc->status != IB_WC_WR_FLUSH_ERR)
				sdp_dbg(&ssk->isk.sk,
					"Recv completion with error. "
					"Status %d\n", wc->status);
			__kfree_skb(skb);
			sdp_set_error(&ssk->isk.sk, -ECONNRESET);
			wake_up(&ssk->wq);
		} else {
			/* TODO: handle msg < bsdh */
			sdp_dbg(&ssk->isk.sk,
				"Recv completion. ID %d Length %d\n",
				(int)wc->wr_id, wc->byte_len);
			skb->len = wc->byte_len;
			skb->data_len = wc->byte_len - sizeof(struct sdp_bsdh);
			if (unlikely(skb->data_len < 0)) {
				printk("SDP: FIXME len %d\n", wc->byte_len);
			}
			h = (struct sdp_bsdh *)skb->data;
			skb->h.raw = skb->data;
			ssk->mseq_ack = ntohl(h->mseq);
			if (ssk->mseq_ack != (int)wc->wr_id)
				printk("SDP BUG! mseq %d != wrid %d\n",
						ssk->mseq_ack, (int)wc->wr_id);
			ssk->bufs = ntohl(h->mseq_ack) - ssk->tx_head + 1 +
				ntohs(h->bufs);

			if (likely(h->mid == SDP_MID_DATA) &&
			    likely(skb->data_len > 0)) {
				skb_pull(skb, sizeof(struct sdp_bsdh));
				/* TODO: queue can fail? */
				/* TODO: free unused fragments */
				sdp_sock_queue_rcv_skb(&ssk->isk.sk, skb);
			} else if (likely(h->mid == SDP_MID_DATA)) {
				__kfree_skb(skb);
			} else if (h->mid == SDP_MID_DISCONN) {
				skb_pull(skb, sizeof(struct sdp_bsdh));
				/* TODO: free unused fragments */
				/* this will wake recvmsg */
				sdp_sock_queue_rcv_skb(&ssk->isk.sk, skb);
				sdp_fin(&ssk->isk.sk);
			} else {
				/* TODO: Handle other messages */
				printk("SDP: FIXME MID %d\n", h->mid);
				__kfree_skb(skb);
			}
			sdp_post_recvs(ssk);
		}
	} else {
		skb = sdp_send_completion(ssk, wc->wr_id);
		if (unlikely(!skb))
			return;
		sk_stream_free_skb(&ssk->isk.sk, skb);
		if (unlikely(wc->status)) {
			if (wc->status != IB_WC_WR_FLUSH_ERR)
				sdp_dbg(&ssk->isk.sk,
					"Send completion with error. "
					"Status %d\n", wc->status);
			sdp_set_error(&ssk->isk.sk, -ECONNRESET);
			wake_up(&ssk->wq);
		}

		sk_stream_write_space(&ssk->isk.sk);
	}

	if (likely(!wc->status)) {
		sdp_post_recvs(ssk);
		sdp_post_sends(ssk, 0);
	}

	if (ssk->time_wait && !ssk->isk.sk.sk_send_head &&
	    ssk->tx_head == ssk->tx_tail) {
		ssk->time_wait = 0;
		ssk->isk.sk.sk_state = TCP_CLOSE;
		sdp_dbg(&ssk->isk.sk, "%s: destroy in time wait state\n",
			__func__);
		queue_work(sdp_workqueue, &ssk->destroy_work);
	}
}

void sdp_completion_handler(struct ib_cq *cq, void *cq_context)
{
	struct sock *sk = cq_context;
	struct sdp_sock *ssk = sdp_sk(sk);
	schedule_work(&ssk->work);
}

void sdp_work(void *data)
{
	struct sock *sk = (struct sock *)data;
	struct sdp_sock *ssk = sdp_sk(sk);
	struct ib_cq *cq;
	int n, i;

	sdp_dbg(sk, "%s\n", __func__);

	cq = ssk->cq;
	if (unlikely(!cq))
		return;

	do {
		lock_sock(sk);
		n = ib_poll_cq(cq, SDP_NUM_WC, ssk->ibwc);
		for (i = 0; i < n; ++i) {
			sdp_handle_wc(ssk, ssk->ibwc + i);
		}
		release_sock(sk);
	} while (n == SDP_NUM_WC);
	sk_stream_mem_reclaim(sk);
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	do {
		lock_sock(sk);
		n = ib_poll_cq(cq, SDP_NUM_WC, ssk->ibwc);
		for (i = 0; i < n; ++i) {
			sdp_handle_wc(ssk, ssk->ibwc + i);
		}
		release_sock(sk);
	} while (n == SDP_NUM_WC);
}
