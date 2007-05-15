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

#define SDP_RESIZE_WAIT 16

struct sdp_chrecvbuf {
	u32 size;
};

static int rcvbuf_scale = 0x10;

module_param_named(rcvbuf_scale, rcvbuf_scale, int, 0644);
MODULE_PARM_DESC(rcvbuf_scale, "Receive buffer size scale factor.");

static int top_mem_usage = 0;
module_param_named(top_mem_usage, top_mem_usage, int, 0644);
MODULE_PARM_DESC(top_mem_usage, "Top system wide sdp memory usage for recv (in MB).");

#ifdef CONFIG_PPC
static int max_large_sockets = 100;
#else
static int max_large_sockets = 1000;
#endif
module_param_named(max_large_sockets, max_large_sockets, int, 0644);
MODULE_PARM_DESC(max_large_sockets, "Max number of large sockets (32k buffers).");

static int curr_large_sockets = 0;
atomic_t sdp_current_mem_usage;
spinlock_t sdp_large_sockets_lock;

static int sdp_can_resize(void)
{
	int count, ret;
	spin_lock_irq(&sdp_large_sockets_lock);
	count = curr_large_sockets;
	ret = curr_large_sockets < max_large_sockets;
	if (ret)
		curr_large_sockets++;
	spin_unlock_irq(&sdp_large_sockets_lock);

	return ret;
}

void sdp_remove_large_sock(void)
{
	spin_lock_irq(&sdp_large_sockets_lock);
	curr_large_sockets--;
	spin_unlock_irq(&sdp_large_sockets_lock);
}

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
	u64 addr;
	struct ib_device *dev;
	struct ib_sge *sge;
	struct ib_send_wr *bad_wr;

	h->mid = mid;
	if (unlikely(TCP_SKB_CB(skb)->flags & TCPCB_URG))
		h->flags = SDP_OOB_PRES | SDP_OOB_PEND;
	else
		h->flags = 0;

	h->bufs = htons(ssk->rx_head - ssk->rx_tail);
	h->len = htonl(skb->len);
	h->mseq = htonl(mseq);
	h->mseq_ack = htonl(ssk->mseq_ack);

	tx_req = &ssk->tx_ring[mseq & (SDP_TX_SIZE - 1)];
	tx_req->skb = skb;
	dev = ssk->ib_device;
	sge = ssk->ibsge;
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

	ssk->tx_wr.next = NULL;
	ssk->tx_wr.wr_id = ssk->tx_head;
	ssk->tx_wr.sg_list = ssk->ibsge;
	ssk->tx_wr.num_sge = frags + 1;
	ssk->tx_wr.opcode = IB_WR_SEND;
	ssk->tx_wr.send_flags = IB_SEND_SIGNALED;
	if (unlikely(mid != SDP_MID_DATA) ||
	    unlikely(TCP_SKB_CB(skb)->flags & TCPCB_URG))
		ssk->tx_wr.send_flags |= IB_SEND_SOLICITED;
	rc = ib_post_send(ssk->qp, &ssk->tx_wr, &bad_wr);
	++ssk->tx_head;
	--ssk->bufs;
	ssk->remote_credits = ssk->rx_head - ssk->rx_tail;
	if (unlikely(rc)) {
		sdp_dbg(&ssk->isk.sk, "ib_post_send failed with status %d.\n", rc);
		sdp_set_error(&ssk->isk.sk, -ECONNRESET);
		wake_up(&ssk->wq);
	}
}

struct sk_buff *sdp_send_completion(struct sdp_sock *ssk, int mseq)
{
	struct ib_device *dev;
	struct sdp_buf *tx_req;
	struct sk_buff *skb;
	int i, frags;

	if (unlikely(mseq != ssk->tx_tail)) {
		printk(KERN_WARNING "Bogus send completion id %d tail %d\n",
			mseq, ssk->tx_tail);
		return NULL;
	}

	dev = ssk->ib_device;
        tx_req = &ssk->tx_ring[mseq & (SDP_TX_SIZE - 1)];
	skb = tx_req->skb;
	ib_dma_unmap_single(dev, tx_req->mapping[0], skb->len - skb->data_len,
			    DMA_TO_DEVICE);
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		ib_dma_unmap_page(dev, tx_req->mapping[i + 1],
				  skb_shinfo(skb)->frags[i].size,
				  DMA_TO_DEVICE);
	}

	ssk->snd_una += TCP_SKB_CB(skb)->end_seq;
	++ssk->tx_tail;
	return skb;
}


static void sdp_post_recv(struct sdp_sock *ssk)
{
	struct sdp_buf *rx_req;
	int i, rc, frags;
	u64 addr;
	struct ib_device *dev;
	struct ib_sge *sge;
	struct ib_recv_wr *bad_wr;
	struct sk_buff *skb;
	struct page *page;
	skb_frag_t *frag;
	struct sdp_bsdh *h;
	int id = ssk->rx_head;

	/* Now, allocate and repost recv */
	/* TODO: allocate from cache */
	skb = sk_stream_alloc_skb(&ssk->isk.sk, SDP_HEAD_SIZE,
				  GFP_KERNEL);
	/* FIXME */
	BUG_ON(!skb);
	h = (struct sdp_bsdh *)skb->head;
	for (i = 0; i < ssk->recv_frags; ++i) {
		page = alloc_pages(GFP_HIGHUSER, 0);
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
	dev = ssk->ib_device;
	sge = ssk->ibsge;
	addr = ib_dma_map_single(dev, h, SDP_HEAD_SIZE, DMA_FROM_DEVICE);
	BUG_ON(ib_dma_mapping_error(dev, addr));

	rx_req->mapping[0] = addr;

	/* TODO: proper error handling */
	sge->addr = (u64)addr;
	sge->length = SDP_HEAD_SIZE;
	sge->lkey = ssk->mr->lkey;
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		++sge;
		addr = ib_dma_map_page(dev, skb_shinfo(skb)->frags[i].page,
				       skb_shinfo(skb)->frags[i].page_offset,
				       skb_shinfo(skb)->frags[i].size,
				       DMA_FROM_DEVICE);
		BUG_ON(ib_dma_mapping_error(dev, addr));
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
	++ssk->rx_head;
	if (unlikely(rc)) {
		sdp_dbg(&ssk->isk.sk, "ib_post_recv failed with status %d\n", rc);
		sdp_reset(&ssk->isk.sk);
	}

	atomic_add(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);
}

void sdp_post_recvs(struct sdp_sock *ssk)
{
	int scale = ssk->rcvbuf_scale;
	if (unlikely(!ssk->id))
		return;

	if (top_mem_usage &&
	    (top_mem_usage * 0x100000) < atomic_read(&sdp_current_mem_usage) * PAGE_SIZE)
		scale = 1;

	while ((likely(ssk->rx_head - ssk->rx_tail < SDP_RX_SIZE) &&
		(ssk->rx_head - ssk->rx_tail - SDP_MIN_BUFS) *
		(SDP_HEAD_SIZE + ssk->recv_frags * PAGE_SIZE) +
		ssk->rcv_nxt - ssk->copied_seq <
		ssk->isk.sk.sk_rcvbuf * scale) ||
	       unlikely(ssk->rx_head - ssk->rx_tail < SDP_MIN_BUFS))
		sdp_post_recv(ssk);
}

struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id)
{
	struct sdp_buf *rx_req;
	struct ib_device *dev;
	struct sk_buff *skb;
	int i, frags;

	if (unlikely(id != ssk->rx_tail)) {
		printk(KERN_WARNING "Bogus recv completion id %d tail %d\n",
			id, ssk->rx_tail);
		return NULL;
	}

	dev = ssk->ib_device;
        rx_req = &ssk->rx_ring[id & (SDP_RX_SIZE - 1)];
	skb = rx_req->skb;
	ib_dma_unmap_single(dev, rx_req->mapping[0], SDP_HEAD_SIZE,
			    DMA_FROM_DEVICE);
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i)
		ib_dma_unmap_page(dev, rx_req->mapping[i + 1],
				  skb_shinfo(skb)->frags[i].size,
				  DMA_FROM_DEVICE);
	++ssk->rx_tail;
	--ssk->remote_credits;
	return skb;
}

/* Here because I do not want queue to fail. */
static inline struct sk_buff *sdp_sock_queue_rcv_skb(struct sock *sk,
						     struct sk_buff *skb)
{
	int skb_len;
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sk_buff *tail;

	/* not needed since sk_rmem_alloc is not currently used
	 * TODO - remove this?
	skb_set_owner_r(skb, sk); */

	skb_len = skb->len;

	TCP_SKB_CB(skb)->seq = ssk->rcv_nxt;
	ssk->rcv_nxt += skb_len;

	if (likely(skb_len && (tail = skb_peek_tail(&sk->sk_receive_queue))) &&
	    unlikely(skb_tailroom(tail) >= skb_len)) {
		skb_copy_bits(skb, 0, skb_put(tail, skb_len), skb_len);
		__kfree_skb(skb);
		skb = tail;
	} else
		skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb_len);
	return skb;
}

static inline void update_send_head(struct sock *sk, struct sk_buff *skb)
{
	struct page *page;
	sk->sk_send_head = skb->next;
	if (sk->sk_send_head == (struct sk_buff *)&sk->sk_write_queue) {
		sk->sk_send_head = NULL;
		page = sk->sk_sndmsg_page;
		if (page) {
			put_page(page);
			sk->sk_sndmsg_page = NULL;
		}
	}
}

static inline int sdp_nagle_off(struct sdp_sock *ssk, struct sk_buff *skb)
{
	return (ssk->nonagle & TCP_NAGLE_OFF) ||
		skb->next != (struct sk_buff *)&ssk->isk.sk.sk_write_queue ||
		skb->len + sizeof(struct sdp_bsdh) >= ssk->xmit_size_goal ||
		(ssk->tx_tail == ssk->tx_head &&
		 !(ssk->nonagle & TCP_NAGLE_CORK)) ||
		(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_PSH);
}

void sdp_post_sends(struct sdp_sock *ssk, int nonagle)
{
	/* TODO: nonagle? */
	struct sk_buff *skb;
	int c;

	if (unlikely(!ssk->id)) {
		if (ssk->isk.sk.sk_send_head) {
			sdp_dbg(&ssk->isk.sk,
				"Send on socket without cmid ECONNRESET.\n");
			/* TODO: flush send queue? */
			sdp_reset(&ssk->isk.sk);
		}
		return;
	}

	if (ssk->recv_request &&
	    ssk->rx_tail >= ssk->recv_request_head &&
	    ssk->bufs >= SDP_MIN_BUFS &&
	    ssk->tx_head - ssk->tx_tail < SDP_TX_SIZE) {
		struct sdp_chrecvbuf *resp_size;
		ssk->recv_request = 0;
		skb = sk_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh) +
					  sizeof(*resp_size),
					  GFP_KERNEL);
		/* FIXME */
		BUG_ON(!skb);
		resp_size = (struct sdp_chrecvbuf *)skb_put(skb, sizeof *resp_size);
		resp_size->size = htons(ssk->recv_frags * PAGE_SIZE);
		sdp_post_send(ssk, skb, SDP_MID_CHRCVBUF_ACK);
	}

	while (ssk->bufs > SDP_MIN_BUFS &&
	       ssk->tx_head - ssk->tx_tail < SDP_TX_SIZE &&
	       (skb = ssk->isk.sk.sk_send_head) &&
		sdp_nagle_off(ssk, skb)) {
		update_send_head(&ssk->isk.sk, skb);
		__skb_dequeue(&ssk->isk.sk.sk_write_queue);
		sdp_post_send(ssk, skb, SDP_MID_DATA);
	}

	if (ssk->bufs == SDP_MIN_BUFS &&
	    !ssk->sent_request &&
	    ssk->tx_head > ssk->sent_request_head + SDP_RESIZE_WAIT &&
	    ssk->tx_head - ssk->tx_tail < SDP_TX_SIZE) {
		struct sdp_chrecvbuf *req_size;
		skb = sk_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh) +
					  sizeof(*req_size),
					  GFP_KERNEL);
		/* FIXME */
		BUG_ON(!skb);
		ssk->sent_request = SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE;
		ssk->sent_request_head = ssk->tx_head;
		req_size = (struct sdp_chrecvbuf *)skb_put(skb, sizeof *req_size);
		req_size->size = htons(ssk->sent_request);
		sdp_post_send(ssk, skb, SDP_MID_CHRCVBUF);
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

static inline void sdp_resize(struct sdp_sock *ssk, u32 new_size)
{
	ssk->recv_frags = PAGE_ALIGN(new_size - SDP_HEAD_SIZE)	/ PAGE_SIZE;
	if (ssk->recv_frags > SDP_MAX_SEND_SKB_FRAGS)
		ssk->recv_frags = SDP_MAX_SEND_SKB_FRAGS;
}

static void sdp_handle_wc(struct sdp_sock *ssk, struct ib_wc *wc)
{
	struct sk_buff *skb;
	struct sdp_bsdh *h;
	int pagesz, i;

	if (wc->wr_id & SDP_OP_RECV) {
		skb = sdp_recv_completion(ssk, wc->wr_id);
		if (unlikely(!skb))
			return;

		atomic_sub(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);

		if (unlikely(wc->status)) {
			if (wc->status != IB_WC_WR_FLUSH_ERR) {
				sdp_dbg(&ssk->isk.sk,
						"Recv completion with error. "
						"Status %d\n", wc->status);
				sdp_reset(&ssk->isk.sk);
			}
			__kfree_skb(skb);
		} else {
			int frags;

			sdp_dbg_data(&ssk->isk.sk,
				     "Recv completion. ID %d Length %d\n",
				     (int)wc->wr_id, wc->byte_len);
			if (unlikely(wc->byte_len < sizeof(struct sdp_bsdh))) {
				printk("SDP BUG! byte_len %d < %zd\n",
				       wc->byte_len, sizeof(struct sdp_bsdh));
				__kfree_skb(skb);
				return;
			}
			skb->len = wc->byte_len;
			if (likely(wc->byte_len > SDP_HEAD_SIZE))
				skb->data_len = wc->byte_len - SDP_HEAD_SIZE;
			else
				skb->data_len = 0;
			skb->data = skb->head;
			skb->tail = skb->head + skb_headlen(skb);
			h = (struct sdp_bsdh *)skb->data;
			skb->h.raw = skb->data;
			ssk->mseq_ack = ntohl(h->mseq);
			if (ssk->mseq_ack != (int)wc->wr_id)
				printk("SDP BUG! mseq %d != wrid %d\n",
						ssk->mseq_ack, (int)wc->wr_id);
			ssk->bufs = ntohl(h->mseq_ack) - ssk->tx_head + 1 +
				ntohs(h->bufs);

			frags = skb_shinfo(skb)->nr_frags;
			pagesz = PAGE_ALIGN(skb->data_len);
			skb_shinfo(skb)->nr_frags = pagesz / PAGE_SIZE;

			for (i = skb_shinfo(skb)->nr_frags;
			     i < frags; ++i) {
				put_page(skb_shinfo(skb)->frags[i].page);
				skb->truesize -= PAGE_SIZE;
			}

			if (unlikely(h->flags & SDP_OOB_PEND))
				sk_send_sigurg(&ssk->isk.sk);

			skb_pull(skb, sizeof(struct sdp_bsdh));

			if (likely(h->mid == SDP_MID_DATA) &&
			    likely(skb->len > 0)) {
				int oob = h->flags & SDP_OOB_PRES;
				skb = sdp_sock_queue_rcv_skb(&ssk->isk.sk, skb);
				if (unlikely(oob))
					sdp_urg(ssk, skb);
			} else if (likely(h->mid == SDP_MID_DATA)) {
				__kfree_skb(skb);
			} else if (h->mid == SDP_MID_DISCONN) {
				/* this will wake recvmsg */
				sdp_sock_queue_rcv_skb(&ssk->isk.sk, skb);
				sdp_fin(&ssk->isk.sk);
			} else if (h->mid == SDP_MID_CHRCVBUF) {
				u32 new_size = *(u32 *)skb->data;

				if (ssk->recv_request || sdp_can_resize()) {
					ssk->rcvbuf_scale = rcvbuf_scale;
					sdp_resize(ssk, ntohs(new_size));
					ssk->recv_request_head = ssk->rx_head + 1;
				} else
					ssk->recv_request_head = ssk->rx_tail;
				ssk->recv_request = 1;
				__kfree_skb(skb);
			} else if (h->mid == SDP_MID_CHRCVBUF_ACK) {
				u32 new_size = *(u32 *)skb->data;
				new_size = ntohs(new_size);

				if (new_size > ssk->xmit_size_goal) {
					ssk->sent_request = -1;
					ssk->xmit_size_goal = new_size;
					ssk->send_frags =
						PAGE_ALIGN(ssk->xmit_size_goal) /
						PAGE_SIZE;
				} else
					ssk->sent_request = 0;
				__kfree_skb(skb);
			} else {
				/* TODO: Handle other messages */
				printk("SDP: FIXME MID %d\n", h->mid);
				__kfree_skb(skb);
			}
		}
	} else {
		skb = sdp_send_completion(ssk, wc->wr_id);
		if (unlikely(!skb))
			return;
		sk_stream_free_skb(&ssk->isk.sk, skb);
		if (unlikely(wc->status)) {
			if (wc->status != IB_WC_WR_FLUSH_ERR) {
				sdp_dbg(&ssk->isk.sk,
						"Send completion with error. "
						"Status %d\n", wc->status);
				sdp_set_error(&ssk->isk.sk, -ECONNRESET);
				wake_up(&ssk->wq);
			}
		}

		sk_stream_write_space(&ssk->isk.sk);
	}

	if (likely(!wc->status)) {
		sdp_post_recvs(ssk);
		sdp_post_sends(ssk, 0);
	}

	if (ssk->time_wait && !ssk->isk.sk.sk_send_head &&
	    ssk->tx_head == ssk->tx_tail) {
		sdp_dbg(&ssk->isk.sk, "%s: destroy in time wait state\n",
			__func__);
		sdp_time_wait_destroy_sk(ssk);
	}
}

void sdp_completion_handler(struct ib_cq *cq, void *cq_context)
{
	struct sock *sk = cq_context;
	struct sdp_sock *ssk = sdp_sk(sk);
	schedule_work(&ssk->work);
}

int sdp_poll_cq(struct sdp_sock *ssk, struct ib_cq *cq)
{
	int n, i;
	int ret = -EAGAIN;
	do {
		n = ib_poll_cq(cq, SDP_NUM_WC, ssk->ibwc);
		for (i = 0; i < n; ++i) {
			sdp_handle_wc(ssk, ssk->ibwc + i);
			ret = 0;
		}
	} while (n == SDP_NUM_WC);
	return ret;
}

void sdp_work(struct work_struct *work)
{
	struct sdp_sock *ssk = container_of(work, struct sdp_sock, work);
	struct sock *sk = &ssk->isk.sk;
	struct ib_cq *cq;

	sdp_dbg_data(sk, "%s\n", __func__);

	lock_sock(sk);
	cq = ssk->cq;
	if (unlikely(!cq))
		goto out;
	sdp_poll_cq(ssk, cq);
	release_sock(sk);
	sk_stream_mem_reclaim(sk);
	lock_sock(sk);
	cq = ssk->cq;
	if (unlikely(!cq))
		goto out;
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	sdp_poll_cq(ssk, cq);
out:
	release_sock(sk);
}
