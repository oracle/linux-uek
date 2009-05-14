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

static int rcvbuf_scale = 0x10;

int rcvbuf_initial_size = 32 * 1024;
module_param_named(rcvbuf_initial_size, rcvbuf_initial_size, int, 0644);
MODULE_PARM_DESC(rcvbuf_initial_size, "Receive buffer initial size in bytes.");

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

static int sdp_get_large_socket(struct sdp_sock *ssk)
{
	int count, ret;

	if (ssk->recv_request)
		return 1;

	spin_lock_irq(&sdp_large_sockets_lock);
	count = curr_large_sockets;
	ret = curr_large_sockets < max_large_sockets;
	if (ret)
		curr_large_sockets++;
	spin_unlock_irq(&sdp_large_sockets_lock);

	return ret;
}

void sdp_remove_large_sock(struct sdp_sock *ssk)
{
	if (ssk->recv_frags) {
		spin_lock_irq(&sdp_large_sockets_lock);
		curr_large_sockets--;
		spin_unlock_irq(&sdp_large_sockets_lock);
	}
}

/* Like tcp_fin - called when SDP_MID_DISCONNECT is received */
static void sdp_fin(struct sock *sk)
{
	sdp_dbg(sk, "%s\n", __func__);

	sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(sk, SOCK_DONE);

	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		sdp_exch_state(sk, TCPF_SYN_RECV | TCPF_ESTABLISHED,
				TCP_CLOSE_WAIT);
		break;

	case TCP_FIN_WAIT1:
		/* Received a reply FIN - start Infiniband tear down */
		sdp_dbg(sk, "%s: Starting Infiniband tear down sending DREQ\n",
				__func__);

		sdp_cancel_dreq_wait_timeout(sdp_sk(sk));

		sdp_exch_state(sk, TCPF_FIN_WAIT1, TCP_TIME_WAIT);

		if (sdp_sk(sk)->id) {
			rdma_disconnect(sdp_sk(sk)->id);
		} else {
			sdp_warn(sk, "%s: sdp_sk(sk)->id is NULL\n", __func__);
			return;
		}
		break;
	case TCP_TIME_WAIT:
		/* This is a mutual close situation and we've got the DREQ from
		   the peer before the SDP_MID_DISCONNECT */
		break;
	case TCP_CLOSE:
		/* FIN arrived after IB teardown started - do nothing */
		sdp_dbg(sk, "%s: fin in state %s\n",
				__func__, sdp_state_str(sk->sk_state));
		return;
	default:
		sdp_warn(sk, "%s: FIN in unexpected state. sk->sk_state=%d\n",
				__func__, sk->sk_state);
		break;
	}


	sk_mem_reclaim(sk);

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

/* lock_sock must be taken before calling this - since rx_ring.head is not 
 * protected (although being atomic
 */
static int sdp_post_recv(struct sdp_sock *ssk)
{
	struct sdp_buf *rx_req;
	int i, rc, frags;
	u64 addr;
	struct ib_device *dev;
	struct ib_recv_wr rx_wr = { 0 };
	struct ib_sge ibsge[SDP_MAX_SEND_SKB_FRAGS + 1];
	struct ib_sge *sge = ibsge;
	struct ib_recv_wr *bad_wr;
	struct sk_buff *skb;
	struct page *page;
	skb_frag_t *frag;
	struct sdp_bsdh *h;
	int id = ring_head(ssk->rx_ring);
	gfp_t gfp_page;
	int ret = 0;

	WARN_ON_UNLOCKED(&ssk->isk.sk, &ssk->rx_ring.lock);
	/* Now, allocate and repost recv */
	/* TODO: allocate from cache */

	if (unlikely(ssk->isk.sk.sk_allocation)) {
		skb = sdp_stream_alloc_skb(&ssk->isk.sk, SDP_HEAD_SIZE,
					  ssk->isk.sk.sk_allocation);
		gfp_page = ssk->isk.sk.sk_allocation | __GFP_HIGHMEM;
	} else {
		skb = sdp_stream_alloc_skb(&ssk->isk.sk, SDP_HEAD_SIZE,
					  GFP_KERNEL);
		gfp_page = GFP_HIGHUSER;
	}

	/* FIXME */
	BUG_ON(!skb);
	h = (struct sdp_bsdh *)skb->head;
	for (i = 0; i < ssk->recv_frags; ++i) {
		page = alloc_pages(gfp_page, 0);
		BUG_ON(!page);
		frag = &skb_shinfo(skb)->frags[i];
		frag->page                = page;
		frag->page_offset         = 0;
		frag->size                =  min(PAGE_SIZE, SDP_MAX_PAYLOAD);
		++skb_shinfo(skb)->nr_frags;
		skb->len += frag->size;
		skb->data_len += frag->size;
		skb->truesize += frag->size;
	}

        rx_req = ssk->rx_ring.buffer + (id & (SDP_RX_SIZE - 1));
	rx_req->skb = skb;
	dev = ssk->ib_device;
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

	rx_wr.next = NULL;
	rx_wr.wr_id = id | SDP_OP_RECV;
	rx_wr.sg_list = ibsge;
	rx_wr.num_sge = frags + 1;
	rc = ib_post_recv(ssk->qp, &rx_wr, &bad_wr);
	SDPSTATS_COUNTER_INC(post_recv);
	atomic_inc(&ssk->rx_ring.head);
	if (unlikely(rc)) {
		sdp_warn(&ssk->isk.sk, "ib_post_recv failed with status %d\n", rc);
		sdp_reset(&ssk->isk.sk);
		ret = -1;
	}

	atomic_add(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);

	return ret;
}

/* lock_sock must be taken before calling this */
static void _sdp_post_recvs(struct sdp_sock *ssk)
{
	struct sock *sk = &ssk->isk.sk;
	int scale = ssk->rcvbuf_scale;

	WARN_ON_UNLOCKED(&ssk->isk.sk, &ssk->rx_ring.lock);

	if (unlikely(!ssk->id || ((1 << sk->sk_state) & 
		(TCPF_CLOSE | TCPF_TIME_WAIT)))) {
		return;
	}

	if (top_mem_usage &&
	    (top_mem_usage * 0x100000) < atomic_read(&sdp_current_mem_usage) * PAGE_SIZE)
		scale = 1;

	while ((likely(ring_posted(ssk->rx_ring) < SDP_RX_SIZE) &&
		(ring_posted(ssk->rx_ring) - SDP_MIN_TX_CREDITS) *
		(SDP_HEAD_SIZE + ssk->recv_frags * PAGE_SIZE) +
		ssk->rcv_nxt - ssk->copied_seq < sk->sk_rcvbuf * scale) ||
	       unlikely(ring_posted(ssk->rx_ring) < SDP_MIN_TX_CREDITS)) {
		if (sdp_post_recv(ssk))
			break;
	}
}

void sdp_post_recvs(struct sdp_sock *ssk)
{
	unsigned long flags;

	rx_ring_lock(ssk, flags);
	_sdp_post_recvs(ssk);
	rx_ring_unlock(ssk, flags);
}

static inline struct sk_buff *sdp_sock_queue_rcv_skb(struct sock *sk,
						     struct sk_buff *skb)
{
	int skb_len;
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sk_buff *tail = NULL;

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

int sdp_init_buffers(struct sdp_sock *ssk, u32 new_size)
{
	ssk->recv_frags = PAGE_ALIGN(new_size - SDP_HEAD_SIZE) / PAGE_SIZE;
	if (ssk->recv_frags > SDP_MAX_SEND_SKB_FRAGS)
		ssk->recv_frags = SDP_MAX_SEND_SKB_FRAGS;
	ssk->rcvbuf_scale = rcvbuf_scale;

	sdp_post_recvs(ssk);

	return 0;
}

int sdp_resize_buffers(struct sdp_sock *ssk, u32 new_size)
{
	u32 curr_size = SDP_HEAD_SIZE + ssk->recv_frags * PAGE_SIZE;
#if defined(__ia64__)
	/* for huge PAGE_SIZE systems, aka IA64, limit buffers size
	   [re-]negotiation to a known+working size that will not
	   trigger a HW error/rc to be interpreted as a IB_WC_LOC_LEN_ERR */
	u32 max_size = (SDP_HEAD_SIZE + SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE) <=
		32784 ?
		(SDP_HEAD_SIZE + SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE): 32784;
#else 
	u32 max_size = SDP_HEAD_SIZE + SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE;
#endif

	if (new_size > curr_size && new_size <= max_size &&
	    sdp_get_large_socket(ssk)) {
		ssk->rcvbuf_scale = rcvbuf_scale;
		ssk->recv_frags = PAGE_ALIGN(new_size - SDP_HEAD_SIZE) / PAGE_SIZE;
		if (ssk->recv_frags > SDP_MAX_SEND_SKB_FRAGS)
			ssk->recv_frags = SDP_MAX_SEND_SKB_FRAGS;
		return 0;
	} else
		return -1;
}

static void sdp_handle_resize_request(struct sdp_sock *ssk, struct sdp_chrecvbuf *buf)
{
	if (sdp_resize_buffers(ssk, ntohl(buf->size)) == 0)
		ssk->recv_request_head = ring_head(ssk->rx_ring) + 1;
	else
		ssk->recv_request_head = ring_tail(ssk->rx_ring);
	ssk->recv_request = 1;
}

static void sdp_handle_resize_ack(struct sdp_sock *ssk, struct sdp_chrecvbuf *buf)
{
	u32 new_size = ntohl(buf->size);

	if (new_size > ssk->xmit_size_goal) {
		ssk->sent_request = -1;
		ssk->xmit_size_goal = new_size;
		ssk->send_frags =
			PAGE_ALIGN(ssk->xmit_size_goal) / PAGE_SIZE;
	} else
		ssk->sent_request = 0;
}

static inline int credit_update_needed(struct sdp_sock *ssk)
{
	int c;

	c = remote_credits(ssk);
	if (likely(c > SDP_MIN_TX_CREDITS))
		c += c/2;

	return unlikely(c < ring_posted(ssk->rx_ring)) &&
	    likely(tx_credits(ssk) > 1) &&
	    likely(sdp_tx_ring_slots_left(&ssk->tx_ring));
}


static struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id)
{
	struct sdp_buf *rx_req;
	struct ib_device *dev;
	struct sk_buff *skb;
	int i, frags;

	WARN_ON_UNLOCKED(&ssk->isk.sk, &ssk->rx_ring.lock);

	if (unlikely(id != ring_tail(ssk->rx_ring))) {
		printk(KERN_WARNING "Bogus recv completion id %d tail %d\n",
			id, ring_tail(ssk->rx_ring));
		return NULL;
	}

	dev = ssk->ib_device;
        rx_req = &ssk->rx_ring.buffer[id & (SDP_RX_SIZE - 1)];
	skb = rx_req->skb;
	ib_dma_unmap_single(dev, rx_req->mapping[0], SDP_HEAD_SIZE,
			    DMA_FROM_DEVICE);
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i)
		ib_dma_unmap_page(dev, rx_req->mapping[i + 1],
				  skb_shinfo(skb)->frags[i].size,
				  DMA_FROM_DEVICE);
	atomic_inc(&ssk->rx_ring.tail);
	atomic_dec(&ssk->remote_credits);
	return skb;
}

/* this must be called while sock_lock is taken */
static int sdp_process_rx_skb(struct sdp_sock *ssk, struct sk_buff *skb)
{
	struct sock *sk = &ssk->isk.sk;
	int frags;
	struct sdp_bsdh *h;
	int pagesz, i;

	h = (struct sdp_bsdh *)skb->data;

	frags = skb_shinfo(skb)->nr_frags;
	pagesz = PAGE_ALIGN(skb->data_len);
	skb_shinfo(skb)->nr_frags = pagesz / PAGE_SIZE;

	for (i = skb_shinfo(skb)->nr_frags;
			i < frags; ++i) {
		put_page(skb_shinfo(skb)->frags[i].page);
		skb->truesize -= PAGE_SIZE;
	}

	if (unlikely(h->flags & SDP_OOB_PEND))
		sk_send_sigurg(sk);

	skb_pull(skb, sizeof(struct sdp_bsdh));

	switch (h->mid) {
	case SDP_MID_DATA:
		if (unlikely(skb->len <= 0)) {
			__kfree_skb(skb);
			break;
		}

		if (unlikely(sk->sk_shutdown & RCV_SHUTDOWN)) {
			/* got data in RCV_SHUTDOWN */
			if (sk->sk_state == TCP_FIN_WAIT1) {
				/* go into abortive close */
				sdp_exch_state(sk, TCPF_FIN_WAIT1,
					       TCP_TIME_WAIT);

				sk->sk_prot->disconnect(sk, 0);
			}

			__kfree_skb(skb);
			break;
		}
		skb = sdp_sock_queue_rcv_skb(sk, skb);
		if (unlikely(h->flags & SDP_OOB_PRES))
			sdp_urg(ssk, skb);
		break;
	case SDP_MID_DISCONN:
		__kfree_skb(skb);
		sdp_fin(sk);
		break;
	case SDP_MID_CHRCVBUF:
		sdp_handle_resize_request(ssk,
			(struct sdp_chrecvbuf *)skb->data);
		__kfree_skb(skb);
		break;
	case SDP_MID_CHRCVBUF_ACK:
		sdp_handle_resize_ack(ssk, (struct sdp_chrecvbuf *)skb->data);
		__kfree_skb(skb);
		break;
	default:
		/* TODO: Handle other messages */
		printk(KERN_WARNING "SDP: FIXME MID %d\n", h->mid);
		__kfree_skb(skb);
	}

	return 0;
}

/* called only from irq */
static struct sk_buff *sdp_process_rx_wc(struct sdp_sock *ssk, struct ib_wc *wc)
{
	struct sk_buff *skb;
	struct sdp_bsdh *h;
	struct sock *sk = &ssk->isk.sk;
	int credits_before;
	unsigned long mseq_ack;
	
	skb = sdp_recv_completion(ssk, wc->wr_id);
	if (unlikely(!skb))
		return NULL;

	atomic_sub(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);

	if (unlikely(wc->status)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			sdp_warn(sk, "Recv completion with error. Status %d\n",
				wc->status);
			sdp_reset(sk);
		}
		__kfree_skb(skb);
		return NULL;
	}

	sdp_dbg_data(sk, "Recv completion. ID %d Length %d\n",
			(int)wc->wr_id, wc->byte_len);
	if (unlikely(wc->byte_len < sizeof(struct sdp_bsdh))) {
		printk(KERN_WARNING "SDP BUG! byte_len %d < %zd\n",
				wc->byte_len, sizeof(struct sdp_bsdh));
		__kfree_skb(skb);
		return NULL;
	}
	skb->len = wc->byte_len;
	if (likely(wc->byte_len > SDP_HEAD_SIZE))
		skb->data_len = wc->byte_len - SDP_HEAD_SIZE;
	else
		skb->data_len = 0;
	skb->data = skb->head;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->tail = skb_headlen(skb);
#else
	skb->tail = skb->head + skb_headlen(skb);
#endif
	h = (struct sdp_bsdh *)skb->data;
	SDP_DUMP_PACKET(&ssk->isk.sk, "RX", skb, h);
	skb_reset_transport_header(skb);
	atomic_set(&ssk->mseq_ack, ntohl(h->mseq));
	if (mseq_ack(ssk) != (int)wc->wr_id)
		printk(KERN_WARNING "SDP BUG! mseq %d != wrid %d\n",
				mseq_ack(ssk), (int)wc->wr_id);

	SDPSTATS_HIST_LINEAR(credits_before_update, tx_credits(ssk));

	mseq_ack = ntohl(h->mseq_ack);
	credits_before = tx_credits(ssk);
	atomic_set(&ssk->tx_ring.credits, mseq_ack - ring_head(ssk->tx_ring) + 1 +
		ntohs(h->bufs));
	if (mseq_ack >= ssk->nagle_last_unacked)
		ssk->nagle_last_unacked = 0;

	sdp_prf(&ssk->isk.sk, skb, "RX %s bufs=%d c before:%d after:%d "
		"mseq:%d, ack:%d", mid2str(h->mid), ntohs(h->bufs), credits_before, 
		tx_credits(ssk), ntohl(h->mseq), ntohl(h->mseq_ack));

	return skb;
}

/* like sk_stream_write_space - execpt measures remote credits */
static void sdp_bzcopy_write_space(struct sdp_sock *ssk)
{
	struct sock *sk = &ssk->isk.sk;
	struct socket *sock = sk->sk_socket;

	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep)) {
		sdp_prf(&ssk->isk.sk, NULL, "credits: %d, min_bufs: %d. tx_head: %d, tx_tail: %d",
				tx_credits(ssk), ssk->min_bufs,
				ring_head(ssk->tx_ring), ring_tail(ssk->tx_ring));
	}

	if (tx_credits(ssk) >= ssk->min_bufs &&
	    ring_head(ssk->tx_ring) == ring_tail(ssk->tx_ring) &&
	   sock != NULL) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
			wake_up_interruptible(sk->sk_sleep);
		if (sock->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(sock, 2, POLL_OUT);
	}
}

/* only from interrupt.
 * drain rx cq into rx_backlog queue */
static int sdp_poll_rx_cq(struct sdp_sock *ssk)
{
	struct ib_cq *cq = ssk->rx_ring.cq;
	struct ib_wc ibwc[SDP_NUM_WC];
	int n, i;
	int wc_processed = 0;
	struct sk_buff *skb;

	WARN_ON_UNLOCKED(&ssk->isk.sk, &ssk->rx_ring.lock);

	do {
		n = ib_poll_cq(cq, SDP_NUM_WC, ibwc);
		for (i = 0; i < n; ++i) {
			struct ib_wc *wc = &ibwc[i];

			BUG_ON(!(wc->wr_id & SDP_OP_RECV));
			skb = sdp_process_rx_wc(ssk, wc);
			if (!skb)
				continue;
			skb_queue_tail(&ssk->rx_backlog, skb);
			wc_processed++;
		}
	} while (n == SDP_NUM_WC);

	if (wc_processed)
		sdp_bzcopy_write_space(ssk);

	return wc_processed;
}

int sdp_process_rx_q(struct sdp_sock *ssk)
{
	struct sk_buff *skb;
	struct sock *sk = &ssk->isk.sk;
	unsigned long flags;

	if (!ssk->rx_backlog.next || !ssk->rx_backlog.prev) {
		sdp_warn(&ssk->isk.sk, "polling a zeroed rx_backlog!!!! %p\n", &ssk->rx_backlog);
		return 0;
	}

	if (skb_queue_empty(&ssk->rx_backlog)) {
		SDPSTATS_COUNTER_INC(rx_poll_miss);
		return -EAGAIN;
	}

	/* update credits */
	sdp_post_sends(ssk, 0);

	spin_lock_irqsave(&ssk->rx_backlog.lock, flags);
	while ((skb = __skb_dequeue(&ssk->rx_backlog))) {
		sdp_process_rx_skb(ssk, skb);
	}
	spin_unlock_irqrestore(&ssk->rx_backlog.lock, flags);

	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		sk_stream_write_space(&ssk->isk.sk);

	return 0;
}

static void sdp_rx_comp_work(struct work_struct *work)
{
	struct sdp_sock *ssk = container_of(work, struct sdp_sock, rx_comp_work);
	struct sock *sk = &ssk->isk.sk;
	struct ib_cq *rx_cq;

	lock_sock(sk);
	rx_cq = ssk->rx_ring.cq;
	if (unlikely(!rx_cq))
		goto out;

	if (unlikely(!ssk->poll_cq)) {
		struct rdma_cm_id *id = ssk->id;
		sdp_warn(sk, "poll cq is 0. socket was reset or wasn't initialized\n");
		if (id && id->qp)
			rdma_notify(id, RDMA_CM_EVENT_ESTABLISHED);
		goto out;
	}

	sdp_process_rx_q(ssk);
	sdp_xmit_poll(ssk,  1); /* if has pending tx because run out of tx_credits - xmit it */
	release_sock(sk);
	sk_mem_reclaim(sk);
	lock_sock(sk);
	rx_cq = ssk->rx_ring.cq;
	if (unlikely(!rx_cq))
		goto out;
	
	sdp_process_rx_q(ssk);
	sdp_xmit_poll(ssk,  1);

out:
	release_sock(sk);
}

static void sdp_rx_irq(struct ib_cq *cq, void *cq_context)
{
	struct sock *sk = cq_context;
	struct sdp_sock *ssk = sdp_sk(sk);
	unsigned long flags;
	int wc_processed = 0;

	sdp_dbg_data(&ssk->isk.sk, "rx irq called\n");

	WARN_ON(cq != ssk->rx_ring.cq);

	SDPSTATS_COUNTER_INC(rx_int_count);

	sdp_prf(sk, NULL, "rx irq");

	rx_ring_lock(ssk, flags);

	if (unlikely(!ssk->poll_cq))
		sdp_warn(sk, "poll cq is 0. socket was reset or wasn't initialized\n");

	if (!ssk->rx_ring.cq) {
		sdp_warn(&ssk->isk.sk, "WARNING: rx irq after cq destroyed\n");

		goto out;
	}

	wc_processed = sdp_poll_rx_cq(ssk);
	sdp_prf(&ssk->isk.sk, NULL, "processed %d", wc_processed);

	if (wc_processed) {
		_sdp_post_recvs(ssk);

		/* Best was to send credit update from here */
/*		sdp_post_credits(ssk); */

		/* issue sdp_rx_comp_work() */
		queue_work(rx_comp_wq, &ssk->rx_comp_work);
	}

	sdp_arm_rx_cq(sk);

out:
	rx_ring_unlock(ssk, flags);
}

static void sdp_rx_ring_purge(struct sdp_sock *ssk)
{
	WARN_ON_UNLOCKED(&ssk->isk.sk, &ssk->rx_ring.lock);

	while (ring_posted(ssk->rx_ring) > 0) {
		struct sk_buff *skb;
		skb = sdp_recv_completion(ssk, ring_tail(ssk->rx_ring));
		if (!skb)
			break;
		atomic_sub(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);
		__kfree_skb(skb);
	}
}

void sdp_rx_ring_init(struct sdp_sock *ssk)
{
	ssk->rx_ring.buffer = NULL;
	spin_lock_init(&ssk->rx_ring.lock);
}

static void sdp_rx_cq_event_handler(struct ib_event *event, void *data)
{
}

int sdp_rx_ring_create(struct sdp_sock *ssk, struct ib_device *device)
{
	struct ib_cq *rx_cq;
	int rc = 0;
	unsigned long flags;

	rx_ring_lock(ssk, flags);

	atomic_set(&ssk->rx_ring.head, 1);
	atomic_set(&ssk->rx_ring.tail, 1);

	ssk->rx_ring.buffer = kmalloc(sizeof *ssk->rx_ring.buffer * SDP_RX_SIZE,
				      GFP_KERNEL);
	if (!ssk->rx_ring.buffer) {
		rc = -ENOMEM;
		sdp_warn(&ssk->isk.sk, "Unable to allocate RX Ring size %zd.\n",
			 sizeof(*ssk->rx_ring.buffer) * SDP_RX_SIZE);

		goto out;
	}

	rx_cq = ib_create_cq(device, sdp_rx_irq, sdp_rx_cq_event_handler,
			  &ssk->isk.sk, SDP_RX_SIZE, 0);

	if (IS_ERR(rx_cq)) {
		rc = PTR_ERR(rx_cq);
		sdp_warn(&ssk->isk.sk, "Unable to allocate RX CQ: %d.\n", rc);
		goto err_cq;
	}

	rc = ib_modify_cq(rx_cq, 10, 200);
	if (rc) {
		sdp_warn(&ssk->isk.sk, "Unable to modify RX CQ: %d.\n", rc);
		goto err_mod;
	}
	sdp_warn(&ssk->isk.sk, "Initialized CQ moderation\n");
	sdp_sk(&ssk->isk.sk)->rx_ring.cq = rx_cq;

	INIT_WORK(&ssk->rx_comp_work, sdp_rx_comp_work);

	sdp_arm_rx_cq(&ssk->isk.sk);

	goto out;

err_mod:
	ib_destroy_cq(rx_cq);
err_cq:
	kfree(ssk->rx_ring.buffer);
	ssk->rx_ring.buffer = NULL;
out:
	rx_ring_unlock(ssk, flags);
	return rc;
}

void sdp_rx_ring_destroy(struct sdp_sock *ssk)
{
	WARN_ON_UNLOCKED(&ssk->isk.sk, &ssk->rx_ring.lock);

	if (ssk->rx_ring.buffer) {
		sdp_rx_ring_purge(ssk);

		kfree(ssk->rx_ring.buffer);
		ssk->rx_ring.buffer = NULL;
	}

	if (ssk->rx_ring.cq) {
		ib_destroy_cq(ssk->rx_ring.cq);
		ssk->rx_ring.cq = NULL;
	}

	WARN_ON(ring_head(ssk->rx_ring) != ring_tail(ssk->rx_ring));
}
