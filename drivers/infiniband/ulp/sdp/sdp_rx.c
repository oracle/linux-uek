/*
 * Copyright (c) 2009 Mellanox Technologies Ltd.  All rights reserved.
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
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/rcupdate.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include "sdp.h"

SDP_MODPARAM_INT(rcvbuf_initial_size, 32 * 1024,
		"Receive buffer initial size in bytes.");

#ifdef CONFIG_PPC
SDP_MODPARAM_SINT(max_large_sockets, 100,
		"Max number of large sockets (32k buffers).");
#else
SDP_MODPARAM_SINT(max_large_sockets, 1000,
		"Max number of large sockets (32k buffers).");
#endif

static int curr_large_sockets;
spinlock_t sdp_large_sockets_lock;

static int sdp_get_large_socket(const struct sdp_sock *ssk)
{
	int ret;

	if (ssk->recv_request)
		return 1;

	spin_lock_irq(&sdp_large_sockets_lock);
	ret = curr_large_sockets < max_large_sockets;
	if (ret)
		curr_large_sockets++;
	spin_unlock_irq(&sdp_large_sockets_lock);

	return ret;
}

void sdp_remove_large_sock(const struct sdp_sock *ssk)
{
	if (ssk->recv_frags) {
		spin_lock_irq(&sdp_large_sockets_lock);
		curr_large_sockets--;
		spin_unlock_irq(&sdp_large_sockets_lock);
	}
}

/* Like tcp_fin - called when SDP_MID_DISCONNECT is received */
void sdp_handle_disconn(struct sock *sk)
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
			sdp_sk(sk)->qp_active = 0;
			rdma_disconnect(sdp_sk(sk)->id);
		} else {
			/* possible in a case of device removal */
			sdp_dbg(sk, "sdp_sk(sk)->id is NULL\n");
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
		sdp_warn(sk, "%s: FIN in unexpected state. sk->sk_state=%s\n",
				__func__, sdp_state_str(sk->sk_state));
		break;
	}

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

static void sdp_sock_rfree(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;

        atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
        sk_mem_uncharge(sk, skb->truesize);
}

static int sdp_post_recv(struct sdp_sock *ssk)
{
	struct sock *sk = sk_ssk(ssk);
	struct sdp_buf *rx_req;
	int i, frags;
	int rc = 0;
	u64 addr;
	struct ib_device *dev;
	struct ib_recv_wr rx_wr = { NULL };
	struct ib_sge ibsge[SDP_MAX_RECV_SGES];
	struct ib_sge *sge = ibsge;
	struct ib_recv_wr *bad_wr;
	struct sk_buff *skb;
	struct page *page;
	skb_frag_t *frag;
	struct sdp_bsdh *h;
	int id = ring_head(ssk->rx_ring);
	gfp_t gfp_page;
	int pages_alloced = 0;

	/* Now, allocate and repost recv */
	/* TODO: allocate from cache */

	if (unlikely(sk_ssk(ssk)->sk_allocation)) {
		skb = sdp_stream_alloc_skb(sk_ssk(ssk), SDP_SKB_HEAD_SIZE,
					  sk_ssk(ssk)->sk_allocation, SK_MEM_RECV);
		gfp_page = sk_ssk(ssk)->sk_allocation | __GFP_HIGHMEM;
	} else {
		skb = sdp_stream_alloc_skb(sk_ssk(ssk), SDP_SKB_HEAD_SIZE,
					  GFP_KERNEL, SK_MEM_RECV);
		gfp_page = GFP_HIGHUSER;
	}

	if (unlikely(!skb))
		return -1;

	sdp_prf(sk_ssk(ssk), skb, "Posting skb");
	h = (struct sdp_bsdh *)skb->head;

	rx_req = ssk->rx_ring.buffer + (id & (sdp_rx_size - 1));
	rx_req->skb = skb;

	for (i = 0; i < ssk->recv_frags; ++i) {
		if (rx_req->mapping[i + 1])
			page = rx_req->pages[i];
		else {
			rx_req->pages[i] = page = alloc_pages(gfp_page, 0);
			if (unlikely(!page))
				goto err;
			pages_alloced++;
		}
		frag = &skb_shinfo(skb)->frags[i];
		frag->page.p              = page;
		frag->page_offset         = 0;
		frag->size                = min(PAGE_SIZE, SDP_MAX_PAYLOAD);
		++skb_shinfo(skb)->nr_frags;
	}
	skb->truesize += ssk->recv_frags * min(PAGE_SIZE, SDP_MAX_PAYLOAD);
	if (!sk_rmem_schedule(sk, skb, ssk->recv_frags * min(PAGE_SIZE,
		SDP_MAX_PAYLOAD))) {
		sdp_dbg(sk, "RX couldn't post, rx posted = %d.",
				rx_ring_posted(sdp_sk(sk)));
		sdp_dbg(sk, "Out of memory\n");
		goto err;
	}

	dev = ssk->ib_device;
	addr = ib_dma_map_single(dev, h, SDP_SKB_HEAD_SIZE, DMA_FROM_DEVICE);
	BUG_ON(ib_dma_mapping_error(dev, addr));

	rx_req->mapping[0] = addr;

	/* TODO: proper error handling */
	sge->addr = (u64)addr;
	sge->length = SDP_SKB_HEAD_SIZE;
	sge->lkey = ssk->sdp_dev->mr->lkey;
	frags = skb_shinfo(skb)->nr_frags;
	for (i = 0; i < frags; ++i) {
		++sge;
		if (rx_req->mapping[i + 1]) {
			addr = rx_req->mapping[i + 1];
		} else {
			addr = ib_dma_map_page(dev,
					skb_shinfo(skb)->frags[i].page.p,
					skb_shinfo(skb)->frags[i].page_offset,
					skb_shinfo(skb)->frags[i].size,
					DMA_FROM_DEVICE);
			BUG_ON(ib_dma_mapping_error(dev, addr));
			rx_req->mapping[i + 1] = addr;
		}
		sge->addr = addr;
		sge->length = skb_shinfo(skb)->frags[i].size;
		sge->lkey = ssk->sdp_dev->mr->lkey;
	}

	rx_wr.next = NULL;
	rx_wr.wr_id = id | SDP_OP_RECV;
	rx_wr.sg_list = ibsge;
	rx_wr.num_sge = frags + 1;
	rc = ib_post_recv(ssk->qp, &rx_wr, &bad_wr);
	if (unlikely(rc)) {
		sdp_warn(sk_ssk(ssk), "ib_post_recv failed. status %d\n", rc);
		goto err;
	}

	skb_set_owner_r(skb, sk_ssk(ssk));
	skb->destructor=sdp_sock_rfree;

	atomic_inc(&ssk->rx_ring.head);
	SDPSTATS_COUNTER_INC(post_recv);

	return 0;

err:
	sdp_cleanup_sdp_buf(ssk, rx_req, SDP_SKB_HEAD_SIZE, DMA_FROM_DEVICE);
	__kfree_skb(skb);

	if (rc)
		sdp_reset(sk_ssk(ssk));
	return -1;
}

static inline int sdp_post_recvs_needed(struct sdp_sock *ssk)
{
	struct sock *sk = sk_ssk(ssk);
	int buffer_size = ssk->recv_frags * PAGE_SIZE;
	int posted = rx_ring_posted(ssk);

	if (unlikely(!ssk->qp_active))
		return 0;

	if  (likely(posted >= sdp_rx_size))
		return 0;

	if (unlikely(posted < SDP_MIN_TX_CREDITS))
		return 1;

	if (rcv_nxt(ssk) - ssk->copied_seq + (posted - SDP_MIN_TX_CREDITS) *
			buffer_size >= sk->sk_rcvbuf) {
		return 0;
	}

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_prot->sysctl_rmem[2])
		return 0;

	return 1;
}

static inline void sdp_post_recvs(struct sdp_sock *ssk)
{
again:
	while (sdp_post_recvs_needed(ssk)) {
		if (sdp_post_recv(ssk))
			return;
	}

	if (sdp_post_recvs_needed(ssk))
		goto again;
}

static inline struct sk_buff *sdp_sock_queue_rcv_skb(struct sock *sk,
						     struct sk_buff *skb)
{
	int skb_len;
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sdp_bsdh *h = (struct sdp_bsdh *)skb_transport_header(skb);

	SDP_SKB_CB(skb)->seq = rcv_nxt(ssk);
	if (unlikely(h->flags & SDP_OOB_PRES))
		sdp_urg(ssk, skb);

	if (h->mid == SDP_MID_SRCAVAIL) {
		struct sdp_srcah *srcah = (struct sdp_srcah *)(h+1);
		struct rx_srcavail_state *rx_sa;

		SDP_WARN_ON(ssk->rx_sa);
		ssk->rx_sa = rx_sa = RX_SRCAVAIL_STATE(skb) = kzalloc(
				sizeof(struct rx_srcavail_state), GFP_ATOMIC);
		if (unlikely(!rx_sa)) {
			/* if there is no space, fall to BCopy. */
			sdp_dbg(sk, "Can't allocate memory for rx_sa\n");
			h->mid = SDP_MID_DATA;
			goto mid_data;
		}

		rx_sa->mseq = ntohl(h->mseq);
		rx_sa->len = skb_len = ntohl(srcah->len);
		rx_sa->rkey = ntohl(srcah->rkey);
		rx_sa->vaddr = be64_to_cpu(srcah->vaddr);
		rx_sa->skb = skb;

		if (ssk->tx_sa) {
			sdp_dbg_data(sk_ssk(ssk), "got RX SrcAvail while waiting "
					"for TX SrcAvail. waking up TX SrcAvail"
					"to be aborted\n");
			wake_up(sdp_sk_sleep(sk));
		}

		atomic_add(skb->len, &ssk->rcv_nxt);
		sdp_dbg_data(sk, "queueing SrcAvail. skb_len = %d vaddr = %lld\n",
			skb_len, rx_sa->vaddr);
	} else {
mid_data:
		skb_len = skb->len;

		atomic_add(skb_len, &ssk->rcv_nxt);
	}

	skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb_len);
	return skb;
}

static int sdp_get_recv_sges(struct sdp_sock *ssk, u32 new_size)
{
	int recv_sges = ssk->max_sge - 1; /* 1 sge is dedicated to sdp header */

	recv_sges = MIN(recv_sges, PAGE_ALIGN(new_size) >> PAGE_SHIFT);
	recv_sges = MIN(recv_sges, SDP_MAX_RECV_SGES - 1);

	return recv_sges;
}

int sdp_init_buffers(struct sdp_sock *ssk, u32 new_size)
{
	ssk->recv_frags = sdp_get_recv_sges(ssk, new_size);

	sdp_post_recvs(ssk);

	return 0;
}

int sdp_resize_buffers(struct sdp_sock *ssk, u32 new_size)
{
	u32 curr_size = ssk->recv_frags << PAGE_SHIFT;
	u32 max_size = (ssk->max_sge - 1) << PAGE_SHIFT;

	if (new_size > curr_size && new_size <= max_size &&
	    sdp_get_large_socket(ssk)) {
		ssk->recv_frags = sdp_get_recv_sges(ssk, new_size);
		return 0;
	} else
		return -1;
}

static void sdp_handle_resize_request(struct sdp_sock *ssk,
		struct sdp_chrecvbuf *buf)
{
	if (sdp_resize_buffers(ssk, ntohl(buf->size)) == 0)
		ssk->recv_request_head = ring_head(ssk->rx_ring) + 1;
	else
		ssk->recv_request_head = ring_tail(ssk->rx_ring);
	ssk->recv_request = 1;
}

static void sdp_handle_resize_ack(struct sdp_sock *ssk,
		struct sdp_chrecvbuf *buf)
{
	u32 new_size = ntohl(buf->size);

	if (new_size > ssk->xmit_size_goal) {
		ssk->sent_request = -1;
		ssk->xmit_size_goal = new_size;
		ssk->send_frags =
			PAGE_ALIGN(ssk->xmit_size_goal) / PAGE_SIZE + 1;
	} else
		ssk->sent_request = 0;
}

static void sdp_reuse_sdp_buf(struct sdp_sock *ssk, struct sdp_buf *sbuf, int len)
{
	struct sock *sk = sk_ssk(ssk);
	int i;
	struct sk_buff *skb;
	struct ib_device *dev = ssk->ib_device;
	enum dma_data_direction dir = DMA_FROM_DEVICE;
	int bytes_reused = 0;
	int used;

	skb = sbuf->skb;

	ib_dma_unmap_single(dev, sbuf->mapping[0], SDP_SKB_HEAD_SIZE, dir);
	used = SDP_SKB_HEAD_SIZE;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (used >= len) {
			int count = min(PAGE_SIZE, SDP_MAX_PAYLOAD) *
				(skb_shinfo(skb)->nr_frags - i);
			skb->truesize -= count;

			skb_shinfo(skb)->nr_frags = i;
			bytes_reused += count;
			break;
		}

		ib_dma_unmap_page(dev, sbuf->mapping[i + 1],
				  skb_shinfo(skb)->frags[i].size,
				  dir);
		sbuf->mapping[i + 1] = 0;

		used += skb_shinfo(skb)->frags[i].size;
	}
	atomic_sub(bytes_reused, &sk->sk_rmem_alloc);
	sk_mem_uncharge(sk, bytes_reused);

}

static struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id, int len)
{
	struct sdp_buf *rx_req;
	struct ib_device *dev;
	struct sk_buff *skb;

	if (unlikely(id != ring_tail(ssk->rx_ring))) {
		sdp_warn(sk_ssk(ssk), "Bogus recv completion id %d tail %d\n",
			id, ring_tail(ssk->rx_ring));
		return NULL;
	}

	dev = ssk->ib_device;
	rx_req = &ssk->rx_ring.buffer[id & (sdp_rx_size - 1)];
	skb = rx_req->skb;
	sdp_reuse_sdp_buf(ssk, rx_req, len);

	atomic_inc(&ssk->rx_ring.tail);
	atomic_dec(&ssk->remote_credits);
	return skb;
}

/* socket lock should be taken before calling this */
static int sdp_process_rx_ctl_skb(struct sdp_sock *ssk, struct sk_buff *skb)
{
	struct sdp_bsdh *h = (struct sdp_bsdh *)skb_transport_header(skb);
	struct sock *sk = sk_ssk(ssk);

	sdp_dbg_data(sk, "Handling %s\n", mid2str(h->mid));
	sdp_prf(sk, skb, "Handling %s", mid2str(h->mid));

	switch (h->mid) {
	case SDP_MID_DATA:
	case SDP_MID_SRCAVAIL:
		SDP_WARN_ON(!(sk->sk_shutdown & RCV_SHUTDOWN));

		sdp_dbg(sk, "DATA after socket rcv was shutdown\n");

		/* got data in RCV_SHUTDOWN */
		if (sk->sk_state == TCP_FIN_WAIT1) {
			sdp_dbg(sk, "RX data when state = FIN_WAIT1\n");
			/* go into abortive close */
			sdp_exch_state(sk, TCPF_FIN_WAIT1,
					TCP_TIME_WAIT);

			sk->sk_prot->disconnect(sk, 0);
		}
		break;
	case SDP_MID_RDMARDCOMPL:
		sdp_warn(sk, "Handling RdmaRdCompl - ERROR\n");
		break;
	case SDP_MID_SENDSM:
		sdp_handle_sendsm(ssk, ntohl(h->mseq_ack));
		break;
	case SDP_MID_SRCAVAIL_CANCEL:
		if (ssk->rx_sa && after(ntohl(h->mseq), ssk->rx_sa->mseq) &&
				!ssk->tx_ring.rdma_inflight) {
			sdp_abort_rx_srcavail(sk, 1);
		}
		break;
	case SDP_MID_SINKAVAIL:
	case SDP_MID_ABORT:
		sdp_reset(sk);
		break;
	case SDP_MID_DISCONN:
		sdp_handle_disconn(sk);
		break;
	case SDP_MID_CHRCVBUF:
		sdp_handle_resize_request(ssk, (struct sdp_chrecvbuf *)(h+1));
		break;
	case SDP_MID_CHRCVBUF_ACK:
		sdp_handle_resize_ack(ssk, (struct sdp_chrecvbuf *)(h+1));
		break;
	default:
		/* TODO: Handle other messages */
		sdp_warn(sk, "SDP: FIXME MID %d\n", h->mid);
	}

	__kfree_skb(skb);
	return 0;
}

static int sdp_process_rx_skb(struct sdp_sock *ssk, struct sk_buff *skb)
{
	struct sock *sk = sk_ssk(ssk);
	int frags;
	struct sdp_bsdh *h;
	int pagesz, i;
	unsigned long mseq_ack;
	int credits_before;

	h = (struct sdp_bsdh *)skb_transport_header(skb);

	SDPSTATS_HIST_LINEAR(credits_before_update, tx_credits(ssk));

	mseq_ack = ntohl(h->mseq_ack);
	credits_before = tx_credits(ssk);
	atomic_set(&ssk->tx_ring.credits, mseq_ack - ring_head(ssk->tx_ring) +
			1 + ntohs(h->bufs));
	if (!before(mseq_ack, ssk->nagle_last_unacked))
		ssk->nagle_last_unacked = 0;

	sdp_prf1(sk_ssk(ssk), skb, "RX: %s +%d c:%d->%d mseq:%d ack:%d",
		mid2str(h->mid), ntohs(h->bufs), credits_before,
		tx_credits(ssk), ntohl(h->mseq), ntohl(h->mseq_ack));

	frags = skb_shinfo(skb)->nr_frags;
	pagesz = PAGE_ALIGN(skb->data_len);
	skb_shinfo(skb)->nr_frags = pagesz / PAGE_SIZE;

	for (i = skb_shinfo(skb)->nr_frags; i < frags; ++i) {
		put_page(skb_shinfo(skb)->frags[i].page.p);
	}

	if (unlikely(h->flags & SDP_OOB_PEND))
		sk_send_sigurg(sk);

	skb_pull(skb, sizeof(struct sdp_bsdh));

	if (unlikely(h->mid == SDP_MID_SRCAVAIL)) {
		if (ssk->rx_sa) {
			sdp_dbg_data(sk, "SrcAvail in the middle of another SrcAvail. Aborting\n");
			h->mid = SDP_MID_DATA;
			sdp_post_sendsm(sk);
			sdp_do_posts(ssk);
		} else {
			skb_pull(skb, sizeof(struct sdp_srcah));
		}
	}

	if (unlikely(h->mid == SDP_MID_DATA && skb->len == 0)) {
		/* Credit update is valid even after RCV_SHUTDOWN */
		__kfree_skb(skb);
		return 0;
	}

	if ((h->mid != SDP_MID_DATA && h->mid != SDP_MID_SRCAVAIL &&
				h->mid != SDP_MID_DISCONN) ||
			unlikely(sk->sk_shutdown & RCV_SHUTDOWN)) {
		sdp_prf(sk, NULL, "Control skb - queing to control queue");
		if (h->mid == SDP_MID_SRCAVAIL_CANCEL) {
			sdp_dbg_data(sk, "Got SrcAvailCancel. "
					"seq: 0x%d seq_ack: 0x%d\n",
					ntohl(h->mseq), ntohl(h->mseq_ack));
			ssk->sa_cancel_mseq = ntohl(h->mseq);
			ssk->sa_cancel_arrived = 1;
			if (ssk->rx_sa)
				wake_up(sdp_sk_sleep(sk));

			skb_queue_tail(&ssk->rx_ctl_q, skb);
		} else if (h->mid == SDP_MID_RDMARDCOMPL) {
			struct sdp_rrch *rrch = (struct sdp_rrch *)(h+1);
			sdp_dbg_data(sk, "RdmaRdCompl message arrived\n");
			sdp_handle_rdma_read_compl(ssk, ntohl(h->mseq_ack),
					ntohl(rrch->len));
			__kfree_skb(skb);
		} else
			skb_queue_tail(&ssk->rx_ctl_q, skb);

		return 0;
	}

	sdp_prf(sk, NULL, "queueing %s skb", mid2str(h->mid));
	sdp_sock_queue_rcv_skb(sk, skb);

	return 0;
}

static struct sk_buff *sdp_process_rx_wc(struct sdp_sock *ssk,
		struct ib_wc *wc)
{
	struct sk_buff *skb;
	struct sdp_bsdh *h;
	struct sock *sk = sk_ssk(ssk);
	int mseq;

	skb = sdp_recv_completion(ssk, wc->wr_id, wc->byte_len);
	if (unlikely(!skb))
		return NULL;

	if (unlikely(wc->status)) {
		if (ssk->qp_active) {
			sdp_dbg(sk, "Recv completion with error. "
					"Status %d, vendor: %d\n",
				wc->status, wc->vendor_err);
			sdp_reset(sk);
			ssk->qp_active = 0;
		}
		__kfree_skb(skb);
		return NULL;
	}

	sdp_dbg_data(sk, "Recv completion. ID %d Length %d\n",
			(int)wc->wr_id, wc->byte_len);
	if (unlikely(wc->byte_len < sizeof(struct sdp_bsdh))) {
		sdp_warn(sk, "SDP BUG! byte_len %d < %zd\n",
				wc->byte_len, sizeof(struct sdp_bsdh));
		__kfree_skb(skb);
		return NULL;
	}
	skb->len = wc->byte_len;
	skb->data = skb->head;

	h = (struct sdp_bsdh *)skb->data;

	if (likely(wc->byte_len > SDP_SKB_HEAD_SIZE))
		skb->data_len = wc->byte_len - SDP_SKB_HEAD_SIZE;
	else
		skb->data_len = 0;

#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->tail = skb_headlen(skb);
#else
	skb->tail = skb->head + skb_headlen(skb);
#endif
	SDP_DUMP_PACKET(sk_ssk(ssk), "RX", skb, h);
	skb_reset_transport_header(skb);

	ssk->rx_packets++;
	ssk->rx_bytes += skb->len;

	mseq = ntohl(h->mseq);
	atomic_set(&ssk->mseq_ack, mseq);
	if (unlikely(mseq != (int)wc->wr_id))
		sdp_warn(sk, "SDP BUG! mseq %d != wrid %d\n",
				mseq, (int)wc->wr_id);

	return skb;
}

/* like sk_stream_write_space - execpt measures remote credits */
static void sdp_bzcopy_write_space(struct sdp_sock *ssk)
{
	struct sock *sk = sk_ssk(ssk);
	struct socket *sock = sk->sk_socket;
	struct socket_wq *wq;

	if (tx_credits(ssk) < ssk->min_bufs || !sock)
		return;

	clear_bit(SOCK_NOSPACE, &sock->flags);
	sdp_prf1(sk, NULL, "Waking up sleepers");

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible(&wq->wait);
	if (wq && wq->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
		sock_wake_async(sock, 2, POLL_OUT);
	rcu_read_unlock();
}

int sdp_poll_rx_cq(struct sdp_sock *ssk)
{
	struct ib_cq *cq = ssk->rx_ring.cq;
	struct ib_wc ibwc[SDP_NUM_WC];
	int n, i;
	int wc_processed = 0;
	struct sk_buff *skb;

	do {
		n = ib_poll_cq(cq, SDP_NUM_WC, ibwc);
		for (i = 0; i < n; ++i) {
			struct ib_wc *wc = &ibwc[i];

			BUG_ON(!(wc->wr_id & SDP_OP_RECV));
			skb = sdp_process_rx_wc(ssk, wc);
			if (!skb)
				continue;

			sdp_process_rx_skb(ssk, skb);
			wc_processed++;
		}
	} while (n == SDP_NUM_WC);

	if (wc_processed) {
		sdp_prf(sk_ssk(ssk), NULL, "processed %d", wc_processed);

		sk_mem_reclaim(sk_ssk(ssk));

		sdp_bzcopy_write_space(ssk);
	}

	return wc_processed;
}

static void sdp_rx_comp_work(struct work_struct *work)
{
	struct sdp_sock *ssk = container_of(work, struct sdp_sock,
			rx_comp_work);
	struct sock *sk = sk_ssk(ssk);

	SDPSTATS_COUNTER_INC(rx_wq);

	sdp_prf(sk, NULL, "%s", __func__);

	if (unlikely(!ssk->qp)) {
		sdp_prf(sk, NULL, "qp was destroyed");
		return;
	}
	if (unlikely(!ssk->rx_ring.cq)) {
		sdp_prf(sk, NULL, "rx_ring.cq is NULL");
		return;
	}

	if (unlikely(!ssk->poll_cq)) {
		struct rdma_cm_id *id = ssk->id;
		if (id && id->qp)
			rdma_notify(id, RDMA_CM_EVENT_ESTABLISHED);
		return;
	}

	lock_sock(sk);

	posts_handler_get(ssk);
	sdp_do_posts(ssk);
	posts_handler_put(ssk, SDP_RX_ARMING_DELAY);
	release_sock(sk);
}

void sdp_do_posts(struct sdp_sock *ssk)
{
	struct sock *sk = sk_ssk(ssk);
	int xmit_poll_force;
	struct sk_buff *skb;

	if (!ssk->qp_active) {
		sdp_dbg(sk, "QP is deactivated\n");
		return;
	}

	if (likely(ssk->rx_ring.cq))
		sdp_poll_rx_cq(ssk);

	while ((skb = skb_dequeue(&ssk->rx_ctl_q)))
		sdp_process_rx_ctl_skb(ssk, skb);

	if (sk->sk_state == TCP_TIME_WAIT)
		return;

	if (!ssk->rx_ring.cq || !ssk->tx_ring.cq)
		return;

	sdp_post_recvs(ssk);

	if (tx_ring_posted(ssk))
		sdp_xmit_poll(ssk, 1);

	sdp_post_sends(ssk, 0);

	xmit_poll_force = sk->sk_write_pending &&
		(tx_credits(ssk) > SDP_MIN_TX_CREDITS);

	if (credit_update_needed(ssk) || xmit_poll_force) {
		/* if has pending tx because run out of tx_credits - xmit it */
		sdp_prf(sk, NULL, "Processing to free pending sends");
		sdp_xmit_poll(ssk,  xmit_poll_force);
		sdp_prf(sk, NULL, "Sending credit update");
		sdp_post_sends(ssk, 0);
	}

}

static inline int should_wake_up(struct sock *sk)
{
	return sdp_sk_sleep(sk) && waitqueue_active(sdp_sk_sleep(sk)) &&
		(posts_handler(sdp_sk(sk)) || somebody_is_waiting(sk));
}

static void sdp_rx_irq(struct ib_cq *cq, void *cq_context)
{
	struct sock *sk = cq_context;
	struct sdp_sock *ssk = sdp_sk(sk);

	if (unlikely(cq != ssk->rx_ring.cq)) {
		sdp_warn(sk, "cq = %p, ssk->cq = %p\n", cq, ssk->rx_ring.cq);
		return;
	}

	SDPSTATS_COUNTER_INC(rx_int_count);

	sdp_prf(sk, NULL, "rx irq");

	if (should_wake_up(sk)) {
		wake_up_interruptible(sdp_sk_sleep(sk));
		SDPSTATS_COUNTER_INC(rx_int_wake_up);
	} else {
		if (queue_work_on(ssk->cpu, rx_comp_wq, &ssk->rx_comp_work))
			SDPSTATS_COUNTER_INC(rx_int_queue);
		else
			SDPSTATS_COUNTER_INC(rx_int_no_op);
	}
}

static void sdp_rx_ring_purge(struct sdp_sock *ssk)
{
	struct ib_device *dev = ssk->ib_device;
	int id, i;

	while (rx_ring_posted(ssk) > 0) {
		struct sk_buff *skb;
		skb = sdp_recv_completion(ssk, ring_tail(ssk->rx_ring), INT_MAX);
		if (!skb)
			break;
		__kfree_skb(skb);
	}

	for (id = 0; id < sdp_rx_size; id++) {
		struct sdp_buf *sbuf = &ssk->rx_ring.buffer[id];

		for (i = 1; i < SDP_MAX_SEND_SGES; i++) {
			if (!sbuf->mapping[i])
				continue;

			ib_dma_unmap_page(dev, sbuf->mapping[i],
					min(PAGE_SIZE, SDP_MAX_PAYLOAD),
					DMA_FROM_DEVICE);
			sbuf->mapping[i] = 0;
			put_page(sbuf->pages[i - 1]);
		}
	}
}

static void sdp_rx_cq_event_handler(struct ib_event *event, void *data)
{
}

static void sdp_arm_cq_timer(unsigned long data)
{
  	struct sdp_sock *ssk = (struct sdp_sock *)data;

	SDPSTATS_COUNTER_INC(rx_cq_arm_timer);
	sdp_arm_rx_cq(sk_ssk(ssk));
}

int sdp_rx_ring_create(struct sdp_sock *ssk, struct ib_device *device)
{
	struct ib_cq *rx_cq;
	int rc = 0, vector = 0;

	atomic_set(&ssk->rx_ring.head, 1);
	atomic_set(&ssk->rx_ring.tail, 1);

	ssk->rx_ring.buffer = kzalloc(
			sizeof *ssk->rx_ring.buffer * sdp_rx_size, GFP_KERNEL);
	if (!ssk->rx_ring.buffer) {
		sdp_warn(sk_ssk(ssk),
			"Unable to allocate RX Ring size %zd.\n",
			 sizeof(*ssk->rx_ring.buffer) * sdp_rx_size);

		return -ENOMEM;
	}

	vector = sdp_get_vector_num(device);

	rx_cq = ib_create_cq(device, sdp_rx_irq, sdp_rx_cq_event_handler,
			  sk_ssk(ssk), sdp_rx_size, vector);

	if (IS_ERR(rx_cq)) {
		rc = PTR_ERR(rx_cq);
		sdp_warn(sk_ssk(ssk), "Unable to allocate RX CQ: %d.\n", rc);
		goto err_cq;
	}

	ssk->rx_ring.cq = rx_cq;

	INIT_WORK(&ssk->rx_comp_work, sdp_rx_comp_work);
	setup_timer(&ssk->rx_ring.cq_arm_timer, sdp_arm_cq_timer,
			(unsigned long)ssk);
	sdp_arm_rx_cq(sk_ssk(ssk));

	return 0;

err_cq:
	kfree(ssk->rx_ring.buffer);
	ssk->rx_ring.buffer = NULL;
	return rc;
}

void sdp_rx_ring_destroy(struct sdp_sock *ssk)
{
	del_timer_sync(&ssk->rx_ring.cq_arm_timer);

	if (ssk->rx_ring.buffer) {
		sdp_rx_ring_purge(ssk);

		kfree(ssk->rx_ring.buffer);
		ssk->rx_ring.buffer = NULL;
	}

	if (ssk->rx_ring.cq) {
		if (ib_destroy_cq(ssk->rx_ring.cq)) {
			sdp_warn(sk_ssk(ssk), "destroy cq(%p) failed\n",
				ssk->rx_ring.cq);
		} else {
			ssk->rx_ring.cq = NULL;
		}
	}

	SDP_WARN_ON(ring_head(ssk->rx_ring) != ring_tail(ssk->rx_ring));
}
