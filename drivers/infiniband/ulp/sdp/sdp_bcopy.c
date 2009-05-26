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

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA
void _dump_packet(const char *func, int line, struct sock *sk, char *str,
		struct sk_buff *skb, const struct sdp_bsdh *h)
{
	int len = 0;
	char buf[256];
	len += snprintf(buf, 255-len, "%s skb: %p mid: %2x:%-20s flags: 0x%x bufs: %d "
		"len: %d mseq: %d mseq_ack: %d",
		str, skb, h->mid, mid2str(h->mid), h->flags,
		ntohs(h->bufs), ntohl(h->len),ntohl(h->mseq),
		ntohl(h->mseq_ack));

	switch (h->mid) {
		case SDP_MID_HELLO:
			{
				const struct sdp_hh *hh = (struct sdp_hh *)h;
				len += snprintf(buf + len, 255-len,
					" | max_adverts: %d  majv_minv: %d localrcvsz: %d "
					"desremrcvsz: %d |",
					hh->max_adverts,
					hh->majv_minv,
					ntohl(hh->localrcvsz),
					ntohl(hh->desremrcvsz));
			}
			break;
		case SDP_MID_HELLO_ACK:
			{
				const struct sdp_hah *hah = (struct sdp_hah *)h;
				len += snprintf(buf + len, 255-len, " | actrcvz: %d |",
						ntohl(hah->actrcvsz));
			}
			break;
		case SDP_MID_CHRCVBUF:
		case SDP_MID_CHRCVBUF_ACK:
			{
				struct sdp_chrecvbuf *req_size = (struct sdp_chrecvbuf *)(h+1);
				len += snprintf(buf + len, 255-len,
					" | req_size: %d |", ntohl(req_size->size));
			}
			break;
		case SDP_MID_DATA:
			len += snprintf(buf + len, 255-len, " | data_len: %ld |", ntohl(h->len) - sizeof(struct sdp_bsdh));
		default:
			break;
	}
	buf[len] = 0;
	_sdp_printk(func, line, KERN_WARNING, sk, "%s: %s\n", str, buf);
}
#endif

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
	int send_now =
		BZCOPY_STATE(skb) ||
		 (ssk->nonagle & TCP_NAGLE_OFF) ||
		!ssk->nagle_last_unacked ||
		skb->next != (struct sk_buff *)&ssk->isk.sk.sk_write_queue ||
		skb->len + sizeof(struct sdp_bsdh) >= ssk->xmit_size_goal ||
		(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_PSH);

	if (send_now) {
		unsigned long mseq = ring_head(ssk->tx_ring);
		ssk->nagle_last_unacked = mseq;

		if (!timer_pending(&ssk->nagle_timer))
			mod_timer(&ssk->nagle_timer, jiffies + SDP_NAGLE_TIMEOUT);
		sdp_dbg_data(&ssk->isk.sk, "Starting nagle timer\n");
	}
	sdp_dbg_data(&ssk->isk.sk, "send_now = %d last_unacked = %ld\n",
		send_now, ssk->nagle_last_unacked);
	
	return send_now;
}

void sdp_nagle_timeout(unsigned long data)
{
	struct sdp_sock *ssk = (struct sdp_sock *)data;
	struct sock *sk = &ssk->isk.sk;

	sdp_dbg_data(&ssk->isk.sk, "last_unacked = %ld\n", ssk->nagle_last_unacked);

	if (!ssk->nagle_last_unacked)
		goto out2;

	/* Only process if the socket is not in use */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		sdp_dbg_data(&ssk->isk.sk, "socket is busy - will try later\n");
		goto out;
	}

	if (sk->sk_state == TCP_CLOSE) {
		bh_unlock_sock(sk);
		return;
	}

	ssk->nagle_last_unacked = 0;
	sdp_post_sends(ssk, 0);

	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		sk_stream_write_space(&ssk->isk.sk);
out:
	bh_unlock_sock(sk);
out2:
	if (sk->sk_send_head) /* If has pending sends - rearm */
		mod_timer(&ssk->nagle_timer, jiffies + SDP_NAGLE_TIMEOUT);
}

int sdp_post_credits(struct sdp_sock *ssk)
{
	int post_count = 0;

	sdp_dbg_data(&ssk->isk.sk, "credits: %d remote credits: %d "
			"tx ring slots left: %d send_head: %p\n",
		tx_credits(ssk), remote_credits(ssk),
		sdp_tx_ring_slots_left(&ssk->tx_ring),
		ssk->isk.sk.sk_send_head);

	if (likely(tx_credits(ssk) > 1) &&
	    likely(sdp_tx_ring_slots_left(&ssk->tx_ring))) {
		struct sk_buff *skb;
		skb = sdp_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh),
					  GFP_KERNEL);
		if (!skb)
			return -ENOMEM;
		sdp_post_send(ssk, skb, SDP_MID_DATA);
		post_count++;
	}

	if (post_count)
		sdp_xmit_poll(ssk, 0);
	return post_count;
}

void _sdp_post_sends(const char *func, int line, struct sdp_sock *ssk, int nonagle)
{
	/* TODO: nonagle? */
	struct sk_buff *skb;
	int c;
	gfp_t gfp_page;
	int post_count = 0;

	sdp_dbg_data(&ssk->isk.sk, "called from %s:%d\n", func, line);

	if (unlikely(!ssk->id)) {
		if (ssk->isk.sk.sk_send_head) {
			sdp_dbg(&ssk->isk.sk,
				"Send on socket without cmid ECONNRESET.\n");
			/* TODO: flush send queue? */
			sdp_reset(&ssk->isk.sk);
		}
		return;
	}

	if (unlikely(ssk->isk.sk.sk_allocation))
		gfp_page = ssk->isk.sk.sk_allocation;
	else
		gfp_page = GFP_KERNEL;

	sdp_dbg_data(&ssk->isk.sk, "credits: %d tx ring slots left: %d send_head: %p\n",
		tx_credits(ssk), sdp_tx_ring_slots_left(&ssk->tx_ring),
		ssk->isk.sk.sk_send_head);

	if (sdp_tx_ring_slots_left(&ssk->tx_ring) < SDP_TX_SIZE / 2) {
		int wc_processed = sdp_xmit_poll(ssk,  1);
		sdp_dbg_data(&ssk->isk.sk, "freed %d\n", wc_processed);
	}

	if (ssk->recv_request &&
	    ring_tail(ssk->rx_ring) >= ssk->recv_request_head &&
	    tx_credits(ssk) >= SDP_MIN_TX_CREDITS &&
	    sdp_tx_ring_slots_left(&ssk->tx_ring)) {
		struct sdp_chrecvbuf *resp_size;
		ssk->recv_request = 0;
		skb = sdp_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh) +
					  sizeof(*resp_size),
					  gfp_page);
		/* FIXME */
		BUG_ON(!skb);
		resp_size = (struct sdp_chrecvbuf *)skb_put(skb, sizeof *resp_size);
		resp_size->size = htonl(ssk->recv_frags * PAGE_SIZE);
		sdp_post_send(ssk, skb, SDP_MID_CHRCVBUF_ACK);
		post_count++;
	}

	if (tx_credits(ssk) <= SDP_MIN_TX_CREDITS &&
	       sdp_tx_ring_slots_left(&ssk->tx_ring) &&
	       (skb = ssk->isk.sk.sk_send_head) &&
		sdp_nagle_off(ssk, skb)) {
		SDPSTATS_COUNTER_INC(send_miss_no_credits);
		sdp_prf(&ssk->isk.sk, skb, "no credits. called from %s:%d", func, line);
	}

	while (tx_credits(ssk) > SDP_MIN_TX_CREDITS &&
	       sdp_tx_ring_slots_left(&ssk->tx_ring) &&
	       (skb = ssk->isk.sk.sk_send_head) &&
		sdp_nagle_off(ssk, skb)) {
		update_send_head(&ssk->isk.sk, skb);
		__skb_dequeue(&ssk->isk.sk.sk_write_queue);
		sdp_post_send(ssk, skb, SDP_MID_DATA);
		post_count++;
	}

	if (0 && tx_credits(ssk) == SDP_MIN_TX_CREDITS &&
	    !ssk->sent_request &&
	    ring_head(ssk->tx_ring) > ssk->sent_request_head + SDP_RESIZE_WAIT &&
	    sdp_tx_ring_slots_left(&ssk->tx_ring)) {
		struct sdp_chrecvbuf *req_size;
		skb = sdp_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh) +
					  sizeof(*req_size),
					  gfp_page);
		/* FIXME */
		BUG_ON(!skb);
		ssk->sent_request = SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE;
		ssk->sent_request_head = ring_head(ssk->tx_ring);
		req_size = (struct sdp_chrecvbuf *)skb_put(skb, sizeof *req_size);
		req_size->size = htonl(ssk->sent_request);
		sdp_post_send(ssk, skb, SDP_MID_CHRCVBUF);
		post_count++;
	}

	c = remote_credits(ssk);
	if (likely(c > SDP_MIN_TX_CREDITS))
		c *= 2;

	if (unlikely(c < ring_posted(ssk->rx_ring)) &&
	    likely(tx_credits(ssk) > 1) &&
	    likely(sdp_tx_ring_slots_left(&ssk->tx_ring)) &&
	    likely((1 << ssk->isk.sk.sk_state) &
		    (TCPF_ESTABLISHED | TCPF_FIN_WAIT1))) {
		skb = sdp_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh),
					  GFP_KERNEL);
		/* FIXME */
		BUG_ON(!skb);
		SDPSTATS_COUNTER_INC(post_send_credits);
		sdp_post_send(ssk, skb, SDP_MID_DATA);
		post_count++;
	}

	/* send DisConn if needed
	 * Do not send DisConn if there is only 1 credit. Compliance with CA4-82:
	 * If one credit is available, an implementation shall only send SDP
	 * messages that provide additional credits and also do not contain ULP
	 * payload. */
	if (unlikely(ssk->sdp_disconnect) &&
			!ssk->isk.sk.sk_send_head &&
			tx_credits(ssk) > 1) {
		ssk->sdp_disconnect = 0;
		skb = sdp_stream_alloc_skb(&ssk->isk.sk,
					  sizeof(struct sdp_bsdh),
					  gfp_page);
		/* FIXME */
		BUG_ON(!skb);
		sdp_post_send(ssk, skb, SDP_MID_DISCONN);
		post_count++;
	}

	if (post_count) {
		sdp_xmit_poll(ssk, 0);

		sdp_prf(&ssk->isk.sk, NULL, "post_sends finished polling [%s:%d].", func, line);
	}
}
