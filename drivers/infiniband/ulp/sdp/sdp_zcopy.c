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
 */
#include <linux/tcp.h>
#include <asm/ioctls.h>
#include <linux/workqueue.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_fmr_pool.h>
#include <linux/pagemap.h>
#include <net/tcp.h> /* for memcpy_toiovec */
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include "sdp.h"

static struct bzcopy_state dummy_bz = {
busy: 1,
};

static int sdp_update_iov_used(struct sock *sk, struct iovec *iov, int len);

static int sdp_post_srcavail(struct sock *sk, struct tx_srcavail_state *tx_sa,
		int page_idx, struct iovec *iov, int off, size_t len)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sdp_srcah *srcah;
	struct sk_buff *skb;
	int payload_len;

	WARN_ON(ssk->tx_sa);

	BUG_ON(!tx_sa);
	BUG_ON(!tx_sa->fmr || !tx_sa->fmr->fmr->lkey);

	skb = sk_stream_alloc_skb(&ssk->isk.sk,
			sizeof(struct sdp_bsdh) +
			sizeof(struct sdp_srcah) + 
			SDP_SRCAVAIL_PAYLOAD_LEN,
			GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}
	sdp_prf1(sk, skb, "sending SrcAvail");
		
	TX_SRCAVAIL_STATE(skb) = tx_sa; /* tx_sa is hanged on the skb 
					 * but continue to live after skb is freed */
	ssk->tx_sa = tx_sa;

	srcah = (struct sdp_srcah *)skb_push(skb, sizeof(*srcah));
	srcah->len = htonl(len);
	srcah->rkey = htonl(tx_sa->fmr->fmr->lkey);
	srcah->vaddr = cpu_to_be64(off);

	if (0) {
		void *payload;
		payload = skb_put(skb, SDP_SRCAVAIL_PAYLOAD_LEN);
		memcpy(payload, iov->iov_base, SDP_SRCAVAIL_PAYLOAD_LEN);
		payload_len = SDP_SRCAVAIL_PAYLOAD_LEN;
	} else {
		/* must have payload inlined in SrcAvail packet in combined mode */
		payload_len = min(len, PAGE_SIZE - off);
		get_page(tx_sa->pages[page_idx]);
		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
				tx_sa->pages[page_idx], off, payload_len);

		skb->len             += payload_len;
		skb->data_len         = payload_len;
		skb->truesize        += payload_len;
//		sk->sk_wmem_queued   += payload_len;
//		sk->sk_forward_alloc -= payload_len;

	}

	skb_entail(sk, ssk, skb);
	
	tx_sa->bytes_sent = len;
	tx_sa->bytes_acked = payload_len;

	/* TODO: pushing the skb into the tx_queue should be enough */

	return 0;
}

static int sdp_post_srcavail_cancel(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	if (!ssk->tx_sa && !ssk->srcavail_cancel)
		return 0; /* srcavail already serviced */

	ssk->srcavail_cancel = 1;

	sdp_post_sends(ssk, 1);

	schedule_delayed_work(&ssk->srcavail_cancel_work,
			SDP_SRCAVAIL_CANCEL_TIMEOUT);

	return 0;
}

void srcavail_cancel_timeout(struct work_struct *work)
{
	struct sdp_sock *ssk =
		container_of(work, struct sdp_sock, srcavail_cancel_work.work);
	struct sock *sk = &ssk->isk.sk;

	lock_sock(sk);

	sdp_warn(sk, "both SrcAvail and SrcAvailCancel timedout."
			" closing connection\n");
	sdp_set_error(sk, -ECONNRESET);
	wake_up(&ssk->wq);

	release_sock(sk);
}

static int sdp_wait_rdmardcompl(struct sdp_sock *ssk, long *timeo_p, int len,
		int ignore_signals)
{
	struct sock *sk = &ssk->isk.sk;
	int err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo_p;
	struct tx_srcavail_state *tx_sa = ssk->tx_sa;
	DEFINE_WAIT(wait);

	sdp_dbg_data(sk, "sleep till RdmaRdCompl. timeo = %ld.\n", *timeo_p);
	sdp_prf1(sk, NULL, "Going to sleep");
	while (ssk->qp_active) {
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

		if (unlikely(!*timeo_p)) {
			err = -ETIME;
			sdp_prf1(sk, NULL, "timeout");
			break;
		}

		if (unlikely(!ignore_signals && signal_pending(current))) {
			err = -EINTR;
			sdp_prf1(sk, NULL, "signalled");
			break;
		}

		if (tx_sa->bytes_acked == tx_sa->bytes_sent)
			break;
		else if (tx_sa->bytes_acked > tx_sa->bytes_sent) {
			err = -EINVAL;
			sdp_warn(sk, "acked bytes > sent bytes\n");
			break;
		}

		if (tx_sa->abort) {
			sdp_prf1(sk, NULL, "Aborting SrcAvail sending");
			err = -EAGAIN;
			break ;
		}

		posts_handler_put(ssk);

		sk_wait_event(sk, &current_timeo,
				tx_sa->abort && 
				(tx_sa->bytes_acked < tx_sa->bytes_sent) && 
				vm_wait);
		sdp_dbg_data(&ssk->isk.sk, "woke up sleepers\n");

		posts_handler_get(ssk);

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo_p;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo_p = current_timeo;
	}

	if (!ssk->qp_active) {
		sdp_warn(sk, "qp is not active\n");
	}

	finish_wait(sk->sk_sleep, &wait);

	sdp_dbg_data(sk, "Finished waiting - RdmaRdCompl: %d/%d bytes, abort: %d\n",
			tx_sa->bytes_acked, tx_sa->bytes_sent, tx_sa->abort);

	if (!ssk->qp_active) {
		sdp_warn(sk, "QP destroyed while waiting\n");
		return -EINVAL;
	}
	return err;
}

static int sdp_wait_rdma_wr_finished(struct sdp_sock *ssk, long *timeo_p)
{
	struct sock *sk = &ssk->isk.sk;
	int err = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT(wait);

	sdp_dbg_data(sk, "Sleep till RDMA wr finished.\n");
	while (1) {
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

		if (unlikely(!*timeo_p)) {
			err = -EAGAIN;
			sdp_warn(sk, "timedout\n");
			break;
		}

		if (unlikely(signal_pending(current))) {
			err = sock_intr_errno(*timeo_p);
			sdp_warn(sk, "signalled\n");
			break;
		}

		if (!ssk->tx_ring.rdma_inflight->busy) {
			sdp_dbg_data(sk, "got rdma cqe\n");
			break;
		}

		posts_handler_put(ssk);

		sdp_prf1(sk, NULL, "Going to sleep");
		sk_wait_event(sk, &current_timeo, 
			!ssk->tx_ring.rdma_inflight->busy);
		sdp_prf1(sk, NULL, "Woke up");
		sdp_dbg_data(&ssk->isk.sk, "woke up sleepers\n");

		posts_handler_get(ssk);

		*timeo_p = current_timeo;
	}

	finish_wait(sk->sk_sleep, &wait);

	sdp_dbg_data(sk, "Finished waiting - rdma's inflight=%d\n",
			ssk->tx_ring.rdma_inflight->busy);

	return err;
}

int sdp_post_rdma_rd_compl(struct sdp_sock *ssk,
		struct rx_srcavail_state *rx_sa)
{
	struct sdp_rrch *rrch;
	struct sk_buff *skb;
	gfp_t gfp_page;
	int copied = rx_sa->used - rx_sa->reported;

	if (rx_sa->used <= rx_sa->reported)
		return 0;

	if (unlikely(ssk->isk.sk.sk_allocation))
		gfp_page = ssk->isk.sk.sk_allocation;
	else
		gfp_page = GFP_KERNEL;

	skb = sdp_stream_alloc_skb(&ssk->isk.sk,
			sizeof(struct sdp_bsdh) +
			sizeof(struct sdp_rrch),
			gfp_page);
	/* FIXME */
	BUG_ON(!skb);

	rrch = (struct sdp_rrch *)skb_put(skb, sizeof(*rrch));
	rrch->len = htonl(copied);
	rx_sa->reported += copied;
	/* TODO: What if no tx_credits available? */
	sdp_post_send(ssk, skb, SDP_MID_RDMARDCOMPL);

	return 0;
}

int sdp_post_sendsm(struct sdp_sock *ssk)
{
	struct sk_buff *skb;
	gfp_t gfp_page;

	if (unlikely(ssk->isk.sk.sk_allocation))
		gfp_page = ssk->isk.sk.sk_allocation;
	else
		gfp_page = GFP_KERNEL;

	skb = sdp_stream_alloc_skb(&ssk->isk.sk,
			sizeof(struct sdp_bsdh),
			gfp_page);
	/* FIXME */
	BUG_ON(!skb);

	sdp_post_send(ssk, skb, SDP_MID_SENDSM);

	return 0;
}

static int sdp_update_iov_used(struct sock *sk, struct iovec *iov, int len)
{
	sdp_dbg_data(sk, "updating consumed %d bytes from iov\n", len);
	while (len > 0) {
		if (iov->iov_len) {
			int copy = min_t(unsigned int, iov->iov_len, len);
			len -= copy;
			iov->iov_len -= copy;
			iov->iov_base += copy;
		}
		iov++;
	}

	return 0;
}

static inline int sge_bytes(struct ib_sge *sge, int sge_cnt)
{
	int bytes = 0;

	while (sge_cnt > 0) {
		bytes += sge->length;
		sge++;
		sge_cnt--;
	}

	return bytes;
}
void sdp_handle_sendsm(struct sdp_sock *ssk, u32 mseq_ack)
{
	struct sock *sk = &ssk->isk.sk;
	unsigned long flags;

	spin_lock_irqsave(&ssk->tx_sa_lock, flags);

	if (!ssk->tx_sa) {
		sdp_prf1(sk, NULL, "SendSM for cancelled/finished SrcAvail");
		goto out;
	}

	if (ssk->tx_sa->mseq < mseq_ack) {
		sdp_prf1(sk, NULL, "SendSM arrived for old SrcAvail. "
			"SendSM mseq_ack: 0x%x, SrcAvail mseq: 0x%x",
			mseq_ack, ssk->tx_sa->mseq);
		goto out;
	}

	sdp_prf1(sk, NULL, "Got SendSM - aborting SrcAvail");

	ssk->tx_sa->abort = 1;
	cancel_delayed_work(&ssk->srcavail_cancel_work);

	wake_up(sk->sk_sleep);
	sdp_dbg_data(sk, "woke up sleepers\n");

out:
	spin_unlock_irqrestore(&ssk->tx_sa_lock, flags);
}

void sdp_handle_rdma_read_compl(struct sdp_sock *ssk, u32 mseq_ack,
		u32 bytes_completed)
{
	struct sock *sk = &ssk->isk.sk;
	unsigned long flags;

	sdp_prf1(sk, NULL, "RdmaRdCompl ssk=%p tx_sa=%p", ssk, ssk->tx_sa);
	sdp_dbg_data(sk, "RdmaRdCompl ssk=%p tx_sa=%p\n", ssk, ssk->tx_sa);

	spin_lock_irqsave(&ssk->tx_sa_lock, flags);

	BUG_ON(!ssk);

	if (!ssk->tx_sa) {
		sdp_warn(sk, "Got RdmaRdCompl for aborted SrcAvail\n");
		goto out;
	}

	if (ssk->tx_sa->mseq < mseq_ack) {
		sdp_warn(sk, "RdmaRdCompl arrived for old SrcAvail. "
			"SendSM mseq_ack: 0x%x, SrcAvail mseq: 0x%x\n",
			mseq_ack, ssk->tx_sa->mseq);
		goto out;
	}

	ssk->tx_sa->bytes_acked += bytes_completed;

	wake_up(sk->sk_sleep);
	sdp_dbg_data(sk, "woke up sleepers\n");

out:
	spin_unlock_irqrestore(&ssk->tx_sa_lock, flags);
	return;
}

int sdp_get_pages(struct sock *sk, struct page **pages, int page_cnt,
		unsigned long addr)
{
	int done_pages = 0;

	sdp_dbg_data(sk, "count: %d addr: 0x%lx\n", page_cnt, addr);

	addr &= PAGE_MASK;
	if (segment_eq(get_fs(), KERNEL_DS)) {
		for (done_pages = 0; done_pages < page_cnt; done_pages++) {
			pages[done_pages] = virt_to_page(addr);
			if (!pages[done_pages])
				break;
			get_page(pages[done_pages]);
			addr += PAGE_SIZE;
		}
	} else {
		if (current->mm) {
			down_write(&current->mm->mmap_sem);
			done_pages = get_user_pages(current, current->mm, addr,
					page_cnt, 0, 0, pages, NULL);
			up_write(&current->mm->mmap_sem);
		}
	}

	if (unlikely(done_pages != page_cnt))
		goto err;

	return 0;

err:
	sdp_warn(sk, "Error getting pages. done_pages: %d page_cnt: %d\n",
			done_pages, page_cnt);
	for (; done_pages > 0; done_pages--)
		put_page(pages[done_pages - 1]);

	return -1;
}

void sdp_put_pages(struct sock *sk, struct page **pages, int page_cnt)
{
	int i;
	sdp_dbg_data(sk, "count: %d\n", page_cnt);

	for (i = 0; i < page_cnt; i++) {
		set_page_dirty_lock(pages[i]);
		page_cache_release(pages[i]);
	}
}

static int sdp_map_dma(struct sock *sk, u64 *addrs, int page_cnt,
		struct page **pages, int offset, int len)
{
	struct ib_device *dev = sdp_sk(sk)->ib_device;
	int i;
	sdp_dbg_data(sk, "offset: %d len: %d\n", offset, len);

	for (i = 0; i < page_cnt; i++) {
		int o = 0;
		int l = PAGE_SIZE;

		if (i == page_cnt - 1) {
			/* Last page */
			l = (len + offset) & (PAGE_SIZE - 1);
			if (l == 0)
				l = PAGE_SIZE;
		}

//		sdp_dbg_data(sk, "mapping %03d: page: %p o: %d l: %d\n",
//				i, pages[i], o, l);

		addrs[i] = ib_dma_map_page(dev,
				pages[i],
				o,
				l,
				DMA_TO_DEVICE);
		if (ib_dma_mapping_error(dev, addrs[i])) {
			sdp_warn(sk, "Error mapping page %p off: %d len: %d\n",
					pages[i], o, l);
			goto err;
		}
	}

	return 0;
err:
	for (; i > 0; i--) {
		ib_dma_unmap_page(dev, addrs[i], PAGE_SIZE, DMA_TO_DEVICE);
	}
	return -1;
}

static void sdp_unmap_dma(struct sock *sk, u64 *addrs, int page_cnt)
{
	int i;
	struct ib_device *dev = sdp_sk(sk)->ib_device;

	sdp_dbg_data(sk, "count: %d\n", page_cnt);

	for (i = 0; i < page_cnt; i++) {
		ib_dma_unmap_page(dev, addrs[i], 4096, DMA_TO_DEVICE);
	}
}

static int sdp_map_dma_sge(struct sock *sk, struct ib_sge *sge, int page_cnt,
		struct page **pages, int offset, int len)
{
	struct ib_device *dev = sdp_sk(sk)->ib_device;
	int i;
	int left = len;
	sdp_dbg_data(sk, "offset: %d len: %d\n", offset, len);

	for (i = 0; i < page_cnt; i++) {
		int o = i == 0 ? offset : 0;
		int l = MIN(left, PAGE_SIZE - o);

		sge[i].lkey = sdp_sk(sk)->sdp_dev->mr->lkey;
		sge[i].length = l;

		sge[i].addr = ib_dma_map_page(dev,
				pages[i],
				0, /* map page with offset (fbo) not working */
				l + o, /* compensate on 0 offset */
				DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(dev, sge[i].addr)) {
			sdp_warn(sk, "Error map page 0x%llx off: %d len: %d\n",
					sge[i].addr, o, l);
			goto err;
		}
		sge[i].addr += o;

		sdp_dbg_data(sk, "mapping %03d: page: %p o: %d l: %d | addr: 0x%llx length: %d\n",
				i, pages[i], o, l, sge[i].addr, sge[i].length);
		left -= l;
	}

	WARN_ON(left != 0);

	return 0;
err:
	for (; i > 0; i--) {
		ib_dma_unmap_page(dev, sge[i].addr, PAGE_SIZE, DMA_FROM_DEVICE);
	}
	return -1;
}

static void sdp_unmap_dma_sge(struct sock *sk, struct ib_sge *sge,
		int page_cnt, int offset, int len)
{
	int i;
	struct ib_device *dev = sdp_sk(sk)->ib_device;

	sdp_dbg_data(sk, "count: %d\n", page_cnt);

	for (i = 0; i < page_cnt; i++) {
		int l = PAGE_SIZE;

		if (i == page_cnt - 1) {
			/* Last page */
			l = (len + offset) & (PAGE_SIZE - 1);
			if (l == 0)
				l = PAGE_SIZE;
		}
		ib_dma_unmap_page(dev, sge[i].addr, l, DMA_FROM_DEVICE);
	}
}

static struct ib_pool_fmr *sdp_map_fmr(struct sock *sk, int page_cnt,
		u64 *addrs)
{
	struct ib_pool_fmr *fmr;
	int ret = 0;

	fmr = ib_fmr_pool_map_phys(sdp_sk(sk)->sdp_dev->fmr_pool, addrs,
			page_cnt, 0);
	if (IS_ERR(fmr)) {
		ret = PTR_ERR(fmr);
		fmr = NULL;
		sdp_warn(sk, "Error allocating fmr: %d\n", ret);
		goto err;
	}

	return fmr;
err:
	return NULL;
}

enum zcopy_type {
	SDP_ZCOPY_TYPE_RX,
	SDP_ZCOPY_TYPE_TX,
};

static struct tx_srcavail_state *sdp_alloc_tx_sa(struct sock *sk, int page_cnt)
{
	struct tx_srcavail_state *tx_sa;


	tx_sa = kzalloc(sizeof(struct tx_srcavail_state) +
			sizeof(struct page *) * page_cnt + 
			sizeof(u64) * page_cnt, GFP_KERNEL);
	if (!tx_sa)
		return ERR_PTR(-ENOMEM);
	
	tx_sa->pages = (struct page **)(tx_sa+1);
	tx_sa->addrs = (u64 *)(&tx_sa->pages[page_cnt]);

	return tx_sa;
}

int sdp_rdma_to_iovec(struct sock *sk, struct iovec *iov, struct sk_buff *skb,
		int len)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct rx_srcavail_state *rx_sa = RX_SRCAVAIL_STATE(skb);
	int rc = 0;
	struct ib_send_wr *bad_wr;
	struct ib_send_wr wr = { 0 };
	long timeo;
	struct ib_sge *sge;
	int sge_left;
	int copied;
	int offset;

	sdp_dbg_data(&ssk->isk.sk, "preparing RDMA read."
		" len: %d. buffer len: %ld\n", len, iov->iov_len);
	if (len > rx_sa->len)
		len = rx_sa->len;

	offset = (unsigned long)iov->iov_base & (PAGE_SIZE - 1);

	rx_sa->page_cnt = PAGE_ALIGN(len + offset) >> PAGE_SHIFT;
	sdp_dbg_data(sk, "page_cnt = %d len:%d offset: %d\n", rx_sa->page_cnt, len, offset);

	rx_sa->pages = 
		(struct page **) kzalloc(sizeof(struct page *) * rx_sa->page_cnt +
		sizeof(struct ib_sge) * rx_sa->page_cnt, GFP_KERNEL);
	if (!rx_sa->pages) {
		sdp_warn(sk, "Error allocating zcopy context\n");
		goto err_alloc_zcopy;
	}

	rx_sa->sge = (struct ib_sge *)(&rx_sa->pages[rx_sa->page_cnt]);

	rc = sdp_get_pages(sk, rx_sa->pages, rx_sa->page_cnt,
			(unsigned long)iov->iov_base);
	if (rc)
		goto err_get_pages;

	rc = sdp_map_dma_sge(sk, rx_sa->sge, rx_sa->page_cnt, rx_sa->pages,
			offset, len);
	if (rc)
		goto err_map_dma;

	wr.opcode = IB_WR_RDMA_READ;
	wr.next = NULL;
	wr.wr_id = SDP_OP_RDMA;
	wr.wr.rdma.rkey = rx_sa->rkey;
	wr.send_flags = 0;

	timeo = sock_sndtimeo(sk, 0);

	ssk->tx_ring.rdma_inflight = rx_sa;
	copied = 0;
	sge = rx_sa->sge;
	sge_left = rx_sa->page_cnt;
	do {
		/* Len error when using sge_cnt > 30 ?? */
		int sge_cnt = min(sge_left, SDP_MAX_SEND_SGES - 2);

		wr.wr.rdma.remote_addr = rx_sa->vaddr + copied + rx_sa->used;
		wr.num_sge = sge_cnt;
		wr.sg_list = sge;
		rx_sa->busy++;

		sdp_dbg_data(sk, "rdma read: sge_cnt: %d vaddr: 0x%llx "
			"copied: 0x%x rkey: 0x%x in_bytes: %d\n",
			sge_cnt, wr.wr.rdma.remote_addr, copied, rx_sa->rkey,
			sge_bytes(sge, sge_cnt));
		sdp_prf1(sk, NULL, "TX: RDMA read");

		if (sge_left == sge_cnt) {
			wr.send_flags = IB_SEND_SIGNALED;
			sdp_dbg_data(sk, "last wr is signaled\n");
		}
		rc = ib_post_send(ssk->qp, &wr, &bad_wr);
		if (unlikely(rc)) {
			sdp_warn(sk, "ib_post_send failed with status %d.\n",
					rc);
			sdp_set_error(&ssk->isk.sk, -ECONNRESET);
			wake_up(&ssk->wq);
			break;
		}

		copied += sge_bytes(sge, sge_cnt);
		sge_left -= sge_cnt;
		sge += sge_cnt;

		if (unlikely(ssk->srcavail_cancel_mseq > rx_sa->mseq)) {
			sdp_warn(sk, "got SrcAvailCancel - Aborting RDMA\n");
			rc = -EAGAIN;
		}
	} while (!rc && sge_left > 0);

	if (!rc || rc == -EAGAIN) {
		int got_srcavail_cancel = (rc == -EAGAIN);

		sdp_arm_tx_cq(sk);

		rc = sdp_wait_rdma_wr_finished(ssk, &timeo);

		/* Ignore any data copied after getting SrcAvailCancel */
		if (!got_srcavail_cancel && !rc) {
			sdp_update_iov_used(sk, iov, copied);
			rx_sa->used += copied;
			atomic_add(copied, &ssk->rcv_nxt);
		}
	}

	if (rc) {
		/* post rdma, wait_for_compl or post rdma_rd_comp failed - 
		 * post sendsm */
		sdp_warn(sk, "post rdma, wait_for_compl "
			"or post rdma_rd_comp failed - post sendsm\n");
		rx_sa->aborted = 1;
	}

	ssk->tx_ring.rdma_inflight = NULL;

	sdp_unmap_dma_sge(sk, rx_sa->sge, rx_sa->page_cnt, offset, len);
err_map_dma:	
	sdp_put_pages(sk, rx_sa->pages, rx_sa->page_cnt);
err_get_pages:
	kfree(rx_sa->pages);
	rx_sa->pages = NULL;
	rx_sa->sge = NULL;
err_alloc_zcopy:	

	return rc;
}

static inline int wait_for_sndbuf(struct sock *sk, long *timeo_p)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int ret = 0;

	sdp_dbg_data(sk, "Wait for mem\n");

	set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

	SDPSTATS_COUNTER_INC(send_wait_for_mem);

	sdp_do_posts(ssk);

	sdp_xmit_poll(ssk, 1);

	ret = sdp_bzcopy_wait_memory(ssk, timeo_p, &dummy_bz);

	return ret;
}

static int sdp_rdma_adv_single(struct sock *sk,
		struct tx_srcavail_state *tx_sa, struct iovec *iov, 
		int p_idx, int page_cnt, int offset, int len)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	long timeo = SDP_SRCAVAIL_ADV_TIMEOUT;
	unsigned long lock_flags;
	int rc = 0;

	if (!sdp_bzcopy_slots_avail(ssk, &dummy_bz)) {
		rc = wait_for_sndbuf(sk, &timeo);
		if (rc) {
			sdp_warn(sk, "Couldn't get send buffer\n");
			return rc;
		}
	}

	tx_sa->fmr = sdp_map_fmr(sk, page_cnt, &tx_sa->addrs[p_idx]);
	if (!tx_sa->fmr) {
		return -ENOMEM;
	}

	rc = sdp_post_srcavail(sk, tx_sa, p_idx, iov, offset, len);
	if (rc)
		goto err_abort_send;


	rc = sdp_wait_rdmardcompl(ssk, &timeo, len, 0);
	if (unlikely(rc)) {
		switch (rc) {
		case -EAGAIN: /* Got SendSM */
			sdp_warn(sk, "got SendSM. use SEND verb.\n");
			break;

		case -ETIME: /* Timedout */
			sdp_warn(sk, "TX srcavail timedout.\n");
		case -EINTR: /* interrupted */
			sdp_prf1(sk, NULL, "Aborting send.");
			sdp_post_srcavail_cancel(sk);

			/* Wait for RdmaRdCompl/SendSM to
			 * finish the transaction */
			timeo = 2 * HZ;
			sdp_warn(sk, "Waiting for SendSM\n");
			sdp_wait_rdmardcompl(ssk, &timeo, len, 1);
			sdp_warn(sk, "finished waiting\n");

			break;

		default:
			sdp_warn(sk, "error sending srcavail. rc = %d\n", rc);
			/* Socked destroyed while waited */
			break;
		}

		goto err_abort_send;
	}
	sdp_prf1(sk, NULL, "got RdmaRdCompl");

	sdp_update_iov_used(sk, iov, tx_sa->bytes_sent);

err_abort_send:
	ib_fmr_pool_unmap(tx_sa->fmr);

	spin_lock_irqsave(&ssk->tx_sa_lock, lock_flags);
	ssk->tx_sa = NULL;
	spin_unlock_irqrestore(&ssk->tx_sa_lock, lock_flags);

	return rc;
}

int sdp_sendmsg_zcopy(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t size)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int iovlen, flags;
	struct iovec *iov = NULL;
	int rc = 0;
	long timeo;
	struct tx_srcavail_state *tx_sa;
	int offset;
	int copied = 0;

	int page_cnt;
	int bytes_left;
	int pages_left;
	int p_idx;

	sdp_dbg_data(sk, "%s\n", __func__);

	lock_sock(sk);

	SDPSTATS_COUNTER_INC(sendmsg_zcopy_segment);

	posts_handler_get(ssk);

	flags = msg->msg_flags;
	timeo = SDP_SRCAVAIL_ADV_TIMEOUT ;

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((rc = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	offset = (unsigned long)iov->iov_base & (PAGE_SIZE - 1);
	sdp_dbg_data(sk, "Sending iov: %p, iovlen: %ld, size: %ld\n",
			iov->iov_base, iov->iov_len, size);

	SDPSTATS_HIST(sendmsg_seglen, iov->iov_len);

	if (iovlen > 1) {
		sdp_warn(sk, "iovlen > 1 not supported\n");
		rc = -ENOTSUPP;
		goto err;
	}

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN)) {
		rc = -EPIPE;
		goto err;
	}

	page_cnt = PAGE_ALIGN(min_t(int, iov->iov_len, MAX_ZCOPY_SEND_SIZE) + offset) 
			>> PAGE_SHIFT;
	tx_sa = sdp_alloc_tx_sa(sk, page_cnt);
	if (IS_ERR(tx_sa)) {
		sdp_warn(sk, "Error allocating zcopy context\n");
		rc = -EAGAIN; /* Buffer too big - fallback to bcopy */
		goto err_alloc_tx_sa;
	}

	do {
		tx_sa->page_cnt = page_cnt;

		rc = sdp_get_pages(sk, tx_sa->pages, tx_sa->page_cnt,
				(unsigned long)iov->iov_base);
		if (rc)
			goto err_get_pages;

		rc = sdp_map_dma(sk, tx_sa->addrs, tx_sa->page_cnt, tx_sa->pages,
				offset, iov->iov_len);
		if (rc)
			goto err_map_dma;

		bytes_left = iov->iov_len;
		pages_left = tx_sa->page_cnt;
		p_idx = 0;
		do {
			int p_cnt = min(256, pages_left);
			int len = min_t(int, page_cnt * PAGE_SIZE - offset, bytes_left);

			sdp_dbg_data(sk, "bytes_left: %d\n", bytes_left);
			rc = sdp_rdma_adv_single(sk, tx_sa, iov,
					p_idx, p_cnt, offset, len);
//					offset, p_cnt, len, addrs);

			copied += len;
			bytes_left -= len;
			pages_left -= p_cnt;
			p_idx += p_cnt;
			offset = 0;
		} while (!rc && !tx_sa->abort && pages_left > 0);

		sdp_unmap_dma(sk, tx_sa->addrs, tx_sa->page_cnt);
err_map_dma:	
		sdp_put_pages(sk, tx_sa->pages, tx_sa->page_cnt);
err_get_pages:

		page_cnt = PAGE_ALIGN(min_t(int, iov->iov_len, MAX_ZCOPY_SEND_SIZE)) 
			>> PAGE_SHIFT;
		tx_sa_reset(tx_sa);
	} while (!rc && iov->iov_len > 0);
	kfree(tx_sa);
err_alloc_tx_sa:
err:

	sdp_prf1(sk, NULL, "Finshed RDMA rc: %d copied: %d", rc, copied);
	posts_handler_put(ssk);
	release_sock(sk);

	return rc ?: copied;
}

