/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
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
 */

/*
 * This file implements  XSCORE API used by client drivers
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/jiffies.h>

#include "xscore.h"
#include "xscore_priv.h"
#include "xsmp.h"

/*
 * For now, to enable the driver to use checksum, and not iCRC, the user should
 * should shca to use set the following module parameters:
 * # modprobe ib_xgc icrc_rx=1 icrc_tx=1
 * # modprobe xscore shca_csum=1
 * You'll need to do this on the chassis's shca too
 */
int shca_csum = 1;
module_param(shca_csum, int, 0644);
MODULE_PARM_DESC(shca_csum,
		 "Set value to 1 to default the shca to use checksum instead"
		 " of icrc32");

struct xt_cm_private_data {
	u64 vid;
	u16 qp_type;
	u16 max_ctrl_msg_size;
	u32 data_qp_type;
} __packed;

struct xscore_desc {
	dma_addr_t mapping;
	dma_addr_t rxmapping[XSCORE_MAX_RXFRAGS];
	void *vaddr;
	size_t size;
	dma_addr_t *sg_mapping;
	struct sk_buff *skb;
	struct page *page;
	int flags;
	unsigned long time_stamp;
	enum dma_data_direction direction;
};

static int xscore_eth_mtu = IB_MTU_4096;
module_param(xscore_eth_mtu, int, 0644);

static int xscore_ib_mtu = IB_MTU_2048;
module_param(xscore_ib_mtu, int, 0644);

static int qp_retry_count = 6;
module_param(qp_retry_count, int, 0644);

static int qp_timeout = 16;
module_param(qp_timeout, int, 0644);

static int rdma_responder_resources = 16;

module_param(rdma_responder_resources, int, 0644);

static int xscore_cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event);
static void _xscore_conn_disconnect(struct xscore_conn_ctx *ctx, int flags);

static void xscore_qp_event(struct ib_event *event, void *context)
{
	pr_err("QP event %d\n", event->event);
}

static void xscore_reset_rxdescriptor(struct xscore_desc *desc)
{
	desc->vaddr = 0;
	desc->page = 0;
	desc->skb = 0;
	desc->sg_mapping = 0;
}

static int xscore_new_cm_id(struct xscore_conn_ctx *ctx)
{
	struct ib_cm_id *new_cm_id;

	new_cm_id = ib_create_cm_id(ctx->port->xs_dev->device,
				    xscore_cm_handler, ctx);
	if (IS_ERR(new_cm_id))
		return PTR_ERR(new_cm_id);

	if (ctx->cm_id)
		ib_destroy_cm_id(ctx->cm_id);
	ctx->cm_id = new_cm_id;

	return 0;
}

static int xs_dma_map_tx(struct xscore_conn_ctx *ctx,
			 struct xscore_desc *desc, int *nfrags)
{
	struct xscore_port *port = ctx->port;
	struct ib_device *ca = port->xs_dev->device;
	struct sk_buff *skb = desc->skb;
	dma_addr_t *mapping = desc->sg_mapping;
	int i;
	int off;
	struct ib_sge *tx_sge = ctx->tx_sge;

	if (skb_headlen(skb)) {
		mapping[0] = ib_dma_map_single(ca, skb->data, skb_headlen(skb),
					       DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[0])))
			return -EIO;
		ib_dma_sync_single_for_device(ca, mapping[0],
					      skb_headlen(skb), DMA_TO_DEVICE);

		off = 1;
		tx_sge[0].addr = mapping[0];
		tx_sge[0].length = skb_headlen(skb);
		tx_sge[0].lkey = port->xs_dev->mr->lkey;
	} else
		off = 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		mapping[i + off] = ib_dma_map_page(ca, skb_frag_page(frag),
						   frag->page_offset,
						   skb_frag_size(frag),
						   DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[i + off])))
			goto partial_error;
		ib_dma_sync_single_for_device(ca, mapping[i + off],
					      frag->size, DMA_TO_DEVICE);
		tx_sge[i + off].addr = mapping[i + off];
		tx_sge[i + off].length = frag->size;
		tx_sge[i + off].lkey = port->xs_dev->mr->lkey;
	}
	*nfrags = skb_shinfo(skb)->nr_frags + off;
	return 0;

partial_error:
	for (; i > 0; --i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i - 1];
		ib_dma_unmap_page(ca, mapping[i - !off], skb_frag_size(frag),
				  DMA_TO_DEVICE);
	}

	if (off)
		ib_dma_unmap_single(ca, mapping[0], skb_headlen(skb),
				    DMA_TO_DEVICE);

	return -EIO;
}

static void xs_dma_unmap_tx(struct ib_device *ca, struct xscore_desc *desc)
{
	struct sk_buff *skb = desc->skb;
	dma_addr_t *mapping = desc->sg_mapping;
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
		ib_dma_unmap_page(ca, mapping[i + off], skb_frag_size(frag),
				  DMA_TO_DEVICE);
	}
}

int xscore_post_send_sg(struct xscore_conn_ctx *ctx, struct sk_buff *skb,
			int oflags)
{
	struct ib_send_wr wr, *bad_wr;
	int ret;
	int nfrags = 0;
	struct xscore_desc *desc;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);

	if (ctx->state != XSCORE_CONN_CONNECTED) {
		ret = -ENOTCONN;
		goto out;
	}

	desc = &ctx->tx_ring[ctx->next_xmit];
	if (desc->skb) {
		ret = -ENOBUFS;
		goto out;
	}

	wr.next = NULL;
	wr.wr_id = ctx->next_xmit;
	wr.sg_list = ctx->tx_sge;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	desc->skb = skb;
	/*
	 * perform DMA mapping of the SKB
	 */
	ret = xs_dma_map_tx(ctx, desc, &nfrags);
	if (unlikely(ret)) {
		desc->skb = 0;
		goto out;
	}

	ctx->next_xmit = (ctx->next_xmit + 1) % ctx->tx_ring_size;

	wr.num_sge = nfrags;

	if (oflags & XSCORE_DEFER_PROCESS)
		wr.send_flags |= XSCORE_DEFER_PROCESS;

	spin_unlock_irqrestore(&ctx->lock, flags);
	/* Note the Time stamp */
	desc->time_stamp = jiffies;

	ret = ib_post_send(ctx->qp, &wr, &bad_wr);

	if (ret) {
		xs_dma_unmap_tx(ctx->port->xs_dev->device, desc);
		desc->skb = 0;
	}

	IB_INFO("%s: ret %d, nxmit: %d, nfrags: %d\n", __func__,
		ret, ctx->next_xmit, nfrags);
	return ret;
out:
	spin_unlock_irqrestore(&ctx->lock, flags);
	return ret;
}
EXPORT_SYMBOL(xscore_post_send_sg);

int xscore_post_send(struct xscore_conn_ctx *ctx, void *addr, int len,
		     int oflags)
{
	struct xscore_port *port = ctx->port;
	struct ib_device *ca = port->xs_dev->device;
	dma_addr_t mapping;
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;
	int ret = 0;
	struct xscore_desc *desc;
	unsigned long flags;

	IB_INFO("%s: Addr: %p, Len: %d, DGUID: 0x%llx\n", __func__, addr,
		len, ctx->dguid);

	spin_lock_irqsave(&ctx->lock, flags);

	if (ctx->state != XSCORE_CONN_CONNECTED) {
		ret = -ENOTCONN;
		goto out;
	}

	desc = &ctx->tx_ring[ctx->next_xmit];
	if (desc->vaddr) {
		ret = -ENOBUFS;
		goto out;
	}

	mapping = ib_dma_map_single(ca, addr, len, DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(ca, mapping))) {
		ret = -EIO;
		goto out;
	}

	list.addr = mapping;
	list.length = len;
	list.lkey = port->xs_dev->mr->lkey;

	wr.next = NULL;
	wr.wr_id = ctx->next_xmit;
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ctx->next_xmit = (ctx->next_xmit + 1) % ctx->tx_ring_size;

	if (oflags & XSCORE_DEFER_PROCESS)
		wr.send_flags |= XSCORE_DEFER_PROCESS;

	ib_dma_sync_single_for_device(ca, mapping, len, DMA_TO_DEVICE);

	desc->vaddr = addr;
	desc->mapping = mapping;
	desc->size = len;
	desc->skb = 0;

	spin_unlock_irqrestore(&ctx->lock, flags);

	ret = ib_post_send(ctx->qp, &wr, &bad_wr);

	spin_lock_irqsave(&ctx->lock, flags);

	if (ret) {
		ib_dma_unmap_single(ca, mapping, len, DMA_TO_DEVICE);
		desc->vaddr = 0;
		desc->mapping = 0;
	}
out:
	spin_unlock_irqrestore(&ctx->lock, flags);

	IB_INFO("%s: ret %d, nxmit: %d\n", __func__, ret, ctx->next_xmit);

	return ret;
}
EXPORT_SYMBOL(xscore_post_send);

static int xs_post_recv(struct xscore_conn_ctx *ctx, int offset, int n,
			int gfp_flags, int fillholes)
{
	struct xscore_port *port = ctx->port;
	struct ib_device *ca = port->xs_dev->device;
	struct ib_sge list[XSCORE_MAX_RXFRAGS];
	struct ib_recv_wr wr;
	struct ib_recv_wr *bad_wr;
	int i, j, ret = 0;
	dma_addr_t *mapping;
	int rsize = ctx->rx_buf_size;

	for (i = 0; i < n; ++i, ++offset) {
		struct xscore_desc *desc = &ctx->rx_ring[offset];
		void *addr = NULL;
		j = 1;

		if (fillholes && (desc->vaddr || desc->page || desc->skb))
			continue;

		xscore_reset_rxdescriptor(desc);

		mapping = desc->rxmapping;

		if (ctx->alloc_page_bufs) {
			desc->page =
			    ctx->alloc_page_bufs(ctx->client_arg,
						 (void **)&desc->page, &rsize,
						 i);
			if (!desc->page)
				ret = -ENOMEM;
		} else if (ctx->alloc_buf) {
			addr =
			    ctx->alloc_buf(ctx->client_arg, (void **)&desc->skb,
					   rsize);
			if (!addr)
				ret = -ENOMEM;
		} else {
			addr = kmalloc(rsize, gfp_flags);
			if (!addr)
				ret = -ENOMEM;
		}

		if (ret == ENOMEM) {
			if (fillholes)
				return ret;
			goto partial_failure;
		}

		desc->size = rsize;
		/*
		 * Map the buffer and give the bus address
		 */
		if (addr) {
			desc->vaddr = addr;
			mapping[0] = ib_dma_map_single(ca, addr, rsize,
						       DMA_FROM_DEVICE);
			if (unlikely(ib_dma_mapping_error(ca, mapping[0]))) {
				ret = -EIO;
				if (fillholes)
					return ret;
				goto partial_failure;
			}
			list[0].addr = mapping[0];
			list[0].length = rsize;
			list[0].lkey = port->xs_dev->mr->lkey;
		} else {
			for (j = 0; j < (rsize / PAGE_SIZE); ++j) {
				/*
				 * ESX doesn't allow to  reference page
				 * descriptor in any form of pointer
				 * arithmetic
				 */
				mapping[j] =
				    ib_dma_map_page(ca, (desc->page + j), 0,
						    PAGE_SIZE, DMA_FROM_DEVICE);
				if (unlikely
				    (ib_dma_mapping_error(ca, mapping[j]))) {
					ret = -EIO;
					for (; j > 0; --j)
						ib_dma_unmap_page(ca,
							mapping[j-1],
							PAGE_SIZE,
							DMA_FROM_DEVICE);
					if (fillholes)
						return ret;
					goto partial_failure;
				}
				list[j].addr = mapping[j];
				list[j].length = PAGE_SIZE;
				list[j].lkey = port->xs_dev->mr->lkey;
			}
		}

		desc->sg_mapping = mapping;
		wr.next = NULL;
		wr.wr_id = (int)offset;
		wr.sg_list = list;
		wr.num_sge = j;
		ret = ib_post_recv(ctx->qp, &wr, &bad_wr);
		if (ret) {
			pr_err("xs_post_recv: ib_post_recv error,");
			pr_err("i = %d, ret = %d\n", i, ret);
			if (fillholes)
				return ret;
			goto partial_failure;
		}
	}
	return 0;
partial_failure:
	pr_err("%s: Failed to allocate buffers\n", __func__);
	for (; i >= 0; i--, offset--) {
		struct xscore_desc *desc = &ctx->rx_ring[offset];

		if (desc->sg_mapping) {
			if (desc->page) {
				for (j = 0; j < (rsize / PAGE_SIZE); ++j)
					ib_dma_unmap_page(ca,
							  desc->sg_mapping[j],
							  PAGE_SIZE,
							  DMA_FROM_DEVICE);
			} else {
				ib_dma_unmap_single(ca, desc->sg_mapping[0],
						    rsize, DMA_FROM_DEVICE);
			}
			desc->sg_mapping = 0;
		}
		if (desc->page || desc->vaddr || desc->skb) {
			if (ctx->free_buf)
				ctx->free_buf(ctx->client_arg,
					      desc->page ? desc->page : (desc->
									 skb ?
									 desc->
									 skb :
									 desc->
									 vaddr),
					      XSCORE_RECV_BUF);
			else
				kfree(desc->vaddr);

			xscore_reset_rxdescriptor(desc);
		}
	}
	return ret;
}

int xscore_refill_recv(struct xscore_conn_ctx *ctx, int gfp_flags)
{
	return xs_post_recv(ctx, 0, ctx->rx_ring_size, gfp_flags, 1);
}
EXPORT_SYMBOL(xscore_refill_recv);

int xscore_enable_txintr(struct xscore_conn_ctx *ctx)
{
	return ib_req_notify_cq(ctx->scq,
				IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
}
EXPORT_SYMBOL(xscore_enable_txintr);

int xscore_enable_rxintr(struct xscore_conn_ctx *ctx)
{
	return ib_req_notify_cq(ctx->rcq,
				IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
}
EXPORT_SYMBOL(xscore_enable_rxintr);

static int _xscore_poll_send(struct xscore_conn_ctx *ctx)
{
	struct ib_device *ca = ctx->port->xs_dev->device;
	struct ib_wc wc;
	struct xscore_desc *desc;
	int i;
	int err = 0;
	int ret;

	IB_INFO("%s: Completion GUID: 0x%llx\n", __func__, ctx->dguid);

	while ((ret = ib_poll_cq(ctx->scq, 1, &wc)) > 0) {
		i = (int)wc.wr_id;
		if (i >= ctx->tx_ring_size) {
			IB_ERROR("%s send completion error wr_id %d > %d\n",
				 __func__, i, ctx->tx_ring_size);
			err++;
			break;
		}
		desc = &ctx->tx_ring[i];
		if (desc->skb)
			xs_dma_unmap_tx(ca, desc);
		else
			ib_dma_unmap_single(ca, desc->mapping, desc->size,
					    DMA_TO_DEVICE);

		if (ctx->send_compl_handler)
			ctx->send_compl_handler(ctx->client_arg, desc->vaddr,
						wc.status, i);
		else if (ctx->free_buf)
			ctx->free_buf(ctx->client_arg,
				      desc->skb ? desc->skb : desc->vaddr,
				      XSCORE_SEND_BUF);
		else if ((ctx->features & XSCORE_DONT_FREE_SENDBUF) == 0)
			kfree(desc->vaddr);

		desc->mapping = 0;
		desc->skb = 0;
		desc->vaddr = 0;
		if (wc.status) {
			err++;
			break;
		}
	}
	if (!ret && !err)
		return 0;
	if (err)
		return wc.status;
	return ret;
}

static void xscore_send_completion(struct ib_cq *cq, void *ctx_ptr)
{
	struct xscore_conn_ctx *ctx = ctx_ptr;
	int err;
again:
	err = _xscore_poll_send(ctx);
	if (!err
	    && ib_req_notify_cq(ctx->scq,
				IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS) >
	    0)
		goto again;
}

int xscore_poll_send(struct xscore_conn_ctx *ctx, struct xscore_buf_info *bp)
{
	struct ib_device *ca = ctx->port->xs_dev->device;
	struct ib_wc *wcp;
	struct xscore_desc *desc;
	int i;
	int ret;

	bp->status = 0;

	/*
	 * Cache it here so that we do not go to IB stack every time
	 */
	if (!ctx->total_swc) {
		ret = ib_poll_cq(ctx->scq, XSCORE_NUM_SWC, &ctx->swc[0]);
		if (ret > 0) {
			ctx->total_swc = ret;
			ctx->cur_swc = 0;
		} else
			return ret;
	}

	ctx->total_swc--;
	wcp = &ctx->swc[ctx->cur_swc++];
	i = (int)wcp->wr_id;
	if (i >= ctx->tx_ring_size) {
		IB_ERROR("%s Send completion error wrid %d (> %d)\n",
			 __func__, i, ctx->tx_ring_size);
		return 0;
	}
	desc = &ctx->tx_ring[i];
	if (desc->skb)
		xs_dma_unmap_tx(ca, desc);
	else
		ib_dma_unmap_single(ca, desc->mapping, desc->size,
				    DMA_TO_DEVICE);
	bp->addr = (unsigned long)desc->vaddr;
	bp->sz = wcp->byte_len;
	bp->cookie = desc->skb;
	bp->time_stamp = desc->time_stamp;
	desc->vaddr = 0;
	desc->skb = 0;
	desc->mapping = 0;
	bp->status = wcp->status;
	return 1;
}
EXPORT_SYMBOL(xscore_poll_send);

int xscore_read_buf(struct xscore_conn_ctx *ctx, struct xscore_buf_info *bp)
{
	struct ib_device *ca = ctx->port->xs_dev->device;
	struct ib_wc *wcp;
	struct xscore_desc *desc;
	int i, j;
	int ret;

	bp->status = 0;

	/*
	 * Cache it here so that we do not go to IB stack every time
	 */
	if (!ctx->total_rwc) {
		ret = ib_poll_cq(ctx->rcq, XSCORE_NUM_RWC, &ctx->rwc[0]);
		if (ret > 0) {
			ctx->total_rwc = ret;
			ctx->cur_rwc = 0;
		} else
			return ret;
	}
	ret = 1;

	ctx->total_rwc--;
	wcp = &ctx->rwc[ctx->cur_rwc++];
	i = (int)wcp->wr_id;
	if (i >= ctx->rx_ring_size) {
		IB_ERROR("%s completion event error with wrid %d (> %d)\n",
			 __func__, i, ctx->rx_ring_size);
		return 0;
	}
	desc = &ctx->rx_ring[i];
	if (desc->page) {
		for (j = 0; j < (desc->size / PAGE_SIZE); ++j)
			ib_dma_unmap_page(ca, desc->sg_mapping[j], PAGE_SIZE,
					  DMA_FROM_DEVICE);
		bp->cookie = desc->page;
	} else if (desc->skb || desc->vaddr) {
		ib_dma_sync_single_for_cpu(ca, desc->sg_mapping[0], desc->size,
					   DMA_FROM_DEVICE);
		ib_dma_unmap_single(ca, desc->sg_mapping[0], desc->size,
				    DMA_FROM_DEVICE);
		bp->addr = (unsigned long)desc->vaddr;
		bp->cookie = desc->skb;
	} else {
		ret = 0;
		goto out;
	}

	bp->sz = wcp->byte_len;
	bp->status = wcp->status;
out:
	xscore_reset_rxdescriptor(desc);
	return ret;
}
EXPORT_SYMBOL(xscore_read_buf);

static int xscore_poll_recv(struct xscore_conn_ctx *ctx)
{
	struct ib_device *ca = ctx->port->xs_dev->device;
	struct ib_wc wc;
	struct xscore_desc *desc;
	int i, j;
	void *vaddr;
	int size;
	int err = 0;
	int ret = 0;

	while ((ret = ib_poll_cq(ctx->rcq, 1, &wc)) > 0) {
		i = (int)wc.wr_id;
		if (i >= ctx->rx_ring_size) {
			IB_ERROR("%s completion error with wr_id%d > size %d\n",
				 __func__, i, ctx->rx_ring_size);
			err++;
			break;
		}
		desc = &ctx->rx_ring[i];
		if (desc->page) {
			for (j = 0; j < (desc->size / PAGE_SIZE); ++j)
				ib_dma_unmap_page(ca, desc->sg_mapping[j],
						  PAGE_SIZE, DMA_FROM_DEVICE);
		} else if (desc->skb || desc->vaddr) {
			ib_dma_sync_single_for_cpu(ca, desc->sg_mapping[0],
						   desc->size, DMA_FROM_DEVICE);
			ib_dma_unmap_single(ca, desc->sg_mapping[0], desc->size,
					    DMA_FROM_DEVICE);
		}
		/*
		 * Post new buffer back
		 */
		vaddr = desc->vaddr;
		size = wc.byte_len;

		xscore_reset_rxdescriptor(desc);

		/*
		 * Call completion callback, pass buffer size
		 * and client arg and status
		 */
		if (ctx->recv_msg_handler)
			ctx->recv_msg_handler(ctx->client_arg, vaddr, size,
					      wc.status, i);
		/*
		 * If there is any error do not post anymore buffers
		 */
		if (wc.status) {
			err++;
			break;
		}
		ctx->status = xs_post_recv(ctx, i, 1, GFP_ATOMIC, 0);
	}
	if (!ret && !err)
		return 0;
	if (err)
		return wc.status;
	return ret;
}

static void xscore_recv_completion(struct ib_cq *cq, void *ctx_ptr)
{
	struct xscore_conn_ctx *ctx = ctx_ptr;
	int err;

	if (ctx->recv_compl_handler) {
		ctx->recv_compl_handler(ctx->client_arg);
		return;
	}
again:
	err = xscore_poll_recv(ctx);
	if (!err
	    && ib_req_notify_cq(ctx->rcq,
				IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS) >
	    0)
		goto again;
}

void xscore_conn_destroy(struct xscore_conn_ctx *ctx)
{
	int i;

	mutex_lock(&ctx->mlock);
	if (ctx->cm_id && !IS_ERR(ctx->cm_id))
		ib_destroy_cm_id(ctx->cm_id);
	if (ctx->qp && !IS_ERR(ctx->qp))
		ib_destroy_qp(ctx->qp);
	ctx->qp = 0;
	/*
	 * Flush all recv and send completions
	 */
	if (ctx->rcq && !IS_ERR(ctx->rcq)) {
		if (ctx->recv_compl_handler)
			ctx->recv_compl_handler(ctx->client_arg);
		else
			(void)xscore_poll_recv(ctx);
		ib_destroy_cq(ctx->rcq);
	}
	ctx->rcq = 0;
	if (ctx->scq && !IS_ERR(ctx->scq)) {
		(void)_xscore_poll_send(ctx);
		ib_destroy_cq(ctx->scq);
	}
	ctx->scq = 0;
	if (ctx->tx_sge != NULL)
		kfree(ctx->tx_sge);
	ctx->tx_sge = 0;
	if (ctx->tx_ring) {
		for (i = 0; i < ctx->tx_ring_size; i++) {
			struct xscore_desc *desc = &ctx->tx_ring[i];
			if (desc->sg_mapping != NULL)
				kfree(desc->sg_mapping);
			desc->sg_mapping = 0;
		}
		vfree(ctx->tx_ring);
	}
	ctx->tx_ring = 0;
	if (ctx->rx_ring)
		vfree(ctx->rx_ring);
	ctx->rx_ring = 0;
	if (ctx->fmr_pool && !IS_ERR(ctx->fmr_pool))
		ib_destroy_fmr_pool(ctx->fmr_pool);
	ctx->fmr_pool = 0;
	mutex_unlock(&ctx->mlock);
	mutex_destroy(&ctx->mlock);
}
EXPORT_SYMBOL(xscore_conn_destroy);

static int xscore_create_qpset(struct xscore_conn_ctx *ctx)
{
	struct ib_qp_init_attr init_attr;
	int ret = 0;

	if (ctx->qp && !IS_ERR(ctx->qp))
		ib_destroy_qp(ctx->qp);

	memset(&init_attr, 0, sizeof(init_attr));

	init_attr.event_handler = xscore_qp_event;
	init_attr.cap.max_send_wr = ctx->tx_ring_size;
	init_attr.cap.max_recv_wr = ctx->rx_ring_size;
	init_attr.cap.max_recv_sge = XSCORE_MAX_RXFRAGS;
	if (ctx->features & XSCORE_SG_SUPPORT)
		init_attr.cap.max_send_sge = MAX_SKB_FRAGS + 1;
	else
		init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = ctx->scq;
	init_attr.recv_cq = ctx->rcq;

	ctx->qp = ib_create_qp(ctx->port->xs_dev->pd, &init_attr);
	if (IS_ERR(ctx->qp)) {
		ret = PTR_ERR(ctx->qp);
		IB_ERROR("%s ib_create_qp failed %d\n", __func__, ret);
	}
	if ((ctx->features & XSCORE_NO_SEND_COMPL_INTR) == 0)
		ib_req_notify_cq(ctx->scq, IB_CQ_NEXT_COMP);
	if ((ctx->features & XSCORE_NO_RECV_COMPL_INTR) == 0)
		ib_req_notify_cq(ctx->rcq, IB_CQ_NEXT_COMP);
	return ret;
}

static int create_fmr_pool(struct xscore_conn_ctx *ctx)
{
	struct xscore_port *port = ctx->port;

	struct ib_fmr_pool_param pool_params = {
		.max_pages_per_fmr = ctx->max_fmr_pages,
		.access = IB_ACCESS_LOCAL_WRITE |
		    IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE,
		.pool_size = ctx->fmr_pool_size,
		.dirty_watermark = 32,
		.page_shift = 12,
		.flush_function = 0,
		.flush_arg = 0,
		.cache = 1
	};

	ctx->fmr_pool = ib_create_fmr_pool(port->xs_dev->pd, &pool_params);
	if (IS_ERR(ctx->fmr_pool))
		return PTR_ERR(ctx->fmr_pool);
	return 0;
}

static void xscore_init_dest(struct xscore_conn_ctx *ctx)
{
	struct xscore_port *port = ctx->port;

	if (port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		ctx->dgid.global.subnet_prefix =
		    port->sgid.global.subnet_prefix;
		ctx->dgid.global.interface_id = cpu_to_be64(ctx->dguid);
	} else {
		u64 mac = ctx->dguid;
		u8 dmac[6];
		int i;

		for (i = 0; i < 6; i++) {
			dmac[5 - i] = mac & 0xFF;
			mac >>= 8;
		}
		iboe_mac_vlan_to_ll(&ctx->dgid, dmac, 0);
	}
}

int xscore_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period)
{
	return ib_modify_cq(cq, cq_count, cq_period);
}
EXPORT_SYMBOL(xscore_modify_cq);

int xscore_conn_init(struct xscore_conn_ctx *ctx, struct xscore_port *port)
{
	int i;
	int ret = 0;

	ctx->cm_id = 0;
	ctx->port = port;
	ctx->next_xmit = 0;
	ctx->fmr_pool = 0;
	ctx->total_rwc = 0;
	ctx->cur_rwc = 0;
	ctx->total_swc = 0;
	ctx->cur_swc = 0;
	spin_lock_init(&ctx->lock);
	mutex_init(&ctx->mlock);
	init_completion(&ctx->done);

	xscore_init_dest(ctx);
	/*
	 * Allocate descriptors
	 */
	ctx->tx_ring = vmalloc(ctx->tx_ring_size * sizeof(struct xscore_desc));
	if (!ctx->tx_ring)
		return -ENOMEM;
	memset(ctx->tx_ring, 0, ctx->tx_ring_size * sizeof(struct xscore_desc));

	ctx->rx_ring = vmalloc(ctx->rx_ring_size * sizeof(struct xscore_desc));
	if (!ctx->rx_ring) {
		ret = -ENOMEM;
		goto err;
	}
	memset(ctx->rx_ring, 0, ctx->rx_ring_size * sizeof(struct xscore_desc));

	ctx->scq = ib_create_cq(ctx->port->xs_dev->device,
				xscore_send_completion, NULL, ctx,
				ctx->tx_ring_size, 0);
	if (IS_ERR(ctx->scq)) {
		ret = PTR_ERR(ctx->scq);
		IB_ERROR("%s ib_create_cq scq  failed %d\n", __func__, ret);
		goto err;
	}

	ctx->rcq = ib_create_cq(ctx->port->xs_dev->device,
				xscore_recv_completion, NULL, ctx,
				ctx->rx_ring_size, 0);
	if (IS_ERR(ctx->rcq)) {
		ret = PTR_ERR(ctx->rcq);
		IB_ERROR("%s ib_create_cq scq  failed %d\n", __func__, ret);
		goto err;
	}

	if ((ctx->features & XSCORE_NO_SEND_COMPL_INTR) == 0) {
		ib_req_notify_cq(ctx->scq, IB_CQ_NEXT_COMP);
		if (!ctx->tx_max_coalesced_frames || !ctx->tx_coalesce_usecs)
			xscore_modify_cq(ctx->scq, ctx->tx_max_coalesced_frames,
					 ctx->tx_coalesce_usecs);
	}

	if ((ctx->features & XSCORE_NO_RECV_COMPL_INTR) == 0) {
		ib_req_notify_cq(ctx->rcq, IB_CQ_NEXT_COMP);
		if (!ctx->rx_max_coalesced_frames || !ctx->rx_coalesce_usecs)
			xscore_modify_cq(ctx->rcq, ctx->rx_max_coalesced_frames,
					 ctx->rx_coalesce_usecs);
	}

	if (ctx->features & XSCORE_SG_SUPPORT) {
		ctx->tx_sge =
		    kmalloc(sizeof(struct ib_sge) * (MAX_SKB_FRAGS + 1),
			    GFP_KERNEL);
		if (!ctx->tx_sge) {
			ret = -ENOMEM;
			goto err;
		}
		for (i = 0; i < ctx->tx_ring_size; i++) {
			struct xscore_desc *desc = &ctx->tx_ring[i];

			desc->sg_mapping =
			    kmalloc(sizeof(dma_addr_t) * (MAX_SKB_FRAGS + 1),
				    GFP_KERNEL);
			if (!desc->sg_mapping) {
				ret = -ENOMEM;
				goto err;
			}
		}
	}
	ret = create_fmr_pool(ctx);
	if ((ctx->features & XSCORE_FMR_SUPPORT)
	    && ret)
		goto err;

	return 0;
err:
	IB_ERROR("%s Error %d\n", __func__, ret);
	xscore_conn_destroy(ctx);
	return ret;
}
EXPORT_SYMBOL(xscore_conn_init);

u8 xscore_port_num(struct xscore_port *port)
{
	return port->port_num;
}
EXPORT_SYMBOL(xscore_port_num);

static void path_rec_complete(int status, struct ib_sa_path_rec *resp,
			      void *context)
{
	struct xscore_conn_ctx *ctx = context;

	IB_INFO("%s status %d\n", __func__, status);

	if (status)
		IB_ERROR("%s: completed with error %d\n", __func__, status);
	else
		memcpy(&ctx->path_rec, resp, sizeof(struct ib_sa_path_rec));
	ctx->status = status;
	complete(&ctx->done);
}

static int use_path_rec;

static int xscore_send_req(struct xscore_conn_ctx *ctx)
{
	struct ib_cm_req_param req;
	struct ib_sa_path_rec path_rec;
	struct ib_port_attr port_attr;
	struct ib_sa_query *query;
	u16 pkey;
	int status;

	memset(&req, 0, sizeof(req));

	req.primary_path = &ctx->path_rec;
	req.alternate_path = NULL;
	req.service_id = ctx->service_id;
	req.qp_num = ctx->qp->qp_num;
	req.qp_type = ctx->qp->qp_type;
	req.private_data = ctx->priv_data;
	req.private_data_len = ctx->priv_data_len;
	req.flow_control = 1;
	req.starting_psn = 0;
	req.peer_to_peer = 0;
	req.initiator_depth = 1;

	if (ctx->priv_data_len == sizeof(struct xt_cm_private_data)) {
		struct xt_cm_private_data *pdata =
		    (struct xt_cm_private_data *)ctx->priv_data;
		if (ctx->port->xs_dev->is_shca && shca_csum) {
			ctx->features |= XSCORE_USE_CHECKSUM;
			pdata->data_qp_type =
			    cpu_to_be32(be32_to_cpu(pdata->data_qp_type) |
					shca_csum);
		} else
			ctx->features &= ~XSCORE_USE_CHECKSUM;
	}

	if (ctx->features & XSCORE_RDMA_SUPPORT)
		req.responder_resources = rdma_responder_resources;
	else
		req.responder_resources = 1;
	req.remote_cm_response_timeout = 20;
	req.local_cm_response_timeout = 20;
	if (ctx->cm_timeout) {
		req.remote_cm_response_timeout = ctx->cm_timeout;
		req.local_cm_response_timeout = ctx->cm_timeout;
	}
	req.retry_count = qp_retry_count;
	req.rnr_retry_count = 7;
	req.max_cm_retries = 1;

	memset(&path_rec, 0, sizeof(path_rec));

	/*
	 * Fill up path record information here
	 */
	(void)ib_query_port(ctx->port->xs_dev->device, ctx->port->port_num,
			    &port_attr);
	path_rec.slid = cpu_to_be16(port_attr.lid);
	path_rec.dlid = cpu_to_be16(ctx->dlid);
	path_rec.sgid = ctx->port->sgid;
	path_rec.dgid = ctx->dgid;
	ib_query_pkey(ctx->port->xs_dev->device, ctx->port->port_num, 0, &pkey);
	path_rec.pkey = cpu_to_be16(pkey);
	path_rec.numb_path = 1;

	if (use_path_rec && ctx->port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		/*
		 * If IB get path record from SA
		 */
		status =
		    ib_sa_path_rec_get(&xscore_sa_client,
				       ctx->port->xs_dev->device,
				       ctx->port->port_num, &path_rec,
				       IB_SA_PATH_REC_DGID | IB_SA_PATH_REC_SGID
				       | IB_SA_PATH_REC_PKEY |
				       IB_SA_PATH_REC_NUMB_PATH, 3000,
				       GFP_KERNEL, &path_rec_complete,
				       (void *)ctx, &query);

		if (status) {
			IB_ERROR
			    ("%s:ib_sa_path_rec_get completed with error %d\n",
			     __func__, status);
			return status;
		}

		wait_for_completion(&ctx->done);
		if (ctx->status) {
			IB_ERROR
			    ("%s:wait_for_completion completed with error %d\n",
			     __func__, ctx->status);
			return ctx->status;
		}
	} else {
		req.primary_path = &path_rec;

		if (ctx->port->link_layer == IB_LINK_LAYER_ETHERNET) {
			path_rec.mtu = port_attr.active_mtu;
			/*
			 * LLE card has an issue where it reports
			 * active MTU=4 for Jumbo and not 5
			 */
			if (path_rec.mtu == 4)
				path_rec.mtu = 5;

			/*
			 * 8k IB MTU support is  for vnics only
			 */
			if (!(ctx->features & XSCORE_8K_IBMTU_SUPPORT)) {
				if (path_rec.mtu > xscore_eth_mtu)
					path_rec.mtu = xscore_eth_mtu;
				if (xscore_eth_mtu > 5)
					path_rec.mtu = 5;
			}

			path_rec.hop_limit = 2;
		} else {
			path_rec.mtu = xscore_ib_mtu;
			path_rec.hop_limit = 0;
		}
		path_rec.reversible = 1;
		path_rec.mtu_selector = 3;
		path_rec.rate_selector = 2;
		path_rec.rate = 3;
		path_rec.packet_life_time_selector = 2;
		path_rec.packet_life_time = 14;
	}

	init_completion(&ctx->done);
	status = ib_send_cm_req(ctx->cm_id, &req);
	if (status)
		IB_ERROR("%s:ib_send_cm_req completed with error %d\n",
			 __func__, status);
	return status;
}

int xscore_conn_connect(struct xscore_conn_ctx *ctx, int flags)
{
	int ret;

	IB_FUNCTION("%s: Connecting to 0x%llx, LID: 0x%x, SID: 0x%llx\n",
		    __func__, ctx->dguid, ctx->dlid, ctx->service_id);

	mutex_lock(&ctx->mlock);
	_xscore_conn_disconnect(ctx, flags);
	xscore_init_dest(ctx);
	ret = xscore_create_qpset(ctx);
	if (ret) {
		IB_ERROR("%s xscore_create_qpset failed %d\n", __func__,
			 ret);
		mutex_unlock(&ctx->mlock);
		return ret;
	}
	ctx->next_xmit = 0;

	ret = xscore_new_cm_id(ctx);
	if (ret) {
		IB_ERROR("%s ib_create_cmid failed %d\n", __func__, ret);
		ctx->cm_id = 0;
		mutex_unlock(&ctx->mlock);
		return ret;
	}
	init_completion(&ctx->done);
	ctx->flags |= flags;
	ret = xscore_send_req(ctx);
	if (ret) {
		IB_ERROR("%s xscore_send_req failed %d\n", __func__, ret);
		mutex_unlock(&ctx->mlock);
		return ret;
	}
	/*
	 * The user wants synchronous completion, wait for connection
	 * to be setup or fail
	 */
	if (flags & XSCORE_SYNCHRONOUS)
		wait_for_completion(&ctx->done);
	ctx->flags &= ~flags;
	mutex_unlock(&ctx->mlock);
	if (flags & XSCORE_SYNCHRONOUS)
		return ctx->status;
	else
		return ret;
}
EXPORT_SYMBOL(xscore_conn_connect);

static void xscore_reclaim_recv_buffers(struct xscore_conn_ctx *ctx)
{
	struct ib_device *ca = ctx->port->xs_dev->device;
	struct ib_wc wc;
	struct xscore_desc *desc;
	int i, j;

	while (ib_poll_cq(ctx->rcq, 1, &wc) > 0) {
		i = (int)wc.wr_id;
		if (i >= ctx->rx_ring_size) {
			IB_ERROR("%s completion error with wrid %d (> %d)\n",
				 __func__, i, ctx->rx_ring_size);
			break;
		}
		desc = &ctx->rx_ring[i];
		if (!desc->page && !desc->vaddr && !desc->skb) {
			IB_ERROR("%s: Bad RCQ completion id: %d, qpn: %d\n",
				 __func__, i, ctx->local_qpn);
			continue;
		}

		if (desc->page) {
			for (j = 0; j < (desc->size / PAGE_SIZE); ++j)
				ib_dma_unmap_page(ca, desc->sg_mapping[j],
						  PAGE_SIZE, DMA_FROM_DEVICE);
		} else if (desc->skb || desc->vaddr) {
			ib_dma_unmap_single(ca, desc->sg_mapping[0], desc->size,
					    DMA_FROM_DEVICE);
		}

		if (ctx->free_buf) {
			ctx->free_buf(ctx->client_arg,
				      desc->page ? desc->page : (desc->
								 skb ? desc->
								 skb : desc->
								 vaddr),
				      XSCORE_RECV_BUF);
		} else {
			kfree(desc->vaddr);
		}
		xscore_reset_rxdescriptor(desc);

	}
	for (i = 0; i < ctx->rx_ring_size; ++i) {
		desc = &ctx->rx_ring[i];

		if (desc->page || desc->vaddr || desc->skb) {
			if (desc->page) {
				for (j = 0; j < (desc->size / PAGE_SIZE); ++j)
					ib_dma_unmap_page(ca,
							  desc->sg_mapping[j],
							  PAGE_SIZE,
							  DMA_FROM_DEVICE);
			} else if (desc->skb || desc->vaddr) {
				ib_dma_unmap_single(ca, desc->sg_mapping[0],
						    desc->size,
						    DMA_FROM_DEVICE);
			}
			if (ctx->free_buf) {
				ctx->free_buf(ctx->client_arg,
					      desc->page ? desc->page : (desc->
									 skb ?
									 desc->
									 skb :
									 desc->
									 vaddr),
					      XSCORE_RECV_BUF);
			} else {
				kfree(desc->vaddr);
			}

			xscore_reset_rxdescriptor(desc);
		}
	}
}

static void xscore_reclaim_send_buffers(struct xscore_conn_ctx *ctx)
{
	struct ib_device *ca = ctx->port->xs_dev->device;
	struct ib_wc wc;
	struct xscore_desc *desc;
	int i;

	while (ib_poll_cq(ctx->scq, 1, &wc) > 0) {
		i = (int)wc.wr_id;
		if (i >= ctx->tx_ring_size) {
			IB_ERROR("%s Send completion error wrid %d (> %d)\n",
				 __func__, i, ctx->tx_ring_size);
			break;
		}
		desc = &ctx->tx_ring[i];
		if (desc->skb)
			xs_dma_unmap_tx(ca, desc);
		else if (desc->vaddr)
			ib_dma_unmap_single(ca, desc->mapping, desc->size,
					    DMA_TO_DEVICE);
		else {
			IB_ERROR("%s: Bad SCQ completion id: %d, qpn: %d\n",
				 __func__, i, ctx->local_qpn);
			continue;
		}
		if (ctx->free_buf)
			ctx->free_buf(ctx->client_arg,
				      desc->skb ? desc->skb : desc->vaddr,
				      XSCORE_SEND_BUF);
		else if ((ctx->features & XSCORE_DONT_FREE_SENDBUF) == 0)
			kfree(desc->vaddr);
		desc->vaddr = 0;
		desc->skb = 0;
		desc->mapping = 0;
	}
	for (i = 0; i < ctx->tx_ring_size; ++i) {
		desc = &ctx->tx_ring[i];

		if (desc->vaddr || desc->skb) {
			if (desc->skb)
				xs_dma_unmap_tx(ca, desc);
			else
				ib_dma_unmap_single(ca, desc->mapping,
						    desc->size, DMA_TO_DEVICE);
			if (ctx->free_buf)
				ctx->free_buf(ctx->client_arg,
					      desc->skb ? desc->skb : desc->
					      vaddr, XSCORE_SEND_BUF);
			else if ((ctx->features & XSCORE_DONT_FREE_SENDBUF) ==
				 0)
				kfree(desc->vaddr);
			desc->vaddr = 0;
			desc->skb = 0;
			desc->mapping = 0;
		}
	}
}

static void _xscore_conn_disconnect(struct xscore_conn_ctx *ctx, int oflags)
{
	struct ib_qp_attr qp_attr;
	unsigned long flags;

	IB_FUNCTION("%s: Disconnecting to 0x%llx, LID: 0x%x\n",
		    __func__, ctx->dguid, ctx->dlid);

	qp_attr.qp_state = IB_QPS_RESET;
	if (ctx->qp && !IS_ERR(ctx->qp))
		(void)ib_modify_qp(ctx->qp, &qp_attr, IB_QP_STATE);

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->state = XSCORE_CONN_INIT;
	spin_unlock_irqrestore(&ctx->lock, flags);

	init_completion(&ctx->done);
	ctx->flags |= oflags;
	if (ctx->cm_id && !ib_send_cm_dreq(ctx->cm_id, NULL, 0)) {
		if (oflags & XSCORE_SYNCHRONOUS)
			wait_for_completion(&ctx->done);
	}
	ctx->flags &= ~oflags;
	/*
	 * This guarantees no CM callbacks are pending after destroy
	 */
	if (ctx->cm_id && !IS_ERR(ctx->cm_id))
		ib_destroy_cm_id(ctx->cm_id);
	ctx->cm_id = 0;
	IB_FUNCTION("%s: Disconnected to 0x%llx\n", __func__, ctx->dguid);
	/*
	 * Reclaim all buffers back here
	 */

	ctx->total_rwc = 0;
	ctx->cur_rwc = 0;
	ctx->total_swc = 0;
	ctx->cur_swc = 0;

	xscore_reclaim_send_buffers(ctx);
	xscore_reclaim_recv_buffers(ctx);
}

void xscore_conn_disconnect(struct xscore_conn_ctx *ctx, int flags)
{
	mutex_lock(&ctx->mlock);
	_xscore_conn_disconnect(ctx, flags);
	mutex_unlock(&ctx->mlock);
}
EXPORT_SYMBOL(xscore_conn_disconnect);

static void handle_cm_rep(struct xscore_conn_ctx *ctx)
{
	struct ib_qp_attr qp_attr;
	int attr_mask = 0;

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_INIT;
	ctx->status = ib_cm_init_qp_attr(ctx->cm_id, &qp_attr, &attr_mask);
	if (ctx->status) {
		IB_ERROR("ib_cm_init_qp_attr: QP to INIT\n");
		return;
	}
	if (ctx->features & XSCORE_USE_CHECKSUM)
		attr_mask |= XSCORE_USE_CHECKSUM;
	ctx->status = ib_modify_qp(ctx->qp, &qp_attr, attr_mask);
	if (ctx->status) {
		IB_ERROR("ib: QP to INIT error\n");
		return;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTR;
	attr_mask = 0;
	ctx->status = ib_cm_init_qp_attr(ctx->cm_id, &qp_attr, &attr_mask);
	if (ctx->status) {
		IB_ERROR("ib_cm_init_qp_attr: QP to RTR, status=%d\n",
			 ctx->status);
		return;
	}

	ctx->remote_qpn = qp_attr.dest_qp_num;
	ctx->local_qpn = ctx->qp->qp_num;

	if (ctx->features & XSCORE_RDMA_SUPPORT) {
		attr_mask |= IB_QP_MAX_DEST_RD_ATOMIC;
		qp_attr.max_dest_rd_atomic = rdma_responder_resources;
	} else {
		qp_attr.max_dest_rd_atomic = 4;
	}

	attr_mask |= IB_QP_MIN_RNR_TIMER;
	qp_attr.min_rnr_timer = IB_RNR_TIMER_000_16;
	/*
	 * Handle some attributes for LLE
	 */
	if (ctx->port->link_layer == IB_LINK_LAYER_ETHERNET) {
		attr_mask |= IB_QP_RQ_PSN;
		qp_attr.rq_psn = 0;
		attr_mask |= IB_QP_AV;
		qp_attr.ah_attr.grh.dgid = ctx->dgid;
		qp_attr.ah_attr.sl = 0;
		qp_attr.ah_attr.port_num = ctx->port->port_num;
		qp_attr.ah_attr.grh.hop_limit = 1;
	}

	ctx->status = ib_modify_qp(ctx->qp, &qp_attr, attr_mask);
	if (ctx->status) {
		IB_ERROR("ib_cm_modify_qp: QP to RTR error, status=%d\n",
			 ctx->status);
		return;
	}
	ctx->status = xs_post_recv(ctx, 0, ctx->rx_ring_size, GFP_KERNEL, 0);
	if (ctx->status) {
		IB_ERROR("ib: xs_post_recv error\n");
		return;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	attr_mask = 0;
	qp_attr.qp_state = IB_QPS_RTS;
	ctx->status = ib_cm_init_qp_attr(ctx->cm_id, &qp_attr, &attr_mask);
	if (ctx->status)
		return;
	attr_mask |= IB_QP_TIMEOUT;
	qp_attr.timeout = qp_timeout;
	ctx->status = ib_modify_qp(ctx->qp, &qp_attr, attr_mask);
	if (ctx->status) {
		IB_ERROR("ib: QP to RTS error\n");
		return;
	}
	ctx->status = ib_send_cm_rtu(ctx->cm_id, NULL, 0);
	if (ctx->status) {
		IB_ERROR("ib: ib_send_cm_rtu error\n");
		return;
	}
}

static int xscore_cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	struct xscore_conn_ctx *ctx = cm_id->context;
	int comp = 0;
	struct ib_qp_attr qp_attr;
	int cback = 1;

	switch (event->event) {
	case IB_CM_REQ_ERROR:
		IB_INFO("%s IB_CM_REQ_ERROR DGUID 0x%llx\n", __func__,
			ctx->dguid);
		ctx->state = XSCORE_CONN_ERR;
		ctx->status = -ECONNRESET;
		comp = 1;
		break;
	case IB_CM_REP_RECEIVED:
		IB_INFO("%s IB_CM_REP_RCVD DGUID 0x%llx\n", __func__,
			ctx->dguid);
		comp = 1;
		/*
		 * Now handle CM rep from remote end
		 */
		handle_cm_rep(ctx);
		if (ctx->status)
			ctx->state = XSCORE_CONN_ERR;
		else
			ctx->state = XSCORE_CONN_CONNECTED;
		break;
	case IB_CM_REJ_RECEIVED:
		IB_INFO("%s IB_CM_REJ_RCVD DGUID 0x%llx", __func__, ctx->dguid);
		IB_INFO(",reason: %d, ", event->param.rej_rcvd.reason);
		IB_INFO("SID: 0x%llx\n", ctx->service_id);
		comp = 1;
		ctx->status = -ECONNRESET;
		ctx->state = XSCORE_CONN_ERR;
		break;
	case IB_CM_DREQ_RECEIVED:
		/*
		 * Handle this gracefully and try to re-connect
		 */
		IB_INFO("%s IB_CM_DREQ_RCVD DGUID 0x%llx\n", __func__,
			ctx->dguid);
		qp_attr.qp_state = IB_QPS_RESET;
		(void)ib_modify_qp(ctx->qp, &qp_attr, IB_QP_STATE);
		ib_send_cm_drep(ctx->cm_id, NULL, 0);
		comp = 1;
		ctx->state = XSCORE_CONN_RDISCONNECTED;
		break;
	case IB_CM_DREP_RECEIVED:
		IB_INFO("%s IB_CM_DREP_RCVD DGUID 0x%llx\n", __func__,
			ctx->dguid);
		comp = 1;
		ctx->status = 0;
		ctx->state = XSCORE_CONN_LDISCONNECTED;
		break;
	case IB_CM_DREQ_ERROR:
		IB_INFO("%s IB_CM_DREQ_ERR DGUID 0x%llx\n", __func__,
			ctx->dguid);
		comp = 1;
		ctx->status = -ECONNRESET;
		ctx->state = XSCORE_CONN_LDISCONNECTED;
		break;
	case IB_CM_TIMEWAIT_EXIT:
		cback = 0;
		break;
	default:
		cback = 0;
		break;
	}
	if (comp && cback && (ctx->flags & XSCORE_SYNCHRONOUS))
		complete(&ctx->done);
	if (ctx->event_handler && cback)
		ctx->event_handler(ctx->client_arg, ctx->state);
	return 0;
}
