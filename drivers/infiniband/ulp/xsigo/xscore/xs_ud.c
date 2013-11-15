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
 * This file implements the UD send/receive stuff
 */

#include "xscore_priv.h"

#define	XS_UD_RECV_WQE		16
#define	XS_UD_SEND_WQE		8

#define MAX_UD_RX_BUF_SIZE         1024
#define MAX_UD_TX_BUF_SIZE         1024

#define XSUD_RECV_WRID         0x10000
#define XSUD_SEND_WRID         0x20000
#define XSUD_WRID_MASK         0x30000

#define QP_DEF_QKEY             0x11111111
#define QP_MULTICAST_QPN        0xFFFFFF
#define QP_MCAST_LID            0xC000

struct ud_tx_buf {
	void *vaddr;
	u64 mapping;
	struct ib_ah *ah;
	int len;
};

struct ud_rx_buf {
	void *vaddr;
	int len;
	u64 mapping;
};

/*
 * This has context inforamtion on UD
 */
struct ib_ud_ctx {
	struct xscore_port *pinfop;
	struct ib_cq *cq;
	struct ib_qp *qp;
	struct ud_rx_buf rxbuf[XS_UD_RECV_WQE];
	struct ud_tx_buf txbuf[XS_UD_SEND_WQE];
	int next_xmit;
	void (*callback) (void *arg, void *msg, int len);
	void *client_arg;
};

static int xs_ud_post_recv(struct ib_ud_ctx *ctx, int offset, int n)
{
	struct xscore_port *pinfop = ctx->pinfop;
	struct ib_device *ca = pinfop->xs_dev->device;
	struct ib_sge list = {
		.lkey = pinfop->xs_dev->mr->lkey
	};
	struct ib_recv_wr wr = {
		.sg_list = &list,
		.num_sge = 1,
	};
	struct ib_recv_wr *bad_wr;
	int i, ret;
	void *addr;
	u64 mapping;

	for (i = 0; i < n; ++i, ++offset) {
		struct ud_rx_buf *rbuf = &ctx->rxbuf[offset];

		addr = kmalloc(MAX_UD_RX_BUF_SIZE, GFP_ATOMIC);
		if (!addr) {
			ret = -ENOMEM;
			goto partial_failure;
		}
		rbuf->vaddr = addr;
		/*
		 * Map the buffer and give the bus address
		 */
		mapping = ib_dma_map_single(ca, addr, MAX_UD_RX_BUF_SIZE,
					    DMA_FROM_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping))) {
			ret = -EIO;
			goto partial_failure;
		}
		rbuf->mapping = mapping;
		list.addr = (unsigned long)mapping;
		list.length = MAX_UD_RX_BUF_SIZE;
		wr.wr_id = (int)(offset | XSUD_RECV_WRID);
		ret = ib_post_recv(ctx->qp, &wr, &bad_wr);
		if (ret) {
			pr_info("xs_ud_post_recv: ib_post_recv");
			pr_info(" error, i %d, ret = %d\n", i, ret);
			goto partial_failure;
		}
	}
	return 0;
partial_failure:
	for (; i >= 0; i--, offset--) {
		struct ud_rx_buf *rbuf = &ctx->rxbuf[offset];

		if (rbuf->mapping) {
			ib_dma_unmap_single(ca, rbuf->mapping,
					    MAX_UD_RX_BUF_SIZE,
					    DMA_FROM_DEVICE);
			rbuf->mapping = 0;
		}
		if (rbuf->vaddr != NULL) {
			kfree(rbuf->vaddr);
			rbuf->vaddr = 0;
		}
	}
	return ret;
}

static void handle_wc(struct ib_ud_ctx *udp, struct ib_wc *wcp)
{
	void *buf;
	struct ib_device *ca = udp->pinfop->xs_dev->device;
	struct ud_tx_buf *tbuf;
	struct ud_rx_buf *rbuf;
	int ind = (int)wcp->wr_id & 0xFFFF;
	int wrid = (int)wcp->wr_id & XSUD_WRID_MASK;

	switch (wrid) {
	case XSUD_SEND_WRID:
		tbuf = &udp->txbuf[ind];
		ib_destroy_ah(tbuf->ah);
		ib_dma_unmap_single(ca, tbuf->mapping, tbuf->len,
				    DMA_TO_DEVICE);
		kfree(tbuf->vaddr);
		tbuf->vaddr = 0;
		tbuf->ah = 0;
		tbuf->mapping = 0;
		break;
	case XSUD_RECV_WRID:
		rbuf = &udp->rxbuf[ind];
		ib_dma_unmap_single(ca, rbuf->mapping, MAX_UD_RX_BUF_SIZE,
				    DMA_FROM_DEVICE);
		buf = rbuf->vaddr;
		/*
		 * Allocate new buffer in its place
		 */
		if ((wcp->status == 0) && udp->callback) {
			(void)xs_ud_post_recv(udp, ind, 1);
			/*
			 * Get rid of the GRH header
			 */
			udp->callback(udp->client_arg,
				      buf + sizeof(struct ib_grh),
				      wcp->byte_len - sizeof(struct ib_grh));
		} else
			kfree(buf);
		break;
	default:
		pr_warn("xscore: UD unknown WR id\n");
		break;
	}
}

static void ud_compl_handler(struct ib_cq *cq, void *cq_context)
{
	struct ib_ud_ctx *udp = cq_context;
	struct ib_wc wc[1];
	int i, n;

	/*
	 * Enable interrupts back again
	 */
	(void)ib_req_notify_cq(cq,
			       IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);

	while ((n = ib_poll_cq(cq, 1, wc)) > 0) {
		for (i = 0; i < n; i++)
			handle_wc(udp, &wc[i]);
	}
}

int xs_ud_send_msg(struct xscore_port *pinfop, uint8_t *macp, void *msgp,
		   int len, int flags)
{
	struct ib_ud_ctx *udp = pinfop->ib_ud_ctx;
	struct ib_device *ca = pinfop->xs_dev->device;
	u64 mapping;
	void *addr = msgp;
	int i;
	struct ib_sge list = {
		.length = len,
		.lkey = pinfop->xs_dev->mr->lkey
	};
	struct ib_send_wr wr = {
		.sg_list = &list,
		.num_sge = 1,
		.opcode = IB_WR_SEND,
		.send_flags = IB_SEND_SIGNALED,
		.wr = {
		       .ud = {
			      .remote_qpn = QP_MULTICAST_QPN,
			      .remote_qkey = QP_DEF_QKEY}
		       }
	};
	struct ib_send_wr *bad_wr;
	union ib_gid dgid;
	struct ib_ah_attr ah_attr = {
		.dlid = QP_MCAST_LID,
		.sl = 0,
		.src_path_bits = 0,
		.port_num = pinfop->port_num
	};
	struct ud_tx_buf *tbuf;
	int ret;

	i = udp->next_xmit;
	tbuf = &udp->txbuf[i];
	if (tbuf->vaddr)
		return -ENOBUFS;
	if (flags & XS_UD_COPY_MSG) {
		addr = kmalloc(len + 40, GFP_KERNEL);
		if (!addr)
			return -ENOMEM;
		memcpy(addr, msgp, len);
	}
	mapping = ib_dma_map_single(ca, addr, len + 40, DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(ca, mapping))) {
		if (flags & XS_UD_COPY_MSG)
			kfree(addr);
		return -EIO;
	}
	tbuf->vaddr = addr;
	tbuf->mapping = mapping;
	tbuf->len = len + 40;
	udp->next_xmit = (i + 1) % XS_UD_SEND_WQE;
	list.addr = mapping;
	wr.wr_id = i | XSUD_SEND_WRID;
	/*
	 * Create a address handle and transmit the message
	 */
	memset(&dgid, 0, sizeof(dgid));
	/*
	 * Send it all Nodes IPv6 multicast address
	 * 0xff02::01
	 */
	*((u32 *) dgid.raw) = cpu_to_be32(0xff020000);
	dgid.raw[15] = 1;

	ah_attr.grh.hop_limit = 1;
	ah_attr.grh.dgid = dgid;
	ah_attr.ah_flags = IB_AH_GRH;
	tbuf->ah = ib_create_ah(pinfop->xs_dev->pd, &ah_attr);
	if (IS_ERR(tbuf->ah)) {
		XDDS_ERROR("%s: ib_create_ah failed, port: %d, index: %d\n",
			   __func__, pinfop->port_num, i);
		ret = PTR_ERR(tbuf->ah);
		goto err;
	}
	wr.wr.ud.ah = tbuf->ah;
	ret = ib_post_send(udp->qp, &wr, &bad_wr);
	if (ret)
		goto err1;
	return 0;
err1:
	ib_destroy_ah(tbuf->ah);
	tbuf->ah = 0;
err:
	tbuf->vaddr = 0;
	ib_dma_unmap_single(ca, tbuf->mapping, tbuf->len, DMA_TO_DEVICE);
	tbuf->mapping = 0;
	if (flags & XS_UD_COPY_MSG)
		kfree(addr);
	return ret;
}

int xs_ud_create(struct xscore_port *pinfop,
		 void (*callback) (void *, void *, int), void *arg)
{
	int ret = 0;
	struct ib_ud_ctx *udp;
	struct ib_qp_init_attr init_attr = {
		.cap = {
			.max_send_wr = XS_UD_SEND_WQE + 1,
			.max_recv_wr = XS_UD_RECV_WQE + 1,
			.max_send_sge = 1,
			.max_recv_sge = 1},
		.qp_type = IB_QPT_UD,
	};
	struct ib_qp_attr qp_attr = {
		.qp_state = IB_QPS_INIT,
		.pkey_index = 0,
		.port_num = pinfop->port_num,
		.qkey = QP_DEF_QKEY
	};

	/*
	 * Only do this once per port
	 */
	if (pinfop->ib_ud_ctx != NULL)
		return 0;

	XDDS_INFO("%s: Creating guid: 0x%llx\n", __func__, pinfop->guid);

	udp = kmalloc(sizeof(*udp), GFP_KERNEL);
	if (!udp)
		return -ENOMEM;
	memset(udp, 0, sizeof(*udp));
	udp->pinfop = pinfop;
	udp->callback = callback;
	udp->client_arg = arg;

	pinfop->ib_ud_ctx = udp;
	/*
	 * Create completion Q for send and receive (A single one is enough)
	 */
	udp->cq = ib_create_cq(pinfop->xs_dev->device,
			       ud_compl_handler, NULL,
			       (void *)udp, XS_UD_RECV_WQE + XS_UD_SEND_WQE, 0);
	if (IS_ERR(udp->cq)) {
		ret = PTR_ERR(udp->cq);
		XDDS_ERROR("%s: b_create_cq, port: %d, ret : %d\n",
			   __func__, pinfop->port_num, ret);
		goto err_0;
	}

	init_attr.send_cq = udp->cq;
	init_attr.recv_cq = udp->cq;

	udp->qp = ib_create_qp(pinfop->xs_dev->pd, &init_attr);
	if (IS_ERR(udp->qp)) {
		ret = PTR_ERR(udp->qp);
		XDDS_ERROR("%s: b_create_qp, port: %d, ret : %d\n",
			   __func__, pinfop->port_num, ret);
		goto err_1;
	}
	/*
	 * Now move the QP to RTS state and post recvs
	 */
	ret = ib_modify_qp(udp->qp, &qp_attr,
			   IB_QP_STATE |
			   IB_QP_PKEY_INDEX | IB_QP_PORT | IB_QP_QKEY);
	if (ret) {
		XDDS_ERROR("%s: ib_modify_qp, port: %d, ret : %d\n",
			   __func__, pinfop->port_num, ret);
		goto err_2;
	}

	qp_attr.qp_state = IB_QPS_RTR;

	ret = ib_modify_qp(udp->qp, &qp_attr, IB_QP_STATE);
	if (ret) {
		XDDS_ERROR("%s: ib_modify_qp, port: %d, ret : %d\n",
			   __func__, pinfop->port_num, ret);
		goto err_2;
	}

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;

	ret = ib_modify_qp(udp->qp, &qp_attr, IB_QP_STATE | IB_QP_SQ_PSN);
	if (ret) {
		XDDS_ERROR("%s: ib_modify_qp, port: %d, ret : %d\n",
			   __func__, pinfop->port_num, ret);
		goto err_2;
	}
	/*
	 * Now post recvs
	 */
	ret = xs_ud_post_recv(udp, 0, XS_UD_RECV_WQE);
	if (ret) {
		XDDS_ERROR("%s: xs_ud_post_recv, port: %d, ret : %d\n",
			   __func__, pinfop->port_num, ret);
		goto err_2;
	}

	(void)ib_req_notify_cq(udp->cq,
			       IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);

	return 0;
err_2:
	ib_destroy_qp(udp->qp);
err_1:
	ib_destroy_cq(udp->cq);
err_0:
	kfree(udp);
	pinfop->ib_ud_ctx = 0;
	return ret;
}

void xs_ud_destroy(struct xscore_port *pinfop)
{
	struct ib_ud_ctx *udp = pinfop->ib_ud_ctx;
	struct ib_device *ca = pinfop->xs_dev->device;
	int i;

	if (!udp)
		return;
	ib_destroy_qp(udp->qp);
	ib_destroy_cq(udp->cq);
	/*
	 * Flush out all buffers
	 */
	for (i = 0; i < XS_UD_RECV_WQE; i++) {
		struct ud_rx_buf *rbuf = &udp->rxbuf[i];

		if (rbuf->mapping)
			ib_dma_unmap_single(ca, rbuf->mapping,
					    MAX_UD_RX_BUF_SIZE,
					    DMA_FROM_DEVICE);
		if (rbuf->vaddr != NULL)
			kfree(rbuf->vaddr);
	}
	for (i = 0; i < XS_UD_SEND_WQE; i++) {
		struct ud_tx_buf *tbuf = &udp->txbuf[i];

		if (tbuf->mapping)
			ib_dma_unmap_single(ca, tbuf->mapping, tbuf->len,
					    DMA_TO_DEVICE);
		if (tbuf->vaddr != NULL)
			kfree(tbuf->vaddr);
	}
	kfree(udp);
}

void xs_ud_free(void *msg)
{
	void *p = msg - sizeof(struct ib_grh);

	XDDS_FUNCTION("%s: Freeing buffer: %p\n", __func__, p);
	kfree(p);
}
