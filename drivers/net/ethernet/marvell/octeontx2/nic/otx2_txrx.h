/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_TXRX_H
#define OTX2_TXRX_H

#define LBK_CHAN_BASE  0x000
#define SDP_CHAN_BASE  0x700
#define CGX_CHAN_BASE  0x800

#define DMA_BUFFER_LEN	1536 /* In multiples of 128bytes */
#define OTX2_DATA_ALIGN(X)	ALIGN(X, OTX2_ALIGN)
#define RCV_FRAG_LEN		\
	((OTX2_DATA_ALIGN(DMA_BUFFER_LEN + NET_SKB_PAD)) + \
	(OTX2_DATA_ALIGN(sizeof(struct skb_shared_info))))

#define OTX2_HEAD_ROOM		OTX2_ALIGN

struct otx2_cq_poll {
	void			*dev;
#define CINT_INVALID_CQ		255
#define MAX_CQS_PER_CNT		2 /* RQ + SQ */
	u8			cint_idx;
	u8			cq_ids[MAX_CQS_PER_CNT];
	struct napi_struct	napi;
};

struct otx2_pool {
	struct qmem		*stack;
	struct qmem		*fc_addr;
	u16			rbsize;
	u32			page_offset;
	u16			pageref;
	struct page		*page;
};

struct otx2_cq_queue {
	u8			cq_idx;
	u8			cint_idx; /* CQ interrupt id */
	u32			cqe_cnt;
	u16			cqe_size;
	void			*cqe_base;
	struct qmem		*cqe;
	struct otx2_pool	*rbpool;
};

struct otx2_qset {
#define OTX2_MAX_CQ_CNT		64
	u16			cq_cnt;
	u16			xqe_size;
	u32			rqe_cnt;
	u32			sqe_cnt;
	struct otx2_pool	*pool;
	struct otx2_cq_poll	*napi;
	struct otx2_cq_queue	*cq;
};

int otx2_poll(struct napi_struct *napi, int budget);
#endif /* OTX2_TXRX_H */
