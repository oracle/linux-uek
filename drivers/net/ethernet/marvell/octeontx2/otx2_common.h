// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_COMMON_H
#define OTX2_COMMON_H

#include <mbox.h>

#include "otx2_reg.h"

/* PCI device IDs */
#define PCI_DEVID_OCTEONTX2_RVU_PF              0xA063

/* PCI BAR nos */
#define PCI_CFG_REG_BAR_NUM                     2
#define PCI_MBOX_BAR_NUM                        4

#define NAME_SIZE                               32

#define RQ_QLEN		1024
#define SQ_QLEN		1024

#define DMA_BUFFER_LEN	1536 /* In multiples of 128bytes */
#define RCV_FRAG_LEN	(SKB_DATA_ALIGN(DMA_BUFFER_LEN + NET_SKB_PAD) + \
			 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

struct otx2_pool {
	struct qmem		*stack;
	struct qmem		*fc_addr;
	u16			rbsize;
	u32			page_offset;
	u16			pageref;
	struct page		*page;
};

struct otx2_qset {
#define OTX2_MAX_CQ_CNT		64
	u16			cq_cnt;
	u16			xqe_size; /* Size of CQE i.e 128 or 512 bytes*/
	struct otx2_pool	*pool;
};

struct  mbox {
	struct otx2_mbox	mbox;
	struct work_struct	mbox_wrk;
	struct otx2_mbox	mbox_up;
	struct work_struct	mbox_up_wrk;
	struct otx2_nic		*pfvf;
};

struct otx2_hw {
	struct pci_dev		*pdev;
	u16                     rx_queues;
	u16                     tx_queues;
	u16			max_queues;
	u16			pool_cnt;

	/* NPA */
	u32			stack_pg_ptrs;  /* No of ptrs per stack page */
	u32			stack_pg_bytes; /* Size of stack page */
	u16			sqb_size;

	/* MSI-X*/
	u16			num_vec;
	u16			npa_msixoff; /* Offset of NPA vectors */
	u16			nix_msixoff; /* Offset of NIX vectors */
	bool			*irq_allocated;
	char			*irq_name;
};

struct otx2_nic {
	void __iomem		*reg_base;
	struct pci_dev		*pdev;
	struct device		*dev;
	struct net_device	*netdev;

	struct otx2_qset	qset;
	struct otx2_hw		hw;
	struct mbox		mbox;
	struct workqueue_struct *mbox_wq;
	u16			pcifunc;
	u16			rx_chan_base;
	u16			tx_chan_base;
};

/* Register read/write APIs */
static inline void otx2_write64(struct otx2_nic *nic, u64 offset, u64 val)
{
	writeq(val, nic->reg_base + offset);
}

static inline u64 otx2_read64(struct otx2_nic *nic, u64 offset)
{
	return readq(nic->reg_base + offset);
}

/* With the absence of API for 128-bit IO memory access for arm64,
 * implement required operations at place.
 */
#ifdef __BIG_ENDIAN
#define otx2_high(high, low)   (low)
#define otx2_low(high, low)    (high)
#else
#define otx2_high(high, low)   (high)
#define otx2_low(high, low)    (low)
#endif

static inline void otx2_write128(__uint128_t val, void __iomem *addr)
{
	__uint128_t *__addr = (__force __uint128_t *)addr;
	u64 h, l;

	otx2_low(h, l) = (__force u64)cpu_to_le64(val);
	otx2_high(h, l) = (__force u64)cpu_to_le64(val >> 64);

	asm volatile("stp %x[x0], %x[x1], %x[p1]"
		: [p1]"=Ump"(*__addr)
		: [x0]"r"(l), [x1]"r"(h));
}

static inline __uint128_t otx2_read128(const void __iomem *addr)
{
	__uint128_t *__addr = (__force __uint128_t *)addr;
	u64 h, l;

	asm volatile("ldp %x[x0], %x[x1], %x[p1]"
		: [x0]"=r"(l), [x1]"=r"(h)
		: [p1]"Ump"(*__addr));

	return (__uint128_t)le64_to_cpu(otx2_low(h, l)) |
		(((__uint128_t)le64_to_cpu(otx2_high(h, l))) << 64);
}

/* Free pointer to a pool/aura */
static inline void otx2_aura_freeptr(struct otx2_nic *pfvf,
				     int aura, s64 buf)
{
	__uint128_t val;

	val = (__uint128_t)buf;
	val |= ((__uint128_t)aura | BIT_ULL(63)) << 64;

	otx2_write128(val, pfvf->reg_base + NPA_LF_AURA_OP_FREE0);
}

/* Update page ref count */
static inline void otx2_get_page(struct otx2_pool *pool)
{
	if (!pool->page)
		return;

	if (pool->pageref)
		page_ref_add(pool->page, pool->pageref);
	pool->pageref = 0;
	pool->page = NULL;
}

/* Mbox APIs */
static inline int otx2_sync_mbox_msg(struct mbox *mbox)
{
	if (!otx2_mbox_nonempty(&mbox->mbox, 0))
		return 0;
	otx2_mbox_msg_send(&mbox->mbox, 0);
	return otx2_mbox_wait_for_rsp(&mbox->mbox, 0);
}

#define M(_name, _id, _req_type, _rsp_type)				\
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _name(struct mbox *mbox)			\
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&mbox->mbox, 0, sizeof(struct _req_type),		\
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	return req;							\
}

MBOX_MESSAGES
#undef M

int otx2_enable_msix(struct otx2_hw *hw);
void otx2_disable_msix(struct otx2_nic *pfvf);

/* RVU block related APIs */
int otx2_attach_npa_nix(struct otx2_nic *pfvf);
int otx2_detach_resources(struct mbox *mbox);
int otx2_config_npa(struct otx2_nic *pfvf);
int otx2_config_nix(struct otx2_nic *pfvf);
int otx2_sq_aura_pool_init(struct otx2_nic *pfvf);
int otx2_rq_aura_pool_init(struct otx2_nic *pfvf);

/* Mbox handlers */
void mbox_handler_MSIX_OFFSET(struct otx2_nic *pfvf,
			      struct msix_offset_rsp *rsp);
void mbox_handler_NPA_LF_ALLOC(struct otx2_nic *pfvf,
			       struct npa_lf_alloc_rsp *rsp);
void mbox_handler_NIX_LF_ALLOC(struct otx2_nic *pfvf,
			       struct nix_lf_alloc_rsp *rsp);

#endif /* OTX2_COMMON_H */
