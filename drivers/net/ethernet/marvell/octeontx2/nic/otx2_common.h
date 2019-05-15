/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_COMMON_H
#define OTX2_COMMON_H

#include <linux/pci.h>

#include <mbox.h>
#include "otx2_reg.h"
#include "otx2_txrx.h"

/* PCI device IDs */
#define PCI_DEVID_OCTEONTX2_RVU_PF              0xA063
#define PCI_DEVID_OCTEONTX2_RVU_VF		0xA064
#define PCI_DEVID_OCTEONTX2_RVU_AFVF		0xA0F8

#define PCI_SUBSYS_DEVID_96XX_RVU_PFVF		0xB200

/* PCI BAR nos */
#define PCI_CFG_REG_BAR_NUM                     2
#define PCI_MBOX_BAR_NUM                        4

#define NAME_SIZE                               32

enum arua_mapped_qtypes {
	AURA_NIX_RQ,
	AURA_NIX_SQ,
};

/* NIX LF interrupts range*/
#define NIX_LF_QINT_VEC_START			0x00
#define NIX_LF_CINT_VEC_START			0x40
#define NIX_LF_GINT_VEC				0x80
#define NIX_LF_ERR_VEC				0x81
#define NIX_LF_POISON_VEC			0x82

/* RSS configuration */
struct otx2_rss_info {
	u8 enable;
	u32 flowkey_cfg;
	u16 rss_size;
	u8  ind_tbl[MAX_RSS_INDIR_TBL_SIZE];
#define RSS_HASH_KEY_SIZE	44   /* 352 bit key */
	u8  key[RSS_HASH_KEY_SIZE];
};

/* NIX TX stats */
enum nix_stat_lf_tx {
	TX_UCAST	= 0x0,
	TX_BCAST	= 0x1,
	TX_MCAST	= 0x2,
	TX_DROP		= 0x3,
	TX_OCTS		= 0x4,
	TX_STATS_ENUM_LAST,
};

/* NIX RX stats */
enum nix_stat_lf_rx {
	RX_OCTS		= 0x0,
	RX_UCAST	= 0x1,
	RX_BCAST	= 0x2,
	RX_MCAST	= 0x3,
	RX_DROP		= 0x4,
	RX_DROP_OCTS	= 0x5,
	RX_FCS		= 0x6,
	RX_ERR		= 0x7,
	RX_DRP_BCAST	= 0x8,
	RX_DRP_MCAST	= 0x9,
	RX_DRP_L3BCAST	= 0xa,
	RX_DRP_L3MCAST	= 0xb,
	RX_STATS_ENUM_LAST,
};

struct  otx2_dev_stats {
	u64 rx_bytes;
	u64 rx_frames;
	u64 rx_ucast_frames;
	u64 rx_bcast_frames;
	u64 rx_mcast_frames;
	u64 rx_drops;

	u64 tx_bytes;
	u64 tx_frames;
	u64 tx_ucast_frames;
	u64 tx_bcast_frames;
	u64 tx_mcast_frames;
	u64 tx_drops;
};

struct  mbox {
	struct otx2_mbox	mbox;
	struct work_struct	mbox_wrk;
	struct otx2_mbox	mbox_up;
	struct work_struct	mbox_up_wrk;
	struct otx2_nic		*pfvf;
	void			*bbuf_base; /* Bounce buffer for mbox memory */
	atomic_t		lock;	/* serialize mailbox access */
	int			num_msgs; /*mbox number of messages*/
	int			up_num_msgs;/* mbox_up number of messages*/

};

struct otx2_hw {
	struct pci_dev		*pdev;
	struct otx2_rss_info	rss_info;
	struct otx2_dev_stats	dev_stats;
	u16                     rx_queues;
	u16                     tx_queues;
	u16			max_queues;
	u16			pool_cnt;
	u16			rqpool_cnt;
	u16			sqpool_cnt;

	/* NPA */
	u32			stack_pg_ptrs;  /* No of ptrs per stack page */
	u32			stack_pg_bytes; /* Size of stack page */
	u16			sqb_size;

	/* MSI-X*/
	u16			npa_msixoff; /* Offset of NPA vectors */
	u16			nix_msixoff; /* Offset of NIX vectors */
	char			*irq_name;
	cpumask_var_t           *affinity_mask;

	u8			cint_cnt; /* CQ interrupt count */
	u16		txschq_list[NIX_TXSCH_LVL_CNT][MAX_TXSCHQ_PER_FUNC];

	/* For TSO segmentation */
	u8			lso_tsov4_idx;
	u8			lso_tsov6_idx;
	u8			hw_tso;

	u64			cgx_rx_stats[CGX_RX_STATS_COUNT];
	u64			cgx_tx_stats[CGX_TX_STATS_COUNT];
};

struct otx2_vf_config {
	struct otx2_nic *pf;
	struct delayed_work link_event_work;
	struct delayed_work mac_vlan_work;
	bool intf_down; /* interface was either configured or not */
	u8 mac[ETH_ALEN];
	u16 vlan;
};

struct otx2_ptp;

struct flr_work {
	struct work_struct work;
	struct otx2_nic *pf;
};

struct otx2_nic {
	void __iomem		*reg_base;
	struct pci_dev		*pdev;
	struct device		*dev;
	struct net_device	*netdev;
	void			*iommu_domain;

	struct otx2_qset	qset;
	struct otx2_hw		hw;

	/* Mbox */
	struct mbox		mbox;
	struct mbox		*mbox_pfvf;
	struct workqueue_struct *mbox_wq;
	struct workqueue_struct *mbox_pfvf_wq;

	u8			intf_down;
	u16			pcifunc;
	u16			rx_chan_base;
	u16			tx_chan_base;
	u8			cq_time_wait;
	u32			cq_ecount_wait;
	u32			msg_enable;
	struct work_struct	reset_task;
	u64			reset_count;
	u8			hw_rx_tstamp;
	u8			hw_tx_tstamp;
	u8			total_vfs;
	u16			bpid[NIX_MAX_BPID_CHAN];
	struct otx2_vf_config	*vf_configs;
	struct cgx_link_user_info linfo;
	struct otx2_ptp		*ptp;
	u16			rxvlan_entry;
	bool			rxvlan_alloc;

	bool			entries_alloc;
	u32			max_flows;
	u32			nr_flows;
	u16			entry_list[NPC_MAX_NONCONTIG_ENTRIES];
	struct list_head	flows;
	struct workqueue_struct	*flr_wq;
	struct flr_work		*flr_wrk;
};

static inline bool is_9xxx_pass1_silicon(struct pci_dev *pdev)
{
	return (pdev->revision == 0x00) &&
		(pdev->subsystem_device == PCI_SUBSYS_DEVID_96XX_RVU_PFVF);
}

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

/* Alloc pointer from pool/aura */
static inline u64 otx2_aura_allocptr(struct otx2_nic *pfvf, int aura)
{
	atomic64_t *ptr = (__force atomic64_t *)(pfvf->reg_base
				+ NPA_LF_AURA_OP_ALLOCX(0));
	u64 incr = (u64)aura | BIT_ULL(63);

	return atomic64_fetch_add_relaxed(incr, ptr);
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

static inline int otx2_get_pool_idx(struct otx2_nic *pfvf, int type, int idx)
{
	if (type == AURA_NIX_SQ)
		return pfvf->hw.rqpool_cnt + idx;

	 /* AURA_NIX_RQ */
	return idx;
}

/* Mbox APIs */
static inline int otx2_sync_mbox_msg(struct mbox *mbox)
{
	int err;

	if (!otx2_mbox_nonempty(&mbox->mbox, 0))
		return 0;
	otx2_mbox_msg_send(&mbox->mbox, 0);
	err = otx2_mbox_wait_for_rsp(&mbox->mbox, 0);
	if (err)
		return err;

	return otx2_mbox_check_rsp_msgs(&mbox->mbox, 0);
}

static inline int otx2_sync_mbox_up_msg(struct mbox *mbox, int devid)
{
	int err;

	if (!otx2_mbox_nonempty(&mbox->mbox_up, devid))
		return 0;
	otx2_mbox_msg_send(&mbox->mbox_up, devid);
	err = otx2_mbox_wait_for_rsp(&mbox->mbox_up, devid);
	if (err)
		return err;

	return otx2_mbox_check_rsp_msgs(&mbox->mbox_up, devid);
}

/* Use this API to send mbox msgs in atomic context
 * where sleeping is not allowed
 */
static inline int otx2_sync_mbox_msg_busy_poll(struct mbox *mbox)
{
	int err;

	if (!otx2_mbox_nonempty(&mbox->mbox, 0))
		return 0;
	otx2_mbox_msg_send(&mbox->mbox, 0);
	err = otx2_mbox_busy_poll_for_rsp(&mbox->mbox, 0);
	if (err)
		return err;

	return otx2_mbox_check_rsp_msgs(&mbox->mbox, 0);
}

#define M(_name, _id, _fn_name, _req_type, _rsp_type)                   \
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct mbox *mbox)                    \
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

#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
int									\
otx2_mbox_up_handler_ ## _fn_name(struct otx2_nic *pfvf,		\
				struct _req_type *req,			\
				struct _rsp_type *rsp);			\

MBOX_UP_CGX_MESSAGES
#undef M

/* Mbox bounce buffer APIs */
static inline int otx2_mbox_bbuf_init(struct mbox *mbox, struct pci_dev *pdev)
{
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *otx2_mbox;

	mbox->bbuf_base = devm_kmalloc(&pdev->dev, MBOX_SIZE, GFP_KERNEL);
	if (!mbox->bbuf_base)
		return -ENOMEM;

	/* Overwrite mbox mbase to point to bounce buffer, so that PF/VF
	 * prepare all mbox messages in bounce buffer instead of directly
	 * in hw mbox memory.
	 */
	otx2_mbox = &mbox->mbox;
	mdev = &otx2_mbox->dev[0];
	mdev->mbase = mbox->bbuf_base;

	otx2_mbox = &mbox->mbox_up;
	mdev = &otx2_mbox->dev[0];
	mdev->mbase = mbox->bbuf_base;
	return 0;
}

static inline void otx2_sync_mbox_bbuf(struct otx2_mbox *mbox, int devid)
{
	u16 msgs_offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);
	void *hw_mbase = mbox->hwbase + (devid * MBOX_SIZE);
	struct otx2_mbox_dev *mdev = &mbox->dev[devid];
	struct mbox_hdr *hdr;
	u64 msg_size;

	if (mdev->mbase == hw_mbase)
		return;

	hdr = hw_mbase + mbox->rx_start;
	msg_size = hdr->msg_size;

	if (msg_size > mbox->rx_size - msgs_offset)
		msg_size = mbox->rx_size - msgs_offset;

	/* Copy mbox messages from mbox memory to bounce buffer */
	memcpy(mdev->mbase + mbox->rx_start,
	       hw_mbase + mbox->rx_start, msg_size + msgs_offset);
}

static inline void otx2_mbox_lock_init(struct mbox *mbox)
{
	atomic_set(&mbox->lock, 0);
}

static inline void otx2_mbox_lock(struct mbox *mbox)
{
	while (!(atomic_add_return(1, &mbox->lock) == 1))
		cpu_relax();
}

static inline void otx2_mbox_unlock(struct mbox *mbox)
{
	atomic_set(&mbox->lock, 0);
}

/* Time to wait before watchdog kicks off.
 * Due to PSE deadlock errata, XOFF on TL2 transmission
 * queues takes more time than default watchdog timeout.
 * Hence setting this value higher.
 */
#define OTX2_TX_TIMEOUT		(100000 * HZ)

#define	RVU_PFVF_PF_SHIFT	10
#define	RVU_PFVF_PF_MASK	0x3F
#define	RVU_PFVF_FUNC_SHIFT	0
#define	RVU_PFVF_FUNC_MASK	0x3FF

static inline int rvu_get_pf(u16 pcifunc)
{
	return (pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;
}

/* MSI-X APIs */
void otx2_free_cints(struct otx2_nic *pfvf, int n);
void otx2_set_cints_affinity(struct otx2_nic *pfvf);

int otx2_hw_set_mac_addr(struct otx2_nic *pfvf, struct net_device *netdev);
int otx2_set_mac_address(struct net_device *netdev, void *p);
int otx2_change_mtu(struct net_device *netdev, int new_mtu);
int otx2_hw_set_mtu(struct otx2_nic *pfvf, int mtu);
void otx2_tx_timeout(struct net_device *netdev);
void otx2_get_mac_from_af(struct net_device *netdev);

/* RVU block related APIs */
int otx2_attach_npa_nix(struct otx2_nic *pfvf);
int otx2_detach_resources(struct mbox *mbox);
int otx2_config_npa(struct otx2_nic *pfvf);
int otx2_sq_aura_pool_init(struct otx2_nic *pfvf);
int otx2_rq_aura_pool_init(struct otx2_nic *pfvf);
void otx2_aura_pool_free(struct otx2_nic *pfvf);
void otx2_free_aura_ptr(struct otx2_nic *pfvf, int type);
int otx2_config_nix(struct otx2_nic *pfvf);
int otx2_config_nix_queues(struct otx2_nic *pfvf);
int otx2_txschq_config(struct otx2_nic *pfvf, int lvl);
int otx2_txsch_alloc(struct otx2_nic *pfvf);
int otx2_txschq_stop(struct otx2_nic *pfvf);
dma_addr_t otx2_alloc_rbuf(struct otx2_nic *pfvf, struct otx2_pool *pool,
			   gfp_t gfp);
int otx2_rxtx_enable(struct otx2_nic *pfvf, bool enable);
void otx2_ctx_disable(struct mbox *mbox, int type, bool npa);
int otx2_nix_config_bp(struct otx2_nic *pfvf, bool enable);

int otx2_napi_handler(struct otx2_cq_queue *cq,
		      struct otx2_nic *pfvf, int budget);

/* RSS configuration APIs*/
int otx2_rss_init(struct otx2_nic *pfvf);
int otx2_set_flowkey_cfg(struct otx2_nic *pfvf);
void otx2_set_rss_key(struct otx2_nic *pfvf);
int otx2_set_rss_table(struct otx2_nic *pfvf);

/* Mbox handlers */
void mbox_handler_msix_offset(struct otx2_nic *pfvf,
			      struct msix_offset_rsp *rsp);
void mbox_handler_npa_lf_alloc(struct otx2_nic *pfvf,
			       struct npa_lf_alloc_rsp *rsp);
void mbox_handler_nix_lf_alloc(struct otx2_nic *pfvf,
			       struct nix_lf_alloc_rsp *rsp);
void mbox_handler_nix_txsch_alloc(struct otx2_nic *pf,
				  struct nix_txsch_alloc_rsp *rsp);
void mbox_handler_cgx_stats(struct otx2_nic *pfvf,
			    struct cgx_stats_rsp *rsp);
void mbox_handler_nix_bp_enable(struct otx2_nic *pfvf,
				struct nix_bp_cfg_rsp *rsp);

/* Device stats APIs */
void otx2_get_dev_stats(struct otx2_nic *pfvf);
void otx2_get_stats64(struct net_device *netdev,
		      struct rtnl_link_stats64 *stats);
void otx2_update_lmac_stats(struct otx2_nic *pfvf);
int otx2_update_rq_stats(struct otx2_nic *pfvf, int qidx);
int otx2_update_sq_stats(struct otx2_nic *pfvf, int qidx);
void otx2_set_ethtool_ops(struct net_device *netdev);
void otx2vf_set_ethtool_ops(struct net_device *netdev);
int otx2_install_rxvlan_offload_flow(struct otx2_nic *pfvf);
int otx2_delete_rxvlan_offload_flow(struct otx2_nic *pfvf);
int otx2_destroy_ethtool_flows(struct otx2_nic *pfvf);

int otx2_open(struct net_device *netdev);
int otx2_stop(struct net_device *netdev);
int otx2_set_real_num_queues(struct net_device *netdev,
			     int tx_queues, int rx_queues);
#endif /* OTX2_COMMON_H */
