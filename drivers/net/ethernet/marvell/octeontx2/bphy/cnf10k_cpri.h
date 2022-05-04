/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _CNF10K_CPRI_H_
#define _CNF10K_CPRI_H_

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>

#include "otx2_bphy.h"
#include "cnf10k_bphy_hw.h"
#include "cnf10k_bphy_netdev_comm_if.h"

#define CNF10K_BPHY_CPRI_MAX_MHAB		3
#define CNF10K_BPHY_CPRI_MAX_LMAC		4
#define CNF10K_BPHY_CPRI_MAX_INTF		12
#define CNF10K_BPHY_CPRI_PKT_BUF_SIZE		1664	/* wqe 128 bytes + 1536 bytes */
#define CNF10K_BPHY_CPRI_WQE_SIZE		128

#define CNF10K_CPRI_RX_INTR_MASK(a)		((1 << (a)) << 29)
#define CNF10K_CPRI_RX_INTR_SHIFT(a)		(29 + (a))

/* Each entry increments by cnt 0x68, 1 unit = 16 bytes */
#define CNF10K_CIRC_BUF_ENTRY(a)		((a) / 0x68)

enum cnf10k_cpri_state {
	CNF10K_CPRI_INTF_DOWN = 1,
};

/* CPRI support */
struct cnf10k_cpri_drv_ctx {
	u8				cpri_num;
	u8				lmac_id;
	int				valid;
	void				*debugfs;
	struct net_device               *netdev;
};

extern struct cnf10k_cpri_drv_ctx cnf10k_cpri_drv_ctx[CNF10K_BPHY_CPRI_MAX_INTF];

struct cnf10k_cpri_stats {
	/* Rx */
	u64				rx_frames;
	u64				rx_octets;
	u64				rx_err;
	u64				bad_crc;
	u64				oversize;
	u64				undersize;
	u64				fifo_ovr;
	u64				rx_dropped;
	u64				malformed;
	u64				rx_bad_octets;
	/* Tx */
	u64				tx_frames;
	u64				tx_octets;
	u64				tx_dropped;
	/* stats lock */
	spinlock_t			lock;
};

/* cpri dl cbuf cfg */
struct cnf10k_dl_cbuf_cfg {
	int				num_entries;
	u64				cbuf_iova_addr;
	void __iomem			*cbuf_virt_addr;
	/* sw */
	u64				sw_wr_ptr;
	/* dl lock */
	spinlock_t			lock;
};

/* cpri ul cbuf cfg */
struct cnf10k_ul_cbuf_cfg {
	int				num_entries;
	u64				cbuf_iova_addr;
	void __iomem			*cbuf_virt_addr;
	/* sw */
	int				sw_rd_ptr;
	/* ul lock */
	spinlock_t			lock;
};

struct cnf10k_cpri_common_cfg {
	struct cnf10k_dl_cbuf_cfg	dl_cfg;
	struct cnf10k_ul_cbuf_cfg	ul_cfg;
	u8				refcnt;
};

struct cnf10k_cpri_link_event {
	u8				cpri_num;
	u8				lmac_id;
	u8				link_state;
};

/* cpri netdev priv */
struct cnf10k_cpri_ndev_priv {
	u8				cpri_num;
	u8				lmac_id;
	struct net_device		*netdev;
	struct pci_dev			*pdev;
	struct otx2_bphy_cdev_priv	*cdev_priv;
	u32				msg_enable;
	void __iomem			*bphy_reg_base;
	void __iomem			*cpri_reg_base;
	struct iommu_domain		*iommu_domain;
	struct cnf10k_cpri_common_cfg	*cpri_common;
	struct napi_struct		napi;
	unsigned long			state;
	struct cnf10k_cpri_stats	stats;
	u8				mac_addr[ETH_ALEN];
	/* priv lock */
	spinlock_t			lock;
	int				if_type;
	u8				link_state;
	unsigned long			last_tx_jiffies;
	unsigned long			last_rx_jiffies;
	unsigned long			last_tx_dropped_jiffies;
	unsigned long			last_rx_dropped_jiffies;
};

int cnf10k_cpri_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				    struct cnf10k_bphy_cpri_netdev_comm_intf_cfg *cfg);

void cnf10k_cpri_rx_napi_schedule(int cpri_num, u32 status);

void cnf10k_cpri_update_stats(struct cnf10k_cpri_ndev_priv *priv);

void cnf10k_bphy_cpri_cleanup(void);

void cnf10k_cpri_enable_intf(int cpri_num);

/* ethtool */
void cnf10k_cpri_set_ethtool_ops(struct net_device *netdev);

/* update carrier state */
void cnf10k_cpri_set_link_state(struct net_device *netdev, u8 state);

#endif
