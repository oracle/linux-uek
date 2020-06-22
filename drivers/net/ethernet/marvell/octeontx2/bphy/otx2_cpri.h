/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _OTX2_CPRI_H_
#define _OTX2_CPRI_H_

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>

#include "otx2_bphy.h"
#include "otx2_bphy_hw.h"
#include "rfoe_bphy_netdev_comm_if.h"

#define OTX2_BPHY_CPRI_MAX_MHAB		3
#define OTX2_BPHY_CPRI_MAX_LMAC		4
#define OTX2_BPHY_CPRI_MAX_INTF		10

#define OTX2_BPHY_CPRI_PKT_BUF_SIZE	1664	/* wqe 128 bytes + 1536 bytes */
#define OTX2_BPHY_CPRI_WQE_SIZE		128

#define CPRI_RX_INTR_MASK(a)		((1UL << (a)) << 13)
#define CPRI_RX_INTR_SHIFT(a)		(13 + (a))

/* Each entry increments by cnt 0x68, 1 unit = 16 bytes */
#define CIRC_BUF_ENTRY(a)		((a) / 0x68)

enum cpri_state {
	CPRI_INTF_DOWN = 1,
};

/* CPRI support */
struct otx2_cpri_drv_ctx {
	u8				cpri_num;
	u8				lmac_id;
	int				valid;
	struct net_device               *netdev;
	int				netdev_registered;
};

extern struct otx2_cpri_drv_ctx cpri_drv_ctx[OTX2_BPHY_CPRI_MAX_INTF];

struct otx2_cpri_stats {
	/* Rx */
	u64				rx_frames;
	u64				rx_octets;
	u64				rx_err;
	u64				bad_crc;
	u64				oversize;
	u64				undersize;
	u64				fifo_ovr;
	u64				rx_dropped;
	/* Tx */
	u64				tx_frames;
	u64				tx_octets;
	u64				tx_dropped;
	/* stats lock */
	spinlock_t			lock;
};

/* cpri dl cbuf cfg */
struct dl_cbuf_cfg {
	int				num_entries;
	u64				cbuf_iova_addr;
	void __iomem			*cbuf_virt_addr;
	/* sw */
	u64				sw_wr_ptr;
	/* dl lock */
	spinlock_t			lock;
};

/* cpri ul cbuf cfg */
struct ul_cbuf_cfg {
	int				num_entries;
	u64				cbuf_iova_addr;
	void __iomem			*cbuf_virt_addr;
	/* sw */
	int				sw_rd_ptr;
	/* ul lock */
	spinlock_t			lock;
};

struct cpri_common_cfg {
	struct dl_cbuf_cfg		dl_cfg;
	struct ul_cbuf_cfg		ul_cfg;
};

/* cpri netdev priv */
struct otx2_cpri_ndev_priv {
	u8				cpri_num;
	u8				lmac_id;
	struct net_device		*netdev;
	struct pci_dev			*pdev;
	struct otx2_bphy_cdev_priv	*cdev_priv;
	u32				msg_enable;
	void __iomem			*bphy_reg_base;
	void __iomem			*cpri_reg_base;
	struct iommu_domain		*iommu_domain;
	struct cpri_common_cfg		*cpri_common;
	struct napi_struct		napi;
	unsigned long			state;
	struct otx2_cpri_stats		stats;
	u8				mac_addr[ETH_ALEN];
	/* priv lock */
	spinlock_t			lock;
};

int otx2_cpri_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				  struct bphy_netdev_comm_intf_cfg *cfg);

void otx2_cpri_rx_napi_schedule(int cpri_num, u32 status);

void otx2_cpri_update_stats(struct otx2_cpri_ndev_priv *priv);

void otx2_bphy_cpri_cleanup(void);

/* ethtool */
void otx2_cpri_set_ethtool_ops(struct net_device *netdev);

#endif
