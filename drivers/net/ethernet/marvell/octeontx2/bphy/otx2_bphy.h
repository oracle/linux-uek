/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _OTX2_BPHY_H_
#define _OTX2_BPHY_H_

#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/iommu.h>

#include "bphy_common.h"
#include "rfoe_bphy_netdev_comm_if.h"
#include "cnf10k_bphy_netdev_comm_if.h"

#define DEVICE_NAME		"otx2_rfoe"
#define DRV_NAME		"octeontx2-bphy-netdev"
#define DRV_STRING		"Marvell OcteonTX2 BPHY Ethernet Driver"

/* char device ioctl numbers */
#define OTX2_RFOE_IOCTL_BASE		0xCC	/* Temporary */
#define OTX2_RFOE_IOCTL_ODP_INTF_CFG	_IOW(OTX2_RFOE_IOCTL_BASE, 0x01, \
					     struct bphy_netdev_comm_intf_cfg)
#define OTX2_RFOE_IOCTL_ODP_DEINIT      _IO(OTX2_RFOE_IOCTL_BASE, 0x02)
#define OTX2_RFOE_IOCTL_RX_IND_CFG	_IOWR(OTX2_RFOE_IOCTL_BASE, 0x03, \
					      struct otx2_rfoe_rx_ind_cfg)
#define OTX2_RFOE_IOCTL_PTP_OFFSET	_IOW(OTX2_RFOE_IOCTL_BASE, 0x04, \
					    struct ptp_clk_cfg)
#define OTX2_RFOE_IOCTL_SEC_BCN_OFFSET	_IOW(OTX2_RFOE_IOCTL_BASE, 0x05, \
					     struct bcn_sec_offset_cfg)
#define OTX2_RFOE_IOCTL_MODE_CPRI	_IOW(OTX2_RFOE_IOCTL_BASE, 0x06, \
					     int)
#define OTX2_RFOE_IOCTL_LINK_EVENT	_IOW(OTX2_RFOE_IOCTL_BASE, 0x07, \
					     struct otx2_rfoe_link_event)
#define OTX2_CPRI_IOCTL_LINK_EVENT	_IOW(OTX2_RFOE_IOCTL_BASE, 0x08, \
					     struct otx2_cpri_link_event)
#define OTX2_IOCTL_RFOE_10x_CFG		_IOW(OTX2_RFOE_IOCTL_BASE, 0x0A, \
					     uint64_t)
#define OTX2_IOCTL_CPRI_INTF_CFG	_IOW(OTX2_RFOE_IOCTL_BASE, 0x0B, \
					     uint64_t)
#define OTX2_IOCTL_PTP_CLK_SRC		_IOW(OTX2_RFOE_IOCTL_BASE, 0x0C, \
					     struct ptp_clk_src_cfg)

//#define ASIM		/* ASIM environment */

#define OTX2_BPHY_MHAB_INST		3

int bcn_ptp_sync(int ptp_phc_idx);
s64 bcn_ptp_delta(int ptp_phc_idx);
int bcn_ptp_start(void);

/* char driver private data */
struct otx2_bphy_cdev_priv {
	struct device			*dev;
	struct cdev			cdev;
	dev_t				devt;
	int				is_open;
	int				odp_intf_cfg;
	int				irq;
	struct mutex			mutex_lock;	/* mutex */
	spinlock_t			lock;		/* irq lock */
	spinlock_t			mbt_lock;	/* mbt ind lock */
	u8				mhab_mode[BPHY_MAX_RFOE_MHAB];
	/* cnf10k specific information */
	u32				hw_version;
	u8				num_rfoe_mhab;
	u8				num_rfoe_lmac;
	u8				tot_rfoe_intf;
	int				gpint2_irq;
#define ODP_INTF_CFG_RFOE		BIT(0)
#define ODP_INTF_CFG_CPRI		BIT(1)
	u32				flags;
};

#endif
