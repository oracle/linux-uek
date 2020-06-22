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

#include "otx2_bphy_hw.h"
#include "rfoe_bphy_netdev_comm_if.h"

/* max ptp tx requests */
extern int max_ptp_req;

/* reg base address */
extern void __iomem *bphy_reg_base;
extern void __iomem *psm_reg_base;
extern void __iomem *rfoe_reg_base;
extern void __iomem *bcn_reg_base;
extern void __iomem *ptp_reg_base;
extern void __iomem *cpri_reg_base;

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
#define OTX2_RFOE_IOCTL_PTP_OFFSET	_IO(OTX2_RFOE_IOCTL_BASE, 0x04)
#define OTX2_RFOE_IOCTL_SEC_BCN_OFFSET	_IOW(OTX2_RFOE_IOCTL_BASE, 0x05, \
					     struct bcn_sec_offset_cfg)

//#define ASIM		/* ASIM environment */

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
};

/* iova to kernel virtual addr */
static inline void *otx2_iova_to_virt(struct iommu_domain *domain, u64 iova)
{
	return phys_to_virt(iommu_iova_to_phys(domain, iova));
}

#endif
