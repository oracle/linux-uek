/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell BPHY Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef _BPHY_COMMON_H_
#define _BPHY_COMMON_H_

/* BPHY definitions */
#define OTX2_BPHY_PCI_VENDOR_ID		0x177D
#define OTX2_BPHY_PCI_DEVICE_ID		0xA089

/* eCPRI ethertype */
#define ETH_P_ECPRI			0xAEFE

/* max ptp tx requests */
extern int max_ptp_req;

/* reg base address */
extern void __iomem *bphy_reg_base;
extern void __iomem *psm_reg_base;
extern void __iomem *rfoe_reg_base;
extern void __iomem *bcn_reg_base;
extern void __iomem *ptp_reg_base;
extern void __iomem *cpri_reg_base;

enum port_link_state {
	LINK_STATE_DOWN,
	LINK_STATE_UP,
};

/* iova to kernel virtual addr */
static inline void *otx2_iova_to_virt(struct iommu_domain *domain, u64 iova)
{
	return phys_to_virt(iommu_iova_to_phys(domain, iova));
}

#endif
