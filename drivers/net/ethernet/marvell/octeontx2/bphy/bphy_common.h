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

/* PSM register offsets */
#define PSM_QUEUE_CMD_LO(a)		(0x0 + (a) * 0x10)
#define PSM_QUEUE_CMD_HI(a)		(0x8 + (a) * 0x10)
#define PSM_QUEUE_CFG(a)		(0x1000 + (a) * 0x10)
#define PSM_QUEUE_PTR(a)		(0x2000 + (a) * 0x10)
#define PSM_QUEUE_SPACE(a)		(0x3000 + (a) * 0x10)
#define PSM_QUEUE_TIMEOUT_CFG(a)	(0x4000 + (a) * 0x10)
#define PSM_QUEUE_INFO(a)		(0x5000 + (a) * 0x10)
#define PSM_QUEUE_ENA_W1S(a)		(0x10000 + (a) * 0x8)
#define PSM_QUEUE_ENA_W1C(a)		(0x10100 + (a) * 0x8)
#define PSM_QUEUE_FULL_STS(a)		(0x10200 + (a) * 0x8)
#define PSM_QUEUE_BUSY_STS(a)		(0x10300 + (a) * 0x8)

/* BPHY PSM GPINT register offsets */
#define PSM_INT_GP_SUM_W1C(a)		(0x10E0000 + (a) * 0x100)
#define PSM_INT_GP_SUM_W1S(a)		(0x10E0040 + (a) * 0x100)
#define PSM_INT_GP_ENA_W1C(a)		(0x10E0080 + (a) * 0x100)
#define PSM_INT_GP_ENA_W1S(a)		(0x10E00C0 + (a) * 0x100)

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
