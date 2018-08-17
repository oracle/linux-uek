// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Physcial Function ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_REG_H
#define OTX2_REG_H

#include <rvu_struct.h>

/* RVU PF registers */
#define	RVU_PF_VFX_PFVF_MBOX0		    (0x00000)
#define	RVU_PF_VFX_PFVF_MBOX1		    (0x00008)
#define RVU_PF_VFX_PFVF_MBOXX(a, b)         (0x0 | (a) << 12 | (b) << 3)
#define RVU_PF_VF_BAR4_ADDR                 (0x10)
#define RVU_PF_BLOCK_ADDRX_DISC(a)          (0x200 | (a) << 3)
#define RVU_PF_VFME_STATUSX(a)              (0x800 | (a) << 3)
#define RVU_PF_VFTRPENDX(a)                 (0x820 | (a) << 3)
#define RVU_PF_VFTRPEND_W1SX(a)             (0x840 | (a) << 3)
#define RVU_PF_VFPF_MBOX_INTX(a)            (0x880 | (a) << 3)
#define RVU_PF_VFPF_MBOX_INT_W1SX(a)        (0x8A0 | (a) << 3)
#define RVU_PF_VFPF_MBOX_INT_ENA_W1SX(a)    (0x8C0 | (a) << 3)
#define RVU_PF_VFPF_MBOX_INT_ENA_W1CX(a)    (0x8E0 | (a) << 3)
#define RVU_PF_VFFLR_INTX(a)                (0x900 | (a) << 3)
#define RVU_PF_VFFLR_INT_W1SX(a)            (0x920 | (a) << 3)
#define RVU_PF_VFFLR_INT_ENA_W1SX(a)        (0x940 | (a) << 3)
#define RVU_PF_VFFLR_INT_ENA_W1CX(a)        (0x960 | (a) << 3)
#define RVU_PF_VFME_INTX(a)                 (0x980 | (a) << 3)
#define RVU_PF_VFME_INT_W1SX(a)             (0x9A0 | (a) << 3)
#define RVU_PF_VFME_INT_ENA_W1SX(a)         (0x9C0 | (a) << 3)
#define RVU_PF_VFME_INT_ENA_W1CX(a)         (0x9E0 | (a) << 3)
#define RVU_PF_PFAF_MBOX0                   (0xC00)
#define RVU_PF_PFAF_MBOX1                   (0xC08)
#define RVU_PF_PFAF_MBOXX(a)                (0xC00 | (a) << 3)
#define RVU_PF_INT                          (0xc20)
#define RVU_PF_INT_W1S                      (0xc28)
#define RVU_PF_INT_ENA_W1S                  (0xc30)
#define RVU_PF_INT_ENA_W1C                  (0xc38)
#define RVU_PF_MSIX_VECX_ADDR(a)            (0x000 | (a) << 4)
#define RVU_PF_MSIX_VECX_CTL(a)             (0x008 | (a) << 4)
#define RVU_PF_MSIX_PBAX(a)                 (0xF0000 | (a) << 3)

/* RVU VF registers */
#define	RVU_VF_VFPF_MBOX0		    (0x00000)
#define	RVU_VF_VFPF_MBOX1		    (0x00008)
#define RVU_VF_VFPF_MBOXX(a)                (0x00 | (a) << 3)
#define RVU_VF_INT                          (0x20)
#define RVU_VF_INT_W1S                      (0x28)
#define RVU_VF_INT_ENA_W1S                  (0x30)
#define RVU_VF_INT_ENA_W1C                  (0x38)
#define RVU_VF_BLOCK_ADDRX_DISC(a)          (0x200 | (a) << 3)
#define RVU_VF_MSIX_VECX_ADDR(a)            (0x000 | (a) << 4)
#define RVU_VF_MSIX_VECX_CTL(a)             (0x008 | (a) << 4)
#define RVU_VF_MSIX_PBAX(a)                 (0xF0000 | (a) << 3)

/* NPA LF registers */
#define NPA_LFBASE			(BLKADDR_NPA << 20)
#define NPA_LF_AURA_OP_ALLOCX(a)	(NPA_LFBASE | 0x10 | (a) << 3)
#define NPA_LF_AURA_OP_FREE0            (NPA_LFBASE | 0x20)
#define NPA_LF_AURA_OP_FREE1            (NPA_LFBASE | 0x28)
#define NPA_LF_AURA_OP_CNT              (NPA_LFBASE | 0x30)
#define NPA_LF_AURA_OP_LIMIT            (NPA_LFBASE | 0x50)
#define NPA_LF_AURA_OP_INT              (NPA_LFBASE | 0x60)
#define NPA_LF_AURA_OP_THRESH           (NPA_LFBASE | 0x70)
#define NPA_LF_POOL_OP_PC               (NPA_LFBASE | 0x100)
#define NPA_LF_POOL_OP_AVAILABLE        (NPA_LFBASE | 0x110)
#define NPA_LF_POOL_OP_PTR_START0       (NPA_LFBASE | 0x120)
#define NPA_LF_POOL_OP_PTR_START1       (NPA_LFBASE | 0x128)
#define NPA_LF_POOL_OP_PTR_END0         (NPA_LFBASE | 0x130)
#define NPA_LF_POOL_OP_PTR_END1         (NPA_LFBASE | 0x138)
#define NPA_LF_POOL_OP_INT              (NPA_LFBASE | 0x160)
#define NPA_LF_POOL_OP_THRESH           (NPA_LFBASE | 0x170)
#define NPA_LF_ERR_INT                  (NPA_LFBASE | 0x200)
#define NPA_LF_ERR_INT_W1S              (NPA_LFBASE | 0x208)
#define NPA_LF_ERR_INT_ENA_W1C          (NPA_LFBASE | 0x210)
#define NPA_LF_ERR_INT_ENA_W1S          (NPA_LFBASE | 0x218)
#define NPA_LF_RAS                      (NPA_LFBASE | 0x220)
#define NPA_LF_RAS_W1S                  (NPA_LFBASE | 0x228)
#define NPA_LF_RAS_ENA_W1C              (NPA_LFBASE | 0x230)
#define NPA_LF_RAS_ENA_W1S              (NPA_LFBASE | 0x238)
#define NPA_LF_QINTX_CNT(a)             (NPA_LFBASE | 0x300 | (a) << 12)
#define NPA_LF_QINTX_INT(a)             (NPA_LFBASE | 0x310 | (a) << 12)
#define NPA_LF_QINTX_INT_W1S(a)         (NPA_LFBASE | 0x318 | (a) << 12)
#define NPA_LF_QINTX_ENA_W1S(a)         (NPA_LFBASE | 0x320 | (a) << 12)
#define NPA_LF_QINTX_ENA_W1C(a)         (NPA_LFBASE | 0x330 | (a) << 12)

/* NIX AF transmit scheduler registers */
#define NIX_AF_SMQX_CFG(a)		(0x700 | (a) << 16)
#define NIX_AF_TL1X_SCHEDULE(a)		(0xC00 | (a) << 16)
#define NIX_AF_TL1X_CIR(a)		(0xC20 | (a) << 16)
#define NIX_AF_TL1X_TOPOLOGY(a)		(0xC80 | (a) << 16)
#define NIX_AF_TL2X_PARENT(a)		(0xE88 | (a) << 16)
#define NIX_AF_TL3X_PARENT(a)		(0x1088 | (a) << 16)
#define NIX_AF_TL4X_PARENT(a)		(0x1288 | (a) << 16)
#define NIX_AF_MDQX_SCHEDULE(a)		(0x1400 | (a) << 16)
#define NIX_AF_MDQX_PARENT(a)		(0x1480 | (a) << 16)
#define NIX_AF_TL3_TL2X_LINKX_CFG(a, b)	(0x1700 | (a) << 16 | (b) << 3)

#endif /* OTX2_REG_H */
