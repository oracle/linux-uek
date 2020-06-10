/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_COMMON_H
#define __CPT9X_COMMON_H

#include "rvu.h"

#define CPT_9X_MAX_VFS_NUM		128
#define CPT_9X_MAX_LFS_NUM		64

#define RVU_PFFUNC(pf, func)	\
	((((pf) & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT) | \
	(((func) & RVU_PFVF_FUNC_MASK) << RVU_PFVF_FUNC_SHIFT))


#define RVU_FUNC_ADDR_S(blk, slot, offs) ((blk << 20) | (slot << 12) | offs)

static inline void cpt_write64(void __iomem *reg_base, u64 blk, u64 slot,
			       u64 offs, u64 val)
{
	writeq_relaxed(val, reg_base + RVU_FUNC_ADDR_S(blk, slot, offs));
}

static inline u64 cpt_read64(void __iomem *reg_base, u64 blk, u64 slot,
			     u64 offs)
{
	return readq_relaxed(reg_base + RVU_FUNC_ADDR_S(blk, slot, offs));
}

u8 cpt_get_blkaddr(struct pci_dev *pdev);

#endif /* __CPT9X_COMMON_H */
