/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OTX2_CPT_COMMON_H
#define __OTX2_CPT_COMMON_H

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include "otx2_cpt_hw_types.h"
#include "rvu.h"

#define OTX2_CPT_MAX_VFS_NUM 128
#define OTX2_CPT_MAX_LFS_NUM 64

#define OTX2_CPT_RVU_PFFUNC(pf, func)	\
	((((pf) & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT) | \
	(((func) & RVU_PFVF_FUNC_MASK) << RVU_PFVF_FUNC_SHIFT))

#define OTX2_CPT_RVU_FUNC_ADDR_S(blk, slot, offs) \
		((blk << 20) | (slot << 12) | offs)

#define OTX2_CPT_DMA_MINALIGN 128
#define OTX2_CPT_INVALID_CRYPTO_ENG_GRP 0xFF

#define OTX2_CPT_NAME_LENGTH 64

#define BAD_OTX2_CPT_ENG_TYPE OTX2_CPT_MAX_ENG_TYPES

enum otx2_cpt_eng_type {
	OTX2_CPT_AE_TYPES = 1,
	OTX2_CPT_SE_TYPES = 2,
	OTX2_CPT_IE_TYPES = 3,
	OTX2_CPT_MAX_ENG_TYPES,
};

static inline void otx2_cpt_write64(void __iomem *reg_base, u64 blk, u64 slot,
				    u64 offs, u64 val)
{
	writeq_relaxed(val, reg_base +
		       OTX2_CPT_RVU_FUNC_ADDR_S(blk, slot, offs));
}

static inline u64 otx2_cpt_read64(void __iomem *reg_base, u64 blk, u64 slot,
				  u64 offs)
{
	return readq_relaxed(reg_base +
			     OTX2_CPT_RVU_FUNC_ADDR_S(blk, slot, offs));
}
#endif /* __OTX2_CPT_COMMON_H */
