/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPT_COMMON_H
#define __CN10K_CPT_COMMON_H

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include "cn10k_cpt_hw_types.h"
#include "rvu.h"

#define CN10K_CPT_MAX_VFS_NUM 128
#define CN10K_CPT_MAX_LFS_NUM 64

#define CN10K_CPT_RVU_PFFUNC(pf, func)	\
	((((pf) & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT) | \
	(((func) & RVU_PFVF_FUNC_MASK) << RVU_PFVF_FUNC_SHIFT))

#define CN10K_CPT_RVU_FUNC_ADDR_S(blk, slot, offs) \
		(((blk) << 20) | ((slot) << 12) | (offs))

#define CN10K_CPT_DMA_MINALIGN 128
#define CN10K_CPT_INVALID_CRYPTO_ENG_GRP 0xFF

#define CN10K_CPT_NAME_LENGTH 64

#define BAD_CN10K_CPT_ENG_TYPE CN10K_CPT_MAX_ENG_TYPES

enum cn10k_cpt_eng_type {
	CN10K_CPT_AE_TYPES = 1,
	CN10K_CPT_SE_TYPES = 2,
	CN10K_CPT_IE_TYPES = 3,
	CN10K_CPT_MAX_ENG_TYPES,
};

static inline void cn10k_cpt_write64(void __iomem *reg_base, u64 blk, u64 slot,
				     u64 offs, u64 val)
{
	writeq_relaxed(val, reg_base +
		       CN10K_CPT_RVU_FUNC_ADDR_S(blk, slot, offs));
}

static inline u64 cn10k_cpt_read64(void __iomem *reg_base, u64 blk, u64 slot,
				   u64 offs)
{
	return readq_relaxed(reg_base +
			     CN10K_CPT_RVU_FUNC_ADDR_S(blk, slot, offs));
}
#endif /* __CN10K_CPT_COMMON_H */
