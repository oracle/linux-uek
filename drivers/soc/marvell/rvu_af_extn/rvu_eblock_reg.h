/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF driver - extension block registers
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef __RVU_EBLOCK_REG_H__
#define __RVU_EBLOCK_REG_H__

/* ML AF block registers */
#define ML_PRIV_AF_CFG		      (0x10188ull)
#define ML_AF_BLK_RST		      (0x101E0ull)
#define ML_AF_LF_RST		      (0x101E8ull)
#define ML_AF_RVU_LF_CFG_DEBUG	      (0x101F8ull)
#define ML_AF_CONST		      (0x10208ull)
#define ML_AF_PIDX_LF_ALLOW(a)        (0x10240ull | (uint64_t)(a) << 3)
#define ML_PRIV_LFX_CFG               (0x10800ull)
#define ML_PRIV_LFX_INT_CFG           (0x10C00ull)

#endif /* __RVU_EBLOCK_REG_H__ */
