/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF driver - extension block registers
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef __RVU_EBLOCK_REG_H__
#define __RVU_EBLOCK_REG_H__

/* Number of scratch registers */
#define ML_SCRATCH_NR 2048

/* Number of ANB registers */
#define ML_ANBX_NR 0x3

/* ML AF block registers */
#define ML_AF_CFG		      (0x10000ull)
#define ML_AF_MLR_BASE		      (0x10008ull)
#define ML_AF_AXI_BRIDGE_CTRLX(a)     (0x10020ull | (uint64_t)(a) << 3)
#define ML_AF_JOB_MGR_CTRL	      (0x10060ull)
#define ML_AF_CORE_INT_LO	      (0x10088ull)
#define ML_AF_CORE_INT_LO_ENA_W1C     (0x10098ull)
#define ML_AF_CORE_INT_LO_ENA_W1S     (0x100A0ull)
#define ML_AF_CORE_INT_HI	      (0x100A8ull)
#define ML_AF_CORE_INT_HI_ENA_W1C     (0x100B8ull)
#define ML_AF_CORE_INT_HI_ENA_W1S     (0x100C0ull)
#define ML_AF_WRAP_ERR_INT	      (0x100C8ull)
#define ML_AF_WRAP_ERR_INT_ENA_W1C    (0x100D8ull)
#define ML_AF_WRAP_ERR_INT_ENA_W1S    (0x100E0ull)
#define ML_PRIV_AF_CFG		      (0x10188ull)
#define ML_PRIV_AF_INT_CFG	      (0x10190ull)
#define ML_AF_RVU_INT		      (0x101C0ull)
#define ML_AF_RVU_INT_ENA_W1S	      (0x101D0ull)
#define ML_AF_RVU_INT_ENA_W1C	      (0x101D8ull)
#define ML_AF_BLK_RST		      (0x101E0ull)
#define ML_AF_LF_RST		      (0x101E8ull)
#define ML_AF_RVU_LF_CFG_DEBUG	      (0x101F8ull)
#define ML_AF_CONST		      (0x10208ull)
#define ML_AF_MLR_SIZE		      (0x10268ull)
#define ML_AF_PIDX_LF_ALLOW(a)        (0x10240ull | (uint64_t)(a) << 3)
#define ML_PRIV_LFX_CFG               (0x10800ull)
#define ML_PRIV_LFX_INT_CFG           (0x10C00ull)
#define ML_AF_SCRATCHX(a)	      (0x14000ull | (uint64_t)(a) << 3)
#define ML_AF_ANBX_BACKP_DISABLE(a)   (0x18000ull | (uint64_t)(a) << 12)
#define ML_AF_ANBX_NCBI_P_OVR(a)      (0x18010ull | (uint64_t)(a) << 12)
#define ML_AF_ANBX_NCBI_NP_OVR(a)     (0x18020ull | (uint64_t)(a) << 12)

/* ML interrupt and error masks */
#define ML_AF_CORE_INT_LO_INT_LO	     BIT_ULL(0)
#define ML_AF_CORE_INT_HI_INT_HI	     BIT_ULL(0)
#define ML_AF_WRAP_ERR_INT_JCEQ_P0_OVFL	     BIT_ULL(0)
#define ML_AF_WRAP_ERR_INT_JCEQ_P1_OVFL	     BIT_ULL(1)
#define ML_AF_WRAP_ERR_INT_JCEQ_P2_OVFL	     BIT_ULL(2)
#define ML_AF_WRAP_ERR_INT_JCEQ_P3_OVFL	     BIT_ULL(3)
#define ML_AF_WRAP_ERR_INT_ACC_RADDR_ERR     BIT_ULL(4)
#define ML_AF_WRAP_ERR_INT_ACC_WADDR_ERR     BIT_ULL(5)
#define ML_AF_WRAP_ERR_INT_ACC_NCB_RRESP_ERR BIT_ULL(6)
#define ML_AF_WRAP_ERR_INT_ACC_NCB_WRESP_ERR BIT_ULL(7)
#define ML_AF_WRAP_ERR_INT_ACC_CSR_RRESP_ERR BIT_ULL(8)
#define ML_AF_WRAP_ERR_INT_ACC_CSR_WRESP_ERR BIT_ULL(9)
#define ML_AF_WRAP_ERR_INT_DMA_RADDR_ERR     BIT_ULL(16)
#define ML_AF_WRAP_ERR_INT_DMA_WADDR_ERR     BIT_ULL(17)
#define ML_AF_WRAP_ERR_INT_DMA_NCB_RRESP_ERR BIT_ULL(18)
#define ML_AF_WRAP_ERR_INT_DMA_NCB_WRESP_ERR BIT_ULL(19)
#define ML_AF_WRAP_ERR_INT_DMA_CSR_RRESP_ERR BIT_ULL(20)
#define ML_AF_WRAP_ERR_INT_DMA_CSR_WRESP_ERR BIT_ULL(21)
#define ML_AF_RVU_INT_UNMAPPED_SLOT	     BIT_ULL(0)

/* ML AF interrupt vector enumeration */
enum ml_af_int_vec_e {
	ML_AF_INT_VEC_CORE_INT_LO	= 0x0,
	ML_AF_INT_VEC_CORE_INT_HI	= 0x1,
	ML_AF_INT_VEC_WRAP_ERR_INT	= 0x2,
	ML_AF_INT_VEC_RVU_INT		= 0x3,
	ML_AF_INT_VEC_CNT		= 0x4,
};

#endif /* __RVU_EBLOCK_REG_H__ */
