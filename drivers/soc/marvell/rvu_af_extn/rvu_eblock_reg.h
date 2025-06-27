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
#define ML_AF_LFX_JOB_IN_JMGR(a)      (0x10400ull | (uint64_t)(a) << 3)
#define ML_PRIV_LFX_CFG               (0x10800ull)
#define ML_AF_LFX_GMCTL(a)	      (0x10A00ull | (uint64_t)(a) << 3)
#define ML_PRIV_LFX_INT_CFG           (0x10C00ull)
#define ML_AF_LFX_MLR_BASE(a)	      (0x10E00ull | (uint64_t)(a) << 3)
#define ML_AF_LFX_MLR_SIZE(a)	      (0x11600ull | (uint64_t)(a) << 3)
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

/* PSW RVU registers */
#define PSW_AF_CONST0                   0x008ull
#define PSW_AF_CONST1                   0x010ull
#define PSW_AF_CONST2                   0x018ull
#define PSW_AF_MISC_CTRL                0x030ull
#define PSW_AF_INJECT_REQ               0x040ull
#define PSW_AF_INJECT_RW_DATA           0x048ull
#define PSW_AF_SCRATCH_ARRAY(a)         (0x060ull | (a) << 3)
#define PSW_AF_CCLK_PART0_ACTIVE_PC(a)  (0x100ull | (a) << 3)
#define PSW_AF_CLK_EN_PART0             0x150ull
#define PSW_PRIV_AF_INT_CFG             0x1000000ull
#define PSW_PRIV_AF_CFG                 0x1000008ull
#define PSW_PRIV_GEN_CFG                0x1000010ull
#define PSW_AF_BLK_RST                  0x1000018ull
#define PSW_AF_LF_RST                   0x1000020ull
#define PSW_AF_RVU_LF_CFG_DEBUG		0x1000028ull
#define PSW_PRIV_CONST			0x1000030ull
#define PSW_AF_MAP_CAPTURE              0x1000100ull
#define PSW_PRIV_LFX_INT_CFG            0x1000200ull
#define PSW_PRIV_LFX_CFG                0x1000400ull
#define PSW_AF_EPF_FLR_DONE_INT		0x1800000ull
#define PSW_AF_EPF_FLR_DONE_INT_W1S	0x1800008ull
#define PSW_AF_EPF_FLR_DONE_INT_ENA_W1C	0x1800010ull
#define PSW_AF_EPF_FLR_DONE_INT_ENA_W1S	0x1800018ull
#define PSW_AF_RAS_INT                  0x1800020ull
#define PSW_AF_RAS_INT_ENA_W1C          0x1800030ull
#define PSW_AF_RAS_INT_ENA_W1S          0x1800038ull
#define PSW_AF_RVU_INT                  0x1800040ull
#define PSW_AF_RVU_INT_ENA_W1C          0x1800050ull
#define PSW_AF_RVU_INT_ENA_W1S          0x1800058ull
#define PSW_AF_APINOTIF_INT             0x1800100ull
#define PSW_AF_APINOTIF_INT_ENA_W1C     0x1800110ull
#define PSW_AF_APINOTIF_INT_ENA_W1S     0x1800118ull
#define PSW_AF_GEN_INT                  0x1800200ull
#define PSW_AF_GEN_INT_ENA_W1C          0x1800210ull
#define PSW_AF_GEN_INT_ENA_W1S          0x1800218ull
#define PSW_AF_ECC_INT                  0x1800300ull
#define PSW_AF_ECC_INT_ENA_W1C          0x1800310ull
#define PSW_AF_ECC_INT_ENA_W1S          0x1800318ull
#define PSW_AF_EVFX_FLR_DONE_INT(a)          (0x1800400ull | ((a) << 3))
#define PSW_AF_EVFX_FLR_DONE_INT_ENA_W1C(a)  (0x1800C00ull | ((a) << 3))
#define PSW_AF_EVFX_FLR_DONE_INT_ENA_W1S(a)  (0x1801000ull | ((a) << 3))
#define PSW_AF_EPFX_LF_SHARED_BASE(a)        (0x2000000ull | ((a) << 3))
#define PSW_AF_EVF_EPFX_SHARED_BASE(a)       (0x2000100ull | ((a) << 3))
#define PSW_AF_EPFX_EVFX_LF_SHARED_BASE(a, b) (0x2008000ull | ((a) << 10) | \
					       ((b) << 3))
#define PSW_AF_FID_TYPEX_CONST(a)           (0x3000000ull | (a) << 3)
#define PSW_AF_FID_RSP_WRR                  0x3000060ull
#define PSW_AF_FID_NOMATCH_CAPTURE          0x3000070ull
#define PSW_AF_FID_ATTR(a)                  (0x3004000ull | ((a) << 3))
#define PSW_AF_FID_BASE(a)                  (0x3008000ull | ((a) << 3))
#define PSW_AF_FID_IND(a)                   (0x300C000ull | ((a) << 3))
#define PSW_AF_EPFX_MAP(a)                  (0x3020000ull | ((a) << 3))
#define PSW_AF_EPFX_EVFX_MAP(a, b)          (0x3030000ull | ((a) << 10) | \
					     ((b) << 3))
#define PSW_AF_GID_PARAM                    0x4000008ull
#define PSW_AF_GID_ERR_CAPTURE              0x4000020ull
#define PSW_AF_GID_BUCKET(a)                (0x4080000ull | ((a) << 3))
#define PSW_AF_GID_ENTRY0(a)                (0x4100000ull | ((a) << 4))
#define PSW_AF_GID_ENTRY1(a)                (0x4100008ull | ((a) << 4))
#define PSW_AF_GID_ENTRY0_W                 0x4200000ull
#define PSW_AF_GID_ENTRY1_W                 0x4200008ull
#define PSW_AF_GID_BUCKET_RESULT            0x4200010ull
#define PSW_AF_GID_ENTRY_RESULT0            0x4200018ull
#define PSW_AF_GID_ENTRY_RESULT1            0x4200020ull
#define PSW_AF_GID_LU                       0x4200028ull
#define PSW_AF_PFX_PIDBL_CFG(a)             (0x5200000ull | ((a) << 3))
#define PSW_AF_PFX_CIDBL_CFG(a)             (0x5200100ull | ((a) << 3))
#define PSW_AF_DBL_TO_TH(a)                 (0x5200200ull | ((a) << 3))
#define PSW_AF_DBL_WIN(a)                   (0x5200400ull | ((a) << 3))
#define PSW_AF_CIDBL_BP_ATTR                0x5200600ull
#define PSW_AF_HO_QE_CAPTURE                0x5200610ull
#define PSW_AF_SHO_QE_CAPTURE               0x5200620ull
#define PSW_AF_NQE_CAPTURE                  0x5200630ull
#define PSW_AF_HOQ_QOS_WRR                  0x5200640ull
#define PSW_AF_HI_QE_CAPTURE                0x6200000ull
#define PSW_AF_SHI_QE_CAPTURE               0x6200010ull
#define PSW_AF_AQE_CAPTURE                  0x6200020ull
#define PSW_AF_ACKQ_WM                      0x6200030ull
#define PSW_AF_ACKQ_WRR                     0x6200040ull
#define PSW_AF_EPFX_PCIE_CFG(a)             (0x70C0000ull | ((a) << 3))
#define PSW_AF_EPFX_EVFX_PCIE_CFG(a, b)     (0x70D0000ull | ((a) << 10) | \
					     ((b) << 3))
#define PSW_AF_MSIX_VEC_STAT(a)             (0x7400000ull | ((a) << 3))
#define PSW_AF_MSIX_VECX_EPF_FUNC(a)        (0x7800000ull | ((a) << 3))
#define PSW_AF_API_NOTIF_QC(a)              (0x8000000ull | ((a) << 3))
#define PSW_AF_API_TO_TH                    0x8000100ull
#define PSW_AF_API_NQE_CAPTURE              0x8000110ull
#define PSW_AF_API_AQE_CAPTURE              0x8000120ull
#define PSW_AF_TIMER_TICK_CFG               0xA000000ull
#define PSW_AF_TICK_CNT                     0xA000008ull
#define PSW_AF_TPS_PAUSE                    0xA000010ull
#define PSW_AF_TIMER_PROFILE_TBL(a)         (0xA000200ull | ((a) << 3))
#define PSW_AF_PST_BASE_ADDR                0xA000400ull
#define PSW_AF_TIMED_POLLING_DRIFT          0xA000408ull
#define PSW_AF_TIMED_POLLING_CFG            0xA000410ull
#define PSW_AF_TIMED_ERR_CAPTURE            0xA000420ull
#define PSW_AF_TIMER_SEL_TBL(a)             (0xA010000ull | ((a) << 3))
#define PSW_AF_LF_MBOX_EPFX_DATAX(a, b)     (0xB000000ull | ((a) << 4) | \
					     ((b) << 3))
#define PSW_AF_LF_MBOX_EPFX_EVFX_DATAX(a, b, c) (0xB100000ull | ((a) << 11) | \
						 ((b) << 4) | ((c) << 3))
#define PSW_AF_LF_EPFX_MBOX_MSIX(a)         (0xB200000ull | ((a) << 3))
#define PSW_AF_LF_EPFX_EVFX_MBOX_MSIX(a, b) (0xB300000ull | ((a) << 10) | \
					     ((b) << 3))
#define PSW_AF_NCB_ATTR                     0xC000000ull
#define PSW_AF_LFX_NCB_ATTR(a)              (0xC000200ull | ((a) << 3))
#define PSW_AF_CCLK_PART1_ACTIVE_PC(a)      (0xC000400ull | ((a) << 3))
#define PSW_AF_CLK_EN_PART1                 0xC000450ull

/* ML AF interrupt vector enumeration */
enum ml_af_int_vec_e {
	ML_AF_INT_VEC_CORE_INT_LO	= 0x0,
	ML_AF_INT_VEC_CORE_INT_HI	= 0x1,
	ML_AF_INT_VEC_WRAP_ERR_INT	= 0x2,
	ML_AF_INT_VEC_RVU_INT		= 0x3,
	ML_AF_INT_VEC_CNT		= 0x4,
};

#endif /* __RVU_EBLOCK_REG_H__ */
