/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OTX2_CPT_HW_TYPES_H
#define __OTX2_CPT_HW_TYPES_H

#include <linux/types.h>

/* Device IDs */
#define OTX2_CPT_PCI_PF_DEVICE_ID 0xa0FD
#define OTX2_CPT_PCI_VF_DEVICE_ID 0xa0FE

/* Mailbox interrupts offset */
#define OTX2_CPT_PF_MBOX_INT	6
#define OTX2_CPT_PF_INT_VEC_E_MBOXX(x, a) ((x) + (a))

/* Number of MSIX supported in PF */
#define	OTX2_CPT_PF_MSIX_VECTORS 7

/* Maximum supported microcode groups */
#define OTX2_CPT_MAX_ENGINE_GROUPS 8

/* CPT instruction size in bytes */
#define OTX2_CPT_INST_SIZE	64
/*
 * CPT VF MSIX vectors and their offsets
 */
#define	OTX2_CPT_VF_MSIX_VECTORS 1
#define OTX2_CPT_VF_INTR_MBOX_MASK BIT(0)

/* CPT LF MSIX vectors */
#define	OTX2_CPT_LF_MSIX_VECTORS 2

/* OcteonTX2 CPT PF registers */
#define OTX2_CPT_PF_CONSTANTS		(0x0ll)
#define OTX2_CPT_PF_RESET		(0x100ll)
#define OTX2_CPT_PF_DIAG		(0x120ll)
#define OTX2_CPT_PF_BIST_STATUS		(0x160ll)
#define OTX2_CPT_PF_ECC0_CTL		(0x200ll)
#define OTX2_CPT_PF_ECC0_FLIP		(0x210ll)
#define OTX2_CPT_PF_ECC0_INT		(0x220ll)
#define OTX2_CPT_PF_ECC0_INT_W1S	(0x230ll)
#define OTX2_CPT_PF_ECC0_ENA_W1S	(0x240ll)
#define OTX2_CPT_PF_ECC0_ENA_W1C	(0x250ll)
#define OTX2_CPT_PF_MBOX_INTX(b)	(0x400ll | (u64)(b) << 3)
#define OTX2_CPT_PF_MBOX_INT_W1SX(b)	(0x420ll | (u64)(b) << 3)
#define OTX2_CPT_PF_MBOX_ENA_W1CX(b)	(0x440ll | (u64)(b) << 3)
#define OTX2_CPT_PF_MBOX_ENA_W1SX(b)	(0x460ll | (u64)(b) << 3)
#define OTX2_CPT_PF_EXEC_INT		(0x500ll)
#define OTX2_CPT_PF_EXEC_INT_W1S	(0x520ll)
#define OTX2_CPT_PF_EXEC_ENA_W1C	(0x540ll)
#define OTX2_CPT_PF_EXEC_ENA_W1S	(0x560ll)
#define OTX2_CPT_PF_GX_EN(b)		(0x600ll | (u64)(b) << 3)
#define OTX2_CPT_PF_EXEC_INFO		(0x700ll)
#define OTX2_CPT_PF_EXEC_BUSY		(0x800ll)
#define OTX2_CPT_PF_EXEC_INFO0		(0x900ll)
#define OTX2_CPT_PF_EXEC_INFO1		(0x910ll)
#define OTX2_CPT_PF_INST_REQ_PC		(0x10000ll)
#define OTX2_CPT_PF_INST_LATENCY_PC	(0x10020ll)
#define OTX2_CPT_PF_RD_REQ_PC		(0x10040ll)
#define OTX2_CPT_PF_RD_LATENCY_PC	(0x10060ll)
#define OTX2_CPT_PF_RD_UC_PC		(0x10080ll)
#define OTX2_CPT_PF_ACTIVE_CYCLES_PC	(0x10100ll)
#define OTX2_CPT_PF_EXE_CTL		(0x4000000ll)
#define OTX2_CPT_PF_EXE_STATUS		(0x4000008ll)
#define OTX2_CPT_PF_EXE_CLK		(0x4000010ll)
#define OTX2_CPT_PF_EXE_DBG_CTL		(0x4000018ll)
#define OTX2_CPT_PF_EXE_DBG_DATA	(0x4000020ll)
#define OTX2_CPT_PF_EXE_BIST_STATUS	(0x4000028ll)
#define OTX2_CPT_PF_EXE_REQ_TIMER	(0x4000030ll)
#define OTX2_CPT_PF_EXE_MEM_CTL		(0x4000038ll)
#define OTX2_CPT_PF_EXE_PERF_CTL	(0x4001000ll)
#define OTX2_CPT_PF_EXE_DBG_CNTX(b)	(0x4001100ll | (u64)(b) << 3)
#define OTX2_CPT_PF_EXE_PERF_EVENT_CNT	(0x4001180ll)
#define OTX2_CPT_PF_EXE_EPCI_INBX_CNT(b) (0x4001200ll | (u64)(b) << 3)
#define OTX2_CPT_PF_EXE_EPCI_OUTBX_CNT(b) (0x4001240ll | (u64)(b) << 3)
#define OTX2_CPT_PF_ENGX_UCODE_BASE(b)	(0x4002000ll | (u64)(b) << 3)
#define OTX2_CPT_PF_QX_CTL(b)		(0x8000000ll | (u64)(b) << 20)
#define OTX2_CPT_PF_QX_GMCTL(b)		(0x8000020ll | (u64)(b) << 20)
#define OTX2_CPT_PF_QX_CTL2(b)		(0x8000100ll | (u64)(b) << 20)
#define OTX2_CPT_PF_VFX_MBOXX(b, c)	(0x8001000ll | (u64)(b) << 20 | \
					 (u64)(c) << 8)

/* OcteonTX2 CPT LF registers */
#define OTX2_CPT_LF_CTL                 (0x10ull)
#define OTX2_CPT_LF_DONE_WAIT           (0x30ull)
#define OTX2_CPT_LF_INPROG              (0x40ull)
#define OTX2_CPT_LF_DONE                (0x50ull)
#define OTX2_CPT_LF_DONE_ACK            (0x60ull)
#define OTX2_CPT_LF_DONE_INT_ENA_W1S    (0x90ull)
#define OTX2_CPT_LF_DONE_INT_ENA_W1C    (0xa0ull)
#define OTX2_CPT_LF_MISC_INT            (0xb0ull)
#define OTX2_CPT_LF_MISC_INT_W1S        (0xc0ull)
#define OTX2_CPT_LF_MISC_INT_ENA_W1S    (0xd0ull)
#define OTX2_CPT_LF_MISC_INT_ENA_W1C    (0xe0ull)
#define OTX2_CPT_LF_Q_BASE              (0xf0ull)
#define OTX2_CPT_LF_Q_SIZE              (0x100ull)
#define OTX2_CPT_LF_Q_INST_PTR          (0x110ull)
#define OTX2_CPT_LF_Q_GRP_PTR           (0x120ull)
#define OTX2_CPT_LF_NQX(a)              (0x400ull | (u64)(a) << 3)
#define OTX2_CPT_RVU_FUNC_BLKADDR_SHIFT	20
/* LMT LF registers */
#define OTX2_CPT_LMT_LFBASE		BIT_ULL(OTX2_CPT_RVU_FUNC_BLKADDR_SHIFT)
#define OTX2_CPT_LMT_LF_LMTLINEX(a)	(OTX2_CPT_LMT_LFBASE | 0x000 | \
					 (a) << 12)

/*
 * Enumeration otx2_cpt_ucode_error_code_e
 *
 * Enumerates ucode errors
 */
enum otx2_cpt_ucode_error_code_e {
	CPT_NO_UCODE_ERROR = 0x00,
	ERR_OPCODE_UNSUPPORTED = 0x01,

	/* Scatter gather */
	ERR_SCATTER_GATHER_WRITE_LENGTH = 0x02,
	ERR_SCATTER_GATHER_LIST = 0x03,
	ERR_SCATTER_GATHER_NOT_SUPPORTED = 0x04,

};

/*
 * Enumeration otx2_cpt_comp_e
 *
 * OcteonTX2 CPT Completion Enumeration
 * Enumerates the values of CPT_RES_S[COMPCODE].
 */
enum otx2_cpt_comp_e {
	OTX2_CPT_COMP_E_NOTDONE = 0x00,
	OTX2_CPT_COMP_E_GOOD = 0x01,
	OTX2_CPT_COMP_E_FAULT = 0x02,
	OTX2_CPT_RESERVED = 0x03,
	OTX2_CPT_COMP_E_HWERR = 0x04,
	OTX2_CPT_COMP_E_INSTERR = 0x05,
	OTX2_CPT_COMP_E_LAST_ENTRY = 0x06
};

/*
 * Enumeration otx2_cpt_vf_int_vec_e
 *
 * OcteonTX2 CPT VF MSI-X Vector Enumeration
 * Enumerates the MSI-X interrupt vectors.
 */
enum otx2_cpt_vf_int_vec_e {
	OTX2_CPT_VF_INT_VEC_E_MBOX = 0x00
};

/*
 * Enumeration otx2_cpt_lf_int_vec_e
 *
 * OcteonTX2 CPT LF MSI-X Vector Enumeration
 * Enumerates the MSI-X interrupt vectors.
 */
enum otx2_cpt_lf_int_vec_e {
	OTX2_CPT_LF_INT_VEC_E_MISC = 0x00,
	OTX2_CPT_LF_INT_VEC_E_DONE = 0x01
};

/*
 * Structure otx2_cpt_inst_s
 *
 * CPT Instruction Structure
 * This structure specifies the instruction layout. Instructions are
 * stored in memory as little-endian unless CPT()_PF_Q()_CTL[INST_BE] is set.
 * cpt_inst_s_s
 * Word 0
 * doneint:1 Done interrupt.
 *	0 = No interrupts related to this instruction.
 *	1 = When the instruction completes, CPT()_VQ()_DONE[DONE] will be
 *	incremented,and based on the rules described there an interrupt may
 *	occur.
 * Word 1
 * res_addr [127: 64] Result IOVA.
 *	If nonzero, specifies where to write CPT_RES_S.
 *	If zero, no result structure will be written.
 *	Address must be 16-byte aligned.
 *	Bits <63:49> are ignored by hardware; software should use a
 *	sign-extended bit <48> for forward compatibility.
 * Word 2
 *  grp:10 [171:162] If [WQ_PTR] is nonzero, the SSO guest-group to use when
 *	CPT submits work SSO.
 *	For the SSO to not discard the add-work request, FPA_PF_MAP() must map
 *	[GRP] and CPT()_PF_Q()_GMCTL[GMID] as valid.
 *  tt:2 [161:160] If [WQ_PTR] is nonzero, the SSO tag type to use when CPT
 *	submits work to SSO
 *  tag:32 [159:128] If [WQ_PTR] is nonzero, the SSO tag to use when CPT
 *	submits work to SSO.
 * Word 3
 *  wq_ptr [255:192] If [WQ_PTR] is nonzero, it is a pointer to a
 *	work-queue entry that CPT submits work to SSO after all context,
 *	output data, and result write operations are visible to other
 *	CNXXXX units and the cores. Bits <2:0> must be zero.
 *	Bits <63:49> are ignored by hardware; software should
 *	use a sign-extended bit <48> for forward compatibility.
 *	Internal:
 *	Bits <63:49>, <2:0> are ignored by hardware, treated as always 0x0.
 * Word 4
 *  ei0; [319:256] Engine instruction word 0. Passed to the AE/SE.
 * Word 5
 *  ei1; [383:320] Engine instruction word 1. Passed to the AE/SE.
 * Word 6
 *  ei2; [447:384] Engine instruction word 1. Passed to the AE/SE.
 * Word 7
 *  ei3; [511:448] Engine instruction word 1. Passed to the AE/SE.
 *
 */
union otx2_cpt_inst_s {
	u64 u[8];

	struct {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 nixtx_addr:60;
		u64 doneint:1;
		u64 nixtxl:3;
#else /* Word 0 - Little Endian */
		u64 nixtxl:3;
		u64 doneint:1;
		u64 nixtx_addr:60;
#endif /* Word 0 - End */
		u64 res_addr;
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 2 - Big Endian */
		u64 rvu_pf_func:16;
		u64 reserved_172_175:4;
		u64 grp:10;
		u64 tt:2;
		u64 tag:32;
#else /* Word 2 - Little Endian */
		u64 tag:32;
		u64 tt:2;
		u64 grp:10;
		u64 reserved_172_175:4;
		u64 rvu_pf_func:16;
#endif /* Word 2 - End */
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 3 - Big Endian */
		u64 wq_ptr:61;
		u64 reserved_194_193:2;
		u64 qord:1;
#else /* Word 3 - Little Endian */
		u64 qord:1;
		u64 reserved_194_193:2;
		u64 wq_ptr:61;
#endif /* Word 3 - End */
		u64 ei0;
		u64 ei1;
		u64 ei2;
		u64 ei3;
	} s;
};

/*
 * Structure otx2_cpt_res_s
 *
 * CPT Result Structure
 * The CPT coprocessor writes the result structure after it completes a
 * CPT_INST_S instruction. The result structure is exactly 16 bytes, and
 * each instruction completion produces exactly one result structure.
 *
 * This structure is stored in memory as little-endian unless
 * CPT()_PF_Q()_CTL[INST_BE] is set.
 * cpt_res_s_s
 * Word 0
 *  doneint:1 [16:16] Done interrupt. This bit is copied from the
 *	corresponding instruction's CPT_INST_S[DONEINT].
 *  compcode:8 [7:0] Indicates completion/error status of the CPT coprocessor
 *	for the	associated instruction, as enumerated by CPT_COMP_E.
 *	Core software may write the memory location containing [COMPCODE] to
 *	0x0 before ringing the doorbell, and then poll for completion by
 *	checking for a nonzero value.
 *	Once the core observes a nonzero [COMPCODE] value in this case,the CPT
 *	coprocessor will have also completed L2/DRAM write operations.
 * Word 1
 *  reserved
 *
 */
union otx2_cpt_res_s {
	u64 u[2];

	struct {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_17_63:47;
		u64 doneint:1;
		u64 uc_compcode:8;
		u64 compcode:8;
#else /* Word 0 - Little Endian */
		u64 compcode:8;
		u64 uc_compcode:8;
		u64 doneint:1;
		u64 reserved_17_63:47;
#endif /* Word 0 - End */
		u64 reserved_64_127;
	} s;
};

/*
 * Register (RVU_PF_BAR0) cpt#_af_constants1
 *
 * CPT AF Constants Register
 * This register contains implementation-related parameters of CPT.
 */
union otx2_cptx_af_constants1 {
	uint64_t u;
	struct otx2_cptx_af_constants1_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t reserved_48_63        : 16;
		uint64_t ae                    : 16;
		uint64_t ie                    : 16;
		uint64_t se                    : 16;
#else /* Word 0 - Little Endian */
		uint64_t se                    : 16;
		uint64_t ie                    : 16;
		uint64_t ae                    : 16;
		uint64_t reserved_48_63        : 16;
#endif /* Word 0 - End */
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_misc_int
 *
 * This register contain the per-queue miscellaneous interrupts.
 *
 */
union otx2_cptx_lf_misc_int {
	uint64_t u;
	struct otx2_cptx_lf_misc_int_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t reserved_7_63               : 57;
		uint64_t fault                       :  1;
		uint64_t hwerr                       :  1;
		uint64_t reserved_4_4                :  1;
		uint64_t nwrp                        :  1;
		uint64_t irde                        :  1;
		uint64_t nqerr                       :  1;
		uint64_t reserved_0_0                :  1;
#else /* Word 0 - Little Endian */
		uint64_t reserved_0_0                :  1;
		uint64_t nqerr                       :  1;
		uint64_t irde                        :  1;
		uint64_t nwrp                        :  1;
		uint64_t reserved_4_4                :  1;
		uint64_t hwerr                       :  1;
		uint64_t fault                       :  1;
		uint64_t reserved_7_63               : 57;
#endif
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_misc_int_ena_w1s
 *
 * This register sets interrupt enable bits.
 *
 */
union otx2_cptx_lf_misc_int_ena_w1s {
	uint64_t u;
	struct otx2_cptx_lf_misc_int_ena_w1s_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t reserved_7_63               : 57;
		uint64_t fault                       :  1;
		uint64_t hwerr                       :  1;
		uint64_t reserved_4_4                :  1;
		uint64_t nwrp                        :  1;
		uint64_t irde                        :  1;
		uint64_t nqerr                       :  1;
		uint64_t reserved_0_0                :  1;
#else /* Word 0 - Little Endian */
		uint64_t reserved_0_0                :  1;
		uint64_t nqerr                       :  1;
		uint64_t irde                        :  1;
		uint64_t nwrp                        :  1;
		uint64_t reserved_4_4                :  1;
		uint64_t hwerr                       :  1;
		uint64_t fault                       :  1;
		uint64_t reserved_7_63               : 57;
#endif
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_ctl
 *
 * This register configures the queue.
 *
 * When the queue is not execution-quiescent (see CPT_LF_INPROG[EENA,INFLIGHT]),
 * software must only write this register with [ENA]=0.
 */
union otx2_cptx_lf_ctl {
	uint64_t u;
	struct otx2_cptx_lf_ctl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t reserved_8_63               : 56;
		uint64_t fc_hyst_bits                :  4;
		uint64_t reserved_3_3                :  1;
		uint64_t fc_up_crossing              :  1;
		uint64_t fc_ena                      :  1;
		uint64_t ena                         :  1;
#else /* Word 0 - Little Endian */
		uint64_t ena                         :  1;
		uint64_t fc_ena                      :  1;
		uint64_t fc_up_crossing              :  1;
		uint64_t reserved_3_3                :  1;
		uint64_t fc_hyst_bits                :  4;
		uint64_t reserved_8_63               : 56;
#endif
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_done_wait
 *
 * This register specifies the per-queue interrupt coalescing settings.
 */
union otx2_cptx_lf_done_wait {
	u64 u;
	struct otx2_cptx_lf_done_wait_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_48_63:16;
		u64 time_wait:16;
		u64 reserved_20_31:12;
		u64 num_wait:20;
#else /* Word 0 - Little Endian */
		u64 num_wait:20;
		u64 reserved_20_31:12;
		u64 time_wait:16;
		u64 reserved_48_63:16;
#endif /* Word 0 - End */
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_done
 *
 * This register contain the per-queue instruction done count.
 */
union otx2_cptx_lf_done {
	u64 u;
	struct otx2_cptx_lf_done_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_20_63:44;
		u64 done:20;
#else /* Word 0 - Little Endian */
		u64 done:20;
		u64 reserved_20_63:44;
#endif /* Word 0 - End */
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_inprog
 *
 * These registers contain the per-queue instruction in flight registers.
 *
 */
union otx2_cptx_lf_inprog {
	uint64_t u;
	struct otx2_cptx_lf_inprog_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t reserved_48_63              : 16;
		uint64_t gwb_cnt                     :  8;
		uint64_t grb_cnt                     :  8;
		uint64_t grb_partial                 :  1;
		uint64_t reserved_18_30              : 13;
		uint64_t grp_drp                     :  1;
		uint64_t eena                        :  1;
		uint64_t reserved_9_15               :  7;
		uint64_t inflight                    :  9;
#else /* Word 0 - Little Endian */
		uint64_t inflight                    :	9;
		uint64_t reserved_9_15               :	7;
		uint64_t eena                        :	1;
		uint64_t grp_drp                     :	1;
		uint64_t reserved_18_30              :	13;
		uint64_t grb_partial                 :	1;
		uint64_t grb_cnt                     :	8;
		uint64_t gwb_cnt                     :	8;
		uint64_t reserved_48_63		     :	16;
#endif
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_q_base
 *
 * CPT initializes these CSR fields to these values on any CPT_LF_Q_BASE write:
 * _ CPT_LF_Q_INST_PTR[XQ_XOR]=0.
 * _ CPT_LF_Q_INST_PTR[NQ_PTR]=2.
 * _ CPT_LF_Q_INST_PTR[DQ_PTR]=2.
 * _ CPT_LF_Q_GRP_PTR[XQ_XOR]=0.
 * _ CPT_LF_Q_GRP_PTR[NQ_PTR]=1.
 * _ CPT_LF_Q_GRP_PTR[DQ_PTR]=1.
 */
union otx2_cptx_lf_q_base {
	uint64_t u;
	struct otx2_cptx_lf_q_base_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
	uint64_t reserved_53_63              : 11;
	uint64_t addr                        : 46;
	uint64_t reserved_1_6                :  6;
	uint64_t fault                       :  1;
#else /* Word 0 - Little Endian */
	uint64_t fault                       :  1;
	uint64_t reserved_1_6                :  6;
	uint64_t addr                        : 46;
	uint64_t reserved_53_63              : 11;
#endif
	} s;
};

/*
 * RVU_PFVF_BAR2 - cpt_lf_q_size
 *
 * CPT initializes these CSR fields to these values on any CPT_LF_Q_SIZE write:
 * _ CPT_LF_Q_INST_PTR[XQ_XOR]=0.
 * _ CPT_LF_Q_INST_PTR[NQ_PTR]=2.
 * _ CPT_LF_Q_INST_PTR[DQ_PTR]=2.
 * _ CPT_LF_Q_GRP_PTR[XQ_XOR]=0.
 * _ CPT_LF_Q_GRP_PTR[NQ_PTR]=1.
 * _ CPT_LF_Q_GRP_PTR[DQ_PTR]=1.
 */
union otx2_cptx_lf_q_size {
	uint64_t u;
	struct otx2_cptx_lf_q_size_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
	uint64_t reserved_15_63              : 49;
	uint64_t size_div40                  : 15;
#else /* Word 0 - Little Endian */
	uint64_t size_div40                  : 15;
	uint64_t reserved_15_63              : 49;
#endif
	} s;
};

/*
 * RVU_PF_BAR0 - cpt_af_lf_ctl
 *
 * This register configures queues. This register should be written only
 * when the queue is execution-quiescent (see CPT_LF_INPROG[INFLIGHT]).
 */
union otx2_cptx_af_lf_ctrl {
	uint64_t u;
	struct otx2_cptx_af_lf_ctrl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
	uint64_t reserved_56_63              :	8;
	uint64_t grp                         :	8;
	uint64_t reserved_17_47              : 31;
	uint64_t nixtx_en                    :	1;
	uint64_t reserved_11_15              :	5;
	uint64_t cont_err                    :	1;
	uint64_t pf_func_inst                :	1;
	uint64_t reserved_1_8                :	8;
	uint64_t pri                         :	1;
#else /* Word 0 - Little Endian */
	uint64_t pri                         :	1;
	uint64_t reserved_1_8                :	8;
	uint64_t pf_func_inst                :	1;
	uint64_t cont_err                    :	1;
	uint64_t reserved_11_15              :	5;
	uint64_t nixtx_en                    :	1;
	uint64_t reserved_17_47              :	31;
	uint64_t grp                         :	8;
	uint64_t reserved_56_63              :	8;
#endif
	} s;
};

#endif /* __OTX2_CPT_HW_TYPES_H */
