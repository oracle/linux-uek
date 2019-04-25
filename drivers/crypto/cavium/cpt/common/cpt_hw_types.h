/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_HW_TYPES_H
#define __CPT_HW_TYPES_H

#include "cpt_common.h"

/* Device IDs */
#define CPT_PCI_PF_8X_DEVICE_ID 0xa040
#define CPT_PCI_VF_8X_DEVICE_ID 0xa041
#define CPT_PCI_PF_9X_DEVICE_ID 0xa0FD
#define CPT_PCI_VF_9X_DEVICE_ID 0xa0FE

#define CPT_81XX_PCI_PF_SUBSYS_ID 0xa240
#define CPT_81XX_PCI_VF_SUBSYS_ID 0xa241
#define CPT_83XX_PCI_PF_SUBSYS_ID 0xa340
#define CPT_83XX_PCI_VF_SUBSYS_ID 0xa341
#define CPT_96XX_PCI_PF_SUBSYS_ID 0xb200

/* Configuration and status registers are in BAR0 on 8X platform */
#define PCI_CPT_PF_8X_CFG_BAR	0
#define PCI_CPT_VF_8X_CFG_BAR	0

#define CPT_BAR_E_CPTX_VFX_8X_BAR0_OFFSET(a, b) \
	(0x000020000000ll + 0x1000000000ll * (a) + 0x100000ll * (b))
#define CPT_BAR_E_CPTX_VFX_8X_BAR0_SIZE	0x400000

/*
 * Mailbox interrupts offset
 */
#define CPT_81XX_PF_MBOX_INT 2
#define CPT_83XX_PF_MBOX_INT 3
#define CPT_96XX_PF_MBOX_INT 6
#define CPT_PF_INT_VEC_E_MBOXX(x, a) ((x) + (a))

/*
 * Number of MSIX supported in PF
 */
#define	CPT_81XX_PF_MSIX_VECTORS 3
#define	CPT_83XX_PF_MSIX_VECTORS 4
#define	CPT_96XX_PF_MSIX_VECTORS 7

/*
 * Maximum supported microcode groups
 */
#define CPT_MAX_ENGINE_GROUPS 8

/*
 * CPT instruction size in bytes
 */
#define CPT_INST_SIZE 64

/*
 * CPT queue next chunk pointer size in bytes
 */
#define CPT_NEXT_CHUNK_PTR_SIZE 8

/*
 * CPT 8X VF MSIX vectors and their offsets
 */
#define	CPT_8X_VF_MSIX_VECTORS 2
#define CPT_8X_VF_INTR_MBOX_MASK BIT(0)
#define CPT_8X_VF_INTR_DOVF_MASK BIT(1)
#define CPT_8X_VF_INTR_IRDE_MASK BIT(2)
#define CPT_8X_VF_INTR_NWRP_MASK BIT(3)
#define CPT_8X_VF_INTR_SERR_MASK BIT(4)

/*
 * CPT 9X VF MSIX vectors and their offsets
 */
#define	CPT_9X_VF_MSIX_VECTORS 1
#define CPT_9X_VF_INTR_MBOX_MASK BIT(0)

/*
 * CPT 9X LF MSIX vectors
 */
#define	CPT_9X_LF_MSIX_VECTORS 2

/* 8XXX CPT PF registers */
#define CPT_PF_CONSTANTS		(0x0ll)
#define CPT_PF_RESET			(0x100ll)
#define CPT_PF_DIAG			(0x120ll)
#define CPT_PF_BIST_STATUS		(0x160ll)
#define CPT_PF_ECC0_CTL			(0x200ll)
#define CPT_PF_ECC0_FLIP		(0x210ll)
#define CPT_PF_ECC0_INT			(0x220ll)
#define CPT_PF_ECC0_INT_W1S		(0x230ll)
#define CPT_PF_ECC0_ENA_W1S		(0x240ll)
#define CPT_PF_ECC0_ENA_W1C		(0x250ll)
#define CPT_PF_MBOX_INTX(b)		(0x400ll | (u64)(b) << 3)
#define CPT_PF_MBOX_INT_W1SX(b)		(0x420ll | (u64)(b) << 3)
#define CPT_PF_MBOX_ENA_W1CX(b)		(0x440ll | (u64)(b) << 3)
#define CPT_PF_MBOX_ENA_W1SX(b)		(0x460ll | (u64)(b) << 3)
#define CPT_PF_EXEC_INT			(0x500ll)
#define CPT_PF_EXEC_INT_W1S		(0x520ll)
#define CPT_PF_EXEC_ENA_W1C		(0x540ll)
#define CPT_PF_EXEC_ENA_W1S		(0x560ll)
#define CPT_PF_GX_EN(b)			(0x600ll | (u64)(b) << 3)
#define CPT_PF_EXEC_INFO		(0x700ll)
#define CPT_PF_EXEC_BUSY		(0x800ll)
#define CPT_PF_EXEC_INFO0		(0x900ll)
#define CPT_PF_EXEC_INFO1		(0x910ll)
#define CPT_PF_INST_REQ_PC		(0x10000ll)
#define CPT_PF_INST_LATENCY_PC		(0x10020ll)
#define CPT_PF_RD_REQ_PC		(0x10040ll)
#define CPT_PF_RD_LATENCY_PC		(0x10060ll)
#define CPT_PF_RD_UC_PC			(0x10080ll)
#define CPT_PF_ACTIVE_CYCLES_PC		(0x10100ll)
#define CPT_PF_EXE_CTL			(0x4000000ll)
#define CPT_PF_EXE_STATUS		(0x4000008ll)
#define CPT_PF_EXE_CLK			(0x4000010ll)
#define CPT_PF_EXE_DBG_CTL		(0x4000018ll)
#define CPT_PF_EXE_DBG_DATA		(0x4000020ll)
#define CPT_PF_EXE_BIST_STATUS		(0x4000028ll)
#define CPT_PF_EXE_REQ_TIMER		(0x4000030ll)
#define CPT_PF_EXE_MEM_CTL		(0x4000038ll)
#define CPT_PF_EXE_PERF_CTL		(0x4001000ll)
#define CPT_PF_EXE_DBG_CNTX(b)		(0x4001100ll | (u64)(b) << 3)
#define CPT_PF_EXE_PERF_EVENT_CNT	(0x4001180ll)
#define CPT_PF_EXE_EPCI_INBX_CNT(b)	(0x4001200ll | (u64)(b) << 3)
#define CPT_PF_EXE_EPCI_OUTBX_CNT(b)	(0x4001240ll | (u64)(b) << 3)
#define CPT_PF_ENGX_UCODE_BASE(b)	(0x4002000ll | (u64)(b) << 3)
#define CPT_PF_QX_CTL(b)		(0x8000000ll | (u64)(b) << 20)
#define CPT_PF_QX_GMCTL(b)		(0x8000020ll | (u64)(b) << 20)
#define CPT_PF_QX_CTL2(b)		(0x8000100ll | (u64)(b) << 20)
#define CPT_PF_VFX_MBOXX(b, c)	(0x8001000ll | (u64)(b) << 20 | (u64)(c) << 8)

/* 8XXX CPT VF registers */
#define CPT_VQX_CTL(b)		(0x100ll | (u64)(b) << 20)
#define CPT_VQX_SADDR(b)	(0x200ll | (u64)(b) << 20)
#define CPT_VQX_DONE_WAIT(b)	(0x400ll | (u64)(b) << 20)
#define CPT_VQX_INPROG(b)	(0x410ll | (u64)(b) << 20)
#define CPT_VQX_DONE(b)		(0x420ll | (u64)(b) << 20)
#define CPT_VQX_DONE_ACK(b)	(0x440ll | (u64)(b) << 20)
#define CPT_VQX_DONE_INT_W1S(b) (0x460ll | (u64)(b) << 20)
#define CPT_VQX_DONE_INT_W1C(b) (0x468ll | (u64)(b) << 20)
#define CPT_VQX_DONE_ENA_W1S(b) (0x470ll | (u64)(b) << 20)
#define CPT_VQX_DONE_ENA_W1C(b) (0x478ll | (u64)(b) << 20)
#define CPT_VQX_MISC_INT(b)	(0x500ll | (u64)(b) << 20)
#define CPT_VQX_MISC_INT_W1S(b) (0x508ll | (u64)(b) << 20)
#define CPT_VQX_MISC_ENA_W1S(b) (0x510ll | (u64)(b) << 20)
#define CPT_VQX_MISC_ENA_W1C(b) (0x518ll | (u64)(b) << 20)
#define CPT_VQX_DOORBELL(b)	(0x600ll | (u64)(b) << 20)
#define CPT_VFX_PF_MBOXX(b, c)	(0x1000ll | ((b) << 20) | ((c) << 3))

/* 9XXX CPT LF registers */
#define CPT_LF_CTL                      (0x10ull)
#define CPT_LF_DONE_WAIT                (0x30ull)
#define CPT_LF_INPROG                   (0x40ull)
#define CPT_LF_DONE                     (0x50ull)
#define CPT_LF_DONE_ACK                 (0x60ull)
#define CPT_LF_DONE_INT_ENA_W1S         (0x90ull)
#define CPT_LF_DONE_INT_ENA_W1C         (0xa0ull)
#define CPT_LF_MISC_INT                 (0xb0ull)
#define CPT_LF_MISC_INT_W1S             (0xc0ull)
#define CPT_LF_MISC_INT_ENA_W1S         (0xd0ull)
#define CPT_LF_MISC_INT_ENA_W1C         (0xe0ull)
#define CPT_LF_Q_BASE                   (0xf0ull)
#define CPT_LF_Q_SIZE                   (0x100ull)
#define CPT_LF_Q_INST_PTR               (0x110ull)
#define CPT_LF_Q_GRP_PTR                (0x120ull)
#define CPT_LF_NQX(a)                   (0x400ull | (u64)(a) << 3)

/**
 * Enumeration cpt_ucode_error_code_e
 *
 * Enumerates ucode errors
 */
enum cpt_ucode_error_code_e {
	NO_ERROR = 0x00,
	ERR_OPCODE_UNSUPPORTED = 0x01,

	/* Scatter gather */
	ERR_SCATTER_GATHER_WRITE_LENGTH = 0x02,
	ERR_SCATTER_GATHER_LIST = 0x03,
	ERR_SCATTER_GATHER_NOT_SUPPORTED = 0x04,

};

/**
 * Enumeration cpt_8x_comp_e
 *
 * CPT 8X Completion Enumeration
 * Enumerates the values of CPT_RES_S[COMPCODE].
 */
enum cpt_8x_comp_e {
	CPT_8X_COMP_E_NOTDONE = 0x00,
	CPT_8X_COMP_E_GOOD = 0x01,
	CPT_8X_COMP_E_FAULT = 0x02,
	CPT_8X_COMP_E_SWERR = 0x03,
	CPT_8X_COMP_E_HWERR = 0x04,
	CPT_8X_COMP_E_LAST_ENTRY = 0x05
};

 /**
  * Enumeration cpt_9x_comp_e
  *
  * CPT 9X Completion Enumeration
  * Enumerates the values of CPT_RES_S[COMPCODE].
  */
enum cpt_9x_comp_e {
	CPT_9X_COMP_E_NOTDONE = 0x00,
	CPT_9X_COMP_E_GOOD = 0x01,
	CPT_9X_COMP_E_FAULT = 0x02,
	CPT_9X_RESERVED = 0x03,
	CPT_9X_COMP_E_HWERR = 0x04,
	CPT_9X_COMP_E_INSTERR = 0x05,
	CPT_9X_COMP_E_LAST_ENTRY = 0x06
};

/**
 * Enumeration cpt_8x_vf_int_vec_e
 *
 * CPT 8X VF MSI-X Vector Enumeration
 * Enumerates the MSI-X interrupt vectors.
 */
enum cpt_8x_vf_int_vec_e {
	CPT_8X_VF_INT_VEC_E_MISC = 0x00,
	CPT_8X_VF_INT_VEC_E_DONE = 0x01
};

/**
 * Enumeration cpt_9x_vf_int_vec_e
 *
 * CPT 9X VF MSI-X Vector Enumeration
 * Enumerates the MSI-X interrupt vectors.
 */
enum cpt_9x_vf_int_vec_e {
	CPT_9X_VF_INT_VEC_E_MBOX = 0x00
};

/**
 * Enumeration cpt_9x_lf_int_vec_e
 *
 * CPT 9X LF MSI-X Vector Enumeration
 * Enumerates the MSI-X interrupt vectors.
 */
enum cpt_9x_lf_int_vec_e {
	CPT_9X_LF_INT_VEC_E_MISC = 0x00,
	CPT_9X_LF_INT_VEC_E_DONE = 0x01
};

/**
 * Structure cpt_inst_s
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
union cpt_inst_s {
	u64 u[8];

	struct cpt_inst_s_8s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_17_63:47;
		u64 doneint:1;
		u64 reserved_0_15:16;
#else /* Word 0 - Little Endian */
		u64 reserved_0_15:16;
		u64 doneint:1;
		u64 reserved_17_63:47;
#endif /* Word 0 - End */
		u64 res_addr;
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 2 - Big Endian */
		u64 reserved_172_191:20;
		u64 grp:10;
		u64 tt:2;
		u64 tag:32;
#else /* Word 2 - Little Endian */
		u64 tag:32;
		u64 tt:2;
		u64 grp:10;
		u64 reserved_172_191:20;
#endif /* Word 2 - End */
		u64 wq_ptr;
		u64 ei0;
		u64 ei1;
		u64 ei2;
		u64 ei3;
	} s8x;

	struct cpt_inst_s_9s {
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
	} s9x;
};

/**
 * Structure cpt_res_s
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
union cpt_res_s {
	u64 u[2];
	struct cpt_res_s_8s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_17_63:47;
		u64 doneint:1;
		u64 reserved_8_15:8;
		u64 compcode:8;
#else /* Word 0 - Little Endian */
		u64 compcode:8;
		u64 reserved_8_15:8;
		u64 doneint:1;
		u64 reserved_17_63:47;
#endif /* Word 0 - End */
		u64 reserved_64_127;
	} s8x;

	struct cpt_res_s_9s {
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
	} s9x;
};

/**
 * Register (NCB) cpt#_pf_bist_status
 *
 * CPT PF Control Bist Status Register
 * This register has the BIST status of memories. Each bit is the BIST result
 * of an individual memory (per bit, 0 = pass and 1 = fail).
 * cptx_pf_bist_status_s
 * Word0
 *  bstatus [29:0](RO/H) BIST status. One bit per memory, enumerated by
 *	CPT_RAMS_E.
 */
union cptx_pf_bist_status {
	u64 u;
	struct cptx_pf_bist_status_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_30_63:34;
		u64 bstatus:30;
#else /* Word 0 - Little Endian */
		u64 bstatus:30;
		u64 reserved_30_63:34;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_pf_constants
 *
 * CPT PF Constants Register
 * This register contains implementation-related parameters of CPT in CNXXXX.
 * cptx_pf_constants_s
 * Word 0
 *  reserved_40_63:24 [63:40] Reserved.
 *  epcis:8 [39:32](RO) Number of EPCI busses.
 *  grps:8 [31:24](RO) Number of engine groups implemented.
 *  ae:8 [23:16](RO/H) Number of AEs. In CNXXXX, for CPT0 returns 0x0,
 *	for CPT1 returns 0x18, or less if there are fuse-disables.
 *  se:8 [15:8](RO/H) Number of SEs. In CNXXXX, for CPT0 returns 0x30,
 *	or less if there are fuse-disables, for CPT1 returns 0x0.
 *  vq:8 [7:0](RO) Number of VQs.
 */
union cptx_pf_constants {
	u64 u;
	struct cptx_pf_constants_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_40_63:24;
		u64 epcis:8;
		u64 grps:8;
		u64 ae:8;
		u64 se:8;
		u64 vq:8;
#else /* Word 0 - Little Endian */
		u64 vq:8;
		u64 se:8;
		u64 ae:8;
		u64 grps:8;
		u64 epcis:8;
		u64 reserved_40_63:24;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_pf_exe_bist_status
 *
 * CPT PF Engine Bist Status Register
 * This register has the BIST status of each engine.  Each bit is the
 * BIST result of an individual engine (per bit, 0 = pass and 1 = fail).
 * cptx_pf_exe_bist_status_s
 * Word0
 *  reserved_48_63:16 [63:48] reserved
 *  bstatus:48 [47:0](RO/H) BIST status. One bit per engine.
 *
 */
union cptx_pf_exe_bist_status {
	u64 u;
	struct cptx_pf_exe_bist_status_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_48_63:16;
		u64 bstatus:48;
#else /* Word 0 - Little Endian */
		u64 bstatus:48;
		u64 reserved_48_63:16;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_pf_q#_ctl
 *
 * CPT Queue Control Register
 * This register configures queues. This register should be changed only
 * when quiescent (see CPT()_VQ()_INPROG[INFLIGHT]).
 * cptx_pf_qx_ctl_s
 * Word0
 *  reserved_60_63:4 [63:60] reserved.
 *  aura:12; [59:48](R/W) Guest-aura for returning this queue's
 *	instruction-chunk buffers to FPA. Only used when [INST_FREE] is set.
 *	For the FPA to not discard the request, FPA_PF_MAP() must map
 *	[AURA] and CPT()_PF_Q()_GMCTL[GMID] as valid.
 *  reserved_45_47:3 [47:45] reserved.
 *  size:13 [44:32](R/W) Command-buffer size, in number of 64-bit words per
 *	command buffer segment. Must be 8*n + 1, where n is the number of
 *	instructions per buffer segment.
 *  reserved_11_31:21 [31:11] Reserved.
 *  cont_err:1 [10:10](R/W) Continue on error.
 *	0 = When CPT()_VQ()_MISC_INT[NWRP], CPT()_VQ()_MISC_INT[IRDE] or
 *	CPT()_VQ()_MISC_INT[DOVF] are set by hardware or software via
 *	CPT()_VQ()_MISC_INT_W1S, then CPT()_VQ()_CTL[ENA] is cleared.  Due to
 *	pipelining, additional instructions may have been processed between the
 *	instruction causing the error and the next instruction in the disabled
 *	queue (the instruction at CPT()_VQ()_SADDR).
 *	1 = Ignore errors and continue processing instructions.
 *	For diagnostic use only.
 *  inst_free:1 [9:9](R/W) Instruction FPA free. When set, when CPT reaches the
 *	end of an instruction chunk, that chunk will be freed to the FPA.
 *  inst_be:1 [8:8](R/W) Instruction big-endian control. When set, instructions,
 *	instruction next chunk pointers, and result structures are stored in
 *	big-endian format in memory.
 *  iqb_ldwb:1 [7:7](R/W) Instruction load don't write back.
 *	0 = The hardware issues NCB transient load (LDT) towards the cache,
 *	which if the line hits and is is dirty will cause the line to be
 *	written back before being replaced.
 *	1 = The hardware issues NCB LDWB read-and-invalidate command towards
 *	the cache when fetching the last word of instructions; as a result the
 *	line will not be written back when replaced.  This improves
 *	performance, but software must not read the instructions after they are
 *	posted to the hardware.	Reads that do not consume the last word of a
 *	cache line always use LDI.
 *  reserved_4_6:3 [6:4] Reserved.
 *  grp:3; [3:1](R/W) Engine group.
 *  pri:1; [0:0](R/W) Queue priority.
 *	1 = This queue has higher priority. Round-robin between higher
 *	priority queues.
 *	0 = This queue has lower priority. Round-robin between lower
 *	priority queues.
 */
union cptx_pf_qx_ctl {
	u64 u;
	struct cptx_pf_qx_ctl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_60_63:4;
		u64 aura:12;
		u64 reserved_45_47:3;
		u64 size:13;
		u64 reserved_11_31:21;
		u64 cont_err:1;
		u64 inst_free:1;
		u64 inst_be:1;
		u64 iqb_ldwb:1;
		u64 reserved_4_6:3;
		u64 grp:3;
		u64 pri:1;
#else /* Word 0 - Little Endian */
		u64 pri:1;
		u64 grp:3;
		u64 reserved_4_6:3;
		u64 iqb_ldwb:1;
		u64 inst_be:1;
		u64 inst_free:1;
		u64 cont_err:1;
		u64 reserved_11_31:21;
		u64 size:13;
		u64 reserved_45_47:3;
		u64 aura:12;
		u64 reserved_60_63:4;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_saddr
 *
 * CPT Queue Starting Buffer Address Registers
 * These registers set the instruction buffer starting address.
 * cptx_vqx_saddr_s
 * Word0
 *  reserved_49_63:15 [63:49] Reserved.
 *  ptr:43 [48:6](R/W/H) Instruction buffer IOVA <48:6> (64-byte aligned).
 *	When written, it is the initial buffer starting address; when read,
 *	it is the next read pointer to be requested from L2C. The PTR field
 *	is overwritten with the next pointer each time that the command buffer
 *	segment is exhausted. New commands will then be read from the newly
 *	specified command buffer pointer.
 *  reserved_0_5:6 [5:0] Reserved.
 *
 */
union cptx_vqx_saddr {
	u64 u;
	struct cptx_vqx_saddr_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_49_63:15;
		u64 ptr:43;
		u64 reserved_0_5:6;
#else /* Word 0 - Little Endian */
		u64 reserved_0_5:6;
		u64 ptr:43;
		u64 reserved_49_63:15;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_misc_ena_w1s
 *
 * CPT Queue Misc Interrupt Enable Set Register
 * This register sets interrupt enable bits.
 * cptx_vqx_misc_ena_w1s_s
 * Word0
 * reserved_5_63:59 [63:5] Reserved.
 * swerr:1 [4:4](R/W1S/H) Reads or sets enable for
 *	CPT(0..1)_VQ(0..63)_MISC_INT[SWERR].
 * nwrp:1 [3:3](R/W1S/H) Reads or sets enable for
 *	CPT(0..1)_VQ(0..63)_MISC_INT[NWRP].
 * irde:1 [2:2](R/W1S/H) Reads or sets enable for
 *	CPT(0..1)_VQ(0..63)_MISC_INT[IRDE].
 * dovf:1 [1:1](R/W1S/H) Reads or sets enable for
 *	CPT(0..1)_VQ(0..63)_MISC_INT[DOVF].
 * mbox:1 [0:0](R/W1S/H) Reads or sets enable for
 *	CPT(0..1)_VQ(0..63)_MISC_INT[MBOX].
 *
 */
union cptx_vqx_misc_ena_w1s {
	u64 u;
	struct cptx_vqx_misc_ena_w1s_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_5_63:59;
		u64 swerr:1;
		u64 nwrp:1;
		u64 irde:1;
		u64 dovf:1;
		u64 mbox:1;
#else /* Word 0 - Little Endian */
		u64 mbox:1;
		u64 dovf:1;
		u64 irde:1;
		u64 nwrp:1;
		u64 swerr:1;
		u64 reserved_5_63:59;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_doorbell
 *
 * CPT Queue Doorbell Registers
 * Doorbells for the CPT instruction queues.
 * cptx_vqx_doorbell_s
 * Word0
 *  reserved_20_63:44 [63:20] Reserved.
 *  dbell_cnt:20 [19:0](R/W/H) Number of instruction queue 64-bit words to add
 *	to the CPT instruction doorbell count. Readback value is the the
 *	current number of pending doorbell requests. If counter overflows
 *	CPT()_VQ()_MISC_INT[DBELL_DOVF] is set. To reset the count back to
 *	zero, write one to clear CPT()_VQ()_MISC_INT_ENA_W1C[DBELL_DOVF],
 *	then write a value of 2^20 minus the read [DBELL_CNT], then write one
 *	to CPT()_VQ()_MISC_INT_W1C[DBELL_DOVF] and
 *	CPT()_VQ()_MISC_INT_ENA_W1S[DBELL_DOVF]. Must be a multiple of 8.
 *	All CPT instructions are 8 words and require a doorbell count of
 *	multiple of 8.
 */
union cptx_vqx_doorbell {
	u64 u;
	struct cptx_vqx_doorbell_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_20_63:44;
		u64 dbell_cnt:20;
#else /* Word 0 - Little Endian */
		u64 dbell_cnt:20;
		u64 reserved_20_63:44;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_inprog
 *
 * CPT Queue In Progress Count Registers
 * These registers contain the per-queue instruction in flight registers.
 * cptx_vqx_inprog_s
 * Word0
 *  reserved_8_63:56 [63:8] Reserved.
 *  inflight:8 [7:0](RO/H) Inflight count. Counts the number of instructions
 *	for the VF for which CPT is fetching, executing or responding to
 *	instructions. However this does not include any interrupts that are
 *	awaiting software handling (CPT()_VQ()_DONE[DONE] != 0x0).
 *	A queue may not be reconfigured until:
 *	1. CPT()_VQ()_CTL[ENA] is cleared by software.
 *	2. [INFLIGHT] is polled until equals to zero.
 */
union cptx_vqx_inprog {
	u64 u;
	struct cptx_vqx_inprog_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_8_63:56;
		u64 inflight:8;
#else /* Word 0 - Little Endian */
		u64 inflight:8;
		u64 reserved_8_63:56;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_misc_int
 *
 * CPT Queue Misc Interrupt Register
 * These registers contain the per-queue miscellaneous interrupts.
 * cptx_vqx_misc_int_s
 * Word 0
 *  reserved_5_63:59 [63:5] Reserved.
 *  swerr:1 [4:4](R/W1C/H) Software error from engines.
 *  nwrp:1  [3:3](R/W1C/H) NCB result write response error.
 *  irde:1  [2:2](R/W1C/H) Instruction NCB read response error.
 *  dovf:1 [1:1](R/W1C/H) Doorbell overflow.
 *  mbox:1 [0:0](R/W1C/H) PF to VF mailbox interrupt. Set when
 *	CPT()_VF()_PF_MBOX(0) is written.
 *
 */
union cptx_vqx_misc_int {
	u64 u;
	struct cptx_vqx_misc_int_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_5_63:59;
		u64 swerr:1;
		u64 nwrp:1;
		u64 irde:1;
		u64 dovf:1;
		u64 mbox:1;
#else /* Word 0 - Little Endian */
		u64 mbox:1;
		u64 dovf:1;
		u64 irde:1;
		u64 nwrp:1;
		u64 swerr:1;
		u64 reserved_5_63:59;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_done_ack
 *
 * CPT Queue Done Count Ack Registers
 * This register is written by software to acknowledge interrupts.
 * cptx_vqx_done_ack_s
 * Word0
 *  reserved_20_63:44 [63:20] Reserved.
 *  done_ack:20 [19:0](R/W/H) Number of decrements to CPT()_VQ()_DONE[DONE].
 *	Reads CPT()_VQ()_DONE[DONE]. Written by software to acknowledge
 *	interrupts. If CPT()_VQ()_DONE[DONE] is still nonzero the interrupt
 *	will be re-sent if the conditions described in CPT()_VQ()_DONE[DONE]
 *	are satisfied.
 *
 */
union cptx_vqx_done_ack {
	u64 u;
	struct cptx_vqx_done_ack_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_20_63:44;
		u64 done_ack:20;
#else /* Word 0 - Little Endian */
		u64 done_ack:20;
		u64 reserved_20_63:44;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_done
 *
 * CPT Queue Done Count Registers
 * These registers contain the per-queue instruction done count.
 * cptx_vqx_done_s
 * Word0
 *  reserved_20_63:44 [63:20] Reserved.
 *  done:20 [19:0](R/W/H) Done count. When CPT_INST_S[DONEINT] set and that
 *	instruction completes, CPT()_VQ()_DONE[DONE] is incremented when the
 *	instruction finishes. Write to this field are for diagnostic use only;
 *	instead software writes CPT()_VQ()_DONE_ACK with the number of
 *	decrements for this field.
 *	Interrupts are sent as follows:
 *	* When CPT()_VQ()_DONE[DONE] = 0, then no results are pending, the
 *	interrupt coalescing timer is held to zero, and an interrupt is not
 *	sent.
 *	* When CPT()_VQ()_DONE[DONE] != 0, then the interrupt coalescing timer
 *	counts. If the counter is >= CPT()_VQ()_DONE_WAIT[TIME_WAIT]*1024, or
 *	CPT()_VQ()_DONE[DONE] >= CPT()_VQ()_DONE_WAIT[NUM_WAIT], i.e. enough
 *	time has passed or enough results have arrived, then the interrupt is
 *	sent.
 *	* When CPT()_VQ()_DONE_ACK is written (or CPT()_VQ()_DONE is written
 *	but this is not typical), the interrupt coalescing timer restarts.
 *	Note after decrementing this interrupt equation is recomputed,
 *	for example if CPT()_VQ()_DONE[DONE] >= CPT()_VQ()_DONE_WAIT[NUM_WAIT]
 *	and because the timer is zero, the interrupt will be resent immediately.
 *	(This covers the race case between software acknowledging an interrupt
 *	and a result returning.)
 *	* When CPT()_VQ()_DONE_ENA_W1S[DONE] = 0, interrupts are not sent,
 *	but the counting described above still occurs.
 *	Since CPT instructions complete out-of-order, if software is using
 *	completion interrupts the suggested scheme is to request a DONEINT on
 *	each request, and when an interrupt arrives perform a "greedy" scan for
 *	completions; even if a later command is acknowledged first this will
 *	not result in missing a completion.
 *	Software is responsible for making sure [DONE] does not overflow;
 *	for example by insuring there are not more than 2^20-1 instructions in
 *	flight that may request interrupts.
 *
 */
union cptx_vqx_done {
	u64 u;
	struct cptx_vqx_done_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_20_63:44;
		u64 done:20;
#else /* Word 0 - Little Endian */
		u64 done:20;
		u64 reserved_20_63:44;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_done_wait
 *
 * CPT Queue Done Interrupt Coalescing Wait Registers
 * Specifies the per queue interrupt coalescing settings.
 * cptx_vqx_done_wait_s
 * Word0
 *  reserved_48_63:16 [63:48] Reserved.
 *  time_wait:16; [47:32](R/W) Time hold-off. When CPT()_VQ()_DONE[DONE] = 0
 *	or CPT()_VQ()_DONE_ACK is written a timer is cleared. When the timer
 *	reaches [TIME_WAIT]*1024 then interrupt coalescing ends.
 *	see CPT()_VQ()_DONE[DONE]. If 0x0, time coalescing is disabled.
 *  reserved_20_31:12 [31:20] Reserved.
 *  num_wait:20 [19:0](R/W) Number of messages hold-off.
 *	When CPT()_VQ()_DONE[DONE] >= [NUM_WAIT] then interrupt coalescing ends
 *	see CPT()_VQ()_DONE[DONE]. If 0x0, same behavior as 0x1.
 *
 */
union cptx_vqx_done_wait {
	u64 u;
	struct cptx_vqx_done_wait_s {
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

/**
 * Register (NCB) cpt#_vq#_done_ena_w1s
 *
 * CPT Queue Done Interrupt Enable Set Registers
 * Write 1 to these registers will enable the DONEINT interrupt for the queue.
 * cptx_vqx_done_ena_w1s_s
 * Word0
 *  reserved_1_63:63 [63:1] Reserved.
 *  done:1 [0:0](R/W1S/H) Write 1 will enable DONEINT for this queue.
 *	Write 0 has no effect. Read will return the enable bit.
 */
union cptx_vqx_done_ena_w1s {
	u64 u;
	struct cptx_vqx_done_ena_w1s_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_1_63:63;
		u64 done:1;
#else /* Word 0 - Little Endian */
		u64 done:1;
		u64 reserved_1_63:63;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_vq#_ctl
 *
 * CPT VF Queue Control Registers
 * This register configures queues. This register should be changed (other than
 * clearing [ENA]) only when quiescent (see CPT()_VQ()_INPROG[INFLIGHT]).
 * cptx_vqx_ctl_s
 * Word0
 *  reserved_1_63:63 [63:1] Reserved.
 *  ena:1 [0:0](R/W/H) Enables the logical instruction queue.
 *	See also CPT()_PF_Q()_CTL[CONT_ERR] and	CPT()_VQ()_INPROG[INFLIGHT].
 *	1 = Queue is enabled.
 *	0 = Queue is disabled.
 */
union cptx_vqx_ctl {
	u64 u;
	struct cptx_vqx_ctl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_1_63:63;
		u64 ena:1;
#else /* Word 0 - Little Endian */
		u64 ena:1;
		u64 reserved_1_63:63;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (NCB) cpt#_pf_q#_gmctl
 *
 * CPT Queue Guest Machine Control Register
 * This register configures queues. This register should be changed only when
 * quiescent, (see CPT()_VQ()_INPROG[INFLIGHT]).
 *
 * Word0
 *  [23:16](R/W) Low 8 bits of the SMMU stream identifier to use when issuing
 *  requests. Stream 0x0 corresponds to the PF, and VFs start at 0x1.
 *  Reset such that VF0/index 0 is 0x1, VF1/index 1 is 0x2, etc.
 *  Maximum legal value is 64.
 *  [15:0](R/W) Guest machine identifier. The GMID to send to FPA for all
 *  buffer free, or to SSO for all submit work operations initiated by this
 *  queue. Must be nonzero or FPA/SSO will drop requests; see FPA_PF_MAP()
 *  and SSO_PF_MAP().
 */
union cptx_pf_qx_gmctl {
	u64 u;
	struct cptx_pf_qx_gmctl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t reserved_24_63			: 40;
		uint64_t strm				: 8;
		uint64_t gmid				: 16;
#else /* Word 0 - Little Endian */
		uint64_t gmid				: 16;
		uint64_t strm				: 8;
		uint64_t reserved_24_63			: 40;
#endif /* Word 0 - End */
	} s;
};

/**
 * Error Address/Error Codes
 *
 * In the event of a severe error, microcode writes an 8-byte Error Code
 * value (ECODE) to host memory at the Rptr address specified by the host
 * system (in the 64-byte request).
 *
 * Word0
 *  [63:56](R) 8-bit completion code
 *  [55:48](R) Number of the core that reported the severe error
 *  [47:0] Lower 6 bytes of M−Inst word2. Used to assist in uniquely
 *  identifying which specific instruction caused the error. This assumes
 *  that each instruction has a unique result location (RPTR), at least
 *  for a given period of time.
 */
union error_code {
	u64 u;
	struct error_code_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		uint64_t ccode				: 8;
		uint64_t coreid				: 8;
		uint64_t rptr6				: 48;
#else /* Word 0 - Little Endian */
		uint64_t rptr6				: 48;
		uint64_t coreid				: 8;
		uint64_t ccode				: 8;
#endif /* Word 0 - End */
	} s;
};

/**
 * Register (RVU_PF_BAR0) cpt#_af_constants1
 *
 * CPT AF Constants Register
 * This register contains implementation-related parameters of CPT.
 */
union cptx_af_constants1 {
	uint64_t u;
	struct cptx_af_constants1_s {
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

/**
 * RVU_PFVF_BAR2 - cpt_lf_misc_int
 *
 * This register contain the per-queue miscellaneous interrupts.
 *
 */
union cptx_lf_misc_int {
	uint64_t u;
	struct cptx_lf_misc_int_s {
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

/**
 * RVU_PFVF_BAR2 - cpt_lf_misc_int_ena_w1s
 *
 * This register sets interrupt enable bits.
 *
 */
union cptx_lf_misc_int_ena_w1s {
	uint64_t u;
	struct cptx_lf_misc_int_ena_w1s_s {
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

/**
 * RVU_PFVF_BAR2 - cpt_lf_ctl
 *
 * This register configures the queue.
 *
 * When the queue is not execution-quiescent (see CPT_LF_INPROG[EENA,INFLIGHT]),
 * software must only write this register with [ENA]=0.
 */
union cptx_lf_ctl {
	uint64_t u;
	struct cptx_lf_ctl_s {
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

/**
 * RVU_PFVF_BAR2 - cpt_lf_inprog
 *
 * These registers contain the per-queue instruction in flight registers.
 *
 */
union cptx_lf_inprog {
	uint64_t u;
	struct cptx_lf_inprog_s {
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

/**
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
union cptx_lf_q_base {
	uint64_t u;
	struct cptx_lf_q_base_s {
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

/**
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
union cptx_lf_q_size {
	uint64_t u;
	struct cptx_lf_q_size_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
	uint64_t reserved_15_63              : 49;
	uint64_t size_div40                  : 15;
#else /* Word 0 - Little Endian */
	uint64_t size_div40                  : 15;
	uint64_t reserved_15_63              : 49;
#endif
	} s;
};

/**
 * RVU_PF_BAR0 - cpt_af_lf_ctl
 *
 * This register configures queues. This register should be written only
 * when the queue is execution-quiescent (see CPT_LF_INPROG[INFLIGHT]).
 */
union cptx_af_lf_ctrl {
	uint64_t u;
	struct cptx_af_lf_ctrl_s {
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

#endif /*__CPT_HW_TYPES_H*/
