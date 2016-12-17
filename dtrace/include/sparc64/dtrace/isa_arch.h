#ifndef _SPARC64_ISA_ARCH_H
#define _SPARC64_ISA_ARCH_H

/*
 * FILE:        isa_arch.c
 * DESCRIPTION: Dynamic Tracing: sparc64 ISA-specific definitions
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2016 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/* Register indices */
#define ASM_REG_G0		0
#define ASM_REG_G1		(ASM_REG_G0 + 1)
#define ASM_REG_G2		(ASM_REG_G0 + 2)
#define ASM_REG_G3		(ASM_REG_G0 + 3)
#define ASM_REG_G4		(ASM_REG_G0 + 4)
#define ASM_REG_G5		(ASM_REG_G0 + 5)
#define ASM_REG_G6		(ASM_REG_G0 + 6)
#define ASM_REG_G7		(ASM_REG_G0 + 7)

#define ASM_REG_O0		(ASM_REG_G7 + 1)	/* 8 */
#define ASM_REG_O1		(ASM_REG_O0 + 1)
#define ASM_REG_O2		(ASM_REG_O0 + 2)
#define ASM_REG_O3		(ASM_REG_O0 + 3)
#define ASM_REG_O4		(ASM_REG_O0 + 4)
#define ASM_REG_O5		(ASM_REG_O0 + 5)
#define ASM_REG_O6		(ASM_REG_O0 + 6)
#define ASM_REG_O7		(ASM_REG_O0 + 7)

#define ASM_REG_L0		(ASM_REG_O7 + 1)	/* 16 */
#define ASM_REG_L1		(ASM_REG_L0 + 1)
#define ASM_REG_L2		(ASM_REG_L0 + 2)
#define ASM_REG_L3		(ASM_REG_L0 + 3)
#define ASM_REG_L4		(ASM_REG_L0 + 4)
#define ASM_REG_L5		(ASM_REG_L0 + 5)
#define ASM_REG_L6		(ASM_REG_L0 + 6)
#define ASM_REG_L7		(ASM_REG_L0 + 7)

#define ASM_REG_I0		(ASM_REG_L7 + 1)	/* 24 */
#define ASM_REG_I1		(ASM_REG_I0 + 1)
#define ASM_REG_I2		(ASM_REG_I0 + 2)
#define ASM_REG_I3		(ASM_REG_I0 + 3)
#define ASM_REG_I4		(ASM_REG_I0 + 4)
#define ASM_REG_I5		(ASM_REG_I0 + 5)
#define ASM_REG_I6		(ASM_REG_I0 + 6)
#define ASM_REG_I7		(ASM_REG_I0 + 7)

#define REG_CCR			(ASM_REG_I7 + 1)	/* 32 */
#define REG_PC			(REG_CCR + 1)		/* 33 */
#define REG_nPC			(REG_PC + 1)		/* 34 */
#define REG_Y			(REG_nPC + 1)		/* 35 */
#define REG_ASI			(REG_Y + 1)		/* 36 */
#define REG_FPRS		(REG_ASI + 1)		/* 37 */

#define ASM_REG_PC		5

#define ASM_REG_ISGLOBAL(r)	((r) >= ASM_REG_G0 && (r) <= ASM_REG_G7)
#define ASM_REG_ISOUTPUT(r)	((r) >= ASM_REG_O0 && (r) <= ASM_REG_O7)
#define ASM_REG_ISLOCAL(r)	((r) >= ASM_REH_L0 && (r) <= ASM_REG_L7)
#define ASM_REG_ISINPUT(r)	((r) >= ASM_REG_I0 && (r) <= ASM_REG_I7)
#define ASM_REG_ISVOLATILE(r)						      \
        ((ASM_REG_ISGLOBAL(r) || ASM_REG_ISOUTPUT(r)) && (r) != ASM_REG_G0)
#define ASM_REG_NLOCALS		8

#define ASM_REG_MARKLOCAL(locals, r)					      \
	if (ASM_REG_ISLOCAL(r))						      \
		(locals)[(r) - ASM_REG_L0] = 1;

#define ASM_REG_INITLOCALS(local, locals)				      \
	for ((local) = 0; (local) < ASM_REG_NLOCALS; (local)++)		      \
		(locals)[(local)] = 0;					      \
	(local) = ASM_REG_L0

#define ASM_REG_ALLOCLOCAL(local, locals)				      \
	while ((locals)[(local) - ASM_REG_L0])				      \
		(local)++;						      \
	(locals)[(local) - ASM_REG_L0] = 1;

#define ASM_OP_MASK		0xc0000000
#define ASM_OP_SHIFT		30
#define ASM_OP(val)		((val) & ASM_OP_MASK)

#define ASM_SIMM13_MASK		0x1fff
#define ASM_SIMM13_MAX		((int32_t)0xfff)
#define ASM_IMM22_MASK		0x3fffff
#define ASM_IMM22_SHIFT		10
#define ASM_IMM10_MASK		0x3ff

#define ASM_DISP30_MASK		0x3fffffff
#define ASM_DISP30(from, to)						      \
	(((long)(to) - (long)(from)) >= 0				      \
	  ? ((((uintptr_t)(to) - (uintptr_t)(from)) >> 2) & ASM_DISP30_MASK)  \
	  : ((((long)(to) - (long)(from)) >> 2) & ASM_DISP30_MASK))

#define ASM_DISP22_MASK		0x3fffff
#define ASM_DISP22(from, to)						      \
	((((uintptr_t)(to) - (uintptr_t)(from)) >> 2) & ASM_DISP22_MASK)

#define ASM_DISP19_MASK		0x7ffff
#define ASM_DISP19(from, to)						      \
	((((uintptr_t)(to) - (uintptr_t)(from)) >> 2) & ASM_DISP19_MASK)

#define ASM_DISP16_HISHIFT	20
#define ASM_DISP16_HIMASK	(0x3 << ASM_DISP16_HISHIFT)
#define ASM_DISP16_LOMASK	(0x3fff)
#define ASM_DISP16_MASK		(ASM_DISP16_HIMASK | ASM_DISP16_LOMASK)
#define ASM_DISP16(val)							      \
	((((val) & ASM_DISP16_HIMASK) >> 6) | ((val) & ASM_DISP16_LOMASK))

#define ASM_DISP14_MASK		0x3fff
#define ASM_DISP14(from, to)						      \
	(((uintptr_t)(to) - (uintptr_t)(from) >> 2) & ASM_DISP14_MASK)

#define ASM_OP0			(((uint32_t)0) << ASM_OP_SHIFT)
#define ASM_OP1			(((uint32_t)1) << ASM_OP_SHIFT)
#define ASM_OP2			(((uint32_t)2) << ASM_OP_SHIFT)
#define ASM_ILLTRAP		0

#define ASM_ANNUL_SHIFT		29
#define ASM_ANNUL		(1 << ASM_ANNUL_SHIFT)

#define ASM_FMT3_OP3_SHIFT	19
#define ASM_FMT3_OP_MASK	0xc1f80000
#define ASM_FMT3_OP(val)	((val) & ASM_FMT3_OP_MASK)

#define ASM_FMT3_RD_SHIFT	25
#define ASM_FMT3_RD_MASK	(0x1f << ASM_FMT3_RD_SHIFT)
#define ASM_FMT3_RD(val)						      \
	(((val) & ASM_FMT3_RD_MASK) >> ASM_FMT3_RD_SHIFT)

#define ASM_FMT3_RS1_SHIFT	14
#define ASM_FMT3_RS1_MASK	(0x1f << ASM_FMT3_RS1_SHIFT)
#define ASM_FMT3_RS1(val)						      \
	(((val) & ASM_FMT3_RS1_MASK) >> ASM_FMT3_RS1_SHIFT)
#define ASM_FMT3_RS1_SET(val, rs1)					      \
	(val) = ((val) & ~ASM_FMT3_RS1_MASK) | ((rs1) << ASM_FMT3_RS1_SHIFT)

#define ASM_FMT3_RS2_SHIFT	0
#define ASM_FMT3_RS2_MASK	(0x1f << ASM_FMT3_RS2_SHIFT)
#define ASM_FMT3_RS2(val)						      \
	(((val) & ASM_FMT3_RS2_MASK) >> ASM_FMT3_RS2_SHIFT)
#define ASM_FMT3_RS2_SET(val, rs2)					      \
	(val) = ((val) & ~ASM_FMT3_RS2_MASK) | ((rs2) << ASM_FMT3_RS2_SHIFT)

#define ASM_FMT3_IMM_SHIFT	13
#define ASM_FMT3_IMM		(1 << ASM_FMT3_IMM_SHIFT)
#define ASM_FMT3_SIMM13_MASK	ASM_SIMM13_MASK

#define ASM_FMT3_ISIMM(val)	((val) & ASM_FMT3_IMM)
#define ASM_FMT3_SIMM13(val)	((val) & ASM_FMT3_SIMM13_MASK)

#define ASM_FMT2_OP2_SHIFT	22
#define ASM_FMT2_OP2_MASK	(0x7 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_RD_SHIFT	25

#define ASM_FMT1_OP(val)	((val) & ASM_OP_MASK)
#define ASM_FMT1_DISP30(val)	((val) & ASM_DISP30_MASK)

#define ASM_FMT2_OP2_BPCC	(0x01 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_OP2_BCC	(0x02 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_OP2_BPR	(0x03 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_OP2_SETHI	(0x04 << ASM_FMT2_OP2_SHIFT)

#define ASM_FMT2_COND_SHIFT	25
#define ASM_FMT2_COND_BA	(0x8 << ASM_FMT2_COND_SHIFT)
#define ASM_FMT2_COND_BL	(0x3 << ASM_FMT2_COND_SHIFT)
#define ASM_FMT2_COND_BGE	(0xb << ASM_FMT2_COND_SHIFT)

#define ASM_OP_RESTORE		(ASM_OP2 | (0x3d << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_SAVE		(ASM_OP2 | (0x3c << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_JMPL		(ASM_OP2 | (0x38 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_RETURN		(ASM_OP2 | (0x39 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_CALL		ASM_OP1
#define ASM_OP_SETHI		(ASM_OP0 | ASM_FMT2_OP2_SETHI)
#define ASM_OP_ADD		(ASM_OP2 | (0x00 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_OR		(ASM_OP2 | (0x02 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_SUB		(ASM_OP2 | (0x04 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_CC		(ASM_OP2 | (0x10 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_UDIV		(ASM_OP2 | (0x0e << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_BA		(ASM_OP0 | ASM_FMT2_OP2_BCC | ASM_FMT2_COND_BA)
#define ASM_OP_BL		(ASM_OP0 | ASM_FMT2_OP2_BCC | ASM_FMT2_COND_BL)
#define ASM_OP_BGE		(ASM_OP0 | ASM_FMT2_OP2_BCC | ASM_FMT2_COND_BGE)
#define ASM_OP_BAPCC		(ASM_OP0 | ASM_FMT2_OP2_BPCC | ASM_FMT2_COND_BA)
#define ASM_OP_RD		(ASM_OP2 | (0x28 << ASM_FMT3_OP3_SHIFT))

#define ASM_ORLO(rs, val, rd)						      \
	(ASM_OP_OR | ((rs) << ASM_FMT3_RS1_SHIFT) |			      \
	 ((rd) << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM | ((val) & ASM_IMM10_MASK))

#define ASM_ORSIMM13(rs, val, rd)					      \
	(ASM_OP_OR | ((rs) << ASM_FMT3_RS1_SHIFT) |			      \
	 ((rd) << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM |			      \
	 ((val) & ASM_SIMM13_MASK))

#define ASM_ADDSIMM13(rs, val, rd)					      \
	(ASM_OP_ADD | ((rs) << ASM_FMT3_RS1_SHIFT) |			      \
	 ((rd) << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM |			      \
	 ((val) & ASM_SIMM13_MASK))

#define ASM_UDIVSIMM13(rs, val, rd)					      \
	(ASM_OP_UDIV | ((rs) << ASM_FMT3_RS1_SHIFT) |			      \
	 ((rd) << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM |			      \
	 ((val) & ASM_SIMM13_MASK))

#define ASM_ADD(rs1, rs2, rd)						      \
	(ASM_OP_ADD | ((rs1) << ASM_FMT3_RS1_SHIFT) |			      \
	 ((rs2) << ASM_FMT3_RS2_SHIFT) | ((rd) << ASM_FMT3_RD_SHIFT))

#define ASM_CMP(rs1, rs2)						      \
	(ASM_OP_SUB | ASM_OP_CC | ((rs1) << ASM_FMT3_RS1_SHIFT) |	      \
	 ((rs2) << ASM_FMT3_RS2_SHIFT) | (ASM_REG_G0 << ASM_FMT3_RD_SHIFT))

#define ASM_MOV(rs, rd)							      \
	(ASM_OP_OR | (ASM_REG_G0 << ASM_FMT3_RS1_SHIFT) |		      \
	 ((rs) << ASM_FMT3_RS2_SHIFT) | ((rd) << ASM_FMT3_RD_SHIFT))

#define ASM_SETHI(val, reg)						      \
	(ASM_OP_SETHI | (reg << ASM_FMT2_RD_SHIFT) |			      \
	 ((val >> ASM_IMM22_SHIFT) & ASM_IMM22_MASK))

#define ASM_NOP			ASM_SETHI(0, 0)

#define ASM_CALL(orig, dest)	(ASM_OP_CALL | ASM_DISP30(orig, dest))

#define ASM_RET								      \
	(ASM_OP_JMPL | (ASM_REG_I7 << ASM_FMT3_RS1_SHIFT) |		      \
	 (ASM_REG_G0 << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM |		      \
	 (sizeof (asm_instr_t) << 1))

#define ASM_RETL							      \
	(ASM_OP_JMPL | (ASM_REG_O7 << ASM_FMT3_RS1_SHIFT) |		      \
	 (ASM_REG_G0 << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM |		      \
	 (sizeof (asm_instr_t) << 1))

#define ASM_SAVEIMM(rd, val, rs1)					      \
	(ASM_OP_SAVE | ((rs1) << ASM_FMT3_RS1_SHIFT) |			      \
	 ((rd) << ASM_FMT3_RD_SHIFT) | ASM_FMT3_IMM | ((val) & ASM_SIMM13_MASK))

#define ASM_RESTORE(rd, rs1, rs2)					      \
	(ASM_OP_RESTORE | ((rs1) << ASM_FMT3_RS1_SHIFT) |		      \
	 ((rd) << ASM_FMT3_RD_SHIFT) | ((rs2) << ASM_FMT3_RS2_SHIFT))

#define ASM_RETURN(rs1, val)						      \
	(ASM_OP_RETURN | ((rs1) << ASM_FMT3_RS1_SHIFT) |		      \
	 ASM_FMT3_IMM | ((val) & ASM_SIMM13_MASK))

#define ASM_BA(orig, dest)	(ASM_OP_BA | ASM_DISP22(orig, dest))
#define ASM_BAA(orig, dest)	(ASM_BA(orig, dest) | ASM_ANNUL)
#define ASM_BL(orig, dest)	(ASM_OP_BL | ASM_DISP22(orig, dest))
#define ASM_BGE(orig, dest)	(ASM_OP_BGE | ASM_DISP22(orig, dest))
#define ASM_BDEST(va, instr)	((uintptr_t)(va) +			      \
	(((int32_t)(((instr) & ASM_DISP22_MASK) << 10)) >> 8))
#define ASM_BPCCDEST(va, instr)	((uintptr_t)(va) +			      \
	(((int32_t)(((instr) & ASM_DISP19_MASK) << 13)) >> 11))
#define ASM_BPRDEST(va, instr)	((uintptr_t)(va) +			      \
	(((int32_t)((ASM_DISP16(instr)) << 16)) >> 14))

/*
 * We're only going to treat a save as safe if
 *   (a) both rs1 and rd are %sp and
 *   (b) if the instruction has a simm, the value isn't 0.
 */
#define ASM_IS_SAVE(instr)						      \
	(ASM_FMT3_OP(instr) == ASM_OP_SAVE &&				      \
	 ASM_FMT3_RD(instr) == ASM_REG_O6 &&				      \
	 ASM_FMT3_RS1(instr) == ASM_REG_O6 &&				      \
	 !(ASM_FMT3_ISIMM(instr) && ASM_FMT3_SIMM13(instr) == 0))

#define ASM_IS_BA(instr)	(((instr) & ~ASM_DISP22_MASK) == ASM_OP_BA)
#define ASM_IS_BAPCC(instr)	(((instr) & ~ASM_DISP22_MASK) == ASM_OP_BAPCC)

#define ASM_IS_RDPC(instr)	((ASM_FMT3_OP(instr) == ASM_OP_RD) &&	      \
				 (ASM_FMT3_RD(instr) == ASM_REG_PC))

#define ASM_IS_PCRELATIVE(instr)					      \
        ((((instr) & ASM_OP_MASK) == ASM_OP0 &&				      \
	  ((instr) & ASM_FMT2_OP2_MASK) != ASM_FMT2_OP2_SETHI) ||	      \
	 ((instr) & ASM_OP_MASK) == ASM_OP1 ||				      \
	 ASM_IS_RDPC(instr))

#define ASM_IS_CTI(instr)						      \
	((((instr) & ASM_OP_MASK) == ASM_OP0 &&				      \
	  ((instr) & ASM_FMT2_OP2_MASK) != ASM_FMT2_OP2_SETHI) ||	      \
	 ((instr) & ASM_OP_MASK) == ASM_OP1 ||				      \
	 (ASM_FMT3_OP(instr) == ASM_OP_JMPL) ||				      \
	 (ASM_FMT3_OP(instr) == ASM_OP_RETURN))

#define ASM_IS_NOP(instr)	((instr) == ASM_NOP)

#define ASM_IS_CALL(instr)	(((instr) & ASM_OP_MASK) == ASM_OP_CALL)

#define ASM_MOD_INPUTS(instr)	(ASM_OP(instr) == ASM_OP2 &&		      \
				 ASM_REG_ISINPUT(ASM_FMT3_RD(instr)))
#define ASM_MOD_OUTPUTS(instr)	(ASM_OP(instr) == ASM_OP2 &&		      \
				 ASM_REG_ISOUTPUT(ASM_FMT3_RD(instr)))

/*
 * Our own personal SPARC V9 stack layout structure, because the one in
 * <kernel-source-tree>/arch/sparc/include/uapi/asm/ptrace.h is wrong.
 */
struct sparc_v9_frame {
	unsigned long locals[8];
	unsigned long ins[6];
	struct sparc_v9_frame *fp;
	unsigned long callers_pc;
	unsigned long xargs[6];
	unsigned long xxargs[1];
};

#endif /* _SPARC64_ISA_ARCH_H */
