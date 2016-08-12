#ifndef _SPARC64_ISA_ARCH_H
#define _SPARC64_ISA_ARCH_H

/*
 * FILE:	isa_arch.h
 * DESCRIPTION:	Dynamic Tracing: sparc64 ISA-specific definitions
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
#define REG_G0		0
#define REG_G1		(REG_G0 + 1)
#define REG_G2		(REG_G0 + 2)
#define REG_G3		(REG_G0 + 3)
#define REG_G4		(REG_G0 + 4)
#define REG_G5		(REG_G0 + 5)
#define REG_G6		(REG_G0 + 6)
#define REG_G7		(REG_G0 + 7)

#define REG_O0		(REG_G7 + 1)	/* 8 */
#define REG_O1		(REG_O0 + 1)
#define REG_O2		(REG_O0 + 2)
#define REG_O3		(REG_O0 + 3)
#define REG_O4		(REG_O0 + 4)
#define REG_O5		(REG_O0 + 5)
#define REG_O6		(REG_O0 + 6)
#define REG_O7		(REG_O0 + 7)

#define REG_L0		(REG_O7 + 1)	/* 16 */
#define REG_L1		(REG_L0 + 1)
#define REG_L2		(REG_L0 + 2)
#define REG_L3		(REG_L0 + 3)
#define REG_L4		(REG_L0 + 4)
#define REG_L5		(REG_L0 + 5)
#define REG_L6		(REG_L0 + 6)
#define REG_L7		(REG_L0 + 7)

#define REG_I0		(REG_L7 + 1)	/* 24 */
#define REG_I1		(REG_I0 + 1)
#define REG_I2		(REG_I0 + 2)
#define REG_I3		(REG_I0 + 3)
#define REG_I4		(REG_I0 + 4)
#define REG_I5		(REG_I0 + 5)
#define REG_I6		(REG_I0 + 6)
#define REG_I7		(REG_I0 + 7)

#define REG_CCR		(REG_I7 + 1)	/* 32 */

#define REG_PC		(REG_CCR + 1)	/* 33 */
#define REG_nPC		(REG_PC + 1)	/* 34 */
#define REG_Y		(REG_nPC + 1)	/* 35 */

#define	REG_ASI		(REG_Y + 1)	/* 36 */
#define	REG_FPRS	(REG_ASI + 1)	/* 37 */

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
