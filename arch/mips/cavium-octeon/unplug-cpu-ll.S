/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Cavium, Inc.
 */
#include <asm/asm.h>
#include <asm/regdef.h>
#include <asm/mipsregs.h>

#define	CVMCTL $9, 7

	.p2align 3
	.globl	octeon_replug_ll
	.type	octeon_replug_ll, @function
	.ent	octeon_replug_ll, 0
	.set	noreorder
	.set	noat
octeon_replug_ll:
	dmfc0	v0, CVMCTL
	nop

	ori	v0, 2
	nop

#ifdef CONFIG_CPU_BIG_ENDIAN
	xori	v0, 2
	nop
#endif
	dmtc0	v0, CVMCTL	/* Set proper endian mode for this kernel */
	nop

	/* Set a known operating mode */
	mfc0	v0, CP0_STATUS
	ori	v0, (ST0_IE | ST0_EXL | ST0_ERL | ST0_KX | ST0_SX | ST0_UX)
	xori	v0, ST0_IE
	mtc0	v0, CP0_STATUS
	/* Wait for NMI, which will vector us to the startup code. */
loop_wait:
	wait
	b	loop_wait
	 nop

	.end	octeon_replug_ll
	.size	octeon_replug_ll, .-octeon_replug_ll
