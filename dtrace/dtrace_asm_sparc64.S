/*
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
 */
/*
 * Copyright 2010-2014 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/linkage.h>
#include <asm/asi.h>

#define CPU_DTRACE_BADADDR	0x0004	/* DTrace fault: bad address */
#define	ASI_USER		ASI_AIUS
#define nwin_minus_one		0x7

	ENTRY(dtrace_getfp)
	retl
	mov	%fp, %o0
	ENDPROC(dtrace_getfp)

	ENTRY(dtrace_cas32)
	cas	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	ENDPROC(dtrace_cas32)

	ENTRY(dtrace_casptr)
	casn	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	ENDPROC(dtrace_casptr)

	ENTRY(dtrace_fish)
	rd	%pc, %g5
	ba	0f
	add	%g5, 12, %g5
	mov	%l0, %g4
	mov	%l1, %g4
	mov	%l2, %g4
	mov	%l3, %g4
	mov	%l4, %g4
	mov	%l5, %g4
	mov	%l6, %g4
	mov	%l7, %g4
	mov	%i0, %g4
	mov	%i1, %g4
	mov	%i2, %g4
	mov	%i3, %g4
	mov	%i4, %g4
	mov	%i5, %g4
	mov	%i6, %g4
	mov	%i7, %g4
0:
	sub	%o1, 16, %o1		! Can only retrieve %l's and %i's
	sll	%o1, 2, %o1		! Multiply by instruction size
	add	%g5, %o1, %g5		! %g5 now contains the instr. to pick

	mov	nwin_minus_one, %g4

	!
	! First we need to see if the frame that we're fishing in is still
	! contained in the register windows.
	!
	rdpr	%canrestore, %g2
	cmp	%g2, %o0
	bl	%icc, 2f
	rdpr	%cwp, %g1
	sub	%g1, %o0, %g3
	brgez,a,pt	%g3, 0f
	wrpr	%g3, %cwp

	!
	! CWP minus the number of frames is negative; we must perform the
	! arithmetic modulo MAXWIN.
	!
	add	%g4, %g3, %g3
	inc	%g3
	wrpr	%g3, %cwp
0:
	jmp	%g5
	ba	1f
1:
	wrpr	%g1, %cwp
	stn	%g4, [%o2]
	retl
	clr	%o0			! Success; return 0.
2:
	!
	! The frame that we're looking for has been flushed to the stack; the
	! caller will be forced to retrieve regiters from there.
	!
	retl
	add	%g2, 1, %o0		! Failure; return deepest frame + 1
	ENDPROC(dtrace_fish)

/* FIXME */
	ENTRY(dtrace_caller)
	mov	nwin_minus_one, %g4
	rdpr	%canrestore, %g2
	cmp	%g2, %o0
	bl	%icc, 1f
	rdpr	%cwp, %g1
	sub	%g1, %o0, %g3
	brgez,a,pt %g3, 0f
	wrpr	%g3, %cwp
	!
	! CWP minus the number of frames is negative; we must perform the
	! arithmetic modulo MAXWIN.
	!
	add	%g4, %g3, %g3
	inc	%g3
	wrpr	%g3, %cwp
0:
	mov	%i7, %g4
	wrpr	%g1, %cwp
	retl
	mov	%g4, %o0
1:
	!
	! The caller has been flushed to the stack.  This is unlikely
        ! (interrupts are disabled in dtrace_probe()), but possible (the
        ! interrupt inducing the spill may have been taken before the
        ! call to dtrace_probe()).
	!
	retl
	mov	-1, %o0
	ENDPROC(dtrace_caller)

	ENTRY(dtrace_copyin_arch)
	tst	%o2
	bz	2f
	clr	%g1
	lduba	[%o0 + %g1]ASI_USER, %g2
0:
	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	stub	%g2, [%o1 + %g1]
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	inc	%g1
	cmp	%g1, %o2
	bl,a	0b
	lduba	[%o0 + %g1]ASI_USER, %g2
2:
	retl
	nop
	ENDPROC(dtrace_copyin_arch)

	ENTRY(dtrace_copyinstr_arch)
	tst	%o2
	bz	2f
	clr	%g1
	lduba	[%o0 + %g1]ASI_USER, %g2
0:
	stub	%g2, [%o1 + %g1]
	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	inc	%g1
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	cmp	%g2, 0
	be	2f
	cmp	%g1, %o2
	bl,a	0b
	lduba	[%o0 + %g1]ASI_USER, %g2
2:
	retl
	nop
	ENDPROC(dtrace_copyinstr_arch)

	ENTRY(dtrace_copyout)
	tst	%o2
	bz	2f
	clr	%g1
	ldub	[%o0 + %g1], %g2
0:
	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	stuba	%g2, [%o1 + %g1]ASI_USER
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	inc	%g1
	cmp	%g1, %o2
	bl,a	0b
	ldub	[%o0 + %g1], %g2
2:
	retl
	nop
	ENDPROC(dtrace_copyout)

	ENTRY(dtrace_copyoutstr)
	tst	%o2
	bz	2f
	clr	%g1
	ldub	[%o0 + %g1], %g2
0:
	stuba	%g2, [%o1 + %g1]ASI_USER
	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	inc	%g1
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	cmp	%g2, 0
	be	2f
	cmp	%g1, %o2
	bl,a	0b
	ldub	[%o0 + %g1], %g2
2:
	retl
	nop
	ENDPROC(dtrace_copyoutstr)

	ENTRY(dtrace_fulword)
	clr	%o1
	ldna	[%o0]ASI_USER, %o1
	retl
	mov	%o1, %o0
	ENDPROC(dtrace_fulword)

	ENTRY(dtrace_fuword8)
	clr	%o1
	lduba	[%o0]ASI_AIUS, %o1
	retl
	mov	%o1, %o0
	ENDPROC(dtrace_fuword8)

	ENTRY(dtrace_fuword16)
	clr	%o1
	lduha	[%o0]ASI_AIUS, %o1
	retl
	mov	%o1, %o0
	ENDPROC(dtrace_fuword16)

	ENTRY(dtrace_fuword32)
	clr	%o1
	lda	[%o0]ASI_AIUS, %o1
	retl
	mov	%o1, %o0
	ENDPROC(dtrace_fuword32)

	ENTRY(dtrace_fuword64)
	clr	%o1
	ldxa	[%o0]ASI_AIUS, %o1
	retl
	mov	%o1, %o0
	ENDPROC(dtrace_fuword64)

	ENTRY(dtrace_probe_error)
	save	%sp, -192, %sp
	sethi	%hi(dtrace_probeid_error), %l0
	ld	[%l0 + %lo(dtrace_probeid_error)], %o0
	mov	%i0, %o1
	mov	%i1, %o2
	mov	%i2, %o3
	mov	%i3, %o4
	call	dtrace_probe
	mov	%i4, %o5
	ret
	restore
	ENDPROC(dtrace_probe_error)
