/*
 * FILE:	fbt_sparc64.c
 * DESCRIPTION:	Function Boundary Tracing: architecture-specific implementation
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
 * Copyright 2010-2014 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace_fbt.h>
#include <asm/dtrace_util.h>
#include <dtrace/isa_arch.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

/*
 * For entry probes, we generate the following trampoline (for id < 0xfff):
 *
 *	sethi	%hi(id), %o0
 *	or	%o0, %lo(id), %o0
 *	mov	%i0, %o1
 *	mov	%i1, %o2
 *	mov	%i2, %o3
 *	mov	%i3, %o4
 *	mov	%i4, %o5
 *	call	dtrace_probe
 *	 nop
 *	sethi	%hi(instr), %o7
 *	or	%o7, %lo(instr), %o7
 *	retl
 *	 nop
 *
 * otherwise we use:
 *
 *	or	%g0, id, %o0
 *	mov	%i0, %o1
 *	mov	%i1, %o2
 *	mov	%i2, %o3
 *	mov	%i3, %o4
 *	mov	%i4, %o5
 *	call	dtrace_probe
 *	 nop
 *	sethi	%hi(instr), %o7
 *	or	%o7, %lo(instr), %o7
 *	retl
 *	 nop
 */
#ifndef FBT_TRAMP_SIZE
# error The kernel must define FBT_TRAMP_SIZE!
#elif FBT_TRAMP_SIZE < 13
# error FBT_TRAMP_SIZE must be at least 13 instructions!
#endif

static void add_entry_tramp(fbt_probe_t *fbp, int nargs)
{
	struct module	*mp = fbp->fbp_module;
	dtrace_id_t	id = fbp->fbp_id;
	size_t		idx = PDATA(mp)->fbt_probe_cnt;
	asm_instr_t	*trampoline = &(PDATA(mp)->fbt_tab[idx *
							   FBT_TRAMP_SIZE]);
	asm_instr_t	*instr = trampoline;

	if (id > (uint32_t)ASM_SIMM13_MAX) {
		*instr++ = ASM_SETHI(id, ASM_REG_O0);
		*instr++ = ASM_ORLO(ASM_REG_O0, id, ASM_REG_O0);
	} else
		*instr++ = ASM_ORSIMM13(ASM_REG_G0, id, ASM_REG_O0);

	if (nargs >= 1)
		*instr++ = ASM_MOV(ASM_REG_I0, ASM_REG_O1);
	if (nargs >= 2)
		*instr++ = ASM_MOV(ASM_REG_I1, ASM_REG_O2);
	if (nargs >= 3)
		*instr++ = ASM_MOV(ASM_REG_I2, ASM_REG_O3);
	if (nargs >= 4)
		*instr++ = ASM_MOV(ASM_REG_I3, ASM_REG_O4);
	if (nargs >= 5)
		*instr++ = ASM_MOV(ASM_REG_I4, ASM_REG_O5);

	*instr = ASM_CALL(instr, dtrace_probe);
        instr++;

	*instr++ = ASM_NOP;

	if ((uintptr_t)fbp->fbp_patchpoint > (uintptr_t)ASM_SIMM13_MAX) {
		*instr++ = ASM_SETHI(
				(uintptr_t)fbp->fbp_patchpoint, ASM_REG_O7
			   );
		*instr++ = ASM_ORLO(ASM_REG_O7, (uintptr_t)fbp->fbp_patchpoint,
				    ASM_REG_O7);
	} else
		*instr++ = ASM_ORSIMM13(ASM_REG_G0,
					(uintptr_t)fbp->fbp_patchpoint,
                                        ASM_REG_O7);

	*instr++ = ASM_RETL;
	*instr++ = ASM_NOP;

	fbp->fbp_patchval = ASM_CALL(fbp->fbp_patchpoint, trampoline);
	fbp->fbp_savedval = *fbp->fbp_patchpoint;
}

void fbt_provide_probe_arch(fbt_probe_t *fbp, int type, int stype)
{
	switch (type) {
	case FBT_ENTRY:
		add_entry_tramp(fbp, stype);
		return;
	case FBT_RETURN:
		pr_info("%s: %s: FBT_RETURN not supported yet\n",
			__func__, fbp->fbp_name);
		return;
	default:
		pr_info("%s: %s: Unknown FBT type %d\n",
			__func__, fbp->fbp_name, type);
		return;
	}
}

void fbt_enable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	*fbp->fbp_patchpoint = fbp->fbp_patchval;
}

void fbt_disable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	*fbp->fbp_patchpoint = fbp->fbp_savedval;
}

int fbt_dev_init_arch(void)
{
	return 0;
}

void fbt_dev_exit_arch(void)
{
}
