/*
 * FILE:	fbt_x86_64.c
 * DESCRIPTION:	DTrace - FBT provider implementation for x86
 *
 * Copyright (c) 2010, 2018, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/dtrace_fbt.h>
#include <linux/vmalloc.h>
#include <asm/dtrace_util.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

/*
 * Use 0xf0 (LOCK Prefix) and X86_TRAP_UD for Invalid Opcode traps to be used.
 * Use 0xcc (INT 3) and X86_TRAP_BP for Breakpoint traps to be used.
 */
#define FBT_ENTRY_PATCHVAL		0xcc
#define FBT_ENTRY_TRAP			X86_TRAP_BP
#define FBT_RETURN_PATCHVAL		0xcc
#define FBT_RETURN_TRAP			X86_TRAP_BP

static uint8_t fbt_invop(struct pt_regs *regs)
{
	fbt_probe_t	*fbp = fbt_probetab[FBT_ADDR2NDX(regs->ip)];

	for (; fbp != NULL; fbp = fbp->fbp_hashnext) {
		if ((uintptr_t)fbp->fbp_patchpoint == regs->ip) {
			struct pt_regs *old_regs = this_cpu_core->cpu_dtrace_regs;

			this_cpu_core->cpu_dtrace_regs = regs;
			if (fbp->fbp_roffset == 0) {
				dtrace_probe(fbp->fbp_id, regs->di, regs->si,
					     regs->dx, regs->cx, regs->r8,
					     regs->r9, 0);
			} else {
				dtrace_probe(fbp->fbp_id, fbp->fbp_roffset,
					     regs->ax, 0, 0, 0, 0, 0);
			}

			this_cpu_core->cpu_dtrace_regs = old_regs;

			return fbp->fbp_rval;
		}
	}

	return 0;
}

uint64_t fbt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		    int aframes)
{
	struct pt_regs  *regs = this_cpu_core->cpu_dtrace_regs;
	uint64_t	*st;
	uint64_t	val;

	if (regs == NULL)
		return 0;

	switch (argno) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->cx;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	}

	ASSERT(argno > 5);

	st = (uint64_t *)regs->sp;
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	/*
	 * Skip the topmost slot of the stack because that holds the return
	 * address for the call to the function we are entering.  At this point
	 * the BP has not been pushed yet, so we are still working within the
	 * caller's stack frame.
	 */
	val = st[1 + argno - 6];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return val;
}

void fbt_provide_probe_arch(fbt_probe_t *fbp, int type, int stype)
{
	fbp->fbp_patchval = type == FBT_ENTRY ? FBT_ENTRY_PATCHVAL
					      : FBT_RETURN_PATCHVAL;
	fbp->fbp_savedval = *fbp->fbp_patchpoint;
	fbp->fbp_rval = type == FBT_ENTRY ? DTRACE_INVOP_PUSH_BP
					  : DTRACE_INVOP_RET;
}

int fbt_can_patch_return_arch(asm_instr_t *addr)
{
	return 1;
}

int fbt_provide_module_arch(void *arg, struct module *mp)
{
	return 1;
}

void fbt_destroy_module(void *arg, struct module *mp)
{
}

void fbt_enable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_invop_enable(fbp->fbp_patchpoint, fbp->fbp_patchval);
}

void fbt_disable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_invop_disable(fbp->fbp_patchpoint, fbp->fbp_savedval);
}

int fbt_dev_init_arch(void)
{
	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab = dtrace_vzalloc_try(fbt_probetab_size *
					  sizeof (fbt_probe_t *));

	if (fbt_probetab == NULL)
		return -ENOMEM;

	return dtrace_invop_add(fbt_invop);
}

void fbt_dev_exit_arch(void)
{
	vfree(fbt_probetab);
	fbt_probetab_mask = 0;
	fbt_probetab_size = 0;

	dtrace_invop_remove(fbt_invop);
}
