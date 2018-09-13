/*
 * FILE:	fbt_arm64.c
 * DESCRIPTION:	DTrace - FBT provider implementation for arm64
 *
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
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
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
#include <asm/dtrace_util.h>
#include <asm/debug-monitors.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

static int fbt_brk_hook(struct pt_regs *regs, unsigned int esr)
{
	uintptr_t	ip = instruction_pointer(regs);
	fbt_probe_t	*fbp = fbt_probetab[FBT_ADDR2NDX(ip)];

	for (; fbp != NULL; fbp = fbp->fbp_hashnext) {
		if ((uintptr_t)fbp->fbp_patchpoint == ip) {
			struct pt_regs	*oregs;

			oregs = this_cpu_core->cpu_dtrace_regs;
			this_cpu_core->cpu_dtrace_regs = regs;

			if (fbp->fbp_roffset == 0) {
				dtrace_probe(fbp->fbp_id, regs->regs[0],
					     regs->regs[1], regs->regs[2],
					     regs->regs[3], regs->regs[4],
					     regs->regs[5], regs->regs[6]);
			} else {
				dtrace_probe(fbp->fbp_id, fbp->fbp_roffset,
					     regs->regs[0], 0, 0, 0, 0, 0);
			}

			this_cpu_core->cpu_dtrace_regs = oregs;

			return DBG_HOOK_HANDLED;
		}
	}

	return DBG_HOOK_ERROR;
}

uint64_t fbt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		    int aframes)
{
	struct pt_regs	*regs = this_cpu_core->cpu_dtrace_regs;
	uint64_t	*st;
	uint64_t	val;

	if (regs == NULL)
		regs = current_pt_regs();

	if (argno < 8)
		return regs->regs[argno];

	/*
	 * Arguments are passed by register for the first 8 arguments, and the
	 * rest is placed on the stack.  The frame pointer (fp) points at the
	 * beginning of the current frame, and the stack pointer (sp) will
	 * point to the end of the frame.  Arguments passed by stack are placed
	 * in stack slots at the end of the frame, so at (sp), (sp + 1), etc...
	 */
	st = (uint64_t *)regs->sp;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = READ_ONCE_NOCHECK(st[argno - 8]);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return 0;
}

void fbt_provide_probe_arch(fbt_probe_t *fbp, int type, int stype)
{
	fbp->fbp_patchval = type == FBT_ENTRY ? BRK64_OPCODE_DPROBE_FBE
					      : BRK64_OPCODE_DPROBE_FBR;
	fbp->fbp_savedval = dtrace_text_peek(fbp->fbp_patchpoint);
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
	dtrace_text_poke(fbp->fbp_patchpoint, fbp->fbp_patchval);
}

void fbt_disable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_text_poke(fbp->fbp_patchpoint, fbp->fbp_savedval);
}

static struct break_hook dtrace_fbe_break_hook = {
	.esr_mask = BRK64_ESR_MASK,
	.esr_val = BRK64_ESR_DPROBES_FBE,
	.fn = fbt_brk_hook,
};

static struct break_hook dtrace_fbr_break_hook = {
	.esr_mask = BRK64_ESR_MASK,
	.esr_val = BRK64_ESR_DPROBES_FBR,
	.fn = fbt_brk_hook,
};

int fbt_dev_init_arch(void)
{
	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab = dtrace_vzalloc_try(fbt_probetab_size *
					  sizeof(fbt_probe_t *));

	if (fbt_probetab == NULL)
		return -ENOMEM;

	dtrace_brk_start(&dtrace_fbe_break_hook);
	dtrace_brk_start(&dtrace_fbr_break_hook);

	return 0;
}

void fbt_dev_exit_arch(void)
{
	dtrace_brk_stop(&dtrace_fbr_break_hook);
	dtrace_brk_stop(&dtrace_fbe_break_hook);

	vfree(fbt_probetab);
	fbt_probetab_mask = 0;
	fbt_probetab_size = 0;
}
