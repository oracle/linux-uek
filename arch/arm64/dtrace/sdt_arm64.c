/*
 * FILE:	sdt_arm64.c
 * DESCRIPTION:	DTrace - SDT provider implementation for arm64
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

#include <linux/ptrace.h>
#include <linux/sdt.h>
#include <asm/debug-monitors.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

static int sdt_brk_hook(struct pt_regs *regs, unsigned int esr)
{
	uintptr_t	ip = instruction_pointer(regs);
	sdt_probe_t	*sdt = sdt_probetab[SDT_ADDR2NDX(ip)];

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint == ip) {
			if (sdt->sdp_ptype == SDTPT_IS_ENABLED)
				regs->regs[0] = 1;
			else {
				this_cpu_core->cpu_dtrace_regs = regs;
				dtrace_probe(sdt->sdp_id, regs->regs[0],
					     regs->regs[1], regs->regs[2],
					     regs->regs[3], regs->regs[4],
					     regs->regs[5], regs->regs[6]);
				this_cpu_core->cpu_dtrace_regs = NULL;
			}

			instruction_pointer_set(regs,
						instruction_pointer(regs) + 4);

			return DBG_HOOK_HANDLED;
		}
	}

	return DBG_HOOK_ERROR;
}

void sdt_provide_probe_arch(sdt_probe_t *sdp, struct module *mp, int idx)
{
	sdp->sdp_patchval = BRK64_OPCODE_DPROBE_SDT;
	sdp->sdp_savedval = dtrace_text_peek(sdp->sdp_patchpoint);
}

int sdt_provide_module_arch(void *arg, struct module *mp)
{
	return 1;
}

void sdt_destroy_module(void *arg, struct module *mp)
{
}

void sdt_enable_arch(sdt_probe_t *sdp, dtrace_id_t id, void *arg)
{
	dtrace_text_poke(sdp->sdp_patchpoint, sdp->sdp_patchval);
}

void sdt_disable_arch(sdt_probe_t *sdp, dtrace_id_t id, void *arg)
{
	dtrace_text_poke(sdp->sdp_patchpoint, sdp->sdp_savedval);
}

static struct break_hook dtrace_sdt_break_hook = {
	.esr_mask = BRK64_ESR_MASK,
	.esr_val = BRK64_ESR_DPROBES_SDT,
	.fn = sdt_brk_hook,
};

int sdt_dev_init_arch(void)
{
	dtrace_brk_start(&dtrace_sdt_break_hook);
	return 0;
}

void sdt_dev_exit_arch(void)
{
	dtrace_brk_stop(&dtrace_sdt_break_hook);
}

uint64_t sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		    int aframes)
{
	struct pt_regs  *regs = this_cpu_core->cpu_dtrace_regs;
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

	return val;
}
