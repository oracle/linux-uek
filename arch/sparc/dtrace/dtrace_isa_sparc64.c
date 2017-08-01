/*
 * FILE:	dtrace_isa_sparc64.c
 * DESCRIPTION:	DTrace - sparc64 architecture specific support functions
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/dtrace_cpu.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/stacktrace.h>

#include "dtrace.h"
#include "dtrace/isa_arch.h"

uint64_t dtrace_getarg(int argno, int aframes)
{
	struct sparc_v9_frame	*fp;
	uint64_t		rval;

	/*
	 * Account for the fact that dtrace_getarg() consumes an additional
	 * stack frame.
	 */
	aframes++;

#ifdef FIXME
	if (argno < 6) {
		if ((lvl = dtrace_fish(aframes, ASM_REG_I0 + argno, &val)) == 0)
			return val;
	} else {
		if ((lvl = dtrace_fish(aframes, ASM_REG_I6, &val)) == 0) {
			/*
			 * We have a stack pointer; grab the argument.
			 */
			fp = (struct sparc_v9_frame *)(val + STACK_BIAS);

			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			rval = fp->ins[argno - 6];
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

			return rval;
		}
	}
#endif
	/*
	 * This is the slow way to get to function arguments.  We force a full
	 * register windows flush, and then walk the chain of frames until we
	 * get to the one we need.  The flush is expensive, so we should try to
	 * avoid this whenever possible.
	 */
	fp = (struct sparc_v9_frame *)((uintptr_t)dtrace_getfp() + STACK_BIAS);
	flushw_all();

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

	for (aframes -= 1; aframes; aframes--)
		fp = (struct sparc_v9_frame *)((uintptr_t)fp->fp + STACK_BIAS);

	if (argno < 6) {
		rval = fp->ins[argno];
	} else {
		fp = (struct sparc_v9_frame *)((uintptr_t)fp->fp + STACK_BIAS);
		rval = fp->xxargs[argno - 6];
	}

	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return rval;
}

ulong_t dtrace_getreg(struct task_struct *task, uint_t reg)
{
	struct pt_regs	*rp = task_pt_regs(task);

	if (reg <= ASM_REG_O7)			/* G[0-7], O[0-7] */
		return rp->u_regs[reg];		/* 0 .. 15 */

	if (reg <= ASM_REG_I7) {		/* L[0-7], I[0-7] */
		if (rp->tstate & TSTATE_PRIV) {
			struct reg_window	*rw;

			rw = (struct reg_window *)(rp->u_regs[14] + STACK_BIAS);

			if (reg <= ASM_REG_L7)
				return rw->locals[reg - ASM_REG_L0];
			else
				return rw->ins[reg - ASM_REG_I0];
		} else {
			mm_segment_t			old_fs;
			struct reg_window __user	*rw;
			ulong_t				val;

			rw = (struct reg_window __user *)
				(rp->u_regs[14] + STACK_BIAS);

			old_fs = get_fs();
			set_fs(USER_DS);

			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

			if (reg <= ASM_REG_L7)
				val = dtrace_fulword(
					&rw->locals[reg - ASM_REG_L0]
				      );
			else
				val = dtrace_fulword(
					&rw->locals[reg - ASM_REG_I0]
				      );

			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

			set_fs(old_fs);

			return val;
		}
	}

	switch (reg) {
	case REG_CCR:
		return (rp->tstate & TSTATE_CCR) >> TSTATE_CCR_SHIFT;
	case REG_PC:
		return rp->tpc;
	case REG_nPC:
		return rp->tnpc;
	case REG_Y:
		return rp->y;
	case REG_ASI:
		return (rp->tstate & TSTATE_ASI) >> TSTATE_ASI_SHIFT;
	case REG_FPRS:
		return 0; /* FIXME */
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}
}

void pdata_init(dtrace_module_t *pdata, struct module *mp)
{
	/*
	 * Throw away existing data as we don't support reusal at
	 * the moment.
	 */
	if (mp->pdata != NULL) {
		pdata_cleanup(pdata, mp);
	}

	pdata->sdt_tab = NULL;
	pdata->fbt_tab = NULL;
}

void pdata_cleanup(dtrace_module_t *pdata, struct module *mp)
{
	if (pdata->sdt_tab != NULL)
		dtrace_free_text(pdata->sdt_tab);
	if (pdata->fbt_tab != NULL)
		dtrace_free_text(pdata->fbt_tab);
}
