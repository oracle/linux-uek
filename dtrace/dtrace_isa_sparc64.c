/*
 * FILE:	dtrace_isa_sparc64.c
 * DESCRIPTION:	Dynamic Tracing: sparc64 arch-specific support functions
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

#include <linux/dtrace_cpu.h>
#include <asm/cacheflush.h>
#include <asm/stacktrace.h>

#include "dtrace.h"
#include "dtrace/isa_arch.h"

uint64_t dtrace_getarg(int argno, int aframes)
{
	uintptr_t		val;
	struct sparc_v9_frame	*fp;
	uint64_t		rval;
	int			lvl;

	/*
	 * Account for the fact that dtrace_getarg() consumes an additional
	 * stack frame.
	 */
	aframes++;

#ifdef FIXME
	if (argno < 6) {
		if ((lvl = dtrace_fish(aframes, REG_I0 + argno, &val)) == 0)
			return val;
	} else {
		if ((lvl = dtrace_fish(aframes, REG_I6, &val)) == 0) {
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

	if (reg <= REG_O7)			/* G[0-7], O[0-7] */
		return rp->u_regs[reg];		/* 0 .. 15 */

	if (reg <= REG_I7) {			/* L[0-7], I[0-7] */
		if (rp->tstate & TSTATE_PRIV) {
			struct reg_window	*rw;

			rw = (struct reg_window *)(rp->u_regs[14] + STACK_BIAS);

			if (reg <= REG_L7)
				return rw->locals[reg - REG_L0];
			else
				return rw->ins[reg - REG_I0];
		} else {
			mm_segment_t			old_fs;
			struct reg_window __user	*rw;
			ulong_t				val;

			rw = (struct reg_window __user *)
				(rp->u_regs[14] + STACK_BIAS);

			old_fs = get_fs();
			set_fs(USER_DS);

			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

			if (reg <= REG_L7)
				val = dtrace_fulword(&rw->locals[reg - REG_L0]);
			else
				val = dtrace_fulword(&rw->locals[reg - REG_I0]);

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
	if (mp->pdata)
		pdata->sdt_tab = mp->pdata;
}

void pdata_cleanup(dtrace_module_t *pdata, struct module *mp)
{
	mp->pdata = pdata->sdt_tab;
}
