/*
 * FILE:	fasttrap_sparc64.c
 * DESCRIPTION:	DTrace - fasttrap provider implementation for sparc64
 *
 * Copyright (c) 2010, 2016, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/uaccess.h>
#include <asm/cacheflush.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fasttrap_impl.h"
#include "dtrace/isa_arch.h"

static uint64_t getarg_arch(struct pt_regs *r, int argno)
{
	struct pt_regs			*regs = r;
	uint64_t			rval;

	if (regs == NULL) {
		regs = this_cpu_core->cpu_dtrace_regs;
		if (regs == NULL)
			return 0;
	}

	if (argno < 6)
		return regs->u_regs[UREG_I0 + argno];

	ASSERT(argno > 5);

	/*
	 * This is the slow way to get to function arguments.  We force a full
	 * user register windows flush, and then walk the chain of frames until
	 * we get to the one we need.  The flush is expensive, so we should try
	 * to avoid this whenever possible.
	 */

	flushw_user();

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	if (test_thread_flag(TIF_32BIT)) {
		/* XXX not implemented */
		return 0; /* ugh */
	} else {
		/*
		 * This relies on argno > 5, since we are plucking data directly
		 * from the xxargs overflow area.
		 */
		__copy_from_user_inatomic_nocache(
			&rval, (void * __user) regs->u_regs[UREG_I6] + STACK_BIAS,
			sizeof(struct sparc_v9_frame) -
			(sizeof (unsigned long) +
			 (sizeof (unsigned long) * (argno - 6))));
		/* XXX should we be ignoring aframes here? */
	}

	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return rval;
}

uint64_t fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg,
			      int argno, int aframes)
{
	return getarg_arch(NULL, argno);
}

static void fasttrap_map_args(fasttrap_probe_t *probe, struct pt_regs *regs,
			      int argc, uintptr_t *argv)
{
	int		i, x, cap = min(argc, (int)probe->ftp_nargs);
	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];
		argv[i] = getarg_arch(regs, x);
	}

	while (i < argc)
		argv[i++] = 0;
}

void fasttrap_pid_probe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs)
{
	if (ftp->ftp_argmap == NULL)
		dtrace_probe(ftp->ftp_id, regs->u_regs[UREG_I0],
			     regs->u_regs[UREG_I1], regs->u_regs[UREG_I2],
			     regs->u_regs[UREG_I3], regs->u_regs[UREG_I4]);
	else {
		uintptr_t	t[5];

		fasttrap_map_args(ftp, regs, sizeof(t) / sizeof(t[0]), t);
		dtrace_probe(ftp->ftp_id, t[0], t[1], t[2], t[3],
			     t[4]);
	}
}

void fasttrap_set_enabled(struct pt_regs *regs)
{
	regs->u_regs[ASM_REG_O0] = 1;
}

