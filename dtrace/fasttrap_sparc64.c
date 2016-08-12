/*
 * FILE:	fasttrap_sparc64.c
 * DESCRIPTION:	Fasttrap Tracing: arch support (sparc64)
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
 * Copyright 2010, 2011, 2012, 2013, 2016 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
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
	regs->u_regs[REG_O0] = 1;
}

