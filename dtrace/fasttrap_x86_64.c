/*
 * FILE:	fasttrap_x86_64.c
 * DESCRIPTION:	Fasttrap Tracing: arch support (x86_64)
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

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fasttrap_impl.h"

uint64_t fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg,
			      int argno, int aframes)
{
	struct pt_regs	*regs = this_cpu_core->cpu_dtrace_regs;
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
	__copy_from_user_inatomic_nocache(&val, (void *)&st[argno - 6],
					  sizeof(st[0]));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return val;
}

static void fasttrap_map_args(fasttrap_probe_t *probe, struct pt_regs *regs,
			      int argc, uintptr_t *argv)
{
	int		i, x, cap = min(argc, (int)probe->ftp_nargs);
	uintptr_t	*st = (uintptr_t *)regs->sp;

	for (i = 0; i < cap; i++) {
		switch (x = probe->ftp_argmap[i]) {
		case 0:
			argv[i] = regs->di;
			break;
		case 1:
			argv[i] = regs->si;
			break;
		case 2:
			argv[i] = regs->dx;
			break;
		case 3:
			argv[i] = regs->cx;
			break;
		case 4:
			argv[i] = regs->r8;
			break;
		case 5:
			argv[i] = regs->r9;
			break;
		default:
			ASSERT(x > 5);

			__copy_from_user_inatomic_nocache(&argv[i],
							  (void *)&st[x - 6],
							  sizeof(st[0]));
		}
	}

	while (i < argc)
		argv[i++] = 0;
}

void fasttrap_pid_probe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs)
{
	if (ftp->ftp_argmap == NULL)
		dtrace_probe(ftp->ftp_id, regs->di, regs->si, regs->dx,
			     regs->cx, regs->r8);
	else {
		uintptr_t	t[5];

		fasttrap_map_args(ftp, regs, sizeof(t) / sizeof(t[0]), t);
		dtrace_probe(ftp->ftp_id, t[0], t[1], t[2], t[3],
			     t[4]);
	}
}

void fasttrap_set_enabled(struct pt_regs *regs)
{
	regs->ax = 1;
}

