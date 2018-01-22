/*
 * FILE:	fasttrap_x86_64.c
 * DESCRIPTION:	DTrace - fasttrap provider implementation for x86
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

