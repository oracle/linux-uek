/*
 * FILE:	dtrace_isa_arm64.c
 * DESCRIPTION:	DTrace - arm64 architecture specific support functions
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

#include <asm/ptrace.h>
#include <asm/stacktrace.h>

#include "dtrace.h"

uintptr_t _userlimit = 0x0000ffffffffffffLL;

void dtrace_copyin_arch(uintptr_t uaddr, uintptr_t kaddr, size_t size,
			volatile uint16_t *flags)
{
}

void dtrace_copyinstr_arch(uintptr_t uaddr, uintptr_t kaddr, size_t size,
			   volatile uint16_t *flags)
{
}

void dtrace_copyout(uintptr_t uaddr, uintptr_t kaddr, size_t size,
		    volatile uint16_t *flags)
{
}

void dtrace_copyoutstr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
		       volatile uint16_t *flags)
{
}

#define DTRACE_FUWORD(bits) \
	uint##bits##_t dtrace_fuword##bits(void *uaddr)			      \
	{								      \
		extern uint##bits##_t	dtrace_fuword##bits##_nocheck(void *);\
									      \
		if ((uintptr_t)uaddr > _userlimit) {			      \
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);		      \
			this_cpu_core->cpuc_dtrace_illval = (uintptr_t)uaddr; \
		}							      \
									      \
		return dtrace_fuword##bits##_nocheck(uaddr);		      \
	}

DTRACE_FUWORD(8)
DTRACE_FUWORD(16)
DTRACE_FUWORD(32)
DTRACE_FUWORD(64)

uint64_t dtrace_getarg(int argno, int aframes)
{
	return 0;
}

ulong_t dtrace_getreg(struct task_struct *task, uint_t reg)
{
	struct pt_regs	*rp = task_pt_regs(task);

	return regs_get_register(rp, reg * sizeof(uint64_t));
}

void pdata_init(dtrace_module_t *pdata, struct module *mp)
{
	/*
	 * Throw away existing data as we don't support reusal at
	 * the moment.
	 */
	if (mp->pdata != NULL)
		pdata_cleanup(pdata, mp);

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
