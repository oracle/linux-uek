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

#include <asm/stacktrace.h>
#include <linux/ptrace.h>

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

static int dtrace_unwind_frame(struct task_struct *task,
			       struct stackframe *frame)
{
	unsigned long	fp = frame->fp;

	if (fp & 0xf)
		return -EINVAL;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	if (!frame->fp && !frame->pc)
		return -EINVAL;

	return 0;
}

uint64_t dtrace_getarg(int argno, int aframes)
{
	uint64_t		*st;
	uint64_t		val;
	int			i;
	struct stackframe	frame;
	struct task_struct	*task = current;

	if (argno < 7)
		return 0;

	if (this_cpu_core->cpu_dtrace_regs)
		st = (uint64_t *)this_cpu_core->cpu_dtrace_regs->regs[29];
	else {
		frame.fp = (unsigned long)__builtin_frame_address(0);
		frame.pc = (unsigned long)dtrace_getarg;

		aframes += 1;		/* Count this function. */
		for (i = 0; i < aframes; i++) {
			if (dtrace_unwind_frame(task, &frame) < 0)
				break;
		}

		/*
		 * If we cannot traverse the expected number of stack frames,
		 * there is something wrong with the stack.
		 */
		if (i < aframes) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADSTACK);

			return 0;
		}

		st = (uint64_t *)frame.fp;
	}

	/*
	 * The first 7 arguments (arg0 through arg6) are passed in registers
	 * to dtrace_probe().  The remaining arguments (arg7 through arg9) are
	 * passed on the stack.
	 *
	 * Stack layout:
	 * bp[0] = pushed fp from caller
	 * bp[1] = return address
	 * bp[2] = 8th argument (arg7 -> argno = 7)
	 * bp[3] = 9th argument (arg8 -> argno = 8)
	 * ...
	 */
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = READ_ONCE_NOCHECK(st[2 + (argno - 7)]);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return val;
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
