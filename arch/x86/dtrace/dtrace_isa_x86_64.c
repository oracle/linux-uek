/*
 * FILE:	dtrace_isa_x86_64.c
 * DESCRIPTION:	DTrace - x86_64 architecture specific support functions
 *
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
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

#include "dtrace.h"

/* Register indices */
#define REG_TRAPNO	25
#define REG_GS		24
#define REG_FS		23
#define REG_ES		22
#define REG_DS		21
#define REG_SS		20
#define REG_RSP		19
#define REG_RFL		18
#define REG_CS		17
#define REG_RIP		16
#define REG_ERR		15
#define REG_RDI		14
#define REG_RSI		13
#define REG_RDX		12
#define REG_RCX		11
#define REG_RAX		10
#define REG_R8		9
#define REG_R9		8
#define REG_R10		7
#define REG_R11		6
#define REG_RBX		5
#define REG_RBP		4
#define REG_R12		3
#define REG_R13		2
#define REG_R14		1
#define REG_R15		0

extern void	dtrace_copy(uintptr_t, uintptr_t, size_t);
extern void	dtrace_copystr(uintptr_t, uintptr_t, size_t,
			       volatile uint16_t *);

uintptr_t _userlimit = 0x00007fffffffffffLL;
uintptr_t kernelbase = 0xffff880000000000LL;

static int dtrace_copycheck(uintptr_t uaddr, uintptr_t kaddr, size_t size)
{
#ifdef FIXME
	ASSERT(kaddr >= kernelbase && kaddr + size >= kaddr);
#else
	if (kaddr < kernelbase || kaddr + size < kaddr) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		this_cpu_core->cpuc_dtrace_illval = kaddr;
		return 0;
	}
#endif

	if (uaddr + size >= kernelbase || uaddr + size < uaddr) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		this_cpu_core->cpuc_dtrace_illval = uaddr;
		return 0;
	}

	return 1;
}

void dtrace_copyin_arch(uintptr_t uaddr, uintptr_t kaddr, size_t size,
			volatile uint16_t *flags)
{
	if (dtrace_copycheck(uaddr, kaddr, size))
		dtrace_copy(uaddr, kaddr, size);
}

void dtrace_copyout(uintptr_t uaddr, uintptr_t kaddr, size_t size,
		    volatile uint16_t *flags)
{
	if (dtrace_copycheck(uaddr, kaddr, size))
		dtrace_copy(kaddr, uaddr, size);
}

void dtrace_copyinstr_arch(uintptr_t uaddr, uintptr_t kaddr, size_t size,
			   volatile uint16_t *flags)
{
	if (dtrace_copycheck(uaddr, kaddr, size))
		dtrace_copystr(uaddr, kaddr, size, flags);
}

void dtrace_copyoutstr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
		       volatile uint16_t *flags)
{
	if (dtrace_copycheck(uaddr, kaddr, size))
		dtrace_copystr(kaddr, uaddr, size, flags);
}

#define DTRACE_FUWORD(bits) \
	uint##bits##_t dtrace_fuword##bits(void *uaddr)			      \
	{								      \
		extern uint##bits##_t	dtrace_fuword##bits##_nocheck(void *);\
									      \
		if ((uintptr_t)uaddr > _userlimit) {			      \
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);		      \
			this_cpu_core->cpuc_dtrace_illval = (uintptr_t)uaddr; \
			return 0;					      \
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
	unsigned long	bp;
	uint64_t	*st;
	uint64_t	val;
	int		i;

	asm volatile("movq %%rbp,%0" : "=m"(bp));

	for (i = 0; i < aframes; i++)
		bp = *((unsigned long *)bp);

	ASSERT(argno >= 5);

	/*
	 * The first 5 arguments (arg0 through arg4) are passed in registers
	 * to dtrace_probe().  The remaining arguments (arg5 through arg9) are
	 * passed on the stack.
	 *
	 * Stack layout:
	 * bp[0] = pushed bp from caller
	 * bp[1] = return address
	 * bp[2] = 6th argument (arg5 -> argno = 5)
	 * bp[3] = 7th argument (arg6 -> argno = 6)
	 * ...
	 */
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	st = (uint64_t *)bp;
	val = st[2 + (argno - 5)];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return val;
}

ulong_t dtrace_getreg(struct task_struct *task, uint_t reg)
{
	struct pt_regs	*rp = task_pt_regs(task);

	int	regmap[] = {
				REG_RBX,	/*  0 -> EBX */
				REG_RCX,	/*  1 -> ECX */
				REG_RDX,	/*  2 -> EDX */
				REG_RSI,	/*  3 -> ESI */
				REG_RDI,	/*  4 -> EDI */
				REG_RBP,	/*  5 -> EBP */
				REG_RAX,	/*  6 -> EAX */
				REG_DS,		/*  7 -> DS */
				REG_ES,		/*  8 -> ES */
				REG_FS,		/*  9 -> FS */
				REG_GS,		/* 10 -> GS */
				REG_TRAPNO,	/* 11 -> TRAPNO */
				REG_RIP,	/* 12 -> EIP */
				REG_CS,		/* 13 -> CS */
				REG_RFL,	/* 14 -> EFL */
				REG_RSP,	/* 15 -> UESP */
				REG_SS,		/* 16 -> SS */
			   };

	if (reg > REG_TRAPNO) {
		/*
		 * Convert register alias index into register mapping index.
		 */
		reg -= REG_TRAPNO + 1;

		if (reg >= sizeof(regmap) / sizeof(int)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return 0;
		}

		reg = regmap[reg];
	}

	/*
	 * Most common case: direct index into pt_regs structure.
	 */
	if (reg <= REG_SS)
		return (&rp->r15)[reg];

	switch (reg) {
	case REG_DS:
		return task->thread.ds;
	case REG_ES:
		return task->thread.es;
	case REG_FS:
		return task->thread.fsbase;
	case REG_GS:
		return task->thread.gsbase;
	case REG_TRAPNO:
		return task->thread.trap_nr;
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}
}

void pdata_init(dtrace_module_t *pdata, struct module *mp)
{
}

void pdata_cleanup(dtrace_module_t *pdata, struct module *mp)
{
}
