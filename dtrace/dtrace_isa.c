/*
 * FILE:	dtrace_isa.c
 * DESCRIPTION:	Dynamic Tracing: architecture specific support functions
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
 * Copyright 2010, 2011, 2012 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace_cpu.h>
#include <linux/hardirq.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <asm/stacktrace.h>

#include "dtrace.h"

/* FIXME */
uintptr_t _userlimit = 0x00007fffffffffffLL;
uintptr_t kernelbase = 0xffff880000000000LL;

EXPORT_SYMBOL(dtrace_getfp);

DEFINE_MUTEX(cpu_lock);
EXPORT_SYMBOL(cpu_lock);

extern void	dtrace_copy(uintptr_t, uintptr_t, size_t);
extern void	dtrace_copystr(uintptr_t, uintptr_t, size_t,
			       volatile uint16_t *);

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

void dtrace_copyin(uintptr_t uaddr, uintptr_t kaddr, size_t size,
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

void dtrace_copyinstr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
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

int dtrace_getipl(void)
{
	return in_interrupt();
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
		return task->thread.fs;
	case REG_GS:
		return task->thread.gs;
	case REG_TRAPNO:
		return task->thread.trap_nr;
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}
}

static void dtrace_sync_func(void)
{
}

void dtrace_sync(void)
{
	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)dtrace_sync_func, NULL);
}

void dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
	if (cpu == DTRACE_CPUALL) {
		smp_call_function(func, arg, 1);
	} else
		smp_call_function_single(cpu, func, arg, 1);
}

void dtrace_toxic_ranges(void (*func)(uintptr_t, uintptr_t))
{
	/* FIXME */
}

ktime_t dtrace_gethrestime(void)
{
	return dtrace_gethrtime();
}

void dtrace_getpcstack(uint64_t *pcstack, int pcstack_limit, int aframes,
		       uint32_t *intrpc)
{
	struct stacktrace_state	st = {
					pcstack,
					NULL,
					pcstack_limit,
					0,
					STACKTRACE_KERNEL
				     };

	dtrace_stacktrace(&st);

	while (st.depth < st.limit)
		pcstack[st.depth++] = 0;
}
EXPORT_SYMBOL(dtrace_getpcstack);

static int is_code_addr(unsigned long addr) {
	struct vm_area_struct   *vma, *first;

	first = NULL;
	for (vma = current->mm->mmap;
	     vma != NULL && vma != first;
	     vma = vma->vm_next) {
		if (!first)
			first = vma;

		if (!(vma->vm_flags & VM_EXEC))
			continue;

		if (addr < vma->vm_start)
			return 0;
		if (addr <= vma->vm_end)
			return 1;
	}

	return 0;
}

void dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack,
			int pcstack_limit)
{
	struct task_struct	*p = current;
	unsigned long		bos, tos;
	unsigned long		*sp;

	*pcstack++ = (uint64_t)p->pid;
	*pcstack++ = (uint64_t)p->tgid;
	pcstack_limit-=2;

	if (p->mm == NULL || (p->flags & PF_KTHREAD))
	    goto out;

	tos = this_cpu_read(old_rsp);
	bos = p->mm->start_stack;

	for (sp = (unsigned long *)tos;
	     sp <= (unsigned long *)bos && pcstack_limit; sp++) {
		unsigned long	addr;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		get_user(addr, sp);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
			break;

		if (addr >= tos && addr <= bos) {
			/* stack address - may need it for the fpstack. */
		} else if (is_code_addr(addr)) {
			*pcstack++ = addr;
			pcstack_limit--;
		}

		sp++;
	}

out:
	while (pcstack_limit--)
		*pcstack++ = 0;
} 

void dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	dtrace_getufpstack(pcstack, NULL, pcstack_limit);
}

int dtrace_getstackdepth(int aframes)
{
	struct stacktrace_state	st = {
					NULL,
					NULL,
					0,
					0,
					STACKTRACE_KERNEL
				     };

	dtrace_stacktrace(&st);

	if (st.depth <= aframes)
		return 0;

	return st.depth - aframes;
}

int dtrace_getustackdepth(void)
{
	int			depth = 0;
	struct task_struct	*p = current;
	unsigned long		*sp = (unsigned long *)p->thread.usersp;
	unsigned long		*bos = (unsigned long *)p->mm->start_stack;

	while (sp <= bos) {
		if (is_code_addr(*sp))
			depth++;

		sp++;
	}

	return depth;
}
