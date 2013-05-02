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

struct frame {
	struct frame	*fr_savfp;
	unsigned long	fr_savpc;
} __attribute__((packed));

static void dtrace_invop_callsite(void)
{
}

uint64_t dtrace_getarg(int arg, int aframes)
{
	struct frame	*fp = (struct frame *)dtrace_getfp();
	uintptr_t	*stack;
	int		i;
	uint64_t	val;
#ifdef __i386__
	int		regmap[] = {
					REG_EAX,
					REG_EDX,
					REG_ECX
				   };
#else
	int		regmap[] = {
					REG_RDI,
					REG_RSI,
					REG_RDX,
					REG_RCX,
					REG_R8,
					REG_R9
				   };
#endif
	int		nreg = sizeof(regmap) / sizeof(regmap[0]) - 1;

	for (i = 1; i <= aframes; i++) {
		fp = fp->fr_savfp;

		if (fp->fr_savpc == (uintptr_t)dtrace_invop_callsite) {
#ifdef __i386__
			/* FIXME */
#else
			/* FIXME */
#endif

			goto load;
		}
	}

	/*
	 * We know that we did not get here through a trap to get into the
	 * dtrace_probe() function, so this was a straight call into it from
	 * a provider.  In that case, we need to shift the argument that we
	 * are looking for, because the probe ID will be the first argument to
	 * dtrace_probe().
	 */
	arg++;

#ifndef __i386__
	if (arg <= nreg) {
		/*
		 * This should not happen.  If the argument was passed in a
		 * register then it should have been, ...passed in a reguster.
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}

	arg -= nreg + 1;
#endif

	stack = (uintptr_t *)&fp[1];

load:
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = stack[arg];
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

#ifdef __i386__
	if (reg > REG_SS) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}

	switch (reg) {
	case REG_GS:
	case REG_FS:
	case REG_ES:
	case REG_DS:
	case REG_CS:
		return rp->cs;
	case REG_EDI:
		return rp->di;
	case REG_ESI:
		return rp->si;
	case REG_EBP:
		return rp->bp;
	case REG_ESP:
	case REG_UESP:
		return rp->sp;
	case REG_EBX:
		return rp->bx;
	case REG_EDX:
		return rp->dx;
	case REG_ECX:
		return rp->cx;
	case REG_EAX:
		return rp->ax;
	case REG_TRAPNO:
		return rp->orig_ax;
	case REG_ERR:
		return rp->di;
	case REG_EIP:
		return rp->ip;
	case REG_EFL:
		return rp->flags;
	case REG_SS:
		return rp->ss;
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}
#else
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
	if (reg > REG_GS) {
		/*
		 * Convert register alias index into register mapping index.
		 */
		reg -= REG_GS + 1;

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
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}
#endif
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
	unsigned long		*sp = (unsigned long *)p->thread.usersp;
	unsigned long		*bos = (unsigned long *)p->mm->start_stack;
	struct vm_area_struct   *stack_vma = find_vma(p->mm, p->thread.usersp);

	*pcstack++ = (uint64_t)p->pid;
	pcstack_limit--;

	while (sp <= bos && pcstack_limit) {
		unsigned long	addr = *sp;

		if (addr >= stack_vma->vm_start && addr < stack_vma->vm_end) {
			/* stack address - may need it for the fpstack. */
		} else if (is_code_addr(addr)) {
			*pcstack++ = addr;
			pcstack_limit--;
		}

		sp++;
	}

	while (pcstack_limit--)
		*pcstack++ = 0;

	ASSERT(current == p);
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
