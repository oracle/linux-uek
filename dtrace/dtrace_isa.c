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
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace_cpu.h>
#include <linux/hardirq.h>
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

ulong_t dtrace_getreg(struct pt_regs *rp, uint_t reg)
{
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
				REG_GS,		/*  0 -> GS */
				REG_FS,		/*  1 -> FS */
				REG_ES,		/*  2 -> ES */
				REG_DS,		/*  3 -> DS */
				REG_RDI,	/*  4 -> EDI */
				REG_RSI,	/*  5 -> ESI */
				REG_RBP,	/*  6 -> EBP */
				REG_RSP,	/*  7 -> ESP */
				REG_RBX,	/*  8 -> EBX */
				REG_RDX,	/*  9 -> EDX */
				REG_RCX,	/* 10 -> ECX */
				REG_RAX,	/* 11 -> EAX */
				REG_TRAPNO,	/* 12 -> TRAPNO */
				REG_ERR,	/* 13 -> ERR */
				REG_RIP,	/* 14 -> EIP */
				REG_CS,		/* 15 -> CS */
				REG_RFL,	/* 16 -> EFL */
				REG_RSP,	/* 17 -> UESP */
				REG_SS,		/* 18 -> SS */
			   };

	if (reg <= REG_SS) {
		if (reg >= sizeof(regmap) / sizeof(int)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return 0;
		}

		reg = regmap[reg];
	} else
		reg -= REG_SS + 1;

	switch (reg) {
	case REG_RDI:
		return rp->di;
	case REG_RSI:
		return rp->si;
	case REG_RDX:
		return rp->dx;
	case REG_RCX:
		return rp->cx;
	case REG_R8:
		return rp->r8;
	case REG_R9:
		return rp->r9;
	case REG_RAX:
		return rp->ax;
	case REG_RBX:
		return rp->bx;
	case REG_RBP:
		return rp->bp;
	case REG_R10:
		return rp->r10;
	case REG_R11:
		return rp->r11;
	case REG_R12:
		return rp->r12;
	case REG_R13:
		return rp->r13;
	case REG_R14:
		return rp->r14;
	case REG_R15:
		return rp->r15;
	case REG_CS:
	case REG_DS:
	case REG_ES:
	case REG_FS:
	case REG_GS:
		return rp->cs;
	case REG_TRAPNO:
		return rp->orig_ax;
	case REG_ERR:
		return rp->di;
	case REG_RIP:
		return rp->ip;
	case REG_SS:
		return rp->ss;
	case REG_RFL:
		return rp->flags;
	case REG_RSP:
		return rp->sp;
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

#if 0
#define STACKTRACE_KERNEL	0x01
#define STACKTRACE_USER		0x02
#define STACKTRACE_SKIP		0x10

struct stacktrace_state {
	uint64_t	*pcs;
	uint64_t	*fps;
	int		limit;
	int		depth;
	int		flags;
};

static int dtrace_stacktrace_stack(void *data, char *name)
{
	struct stacktrace_state	*st = (struct stacktrace_state *)data;

	/*
	 * We do not skip anything for non-user stack analysis.
	 */
	if (!(st->flags & STACKTRACE_USER))
		return 0;

	if (name != NULL && strlen(name) > 3) {
		/*
		 * Sadly, the dump stack code calls us with both <EOE> and EOI.
		 * Consistency would be much nicer.
		 */
		if ((name[0] == '<' && name[1] == 'E' && name[2] == 'O') ||
		    (name[0] == 'E' && name[2] == 'O'))
			st->flags &= ~STACKTRACE_SKIP;
	}

	return 0;
}

static void dtrace_stacktrace_address(void *data, unsigned long addr,
				      int reliable)
{
	struct stacktrace_state	*st = (struct stacktrace_state *)data;

	if (st->flags & STACKTRACE_SKIP)
		return;

	if (reliable == 2) {
		if (st->fps)
			st->fps[st->depth] = addr;
	} else {
		if (st->pcs != NULL) {
			if (st->depth < st->limit)
				st->pcs[st->depth++] = addr;
		} else
			st->depth++;
	}
}

static inline int valid_sp(struct thread_info *tinfo, void *p,
			   unsigned int size, void *end)
{
	void	*t = tinfo;

	if (end) {
		if (p < end && p >= (end - THREAD_SIZE))
			return 1;
		else
			return 0;
	}

	return p > t && p < t + THREAD_SIZE - size;
}

static unsigned long dtrace_stacktrace_walk_stack(
					struct thread_info *tinfo,
					unsigned long *stack,
					unsigned long bp,
					const struct stacktrace_ops *ops,
					void *data, unsigned long *end,
					int *graph)
{
	struct frame	*fr = (struct frame *)bp;
	unsigned long	*pcp = &(fr->fr_savpc);

	while (valid_sp(tinfo, pcp, sizeof(*pcp), end)) {
		unsigned long	addr = *pcp;

		fr = fr->fr_savfp;
		ops->address(data, (unsigned long)fr, 2);
		ops->address(data, addr, 1);
		pcp = &(fr->fr_savpc);
	}

	return (unsigned long)fr;
}

static const struct stacktrace_ops	dtrace_tracetrace_ops = {
	.stack		= dtrace_stacktrace_stack,
	.address	= dtrace_stacktrace_address,
	.walk_stack	= print_context_stack
};

static const struct stacktrace_ops	dtrace_tracetrace_ops_alt = {
	.stack		= dtrace_stacktrace_stack,
	.address	= dtrace_stacktrace_address,
	.walk_stack	= dtrace_stacktrace_walk_stack
};
#endif

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

#if 0
	dump_trace(NULL, NULL, NULL, 0, &dtrace_tracetrace_ops, &st);
#else
	dtrace_stacktrace(&st);
#endif

	while (st.depth < st.limit)
		pcstack[st.depth++] = 0;
}

void dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	struct stacktrace_state	st = {
					pcstack,
					NULL,
					pcstack_limit,
					0,
					STACKTRACE_USER
				     };

#if 0
	dump_trace(NULL, NULL, NULL, 0, &dtrace_tracetrace_ops, &st);
#else
	dtrace_stacktrace(&st);
#endif

	while (st.depth < st.limit)
		pcstack[st.depth++] = 0;
}

void dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack,
			int pcstack_limit)
{
	struct stacktrace_state	st = {
					pcstack,
					fpstack,
					pcstack_limit,
					0,
					STACKTRACE_USER
				     };

#if 0
	dump_trace(NULL, NULL, NULL, 0, &dtrace_tracetrace_ops_alt, &st);
#else
	dtrace_stacktrace(&st);
#endif

	while (st.depth < st.limit) {
		fpstack[st.depth] = 0;
		pcstack[st.depth++] = 0;
	}
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

#if 0
	dump_trace(NULL, NULL, NULL, 0, &dtrace_tracetrace_ops, &st);
#else
	dtrace_stacktrace(&st);
#endif

	if (st.depth <= aframes)
		return 0;

	return st.depth - aframes;
}

int dtrace_getustackdepth(void)
{
	struct stacktrace_state	st = {
					NULL,
					NULL,
					0,
					0,
					STACKTRACE_USER
				     };

#if 0
	dump_trace(NULL, NULL, NULL, 0, &dtrace_tracetrace_ops, &st);
#else
	dtrace_stacktrace(&st);
#endif

	return st.depth;
}
