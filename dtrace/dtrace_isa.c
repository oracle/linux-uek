/*
 * FILE:	dtrace_isa.c
 * DESCRIPTION:	DTrace - architecture specific code
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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
#include <linux/hardirq.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/ptrace.h>
#include <asm/stacktrace.h>

#include "dtrace.h"

EXPORT_SYMBOL(dtrace_getfp);

DEFINE_MUTEX(cpu_lock);
EXPORT_SYMBOL(cpu_lock);

int dtrace_getipl(void)
{
	return in_interrupt();
}

static void dtrace_sync_func(void)
{
}

void dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
	if (cpu == DTRACE_CPUALL) {
		smp_call_function(func, arg, 1);
	} else
		smp_call_function_single(cpu, func, arg, 1);
}

void dtrace_sync(void)
{
	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)dtrace_sync_func, NULL);
}

void dtrace_toxic_ranges(void (*func)(uintptr_t, uintptr_t))
{
	/* FIXME */
}

/*
 * Handle a few special cases where we store information in kernel memory that
 * in other systems is typically found in userspace.
 */
static int dtrace_fake_copyin(intptr_t addr, size_t size)
{
	dtrace_psinfo_t	*psinfo = current->dtrace_psinfo;
	uintptr_t	argv = (uintptr_t)psinfo->argv;
	unsigned long	argc = psinfo->argc;
	uintptr_t	envp = (uintptr_t)psinfo->envp;
	unsigned long	envc = psinfo->envc;

	/*
	 * Ensure addr is within the argv array (or the envp array):
	 * 	addr in [argv..argv + argc * sizeof(psinfo->argv[0])[
	 * Ensure that addr + size is within the same array
	 *	addr + size in [argv..argv * sizeof(psinfo->argv[0])]
	 *
	 * To guard against overflows on (addr + size) we rewrite this basic
	 * equation:
	 *	addr + size <= argv + argc * sizeof(psinfo->argv[0])
	 * into:
	 *	addr - argv <= argc * sizeof(psinfo->argv[0]) - size
	 */
	return (addr >= argv && addr - argv < argc * sizeof(psinfo->argv[0])
		    && addr - argv <= argc * sizeof(psinfo->argv[0]) - size) ||
	       (addr >= envp && addr - envp < envc * sizeof(psinfo->envp[0])
		    && addr - envp <= envc * sizeof(psinfo->envp[0]) - size);
}

void dtrace_copyin(uintptr_t uaddr, uintptr_t kaddr, size_t size,
		   volatile uint16_t *flags)
{
	if (dtrace_fake_copyin(uaddr, size)) {
		memcpy((char *)kaddr, (char *)uaddr, size);
		return;
	}

	dtrace_copyin_arch(uaddr, kaddr, size, flags);
}

void dtrace_copyinstr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
		      volatile uint16_t *flags)
{
	if (dtrace_fake_copyin(uaddr, size)) {
		strncpy((char *)kaddr, (char *)uaddr,
			 min(size, (size_t)PR_PSARGS_SZ));
		return;
	}

	dtrace_copyinstr_arch(uaddr, kaddr, size, flags);
}

/*
 * FIXME: aframes + 3 should really be aframes + 1, dtrace_stacktrace() in the
 *	  kernel should do its own aframes + 2
 */
void dtrace_getpcstack(uint64_t *pcstack, int pcstack_limit, int aframes,
		       uint32_t *intrpc)
{
	stacktrace_state_t	st = {
					pcstack,
					NULL,
					pcstack_limit,
					aframes + 3,
					STACKTRACE_KERNEL
				     };

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	dtrace_stacktrace(&st);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	while (st.depth < st.limit)
		pcstack[st.depth++] = 0;
}
EXPORT_SYMBOL(dtrace_getpcstack);

/*
 * Get user stack entries up to the pcstack_limit; return the number of entries
 * acquired.  If pcstack is NULL, return the number of entries potentially
 * acquirable.
 */
unsigned long dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack,
				 int pcstack_limit)
{
	struct task_struct	*p = current;
	stacktrace_state_t	st;
	unsigned long		depth;

	if (pcstack) {
		if (unlikely(pcstack_limit < 2)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return 0;
		}
		*pcstack++ = (uint64_t)p->pid;
		*pcstack++ = (uint64_t)p->tgid;
		pcstack_limit -= 2;
	}

	st.pcs = pcstack;
	st.fps = fpstack;
	st.limit = pcstack_limit;
	st.depth = 0;
	st.flags = STACKTRACE_USER;

	dtrace_stacktrace(&st);

	depth = st.depth;
	if (pcstack) {
	        while (st.depth < st.limit) {
			pcstack[st.depth++] = 0;
			if (fpstack)
				fpstack[st.depth++] = 0;
		}
	}

	return depth;
}

void dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	dtrace_getufpstack(pcstack, NULL, pcstack_limit);
}

/*
 * FIXME: aframes + 3 should really be aframes + 1, dtrace_stacktrace() in the
 *	  kernel should do its own aframes + 2
 */
int dtrace_getstackdepth(dtrace_mstate_t *mstate, int aframes)
{
	uintptr_t		old = mstate->dtms_scratch_ptr;
	stacktrace_state_t	st = {
					NULL,
					NULL,
					0,
					aframes + 3,
					STACKTRACE_KERNEL
				     };

	st.pcs = (uint64_t *)ALIGN(old, 8);
	if ((uintptr_t)st.pcs >
	    mstate->dtms_scratch_base + mstate->dtms_scratch_size) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return 0;
	}

	/*
	 * Calculate how many (64-bit) PCs we can fit in the remaining scratch
	 * memory.
	 */
	st.limit = (mstate->dtms_scratch_base + mstate->dtms_scratch_size -
		    (uintptr_t)st.pcs) >> 3;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	dtrace_stacktrace(&st);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	mstate->dtms_scratch_ptr = old;

	return st.depth;
}

int dtrace_getustackdepth(void)
{
	return dtrace_getufpstack(NULL, NULL, INT_MAX);
}
