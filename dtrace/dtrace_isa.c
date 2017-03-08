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
 * Copyright 2010-2017 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
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

void dtrace_getpcstack(uint64_t *pcstack, int pcstack_limit, int aframes,
		       uint32_t *intrpc)
{
	stacktrace_state_t	st = {
					pcstack,
					NULL,
					pcstack_limit,
					aframes,
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
        while (st.depth < st.limit) {
		if (pcstack)
			pcstack[st.depth++] = 0;
		if (fpstack)
			fpstack[st.depth++] = 0;
	}

	return depth;
}

void dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	dtrace_getufpstack(pcstack, NULL, pcstack_limit);
}

int dtrace_getstackdepth(dtrace_mstate_t *mstate, int aframes)
{
	uintptr_t		old = mstate->dtms_scratch_ptr;
	size_t			size;
	stacktrace_state_t	st = {
					NULL,
					NULL,
					0,
					aframes,
					STACKTRACE_KERNEL
				     };

	st.pcs = (uint64_t *)P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
	size = (uintptr_t)st.pcs - mstate->dtms_scratch_ptr +
			  aframes * sizeof(uint64_t);
	if (mstate->dtms_scratch_ptr + size >
	    mstate->dtms_scratch_base + mstate->dtms_scratch_size) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return 0;
	}

	dtrace_stacktrace(&st);

	mstate->dtms_scratch_ptr = old;

	return st.depth;
}

int dtrace_getustackdepth(void)
{
	return dtrace_getufpstack(NULL, NULL, 0);
}
