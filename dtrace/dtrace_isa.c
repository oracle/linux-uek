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
#include <linux/cpumask.h>
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

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously (and at a regular interval) from outside of probe context
 * by the DTrace framework to sync shared data which DTrace probe context
 * may access without locks.
 *
 * Whenever the framework updates data which can be accessed from probe context,
 * the framework then calls dtrace_sync().  dtrace_sync() guarantees all probes
 * are using the new data before returning.
 *
 * See the comment in dtrace_impl.h which describes this algorithm.
 * The cpuc_in_probe_ctxt flag is an increasing 16-bit count.  It is odd when
 * in DTrace probe context and even when not in DTrace probe context.
 * The upper 15 bits are a counter which are incremented when exiting DTrace
 * probe context.  These upper 15 bits are used to detect "sample aliasing":
 * i.e. the target CPU is not in DTrace probe context between samples but
 * continually enters probe context just before being sampled.
 *
 * dtrace_sync() loops over NCPUs.  CPUs which are not in DTrace probe context
 * (cpuc_in_probe_ctxt is even) are removed from the list.  This is repeated
 * until there are no CPUs left in the sync list.
 *
 * In the rare cases where dtrace_sync() loops over all NCPUs more than
 * dtrace_sync_sample_count times, dtrace_sync() then spins on one CPU's
 * cpuc_in_probe_ctxt count until the count increments.  This is intended to
 * avoid sample aliasing.
 */
void dtrace_sync(void)
{
	/*
	 * sync_cpus is a bitmap of CPUs that need to be synced with.
	 */
	cpumask_t	sync_cpus;
	uint64_t	sample_count = 0;
	int		cpuid, sample_cpuid;
	int		outstanding;

	/*
	 * Create bitmap of CPUs that need to be synced with.
	 */
	cpumask_copy(&sync_cpus, cpu_online_mask);
	outstanding = 0;
	for_each_cpu(cpuid, &sync_cpus) {
		++outstanding;

		/*
		 * Set a flag to let the CPU know we are syncing with it.
		 */
		DTRACE_SYNC_START(cpuid);
	}

	/*
	 * The preceding stores by DTRACE_SYNC_START() must complete before
	 * subsequent loads or stores.  No membar is needed because the
	 * atomic-add operation in DTRACE_SYNC_START is a memory barrier on
	 * SPARC and X86.
	 */

	while (outstanding > 0) {
		/*
		 * Loop over the map of CPUs that need to be synced with.
		 */
		for_each_cpu(cpuid, &sync_cpus) {
			if (!DTRACE_SYNC_IN_CRITICAL(cpuid)) {

				/* Clear the CPU's sync request flag */
				DTRACE_SYNC_END(cpuid);

				/*
				 * remove cpuid from list of CPUs that
				 * still need to be synced with.
				 */
				DTRACE_SYNC_DONE(cpuid, &sync_cpus);
				--outstanding;
			} else {
				/*
				 * Remember one of the outstanding CPUs to spin
				 * on once we reach the sampling limit.
				 */
				sample_cpuid = cpuid;
			}
		}

		/*
		 * dtrace_probe may be running in sibling threads in this core.
		 */
		if (outstanding > 0) {
			dtrace_safe_smt_pause();

			/*
			 * After sample_count loops, spin on one CPU's count
			 * instead of just checking for odd/even.
			 */
			if (++sample_count > dtrace_sync_sample_count) {
				uint64_t count =
				    DTRACE_SYNC_CRITICAL_COUNT(sample_cpuid);

				/*
				 * Spin until critical section count increments.
				 */
				if (DTRACE_SYNC_IN_CRITICAL(sample_cpuid)) {
					while (count ==
					    DTRACE_SYNC_CRITICAL_COUNT(
					    sample_cpuid)) {

						dtrace_safe_smt_pause();
					}
				}

				DTRACE_SYNC_END(sample_cpuid);
				DTRACE_SYNC_DONE(sample_cpuid, &sync_cpus);
				--outstanding;
			}
		}
	}

/*
 * All preceding loads by DTRACE_SYNC_IN_CRITICAL() and
 * DTRACE_SYNC_CRITICAL_COUNT() must complete before subsequent loads
 * or stores.  No membar is needed because the atomic-add operation in
 * DTRACE_SYNC_END() is a memory barrier on SPARC and X86.
 */
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

	dtrace_stacktrace(&st);

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
