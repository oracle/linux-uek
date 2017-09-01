/*
 * Dynamic Tracing for Linux - Implementation Defines
 *
 * Copyright (c) 2009, 2016, Oracle and/or its affiliates. All rights reserved.
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

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_IMPL_DEFINES_H
#define _LINUX_DTRACE_IMPL_DEFINES_H

#include <linux/dtrace/universal.h>
#include <linux/preempt.h>
#include <asm/ptrace.h>

#include <dtrace/mod_arch.h>

typedef typeof(instruction_pointer((struct pt_regs *)0))	pc_t;

typedef enum dtrace_activity {
	DTRACE_ACTIVITY_INACTIVE = 0,
	DTRACE_ACTIVITY_WARMUP,
	DTRACE_ACTIVITY_ACTIVE,
	DTRACE_ACTIVITY_DRAINING,
	DTRACE_ACTIVITY_COOLDOWN,
	DTRACE_ACTIVITY_STOPPED,
	DTRACE_ACTIVITY_KILLED
} dtrace_activity_t;

typedef enum dtrace_dstate_state {
	DTRACE_DSTATE_CLEAN = 0,
	DTRACE_DSTATE_EMPTY,
	DTRACE_DSTATE_DIRTY,
	DTRACE_DSTATE_RINSING
} dtrace_dstate_state_t;

typedef enum dtrace_dynvar_op {
	DTRACE_DYNVAR_ALLOC,
	DTRACE_DYNVAR_NOALLOC,
	DTRACE_DYNVAR_DEALLOC
} dtrace_dynvar_op_t;

#define DTRACE_MSTATE_ARGS		0x00000001
#define DTRACE_MSTATE_PROBE		0x00000002
#define DTRACE_MSTATE_EPID		0x00000004
#define DTRACE_MSTATE_TIMESTAMP		0x00000008
#define DTRACE_MSTATE_STACKDEPTH	0x00000010
#define DTRACE_MSTATE_CALLER		0x00000020
#define DTRACE_MSTATE_IPL		0x00000040
#define DTRACE_MSTATE_FLTOFFS		0x00000080
#define DTRACE_MSTATE_USTACKDEPTH	0x00000100
#define DTRACE_MSTATE_UCALLER		0x00000200

#define DTRACE_PROBEKEY_MAXDEPTH	8

typedef enum dtrace_speculation_state {
	DTRACESPEC_INACTIVE = 0,
	DTRACESPEC_ACTIVE,
	DTRACESPEC_ACTIVEONE,
	DTRACESPEC_ACTIVEMANY,
	DTRACESPEC_COMMITTING,
	DTRACESPEC_COMMITTINGMANY,
	DTRACESPEC_DISCARDING
} dtrace_speculation_state_t;

#define DTRACE_HELPER_ACTION_USTACK	0
#define DTRACE_NHELPER_ACTIONS		1

#define DTRACE_HELPTRACE_NEXT	(-1)
#define DTRACE_HELPTRACE_DONE	(-2)
#define DTRACE_HELPTRACE_ERR	(-3)

#undef ASSERT
#ifdef CONFIG_DT_DEBUG
# define ASSERT(x)	((void)((x) || dtrace_assfail(#x, __FILE__, __LINE__)))
#else
# define ASSERT(x)	((void)0)
#endif

/*
 * DTrace Probe Hashing
 */

#define DTRACE_HASHNEXT(hash, probe)					\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_nextoffs)
#define DTRACE_HASHPREV(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_prevoffs)

/*
 * DTrace Probe Management
 */
#define DTRACE_ANCHORED(probe)	((probe)->dtpr_func[0] != '\0')
#define DTRACE_FLAGS2FLT(flags)						\
	(((flags) & CPU_DTRACE_BADADDR) ? DTRACEFLT_BADADDR :		\
	 ((flags) & CPU_DTRACE_ILLOP) ? DTRACEFLT_ILLOP :		\
	 ((flags) & CPU_DTRACE_DIVZERO) ? DTRACEFLT_DIVZERO :		\
	 ((flags) & CPU_DTRACE_KPRIV) ? DTRACEFLT_KPRIV :		\
	 ((flags) & CPU_DTRACE_UPRIV) ? DTRACEFLT_UPRIV :		\
	 ((flags) & CPU_DTRACE_TUPOFLOW) ?  DTRACEFLT_TUPOFLOW :	\
	 ((flags) & CPU_DTRACE_BADALIGN) ?  DTRACEFLT_BADALIGN :	\
	 ((flags) & CPU_DTRACE_NOSCRATCH) ?  DTRACEFLT_NOSCRATCH :	\
	 ((flags) & CPU_DTRACE_BADSTACK) ?  DTRACEFLT_BADSTACK :	\
	 DTRACEFLT_UNKNOWN)

/*
 * Test whether alloc_sz bytes will fit in the scratch region.  We isolate
 * alloc_sz on the righthand side of the comparison in order to avoid overflow
 * or underflow in the comparison with it.  This is simpler than the INRANGE
 * check above, because we know that the dtms_scratch_ptr is valid in the
 * range.  Allocations of size zero are allowed.
 */
#define DTRACE_INSCRATCH(mstate, alloc_sz) \
	((mstate)->dtms_scratch_base + (mstate)->dtms_scratch_size - \
	 (mstate)->dtms_scratch_ptr >= (alloc_sz))

/*
 * Buffering.
 */

#define DTRACEBUF_RING		0x0001		/* bufpolicy set to "ring" */
#define DTRACEBUF_FILL		0x0002		/* bufpolicy set to "fill" */
#define DTRACEBUF_NOSWITCH	0x0004		/* do not switch buffer */
#define DTRACEBUF_WRAPPED	0x0008		/* ring buffer has wrapped */
#define DTRACEBUF_DROPPED	0x0010		/* drops occurred */
#define DTRACEBUF_ERROR		0x0020		/* errors occurred */
#define DTRACEBUF_FULL		0x0040		/* "fill" buffer is full */
#define DTRACEBUF_CONSUMED	0x0080		/* buffer has been consumed */
#define DTRACEBUF_INACTIVE	0x0100		/* buffer is not yet active */

#define DTRACE_STORE(type, tomax, offset, what) \
	do { \
	*((type *)((uintptr_t)(tomax) + (uintptr_t)(offset))) = (type)(what); \
	} while (0)

#define KERNELBASE	(uintptr_t)_text

#ifdef CONFIG_DT_DEBUG_MUTEX
# define real_mutex_lock(x)		mutex_lock(x)
# define real_mutex_unlock(x)		mutex_unlock(x)

# define mutex_lock(x)		do {					      \
				    printk(KERN_DEBUG			      \
					   "mutex_lock(%s) at %s::%d "	      \
					   " for %p (PID %d)\n",	      \
					   __stringify(x),		      \
					   __FILE__, __LINE__, current,	      \
					   current ? current->pid : -1);      \
				    real_mutex_lock(x);			      \
				} while (0)
# define mutex_unlock(x)	do {					      \
				    printk(KERN_DEBUG			      \
					   "mutex_unlock(%s) at %s::%d"	      \
					   " for %p (PID %d)\n",	      \
					   __stringify(x),		      \
					   __FILE__, __LINE__, current,	      \
					   current ? current->pid : -1);      \
				    real_mutex_unlock(x);		      \
				} while (0)
#endif

#define MUTEX_HELD(lock)	mutex_owned(lock)

#ifdef CONFIG_PREEMPT_VOLUNTARY
# define dtrace_is_preemptive()	(preempt_count() == 0)
# define dtrace_preempt_off()	preempt_disable()
# define dtrace_preempt_on()	preempt_enable()
#endif

#ifdef CONFIG_PREEMPT
# define dtrace_is_preemptive()	(preempt_count() == 0)
# define dtrace_preempt_off()	preempt_disable()
# define dtrace_preempt_on()	preempt_enable_no_resched()
#endif

#define PDATA(mp)		((dtrace_module_t *)mp->pdata)

#endif /* _LINUX_DTRACE_IMPL_DEFINES_H */
