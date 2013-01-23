/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _DTRACE_CPU_H_
#define _DTRACE_CPU_H_

#include <linux/ktime.h>
#include <linux/mutex.h>

#define CPUC_SIZE	(sizeof (uint16_t) + sizeof(uint8_t) + \
			 sizeof(uintptr_t) + sizeof(struct mutex))
#define CPUC_PADSIZE	(192 - CPUC_SIZE)

typedef struct cpu_core {
	uint16_t cpuc_dtrace_flags;
	uint8_t cpuc_dcpc_intr_state;
	uint8_t cpuc_pad[CPUC_PADSIZE];
	uintptr_t cpuc_dtrace_illval;
	struct mutex cpuc_pid_lock;

	uintptr_t cpu_dtrace_caller;
	ktime_t cpu_dtrace_chillmark;
	ktime_t cpu_dtrace_chilled;
} cpu_core_t;

DECLARE_PER_CPU_SHARED_ALIGNED(cpu_core_t, dtrace_cpu_core);

#define per_cpu_core(cpu)	(&per_cpu(dtrace_cpu_core, (cpu)))
#define this_cpu_core		(&__get_cpu_var(dtrace_cpu_core))

#define DTRACE_CPUFLAG_ISSET(flag) \
	(this_cpu_core->cpuc_dtrace_flags & (flag))

#define DTRACE_CPUFLAG_SET(flag) \
	(this_cpu_core->cpuc_dtrace_flags |= (flag))

#define DTRACE_CPUFLAG_CLEAR(flag) \
	(this_cpu_core->cpuc_dtrace_flags &= ~(flag))

#define CPU_DTRACE_NOFAULT	0x0001
#define CPU_DTRACE_DROP		0x0002
#define CPU_DTRACE_BADADDR	0x0004
#define CPU_DTRACE_BADALIGN	0x0008
#define CPU_DTRACE_DIVZERO	0x0010
#define CPU_DTRACE_ILLOP	0x0020
#define CPU_DTRACE_NOSCRATCH	0x0040
#define CPU_DTRACE_KPRIV	0x0080
#define CPU_DTRACE_UPRIV	0x0100
#define CPU_DTRACE_TUPOFLOW	0x0200
#define CPU_DTRACE_ENTRY	0x0800
#define CPU_DTRACE_BADSTACK	0x1000

#define CPU_DTRACE_FAULT	(CPU_DTRACE_BADADDR | CPU_DTRACE_BADALIGN | \
				 CPU_DTRACE_DIVZERO | CPU_DTRACE_ILLOP | \
				 CPU_DTRACE_NOSCRATCH | CPU_DTRACE_KPRIV | \
				 CPU_DTRACE_UPRIV | CPU_DTRACE_TUPOFLOW | \
				 CPU_DTRACE_BADSTACK)
#define CPU_DTRACE_ERROR	(CPU_DTRACE_FAULT | CPU_DTRACE_DROP)

typedef uint32_t	processorid_t;
typedef uint32_t	psetid_t;
typedef uint32_t	chipid_t;
typedef uint32_t	lgrp_id_t;

typedef struct cpuinfo {
	processorid_t cpu_id;
	psetid_t cpu_pset;
	chipid_t cpu_chip;
	lgrp_id_t cpu_lgrp;
	struct cpuinfo_x86 *cpu_info;
} cpuinfo_t;

DECLARE_PER_CPU_SHARED_ALIGNED(cpuinfo_t, dtrace_cpu_info);

#define per_cpu_info(cpu)	(&per_cpu(dtrace_cpu_info, (cpu)))
#define this_cpu_info		(&__get_cpu_var(dtrace_cpu_info))

extern void dtrace_cpu_init(void);

#endif /* _DTRACE_CPU_H_ */
