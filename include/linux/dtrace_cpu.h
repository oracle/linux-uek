/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _LINUX_DTRACE_CPU_H_
#define _LINUX_DTRACE_CPU_H_

#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/rwlock.h>
#include <linux/dtrace_cpu_defines.h>

typedef struct cpu_core {
	uint16_t cpuc_dtrace_flags;
	uint8_t cpuc_dcpc_intr_state;
	uint8_t cpuc_pad[CPUC_PADSIZE];
	uintptr_t cpuc_dtrace_illval;
	struct mutex cpuc_pid_lock;

	uintptr_t cpu_dtrace_caller;
	ktime_t cpu_dtrace_chillmark;
	ktime_t cpu_dtrace_chilled;
	rwlock_t cpu_ft_lock;
} cpu_core_t;

DECLARE_PER_CPU_SHARED_ALIGNED(cpu_core_t, dtrace_cpu_core);

typedef struct cpuinfo {
	processorid_t cpu_id;
	psetid_t cpu_pset;
	chipid_t cpu_chip;
	lgrp_id_t cpu_lgrp;
	struct cpuinfo_x86 *cpu_info;
} cpuinfo_t;

DECLARE_PER_CPU_SHARED_ALIGNED(cpuinfo_t, dtrace_cpu_info);

extern void dtrace_cpu_init(void);

#endif /* _LINUX_DTRACE_CPU_H_ */
