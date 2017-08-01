/*
 * FILE:	dtrace_cpu.c
 * DESCRIPTION:	DTrce - per-CPU state
 *
 * Copyright (c) 2010, 2014, Oracle and/or its affiliates. All rights reserved.
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
#include <linux/module.h>
#include <asm/dtrace_cpuinfo.h>

DEFINE_PER_CPU_SHARED_ALIGNED(cpu_core_t, dtrace_cpu_core);
EXPORT_PER_CPU_SYMBOL(dtrace_cpu_core);

DEFINE_PER_CPU_SHARED_ALIGNED(cpuinfo_t, dtrace_cpu_info);
EXPORT_PER_CPU_SYMBOL(dtrace_cpu_info);

void dtrace_cpu_init(void)
{
	int	cpu;

	for_each_present_cpu(cpu) {
		cpuinfo_arch_t		*ci = &cpu_data(cpu);
		cpuinfo_t		*cpui = per_cpu_info(cpu);
		cpu_core_t		*cpuc = per_cpu_core(cpu);

		cpui->cpu_id = cpu;
		cpui->cpu_pset = 0;
		cpui->cpu_chip = dtrace_cpuinfo_chip(ci);
		cpui->cpu_lgrp = 0;
		cpui->cpu_info = ci;

		cpuc->cpuc_dtrace_flags = 0;
		cpuc->cpuc_dcpc_intr_state = 0;
		cpuc->cpuc_dtrace_illval = 0;
		mutex_init(&cpuc->cpuc_pid_lock);

		cpuc->cpu_dtrace_regs = NULL;
		cpuc->cpu_dtrace_caller = 0;
		rwlock_init(&cpuc->cpu_ft_lock);
	}
}
