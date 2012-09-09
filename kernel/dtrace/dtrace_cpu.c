/*
 * FILE:	dtrace_cpu.c
 * DESCRIPTION:	Dynamic Tracing: CPU info - part of kernel core
 *
 * Copyright (C) 2010, 2011 Oracle Corporation
 */

#include <linux/dtrace_cpu.h>
#include <linux/module.h>
#include <asm/percpu.h>

DEFINE_PER_CPU_SHARED_ALIGNED(cpu_core_t, dtrace_cpu_core);
EXPORT_PER_CPU_SYMBOL(dtrace_cpu_core);

DEFINE_PER_CPU_SHARED_ALIGNED(cpuinfo_t, dtrace_cpu_info);
EXPORT_PER_CPU_SYMBOL(dtrace_cpu_info);

void dtrace_cpu_init(void)
{
	int	cpu;

	for_each_present_cpu(cpu) {
		struct cpuinfo_x86	*c = &cpu_data(cpu);
		cpuinfo_t		*i = per_cpu_info(cpu);

		i->cpu_id = cpu;
		i->cpu_pset = 0;
		i->cpu_chip = c->phys_proc_id;
		i->cpu_lgrp = 0;
		i->cpu_info = c;
	}
}
