/*
 * FILE:	dtrace_cpu.c
 * DESCRIPTION:	Dynamic Tracing: CPU info - part of kernel core
 *
 * Copyright (C) 2010, 2011 Oracle Corporation
 */

#include <linux/dtrace_cpu.h>
#include <asm/percpu.h>

DEFINE_PER_CPU_SHARED_ALIGNED(cpu_core_t, dtrace_cpu_info);
EXPORT_PER_CPU_SYMBOL(dtrace_cpu_info);
