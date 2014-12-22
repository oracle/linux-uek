/* Copyright (C) 2013-2014 Oracle, Inc. */

#ifndef _ASM_X86_DTRACE_CPUINFO_H_
#define _ASM_X86_DTRACE_CPUINFO_H_

#include <asm/processor.h>

typedef struct cpuinfo_x86	cpuinfo_arch_t;

#define dtrace_cpuinfo_chip(ci)	((ci)->phys_proc_id)

#endif /* _ASM_X86_DTRACE_CPUINFO_H_ */
