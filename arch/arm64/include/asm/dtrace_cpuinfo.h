/* Copyright (C) 2018 Oracle, Inc. */

#ifndef _ASM_ARM64_DTRACE_CPUINFO_H_
#define _ASM_ARM64_DTRACE_CPUINFO_H_

#include <asm/cpu.h>

typedef struct cpuinfo_arm64		cpuinfo_arch_t;

#define dtrace_cpuinfo_chip(ci)		((ci)->cpu.node_id)

#endif /* _ASM_ARM64_DTRACE_CPUINFO_H_ */
