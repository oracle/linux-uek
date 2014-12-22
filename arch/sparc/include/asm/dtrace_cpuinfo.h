/* Copyright (C) 2013,2014 Oracle, Inc. */

#ifndef _ASM_SPARC_DTRACE_CPUINFO_H_
#define _ASM_SPARC_DTRACE_CPUINFO_H_

#include <asm/cpudata.h>

typedef cpuinfo_sparc		cpuinfo_arch_t;

#define dtrace_cpuinfo_chip(ci)	((ci)->proc_id)

#define TSTATE_CCR_SHIFT	32
#define TSTATE_ASI_SHIFT	24

#endif /* _ASM_SPARC_DTRACE_CPUINFO_H_ */
