/* Copyright (c) 2013, 2017, Oracle and/or its affiliates. All rights reserved. */

#ifndef _SPARC_DTRACE_ARCH_H
#define _SPARC_DTRACE_ARCH_H

#include <linux/module.h>

typedef uint32_t	asm_instr_t;

asmlinkage void dtrace_fbt_trap(unsigned long, struct pt_regs *);

/*
 * Structure to hold DTrace specific information about modules (including the
 * core kernel module).  Note that each module (and the main kernel) already
 * has three fields that relate to probing:
 *	- sdt_probes: description of SDT probes in the module
 *	- sdt_probec: number of SDT probes in the module
 *	- pdata: pointer to a dtrace_module struct (for DTrace)
 */
typedef struct dtrace_module {
	int             enabled_cnt;
	size_t          sdt_probe_cnt;
	asm_instr_t	*sdt_tab;
	size_t          fbt_probe_cnt;
	asm_instr_t	*fbt_tab;
} dtrace_module_t;

#endif /* _SPARC_DTRACE_ARCH_H */
