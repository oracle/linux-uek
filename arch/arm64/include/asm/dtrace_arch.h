/* Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved. */

#ifndef _ASM_ARM64_DTRACE_ARCH_H
#define _ASM_ARM64_DTRACE_ARCH_H

/* Number of argumens stored inside the mstate. */
#define	DTRACE_MSTATE_ARGS_MAX		7

typedef uint32_t	asm_instr_t;

typedef int (*prov_exit_f)(void);

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
	prov_exit_f	prov_exit;	/* Called with module_mutex held */
} dtrace_module_t;

#endif /* _ASM_ARM64_DTRACE_ARCH_H */
