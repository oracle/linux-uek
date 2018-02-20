/* Copyright (c) 2013, 2018, Oracle and/or its affiliates. All rights reserved. */

#ifndef _X86_DTRACE_ARCH_H
#define _X86_DTRACE_ARCH_H

/* Number of argumens stored inside the mstate. */
#define	DTRACE_MSTATE_ARGS_MAX		6

typedef uint8_t		asm_instr_t;

#define ASM_CALL_SIZE			5

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
	size_t          fbt_probe_cnt;
	prov_exit_f	prov_exit;	/* Called with module_mutex held */
} dtrace_module_t;

#endif /* _X86_DTRACE_ARCH_H */
