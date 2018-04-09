/*
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _DTRACE_SDT_H_
#define	_DTRACE_SDT_H_

#ifdef CONFIG_DTRACE
#include <linux/module.h>
#include <asm/dtrace_arch.h>

/*
 * SDT probe called relocation information for the core kernel, provided by
 * .tmp_sdtinfo.S.
 */
typedef struct dtrace_sdt_probeinfo {
	unsigned long		addr;
	unsigned long		name_len;
	unsigned long		func_len;
	char			name[0];
} __aligned(sizeof(unsigned long)) dtrace_sdt_probeinfo_t;

extern unsigned long dtrace_sdt_nprobes __attribute__((weak));
extern void *dtrace_sdt_probes __attribute__((weak));

extern void __init dtrace_sdt_init(void);
extern void __init dtrace_sdt_register(struct module *);
extern void dtrace_sdt_register_module(struct module *,
				       void *sdt_names_addr, size_t,
				       void *sdt_args_addr, size_t);
extern void dtrace_sdt_exit(void);

/*
 * Functions to be defined in arch/<arch>/kernel/dtrace_sdt.c
 */
extern void __init_or_module dtrace_sdt_nop_multi(asm_instr_t **, int *, int);

#ifdef CONFIG_X86_64
extern void __init dtrace_sdt_init_arch(void);
#else
#define	dtrace_sdt_init_arch()
#endif /* CONFIG_X86_64 */

#endif	/* CONFIG_DTRACE */
#endif	/* _DTRACE_SDT_H_ */
