/* Copyright (c) 2013, 2017, Oracle and/or its affiliates. All rights reserved. */

#ifndef _SPARC_DTRACE_ARCH_H
#define _SPARC_DTRACE_ARCH_H

#include <linux/module.h>

typedef uint32_t	asm_instr_t;

asmlinkage void dtrace_fbt_trap(unsigned long, struct pt_regs *);

#endif /* _SPARC_DTRACE_ARCH_H */
