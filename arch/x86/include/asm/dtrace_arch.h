/* Copyright (C) 2013-2016 Oracle, Inc. */

#ifndef _X86_DTRACE_ARCH_H
#define _X86_DTRACE_ARCH_H

typedef uint8_t		asm_instr_t;

/*
 * No additional memory needs to be allocated for the PDATA section on x86.
 */
#define DTRACE_PD_MAXSIZE(mp)           (0)

#define DTRACE_PD_MAXSIZE_KERNEL        (0)

#define ASM_CALL_SIZE			5

#endif /* _X86_DTRACE_ARCH_H */
