/* Copyright (C) 2013-2016 Oracle, Inc. */

#ifndef _X86_DTRACE_ARCH_H
#define _X86_DTRACE_ARCH_H

typedef uint8_t		asm_instr_t;

#define DTRACE_PDATA_SIZE	64
#define DTRACE_PDATA_EXTRA      0
#define DTRACE_PDATA_MAXSIZE    (DTRACE_PDATA_SIZE + DTRACE_PDATA_EXTRA)

#define ASM_CALL_SIZE		5

#endif /* _X86_DTRACE_ARCH_H */
