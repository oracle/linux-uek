/* Copyright (C) 2013-2014 Oracle, Inc. */

#ifndef _X86_DTRACE_UTIL_H
#define _X86_DTRACE_UTIL_H

#define DTRACE_INVOP_NOPS		0x0f	/* 5-byte NOP sequence */
#define DTRACE_INVOP_MOV_RSP_RBP	0x48	/* mov %rsp, %rbp = 48 89 e5 */
#define DTRACE_INVOP_PUSH_BP		0x55	/* push %rbp = 55 */
#define DTRACE_INVOP_NOP		0x90	/* nop = 90 */
#define DTRACE_INVOP_LEAVE		0xc9	/* leave = c9 */
#define DTRACE_INVOP_RET		0xc3	/* ret = c3 */

#ifndef __ASSEMBLY__

#include <asm/ptrace.h>

extern int dtrace_invop_add(uint8_t (*func)(struct pt_regs *));
extern void dtrace_invop_remove(uint8_t (*func)(struct pt_regs *));

extern void dtrace_invop_enable(uint8_t *);
extern void dtrace_invop_disable(uint8_t *, uint8_t);

extern int dtrace_user_addr_is_exec(uintptr_t);

#endif

#endif /* _X86_DTRACE_UTIL_H */
