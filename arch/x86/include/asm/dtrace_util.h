/* Copyright (C) 2013-2014 Oracle, Inc. */

#ifndef _X86_DTRACE_UTIL_H
#define _X86_DTRACE_UTIL_H

#include <asm/ptrace.h>

extern int dtrace_invop_add(uint8_t (*func)(struct pt_regs *));
extern void dtrace_invop_remove(uint8_t (*func)(struct pt_regs *));

extern void dtrace_invop_enable(uint8_t *);
extern void dtrace_invop_disable(uint8_t *, uint8_t);

#endif /* _X86_DTRACE_UTIL_H */
