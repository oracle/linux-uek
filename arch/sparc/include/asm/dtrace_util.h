/* Copyright (C) 2013, 2017, Oracle and/or its affiliates. All rights reserved. */

#ifndef _SPARC_DTRACE_UTIL_H
#define _SPARC_DTRACE_UTIL_H

#include <asm/dtrace_arch.h>

extern int dtrace_user_addr_is_exec(uintptr_t);

extern int dtrace_fbt_set_handler(void (*func)(struct pt_regs *));

#endif /* _SPARC_DTRACE_UTIL_H */
