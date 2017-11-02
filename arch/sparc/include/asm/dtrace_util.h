/* Copyright (C) 2013, 2017, Oracle and/or its affiliates. All rights reserved. */

#ifndef _SPARC_DTRACE_UTIL_H
#define _SPARC_DTRACE_UTIL_H

#include <asm/dtrace_arch.h>

extern int dtrace_user_addr_is_exec(uintptr_t);

extern int dtrace_fbt_set_handler(void (*func)(struct pt_regs *));

extern void dtrace_mod_pdata_init(dtrace_module_t *);
extern void dtrace_mod_pdata_cleanup(dtrace_module_t *);

#endif /* _SPARC_DTRACE_UTIL_H */
