/* Copyright (C) 2015, 2017, Oracle and/or its affiliates. All rights reserved. */

#ifndef _LINUX_DTRACE_FBT_H
#define _LINUX_DTRACE_FBT_H

#include <linux/module.h>
#include <asm/dtrace_arch.h>

extern unsigned long dtrace_fbt_nfuncs __attribute__((weak));

/*
 * Prototype for callback function that handles the actual creation of FBT
 * probes.
 *
 * Arguments to pass:
 *	- Pointer to module the probe will belong to
 *	- function name
 *	- probe type (FBT_ENTRY or FBT_RETURN)
 *	- probe subtype (arch-specific)
 *	- address (location of the probe)
 *	- return value from previous callback invocation
 * Returns:
 *	- generic pointer (only to be used to pass back in)
 */
#define FBT_ENTRY	0
#define FBT_RETURN	1

typedef void *(*fbt_add_probe_fn)(struct module *, char *, int, int,
				  asm_instr_t *, uintptr_t, void *);
extern void dtrace_fbt_init(fbt_add_probe_fn);

/*
 * Dynamic blacklist routines.
 */
typedef struct dt_fbt_bl_entry dt_fbt_bl_entry_t;

extern dt_fbt_bl_entry_t *dtrace_fbt_bl_add(unsigned long, const char *);
extern dt_fbt_bl_entry_t *dtrace_fbt_bl_first(void);
extern dt_fbt_bl_entry_t *dtrace_fbt_bl_next(dt_fbt_bl_entry_t *);
extern unsigned long dtrace_fbt_bl_entry_addr(dt_fbt_bl_entry_t *);
extern const char *dtrace_fbt_bl_entry_name(dt_fbt_bl_entry_t *);

#endif /* _LINUX_DTRACE_FBT_H */
