/*
 * Dynamic Tracing for Linux - Framework per-module data
 *
 * Copyright (c) 2009, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _X86_64_MOD_ARCH_H
#define _X86_64_MOD_ARCH_H

#include <asm/dtrace_arch.h>

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
} dtrace_module_t;

#endif /* _X86_64_MOD_ARCH_H */
