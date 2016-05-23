#ifndef _X86_64_MOD_ARCH_H
#define _X86_64_MOD_ARCH_H

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2009-2014 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
        size_t          sdt_probe_cnt;
        int             sdt_enabled;
        size_t          fbt_probe_cnt;
} dtrace_module_t;

#endif /* _X86_64_MOD_ARCH_H */
