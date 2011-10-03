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
 */

/* Copyright (C) 2011 Oracle Corporation */

#ifndef _SYSTRACE_H_
#define _SYSTRACE_H_

#include "dtrace.h"

typedef void (*sys_call_ptr_t)(void);
typedef long (*dt_sys_call_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
			      uintptr_t, uintptr_t);

typedef struct dtrace_syscalls {
	const char	*name;
	dtrace_id_t	stsy_entry;
	dtrace_id_t	stsy_return;
	dt_sys_call_t	stsy_underlying;
	sys_call_ptr_t	*stsy_tblent;
} dtrace_syscalls_t;

typedef void (*dtrace_systrace_probe_t)(dtrace_id_t, uintptr_t, uintptr_t,
					uintptr_t, uintptr_t, uintptr_t,
					uintptr_t);

typedef struct systrace_info {
	dtrace_systrace_probe_t	*probep;
	dtrace_systrace_probe_t	stub;
	dt_sys_call_t		syscall;
	dtrace_syscalls_t	sysent[NR_syscalls];
} systrace_info_t;

extern systrace_info_t *dtrace_syscalls_init(void);

extern void systrace_provide(void *, const dtrace_probedesc_t *);
extern int systrace_enable(void *arg, dtrace_id_t, void *);
extern void systrace_disable(void *arg, dtrace_id_t, void *);
extern void systrace_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	syscall_id;

extern int syscall_dev_init(void);
extern void syscall_dev_exit(void);

#endif /* _SYSTRACE_H_ */
