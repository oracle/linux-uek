/*
 * Dynamic Tracing for Linux - syscall tracing provider
 *
 * Copyright (c) 2011, 2017, Oracle and/or its affiliates. All rights reserved.
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

#ifndef _SYSTRACE_H_
#define _SYSTRACE_H_

#include "dtrace.h"

extern void systrace_provide(void *, const dtrace_probedesc_t *);
extern int systrace_enable(void *arg, dtrace_id_t, void *);
extern void systrace_disable(void *arg, dtrace_id_t, void *);
extern void systrace_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	syscall_id;

extern int syscall_dev_init(void);
extern void syscall_dev_exit(void);

#endif /* _SYSTRACE_H_ */
