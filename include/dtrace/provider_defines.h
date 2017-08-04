/*
 * Dynamic Tracing for Linux - Provider defines
 *
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
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

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _DTRACE_PROVIDER_DEFINES_H
#define _DTRACE_PROVIDER_DEFINES_H

#include <linux/dtrace/universal.h>
#include <linux/cred.h>
#include <linux/in6.h>

typedef uintptr_t		dtrace_provider_id_t;
typedef uintptr_t		dtrace_meta_provider_id_t;
typedef struct cred	cred_t;
typedef __be32		ipaddr_t;
typedef ipaddr_t *	ipaddr_t_p;
typedef struct in6_addr	in6_addr_t;

struct dtrace_pops;
struct dtrace_helper_probedesc;
struct dtrace_helper_provdesc;
struct dtrace_mops;
struct dtrace_meta;

#endif /* _DTRACE_PROVIDER_DEFINES_H */
