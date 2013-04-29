#ifndef _DTRACE_PROVIDER_DEFINES_H
#define _DTRACE_PROVIDER_DEFINES_H

/*
 * DTrace Dynamic Tracing Software: DTrace Provider defines
 *
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

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
 * Copyright 2009 -- 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace/universal.h>
#include <linux/cred.h>

typedef uintptr_t		dtrace_provider_id_t;
typedef uintptr_t		dtrace_meta_provider_id_t;
typedef struct cred	cred_t;
typedef __be32		ipaddr_t;

struct dtrace_pops;
struct dtrace_helper_probedesc;
struct dtrace_helper_provdesc;
struct dtrace_mops;
struct dtrace_meta;

#endif /* _DTRACE_PROVIDER_DEFINES_H */
