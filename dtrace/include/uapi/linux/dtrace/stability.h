#ifndef _LINUX_DTRACE_STABILITY_H
#define _LINUX_DTRACE_STABILITY_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Stability Attributes
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
#include <linux/dtrace/stability_defines.h>

/*
 * Each DTrace provider advertises the name and data stability of each of its
 * probe description components, as well as its architectural dependencies.  The
 * D compiler can query the provider attributes (dtrace_pattr_t) in order to
 * compute the properties of an input program and report them.
 */

typedef struct dtrace_ppriv {
	uint32_t dtpp_flags;			/* privilege flags */
	uid_t dtpp_uid;				/* user ID */
} dtrace_ppriv_t;

typedef struct dtrace_attribute {
	dtrace_stability_t dtat_name;		/* entity name stability */
	dtrace_stability_t dtat_data;		/* entity data stability */
	dtrace_class_t dtat_class;		/* entity data dependency */
} dtrace_attribute_t;

typedef struct dtrace_pattr {
	dtrace_attribute_t dtpa_provider;	/* provider attributes */
	dtrace_attribute_t dtpa_mod;		/* module attributes */
	dtrace_attribute_t dtpa_func;		/* function attributes */
	dtrace_attribute_t dtpa_name;		/* name attributes */
	dtrace_attribute_t dtpa_args;		/* args[] attributes */
} dtrace_pattr_t;

typedef struct dtrace_providerdesc {
	char dtvd_name[DTRACE_PROVNAMELEN];	/* provider name */
	dtrace_pattr_t dtvd_attr;		/* stability attributes */
	dtrace_ppriv_t dtvd_priv;		/* privileges required */
} dtrace_providerdesc_t;

#endif /* _LINUX_DTRACE_STABILITY_H */
