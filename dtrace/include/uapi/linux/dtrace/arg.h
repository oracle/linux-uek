#ifndef _LINUX_DTRACE_ARG_H
#define _LINUX_DTRACE_ARG_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Argument Types
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
#include <linux/dtrace/arg_defines.h>

/*
 * Because it would waste both space and time, argument types do not reside
 * with the probe.  In order to determine argument types for args[X]
 * variables, the D compiler queries for argument types on a probe-by-probe
 * basis.  (This optimizes for the common case that arguments are either not
 * used or used in an untyped fashion.)  Typed arguments are specified with a
 * string of the type name in the dtragd_native member of the argument
 * description structure.  Typed arguments may be further translated to types
 * of greater stability; the provider indicates such a translated argument by
 * filling in the dtargd_xlate member with the string of the translated type.
 * Finally, the provider may indicate which argument value a given argument
 * maps to by setting the dtargd_mapping member -- allowing a single argument
 * to map to multiple args[X] variables.
 */
typedef struct dtrace_argdesc {
	dtrace_id_t dtargd_id;
	int dtargd_ndx;
	int dtargd_mapping;
	char dtargd_native[DTRACE_ARGTYPELEN];
	char dtargd_xlate[DTRACE_ARGTYPELEN];
} dtrace_argdesc_t;

#endif /* _LINUX_DTRACE_ARG_H */
