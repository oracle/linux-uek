#ifndef _LINUX_DTRACE_OPTIONS_DEFINES_H
#define _LINUX_DTRACE_OPTIONS_DEFINES_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Option Interface defines
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

/*
 * Run-time DTrace options are set and retrieved via DOF_SECT_OPTDESC sections
 * in a DOF image.  The dof_optdesc structure contains an option identifier and
 * an option value.  The valid option identifiers are found below; the mapping
 * between option identifiers and option identifying strings is maintained at
 * user-level.  Note that the value of DTRACEOPT_UNSET is such that all of the
 * following are potentially valid option values:  all positive integers, zero
 * and negative one.  Some options (notably "bufpolicy" and "bufresize") take
 * predefined tokens as their values; these are defined with
 * DTRACEOPT_{option}_{token}.
 */

#define	DTRACEOPT_BUFSIZE	0	/* buffer size */
#define	DTRACEOPT_BUFPOLICY	1	/* buffer policy */
#define	DTRACEOPT_DYNVARSIZE	2	/* dynamic variable size */
#define	DTRACEOPT_AGGSIZE	3	/* aggregation size */
#define	DTRACEOPT_SPECSIZE	4	/* speculation size */
#define	DTRACEOPT_NSPEC		5	/* number of speculations */
#define	DTRACEOPT_STRSIZE	6	/* string size */
#define	DTRACEOPT_CLEANRATE	7	/* dynvar cleaning rate */
#define	DTRACEOPT_CPU		8	/* CPU to trace */
#define	DTRACEOPT_BUFRESIZE	9	/* buffer resizing policy */
#define	DTRACEOPT_GRABANON	10	/* grab anonymous state, if any */
#define	DTRACEOPT_FLOWINDENT	11	/* indent function entry/return */
#define	DTRACEOPT_QUIET		12	/* only output explicitly traced data */
#define	DTRACEOPT_STACKFRAMES	13	/* number of stack frames */
#define	DTRACEOPT_USTACKFRAMES	14	/* number of user stack frames */
#define	DTRACEOPT_AGGRATE	15	/* aggregation snapshot rate */
#define	DTRACEOPT_SWITCHRATE	16	/* buffer switching rate */
#define	DTRACEOPT_STATUSRATE	17	/* status rate */
#define	DTRACEOPT_DESTRUCTIVE	18	/* destructive actions allowed */
#define	DTRACEOPT_STACKINDENT	19	/* output indent for stack traces */
#define	DTRACEOPT_RAWBYTES	20	/* always print bytes in raw form */
#define	DTRACEOPT_JSTACKFRAMES	21	/* number of jstack() frames */
#define	DTRACEOPT_JSTACKSTRSIZE	22	/* size of jstack() string table */
#define	DTRACEOPT_AGGSORTKEY	23	/* sort aggregations by key */
#define	DTRACEOPT_AGGSORTREV	24	/* reverse-sort aggregations */
#define	DTRACEOPT_AGGSORTPOS	25	/* agg. position to sort on */
#define	DTRACEOPT_AGGSORTKEYPOS	26	/* agg. key position to sort on */
#define DTRACEOPT_QUIETRESIZE	27	/* quieten buffer-resize messages */
#define	DTRACEOPT_MAX		28	/* number of options */

#define	DTRACEOPT_UNSET		(dtrace_optval_t)-2	/* unset option */

#define	DTRACEOPT_BUFPOLICY_RING	0	/* ring buffer */
#define	DTRACEOPT_BUFPOLICY_FILL	1	/* fill buffer, then stop */
#define	DTRACEOPT_BUFPOLICY_SWITCH	2	/* switch buffers */

#define	DTRACEOPT_BUFRESIZE_AUTO	0	/* automatic resizing */
#define	DTRACEOPT_BUFRESIZE_MANUAL	1	/* manual resizing */

#endif /* _LINUX_DTRACE_OPTIONS_DEFINES_H */
