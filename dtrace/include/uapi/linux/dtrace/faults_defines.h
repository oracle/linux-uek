#ifndef _LINUX_DTRACE_FAULTS_DEFINES_H
#define _LINUX_DTRACE_FAULTS_DEFINES_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Faults
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
 * The constants below DTRACEFLT_LIBRARY indicate probe processing faults;
 * constants at or above DTRACEFLT_LIBRARY indicate faults in probe
 * postprocessing at user-level.  Probe processing faults induce an ERROR
 * probe and are replicated in unistd.d to allow users' ERROR probes to decode
 * the error condition using thse symbolic labels.
 */
#define DTRACEFLT_UNKNOWN		0	/* Unknown fault */
#define DTRACEFLT_BADADDR		1	/* Bad address */
#define DTRACEFLT_BADALIGN		2	/* Bad alignment */
#define DTRACEFLT_ILLOP			3	/* Illegal operation */
#define DTRACEFLT_DIVZERO		4	/* Divide-by-zero */
#define DTRACEFLT_NOSCRATCH		5	/* Out of scratch space */
#define DTRACEFLT_KPRIV			6	/* Illegal kernel access */
#define DTRACEFLT_UPRIV			7	/* Illegal user access */
#define DTRACEFLT_TUPOFLOW		8	/* Tuple stack overflow */
#define DTRACEFLT_BADSTACK		9	/* Bad stack */

#define DTRACEFLT_LIBRARY		1000	/* Library-level fault */

#endif /* _LINUX_DTRACE_FAULTS_DEFINES_H */
