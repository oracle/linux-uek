/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_FAULTS_DEFINES_H
#define _LINUX_DTRACE_FAULTS_DEFINES_H

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
