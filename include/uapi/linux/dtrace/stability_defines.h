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

#ifndef _LINUX_DTRACE_STABILITY_DEFINES_H
#define _LINUX_DTRACE_STABILITY_DEFINES_H

#include <linux/dtrace/universal.h>

typedef uint8_t dtrace_stability_t;	/* stability code */
typedef uint8_t dtrace_class_t;		/* architectural dependency class */

#define	DTRACE_STABILITY_INTERNAL	0	/* private to DTrace itself */
#define	DTRACE_STABILITY_PRIVATE	1	/* private to Sun (see docs) */
#define	DTRACE_STABILITY_OBSOLETE	2	/* scheduled for removal */
#define	DTRACE_STABILITY_EXTERNAL	3	/* not controlled by Sun */
#define	DTRACE_STABILITY_UNSTABLE	4	/* new or rapidly changing */
#define	DTRACE_STABILITY_EVOLVING	5	/* less rapidly changing */
#define	DTRACE_STABILITY_STABLE		6	/* mature interface from Sun */
#define	DTRACE_STABILITY_STANDARD	7	/* industry standard */
#define	DTRACE_STABILITY_MAX		7	/* maximum valid stability */

#define	DTRACE_CLASS_UNKNOWN	0	/* unknown architectural dependency */
#define	DTRACE_CLASS_CPU	1	/* CPU-module-specific */
#define	DTRACE_CLASS_PLATFORM	2	/* platform-specific (uname -i) */
#define	DTRACE_CLASS_GROUP	3	/* hardware-group-specific (uname -m) */
#define	DTRACE_CLASS_ISA	4	/* ISA-specific (uname -p) */
#define	DTRACE_CLASS_COMMON	5	/* common to all systems */
#define	DTRACE_CLASS_MAX	5	/* maximum valid class */

#define DTRACE_PRIV_NONE	0x0000
#define DTRACE_PRIV_KERNEL	0x0001
#define DTRACE_PRIV_USER	0x0002
#define DTRACE_PRIV_PROC	0x0004
#define DTRACE_PRIV_OWNER	0x0008
#define DTRACE_PRIV_ALL		(DTRACE_PRIV_KERNEL | DTRACE_PRIV_USER | \
				 DTRACE_PRIV_PROC | DTRACE_PRIV_OWNER)

struct dtrace_ppriv;
struct dtrace_attribute;
struct dtrace_pattr;
struct dtrace_providerdesc;

#endif /* _LINUX_DTRACE_STABILITY_DEFINES_H */
