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

#ifndef _LINUX_DTRACE_CONF_H
#define _LINUX_DTRACE_CONF_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/conf_defines.h>

/*
 * User-level may need to understand some elements of the kernel DTrace
 * configuration in order to generate correct DIF.  This information is
 * conveyed via the dtrace_conf structure.
 */
typedef struct dtrace_conf {
	uint_t dtc_difversion;			/* supported DIF version */
	uint_t dtc_difintregs;			/* # of DIF integer registers */
	uint_t dtc_diftupregs;			/* # of DIF tuple registers */
	uint_t dtc_ctfmodel;			/* CTF data model */
	/* Deviation from Solaris...  Used to just be 8 padding entries. */
	uint_t dtc_maxbufs;			/* max # of buffers */
	uint_t dtc_pad[7];			/* reserved for future use */
} dtrace_conf_t;

#endif /* _LINUX_DTRACE_CONF_H */
