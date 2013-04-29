#ifndef _LINUX_DTRACE_CONF_H
#define _LINUX_DTRACE_CONF_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Configuration
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
