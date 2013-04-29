#ifndef _LINUX_DTRACE_STATUS_H
#define _LINUX_DTRACE_STATUS_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Status
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
 * The status of DTrace is relayed via the dtrace_status structure.  This
 * structure contains members to count drops other than the capacity drops
 * available via the buffer interface (see above).  This consists of dynamic
 * drops (including capacity dynamic drops, rinsing drops and dirty drops), and
 * speculative drops (including capacity speculative drops, drops due to busy
 * speculative buffers and drops due to unavailable speculative buffers).
 * Additionally, the status structure contains a field to indicate the number
 * of "fill"-policy buffers have been filled and a boolean field to indicate
 * that exit() has been called.  If the dtst_exiting field is non-zero, no
 * further data will be generated until tracing is stopped (at which time any
 * enablings of the END action will be processed); if user-level sees that
 * this field is non-zero, tracing should be stopped as soon as possible.
 */

typedef struct dtrace_status {
	uint64_t dtst_dyndrops;			/* dynamic drops */
	uint64_t dtst_dyndrops_rinsing;		/* dyn drops due to rinsing */
	uint64_t dtst_dyndrops_dirty;		/* dyn drops due to dirty */
	uint64_t dtst_specdrops;		/* speculative drops */
	uint64_t dtst_specdrops_busy;		/* spec drops due to busy */
	uint64_t dtst_specdrops_unavail;	/* spec drops due to unavail */
	uint64_t dtst_errors;			/* total errors */
	uint64_t dtst_filled;			/* number of filled bufs */
	uint64_t dtst_stkstroverflows;		/* stack string tab overflows */
	uint64_t dtst_dblerrors;		/* errors in ERROR probes */
	char dtst_killed;			/* non-zero if killed */
	char dtst_exiting;			/* non-zero if exit() called */
	char dtst_pad[6];			/* pad out to 64-bit align */
} dtrace_status_t;

#endif /* _LINUX_DTRACE_STATUS_H */
