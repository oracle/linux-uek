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

#ifndef _LINUX_DTRACE_STATUS_H
#define _LINUX_DTRACE_STATUS_H

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
