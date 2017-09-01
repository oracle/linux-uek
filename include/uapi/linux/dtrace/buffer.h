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

#ifndef _LINUX_DTRACE_BUFFER_H
#define _LINUX_DTRACE_BUFFER_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/actions_defines.h>
#include <linux/dtrace/buffer_defines.h>

/*
 * In order to get a snapshot of the principal or aggregation buffer,
 * user-level passes a buffer description to the kernel with the dtrace_bufdesc
 * structure.  This describes which CPU user-level is interested in, and
 * where user-level wishes the kernel to snapshot the buffer to (the
 * dtbd_data field).  The kernel uses the same structure to pass back some
 * information regarding the buffer:  the size of data actually copied out, the
 * number of drops, the number of errors, and the offset of the oldest record.
 * If the buffer policy is a "switch" policy, taking a snapshot of the
 * principal buffer has the additional effect of switching the active and
 * inactive buffers.  Taking a snapshot of the aggregation buffer _always_ has
 * the additional effect of switching the active and inactive buffers.
 */
typedef struct dtrace_bufdesc {
	uint64_t dtbd_size;			/* size of buffer */
	uint32_t dtbd_cpu;			/* CPU or DTRACE_CPUALL */
	uint32_t dtbd_errors;			/* number of errors */
	uint64_t dtbd_drops;			/* number of drops */
	DTRACE_PTR(char, dtbd_data);		/* data */
	uint64_t dtbd_oldest;			/* offset of oldest record */
} dtrace_bufdesc_t;

#endif /* _LINUX_DTRACE_BUFFER_H */
