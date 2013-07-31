/* Copyright (C) 2013 Oracle, Inc. */

#ifndef _LINUX_DTRACE_IOCTL_DEBUG_H_
#define _LINUX_DTRACE_IOCTL_DEBUG_H_

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
 * Copyright 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace/ioctl.h>

void dtrace_size_dbg_print(const char *type, size_t size);

static void dtrace_ioctl_sizes(void) {
#define DBG_PRINT(x) dtrace_size_dbg_print(#x, sizeof(x))
	DBG_PRINT(dtrace_providerdesc_t);
	DBG_PRINT(dtrace_probedesc_t);
	DBG_PRINT(dtrace_bufdesc_t);
	DBG_PRINT(dtrace_eprobedesc_t);
	DBG_PRINT(dtrace_argdesc_t);
	DBG_PRINT(dtrace_conf_t);
	DBG_PRINT(dtrace_status_t);
	DBG_PRINT(processorid_t);
	DBG_PRINT(dtrace_aggdesc_t);
	DBG_PRINT(dtrace_fmtdesc_t);
	DBG_PRINT(dof_hdr_t);
#undef DBG_PRINT
}

#endif /* _LINUX_DTRACE_IOCTL_DEBUG_H */
