/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _LINUX_DTRACE_IOCTL_H_
#define _LINUX_DTRACE_IOCTL_H_

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

#include <linux/ioctl.h>
#include <linux/dtrace/arg.h>
#include <linux/dtrace/buffer.h>
#include <linux/dtrace/conf.h>
#include <linux/dtrace/dof.h>
#include <linux/dtrace/enabling.h>
#include <linux/dtrace/helpers.h>
#include <linux/dtrace/metadesc.h>
#include <linux/dtrace/stability.h>
#include <linux/dtrace/status.h>
#include <linux/dtrace_cpu_defines.h>

#define DTRACEIOC		0xd4
#define DTRACEIOC_PROVIDER	_IOR(DTRACEIOC, 1, dtrace_providerdesc_t)
#define DTRACEIOC_PROBES	_IOR(DTRACEIOC, 2, dtrace_probedesc_t)
#define DTRACEIOC_BUFSNAP	_IOR(DTRACEIOC, 4, dtrace_bufdesc_t)
#define DTRACEIOC_PROBEMATCH	_IOR(DTRACEIOC, 5, dtrace_probedesc_t)
#define DTRACEIOC_ENABLE	_IOW(DTRACEIOC, 6, void *)
#define DTRACEIOC_AGGSNAP	_IOR(DTRACEIOC, 7, dtrace_bufdesc_t)
#define DTRACEIOC_EPROBE	_IOW(DTRACEIOC, 8, dtrace_eprobedesc_t)
#define DTRACEIOC_PROBEARG	_IOR(DTRACEIOC, 9, dtrace_argdesc_t)
#define DTRACEIOC_CONF		_IOR(DTRACEIOC, 10, dtrace_conf_t)
#define DTRACEIOC_STATUS	_IOR(DTRACEIOC, 11, dtrace_status_t)
#define DTRACEIOC_GO		_IOW(DTRACEIOC, 12, processorid_t)
#define DTRACEIOC_STOP		_IOW(DTRACEIOC, 13, processorid_t)
#define DTRACEIOC_AGGDESC	_IOR(DTRACEIOC, 15, dtrace_aggdesc_t)
#define DTRACEIOC_FORMAT	_IOR(DTRACEIOC, 16, dtrace_fmtdesc_t)
#define DTRACEIOC_DOFGET	_IOR(DTRACEIOC, 17, dof_hdr_t)
#define DTRACEIOC_REPLICATE	_IOR(DTRACEIOC, 18, void *)

#define DTRACEHIOC		0xd8
#define DTRACEHIOC_ADD		_IOW(DTRACEHIOC, 1, dof_hdr_t)
#define DTRACEHIOC_REMOVE	_IOW(DTRACEHIOC, 2, int)
#define DTRACEHIOC_ADDDOF	_IOW(DTRACEHIOC, 3, dof_helper_t)

/*
 * This file can be #included by DTrace itself, which cannot parse C functions.
 */
#ifndef __SUNW_D

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

#endif

#endif /* _LINUX_DTRACE_IOCTL_H */
