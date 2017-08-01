/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_IOCTL_H_
#define _LINUX_DTRACE_IOCTL_H_

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
#include <linux/dtrace/cpu_defines.h>

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

#endif /* _LINUX_DTRACE_IOCTL_H */
