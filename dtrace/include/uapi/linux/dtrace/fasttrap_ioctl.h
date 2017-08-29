/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _LINUX_DTRACE_FASTRRAP_IOCTL_H_
#define _LINUX_DTRACE_FASTTRAP_IOCTL_H_

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
#include <linux/dtrace/fasttrap.h>

#define FASTTRAPIOC		0xf4
#define FASTTRAPIOC_MAKEPROBE	_IOW(FASTTRAPIOC, 1, fasttrap_probe_spec_t)
#define FASTTRAPIOC_GETINSTR	_IOR(FASTTRAPIOC, 2, fasttrap_instr_query_t)

#endif /* _LINUX_DTRACE_FASTTRAP_IOCTL_H_ */
