#ifndef _LINUX_DTRACE_H_
#define _LINUX_DTRACE_H_

/*
 * DTrace Dynamic Tracing Software: Kernel Interfaces
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

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/dtrace/universal.h>
#include <linux/dtrace/dif.h>
#include <linux/dtrace/actions.h>
#include <linux/dtrace/dof.h>
#include <linux/dtrace/difo.h>
#include <linux/dtrace/enabling.h>
#include <linux/dtrace/metadesc.h>
#include <linux/dtrace/options.h>
#include <linux/dtrace/buffer.h>
#include <linux/dtrace/status.h>
#include <linux/dtrace/conf.h>
#include <linux/dtrace/faults.h>
#include <linux/dtrace/arg.h>
#include <linux/dtrace/stability.h>
#include <linux/dtrace/helpers.h>

#ifdef	__cplusplus
}
#endif

#endif /* _LINUX_DTRACE_H_ */
