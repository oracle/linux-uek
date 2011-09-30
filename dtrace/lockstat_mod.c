/*
 * FILE:	lockstat_mod.c
 * DESCRIPTION:	Lock Statistics: module handling
 *
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
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "lockstat.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Lock Statistics");
MODULE_VERSION("v0.1");
MODULE_LICENSE("CDDL");

static const dtrace_pattr_t lockstat_attr = {
};

static dtrace_pops_t lockstat_pops = {
};

DT_PROVIDER_MODULE(lockstat, DTRACE_PRIV_KERNEL)
