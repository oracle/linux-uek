/*
 * FILE:	systrace_mod.c
 * DESCRIPTION:	DTrace - systrace provider kernel module
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "systrace.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("System Call Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

static const dtrace_pattr_t syscall_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

DT_PROVIDER_POPS(systrace)

static dtrace_pops_t syscall_pops = {
	.dtps_provide = systrace_provide,
	.dtps_provide_module = NULL,
	.dtps_destroy_module = NULL,
	.dtps_enable = systrace_enable,
	.dtps_disable = systrace_disable,
	.dtps_suspend = NULL,
	.dtps_resume = NULL,
	.dtps_getargdesc = NULL,
	.dtps_getargval = NULL,
	.dtps_usermode = NULL,
	.dtps_destroy = systrace_destroy
};

DT_PROVIDER_MODULE(syscall, DTRACE_PRIV_USER)
