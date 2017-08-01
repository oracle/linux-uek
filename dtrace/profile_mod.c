/*
 * FILE:	profile_mod.c
 * DESCRIPTION:	DTrace - Profile provider kernel module
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
#include "profile.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Profile Interrupt Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

static const dtrace_pattr_t profile_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
};

DT_PROVIDER_POPS(profile)

static dtrace_pops_t profile_pops = {
	.dtps_provide = profile_provide,
	.dtps_provide_module = NULL,
	.dtps_destroy_module = NULL,
	.dtps_enable = profile_enable,
	.dtps_disable = profile_disable,
	.dtps_suspend = NULL,
	.dtps_resume = NULL,
	.dtps_getargdesc = NULL,
	.dtps_getargval = NULL,
	.dtps_usermode = profile_usermode,
	.dtps_destroy = profile_destroy,
};

DT_PROVIDER_MODULE(profile, DTRACE_PRIV_KERNEL | DTRACE_PRIV_USER)
