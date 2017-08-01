/*
 * FILE:	fbt_mod.c
 * DESCRIPTION:	DTrace - FBT provider kernel module
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
#include "fbt_impl.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Function Boundary Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

static const dtrace_pattr_t fbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

DT_PROVIDER_POPS(fbt)

static dtrace_pops_t fbt_pops = {
	.dtps_provide = NULL,
	.dtps_provide_module = fbt_provide_module,
	.dtps_destroy_module = fbt_destroy_module,
	.dtps_enable = fbt_enable,
	.dtps_disable = fbt_disable,
	.dtps_suspend = NULL,
	.dtps_resume = NULL,
	.dtps_getargdesc = NULL,
	.dtps_getargval = NULL,
	.dtps_usermode = NULL,
	.dtps_destroy = fbt_destroy
};

DT_PROVIDER_MODULE(fbt, DTRACE_PRIV_KERNEL)
