/*
 * FILE:	dt_test_mod.c
 * DESCRIPTION:	DTrace - test provider kernel module
 *
 * Copyright (c) 2011, 2017, Oracle and/or its affiliates. All rights reserved.
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
#include "dt_test.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("DTrace Test Probe");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

static const dtrace_pattr_t dt_test_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

DT_PROVIDER_POPS(dt_test)

static dtrace_pops_t dt_test_pops = {
	.dtps_provide = dt_test_provide,
	.dtps_provide_module = NULL,
	.dtps_destroy_module = NULL,
	.dtps_enable = dt_test_enable,
	.dtps_disable = dt_test_disable,
	.dtps_suspend = NULL,
	.dtps_resume = NULL,
	.dtps_getargdesc = NULL,
	.dtps_getargval = NULL,
	.dtps_usermode = NULL,
	.dtps_destroy = dt_test_destroy
};

DT_PROVIDER_MODULE(dt_test, DTRACE_PRIV_USER)

void foo(void)
{
	DTRACE_PROBE(sdt__test2);
}
