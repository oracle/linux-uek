/*
 * FILE:	dtrace_mod.c
 * DESCRIPTION:	DTrace - framework kernel module
 *
 * Copyright (c) 2010, 2011, Oracle and/or its affiliates. All rights reserved.
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

#include "dtrace_dev.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Dynamic Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

/*
 * Initialize the module.
 */
static int __init dtrace_init(void)
{
	return dtrace_dev_init();
}

/*
 * Perform cleanup before the module is removed.
 */
static void __exit dtrace_exit(void)
{
	dtrace_dev_exit();
}

module_init(dtrace_init);
module_exit(dtrace_exit);
