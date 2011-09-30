/*
 * FILE:	dtrace_mod.c
 * DESCRIPTION:	Dynamic Tracing: module handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/module.h>

#include "dtrace_dev.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Dynamic Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("Proprietary");

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
