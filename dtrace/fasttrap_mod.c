/*
 * FILE:	fasttrap_mod.c
 * DESCRIPTION:	DTrace - fasttrap provider kernel module
 *
 * Copyright (c) 2010, 2013, Oracle and/or its affiliates. All rights reserved.
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
#include "fasttrap_impl.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Fasttrap Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

static dtrace_mops_t fasttrap_mops = {
	fasttrap_meta_create_probe,
	fasttrap_meta_provide,
	fasttrap_meta_remove
};

DT_META_PROVIDER_MODULE(fasttrap)
