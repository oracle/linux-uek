/*
 * FILE:	fbt_dmod.c
 * DESCRIPTION:	Function Boundary Tracing: module handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Function Boundary Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("Proprietary");

static const dtrace_pattr_t fbt_attr = {
};

static dtrace_pops_t fbt_pops = {
};

DT_PROVIDER_MODULE(fbt, DTRACE_PRIV_KERNEL);
