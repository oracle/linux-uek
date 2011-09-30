/*
 * FILE:	fasttrap_mod.c
 * DESCRIPTION:	Fasttrap Tracing: module handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fasttrap.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Fasttrap Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("Proprietary");

static const dtrace_pattr_t fasttrap_attr = {
};

static dtrace_pops_t fasttrap_pops = {
};

DT_PROVIDER_MODULE(fasttrap, DTRACE_PRIV_PROC | DTRACE_PRIV_OWNER)
