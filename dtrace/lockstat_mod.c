/*
 * FILE:	lockstat_mod.c
 * DESCRIPTION:	Lock Statistics: module handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "lockstat.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Lock Statistics");
MODULE_VERSION("v0.1");
MODULE_LICENSE("Proprietary");

static const dtrace_pattr_t lockstat_attr = {
};

static dtrace_pops_t lockstat_pops = {
};

DT_PROVIDER_MODULE(lockstat, DTRACE_PRIV_KERNEL)
