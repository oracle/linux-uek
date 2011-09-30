/*
 * FILE:	systrace_mod.c
 * DESCRIPTION:	System Call Tracing: module handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "systrace.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("System Call Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("Proprietary");

static const dtrace_pattr_t syscall_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t syscall_pops = {
	systrace_provide,
	NULL,
	systrace_enable,
	systrace_disable,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	systrace_destroy
};

DT_PROVIDER_MODULE(syscall, DTRACE_PRIV_USER);
