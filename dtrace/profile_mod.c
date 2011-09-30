/*
 * FILE:	profile_mod.c
 * DESCRIPTION:	Profile Interrupt Tracing: module handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "profile.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Profile Interrupt Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("Proprietary");

static const dtrace_pattr_t profile_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
};

static dtrace_pops_t profile_pops = {
	profile_provide,
	NULL,
	profile_enable,
	profile_disable,
	NULL,
	NULL,
	NULL,
	NULL,
	profile_usermode,
	profile_destroy,
};

DT_PROVIDER_MODULE(profile, DTRACE_PRIV_KERNEL | DTRACE_PRIV_USER)
