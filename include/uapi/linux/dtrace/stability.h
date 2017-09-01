/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2015, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_STABILITY_H
#define _LINUX_DTRACE_STABILITY_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/stability_defines.h>

/*
 * Each DTrace provider advertises the name and data stability of each of its
 * probe description components, as well as its architectural dependencies.  The
 * D compiler can query the provider attributes (dtrace_pattr_t) in order to
 * compute the properties of an input program and report them.
 */

typedef struct dtrace_ppriv {
	uint32_t dtpp_flags;			/* privilege flags */
	uid_t dtpp_uid;				/* user ID */
} dtrace_ppriv_t;

typedef struct dtrace_attribute {
	dtrace_stability_t dtat_name;		/* entity name stability */
	dtrace_stability_t dtat_data;		/* entity data stability */
	dtrace_class_t dtat_class;		/* entity data dependency */
} dtrace_attribute_t;

typedef struct dtrace_pattr {
	dtrace_attribute_t dtpa_provider;	/* provider attributes */
	dtrace_attribute_t dtpa_mod;		/* module attributes */
	dtrace_attribute_t dtpa_func;		/* function attributes */
	dtrace_attribute_t dtpa_name;		/* name attributes */
	dtrace_attribute_t dtpa_args;		/* args[] attributes */
} dtrace_pattr_t;

typedef struct dtrace_providerdesc {
	char dtvd_name[DTRACE_PROVNAMELEN];	/* provider name */
	dtrace_pattr_t dtvd_attr;		/* stability attributes */
	dtrace_ppriv_t dtvd_priv;		/* privileges required */
} dtrace_providerdesc_t;

#endif /* _LINUX_DTRACE_STABILITY_H */
