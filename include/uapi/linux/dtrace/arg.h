/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_ARG_H
#define _LINUX_DTRACE_ARG_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/arg_defines.h>

/*
 * Because it would waste both space and time, argument types do not reside
 * with the probe.  In order to determine argument types for args[X]
 * variables, the D compiler queries for argument types on a probe-by-probe
 * basis.  (This optimizes for the common case that arguments are either not
 * used or used in an untyped fashion.)  Typed arguments are specified with a
 * string of the type name in the dtragd_native member of the argument
 * description structure.  Typed arguments may be further translated to types
 * of greater stability; the provider indicates such a translated argument by
 * filling in the dtargd_xlate member with the string of the translated type.
 * Finally, the provider may indicate which argument value a given argument
 * maps to by setting the dtargd_mapping member -- allowing a single argument
 * to map to multiple args[X] variables.
 */
typedef struct dtrace_argdesc {
	dtrace_id_t dtargd_id;
	int dtargd_ndx;
	int dtargd_mapping;
	char dtargd_native[DTRACE_ARGTYPELEN];
	char dtargd_xlate[DTRACE_ARGTYPELEN];
} dtrace_argdesc_t;

#endif /* _LINUX_DTRACE_ARG_H */
