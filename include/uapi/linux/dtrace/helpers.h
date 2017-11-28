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

#ifndef _LINUX_DTRACE_HELPERS_H
#define _LINUX_DTRACE_HELPERS_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/helpers_defines.h>

/*
 * DTrace Helpers
 *
 * In general, DTrace establishes probes in processes and takes actions on
 * processes without knowing their specific user-level structures.  Instead of
 * existing in the framework, process-specific knowledge is contained by the
 * enabling D program -- which can apply process-specific knowledge by making
 * appropriate use of DTrace primitives like copyin() and copyinstr() to
 * operate on user-level data.  However, there may exist some specific probes
 * of particular semantic relevance that the application developer may wish to
 * explicitly export.  For example, an application may wish to export a probe
 * at the point that it begins and ends certain well-defined transactions.  In
 * addition to providing probes, programs may wish to offer assistance for
 * certain actions.  For example, in highly dynamic environments (e.g., Java),
 * it may be difficult to obtain a stack trace in terms of meaningful symbol
 * names (the translation from instruction addresses to corresponding symbol
 * names may only be possible in situ); these environments may wish to define
 * a series of actions to be applied in situ to obtain a meaningful stack
 * trace.
 *
 * These two mechanisms -- user-level statically defined tracing and assisting
 * DTrace actions -- are provided via DTrace _helpers_.  Helpers are specified
 * via DOF, but unlike enabling DOF, helper DOF may contain definitions of
 * providers, probes and their arguments.  If a helper wishes to provide
 * action assistance, probe descriptions and corresponding DIF actions may be
 * specified in the helper DOF.  For such helper actions, however, the probe
 * description describes the specific helper:  all DTrace helpers have the
 * provider name "dtrace" and the module name "helper", and the name of the
 * helper is contained in the function name (for example, the ustack() helper
 * is named "ustack").  Any helper-specific name may be contained in the name
 * (for example, if a helper were to have a constructor, it might be named
 * "dtrace:helper:<helper>:init").  Helper actions are only called when the
 * action that they are helping is taken.  Helper actions may only return DIF
 * expressions, and may only call the following subroutines:
 *
 *    alloca()      <= Allocates memory out of the consumer's scratch space
 *    bcopy()       <= Copies memory to scratch space
 *    copyin()      <= Copies memory from user-level into consumer's scratch
 *    copyinto()    <= Copies memory into a specific location in scratch
 *    copyinstr()   <= Copies a string into a specific location in scratch
 *
 * Helper actions may only access the following built-in variables:
 *
 *    curthread     <= Current kthread_t pointer
 *    tid           <= Current thread identifier
 *    pid           <= Current process identifier
 *    ppid          <= Parent process identifier
 *    uid           <= Current user ID
 *    gid           <= Current group ID
 *    execname      <= Current executable name
 *    zonename      <= Current zone name
 *
 * Helper actions may not manipulate or allocate dynamic variables, but they
 * may have clause-local and statically-allocated global variables.  The
 * helper action variable state is specific to the helper action -- variables
 * used by the helper action may not be accessed outside of the helper
 * action, and the helper action may not access variables that like outside
 * of it.  Helper actions may not load from kernel memory at-large; they are
 * restricting to loading current user state (via copyin() and variants) and
 * scratch space.  As with probe enablings, helper actions are executed in
 * program order.  The result of the helper action is the result of the last
 * executing helper expression.
 *
 * Helpers -- composed of either providers/probes or probes/actions (or both)
 * -- are added by opening the "helper" minor node, and issuing an ioctl(2)
 * (DTRACEHIOC_ADDDOF) that specifies the dof_helper_t structure. This
 * encapsulates the name and base address of the user-level library or
 * executable publishing the helpers and probes as well as the DOF that
 * contains the definitions of those helpers and probes.
 *
 * The DTRACEHIOC_ADD and DTRACEHIOC_REMOVE are left in place for legacy
 * helpers and should no longer be used.  No other ioctls are valid on the
 * helper minor node.
 */

typedef struct dof_helper {
	char dofhp_mod[DTRACE_MODNAMELEN];	/* executable or library name */
	uint64_t dofhp_addr;			/* base address of object */
	uint64_t dofhp_dof;			/* address of helper DOF */
} dof_helper_t;

#endif /* _LINUX_DTRACE_HELPERS_H */
