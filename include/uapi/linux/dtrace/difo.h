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

#ifndef _LINUX_DTRACE_DIFO_H
#define _LINUX_DTRACE_DIFO_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/dif.h>
#include <linux/dtrace/dof_defines.h>

/*
 * A DIFO is used to store the compiled DIF for a D expression, its return
 * type, and its string and variable tables.  The string table is a single
 * buffer of character data into which sets instructions and variable
 * references can reference strings using a byte offset.  The variable table
 * is an array of dtrace_difv_t structures that describe the name and type of
 * each variable and the id used in the DIF code.  This structure is described
 * above in the DIF section of this header file.  The DIFO is used at both
 * user-level (in the library) and in the kernel, but the structure is never
 * passed between the two: the DOF structures form the only interface.  As a
 * result, the definition can change depending on the presence of _KERNEL.
 */

typedef struct dtrace_difo {
	dif_instr_t *dtdo_buf;			/* instruction buffer */
	uint64_t *dtdo_inttab;			/* integer table (optional) */
	char *dtdo_strtab;			/* string table (optional) */
	dtrace_difv_t *dtdo_vartab;		/* variable table (optional) */
	uint_t dtdo_len;			/* length of instruction buffer */
	uint_t dtdo_intlen;			/* length of integer table */
	uint_t dtdo_strlen;			/* length of string table */
	uint_t dtdo_varlen;			/* length of variable table */
	dtrace_diftype_t dtdo_rtype;		/* return type */
	uint_t dtdo_refcnt;			/* owner reference count */
	uint_t dtdo_destructive;		/* invokes destructive subroutines */
#ifndef _KERNEL
	dtrace_diftype_t orig_dtdo_rtype;	/* orignal return type */
	struct dof_relodesc *dtdo_kreltab;	/* kernel relocations */
	struct dof_relodesc *dtdo_ureltab;	/* user relocations */
	struct dt_node **dtdo_xlmtab;		/* translator references */
	uint_t dtdo_krelen;			/* length of krelo table */
	uint_t dtdo_urelen;			/* length of urelo table */
	uint_t dtdo_xlmlen;			/* length of translator table */
#endif
} dtrace_difo_t;

#endif /* _LINUX_DTRACE_DIFO_H */
