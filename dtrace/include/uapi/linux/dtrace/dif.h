#ifndef _LINUX_DTRACE_DIF_H
#define _LINUX_DTRACE_DIF_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Intermediate Format (DIF)
 * 
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2009 -- 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace/universal.h>
#include <linux/dtrace/dif_defines.h>

/*
 * The following definitions describe the DTrace Intermediate Format (DIF), a a
 * RISC-like instruction set and program encoding used to represent predicates
 * and actions that can be bound to DTrace probes.  The constants below defining
 * the number of available registers are suggested minimums; the compiler should
 * use DTRACEIOC_CONF to dynamically obtain the number of registers provided by
 * the current DTrace implementation.
 */

/*
 * A DTrace Intermediate Format Type (DIF Type) is used to represent the types
 * of variables, function and associative array arguments, and the return type
 * for each DIF object (shown below).  It contains a description of the type,
 * its size in bytes, and a module identifier.
 */

typedef struct dtrace_diftype {
	uint8_t dtdt_kind;
	uint8_t dtdt_ckind;
	uint8_t dtdt_flags;
	uint8_t dtdt_pad;
	uint32_t dtdt_size;
} dtrace_diftype_t;

/*
 * A DTrace Intermediate Format variable record is used to describe each of the
 * variables referenced by a given DIF object.  It contains an integer variable
 * identifier along with variable scope and properties, as shown below.  The
 * size of this structure must be sizeof (int) aligned.
 */

typedef struct dtrace_difv {
	uint32_t dtdv_name;
	uint32_t dtdv_id;
	uint8_t dtdv_kind;
	uint8_t dtdv_scope;
	uint16_t dtdv_flags;
	dtrace_diftype_t dtdv_type;
} dtrace_difv_t;

#endif /* _LINUX_DTRACE_DIF_H */
