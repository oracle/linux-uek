#ifndef _LINUX_DTRACE_ENABLING_H
#define _LINUX_DTRACE_ENABLING_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Enabling Description Structures
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
#include <linux/dtrace/difo_defines.h>
#include <linux/dtrace/enabling_defines.h>

/*
 * When DTrace is tracking the description of a DTrace enabling entity (probe,
 * predicate, action, ECB, record, etc.), it does so in a description
 * structure.  These structures all end in "desc", and are used at both
 * user-level and in the kernel -- but (with the exception of
 * dtrace_probedesc_t) they are never passed between them.  Typically,
 * user-level will use the description structures when assembling an enabling.
 * It will then distill those description structures into a DOF object (see
 * above), and send it into the kernel.  The kernel will again use the
 * description structures to create a description of the enabling as it reads
 * the DOF.  When the description is complete, the enabling will be actually
 * created -- turning it into the structures that represent the enabling
 * instead of merely describing it.  Not surprisingly, the description
 * structures bear a strong resemblance to the DOF structures that act as their
 * conduit.
 */

struct dtrace_predicate;

typedef struct dtrace_probedesc {
	dtrace_id_t dtpd_id;			/* probe identifier */
	char dtpd_provider[DTRACE_PROVNAMELEN]; /* probe provider name */
	char dtpd_mod[DTRACE_MODNAMELEN];	/* probe module name */
	char dtpd_func[DTRACE_FUNCNAMELEN];	/* probe function name */
	char dtpd_name[DTRACE_NAMELEN];		/* probe name */
} dtrace_probedesc_t;

typedef struct dtrace_repldesc {
	dtrace_probedesc_t dtrpd_match;		/* probe descr. to match */
	dtrace_probedesc_t dtrpd_create;	/* probe descr. to create */
} dtrace_repldesc_t;

typedef struct dtrace_preddesc {
	struct dtrace_difo *dtpdd_difo;		/* pointer to DIF object */
	struct dtrace_predicate *dtpdd_predicate; /* pointer to predicate */
} dtrace_preddesc_t;

typedef struct dtrace_actdesc {
	struct dtrace_difo *dtad_difo;		/* pointer to DIF object */
	struct dtrace_actdesc *dtad_next;	/* next action */
	dtrace_actkind_t dtad_kind;		/* kind of action */
	uint32_t dtad_ntuple;			/* number in tuple */
	uint64_t dtad_arg;			/* action argument */
	uint64_t dtad_uarg;			/* user argument */
	int dtad_refcnt;			/* reference count */
} dtrace_actdesc_t;

typedef struct dtrace_ecbdesc {
	dtrace_actdesc_t *dted_action;		/* action description(s) */
	dtrace_preddesc_t dted_pred;		/* predicate description */
	dtrace_probedesc_t dted_probe;		/* probe description */
	uint64_t dted_uarg;			/* library argument */
	int dted_refcnt;			/* reference count */
} dtrace_ecbdesc_t;

#endif /* _LINUX_DTRACE_ENABLING_H */
