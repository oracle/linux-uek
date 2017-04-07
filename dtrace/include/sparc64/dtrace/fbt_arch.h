#ifndef _SPARC64_FBT_ARCH_H
#define _SPARC64_FBT_ARCH_H

/*
 * Function Boundary Tracing Implementation defines
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
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#define FBT_AFRAMES	1

typedef struct fbt_probe {
        char			*fbp_name;	/* name of probe */
        dtrace_id_t		fbp_id;		/* probe ID */
        struct module		*fbp_module;	/* defining module */
        int			fbp_loadcnt;	/* load count for module */
        int			fbp_primary;	/* non-zero if primary mod */
        asm_instr_t		*fbp_patchpoint;/* patch point */
        asm_instr_t		fbp_patchval;	/* instruction to patch */
        asm_instr_t		fbp_savedval;	/* saved instruction value */
	uint64_t		fbp_roffset;	/* relative offset */
        int			fbp_rval;
        struct fbt_probe	*fbp_next;	/* next probe */
        struct fbt_probe	*fbp_hashnext;	/* next on hash */
	int			fbp_isret;
	asm_instr_t		*fbp_trampdest;
} fbt_probe_t;

#endif /* _SPARC64_FBT_ARCH_H */
