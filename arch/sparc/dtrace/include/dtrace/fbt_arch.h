/*
 * Dynamic Tracing for Linux - FBT Implementation defines
 *
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _SPARC64_FBT_ARCH_H
#define _SPARC64_FBT_ARCH_H

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
