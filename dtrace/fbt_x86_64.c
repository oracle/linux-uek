/*
 * FILE:	fbt_x86_64.c
 * DESCRIPTION:	Function Boundary Tracing: architecture-specific implementation
 *
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
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/dtrace_fbt.h>
#include <linux/vmalloc.h>
#include <asm/dtrace_util.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

/*
 * Use 0xf0 (LOCK Prefix) and X86_TRAP_UD for Invalid Opcode traps to be used.
 * Use 0xcc (INT 3) and X86_TRAP_BP for Breakpoint traps to be used.
 */
#define FBT_ENTRY_PATCHVAL		0xcc
#define FBT_RETURN_PATCHVAL		0xcc

static uint8_t fbt_invop(struct pt_regs *regs)
{
	fbt_probe_t	*fbp = fbt_probetab[FBT_ADDR2NDX(regs->ip)];

	for (; fbp != NULL; fbp = fbp->fbp_hashnext) {
		if ((uintptr_t)fbp->fbp_patchpoint == regs->ip) {
			this_cpu_core->cpu_dtrace_regs = regs;
			if (fbp->fbp_roffset == 0) {
				dtrace_probe(fbp->fbp_id, regs->di, regs->si,
					     regs->dx, regs->cx, regs->r8);
			} else {
				dtrace_probe(fbp->fbp_id, fbp->fbp_roffset,
					     regs->ax, 0, 0, 0);
			}

			this_cpu_core->cpu_dtrace_regs = NULL;

			return fbp->fbp_rval;
		}
	}

	return 0;
}

void fbt_provide_probe_arch(fbt_probe_t *fbp, int type, int stype)
{
	fbp->fbp_patchval = type == FBT_ENTRY ? FBT_ENTRY_PATCHVAL
					      : FBT_RETURN_PATCHVAL;
	fbp->fbp_savedval = *fbp->fbp_patchpoint;
	fbp->fbp_rval = type == FBT_ENTRY ? DTRACE_INVOP_PUSH_BP
					  : DTRACE_INVOP_RET;
}

int fbt_can_patch_return_arch(asm_instr_t *addr)
{
	return 1;
}

int fbt_provide_module_arch(void *arg, struct module *mp)
{
	return 1;
}

void fbt_destroy_module(void *arg, struct module *mp)
{
}

void fbt_enable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_invop_enable(fbp->fbp_patchpoint, fbp->fbp_patchval);
}

void fbt_disable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_invop_disable(fbp->fbp_patchpoint, fbp->fbp_savedval);
}

int fbt_dev_init_arch(void)
{
	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab = dtrace_vzalloc_try(fbt_probetab_size *
					  sizeof (fbt_probe_t *));

	if (fbt_probetab == NULL)
		return -ENOMEM;

	return dtrace_invop_add(fbt_invop);
}

void fbt_dev_exit_arch(void)
{
	vfree(fbt_probetab);
	fbt_probetab_mask = 0;
	fbt_probetab_size = 0;

	dtrace_invop_remove(fbt_invop);
}
