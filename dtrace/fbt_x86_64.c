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
 * Copyright 2010-2014 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace_fbt.h>
#include <asm/dtrace_util.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

#define FBT_PATCHVAL		0xf0

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
	fbp->fbp_patchval = FBT_PATCHVAL;
	fbp->fbp_savedval = *fbp->fbp_patchpoint;
	fbp->fbp_rval = type == FBT_ENTRY ? DTRACE_INVOP_PUSH_BP
					  : DTRACE_INVOP_RET;
}

void fbt_enable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_invop_enable((uint8_t *)fbp->fbp_patchpoint);
}

void fbt_disable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	dtrace_invop_disable((uint8_t *)fbp->fbp_patchpoint,
			     fbp->fbp_savedval);
}

int fbt_dev_init_arch(void)
{
	return dtrace_invop_add(fbt_invop);
}

void fbt_dev_exit_arch(void)
{
	dtrace_invop_remove(fbt_invop);
}
