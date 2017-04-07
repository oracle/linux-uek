/*
 * FILE:	sdt_dev.c
 * DESCRIPTION:	Statically Defined Tracing: device file handling
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
 * Copyright 2010-2016 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/dtrace_util.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

#define SDT_PATCHVAL		0xf0

static uint8_t sdt_invop(struct pt_regs *regs)
{
	sdt_probe_t	*sdt = sdt_probetab[SDT_ADDR2NDX(regs->ip)];

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint == regs->ip) {
			if (sdt->sdp_ptype == SDTPT_IS_ENABLED)
				regs->ax = 1;
			else {
				this_cpu_core->cpu_dtrace_regs = regs;

				dtrace_probe(sdt->sdp_id, regs->di, regs->si,
					     regs->dx, regs->cx, regs->r8);

				this_cpu_core->cpu_dtrace_regs = NULL;
			}

			return DTRACE_INVOP_NOPS;
		}
	}

	return 0;
}

void sdt_provide_probe_arch(sdt_probe_t *sdp, struct module *mp, int idx)
{
	sdp->sdp_patchval = SDT_PATCHVAL;
	sdp->sdp_savedval = *sdp->sdp_patchpoint;
}

int sdt_provide_module_arch(void *arg, struct module *mp)
{
	return 1;
}

void sdt_destroy_module(void *arg, struct module *mp)
{
}

void sdt_enable_arch(sdt_probe_t *sdp, dtrace_id_t id, void *arg)
{
	dtrace_invop_enable(sdp->sdp_patchpoint, sdp->sdp_patchval);
}

void sdt_disable_arch(sdt_probe_t *sdp, dtrace_id_t id, void *arg)
{
	dtrace_invop_disable(sdp->sdp_patchpoint, sdp->sdp_savedval);
}

uint64_t sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		    int aframes)
{
	struct pt_regs  *regs = this_cpu_core->cpu_dtrace_regs;
	uint64_t	*st;
	uint64_t	val;

	if (regs == NULL)
		return 0;

	switch (argno) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->cx;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	}

	ASSERT(argno > 5);

	st = (uint64_t *)regs->sp;
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	__copy_from_user_inatomic_nocache(&val, (void *)&st[argno - 6],
					  sizeof(st[0]));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return val;
}

int sdt_dev_init_arch(void)
{
	return dtrace_invop_add(sdt_invop);
}

void sdt_dev_exit_arch(void)
{
	dtrace_invop_remove(sdt_invop);
}
