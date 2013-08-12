/*
 * FILE:	dtrace_actdesc.c
 * DESCRIPTION:	Dynamic Tracing: action description functions
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
 * Copyright 2010, 2011, 2012 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/slab.h>

#include "dtrace.h"

dtrace_actdesc_t *dtrace_actdesc_create(dtrace_actkind_t kind, uint32_t ntuple,
					uint64_t uarg, uint64_t arg)
{
	dtrace_actdesc_t	*act;

#ifdef FIXME
	ASSERT(!DTRACEACT_ISPRINTFLIKE(kind) ||
	       (arg != 0 && (uintptr_t)arg >= KERNELBASE) ||
	       (arg == 0 && kind == DTRACEACT_PRINTA));
#else
	ASSERT(!DTRACEACT_ISPRINTFLIKE(kind) ||
	       (arg != 0) ||
	       (arg == 0 && kind == DTRACEACT_PRINTA));
#endif

	act = vzalloc(sizeof (dtrace_actdesc_t));
	if (act == NULL)
		return NULL;

	act->dtad_kind = kind;
	act->dtad_ntuple = ntuple;
	act->dtad_uarg = uarg;
	act->dtad_arg = arg;
	act->dtad_refcnt = 1;

	return act;
}

void dtrace_actdesc_hold(dtrace_actdesc_t *act)
{
	ASSERT(act->dtad_refcnt >= 1);

	act->dtad_refcnt++;
}

void dtrace_actdesc_release(dtrace_actdesc_t *act, dtrace_vstate_t *vstate)
{
	dtrace_actkind_t	kind = act->dtad_kind;
	dtrace_difo_t		*dp;

	ASSERT(act->dtad_refcnt >= 1);

	if (--act->dtad_refcnt != 0)
		return;

	if ((dp = act->dtad_difo) != NULL)
		dtrace_difo_release(dp, vstate);

	if (DTRACEACT_ISPRINTFLIKE(kind)) {
		char	*str = (char *)(uintptr_t)act->dtad_arg;

#ifdef FIXME
		ASSERT((str != NULL && (uintptr_t)str >= KERNELBASE) ||
		       (str == NULL && act->dtad_kind == DTRACEACT_PRINTA));
#else
		ASSERT((str != NULL) ||
		       (str == NULL && act->dtad_kind == DTRACEACT_PRINTA));
#endif

		if (str != NULL)
			vfree(str);
	}

	vfree(act);
}
