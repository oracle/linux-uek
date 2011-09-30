/*
 * FILE:	dtrace_helper.c
 * DESCRIPTION:	Dynamic Tracing: helper functions
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
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dtrace.h"

static uint32_t	dtrace_helptrace_next = 0;
static uint32_t	dtrace_helptrace_nlocals;
static char	*dtrace_helptrace_buffer;
static int	dtrace_helptrace_bufsize = 512 * 1024;

#ifdef CONFIG_DT_DEBUG
static int	dtrace_helptrace_enabled = 1;
#else
static int	dtrace_helptrace_enabled = 0;
#endif

static void dtrace_helper_trace(dtrace_helper_action_t *helper,
				dtrace_mstate_t *mstate,
				dtrace_vstate_t *vstate, int where)
{
	uint32_t		size, next, nnext, i;
	dtrace_helptrace_t	*ent;
	uint16_t		flags = cpu_core[
					    smp_processor_id()
					].cpuc_dtrace_flags;

	if (!dtrace_helptrace_enabled)
		return;

	ASSERT(vstate->dtvs_nlocals <= dtrace_helptrace_nlocals);

	/*
	 * What would a tracing framework be without its own tracing
	 * framework?  (Well, a hell of a lot simpler, for starters...)
	 */
	size = sizeof(dtrace_helptrace_t) + dtrace_helptrace_nlocals *
	       sizeof(uint64_t) - sizeof(uint64_t);

	/*
	 * Iterate until we can allocate a slot in the trace buffer.
	 */
	do {
		next = dtrace_helptrace_next;

		if (next + size < dtrace_helptrace_bufsize)
			nnext = next + size;
		else
			nnext = size;
	} while (cmpxchg(&dtrace_helptrace_next, next, nnext) != next);

	/*
	 * We have our slot; fill it in.
	*/
	if (nnext == size)
		next = 0;

	ent = (dtrace_helptrace_t *)&dtrace_helptrace_buffer[next];
	ent->dtht_helper = helper;
	ent->dtht_where = where;
	ent->dtht_nlocals = vstate->dtvs_nlocals;

	ent->dtht_fltoffs = (mstate->dtms_present & DTRACE_MSTATE_FLTOFFS)
				?  mstate->dtms_fltoffs
				: -1;
	ent->dtht_fault = DTRACE_FLAGS2FLT(flags);
	ent->dtht_illval = cpu_core[smp_processor_id()].cpuc_dtrace_illval;

	for (i = 0; i < vstate->dtvs_nlocals; i++) {
		dtrace_statvar_t	*svar;

		if ((svar = vstate->dtvs_locals[i]) == NULL)
			continue;

		ASSERT(svar->dtsv_size >= NR_CPUS * sizeof(uint64_t));
		ent->dtht_locals[i] =
			((uint64_t *)(uintptr_t)svar->dtsv_data)[
							smp_processor_id()];
	}
}

uint64_t dtrace_helper(int which, dtrace_mstate_t *mstate,
		       dtrace_state_t *state, uint64_t arg0, uint64_t arg1)
{
	uint16_t		*flags = &cpu_core[
						smp_processor_id()
					  ].cpuc_dtrace_flags;
	uint64_t		sarg0 = mstate->dtms_arg[0];
	uint64_t		sarg1 = mstate->dtms_arg[1];
	uint64_t		rval = 0;
	dtrace_helpers_t	*helpers = current->dtrace_helpers;
	dtrace_helper_action_t	*helper;
	dtrace_vstate_t		*vstate;
	dtrace_difo_t		*pred;
	int			i, trace = dtrace_helptrace_enabled;

	ASSERT(which >= 0 && which < DTRACE_NHELPER_ACTIONS);

	if (helpers == NULL)
		return 0;

	if ((helper = helpers->dthps_actions[which]) == NULL)
		return 0;

	vstate = &helpers->dthps_vstate;
	mstate->dtms_arg[0] = arg0;
	mstate->dtms_arg[1] = arg1;

	/*
	 * Now iterate over each helper.  If its predicate evaluates to 'true',
	 * we'll call the corresponding actions.  Note that the below calls
	 * to dtrace_dif_emulate() may set faults in machine state.  This is
	 * okay:  our caller (the outer dtrace_dif_emulate()) will simply plow
	 * the stored DIF offset with its own (which is the desired behavior).
	 * Also, note the calls to dtrace_dif_emulate() may allocate scratch
	 * from machine state; this is okay, too.
	 */
	for (; helper != NULL; helper = helper->dtha_next) {
		if ((pred = helper->dtha_predicate) != NULL) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate, 0);

			if (!dtrace_dif_emulate(pred, mstate, vstate, state))
				goto next;

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

		for (i = 0; i < helper->dtha_nactions; i++) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate,
						    i + 1);

			rval = dtrace_dif_emulate(helper->dtha_actions[i],
						  mstate, vstate, state);

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

next:
		if (trace)
			dtrace_helper_trace(helper, mstate, vstate,
					    DTRACE_HELPTRACE_NEXT);
	}

	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
				    DTRACE_HELPTRACE_DONE);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return rval;

err:
	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
				    DTRACE_HELPTRACE_ERR);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return 0;
}
