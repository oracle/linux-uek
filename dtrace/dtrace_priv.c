/*
 * FILE:	dtrace_priv.c
 * DESCRIPTION:	Dynamic Tracing: privilege check functions
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

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the user credentials of the process that enabled the
 * invoking ECB match the target credentials
 */
int dtrace_priv_proc_common_user(dtrace_state_t *state)
{
	const cred_t	*cr, *s_cr = state->dts_cred.dcr_cred;

	/*
	 * We should always have a non-NULL state cred here, since if cred
	 * is null (anonymous tracing), we fast-path bypass this routine.
	 */
	ASSERT(s_cr != NULL);

	if ((cr = current_cred()) != NULL &&
	    s_cr->euid == cr->euid &&
	    s_cr->euid == cr->uid &&
	    s_cr->euid == cr->suid &&
	    s_cr->egid == cr->egid &&
	    s_cr->egid == cr->gid &&
	    s_cr->egid == cr->sgid)
		return 1;

	return 0;
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the process has not setuid or changed credentials.
 */
int dtrace_priv_proc_common_nocd(void)
{
#ifdef FIXME
	proc_t	*proc;

	if ((proc = ttoproc(curthread)) != NULL && !(proc->p_flag & SNOCD))
		return 1;
#endif

	return 0;
}

int dtrace_priv_proc_destructive(dtrace_state_t *state)
{
	int	action = state->dts_cred.dcr_action;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER) == 0) &&
	    dtrace_priv_proc_common_user(state) == 0)
		goto bad;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG) == 0) &&
	    dtrace_priv_proc_common_nocd() == 0)
		goto bad;

	return 1;

bad:
	DTRACE_CPUFLAG_SET(CPU_DTRACE_UPRIV);
   
	return 0;
}

int dtrace_priv_proc_control(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC_CONTROL)
		return 1;

	if (dtrace_priv_proc_common_user(state) &&
	    dtrace_priv_proc_common_nocd())
		return 1;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_UPRIV);

	return 0;
}

int dtrace_priv_proc(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC)
		return 1;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_UPRIV);

	return 0;
}

int dtrace_priv_kernel(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_KERNEL)
		return 1;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_KPRIV);

	return 0;
}
