/*
 * FILE:	dtrace_priv.c
 * DESCRIPTION:	DTrace - privilege support implementation
 *
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/dtrace_cpu.h>

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
	    uid_eq(s_cr->euid, cr->euid) &&
	    uid_eq(s_cr->euid, cr->uid) &&
	    uid_eq(s_cr->euid, cr->suid) &&
	    gid_eq(s_cr->egid, cr->egid) &&
	    gid_eq(s_cr->egid, cr->gid) &&
	    gid_eq(s_cr->egid, cr->sgid))
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
