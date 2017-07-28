/*
 * FILE:	dtrace_probe.c
 * DESCRIPTION:	DTrace - probe implementation
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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
#include <linux/hardirq.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/cmpxchg.h>
#include <linux/sched/signal.h>

#include "dtrace.h"

ktime_t				dtrace_chill_interval =
					KTIME_INIT(1, 0);
ktime_t				dtrace_chill_max =
					KTIME_INIT(0,
						   500 * (NANOSEC / MILLISEC));

dtrace_genid_t			dtrace_probegen;
struct kmem_cache		*dtrace_probe_cachep;

static struct idr		dtrace_probe_idr;

static struct task_struct	*dtrace_panicked;

/*
 * Create a new probe.
 */
dtrace_id_t dtrace_probe_create(dtrace_provider_id_t prov, const char *mod,
				const char *func, const char *name,
				int aframes, void *arg)
{
	dtrace_probe_t		*probe;
	dtrace_provider_t	*provider = (dtrace_provider_t *)prov;
	dtrace_id_t		id;

	probe = kmem_cache_alloc(dtrace_probe_cachep, __GFP_NOFAIL);

	/*
	 * The idr_preload() should be called without holding locks as it may
	 * block.  At the same time it is required to protect DTrace structures.
	 * We can't drop it before idr_preload() and acquire after it because
	 * we can't sleep in atomic context (until we reach idr_preload_end()).
	 *
	 * It is better to delay DTrace framework than traced host so the lock
	 * is being held for the duration of idr allocation.
	 *
	 * When the provider is the DTrace core itself, dtrace_lock will be
	 * held when we enter this function.
	 */
	if (provider == dtrace_provider) {
		ASSERT(MUTEX_HELD(&dtrace_lock));
	} else {
		mutex_lock(&dtrace_lock);
	}

	idr_preload(GFP_KERNEL);
	id = idr_alloc_cyclic(&dtrace_probe_idr, probe, 0, 0, GFP_NOWAIT);
	idr_preload_end();
	if (id < 0) {
		/* FIXME: Need to handle failure */
	}

	probe->dtpr_id = id;
	probe->dtpr_ecb = NULL;
	probe->dtpr_ecb_last = NULL;
	probe->dtpr_arg = arg;
	probe->dtpr_predcache = DTRACE_CACHEIDNONE;
	probe->dtpr_aframes = aframes;
	probe->dtpr_provider = provider;
	probe->dtpr_mod = dtrace_strdup(mod);
	probe->dtpr_func = dtrace_strdup(func);
	probe->dtpr_name = dtrace_strdup(name);
	probe->dtpr_nextmod = probe->dtpr_prevmod = NULL;
	probe->dtpr_nextfunc = probe->dtpr_prevfunc = NULL;
	probe->dtpr_nextname = probe->dtpr_prevname = NULL;
	probe->dtpr_gen = dtrace_probegen++;

	dtrace_hash_add(dtrace_bymod, probe);
	dtrace_hash_add(dtrace_byfunc, probe);
	dtrace_hash_add(dtrace_byname, probe);

	if (provider != dtrace_provider)
		mutex_unlock(&dtrace_lock);

	return id;
}
EXPORT_SYMBOL(dtrace_probe_create);

int dtrace_probe_enable(const dtrace_probedesc_t *desc, dtrace_enabling_t *enab)
{
	dtrace_probekey_t	pkey;
	uint32_t		priv;
	kuid_t			uid;

	dtrace_ecb_create_cache = NULL;

	if (desc == NULL) {
		(void) dtrace_ecb_create_enable(NULL, enab);

		return 0;
	}

	dtrace_probekey(desc, &pkey);
	dtrace_cred2priv(enab->dten_vstate->dtvs_state->dts_cred.dcr_cred,
			 &priv, &uid);

	return dtrace_match(&pkey, priv, uid, dtrace_ecb_create_enable, enab);
}

/*
 * Return the probe argument associated with the specified probe.
 */
void *dtrace_probe_arg(dtrace_provider_id_t id, dtrace_id_t pid)
{
	dtrace_probe_t	*probe;
	void		*rval = NULL;

	mutex_lock(&dtrace_lock);

	if ((probe = dtrace_probe_lookup_id(pid)) != NULL &&
	    probe->dtpr_provider == (dtrace_provider_t *)id)
		rval = probe->dtpr_arg;

	mutex_unlock(&dtrace_lock);

	return rval;
}
EXPORT_SYMBOL(dtrace_probe_arg);

/*
 * Copy a probe into a probe description.
 */
void dtrace_probe_description(const dtrace_probe_t *prp,
			      dtrace_probedesc_t *pdp)
{
	memset(pdp, 0, sizeof(dtrace_probedesc_t));
	pdp->dtpd_id = prp->dtpr_id;

	strncpy(pdp->dtpd_provider, prp->dtpr_provider->dtpv_name,
		DTRACE_PROVNAMELEN - 1);

	strncpy(pdp->dtpd_mod, prp->dtpr_mod, DTRACE_MODNAMELEN - 1);
	strncpy(pdp->dtpd_func, prp->dtpr_func, DTRACE_FUNCNAMELEN - 1);
	strncpy(pdp->dtpd_name, prp->dtpr_name, DTRACE_NAMELEN - 1);
}

void dtrace_probe_provide(dtrace_probedesc_t *desc, dtrace_provider_t *prv)
{
	int		all = 0;

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}

	do {
		prv->dtpv_pops.dtps_provide(prv->dtpv_arg, desc);
		dtrace_for_each_module(prv->dtpv_pops.dtps_provide_module, prv->dtpv_arg);
	} while (all && (prv = prv->dtpv_next) != NULL);
}

/*
 * Atomically increment a specified error counter from probe context.
 */
static void dtrace_error(uint32_t *counter)
{
	/*
	 * Most counters stored to in probe context are per-CPU counters.
	 * However, there are some error conditions that are sufficiently
	 * arcane that they don't merit per-CPU storage.  If these counters
	 * are incremented concurrently on different CPUs, scalability will be
	 * adversely affected -- but we don't expect them to be white-hot in a
	 * correctly constructed enabling...
	 */
	uint32_t	oval, nval;

	do {
		oval = *counter;

		if ((nval = oval + 1) == 0) {
			/*
			 * If the counter would wrap, set it to 1 -- assuring
			 * that the counter is never zero when we have seen
			 * errors.  (The counter must be 32-bits because we
			 * aren't guaranteed a 64-bit compare&swap operation.)
			 * To save this code both the infamy of being fingered
			 * by a priggish news story and the indignity of being
			 * the target of a neo-puritan witch trial, we're
			 * carefully avoiding any colorful description of the
			 * likelihood of this condition -- but suffice it to
			 * say that it is only slightly more likely than the
			 * overflow of predicate cache IDs, as discussed in
			 * dtrace_predicate_create().
			 */
			nval = 1;
		}
	} while (cmpxchg(counter, oval, nval) != oval);
}

static int dtrace_priv_kernel_destructive(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_KERNEL_DESTRUCTIVE)
		return 1;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_KPRIV);

	return 0;
}

static void dtrace_action_breakpoint(dtrace_ecb_t *ecb)
{
	dtrace_probe_t		*probe = ecb->dte_probe;
	dtrace_provider_t	*prov = probe->dtpr_provider;
	char			c[DTRACE_FULLNAMELEN + 80], *str;
	char			*msg = "dtrace: breakpoint action at probe ";
	char			*ecbmsg = " (ecb ";
	uintptr_t		mask = (0xf << (sizeof(uintptr_t) * NBBY / 4));
	uintptr_t		val = (uintptr_t)ecb;
	int			shift = (sizeof(uintptr_t) * NBBY) - 4, i = 0;

	if (dtrace_destructive_disallow)
		return;

	/*
	 * It's impossible to be taking action on the NULL probe.
	 */
	ASSERT(probe != NULL);

	/*
	 * This is a poor man's (destitute man's?) sprintf():  we want to
	 * print the provider name, module name, function name and name of
	 * the probe, along with the hex address of the ECB with the breakpoint
	 * action -- all of which we must place in the character buffer by
	 * hand.
	 */
	while (*msg != '\0')
		c[i++] = *msg++;

	for (str = prov->dtpv_name; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_mod; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_func; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_name; *str != '\0'; str++)
		c[i++] = *str;

	while (*ecbmsg != '\0')
		c[i++] = *ecbmsg++;

	while (shift >= 0) {
		mask = (uintptr_t)0xf << shift;

		if (val >= ((uintptr_t)1 << shift))
			c[i++] = "0123456789abcdef"[(val & mask) >> shift];

		shift -= 4;
	}

	c[i++] = ')';
	c[i] = '\0';

//	debug_enter(c); /* FIXME */
}

static void dtrace_action_panic(dtrace_ecb_t *ecb)
{
	dtrace_probe_t	*probe = ecb->dte_probe;

	/*
	 * It's impossible to be taking action on the NULL probe.
	 */
	ASSERT(probe != NULL);

	if (dtrace_destructive_disallow)
		return;

	if (dtrace_panicked != NULL)
		return;

	if (cmpxchg(&dtrace_panicked, NULL, current) != NULL)
		return;

	/*
	 * We won the right to panic.  (We want to be sure that only one
	 * thread calls panic() from dtrace_probe(), and that panic() is
	 * called exactly once.)
	 */
	dtrace_panic(KERN_EMERG
		     "dtrace: panic action at probe %s:%s:%s:%s (ecb %p)",
		     probe->dtpr_provider->dtpv_name, probe->dtpr_mod,
		     probe->dtpr_func, probe->dtpr_name, (void *)ecb);
}

static void dtrace_action_raise(uint64_t sig)
{
	if (dtrace_destructive_disallow)
		return;

	if (sig >= _NSIG) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return;
	}

	/*
	 * raise() has a queue depth of 1 -- we ignore all subsequent
	 * invocations of the raise() action.
	 */
	if (current->dtrace_sig == 0)
		current->dtrace_sig = (uint8_t)sig;
}

static void dtrace_action_stop(void)
{
	if (dtrace_destructive_disallow)
		return;

	if (!current->dtrace_stop) {
		current->dtrace_stop = 1;
//		current->sig_check = 1; /* FIXME */
//		aston(current);		/* FIXME */
	}
}

static void dtrace_action_chill(dtrace_mstate_t *mstate, ktime_t val)
{
	if (dtrace_destructive_disallow)
		return;

	dtrace_chill(val, dtrace_chill_interval, dtrace_chill_max);

	mstate->dtms_present &= ~DTRACE_MSTATE_TIMESTAMP;
}

static void dtrace_action_ustack(dtrace_mstate_t *mstate,
				 dtrace_state_t *state, uint64_t *buf,
				 uint64_t arg)
{
	int		nframes = DTRACE_USTACK_NFRAMES(arg);
	int		strsize = DTRACE_USTACK_STRSIZE(arg);
	uint64_t	*pcs = &buf[2], *fps;
	char		*str = (char *)&pcs[nframes];
	int		size, offs = 0, i, j;
	uintptr_t	old = mstate->dtms_scratch_ptr, saved;
	uint16_t	*flags = &this_cpu_core->cpuc_dtrace_flags;
	char		*sym;

	/*
	 * Should be taking a faster path if string space has not been
	 * allocated.
	 */
	ASSERT(strsize != 0);

	/*
	 * We will first allocate some temporary space for the frame pointers.
	 */
	fps = (uint64_t *)P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
	size = (uintptr_t)fps - mstate->dtms_scratch_ptr +
	       (nframes * sizeof (uint64_t));

	if (!DTRACE_INSCRATCH(mstate, size)) {
		/*
		 * Not enough room for our frame pointers -- need to indicate
		 * that we ran out of scratch space.
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return;
	}

	mstate->dtms_scratch_ptr += size;
	saved = mstate->dtms_scratch_ptr;

	/*
	 * Now get a stack with both program counters and frame pointers.
	 */
	dtrace_getufpstack(buf, fps, nframes + 2);

	/*
	 * If that faulted, we're cooked.
	 */
	if (*flags & CPU_DTRACE_FAULT)
		goto out;

	/*
	 * Now we want to walk up the stack, calling the USTACK helper.  For
	 * each iteration, we restore the scratch pointer.
	 */
	for (i = 0; i < nframes; i++) {
		mstate->dtms_scratch_ptr = saved;

		if (offs >= strsize)
			break;

		sym = (char *)(uintptr_t)dtrace_helper(
						DTRACE_HELPER_ACTION_USTACK,
						mstate, state, pcs[i], fps[i]);

		/*
		 * If we faulted while running the helper, we're going to
		 * clear the fault and null out the corresponding string.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			str[offs++] = '\0';
			continue;
		}

		if (sym == NULL) {
			str[offs++] = '\0';
			continue;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

		/*
		 * Now copy in the string that the helper returned to us.
		 */
		for (j = 0; offs + j < strsize; j++) {
			if ((str[offs + j] = sym[j]) == '\0')
			break;
		}

		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		offs += j + 1;
	}

	/*
	 * If we didn't have room for all of the strings, we don't abort
	 * processing -- this needn't be a fatal error -- but we still want
	 * to increment a counter (dts_stkstroverflows) to allow this condition
	 * to be warned about.  (If this is from a jstack() action, it is
	 * easily tuned via jstackstrsize.)
	 */
	if (offs >= strsize)
		dtrace_error(&state->dts_stkstroverflows);

	while (offs < strsize)
		str[offs++] = '\0';

out:
	mstate->dtms_scratch_ptr = old;
}

void dtrace_probe(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
		  uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
	processorid_t		cpuid;
	dtrace_icookie_t	cookie;
	dtrace_probe_t		*probe;
	dtrace_mstate_t		mstate;
	dtrace_ecb_t		*ecb;
	dtrace_action_t		*act;
	intptr_t		offs;
	size_t			size;
	int			onintr;
	volatile uint16_t	*flags;
	int			pflag = 0;
	uint32_t		re_entry;

#ifdef FIXME
	/*
	 * Kick out immediately if this CPU is still being born (in which case
	 * curthread will be set to -1) or the current thread can't allow
	 * probes in its current context.
	 */
	if (((uintptr_t)curthread & 1) || (curthread->t_flag & T_DONTDTRACE))
		return;
#endif

	DTRACE_SYNC_ENTER_CRITICAL(cookie, re_entry);

	/*
	 * If preemption has already been disabled before we get here, we
	 * accept it as a free gift.  We just need to make sure that we don't
	 * re-enable preemption on the way out...
	 */
	if ((pflag = dtrace_is_preemptive()))
		dtrace_preempt_off();

	probe = dtrace_probe_lookup_id(id);
	cpuid = smp_processor_id();
	onintr = in_interrupt();

	if (!onintr && probe->dtpr_predcache != DTRACE_CACHEIDNONE &&
	    probe->dtpr_predcache == current->predcache) {
		/*
		 * We have hit in the predicate cache; we know that
		 * this predicate would evaluate to be false.
		 */
		if (pflag)
			dtrace_preempt_on();
		DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry);
		return;
	}

	if (oops_in_progress) {
		/*
		 * We don't trace anything if we're panicking.
		 */
		if (pflag)
			dtrace_preempt_on();
		DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry);
		return;
	}

	flags = (volatile uint16_t *)&this_cpu_core->cpuc_dtrace_flags;

	/*
	 * Probe context is not re-entrant, unless we're getting called to
	 * process an ERROR probe.
	 */
	if ((*flags & CPU_DTRACE_PROBE_CTX) && id != dtrace_probeid_error) {
		dt_dbg_probe("Attempt to fire probe from within a probe " \
			     "(ID %d, CPoID %d, U %d, pflag %d)\n", id,
			     (int)this_cpu_core->cpu_dtrace_caller, cpuid,
			     pflag);
		if (pflag)
			dtrace_preempt_on();
		DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry);
		return;
	}

	*flags |= CPU_DTRACE_PROBE_CTX;
	this_cpu_core->cpu_dtrace_caller = id;

	if (id != dtrace_probeid_error)
		dtrace_vtime_suspend();

	mstate.dtms_difo = NULL;
	mstate.dtms_probe = probe;
	mstate.dtms_strtok = (uintptr_t)NULL;
	mstate.dtms_arg[0] = arg0;
	mstate.dtms_arg[1] = arg1;
	mstate.dtms_arg[2] = arg2;
	mstate.dtms_arg[3] = arg3;
	mstate.dtms_arg[4] = arg4;

	for (ecb = probe->dtpr_ecb; ecb != NULL; ecb = ecb->dte_next) {
		dtrace_predicate_t	*pred = ecb->dte_predicate;
		dtrace_state_t		*state = ecb->dte_state;
		dtrace_buffer_t		*buf = &state->dts_buffer[cpuid];
		dtrace_buffer_t		*aggbuf = &state->dts_aggbuffer[cpuid];
		dtrace_vstate_t		*vstate = &state->dts_vstate;
		dtrace_provider_t	*prov = probe->dtpr_provider;
		int			committed = 0;
		caddr_t			tomax;

		/*
		 * A little subtlety with the following (seemingly innocuous)
		 * declaration of the automatic 'val':  by looking at the
		 * code, you might think that it could be declared in the
		 * action processing loop, below.  (That is, it's only used in
		 * the action processing loop.)  However, it must be declared
		 * out of that scope because in the case of DIF expression
		 * arguments to aggregating actions, one iteration of the
		 * action loop will use the last iteration's value.
		 */
		uint64_t val = 0;

		mstate.dtms_present = DTRACE_MSTATE_ARGS | DTRACE_MSTATE_PROBE;
		*flags &= ~CPU_DTRACE_ERROR;

		if (prov == dtrace_provider) {
			/*
			 * If dtrace itself is the provider of this probe,
			 * we're only going to continue processing the ECB if
			 * arg0 (the dtrace_state_t) is equal to the ECB's
			 * creating state.  (This prevents disjoint consumers
			 * from seeing one another's metaprobes.)
			 */
			if (arg0 != (uint64_t)(uintptr_t)state)
				continue;
		}

		if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE) {
			/*
			 * We're not currently active.  If our provider isn't
			 * the dtrace pseudo provider, we're not interested.
			 */
			if (prov != dtrace_provider)
				continue;

			/*
			 * Now we must further check if we are in the BEGIN
			 * probe.  If we are, we will only continue orocessing
			 * if we're still in WARMUP -- if one BEGIN enabling
			 * has invoked the exit() action, we don't want to
			 * evaluate subsequent BEGIN enablings.
			 */
			if (probe->dtpr_id == dtrace_probeid_begin &&
			    state->dts_activity != DTRACE_ACTIVITY_WARMUP) {
				ASSERT(state->dts_activity ==
				       DTRACE_ACTIVITY_DRAINING);
				continue;
			}
		}

		dt_dbg_probe("Probe (ID %d EPID %d) on CPU %d...\n",
			     id, ecb->dte_epid, cpuid);
		if (ecb->dte_cond) {
			/*
			 * If the dte_cond bits indicate that this
			 * consumer is only allowed to see user-mode firings
			 * of this probe, call the provider's dtps_usermode()
			 * entry point to check that the probe was fired
			 * while in a user context. Skip this ECB if that's
			 * not the case.
			 */
			if ((ecb->dte_cond & DTRACE_COND_USERMODE) &&
			    prov->dtpv_pops.dtps_usermode(
				prov->dtpv_arg, probe->dtpr_id, probe->dtpr_arg
			    ) == 0) {
				dt_dbg_probe("Probe (ID %d EPID %d) Skipped\n",
					     id, ecb->dte_epid);
				continue;
			}

			/*
			 * This is more subtle than it looks. We have to be
			 * absolutely certain that current_cred() isn't going
			 * to change out from under us so it's only legit to
			 * examine that structure if we're in constrained
			 * situations. Currently, the only times we'll use this
			 * check is if a non-super-user has enabled the
			 * profile or syscall providers -- providers that
			 * allow visibility of all processes. For the
			 * profile case, the check above will ensure that
			 * we're examining a user context.
			 */
			if (ecb->dte_cond & DTRACE_COND_OWNER) {
				const cred_t	*cr;
				const cred_t	*s_cr =
					ecb->dte_state->dts_cred.dcr_cred;

				ASSERT(s_cr != NULL);

				if ((cr = current_cred()) == NULL ||
				    !uid_eq(s_cr->euid, cr->euid) ||
				    !uid_eq(s_cr->euid, cr->uid) ||
				    !uid_eq(s_cr->euid, cr->suid) ||
				    !gid_eq(s_cr->egid, cr->egid) ||
				    !gid_eq(s_cr->egid, cr->gid) ||
				    !gid_eq(s_cr->egid, cr->sgid)) {
					dt_dbg_probe("Probe (ID %d EPID %d) "
						     "Skipped\n",
						     id, ecb->dte_epid);
					continue;
				}
			}
		}

		if (ktime_gt(ktime_sub(current->dtrace_start, state->dts_alive),
			     dtrace_deadman_timeout)) {
			/*
			 * We seem to be dead.  Unless we (a) have kernel
			 * destructive permissions (b) have expicitly enabled
			 * destructive actions and (c) destructive actions have
			 * not been disabled, we're going to transition into
			 * the KILLED state, from which no further processing
			 * on this state will be performed.
			 */
			if (!dtrace_priv_kernel_destructive(state) ||
			    !state->dts_cred.dcr_destructive ||
			    dtrace_destructive_disallow) {
				dtrace_activity_t	*activity =
							&state->dts_activity;
				dtrace_activity_t	curr;

				do {
					curr = state->dts_activity;
				} while (cmpxchg(activity, curr,
					 DTRACE_ACTIVITY_KILLED) != curr);

				dt_dbg_probe("Probe (ID %d EPID %d) Skipped\n",
					     id, ecb->dte_epid);
				continue;
			}
		}

		if ((offs = dtrace_buffer_reserve(buf, ecb->dte_needed,
						  ecb->dte_alignment, state,
						  &mstate)) < 0) {
			dt_dbg_probe("Probe (ID %d EPID %d) Skipped\n",
				     id, ecb->dte_epid);
			continue;
		}

		tomax = buf->dtb_tomax;
		ASSERT(tomax != NULL);

		if (ecb->dte_size != 0) {
			DTRACE_STORE(uint32_t, tomax, offs, ecb->dte_epid);
			dt_dbg_buf("    Store: %p[%ld .. %ld] <- %d [EPID] "
				   "(from %s::%d)\n",
				   buf, offs, offs + sizeof(uint32_t) - 1,
				   ecb->dte_epid, __FUNCTION__, __LINE__);
		}

		mstate.dtms_epid = ecb->dte_epid;
		mstate.dtms_present |= DTRACE_MSTATE_EPID;

		if (state->dts_cred.dcr_visible & DTRACE_CRV_KERNEL)
			mstate.dtms_access = DTRACE_ACCESS_KERNEL;
		else
			mstate.dtms_access = 0;

		if (pred != NULL) {
			dtrace_difo_t	*dp = pred->dtp_difo;
			int		rval;

			dt_dbg_probe("  Evaluating predicate...\n");

			rval = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (!(*flags & CPU_DTRACE_ERROR) && !rval) {
				dtrace_cacheid_t	cid =
							probe->dtpr_predcache;

				if (cid != DTRACE_CACHEIDNONE && !onintr) {
					/*
					 * Update the predicate cache...
					 */
					ASSERT(cid == pred->dtp_cacheid);
					current->predcache = cid;
				}

				dt_dbg_probe("  Predicate not met (%d)\n",
					     rval);
				dt_dbg_probe("Probe (ID %d EPID %d) Done\n",
					     id, ecb->dte_epid);
				continue;
			}

			dt_dbg_probe("  Predicate met (%d)\n", rval);
		}

		for (act = ecb->dte_action;
		     !(*flags & CPU_DTRACE_ERROR) && act != NULL;
		     act = act->dta_next) {
			size_t			valoffs;
			dtrace_difo_t		*dp;
			dtrace_recdesc_t	*rec = &act->dta_rec;

			dt_dbg_probe("  Evaluating action %p (kind %d)...\n",
				    act, act->dta_kind);

			size = rec->dtrd_size;
			valoffs = offs + rec->dtrd_offset;

			if (DTRACEACT_ISAGG(act->dta_kind)) {
				uint64_t		v = 0xbad;
				dtrace_aggregation_t	*agg;

				agg = (dtrace_aggregation_t *)act;

				if ((dp = act->dta_difo) != NULL)
					v = dtrace_dif_emulate(dp, &mstate,
							       vstate, state);

				if (*flags & CPU_DTRACE_ERROR)
					continue;

				/*
				 * Note that we always pass the expression
				 * value from the previous iteration of the
				 * action loop.  This value will only be used
				 * if there is an expression argument to the
				 * aggregating action, denoted by the
				 * dtag_hasarg field.
				 */
				dtrace_aggregate(agg, buf, offs, aggbuf, v,
						 val);
				continue;
			}

			switch (act->dta_kind) {
			case DTRACEACT_STOP:
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_stop();
				continue;

			case DTRACEACT_BREAKPOINT:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_breakpoint(ecb);
				continue;

			case DTRACEACT_PANIC:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_panic(ecb);
				continue;

			case DTRACEACT_STACK:
				if (!dtrace_priv_kernel(state))
					continue;

				dtrace_getpcstack(
					(uint64_t *)(tomax + valoffs),
					size / sizeof(pc_t),
					probe->dtpr_aframes + 1,
					DTRACE_ANCHORED(probe)
						? NULL
						: (uint32_t *)arg0);

				continue;

			case DTRACEACT_JSTACK:
			case DTRACEACT_USTACK:
				if (!dtrace_priv_proc(state))
					continue;

				/*
				 * See comment in DIF_VAR_PID.
				 */
				if (DTRACE_ANCHORED(mstate.dtms_probe) &&
				    in_interrupt()) {
					int	depth = DTRACE_USTACK_NFRAMES(
							    rec->dtrd_arg) + 2;

					dtrace_bzero((void *)(tomax + valoffs),
						     DTRACE_USTACK_STRSIZE(
							rec->dtrd_arg) +
						     depth * sizeof(uint64_t));

					continue;
				}

				if (DTRACE_USTACK_STRSIZE(rec->dtrd_arg) != 0 &&
				    current->dtrace_helpers != NULL) {
					/*
					 * This is the slow path -- we have
					 * allocated string space, and we're
					 * getting the stack of a process that
					 * has helpers.  Call into a separate
					 * routine to perform this processing.
					 */
					dtrace_action_ustack(
						&mstate, state,
						(uint64_t *)(tomax + valoffs),
						rec->dtrd_arg);
					continue;
				}

				dtrace_getupcstack(
					(uint64_t *)(tomax + valoffs),
					DTRACE_USTACK_NFRAMES(rec->dtrd_arg) +
					2);
				continue;

			default:
				break;
			}

			dp = act->dta_difo;
			ASSERT(dp != NULL);

			val = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (*flags & CPU_DTRACE_ERROR)
				continue;

			switch (act->dta_kind) {
			case DTRACEACT_SPECULATE:
				ASSERT(buf == &state->dts_buffer[cpuid]);
				buf = dtrace_speculation_buffer(state, cpuid,
								val);

				if (buf == NULL) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				offs = dtrace_buffer_reserve(buf,
							     ecb->dte_needed,
							     ecb->dte_alignment,
							     state, NULL);

				if (offs < 0) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				tomax = buf->dtb_tomax;
				ASSERT(tomax != NULL);

				if (ecb->dte_size != 0) {
					DTRACE_STORE(uint32_t, tomax, offs,
						     ecb->dte_epid);
					dt_dbg_buf("    Store: %p[%ld .. %ld] "
						   "<- %d [EPID] "
						   "(from %s::%d)\n",
						   buf, offs,
						   offs + sizeof(uint32_t) - 1,
						   ecb->dte_epid,
						   __FUNCTION__, __LINE__);
				}

				continue;

			case DTRACEACT_CHILL:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_chill(&mstate,
							    ns_to_ktime(val));

				continue;

			case DTRACEACT_RAISE:
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_raise(val);

				continue;

			case DTRACEACT_COMMIT:
				ASSERT(!committed);

				/*
				 * We need to commit our buffer state.
				 */
				if (ecb->dte_size) {
					buf->dtb_offset = offs + ecb->dte_size;
					dt_dbg_buf("  Consume: %p[%ld .. "
						   "%lld]\n",
						   buf, offs,
						   buf->dtb_offset - 1);
				}

				buf = &state->dts_buffer[cpuid];
				dtrace_speculation_commit(state, cpuid, val);
				committed = 1;
				continue;

			case DTRACEACT_DISCARD:
				dtrace_speculation_discard(state, cpuid, val);
				continue;

			case DTRACEACT_DIFEXPR:
			case DTRACEACT_LIBACT:
			case DTRACEACT_PRINTF:
			case DTRACEACT_PRINTA:
			case DTRACEACT_SYSTEM:
			case DTRACEACT_FREOPEN:
			case DTRACEACT_TRACEMEM:
				break;

			case DTRACEACT_SYM:
			case DTRACEACT_MOD:
				if (!dtrace_priv_kernel(state))
					continue;
				break;

			case DTRACEACT_USYM:
			case DTRACEACT_UMOD:
			case DTRACEACT_UADDR: {
				pid_t	pid = current->pid;
				pid_t	tgid = current->tgid;

				if (!dtrace_priv_proc(state))
					continue;

				DTRACE_STORE(uint64_t, tomax, valoffs,
					     (uint64_t)pid);
				dt_dbg_buf("    Store: %p[%ld .. %ld] <- %lld "
					   "[PID] (from %s::%d)\n",
					   buf, valoffs,
					   valoffs + sizeof(uint64_t) - 1,
					   (uint64_t)pid,
					   __FUNCTION__, __LINE__);
				DTRACE_STORE(uint64_t, tomax,
					     valoffs + sizeof(uint64_t),
					     (uint64_t)tgid);
				dt_dbg_buf("    Store: %p[%ld .. %ld] <- %lld "
					   "[TGID] (from %s::%d)\n",
					   buf, valoffs + sizeof(uint64_t),
					   valoffs + 2 * sizeof(uint64_t) - 1,
					   (uint64_t)tgid,
					   __FUNCTION__, __LINE__);
				DTRACE_STORE(uint64_t, tomax,
					     valoffs + 2 * sizeof(uint64_t),
					     val);
				dt_dbg_buf("    Store: %p[%ld .. %ld] <- %lld "
					   "(from %s::%d)\n",
					   buf, valoffs + 2 * sizeof(uint64_t),
					   valoffs + 3 * sizeof(uint64_t) - 1,
					   val, __FUNCTION__, __LINE__);

				continue;
			}

			case DTRACEACT_EXIT: {
				/*
				 * For the exit action, we are going to attempt
				 * to atomically set our activity to be
				 * draining.  If this fails (either because
				 * another CPU has beat us to the exit action,
				 * or because our current activity is something
				 * other than ACTIVE or WARMUP), we will
				 * continue.  This assures that the exit action
				 * can be successfully recorded at most once
				 * when we're in the ACTIVE state.  If we're
				 * encountering the exit() action while in
				 * COOLDOWN, however, we want to honor the new
				 * status code.  (We know that we're the only
				 * thread in COOLDOWN, so there is no race.)
				 */
				dtrace_activity_t	*activity =
							&state->dts_activity;
				dtrace_activity_t	curr =
							state->dts_activity;

				if (curr == DTRACE_ACTIVITY_COOLDOWN)
					break;

				if (curr != DTRACE_ACTIVITY_WARMUP)
					curr = DTRACE_ACTIVITY_ACTIVE;

				if (cmpxchg(activity, curr,
					    DTRACE_ACTIVITY_DRAINING) != curr) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				break;
			}

			default:
				ASSERT(0);
			}

			if (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t	end = valoffs + size;

				if (!dtrace_vcanload((void *)(uintptr_t)val,
						      &dp->dtdo_rtype, &mstate,
						      vstate))
					continue;

				/*
				 * If this is a string, we're going to only
				 * load until we find the zero byte -- after
				 * which we'll store zero bytes.
				 */
				if (dp->dtdo_rtype.dtdt_kind ==
				    DIF_TYPE_STRING) {
					char	c = '\0' + 1;
					int	intuple = act->dta_intuple;
					size_t	s;

					for (s = 0; s < size; s++) {
						if (c != '\0')
							c = dtrace_load8(val++);

						DTRACE_STORE(uint8_t, tomax,
							     valoffs++, c);
						dt_dbg_buf("    Store: %p[%ld]"
							   " <- %d (from "
							   "%s::%d)\n",
							   buf, valoffs, c,
							   __FUNCTION__,
							   __LINE__);

						if (c == '\0' && intuple)
							break;
					}

					continue;
				}

				while (valoffs < end) {
					DTRACE_STORE(uint8_t, tomax, valoffs++,
						     dtrace_load8(val++));
					dt_dbg_buf("    Store: %p[%ld] <- ??? "
						   "(from %s::%d)\n",
						   buf, valoffs,
						   __FUNCTION__, __LINE__);
				}

				continue;
			}

			switch (size) {
			case 0:
				break;
			case sizeof(uint8_t):
				DTRACE_STORE(uint8_t, tomax, valoffs, val);
				dt_dbg_buf("    Store: %p[%ld] <- %d "
					   "(from %s::%d)\n",
					   buf, valoffs, (uint8_t)val,
					   __FUNCTION__, __LINE__);
				break;
			case sizeof(uint16_t):
				DTRACE_STORE(uint16_t, tomax, valoffs, val);
				dt_dbg_buf("    Store: %p[%ld .. %ld] <- %d "
					   "(from %s::%d)\n",
					   buf, valoffs,
					   valoffs + sizeof(uint16_t) - 1,
					   (uint16_t)val,
					   __FUNCTION__, __LINE__);
				break;
			case sizeof(uint32_t):
				DTRACE_STORE(uint32_t, tomax, valoffs, val);
				dt_dbg_buf("    Store: %p[%ld] <- %d "
					   "(from %s::%d)\n",
					   buf, valoffs,
					   (uint32_t)val,
					   __FUNCTION__, __LINE__);
				break;
			case sizeof(uint64_t):
				DTRACE_STORE(uint64_t, tomax, valoffs, val);
				dt_dbg_buf("    Store: %p[%ld] <- %lld "
					   "(from %s::%d)\n",
					   buf, valoffs,
					   val,
					   __FUNCTION__, __LINE__);
				break;
			default:
				/*
				 * Any other size should have been returned by
				 * reference, not by value.
				 */
				ASSERT(0);
				break;
			}
		}

		if (*flags & CPU_DTRACE_DROP) {
			dt_dbg_probe("  -> Dropped\n");
			continue;
		}

		if (*flags & CPU_DTRACE_FAULT) {
			int		ndx;
			dtrace_action_t	*err;

			dt_dbg_probe("  -> Failed (%x)\n", *flags);

			buf->dtb_errors++;

			if (probe->dtpr_id == dtrace_probeid_error) {
				/*
				 * There's nothing we can do -- we had an
				 * error on the error probe.  We bump an
				 * error counter to at least indicate that
				 * this condition happened.
				 */
				dtrace_error(&state->dts_dblerrors);
				continue;
			}

			/*
			 * Iterate over the actions to figure out which action
			 * we were processing when we experienced the error.
			 * Note that act points _past_ the faulting action; if
			 * act is ecb->dte_action, the fault was in the
			 * predicate, if it's ecb->dte_action->dta_next it's
			 * in action #1, and so on.
			 */
			for (err = ecb->dte_action, ndx = 0;
			     err != act; err = err->dta_next, ndx++)
				continue;

			dtrace_probe_error(
				state, ecb->dte_epid, ndx,
				(mstate.dtms_present & DTRACE_MSTATE_FLTOFFS)
					? mstate.dtms_fltoffs
					: -1,
				DTRACE_FLAGS2FLT(*flags),
				this_cpu_core->cpuc_dtrace_illval);

			continue;
		}

		if (!committed) {
			buf->dtb_offset = offs + ecb->dte_size;
			dt_dbg_buf("  Consume: %p[%ld .. %lld]\n",
				   buf, offs, buf->dtb_offset);
		}

		dt_dbg_probe("Probe (ID %d EPID %d) Done\n",
			     id, ecb->dte_epid);
	}

	dtrace_vtime_resume();

	/*
	 * Only clear the flag if this is not the ERROR probe.  We know that
	 * an ERROR probe executes from within another probe, and therefore
	 * we need to retain the probe context flag in the flags.
	 */
	if (id != dtrace_probeid_error) {
		*flags &= ~CPU_DTRACE_PROBE_CTX;
		this_cpu_core->cpu_dtrace_caller = 0;
	}

	if (pflag)
		dtrace_preempt_on();
	DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry);

	if (current->dtrace_sig != 0) {
		int	sig = current->dtrace_sig;

		current->dtrace_sig = 0;

		send_sig(sig, current, 0);
	}
}
EXPORT_SYMBOL(dtrace_probe);

int dtrace_probe_init(void)
{
	dtrace_id_t	id;

	dtrace_probe_cachep = KMEM_CACHE(dtrace_probe, SLAB_HWCACHE_ALIGN);
	if (dtrace_probe_cachep == NULL)
		return -ENOMEM;

	idr_init(&dtrace_probe_idr);

	/*
	 * We create a ID 0 entry as a sentinel, so we can always depend on it
	 * being the very first entry.  This is used in functionality that runs
	 * through the list of probes.
	 *
	 * We need to drop our locks when calling idr_preload(), so we try to
	 * get them back right after.
	 */
	idr_preload(GFP_KERNEL);
	id = idr_alloc_cyclic(&dtrace_probe_idr, NULL, 0, 0, GFP_NOWAIT);
	idr_preload_end();

	return id == 0 ? 0 : -EAGAIN;
}

void dtrace_probe_exit(void)
{
	idr_destroy(&dtrace_probe_idr);
	kmem_cache_destroy(dtrace_probe_cachep);
}

void dtrace_probe_remove_id(dtrace_id_t id)
{
	idr_remove(&dtrace_probe_idr, id);
}

dtrace_probe_t *dtrace_probe_lookup_id(dtrace_id_t id)
{
	return idr_find(&dtrace_probe_idr, id);
}

static int dtrace_probe_lookup_match(dtrace_probe_t *probe, void *arg)
{
	*((dtrace_id_t *)arg) = probe->dtpr_id;

	return DTRACE_MATCH_DONE;
}

dtrace_id_t dtrace_probe_lookup(dtrace_provider_id_t prid, const char *mod,
				const char *func, const char *name)
{
	dtrace_probekey_t	pkey;
	dtrace_id_t		id;
	int			match;

	pkey.dtpk_prov = ((dtrace_provider_t *)prid)->dtpv_name;
	pkey.dtpk_pmatch = &dtrace_match_string;
	pkey.dtpk_mod = mod;
	pkey.dtpk_mmatch = mod ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_func = func;
	pkey.dtpk_fmatch = func ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_name = name;
	pkey.dtpk_nmatch = name ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_id = DTRACE_IDNONE;

	mutex_lock(&dtrace_lock);
	match = dtrace_match(&pkey, DTRACE_PRIV_ALL,
			     make_kuid(init_user_namespace, 0),
			     dtrace_probe_lookup_match, &id);
	mutex_unlock(&dtrace_lock);

	ASSERT(match == 1 || match == 0);

	return match ? id : 0;
}
EXPORT_SYMBOL(dtrace_probe_lookup);

dtrace_probe_t *dtrace_probe_get_next(dtrace_id_t *idp)
{
	return idr_get_next(&dtrace_probe_idr, idp);
}

int dtrace_probe_for_each(int (*fn)(int id, void *p, void *data), void *data)
{
	return idr_for_each(&dtrace_probe_idr, fn, data);
}
