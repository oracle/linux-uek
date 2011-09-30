/*
 * FILE:	dtrace_enable.c
 * DESCRIPTION:	Dynamic Tracing: enabling functions
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "dtrace.h"

size_t			dtrace_retain_max = 1024;
dtrace_enabling_t	*dtrace_retained;
dtrace_genid_t		dtrace_retained_gen;

dtrace_enabling_t *dtrace_enabling_create(dtrace_vstate_t *vstate)
{
	dtrace_enabling_t	*enab;

	enab = kzalloc(sizeof (dtrace_enabling_t), GFP_KERNEL);
	enab->dten_vstate = vstate;

	return enab;
}

void dtrace_enabling_add(dtrace_enabling_t *enab, dtrace_ecbdesc_t *ecb)
{
	dtrace_ecbdesc_t	**ndesc;
	size_t			osize, nsize;

	/*
	 * We can't add to enablings after we've enabled them, or after we've
	 * retained them.
	 */
	ASSERT(enab->dten_probegen == 0);
	ASSERT(enab->dten_next == NULL && enab->dten_prev == NULL);

	if (enab->dten_ndesc < enab->dten_maxdesc) {
		enab->dten_desc[enab->dten_ndesc++] = ecb;
		return;
	}

	osize = enab->dten_maxdesc * sizeof (dtrace_enabling_t *);

	if (enab->dten_maxdesc == 0)
		enab->dten_maxdesc = 1;
	else
		enab->dten_maxdesc <<= 1;

	ASSERT(enab->dten_ndesc < enab->dten_maxdesc);

	nsize = enab->dten_maxdesc * sizeof (dtrace_enabling_t *);
	ndesc = kzalloc(nsize, GFP_KERNEL);
	memcpy(ndesc, enab->dten_desc, osize);
	kfree(enab->dten_desc);

	enab->dten_desc = ndesc;
	enab->dten_desc[enab->dten_ndesc++] = ecb;
}

static void dtrace_enabling_addlike(dtrace_enabling_t *enab,
				    dtrace_ecbdesc_t *ecb,
				    dtrace_probedesc_t *pd)
{
	dtrace_ecbdesc_t *new;
	dtrace_predicate_t	*pred;
	dtrace_actdesc_t	*act;

	/*
	 * We're going to create a new ECB description that matches the
	 * specified ECB in every way, but has the specified probe description.
	 */
	new = kzalloc(sizeof (dtrace_ecbdesc_t), GFP_KERNEL);

	if ((pred = ecb->dted_pred.dtpdd_predicate) != NULL)
		dtrace_predicate_hold(pred);

	for (act = ecb->dted_action; act != NULL; act = act->dtad_next)
		dtrace_actdesc_hold(act);

	new->dted_action = ecb->dted_action;
	new->dted_pred = ecb->dted_pred;
	new->dted_probe = *pd;
	new->dted_uarg = ecb->dted_uarg;

	dtrace_enabling_add(enab, new);
}

void dtrace_enabling_dump(dtrace_enabling_t *enab)
{
	int	i;

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_probedesc_t	*desc =
					&enab->dten_desc[i]->dted_probe;

		pr_info("enabling probe %d (%s:%s:%s:%s)",
			i, desc->dtpd_provider, desc->dtpd_mod,
			desc->dtpd_func, desc->dtpd_name);
	}
}

void dtrace_enabling_destroy(dtrace_enabling_t *enab)
{
	int			i;
	dtrace_ecbdesc_t	*ep;
	dtrace_vstate_t		*vstate = enab->dten_vstate;

	ASSERT(mutex_is_locked(&dtrace_lock));

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_actdesc_t	*act, *next;
		dtrace_predicate_t	*pred;

		ep = enab->dten_desc[i];

		if ((pred = ep->dted_pred.dtpdd_predicate) != NULL)
			dtrace_predicate_release(pred, vstate);

		for (act = ep->dted_action; act != NULL; act = next) {
			next = act->dtad_next;
			dtrace_actdesc_release(act, vstate);
		}

		kfree(ep);
	}

	kfree(enab->dten_desc);

	/*
	 * If this was a retained enabling, decrement the dts_nretained count
	 * and remove it from the dtrace_retained list.
	 */
	if (enab->dten_prev != NULL || enab->dten_next != NULL ||
	    dtrace_retained == enab) {
		ASSERT(enab->dten_vstate->dtvs_state != NULL);
		ASSERT(enab->dten_vstate->dtvs_state->dts_nretained > 0);
		enab->dten_vstate->dtvs_state->dts_nretained--;
		dtrace_retained_gen++;
	}

	if (enab->dten_prev == NULL) {
		if (dtrace_retained == enab) {
			dtrace_retained = enab->dten_next;

			if (dtrace_retained != NULL)
				dtrace_retained->dten_prev = NULL;
		}
	} else {
		ASSERT(enab != dtrace_retained);
		ASSERT(dtrace_retained != NULL);
		enab->dten_prev->dten_next = enab->dten_next;
	}

	if (enab->dten_next != NULL) {
		ASSERT(dtrace_retained != NULL);
		enab->dten_next->dten_prev = enab->dten_prev;
	}

	kfree(enab);
}

int dtrace_enabling_retain(dtrace_enabling_t *enab)
{
	dtrace_state_t	*state;

	ASSERT(mutex_is_locked(&dtrace_lock));
	ASSERT(enab->dten_next == NULL && enab->dten_prev == NULL);
	ASSERT(enab->dten_vstate != NULL);

	state = enab->dten_vstate->dtvs_state;
	ASSERT(state != NULL);

	/*
	 * We only allow each state to retain dtrace_retain_max enablings.
	 */
	if (state->dts_nretained >= dtrace_retain_max)
		return -ENOSPC;

	state->dts_nretained++;
	dtrace_retained_gen++;

	if (dtrace_retained == NULL) {
		dtrace_retained = enab;
		return 0;
	}

	enab->dten_next = dtrace_retained;
	dtrace_retained->dten_prev = enab;
	dtrace_retained = enab;

	return 0;
}

int dtrace_enabling_replicate(dtrace_state_t *state, dtrace_probedesc_t *match,
			      dtrace_probedesc_t *create)
{
	dtrace_enabling_t	*new, *enab;
	int			found = 0, err = -ENOENT;

	ASSERT(mutex_is_locked(&dtrace_lock));
	ASSERT(strlen(match->dtpd_provider) < DTRACE_PROVNAMELEN);
	ASSERT(strlen(match->dtpd_mod) < DTRACE_MODNAMELEN);
	ASSERT(strlen(match->dtpd_func) < DTRACE_FUNCNAMELEN);
	ASSERT(strlen(match->dtpd_name) < DTRACE_NAMELEN);

	new = dtrace_enabling_create(&state->dts_vstate);

	/*
	 * Iterate over all retained enablings, looking for enablings that
	 * match the specified state.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		int	i;

		/*
		 * dtvs_state can only be NULL for helper enablings -- and
		 * helper enablings can't be retained.
		 */
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state != state)
			continue;

		/*
		 * Now iterate over each probe description; we're looking for
		 * an exact match to the specified probe description.
		 */
		for (i = 0; i < enab->dten_ndesc; i++) {
			dtrace_ecbdesc_t	*ep = enab->dten_desc[i];
			dtrace_probedesc_t	*pd = &ep->dted_probe;

			if (strcmp(pd->dtpd_provider, match->dtpd_provider))
				continue;

			if (strcmp(pd->dtpd_mod, match->dtpd_mod))
				continue;

			if (strcmp(pd->dtpd_func, match->dtpd_func))
				continue;

			if (strcmp(pd->dtpd_name, match->dtpd_name))
				continue;

			/*
			 * We have a winning probe!  Add it to our growing
			 * enabling.
			 */
			found = 1;
			dtrace_enabling_addlike(new, ep, create);
		}
	}

	if (!found || (err = dtrace_enabling_retain(new)) != 0) {
		dtrace_enabling_destroy(new);
		return err;
	}

	return 0;
}

void dtrace_enabling_retract(dtrace_state_t *state)
{
	dtrace_enabling_t	*enab, *next;

	ASSERT(mutex_is_locked(&dtrace_lock));

	/*
	 * Iterate over all retained enablings, destroy the enablings retained
	 * for the specified state.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = next) {
		next = enab->dten_next;

		/*
		 * dtvs_state can only be NULL for helper enablings, and helper
		 * enablings can't be retained.
		 */
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state == state) {
			ASSERT(state->dts_nretained > 0);
			dtrace_enabling_destroy(enab);
		}
	}

	ASSERT(state->dts_nretained == 0);
}

int dtrace_enabling_match(dtrace_enabling_t *enab, int *nmatched)
{
	int	i;
	int	total_matched = 0, matched = 0;

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_ecbdesc_t	*ep = enab->dten_desc[i];

		enab->dten_current = ep;
		enab->dten_error = 0;

		if ((matched = dtrace_probe_enable(&ep->dted_probe, enab)) < 0)
			return -EBUSY;

		total_matched += matched;

		if (enab->dten_error != 0) {
			if (nmatched == NULL)
				pr_warning("dtrace_enabling_match() error on %p: %d\n", (void *)ep, enab->dten_error);

			return enab->dten_error;
		}
	}

	enab->dten_probegen = dtrace_probegen;
	if (nmatched != NULL)
		*nmatched = total_matched;

	return 0;
}

void dtrace_enabling_matchall(void)
{
	dtrace_enabling_t	*enab;

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);

	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next)
		(void) dtrace_enabling_match(enab, NULL);

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&cpu_lock);
}

/*
 * If an enabling is to be enabled without having matched probes (that is, if
 * dtrace_state_go() is to be called on the underlying dtrace_state_t), the
 * enabling must be _primed_ by creating an ECB for every ECB description.
 * This must be done to assure that we know the number of speculations, the
 * number of aggregations, the minimum buffer size needed, etc. before we
 * transition out of DTRACE_ACTIVITY_INACTIVE.  To do this without actually
 * enabling any probes, we create ECBs for every ECB decription, but with a
 * NULL probe -- which is exactly what this function does.
 */
void dtrace_enabling_prime(dtrace_state_t *state)
{
	dtrace_enabling_t	*enab;
	int			i;

	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state != state)
			continue;

		/*
		 * We don't want to prime an enabling more than once, lest
		 * we allow a malicious user to induce resource exhaustion.
		 * (The ECBs that result from priming an enabling aren't
		 * leaked -- but they also aren't deallocated until the
		 * consumer state is destroyed.)
		 */
		if (enab->dten_primed)
			continue;

		for (i = 0; i < enab->dten_ndesc; i++) {
			enab->dten_current = enab->dten_desc[i];
			dtrace_probe_enable(NULL, enab);
		}

		enab->dten_primed = 1;
	}
}

void dtrace_enabling_provide(dtrace_provider_t *prv)
{
	int		all = 0;
	dtrace_genid_t	gen;

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}

	do {
		dtrace_enabling_t	*enab;
		void			*parg = prv->dtpv_arg;

retry:
		gen = dtrace_retained_gen;
		for (enab = dtrace_retained; enab != NULL;
		     enab = enab->dten_next) {
			int	i;

			for (i = 0; i < enab->dten_ndesc; i++) {
				dtrace_probedesc_t	desc;

				desc = enab->dten_desc[i]->dted_probe;
				mutex_unlock(&dtrace_lock);
				prv->dtpv_pops.dtps_provide(parg, &desc);
				mutex_lock(&dtrace_lock);

				if (gen != dtrace_retained_gen)
					goto retry;
			}
		}
	} while (all && (prv = prv->dtpv_next) != NULL);

	mutex_unlock(&dtrace_lock);
	dtrace_probe_provide(NULL, all ? NULL : prv);
	mutex_lock(&dtrace_lock);
}
