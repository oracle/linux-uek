/*
 * FILE:	dtrace_predicate.c
 * DESCRIPTION:	Dynamic Tracing: predicate functions
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/slab.h>

#include "dtrace.h"

static dtrace_cacheid_t	dtrace_predcache_id = DTRACE_CACHEIDNONE + 1;

dtrace_predicate_t *dtrace_predicate_create(dtrace_difo_t *dp)
{
	dtrace_predicate_t	*pred;

	ASSERT(mutex_is_locked(&dtrace_lock));
	ASSERT(dp->dtdo_refcnt != 0);

	pred = kzalloc(sizeof (dtrace_predicate_t), GFP_KERNEL);
	pred->dtp_difo = dp;
	pred->dtp_refcnt = 1;

	if (!dtrace_difo_cacheable(dp))
		return pred;

	/*
	 * This is only theoretically possible -- we have had 2^32 cacheable
	 * predicates on this machine.  We cannot allow any more predicates to
	 * become cacheable:  as unlikely as it is, there may be a thread
	 * caching a (now stale) predicate cache ID. (N.B.: the temptation is
	 * being successfully resisted to have this cmn_err() "Holy shit -- we
	 * executed this code!")
	 */
	if (dtrace_predcache_id == DTRACE_CACHEIDNONE)
		return pred;

	pred->dtp_cacheid = dtrace_predcache_id++;

	return pred;
}

void dtrace_predicate_hold(dtrace_predicate_t *pred)
{
	ASSERT(mutex_is_locked(&dtrace_lock));
	ASSERT(pred->dtp_difo != NULL && pred->dtp_difo->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	pred->dtp_refcnt++;
}

void dtrace_predicate_release(dtrace_predicate_t *pred,
			      dtrace_vstate_t *vstate)
{
	dtrace_difo_t *dp = pred->dtp_difo;

	ASSERT(mutex_is_locked(&dtrace_lock));
	ASSERT(dp != NULL && dp->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	if (--pred->dtp_refcnt == 0) {
		dtrace_difo_release(dp, vstate);
		kfree(pred);
	}
}
