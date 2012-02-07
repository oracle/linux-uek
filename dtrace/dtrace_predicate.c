/*
 * FILE:	dtrace_predicate.c
 * DESCRIPTION:	Dynamic Tracing: predicate functions
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

#include <linux/slab.h>

#include "dtrace.h"

static dtrace_cacheid_t	dtrace_predcache_id = DTRACE_CACHEIDNONE + 1;

dtrace_predicate_t *dtrace_predicate_create(dtrace_difo_t *dp)
{
	dtrace_predicate_t	*pred;

	ASSERT(MUTEX_HELD(&dtrace_lock));
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
	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(pred->dtp_difo != NULL && pred->dtp_difo->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	pred->dtp_refcnt++;
}

void dtrace_predicate_release(dtrace_predicate_t *pred,
			      dtrace_vstate_t *vstate)
{
	dtrace_difo_t *dp = pred->dtp_difo;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dp != NULL && dp->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	if (--pred->dtp_refcnt == 0) {
		dtrace_difo_release(dp, vstate);
		kfree(pred);
	}
}
