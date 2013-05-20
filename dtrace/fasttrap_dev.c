/*
 * FILE:	fasttrap_dev.c
 * DESCRIPTION:	Fasttrap Tracing: device file handling
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
 * Copyright 2010, 2011, 2012, 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/workqueue.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fasttrap_impl.h"

#define FASTTRAP_MAX_DEFAULT	250000
static uint32_t			fasttrap_max;
static uint64_t			fasttrap_pid_count;
static atomic_t			fasttrap_total;

#define FASTTRAP_TPOINTS_DEFAULT_SIZE	0x4000
#define FASTTRAP_PROVIDERS_DEFAULT_SIZE	0x100
#define FASTTRAP_PROCS_DEFAULT_SIZE	0x100

#define FASTTRAP_PID_NAME	"pid"
#define FASTTRAP_ENABLE_FAIL	1
#define FASTTRAP_ENABLE_PARTIAL	2

fasttrap_hash_t			fasttrap_tpoints;
static fasttrap_hash_t		fasttrap_provs;
static fasttrap_hash_t		fasttrap_procs;

#define FASTTRAP_PROVS_INDEX(pid, name) \
	((fasttrap_hash_str(name) + (pid)) & fasttrap_provs.fth_mask)
#define FASTTRAP_PROCS_INDEX(pid) ((pid) & fasttrap_procs.fth_mask)

#define CLEANUP_NONE		0
#define CLEANUP_SCHEDULED	1
#define CLEANUP_DEFERRED	2

DEFINE_MUTEX(fasttrap_cleanup_mtx);
DEFINE_MUTEX(fasttrap_count_mtx);
static uint_t			fasttrap_cleanup_state;
static uint_t			fasttrap_cleanup_work;

/*
 * Generation count on modifications to the global tracepoint lookup table.
 */
static volatile uint64_t	fasttrap_mod_gen;

static void fasttrap_pid_cleanup(void);

static void fasttrap_pid_probe(fasttrap_machtp_t *mtp, struct pt_regs *regs) {
	fasttrap_tracepoint_t	*tp = container_of(mtp, fasttrap_tracepoint_t,
						   ftt_mtp);
	fasttrap_id_t		*id;

pr_info("fasttrap_pid_probe(PID %d, PC %lx)\n", tp->ftt_pid, tp->ftt_pc);
	for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
		fasttrap_probe_t	*ftp = id->fti_probe;

pr_info("    Probe ID %d for PID %d\n", ftp->ftp_id, ftp->ftp_pid);
		dtrace_probe(ftp->ftp_id, regs->di, regs->si, regs->dx,
			     regs->cx, regs->r8);
	}
}

static void fasttrap_pid_provide(void *arg, const dtrace_probedesc_t *desc)
{
	/*
	 * There are no "default" pid probes.
	 */
}

static void fasttrap_enable_callbacks(void)
{
	/*
	 * We don't have to play the RW lock game here because we're providing
	 * something rather than taking something away -- we can be sure that
	 * no threads have tried to follow these function pointers yet.
	 */
	mutex_lock(&fasttrap_count_mtx);
	if (fasttrap_pid_count == 0) {
		ASSERT(dtrace_tracepoint_hit == NULL);

		dtrace_tracepoint_hit = &fasttrap_pid_probe;
	}

	ASSERT(dtrace_tracepoint_hit == &fasttrap_pid_probe);

	fasttrap_pid_count++;
	mutex_unlock(&fasttrap_count_mtx);
}

static void fasttrap_disable_callbacks(void)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	mutex_lock(&fasttrap_count_mtx);
	ASSERT(fasttrap_pid_count > 0);
	fasttrap_pid_count--;

	if (fasttrap_pid_count == 0) {
		int	cpu;

		for_each_present_cpu(cpu) {
			cpu_core_t	*cpuc = per_cpu_core(cpu);

			write_lock(&cpuc->cpu_ft_lock);
		}

		dtrace_tracepoint_hit = NULL;

		for_each_present_cpu(cpu) {
			cpu_core_t	*cpuc = per_cpu_core(cpu);

			write_unlock(&cpuc->cpu_ft_lock);
		}
	}

	mutex_unlock(&fasttrap_count_mtx);
}

/*
 * his function ensures that no threads are actively using the memory
 * associated with probes that were formerly live.
 */
static void fasttrap_mod_barrier(uint64_t gen)
{
	int	cpu;

	if (gen < fasttrap_mod_gen)
		return;

	fasttrap_mod_gen++;

	for_each_present_cpu(cpu) {
		cpu_core_t	*cpuc = per_cpu_core(cpu);

		mutex_lock(&cpuc->cpuc_pid_lock);
		mutex_unlock(&cpuc->cpuc_pid_lock);
	}
}

static int fasttrap_tracepoint_enable(fasttrap_probe_t *probe, uint_t index)
{
	fasttrap_tracepoint_t	*tp, *new_tp = NULL;
	fasttrap_bucket_t	*bucket;
	fasttrap_id_t		*id;
	pid_t			pid;
	uintptr_t		pc;

	ASSERT(index < probe->ftp_ntps);

	pid = probe->ftp_pid;
	pc = probe->ftp_tps[index].fit_tp->ftt_pc;
	id = &probe->ftp_tps[index].fit_id;

	ASSERT(probe->ftp_tps[index].fit_tp->ftt_pid == pid);

	/*
	 * Before we make any modifications, make sure we've imposed a barrier
	 * on the generation in which this probe was last modified.
	 */
	fasttrap_mod_barrier(probe->ftp_gen);

	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * If the tracepoint has already been enabled, just add our id to the
	 * list of interested probes. This may be our second time through
	 * this path in which case we'll have constructed the tracepoint we'd
	 * like to install. If we can't find a match, and have an allocated
	 * tracepoint ready to go, enable that one now.
	 *
	 * A tracepoint whose process is defunct is also considered defunct.
	 */
again:
	mutex_lock(&bucket->ftb_mtx);
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		/*
		 * Note that it's safe to access the active count on the
		 * associated proc structure because we know that at least one
		 * provider (this one) will still be around throughout this
		 * operation.
		 */
		if (tp->ftt_pid != pid || tp->ftt_pc != pc ||
		    atomic64_read(&tp->ftt_proc->ftpc_acount) == 0)
			continue;

		/*
		 * Now that we've found a matching tracepoint, it would be
		 * a decent idea to confirm that the tracepoint is still
		 * enabled and the trap instruction hasn't been overwritten.
		 * Since this is a little hairy, we'll punt for now.
		 */

		/*
		 * This can't be the first interested probe. We don't have
		 * to worry about another thread being in the midst of
		 * deleting this tracepoint (which would be the only valid
		 * reason for a tracepoint to have no interested probes)
		 * since we're holding P_PR_LOCK for this process.
		 */
		ASSERT(tp->ftt_ids != NULL || tp->ftt_retids != NULL);

		switch (id->fti_ptype) {
		case DTFTP_ENTRY:
		case DTFTP_OFFSETS:
		case DTFTP_IS_ENABLED:
			id->fti_next = tp->ftt_ids;
			dtrace_membar_producer();
			tp->ftt_ids = id;
			dtrace_membar_producer();
			break;

		case DTFTP_RETURN:
		case DTFTP_POST_OFFSETS:
			id->fti_next = tp->ftt_retids;
			dtrace_membar_producer();
			tp->ftt_retids = id;
			dtrace_membar_producer();
			break;

		default:
			ASSERT(0);	/* FIXME */
		}

		mutex_unlock(&bucket->ftb_mtx);

		if (new_tp != NULL) {
			new_tp->ftt_ids = NULL;
			new_tp->ftt_retids = NULL;
		}

		return 0;
	}

	/*
	 * If we have a good tracepoint ready to go, install it now while
	 * we have the lock held and no one can screw with us.
	 */
	if (new_tp != NULL) {
		int	rc = 0;

		new_tp->ftt_next = bucket->ftb_data;
		dtrace_membar_producer();
		bucket->ftb_data = new_tp;
		dtrace_membar_producer();
		mutex_unlock(&bucket->ftb_mtx);

		/*
		 * Activate the tracepoint in the ISA-specific manner.
		 * If this fails, we need to report the failure, but
		 * indicate that this tracepoint must still be disabled
		 * by calling fasttrap_tracepoint_disable().
		 */
		if (dtrace_tracepoint_enable(pid, pc, &new_tp->ftt_mtp) != 0)
			rc = FASTTRAP_ENABLE_PARTIAL;

		return rc;
	}

	mutex_unlock(&bucket->ftb_mtx);

	/*
	 * Initialize the tracepoint that's been preallocated with the probe.
	 */
	new_tp = probe->ftp_tps[index].fit_tp;

	ASSERT(new_tp->ftt_pid == pid);
	ASSERT(new_tp->ftt_pc == pc);
	ASSERT(new_tp->ftt_proc == probe->ftp_prov->ftp_proc);
	ASSERT(new_tp->ftt_ids == NULL);
	ASSERT(new_tp->ftt_retids == NULL);

	switch (id->fti_ptype) {
	case DTFTP_ENTRY:
	case DTFTP_OFFSETS:
	case DTFTP_IS_ENABLED:
		id->fti_next = NULL;
		new_tp->ftt_ids = id;
		break;

	case DTFTP_RETURN:
	case DTFTP_POST_OFFSETS:
		id->fti_next = NULL;
		new_tp->ftt_retids = id;
		break;

	default:
		ASSERT(0);
	}

	goto again;
}

static void fasttrap_tracepoint_disable(fasttrap_probe_t *probe, uint_t index)
{
	fasttrap_bucket_t	*bucket;
	fasttrap_provider_t	*prov = probe->ftp_prov;
	fasttrap_tracepoint_t	**pp, *tp;
	fasttrap_id_t		*id, **idp = NULL;
	pid_t			pid;
	uintptr_t		pc;

	ASSERT(index < probe->ftp_ntps);

	pid = probe->ftp_pid;
	pc = probe->ftp_tps[index].fit_tp->ftt_pc;
	id = &probe->ftp_tps[index].fit_id;

	ASSERT(probe->ftp_tps[index].fit_tp->ftt_pid == pid);

	/*
	 * Find the tracepoint and make sure that our id is one of the
	 * ones registered with it.
	 */
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];
	mutex_lock(&bucket->ftb_mtx);
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (tp->ftt_pid == pid && tp->ftt_pc == pc &&
		    tp->ftt_proc == prov->ftp_proc)
			break;
	}

	/*
	 * If we somehow lost this tracepoint, we are in trouble.
	 */
	ASSERT(tp != NULL);

	switch (id->fti_ptype) {
	case DTFTP_ENTRY:
	case DTFTP_OFFSETS:
	case DTFTP_IS_ENABLED:
		ASSERT(tp->ftt_ids != NULL);
		idp = &tp->ftt_ids;
		break;

	case DTFTP_RETURN:
	case DTFTP_POST_OFFSETS:
		ASSERT(tp->ftt_retids != NULL);
		idp = &tp->ftt_retids;
		break;

	default:
		ASSERT(0);
	}

	while ((*idp)->fti_probe != probe) {
		idp = &(*idp)->fti_next;
		ASSERT(*idp != NULL);
	}

	id = *idp;
	*idp = id->fti_next;
	dtrace_membar_producer();

	ASSERT(id->fti_probe == probe);

	/*
	 * If there are other registered enablings of this tracepoint, we're
	 * all done, but if this was the last probe assocated with this
	 * this tracepoint, we need to remove and free it.
	 */
	if (tp->ftt_ids != NULL || tp->ftt_retids != NULL) {
		/*
		 * If the current probe's tracepoint is in use, swap it
		 * for an unused tracepoint.
		 */
		if (tp == probe->ftp_tps[index].fit_tp) {
			fasttrap_probe_t	*tmp_probe;
			fasttrap_tracepoint_t	**tmp_tp;
			uint_t			tmp_index;

			if (tp->ftt_ids != NULL) {
				tmp_probe = tp->ftt_ids->fti_probe;
				tmp_index = FASTTRAP_ID_INDEX(tp->ftt_ids);
				tmp_tp = &tmp_probe->ftp_tps[tmp_index].fit_tp;
			} else {
				tmp_probe = tp->ftt_retids->fti_probe;
				tmp_index = FASTTRAP_ID_INDEX(tp->ftt_retids);
				tmp_tp = &tmp_probe->ftp_tps[tmp_index].fit_tp;
			}

			ASSERT(*tmp_tp != NULL);
			ASSERT(*tmp_tp != probe->ftp_tps[index].fit_tp);
			ASSERT((*tmp_tp)->ftt_ids == NULL);
			ASSERT((*tmp_tp)->ftt_retids == NULL);

			probe->ftp_tps[index].fit_tp = *tmp_tp;
			*tmp_tp = tp;
		}

		mutex_unlock(&bucket->ftb_mtx);

		/*
		 * Tag the modified probe with the generation in which it was
		 * changed.
		 */
		probe->ftp_gen = fasttrap_mod_gen;
		return;
	}

	mutex_unlock(&bucket->ftb_mtx);

	dtrace_tracepoint_disable(pid, pc, &tp->ftt_mtp);

	/*
	 * Remove the probe from the hash table of active tracepoints.
	 */
	mutex_lock(&bucket->ftb_mtx);
	pp = (fasttrap_tracepoint_t **)&bucket->ftb_data;
	ASSERT(*pp != NULL);
	while (*pp != tp) {
		pp = &(*pp)->ftt_next;
		ASSERT(*pp != NULL);
	}

	*pp = tp->ftt_next;
	dtrace_membar_producer();

	mutex_unlock(&bucket->ftb_mtx);

	/*
	 * Tag the modified probe with the generation in which it was changed.
	 */
	probe->ftp_gen = fasttrap_mod_gen;
}

static int fasttrap_pid_enable(void *arg, dtrace_id_t id, void *parg)
{
	fasttrap_probe_t	*probe = parg;
	int			i, rc;

	ASSERT(probe != NULL);
	ASSERT(!probe->ftp_enabled);
	ASSERT(id == probe->ftp_id);
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Increment the count of enabled probes on this probe's provider;
	 * the provider can't go away while the probe still exists. We
	 * must increment this even if we aren't able to properly enable
	 * this probe.
	 */
	mutex_lock(&probe->ftp_prov->ftp_mtx);
	probe->ftp_prov->ftp_rcount++;
	mutex_unlock(&probe->ftp_prov->ftp_mtx);

	/*
	 * If this probe's provider is retired (meaning it was valid in a
	 * previously exec'ed incarnation of this address space), bail out. The
	 * provider can't go away while we're in this code path.
	 */
	if (probe->ftp_prov->ftp_retired)
		return 0;

#ifdef FIXME
	/*
	 * If we can't find the process, it may be that we're in the context of
	 * a fork in which the traced process is being born and we're copying
	 * USDT probes. Otherwise, the process is gone so bail.
	 */
	if ((p = sprlock(probe->ftp_pid)) == NULL) {
		if ((curproc->p_flag & SFORKING) == 0)
			return 0;

		mutex_enter(&pidlock);
		p = prfind(probe->ftp_pid);

		/*
		 * Confirm that curproc is indeed forking the process in which
		 * we're trying to enable probes.
		 */
		ASSERT(p != NULL);
		ASSERT(p->p_parent == curproc);
		ASSERT(p->p_stat == SIDL);

		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);

		sprlock_proc(p);
	}

	ASSERT(!(p->p_flag & SVFORK));
	mutex_exit(&p->p_lock);
#endif

	/*
	 * We have to enable the trap entry point before any user threads have
	 * the chance to execute the trap instruction we're about to place
	 * in their process's text.
	 */
	fasttrap_enable_callbacks();

	/*
	 * Enable all the tracepoints and add this probe's id to each
	 * tracepoint's list of active probes.
	 */
	for (i = 0; i < probe->ftp_ntps; i++) {
		if ((rc = fasttrap_tracepoint_enable(probe, i)) != 0) {
			/*
			 * If enabling the tracepoint failed completely,
			 * we don't have to disable it; if the failure
			 * was only partial we must disable it.
			 */
			if (rc == FASTTRAP_ENABLE_FAIL)
				i--;
			else
				ASSERT(rc == FASTTRAP_ENABLE_PARTIAL);

			/*
			 * Back up and pull out all the tracepoints we've
			 * created so far for this probe.
			 */
			while (i >= 0) {
				fasttrap_tracepoint_disable(probe, i);
				i--;
			}

#ifdef FIXME
			mutex_enter(&p->p_lock);
			sprunlock(p);
#endif

			/*
			 * Since we're not actually enabling this probe,
			 * drop our reference on the trap table entry.
			 */
			fasttrap_disable_callbacks();
			return 0;
		}
	}

#ifdef FIXME
	mutex_enter(&p->p_lock);
	sprunlock(p);

	probe->ftp_enabled = 1;
#endif
	return 0;
}

static void fasttrap_pid_disable(void *arg, dtrace_id_t id, void *parg)
{
	fasttrap_probe_t	*probe = parg;
	fasttrap_provider_t	*prov = probe->ftp_prov;
	int			i, whack = 0;

	ASSERT(id == probe->ftp_id);

	mutex_lock(&prov->ftp_mtx);

	/*
	 * Disable all the associated tracepoints (for fully enabled probes).
	 */
	if (probe->ftp_enabled) {
		for (i = 0; i < probe->ftp_ntps; i++)
			fasttrap_tracepoint_disable(probe, i);
	}

	ASSERT(prov->ftp_rcount > 0);
	prov->ftp_rcount--;

	if ((prov->ftp_retired || prov->ftp_rcount == 0) && !prov->ftp_marked)
		whack = prov->ftp_marked = 1;

	if (whack)
		fasttrap_pid_cleanup();

	if (!probe->ftp_enabled)
		return;

	probe->ftp_enabled = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));
	fasttrap_disable_callbacks();
}

static void fasttrap_pid_getargdesc(void *arg, dtrace_id_t id, void *parg,
				    dtrace_argdesc_t *desc)
{
	/* FIXME */
}

static uint64_t fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg,
				     int argno, int aframes)
{
	return 0;	/* FIXME */
}

static void fasttrap_pid_destroy(void *arg, dtrace_id_t id, void *parg)
{
	/* FIXME */
}

static const dtrace_pattr_t pid_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
};

static dtrace_pops_t pid_pops = {
#ifdef FIXME
	fasttrap_pid_provide,
	NULL,
	fasttrap_pid_enable,
	fasttrap_pid_disable,
	NULL,
	NULL,
	fasttrap_pid_getargdesc,
	fasttrap_pid_getarg,
	NULL,
	fasttrap_pid_destroy
#endif
};

static dtrace_pops_t usdt_pops = {
	fasttrap_pid_provide,
	NULL,
	fasttrap_pid_enable,
	fasttrap_pid_disable,
	NULL,
	NULL,
	fasttrap_pid_getargdesc,
	fasttrap_usdt_getarg,
	NULL,
	fasttrap_pid_destroy
};

static uint_t fasttrap_hash_str(const char *p)
{
	unsigned int	g;
	uint_t		hval = 0;

	while (*p) {
		hval = (hval << 4) + *p++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}

	return hval;
}

static int fasttrap_uint32_cmp(const void *ap, const void *bp)
{
	return (*(const uint32_t *)ap - *(const uint32_t *)bp);
}

static int fasttrap_uint64_cmp(const void *ap, const void *bp)
{
	return (*(const uint64_t *)ap - *(const uint64_t *)bp);
}

void fasttrap_meta_create_probe(void *arg, void *parg,
				dtrace_helper_probedesc_t *dhpb)
{
	fasttrap_provider_t	*provider = parg;
	fasttrap_probe_t	*pp;
	fasttrap_tracepoint_t	*tp;
	int			i, j;
	uint32_t		ntps;

	/*
	 * Since the meta provider count is non-zero we don't have to worry
	 * about this provider disappearing.
	 */
	ASSERT(provider->ftp_mcount > 0);

	/*
	 * The offsets must be unique.
	 */
	sort(dhpb->dthpb_offs, dhpb->dthpb_noffs, sizeof(uint32_t),
	     fasttrap_uint32_cmp, NULL);
	for (i = 1; i < dhpb->dthpb_noffs; i++) {
		if (dhpb->dthpb_base + dhpb->dthpb_offs[i] <=
		    dhpb->dthpb_base + dhpb->dthpb_offs[i - 1])
			return;
	}

	sort(dhpb->dthpb_enoffs, dhpb->dthpb_nenoffs, sizeof(uint32_t),
	     fasttrap_uint32_cmp, NULL);
	for (i = 1; i < dhpb->dthpb_nenoffs; i++) {
		if (dhpb->dthpb_base + dhpb->dthpb_enoffs[i] <=
		    dhpb->dthpb_base + dhpb->dthpb_enoffs[i - 1])
			return;
	}

	/*
	 * Grab the creation lock to ensure consistency between calls to
	 * dtrace_probe_lookup() and dtrace_probe_create() in the face of
	 * other threads creating probes.
	 */
	mutex_lock(&provider->ftp_cmtx);

	if (dtrace_probe_lookup(provider->ftp_provid, dhpb->dthpb_mod,
				dhpb->dthpb_func, dhpb->dthpb_name) != 0) {
		mutex_unlock(&provider->ftp_cmtx);
		return;
	}

	ntps = dhpb->dthpb_noffs + dhpb->dthpb_nenoffs;
	ASSERT(ntps > 0);

	atomic_add(ntps, &fasttrap_total);

	if (atomic_read(&fasttrap_total) > fasttrap_max) {
		atomic_add(-ntps, &fasttrap_total);
		mutex_unlock(&provider->ftp_cmtx);
		return;
	}

	pp = kzalloc(offsetof(fasttrap_probe_t, ftp_tps[ntps]), GFP_KERNEL);

	pp->ftp_prov = provider;
	pp->ftp_pid = provider->ftp_pid;
	pp->ftp_ntps = ntps;
	pp->ftp_nargs = dhpb->dthpb_xargc;
	pp->ftp_xtypes = dhpb->dthpb_xtypes;
	pp->ftp_ntypes = dhpb->dthpb_ntypes;

	/*
	 * First create a tracepoint for each actual point of interest.
	 */
	for (i = 0; i < dhpb->dthpb_noffs; i++) {
		tp = kzalloc(sizeof(fasttrap_tracepoint_t), GFP_KERNEL);

		tp->ftt_proc = provider->ftp_proc;
		tp->ftt_pc = dhpb->dthpb_base + dhpb->dthpb_offs[i];
		tp->ftt_pid = provider->ftp_pid;

		pp->ftp_tps[i].fit_tp = tp;
		pp->ftp_tps[i].fit_id.fti_probe = pp;
#ifdef __sparc
		pp->ftp_tps[i].fit_id.fti_ptype = DTFTP_POST_OFFSETS;
#else
		pp->ftp_tps[i].fit_id.fti_ptype = DTFTP_OFFSETS;
#endif
	}

	/*
	 * Then create a tracepoint for each is-enabled point.
	 */
	for (j = 0; i < ntps; i++, j++) {
		tp = kzalloc(sizeof(fasttrap_tracepoint_t), GFP_KERNEL);

		tp->ftt_proc = provider->ftp_proc;
		tp->ftt_pc = dhpb->dthpb_base + dhpb->dthpb_enoffs[j];
		tp->ftt_pid = provider->ftp_pid;

		pp->ftp_tps[i].fit_tp = tp;
		pp->ftp_tps[i].fit_id.fti_probe = pp;
		pp->ftp_tps[i].fit_id.fti_ptype = DTFTP_IS_ENABLED;
	}

	/*
	 * If the arguments are shuffled around we set the argument remapping
	 * table. Later, when the probe fires, we only remap the arguments
	 * if the table is non-NULL.
	 */
	for (i = 0; i < dhpb->dthpb_xargc; i++) {
		if (dhpb->dthpb_args[i] != i) {
			pp->ftp_argmap = dhpb->dthpb_args;
			break;
		}
	}

	/*
	 * The probe is fully constructed -- register it with DTrace.
	 */
	pp->ftp_id = dtrace_probe_create(provider->ftp_provid, dhpb->dthpb_mod,
					 dhpb->dthpb_func, dhpb->dthpb_name,
					 FASTTRAP_OFFSET_AFRAMES, pp);

	mutex_unlock(&provider->ftp_cmtx);
}

static void fasttrap_proc_release(fasttrap_proc_t *proc)
{
	fasttrap_bucket_t	*bucket;
	fasttrap_proc_t		*fprc, **fprcp;
	pid_t			pid = proc->ftpc_pid;

	mutex_lock(&proc->ftpc_mtx);

	ASSERT(proc->ftpc_rcount != 0);
	ASSERT(atomic64_read(&proc->ftpc_acount) <= proc->ftpc_rcount);

	if (--proc->ftpc_rcount != 0) {
		mutex_unlock(&proc->ftpc_mtx);
		return;
	}

	mutex_unlock(&proc->ftpc_mtx);

	/*
	 * There should definitely be no live providers associated with this
	 * process at this point.
	 */
	ASSERT(atomic64_read(&proc->ftpc_acount) == 0);

	bucket = &fasttrap_procs.fth_table[FASTTRAP_PROCS_INDEX(pid)];
	mutex_lock(&bucket->ftb_mtx);

	fprcp = (fasttrap_proc_t **)&bucket->ftb_data;
	while ((fprc = *fprcp) != NULL) {
		if (fprc == proc)
			break;

		fprcp = &fprc->ftpc_next;
	}

	/*
	 * Something strange has happened if we can't find the proc.
	 */
	ASSERT(fprc != NULL);

	*fprcp = fprc->ftpc_next;

	mutex_unlock(&bucket->ftb_mtx);

	kfree(fprc);
}

static void fasttrap_provider_free(fasttrap_provider_t *provider)
{
	pid_t			pid = provider->ftp_pid;

	/*
	 * There need to be no associated enabled probes, no consumers
	 * creating probes, and no meta providers referencing this provider.
	 */
	ASSERT(provider->ftp_rcount == 0);
	ASSERT(provider->ftp_ccount == 0);
	ASSERT(provider->ftp_mcount == 0);

	/*
	 * If this provider hasn't been retired, we need to explicitly drop the
	 * count of active providers on the associated process structure.
	 */
	if (!provider->ftp_retired) {
		atomic64_add(-1, &provider->ftp_proc->ftpc_acount);
		ASSERT(atomic64_read(&provider->ftp_proc->ftpc_acount) <
		       provider->ftp_proc->ftpc_rcount);
	}

	fasttrap_proc_release(provider->ftp_proc);

	kfree(provider);

	unregister_pid_provider(pid);
}

static fasttrap_proc_t *fasttrap_proc_lookup(pid_t pid)
{
	fasttrap_bucket_t	*bucket;
	fasttrap_proc_t		*fprc, *new_fprc;

	bucket = &fasttrap_procs.fth_table[FASTTRAP_PROCS_INDEX(pid)];
	mutex_lock(&bucket->ftb_mtx);

	for (fprc = bucket->ftb_data; fprc != NULL; fprc = fprc->ftpc_next) {
		if (fprc->ftpc_pid == pid &&
		    atomic64_read(&fprc->ftpc_acount) != 0) {
			mutex_lock(&fprc->ftpc_mtx);
			mutex_unlock(&bucket->ftb_mtx);
			fprc->ftpc_rcount++;
			atomic64_inc(&fprc->ftpc_acount);
			ASSERT(atomic64_read(&fprc->ftpc_acount) <=
			       fprc->ftpc_rcount);
			mutex_unlock(&fprc->ftpc_mtx);

			return fprc;
		}
	}

	/*
	 * Drop the bucket lock so we don't try to perform a sleeping
	 * allocation under it.
	 */
	mutex_unlock(&bucket->ftb_mtx);

	new_fprc = kzalloc(sizeof(fasttrap_proc_t), GFP_KERNEL);
	new_fprc->ftpc_pid = pid;
	new_fprc->ftpc_rcount = 1;
	atomic64_set(&new_fprc->ftpc_acount, 1);
	mutex_init(&new_fprc->ftpc_mtx);

	mutex_lock(&bucket->ftb_mtx);

	/*
	 * Take another lap through the list to make sure a proc hasn't
	 * been created for this pid while we weren't under the bucket lock.
	 */
	for (fprc = bucket->ftb_data; fprc != NULL; fprc = fprc->ftpc_next) {
		if (fprc->ftpc_pid == pid &&
		    atomic64_read(&fprc->ftpc_acount) != 0) {
			mutex_lock(&fprc->ftpc_mtx);
			mutex_unlock(&bucket->ftb_mtx);
			fprc->ftpc_rcount++;
			atomic64_inc(&fprc->ftpc_acount);
			ASSERT(atomic64_read(&fprc->ftpc_acount) <=
			       fprc->ftpc_rcount);
			mutex_unlock(&fprc->ftpc_mtx);

			kfree(new_fprc);

			return fprc;
		}
	}

	new_fprc->ftpc_next = bucket->ftb_data;
	bucket->ftb_data = new_fprc;

	mutex_unlock(&bucket->ftb_mtx);

	return new_fprc;
}

/*
 * Lookup a fasttrap-managed provider based on its name and associated pid.
 * If the pattr argument is non-NULL, this function instantiates the provider
 * if it doesn't exist otherwise it returns NULL. The provider is returned
 * with its lock held.
 */
static fasttrap_provider_t *fasttrap_provider_lookup(pid_t pid,
						     const char *name,
						     const dtrace_pattr_t *pa)
{
	fasttrap_provider_t	*fp, *new_fp = NULL;
	fasttrap_bucket_t	*bucket;
	char			provname[DTRACE_PROVNAMELEN];
	struct task_struct	*p;
	const cred_t		*cred;

	ASSERT(strlen(name) < sizeof (fp->ftp_name));
	ASSERT(pa != NULL);

	bucket = &fasttrap_provs.fth_table[FASTTRAP_PROVS_INDEX(pid, name)];
	mutex_lock(&bucket->ftb_mtx);

	/*
	 * Take a lap through the list and return the match if we find it.
	 */
	for (fp = bucket->ftb_data; fp != NULL; fp = fp->ftp_next) {
		if (fp->ftp_pid == pid && strcmp(fp->ftp_name, name) == 0 &&
		    !fp->ftp_retired) {
			mutex_lock(&fp->ftp_mtx);
			mutex_unlock(&bucket->ftb_mtx);
			return fp;
		}
	}

	/*
	 * Drop the bucket lock so we don't try to perform a sleeping
	 * allocation under it.
	 */
	mutex_unlock(&bucket->ftb_mtx);

	if ((p = register_pid_provider(pid)) == NULL)
		return NULL;

	/*
	 * Grab the credentials for this process so we have
	 * something to pass to dtrace_register().
	 */
	cred = get_cred(p->cred);

	new_fp = kzalloc(sizeof(fasttrap_provider_t), GFP_KERNEL);
	new_fp->ftp_pid = pid;
	new_fp->ftp_proc = fasttrap_proc_lookup(pid);
	mutex_init(&new_fp->ftp_mtx);
	mutex_init(&new_fp->ftp_cmtx);

	ASSERT(new_fp->ftp_proc != NULL);

	mutex_lock(&bucket->ftb_mtx);

	/*
	 * Take another lap through the list to make sure a provider hasn't
	 * been created for this pid while we weren't under the bucket lock.
	 */
	for (fp = bucket->ftb_data; fp != NULL; fp = fp->ftp_next) {
		if (fp->ftp_pid == pid && strcmp(fp->ftp_name, name) == 0 &&
		    !fp->ftp_retired) {
			mutex_lock(&fp->ftp_mtx);
			mutex_unlock(&bucket->ftb_mtx);
			fasttrap_provider_free(new_fp);
			put_cred(cred);
			return fp;
		}
	}

	strcpy(new_fp->ftp_name, name);

	/*
	 * Fail and return NULL if either the provider name is too long
	 * or we fail to register this new provider with the DTrace
	 * framework. Note that this is the only place we ever construct
	 * the full provider name -- we keep it in pieces in the provider
	 * structure.
	 */
	if (snprintf(provname, sizeof(provname), "%s%u", name, (uint_t)pid) >=
	    sizeof(provname) ||
	    dtrace_register(provname, pa,
			    DTRACE_PRIV_PROC | DTRACE_PRIV_OWNER, cred,
			    pa == &pid_attr ? &pid_pops : &usdt_pops,
			    new_fp, &new_fp->ftp_provid) != 0) {
		mutex_unlock(&bucket->ftb_mtx);
		fasttrap_provider_free(new_fp);
		put_cred(cred);
		return NULL;
	}

	new_fp->ftp_next = bucket->ftb_data;
	bucket->ftb_data = new_fp;

	mutex_lock(&new_fp->ftp_mtx);
	mutex_unlock(&bucket->ftb_mtx);

	put_cred(cred);
	return new_fp;
}

void *fasttrap_meta_provide(void *arg, dtrace_helper_provdesc_t *dhpv,
			    pid_t pid)
{
	fasttrap_provider_t	*provider;

	if (strlen(dhpv->dthpv_provname) + 10 >= sizeof (provider->ftp_name)) {
		pr_warn("Failed to instantiate provider %s: name too long "
			"to accomodate pid\n", dhpv->dthpv_provname);
		return NULL;
	}

	/*
	 * Don't let folks spoof the true pid provider.
	 */
	if (strcmp(dhpv->dthpv_provname, FASTTRAP_PID_NAME) == 0) {
		pr_warn("Failed to instantiate provider %s: %s is an invalid "
			"name\n", dhpv->dthpv_provname, FASTTRAP_PID_NAME);
		return NULL;
	}

	/*
	 * The highest stability class that fasttrap supports is ISA; cap
	 * the stability of the new provider accordingly.
	 */
	if (dhpv->dthpv_pattr.dtpa_provider.dtat_class > DTRACE_CLASS_ISA)
		dhpv->dthpv_pattr.dtpa_provider.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_mod.dtat_class > DTRACE_CLASS_ISA)
		dhpv->dthpv_pattr.dtpa_mod.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_func.dtat_class > DTRACE_CLASS_ISA)
		dhpv->dthpv_pattr.dtpa_func.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_name.dtat_class > DTRACE_CLASS_ISA)
		dhpv->dthpv_pattr.dtpa_name.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_args.dtat_class > DTRACE_CLASS_ISA)
		dhpv->dthpv_pattr.dtpa_args.dtat_class = DTRACE_CLASS_ISA;

	provider = fasttrap_provider_lookup(pid, dhpv->dthpv_provname,
					    &dhpv->dthpv_pattr);
	if (provider == NULL) {
		pr_warn("Failed to instantiate provider %s for process %u\n",
			dhpv->dthpv_provname, (uint_t)pid);
		return NULL;
	}

	/*
	 * Up the meta provider count so this provider isn't removed until the
	 * meta provider has been told to remove it.
	 */
	provider->ftp_mcount++;

	mutex_unlock(&provider->ftp_mtx);

	return provider;
}

static void fasttrap_pid_cleanup_cb(struct work_struct *work)
{
	fasttrap_provider_t	**fpp, *fp;
	fasttrap_bucket_t	*bucket;
	dtrace_provider_id_t	provid;
	int			i, later = 0;

	static volatile int	in = 0;

	ASSERT(in == 0);
	in = 1;

	mutex_lock(&fasttrap_cleanup_mtx);
	while (fasttrap_cleanup_work) {
		fasttrap_cleanup_work = 0;
		mutex_unlock(&fasttrap_cleanup_mtx);

		later = 0;

		/*
		 * Iterate over all the providers trying to remove the marked
		 * ones. If a provider is marked but not retired, we just
		 * have to take a crack at removing it -- it's no big deal if
		 * we can't.
		 */
		for (i = 0; i < fasttrap_provs.fth_nent; i++) {
			bucket = &fasttrap_provs.fth_table[i];
			mutex_lock(&bucket->ftb_mtx);
			fpp = (fasttrap_provider_t **)&bucket->ftb_data;

			while ((fp = *fpp) != NULL) {
				if (!fp->ftp_marked) {
					fpp = &fp->ftp_next;
					continue;
				}

				mutex_lock(&fp->ftp_mtx);

				/*
				 * If this provider has consumers actively
				 * creating probes (ftp_ccount) or is a USDT
				 * provider (ftp_mcount), we can't unregister
				 * or even condense.
				 */
				if (fp->ftp_ccount != 0 ||
				    fp->ftp_mcount != 0) {
					mutex_unlock(&fp->ftp_mtx);
					fp->ftp_marked = 0;
					continue;
				}

				if (!fp->ftp_retired || fp->ftp_rcount != 0)
					fp->ftp_marked = 0;

				mutex_unlock(&fp->ftp_mtx);

				/*
				 * If we successfully unregister this
				 * provider we can remove it from the hash
				 * chain and free the memory. If our attempt
				 * to unregister fails and this is a retired
				 * provider, increment our flag to try again
				 * pretty soon. If we've consumed more than
				 * half of our total permitted number of
				 * probes call dtrace_condense() to try to
				 * clean out the unenabled probes.
				 */
				provid = fp->ftp_provid;
				if (dtrace_unregister(provid) != 0) {
					if (atomic_read(&fasttrap_total) >
					    fasttrap_max / 2)
						dtrace_condense(provid);
					later += fp->ftp_marked;
					fpp = &fp->ftp_next;
				} else {
					*fpp = fp->ftp_next;
					fasttrap_provider_free(fp);
				}
			}

			mutex_unlock(&bucket->ftb_mtx);
		}

		mutex_lock(&fasttrap_cleanup_mtx);
	}

	ASSERT(fasttrap_cleanup_state != CLEANUP_NONE);

	/*
	 * If we were unable to remove a retired provider, try again after
	 * a second. This situation can occur in certain circumstances where
	 * providers cannot be unregistered even though they have no probes
	 * enabled because of an execution of dtrace -l or something similar.
	 * If the timeout has been disabled (set to 1 because we're trying
	 * to detach), we set fasttrap_cleanup_work to ensure that we'll
	 * get a chance to do that work if and when the timeout is reenabled
	 * (if detach fails).
	 */
	if (later > 0 && fasttrap_cleanup_state != CLEANUP_DEFERRED) {
		struct delayed_work	*dw = container_of(work,
							   struct delayed_work,
							   work);

		fasttrap_cleanup_state = CLEANUP_SCHEDULED;
		schedule_delayed_work(dw, HZ);
	} else if (later > 0) {
		fasttrap_cleanup_work = 1;
	} else
		fasttrap_cleanup_state = CLEANUP_NONE;

	mutex_unlock(&fasttrap_cleanup_mtx);
	in = 0;
}

static DECLARE_DELAYED_WORK(fasttrap_cleanup, fasttrap_pid_cleanup_cb);

/*
 * Activate the asynchronous cleanup mechanism.
 */
static void fasttrap_pid_cleanup(void)
{
        mutex_lock(&fasttrap_cleanup_mtx);
        fasttrap_cleanup_work = 1;
        fasttrap_cleanup_state = CLEANUP_SCHEDULED;
pr_info("FASTTRAP:     -> Scheduling delayed cleanup...\n");
	schedule_delayed_work(&fasttrap_cleanup, 3);
        mutex_unlock(&fasttrap_cleanup_mtx);
}

void fasttrap_provider_retire(pid_t pid, const char *name, int mprov)
{
	fasttrap_provider_t	*fp;
	fasttrap_bucket_t	*bucket;
	dtrace_provider_id_t	provid;

	ASSERT(strlen(name) < sizeof (fp->ftp_name));
pr_info("FASTTRAP: Retiring provider '%s' for PID %d\n", name, pid);

	bucket = &fasttrap_provs.fth_table[FASTTRAP_PROVS_INDEX(pid, name)];
	mutex_lock(&bucket->ftb_mtx);

	for (fp = bucket->ftb_data; fp != NULL; fp = fp->ftp_next) {
		if (fp->ftp_pid == pid && strcmp(fp->ftp_name, name) == 0 &&
		    !fp->ftp_retired)
			break;
	}

	if (fp == NULL) {
		mutex_unlock(&bucket->ftb_mtx);
pr_info("FASTTRAP:   -> Provider not found...\n");
		return;
	}

	mutex_lock(&fp->ftp_mtx);
	ASSERT(!mprov || fp->ftp_mcount > 0);
	if (mprov && --fp->ftp_mcount != 0)  {
		mutex_unlock(&fp->ftp_mtx);
		mutex_unlock(&bucket->ftb_mtx);
		return;
	}

	/*
	 * Mark the provider to be removed in our post-processing step, mark it
	 * retired, and drop the active count on its proc. Marking it indicates
	 * that we should try to remove it; setting the retired flag indicates
	 * that we're done with this provider; dropping the active count on the
	 * proc releases our hold, and when this reaches zero (as it will
	 * during exit or exec) the proc and associated providers become
	 * defunct.
	 *
	 * We obviously need to take the bucket lock before the provider lock
	 * to perform the lookup, but we need to drop the provider lock
	 * before calling into the DTrace framework since we acquire the
	 * provider lock in callbacks invoked from the DTrace framework. The
	 * bucket lock therefore protects the integrity of the provider hash
	 * table.
	 */
	atomic64_dec(&fp->ftp_proc->ftpc_acount);
	ASSERT(atomic64_read(&fp->ftp_proc->ftpc_acount) <
	       fp->ftp_proc->ftpc_rcount);

	fp->ftp_retired = 1;
	fp->ftp_marked = 1;
	provid = fp->ftp_provid;
	mutex_unlock(&fp->ftp_mtx);

	/*
	 * We don't have to worry about invalidating the same provider twice
	 * since fasttrap_provider_lookup() will ignore provider that have
	 * been marked as retired.
	 */
pr_info("FASTTRAP:   -> Invalidating provider...\n");
	dtrace_invalidate(provid);

	mutex_unlock(&bucket->ftb_mtx);

pr_info("FASTTRAP:   -> Calling fasttrap_pid_cleanup()...\n");
	fasttrap_pid_cleanup();
}

void fasttrap_meta_remove(void *arg, dtrace_helper_provdesc_t *dhpv, pid_t pid)
{
	/*
	 * Clean up the USDT provider. There may be active consumers of the
	 * provider busy adding probes, no damage will actually befall the
	 * provider until that count has dropped to zero. This just puts
	 * the provider on death row.
	 */
	fasttrap_provider_retire(pid, dhpv->dthpv_provname, 1);
}

static long fasttrap_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	return -EAGAIN;
}

static int fasttrap_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int fasttrap_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations fasttrap_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = fasttrap_ioctl,
        .open   = fasttrap_open,
        .release = fasttrap_close,
};

static struct miscdevice fasttrap_dev = {
	.minor = DT_DEV_FASTTRAP_MINOR,
	.name = "fasttrap",
	.nodename = "dtrace/provider/fasttrap",
	.fops = &fasttrap_fops,
};

static void fasttrap_init_htable(fasttrap_hash_t *fth, ulong_t nent)
{
	ulong_t		i;

	if ((nent & (nent - 1)) == 0)
		fth->fth_nent = nent;
	else
		fth->fth_nent = 1 << fls(nent);

	ASSERT(fth->fth_nent > 0);

	fth->fth_mask = fth->fth_nent - 1;
	fth->fth_table = kzalloc(fth->fth_nent * sizeof(fasttrap_bucket_t),
				 GFP_KERNEL);

	for (i = 0; i < fth->fth_nent; i++)
		mutex_init(&fth->fth_table[i].ftb_mtx);
}

int fasttrap_dev_init(void)
{
	int	ret = 0;
	ulong_t	nent;

	ret = misc_register(&fasttrap_dev);
	if (ret) {
		pr_err("%s: Can't register misc device %d\n",
		       fasttrap_dev.name, fasttrap_dev.minor);
		goto fail;
	}

#ifdef FIXME
	dtrace_fasttrap_fork_ptr = &fasttrap_fork;
	dtrace_fasttrap_exit_ptr = &fasttrap_exec_exit;
	dtrace_fasttrap_exec_ptr = &fasttrap_exec_exit;
#endif

	fasttrap_max = FASTTRAP_MAX_DEFAULT;
	atomic_set(&fasttrap_total, 0);

	/*
	 * Conjure up the tracepoints hashtable...
	 */
	nent = FASTTRAP_TPOINTS_DEFAULT_SIZE;

	if (nent == 0 || nent > 0x1000000)
		nent = FASTTRAP_TPOINTS_DEFAULT_SIZE;

	fasttrap_init_htable(&fasttrap_tpoints, nent);

	/*
	 * ... and the providers hash table...
	 */
	nent = FASTTRAP_PROVIDERS_DEFAULT_SIZE;
	fasttrap_init_htable(&fasttrap_provs, nent);

	/*
	 * ... and the procs hash table.
	 */
	nent = FASTTRAP_PROCS_DEFAULT_SIZE;
	fasttrap_init_htable(&fasttrap_procs, nent);

fail:
	return ret;
}

void fasttrap_dev_exit(void)
{
	int	fail = 0;
	ulong_t	i;

	/*
	 * Prevent any new timeouts from running by setting fasttrap_timeout
	 * to a non-zero value, and wait for the current timeout to complete.
	 */
	mutex_lock(&fasttrap_cleanup_mtx);
	fasttrap_cleanup_work = 0;

	while (fasttrap_cleanup_state != CLEANUP_DEFERRED) {
		uint_t	tmp;

		tmp = fasttrap_cleanup_state;
		fasttrap_cleanup_state = CLEANUP_DEFERRED;

		if (tmp != CLEANUP_NONE) {
			mutex_unlock(&fasttrap_cleanup_mtx);
			flush_delayed_work_sync(&fasttrap_cleanup);
			mutex_lock(&fasttrap_cleanup_mtx);
		}
	}

	fasttrap_cleanup_work = 0;
	mutex_unlock(&fasttrap_cleanup_mtx);

	/*
	 * Iterate over all of our providers. If there's still a process
	 * that corresponds to that pid, fail to detach.
	 */
	for (i = 0; i < fasttrap_provs.fth_nent; i++) {
		fasttrap_provider_t	**fpp, *fp;
		fasttrap_bucket_t	*bucket = &fasttrap_provs.fth_table[i];

		mutex_lock(&bucket->ftb_mtx);
		fpp = (fasttrap_provider_t **)&bucket->ftb_data;
		while ((fp = *fpp) != NULL) {
			/*
			 * Acquire and release the lock as a simple way of
			 * waiting for any other consumer to finish with
			 * this provider. A thread must first acquire the
			 * bucket lock so there's no chance of another thread
			 * blocking on the provider's lock.
			 */
			mutex_lock(&fp->ftp_mtx);
			mutex_unlock(&fp->ftp_mtx);

			if (dtrace_unregister(fp->ftp_provid) != 0) {
				fail = 1;
				fpp = &fp->ftp_next;
			} else {
				*fpp = fp->ftp_next;
				fasttrap_provider_free(fp);
			}
		}

		mutex_unlock(&bucket->ftb_mtx);
	}

#ifdef FIXME
	if (fail) {
		uint_t	work;

		/*
		 * If we're failing to detach, we need to unblock timeouts
		 * and start a new timeout if any work has accumulated while
		 * we've been unsuccessfully trying to detach.
		 */
		mutex_lock(&fasttrap_cleanup_mtx);
		fasttrap_cleanup_state = CLEANUP_NONE;
		work = fasttrap_cleanup_work;
		mutex_unlock(&fasttrap_cleanup_mtx);

		if (work)
			fasttrap_pid_cleanup();

		dtrace_meta_register("fasttrap", &fasttrap_mops, NULL,
				     &fasttrap_meta_id);

		return (DDI_FAILURE);
	}
#else
	/*
	 * If we fail to detach, we are in lots of trouble because Linux does
	 * not allow us to fail on a module unload.  We try to continue anyway
	 * since triggering an OOPS at this point is even worse.
	 */
	if (fail)
		pr_err("Unrecoverable error removing the fasttrap provider\n");
#endif

#ifdef DEBUG
	mutex_lock(&fasttrap_count_mtx);
	ASSERT(fasttrap_pid_count == 0);
	mutex_unlock(&fasttrap_count_mtx);
#endif

	kfree(fasttrap_tpoints.fth_table);
	fasttrap_tpoints.fth_nent = 0;

	kfree(fasttrap_provs.fth_table);
	fasttrap_provs.fth_nent = 0;

	kfree(fasttrap_procs.fth_table);
	fasttrap_procs.fth_nent = 0;

	/*
	 * We know there are no tracepoints in any process anywhere in
	 * the system so there is no process which has its p_dtrace_count
	 * greater than zero, therefore we know that no thread can actively
	 * be executing code in fasttrap_fork(). Similarly for p_dtrace_probes
	 * and fasttrap_exec() and fasttrap_exit().
	 */
#ifdef FIXME
	ASSERT(dtrace_fasttrap_fork_ptr == &fasttrap_fork);
	dtrace_fasttrap_fork_ptr = NULL;

	ASSERT(dtrace_fasttrap_exec_ptr == &fasttrap_exec_exit);
	dtrace_fasttrap_exec_ptr = NULL;

	ASSERT(dtrace_fasttrap_exit_ptr == &fasttrap_exec_exit);
	dtrace_fasttrap_exit_ptr = NULL;
#endif

	misc_deregister(&fasttrap_dev);
}
