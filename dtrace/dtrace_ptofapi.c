/*
 * FILE:	dtrace_ptofapi.c
 * DESCRIPTION:	Dynamic Tracing: (meta) provider-to-framework API
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

#include <linux/idr.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "dtrace.h"

dtrace_provider_t	*dtrace_provider;
dtrace_meta_t		*dtrace_meta_pid;
dtrace_helpers_t	*dtrace_deferred_pid;

DEFINE_MUTEX(dtrace_provider_lock);
DEFINE_MUTEX(dtrace_meta_lock);

static LIST_HEAD(provider_modules);

#ifdef DT_DBG_PMOD
void dtrace_pmod_debug(void)
{
	dtrace_pmod_t	*pmod;
	int		i = 0;

	mutex_lock(&dtrace_provider_lock);
	if (list_empty(&provider_modules))
		pr_info("provider_modules[] is empty\n");
	else {
		list_for_each_entry(pmod, &provider_modules, list)
			pr_info("provider_modules[%3d] = %p (%s)\n",
				i++, pmod->mod, pmod->mod->name);
	}
	mutex_unlock(&dtrace_provider_lock);
}
#endif /* CONFIG_DT_DEBUG */

/*
 * Register a kernel module as a container for one or more providers.  This is
 * called during module initialization.
 */
void dtrace_pmod_register(dtrace_pmod_t *pmod)
{
	if (pmod->mod == NULL) {
		pr_warn("Provider module without a module?  Ignored!\n");
		return;
	}

	mutex_lock(&dtrace_provider_lock);
	list_add(&pmod->list, &provider_modules);
	mutex_unlock(&dtrace_provider_lock);

	/*
	 * If there already are consumers, we need to increase the reference
	 * count on the provider module with the number of consumers.  Failing
	 * to do so will result in very unhappy module handling when the
	 * reference count drops below zero.
	 */
	mutex_lock(&dtrace_lock);
	if (dtrace_opens) {
		preempt_disable();
		__this_cpu_add(pmod->mod->refptr->incs, dtrace_opens);
		preempt_enable();
	}
	mutex_unlock(&dtrace_lock);
#ifdef DT_DBG_PMOD
	pr_info("After dtrace_pmod_register(%p):\n", pmod);
	dtrace_pmod_debug();
#endif
}
EXPORT_SYMBOL(dtrace_pmod_register);

/*
 * Account for a new consumer that opened /dev/dtrace/dtrace.  We can use
 * __module_get() because a module in the provider_modules list is guaranteed
 * to have been initialized, which means __module_get() cannot fail.
 */
void dtrace_pmod_add_consumer(void)
{
	dtrace_pmod_t	*pmod, *next;

	list_for_each_entry_safe(pmod, next, &provider_modules, list)
		__module_get(pmod->mod);
}

/*
 * Account for a consumer that is done with its work, thereby closing the
 * /dev/dtrace/dtrace device file.
 */
void dtrace_pmod_del_consumer(void)
{
	dtrace_pmod_t	*pmod, *next;

	list_for_each_entry_safe(pmod, next, &provider_modules, list)
		module_put(pmod->mod);
}

/*
 * Deregister a kernel module as a container for providers.  This is called
 * during module exit.
 */
void dtrace_pmod_unregister(dtrace_pmod_t *pmod)
{
	mutex_lock(&dtrace_provider_lock);
	list_del(&pmod->list);
	mutex_unlock(&dtrace_provider_lock);
#ifdef DT_DBG_PMOD
	pr_info("After dtrace_pmod_unregister(%p):\n", pmod);
	dtrace_pmod_debug();
#endif
}
EXPORT_SYMBOL(dtrace_pmod_unregister);

/*
 * Register the calling provider with the DTrace core.  This should generally
 * be called by providers during module initialization.
 */
int dtrace_register(const char *name, const dtrace_pattr_t *pap, uint32_t priv,
		    const cred_t *cr, const dtrace_pops_t *pops, void *arg,
		    dtrace_provider_id_t *idp)
{
	dtrace_provider_t	*provider;

	if (name == NULL || pap == NULL || pops == NULL || idp == NULL) {
		pr_warning("Failed to register provider %s: invalid args\n",
			   name ? name : "<NULL>");
		return -EINVAL;
	}

	if (name[0] == '\0' || dtrace_badname(name)) {
		pr_warning("Failed to register provider %s: invalid name\n",
			   name);
		return -EINVAL;
	}

	if ((pops->dtps_provide == NULL && pops->dtps_provide_module == NULL) ||
	    pops->dtps_enable == NULL || pops->dtps_disable == NULL ||
	    pops->dtps_destroy == NULL ||
	    ((pops->dtps_resume == NULL) != (pops->dtps_suspend == NULL))) {
		pr_warning("Failed to register provider %s: invalid ops\n",
			   name);
		return -EINVAL;
	}

	if (dtrace_badattr(&pap->dtpa_provider) ||
	    dtrace_badattr(&pap->dtpa_mod) ||
	    dtrace_badattr(&pap->dtpa_func) ||
	    dtrace_badattr(&pap->dtpa_name) ||
	    dtrace_badattr(&pap->dtpa_args)) {
		pr_warning("Failed to register provider %s: invalid "
			   "attributes\n", name);
		return -EINVAL;
	}

	if (priv & ~DTRACE_PRIV_ALL) {
		pr_warning("Failed to register provider %s: invalid privilege "
			   "attributes\n", name);
		return -EINVAL;
	}

	if ((priv & DTRACE_PRIV_KERNEL) &&
	    (priv & (DTRACE_PRIV_USER | DTRACE_PRIV_OWNER)) &&
	    pops->dtps_usermode == NULL) {
		pr_warning("Failed to register provider %s: need "
			   "dtps_usermode() op for given privilege "
			   "attributes\n", name);
		return -EINVAL;
	}

	provider = kzalloc(sizeof (dtrace_provider_t), GFP_KERNEL);
	if (provider == NULL)
		return -ENOMEM;
	provider->dtpv_name = dtrace_strdup(name);
	if (provider->dtpv_name == NULL) {
		kfree(provider);
		return -ENOMEM;
	}
	provider->dtpv_attr = *pap;
	provider->dtpv_priv.dtpp_flags = priv;

	if (cr != NULL) {
		provider->dtpv_priv.dtpp_uid = get_cred(cr)->uid;
		put_cred(cr);
	}

	provider->dtpv_pops = *pops;

	if (pops->dtps_provide == NULL) {
		ASSERT(pops->dtps_provide_module != NULL);
		provider->dtpv_pops.dtps_provide =
		    (void (*)(void *, const dtrace_probedesc_t *))dtrace_nullop;
	}

	if (pops->dtps_provide_module == NULL) {
		ASSERT(pops->dtps_provide != NULL);
		provider->dtpv_pops.dtps_provide_module =
		    (void (*)(void *, struct module *))dtrace_nullop;
	}

	if (pops->dtps_suspend == NULL) {
		ASSERT(pops->dtps_resume == NULL);
		provider->dtpv_pops.dtps_suspend =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
		provider->dtpv_pops.dtps_resume =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
	}

	provider->dtpv_arg = arg;
	*idp = (dtrace_provider_id_t)provider;

	if (pops == &dtrace_provider_ops) {
		ASSERT(MUTEX_HELD(&dtrace_provider_lock));
		ASSERT(MUTEX_HELD(&dtrace_lock));
		ASSERT(dtrace_anon.dta_enabling == NULL);

		/*
		 * The DTrace provider must be at the head of the provider
		 * chain.
		 */
		provider->dtpv_next = dtrace_provider;
		dtrace_provider = provider;

		return 0;
	}

	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * If there is at least one provider registered, we'll add this new one
	 * after the first provider.
	 */
	if (dtrace_provider != NULL) {
		provider->dtpv_next = dtrace_provider->dtpv_next;
		dtrace_provider->dtpv_next = provider;
	} else
		dtrace_provider = provider;

	if (dtrace_retained != NULL) {
		dtrace_enabling_provide(provider);

		/*
		 * We must now call dtrace_enabling_matchall() which needs to
		 * acquire cpu_lock and dtrace_lock.  We therefore need to drop
		 * our locks before calling it.
		 */
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_provider_lock);
		dtrace_enabling_matchall();

		return 0;
	}

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);

	return 0;
}
EXPORT_SYMBOL(dtrace_register);

struct unreg_state {
	dtrace_provider_t	*prov;
	dtrace_probe_t		*first;
};

/*
 * Check whether the given probe is still enabled for the given provider.
 */
static int dtrace_unregister_check(int id, void *p, void *data)
{
	dtrace_probe_t		*probe = (dtrace_probe_t *)p;
	struct unreg_state	*st = (struct unreg_state *)data;

	if (probe->dtpr_provider != st->prov)
		return 0;

	if (probe->dtpr_ecb == NULL)
		return 0;

	return -EBUSY;
}

/*
 * Remove the given probe from the hash tables and the probe IDR, if it is
 * associated with the given provider.  The probes are chained for further
 * processing.
 */
static int dtrace_unregister_probe(int id, void *p, void *data)
{
	dtrace_probe_t		*probe = (dtrace_probe_t *)p;
	struct unreg_state	*st = (struct unreg_state *)data;

	if (probe->dtpr_provider != st->prov)
		return 0;

	dtrace_hash_remove(dtrace_bymod, probe);
	dtrace_hash_remove(dtrace_byfunc, probe);
	dtrace_hash_remove(dtrace_byname, probe);

	if (st->first == NULL) {
		st->first = probe;
		probe->dtpr_nextmod = NULL;
	} else {
		probe->dtpr_nextmod = st->first;
		st->first = probe;
	}

	return 0;
}

/*
 * Remove the given probe from the hash tables and the probe IDR, if it is
 * associated with the given provider and if it does not have any enablings.
 * The probes are chained for further processing.
 */
static int dtrace_condense_probe(int id, void *p, void *data)
{
	dtrace_probe_t		*probe = (dtrace_probe_t *)p;
	struct unreg_state	*st = (struct unreg_state *)data;

	if (probe->dtpr_provider != st->prov)
		return 0;

	if (probe->dtpr_ecb == NULL)
		return 0;

	dtrace_hash_remove(dtrace_bymod, probe);
	dtrace_hash_remove(dtrace_byfunc, probe);
	dtrace_hash_remove(dtrace_byname, probe);

	if (st->first == NULL) {
		st->first = probe;
		probe->dtpr_nextmod = NULL;
	} else {
		probe->dtpr_nextmod = st->first;
		st->first = probe;
	}

	return 0;
}

/*
 * Unregister the specified provider from the DTrace core.  This should be
 * called by provider during module cleanup.
 */
int dtrace_unregister(dtrace_provider_id_t id)
{
	dtrace_provider_t	*old = (dtrace_provider_t *)id;
	dtrace_provider_t	*prev = NULL;
	int			err, self = 0;
	dtrace_probe_t		*probe;
	struct unreg_state	st = {
					old,
					NULL
				     };

	if (old->dtpv_pops.dtps_enable ==
	    (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop) {
		/*
		 * When the provider is the DTrace core itself, we're called
		 * with locks already held.
		 */
		ASSERT(old == dtrace_provider);
		ASSERT(MUTEX_HELD(&dtrace_provider_lock));
		ASSERT(MUTEX_HELD(&dtrace_lock));

		self = 1;

		if (dtrace_provider->dtpv_next != NULL) {
			/*
			 * We cannot and should not remove the DTrace provider
			 * if there is any other provider left.
			 */
			return -EBUSY;
		}
	} else {
		mutex_lock(&dtrace_provider_lock);
		/* FIXME: mutex_lock(&mod_lock); */
		mutex_lock(&dtrace_lock);
	}

	/*
	 * If /dev/dtrace/dtrace is still held open by a process, or if there
	 * are anonymous probes that are still enabled, we refuse to deregister
	 * providers, unless the provider has been invalidated explicitly.
	 */
	if (!old->dtpv_defunct &&
	    (dtrace_opens || (dtrace_anon.dta_state != NULL &&
	     dtrace_anon.dta_state->dts_necbs > 0))) {
		if (!self) {
			mutex_unlock(&dtrace_lock);
			/* FIXME: mutex_unlock(&mod_lock); */
			mutex_unlock(&dtrace_provider_lock);
		}

		return -EBUSY;
	}

	/*
	 * Check whether any of the probes associated with this provider are
	 * still enabled (having at least one ECB).  If any are found, we
	 * cannot remove this provider.
	 */
	st.prov = old;
	err = dtrace_probe_for_each(dtrace_unregister_check, &st);
	if (err < 0) {
		if (!self) {
			mutex_unlock(&dtrace_lock);
			/* FIXME: mutex_unlock(&mod_lock); */
			mutex_unlock(&dtrace_provider_lock);
		}

		return err;
	}

	/*
	 * All the probes associated with this provider are disabled.  We can
	 * safely remove these probes from the hashtables and the probe array.
	 * We chain all the probes together for further processing.
	 */
	dtrace_probe_for_each(dtrace_unregister_probe, &st);

	/*
	 * The probes associated with the provider have been removed.  Ensure
	 * synchronization on probe IDR processing.
	 */
	dtrace_sync();

	/*
	 * Now get rid of the actual probes.
	 */
	for (probe = st.first; probe != NULL; probe = st.first) {
		int	probe_id = probe->dtpr_id;

		st.first = probe->dtpr_nextmod;

		old->dtpv_pops.dtps_destroy(old->dtpv_arg, probe_id,
					    probe->dtpr_arg);

		kfree(probe->dtpr_mod);
		kfree(probe->dtpr_func);
		kfree(probe->dtpr_name);
		kmem_cache_free(dtrace_probe_cachep, probe);

		dtrace_probe_remove_id(probe_id);
	}

	if ((prev = dtrace_provider) == old) {
		/*
		 * We are removing the provider at the head of the chain.
		 */
		ASSERT(self);
		ASSERT(old->dtpv_next == NULL);

		dtrace_provider = old->dtpv_next;
	} else {
		while (prev != NULL && prev->dtpv_next != old)
			prev = prev->dtpv_next;

		if (prev == NULL) {
			pr_err("Attempt to unregister non-existent DTrace "
			       "provider %p\n", (void *)id);
			BUG();
		}

		prev->dtpv_next = old->dtpv_next;
	}

	if (!self) {
		mutex_unlock(&dtrace_lock);
		/* FIXME: mutex_unlock(&mod_lock); */
		mutex_unlock(&dtrace_provider_lock);
	}

	kfree(old->dtpv_name);
	kfree(old);

	return 0;
}
EXPORT_SYMBOL(dtrace_unregister);

/*
 * Invalidate the specified provider.  All subsequent probe lookups for the
 * specified provider will fail, but the probes will not be removed.
 */
void dtrace_invalidate(dtrace_provider_id_t id)
{
	dtrace_provider_t	*pvp = (dtrace_provider_t *)id;

	ASSERT(pvp->dtpv_pops.dtps_enable !=
	       (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop);

	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	pvp->dtpv_defunct = 1;

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
}
EXPORT_SYMBOL(dtrace_invalidate);

/*
 * Indicate whether or not DTrace has attached.
 */
int dtrace_attached(void)
{
	/*
	 * dtrace_provider will be non-NULL iff the DTrace driver has
	 * attached.  (It's non-NULL because DTrace is always itself a
	 * provider.)
	 */
	return dtrace_provider != NULL;
}
EXPORT_SYMBOL(dtrace_attached);

/*
 * Remove all the unenabled probes for the given provider.  This function is
 * not unlike dtrace_unregister(), except that it doesn't remove the provider
 * -- just as many of its associated probes as it can.
 */
int dtrace_condense(dtrace_provider_id_t id)
{
	dtrace_provider_t	*prov = (dtrace_provider_t *)id;
	dtrace_probe_t		*probe;
	struct unreg_state	st = {
					prov,
					NULL
				     };

	/*
	 * Make sure this isn't the DTrace provider itself.
	 */
	ASSERT(prov->dtpv_pops.dtps_enable !=
	       (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop);

	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * Attempt to destroy the probes associated with this provider.
	 */
	dtrace_probe_for_each(dtrace_condense_probe, &st);

	/*
	 * The probes associated with the provider have been removed.  Ensure
	 * synchronization on probe IDR processing.
	 */
	dtrace_sync();

	/*
	 * Now get rid of the actual probes.
	 */
	for (probe = st.first; probe != NULL; probe = st.first) {
		int	probe_id = probe->dtpr_id;

		st.first = probe->dtpr_nextmod;

		prov->dtpv_pops.dtps_destroy(prov->dtpv_arg, probe_id,
					     probe->dtpr_arg);

		kfree(probe->dtpr_mod);
		kfree(probe->dtpr_func);
		kfree(probe->dtpr_name);
		kfree(probe);

		dtrace_probe_remove_id(probe_id);
	}

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);

	return 0;
}
EXPORT_SYMBOL(dtrace_condense);

int dtrace_meta_register(const char *name, const dtrace_mops_t *mops,
			 void *arg, dtrace_meta_provider_id_t *idp)
{
	dtrace_meta_t		*meta;
	dtrace_helpers_t	*help, *next;
	int			i;

	*idp = DTRACE_METAPROVNONE;

	/*
	 * We strictly don't need the name, but we hold onto it for
	 * debuggability. All hail error queues!
	 */
	if (name == NULL) {
		pr_warn("failed to register meta-provider: invalid name\n");
		return -EINVAL;
	}

	if (mops == NULL ||
	    mops->dtms_create_probe == NULL ||
	    mops->dtms_provide_pid == NULL ||
	    mops->dtms_remove_pid == NULL) {
		pr_warn("failed to register meta-register %s: invalid ops\n",
			name);
		return -EINVAL;
	}

	meta = kzalloc(sizeof(dtrace_meta_t), GFP_KERNEL);
	if (meta == NULL)
		return -ENOMEM;
	meta->dtm_mops = *mops;
	meta->dtm_name = kmalloc(strlen(name) + 1, GFP_KERNEL);
	if (meta->dtm_name == NULL) {
		kfree(meta);
		return -ENOMEM;
	}
	strcpy(meta->dtm_name, name);
	meta->dtm_arg = arg;

	mutex_lock(&dtrace_meta_lock);
	mutex_lock(&dtrace_lock);

	if (dtrace_meta_pid != NULL) {
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_meta_lock);
		pr_warn("failed to register meta-register %s: user-land "
			"meta-provider exists", name);
		kfree(meta->dtm_name);
		kfree(meta);
		return -EINVAL;
	}

	dtrace_meta_pid = meta;
	*idp = (dtrace_meta_provider_id_t)meta;

	/*
	 * If there are providers and probes ready to go, pass them
	 * off to the new meta provider now.
	 */
	help = dtrace_deferred_pid;
	dtrace_deferred_pid = NULL;

	mutex_unlock(&dtrace_lock);

	while (help != NULL) {
		for (i = 0; i < help->dthps_nprovs; i++) {
			dtrace_helper_provide(&help->dthps_provs[i]->dthp_prov,
					      help->dthps_pid);
		}

		next = help->dthps_next;
		help->dthps_next = NULL;
		help->dthps_prev = NULL;
		help->dthps_deferred = 0;
		help = next;
	}

	mutex_unlock(&dtrace_meta_lock);

	return 0;
}
EXPORT_SYMBOL(dtrace_meta_register);

int dtrace_meta_unregister(dtrace_meta_provider_id_t id)
{
	dtrace_meta_t	**pp, *old = (dtrace_meta_t *)id;

	mutex_lock(&dtrace_meta_lock);
	mutex_lock(&dtrace_lock);

	if (old == dtrace_meta_pid) {
		pp = &dtrace_meta_pid;
	} else {
		pr_err("Attempt to unregister non-existent DTrace meta-"
		       "provider %p\n", (void *)old);
		BUG();
	}

	if (old->dtm_count != 0) {
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_meta_lock);
		return -EBUSY;
	}

	*pp = NULL;

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_meta_lock);

	kfree(old->dtm_name);
	kfree(old);

	return 0;
}
EXPORT_SYMBOL(dtrace_meta_unregister);
