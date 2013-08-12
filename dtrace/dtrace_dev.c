/*
 * FILE:	dtrace_dev.c
 * DESCRIPTION:	Dynamic Tracing: device file handling
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

#include <linux/delay.h>
#include <dtrace/types.h>
#include <linux/dtrace/ioctl.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include "ctf_api.h"
#include "dtrace.h"
#include "dtrace_dev.h"
#include <linux/dtrace/ioctl_debug.h>

uint32_t			dtrace_helptrace_next = 0;
uint32_t			dtrace_helptrace_nlocals;
char				*dtrace_helptrace_buffer;
int				dtrace_helptrace_bufsize = 512 * 1024;

#ifdef CONFIG_DT_DEBUG
int				dtrace_helptrace_enabled = 1;
#else
int				dtrace_helptrace_enabled = 0;
#endif

int				dtrace_opens;
int				dtrace_err_verbose;

dtrace_pops_t			dtrace_provider_ops = {
	(void (*)(void *, const dtrace_probedesc_t *))dtrace_nullop,
	(void (*)(void *, struct module *))dtrace_nullop,
	(int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	NULL,
	NULL,
	NULL,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop
};

dtrace_toxrange_t		*dtrace_toxrange;
int				dtrace_toxranges;

static size_t			dtrace_retain_max = 1024;

static int			dtrace_toxranges_max;

static dtrace_pattr_t		dtrace_provider_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

void (*dtrace_modload)(struct module *);
void (*dtrace_modunload)(struct module *);

void dtrace_nullop(void)
{
}

int dtrace_enable_nullop(void)
{
	return 0;
}

static int dtrace_open(struct inode *inode, struct file *file)
{
	dtrace_state_t	*state;
	uint32_t	priv;
	uid_t		uid;

	dtrace_cred2priv(file->f_cred, &priv, &uid);
	if (priv == DTRACE_PRIV_NONE)
		return -EACCES;

#ifdef CONFIG_DT_DEBUG
	dtrace_ioctl_sizes();
#endif
	mutex_lock(&dtrace_provider_lock);
	dtrace_probe_provide(NULL, NULL);
	mutex_unlock(&dtrace_provider_lock);

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);
	dtrace_opens++;
	dtrace_membar_producer();

#ifdef FIXME
	/*
	 * Is this relevant for Linux?  Is there an equivalent?
	 */
	if (kdi_dtrace_set(KDI_DTSET_DTRACE_ACTIVATE) != 0) {
		dtrace_opens--;
		mutex_unlock(&cpu_lock);
		mutex_unlock(&dtrace_lock);
		return -EBUSY;
	}
#endif

	state = dtrace_state_create(file);
	mutex_unlock(&cpu_lock);

	if (state == NULL) {
#ifdef FIXME
		if (--dtrace_opens == 0 && dtrace_anon.dta_enabling == NULL)
			(void)kdi_dtrace_set(KDI_DTSET_DTRACE_DEACTIVATE);
#endif

		mutex_unlock(&dtrace_lock);

		return -EAGAIN;
	}

	file->private_data = state;

	/*
	 * We only want to enable trap handling once, so we'll do it for the
	 * first open of the DTrace core device file.
	 * FIXME: If anonymous tracing is enabled, that would have enabled trap
	 *	  handling already, so we should not do it here again.
	 */
	if (dtrace_opens == 1)
		dtrace_enable();

	dtrace_pmod_add_consumer();

	mutex_unlock(&dtrace_lock);

	return 0;
}

static long dtrace_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	dtrace_state_t	*state = (dtrace_state_t *)file->private_data;
	int		rval;
	void __user	*argp = (void __user *)arg;

	if (state->dts_anon) {
		ASSERT(dtrace_anon.dta_state == NULL);
		state = state->dts_anon;
	}

	switch (cmd) {
	case DTRACEIOC_PROVIDER: {
		dtrace_providerdesc_t	pvd;
		dtrace_provider_t	*pvp;

		dt_dbg_ioctl("IOCTL PROVIDER (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&pvd, argp, sizeof(pvd)) != 0)
			return -EFAULT;

		pvd.dtvd_name[DTRACE_PROVNAMELEN - 1] = '\0';
		mutex_lock(&dtrace_provider_lock);

		for (pvp = dtrace_provider; pvp != NULL; pvp = pvp->dtpv_next) {
			if (strcmp(pvp->dtpv_name, pvd.dtvd_name) == 0)
				break;
		}

		mutex_unlock(&dtrace_provider_lock);

		if (pvp == NULL)
			return -ESRCH;

		memcpy(&pvd.dtvd_priv, &pvp->dtpv_priv,
		       sizeof(dtrace_ppriv_t));
		memcpy(&pvd.dtvd_attr, &pvp->dtpv_attr,
		       sizeof(dtrace_pattr_t));

		if (copy_to_user(argp, &pvd, sizeof(pvd)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_EPROBE: {
		dtrace_eprobedesc_t	epdesc;
		dtrace_ecb_t		*ecb;
		dtrace_action_t		*act;
		void			*buf;
		size_t			size;
		uint8_t			*dest;
		int			nrecs;

		dt_dbg_ioctl("IOCTL EPROBE (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&epdesc, argp, sizeof(epdesc)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);

		if ((ecb = dtrace_epid2ecb(state, epdesc.dtepd_epid)) == NULL) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		if (ecb->dte_probe == NULL) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		epdesc.dtepd_probeid = ecb->dte_probe->dtpr_id;
		epdesc.dtepd_uarg = ecb->dte_uarg;
		epdesc.dtepd_size = ecb->dte_size;

		nrecs = epdesc.dtepd_nrecs;
		epdesc.dtepd_nrecs = 0;
		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			epdesc.dtepd_nrecs++;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copy_to_user(), below.
		 */
		size = sizeof(dtrace_eprobedesc_t) +
		       (epdesc.dtepd_nrecs * sizeof(dtrace_recdesc_t));

		buf = vmalloc(size);
		if (buf == NULL)
			return -ENOMEM;

		dest = buf;
		memcpy(dest, &epdesc, sizeof(epdesc));
		dest += offsetof(dtrace_eprobedesc_t, dtepd_rec[0]);

		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			if (nrecs-- == 0)
				break;

			memcpy(dest, &act->dta_rec, sizeof(dtrace_recdesc_t));
			dest += sizeof(dtrace_recdesc_t);
		}

		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, buf,
				 (uintptr_t)(dest - (uint8_t *)buf)) != 0) {
			vfree(buf);
			return -EFAULT;
		}

		vfree(buf);
		return 0;
	}

	case DTRACEIOC_AGGDESC: {
		dtrace_aggdesc_t	aggdesc;
		dtrace_action_t		*act;
		dtrace_aggregation_t	*agg;
		int			nrecs;
		uint32_t		offs;
		dtrace_recdesc_t	*lrec;
		void			*buf;
		size_t			size;
		uint8_t			*dest;

		dt_dbg_ioctl("IOCTL AGGDESC (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&aggdesc, argp, sizeof(aggdesc)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);

		if ((agg = dtrace_aggid2agg(state, aggdesc.dtagd_id)) == NULL) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		aggdesc.dtagd_epid = agg->dtag_ecb->dte_epid;

		nrecs = aggdesc.dtagd_nrecs;
		aggdesc.dtagd_nrecs = 0;

		offs = agg->dtag_base;
		lrec = &agg->dtag_action.dta_rec;
		aggdesc.dtagd_size = lrec->dtrd_offset + lrec->dtrd_size -
				     offs;

		for (act = agg->dtag_first; ; act = act->dta_next) {
			ASSERT(act->dta_intuple ||
			       DTRACEACT_ISAGG(act->dta_kind));

			/*
			 * If this action has a record size of zero, it
			 * denotes an argument to the aggregating action.
			 * Because the presence of this record doesn't (or
			 * shouldn't) affect the way the data is interpreted,
			 * we don't copy it out to save user-level the
			 * confusion of dealing with a zero-length record.
			 */
			if (act->dta_rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			aggdesc.dtagd_nrecs++;

			if (act == &agg->dtag_action)
				break;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copyout(), below.
		 */
		size = sizeof(dtrace_aggdesc_t) +
		       (aggdesc.dtagd_nrecs * sizeof(dtrace_recdesc_t));

		buf = vmalloc(size);
		if (buf == NULL)
			return -ENOMEM;

		dest = buf;
		memcpy(dest, &aggdesc, sizeof(aggdesc));
		dest += offsetof(dtrace_aggdesc_t, dtagd_rec[0]);

		for (act = agg->dtag_first; ; act = act->dta_next) {
			dtrace_recdesc_t	rec = act->dta_rec;

			/*
			 * See the comment in the above loop for why we pass
			 * over zero-length records.
			 */
			if (rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			if (nrecs-- == 0)
				break;

			rec.dtrd_offset -= offs;
			memcpy(dest, &rec, sizeof(rec));
			dest += sizeof(dtrace_recdesc_t);

			if (act == &agg->dtag_action)
				break;
		}

		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, buf,
				 (uintptr_t)(dest - (uint8_t *)buf)) != 0) {
			vfree(buf);
			return -EFAULT;
		}

		vfree(buf);
		return 0;
	}

	case DTRACEIOC_ENABLE: {
		dof_hdr_t		*dof;
		dtrace_enabling_t	*enab = NULL;
		dtrace_vstate_t		*vstate;
		int			err = 0;
		int			rv;

		dt_dbg_ioctl("IOCTL ENABLE (cmd %#x), argp %p\n", cmd, argp);

		rv = 0;

		/*
		 * If a NULL argument has been passed, we take this as our
		 * cue to reevaluate our enablings.
		 */
		if (argp == NULL) {
			dtrace_enabling_matchall();

			return 0;
		}

		if ((dof = dtrace_dof_copyin(argp, &rval)) == NULL)
			return rval;

		mutex_lock(&cpu_lock);
		mutex_lock(&dtrace_lock);
		vstate = &state->dts_vstate;

		if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return -EBUSY;
		}

		if (dtrace_dof_slurp(dof, vstate, file->f_cred, &enab, 0,
				     TRUE) != 0) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return -EINVAL;
		}

		if ((rval = dtrace_dof_options(dof, state)) != 0) {
			dtrace_enabling_destroy(enab);
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return rval;
		}

		if ((err = dtrace_enabling_match(enab, &rv)) == 0)
			err = dtrace_enabling_retain(enab);
		else
			dtrace_enabling_destroy(enab);

		mutex_unlock(&dtrace_lock);
		mutex_unlock(&cpu_lock);
		dtrace_dof_destroy(dof);

		return err == 0 ? rv : err;
	}

	case DTRACEIOC_REPLICATE: {
		dtrace_repldesc_t	desc;
		dtrace_probedesc_t	*match = &desc.dtrpd_match;
		dtrace_probedesc_t	*create = &desc.dtrpd_create;
		int			err;

		dt_dbg_ioctl("IOCTL REPLICATE (cmd %#x), argp %p\n",
			     cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		match->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		match->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		match->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		match->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		create->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		create->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		create->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		create->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		mutex_lock(&dtrace_lock);
		err = dtrace_enabling_replicate(state, match, create);
		mutex_unlock(&dtrace_lock);

		return err;
	}

	case DTRACEIOC_PROBEMATCH:
	case DTRACEIOC_PROBES: {
		dtrace_probe_t		*probe = NULL;
		dtrace_probedesc_t	desc;
		dtrace_probekey_t	pkey;
		uint32_t		priv;
		uid_t			uid;

		dt_dbg_ioctl("IOCTL %s (cmd %#x), argp %p\n",
			     cmd == DTRACEIOC_PROBES ? "PROBES"
						     : "PROBEMATCH",
			     cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		desc.dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		desc.dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		desc.dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		desc.dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		/*
		 * Before we attempt to match this probe, we want to give
		 * all providers the opportunity to provide it.
		 */
		if (desc.dtpd_id == DTRACE_IDNONE) {
			mutex_lock(&dtrace_provider_lock);
			dtrace_probe_provide(&desc, NULL);
			mutex_unlock(&dtrace_provider_lock);
		}

		if (cmd == DTRACEIOC_PROBEMATCH)  {
			dtrace_probekey(&desc, &pkey);
			pkey.dtpk_id = DTRACE_IDNONE;
		}

		dtrace_cred2priv(file->f_cred, &priv, &uid);

		mutex_lock(&dtrace_lock);

		if (cmd == DTRACEIOC_PROBEMATCH)  {
			int	m = 0;

			while ((probe = dtrace_probe_get_next(desc.dtpd_id))
			       != NULL) {
				if ((m = dtrace_match_probe(
						probe, &pkey, priv, uid)))
					break;

				desc.dtpd_id = probe->dtpr_id + 1;
			}

			if (m < 0) {
				mutex_unlock(&dtrace_lock);
				return -EINVAL;
			}
		} else {
			while ((probe = dtrace_probe_get_next(desc.dtpd_id))
			       != NULL) {
				if (dtrace_match_priv(probe, priv, uid))
					break;

				desc.dtpd_id = probe->dtpr_id + 1;
			}
		}

		if (probe == NULL) {
			mutex_unlock(&dtrace_lock);
			return -ESRCH;
		}

		dtrace_probe_description(probe, &desc);
		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_PROBEARG: {
		dtrace_argdesc_t	desc;
		dtrace_probe_t		*probe;
		dtrace_provider_t	*prov;

		dt_dbg_ioctl("IOCTL PROBEARG (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		if (desc.dtargd_id == DTRACE_IDNONE)
			return -EINVAL;

		if (desc.dtargd_ndx == DTRACE_ARGNONE)
			return -EINVAL;

		mutex_lock(&dtrace_provider_lock);
//		mutex_lock(&module_mutex); /* FIXME */
		mutex_lock(&dtrace_lock);

		probe = dtrace_probe_lookup_id(desc.dtargd_id);
		if (probe == NULL) {
			mutex_unlock(&dtrace_lock);
//			mutex_unlock(&module_mutex); /* FIXME */
			mutex_unlock(&dtrace_provider_lock);

			return -EINVAL;
		}

		mutex_unlock(&dtrace_lock);

		prov = probe->dtpr_provider;

		if (prov->dtpv_pops.dtps_getargdesc == NULL) {
			/*
			 * There isn't any typed information for this probe.
			 * Set the argument number to DTRACE_ARGNONE.
			 */
			desc.dtargd_ndx = DTRACE_ARGNONE;
		} else {
			desc.dtargd_native[0] = '\0';
			desc.dtargd_xlate[0] = '\0';
			desc.dtargd_mapping = desc.dtargd_ndx;

			prov->dtpv_pops.dtps_getargdesc(
				prov->dtpv_arg, probe->dtpr_id,
				probe->dtpr_arg, &desc);
		}

//		mutex_unlock(&module_mutex); /* FIXME */
		mutex_unlock(&dtrace_provider_lock);

		if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_GO: {
		processorid_t	cpuid;

		dt_dbg_ioctl("IOCTL GO (cmd %#x), argp %p\n", cmd, argp);

		rval = dtrace_state_go(state, &cpuid);

		if (rval != 0)
			return rval;

		if (copy_to_user(argp, &cpuid, sizeof(cpuid)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_STOP: {
		processorid_t	cpuid;

		dt_dbg_ioctl("IOCTL STOP (cmd %#x), argp %p\n", cmd, argp);

		mutex_lock(&dtrace_lock);
		rval = dtrace_state_stop(state, &cpuid);
		mutex_unlock(&dtrace_lock);

		if (rval != 0)
			return rval;

		if (copy_to_user(argp, &cpuid, sizeof(cpuid)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_DOFGET: {
		dof_hdr_t	hdr, *dof;
		uint64_t	len;

		dt_dbg_ioctl("IOCTL DOFGET (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&hdr, argp, sizeof(hdr)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);
		dof = dtrace_dof_create(state);
		mutex_unlock(&dtrace_lock);
		if (dof == NULL)
			return -ENOMEM;

		len = min(hdr.dofh_loadsz, dof->dofh_loadsz);
		rval = copy_to_user(argp, dof, len);
		dtrace_dof_destroy(dof);

		return rval == 0 ? 0 : -EFAULT;
	}

	case DTRACEIOC_AGGSNAP:
	case DTRACEIOC_BUFSNAP: {
		dtrace_bufdesc_t	desc;
		caddr_t			cached;
		dtrace_buffer_t		*buf;

		dt_dbg_ioctl("IOCTL %s (cmd %#x), argp %p\n",
			     cmd == DTRACEIOC_AGGSNAP ? "AGGSNAP"
						      : "BUFSNAP",
			     cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		if (desc.dtbd_cpu < 0 || desc.dtbd_cpu >= NR_CPUS)
			return -EINVAL;

		mutex_lock(&dtrace_lock);

		if (cmd == DTRACEIOC_BUFSNAP)
			buf = &state->dts_buffer[desc.dtbd_cpu];
		else
			buf = &state->dts_aggbuffer[desc.dtbd_cpu];

		if (buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL)) {
			size_t	sz = buf->dtb_offset;

			if (state->dts_activity != DTRACE_ACTIVITY_STOPPED) {
				mutex_unlock(&dtrace_lock);
				return -EBUSY;
			}

			/*
			 * If this buffer has already been consumed, we're
			 * going to indicate that there's nothing left here
			 * to consume.
			 */
			if (buf->dtb_flags & DTRACEBUF_CONSUMED) {
				mutex_unlock(&dtrace_lock);

				desc.dtbd_size = 0;
				desc.dtbd_drops = 0;
				desc.dtbd_errors = 0;
				desc.dtbd_oldest = 0;
				sz = sizeof(desc);

				if (copy_to_user(argp, &desc, sz) != 0)
					return -EFAULT;

				return 0;
			}

			/*
			 * If this is a ring buffer that has wrapped, we want
			 * to copy the whole thing out.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				dtrace_buffer_polish(buf);
				sz = buf->dtb_size;
			}

			if (copy_to_user(desc.dtbd_data, buf->dtb_tomax,
					 sz) != 0) {
				mutex_unlock(&dtrace_lock);
				return -EFAULT;
			}

			desc.dtbd_size = sz;
			desc.dtbd_drops = buf->dtb_drops;
			desc.dtbd_errors = buf->dtb_errors;
			desc.dtbd_oldest = buf->dtb_xamot_offset;

			mutex_unlock(&dtrace_lock);

			if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
				return -EFAULT;

			buf->dtb_flags |= DTRACEBUF_CONSUMED;

			return 0;
		}

		if (buf->dtb_tomax == NULL) {
			ASSERT(buf->dtb_xamot == NULL);
			mutex_unlock(&dtrace_lock);
			return -ENOENT;
		}

		cached = buf->dtb_tomax;

		dtrace_xcall(desc.dtbd_cpu,
			     (dtrace_xcall_t)dtrace_buffer_switch, buf);

		state->dts_errors += buf->dtb_xamot_errors;

		/*
		 * If the buffers did not actually switch, then the cross call
		 * did not take place -- presumably because the given CPU is
		 * not in the ready set.  If this is the case, we'll return
		 * ENOENT.
		 */
		if (buf->dtb_tomax == cached) {
			ASSERT(buf->dtb_xamot != cached);
			mutex_unlock(&dtrace_lock);
			return -ENOENT;
		}

		ASSERT(cached == buf->dtb_xamot);

		/*
		 * We have our snapshot; now copy it out.
		 */
		if (copy_to_user(desc.dtbd_data, buf->dtb_xamot,
				 buf->dtb_xamot_offset) != 0) {
			mutex_unlock(&dtrace_lock);
			return -EFAULT;
		}

		desc.dtbd_size = buf->dtb_xamot_offset;
		desc.dtbd_drops = buf->dtb_xamot_drops;
		desc.dtbd_errors = buf->dtb_xamot_errors;
		desc.dtbd_oldest = 0;

		mutex_unlock(&dtrace_lock);

		/*
		 * Finally, copy out the buffer description.
		 */
		if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_CONF: {
		dtrace_conf_t	conf;

		dt_dbg_ioctl("IOCTL CONF (cmd %#x), argp %p\n", cmd, argp);

		memset(&conf, 0, sizeof(conf));
		conf.dtc_difversion = DIF_VERSION;
		conf.dtc_difintregs = DIF_DIR_NREGS;
		conf.dtc_diftupregs = DIF_DTR_NREGS;
		conf.dtc_ctfmodel = CTF_MODEL_NATIVE;
		conf.dtc_maxbufs = nr_cpu_ids;

		if (copy_to_user(argp, &conf, sizeof(conf)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_STATUS: {
		dtrace_status_t	stat;
		dtrace_dstate_t	*dstate;
		int		i, j;
		uint64_t	nerrs;

		dt_dbg_ioctl("IOCTL STATUS (cmd %#x), argp %p\n", cmd, argp);

		/*
		 * See the comment in dtrace_state_deadman() for the reason
		 * for setting dts_laststatus to INT64_MAX before setting
		 * it to the correct value.
		 */
		state->dts_laststatus = ns_to_ktime(INT64_MAX);
		dtrace_membar_producer();
		state->dts_laststatus = dtrace_gethrtime();

		memset(&stat, 0, sizeof(stat));

		mutex_lock(&dtrace_lock);

		if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE) {
			mutex_unlock(&dtrace_lock);
			return -ENOENT;
		}

		if (state->dts_activity == DTRACE_ACTIVITY_DRAINING)
			stat.dtst_exiting = 1;

		nerrs = state->dts_errors;
		dstate = &state->dts_vstate.dtvs_dynvars;

		for (i = 0; i < NR_CPUS; i++) {
			dtrace_dstate_percpu_t	*dcpu = &dstate->dtds_percpu[i];

			stat.dtst_dyndrops += dcpu->dtdsc_drops;
			stat.dtst_dyndrops_dirty += dcpu->dtdsc_dirty_drops;
			stat.dtst_dyndrops_rinsing += dcpu->dtdsc_rinsing_drops;

			if (state->dts_buffer[i].dtb_flags & DTRACEBUF_FULL)
				stat.dtst_filled++;

			nerrs += state->dts_buffer[i].dtb_errors;

			for (j = 0; j < state->dts_nspeculations; j++) {
				dtrace_speculation_t	*spec;
				dtrace_buffer_t		*buf;

				spec = &state->dts_speculations[j];
				buf = &spec->dtsp_buffer[i];
				stat.dtst_specdrops += buf->dtb_xamot_drops;
			}
		}

		stat.dtst_specdrops_busy = state->dts_speculations_busy;
		stat.dtst_specdrops_unavail = state->dts_speculations_unavail;
		stat.dtst_stkstroverflows = state->dts_stkstroverflows;
		stat.dtst_dblerrors = state->dts_dblerrors;
		stat.dtst_killed = (state->dts_activity ==
				    DTRACE_ACTIVITY_KILLED);
		stat.dtst_errors = nerrs;

		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, &stat, sizeof(stat)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_FORMAT: {
		dtrace_fmtdesc_t	fmt;
		char			*str;
		int			len;

		dt_dbg_ioctl("IOCTL FORMAT (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&fmt, argp, sizeof (fmt)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);

		if (fmt.dtfd_format == 0 ||
		    fmt.dtfd_format > state->dts_nformats) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		/*
		 * Format strings are allocated contiguously and they are
		 * never freed; if a format index is less than the number
		 * of formats, we can assert that the format map is non-NULL
		 * and that the format for the specified index is non-NULL.
		 */
		ASSERT(state->dts_formats != NULL);
		str = state->dts_formats[fmt.dtfd_format - 1];
		ASSERT(str != NULL);

		len = strlen(str) + 1;

		if (len > fmt.dtfd_length) {
			fmt.dtfd_length = len;

			if (copy_to_user(argp, &fmt, sizeof (fmt)) != 0) {
				mutex_unlock(&dtrace_lock);
				return -EINVAL;
			}
		} else {
			if (copy_to_user(fmt.dtfd_string, str, len) != 0) {
				mutex_unlock(&dtrace_lock);
				return -EINVAL;
			}
		}

		mutex_unlock(&dtrace_lock);

		return 0;
	}

	default:
		dt_dbg_ioctl("IOCTL *UNKNOWN* (cmd %#x), argp %p\n",
			     cmd, argp);
		break;
	}

	return -ENOTTY;
}

#ifdef CONFIG_DT_DEBUG

void dtrace_size_dbg_print(const char *type, size_t size)
{
	dt_dbg_ioctl("Size of %s: %lx\n", type, size);
}

#endif

static int dtrace_close(struct inode *inode, struct file *file)
{
	dtrace_state_t	*state = file->private_data;

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * If there is anonymous state, destroy that first.
	 */
	if (state->dts_anon) {
		ASSERT(dtrace_anon.dta_state == NULL);

		dtrace_state_destroy(state->dts_anon);
	}

	dtrace_state_destroy(state);
	ASSERT(dtrace_opens > 0);

#ifdef FIXME
	if (--dtrace_opens == 0 && dtrace_anon.dta_enabling == NULL)
		(void)kdi_dtrace_set(KDI_DTSET_DTRACE_DEACTIVATE);
#else
	/*
	 * Once the last user of DTrace is gone, we can safely disable trap
	 * handling.
	 * FIXME: We should not disable it if anonymous tracing is enabled as
	 *	  we still have probes running in that case even without any
	 *	  client holding the device file open.
	 */
	if (--dtrace_opens == 0)
		dtrace_disable();
#endif

	dtrace_pmod_del_consumer();

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&cpu_lock);

	return 0;
}

static int dtrace_helper_open(struct inode *inode, struct file *file)
{
	return 0;
}

static long dtrace_helper_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	int		rval;
	dof_helper_t	help, *dhp = NULL;
	void __user	*argp = (void __user *)arg;

	switch (cmd) {
	case DTRACEHIOC_ADDDOF:
		dt_dbg_ioctl("Helper IOCTL ADDDOF (cmd %#x), argp %p\n",
			     cmd, argp);

		if (copy_from_user(&help, argp, sizeof(help)) != 0) {
			dtrace_dof_error(NULL, "failed to copy DOF helper");
			return -EFAULT;
		}

		dhp = &help;
		argp = (void __user *)help.dofhp_dof;

		/* fallthrough */

	case DTRACEHIOC_ADD: {
		dof_hdr_t	*dof = dtrace_dof_copyin(argp, &rval);

		if (dof == NULL)
			return rval;

		if (cmd == DTRACEHIOC_ADD)
			dt_dbg_ioctl("Helper IOCTL ADD (cmd %#x), argp %p\n",
				     cmd, argp);

		mutex_lock(&dtrace_lock);

		/*
		 * The dtrace_helper_slurp() routine takes responsibility for
		 * the dof -- it may free it now, or it may save it and free it
		 * later.
		 */
		if ((rval = dtrace_helper_slurp(dof, dhp)) == -1)
			rval = -EINVAL;

		mutex_unlock(&dtrace_lock);

		dt_dbg_ioctl("Helper IOCTL %s returning %d\n",
			     cmd == DTRACEHIOC_ADD ? "ADD"
						   : "ADDDOF",
			     rval);

		return rval;
	}

	case DTRACEHIOC_REMOVE:
		dt_dbg_ioctl("Helper IOCTL REMOVE (cmd %#x), argp %p\n",
			     cmd, argp);

		mutex_lock(&dtrace_lock);

		rval = dtrace_helper_destroygen((uintptr_t)argp);

		mutex_unlock(&dtrace_lock);

		dt_dbg_ioctl("Helper IOCTL REMOVE returning %d\n", rval);

		return rval;
	default:
		break;
	}

	return -ENOTTY;
}

static int dtrace_helper_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations dtrace_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = dtrace_ioctl,
        .open   = dtrace_open,
        .release = dtrace_close,
};

static const struct file_operations helper_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = dtrace_helper_ioctl,
        .open   = dtrace_helper_open,
        .release = dtrace_helper_close,
};

static struct miscdevice dtrace_dev = {
	.minor = DT_DEV_DTRACE_MINOR,
	.name = "dtrace",
	.nodename = "dtrace/dtrace",
	.fops = &dtrace_fops,
};

static struct miscdevice helper_dev = {
	.minor = DT_DEV_HELPER_MINOR,
	.name = "helper",
	.nodename = "dtrace/helper",
	.fops = &helper_fops,
};

static void
dtrace_module_loaded(struct module *module)
{
	dtrace_provider_t *prv;

	mutex_lock(&dtrace_provider_lock);
	/* FIXME: mutex_lock(&mod_lock); */

	//ASSERT(ctl->mod_busy);

	/*
	 * We're going to call each providers per-module provide operation
	 * specifying only this module.
	 */
	for (prv = dtrace_provider; prv != NULL; prv = prv->dtpv_next)
		prv->dtpv_pops.dtps_provide_module(prv->dtpv_arg, module);

	/* FIXME: mutex_unlock(&mod_lock); */
	mutex_unlock(&dtrace_provider_lock);

	/*
	 * If we have any retained enablings, we need to match against them.
	 * Enabling probes requires that cpu_lock be held, and we cannot hold
	 * cpu_lock here -- it is legal for cpu_lock to be held when loading a
	 * module.  (In particular, this happens when loading scheduling
	 * classes.)  So if we have any retained enablings, we need to dispatch
	 * our task queue to do the match for us.
	 */
	mutex_lock(&dtrace_lock);

	if (dtrace_retained == NULL) {
		mutex_unlock(&dtrace_lock);
		return;
	}

#ifdef FIXME
	/* FIXME: maybe convert to a Linux workqueue */
	(void) taskq_dispatch(dtrace_taskq,
	    (task_func_t *)dtrace_enabling_matchall, NULL, TQ_SLEEP);
#else
	dtrace_enabling_matchall();
#endif

	mutex_unlock(&dtrace_lock);

	/*
	 * And now, for a little heuristic sleaze:  in general, we want to
	 * match modules as soon as they load.  However, we cannot guarantee
	 * this, because it would lead us to the lock ordering violation
	 * outlined above.  The common case, of course, is that cpu_lock is
	 * _not_ held -- so we delay here for a clock tick, hoping that that's
	 * long enough for the task queue to do its work.  If it's not, it's
	 * not a serious problem -- it just means that the module that we
	 * just loaded may not be immediately instrumentable.
	 */
	udelay(jiffies_to_usecs(1));
}

static void
dtrace_module_unloaded(struct module *module)
{
	dtrace_probe_t template, *probe, *first, *next;
	dtrace_provider_t *prov;

	template.dtpr_mod = module->name;

	mutex_lock(&dtrace_provider_lock);
	/* FIXME: mutex_lock(&mod_lock); */
	mutex_lock(&dtrace_lock);

	if (dtrace_bymod == NULL) {
		/*
		 * The DTrace module is loaded (obviously) but not attached;
		 * we don't have any work to do.
		 */
		mutex_unlock(&dtrace_provider_lock);
		/* FIXME: mutex_unlock(&mod_lock); */
		mutex_unlock(&dtrace_lock);
		return;
	}

	for (probe = first = dtrace_hash_lookup(dtrace_bymod, &template);
	    probe != NULL; probe = probe->dtpr_nextmod) {
		if (probe->dtpr_ecb != NULL) {
			mutex_unlock(&dtrace_provider_lock);
			/* FIXME: mutex_unlock(&mod_lock); */
			mutex_unlock(&dtrace_lock);

			/*
			 * This shouldn't _actually_ be possible -- we're
			 * unloading a module that has an enabled probe in it.
			 * (It's normally up to the provider to make sure that
			 * this can't happen.)  However, because dtps_enable()
			 * doesn't have a failure mode, there can be an
			 * enable/unload race.  Upshot:  we don't want to
			 * assert, but we're not going to disable the
			 * probe, either.
			 */
			if (dtrace_err_verbose) {
				pr_warning("unloaded module '%s' had "
				    "enabled probes", module->name);
			}

			return;
		}
	}

	probe = first;

	for (first = NULL; probe != NULL; probe = next) {
//TBD		ASSERT(dtrace_probes[probe->dtpr_id - 1] == probe);

//TBD		dtrace_probes[probe->dtpr_id - 1] = NULL;

		next = probe->dtpr_nextmod;
		dtrace_hash_remove(dtrace_bymod, probe);
		dtrace_hash_remove(dtrace_byfunc, probe);
		dtrace_hash_remove(dtrace_byname, probe);

		if (first == NULL) {
			first = probe;
			probe->dtpr_nextmod = NULL;
		} else {
			probe->dtpr_nextmod = first;
			first = probe;
		}
	}

	/*
	 * We've removed all of the module's probes from the hash chains and
	 * from the probe array.  Now issue a dtrace_sync() to be sure that
	 * everyone has cleared out from any probe array processing.
	 */
	dtrace_sync();

	for (probe = first; probe != NULL; probe = first) {
		first = probe->dtpr_nextmod;
		prov = probe->dtpr_provider;
		prov->dtpv_pops.dtps_destroy(prov->dtpv_arg, probe->dtpr_id,
		    probe->dtpr_arg);
		kfree(probe->dtpr_mod);
		kfree(probe->dtpr_func);
		kfree(probe->dtpr_name);
//FIXME		vmem_free(dtrace_arena, (void *)(uintptr_t)probe->dtpr_id, 1);
		kfree(probe);
	}

	mutex_unlock(&dtrace_lock);
	/* FIXME: mutex_unlock(&mod_lock); */
	mutex_unlock(&dtrace_provider_lock);
}

/*
 * Register a toxic range.
 */
static void dtrace_toxrange_add(uintptr_t base, uintptr_t limit)
{
	if (dtrace_toxranges >= dtrace_toxranges_max) {
		int			osize, nsize;
		dtrace_toxrange_t	*range;

		osize = dtrace_toxranges_max * sizeof(dtrace_toxrange_t);

		if (osize == 0) {
			ASSERT(dtrace_toxrange == NULL);
			ASSERT(dtrace_toxranges_max == 0);

			dtrace_toxranges_max = 1;
		} else
			dtrace_toxranges_max <<= 1;

		nsize = dtrace_toxranges_max * sizeof(dtrace_toxrange_t);
		range = vzalloc(nsize);
		if (range == NULL) {
			pr_warn("Failed to add toxic range: out of memory\n");
			return;
		}

		if (dtrace_toxrange != NULL) {
			ASSERT(osize != 0);

			memcpy(range, dtrace_toxrange, osize);
			vfree(dtrace_toxrange);
		}

		dtrace_toxrange = range;
	}

	ASSERT(dtrace_toxrange[dtrace_toxranges].dtt_base == (uintptr_t)NULL);
	ASSERT(dtrace_toxrange[dtrace_toxranges].dtt_limit == (uintptr_t)NULL);

	dtrace_toxrange[dtrace_toxranges].dtt_base = base;
	dtrace_toxrange[dtrace_toxranges].dtt_limit = limit;
	dtrace_toxranges++;
}

/*
 * Check if an address falls within a toxic region.
 */
int dtrace_istoxic(uintptr_t kaddr, size_t size)
{
	uintptr_t	taddr, tsize;
	int		i;

	for (i = 0; i < dtrace_toxranges; i++) {
		taddr = dtrace_toxrange[i].dtt_base;
		tsize = dtrace_toxrange[i].dtt_limit - taddr;

		if (kaddr - taddr < tsize) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			this_cpu_core->cpuc_dtrace_illval = kaddr;
			return 1;
		}

		if (taddr - kaddr < size) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			this_cpu_core->cpuc_dtrace_illval = kaddr;
			return 1;
		}
	}

	return 0;
}

/*
 * Initialize the DTrace core.
 *
 * Equivalent to: dtrace_attach()
 */
int dtrace_dev_init(void)
{
	dtrace_provider_id_t	id;
	int			rc = 0;

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * Register the device for the DTrace core.
	 */
	rc = misc_register(&dtrace_dev);
	if (rc) {
		pr_err("%s: Can't register misc device %d\n",
		       dtrace_dev.name, dtrace_dev.minor);

		mutex_unlock(&cpu_lock);
		mutex_unlock(&dtrace_provider_lock);
		mutex_unlock(&dtrace_lock);

		return rc;
	}

	/*
	 * Register the device for the DTrace helper.
	 */
	rc = misc_register(&helper_dev);
	if (rc) {
		pr_err("%s: Can't register misc device %d\n",
		       helper_dev.name, helper_dev.minor);

		mutex_unlock(&cpu_lock);
		mutex_unlock(&dtrace_provider_lock);
		mutex_unlock(&dtrace_lock);

		return rc;
	}

	ctf_forceload();

	dtrace_modload = dtrace_module_loaded;
	dtrace_modunload = dtrace_module_unloaded;
	dtrace_helpers_cleanup = dtrace_helpers_destroy;
#ifdef FIXME
	dtrace_cpu_init = dtrace_cpu_setup_initial;
	dtrace_cpustart_init = dtrace_suspend;
	dtrace_cpustart_fini = dtrace_resume;
	dtrace_debugger_init = dtrace_suspend;
	dtrace_debugger_fini = dtrace_resume;

	register_cpu_setup_func((cpu_setup_func_t *)dtrace_cpu_setup, NULL);
#endif

	dtrace_probe_init();

#ifdef FIXME
	dtrace_taskq = taskq_create("dtrace_taskq", 1, maxclsyspri, 1, INT_MAX,
				    0);
#endif

	dtrace_state_cache = kmem_cache_create("dtrace_state_cache",
				sizeof(dtrace_dstate_percpu_t) * NR_CPUS,
				__alignof__(dtrace_dstate_percpu_t),
				SLAB_PANIC, NULL);

	/*
	 * Create the probe hashtables.
	 */
	dtrace_bymod = dtrace_hash_create(
				offsetof(dtrace_probe_t, dtpr_mod),
				offsetof(dtrace_probe_t, dtpr_nextmod),
				offsetof(dtrace_probe_t, dtpr_prevmod));
	dtrace_byfunc = dtrace_hash_create(
				offsetof(dtrace_probe_t, dtpr_func),
				offsetof(dtrace_probe_t, dtpr_nextfunc),
				offsetof(dtrace_probe_t, dtpr_prevfunc));
	dtrace_byname = dtrace_hash_create(
				offsetof(dtrace_probe_t, dtpr_name),
				offsetof(dtrace_probe_t, dtpr_nextname),
				offsetof(dtrace_probe_t, dtpr_prevname));

	/*
	 * Ensure that the X configuration parameter has a legal value.
	 */
	if (dtrace_retain_max < 1) {
		pr_warning("Illegal value (%lu) for dtrace_retain_max; "
			   "setting to 1", (unsigned long)dtrace_retain_max);

		dtrace_retain_max = 1;
	}

	/*
	 * Discover our toxic ranges.
	 */
	dtrace_toxic_ranges(dtrace_toxrange_add);

	/*
	 * Register ourselves as a provider.
	 */
	dtrace_register("dtrace", &dtrace_provider_attr, DTRACE_PRIV_NONE, 0,
			&dtrace_provider_ops, NULL, &id);

	ASSERT(dtrace_provider != NULL);
	ASSERT((dtrace_provider_id_t)dtrace_provider == id);

	/*
	 * Create BEGIN, END, and ERROR probes.
	 */
	dtrace_probeid_begin = dtrace_probe_create(
				(dtrace_provider_id_t)dtrace_provider, NULL,
				NULL, "BEGIN", 0, NULL);
	dtrace_probeid_end = dtrace_probe_create(
				(dtrace_provider_id_t)dtrace_provider, NULL,
				NULL, "END", 0, NULL);
	dtrace_probeid_error = dtrace_probe_create(
				(dtrace_provider_id_t)dtrace_provider, NULL,
				NULL, "ERROR", 1, NULL);

	dtrace_anon_property();
	mutex_unlock(&cpu_lock);

	/*
	 * If DTrace helper tracing is enabled, we need to allocate a trace
	 * buffer.
	 */
	if (dtrace_helptrace_enabled) {
		ASSERT(dtrace_helptrace_buffer == NULL);

		dtrace_helptrace_buffer = vzalloc(dtrace_helptrace_bufsize);
		dtrace_helptrace_next = 0;

		if (dtrace_helptrace_buffer == NULL) {
			pr_warn("Cannot allocate helptrace buffer; "
				"disabling dtrace_helptrace\n");
			dtrace_helptrace_enabled = 0;
		}
	}

#ifdef FIXME
	/*
	 * There is usually code here to handle the case where there already
	 * are providers when we get to this code.  On Linux, that does not
	 * seem to be possible since the DTrace core module (this code) is
	 * loaded as a dependency for each provider, and thus this
	 * initialization code is executed prior to the initialization code of
	 * the first provider causing the core to be loaded.
	 */
#endif
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&dtrace_lock);

	return 0;
}

void dtrace_dev_exit(void)
{
	kmem_cache_destroy(dtrace_state_cache);
	misc_deregister(&helper_dev);
	misc_deregister(&dtrace_dev);

	dtrace_probe_exit();
}
