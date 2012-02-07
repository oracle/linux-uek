/*
 * FILE:	dtrace_dof.c
 * DESCRIPTION:	Dynamic Tracing: DOF object functions
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
#include <linux/types.h>
#include <asm/uaccess.h>

#include "dtrace.h"

size_t		dtrace_difo_maxsize = 256 * 1024;
dtrace_optval_t	dtrace_dof_maxsize = 256 * 1024;
size_t		dtrace_actions_max = 16 * 1024;

static void dtrace_dof_error(dof_hdr_t *dof, const char *str)
{
	if (dtrace_err_verbose)
		pr_warning("failed to process DOF: %s", str);

#ifdef DTRACE_ERRDEBUG
	dtrace_errdebug(str);
#endif
}

/*
 * Create DOF out of a currently enabled state.  Right now, we only create
 * DOF containing the run-time options -- but this could be expanded to create
 * complete DOF representing the enabled state.
 */
dof_hdr_t *dtrace_dof_create(dtrace_state_t *state)
{
	dof_hdr_t	*dof;
	dof_sec_t	*sec;
	dof_optdesc_t	*opt;
	int		i, len = sizeof(dof_hdr_t) +
				 roundup(sizeof(dof_sec_t), sizeof(uint64_t)) +
				 sizeof(dof_optdesc_t) * DTRACEOPT_MAX;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	dof = kmalloc(len, GFP_KERNEL);
	dof->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	dof->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	dof->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	dof->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
	dof->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	dof->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	dof->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;

	dof->dofh_flags = 0;
	dof->dofh_hdrsize = sizeof(dof_hdr_t);
	dof->dofh_secsize = sizeof(dof_sec_t);
	dof->dofh_secnum = 1;   /* only DOF_SECT_OPTDESC */
	dof->dofh_secoff = sizeof(dof_hdr_t);
	dof->dofh_loadsz = len;
	dof->dofh_filesz = len;
	dof->dofh_pad = 0;

	/*
	 * Fill in the option section header...
	 */
	sec = (dof_sec_t *)((uintptr_t)dof + sizeof(dof_hdr_t));
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = sizeof(uint64_t);
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = sizeof(dof_optdesc_t);

	opt = (dof_optdesc_t *)((uintptr_t)sec +
				roundup(sizeof(dof_sec_t), sizeof(uint64_t)));

	sec->dofs_offset = (uintptr_t)opt - (uintptr_t)dof;
	sec->dofs_size = sizeof(dof_optdesc_t) * DTRACEOPT_MAX;

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		opt[i].dofo_option = i;
		opt[i].dofo_strtab = DOF_SECIDX_NONE;
		opt[i].dofo_value = state->dts_options[i];
	}

	return dof;
}

dof_hdr_t *dtrace_dof_copyin(void __user *argp, int *errp)
{
	dof_hdr_t	hdr, *dof;

	ASSERT(!MUTEX_HELD(&dtrace_lock));

	/*
	 * First, we're going to copyin() the sizeof(dof_hdr_t).
	 */
	if (copy_from_user(&hdr, argp, sizeof(hdr)) != 0) {
		dtrace_dof_error(NULL, "failed to copyin DOF header");
		*errp = -EFAULT;
		return NULL;
	}

	/*
	 * Now we'll allocate the entire DOF and copy it in -- provided
	 * that the length isn't outrageous.
	 */
	if (hdr.dofh_loadsz >= dtrace_dof_maxsize) {
		dtrace_dof_error(&hdr, "load size exceeds maximum");
		*errp = -E2BIG;
		return NULL;
	}

	if (hdr.dofh_loadsz < sizeof(hdr)) {
		dtrace_dof_error(&hdr, "invalid load size");
		*errp = -EINVAL;
		return NULL;
	}

	dof = kmalloc(hdr.dofh_loadsz, GFP_KERNEL);

	if (copy_from_user(dof, argp, hdr.dofh_loadsz) != 0 ||
		dof->dofh_loadsz != hdr.dofh_loadsz) {
		kfree(dof);
		*errp = -EFAULT;
		return NULL;
	}

	return dof;
}

dof_hdr_t *dtrace_dof_property(const char *name)
{
	uchar_t		*buf;
	uint64_t	loadsz;
	unsigned int	len, i;
	dof_hdr_t	*dof;

	/*
	 * Unfortunately, array of values in .conf files are always (and
	 * only) interpreted to be integer arrays.  We must read our DOF
	 * as an integer array, and then squeeze it into a byte array.
	 */
#ifdef FIXME
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dtrace_devi, 0,
				      (char *)name, (int **)&buf, &len) !=
	    DDI_PROP_SUCCESS)
		return NULL;
#else
	return NULL;
#endif

	for (i = 0; i < len; i++)
		buf[i] = (uchar_t)(((int *)buf)[i]);

	if (len < sizeof(dof_hdr_t)) {
#ifdef FIXME
		ddi_prop_free(buf);
#endif
		dtrace_dof_error(NULL, "truncated header");
		return NULL;
	}

	if (len < (loadsz = ((dof_hdr_t *)buf)->dofh_loadsz)) {
#ifdef FIXME
		ddi_prop_free(buf);
#endif
		dtrace_dof_error(NULL, "truncated DOF");
		return NULL;
	}

	if (loadsz >= dtrace_dof_maxsize) {
#ifdef FIXME
		ddi_prop_free(buf);
#endif
		dtrace_dof_error(NULL, "oversized DOF");
		return NULL;
	}

	dof = kmalloc(loadsz, GFP_KERNEL);
	memcpy(dof, buf, loadsz);
#ifdef FIXME
	ddi_prop_free(buf);
#endif

	return dof;
}

void dtrace_dof_destroy(dof_hdr_t *dof)
{
	kfree(dof);
}

/*
 * Return the dof_sec_t pointer corresponding to a given section index.  If the
 * index is not valid, dtrace_dof_error() is called and NULL is returned.  If
 * a type other than DOF_SECT_NONE is specified, the header is checked against
 * this type and NULL is returned if the types do not match.
 */
static dof_sec_t *dtrace_dof_sect(dof_hdr_t *dof, uint32_t type,
				  dof_secidx_t i)
{
	dof_sec_t	*sec = (dof_sec_t *)(uintptr_t)((uintptr_t)dof +
							dof->dofh_secoff +
							i * dof->dofh_secsize);

	if (i >= dof->dofh_secnum) {
		dtrace_dof_error(dof, "referenced section index is invalid");
		return NULL;
	}

	if (!(sec->dofs_flags & DOF_SECF_LOAD)) {
		dtrace_dof_error(dof, "referenced section is not loadable");
		return NULL;
	}

	if (type != DOF_SECT_NONE && type != sec->dofs_type) {
		dtrace_dof_error(dof, "referenced section is the wrong type");
		return NULL;
	}

	return sec;
}

static dtrace_probedesc_t *dtrace_dof_probedesc(dof_hdr_t *dof, dof_sec_t *sec,
						dtrace_probedesc_t *desc)
{
	dof_probedesc_t	*probe;
	dof_sec_t	*strtab;
	uintptr_t	daddr = (uintptr_t)dof;
	uintptr_t	str;
	size_t		size;

	if (sec->dofs_type != DOF_SECT_PROBEDESC) {
		dtrace_dof_error(dof, "invalid probe section");
		return NULL;
	}

	if (sec->dofs_align != sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "bad alignment in probe description");
		return NULL;
	}

	if (sec->dofs_offset + sizeof(dof_probedesc_t) > dof->dofh_loadsz) {
		dtrace_dof_error(dof, "truncated probe description");
		return NULL;
	}

	probe = (dof_probedesc_t *)(uintptr_t)(daddr + sec->dofs_offset);
	strtab = dtrace_dof_sect(dof, DOF_SECT_STRTAB, probe->dofp_strtab);

	if (strtab == NULL)
		return NULL;

	str = daddr + strtab->dofs_offset;
	size = strtab->dofs_size;

	if (probe->dofp_provider >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe provider");
		return NULL;
	}

	strncpy(desc->dtpd_provider, (char *)(str + probe->dofp_provider),
		min((size_t)DTRACE_PROVNAMELEN - 1,
		    size - probe->dofp_provider));

	if (probe->dofp_mod >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe module");
		return NULL;
	}

	strncpy(desc->dtpd_mod, (char *)(str + probe->dofp_mod),
		min((size_t)DTRACE_MODNAMELEN - 1, size - probe->dofp_mod));

	if (probe->dofp_func >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe function");
		return NULL;
	}

	strncpy(desc->dtpd_func, (char *)(str + probe->dofp_func),
		min((size_t)DTRACE_FUNCNAMELEN - 1, size - probe->dofp_func));

	if (probe->dofp_name >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe name");
		return NULL;
	}

	strncpy(desc->dtpd_name, (char *)(str + probe->dofp_name),
		min((size_t)DTRACE_NAMELEN - 1, size - probe->dofp_name));

	return desc;
}

static dtrace_difo_t *dtrace_dof_difo(dof_hdr_t *dof, dof_sec_t *sec,
				      dtrace_vstate_t *vstate,
				      const cred_t *cr)
{
	dtrace_difo_t	*dp;
	size_t		ttl = 0;
	dof_difohdr_t	*dofd;
	uintptr_t	daddr = (uintptr_t)dof;
	size_t		max = dtrace_difo_maxsize;
	int		i, l, n;

	static const struct {
		int section;
		int bufoffs;
		int lenoffs;
		int entsize;
		int align;
		const char *msg;
	} difo[] = {
		{
			DOF_SECT_DIF,
			offsetof(dtrace_difo_t, dtdo_buf),
			offsetof(dtrace_difo_t, dtdo_len),
			sizeof(dif_instr_t),
			sizeof(dif_instr_t),
			"multiple DIF sections"
		},
		{
			DOF_SECT_INTTAB,
			offsetof(dtrace_difo_t, dtdo_inttab),
			offsetof(dtrace_difo_t, dtdo_intlen),
			sizeof(uint64_t),
			sizeof(uint64_t),
			"multiple integer tables"
		},
		{
			DOF_SECT_STRTAB,
			offsetof(dtrace_difo_t, dtdo_strtab),
			offsetof(dtrace_difo_t, dtdo_strlen),
			0,
			sizeof(char),
			"multiple string tables"
		},
		{
			DOF_SECT_VARTAB,
			offsetof(dtrace_difo_t, dtdo_vartab),
			offsetof(dtrace_difo_t, dtdo_varlen),
			sizeof(dtrace_difv_t),
			sizeof(uint_t),
			"multiple variable tables"
		},
		{
			DOF_SECT_NONE,
			0,
			0,
			0,
			0,
			NULL
		}
	};

	if (sec->dofs_type != DOF_SECT_DIFOHDR) {
		dtrace_dof_error(dof, "invalid DIFO header section");
		return NULL;
	}

	if (sec->dofs_align != sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "bad alignment in DIFO header");
		return NULL;
	}

	if (sec->dofs_size < sizeof(dof_difohdr_t) ||
	    sec->dofs_size % sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "bad size in DIFO header");
		return NULL;
	}

	dofd = (dof_difohdr_t *)(uintptr_t)(daddr + sec->dofs_offset);
	n = (sec->dofs_size - sizeof(*dofd)) / sizeof(dof_secidx_t) + 1;

	dp = kzalloc(sizeof(dtrace_difo_t), GFP_KERNEL);
	dp->dtdo_rtype = dofd->dofd_rtype;

	for (l = 0; l < n; l++) {
		dof_sec_t	*subsec;
		void		**bufp;
		uint32_t	*lenp;

		if ((subsec =
		     dtrace_dof_sect(dof, DOF_SECT_NONE, dofd->dofd_links[l]))
		    == NULL)
			goto err; /* invalid section link */

		if (ttl + subsec->dofs_size > max) {
			dtrace_dof_error(dof, "exceeds maximum size");
			goto err;
		}

		ttl += subsec->dofs_size;

		for (i = 0; difo[i].section != DOF_SECT_NONE; i++) {
			if (subsec->dofs_type != difo[i].section)
				continue;

			if (!(subsec->dofs_flags & DOF_SECF_LOAD)) {
				dtrace_dof_error(dof, "section not loaded");
				goto err;
			}

			if (subsec->dofs_align != difo[i].align) {
				dtrace_dof_error(dof, "bad alignment");
				goto err;
			}

			bufp = (void **)((uintptr_t)dp + difo[i].bufoffs);
			lenp = (uint32_t *)((uintptr_t)dp + difo[i].lenoffs);

			if (*bufp != NULL) {
				dtrace_dof_error(dof, difo[i].msg);
				goto err;
			}

			if (difo[i].entsize != subsec->dofs_entsize) {
				dtrace_dof_error(dof, "entry size mismatch");
				goto err;
			}

			if (subsec->dofs_entsize != 0) {
				uint64_t	n = subsec->dofs_size;

				if (do_div(n, subsec->dofs_entsize) != 0) {
					dtrace_dof_error(dof,
							 "corrupt entry size");
					goto err;
				}
			}

			*lenp = subsec->dofs_size;
			*bufp = kmalloc(subsec->dofs_size, GFP_KERNEL);
			memcpy(*bufp,
			       (char *)(uintptr_t)(daddr + subsec->dofs_offset),
			       subsec->dofs_size);

			if (subsec->dofs_entsize != 0)
				*lenp /= subsec->dofs_entsize;

			break;
		}

		/*
		 * If we encounter a loadable DIFO sub-section that is not
		 * known to us, assume this is a broken program and fail.
		 */
		if (difo[i].section == DOF_SECT_NONE &&
		    (subsec->dofs_flags & DOF_SECF_LOAD)) {
			dtrace_dof_error(dof, "unrecognized DIFO subsection");
			goto err;
		}
	}

	if (dp->dtdo_buf == NULL) {
		/*
		 * We can't have a DIF object without DIF text.
		 */
		dtrace_dof_error(dof, "missing DIF text");
		goto err;
	}

	/*
	 * Before we validate the DIF object, run through the variable table
	 * looking for the strings -- if any of their size are under, we'll set
	 * their size to be the system-wide default string size.  Note that
	 * this should _not_ happen if the "strsize" option has been set --
	 * in this case, the compiler should have set the size to reflect the
	 * setting of the option.
	 */
	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t		*v = &dp->dtdo_vartab[i];
		dtrace_diftype_t	*t = &v->dtdv_type;

		if (v->dtdv_id < DIF_VAR_OTHER_UBASE)
			continue;

		if (t->dtdt_kind == DIF_TYPE_STRING && t->dtdt_size == 0)
			t->dtdt_size = dtrace_strsize_default;
	}

	if (dtrace_difo_validate(dp, vstate, DIF_DIR_NREGS, cr) != 0)
		goto err;

	dtrace_difo_init(dp, vstate);
	return dp;

err:
	kfree(dp->dtdo_buf);
	kfree(dp->dtdo_inttab);
	kfree(dp->dtdo_strtab);
	kfree(dp->dtdo_vartab);

	kfree(dp);
	return NULL;
}

static dtrace_predicate_t *dtrace_dof_predicate(dof_hdr_t *dof, dof_sec_t *sec,
						dtrace_vstate_t *vstate,
						const cred_t *cr)
{
        dtrace_difo_t *dp;

        if ((dp = dtrace_dof_difo(dof, sec, vstate, cr)) == NULL)
                return NULL;

        return dtrace_predicate_create(dp);
}

static dtrace_actdesc_t *dtrace_dof_actdesc(dof_hdr_t *dof, dof_sec_t *sec,
					    dtrace_vstate_t *vstate,
					    const cred_t *cr)
{
	dtrace_actdesc_t	*act, *first = NULL, *last = NULL, *next;
	dof_actdesc_t		*desc;
	dof_sec_t		*difosec;
	size_t			offs;
	uintptr_t		daddr = (uintptr_t)dof;
	uint64_t		arg;
	dtrace_actkind_t	kind;

	if (sec->dofs_type != DOF_SECT_ACTDESC) {
		dtrace_dof_error(dof, "invalid action section");
		return NULL;
	}

	if (sec->dofs_offset + sizeof(dof_actdesc_t) > dof->dofh_loadsz) {
		dtrace_dof_error(dof, "truncated action description");
		return NULL;
	}

	if (sec->dofs_align != sizeof(uint64_t)) {
		dtrace_dof_error(dof, "bad alignment in action description");
		return NULL;
	}

	if (sec->dofs_size < sec->dofs_entsize) {
		dtrace_dof_error(dof, "section entry size exceeds total size");
		return NULL;
	}

	if (sec->dofs_entsize != sizeof(dof_actdesc_t)) {
		dtrace_dof_error(dof, "bad entry size in action description");
		return NULL;
	}

	/*
	 * Was: sec->dofs_size / sec->dofs_entsize > dtrace_actions_max
	 * but it is safer to simply avoid the division (it requires use of
	 * a macro in Linux to cover 64-bit division in a 32-bit kernel.
	 */
	if (sec->dofs_size > sec->dofs_entsize * dtrace_actions_max) {
		dtrace_dof_error(dof, "actions exceed dtrace_actions_max");
		return NULL;
	}

	for (offs = 0; offs < sec->dofs_size; offs += sec->dofs_entsize) {
		desc = (dof_actdesc_t *)(daddr +
					 (uintptr_t)sec->dofs_offset + offs);
		kind = (dtrace_actkind_t)desc->dofa_kind;

		if (DTRACEACT_ISPRINTFLIKE(kind) &&
		    (kind != DTRACEACT_PRINTA ||
		     desc->dofa_strtab != DOF_SECIDX_NONE)) {
			dof_sec_t	*strtab;
			char		*str, *fmt;
			uint64_t	i;

			/*
			 * The printf()-like actions must have a format string.
			 */
			if ((strtab =
			     dtrace_dof_sect(dof, DOF_SECT_STRTAB,
					     desc->dofa_strtab)) == NULL)
				goto err;

			str = (char *)((uintptr_t)dof +
				       (uintptr_t)strtab->dofs_offset);
	
			for (i = desc->dofa_arg; i < strtab->dofs_size; i++) {
				if (str[i] == '\0')
					break;
			}

			if (i >= strtab->dofs_size) {
				dtrace_dof_error(dof, "bogus format string");
				goto err;
			}

			if (i == desc->dofa_arg) {
				dtrace_dof_error(dof, "empty format string");
				goto err;
			}

			i -= desc->dofa_arg;
			fmt = kmalloc(i + 1, GFP_KERNEL);
			memcpy(fmt, &str[desc->dofa_arg], i + 1);
			arg = (uint64_t)(uintptr_t)fmt;
		} else {
			if (kind == DTRACEACT_PRINTA) {
				ASSERT(desc->dofa_strtab == DOF_SECIDX_NONE);
				arg = 0;
			} else
				arg = desc->dofa_arg;
		}

		act = dtrace_actdesc_create(kind, desc->dofa_ntuple,
					    desc->dofa_uarg, arg);

		if (last != NULL)
			last->dtad_next = act;
		else
			first = act;

		last = act;

		if (desc->dofa_difo == DOF_SECIDX_NONE)
			continue;

		if ((difosec = dtrace_dof_sect(dof, DOF_SECT_DIFOHDR,
					       desc->dofa_difo)) == NULL)
			goto err;

		act->dtad_difo = dtrace_dof_difo(dof, difosec, vstate, cr);

		if (act->dtad_difo == NULL)
			goto err;
	}

	ASSERT(first != NULL);
	return first;

err:
	for (act = first; act != NULL; act = next) {
		next = act->dtad_next;
		dtrace_actdesc_release(act, vstate);
	}

	return NULL;
}

static dtrace_ecbdesc_t *dtrace_dof_ecbdesc(dof_hdr_t *dof, dof_sec_t *sec,
					    dtrace_vstate_t *vstate,
					    const cred_t *cr)
{
	dtrace_ecbdesc_t	*ep;
	dof_ecbdesc_t		*ecb;
	dtrace_probedesc_t	*desc;
	dtrace_predicate_t	*pred = NULL;

	if (sec->dofs_size < sizeof(dof_ecbdesc_t)) {
		dtrace_dof_error(dof, "truncated ECB description");
		return NULL;
	}

	if (sec->dofs_align != sizeof(uint64_t)) {
		dtrace_dof_error(dof, "bad alignment in ECB description");
		return NULL;
	}

	ecb = (dof_ecbdesc_t *)((uintptr_t)dof + (uintptr_t)sec->dofs_offset);
	sec = dtrace_dof_sect(dof, DOF_SECT_PROBEDESC, ecb->dofe_probes);

	if (sec == NULL)
		return NULL;

	ep = kzalloc(sizeof(dtrace_ecbdesc_t), GFP_KERNEL);
	ep->dted_uarg = ecb->dofe_uarg;
	desc = &ep->dted_probe;

	if (dtrace_dof_probedesc(dof, sec, desc) == NULL)
		goto err;

	if (ecb->dofe_pred != DOF_SECIDX_NONE) {
		if ((sec = dtrace_dof_sect(dof, DOF_SECT_DIFOHDR,
					   ecb->dofe_pred)) == NULL)
			goto err;

		if ((pred = dtrace_dof_predicate(dof, sec, vstate, cr)) == NULL)
			goto err;

		ep->dted_pred.dtpdd_predicate = pred;
	}

	if (ecb->dofe_actions != DOF_SECIDX_NONE) {
		if ((sec = dtrace_dof_sect(dof, DOF_SECT_ACTDESC,
					   ecb->dofe_actions)) == NULL)
			goto err;

		ep->dted_action = dtrace_dof_actdesc(dof, sec, vstate, cr);

		if (ep->dted_action == NULL)
			goto err;
	}

	return ep;

err:
	if (pred != NULL)
		dtrace_predicate_release(pred, vstate);
	kfree(ep);
	return NULL;
}

/*
 * Apply the relocations from the specified 'sec' (a DOF_SECT_URELHDR) to the
 * specified DOF.  At present, this amounts to simply adding 'ubase' to the
 * site of any user SETX relocations to account for load object base address.
 * In the future, if we need other relocations, this function can be extended.
 */
static int dtrace_dof_relocate(dof_hdr_t *dof, dof_sec_t *sec, uint64_t ubase)
{
	uintptr_t	daddr = (uintptr_t)dof;
	dof_relohdr_t	*dofr = (dof_relohdr_t *)(uintptr_t)(daddr +
							     sec->dofs_offset);
	dof_sec_t	*ss, *rs, *ts;
	dof_relodesc_t	*r;
	uint_t		i, n;

	if (sec->dofs_size < sizeof(dof_relohdr_t) ||
	    sec->dofs_align != sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "invalid relocation header");
		return -1;
	}

	ss = dtrace_dof_sect(dof, DOF_SECT_STRTAB, dofr->dofr_strtab);
	rs = dtrace_dof_sect(dof, DOF_SECT_RELTAB, dofr->dofr_relsec);
	ts = dtrace_dof_sect(dof, DOF_SECT_NONE, dofr->dofr_tgtsec);

	if (ss == NULL || rs == NULL || ts == NULL)
		return -1; /* dtrace_dof_error() has been called already */

	if (rs->dofs_entsize < sizeof(dof_relodesc_t) ||
	    rs->dofs_align != sizeof(uint64_t)) {
		dtrace_dof_error(dof, "invalid relocation section");
		return -1;
	}

	r = (dof_relodesc_t *)(uintptr_t)(daddr + rs->dofs_offset);
	/*
	 * Was: n = rs->dofs_size / rs->dofs_entsize;
	 * but on Linux we need to use a macro for the division to handle the
	 * possible case of 64-bit division on a 32-bit kernel.
	 */
	n = rs->dofs_size;
	do_div(n, rs->dofs_entsize);

	for (i = 0; i < n; i++) {
		uintptr_t	taddr = daddr + ts->dofs_offset +
						r->dofr_offset;

		switch (r->dofr_type) {
		case DOF_RELO_NONE:
			break;
		case DOF_RELO_SETX:
			if (r->dofr_offset >= ts->dofs_size ||
			    r->dofr_offset + sizeof(uint64_t) >
				ts->dofs_size) {
				dtrace_dof_error(dof, "bad relocation offset");
				return -1;
			}

			if (!IS_ALIGNED(taddr, sizeof(uint64_t))) {
				dtrace_dof_error(dof, "misaligned setx relo");
				return -1;
			}

			*(uint64_t *)taddr += ubase;
			break;
		default:
			dtrace_dof_error(dof, "invalid relocation type");
			return -1;
		}

		r = (dof_relodesc_t *)((uintptr_t)r + rs->dofs_entsize);
	}

	return 0;
}

/*
 * The dof_hdr_t passed to dtrace_dof_slurp() should be a partially validated
 * header:  it should be at the front of a memory region that is at least
 * sizeof(dof_hdr_t) in size -- and then at least dof_hdr.dofh_loadsz in
 * size.  It need not be validated in any other way.
 */
int dtrace_dof_slurp(dof_hdr_t *dof, dtrace_vstate_t *vstate, const cred_t *cr,
		     dtrace_enabling_t **enabp, uint64_t ubase, int noprobes)
{
	uint64_t		len = dof->dofh_loadsz, seclen;
	uintptr_t		daddr = (uintptr_t)dof;
	dtrace_ecbdesc_t	*ep;
	dtrace_enabling_t	*enab;
	uint_t			i;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dof->dofh_loadsz >= sizeof(dof_hdr_t));

	/*
	 * Check the DOF header identification bytes.  In addition to checking
	 * valid settings, we also verify that unused bits/bytes are zeroed so
	 * we can use them later without fear of regressing existing binaries.
	 */
	if (memcmp(&dof->dofh_ident[DOF_ID_MAG0], DOF_MAG_STRING,
		   DOF_MAG_STRLEN) != 0) {
		dtrace_dof_error(dof, "DOF magic string mismatch");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_ILP32 &&
	    dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_LP64) {
		dtrace_dof_error(dof, "DOF has invalid data model");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_ENCODING] != DOF_ENCODE_NATIVE) {
		dtrace_dof_error(dof, "DOF encoding mismatch");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_2) {
		dtrace_dof_error(dof, "DOF version mismatch");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_DIFVERS] != DIF_VERSION_2) {
		dtrace_dof_error(dof, "DOF uses unsupported instruction set");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_DIFIREG] > DIF_DIR_NREGS) {
		dtrace_dof_error(dof, "DOF uses too many integer registers");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_DIFTREG] > DIF_DTR_NREGS) {
		dtrace_dof_error(dof, "DOF uses too many tuple registers");
		return -1;
	}

	for (i = DOF_ID_PAD; i < DOF_ID_SIZE; i++) {
		if (dof->dofh_ident[i] != 0) {
			dtrace_dof_error(dof, "DOF has invalid ident byte set");                        return -1;
		}
	}

	if (dof->dofh_flags & ~DOF_FL_VALID) {
		dtrace_dof_error(dof, "DOF has invalid flag bits set");
		return -1;
	}

	if (dof->dofh_secsize == 0) {
		dtrace_dof_error(dof, "zero section header size");
		return -1;
	}

	/*
	 * Check that the section headers don't exceed the amount of DOF
	 * data.  Note that we cast the section size and number of sections
	 * to uint64_t's to prevent possible overflow in the multiplication.
	 */
	seclen = (uint64_t)dof->dofh_secnum * (uint64_t)dof->dofh_secsize;

	if (dof->dofh_secoff > len || seclen > len ||
	    dof->dofh_secoff + seclen > len) {
		dtrace_dof_error(dof, "truncated section headers");
		return -1;
	}

	if (!IS_ALIGNED(dof->dofh_secoff, sizeof(uint64_t))) {
		dtrace_dof_error(dof, "misaligned section headers");
		return -1;
	}

	if (!IS_ALIGNED(dof->dofh_secsize, sizeof(uint64_t))) {
		dtrace_dof_error(dof, "misaligned section size");
		return -1;
	}

	/*
	 * Take an initial pass through the section headers to be sure that
	 * the headers don't have stray offsets.  If the 'noprobes' flag is
	 * set, do not permit sections relating to providers, probes, or args.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t	*sec =
				(dof_sec_t *)(daddr +
					      (uintptr_t)dof->dofh_secoff +
					      i * dof->dofh_secsize);

		if (noprobes) {
			switch (sec->dofs_type) {
			case DOF_SECT_PROVIDER:
			case DOF_SECT_PROBES:
			case DOF_SECT_PRARGS:
			case DOF_SECT_PROFFS:
				dtrace_dof_error(
					dof, "illegal sections for enabling");
				return -1;
			}
		}

		if (DOF_SEC_ISLOADABLE(sec->dofs_type) &&
		    !(sec->dofs_flags & DOF_SECF_LOAD)) {
			dtrace_dof_error(
				dof, "loadable section with load flag unset");
			return -1;
		}

		/*
		 * Just ignore non-loadable sections.
		 */
		if (!(sec->dofs_flags & DOF_SECF_LOAD))
			continue;

		if (sec->dofs_align & (sec->dofs_align - 1)) {
			dtrace_dof_error(dof, "bad section alignment");
			return -1;
		}

		if (sec->dofs_offset & (sec->dofs_align - 1)) {
			dtrace_dof_error(dof, "misaligned section");
			return -1;
		}

		if (sec->dofs_offset > len || sec->dofs_size > len ||
		    sec->dofs_offset + sec->dofs_size > len) {
			dtrace_dof_error(dof, "corrupt section header");
			return -1;
		}

		if (sec->dofs_type == DOF_SECT_STRTAB && *((char *)daddr +
		    sec->dofs_offset + sec->dofs_size - 1) != '\0') {
			dtrace_dof_error(dof, "non-terminating string table");
			return -1;
		}
	}

	/*
	 * Take a second pass through the sections and locate and perform any
	 * relocations that are present.  We do this after the first pass to
	 * be sure that all sections have had their headers validated.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t	*sec =
				(dof_sec_t *)(daddr +
					      (uintptr_t)dof->dofh_secoff +
					      i * dof->dofh_secsize);

		/*
		 * Skip sections that are not loadable.
		 */
		if (!(sec->dofs_flags & DOF_SECF_LOAD))
			continue;

		switch (sec->dofs_type) {
		case DOF_SECT_URELHDR:
			if (dtrace_dof_relocate(dof, sec, ubase) != 0)
				return -1;
			break;
		}
	}

	if ((enab = *enabp) == NULL)
		enab = *enabp = dtrace_enabling_create(vstate);

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t	*sec =
				(dof_sec_t *)(daddr +
					      (uintptr_t)dof->dofh_secoff +
					      i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_ECBDESC)
			continue;

		if ((ep = dtrace_dof_ecbdesc(dof, sec, vstate, cr)) == NULL) {
			dtrace_enabling_destroy(enab);
			*enabp = NULL;
			return -1;
		}

		dtrace_enabling_add(enab, ep);
	}

	return 0;
}

/*
 * Process DOF for any options.  This should be called after the DOF has been
 * processed by dtrace_dof_slurp().
 */
int dtrace_dof_options(dof_hdr_t *dof, dtrace_state_t *state)
{
	int		i, rval;
	uint32_t	entsize;
	size_t		offs;
	dof_optdesc_t	*desc;

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t	*sec = (dof_sec_t *)((uintptr_t)dof +
				       (uintptr_t)dof->dofh_secoff +
				       i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_OPTDESC)
			continue;

		if (sec->dofs_align != sizeof(uint64_t)) {
			dtrace_dof_error(
				dof, "bad alignment in option description");
			return -EINVAL;
		}

		if ((entsize = sec->dofs_entsize) == 0) {
			dtrace_dof_error(dof, "zeroed option entry size");
			return -EINVAL;
		}

		if (entsize < sizeof(dof_optdesc_t)) {
			dtrace_dof_error(dof, "bad option entry size");
			return -EINVAL;
		}

		for (offs = 0; offs < sec->dofs_size; offs += entsize) {
			desc = (dof_optdesc_t *)((uintptr_t)dof +
						 (uintptr_t)sec->dofs_offset +
						 offs);

			if (desc->dofo_strtab != DOF_SECIDX_NONE) {
				dtrace_dof_error(
					dof, "non-zero option string");
				return -EINVAL;
			}

			if (desc->dofo_value == DTRACEOPT_UNSET) {
				dtrace_dof_error(dof, "unset option");
				return -EINVAL;
			}

			if ((rval = dtrace_state_option(
					state, desc->dofo_option,
					desc->dofo_value)) != 0) {
				dtrace_dof_error(dof, "rejected option");
				return rval;
			}
		}
	}

	return 0;
}
