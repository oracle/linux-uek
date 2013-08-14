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
 * Copyright 2010, 2011, 2012, 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/slab.h>
#include <linux/types.h>
#include <asm/uaccess.h>

#include "dtrace.h"

size_t			dtrace_difo_maxsize = 256 * 1024;
dtrace_optval_t		dtrace_dof_maxsize = 256 * 1024;
size_t			dtrace_actions_max = 16 * 1024;
dtrace_optval_t		dtrace_helper_actions_max = 32;
dtrace_optval_t		dtrace_helper_providers_max = 32;

static int		dtrace_helpers;

static uint32_t		dtrace_helptrace_next = 0;
static uint32_t		dtrace_helptrace_nlocals;
static char		*dtrace_helptrace_buffer;
static int		dtrace_helptrace_bufsize = 512 * 1024;

#ifdef CONFIG_DT_DEBUG
static int		dtrace_helptrace_enabled = 1;
#else
static int		dtrace_helptrace_enabled = 0;
#endif

void dtrace_dof_error(dof_hdr_t *dof, const char *str)
{
	if (dtrace_err_verbose)
		pr_warning("failed to process DOF: %s", str);
	else
		dt_dbg_dof("Failed to process DOF: %s\n", str);

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

	dof = vmalloc(len);
	if (dof == NULL)
		return NULL;

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

	dof = vmalloc(hdr.dofh_loadsz);
	if (dof == NULL) {
		*errp = -ENOMEM;
		return NULL;
	}

	if (copy_from_user(dof, argp, hdr.dofh_loadsz) != 0 ||
		dof->dofh_loadsz != hdr.dofh_loadsz) {
		vfree(dof);
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

	dof = vmalloc(loadsz);
	if (dof == NULL) {
		dtrace_dof_error(NULL, "out-of-memory");
		return NULL;
	}
	memcpy(dof, buf, loadsz);
#ifdef FIXME
	ddi_prop_free(buf);
#endif

	return dof;
}

void dtrace_dof_destroy(dof_hdr_t *dof)
{
	vfree(dof);
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

	dt_dbg_dof("    ECB Probe %s:%s:%s:%s\n",
		   desc->dtpd_provider, desc->dtpd_mod, desc->dtpd_func,
		   desc->dtpd_name);

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

	dp = vzalloc(sizeof(dtrace_difo_t));
	if (dp == NULL) {
		dtrace_dof_error(dof, "out-of-memory");
		return NULL;
	}
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
			*bufp = vmalloc(subsec->dofs_size);
			if (*bufp == NULL) {
				dtrace_dof_error(dof, "out-of-memory");
				goto err;
			}
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
	if (dp->dtdo_buf != NULL)
		vfree(dp->dtdo_buf);
	if (dp->dtdo_inttab != NULL)
		vfree(dp->dtdo_inttab);
	if (dp->dtdo_strtab != NULL)
		vfree(dp->dtdo_strtab);
	if (dp->dtdo_vartab != NULL)
		vfree(dp->dtdo_vartab);

	vfree(dp);

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
			fmt = vmalloc(i + 1);
			if (fmt == NULL) {
				dtrace_dof_error(dof, "out-of-memory");
				goto err;
			}
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
		if (act == NULL)
			goto err;

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

	ep = vzalloc(sizeof(dtrace_ecbdesc_t));
	if (ep == NULL)
		return NULL;
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
	vfree(ep);
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

			dt_dbg_dof("      Relocate 0x%llx + 0x%llx = 0x%llx\n",
				   *(uint64_t *)taddr, ubase,
				   *(uint64_t *)taddr + ubase);

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

	dt_dbg_dof("  DOF 0x%p Slurping...\n", dof);

	dt_dbg_dof("    DOF 0x%p Validating...\n", dof);

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
	dt_dbg_dof("    DOF 0x%p Checking section offsets...\n", dof);

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
	dt_dbg_dof("    DOF 0x%p Performing relocations...\n", dof);

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

	dt_dbg_dof("    DOF 0x%p Processing enablings...\n", dof);

	if ((enab = *enabp) == NULL)
		enab = *enabp = dtrace_enabling_create(vstate);

	if (enab == NULL)
		return -1;

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

static dtrace_helpers_t *dtrace_helpers_create(struct task_struct *curr)
{
	dtrace_helpers_t	*dth;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(curr->dtrace_helpers == NULL);

	dth = vzalloc(sizeof(dtrace_helpers_t));
	if (dth == NULL)
		return NULL;

	dth->dthps_actions = vzalloc(sizeof(dtrace_helper_action_t *) *
				     DTRACE_NHELPER_ACTIONS);
	if (dth->dthps_actions == NULL) {
		vfree(dth);
		return NULL;
	}

	curr->dtrace_helpers = dth;
	dtrace_helpers++;

	dt_dbg_dof("  Helpers allocated for task 0x%p (%d system-wide)\n",
		   curr, dtrace_helpers);

	return dth;
}

static int dtrace_helper_validate(dtrace_helper_action_t *helper)
{
	int		err = 0, i;
	dtrace_difo_t	*dp;

	if ((dp = helper->dtha_predicate) != NULL)
		err += dtrace_difo_validate_helper(dp);

	for (i = 0; i < helper->dtha_nactions; i++)
		err += dtrace_difo_validate_helper(helper->dtha_actions[i]);

	return (err == 0);
}

static int dtrace_helper_provider_validate(dof_hdr_t *dof, dof_sec_t *sec)
{
	uintptr_t	daddr = (uintptr_t)dof;
	dof_sec_t	*str_sec, *prb_sec, *arg_sec, *off_sec, *enoff_sec;
	dof_provider_t	*prov;
	dof_probe_t	*prb;
	uint8_t		*arg;
	char		*strtab, *typestr;
	dof_stridx_t	typeidx;
	size_t		typesz;
	uint_t		 nprobes, j, k;

	ASSERT(sec->dofs_type == DOF_SECT_PROVIDER);

	if (sec->dofs_offset & (sizeof(uint_t) - 1)) {
		dtrace_dof_error(dof, "misaligned section offset");
		return -1;
	}

	/*
	 * The section needs to be large enough to contain the DOF provider
	 * structure appropriate for the given version.
	 */
	if (sec->dofs_size <
	    ((dof->dofh_ident[DOF_ID_VERSION] == DOF_VERSION_1)
			? offsetof(dof_provider_t, dofpv_prenoffs)
			: sizeof(dof_provider_t))) {
		dtrace_dof_error(dof, "provider section too small");
		return -1;
	}

	prov = (dof_provider_t *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = dtrace_dof_sect(dof, DOF_SECT_STRTAB, prov->dofpv_strtab);
	prb_sec = dtrace_dof_sect(dof, DOF_SECT_PROBES, prov->dofpv_probes);
	arg_sec = dtrace_dof_sect(dof, DOF_SECT_PRARGS, prov->dofpv_prargs);
	off_sec = dtrace_dof_sect(dof, DOF_SECT_PROFFS, prov->dofpv_proffs);

	if (str_sec == NULL || prb_sec == NULL ||
	    arg_sec == NULL || off_sec == NULL)
		return -1;

	enoff_sec = NULL;

	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    prov->dofpv_prenoffs != DOF_SECT_NONE &&
	    (enoff_sec = dtrace_dof_sect(dof, DOF_SECT_PRENOFFS,
					 prov->dofpv_prenoffs)) == NULL)
		return -1;

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);

	if (prov->dofpv_name >= str_sec->dofs_size ||
	    strlen(strtab + prov->dofpv_name) >= DTRACE_PROVNAMELEN) {
		dtrace_dof_error(dof, "invalid provider name");
		return -1;
	}

	if (prb_sec->dofs_entsize == 0 ||
	    prb_sec->dofs_entsize > prb_sec->dofs_size) {
		dtrace_dof_error(dof, "invalid entry size");
		return -1;
	}

	if (prb_sec->dofs_entsize & (sizeof(uintptr_t) - 1)) {
		dtrace_dof_error(dof, "misaligned entry size");
		return -1;
	}

	if (off_sec->dofs_entsize != sizeof(uint32_t)) {
		dtrace_dof_error(dof, "invalid entry size");
		return -1;
	}

	if (off_sec->dofs_offset & (sizeof(uint32_t) - 1)) {
		dtrace_dof_error(dof, "misaligned section offset");
		return -1;
	}

	if (arg_sec->dofs_entsize != sizeof(uint8_t)) {
		dtrace_dof_error(dof, "invalid entry size");
		return -1;
	}

	arg = (uint8_t *)(uintptr_t)(daddr + arg_sec->dofs_offset);
	nprobes = prb_sec->dofs_size / prb_sec->dofs_entsize;

	dt_dbg_dof("    DOF 0x%p %s::: with %d probes\n",
		   dof, strtab + prov->dofpv_name, nprobes);

	/*
	 * Take a pass through the probes to check for errors.
	 */
	for (j = 0; j < nprobes; j++) {
		prb = (dof_probe_t *)(uintptr_t)
			(daddr + prb_sec->dofs_offset +
			 j * prb_sec->dofs_entsize);

		if (prb->dofpr_func >= str_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid function name");
			return -1;
		}

		if (strlen(strtab + prb->dofpr_func) >= DTRACE_FUNCNAMELEN) {
			dtrace_dof_error(dof, "function name too long");
			return -1;
		}

		if (prb->dofpr_name >= str_sec->dofs_size ||
		    strlen(strtab + prb->dofpr_name) >= DTRACE_NAMELEN) {
			dtrace_dof_error(dof, "invalid probe name");
			return -1;
		}

		/*
		 * The offset count must not wrap the index, and the offsets
		 * must also not overflow the section's data.
		 */
		if (prb->dofpr_offidx + prb->dofpr_noffs < prb->dofpr_offidx ||
		    (prb->dofpr_offidx + prb->dofpr_noffs) *
		    off_sec->dofs_entsize > off_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid probe offset");
			return -1;
		}

		if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1) {
			/*
			 * If there's no is-enabled offset section, make sure
			 * there aren't any is-enabled offsets. Otherwise
			 * perform the same checks as for probe offsets
			 * (immediately above).
			 */
			if (enoff_sec == NULL) {
				if (prb->dofpr_enoffidx != 0 ||
				    prb->dofpr_nenoffs != 0) {
					dtrace_dof_error(dof,
							 "is-enabled offsets "
							 "with null section");
					return -1;
				}
			} else if (prb->dofpr_enoffidx + prb->dofpr_nenoffs <
				   prb->dofpr_enoffidx ||
				   (prb->dofpr_enoffidx + prb->dofpr_nenoffs) *
				   enoff_sec->dofs_entsize >
				   enoff_sec->dofs_size) {
				dtrace_dof_error(dof, "invalid is-enabled "
						      "offset");
				return -1;
			}

			if (prb->dofpr_noffs + prb->dofpr_nenoffs == 0) {
				dtrace_dof_error(dof, "zero probe and "
						      "is-enabled offsets");
				return -1;
			}
		} else if (prb->dofpr_noffs == 0) {
			dtrace_dof_error(dof, "zero probe offsets");
			return -1;
		}

		if (prb->dofpr_argidx + prb->dofpr_xargc < prb->dofpr_argidx ||
		    (prb->dofpr_argidx + prb->dofpr_xargc) *
		    arg_sec->dofs_entsize > arg_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid args");
			return -1;
		}

		typeidx = prb->dofpr_nargv;
		typestr = strtab + prb->dofpr_nargv;
		for (k = 0; k < prb->dofpr_nargc; k++) {
			if (typeidx >= str_sec->dofs_size) {
				dtrace_dof_error(dof, "bad native argument "
						      "type");
				return -1;
			}

			typesz = strlen(typestr) + 1;
			if (typesz > DTRACE_ARGTYPELEN) {
				dtrace_dof_error(dof, "native argument type "
						      "too long");
				return -1;
			}

			typeidx += typesz;
			typestr += typesz;
		}

		typeidx = prb->dofpr_xargv;
		typestr = strtab + prb->dofpr_xargv;
		for (k = 0; k < prb->dofpr_xargc; k++) {
			if (arg[prb->dofpr_argidx + k] > prb->dofpr_nargc) {
				dtrace_dof_error(dof, "bad native argument "
						      "index");
				return -1;
			}

			if (typeidx >= str_sec->dofs_size) {
				dtrace_dof_error(dof, "bad translated "
						      "argument type");
				return -1;
			}

			typesz = strlen(typestr) + 1;
			if (typesz > DTRACE_ARGTYPELEN) {
				dtrace_dof_error(dof, "translated argument "
						      "type too long");
				return -1;
			}

			typeidx += typesz;
			typestr += typesz;
		}

		dt_dbg_dof("      Probe %d %s:%s:%s:%s with %d offsets, "
			   "%d is-enabled offsets\n", j,
			   strtab + prov->dofpv_name, "",
			   strtab + prb->dofpr_func, strtab + prb->dofpr_name,
			   prb->dofpr_noffs, prb->dofpr_nenoffs);
	}

	return 0;
}

static void dtrace_helper_action_destroy(dtrace_helper_action_t *helper,
					 dtrace_vstate_t *vstate)
{
	int	i;

	if (helper->dtha_predicate != NULL)
		dtrace_difo_release(helper->dtha_predicate, vstate);

	for (i = 0; i < helper->dtha_nactions; i++) {
		ASSERT(helper->dtha_actions[i] != NULL);
		dtrace_difo_release(helper->dtha_actions[i], vstate);
	}

	vfree(helper->dtha_actions);
	vfree(helper);
}

static int dtrace_helper_action_add(int which, dtrace_ecbdesc_t *ep)
{
	dtrace_helpers_t	*dth;
	dtrace_helper_action_t	*helper, *last;
	dtrace_actdesc_t	*act;
	dtrace_vstate_t		*vstate;
	dtrace_predicate_t	*pred;
	int			count = 0, nactions = 0, i;

	if (which < 0 || which >= DTRACE_NHELPER_ACTIONS)
		return -EINVAL;

	dth = current->dtrace_helpers;
	last = dth->dthps_actions[which];
	vstate = &dth->dthps_vstate;

	for (count = 0; last != NULL; last = last->dtha_next) {
		count++;
		if (last->dtha_next == NULL)
			break;
	}

	/*
	 * If we already have dtrace_helper_actions_max helper actions for this
	 * helper action type, we'll refuse to add a new one.
	 */
	if (count >= dtrace_helper_actions_max)
		return -ENOSPC;

	helper = vzalloc(sizeof(dtrace_helper_action_t));
	if (helper == NULL)
		return -ENOMEM;

	helper->dtha_generation = dth->dthps_generation;

	if ((pred = ep->dted_pred.dtpdd_predicate) != NULL) {
		ASSERT(pred->dtp_difo != NULL);
		dtrace_difo_hold(pred->dtp_difo);
		helper->dtha_predicate = pred->dtp_difo;
	}

	for (act = ep->dted_action; act != NULL; act = act->dtad_next) {
		if (act->dtad_kind != DTRACEACT_DIFEXPR)
			goto err;

		if (act->dtad_difo == NULL)
			goto err;

		nactions++;
	}

	helper->dtha_actions = vzalloc(sizeof(dtrace_difo_t *) *
				       (helper->dtha_nactions = nactions));
	if (helper->dtha_actions == NULL)
		goto err;

	for (act = ep->dted_action, i = 0; act != NULL; act = act->dtad_next) {
		dtrace_difo_hold(act->dtad_difo);
		helper->dtha_actions[i++] = act->dtad_difo;
	}

	if (!dtrace_helper_validate(helper))
		goto err;

	if (last == NULL)
		dth->dthps_actions[which] = helper;
	else
		last->dtha_next = helper;

	if (vstate->dtvs_nlocals > dtrace_helptrace_nlocals) {
		dtrace_helptrace_nlocals = vstate->dtvs_nlocals;
		dtrace_helptrace_next = 0;
	}

	return 0;

err:
	dtrace_helper_action_destroy(helper, vstate);
	if (helper->dtha_actions != NULL)
		vfree(helper->dtha_actions);
	else
		return -ENOMEM;

	return -EINVAL;
}

static int dtrace_helper_provider_add(dof_helper_t *dofhp, int gen)
{
	dtrace_helpers_t		*dth;
	dtrace_helper_provider_t	*hprov, **tmp_provs;
	uint_t				tmp_maxprovs, i;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	dth = current->dtrace_helpers;
	ASSERT(dth != NULL);

	/*
	 * If we already have dtrace_helper_providers_max helper providers,
	 * we're refuse to add a new one.
	 */
	if (dth->dthps_nprovs >= dtrace_helper_providers_max)
		return -ENOSPC;

	/*
	 * Check to make sure this isn't a duplicate.
	 */
	for (i = 0; i < dth->dthps_nprovs; i++) {
		if (dofhp->dofhp_addr ==
		    dth->dthps_provs[i]->dthp_prov.dofhp_addr)
			return -EALREADY;
	}

	hprov = vzalloc(sizeof(dtrace_helper_provider_t));
	if (hprov == NULL)
		return -ENOMEM;
	hprov->dthp_prov = *dofhp;
	hprov->dthp_ref = 1;
	hprov->dthp_generation = gen;

	/*
	 * Allocate a bigger table for helper providers if it's already full.
	 */
	if (dth->dthps_maxprovs == dth->dthps_nprovs) {
		tmp_maxprovs = dth->dthps_maxprovs;
		tmp_provs = dth->dthps_provs;

		if (dth->dthps_maxprovs == 0)
			dth->dthps_maxprovs = 2;
		else
			dth->dthps_maxprovs *= 2;

		if (dth->dthps_maxprovs > dtrace_helper_providers_max)
			dth->dthps_maxprovs = dtrace_helper_providers_max;

		ASSERT(tmp_maxprovs < dth->dthps_maxprovs);

		dth->dthps_provs = vzalloc(dth->dthps_maxprovs *
					   sizeof(dtrace_helper_provider_t *));
		if (dth->dthps_provs == NULL) {
			vfree(hprov);
			return -ENOMEM;
		}

		if (tmp_provs != NULL) {
			memcpy(dth->dthps_provs, tmp_provs,
			       tmp_maxprovs *
			       sizeof(dtrace_helper_provider_t *));
			vfree(tmp_provs);
		}
	}

	dth->dthps_provs[dth->dthps_nprovs] = hprov;
	dth->dthps_nprovs++;

	return 0;
}

static void dtrace_helper_provider_destroy(dtrace_helper_provider_t *hprov)
{
	mutex_lock(&dtrace_lock);

	if (--hprov->dthp_ref == 0) {
		dof_hdr_t	*dof;

		mutex_unlock(&dtrace_lock);

		dof = (dof_hdr_t *)(uintptr_t)hprov->dthp_prov.dofhp_dof;
		dtrace_dof_destroy(dof);
		vfree(hprov);
	} else
		mutex_unlock(&dtrace_lock);
}

static void dtrace_dofattr2attr(dtrace_attribute_t *attr,
				const dof_attr_t dofattr)
{
	attr->dtat_name = DOF_ATTR_NAME(dofattr);
	attr->dtat_data = DOF_ATTR_DATA(dofattr);
	attr->dtat_class = DOF_ATTR_CLASS(dofattr);
}

static void dtrace_dofprov2hprov(dtrace_helper_provdesc_t *hprov,
				 const dof_provider_t *dofprov, char *strtab)
{
	hprov->dthpv_provname = strtab + dofprov->dofpv_name;
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_provider,
			    dofprov->dofpv_provattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_mod,
			    dofprov->dofpv_modattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_func,
			    dofprov->dofpv_funcattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_name,
			    dofprov->dofpv_nameattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_args,
			    dofprov->dofpv_argsattr);
}

static void dtrace_helper_provider_remove_one(dof_helper_t *dhp,
					      dof_sec_t *sec, pid_t pid)
{
	uintptr_t			daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t			*dof = (dof_hdr_t *)daddr;
	dof_sec_t			*str_sec;
	dof_provider_t			*prov;
	char				*strtab;
	dtrace_helper_provdesc_t	dhpv;
	dtrace_meta_t			*meta = dtrace_meta_pid;
	dtrace_mops_t			*mops = &meta->dtm_mops;

	prov = (dof_provider_t *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
					   prov->dofpv_strtab *
						dof->dofh_secsize);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);

	/*
	 * Create the provider.
	 */
	dtrace_dofprov2hprov(&dhpv, prov, strtab);

	dt_dbg_dof("    Removing provider %s for PID %d\n",
		   dhpv.dthpv_provname, pid);

	mops->dtms_remove_pid(meta->dtm_arg, &dhpv, pid);

	meta->dtm_count--;
}

static void dtrace_helper_provider_remove(dof_helper_t *dhp, pid_t pid)
{
	uintptr_t	daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t	*dof = (dof_hdr_t *)daddr;
	int		i;

	ASSERT(MUTEX_HELD(&dtrace_meta_lock));

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t	*sec = (dof_sec_t *)(uintptr_t)
				       (daddr + dof->dofh_secoff +
					i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_PROVIDER)
			continue;

		dtrace_helper_provider_remove_one(dhp, sec, pid);
	}
}

static void dtrace_helper_provide_one(dof_helper_t *dhp, dof_sec_t *sec,
				      pid_t pid)
{
	uintptr_t			daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t			*dof = (dof_hdr_t *)daddr;
	dof_sec_t			*str_sec, *prb_sec, *arg_sec, *off_sec,
					*enoff_sec;
	dof_provider_t			*prov;
	dof_probe_t			*probe;
	uint32_t			*off, *enoff;
	uint8_t				*arg;
	char				*strtab;
	uint_t				i, nprobes;
	dtrace_helper_provdesc_t	dhpv;
	dtrace_helper_probedesc_t	dhpb;
	dtrace_meta_t			*meta = dtrace_meta_pid;
	dtrace_mops_t			*mops = &meta->dtm_mops;
	void				*parg;

	prov = (dof_provider_t *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
					   prov->dofpv_strtab *
						dof->dofh_secsize);
	prb_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
					   prov->dofpv_probes *
						dof->dofh_secsize);
	arg_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
					   prov->dofpv_prargs *
						dof->dofh_secsize);
	off_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
					   prov->dofpv_proffs *
						dof->dofh_secsize);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);
	off = (uint32_t *)(uintptr_t)(daddr + off_sec->dofs_offset);
	arg = (uint8_t *)(uintptr_t)(daddr + arg_sec->dofs_offset);
	enoff = NULL;

	/*
	 * See dtrace_helper_provider_validate().
	 */
	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    prov->dofpv_prenoffs != DOF_SECT_NONE) {
		enoff_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
						     prov->dofpv_prenoffs *
							dof->dofh_secsize);
		enoff = (uint32_t *)(uintptr_t)(daddr +
						enoff_sec->dofs_offset);
	}

	nprobes = prb_sec->dofs_size / prb_sec->dofs_entsize;

	/*
	 * Create the provider.
	 */
	dtrace_dofprov2hprov(&dhpv, prov, strtab);

	dt_dbg_dof("    Creating provider %s for PID %d\n",
		   strtab + prov->dofpv_name, pid);

	if ((parg = mops->dtms_provide_pid(meta->dtm_arg, &dhpv, pid)) == NULL)
		return;

	meta->dtm_count++;

	/*
	 * Create the probes.
	 */
	for (i = 0; i < nprobes; i++) {
		probe = (dof_probe_t *)(uintptr_t)(daddr +
						   prb_sec->dofs_offset +
						   i * prb_sec->dofs_entsize);

		dhpb.dthpb_mod = dhp->dofhp_mod;
		dhpb.dthpb_func = strtab + probe->dofpr_func;
		dhpb.dthpb_name = strtab + probe->dofpr_name;
		dhpb.dthpb_base = probe->dofpr_addr;
		dhpb.dthpb_offs = off + probe->dofpr_offidx;
		dhpb.dthpb_noffs = probe->dofpr_noffs;

		if (enoff != NULL) {
			dhpb.dthpb_enoffs = enoff + probe->dofpr_enoffidx;
			dhpb.dthpb_nenoffs = probe->dofpr_nenoffs;
		} else {
			dhpb.dthpb_enoffs = NULL;
			dhpb.dthpb_nenoffs = 0;
		}

		dhpb.dthpb_args = arg + probe->dofpr_argidx;
		dhpb.dthpb_nargc = probe->dofpr_nargc;
		dhpb.dthpb_xargc = probe->dofpr_xargc;
		dhpb.dthpb_ntypes = strtab + probe->dofpr_nargv;
		dhpb.dthpb_xtypes = strtab + probe->dofpr_xargv;

		dt_dbg_dof("      Creating probe %s:%s:%s:%s\n",
			   strtab + prov->dofpv_name, "", dhpb.dthpb_func,
			   dhpb.dthpb_name);

		mops->dtms_create_probe(meta->dtm_arg, parg, &dhpb);
	}
}

void dtrace_helper_provide(dof_helper_t *dhp, pid_t pid)
{
	uintptr_t	daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t	*dof = (dof_hdr_t *)daddr;
	int		i;

	ASSERT(MUTEX_HELD(&dtrace_meta_lock));

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t	*sec = (dof_sec_t *)(uintptr_t)
					(daddr + dof->dofh_secoff +
						 i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_PROVIDER)
			continue;

		dtrace_helper_provide_one(dhp, sec, pid);
	}

	/*
	 * We may have just created probes, so we must now rematch against any
	 * retained enablings.  Note that this call will acquire both cpu_lock
	 * and dtrace_lock; the fact that we are holding dtrace_meta_lock now
	 * is what defines the ordering with respect to these three locks.
	 */
	dt_dbg_dof("    Re-matching against any retained enablings\n");
	dtrace_enabling_matchall();
}

static void dtrace_helper_provider_register(struct task_struct *curr,
					    dtrace_helpers_t *dth,
					    dof_helper_t *dofhp)
{
	ASSERT(!MUTEX_HELD(&dtrace_lock));

	mutex_lock(&dtrace_meta_lock);
	mutex_lock(&dtrace_lock);

	if (!dtrace_attached() || dtrace_meta_pid == NULL) {
		dt_dbg_dof("    No meta provider registered -- deferred\n");

		/*
		 * If the dtrace module is loaded but not attached, or if there
		 * isn't a meta provider registered to deal with these provider
		 * descriptions, we need to postpone creating the actual
		 * providers until later.
		 */
		if (dth->dthps_next == NULL && dth->dthps_prev == NULL &&
		    dtrace_deferred_pid != dth) {
			dth->dthps_deferred = 1;
			dth->dthps_pid = current->pid;
			dth->dthps_next = dtrace_deferred_pid;
			dth->dthps_prev = NULL;
			if (dtrace_deferred_pid != NULL)
				dtrace_deferred_pid->dthps_prev = dth;
			dtrace_deferred_pid = dth;
		}

		mutex_unlock(&dtrace_lock);
	} else if (dofhp != NULL) {
		/*
		 * If the dtrace module is loaded and we have a particular
		 * helper provider description, pass that off to the meta
		 * provider.
		 */
		mutex_unlock(&dtrace_lock);

		dtrace_helper_provide(dofhp, current->pid);
	} else {
		/*
		 * Otherwise, just pass all the helper provider descriptions
		 * off to the meta provider.
		 */
		int	i;

		mutex_unlock(&dtrace_lock);

		for (i = 0; i < dth->dthps_nprovs; i++) {
			dtrace_helper_provide(&dth->dthps_provs[i]->dthp_prov,
					      current->pid);
		}
	}

	mutex_unlock(&dtrace_meta_lock);
}

int dtrace_helper_slurp(dof_hdr_t *dof, dof_helper_t *dhp)
{
	dtrace_helpers_t	*dth;
	dtrace_vstate_t		*vstate;
	dtrace_enabling_t	*enab = NULL;
	int			i, gen, rv;
	int			nhelpers = 0, nprovs = 0,destroy = 1;
	uintptr_t		daddr = (uintptr_t)dof;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if ((dth = current->dtrace_helpers) == NULL)
		dth = dtrace_helpers_create(current);

	if (dth == NULL) {
		dtrace_dof_destroy(dof);
		return -1;
	}

	vstate = &dth->dthps_vstate;

	if ((rv = dtrace_dof_slurp(dof, vstate, NULL, &enab,
				   dhp != NULL ? dhp->dofhp_addr : 0,
				   FALSE)) != 0) {
		dtrace_dof_destroy(dof);
		return rv;
	}

	/*
	 * Look for helper providers and validate their descriptions.
	 */
	if (dhp != NULL) {
		dt_dbg_dof("  DOF 0x%p Validating providers...\n", dof);

		for (i = 0; i < dof->dofh_secnum; i++) {
			dof_sec_t	*sec = (dof_sec_t *)(uintptr_t)
						(daddr + dof->dofh_secoff +
						 i * dof->dofh_secsize);

			if (sec->dofs_type != DOF_SECT_PROVIDER)
				continue;

			if (dtrace_helper_provider_validate(dof, sec) != 0) {
				dtrace_enabling_destroy(enab);
				dtrace_dof_destroy(dof);
				return -1;
			}

			nprovs++;
		}
	}

	/*
	 * Now we need to walk through the ECB descriptions in the enabling.
	 */
	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_ecbdesc_t	*ep = enab->dten_desc[i];
		dtrace_probedesc_t	*desc = &ep->dted_probe;

		dt_dbg_dof("  ECB Desc %s:%s:%s:%s\n",
			   desc->dtpd_provider, desc->dtpd_mod,
			   desc->dtpd_func, desc->dtpd_name);
		if (strcmp(desc->dtpd_provider, "dtrace") != 0)
			continue;

		if (strcmp(desc->dtpd_mod, "helper") != 0)
			continue;

		if (strcmp(desc->dtpd_func, "ustack") != 0)
			continue;

		if ((rv = dtrace_helper_action_add(DTRACE_HELPER_ACTION_USTACK,
						   ep)) != 0) {
			/*
			 * Adding this helper action failed -- we are now going
			 * to rip out the entire generation and return failure.
			 */
			dtrace_helper_destroygen(dth->dthps_generation);
			dtrace_enabling_destroy(enab);
			dtrace_dof_destroy(dof);
			return -1;
		}

		nhelpers++;
	}

	if (nhelpers < enab->dten_ndesc)
		dtrace_dof_error(dof, "unmatched helpers");

	gen = dth->dthps_generation++;
	dtrace_enabling_destroy(enab);

	if (dhp != NULL && nprovs > 0) {
		dt_dbg_dof("  DOF 0x%p Adding and registering providers\n",
			   dof);

		dhp->dofhp_dof = (uint64_t)(uintptr_t)dof;
		if (dtrace_helper_provider_add(dhp, gen) == 0) {
			mutex_unlock(&dtrace_lock);
			dtrace_helper_provider_register(current, dth, dhp);
			mutex_lock(&dtrace_lock);

			destroy = 0;
		}
	}

	if (destroy)
		dtrace_dof_destroy(dof);

	return gen;
}

void dtrace_helpers_destroy(struct task_struct *tsk)
{
	dtrace_helpers_t	*help;
	dtrace_vstate_t		*vstate;
	int			i;

	mutex_lock(&dtrace_lock);

	ASSERT(tsk->dtrace_helpers != NULL);
	ASSERT(dtrace_helpers > 0);

	dt_dbg_dof("Helper cleanup: PID %d\n", tsk->pid);

	help = tsk->dtrace_helpers;
	vstate = &help->dthps_vstate;

	/*
	 * We're now going to lose the help from this process.
	 */
	tsk->dtrace_helpers = NULL;
	dtrace_sync();

	/*
	 * Destory the helper actions.
	 */
	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		dtrace_helper_action_t	*h, *next;

		for (h = help->dthps_actions[i]; h != NULL; h = next) {
			next = h->dtha_next;
			dtrace_helper_action_destroy(h, vstate);
			h = next;
		}
	}

	mutex_unlock(&dtrace_lock);

	/*
	 * Destroy the helper providers.
	 */
	if (help->dthps_maxprovs > 0) {
		mutex_lock(&dtrace_meta_lock);
		if (dtrace_meta_pid != NULL) {
			ASSERT(dtrace_deferred_pid == NULL);

			for (i = 0; i < help->dthps_nprovs; i++) {
				dtrace_helper_provider_remove(
					&help->dthps_provs[i]->dthp_prov,
					tsk->pid);
			}
		} else {
			mutex_lock(&dtrace_lock);
			ASSERT(help->dthps_deferred == 0 ||
			       help->dthps_next != NULL ||
			       help->dthps_prev != NULL ||
			       help == dtrace_deferred_pid);

			/*
			 * Remove the helper from the deferred list.
			 */
			if (help->dthps_next != NULL)
				help->dthps_next->dthps_prev = help->dthps_prev;
			if (help->dthps_prev != NULL)
				help->dthps_prev->dthps_next = help->dthps_next;
			if (dtrace_deferred_pid == help) {
				dtrace_deferred_pid = help->dthps_next;
				ASSERT(help->dthps_prev == NULL);
			}

			mutex_unlock(&dtrace_lock);
		}

		mutex_unlock(&dtrace_meta_lock);

		for (i = 0; i < help->dthps_nprovs; i++)
			dtrace_helper_provider_destroy(help->dthps_provs[i]);

		vfree(help->dthps_provs);
	}

	mutex_lock(&dtrace_lock);

	dtrace_vstate_fini(&help->dthps_vstate);
	vfree(help->dthps_actions);
	vfree(help);

	--dtrace_helpers;
	mutex_unlock(&dtrace_lock);
}

int dtrace_helper_destroygen(int gen)
{
	struct task_struct	*p = current;
	dtrace_helpers_t	*dth = p->dtrace_helpers;
	dtrace_vstate_t		*vstate;
	int			i;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (dth == NULL || gen > dth->dthps_generation)
		return -EINVAL;

	vstate = &dth->dthps_vstate;

	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		dtrace_helper_action_t	*last = NULL, *h, *next;

		for (h = dth->dthps_actions[i]; h != NULL; h = next) {
			next = h->dtha_next;

			dt_dbg_dof("  Comparing action (agen %d vs rgen %d)\n",
				   h->dtha_generation, gen);

			if (h->dtha_generation == gen) {
				if (last != NULL)
					last->dtha_next = next;
				else
					dth->dthps_actions[i] = next;

				dtrace_helper_action_destroy(h, vstate);
			} else
				last = h;
		}
	}

	/*
	 * Iterate until we've cleared out all helper providers with the given
	 * generation number.
	 */
	for (;;) {
		dtrace_helper_provider_t	*prov = NULL;

		/*
		 * Look for a helper provider with the right generation.  We
		 * have to start back at the beginning of the list each time
		 * because we drop dtrace_lock.  It's unlikely that we'll make
		 * more than two passes.
		 */
		for (i = 0; i < dth->dthps_nprovs; i++) {
			prov = dth->dthps_provs[i];

			if (prov->dthp_generation == gen)
				break;
		}

		/*
		 * If there were no matches, we are done.
		 */
		if (i == dth->dthps_nprovs)
			break;

		dt_dbg_dof("  Found provider with gen %d\n", gen);

		/*
		 * Move the last helper provider into this slot.
		 */
		dth->dthps_nprovs--;
		dth->dthps_provs[i] = dth->dthps_provs[dth->dthps_nprovs];
		dth->dthps_provs[dth->dthps_nprovs] = NULL;

		mutex_unlock(&dtrace_lock);

		/*
		 * If we have a meta provider, remove this helper provider.
		 */
		mutex_lock(&dtrace_meta_lock);

		if (dtrace_meta_pid != NULL) {
			ASSERT(dtrace_deferred_pid == NULL);

			dtrace_helper_provider_remove(&prov->dthp_prov,
						      p->pid);
		}

		mutex_unlock(&dtrace_meta_lock);

		dtrace_helper_provider_destroy(prov);

		mutex_lock(&dtrace_lock);
	}

	return 0;
}

static void dtrace_helper_trace(dtrace_helper_action_t *helper,
				dtrace_mstate_t *mstate,
				dtrace_vstate_t *vstate, int where)
{
	uint32_t		size, next, nnext, i;
	dtrace_helptrace_t	*ent;
	uint16_t		flags = this_cpu_core->cpuc_dtrace_flags;

	if (!dtrace_helptrace_enabled)
		return;

	ASSERT(vstate->dtvs_nlocals <= dtrace_helptrace_nlocals);

	/*
	 * What would a tracing framework be without its own tracing
	 * framework?  (Well, a hell of a lot simpler, for starters...)
	 */
	size = sizeof(dtrace_helptrace_t) + dtrace_helptrace_nlocals *
	       sizeof(uint64_t) - sizeof(uint64_t);

	/*
	 * Iterate until we can allocate a slot in the trace buffer.
	 */
	do {
		next = dtrace_helptrace_next;

		if (next + size < dtrace_helptrace_bufsize)
			nnext = next + size;
		else
			nnext = size;
	} while (cmpxchg(&dtrace_helptrace_next, next, nnext) != next);

	/*
	 * We have our slot; fill it in.
	*/
	if (nnext == size)
		next = 0;

	ent = (dtrace_helptrace_t *)&dtrace_helptrace_buffer[next];
	ent->dtht_helper = helper;
	ent->dtht_where = where;
	ent->dtht_nlocals = vstate->dtvs_nlocals;

	ent->dtht_fltoffs = (mstate->dtms_present & DTRACE_MSTATE_FLTOFFS)
				?  mstate->dtms_fltoffs
				: -1;
	ent->dtht_fault = DTRACE_FLAGS2FLT(flags);
	ent->dtht_illval = this_cpu_core->cpuc_dtrace_illval;

	for (i = 0; i < vstate->dtvs_nlocals; i++) {
		dtrace_statvar_t	*svar;

		if ((svar = vstate->dtvs_locals[i]) == NULL)
			continue;

		ASSERT(svar->dtsv_size >= NR_CPUS * sizeof(uint64_t));
		ent->dtht_locals[i] =
			((uint64_t *)(uintptr_t)svar->dtsv_data)[
							smp_processor_id()];
	}
}

uint64_t dtrace_helper(int which, dtrace_mstate_t *mstate,
		       dtrace_state_t *state, uint64_t arg0, uint64_t arg1)
{
	uint16_t		*flags = &this_cpu_core->cpuc_dtrace_flags;
	uint64_t		sarg0 = mstate->dtms_arg[0];
	uint64_t		sarg1 = mstate->dtms_arg[1];
	uint64_t		rval = 0;
	dtrace_helpers_t	*helpers = current->dtrace_helpers;
	dtrace_helper_action_t	*helper;
	dtrace_vstate_t		*vstate;
	dtrace_difo_t		*pred;
	int			i, trace = dtrace_helptrace_enabled;

	ASSERT(which >= 0 && which < DTRACE_NHELPER_ACTIONS);

	if (helpers == NULL)
		return 0;

	if ((helper = helpers->dthps_actions[which]) == NULL)
		return 0;

	vstate = &helpers->dthps_vstate;
	mstate->dtms_arg[0] = arg0;
	mstate->dtms_arg[1] = arg1;

	/*
	 * Now iterate over each helper.  If its predicate evaluates to 'true',
	 * we'll call the corresponding actions.  Note that the below calls
	 * to dtrace_dif_emulate() may set faults in machine state.  This is
	 * okay:  our caller (the outer dtrace_dif_emulate()) will simply plow
	 * the stored DIF offset with its own (which is the desired behavior).
	 * Also, note the calls to dtrace_dif_emulate() may allocate scratch
	 * from machine state; this is okay, too.
	 */
	for (; helper != NULL; helper = helper->dtha_next) {
		if ((pred = helper->dtha_predicate) != NULL) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate, 0);

			if (!dtrace_dif_emulate(pred, mstate, vstate, state))
				goto next;

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

		for (i = 0; i < helper->dtha_nactions; i++) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate,
						    i + 1);

			rval = dtrace_dif_emulate(helper->dtha_actions[i],
						  mstate, vstate, state);

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

next:
		if (trace)
			dtrace_helper_trace(helper, mstate, vstate,
					    DTRACE_HELPTRACE_NEXT);
	}

	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
				    DTRACE_HELPTRACE_DONE);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return rval;

err:
	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
				    DTRACE_HELPTRACE_ERR);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return 0;
}
