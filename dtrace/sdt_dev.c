/*
 * FILE:	sdt_dev.c
 * DESCRIPTION:	Statically Defined Tracing: device file handling
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
 * Copyright 2010-2014 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

#define SDT_PROBETAB_SIZE	0x1000		/* 4k entries -- 16K total */

sdt_probe_t		**sdt_probetab;
int			sdt_probetab_size;
int			sdt_probetab_mask;

/*
 * Return, in newly-allocated space, a version of the passed-in type which has
 * been cleaned up suitably for CTF: leading and trailing spaces (if any)
 * removed, and optionally a trailing argument removed as well.
 *
 * Type strings look like either
 *
 * type (for SDT, as in function prototypes), or
 *
 * type argname (for perf: as in function declarations).
 *
 * Translator components ": (foo, foo)", if any, have been removed by this
 * stage.
 */
static char *cleanup_type(const char *type, int arg_strip)
{
	const char *cleaned;
	const char *p;

	cleaned = type + strspn(type, " \t");
	for (p = cleaned + strlen(cleaned) - 1; p > cleaned &&
		     isspace(*p); p--);
	if (arg_strip) {
		for (; p > cleaned && (isalnum(*p) || *p == '_'); p--);
		for (; p > cleaned && isspace(*p); p--);
	}
	p++;

	return kstrndup(cleaned, p - cleaned, GFP_KERNEL);
}

/*
 * Set up the args lists, extracting them from their sdpd entry and parsing them
 * into an sdt_argdesc array for each probe.
 */
static sdt_argdesc_t *sdt_setup_args(sdt_probedesc_t *sdpd, size_t *sdp_nargdesc)
{
	sdt_argdesc_t *args;
	char *argstr;
	char *p;
	int arg_strip = 0;
	char *next_arg = NULL;
	size_t arg = 0, sarg = 0, i;

	*sdp_nargdesc = 0;

	if ((sdpd->sdpd_args == NULL) || (sdpd->sdpd_args[0] == '\0'))
		return NULL;

	/*
	 * Take a copy of the string so we can mutate it without causing trouble
	 * on module reload.
	 */
 	argstr = kstrdup(sdpd->sdpd_args, GFP_KERNEL);
	if (argstr == NULL)
		goto oom;

	/*
	 * Handle the common case of a trailing comma before we allocate space,
	 * and elide it.
	 */
	p = argstr + strlen(argstr) - 1;
	if (p[0] == ',' && p[1] == '\0')
		*p = '\0';

	/*
	 * This works for counting the number of args even though translator
	 * strings can contain commas, because each comma denotes a new probe
	 * argument.  It may overcount in the case of elided arguments
	 * ("foo : ,"): we compensate for that further down, and ignore the tiny
	 * memory leak that results.
	 */
	for (p = argstr; p != NULL; p = strchr(p + 1, ','))
		(*sdp_nargdesc)++;

	args = kzalloc(*sdp_nargdesc * sizeof (struct sdt_argdesc),
		GFP_KERNEL);
	if (args == NULL)
		goto oom_argstr;

	/*
	 * We need to transform each arg (stripping off a terminal argument
	 * name) if this is a perf probe.
	 */
	if (strncmp(sdpd->sdpd_name, "__perf_", strlen("__perf_")) == 0)
		arg_strip = 1;

	next_arg = argstr;
	do {
		char *tok;
		char *xlator = NULL, *p;
		char *native;
		int parens = 0;
		int empty_xlation;

		/*
		 * Find the end of this arg, and figure out if it has any
		 * translators.  Clean up the type of the arg (or native type,
		 * if this is a translated type).
		 */
		tok = next_arg;
		next_arg = NULL;
		p = strpbrk(tok, "():,");
		while (p && !next_arg) {
			switch(*p) {
			case '(': parens++;
				break;
			case ')': if (parens > 0)
					parens--;
				break;
			case ':': *p = '\0';
				xlator = p + 1;
				break;
			case ',': if (parens == 0) {
					*p = '\0';
					next_arg = p + 1;
				}
				break;
			}
			p = strpbrk(p + 1, "():,");
		}

		native = cleanup_type(tok, arg_strip);
		if (native == NULL) {
			args[arg].sda_native = args[arg].sda_xlate = NULL;
			goto full_oom;
		}

		/*
		 * Special case: perf's DECLARE_TRACE_NOARGS passes a single arg
		 * 'void'. Spot and skip it.
		 */
		if (!xlator && arg_strip && strcmp(native, "void") == 0) {
			kfree(native);
			(*sdp_nargdesc)--;
			sarg++;
			continue;
		}

		/*
		 * No translator: straight mapping.
		 */
		if (xlator == NULL) {
			ASSERT(arg < *sdp_nargdesc);
			args[arg].sda_mapping = sarg;
			args[arg].sda_native = native;
			args[arg].sda_xlate = NULL;
			arg++;
			sarg++;
			continue;
		}

		/*
		 * If this is a perf probe, warn: translations cannot exist for
		 * these, and have no defined format yet in any case.  We can
		 * struggle on by assuming they look like SDT translations.
		 */
		if (arg_strip)
			pr_warn("Perf probe %s has at least one SDT translation, "
				"which should be impossible.", sdpd->sdpd_name);

		/*
		 * Zero or more translations.  (If there are zero, i.e. a pair
		 * of empty parentheses or a colon with nothing after it, we
		 * have to decrement the nargdesc.)
		 */

		empty_xlation = 1;
		while ((p = strsep(&xlator, "(,)")) != NULL) {
			/*
			 * Skip the empty space before the ( or after the ).
			 */
			if (strspn(p, " \t") == strlen(p))
				continue;

			ASSERT(arg < *sdp_nargdesc);

			empty_xlation = 0;
			args[arg].sda_mapping = sarg;
			args[arg].sda_native = kstrdup(native, GFP_KERNEL);
			args[arg].sda_xlate = cleanup_type(p, 0);
			if ((args[arg].sda_native == NULL) ||
			    (args[arg].sda_xlate == NULL)) {
				pr_warn("Unable to create argdesc list for "
					"probe %s: out-of-memory\n",
					sdpd->sdpd_name);
				kfree(native);
				goto full_oom;
			}
			arg++;
		}
		if (empty_xlation)
			(*sdp_nargdesc)--;

		kfree(native);
		sarg++;
	} while (next_arg != NULL);

	kfree(argstr);
	return args;

full_oom:
	for (i = 0; i < arg; i++) {
		kfree(args[i].sda_native);
		kfree(args[i].sda_xlate);
	}
	kfree(args);
oom_argstr:
	kfree(argstr);
oom:
	*sdp_nargdesc = 0;
	pr_warn("Unable to create argdesc list for probe %s: "
		"out-of-memory\n", sdpd->sdpd_name);
	return NULL;
}

void sdt_provide_module(void *arg, struct module *mp)
{
	char			*modname = mp->name;
	dtrace_mprovider_t	*prov;
	sdt_probedesc_t		*sdpd;
	sdt_probe_t		*sdp, *prv;
	int			idx, len;

	/*
	 * Nothing to do if the module SDT probes were already created.
	 */
	if (PDATA(mp)->sdt_probe_cnt != 0)
		return;

	/*
	 * Nothing to do if there are no SDT probes.
	 */
	if (mp->sdt_probec == 0)
		return;

	/*
	 * Do not provide any probes unless all SDT providers have been created
	 * for this meta-provider.
	 */
	for (prov = sdt_providers; prov->dtmp_name != NULL; prov++) {
		if (prov->dtmp_id == DTRACE_PROVNONE)
			return;
	}

	if (!sdt_provide_module_arch(arg, mp))
		return;

	for (idx = 0, sdpd = mp->sdt_probes; idx < mp->sdt_probec;
	     idx++, sdpd++) {
		char			*name = sdpd->sdpd_name, *nname;
		int			i, j;
		dtrace_mprovider_t	*prov;
		dtrace_id_t		id;

		for (prov = sdt_providers; prov->dtmp_pref != NULL; prov++) {
			char	*prefix = prov->dtmp_pref;
			int	len = strlen(prefix);

			if (strncmp(name, prefix, len) == 0) {
				name += len;
				break;
			}
		}

		nname = kmalloc(len = strlen(name) + 1, GFP_KERNEL);
		if (nname == NULL) {
			pr_warn("Unable to create probe %s: out-of-memory\n",
				name);
			continue;
		}

		for (i = j = 0; name[j] != '\0'; i++) {
			if (name[j] == '_' && name[j + 1] == '_') {
				nname[i] = '-';
				j += 2;
			} else
				nname[i] = name[j++];
		}

		nname[i] = '\0';

		sdp = kzalloc(sizeof(sdt_probe_t), GFP_KERNEL);
		if (sdp == NULL) {
			pr_warn("Unable to create probe %s: out-of-memory\n",
				nname);
			continue;
		}

		sdp->sdp_loadcnt = 1; /* FIXME */
		sdp->sdp_module = mp;
		sdp->sdp_name = nname;
		sdp->sdp_namelen = len;
		sdp->sdp_provider = prov;

		sdp->sdp_argdesc = sdt_setup_args(sdpd, &sdp->sdp_nargdesc);

		if ((id = dtrace_probe_lookup(prov->dtmp_id, modname,
					      sdpd->sdpd_func, nname)) !=
				DTRACE_IDNONE) {
			prv = dtrace_probe_arg(prov->dtmp_id, id);
			ASSERT(prv != NULL);

			sdp->sdp_next = prv->sdp_next;
			sdp->sdp_id = id;
			prv->sdp_next = sdp;
		} else {
			sdp->sdp_id = dtrace_probe_create(prov->dtmp_id,
							  modname,
							  sdpd->sdpd_func,
							  nname, SDT_AFRAMES,
							  sdp);
			PDATA(mp)->sdt_probe_cnt++;
		}

		sdp->sdp_hashnext = sdt_probetab[
					SDT_ADDR2NDX(sdpd->sdpd_offset)];
		sdt_probetab[SDT_ADDR2NDX(sdpd->sdpd_offset)] = sdp;

		sdp->sdp_patchpoint = (asm_instr_t *)sdpd->sdpd_offset;

		sdt_provide_probe_arch(sdp, mp, idx);
	}
}

int _sdt_enable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t	*sdp = parg;

	/*
	 * Ensure that we have a reference to the module.
	 */
	if (!try_module_get(sdp->sdp_module))
		return -EAGAIN;

	/*
	 * If at least one other enabled probe exists for this module, drop the
	 * reference we took above, because we only need one to prevent the
	 * module from being unloaded.
	 */
	PDATA(sdp->sdp_module)->sdt_enabled++;
	if (PDATA(sdp->sdp_module)->sdt_enabled > 1)
		module_put(sdp->sdp_module);

	while (sdp != NULL) {
		sdt_enable_arch(sdp, id, arg);
		sdp = sdp->sdp_next;
	}

	return 0;
}

void _sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t	*sdp = parg;

	/*
	 * If we are disabling a probe, we know it was enabled, and therefore
	 * we know that we have a reference on the module to prevent it from
	 * being unloaded.  If we disable the last probe on the module, we can
	 * drop the reference.
	 */
	PDATA(sdp->sdp_module)->sdt_enabled--;
	if (PDATA(sdp->sdp_module)->sdt_enabled == 0)
		module_put(sdp->sdp_module);

	while (sdp != NULL) {
		sdt_disable_arch(sdp, id, arg);
		sdp = sdp->sdp_next;
	}
}

void sdt_getargdesc(void *arg, dtrace_id_t id, void *parg,
		    dtrace_argdesc_t *desc)
{
	sdt_probe_t	*sdp = parg;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	if (sdp->sdp_nargdesc <= desc->dtargd_ndx) {
		desc->dtargd_ndx = DTRACE_ARGNONE;
		return;
	}

	if (sdp->sdp_argdesc[desc->dtargd_ndx].sda_native != NULL)
		strlcpy(desc->dtargd_native,
			sdp->sdp_argdesc[desc->dtargd_ndx].sda_native,
			sizeof(desc->dtargd_native));

	if (sdp->sdp_argdesc[desc->dtargd_ndx].sda_xlate != NULL)
		strlcpy(desc->dtargd_xlate,
			sdp->sdp_argdesc[desc->dtargd_ndx].sda_xlate,
			sizeof(desc->dtargd_xlate));

	desc->dtargd_mapping = sdp->sdp_argdesc[desc->dtargd_ndx].sda_mapping;
}

void sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t	*sdp = parg;

	PDATA(sdp->sdp_module)->sdt_probe_cnt--;

	while (sdp != NULL) {
		sdt_probe_t	*old = sdp, *last, *hash;
		int		ndx;
		size_t		i;

		ndx = SDT_ADDR2NDX(sdp->sdp_patchpoint);
		last = NULL;
		hash = sdt_probetab[ndx];

		while (hash != sdp) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->sdp_hashnext;
		}

		if (last != NULL)
			last->sdp_hashnext = sdp->sdp_hashnext;
		else
			sdt_probetab[ndx] = sdp->sdp_hashnext;

		for (i = 0; i < sdp->sdp_nargdesc; i++) {
			kfree(sdp->sdp_argdesc[i].sda_native);
			kfree(sdp->sdp_argdesc[i].sda_xlate);
		}
		kfree(sdp->sdp_argdesc);
		kfree(sdp->sdp_name);
		sdp = sdp->sdp_next;
		kfree(old);
	}
}

static long sdt_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	return -EAGAIN;
}

static int sdt_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int sdt_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations sdt_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = sdt_ioctl,
        .open   = sdt_open,
        .release = sdt_close,
};

static struct miscdevice sdt_dev = {
	.minor = DT_DEV_SDT_MINOR,
	.name = "sdt",
	.nodename = "dtrace/provider/sdt",
	.fops = &sdt_fops,
};

int sdt_dev_init(void)
{
	int ret = 0;

	ret = misc_register(&sdt_dev);
	if (ret) {
		pr_err("%s: Can't register misc device %d\n",
		       sdt_dev.name, sdt_dev.minor);
		return ret;
	}

	if (sdt_probetab_size == 0)
		sdt_probetab_size = SDT_PROBETAB_SIZE;

	sdt_probetab_mask = sdt_probetab_size - 1;
	sdt_probetab = vzalloc(sdt_probetab_size * sizeof(sdt_probe_t *));
	if (sdt_probetab == NULL)
		return -ENOMEM;

	sdt_dev_init_arch();

	return ret;
}

void sdt_dev_exit(void)
{
	sdt_dev_exit_arch();

	vfree(sdt_probetab);

	misc_deregister(&sdt_dev);
}
