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

static sdt_argdesc_t	sdt_args[] = {
	/*
	 * { name, provider, ndx, mapping, native, xlate }
	 */
	{ "io", "done", 0, 0, "struct buffer_head *", "bufinfo_t *" },
	{ "io", "done", 1, 0, "struct buffer_head *", "devinfo_t *" },
	{ "io", "done", 2, 0, "struct buffer_head *", "fileinfo_t *" },
	{ "io", "start", 0, 0, "struct buffer_head *", "bufinfo_t *" },
	{ "io", "start", 1, 0, "struct buffer_head *", "devinfo_t *" },
	{ "io", "start", 2, 0, "struct buffer_head *", "fileinfo_t *" },
	{ "io", "wait-done", 0, 0, "struct buffer_head *", "bufinfo_t *" },
	{ "io", "wait-done", 1, 0, "struct buffer_head *", "devinfo_t *" },
	{ "io", "wait-done", 2, 0, "struct buffer_head *", "fileinfo_t *" },
	{ "io", "wait-start", 0, 0, "struct buffer_head *", "bufinfo_t *" },
	{ "io", "wait-start", 1, 0, "struct buffer_head *", "devinfo_t *" },
	{ "io", "wait-start", 2, 0, "struct buffer_head *", "fileinfo_t *" },

	{ "proc", "create", 0, 0, "struct task_struct *", "psinfo_t *" },
	{ "proc", "exec", 0, 0, "char *", },
	{ "proc", "exec-failure", 0, 0, "int", },
	{ "proc", "exit", 0, 0, "int", },
#if 0
	{ "proc", "fault", 0, 0, "int", },
	{ "proc", "fault", 1, 1, "siginfo_t", },
#endif
	{ "proc", "lwp-create", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "proc", "lwp-create", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "proc", "signal-clear", 0, 0, "int", },
	{ "proc", "signal-discard", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "proc", "signal-discard", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "proc", "signal-discard", 2, 1, "int", },
	{ "proc", "signal-handle", 0, 0, "int" },
	{ "proc", "signal-handle", 1, 1, "siginfo_t *" },
	{ "proc", "signal-handle", 2, 2, "void (*)(void)" },
	{ "proc", "signal-send", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "proc", "signal-send", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "proc", "signal-send", 2, 1, "int", },

	{ "sched", "change-pri", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "change-pri", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "sched", "change-pri", 2, 1, "int", },
	{ "sched", "dequeue", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "dequeue", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "sched", "dequeue", 2, 1, "cpuinfo_t *", },
	{ "sched", "dequeue", 3, 2, "int", },
	{ "sched", "enqueue", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "enqueue", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "sched", "enqueue", 2, 1, "cpuinfo_t *", },
	{ "sched", "off-cpu", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "off-cpu", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "sched", "surrender", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "surrender", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "sched", "tick", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "tick", 1, 0, "struct task_struct *", "psinfo_t *" },
	{ "sched", "wakeup", 0, 0, "struct task_struct *", "lwpsinfo_t *" },
	{ "sched", "wakeup", 1, 0, "struct task_struct *", "psinfo_t *" },

	{ NULL, }
};

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

		sdp->sdp_patchpoint = (sdt_instr_t *)sdpd->sdpd_offset;

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
	int		i;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	for (i = 0; sdt_args[i].sda_provider != NULL; i++) {
		sdt_argdesc_t	*a = &sdt_args[i];

		if (strcmp(sdp->sdp_provider->dtmp_name, a->sda_provider) != 0)
			continue;

		if (a->sda_name != NULL &&
		    strcmp(sdp->sdp_name, a->sda_name) != 0)
				continue;

		if (desc->dtargd_ndx != a->sda_ndx)
			continue;

		if (a->sda_native != NULL)
			strcpy(desc->dtargd_native, a->sda_native);

		if (a->sda_xlate != NULL)
			strcpy(desc->dtargd_xlate, a->sda_xlate);

		desc->dtargd_mapping = a->sda_mapping;

		return;
	}

	desc->dtargd_ndx = DTRACE_ARGNONE;
}

void sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t	*sdp = parg;

	PDATA(sdp->sdp_module)->sdt_probe_cnt--;

	while (sdp != NULL) {
		sdt_probe_t	*old = sdp, *last, *hash;
		int		ndx;

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
