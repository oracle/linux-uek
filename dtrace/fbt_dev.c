/*
 * FILE:	fbt_dev.c
 * DESCRIPTION:	Function Boundary Tracing: device file handling
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
 * Copyright 2010-2017 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/dtrace_fbt.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

#define FBT_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

fbt_probe_t		**fbt_probetab;
int			fbt_probetab_size = FBT_PROBETAB_SIZE;
int			fbt_probetab_mask;

static void *fbt_provide_probe(struct module *mp, char *func, int type, int
			       stype, asm_instr_t *addr, uintptr_t off,
			       void *pfbt)
{
	fbt_probe_t	*fbp;
	fbt_probe_t	*prev;

	switch (type) {
	case FBT_ENTRY:
		fbp = kzalloc(sizeof(fbt_probe_t), GFP_KERNEL);
		fbp->fbp_name = kstrdup(func, GFP_KERNEL);
		fbp->fbp_id = dtrace_probe_create(fbt_id, mp->name, func,
						  "entry", FBT_AFRAMES, fbp);
		fbp->fbp_module = mp;
		fbp->fbp_loadcnt = 1; /* FIXME */
		fbp->fbp_primary = 1; /* FIXME */
		fbp->fbp_roffset = off;
		fbp->fbp_patchpoint = addr;
		fbt_provide_probe_arch(fbp, type, stype);
                fbp->fbp_hashnext = fbt_probetab[FBT_ADDR2NDX(addr)];

		fbt_probetab[FBT_ADDR2NDX(addr)] = fbp;

		PDATA(mp)->fbt_probe_cnt++;

		return fbp;
	case FBT_RETURN:
		fbp = kzalloc(sizeof(fbt_probe_t), GFP_KERNEL);
		fbp->fbp_name = kstrdup(func, GFP_KERNEL);

		prev = (fbt_probe_t *)pfbt;
		if (prev != NULL) {
			prev->fbp_next = fbp;
			fbp->fbp_id = prev->fbp_id;
		} else {
			fbp->fbp_id = dtrace_probe_create(fbt_id, mp->name,
							  func, "return",
							  FBT_AFRAMES, fbp);
		}

		fbp->fbp_module = mp;
		fbp->fbp_loadcnt = 1; /* FIXME */
		fbp->fbp_primary = 1; /* FIXME */
		fbp->fbp_roffset = off;
		fbp->fbp_patchpoint = addr;
		fbt_provide_probe_arch(fbp, type, stype);
                fbp->fbp_hashnext = fbt_probetab[FBT_ADDR2NDX(addr)];

		fbt_probetab[FBT_ADDR2NDX(addr)] = fbp;

		PDATA(mp)->fbt_probe_cnt++;

		return fbp;
	default:
		printk(KERN_INFO "FBT: Invalid probe type %d (%d) for %s\n",
		       type, stype, func);

		return NULL;
	}
}

void fbt_provide_module(void *arg, struct module *mp)
{
	/*
	 * Nothing to do if the module FBT probes were already created.
	 */
	if (PDATA(mp)->fbt_probe_cnt != 0)
		return;

	if (strncmp(mp->name, "vmlinux", 7))
		return;

	dtrace_fbt_init((fbt_add_probe_fn)fbt_provide_probe);
}

int _fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t	*fbp = parg;
	fbt_probe_t	*curr;

	/*
	 * Ensure that we have a reference to the module.
	 */
	if (!try_module_get(fbp->fbp_module))
		return -EAGAIN;

	/*
	 * If at least one other enabled probe exists for this module, drop the
	 * reference we took above, because we only need one to prevent the
	 * module from being unloaded.
	 */
	PDATA(fbp->fbp_module)->enabled_cnt++;
	if (PDATA(fbp->fbp_module)->enabled_cnt > 1)
		module_put(fbp->fbp_module);

	for (curr = fbp; curr != NULL; curr = curr->fbp_next)
		fbt_enable_arch(curr, id, arg);

	return 0;
}

void _fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t	*fbp = parg;
	fbt_probe_t	*curr;

	for (curr = fbp; curr != NULL; curr = curr->fbp_next)
		fbt_disable_arch(curr, id, arg);

	/*
	 * If we are disabling a probe, we know it was enabled, and therefore
	 * we know that we have a reference on the module to prevent it from
	 * being unloaded.  If we disable the last probe on the module, we can
	 * drop the reference.
	 */
	PDATA(fbp->fbp_module)->enabled_cnt--;
	if (PDATA(fbp->fbp_module)->enabled_cnt == 0)
		module_put(fbp->fbp_module);
}

void fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t	*fbp = parg;
	fbt_probe_t	*nxt, *hbp, *lst;
	struct module	*mp = fbp->fbp_module;
	int		ndx;

	do {
		if (mp != NULL)
			PDATA(mp)->fbt_probe_cnt--;

		ndx = FBT_ADDR2NDX(fbp->fbp_patchpoint);
		lst = NULL;
		hbp = fbt_probetab[ndx];

		while (hbp != fbp) {
			ASSERT(hbp != NULL);

			lst = hbp;
			hbp = hbp->fbp_hashnext;
		}

		if (lst != NULL)
			lst->fbp_hashnext = fbp->fbp_hashnext;
		else
			fbt_probetab[ndx] = fbp->fbp_hashnext;

		nxt = fbp->fbp_next;

		kfree(fbp);

		fbp = nxt;
	} while (fbp != NULL);
}

static long fbt_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	return -EAGAIN;
}

static int fbt_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int fbt_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations fbt_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = fbt_ioctl,
        .open   = fbt_open,
        .release = fbt_close,
};

static struct miscdevice fbt_dev = {
	.minor = DT_DEV_FBT_MINOR,
	.name = "fbt",
	.nodename = "dtrace/provider/fbt",
	.fops = &fbt_fops,
};

int fbt_dev_init(void)
{
	int ret = 0;

	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab = dtrace_vzalloc_try(fbt_probetab_size *
					  sizeof (fbt_probe_t *));

	ret = misc_register(&fbt_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       fbt_dev.name, fbt_dev.minor);

	fbt_dev_init_arch();

	return ret;
}

void fbt_dev_exit(void)
{
	fbt_dev_exit_arch();

	misc_deregister(&fbt_dev);

	vfree(fbt_probetab);
	fbt_probetab_mask = 0;
	fbt_probetab_size = 0;
}
