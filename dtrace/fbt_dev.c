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
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <asm/insn.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

#define FBT_PATCHVAL	0xf0
#define FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)
#define FBT_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

static fbt_probe_t		**fbt_probetab;
static int			fbt_probetab_size;
static int			fbt_probetab_mask;

static unsigned long	fbt_cnt_entry = 0;
static unsigned long	fbt_cnt_return = 0;

static void *fbt_provide_probe(struct module *mp, char *func,
				      uint8_t opc, uint8_t *addr,
				      void *pfbt)
{
	fbt_probe_t	*fbt;
	fbt_probe_t	*prev;

	switch (opc) {
	case FBT_PUSHL_EBP:
		fbt = kzalloc(sizeof(fbt_probe_t), GFP_KERNEL);
		fbt->fbp_name = func;
		fbt->fbp_id = dtrace_probe_create(fbt_id, mp->name, func,
						  "entry", 3, fbt);
		fbt->fbp_module = mp;
		fbt->fbp_loadcnt = 1; /* FIXME */
		fbt->fbp_primary = 1; /* FIXME */
		fbt->fbp_patchpoint = addr;
		fbt->fbp_patchval = FBT_PATCHVAL;
		fbt->fbp_savedval = *addr;
		fbt->fbp_rval = opc;
                fbt->fbp_hashnext = fbt_probetab[FBT_ADDR2NDX(addr)];

		fbt_probetab[FBT_ADDR2NDX(addr)] = fbt;

                mp->fbt_nprobes++;

		fbt_cnt_entry++;

		return fbt;
	case FBT_RET:
	case FBT_RET_IMM16:
		fbt = kzalloc(sizeof(fbt_probe_t), GFP_KERNEL);
		fbt->fbp_name = func;

		prev = (fbt_probe_t *)pfbt;
		if (prev != NULL) {
			prev->fbp_next = fbt;
			fbt->fbp_id = prev->fbp_id;
		} else {
			fbt->fbp_id = dtrace_probe_create(fbt_id, mp->name,
							  func, "return", 3,
							  fbt);
		}

		fbt->fbp_module = mp;
		fbt->fbp_loadcnt = 1; /* FIXME */
		fbt->fbp_primary = 1; /* FIXME */
		fbt->fbp_patchpoint = addr;
		fbt->fbp_patchval = FBT_PATCHVAL;
		fbt->fbp_savedval = *addr;
		fbt->fbp_rval = opc;
                fbt->fbp_hashnext = fbt_probetab[FBT_ADDR2NDX(addr)];

		fbt_probetab[FBT_ADDR2NDX(addr)] = fbt;

		mp->fbt_nprobes++;

		fbt_cnt_return++;

		return fbt;
	default:
		printk(KERN_INFO "FBT: Invalid opcode for %s\n", func);

		return NULL;
	}
}

void fbt_provide_module(void *arg, struct module *mp)
{
	printk(KERN_INFO "FBT: provide_module(%s)...\n", mp->name);

	/*
	 * Nothing to do if the module FBT probes were already created.
	 */
	if (mp->fbt_nprobes != 0)
		return;

#if 1
{
ktime_t tm0;
ktime_t tm1;

tm0 = dtrace_gethrtime();
	dtrace_fbt_init(fbt_provide_probe);
tm1 = dtrace_gethrtime();
printk(KERN_INFO "FBT: dtrace_fbt_init() took %lld nsec\n", (signed long long)tm1.tv64 - tm0.tv64);
}

	printk(KERN_INFO "FBT: Number of entry probes:  %lu\n", fbt_cnt_entry);
	printk(KERN_INFO "FBT: Number of return probes: %lu\n", fbt_cnt_return);
#else
	analyze_symbols();
#endif
}

int _fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
	return 1;
}

void _fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
}

void fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{ 
	fbt_probe_t	*fbt = parg;
	fbt_probe_t	*nxt, *hbp, *lst;
	struct module	*mp = fbt->fbp_module;
	int		ndx;

	do {
		if (mp != NULL)
			mp->fbt_nprobes--;

		ndx = FBT_ADDR2NDX(fbt->fbp_patchpoint);
		lst = NULL;
		hbp = fbt_probetab[ndx];

		while (hbp != fbt) {
			ASSERT(hbp != NULL);

			lst = hbp;
			hbp = hbp->fbp_hashnext;
		}

		if (lst != NULL)
			lst->fbp_hashnext = fbt->fbp_hashnext;
		else
			fbt_probetab[ndx] = fbt->fbp_hashnext;

		nxt = fbt->fbp_next;

		kfree(fbt);

		fbt = nxt;
	} while (fbt != NULL);
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

	if (fbt_probetab_size == 0)
		fbt_probetab_size = FBT_PROBETAB_SIZE;

	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab = dtrace_vzalloc_try(fbt_probetab_size *
					  sizeof (fbt_probe_t *));

	ret = misc_register(&fbt_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       fbt_dev.name, fbt_dev.minor);

	return ret;
}

void fbt_dev_exit(void)
{
	misc_deregister(&fbt_dev);

	vfree(fbt_probetab);
	fbt_probetab_mask = 0;
	fbt_probetab_size = 0;
}
