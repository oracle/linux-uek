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

#include "dtrace_dev.h"

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

	ret = misc_register(&fbt_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       fbt_dev.name, fbt_dev.minor);

	return ret;
}

void fbt_dev_exit(void)
{
	misc_deregister(&fbt_dev);
}
