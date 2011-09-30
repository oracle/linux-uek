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
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "dtrace_dev.h"

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
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       sdt_dev.name, sdt_dev.minor);

	return ret;
}

void sdt_dev_exit(void)
{
	misc_deregister(&sdt_dev);
}
