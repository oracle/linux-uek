/*
 * FILE:	lockstat_dev.c
 * DESCRIPTION:	Lock Statistics: device file handling
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

#include "dtrace.h"
#include "dtrace_dev.h"

static long lockstat_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	return -EAGAIN;
}

static int lockstat_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int lockstat_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations lockstat_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = lockstat_ioctl,
        .open   = lockstat_open,
        .release = lockstat_close,
};

static struct miscdevice lockstat_dev = {
	.minor = DT_DEV_LOCKSTAT_MINOR,
	.name = "dtrace",
	.nodename = "dtrace/provider/lockstat",
	.fops = &lockstat_fops,
};

int lockstat_dev_init(void)
{
	int ret = 0;

	ret = misc_register(&lockstat_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       lockstat_dev.name, lockstat_dev.minor);

	return ret;
}

void lockstat_dev_exit(void)
{
	misc_deregister(&lockstat_dev);
}
