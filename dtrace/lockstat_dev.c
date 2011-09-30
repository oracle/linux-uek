/*
 * FILE:	lockstat_dev.c
 * DESCRIPTION:	Lock Statistics: device file handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>

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
