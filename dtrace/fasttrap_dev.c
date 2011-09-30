/*
 * FILE:	fasttrap_dev.c
 * DESCRIPTION:	Fasttrap Tracing: device file handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "dtrace_dev.h"

static long fasttrap_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	return -EAGAIN;
}

static int fasttrap_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int fasttrap_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations fasttrap_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = fasttrap_ioctl,
        .open   = fasttrap_open,
        .release = fasttrap_close,
};

static struct miscdevice fasttrap_dev = {
	.minor = DT_DEV_FASTTRAP_MINOR,
	.name = "fasttrap",
	.nodename = "dtrace/provider/fasttrap",
	.fops = &fasttrap_fops,
};

int fasttrap_dev_init(void)
{
	int ret = 0;

	ret = misc_register(&fasttrap_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       fasttrap_dev.name, fasttrap_dev.minor);

	return ret;
}

void fasttrap_dev_exit(void)
{
	misc_deregister(&fasttrap_dev);
}
