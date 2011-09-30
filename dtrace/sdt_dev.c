/*
 * FILE:	sdt_dev.c
 * DESCRIPTION:	Statically Defined Tracing: device file handling
 *
 * Copyright (C) 2010 Oracle Corporation
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
