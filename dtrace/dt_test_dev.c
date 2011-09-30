/*
 * FILE:	dt_test_dev.c
 * DESCRIPTION:	DTrace Test Probe: device file handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <trace/syscall.h>
#include <asm/unistd.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "dt_test.h"

static dtrace_id_t	pid = 0;
static int		enabled = 0;

void dt_test_provide(void *arg, const dtrace_probedesc_t *desc)
{
	if (dtrace_probe_lookup(dt_test_id, "dt_test", NULL, "test") != 0)
		return;

	pid = dtrace_probe_create(dt_test_id,
				  "dt_test", NULL, "test", 0, NULL);
}

int dt_test_enable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 1;

	return 0;
}

void dt_test_disable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 0;
}

void dt_test_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static long dt_test_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	if (enabled) {
		dtrace_probe(pid, cmd, arg, 2, 3, 4);

		return 0;
	}

	return -EAGAIN;
}

static int dt_test_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dt_test_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations dt_test_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = dt_test_ioctl,
        .open   = dt_test_open,
        .release = dt_test_close,
};

static struct miscdevice dt_test_dev = {
	.minor = DT_DEV_DT_TEST_MINOR,
	.name = "dt_test",
	.nodename = "dtrace/provider/dt_test",
	.fops = &dt_test_fops,
};

int dt_test_dev_init(void)
{
	int	ret = 0;

	ret = misc_register(&dt_test_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       dt_test_dev.name, dt_test_dev.minor);

	return ret;
}

void dt_test_dev_exit(void)
{
	misc_deregister(&dt_test_dev);
}
