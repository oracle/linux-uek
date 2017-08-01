/*
 * FILE:	dt_pref_dev.c
 * DESCRIPTION:	DTrace - perf provider device driver
 *
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <trace/syscall.h>
#include <asm/unistd.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "dt_perf.h"

static dtrace_id_t	invoke_pid = 0;
static dtrace_id_t	result_pid = 0;
static int		enabled = 0;

void dt_perf_provide(void *arg, const dtrace_probedesc_t *desc)
{
	if (dtrace_probe_lookup(dt_perf_id, "dt_perf", NULL, "invoke") != 0)
		return;

	invoke_pid = dtrace_probe_create(dt_perf_id,
				  "dt_perf", NULL, "invoke", 0, NULL);
	result_pid = dtrace_probe_create(dt_perf_id,
				  "dt_perf", NULL, "result", 0, NULL);
}

int _dt_perf_enable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 1;

	return 0;
}

void _dt_perf_disable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 0;
}

void dt_perf_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static long dt_perf_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	unsigned long	i;
	ktime_t		tm0, tm1;

	if (!enabled)
		return -EAGAIN;

	switch (cmd) {
	case _IOW(1, 1, int):
		tm0 = dtrace_gethrtime();
		for (i = 0; i < arg; i++)
		    dtrace_probe(invoke_pid, cmd, arg, 2, 3, 4);

		tm1 = dtrace_gethrtime();
		tm1 -= tm0;

		dtrace_probe(result_pid, cmd, arg, tm1, tm1 >> 32, 0);
		break;

	case _IOW(1, 2, int): {
		extern void dtrace_sdt_perf(void);

		tm0 = dtrace_gethrtime();
		for (i = 0; i < arg; i++)
		    dtrace_sdt_perf();

		tm1 = dtrace_gethrtime();
		tm1 -= tm0;

		dtrace_probe(result_pid, cmd, arg, tm1, tm1 >> 32, 0);
		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

static int dt_perf_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dt_perf_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations dt_perf_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = dt_perf_ioctl,
        .open   = dt_perf_open,
        .release = dt_perf_close,
};

static struct miscdevice dt_perf_dev = {
	.minor = DT_DEV_DT_PERF_MINOR,
	.name = "dt_perf",
	.nodename = "dtrace/provider/dt_perf",
	.fops = &dt_perf_fops,
};

int dt_perf_dev_init(void)
{
	int	ret = 0;

	ret = misc_register(&dt_perf_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       dt_perf_dev.name, dt_perf_dev.minor);

	return ret;
}

void dt_perf_dev_exit(void)
{
	misc_deregister(&dt_perf_dev);
}
