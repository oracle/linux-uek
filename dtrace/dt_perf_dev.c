/*
 * FILE:	dt_pref_dev.c
 * DESCRIPTION:	DTrace Performance Test Probe: device file handling
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
 * Copyright 2011, 2012, 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
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
		tm1.tv64 -= tm0.tv64;

		dtrace_probe(result_pid, cmd, arg, tm1.tv64, tm1.tv64 >> 32, 0);
		break;

	case _IOW(1, 2, int): {
		extern void dtrace_sdt_perf(void);

		tm0 = dtrace_gethrtime();
		for (i = 0; i < arg; i++)
		    dtrace_sdt_perf();

		tm1 = dtrace_gethrtime();
		tm1.tv64 -= tm0.tv64;

		dtrace_probe(result_pid, cmd, arg, tm1.tv64, tm1.tv64 >> 32, 0);
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
	.minor = DT_DEV_DT_TEST_MINOR,
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
