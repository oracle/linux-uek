/*
 * FILE:	dt_test_dev.c
 * DESCRIPTION:	DTrace Test Probe: device file handling
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
 * Copyright 2011, 2012 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
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

int _dt_test_enable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 1;

	return 0;
}

void _dt_test_disable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 0;
}

void dt_test_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static long dt_test_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	/*
	 * Yes, this is not nice.
	 * Not at all.
	 * But we're doing it anyway...
	 */
	void (*dt_test_probe)(dtrace_id_t, uintptr_t, uintptr_t, uintptr_t,
			      uintptr_t, uintptr_t, uintptr_t, uintptr_t,
			      uintptr_t, uintptr_t, uintptr_t);

	if (enabled) {
		dt_test_probe = (void *)&dtrace_probe;
		dt_test_probe(pid, cmd, arg, 2ULL, 3ULL, 4ULL, 5ULL,
					     6ULL, 7ULL, 8ULL, 9ULL);

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
