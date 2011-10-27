/*
 * FILE:	systrace_dev.c
 * DESCRIPTION:	System Call Tracing: device file handling
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
#include <asm/unistd.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "systrace.h"

#define SYSTRACE_ARTIFICIAL_FRAMES	1

#define SYSTRACE_SHIFT			16
#define SYSTRACE_ENTRY(id)		((1 << SYSTRACE_SHIFT) | (id))
#define SYSTRACE_RETURN(id)		(id)
#define SYSTRACE_SYSNUM(x)		((int)(x) & ((1 << SYSTRACE_SHIFT) - 1))
#define SYSTRACE_ISENTRY(x)		((int)(x) >> SYSTRACE_SHIFT)

#if ((1 << SYSTRACE_SHIFT) <= NR_syscalls)
# error 1 << SYSTRACE_SHIFT must exceed number of system calls
#endif

static systrace_info_t	*systrace_info = NULL;

void systrace_provide(void *arg, const dtrace_probedesc_t *desc)
{
	int	i;

	ASSERT(systrace_info != NULL);

	if (desc != NULL)
		return;

	for (i = 0; i < NR_syscalls; i++) {
		const char		*nm = systrace_info->sysent[i].name;
		int			sz;

		if (nm == NULL)
			continue;

		if (systrace_info->sysent[i].stsy_underlying == NULL)
			continue;

		sz = strlen(nm);
		if (sz > 4 && memcmp(nm, "sys_", 4) == 0)
			nm += 4;
		else if (sz > 5 && memcmp(nm, "stub_", 5) == 0)
			nm += 5;

		if (dtrace_probe_lookup(syscall_id, NULL, nm, "entry") != 0)
			continue;

		dtrace_probe_create(syscall_id, NULL, nm, "entry",
				    SYSTRACE_ARTIFICIAL_FRAMES,
				    (void *)((uintptr_t)SYSTRACE_ENTRY(i)));
		dtrace_probe_create(syscall_id, NULL, nm, "return",
				    SYSTRACE_ARTIFICIAL_FRAMES,
				    (void *)((uintptr_t)SYSTRACE_RETURN(i)));

		systrace_info->sysent[i].stsy_entry = DTRACE_IDNONE;
		systrace_info->sysent[i].stsy_return = DTRACE_IDNONE;
	}
}

static dt_sys_call_t get_intercept(int sysnum)
{
	switch (sysnum) {
	default:
		return systrace_info->syscall;
	case __NR_clone:
		return systrace_info->stubs[SCE_CLONE];
	case __NR_fork:
		return systrace_info->stubs[SCE_FORK];
	case __NR_vfork:
		return systrace_info->stubs[SCE_VFORK];
	case __NR_sigaltstack:
		return systrace_info->stubs[SCE_SIGALTSTACK];
	case __NR_iopl:
		return systrace_info->stubs[SCE_IOPL];
	case __NR_execve:
		return systrace_info->stubs[SCE_EXECVE];
	case __NR_rt_sigreturn:
		return systrace_info->stubs[SCE_RT_SIGRETURN];
	}
}

int systrace_enable(void *arg, dtrace_id_t id, void *parg)
{
	int		sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int		enabled =
		systrace_info->sysent[sysnum].stsy_entry != DTRACE_IDNONE ||
		systrace_info->sysent[sysnum].stsy_return != DTRACE_IDNONE;
	dt_sys_call_t	intercept = get_intercept(sysnum);;

	if (!enabled) {
		if (cmpxchg(systrace_info->sysent[sysnum].stsy_tblent,
			    systrace_info->sysent[sysnum].stsy_underlying,
			    intercept) !=
		    systrace_info->sysent[sysnum].stsy_underlying)
			return 0;
	} else
		ASSERT((void *)*(systrace_info->sysent[sysnum].stsy_tblent) ==
		       (void *)intercept);

	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		systrace_info->sysent[sysnum].stsy_entry = id;
	else
		systrace_info->sysent[sysnum].stsy_return = id;

	return 0;
}

void systrace_disable(void *arg, dtrace_id_t id, void *parg)
{
	int		sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int		enabled =
		systrace_info->sysent[sysnum].stsy_entry != DTRACE_IDNONE ||
		systrace_info->sysent[sysnum].stsy_return != DTRACE_IDNONE;
	dt_sys_call_t	intercept = get_intercept(sysnum);;

	if (enabled)
		(void)cmpxchg(systrace_info->sysent[sysnum].stsy_tblent,
			      intercept,
			      systrace_info->sysent[sysnum].stsy_underlying);

	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		systrace_info->sysent[sysnum].stsy_entry = DTRACE_IDNONE;
	else
		systrace_info->sysent[sysnum].stsy_return = DTRACE_IDNONE;
}

void systrace_destroy(void *arg, dtrace_id_t id, void *parg)
{
	int	sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);

	/*
	 * Nothing to be done here - just ensure our probe has been disabled.
	 */
	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		ASSERT(systrace_info->sysent[sysnum].stsy_entry ==
		       DTRACE_IDNONE);
	else
		ASSERT(systrace_info->sysent[sysnum].stsy_return ==
		       DTRACE_IDNONE);
}

static long systrace_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	return -EAGAIN;
}

static int systrace_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int systrace_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations systrace_fops = {
	.owner  = THIS_MODULE,
        .unlocked_ioctl = systrace_ioctl,
        .open   = systrace_open,
        .release = systrace_close,
};

static struct miscdevice systrace_dev = {
	.minor = DT_DEV_SYSTRACE_MINOR,
	.name = "systrace",
	.nodename = "dtrace/provider/systrace",
	.fops = &systrace_fops,
};

int syscall_dev_init(void)
{
	int	ret = 0;

	systrace_info = dtrace_syscalls_init();

	ret = misc_register(&systrace_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       systrace_dev.name, systrace_dev.minor);

	*(systrace_info->probep) = (dtrace_systrace_probe_t)dtrace_probe;

	return ret;
}

void syscall_dev_exit(void)
{
	*(systrace_info->probep) = systrace_info->stub;

	misc_deregister(&systrace_dev);
}
