/*
 * FILE:	systrace_dev.c
 * DESCRIPTION:	System Call Tracing: device file handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#if 0
#include <trace/syscall.h>
#endif
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
#if 0
		struct syscall_metadata	*sm = syscall_nr_to_meta(i);
		const char		*nm;

		if (sm == NULL)
			continue;
#else
		const char		*nm = systrace_info->sysent[i].name;
		int			sz;
#endif
printk(KERN_INFO "systrace_provide: [%d] = %s\n", i, nm);
		if (nm == NULL)
			continue;

		if (systrace_info->sysent[i].stsy_underlying == NULL)
			continue;

#if 0
		nm = sm->name;
#endif
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

int systrace_enable(void *arg, dtrace_id_t id, void *parg)
{
	int	sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int	enabled =
		systrace_info->sysent[sysnum].stsy_entry != DTRACE_IDNONE ||
		systrace_info->sysent[sysnum].stsy_return != DTRACE_IDNONE;

#if 0
	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		systrace_info->sysent[sysnum].stsy_entry = id;
	else
		systrace_info->sysent[sysnum].stsy_return = id;

	if (enabled) {
		ASSERT((void *)*(systrace_info->sysent[sysnum].stsy_tblent) ==
		       (void *)systrace_info->syscall);

		return 0;
	}

	(void)cmpxchg(systrace_info->sysent[sysnum].stsy_tblent,
		      systrace_info->sysent[sysnum].stsy_underlying,
		      systrace_info->syscall);
#else
	if (!enabled) {
		if (cmpxchg(systrace_info->sysent[sysnum].stsy_tblent,
			    systrace_info->sysent[sysnum].stsy_underlying,
			    systrace_info->syscall) !=
		    systrace_info->sysent[sysnum].stsy_underlying)
			return 0;
	} else
		ASSERT((void *)*(systrace_info->sysent[sysnum].stsy_tblent) ==
		       (void *)systrace_info->syscall);

	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		systrace_info->sysent[sysnum].stsy_entry = id;
	else
		systrace_info->sysent[sysnum].stsy_return = id;
#endif

	return 0;
}

void systrace_disable(void *arg, dtrace_id_t id, void *parg)
{
	int	sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int	enabled =
		systrace_info->sysent[sysnum].stsy_entry != DTRACE_IDNONE ||
		systrace_info->sysent[sysnum].stsy_return != DTRACE_IDNONE;

	if (enabled)
		(void)cmpxchg(systrace_info->sysent[sysnum].stsy_tblent,
			      systrace_info->syscall,
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
