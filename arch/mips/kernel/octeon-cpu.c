/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2009 Wind River Systems,
 *   written by Ralf Baechle <ralf@linux-mips.org>
 */
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/notifier.h>
#include <linux/prefetch.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>

#include <asm/processor.h>
#include <asm/cop2.h>
#include <asm/current.h>
#include <asm/mipsregs.h>
#include <asm/page.h>
#include <asm/octeon/octeon.h>

/* the caller must hold RCU read lock */
static int is_task_and_current_same(struct task_struct *t)
{
	const struct cred *cred = current_cred(), *tcred;

	tcred = __task_cred(t);
	if ((__kuid_val(cred->euid) ^ __kuid_val(tcred->suid)) &&
	    (__kuid_val(cred->euid) ^ __kuid_val(tcred->uid)) &&
	    (__kuid_val(cred->uid)  ^ __kuid_val(tcred->suid)) &&
	    (__kuid_val(cred->uid)  ^ __kuid_val(tcred->uid))) {
		return 0;
	}
	return 1;
}

#if defined(CONFIG_CAVIUM_OCTEON_USER_MEM_PER_PROCESS) || \
	defined(CONFIG_CAVIUM_OCTEON_USER_IO_PER_PROCESS)
void octeon_prepare_arch_switch(struct task_struct *next)
{
	struct task_struct *group_leader = next->group_leader;
	union octeon_cvmemctl cvmmemctl;
	cvmmemctl.u64 = read_c0_cvmmemctl();

#if defined(CONFIG_CAVIUM_OCTEON_USER_MEM_PER_PROCESS)
	cvmmemctl.s.xkmemenau = test_tsk_thread_flag(group_leader, TIF_XKPHYS_MEM_EN) ? 1 : 0;
#endif

#if defined(CONFIG_CAVIUM_OCTEON_USER_IO_PER_PROCESS)
	cvmmemctl.s.xkioenau = test_tsk_thread_flag(group_leader, TIF_XKPHYS_IO_EN) ? 1 : 0;
#endif
	write_c0_cvmmemctl(cvmmemctl.u64);
}
#else
static void octeon_prepare_arch_switch(struct task_struct *next)
{
}
#endif

static struct task_struct *xkphys_get_task(pid_t pid)
{
	struct task_struct *task, *group_leader;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		read_unlock(&tasklist_lock);
		return NULL;
	}
	group_leader = task->group_leader;
	get_task_struct(group_leader);

	rcu_read_unlock();
	return group_leader;
}

int xkphys_usermem_read(long pid)
{
	struct task_struct *task;
	int io, mem;

	task = xkphys_get_task(pid);
	if (!task)
		return -ESRCH;
#if defined(CONFIG_CAVIUM_OCTEON_USER_IO)
	io = 1;
#elif defined(CONFIG_CAVIUM_OCTEON_USER_IO_PER_PROCESS)
	io = test_tsk_thread_flag(task, TIF_XKPHYS_IO_EN);
#else
	io = 0;
#endif

#if defined(CONFIG_CAVIUM_OCTEON_USER_MEM)
	mem = 1;
#elif defined(CONFIG_CAVIUM_OCTEON_USER_MEM_PER_PROCESS)
	mem = test_tsk_thread_flag(task, TIF_XKPHYS_MEM_EN);
#else
	mem = 0;
#endif
	put_task_struct(task);
	return (io ? 2 : 0) | (mem ? 1 : 0);
}

int xkphys_usermem_write(long pid, int value)
{
	struct task_struct *task, *group_leader;
	int permission_ok = 0;

#if defined(CONFIG_CAVIUM_OCTEON_USER_IO)
	if ((value & 2) == 0)
		return -EINVAL;
#elif !defined(CONFIG_CAVIUM_OCTEON_USER_IO_PER_PROCESS)
	if (value & 2)
		return -EINVAL;
#endif
#if defined(CONFIG_CAVIUM_OCTEON_USER_MEM)
	if ((value & 1) == 0)
		return -EINVAL;
#elif !defined(CONFIG_CAVIUM_OCTEON_USER_MEM_PER_PROCESS)
	if (value & 1)
		return -EINVAL;
#endif

	task = xkphys_get_task(pid);
	group_leader = task->group_leader;

	if (!task)
		return -ESRCH;

	rcu_read_lock();
	/* Allow XKPHYS disable of other tasks from the current user*/
	if (value == 0 && is_task_and_current_same(task))
		permission_ok = 1;
	rcu_read_unlock();

	if (capable(CAP_SYS_RAWIO))
		permission_ok = 1;

	if (!permission_ok) {
		put_task_struct(task);
		return -EPERM;
	}

	if (value & 1)
		set_tsk_thread_flag(group_leader, TIF_XKPHYS_MEM_EN);
	else
		clear_tsk_thread_flag(group_leader, TIF_XKPHYS_MEM_EN);

	if (value & 2)
		set_tsk_thread_flag(group_leader, TIF_XKPHYS_IO_EN);
	else
		clear_tsk_thread_flag(group_leader, TIF_XKPHYS_IO_EN);

	preempt_disable();

	/*
	 * If we are adjusting ourselves, make the change effective
	 * immediatly.
	 */
	if (group_leader == current->group_leader)
		octeon_prepare_arch_switch(current);

	preempt_enable();

	put_task_struct(task);
	return 0;
}

static int cnmips_cu2_call(struct notifier_block *nfb, unsigned long action,
	void *data)
{
	unsigned long flags;
	unsigned int status;

	switch (action) {
	case CU2_EXCEPTION:
		prefetch(&current->thread.cp2);
		local_irq_save(flags);
		KSTK_STATUS(current) |= ST0_CU2;
		status = read_c0_status();
		write_c0_status(status | ST0_CU2);
		octeon_cop2_restore(&(current->thread.cp2));
		write_c0_status(status & ~ST0_CU2);
		local_irq_restore(flags);

		return NOTIFY_BAD;	/* Don't call default notifier */
	}

	return NOTIFY_OK;		/* Let default notifier send signals */
}

static int __init cnmips_cu2_setup(void)
{
	return cu2_notifier(cnmips_cu2_call, 0);
}
early_initcall(cnmips_cu2_setup);
