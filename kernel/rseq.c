// SPDX-License-Identifier: GPL-2.0+
/*
 * Restartable sequences system call
 *
 * Copyright (C) 2015, Google, Inc.,
 * Paul Turner <pjt@google.com> and Andrew Hunter <ahh@google.com>
 * Copyright (C) 2015-2018, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/* Required to select the proper per_cpu ops for rseq_stats_inc() */
#define RSEQ_BUILD_SLOW_PATH

#include <linux/debugfs.h>
#include <linux/ratelimit.h>
#include <linux/hrtimer.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/rseq_entry.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <asm/ptrace.h>
#include <linux/prctl.h>

#define CREATE_TRACE_POINTS
#include <trace/events/rseq.h>

#define RSEQ_CS_PREEMPT_MIGRATE_FLAGS (RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE | \
				       RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT)

/*
 *
 * Restartable sequences are a lightweight interface that allows
 * user-level code to be executed atomically relative to scheduler
 * preemption and signal delivery. Typically used for implementing
 * per-cpu operations.
 *
 * It allows user-space to perform update operations on per-cpu data
 * without requiring heavy-weight atomic operations.
 *
 * Detailed algorithm of rseq user-space assembly sequences:
 *
 *                     init(rseq_cs)
 *                     cpu = TLS->rseq::cpu_id_start
 *   [1]               TLS->rseq::rseq_cs = rseq_cs
 *   [start_ip]        ----------------------------
 *   [2]               if (cpu != TLS->rseq::cpu_id)
 *                             goto abort_ip;
 *   [3]               <last_instruction_in_cs>
 *   [post_commit_ip]  ----------------------------
 *
 *   The address of jump target abort_ip must be outside the critical
 *   region, i.e.:
 *
 *     [abort_ip] < [start_ip]  || [abort_ip] >= [post_commit_ip]
 *
 *   Steps [2]-[3] (inclusive) need to be a sequence of instructions in
 *   userspace that can handle being interrupted between any of those
 *   instructions, and then resumed to the abort_ip.
 *
 *   1.  Userspace stores the address of the struct rseq_cs assembly
 *       block descriptor into the rseq_cs field of the registered
 *       struct rseq TLS area. This update is performed through a single
 *       store within the inline assembly instruction sequence.
 *       [start_ip]
 *
 *   2.  Userspace tests to check whether the current cpu_id field match
 *       the cpu number loaded before start_ip, branching to abort_ip
 *       in case of a mismatch.
 *
 *       If the sequence is preempted or interrupted by a signal
 *       at or after start_ip and before post_commit_ip, then the kernel
 *       clears TLS->__rseq_abi::rseq_cs, and sets the user-space return
 *       ip to abort_ip before returning to user-space, so the preempted
 *       execution resumes at abort_ip.
 *
 *   3.  Userspace critical section final instruction before
 *       post_commit_ip is the commit. The critical section is
 *       self-terminating.
 *       [post_commit_ip]
 *
 *   4.  <success>
 *
 *   On failure at [2], or if interrupted by preempt or signal delivery
 *   between [1] and [3]:
 *
 *       [abort_ip]
 *   F1. <failure>
 */

DEFINE_STATIC_KEY_MAYBE(CONFIG_RSEQ_DEBUG_DEFAULT_ENABLE, rseq_debug_enabled);

static inline void rseq_control_debug(bool on)
{
	if (on)
		static_branch_enable(&rseq_debug_enabled);
	else
		static_branch_disable(&rseq_debug_enabled);
}

static int __init rseq_setup_debug(char *str)
{
	bool on;

	if (kstrtobool(str, &on))
		return -EINVAL;
	rseq_control_debug(on);
	return 1;
}
__setup("rseq_debug=", rseq_setup_debug);

#ifdef CONFIG_RSEQ_STATS
DEFINE_PER_CPU(struct rseq_stats, rseq_stats);

static int rseq_stats_show(struct seq_file *m, void *p)
{
	struct rseq_stats stats = { };
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		if (IS_ENABLED(CONFIG_RSEQ_SLICE_EXTENSION)) {
			stats.s_granted	+= data_race(per_cpu(rseq_stats.s_granted, cpu));
			stats.s_expired	+= data_race(per_cpu(rseq_stats.s_expired, cpu));
			stats.s_revoked	+= data_race(per_cpu(rseq_stats.s_revoked, cpu));
			stats.s_yielded	+= data_race(per_cpu(rseq_stats.s_yielded, cpu));
			stats.s_aborted	+= data_race(per_cpu(rseq_stats.s_aborted, cpu));
		}
	}

	if (IS_ENABLED(CONFIG_RSEQ_SLICE_EXTENSION)) {
		seq_printf(m, "sgrant: %16lu\n", stats.s_granted);
		seq_printf(m, "sexpir: %16lu\n", stats.s_expired);
		seq_printf(m, "srevok: %16lu\n", stats.s_revoked);
		seq_printf(m, "syield: %16lu\n", stats.s_yielded);
		seq_printf(m, "sabort: %16lu\n", stats.s_aborted);
	}
	return 0;
}

static int rseq_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, rseq_stats_show, inode->i_private);
}

static const struct file_operations stat_ops = {
	.open		= rseq_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init rseq_stats_init(struct dentry *root_dir)
{
	debugfs_create_file("stats", 0444, root_dir, NULL, &stat_ops);
	return 0;
}
#else
static inline void rseq_stats_init(struct dentry *root_dir) { }
#endif /* CONFIG_RSEQ_STATS */

static int rseq_debug_show(struct seq_file *m, void *p)
{
	bool on = static_branch_unlikely(&rseq_debug_enabled);

	seq_printf(m, "%d\n", on);
	return 0;
}

static ssize_t rseq_debug_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	bool on;

	if (kstrtobool_from_user(ubuf, count, &on))
		return -EINVAL;

	rseq_control_debug(on);
	return count;
}

static int rseq_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, rseq_debug_show, inode->i_private);
}

static const struct file_operations debug_ops = {
	.open		= rseq_debug_open,
	.read		= seq_read,
	.write		= rseq_debug_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void rseq_slice_ext_init(struct dentry *root_dir);

static int __init rseq_debugfs_init(void)
{
	struct dentry *root_dir = debugfs_create_dir("rseq", NULL);

	debugfs_create_file("debug", 0644, root_dir, NULL, &debug_ops);
	rseq_stats_init(root_dir);
	if (IS_ENABLED(CONFIG_RSEQ_SLICE_EXTENSION))
		rseq_slice_ext_init(root_dir);
	return 0;
}
__initcall(rseq_debugfs_init);

static int rseq_update_cpu_id(struct task_struct *t)
{
	u32 cpu_id = raw_smp_processor_id();
	struct rseq __user *rseq = t->rseq;

	if (!user_write_access_begin(rseq, sizeof(*rseq)))
		goto efault;
	unsafe_put_user(cpu_id, &rseq->cpu_id_start, efault_end);
	unsafe_put_user(cpu_id, &rseq->cpu_id, efault_end);
	/* Open coded, so it's in the same user access region */
	if (rseq_slice_extension_enabled()) {
		/* Unconditionally clear it, no point in conditionals */
		unsafe_put_user(0U, &rseq->slice_ctrl.all, efault_end);
	}

	user_write_access_end();
	rseq_slice_clear_grant(t);
	trace_rseq_update(t);
	return 0;

efault_end:
	user_write_access_end();
efault:
	return -EFAULT;
}

static int rseq_reset_rseq_cpu_id(struct task_struct *t)
{
	u32 cpu_id_start = 0, cpu_id = RSEQ_CPU_ID_UNINITIALIZED;

	/*
	 * Reset cpu_id_start to its initial state (0).
	 */
	if (put_user(cpu_id_start, &t->rseq->cpu_id_start))
		return -EFAULT;
	/*
	 * Reset cpu_id to RSEQ_CPU_ID_UNINITIALIZED, so any user coming
	 * in after unregistration can figure out that rseq needs to be
	 * registered again.
	 */
	if (put_user(cpu_id, &t->rseq->cpu_id))
		return -EFAULT;
	return 0;
}

/*
 * Get the user-space pointer value stored in the 'rseq_cs' field.
 */
static int rseq_get_rseq_cs_ptr_val(struct rseq __user *rseq, u64 *rseq_cs)
{
	if (!rseq_cs)
		return -EFAULT;

#ifdef CONFIG_64BIT
	if (get_user(*rseq_cs, &rseq->rseq_cs))
		return -EFAULT;
#else
	if (copy_from_user(rseq_cs, &rseq->rseq_cs, sizeof(*rseq_cs)))
		return -EFAULT;
#endif

	return 0;
}

/*
 * If the rseq_cs field of 'struct rseq' contains a valid pointer to
 * user-space, copy 'struct rseq_cs' from user-space and validate its fields.
 */
static int rseq_get_rseq_cs(struct task_struct *t, struct rseq_cs *rseq_cs)
{
	struct rseq_cs __user *urseq_cs;
	u64 ptr;
	u32 __user *usig;
	u32 sig;
	int ret;

	ret = rseq_get_rseq_cs_ptr_val(t->rseq, &ptr);
	if (ret)
		return ret;

	/* If the rseq_cs pointer is NULL, return a cleared struct rseq_cs. */
	if (!ptr) {
		memset(rseq_cs, 0, sizeof(*rseq_cs));
		return 0;
	}
	/* Check that the pointer value fits in the user-space process space. */
	if (ptr >= TASK_SIZE)
		return -EINVAL;
	urseq_cs = (struct rseq_cs __user *)(unsigned long)ptr;
	if (copy_from_user(rseq_cs, urseq_cs, sizeof(*rseq_cs)))
		return -EFAULT;

	if (rseq_cs->start_ip >= TASK_SIZE ||
	    rseq_cs->start_ip + rseq_cs->post_commit_offset >= TASK_SIZE ||
	    rseq_cs->abort_ip >= TASK_SIZE ||
	    rseq_cs->version > 0)
		return -EINVAL;
	/* Check for overflow. */
	if (rseq_cs->start_ip + rseq_cs->post_commit_offset < rseq_cs->start_ip)
		return -EINVAL;
	/* Ensure that abort_ip is not in the critical section. */
	if (rseq_cs->abort_ip - rseq_cs->start_ip < rseq_cs->post_commit_offset)
		return -EINVAL;

	usig = (u32 __user *)(unsigned long)(rseq_cs->abort_ip - sizeof(u32));
	ret = get_user(sig, usig);
	if (ret)
		return ret;

	if (current->rseq_sig != sig) {
		printk_ratelimited(KERN_WARNING
			"Possible attack attempt. Unexpected rseq signature 0x%x, expecting 0x%x (pid=%d, addr=%p).\n",
			sig, current->rseq_sig, current->pid, usig);
		return -EINVAL;
	}
	return 0;
}

static int rseq_need_restart(struct task_struct *t, u32 cs_flags)
{
	u32 flags, event_mask;
	int ret;

	/* Get thread flags. */
	ret = get_user(flags, &t->rseq->flags);
	if (ret)
		return ret;

	/* Take critical section flags into account. */
	flags |= cs_flags;

	/*
	 * Restart on signal can only be inhibited when restart on
	 * preempt and restart on migrate are inhibited too. Otherwise,
	 * a preempted signal handler could fail to restart the prior
	 * execution context on sigreturn.
	 */
	if (unlikely((flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL) &&
		     (flags & RSEQ_CS_PREEMPT_MIGRATE_FLAGS) !=
		     RSEQ_CS_PREEMPT_MIGRATE_FLAGS))
		return -EINVAL;

	/*
	 * Load and clear event mask atomically with respect to
	 * scheduler preemption.
	 */
	preempt_disable();
	event_mask = t->rseq_event_mask;
	t->rseq_event_mask = 0;
	preempt_enable();

	return !!(event_mask & ~flags);
}

static int clear_rseq_cs(struct rseq __user *rseq)
{
	/*
	 * The rseq_cs field is set to NULL on preemption or signal
	 * delivery on top of rseq assembly block, as well as on top
	 * of code outside of the rseq assembly block. This performs
	 * a lazy clear of the rseq_cs field.
	 *
	 * Set rseq_cs to NULL.
	 */
#ifdef CONFIG_64BIT
	return put_user(0UL, &rseq->rseq_cs);
#else
	if (clear_user(&rseq->rseq_cs, sizeof(rseq->rseq_cs)))
		return -EFAULT;
	return 0;
#endif
}

/*
 * Unsigned comparison will be true when ip >= start_ip, and when
 * ip < start_ip + post_commit_offset.
 */
static bool in_rseq_cs(unsigned long ip, struct rseq_cs *rseq_cs)
{
	return ip - rseq_cs->start_ip < rseq_cs->post_commit_offset;
}

static int rseq_ip_fixup(struct pt_regs *regs)
{
	unsigned long ip = instruction_pointer(regs);
	struct task_struct *t = current;
	struct rseq_cs rseq_cs;
	int ret;

	ret = rseq_get_rseq_cs(t, &rseq_cs);
	if (ret)
		return ret;

	/*
	 * Handle potentially not being within a critical section.
	 * If not nested over a rseq critical section, restart is useless.
	 * Clear the rseq_cs pointer and return.
	 */
	if (!in_rseq_cs(ip, &rseq_cs))
		return clear_rseq_cs(t->rseq);
	ret = rseq_need_restart(t, rseq_cs.flags);
	if (ret <= 0)
		return ret;
	ret = clear_rseq_cs(t->rseq);
	if (ret)
		return ret;
	trace_rseq_ip_fixup(ip, rseq_cs.start_ip, rseq_cs.post_commit_offset,
			    rseq_cs.abort_ip);
	instruction_pointer_set(regs, (unsigned long)rseq_cs.abort_ip);
	return 0;
}

/*
 * This resume handler must always be executed between any of:
 * - preemption,
 * - signal delivery,
 * and return to user-space.
 *
 * This is how we can ensure that the entire rseq critical section
 * will issue the commit instruction only if executed atomically with
 * respect to other threads scheduled on the same CPU, and with respect
 * to signal handlers.
 */
void __rseq_handle_notify_resume(struct ksignal *ksig, struct pt_regs *regs)
{
	struct task_struct *t = current;
	int ret, sig;

	if (unlikely(t->flags & PF_EXITING))
		return;

	/*
	 * regs is NULL if and only if the caller is in a syscall path.  Skip
	 * fixup and leave rseq_cs as is so that rseq_sycall() will detect and
	 * kill a misbehaving userspace on debug kernels.
	 */
	if (regs) {
		ret = rseq_ip_fixup(regs);
		if (unlikely(ret < 0))
			goto error;
	}
	if (unlikely(rseq_update_cpu_id(t)))
		goto error;
	return;

error:
	/* Ensure grant is cleared in kernel state and user space */
	if (t->rseq_slice.state.granted) {
		t->rseq_slice.state.granted = false;
		(void)put_user(0U, &t->rseq->slice_ctrl.all);
	}
	sig = ksig ? ksig->sig : 0;
	force_sigsegv(sig);
}

#ifdef CONFIG_DEBUG_RSEQ

/*
 * Terminate the process if a syscall is issued within a restartable
 * sequence.
 */
void rseq_syscall(struct pt_regs *regs)
{
	unsigned long ip = instruction_pointer(regs);
	struct task_struct *t = current;
	struct rseq_cs rseq_cs;

	if (!t->rseq)
		return;
	if (rseq_get_rseq_cs(t, &rseq_cs) || in_rseq_cs(ip, &rseq_cs))
		force_sig(SIGSEGV);
}

#endif

/*
 * sys_rseq - setup restartable sequences for caller thread.
 */
SYSCALL_DEFINE4(rseq, struct rseq __user *, rseq, u32, rseq_len,
		int, flags, u32, sig)
{
	int ret;
	u64 rseq_cs;
	u32 rseqfl = 0;

	if (flags & RSEQ_FLAG_UNREGISTER) {
		if (flags & ~RSEQ_FLAG_UNREGISTER)
			return -EINVAL;
		/* Unregister rseq for current thread. */
		if (current->rseq != rseq || !current->rseq)
			return -EINVAL;
		if (rseq_len != sizeof(*rseq))
			return -EINVAL;
		if (current->rseq_sig != sig)
			return -EPERM;
		ret = rseq_reset_rseq_cpu_id(current);
		if (ret)
			return ret;
		rseq_reset(current);
		return 0;
	}

	if (unlikely(flags & ~(RSEQ_FLAG_SLICE_EXT_DEFAULT_ON)))
		return -EINVAL;

	if (current->rseq) {
		/*
		 * If rseq is already registered, check whether
		 * the provided address differs from the prior
		 * one.
		 */
		if (current->rseq != rseq || rseq_len != sizeof(*rseq))
			return -EINVAL;
		if (current->rseq_sig != sig)
			return -EPERM;
		/* Already registered. */
		return -EBUSY;
	}

	/*
	 * If there was no rseq previously registered,
	 * ensure the provided rseq is properly aligned and valid.
	 */
	if (!IS_ALIGNED((unsigned long)rseq, __alignof__(*rseq)) ||
	    rseq_len != sizeof(*rseq))
		return -EINVAL;
	if (!access_ok(rseq, rseq_len))
		return -EFAULT;

	/*
	 * If the rseq_cs pointer is non-NULL on registration, clear it to
	 * avoid a potential segfault on return to user-space. The proper thing
	 * to do would have been to fail the registration but this would break
	 * older libcs that reuse the rseq area for new threads without
	 * clearing the fields.
	 */
	if (rseq_get_rseq_cs_ptr_val(rseq, &rseq_cs))
	        return -EFAULT;
	if (rseq_cs && clear_rseq_cs(rseq))
		return -EFAULT;

	current->rseq = rseq;
	current->rseq_sig = sig;

	if (IS_ENABLED(CONFIG_RSEQ_SLICE_EXTENSION)) {
		rseqfl |= RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE;
		if (rseq_slice_extension_enabled() &&
		    (flags & RSEQ_FLAG_SLICE_EXT_DEFAULT_ON))
			rseqfl |= RSEQ_CS_FLAG_SLICE_EXT_ENABLED;
	}

	if (!user_write_access_begin(rseq, sizeof(*rseq)))
		return -EFAULT;

	unsafe_put_user(rseqfl, &rseq->flags, efault);
	unsafe_put_user(0U, &rseq->slice_ctrl.all, efault);
	user_write_access_end();

#ifdef CONFIG_RSEQ_SLICE_EXTENSION
	current->rseq_slice.state.enabled = !!(rseqfl & RSEQ_CS_FLAG_SLICE_EXT_ENABLED);
#endif

	/*
	 * If rseq was previously inactive, and has just been
	 * registered, ensure the cpu_id_start and cpu_id fields
	 * are updated before returning to user-space.
	 */
	rseq_set_notify_resume(current);

	return 0;
efault:
	user_write_access_end();
	return -EFAULT;
}

#ifdef CONFIG_RSEQ_SLICE_EXTENSION
struct slice_timer {
	struct hrtimer	timer;
	void		*cookie;
};

static const unsigned int rseq_slice_ext_nsecs_min =  5 * NSEC_PER_USEC;
static const unsigned int rseq_slice_ext_nsecs_max = 50 * NSEC_PER_USEC;
unsigned int rseq_slice_ext_nsecs __read_mostly = rseq_slice_ext_nsecs_min;
static DEFINE_PER_CPU(struct slice_timer, slice_timer);
DEFINE_STATIC_KEY_TRUE(rseq_slice_extension_key);

/*
 * When the timer expires and the task is still in user space, the return
 * from interrupt will revoke the grant and schedule. If the task already
 * entered the kernel via a syscall and the timer fires before the syscall
 * work was able to cancel it, then depending on the preemption model this
 * will either reschedule on return from interrupt or in the syscall work
 * below.
 */
static enum hrtimer_restart rseq_slice_expired(struct hrtimer *tmr)
{
	struct slice_timer *st = container_of(tmr, struct slice_timer, timer);

	/*
	 * Validate that the task which armed the timer is still on the
	 * CPU. It could have been scheduled out without canceling the
	 * timer.
	 */
	if (st->cookie == current && current->rseq_slice.state.granted) {
		rseq_stat_inc(rseq_stats.s_expired);
		set_need_resched_current();
	}
	return HRTIMER_NORESTART;
}

bool __rseq_arm_slice_extension_timer(void)
{
	struct slice_timer *st = this_cpu_ptr(&slice_timer);
	struct task_struct *curr = current;

	lockdep_assert_irqs_disabled();

	/*
	 * This check prevents a task, which got a time slice extension
	 * granted, from exceeding the maximum scheduling latency when the
	 * grant expired before going out to user space. Don't bother to
	 * clear the grant here, it will be cleaned up automatically before
	 * going out to user space after being scheduled back in.
	 */
	if ((unlikely(curr->rseq_slice_expires < ktime_get_mono_fast_ns()))) {
		set_need_resched_current();
		return true;
	}

	/*
	 * Store the task pointer as a cookie for comparison in the timer
	 * function. This is safe as the timer is CPU local and cannot be
	 * in the expiry function at this point.
	 */
	st->cookie = curr;
	hrtimer_start(&st->timer, curr->rseq_slice_expires, HRTIMER_MODE_ABS_PINNED_HARD);
	/* Arm the syscall entry work */
	set_task_syscall_work(curr, SYSCALL_RSEQ_SLICE);
	return false;
}

static void rseq_cancel_slice_extension_timer(void)
{
	struct slice_timer *st = this_cpu_ptr(&slice_timer);

	/*
	 * st->cookie can be safely read as preemption is disabled and the
	 * timer is CPU local.
	 *
	 * As this is most probably the first expiring timer, the cancel is
	 * expensive as it has to reprogram the hardware, but that's less
	 * expensive than going through a full hrtimer_interrupt() cycle
	 * for nothing.
	 *
	 * hrtimer_try_to_cancel() is sufficient here as the timer is CPU
	 * local and once the hrtimer code disabled interrupts the timer
	 * callback cannot be running.
	 */
	if (st->cookie == current)
		hrtimer_try_to_cancel(&st->timer);
}

static inline void rseq_slice_set_need_resched(struct task_struct *curr)
{
	/*
	 * The interrupt guard is required to prevent inconsistent state in
	 * this case:
	 *
	 * set_tsk_need_resched()
	 * --> Interrupt
	 *       wakeup()
	 *        set_tsk_need_resched()
	 *	  set_preempt_need_resched()
	 *     schedule_on_return()
	 *        clear_tsk_need_resched()
	 *	  clear_preempt_need_resched()
	 * set_preempt_need_resched()		<- Inconsistent state
	 *
	 * This is safe vs. a remote set of TIF_NEED_RESCHED because that
	 * only sets the already set bit and does not create inconsistent
	 * state.
	 */
	local_irq_disable();
	set_need_resched_current();
	local_irq_enable();
}

static void rseq_slice_validate_ctrl(u32 expected)
{
	u32 __user *sctrl = &current->rseq->slice_ctrl.all;
	u32 uval;

	if (get_user(uval, sctrl) || uval != expected)
		force_sig(SIGSEGV);
}

/*
 * Invoked from syscall entry if a time slice extension was granted and the
 * kernel did not clear it before user space left the critical section.
 *
 * While the recommended way to relinquish the CPU side effect free is
 * rseq_slice_yield(2), any syscall within a granted slice terminates the
 * grant and immediately reschedules if required. This supports onion layer
 * applications, where the code requesting the grant cannot control the
 * code within the critical section.
 */
void rseq_syscall_enter_work(long syscall)
{
	struct task_struct *curr = current;
	struct rseq_slice_ctrl ctrl = { .granted = curr->rseq_slice.state.granted };

	clear_task_syscall_work(curr, SYSCALL_RSEQ_SLICE);

	if (static_branch_unlikely(&rseq_debug_enabled))
		rseq_slice_validate_ctrl(ctrl.all);

	/*
	 * The kernel might have raced, revoked the grant and updated
	 * userspace, but kept the SLICE work set.
	 */
	if (!ctrl.granted)
		return;

	/*
	 * Required to stabilize the per CPU timer pointer and to make
	 * set_tsk_need_resched() correct on PREEMPT[RT] kernels.
	 *
	 * Leaving the scope will reschedule on preemption models FULL,
	 * LAZY and RT if necessary.
	 */
	preempt_disable();
	rseq_cancel_slice_extension_timer();
	rseq_slice_set_need_resched(curr);

	if (syscall == __NR_rseq_slice_yield) {
		rseq_stat_inc(rseq_stats.s_yielded);
		/* Update the yielded state for syscall return */
		curr->rseq_slice.yielded = 1;
	} else {
		rseq_stat_inc(rseq_stats.s_aborted);
	}
	preempt_enable();

	/* Reschedule on NONE/VOLUNTARY preemption models */
	cond_resched();

	/* Clear the grant in kernel state and user space */
	curr->rseq_slice.state.granted = false;
	if (put_user(0U, &curr->rseq->slice_ctrl.all))
		force_sig(SIGSEGV);
}

int rseq_slice_extension_prctl(unsigned long arg2, unsigned long arg3)
{
	switch (arg2) {
	case PR_RSEQ_SLICE_EXTENSION_GET:
		if (arg3)
			return -EINVAL;
		return current->rseq_slice.state.enabled ? PR_RSEQ_SLICE_EXT_ENABLE : 0;

	case PR_RSEQ_SLICE_EXTENSION_SET: {
		u32 rflags, valid = RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE;
		bool enable = !!(arg3 & PR_RSEQ_SLICE_EXT_ENABLE);

		if (arg3 & ~PR_RSEQ_SLICE_EXT_ENABLE)
			return -EINVAL;
		if (!rseq_slice_extension_enabled())
			return -ENOTSUPP;
		if (!current->rseq)
			return -ENXIO;

		/* No change? */
		if (enable == !!current->rseq_slice.state.enabled)
			return 0;

		if (get_user(rflags, &current->rseq->flags))
			goto die;

		if (current->rseq_slice.state.enabled)
			valid |= RSEQ_CS_FLAG_SLICE_EXT_ENABLED;

		if ((rflags & valid) != valid)
			goto die;

		rflags &= ~RSEQ_CS_FLAG_SLICE_EXT_ENABLED;
		rflags |= RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE;
		if (enable)
			rflags |= RSEQ_CS_FLAG_SLICE_EXT_ENABLED;

		if (put_user(rflags, &current->rseq->flags))
			goto die;

		current->rseq_slice.state.enabled = enable;
		return 0;
	}
	default:
		return -EINVAL;
	}
die:
	force_sig(SIGSEGV);
	return -EFAULT;
}

/**
 * sys_rseq_slice_yield - yield the current processor side effect free if a
 *			  task granted with a time slice extension is done with
 *			  the critical work before being forced out.
 *
 * Return: 1 if the task successfully yielded the CPU within the granted slice.
 *         0 if the slice extension was either never granted or was revoked by
 *	     going over the granted extension, using a syscall other than this one
 *	     or being scheduled out earlier due to a subsequent interrupt.
 *
 * The syscall does not schedule because the syscall entry work immediately
 * relinquishes the CPU and schedules if required.
 */
SYSCALL_DEFINE0(rseq_slice_yield)
{
	int yielded = !!current->rseq_slice.yielded;

	current->rseq_slice.yielded = 0;
	return yielded;
}

static int rseq_slice_ext_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", rseq_slice_ext_nsecs);
	return 0;
}

static ssize_t rseq_slice_ext_write(struct file *file, const char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	unsigned int nsecs;

	if (kstrtouint_from_user(ubuf, count, 10, &nsecs))
		return -EINVAL;

	if (nsecs < rseq_slice_ext_nsecs_min)
		return -ERANGE;

	if (nsecs > rseq_slice_ext_nsecs_max)
		return -ERANGE;

	rseq_slice_ext_nsecs = nsecs;

	return count;
}

static int rseq_slice_ext_open(struct inode *inode, struct file *file)
{
	return single_open(file, rseq_slice_ext_show, inode->i_private);
}

static const struct file_operations slice_ext_ops = {
	.open		= rseq_slice_ext_open,
	.read		= seq_read,
	.write		= rseq_slice_ext_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void rseq_slice_ext_init(struct dentry *root_dir)
{
	debugfs_create_file("slice_ext_nsec", 0644, root_dir, NULL, &slice_ext_ops);
}

static int __init rseq_slice_cmdline(char *str)
{
	bool on;

	if (kstrtobool(str, &on))
		return 0;

	if (!on)
		static_branch_disable(&rseq_slice_extension_key);
	return 1;
}
__setup("rseq_slice_ext=", rseq_slice_cmdline);

static int __init rseq_slice_init(void)
{
	unsigned int cpu;
	struct hrtimer *ht;

	for_each_possible_cpu(cpu) {
		ht = per_cpu_ptr(&slice_timer.timer, cpu);
		hrtimer_init(ht, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_PINNED_HARD);
		ht->function = rseq_slice_expired;
	}
	return 0;
}
device_initcall(rseq_slice_init);
#else
static void rseq_slice_ext_init(struct dentry *root_dir) { }
#endif /* CONFIG_RSEQ_SLICE_EXTENSION */
