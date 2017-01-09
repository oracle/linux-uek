/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	Dynamic Tracing: OS support functions - part of kernel core
 *
 * Copyright (C) 2010-2017 Oracle Corporation
 */

#include <linux/binfmts.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_sdt.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <asm/ptrace.h>

#if defined(CONFIG_DT_FASTTRAP) || defined(CONFIG_DT_FASTTRAP_MODULE)
# include <linux/uprobes.h>
#endif /* CONFIG_DT_FASTTRAP || CONFIG_DT_FASTTRAP_MODULE */

/*---------------------------------------------------------------------------*\
(* OS SPECIFIC DTRACE SETUP                                                  *)
\*---------------------------------------------------------------------------*/
struct module		*dtrace_kmod = NULL;
EXPORT_SYMBOL(dtrace_kmod);

int			dtrace_ustackdepth_max = 2048;

struct kmem_cache	*psinfo_cachep;

void dtrace_os_init(void)
{
	size_t module_size;

	if (dtrace_kmod != NULL) {
		pr_warn_once("%s: cannot be called twice\n", __func__);
		return;
	}

	/*
	 * A little bit of magic...
	 * We create a dummy module to represent the core Linux kernel.  The
	 * only data we're interested in is the name, the SDT probe points data
	 * (to be filled in by dtrace_sdt_register()), and the probe data.
	 * DTrace uses an architecture-specific structure (hidden from us here)
	 * to hold some data, and since we do not know the layout or the size,
	 * we ensure that we allocate enough memory to accomodate the largest
	 * of those structures.
	 * So, the memory we allocate will hold:
	 *	- the dtrace_kmod module structure
	 *	- a block of memory (aligned at a structure boundary) to be
	 *	  used for pdata and other related data
	 * The memory is allocated from the modules space.
	 */
	module_size = ALIGN(sizeof(struct module), 8) + DTRACE_PDATA_MAXSIZE;
	dtrace_kmod = module_alloc(module_size);
	if (dtrace_kmod == NULL) {
		pr_warning("%s: cannot allocate kernel pseudo-module\n",
			   __func__);
		return;
	}

	memset(dtrace_kmod, 0, module_size);
	strlcpy(dtrace_kmod->name, "vmlinux", MODULE_NAME_LEN);
	dtrace_kmod->state = MODULE_STATE_LIVE;
	atomic_inc(&dtrace_kmod->refcnt);
	dtrace_kmod->pdata = (char *)dtrace_kmod +
				ALIGN(sizeof(struct module), 8);
	dtrace_kmod->core_layout.size = DTRACE_PDATA_MAXSIZE;

	psinfo_cachep = kmem_cache_create("psinfo_cache",
				sizeof(dtrace_psinfo_t), 0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK,
				NULL);

	/*
	 * We need to set up a psinfo structure for PID 0 (swapper).
	 */
	dtrace_psinfo_alloc(&init_task);

	dtrace_sdt_init();
	dtrace_sdt_register(dtrace_kmod);
}
EXPORT_SYMBOL(dtrace_os_init);

/*---------------------------------------------------------------------------*\
(* TASK PSINFO SUPPORT                                                       *)
\*---------------------------------------------------------------------------*/
/*
 * Allocate a new dtrace_psinfo_t structure.
 */
void dtrace_psinfo_alloc(struct task_struct *tsk)
{
	dtrace_psinfo_t		*psinfo;
	struct mm_struct	*mm = NULL;

	if (likely(tsk->dtrace_psinfo)) {
		put_psinfo(tsk);
		tsk->dtrace_psinfo = NULL;	/* while we build one */
	}

	psinfo = kmem_cache_alloc(psinfo_cachep, GFP_KERNEL);
	if (psinfo == NULL)
		goto fail;

	mm = get_task_mm(tsk);
	if (mm) {
		size_t	len = mm->arg_end - mm->arg_start;
		int	i = 0;
		char	*p;

		/*
		 * Construct the psargs string.
		 */
		if (len > 0) {
			if (len >= PR_PSARGS_SZ)
				len = PR_PSARGS_SZ - 1;

			i = access_process_vm(tsk, mm->arg_start,
					      psinfo->psargs, len, 0);

			if (i > 0) {
				if (i < len)
					len = i;

				for (i = 0, --len; i < len; i++) {
					if (psinfo->psargs[i] == '\0')
						psinfo->psargs[i] = ' ';
				}
			}
		}

		if (i < 0)
			i = 0;

		while (i < PR_PSARGS_SZ)
			psinfo->psargs[i++] = 0;

		/*
		 * Determine the number of arguments.
		 */
		psinfo->argc = 0;
		for (p = (char *)mm->arg_start; p < (char *)mm->arg_end;
		     psinfo->argc++) {
			size_t	l = strnlen_user(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		/*
		 * Limit the number of stored argument pointers.
		 */
		if ((len = psinfo->argc) >= PR_ARGV_SZ)
			len = PR_ARGV_SZ - 1;

		psinfo->argv = kmalloc((len + 1) * sizeof(char *),
					 GFP_KERNEL);
		if (psinfo->argv == NULL)
			goto fail;

		/*
		 * Now populate the array of argument strings.
		 */
		for (i = 0, p = (char *)mm->arg_start; i < len; i++) {
			psinfo->argv[i] = p;
			p += strnlen_user(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->argv[len] = NULL;

		/*
		 * Determine the number of environment variables.
		 */
		psinfo->envc = 0;
		for (p = (char *)mm->env_start; p < (char *)mm->env_end;
		     psinfo->envc++) {
			size_t	l = strnlen_user(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		/*
		 * Limit the number of stored environment pointers.
		 */
		if ((len = psinfo->envc) >= PR_ENVP_SZ)
			len = PR_ENVP_SZ - 1;

		psinfo->envp = kmalloc((len + 1) * sizeof(char *),
					 GFP_KERNEL);
		if (psinfo->envp == NULL)
			goto fail;

		/*
		 * Now populate the array of environment variable strings.
		 */
		for (i = 0, p = (char *)mm->env_start; i < len; i++) {
			psinfo->envp[i] = p;
			p += strnlen_user(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->envp[len] = NULL;

		mmput(mm);
	} else {
		size_t	len = min(TASK_COMM_LEN, PR_PSARGS_SZ);
		int	i;

		/*
		 * We end up here for tasks that do not have managed memory at
		 * all, which generally means that this is a kernel thread.
		 * If it is not, this is still safe because we know that tasks
		 * always have the comm member populated with something (even
		 * if it would be an empty string).
		 */
		memcpy(psinfo->psargs, tsk->comm, len);
		for (i = len; i < PR_PSARGS_SZ; i++)
			psinfo->psargs[i] = 0;

		psinfo->argc = 0;
		psinfo->argv = kmalloc(sizeof(char *), GFP_KERNEL);
		psinfo->argv[0] = NULL;
		psinfo->envc = 0;
		psinfo->envp = kmalloc(sizeof(char *), GFP_KERNEL);
		psinfo->envp[0] = NULL;
	}

	atomic_set(&psinfo->usage, 1);
	tsk->dtrace_psinfo = psinfo;		/* new one */

	return;

fail:
	if (mm)
		mmput(mm);

	if (psinfo) {
		if (psinfo->argv)
			kfree(psinfo->argv);
		if (psinfo->envp)
			kfree(psinfo->envp);

		kmem_cache_free(psinfo_cachep, psinfo);
	}
}

static DEFINE_SPINLOCK(psinfo_lock);
static dtrace_psinfo_t *psinfo_free_list;

/*
 * Work queue handler to clean up psinfo structures for tasks that no longer
 * exist.
 */
static void psinfo_cleaner(struct work_struct *work)
{
	unsigned long	flags;
	dtrace_psinfo_t	*psinfo;

	spin_lock_irqsave(&psinfo_lock, flags);
	psinfo = psinfo_free_list;
	psinfo_free_list = NULL;
	spin_unlock_irqrestore(&psinfo_lock, flags);

#ifdef CONFIG_DT_DEBUG
	DTRACE_PROBE(test, uint64_t, 10, uint64_t, 20, uint64_t, 30,
			   uint64_t, 40, uint64_t, 50, uint64_t, 60,
			   uint64_t, 70, uint64_t, 80);
#endif

	while (psinfo) {
		dtrace_psinfo_t	*next = psinfo->next;

		if (psinfo->argv)
			kfree(psinfo->argv);
		if (psinfo->envp)
			kfree(psinfo->envp);

		kmem_cache_free(psinfo_cachep, psinfo);
		psinfo = next;
	}
}

static DECLARE_WORK(psinfo_cleanup, psinfo_cleaner);

/*
 * Schedule a psinfo structure for free'ing.
 */
void dtrace_psinfo_free(struct task_struct *tsk)
{
	unsigned long	flags;
	dtrace_psinfo_t	*psinfo = tsk->dtrace_psinfo;

	/*
	 * There are (very few) tasks without psinfo...
	 */
	if (unlikely(psinfo == NULL))
		return;

	tsk->dtrace_psinfo = NULL;

	spin_lock_irqsave(&psinfo_lock, flags);
	psinfo->next = psinfo_free_list;
	psinfo_free_list = psinfo;
	spin_unlock_irqrestore(&psinfo_lock, flags);

	schedule_work(&psinfo_cleanup);
}

/*---------------------------------------------------------------------------*\
(* TIME SUPPORT FUNCTIONS                                                    *)
\*---------------------------------------------------------------------------*/
dtrace_vtime_state_t	dtrace_vtime_active = 0;

/*
 * Return a high resolution timer value that is guaranteed to always increase.
 */
ktime_t dtrace_gethrtime(void)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(dtrace_gethrtime);

/*
 * Return the current wall-clock time, in nanoseconds since the epoch.
 */
ktime_t dtrace_getwalltime(void)
{
	struct timespec ts;

	getnstimeofday(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(dtrace_getwalltime);

void dtrace_vtime_enable(void)
{
	dtrace_vtime_state_t	old, new;

	do {
		old = dtrace_vtime_active;
		if (old == DTRACE_VTIME_ACTIVE) {
			pr_warn_once("DTrace virtual time already enabled");
			return;
		}

		new = DTRACE_VTIME_ACTIVE;
	} while (cmpxchg(&dtrace_vtime_active, old, new) != old);
}
EXPORT_SYMBOL(dtrace_vtime_enable);

void dtrace_vtime_disable(void)
{
	int	old, new;

	do {
		old = dtrace_vtime_active;
		if (old == DTRACE_VTIME_INACTIVE) {
			pr_warn_once("DTrace virtual time already disabled");
			return;
		}

		new = DTRACE_VTIME_INACTIVE;
	} while (cmpxchg(&dtrace_vtime_active, old, new) != old);
}
EXPORT_SYMBOL(dtrace_vtime_disable);

void dtrace_vtime_switch(struct task_struct *prev, struct task_struct *next)
{
	ktime_t	now = dtrace_gethrtime();

	if (ktime_nz(prev->dtrace_start)) {
		prev->dtrace_vtime = ktime_add(prev->dtrace_vtime,
					       ktime_sub(now,
							 prev->dtrace_start));
		prev->dtrace_start = ktime_set(0, 0);
	}

	next->dtrace_start = now;
}

void dtrace_stacktrace(stacktrace_state_t *st)
{
	struct stack_trace	trace;
	int			i;

	trace.nr_entries = 0;
	trace.max_entries = st->limit ? st->limit : 512;
	trace.entries = (typeof(trace.entries))st->pcs;
	trace.skip = st->depth;

	if (st->pcs == NULL) {
		st->depth = 0;
		return;
	}

	save_stack_trace(&trace);

	/*
	 * For entirely unknown reasons, the save_stack_trace() implementation
	 * on x86_64 adds a ULONG_MAX entry after the last stack trace entry.
	 * This might be a sentinel value, but given that struct stack_trace
	 * already contains a nr_entries counter, this seems rather pointless.
	 * Alas, we need to add a special case for that...
	 */
#ifdef CONFIG_X86_64
	st->depth = trace.nr_entries - 1;
#else
	st->depth = trace.nr_entries;
#endif

	if (st->fps != NULL) {
		for (i = 0; i < st->limit; i++)
			st->fps[i] = 0;
	}
}
EXPORT_SYMBOL(dtrace_stacktrace);

/*---------------------------------------------------------------------------*\
(* INVALID OPCODE AND PAGE FAULT HANDLING                                    *)
\*---------------------------------------------------------------------------*/
static struct notifier_block	dtrace_die = {
	.notifier_call = dtrace_die_notifier,
};

static int	dtrace_enabled = 0;

void dtrace_enable(void)
{
	if (!dtrace_enabled) {
		register_die_notifier(&dtrace_die);
		dtrace_enabled = 1;
	}
}
EXPORT_SYMBOL(dtrace_enable);

void dtrace_disable(void)
{
	if (!dtrace_enabled)
		return;

	unregister_die_notifier(&dtrace_die);
	dtrace_enabled = 0;
}
EXPORT_SYMBOL(dtrace_disable);

/*---------------------------------------------------------------------------*\
(* USER SPACE TRACING (FASTTRAP) SUPPORT                                     *)
\*---------------------------------------------------------------------------*/
void (*dtrace_helpers_cleanup)(struct task_struct *);
EXPORT_SYMBOL(dtrace_helpers_cleanup);
void (*dtrace_fasttrap_probes_cleanup)(struct task_struct *);
EXPORT_SYMBOL(dtrace_fasttrap_probes_cleanup);
void (*dtrace_helpers_fork)(struct task_struct *, struct task_struct *);
EXPORT_SYMBOL(dtrace_helpers_fork);

void dtrace_task_reinit(struct task_struct *tsk)
{
	tsk->predcache = 0;
	tsk->dtrace_stop = 0;
	tsk->dtrace_sig = 0;

	tsk->dtrace_helpers = NULL;
	tsk->dtrace_probes = 0;
	tsk->dtrace_tp_count = 0;
}

void dtrace_task_init(struct task_struct *tsk)
{
	dtrace_task_reinit(tsk);

	tsk->dtrace_vtime = ktime_set(0, 0);
	tsk->dtrace_start = ktime_set(0, 0);
}

void dtrace_task_fork(struct task_struct *tsk, struct task_struct *child)
{
	if (likely(dtrace_helpers_fork == NULL))
		return;

	if (tsk->dtrace_helpers != NULL)
		(*dtrace_helpers_fork)(tsk, child);
}

void dtrace_task_cleanup(struct task_struct *tsk)
{
	if (likely(dtrace_helpers_cleanup == NULL))
		return;

	if (tsk->dtrace_helpers != NULL)
		(*dtrace_helpers_cleanup)(tsk);

	if (tsk->dtrace_probes) {
		if (dtrace_fasttrap_probes_cleanup != NULL)
			(*dtrace_fasttrap_probes_cleanup)(tsk);
	}
}

#if defined(CONFIG_DT_FASTTRAP) || defined(CONFIG_DT_FASTTRAP_MODULE)
int (*dtrace_tracepoint_hit)(fasttrap_machtp_t *, struct pt_regs *);
EXPORT_SYMBOL(dtrace_tracepoint_hit);

struct task_struct *register_pid_provider(pid_t pid)
{
	struct task_struct	*p;

	/*
	 * Make sure the process exists, (FIXME: isn't a child created as the
	 * result of a vfork(2)), and isn't a zombie (but may be in fork).
	 */
	rcu_read_lock();
	read_lock(&tasklist_lock);
	if ((p = find_task_by_vpid(pid)) == NULL) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		return NULL;
	}

	get_task_struct(p);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	if (p->state & TASK_DEAD ||
	    p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)) {
		put_task_struct(p);
		return NULL;
	}

	/*
	 * Increment dtrace_probes so that the process knows to inform us
	 * when it exits or execs. fasttrap_provider_free() decrements this
	 * when we're done with this provider.
	 */
	p->dtrace_probes++;
	put_task_struct(p);

	return p;
}
EXPORT_SYMBOL(register_pid_provider);

void unregister_pid_provider(pid_t pid)
{
	struct task_struct	*p;

	/*
	 * Decrement dtrace_probes on the process whose provider we're
	 * freeing. We don't have to worry about clobbering somone else's
	 * modifications to it because we have locked the bucket that
	 * corresponds to this process's hash chain in the provider hash
	 * table. Don't sweat it if we can't find the process.
	 */
	rcu_read_lock();
	read_lock(&tasklist_lock);
	if ((p = find_task_by_vpid(pid)) == NULL) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		return;
	}

	get_task_struct(p);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	p->dtrace_probes--;
	put_task_struct(p);
}
EXPORT_SYMBOL(unregister_pid_provider);

static int handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	fasttrap_machtp_t	*mtp = container_of(self, fasttrap_machtp_t,
						    fmtp_cns);
	int			rc = 0;

	read_lock(&this_cpu_core->cpu_ft_lock);
	if (dtrace_tracepoint_hit == NULL)
		pr_warn("Fasttrap probes, but no handler\n");
	else
		rc = (*dtrace_tracepoint_hit)(mtp, regs);
	read_unlock(&this_cpu_core->cpu_ft_lock);

	return rc;
}

int dtrace_tracepoint_enable(pid_t pid, uintptr_t addr,
			     fasttrap_machtp_t *mtp)
{
	struct task_struct	*p;
	struct inode		*ino;
	struct vm_area_struct	*vma;
	loff_t			off;
	int			rc = 0;

	mtp->fmtp_ino = NULL;
	mtp->fmtp_off = 0;

	p = find_task_by_vpid(pid);
	if (!p) {
		pr_warn("PID %d not found\n", pid);
		return -ESRCH;
	}

	vma = find_vma(p->mm, addr);
	if (vma == NULL || vma->vm_file == NULL)
		return -EFAULT;

	ino = vma->vm_file->f_mapping->host;
	off = ((loff_t)vma->vm_pgoff << PAGE_SHIFT) + (addr - vma->vm_start);

	mtp->fmtp_cns.handler = handler;

	rc = uprobe_register(ino, off, &mtp->fmtp_cns);

	/*
	 * If successful, increment the count of the number of
	 * tracepoints active in the victim process.
	 */
	if (rc == 0) {
		mtp->fmtp_ino = ino;
		mtp->fmtp_off = off;

		p->dtrace_tp_count++;
	}

	return rc;
}
EXPORT_SYMBOL(dtrace_tracepoint_enable);

int dtrace_tracepoint_disable(pid_t pid, fasttrap_machtp_t *mtp)
{
	struct task_struct	*p;

	if (!mtp || !mtp->fmtp_ino) {
		pr_warn("DTRACE: Tracepoint was never enabled\n");
		return -ENOENT;
	}

	if (!mtp->fmtp_cns.handler) {
		pr_warn("DTRACE: No handler for tracepoint\n");
		return -ENOENT;
	}

	uprobe_unregister(mtp->fmtp_ino, mtp->fmtp_off, &mtp->fmtp_cns);

	mtp->fmtp_ino = NULL;
	mtp->fmtp_off = 0;

	/*
	 * Decrement the count of the number of tracepoints active in
	 * the victim process (if it still exists).
	 */
	p = find_task_by_vpid(pid);
	if (p)
		p->dtrace_tp_count--;

	return 0;
}
EXPORT_SYMBOL(dtrace_tracepoint_disable);
#endif /* CONFIG_DT_FASTTRAP || CONFIG_DT_FASTTRAP_MODULE */
