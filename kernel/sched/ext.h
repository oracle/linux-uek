/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
enum scx_exit_kind {
	SCX_EXIT_NONE,
	SCX_EXIT_DONE,

	SCX_EXIT_UNREG = 64,	/* User-space initiated unregistration */
	SCX_EXIT_UNREG_BPF,	/* BPF-initiated unregistration */
	SCX_EXIT_UNREG_KERN,	/* Main-kernel-initiated unregistration */
	SCX_EXIT_SYSRQ,		/* requested by 'S' sysrq */

	SCX_EXIT_ERROR = 1024,	/* runtime error, error msg contains details */
	SCX_EXIT_ERROR_BPF,	/* ERROR but triggered through scx_bpf_error() */
	SCX_EXIT_ERROR_STALL,	/* watchdog detected stalled runnable tasks */
};

#ifdef CONFIG_SCHED_CLASS_EXT

struct sched_enq_and_set_ctx {
	struct task_struct	*p;
	int			queue_flags;
	bool			queued;
	bool			running;
};

void sched_deq_and_put_task(struct task_struct *p, int queue_flags,
			    struct sched_enq_and_set_ctx *ctx);
void sched_enq_and_set_task(struct sched_enq_and_set_ctx *ctx);

extern const struct sched_class ext_sched_class;
extern const struct bpf_verifier_ops bpf_sched_ext_verifier_ops;
extern unsigned long scx_watchdog_timeout;
extern unsigned long scx_watchdog_timestamp;

DECLARE_STATIC_KEY_FALSE(__scx_ops_enabled);
DECLARE_STATIC_KEY_FALSE(__scx_switched_all);
#define scx_enabled()		static_branch_unlikely(&__scx_ops_enabled)
#define scx_switched_all()	static_branch_unlikely(&__scx_switched_all)

DECLARE_STATIC_KEY_FALSE(scx_ops_cpu_preempt);

static inline bool task_on_scx(const struct task_struct *p)
{
	return scx_enabled() && p->sched_class == &ext_sched_class;
}

bool task_should_scx(struct task_struct *p);
void scx_pre_fork(struct task_struct *p);
int scx_fork(struct task_struct *p);
void scx_post_fork(struct task_struct *p);
void scx_cancel_fork(struct task_struct *p);
int scx_check_setscheduler(struct task_struct *p, int policy);
bool scx_can_stop_tick(struct rq *rq);
void init_sched_ext_class(void);

__printf(3, 4) void scx_ops_exit_kind(enum scx_exit_kind kind,
				      s64 exit_code,
				      const char *fmt, ...);
#define scx_ops_error_kind(__err, fmt, args...)					\
	scx_ops_exit_kind(__err, 0, fmt, ##args)

#define scx_ops_exit(__code, fmt, args...)					\
	scx_ops_exit_kind(SCX_EXIT_UNREG_KERN, __code, fmt, ##args)

#define scx_ops_error(fmt, args...)						\
	scx_ops_error_kind(SCX_EXIT_ERROR, fmt, ##args)

void __scx_notify_pick_next_task(struct rq *rq,
				 struct task_struct *p,
				 const struct sched_class *active);

static inline void scx_notify_pick_next_task(struct rq *rq,
					     struct task_struct *p,
					     const struct sched_class *active)
{
	if (!scx_enabled())
		return;
#ifdef CONFIG_SMP
	/*
	 * Pairs with the smp_load_acquire() issued by a CPU in
	 * kick_cpus_irq_workfn() who is waiting for this CPU to perform a
	 * resched.
	 */
	smp_store_release(&rq->scx.pnt_seq, rq->scx.pnt_seq + 1);
#endif
	if (!static_branch_unlikely(&scx_ops_cpu_preempt))
		return;
	__scx_notify_pick_next_task(rq, p, active);
}

static inline void scx_notify_sched_tick(void)
{
	unsigned long last_check;

	if (!scx_enabled())
		return;

	last_check = READ_ONCE(scx_watchdog_timestamp);
	if (unlikely(time_after(jiffies,
				last_check + READ_ONCE(scx_watchdog_timeout)))) {
		u32 dur_ms = jiffies_to_msecs(jiffies - last_check);

		scx_ops_error_kind(SCX_EXIT_ERROR_STALL,
				   "watchdog failed to check in for %u.%03us",
				   dur_ms / 1000, dur_ms % 1000);
	}
}

static inline const struct sched_class *next_active_class(const struct sched_class *class)
{
	class++;
	if (scx_switched_all() && class == &fair_sched_class)
		class++;
	if (!scx_enabled() && class == &ext_sched_class)
		class++;
	return class;
}

#define for_active_class_range(class, _from, _to)				\
	for (class = (_from); class != (_to); class = next_active_class(class))

#define for_each_active_class(class)						\
	for_active_class_range(class, __sched_class_highest, __sched_class_lowest)

/*
 * SCX requires a balance() call before every pick_next_task() call including
 * when waking up from idle.
 */
#define for_balance_class_range(class, prev_class, end_class)			\
	for_active_class_range(class, (prev_class) > &ext_sched_class ?		\
			       &ext_sched_class : (prev_class), (end_class))

#ifdef CONFIG_SCHED_CORE
bool scx_prio_less(const struct task_struct *a, const struct task_struct *b,
		   bool in_fi);
#endif

#else	/* CONFIG_SCHED_CLASS_EXT */

#define scx_enabled()		false
#define scx_switched_all()	false

static inline bool task_on_scx(const struct task_struct *p) { return false; }
static inline void scx_pre_fork(struct task_struct *p) {}
static inline int scx_fork(struct task_struct *p) { return 0; }
static inline void scx_post_fork(struct task_struct *p) {}
static inline void scx_cancel_fork(struct task_struct *p) {}
static inline int scx_check_setscheduler(struct task_struct *p,
					 int policy) { return 0; }
static inline bool scx_can_stop_tick(struct rq *rq) { return true; }
static inline void init_sched_ext_class(void) {}
static inline void scx_notify_pick_next_task(struct rq *rq,
					     const struct task_struct *p,
					     const struct sched_class *active) {}
static inline void scx_notify_sched_tick(void) {}

#define for_each_active_class		for_each_class
#define for_balance_class_range		for_class_range

#endif	/* CONFIG_SCHED_CLASS_EXT */

#if defined(CONFIG_SCHED_CLASS_EXT) && defined(CONFIG_SMP)
void __scx_update_idle(struct rq *rq, bool idle);

static inline void scx_update_idle(struct rq *rq, bool idle)
{
	if (scx_enabled())
		__scx_update_idle(rq, idle);
}
#else
static inline void scx_update_idle(struct rq *rq, bool idle) {}
#endif

#ifdef CONFIG_CGROUP_SCHED
#ifdef CONFIG_EXT_GROUP_SCHED
int scx_tg_online(struct task_group *tg);
void scx_tg_offline(struct task_group *tg);
int scx_cgroup_can_attach(struct cgroup_taskset *tset);
void scx_move_task(struct task_struct *p);
void scx_cgroup_finish_attach(void);
void scx_cgroup_cancel_attach(struct cgroup_taskset *tset);
void scx_group_set_weight(struct task_group *tg, unsigned long cgrp_weight);
#else	/* CONFIG_EXT_GROUP_SCHED */
static inline int scx_tg_online(struct task_group *tg) { return 0; }
static inline void scx_tg_offline(struct task_group *tg) {}
static inline int scx_cgroup_can_attach(struct cgroup_taskset *tset) { return 0; }
static inline void scx_move_task(struct task_struct *p) {}
static inline void scx_cgroup_finish_attach(void) {}
static inline void scx_cgroup_cancel_attach(struct cgroup_taskset *tset) {}
static inline void scx_group_set_weight(struct task_group *tg, unsigned long cgrp_weight) {}
#endif	/* CONFIG_EXT_GROUP_SCHED */
#endif	/* CONFIG_CGROUP_SCHED */
