BL_SENTRY(void *, update_vsyscall)
BL_DENTRY(void *, read_tsc)
BL_DENTRY(void *, notifier_call_chain)
BL_SENTRY(typeof(__atomic_notifier_call_chain), __atomic_notifier_call_chain)
BL_SENTRY(typeof(atomic_notifier_call_chain), atomic_notifier_call_chain)
BL_SENTRY(typeof(__raw_notifier_call_chain), __raw_notifier_call_chain)
BL_SENTRY(typeof(raw_notifier_call_chain), raw_notifier_call_chain)
BL_DENTRY(void *, timekeeping_get_ns)
BL_SENTRY(typeof(getrawmonotonic64), getrawmonotonic64)
BL_DENTRY(void *, update_fast_timekeeper)
BL_DENTRY(void *, timekeeping_update.clone.3)
BL_SENTRY(typeof(idr_find_slowpath), idr_find_slowpath)
BL_SENTRY(typeof(poke_int3_handler), poke_int3_handler)	/* MAYBE */
BL_SENTRY(void *, ftrace_int3_handler)			/* MAYBE */
BL_SENTRY(void *, kprobe_int3_handler)			/* MAYBE */
BL_DENTRY(void *, set_intr_gate_ist)			/* MAYBE */
BL_DENTRY(void *, ist_enter)				/* MAYBE */
BL_DENTRY(void *, ist_exit)				/* MAYBE */
BL_DENTRY(void *, hw_breakpoint_exceptions_notify)
BL_DENTRY(void *, kprobe_exceptions_notify)
BL_SENTRY(void *, notify_die)
BL_SENTRY(void *, rcu_nmi_exit)
BL_SENTRY(void *, rcu_nmi_enter)
BL_SENTRY(void *, get_kprobe)
BL_DENTRY(void *, xen_timer_interrupt)
