/*
 * vmcoreinfo trace extern kexec setup
 *
 * Copyright (C) 2019 Isaac Chen <isaac.chen@oracle.com>
 */
#include <asm/processor.h>
#include <linux/cpu.h>
#include <linux/elf.h>
#include <linux/ftrace_event.h>
#include <linux/kallsyms.h>
#include <linux/kexec.h>
#include <linux/kthread.h>
#include <linux/mm_types.h>
#include <linux/pid.h>
#include <linux/signal.h>
#include <trace/syscall.h>
#include <linux/types.h>
#include <uapi/asm-generic/siginfo.h>
#include <asm-generic/cputime_nsecs.h>
#include "../sched/sched.h"
#include "trace.h"

#ifdef CONFIG_KEXEC
void trace_extern_kexec_setup(void)
{
	VMCOREINFO_SYMBOL(nr_cpu_ids);
	VMCOREINFO_SYMBOL(ring_buffer_read);

	VMCOREINFO_OFFSET(ftrace_event_class, system);
	VMCOREINFO_OFFSET(ftrace_event_class, get_fields);
	VMCOREINFO_OFFSET(ftrace_event_class, fields);
	VMCOREINFO_OFFSET(trace_event, type);
	VMCOREINFO_OFFSET(ftrace_event_call, list);
	VMCOREINFO_OFFSET(ftrace_event_call, class);
	VMCOREINFO_OFFSET(ftrace_event_call, tp); 
	VMCOREINFO_OFFSET(ftrace_event_call, event);
	VMCOREINFO_OFFSET(ftrace_event_call, print_fmt);
	VMCOREINFO_OFFSET(ftrace_event_call, data);
	VMCOREINFO_OFFSET(ftrace_event_call, flags);
	VMCOREINFO_OFFSET(ftrace_event_field, link);
	VMCOREINFO_OFFSET(ftrace_event_field, name);
	VMCOREINFO_OFFSET(ftrace_event_field, type);
	VMCOREINFO_OFFSET(ftrace_event_field, offset);
	VMCOREINFO_OFFSET(ftrace_event_field, size);
	VMCOREINFO_OFFSET(ftrace_event_field, is_signed);
	VMCOREINFO_OFFSET(tracer, name);
	VMCOREINFO_OFFSET(trace_buffer, buffer);
	VMCOREINFO_OFFSET(trace_array, name);
	VMCOREINFO_OFFSET(trace_array, trace_buffer);
	VMCOREINFO_OFFSET(trace_array, current_trace);
	VMCOREINFO_OFFSET(trace_array, max_buffer);
	VMCOREINFO_OFFSET(tracepoint, name);
	VMCOREINFO_OFFSET(syscall_metadata, enter_fields);

	VMCOREINFO_SYMBOL(__vmcore_ptr_pid_hash);
	VMCOREINFO_SYMBOL(__vmcore_ptr_pidhash_shift);
	VMCOREINFO_STRUCT_SIZE(hlist_head);
	VMCOREINFO_STRUCT_SIZE(hlist_node);
	VMCOREINFO_OFFSET(hlist_node, next);
	VMCOREINFO_OFFSET(hlist_node, pprev);
	VMCOREINFO_SIZE(u64);
	VMCOREINFO_SYMBOL(__vmcore_ptr_runqueues);
	VMCOREINFO_SYMBOL(__per_cpu_offset);
	VMCOREINFO_SYMBOL(cpu_number);
	VMCOREINFO_SYMBOL(init_pid_ns);
	VMCOREINFO_SYMBOL(cpu_present_mask);
	VMCOREINFO_OFFSET(rq, idle);
	VMCOREINFO_STRUCT_SIZE(rq);
	VMCOREINFO_OFFSET(thread_info, task);
	VMCOREINFO_OFFSET(thread_info, flags);
	VMCOREINFO_OFFSET(thread_info, cpu);
	VMCOREINFO_STRUCT_SIZE(thread_info);
	VMCOREINFO_OFFSET(upid, nr);
	VMCOREINFO_OFFSET(upid, ns);
	VMCOREINFO_OFFSET(upid, pid_chain);
	VMCOREINFO_OFFSET(pid, tasks);
	VMCOREINFO_OFFSET(pid, numbers);
	VMCOREINFO_OFFSET(pid_link, pid);
	VMCOREINFO_STRUCT_SIZE(upid);
	VMCOREINFO_STRUCT_SIZE(pid_link);
	VMCOREINFO_SIZE(cpumask_t);
	VMCOREINFO_SYMBOL(nr_threads);
	VMCOREINFO_OFFSET(task_struct, state);
	VMCOREINFO_OFFSET(task_struct, stack);
	VMCOREINFO_OFFSET(task_struct, flags);
	VMCOREINFO_OFFSET(task_struct, sched_info);
	VMCOREINFO_OFFSET(task_struct, mm);
	VMCOREINFO_OFFSET(task_struct, active_mm);
	VMCOREINFO_OFFSET(task_struct, rss_stat);
	VMCOREINFO_OFFSET(task_struct, exit_state);
	VMCOREINFO_OFFSET(task_struct, pid);
	VMCOREINFO_OFFSET(task_struct, tgid);
	VMCOREINFO_OFFSET(task_struct, utime);
	VMCOREINFO_OFFSET(task_struct, stime);
	VMCOREINFO_OFFSET(task_struct, start_time);
	VMCOREINFO_OFFSET(task_struct, comm);
	VMCOREINFO_OFFSET(task_struct, real_parent);
	VMCOREINFO_OFFSET(task_struct, parent);
	VMCOREINFO_OFFSET(task_struct, pids);
	VMCOREINFO_OFFSET(task_struct, thread);
	VMCOREINFO_OFFSET(task_struct, signal);
	VMCOREINFO_OFFSET(task_struct, sighand);
	VMCOREINFO_OFFSET(task_struct, blocked);
	VMCOREINFO_OFFSET(task_struct, pending);
	VMCOREINFO_OFFSET(signal_struct, nr_threads);
	VMCOREINFO_OFFSET(signal_struct, shared_pending);
	VMCOREINFO_OFFSET(sched_info, last_arrival);
	VMCOREINFO_OFFSET(sighand_struct, action);
	VMCOREINFO_STRUCT_SIZE(task_struct);
	VMCOREINFO_STRUCT_SIZE(sighand_struct);
	VMCOREINFO_OFFSET(task_rss_stat, count);
	VMCOREINFO_STRUCT_SIZE(mm_struct);
	VMCOREINFO_OFFSET(thread_struct, sp);
	VMCOREINFO_OFFSET(k_sigaction, sa);
	VMCOREINFO_OFFSET(sigaction, sa_handler);
	VMCOREINFO_OFFSET(sigaction, sa_flags);
	VMCOREINFO_OFFSET(sigaction, sa_mask);
	VMCOREINFO_OFFSET(sigpending, list);
	VMCOREINFO_OFFSET(sigpending, signal);
	VMCOREINFO_STRUCT_SIZE(sigqueue);
	VMCOREINFO_STRUCT_SIZE(k_sigaction);
	VMCOREINFO_OFFSET(siginfo, si_signo);
	VMCOREINFO_SIZE(cputime_t);

	/*
	 * The following symbol and offsets are for reading symbols
	 * defined in dynamically loaded modules.  To dump kallsyms,
	 * modules need to be processed as well.
	 */
	VMCOREINFO_SYMBOL(vmcore_modules);
	VMCOREINFO_OFFSET(module, state);
	VMCOREINFO_OFFSET(module, list);
	VMCOREINFO_OFFSET(module, name);
	VMCOREINFO_OFFSET(module, num_syms);
	VMCOREINFO_OFFSET(module, symtab);
	VMCOREINFO_OFFSET(module, num_symtab);
	VMCOREINFO_OFFSET(module, strtab);
	VMCOREINFO_OFFSET(elf64_sym, st_name); 
	VMCOREINFO_OFFSET(elf64_sym, st_info);
	VMCOREINFO_OFFSET(elf64_sym, st_value);
}
#endif
