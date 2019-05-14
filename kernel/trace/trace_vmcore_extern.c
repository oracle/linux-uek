/*
 * vmcoreinfo trace extern kexec setup
 *
 * Copyright (C) 2019 Isaac Chen <isaac.chen@oracle.com>
 */
#include <linux/ftrace_event.h>
#include <linux/kexec.h>
#include <trace/syscall.h>
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
}
#endif
