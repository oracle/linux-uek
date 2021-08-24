/* SPDX-License-Identifier: GPL-2.0-only */
/* Trace point definitions for resilient rdma events.
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rdmaip
#if !defined(__RDMAIP_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RDMAIP_TRACE_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM	rdmaip

#define MAX_MSG_LEN	256

DECLARE_EVENT_CLASS(rdmaip_debug,
	TP_PROTO(int level, const char *func, struct va_format *vaf),
	TP_ARGS(level, func, vaf),
	TP_STRUCT__entry(
		__field(int, level)
		__string(func, func)
		__dynamic_array(char, msg, MAX_MSG_LEN)
	),
	TP_fast_assign(
		__entry->level = level;
		__assign_str(func, func);
		WARN_ON_ONCE(vsnprintf(__get_dynamic_array(msg),
				       MAX_MSG_LEN, vaf->fmt,
				       *vaf->va) >= MAX_MSG_LEN);
	),
	TP_printk("%s: %s", __get_str(func), __get_str(msg))
);

DEFINE_EVENT(rdmaip_debug, rdmaip_debug_1,
	TP_PROTO(int level, const char *func, struct va_format *vaf),
	TP_ARGS(level, func, vaf)
);

DEFINE_EVENT(rdmaip_debug, rdmaip_debug_2,
	TP_PROTO(int level, const char *func, struct va_format *vaf),
	TP_ARGS(level, func, vaf)
);

DEFINE_EVENT(rdmaip_debug, rdmaip_debug_3,
	TP_PROTO(int level, const char *func, struct va_format *vaf),
	TP_ARGS(level, func, vaf)
);

#endif /* __RDMAIP_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE rdmaip_trace
#include <trace/define_trace.h>
