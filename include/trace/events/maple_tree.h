/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM maple_tree

#if !defined(_TRACE_MM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MM_H


#include <linux/tracepoint.h>

struct ma_state;
struct maple_subree_state;
struct maple_big_node;

TRACE_EVENT(mas_split,

	TP_PROTO(struct ma_state *mas),

	TP_ARGS(mas),

	TP_STRUCT__entry(
			__field(struct ma_state *, mas)
			__field(unsigned long, index)
			__field(unsigned long, last)
	),

	TP_fast_assign(
			__entry->mas		= mas;
			__entry->index		= mas->index;
			__entry->last		= mas->last;
	),

	TP_printk("\t%lu-%lu",
		  (unsigned long) __entry->index,
		  (unsigned long) __entry->last
	)
);

TRACE_EVENT(mas_spanning_store,

	TP_PROTO(struct ma_state *mas),

	TP_ARGS(mas),

	TP_STRUCT__entry(
			__field(struct ma_state *, mas)
			__field(unsigned long, index)
			__field(unsigned long, last)
	),

	TP_fast_assign(
			__entry->mas		= mas;
			__entry->index		= mas->index;
			__entry->last		= mas->last;
	),

	TP_printk("\t%lu-%lu",
		  (unsigned long) __entry->index,
		  (unsigned long) __entry->last
	)
);

TRACE_EVENT(mas_rebalance,

	TP_PROTO(struct ma_state *mas),

	TP_ARGS(mas),

	TP_STRUCT__entry(
			__field(struct ma_state *, mas)
			__field(unsigned long, index)
			__field(unsigned long, last)
	),

	TP_fast_assign(
			__entry->mas		= mas;
			__entry->index		= mas->index;
			__entry->last		= mas->last;
	),

	TP_printk("\t%lu-%lu",
		  (unsigned long) __entry->index,
		  (unsigned long) __entry->last
	)
);

TRACE_EVENT(mas_spanning_rebalance,

	TP_PROTO(struct ma_state *mas),

	TP_ARGS(mas),

	TP_STRUCT__entry(
			__field(struct ma_state *, mas)
			__field(unsigned long, index)
			__field(unsigned long, last)
	),

	TP_fast_assign(
			__entry->mas		= mas;
			__entry->index		= mas->index;
			__entry->last		= mas->last;
	),

	TP_printk("\t%lu-%lu",
		  (unsigned long) __entry->index,
		  (unsigned long) __entry->last
	)
);


#endif /* _TRACE_MM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
