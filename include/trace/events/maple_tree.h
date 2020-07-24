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

TRACE_EVENT(mtree_load,

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
)

TRACE_EVENT(mtree_erase,

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
)

TRACE_EVENT(mtree_store_range,

	TP_PROTO(struct ma_state *mas, void *val),

	TP_ARGS(mas, val),

	TP_STRUCT__entry(
			__field(struct ma_state *, mas)
			__field(unsigned long, index)
			__field(unsigned long, last)
			__field(void *, val)
	),

	TP_fast_assign(
			__entry->mas		= mas;
			__entry->index		= mas->index;
			__entry->last		= mas->last;
			__entry->val		= val;
	),

	TP_printk("\t%lu-%lu => %px",
		  (unsigned long) __entry->index,
		  (unsigned long) __entry->last,
		  (void *) __entry->val
	)
)

TRACE_EVENT(mas_is_span_wr,

	TP_PROTO(struct ma_state *mas, unsigned long piv, void *val),

	TP_ARGS(mas, piv, val),

	TP_STRUCT__entry(
			__field(struct ma_state *, mas)
			__field(unsigned long, min)
			__field(unsigned long, max)
			__field(unsigned long, index)
			__field(unsigned long, last)
			__field(unsigned long, piv)
			__field(void *, val)
			__field(void *, node)
	),

	TP_fast_assign(
			__entry->mas		= mas;
			__entry->min		= mas->min;
			__entry->max		= mas->max;
			__entry->index		= mas->index;
			__entry->last		= mas->last;
			__entry->piv		= piv;
			__entry->val		= val;
			__entry->node		= mas->node;
	),

	TP_printk("\t%px (%lu %lu): %lu-%lu (%lu) %px",
		  (void *) __entry->node,
		  (unsigned long) __entry->min,
		  (unsigned long) __entry->max,
		  (unsigned long) __entry->index,
		  (unsigned long) __entry->last,
		  (unsigned long) __entry->piv,
		  (void *) __entry->val
	)
)
#endif /* _TRACE_MM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
