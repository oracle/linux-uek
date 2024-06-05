/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM dcache_neg_dentry

#if !defined(_TRACE_DCACHE_NEG_DENTRY_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DCACHE_NEG_DENTRY_H

#include <linux/tracepoint.h>

TRACE_EVENT(prune_negative_dentry,
	TP_PROTO(unsigned long prune_count),
	TP_ARGS(prune_count),
	TP_STRUCT__entry(
		__field(unsigned long, prune_count)
	),
	TP_fast_assign(
		__entry->prune_count = prune_count;
	),
	TP_printk("neg-dentry pruned in this iteration: %lu", __entry->prune_count)
);

TRACE_EVENT(prune_negative_one_sb_begin,
	TP_PROTO(struct super_block *sb, const char *s_id),
	TP_ARGS(sb, s_id),
	TP_STRUCT__entry(
		__field(void *, sb)
		__string(s_id,  s_id)
	),
	TP_fast_assign(
		__entry->sb = sb;
		__assign_str(s_id);
	),
	TP_printk("SB=%s, sb: %p", __get_str(s_id), __entry->sb)
);

TRACE_EVENT(prune_negative_one_sb_end,
	TP_PROTO(struct super_block *sb,
		 unsigned long scan_once,
		 unsigned long freed),
	TP_ARGS(sb, scan_once, freed),
	TP_STRUCT__entry(
		__field(void *, sb)
		__field(unsigned long, scan_once)
		__field(unsigned long, freed)
	),
	TP_fast_assign(
		__entry->sb = sb;
		__entry->scan_once = scan_once;
		__entry->freed = freed;
	),
	TP_printk("sb: %p scanned: %lu pruned: %lu",
				__entry->sb, __entry->scan_once, __entry->freed)
);

#endif /* _TRACE_DCACHE_NEG_DENTRY_H */

/* This part must be outside protection */
#define TRACE_INCLUDE_FILE dcache_neg_dentry_trace
#include <trace/define_trace.h>
