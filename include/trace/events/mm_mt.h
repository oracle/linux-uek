/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM mm_mt

#if !defined(_TRACE_MM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MM_H


#include <linux/tracepoint.h>

struct mm_struct;
struct vm_area_struct;

/**
 * vma_mt_erase - called to erase an entry from the mm_mt
 *
 * @mm:		the mm_struct which contains the mt
 * @vma:	the vma that is to be erased.
 *
 */
TRACE_EVENT(vma_mt_erase,

	TP_PROTO(struct mm_struct *mm, struct vm_area_struct *vma),

	TP_ARGS(mm, vma),

	TP_STRUCT__entry(
			__field(struct mm_struct *, mm)
			__field(struct vm_area_struct *, vma)
			__field(unsigned long, vm_start)
			__field(unsigned long, vm_end)
	),

	TP_fast_assign(
			__entry->mm		= mm;
			__entry->vma		= vma;
			__entry->vm_start	= vma->vm_start;
			__entry->vm_end		= vma->vm_end - 1;
	),

	TP_printk("mt_mod %p, (%p), ERASE, %lu, %lu",
		  __entry->mm, __entry->vma,
		  (unsigned long) __entry->vm_start,
		  (unsigned long) __entry->vm_end
	)
);

/**
 * vma_mt_szero - Called to set a range to NULL in the mm_mt
 *
 */
TRACE_EVENT(vma_mt_szero,
	TP_PROTO(struct mm_struct *mm, unsigned long start,
		 unsigned long end),

	TP_ARGS(mm, start, end),

	TP_STRUCT__entry(
			__field(struct mm_struct*, mm)
			__field(unsigned long, start)
			__field(unsigned long, end)
	),

	TP_fast_assign(
			__entry->mm		= mm;
			__entry->start		= start;
			__entry->end		= end - 1;
	),

	TP_printk("mt_mod %p, (NULL), SNULL, %lu, %lu",
		  __entry->mm,
		  (unsigned long) __entry->start,
		  (unsigned long) __entry->end
	)
);

TRACE_EVENT(vma_mt_store,
	TP_PROTO(struct mm_struct *mm, struct vm_area_struct *vma),

	TP_ARGS(mm, vma),

	TP_STRUCT__entry(
			__field(struct mm_struct*, mm)
			__field(struct vm_area_struct*, vma)
			__field(unsigned long, vm_start)
			__field(unsigned long, vm_end)
	),

	TP_fast_assign(
			__entry->mm		= mm;
			__entry->vma		= vma;
			__entry->vm_start	= vma->vm_start;
			__entry->vm_end		= vma->vm_end - 1;
	),

	TP_printk("mt_mod %p, (%p), STORE, %lu, %lu",
		  __entry->mm, __entry->vma,
		  (unsigned long) __entry->vm_start,
		  (unsigned long) __entry->vm_end - 1
	)
);


TRACE_EVENT(exit_mmap,
	TP_PROTO(struct mm_struct *mm),

	TP_ARGS(mm),

	TP_STRUCT__entry(
			__field(struct mm_struct*, mm)
	),

	TP_fast_assign(
			__entry->mm		= mm;
	),

	TP_printk("mt_mod %p, DESTROY\n",
		  __entry->mm
	)
);

#endif /* _TRACE_MM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
