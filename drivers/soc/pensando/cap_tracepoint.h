/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM pensando

#if !defined(_CAP_TRACEPOINT_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _CAP_TRACEPOINT_H_

#include <linux/tracepoint.h>
#include <linux/mm_types.h>

DECLARE_EVENT_CLASS(cap_mem_fault,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf),

	TP_ARGS(vma, vmf),

	TP_STRUCT__entry(
		__field(unsigned long, vm_start)
		__field(unsigned long, vm_end)
		__field(unsigned long, va)
		__field(unsigned long, pa)
	),

	TP_fast_assign(
		__entry->vm_start = vma->vm_start;
		__entry->vm_end = vma->vm_end;
		__entry->va = vmf->address;
		__entry->pa = vmf->pgoff << PAGE_SHIFT;
	),

	TP_printk("vm_start 0x%lx vm_end 0x%lx va 0x%lx pa 0x%lx",
		__entry->vm_start,
		__entry->vm_end,
		__entry->va,
		__entry->pa
	)
);

DEFINE_EVENT(cap_mem_fault, cap_mem_fault_enter,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf),

	TP_ARGS(vma, vmf)
);

DEFINE_EVENT(cap_mem_fault, cap_mem_fault_exit,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf),

	TP_ARGS(vma, vmf)
);

DEFINE_EVENT(cap_mem_fault, cap_mem_pte_fault,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf),

	TP_ARGS(vma, vmf)
);

DEFINE_EVENT(cap_mem_fault, cap_mem_pmd_fault,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf),

	TP_ARGS(vma, vmf)
);

DEFINE_EVENT(cap_mem_fault, cap_mem_pud_fault,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf),

	TP_ARGS(vma, vmf)
);

DECLARE_EVENT_CLASS(cap_mem_get_unmapped_area,

TP_PROTO(unsigned long va, unsigned long len, unsigned long pgoff, unsigned long align),

	TP_ARGS(va, len, pgoff, align),

	TP_STRUCT__entry(
		__field(unsigned long, va)
		__field(unsigned long, len)
		__field(unsigned long, pa)
		__field(unsigned long, align)
	),

	TP_fast_assign(
		__entry->va = va;
		__entry->len = len;
		__entry->pa = pgoff << PAGE_SHIFT;
		__entry->align = align;
	),

	TP_printk("vm_start 0x%lx vm_end 0x%lx pa 0x%lx align 0x%lx",
		__entry->va,
		__entry->va + __entry->len,
		__entry->pa,
		__entry->align
	)
);

DEFINE_EVENT(cap_mem_get_unmapped_area, cap_mem_get_unmapped_area_enter,

	TP_PROTO(unsigned long va, unsigned long len, unsigned long pgoff, unsigned long align),

	TP_ARGS(va, len, pgoff, align)
);

DEFINE_EVENT(cap_mem_get_unmapped_area, cap_mem_get_unmapped_area_exit,

	TP_PROTO(unsigned long va, unsigned long len, unsigned long pgoff, unsigned long align),

	TP_ARGS(va, len, pgoff, align)
);

DECLARE_EVENT_CLASS(cap_mem_vmf_insert_pfn,

TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf, unsigned long pa),

	TP_ARGS(vma, vmf, pa),

	TP_STRUCT__entry(
		__field(unsigned long, vm_start)
		__field(unsigned long, vm_end)
		__field(unsigned long, va)
		__field(unsigned long, pa)
	),

	TP_fast_assign(
		__entry->vm_start = vma->vm_start;
		__entry->vm_end = vma->vm_end;
		__entry->va = vmf->address;
		__entry->pa = pa;
	),

	TP_printk("vm_start 0x%lx vm_end 0x%lx va 0x%lx pa 0x%lx",
		__entry->vm_start,
		__entry->vm_end,
		__entry->va,
		__entry->pa
	)
);

DEFINE_EVENT(cap_mem_vmf_insert_pfn, cap_mem_vmf_insert_pfn_pte,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf, unsigned long pa),

	TP_ARGS(vma, vmf, pa)
);

DEFINE_EVENT(cap_mem_vmf_insert_pfn, cap_mem_vmf_insert_pfn_pmd,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf, unsigned long pa),

	TP_ARGS(vma, vmf, pa)
);

DEFINE_EVENT(cap_mem_vmf_insert_pfn, cap_mem_vmf_insert_pfn_pud,

	TP_PROTO(struct vm_area_struct *vma, struct vm_fault *vmf, unsigned long pa),

	TP_ARGS(vma, vmf, pa)
);

#endif  /* !defined(_CAP_TRACEPOINT_H_) || defined(TRACE_HEADER_MULTI_READ) */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE cap_tracepoint
#include <trace/define_trace.h>
