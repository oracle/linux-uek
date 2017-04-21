/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#ifndef _DAX_IMPL_H
#define _DAX_IMPL_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/hugetlb.h>
#include <linux/nodemask.h>
#include <linux/bug.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/hugetlb.h>
#include <asm/hypervisor.h>
#include <asm/pgtable.h>
#include <asm/mdesc.h>
#include <asm/atomic.h>
#include "ccb.h"
#include "sys_dax.h"

extern bool dax_no_flow_ctl, dax_no_ra_pgsz;
extern int dax_debug;
extern atomic_t dax_alloc_counter;
extern atomic_t dax_actual_mem;
extern atomic_t dax_requested_mem;
extern int dax_peak_waste;
extern spinlock_t dm_list_lock;
extern const struct vm_operations_struct dax_vm_ops;

#define DAX_BIP_MAX_CONTIG_BLOCKS	2
#define FORCE_LOAD_ON_ERROR		0x1
#define FORCE_LOAD_ON_NO_FLOW_CTL	0x2

#define	DAX_DBG_FLG_BASIC	0x01
#define	DAX_DBG_FLG_DRV		0x02
#define	DAX_DBG_FLG_MAP		0x04
#define DAX_DBG_FLG_LIST	0x08
#define DAX_DBG_FLG_PERF	0x10
#define DAX_DBG_FLG_NOMAP	0x20
#define DAX_DBG_FLG_KILL_INFO	0x40
#define	DAX_DBG_FLG_ALL		0xff

#define dax_info(fmt, ...)	pr_info("%s: " fmt "\n", __func__,\
					##__VA_ARGS__)
#define dax_err(fmt, ...)	pr_err("%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define dax_alert(fmt, ...)	pr_alert("%s: " fmt "\n", __func__,\
					##__VA_ARGS__)
#define dax_warn(fmt, ...)	pr_warn("%s: " fmt "\n", __func__,\
					##__VA_ARGS__)

#define	dax_dbg(fmt, ...)	do {\
					if (dax_debug & DAX_DBG_FLG_BASIC)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)
#define	dax_drv_dbg(fmt, ...)	do {\
					if (dax_debug & DAX_DBG_FLG_DRV)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)
#define	dax_map_dbg(fmt, ...)	do {\
					if (dax_debug & DAX_DBG_FLG_MAP)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)
#define	dax_list_dbg(fmt, ...)	do {\
					if (dax_debug & DAX_DBG_FLG_LIST)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)
#define	dax_perf_dbg(fmt, ...)	do {\
					if (dax_debug & DAX_DBG_FLG_PERF)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)
#define	dax_nomap_dbg(fmt, ...)	do {\
					if (dax_debug & DAX_DBG_FLG_NOMAP)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)
#define	dax_kill_info_dbg(fmt, ...)	do {				\
					if (dax_debug & DAX_DBG_FLG_KILL_INFO)\
						dax_info(fmt, ##__VA_ARGS__);\
				} while (0)

#define DAX_VALIDATE_AT(hdr, type, label)				\
	do {								\
		if (!((hdr)->at_##type == CCB_AT_VA ||			\
		    (hdr)->at_##type == CCB_AT_IMM)) {			\
			dax_err(					\
			"invalid at_"#type" address type (%d) in user CCB", \
				(hdr)->at_##type);			\
			goto label;					\
		}							\
	} while (0)

#define	DAX_NAME		"dax"
#define DAX_MINOR		1UL
#define DAX_MAJOR		1UL

#define DAX1_STR    "ORCL,sun4v-dax"
#define DAX1_FC_STR "ORCL,sun4v-dax-fc"
#define DAX2_STR    "ORCL,sun4v-dax2"

#define CCB_BYTE_TO_NCCB(a)	((a) / sizeof(union ccb))
#define NCCB_TO_CCB_BYTE(a)	((a) * sizeof(union ccb))
#define CA_BYTE_TO_NCCB(a)	((a) / sizeof(struct ccb_completion_area))
#define NCCB_TO_CA_BYTE(a)	((a) * sizeof(struct ccb_completion_area))

#ifndef U16_MAX
#define U16_MAX 65535
#endif
#define DAX_NOMAP_RETRIES	3
#define DAX_DEFAULT_MAX_CCB	15
#define DAX_SYN_LARGE_PAGE_SIZE	(4*1024*1024UL)
#define	DAX_CCB_BUF_SZ		PAGE_SIZE
#define	DAX_CCB_BUF_NELEMS	(DAX_CCB_BUF_SZ / sizeof(union ccb))

#define	DAX_CA_BUF_SZ		(DAX_CCB_BUF_NELEMS * \
				 sizeof(struct ccb_completion_area))

#define	DAX_MMAP_SZ		DAX_CA_BUF_SZ
#define	DAX_MMAP_OFF		(off_t)(0x0)

#define	DWORDS_PER_CCB		8

#define	CCB_HDR(ccb)		((struct ccb_hdr *)(ccb))
#define	IS_LONG_CCB(ccb)	((CCB_HDR(ccb))->sync_flags & CCB_SYNC_LONGCCB)
/* VM spec 36.2.1.1.8 & 36.2.1.2 / PRM 23.7.1 */
#define PAGE_CHECK_SHIFT  56
#define NO_PAGE_RANGE 0xfLL
#define NO_PAGE_RANGE_CHECK  (NO_PAGE_RANGE << PAGE_CHECK_SHIFT)
#define CHECK_4MB_PAGE_RANGE (_PAGE_SZ4MB_4V << PAGE_CHECK_SHIFT)

#define	DAX_CCB_WAIT_USEC		100
#define	DAX_CCB_WAIT_RETRIES_MAX	10000

#define	DAX_KILL_WAIT_USEC	100UL
#define	DAX_KILL_RETRIES_MAX	10000

#define	DAX_INFO_WAIT_USEC	100UL
#define	DAX_INFO_RETRIES_MAX	2

#define DAX_OUT_SIZE_FROM_CCB(sz)	((1 + (sz)) * 64)
#define DAX_IN_SIZE_FROM_CCB(sz)		(1 + (sz))

/* Dax PERF registers */
#define DAX_PERF_CTR_CTL			171
#define DAX_PERF_CTR_0				168
#define DAX_PERF_CTR_1				169
#define DAX_PERF_CTR_2				170
#define DAX_PERF_REG_OFF(num, reg, node, dax) \
		(((reg) + (num)) + ((node) * 196) + ((dax) * 4))
#define DAX_PERF_CTR_CTL_OFFSET(node, dax) \
		DAX_PERF_REG_OFF(0, DAX_PERF_CTR_CTL, (node), (dax))
#define DAX_PERF_CTR_OFFSET(num, node, dax) \
		DAX_PERF_REG_OFF(num, DAX_PERF_CTR_0, (node), (dax))

/* dax flow control and ra/pgsz test constants */
#define DAX_FLOW_LIMIT		64UL
#define	DAX_INPUT_ELEMS		128
#define	DAX_INPUT_ELEM_SZ	1
#define	DAX_OUTPUT_ELEMS	128
#define	DAX_OUTPUT_ELEM_SZ	1

enum dax_types {
	DAX1,
	DAX2
};

/* dax address type */
enum dax_at {
	AT_DST,
	AT_SRC0,
	AT_SRC1,
	AT_TBL,
	AT_MAX
};

/*
 * Per mm dax structure. Thread contexts related to a
 * mm are added to the ctx_list. Each instance of these dax_mms
 * are maintained in a global dax_mm_list
 */
struct dax_mm {
	struct list_head	mm_list;
	struct list_head	ctx_list;
	struct mm_struct	*this_mm;
	spinlock_t		lock;
	int			vma_count;
	int			ctx_count;
};

/*
 * Per vma dax structure. This is stored in the vma
 * private pointer.
 */
struct dax_vma {
	struct dax_mm		*dax_mm;
	struct vm_area_struct	*vma;
	void			*kva;	/* kernel virtual address */
	unsigned long		pa;	/* physical address */
	size_t			length;
};


/*
 * DAX per thread CCB context structure
 *
 * *owner : pointer to thread that owns this ctx
 * ctx_list : to add this struct to a linked list
 * *dax_mm : pointer to per process dax mm
 * *ccb_buf : CCB buffer
 * ccb_buf_ra : cached RA of CCB
 * **pages : pages for CCBs
 * *ca_buf : CCB completion area (CA) buffer
 * ca_buf_ra : cached RA of completion area
 * ccb_buflen : CCB buffer length in bytes
 * ccb_submit_maxlen : max user ccb byte len per call
 * ca_buflen : Completion area buffer length in bytes
 * a_start : Start of region A of BIP buffer
 * a_end : End of region A of BIP buffer
 * b_end : End of region B of BIP buffer.
 *          region B always starts at 0
 * resv_start : Start of memory reserved in BIP buffer, set by
 *	dax_ccb_buffer_reserve and cleared by dax_ccb_buffer_commit
 * resv_end : End of memory reserved in BIP buffer, set by
 *	dax_ccb_buffer_reserve and cleared by dax_ccb_buffer_commit
 * bufcnt : Number of bytes currently used by the BIP buffer
 * ccb_count : Number of ccbs submitted via dax_ioctl_ccb_exec
 * fail_count : Number of ccbs that failed the submission via dax_ioctl_ccb_exec
 */
struct dax_ctx {
	struct task_struct		*owner;
	struct list_head		ctx_list;
	struct dax_mm			*dax_mm;
	union ccb			*ccb_buf;
	u64				ccb_buf_ra;
	/*
	 * The array is used to hold a *page for each locked page. And each VA
	 * type in a ccb will need an entry in this. The other
	 * dimension of the array is to hold this quad for each ccb.
	 */
	struct page			**pages[AT_MAX];
	struct ccb_completion_area	*ca_buf;
	u64				ca_buf_ra;
	u32				ccb_buflen;
	u32				ccb_submit_maxlen;
	u32				ca_buflen;
	/* BIP related variables */
	u32				a_start;
	u32				a_end;
	u32				b_end;
	u32				resv_start;
	u32				resv_end;
	u32				bufcnt;
	u32				ccb_count;
	u32				fail_count;
};

int dax_alloc_page_arrays(struct dax_ctx *ctx);
void dax_dealloc_page_arrays(struct dax_ctx *ctx);
void dax_unlock_pages_ccb(struct dax_ctx *ctx, int ccb_num, union ccb *ccbp);
void dax_prt_ccbs(union ccb *ccb, u64 len);
bool dax_has_flow_ctl_numa(void);
bool dax_has_ra_pgsz(void);
int dax_ccb_kill(u64 ca, u16 *kill_res);
long dax_perfcount_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
union ccb *dax_ccb_buffer_reserve(struct dax_ctx *ctx, size_t len,
				  size_t *reserved);
void dax_ccb_buffer_commit(struct dax_ctx *ctx, size_t len);
int dax_ccb_buffer_get_contig_ccbs(struct dax_ctx *ctx, int *len_ccb);
void dax_ccb_buffer_decommit(struct dax_ctx *ctx, int n_ccb);
int dax_devmap(struct file *f, struct vm_area_struct *vma);
void dax_vm_open(struct vm_area_struct *vma);
void dax_vm_close(struct vm_area_struct *vma);
void dax_overflow_check(struct dax_ctx *ctx, int idx);
int dax_clean_dm(struct dax_mm *dm);
void dax_ccbs_drain(struct dax_ctx *ctx, struct dax_vma *dv);
int dax_map_segment(struct dax_ctx *dax_ctx, union ccb *ccb,
		     size_t ccb_len);
void dax_unlock_pages(struct dax_ctx *dax_ctx, union ccb *ccb,
			     size_t ccb_len);
int dax_address_in_use(struct dax_vma *dv, u32 addr_type,
			      unsigned long addr);
void dax_debugfs_init(void);
void dax_debugfs_clean(void);
#endif /* _DAX_IMPL_H */
