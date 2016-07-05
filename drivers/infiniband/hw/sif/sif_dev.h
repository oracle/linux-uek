/*
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_dev.h: Driver specific data structure definitions
 */

#ifndef __SIF_DEV_H
#define __SIF_DEV_H

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <rdma/ib_verbs.h>
#include <linux/mm.h>
#include <linux/workqueue.h>


#include "sif_idr.h"
#include "sif_fwa.h"
#include "sif_mmu.h"
#include "sif_pqp.h"
#include "sif_mem.h"


#include "sif_verbs.h"

#include "sif_r3.h"

#define PCI_VENDOR_ID_SUN	0x108e
#define PCI_DEVICE_ID_PSIF_PF	0x2088
#define PCI_DEVICE_ID_PSIF_VF	0x2089
#define PCI_DEVICE_ID_SN1_PF	0x2188
#define PCI_DEVICE_ID_SN1_VF	0x2189
#define PCI_DEVICE_ID_SN2_PF	0x2198
#define PCI_DEVICE_ID_SN2_VF	0x2199
#define PCI_DEVICE_ID_SN3_PF	0x21A8
#define PCI_DEVICE_ID_SN3_VF	0x21A9

#define PSIF_DEVICE(sdevice) ((sdevice)->pdev->device)
#define PSIF_SUBSYSTEM(sdevice) ((sdevice)->pdev->subsystem_device)

#define IS_PSIF(sdevice) (PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_PSIF_PF || \
				PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_PSIF_VF)

#define IS_SIBS(sdevice) (PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_SN1_PF || \
				PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_SN1_VF || \
				PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_SN2_PF || \
				PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_SN2_VF || \
				PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_SN3_PF || \
				PSIF_DEVICE(sdevice) == PCI_DEVICE_ID_SN3_VF)

/* Sonoma rev 1 most closely resembles PSIF rev 2
 * TBD: Need a more fine grained solution to feature/bug checking as we move on..
 */
#define PSIF_REVISION(sdevice) \
	(IS_SIBS(sdevice) ? (sdevice)->pdev->revision + 1 : (sdevice)->pdev->revision)


/* Tested limit on #of CQEs - may support 2^30 but
 * need machine with lots of memory to test it!
 */
#define SIF_SW_MAX_CQE_LOG2 0x18  /* = 16 MB - tested and should cover most use cases.. */
#define SIF_SW_MAX_CQE (1 << SIF_SW_MAX_CQE_LOG2)

#define SIF_SW_MAX_SQE_LOG2 0xf  /* = 32K */
#define SIF_SW_MAX_SQE (1 << SIF_SW_MAX_SQE_LOG2)

/* Start offset of the special sq_cmpl mapping:
 * each queue have at most 1 << SIF_SW_MAX_SQE_LOG2 entries
 * Maximal extent of elements in a queue is 1 << 1f
 * We then shift an additional bit to get to an unused upper bit
 * to set just to avoid starting at vaddr 0:
 */
#define SIF_SQ_CMPL_SHIFT (SIF_SW_MAX_SQE_LOG2 + 0x1f + 1)
#define SIF_SQ_CMPL_START (1ULL << SIF_SQ_CMPL_SHIFT)

/* Use easily identifiable high addresses to map descriptor arrays
 * when GVA2GPA mapping is needed. These are virtual addresses
 * that will only be used by sif.
 * For debug purposes, encode the sif_tab_type index in the address:
 */
#define SIF_BASE_ADDR_START(queue) \
	((1ULL << (SIF_SQ_CMPL_SHIFT + 1)) + ((u64)(queue) << (SIF_SQ_CMPL_SHIFT - 6)))
#define SIF_BASE_ADDR_EQ_START(queue) \
	(SIF_BASE_ADDR_START(queue) + (1ULL << SIF_SQ_CMPL_SHIFT))

#define SIF_HW_MAX_SEND_SGE 16

/* This defines the defaults for implicit timers within the driver */
#define SIF_HW_TIMEOUT 5000

/* BAR indices for SIF */
#define SIF_MSIX_BAR  0
#define SIF_CBU_BAR   2
#define SIF_EPS_BAR   4

struct sif_mmu_ctx; /* See sif_mmu.h */

/* Hardware/firmware accessible tables in memory
 * NB! If you change anything here (including order)
 * remember to update
 * - struct sif_table_layout in sif_base.c
 * - define_funcs call list in sif_base.h
 */
#define sif_tab_init_max epsa0_csr_req

enum sif_tab_type {
	epsc_csr_req,		/* EPSC request queue */
	epsc_csr_rsp,		/* EPSC response queue (EPSC completions) */
	key,			/* Key validation table */
	qp,			/* QP descriptor table (hw owned) */
	rqsp,			/* RQ scratch pad data */
	atsp,			/* Atomic replay data */
	ah,			/* Address handle table (sw owned) */
	cq_hw,			/* Compl desc (read only for sw) */
	cq_sw,			/* Compl desc (writable for sw) */
	rq_hw,			/* Receive queue (read only for sw) */
	rq_sw,			/* Receive queue (writable for sw) */
	sq_hw,			/* Send queue (readable for sw) */
	sq_sw,			/* Send queue (writable for sw)*/
	sq_cmpl,		/* sqe cache for cq block (used by hw only) */
	sq_ring,		/* Send queue scheduler ring buffer */
	sq_tvl,			/* Send queue scheduler (TBD-what is this?) */
	sq_rspq,		/* Send queue scheduler response queue */
	bw_cb,			/* High bandwidth collect buffers (NB! Device addr space) */
	lat_cb,			/* Low latency collect buffers (NB! Device addr space) */
	epsa0_csr_req,		/* EPSA-n request queue */
	epsa0_csr_rsp,		/* EPSA-n response queue (EPSC completions) */
	epsa1_csr_req,
	epsa1_csr_rsp,
	epsa2_csr_req,
	epsa2_csr_rsp,
	epsa3_csr_req,
	epsa3_csr_rsp,
	sif_tab_max
};

/* Depends on sif_tab_type: */
#include "sif_epsc.h"

/* Driver record of a block of entries associated with a particular PD
 * Used for tables that have entry_per_block > 1:
 */
struct sif_table_block {
	struct sif_pd *pd;  /* Owning protection domain, if allocated */
	struct sif_table *table;  /* Pointer back to table this is a block within */
	struct list_head pd_list; /* Used by pd to chain it's allocated blocks */
	u32 offset;         /* Index offset that this block starts at */
	u32 last_used;      /* Last alloc'ed entry - used to support round-robin alloc */
	ulong bitmap[0];    /* Used bitmap for entries, follows right after struct */
};

/* Driver record of a sif in-memory table */
struct sif_table {
	bool is_eq;
	union {
		enum sif_tab_type type; /* Our type (and index within sdev->ba) */
		u32 index;  /* index of this eq - valid iff @is_eq */
	};
	bool from_interrupt;    /* If set, alloc/free must be permitted from intr.ctxt */
	bool alloc_rr;          /* Set if round-robin allocation is to be used */
	spinlock_t lock;	/* Protects bitmap */
	ulong *bitmap;		/* Used bitmap for blocks of entries */
	struct sif_mem *mem;    /* Allocated memory for the table */
	void *drv_ref;		/* array of driver struct pointers for non-inline structs */
	union {
		u64 sif_base;	/* Virtual base address as seen from SIF */
		void __iomem *sif_off;  /* Used for collect buffer mgmt */
	};
	size_t table_sz;	/* Size in byte of the table */
	u32 ext_sz;		/* Dist.in bytes between start of each entry */
	u32 entry_cnt;		/* Number of entries in table */
	u32 block_cnt;          /* No.of blocks (1st level alloc granularity) in table */
	u32 entry_per_block;    /* entry_per_block = entry_cnt / block_cnt */
	u32 last_used;          /* Last alloc'ed entry - used to support round-robin alloc */
	struct sif_mmu_ctx mmu_ctx; /* MMU context bookkeeping */
	void *block;            /* Space for array with block_cnt elems + bitmap iff entry_per_block > 1 */
	u32 block_ext;          /* Dist in bytes between sif_table_block elements in block */
	struct sif_dev *sdev;	/* Pointer back to main driver struct */
};

/* Driver management of event queues and interrupt channel coalescing settings*/

#define SIF_EQ_NAME_LEN 15

struct sif_irq_ch {
	bool enable_adaptive;  /* Adaptive coalescing */
	u16 channel_rx_scale;   /* rx-to-tx timer scaling factor, 2-exponent value */
	u32 channel_rate_low;   /* Message rate in messages per second. Low rate threshold. */
	u32 channel_rate_high;  /* Message rate in messages per second. High rate threshold. */
	u16 channel_ausec;      /* How many usecs to delay after first packet. */
	u16 channel_ausec_low;  /* How many usecs to delay after first packet. Low rate value. */
	u16 channel_ausec_high; /* How many usecs to delay after first packet. High rate value. */
	u16 channel_pusec;      /* How many usecs to delay after packet. */
	u16 channel_pusec_low;  /* How many usecs to delay after packet. Low rate value. */
	u16 channel_pusec_high; /* How many usecs to delay after packet. High rate value. */
	u32 entries;
	u32 mask;  /* entries - 1 for modulo using & */
	u32 extent;
	struct sif_mem *mem;   /* Ref. to ba.mem to implement macro patterns */
};

struct sif_eq {
	struct sif_table ba; /* Layout of hardware exposed table */
	struct sif_eps *eps; /* Pointer back to controlling EPS */
	u32 index;	     /* EQ index - EPS is 0, hw starts at 1 */
	u32 next_seq;	     /* Next seq to look for in eq */
	u32 entries;
	u32 extent;	     /* Size in byte of each entry */
	u32 mask;	     /* entries - 1 for modulo using & */
	struct sif_mem *mem;   /* Ref. to ba.mem to implement macro patterns */
	int intr_vec;          /* Index into s->entries[..] for the interrupt vector used */
	bool requested;	       /* Whether the irq has been requested or not on this eq */
	u32 sw_index_interval; /* No. of events we can receive before the sw index must be updated */
	u32 sw_index_next_update; /* Next scheduled update point */
	atomic_t intr_cnt;   /* Number of interrupts for the interrupt vector for this eq */
	atomic_t work_cnt;   /* No. of work queue elements processed */
	char name[SIF_EQ_NAME_LEN+1];	      /* Storage for name visible from /proc/interrupts */
	struct sif_irq_ch irq_ch; /* Per channel interrupt coalescing settings */
	cpumask_var_t affinity_mask; /* cpu affinity_mask for set_irq_hints. */
};

/* Driver specific per instance data */

struct sif_dfs;  /* Declared in sif_debug.c */
struct sif_compl; /* Declared in sif_cq.h */

struct sif_dev {
	struct ib_device ib_dev;
	struct device *hwmon_dev;
	struct sif_verbs sv;
	struct pci_dev *pdev;
	struct sif_dfs *dfs;    /* Optional debugfs info, if enabled in kernel */
	struct sif_mem_info mi; /* Used by sif_mem.c - configured SIF page sizes etc */
	struct sif_fwa fwa;     /* Used by sif_fwa.c - firmware access API */
	u8 __iomem *cb_base;		/* Collect buffer space base address */
	u8 __iomem *msi_base;		/* Base for the MSI-X vector table */
	u8 __iomem *eps_base;		/* "Raw" pointer to EPSC BAR space */
	u32 num_vfs;		/* #of virtual functions to enable */
	int fw_vfs;		/* #of virtual functions enabled in firmware */
	bool is_vf;             /* Set if this is a VF instance */
	u8 mbox_epsc;		/* EPSC mailbox index (differs between SIBS and PSIF) */
	u8 eps_cnt;		/* Number of EPSes on the chip */
	int cbu_mtrr;		/* mtrr register for the cbu - save for cleanup */
	struct psif_pcie_mbox __iomem *eps; /* Pointer to EPS-* mailboxes */
	struct workqueue_struct *wq; /* Used a.o. for async event processing */
	struct sif_mr *dma_mr; /* Privileged kernel mem MR (bypass mode) used for local_lkey */
	struct sif_mr *dma_inv_mr; /* Invalid MR for key 0 */
	struct sif_pd *pd; /* PD used for driver private table resources */

	/* BAR space sizes */
	size_t cb_sz;
	size_t msi_sz;
	size_t eps_sz;

	/* Interrupt allocation */
	size_t intr_req;  /* Number of irqs requested */
	size_t intr_cnt;  /* Number of irqs allocated */
	size_t bw_cb_cnt;   /* No.of bandwidth optimized virtual collect buffers available */
	size_t lat_cb_cnt;  /* No.of latency optimized virtual collect buffers available */
	size_t res_frac;   /* Fraction of the available hardware resources allocated to this UF */
	size_t msix_entries_sz; /* Size of the allocated msix_entries array */
	spinlock_t msix_lock;	/* Protects intr_used */
	struct msix_entry *msix_entries; /* MSI-X vector info */
	ulong *intr_used;  /* Bitmap for allocation of irqs */

	atomic_t sqp_usecnt[4];	/* track if someone has created QP 0/1 for port 1/2 */
	atomic_t cq_count; /* Track #used CQs to better scale (internal debug) timeouts */
	atomic_t cq_miss_cnt; /* Historic #completions sif_poll_cq had to busy wait for */
	atomic_t cq_miss_occ; /* Global #times sif_poll_cq had to busy wait (upd.by destroy_cq) */
	struct sif_eps *es; /* State for the EPS comm (sif_epsc.h) */
	struct sif_table ba[sif_tab_max]; /* Base address setup structures */
	struct sif_pqp **pqp;  /* PSIF management QPs */
	struct sif_cb **kernel_cb[2]; /* cb's for the kernel (bw and low latency per cpu) */
	int pqp_cnt;		  /* Number of PQPs set up */
	atomic_t next_pqp;	  /* Used for round robin assignment of pqp */
	int kernel_cb_cnt[2];	  /* Number of CBs set up for the kernel for each kind */
	struct sif_idr xrcd_refs; /* Mgmt of sif_xrcd allocations */
	struct sif_idr pd_refs;   /* Mgmt of sif_pd allocations */
	struct sif_spqp_pool ki_spqp; /* Stencil PQPs for key invalidates */
	/* Misc settings */
	struct completion ready_for_events; /* Set when we are ready to receive events from sif */
	bool registered;	/* Set when we are registered with the verbs layer */
	u64 min_resp_ticks;   /* expected min. hw resp.time in ticks */

	u16 jiffies_sampling_cnt;    /* 1/N counter used to display performance measurement.  */
	/* Support for workaround for #3552 - feature_mask create_do_not_evict_qp: */
	u32 dne_qp;

	/* Support for WA#3714 */
	u32 flush_qp[2];
	struct mutex flush_lock[2];

	/* Support for PMA proxy QP (indexes for port 1 and 2) bug #3357 */
	u32 pma_qp_idxs[2];

	/* Support for WA for bug #4096 */
	bool single_pte_pt;  /* If set, use a level + 1 page table even for a single pte */

	enum sif_mem_type mt_override;  /* Special memory type override available from sysfs */
	/* TBD: Make sure it gets updated upon value changes (handle error events) */
	struct ib_port_attr port[2];  /* cached port info. */

	/* SL to TSL map. Indexed by sl, port (0-1 range) and qosl */
	char sl2tsl[16][2][2];

	/* qosl hint for regular qps, indexed by sl and port (0-1 range) */
	enum psif_tsu_qos qp_qosl_hint[16][2];

	/* tsl for pqps, latency sensitive (RCN) and bulk (non-critical) per port */
	char pqp_rcn_tsl[2];
	char pqp_bulk_tsl[2];

	/* pqp qosl hint per port */
	enum psif_tsu_qos pqp_qosl_rcn_hint[2];
	enum psif_tsu_qos pqp_qosl_bulk_hint[2];

	/* tsl for qp 0 (per port) */
	char qp0_tsl[2];

	/* qp 0 qosl hint (per port) */
	enum psif_tsu_qos qp0_qosl_hint[2];

	/* limited mode for device, no IB traffic possible */
	bool limited_mode;
	/* PSIF is degraded */
	bool degraded;

	/* Owned by sif_r3.c - wa support */
	struct sif_wa_stats wa_stats;
	struct workqueue_struct *misc_wq; /* Used to flush send/receive queue */
};

/* TBD: These should probably come from common pci headers
 */
#ifndef PCI_MSIX_ENTRY_SIZE
#define PCI_MSIX_ENTRY_SIZE 16
#endif
#ifndef PCI_MSIX_ENTRY_VECTOR_CTRL
#define PCI_MSIX_ENTRY_VECTOR_CTRL 12
#endif

/* SIF specific debugging facilities */
extern ulong sif_debug_mask;
extern ulong sif_trace_mask;

/* Defined classes */
#define SIF_INFO	      0x1L
#define SIF_INIT	      0x2L
#define SIF_QPE	              0x4L
#define SIF_INFO_V	      0x8L
#define SIF_WCE		     0x10L /* Log error completions */
#define SIF_PQPT	     0x20L  /* Log WR upon PQP timeouts */
#define SIF_NCQ		     0x40L
#define SIF_XRC		     0x80L
#define SIF_INTR	    0x100L
#define SIF_VERBS	    0x200L
#define SIF_PQP		    0x400L
#define SIF_EPS		    0x800L
#define SIF_PD	           0x1000L
#define SIF_QP	           0x2000L
#define SIF_CQ	           0x4000L
#define SIF_MR	           0x8000L
#define SIF_FMR	          0x10000L
#define SIF_MEM	          0x20000L
#define SIF_AH	          0x40000L
#define SIF_SRQ	          0x80000L
#define SIF_SND	         0x100000L
#define SIF_RCV	         0x200000L
#define SIF_DMA	         0x400000L
#define SIF_RQ	         0x800000L
#define SIF_WCE_V       0x1000000L
#define SIF_SQ	        0x2000000L
#define SIF_POLL        0x4000000L
#define SIF_PT	        0x8000000L
#define SIF_MMU	       0x10000000L
#define SIF_IPOLL      0x20000000L
#define SIF_MMAP       0x40000000L
#define SIF_MC	       0x80000000L
#define SIF_IDX	      0x100000000L
#define SIF_IDX2      0x200000000L
#define SIF_MEM_SG    0x400000000L
#define SIF_DFS	      0x800000000L
#define SIF_FWA      0x1000000000L
#define SIF_VERBS_V  0x2000000000L
#define SIF_DUMP     0x4000000000L
#define SIF_MMU_V    0x8000000000L
#define SIF_MEM_V   0x10000000000L
#define SIF_TSL     0x20000000000L
#define SIF_CSR	    0x40000000000L
#define SIF_PT_V    0x80000000000L
#define SIF_PT_VV  0x100000000000L
#define SIF_QP_V   0x200000000000L
#define SIF_PERF_V 0x400000000000L

#ifdef SIF_TRACE_MASK
#define sif_log_trace(class, format, arg...) \
	do { \
		if (unlikely((sif_trace_mask) & (class))) {	\
			const char *cl = #class;		 \
			trace_printk("%5s " format "\n", &cl[4], ##arg); \
		} \
	} while (0)
#else
#define sif_log_trace(class, format, arg...)
#endif

#define sif_log(sdev, class, format, arg...)	\
	do { \
		sif_log_trace(class, format, ## arg);	\
		if (unlikely((sif_debug_mask) & (class))) {		\
			dev_info(&(sdev)->pdev->dev,	\
				   "[%d] %s: " format "\n", \
				   current->pid, __func__,  \
				   ## arg); \
		} \
	} while (0)

#define sif_logi(ibdev, class, format, arg...)	\
	do { \
		sif_log_trace(class, format, ## arg);	\
		if (unlikely((sif_debug_mask) & (class))) {		\
			dev_info((ibdev)->dma_device,     \
				   "[%d] %s: " format "\n", \
				   current->pid, __func__,  \
				   ## arg); \
		} \
	} while (0)

#define sif_log0(class, format, arg...)	\
	do { \
		if (unlikely((sif_debug_mask) & (class)))	\
			pr_info("sif [%d] " format "\n", \
				current->pid, \
				## arg);		     \
	} while (0)

#define sif_dump(class, txt, addr, len)		\
	do { \
		if (unlikely((sif_debug_mask) & (class))) { \
			print_hex_dump(KERN_INFO, txt,	\
			DUMP_PREFIX_ADDRESS, 8, 1, addr, len, 0); \
		} \
	} while (0)

#define sif_logs(class, stmt_list) \
	do { \
		if (unlikely((sif_debug_mask) & (class))) { \
			stmt_list;\
		} \
	} while (0)

#define sif_log_rlim(sdev, class, format, arg...)	\
	do { \
		sif_log_trace(class, format, ## arg);	\
		if (unlikely((sif_debug_mask) & (class) && printk_ratelimit())) { \
			dev_info(&sdev->pdev->dev,	\
				"[%d] %s: " format "\n",\
				current->pid, __func__,	\
				## arg);		\
		} \
	} while (0)

/* some convenience pointer conversion macros: */
#define to_sdev(ibdev)  container_of((ibdev), struct sif_dev, ib_dev)

#include <asm/byteorder.h>

#define def_copy_conv(name, type1, type2) \
static inline void copy_conv_to_##name(type1 void *dest, const type2 void *src, size_t n) \
{ \
	int words = n / 8; \
	int i; \
	type1 u64 *dp = (type1 u64 *) dest; \
	type2 u64 *sp = (type2 u64 *) src; \
	for (i = 0; i < words; i++) \
		dp[i] = cpu_to_be64(sp[i]); \
	wmb(); \
}

/* make checkpatch happy */
#define N

def_copy_conv(hw, volatile, N)
def_copy_conv(sw, N, volatile)

static inline void copy_conv_to_le(void *dest, const void *src, size_t n)
{
	int words = n / 8;
	int i;
	u64 *dp = (u64 *) dest;
	u64 *sp = (u64 *) src;

	BUG_ON(n & 7);
	for (i = 0; i < words; i++)
		dp[i] = cpu_to_le64(sp[i]);
	wmb();
}

static inline void copy_conv_to_mmio(void __iomem *dest, const void *src, size_t n)
{
	int words = n / 8;
	int i;
	u64 __iomem *dp = (u64 __iomem *) dest;
	u64 *sp = (u64 *) src;

	BUG_ON(n & 7);
	for (i = 0; i < words; i++)
		__raw_writeq(cpu_to_be64(sp[i]), &dp[i]);
}

/* Non-converting copy routines */
#define def_copy_plain(name, type1, type2) \
static inline void copy_to_##name(type1 void *dest, const type2 void *src, size_t n) \
{ \
	int words = n / 8; \
	int i; \
	type1 u64 *dp = (type1 u64 *) dest; \
	type2 u64 *sp = (type2 u64 *) src; \
	for (i = 0; i < words; i++) \
		dp[i] = sp[i]; \
}

def_copy_plain(hw, volatile, N)
def_copy_plain(sw, N, volatile)

static __always_inline void *sif_kmalloc(struct sif_dev *sdev, size_t size, gfp_t flags)
{
#ifdef CONFIG_NUMA
	void *m;

	m = kmalloc_node(size, flags, sdev->pdev->dev.numa_node);
	if (m)
		return m;

	sif_log(sdev, SIF_INFO, "Warning: unable to allocate memory on numa node %d",
		sdev->pdev->dev.numa_node);
#endif
	return kmalloc(size, flags);
}

static inline const char *get_product_str(struct sif_dev *sdev)
{
	if (IS_PSIF(sdev))
		return
			(PSIF_SUBSYSTEM(sdev) == 0x6278) ? "Oracle Dual-port QDR IB Adapter M4" :
			(PSIF_SUBSYSTEM(sdev) == 0x6279) ? "Oracle Dual-port EDR IB Adapter"    :
			(PSIF_SUBSYSTEM(sdev) == 0x6280) ? "Oracle InfiniBand Switch IS2-46"    :
			(PSIF_SUBSYSTEM(sdev) == 0x6281) ? "Oracle InfiniBand Switch IS2-254"   :
			(PSIF_SUBSYSTEM(sdev) == 0x6282) ? "Oracle Fabric Interconnect F2-12"   :
			"Unknown PSIF based card";

	switch (PSIF_DEVICE(sdev)) {
	case	PCI_DEVICE_ID_SN1_PF:
	case	PCI_DEVICE_ID_SN1_VF:
		return "SPARC Integrated FDR IB M1";
	case	PCI_DEVICE_ID_SN2_PF:
	case	PCI_DEVICE_ID_SN2_VF:
		return "SPARC Integrated EDR IB M2";
	case	PCI_DEVICE_ID_SN3_PF:
	case	PCI_DEVICE_ID_SN3_VF:
		return "SPARC Integrated EDR IB M3";
	default:
		return "Unknown Sonoma or PSIF based system";
	}
}

/* Param feature_mask defines */
extern ulong sif_feature_mask;

/* Disable INVALIDATE_*KEY(S) */
#define SIFF_disable_invalidate_key	   0x1

/* Disable RQ flushing */
#define SIFF_disable_rq_flush		   0x2

/* Disable SRQ */
#define SIFF_disable_srq		   0x8

/* Disable INVALIDATE_CQ only: */
#define SIFF_disable_invalidate_cq	  0x10

/* Disable INVALIDATE_RQ only: */
#define SIFF_disable_invalidate_rq	  0x20

/* Disable INVALIDATE_TLB only: */
#define SIFF_disable_invalidate_tlb	  0x40

/* Disable support for use of huge pages
 * This feature is necessary to avoid running into bugDB #21690736
 * on OVM:
 */
#define SIFF_no_huge_pages		  0x80

/* Use stencil pqp for invalidation of FMR keys */
#define SIFF_disable_stencil_invalidate	 0x100

/* Force disable vpci iommu trapping (to operate as on real hardware..) */
#define SIFF_disable_vpci_iommu		 0x400

/* Toss all multipacket qp's instead of resetting and reusing, see #3334 */
#define SIFF_no_multipacket_qp_reuse	 0x800

/* Set PCI max payload size to the supported max payload size to avoid #2105 */
#define SIFF_max_supported_payload	0x1000

/* Let driver do page table walk instead of EPSC for query QP - to avoid #3583 */
#define SIFF_passthrough_query_qp	0x4000

/* Check all event queues on all interrupts */
#define SIFF_check_all_eqs_on_intr	0x8000

/* Default behavior is: Make all vlinks behave in sync with the correspondinding external port.
 * This flag turns off this behavior and the vlink state becomes unrelated to physical link.
 */
#define SIFF_vlink_disconnect	    0x10000

/* Don't allocate vcbs in a round robin fashion */
#define SIFF_alloc_cb_round_robin      0x20000

/* Don't allocate from all other queues (except cb and qp) in a round robin fashion */
#define SIFF_disable_alloc_round_robin 0x40000

/* Default on rev1 is to force rnr_retry_init to 0 - this feature
 * forces it to 7 (infinite retry) instead:
 */
#define SIFF_infinite_rnr	       0x80000

/* Default is to allocate table entries
 * from a two-level allocation where each pd reserves all entries
 * within a page and allocates from within this.
 * This disables the second level to revert to a
 * flat 1-level allocation scheme:
 */
#define SIFF_flat_alloc		      0x100000

/* SQS Atomics (only has effect for PSIF rev > 3) */
#define SIFF_force_sqs_atomic_disable 0x200000

#define SIFF_force_ib_atomic_hca_mode 0x400000

/* Force link retraining upon some errors to ease PCIe triggering */
#define SIFF_pcie_trigger	      0x800000

/* Use 0 as magic value in qp setup to debug #3595 */
#define SIFF_zero_magic		     0x1000000

/* Use optimization of 2 sge_entries with the first being 48 */
#define SIFF_disable_inline_first_sge 0x2000000
/* disable Adaptive int coalescing */
#define SIFF_dis_auto_int_coalesce    0x4000000

/*
 * Bringup SIF a in limited mode, where no IB traffic and only
 * limited mailbox traffic will be possible
 */
#define SIFF_force_limited_mode       0x8000000

/*
 * Force WA for HW bug bug 3646, PSIF does not honor min_rnr_timer,
 * assumes a homogenous PSIF cluster.
 */
#define SIFF_force_wa_3646           0x10000000

#define SIFF_force_rc_2048_mtu       0x20000000

/* Configure PSIF to use the opposite base page size (e.g. 8K on x86 and 4K on sparc) */
#define SIFF_toggle_page_size        0x40000000

#define SIFF_all_features	     0x7fffddfb

#define sif_feature(x) (sif_feature_mask & (SIFF_##x))

extern ulong sif_vendor_flags;
#define sif_vendor_enable(x, uflags) ((sif_vendor_flags | uflags) & x)

extern uint sif_vf_en;
extern uint sif_fwa_mr_en;

extern uint sif_max_inline;

extern uint sif_qp_size;
extern uint sif_mr_size;
extern uint sif_ah_size;
extern uint sif_cq_size;
extern uint sif_rq_size;

extern ulong sif_eps_log_size;
extern ushort sif_eps_log_level;

extern ushort sif_perf_sampling_threshold;
extern uint sif_fmr_cache_flush_threshold;

/* Maximum number of outstanding privileged QP requests supported */
extern uint sif_max_pqp_wr;

/* Max number of stencil PQPs for (bulk) key invalidate to allocate */
extern uint sif_ki_spqp_size;

/* Max number of collect buffers supported */
extern uint sif_cb_max;

/* Number of VFs to request firmware to configure, 0 = use driver defaults */
extern int sif_vf_max;

/* Initialized in init */
extern struct kmem_cache *compl_cache;

#endif
