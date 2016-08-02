/*
 * Copyright (c) 2011, 2016, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_rq.h: Interface to sif receive queues
 */

#ifndef _SIF_RQ_H
#define _SIF_RQ_H

struct sif_rq {
	volatile struct psif_rq_hw d;	/* Hardware descriptor */
	struct ib_srq ibsrq ____cacheline_internodealigned_in_smp; /* Only used if this is an SRQ */
	spinlock_t lock ____cacheline_internodealigned_in_smp;
	struct sif_mmu_ctx mmu_ctx;
	struct sif_pd *pd;  /* Ref to owning protection domain */
	int index;
	int cq_idx;  /* Default compl.queue index to use, if any */
	bool user_mode;  /* Set if this is an RQ to be mapped to user space */
	bool is_srq; /* Set if this is a shared receive queue */
	int xrc_domain; /* If != 0: This is an XRC SRQ member of this domain idx */
	atomic_t refcnt; /* Ref.count for usage as a shared receive queue */
	atomic_t flush_in_progress; /* flush in progress synchronization */
	struct completion can_reset; /* use flush_in_progress to synchronization reset and flush */
	u16 entries;      /* Allocated entries */
	u16 entries_user; /* Entries reported to user (entries -1 if max) */
	u32 sg_entries; /* Max receive scatter/gather configured for this rq */
	u32 mask;  /* entries - 1 for modulo using & */
	u32 extent;
	u16 srq_limit;
	struct sif_mem *mem; /* Allocated queue memory */
};

struct flush_rq_work {
	struct work_struct ws;
	struct sif_dev *sdev;
	struct sif_rq *rq;
	struct sif_qp *qp;
	int entries;
};

static inline struct sif_rq *to_srq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct sif_rq, ibsrq);
}

int poll_wait_for_rq_writeback(struct sif_dev *sdev, struct sif_rq *rq);

/* Allocate a receive queue - if @srq_init_attr is non-nil
 * this is a shared receive queue (SRQ)
 * A return value >= 0 is the index of the receive queue descriptor allocated
 * otherwise it is -errno
 */
int alloc_rq(struct sif_dev *sdev, struct sif_pd *pd,
	u32 entries, u32 sge_entries,
	struct ib_srq_init_attr *srq_init_attr,
	bool user_mode);

/* Invalidate the RQ cache and flush a desired amount of
 * the remaining entries in the given receive queue.
 * @target_qp indicates the value of the local_qp field in the generated
 * completion but is not interpreted by SIF in any way.
 */
int sif_flush_rq_wq(struct sif_dev *sdev, struct sif_rq *rq,
		struct sif_qp *target_qp, int max_flushed_in_err);

int free_rq(struct sif_dev *sdev, int rq_idx);

/* Low level callbacks to release memory for these queues
 * Called from sif_hiw::handle_invalidate_wc
 */
void sif_release_rq(struct sif_dev *sdev, int index);

void sif_dfs_print_rq_hw(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

#endif
