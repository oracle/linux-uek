/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_sq.h: Implementation of the send queue side of an IB queue pair
 */

#ifndef __SIF_SQ_H
#define __SIF_SQ_H

struct sif_sq_hdl {
	u64 wr_id;  /* Stored work id */
	u32 sq_seq; /* Extra sanity checks */
	bool used;
};


struct sif_sq {
	volatile struct psif_sq_hw d; /* Hardware descriptor */
	/* Serializes access to sq_sw->last_seq (alloc of new sqes): */
	spinlock_t lock ____cacheline_internodealigned_in_smp;
	struct sif_mmu_ctx mmu_ctx;
	int index;   /* Send queue index (same as the qp index) */
	int cq_idx;  /* Default send compl.queue index to use */
	u32 sg_entries; /* Max send scatter/gather configured for this sq */
	u16 entries;
	u16 mask;  /* entries - 1 for modulo using & */
	u16 max_outstanding;  /* Longest observed send queue len */
	u8 complete_all;          /* Gets or'ed into completion bit in WRs */
	u32 extent;
	u32 sgl_offset; /* Offset from start of the sqe where the sgl starts */
	bool user_mode;  /* Set if this is an SQ to be mapped to user space */
	struct sif_mem *mem; /* Allocated queue memory */
	void *wr_hdl; /* map from sq entry index to wr_id + optional bookkeeping */
	int wr_hdl_sz; /* Sz of each elem. in wr_hdl - PQP and std send path uses different sizes */
	struct sif_mr *sg_mr; /* DMA val.entry for the sge list when in the send queue */
	struct psif_rq_scatter tmp_sge[16]; /* Temp.storage for buildup of LE sge list */
};


/* Lookup function for the handle for a particular request: */
static inline struct sif_sq_hdl *get_sq_hdl(struct sif_sq *sq, u32 seq)
{
	return (struct sif_sq_hdl *)(sq->wr_hdl + sq->wr_hdl_sz * (seq & sq->mask));
}

int sif_sq_cmpl_setup(struct sif_table *tp);

int sif_alloc_sq(struct sif_dev *sdev, struct sif_pd *pd,
		struct sif_qp *qp, struct ib_qp_cap *cap,
		bool user_mode, int sq_hdl_sz);

void sif_free_sq(struct sif_dev *sdev, struct sif_qp *qp);

int sif_flush_sqs(struct sif_dev *sdev, struct sif_sq *sq);

int sif_sq_cmpl_map_sq(struct sif_dev *sdev, struct sif_sq *sq);
int sif_sq_cmpl_unmap_sq(struct sif_dev *sdev, struct sif_sq *sq);

/* Line printers for debugfs files */
void sif_dfs_print_sq_hw(struct seq_file *s, struct sif_dev *sdev, loff_t pos);
void sif_dfs_print_sq_cmpl(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

#endif
