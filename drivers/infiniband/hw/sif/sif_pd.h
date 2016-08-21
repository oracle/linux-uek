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
 * sif_pd.h: Internal interface to protection domains
 *   and collect buffer management for SIF
 */

#ifndef __SIF_PD_H
#define __SIF_PD_H

struct sif_dev;
struct sif_pd;
struct sif_cb;
struct sif_qp;
struct sif_ucontext;

/**** Protection domains ****/

/* SIF supports a 24 bit PD index: */
#define SIF_MAX_PD_INDEX ((1 << 24) - 1)

struct sif_pd {
	struct ib_pd ibpd;
	int idx;     /* index of this pd */
	struct sif_xrcd *xrcd; /* If set, this pd is owned by an xrcd */
	spinlock_t lock;    /* Protects lists and their bitmaps while owned by us */
	/* List of blocks of descriptor entries owned by this pd */
	struct list_head qp_list;
	struct list_head cq_list;
	struct list_head rq_list;
};

struct sif_shpd {
	struct ib_shpd ibshpd;
	struct sif_pd *pd;
};

/* Initialize driver information about the number of CBs of each type available */
void sif_cb_init(struct sif_dev *sdev);

/* Initialize/deinitialize the pd subsystem */
int sif_init_pd(struct sif_dev *sdev);
void sif_deinit_pd(struct sif_dev *sdev);

struct sif_pd *alloc_pd(struct sif_dev *sdev);
int dealloc_pd(struct sif_pd *pd);


/* Per protection domain table index allocations (2nd level allocation) */
int sif_pd_alloc_index(struct sif_pd *pd, enum sif_tab_type type);
void sif_pd_free_index(struct sif_pd *pd, enum sif_tab_type type, int index);

/* 2-level and 1-level safe index usage check:
 * idx is the entry index (not block index)
 * and is assumed to be within bounds:
 *
 */
bool sif_pd_index_used(struct sif_table *tp, int idx);

bool sif_is_user_pd(struct sif_pd *pd);


/****  Collect buffers  ****/

static inline bool is_cb_table(enum sif_tab_type type)
{
	return type == bw_cb || type == lat_cb;
}


/* Called from sif_base.c to initialize the cb tables */
void sif_cb_table_init(struct sif_dev *sdev, enum sif_tab_type type);


/* per collect buffer struct */
struct sif_cb {
	int idx;	 /* index of this cb */
	bool is_lat_cb;	 /* High bandwidth or low latency cb */
	spinlock_t lock; /* Serializes access to this cb */
	u64 reqs;	 /* Number of requests on this cb */
	struct psif_cb __iomem *cb; /* Pointer to the actual collect buffer space */
};

/* Allocation and deallocation of collect buffers
 * If @lat_cb is set, allocate low latency CB instead of high bandwidth one:
 */
struct sif_cb *alloc_cb(struct sif_dev *sdev, bool lat_cb);
void release_cb(struct sif_dev *sdev, struct sif_cb *cb);

/* Find the driver struct for a collect buffer index, if associated with @uc
 */
struct sif_cb *sif_cb_from_uc(struct sif_ucontext *uc, u32 index);


/*
 * Write a prepared work request (in wqe) to the associated collect buffer:
 * Return 0 on success otherwise -EBUSY if lock is held
 */
int sif_cb_write(struct sif_qp *qp, struct psif_wr *wqe, int cp_len);


/*
 * Notify about a work request to the cb doorbell - triggering SQ mode:
 */
void sif_doorbell_write(struct sif_qp *qp, struct psif_wr *wqe, bool start);


/*
 * Force the SQS to process an already posted WR:
 */
void sif_doorbell_from_sqe(struct sif_qp *qp, u16 seq, bool start);

#endif
