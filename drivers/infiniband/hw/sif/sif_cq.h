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
 * sif_cq.h: Internal interface to psif completion queue logic
 */

#ifndef __SIF_CQ_H
#define __SIF_CQ_H
#include "psif_hw_data.h"
#include "sif_user.h"
#include "sif_mmu.h"

struct sif_dev;
struct sif_cqe;
struct sif_compl;
struct sif_pd;
struct sif_qp;
struct sif_sq;

struct sif_cq {
	volatile struct psif_cq_hw d; /* Hardware descriptor */
	struct ib_cq ibcq ____cacheline_internodealigned_in_smp;
	struct sif_pd *pd; /* Unlike the rest of ofed we tie a CQ to a PD */
	struct sif_mem *mem; /* Allocated queue memory */
	int index;
	u32 entries;
	u32 mask;  /* entries - 1 for modulo using & */
	u32 extent;
	atomic_t refcnt;  /* refc.count on this object */
	struct completion cleanup_ok; /* Used to synchronize cleanup with event handling */
	u32 high_watermark; /* if < used entries (as seen by hw), update hw: head */
	struct psif_cq_hw cq_hw; /* Local copy of cq_hw, as initialized, in host endianness */
	struct sif_mmu_ctx mmu_ctx;
	/* lock protects the below data structure and access/freeing of sq elems */
	spinlock_t lock ____cacheline_internodealigned_in_smp;
	bool user_mode;  /* Set if this is a CQ to be mapped to user space */
	bool pd_is_set;  /* Whether or not this cq has a pd set in it's descriptor */
	bool rcn_sent;   /* Set if ib_req_notify_cq() has been called on this cq */
	u8 eq_idx;       /* Index of the event queue that gets completion events for this cq */
	atomic_t error_cnt;   /* No. of error completions observed on this cq */
	atomic_t timeout_cnt; /* No. of completion timeouts observed on this cq */
	atomic_t event_cnt;   /* No. of completion events observed for this cq (will wrap..) */
	struct sif_rq *xsrq; /* The XRC SRQ using this completion queue (see #3521) */
	struct sif_pqp *pqp; /* The PQP using this completion queue (for dfs reporting..) */
};

static inline struct sif_cq *to_scq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct sif_cq, ibcq);
}

/* Poll wait for a cq descriptor to be written back in invalid state */
int poll_wait_for_cq_writeback(struct sif_dev *sdev, struct sif_cq *cq);


struct sif_cq *create_cq(struct sif_pd *pd, int cqe,
			int comp_vector,
			enum sif_proxy_type proxy,
			bool user_mode);


/* internal poll/peek of completion queue:
 *  - Return value: 0 - @num_entries representing
 * the number of ready completions on the queue.
 *
 * If @wc is set, @poll_cq processes entries and updates the local cq state.
 * If @wc is NULL @poll_cq behaves as a peek, not modifying
 * the local completion queue state.
 *
 * Note that @poll_cq does not modify any state shared with
 * hardware except the head pointer
 */
int poll_cq(struct sif_dev *sdev, struct sif_cq *cq, int num_entries,
	struct sif_cqe *cqe);

int destroy_cq(struct sif_cq *cq);


/* Clean up resource usage associated with this cq
 * If return value is -EIDRM it means that this cq was used with a privileged
 * QP. In that case no more polls can be made at this point since the completion queue
 * polled just self destructed..
 */
int sif_release_cq(struct sif_dev *sdev, int index);


/* Printer for debugfs cq_hw file */
void sif_dfs_print_cq_hw(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos);

extern int sif_fixup_cqes(struct sif_cq *cq, struct sif_sq *sq, struct sif_qp *qp);

#endif
