/*
 * Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_pqp.h: Privileged QP handling
 */

#ifndef __SIF_PQP_H
#define __SIF_PQP_H

struct sif_qp;
struct sif_cq;
struct sif_rq;
struct sif_sq;
struct completion;
enum post_mode;

/* Data structure used by PQP requesters to get the completion information,
 * and optionally block waiting for it to arrive:
 */
struct sif_cqe {
	struct psif_cq_entry cqe; /* host order copy of hw cqe */
	struct completion cmpl;   /* a completion to wait on for response */
	struct sif_pqp *pqp;	  /* Priv.qp to wait on */
	bool need_complete;	  /* cmpl is initialized and a waiter is present */
	bool written;		  /* Set to true when a completion has been copied here */
	u16 sq_seq;		  /* set by post_send to allow us to reset ourselves */
};

/*
 * Declare and initialize data structure to receive a poll completion
 * cqe.status initialized tosomething != SUCCESS
 */
#define DECLARE_SIF_CQE_POLL(d_, c_)\
	struct sif_cqe c_ = { \
		.cqe.status = PSIF_WC_STATUS_FIELD_MAX,\
		.pqp = get_pqp(d_),\
		.need_complete = false,\
		.written = false,\
	}

#define DECLARE_SIF_CQE_WITH_SAME_EQ(d_, c_, e_)	\
	struct sif_cqe c_ = { \
		.cqe.status = PSIF_WC_STATUS_FIELD_MAX,\
		.pqp = get_pqp_same_eq(d_, e_),	\
		.need_complete = false,\
		.written = false,\
	}


#define DECLARE_SIF_CQE_WAIT(d_, c_)\
	struct sif_cqe c_ = { \
		.cqe.status = PSIF_WC_STATUS_FIELD_MAX,\
		.pqp = get_pqp(d_),\
		.need_complete = true,\
		.written = false,\
	};\
	init_completion(&c_.cmpl)

#define DECLARE_SIF_CQE_POLL_WITH_RR_PQP(d_, c_)\
	struct sif_cqe c_ = { \
		.cqe.status = PSIF_WC_STATUS_FIELD_MAX,\
		.pqp = get_next_pqp(d_),\
		.need_complete = false,\
		.written = false,\
	}


struct sif_pqp {
	struct sif_qp *qp;  /* The qp used */
	struct sif_cq *cq;  /* Associated completion queue for this priv.QP */
	unsigned long timeout; /* rescheduled when new completions observed */
	struct completion nonfull; /* allow a poster to wait for a cred */
	atomic_t waiters; /* number of waiters on nonfull */
	u16 last_full_seq;  /* For logging purposes, record when last observed full */
	u16 last_nc_full;   /* Track when to return EAGAIN to flush non-compl.entries */
	u16 lowpri_lim;  /* Max number of outstanding low priority reqs */
};

struct sif_pqp *sif_create_pqp(struct sif_dev *sdev, int comp_vector);
int sif_destroy_pqp(struct sif_dev *sdev, struct sif_pqp *pqp);

/* Get the right PQP for the current CPU */
struct sif_pqp *get_pqp(struct sif_dev *sdev);

/* Get the right PQP with the same EQ */
struct sif_pqp *get_pqp_same_eq(struct sif_dev *sdev, int comp_vector);

/* Get the next PQP in round robin fashion */
struct sif_pqp *get_next_pqp(struct sif_dev *sdev);

/* Get the right CB for the current CPU for the given QP and wr */
struct sif_cb *get_cb(struct sif_qp *qp, struct psif_wr *wr);

static inline struct sif_cq *pqp_cq(struct sif_dev *sdev)
{
	return (get_pqp(sdev))->cq;
}

static inline struct sif_qp *pqp_qp(struct sif_dev *sdev)
{
	return (get_pqp(sdev))->qp;
}

/* Fill in common parts and post a work request to the management QP for the current CPU
 * If @cqe is non-null, a completion will be requested and eventually reflected to @cqe
 * in host order.
 */
int sif_pqp_post_send(struct sif_dev *sdev, struct psif_wr *wr, struct sif_cqe *cqe);

/* Same as post send but allow post_mode - sif_pqp_post_send uses PM_CB */
int sif_pqp_write_send(struct sif_pqp *pqp, struct psif_wr *wr, struct sif_cqe *cqe,
		enum post_mode mode);


/* Poll and process incoming (internal) completions
 * while waiting for this particular completion
 */
int poll_cq_waitfor(struct sif_cqe *lcqe);

int sif_pqp_poll_wr(struct sif_dev *sdev, struct psif_wr *wr, struct sif_cqe *cqe);



/* Generate a SUCCESS completion on the PQP itself
 * We use this to be able to wait for a set of generated completions to other
 * CQs to have been completed:
 */
int gen_pqp_cqe(struct sif_cqe *cqe);

/* Post a request to generate a flushed-in-error completion for an outstanding rq entry
 * on the given qp. This request generates no completion on the PQP itself:
 */
int sif_gen_rq_flush_cqe(struct sif_dev *sdev, struct sif_rq *rq,
			u32 rq_seq, struct sif_qp *target_qp);

/* Post a request to generate a flushed-in-error completion for an outstanding sq entry
 * on the given qp. This request generates no completion on the PQP itself:
 */
int sif_gen_sq_flush_cqe(struct sif_dev *sdev, struct sif_sq *sq,
			 u32 sq_seq, u32 target_qp, bool notify_ev);

/* Stencil PQP support - pre-populated PQPs for special performance sensitive use cases */

#define SPQP_DOORBELL_INTERVAL 8192

struct sif_st_pqp {
	struct sif_pqp pqp;	/* The PQP to use - must be first */
	struct sif_sq *sq;	/* Short path to sq */
	struct sif_sq_sw *sq_sw;/* Short path to sq_sw */
	int index;		/* The index of this st_pqp within it's pool */
	u16 doorbell_interval;  /* Interval between each doorbell write */
	u16 doorbell_seq;	/* Seq.no to use in next doorbell */
	u16 next_doorbell_seq;  /* Next seqno to ring doorbell */
	u16 req_compl;		/* Number of completions requested */
	u16 next_poll_seq;	/* Next seqno to set completion and wait/poll for one */
	u64 checksum;		/* Host endian partial checksum of stencil WR entries */
};


/* Stencil PQP management */
struct sif_spqp_pool {
	struct mutex lock;	  /* Protects access to this pool */
	struct sif_st_pqp **spqp; /* Key invalidate stencil PQPs */
	u32 pool_sz;		  /* Number of stencil PQPs set up */
	ulong *bitmap;		  /* Bitmap for allocation from spqp */
};


struct sif_st_pqp *sif_create_inv_key_st_pqp(struct sif_dev *sdev);

/* get exclusive access to a stencil pqp */
struct sif_st_pqp *sif_alloc_ki_spqp(struct sif_dev *sdev);
void sif_release_ki_spqp(struct sif_st_pqp *spqp);

/* Update a new invalidate key request into a preconfigured stencil pqp
 * Assumes exclusive access to the PQP SQ.
 */
int sif_inv_key_update_st(struct sif_st_pqp *spqp, int index, enum wr_mode mode);


int sif_destroy_st_pqp(struct sif_dev *sdev, struct sif_st_pqp *spqp);

#endif
