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
 * sif_pd.c: Implementation of IB protection domains for SIF
 */

#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_ibpd.h"
#include "sif_pd.h"
#include "sif_defs.h"
#include "sif_base.h"
#include "sif_mmu.h"
#include "sif_mr.h"
#include "sif_xrc.h"
#include "sif_query.h"


int sif_init_pd(struct sif_dev *sdev)
{
	/* Avoid using pd == 0 to have HW trap use of blank AHs: */
	return sif_idr_init(&sdev->pd_refs, 1, SIF_MAX_PD_INDEX);
}


void sif_deinit_pd(struct sif_dev *sdev)
{
	sif_idr_deinit(&sdev->pd_refs);
}


inline void cancel_cb(struct psif_cb __iomem *cb)
{
	u64 __iomem *c_adr = (u64 __iomem *)((u8 __iomem *)cb + 0xff8);
	u64 c_val = PSIF_WR_CANCEL_CMD_BE;

	__raw_writeq(cpu_to_be64(c_val), c_adr);
}


struct sif_pd *alloc_pd(struct sif_dev *sdev)
{
	struct sif_pd *pd = kzalloc(sizeof(struct sif_pd), GFP_KERNEL);

	if (!pd)
		return NULL;

	pd->idx = sif_idr_alloc(&sdev->pd_refs, pd, GFP_KERNEL);
	spin_lock_init(&pd->lock);
	INIT_LIST_HEAD(&pd->qp_list);
	INIT_LIST_HEAD(&pd->cq_list);
	INIT_LIST_HEAD(&pd->rq_list);

	sif_log(sdev, SIF_PD, "pd idx %d", pd->idx);
	return pd;
}


int dealloc_pd(struct sif_pd *pd)
{
	struct sif_dev *sdev = to_sdev(pd->ibpd.device);

	sif_log(sdev, SIF_PD, "pd idx %d", pd->idx);

	if (!list_empty(&pd->qp_list)) {
		sif_log(sdev, SIF_INFO, "pd idx %d: failed - still active qp blocks", pd->idx);
		return -EBUSY;
	}
	if (!list_empty(&pd->cq_list)) {
		sif_log(sdev, SIF_INFO, "pd idx %d: failed - still active cq blocks", pd->idx);
		return -EBUSY;
	}
	if (!list_empty(&pd->rq_list)) {
		sif_log(sdev, SIF_INFO, "pd idx %d: failed - still active rq blocks", pd->idx);
		return -EBUSY;
	}

	sif_idr_remove(&sdev->pd_refs, pd->idx);
	kfree(pd);
	return 0;
}


/* IB Verbs level interfaces (sif_ibpd.h) */


struct ib_pd *sif_alloc_pd(struct ib_device *ibdev,
			   struct ib_ucontext *context, struct ib_udata *udata)
{
	struct sif_dev *sdev = to_sdev(ibdev);
	struct sif_pd *pd;
	int ret;

	pd = alloc_pd(sdev);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	/* For bw comp with libsif */
	if (udata) {
		struct sif_ucontext *uc = to_sctx(context);
		struct sif_alloc_pd_resp_ext resp;

		memset(&resp, 0, sizeof(resp));
		resp.cb_idx = uc->cb->idx;
		ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (ret) {
			dealloc_pd(pd);
			return ERR_PTR(-EFAULT);
		}
	}
	return &pd->ibpd;
}

int sif_dealloc_pd(struct ib_pd *ibpd)
{
	return ibpd->shpd ? 0 : dealloc_pd(to_spd(ibpd));
}

struct ib_shpd *sif_alloc_shpd(struct ib_device *ibdev,
			struct ib_pd *ibpd,
			struct ib_udata *udata)
{
	struct sif_dev *sdev = to_sdev(ibdev);
	struct sif_pd *pd = to_spd(ibpd);
	struct sif_shpd *shpd;

	shpd = kzalloc(sizeof(struct sif_shpd), GFP_KERNEL);
	if (!shpd)
		return ERR_PTR(-ENOMEM);

	shpd->ibshpd.device = &sdev->ib_dev;
	shpd->pd = pd;

	return &shpd->ibshpd;
}

struct ib_pd *sif_share_pd(struct ib_device *ibdev,
			struct ib_ucontext *context,
			struct ib_udata *udata,
			struct ib_shpd *ibshpd)
{
	struct sif_shpd *shpd = to_sshpd(ibshpd);
	struct sif_pd *pd = shpd->pd;
	int ret;

	if (udata) {
		struct sif_ucontext *uc = to_sctx(context);
		struct sif_share_pd_resp_ext resp;

		memset(&resp, 0, sizeof(resp));
		resp.cb_idx = uc->cb->idx;
		ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (ret)
			return ERR_PTR(-EFAULT);
	}

	return &pd->ibpd;
}

int sif_remove_shpd(struct ib_device *ibdev,
		struct ib_shpd *ibshpd,
		int atinit)
{
	struct sif_shpd *shpd = to_sshpd(ibshpd);

	if (!atinit && shpd->pd)
		dealloc_pd(shpd->pd);

	kfree(ibshpd);

	return 0;
}

/* Collect buffer management */


/* Obtain information about lat_cb and bw_cb resources
 * We cannot use the ba structs yet as they are not initialized at this point:
 */
static void sif_cb_init(struct sif_dev *sdev)
{
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];

	/* EPSC supports the new requests starting from v.0.36 */
	if (eps_version_ge(es, 0, 37)) {
		int ret = 0;

		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_QUERY;
		req.u.query.data.op = EPSC_QUERY_CAP_VCB_LO;
		req.u.query.info.op = EPSC_QUERY_CAP_VCB_HI;
		ret = sif_epsc_wr(sdev, &req, &rsp);
		if (ret)
			sif_log(sdev, SIF_INFO, "Request for VCB info failed with %d", ret);
		else {
			sdev->bw_cb_cnt = rsp.data;
			sdev->lat_cb_cnt = rsp.info;
			sif_log(sdev, SIF_INIT, "Got %ld bw_cbs and %ld lat_cbs",
				sdev->bw_cb_cnt, sdev->lat_cb_cnt);
		}
	}
}


/* Called from sif_base.c to initialize each of the cb tables */
void sif_cb_table_init(struct sif_dev *sdev, enum sif_tab_type type)
{
	struct sif_table *tp;

	BUG_ON(!is_cb_table(type));
	tp = &sdev->ba[type];

	/* Update table values with EPSC data: */
	if (type == bw_cb) {
		sif_cb_init(sdev);
		if (sdev->bw_cb_cnt) {
			tp->entry_cnt = sdev->bw_cb_cnt;
			tp->table_sz = tp->ext_sz * tp->entry_cnt;
		}
		tp->sif_off = sdev->cb_base;
	} else {
		/* lat_cb */
		if (sdev->lat_cb_cnt) {
			tp->entry_cnt = sdev->lat_cb_cnt;
			tp->table_sz = tp->ext_sz * tp->entry_cnt;
			tp->sif_off = sdev->cb_base + sdev->ba[bw_cb].table_sz;
		} else
			tp->entry_cnt = 0;
	}

	tp->mem = sif_mem_create_ref(sdev, SIFMT_NOMEM, tp->sif_base,
				tp->table_sz, GFP_KERNEL);
}


struct sif_cb *alloc_cb(struct sif_dev *sdev, bool lat_cb)
{
	int idx;
	struct sif_cb *cb = kzalloc(sizeof(struct sif_cb), GFP_KERNEL);

	if (!cb)
		return NULL;

	if (unlikely(lat_cb)) {
		idx = sif_alloc_lat_cb_idx(sdev);
		if (idx < 0)
			goto err_index;
		cb->cb = get_lat_cb(sdev, idx);
	} else {
		idx = sif_alloc_bw_cb_idx(sdev);
		if (idx < 0)
			goto err_index;
		cb->cb = get_bw_cb(sdev, idx);
	}

	/* Reset Collect buffer */
	cb->idx = idx;
	cb->is_lat_cb = lat_cb;

	cancel_cb(cb->cb);

	spin_lock_init(&cb->lock);
	return cb;
err_index:
	kfree(cb);
	return NULL;
}


void release_cb(struct sif_dev *sdev, struct sif_cb *cb)
{
	cancel_cb(cb->cb);
	if (unlikely(cb->is_lat_cb))
		sif_free_lat_cb_idx(sdev, cb->idx);
	else
		sif_free_bw_cb_idx(sdev, cb->idx);
	kfree(cb);
}


/* Find the driver struct for a collect buffer index, if associated with @uc
 */
struct sif_cb *sif_cb_from_uc(struct sif_ucontext *uc, u32 index)
{
	if (uc->cb->idx == index)
		return uc->cb;
	return NULL;
}


/*
 * Write a prepared work request (in wqe) to the associated collect buffer:
 * Return 0 on success otherwise -EBUSY if lock is held
 */
int sif_cb_write(struct sif_qp *qp, struct psif_wr *wqe, int cp_len)
{
	unsigned long flags;
	struct sif_cb *cb = get_cb(qp, wqe);

	if (!spin_trylock_irqsave(&cb->lock, flags))
		return -EBUSY;

	wmb(); /* Previous memory writes must be ordered wrt the I/O writes */
	copy_conv_to_mmio(cb->cb, wqe, cp_len);
	wc_wmb(); /* I/O writes must be completed before we let go of the lock! */
	spin_unlock_irqrestore(&cb->lock, flags);

	return 0;
}


#define SQS_START_DOORBELL 0xfc0
#define SQS_STOP_DOORBELL  0xf80

/*
 * Notify about a work request to the cb doorbell - triggering SQ mode:
 */
void sif_doorbell_write(struct sif_qp *qp, struct psif_wr *wqe, bool start)
{
	unsigned long flags;
	u16 doorbell_offset = start ? SQS_START_DOORBELL : SQS_STOP_DOORBELL;
	struct sif_cb *cb = get_cb(qp, wqe);
	struct sif_dev *sdev = to_sdev(qp->ibqp.pd->device);

	sif_log(sdev, SIF_QP, "%s sqs for qp %d sq_seq %d", (start ? "start" : "stop"),
		qp->qp_idx, wqe->sq_seq);
	spin_lock_irqsave(&cb->lock, flags);
	wmb();
	copy_conv_to_mmio((u8 __iomem *)cb->cb + doorbell_offset, wqe, 8);

	/* Flush write combining */
	wc_wmb();
	spin_unlock_irqrestore(&cb->lock, flags);
}


/*
 * Force the SQS to process an already posted WR:
 */

void sif_doorbell_from_sqe(struct sif_qp *qp, u16 seq, bool start)
{
	u16 doorbell_offset = start ? SQS_START_DOORBELL : SQS_STOP_DOORBELL;
	struct sif_dev *sdev = to_sdev(qp->ibqp.pd->device);
	struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
	u64 *wqe = (u64 *)get_sq_entry(sq, seq);
	struct sif_cb *cb = get_cb(qp, (struct psif_wr *)wqe);

	/* Pick the 1st 8 bytes directly from the sq entry: */
	wmb();
	__raw_writeq(*wqe, ((u8 __iomem *)cb->cb + doorbell_offset));

	/* Flush write combining */
	wc_wmb();
	sif_log(sdev, SIF_QP, "%s sqs for qp %d sq_seq %d", (start ? "start" : "stop"),
		qp->qp_idx, seq);
}


static struct list_head *type_to_list(struct sif_pd *pd, enum sif_tab_type type)
{
	switch (type) {
	case cq_hw:
		return &pd->cq_list;
	case rq_hw:
		return &pd->rq_list;
	case qp:
		return &pd->qp_list;
	default:
		BUG();
	}
	return NULL;
}


/* Allocate a free index from a block:
 * The index is a global index
 */
static int alloc_from_block(struct sif_table_block *b, enum sif_tab_type type)
{
	int next = 0;
	int index;
	int loc_idx;

	struct sif_table *table = b->table;

	if (table->alloc_rr)
		next = (b->last_used + 1) & (table->entry_per_block - 1);
	loc_idx = find_next_zero_bit(b->bitmap, table->entry_per_block, next);
	if (table->alloc_rr && loc_idx >= table->entry_per_block)
		loc_idx = find_next_zero_bit(b->bitmap, table->entry_per_block, 0);
	if (loc_idx < table->entry_per_block) {
		set_bit(loc_idx, b->bitmap);
		if (table->alloc_rr)
			b->last_used = loc_idx;
		index = loc_idx + b->offset;
		sif_log(table->sdev, SIF_IDX2,
			"%s[%d:%d] -> %d ", sif_table_name(type),
			b->offset / table->entry_per_block, loc_idx, index);
		return index;
	}
	return -1;
}


/* Free a used index back to a block:
 * The index is a global index
 */
static void free_to_block(struct sif_table_block *b, enum sif_tab_type type, int index)
{
	struct sif_table *table = b->table;
	size_t ext_sz = table->ext_sz;
	char *desc = sif_mem_kaddr(table->mem, index * ext_sz);

	/* Get from global index to block index */
	index -= b->offset;

	/* Clean descriptor entry for reuse:
	 * note that we clean the whole extent here which
	 * includes all of sif_##type for inlined types:
	 */
	if (type == rq_hw) /* only zero out driver data structure */
		memset(desc + sizeof(struct psif_rq_hw), 0, ext_sz - sizeof(struct psif_rq_hw));
	else if (!is_cb_table(type) && type != qp && type != cq_hw)
		memset(desc, 0, ext_sz);

	sif_log(table->sdev, SIF_IDX2,
		"%s[%d:%d] ", sif_table_name(type),
		b->offset / table->entry_per_block, index);
	clear_bit(index, b->bitmap);
}


/* Support for per protection domain table index allocations (2nd level allocation):
 * Invariants:
 * - sif_table_block entries are 0-initialized, and initialized to real values on demand.
 * - We keep a list of blocks and try to allocate starting from the first in the list
 *   assuming that the last added block has the most free entries.
 */

int sif_pd_alloc_index(struct sif_pd *pd, enum sif_tab_type type)
{
	struct sif_dev *sdev = to_sdev(pd->ibpd.device);
	struct sif_table *tp = &sdev->ba[type];
	struct list_head *list = type_to_list(pd, type);
	struct sif_table_block *b;
	int idx = -1;

	if (tp->entry_per_block == 1) /* Handle 1-level alloc case */
		return sif_alloc_index(sdev, type);

	spin_lock(&pd->lock);
	list_for_each_entry(b, list, pd_list) {
		idx = alloc_from_block(b, type);
		if (idx >= 0)
			break;
	}
	if (idx < 0) {
		/* Allocate a new block */
		int blk_idx = sif_alloc_index(sdev, type);

		if (blk_idx >= 0) {
			b = sif_get_block(tp, blk_idx);
			sif_log(sdev, SIF_IDX2, "%s blk_idx %d: %p [%ld/%d]",
				sif_table_name(type), blk_idx, b,
				sizeof(struct sif_table_block), tp->block_ext);
			b->table = tp;
			b->pd = pd;
			b->offset = blk_idx * tp->entry_per_block;
			/* Don't modify last_used as we want it to survive (de)allocations */
			list_add(&b->pd_list, list);
			idx = alloc_from_block(b, type);
		}
	}
	spin_unlock(&pd->lock);
	return idx;
}


void sif_pd_free_index(struct sif_pd *pd, enum sif_tab_type type, int index)
{
	struct sif_dev *sdev = to_sdev(pd->ibpd.device);
	struct sif_table *tp = &sdev->ba[type];
	struct sif_table_block *b;
	int bits_used;
	int blk_idx = index / tp->entry_per_block;

	if (tp->entry_per_block == 1) /* Handle 1-level alloc case */
		return sif_free_index(sdev, type, index);

	b = sif_get_block(tp, blk_idx);
	if (!b->table) {
		/* BUG */
		sif_log(sdev, SIF_INFO, "index %d: block table ptr NULL - blk_idx %d table %s",
			index, blk_idx, sif_table_name(type));
		return;
	}
	spin_lock(&pd->lock);
	free_to_block(b, type, index);
	bits_used = bitmap_weight(b->bitmap, tp->entry_per_block);
	if (!bits_used) {
		list_del(&b->pd_list);
		sif_free_index(sdev, type, blk_idx);
	}
	spin_unlock(&pd->lock);
}


bool sif_pd_index_used(struct sif_table *tp, int idx)
{
	struct sif_table_block *b;
	int blk_idx = idx / tp->entry_per_block;

	if (!test_bit(blk_idx, tp->bitmap))
		return false;
	b = sif_get_block(tp, blk_idx);
	return test_bit(idx % tp->entry_per_block, b->bitmap);
}


bool sif_is_user_pd(struct sif_pd *pd)
{
	if (pd->ibpd.uobject)
		return true;
	/* TBD: We don't know if an XRC domain originates from user space,
	 * as it does not get any uobject
	 */
	if (pd->xrcd) /* TBD: && pd->xrcd->ib_xrcd.uobject) */
		return true;
	return false;
}
