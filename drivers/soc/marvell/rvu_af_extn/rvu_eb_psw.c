// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "rvu.h"
#include "mbox.h"
#include "rvu_struct.h"
#include "rvu_reg.h"
#include "rvu_eblock.h"
#include "rvu_eblock_reg.h"
#include "rvu_trace.h"
#include "rvu_psw_mbox.h"

#define PSW_EPFS_PER_PORT 8
#define PCI_DEVID_PSW_PF  0xEA
#define PSW_EPFFUNC(port, epf, vf_id)	\
		((((port) & 0x1) << 14) | (((epf) & 0x7) << 9) | \
		((vf_id) & 0xFF))
#define PSW_ECC_INT_BITS 37
#define PSW_MAX_RID_CNT_PER_FUNC 260
#define PSW_MAX_QUEUES 4096

#define CONST_MAX_EPFS  GENMASK_ULL(63, 48)
#define CONST1_MAX_GID  GENMASK_ULL(63, 48)

#define PSW_PEM_ID(epf) (((epf) < PSW_EPFS_PER_PORT) ? 0 : 1)
#define PSW_PEM_EPF(epf) (((epf) < PSW_EPFS_PER_PORT) ? (epf) : (epf) - PSW_EPFS_PER_PORT)

#define gid_entry0_w(link, mid, qid, mvalid, iqvalid, oqvalid)      \
({                                                                  \
	u64 reg;                                                    \
								    \
	reg = FIELD_PREP(GID_ENT_LINK, link);                       \
	reg |= FIELD_PREP(GID_ENT_MID, mid);                        \
	reg |= FIELD_PREP(GID_ENT_QID, qid);                        \
	reg |= FIELD_PREP(GID_ENT_MVALID, mvalid);                  \
	reg |= FIELD_PREP(GID_ENT_IQVALID, iqvalid);                \
	reg |= FIELD_PREP(GID_ENT_OQVALID, oqvalid);                \
	rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY0_W, reg);    \
})

#define gid_entry1_w(wnum, rid, epffunc)                            \
({                                                                  \
	u64 reg;                                                    \
								    \
	reg = FIELD_PREP(GID_ENT_WNUM, wnum);                       \
	reg |= FIELD_PREP(GID_ENT_RID, rid);                        \
	reg |= FIELD_PREP(GID_ENT_EPFFUNC, epffunc);                \
	rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY1_W, reg);    \
})

#define GID_LU_EPFFUNC	GENMASK_ULL(15, 0)
#define GID_LU_RID	GENMASK_ULL(24, 16)

#define GID_BKT_RSLT_BVALID GENMASK_ULL(0, 0)
#define GID_BKT_RSLT_BSTART GENMASK_ULL(29, 16)
#define GID_BKT_RSLT_BHASH  GENMASK_ULL(45, 32)

#define GID_ENT_OQVALID GENMASK_ULL(0, 0)
#define GID_ENT_IQVALID GENMASK_ULL(1, 1)
#define GID_ENT_MVALID  GENMASK_ULL(2, 2)
#define GID_ENT_QID     GENMASK_ULL(29, 16)
#define GID_ENT_MID     GENMASK_ULL(45, 32)
#define GID_ENT_LINK    GENMASK_ULL(61, 48)

#define GID_ENT_EPFFUNC	GENMASK_ULL(15, 0)
#define GID_ENT_RID	GENMASK_ULL(24, 16)
#define GID_ENT_WNUM	GENMASK_ULL(45, 32)

#define GID_BKT_BVALID  GENMASK_ULL(0, 0)
#define GID_BKT_BSTART  GENMASK_ULL(29, 16)

#define GID_ENT_RSLT1_MLL_ERR   GENMASK_ULL(0, 0)
#define GID_ENT_RSLT1_LL_LENGTH GENMASK_ULL(31, 16)
#define GID_ENT_RSLT1_PREV_LINK GENMASK_ULL(47, 32)
#define GID_ENT_RSLT1_MATCH_LINK GENMASK_ULL(63, 48)

#define GID_PARAM_LL_DEPTH GENMASK_ULL(31, 16)

#define FID_LOG2STRIDE GENMASK_ULL(44, 40)
#define FID_LOG2SIZE   GENMASK_ULL(36, 32)
#define FID_OFFSET     GENMASK_ULL(31, 4)
#define FID_PSW_TYPE   GENMASK_ULL(3, 0)

#define FID_BASE_ADDR  GENMASK_ULL(31, 3)
#define FID_BASE_MASK  GENMASK_ULL(63, 35)

#define FID_EPF_NUM    GENMASK_ULL(43, 40)
#define FID_EPF_MASK   GENMASK_ULL(35, 32)
#define FID_EVFM1_NUM  GENMASK_ULL(30, 24)
#define FID_EVFM1_MASK GENMASK_ULL(22, 16)
#define FID_ISEPF      GENMASK_ULL(6, 6)
#define FID_EBAR       GENMASK_ULL(5, 4)
#define FID_READ       GENMASK_ULL(3, 3)
#define FID_READ_MASK  GENMASK_ULL(2, 2)
#define FID_VALID      GENMASK_ULL(0, 0)

struct gid_key {
	u16 epffunc;
	u16 rid;
};

struct gid_action {
	u16 link;
	u16 mid;
	u16 qid;
	bool mvalid;
	bool iqvalid;
	bool oqvalid;
};

struct psw_rsrc {
	u8 *pf2epf_map;
	u64 const0;
	u64 const1;
	u64 const2;
	u8 num_epfs;
	struct rsrc_bmap gid_t;
	struct rsrc_bmap qid_t;
	struct rsrc_bmap mid_t;
	struct rsrc_bmap fid_t;
};

struct psw_drvdata {
	struct psw_rsrc	rsrc;
	int res_idx;
};

static irqreturn_t psw_api_notif_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_APINOTIF_INT);

	rvu_write64(rvu, blkaddr, PSW_AF_APINOTIF_INT, reg);

	return IRQ_HANDLED;
}

static irqreturn_t psw_gen_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_GEN_INT);

	rvu_write64(rvu, blkaddr, PSW_AF_GEN_INT, reg);

	return IRQ_HANDLED;
}

static irqreturn_t psw_rvu_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_RVU_INT);
	dev_err_ratelimited(rvu->dev, "Received PSWAF RVU irq : 0x%llx", reg);

	rvu_write64(rvu, blkaddr, PSW_AF_RVU_INT, reg);
	return IRQ_HANDLED;
}

static irqreturn_t psw_ras_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 reg, cap_reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_RAS_INT);
	dev_err_ratelimited(rvu->dev, "Received PSWAF RAS irq : 0x%llx", reg);

	if (reg & BIT_ULL(8)) {
		dev_err_ratelimited(rvu->dev,
				    "Host transaction with no match on FID");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_FID_NOMATCH_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_FID_NOMATCH_CAPTURE: 0x%llx",
				    cap_reg);
		rvu_write64(rvu, blkaddr, PSW_AF_FID_NOMATCH_CAPTURE, 0x0);
	}
	if (reg & BIT_ULL(7)) {
		dev_err_ratelimited(rvu->dev,
				    "Disabled queue needs access by HW");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_HO_QE_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_HO_QE_CAPTURE: 0x%llx",
				    cap_reg);
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_SHO_QE_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_SHO_QE_CAPTURE: 0x%llx",
				    cap_reg);
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_NQE_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_NQE_CAPTURE: 0x%llx",
				    cap_reg);
	}
	if (reg & BIT_ULL(6))
		dev_err_ratelimited(rvu->dev, "Timed poll drift");

	if (reg & BIT_ULL(5)) {
		dev_err_ratelimited(rvu->dev, "Polling transaction error");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_TIMED_ERR_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_TIMED_ERR_CAPTURE: 0x%llx",
				    cap_reg);
	}
	if (reg & BIT_ULL(4)) {
		dev_err_ratelimited(rvu->dev, "GID lookup MAX_LL_DEPTH error");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_GID_ERR_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_GID_ERR_CAPTURE: 0x%llx",
				    cap_reg);
	}
	if (reg & BIT_ULL(3)) {
		dev_err_ratelimited(rvu->dev, "GID no match error");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_GID_ERR_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_GID_ERR_CAPTURE: 0x%llx",
				    cap_reg);
	}
	if ((reg & BIT_ULL(2)) || (reg & BIT_ULL(1))) {
		dev_err_ratelimited(rvu->dev, "EVF/EPF LF map error");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_MAP_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_MAP_CAPTURE: 0x%llx",
				    cap_reg);
	}
	if (reg & BIT_ULL(0)) {
		dev_err_ratelimited(rvu->dev, "API notification queue error");
		cap_reg = rvu_read64(rvu, blkaddr, PSW_AF_API_NQE_CAPTURE);
		dev_err_ratelimited(rvu->dev, "PSW_AF_API_NQE_CAPTURE: 0x%llx",
				    cap_reg);
	}

	rvu_write64(rvu, blkaddr, PSW_AF_RAS_INT, reg);
	return IRQ_HANDLED;
}

static irqreturn_t psw_ecc_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_ECC_INT);
	dev_err_ratelimited(rvu->dev, "Received PSWAF ECC irq : 0x%llx", reg);

	rvu_write64(rvu, blkaddr, PSW_AF_ECC_INT, reg);
	return IRQ_HANDLED;
}

static int psw_do_register_interrupt(struct rvu_block *block, int irq_off,
				     irq_handler_t handler, const char *name)
{
	struct rvu *rvu = block->rvu;
	int ret;

	ret = request_irq(pci_irq_vector(rvu->pdev, irq_off), handler, 0,
			  name, block);
	if (ret) {
		dev_err(rvu->dev, "RVUAF: %s irq registration failed", name);
		return ret;
	}
	WARN_ON(rvu->irq_allocated[irq_off]);
	rvu->irq_allocated[irq_off] = true;

	return 0;
}

static int rvu_psw_check_rsrc_availability(struct rvu *rvu,
					   struct psw_rsrc_attach_req *req,
					   u16 pcifunc, int blkaddr)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	struct rvu_hwinfo *hw = rvu->hw;
	int free_lfs, mappedlfs;
	struct rvu_block *block;

	block = &hw->block[blkaddr];
	if (!block->lf.bmap)
		return -EINVAL;
	if (req->pswlfs > block->lf.max) {
		dev_err(&rvu->pdev->dev,
			"Func 0x%x: Invalid PSWLF req, %d > max %d\n",
			 pcifunc, req->pswlfs, block->lf.max);
		return -EINVAL;
	}
	mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
	free_lfs = rvu_rsrc_free_count(&block->lf);
	if (req->pswlfs > mappedlfs &&
	    ((req->pswlfs - mappedlfs) > free_lfs)) {
		dev_info(rvu->dev, "Request for %s failed\n", block->name);
		return -ENOSPC;
	}

	return 0;
}

static inline bool lookup_gid_entry(struct rvu *rvu, struct gid_key *key,
				    u64 *result, u64 *result1, u64 *result0)
{
	u64 reg;

	reg = FIELD_PREP(GID_LU_EPFFUNC, key->epffunc);
	reg |= FIELD_PREP(GID_LU_RID, key->rid);
	rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_LU, reg);

	*result = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_BUCKET_RESULT);
	if (!FIELD_GET(GID_BKT_RSLT_BVALID, *result))
		return false;

	*result1 = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY_RESULT1);
	*result0 = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY_RESULT0);

	return true;
}

static inline void handle_first_entry(struct rvu *rvu, u16 bkt_id,
				      u16 match_link, u16 rslt_link)
{
	u64 reg;

	if (match_link == rslt_link) {
		reg = FIELD_PREP(GID_BKT_BVALID, 0);
		reg |= FIELD_PREP(GID_BKT_BSTART, 0);
	} else {
		/* Direct bucket to next link */
		reg = FIELD_PREP(GID_BKT_BVALID, 1);
		reg |= FIELD_PREP(GID_BKT_BSTART, rslt_link);
	}
	rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_BUCKET(bkt_id), reg);
}

static inline void update_previous_link(struct rvu *rvu, u16 prev_link,
					u16 match_link, u16 rslt_link)
{
	u16 link = (match_link == rslt_link) ? prev_link : rslt_link;
	u64 prev_entry;

	prev_entry = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY0(prev_link));
	gid_entry0_w(link, FIELD_GET(GID_ENT_MID, prev_entry),
		     FIELD_GET(GID_ENT_QID, prev_entry),
		     FIELD_GET(GID_ENT_MVALID, prev_entry),
		     FIELD_GET(GID_ENT_IQVALID, prev_entry),
		     FIELD_GET(GID_ENT_OQVALID, prev_entry));

	prev_entry = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY1(prev_link));
	gid_entry1_w(prev_link, FIELD_GET(GID_ENT_RID, prev_entry),
		     FIELD_GET(GID_ENT_EPFFUNC, prev_entry));
}

static int psw_gid_delete(struct rvu *rvu, struct gid_key *key,
			  struct gid_action *action)
{
	u64 result, result1, result0;
	u8 iqvalid, oqvalid, mvalid;
	u16 match_link, rslt_link;
	u16 bkt_id, prev_link;
	u64 match_entry;

	if (!lookup_gid_entry(rvu, key, &result, &result1, &result0))
		return PSW_AF_ERR_GID_NOENT;

	if (FIELD_GET(GID_ENT_RSLT1_MLL_ERR, result1))
		return PSW_AF_ERR_GID_MLL;

	iqvalid = FIELD_GET(GID_ENT_IQVALID, result0);
	oqvalid = FIELD_GET(GID_ENT_OQVALID, result0);
	mvalid = FIELD_GET(GID_ENT_MVALID, result0);

	if (!iqvalid && !oqvalid && !mvalid)
		return PSW_AF_ERR_GID_NOENT;

	match_link = FIELD_GET(GID_ENT_RSLT1_MATCH_LINK, result1);
	prev_link = FIELD_GET(GID_ENT_RSLT1_PREV_LINK, result1);
	rslt_link = FIELD_GET(GID_ENT_LINK, result0);

	match_entry = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY1(match_link));
	if (FIELD_GET(GID_ENT_RID, match_entry) != key->rid ||
	    FIELD_GET(GID_ENT_EPFFUNC, match_entry) != key->epffunc)
		return PSW_AF_ERR_GID_NOENT;

	bkt_id = FIELD_GET(GID_BKT_RSLT_BHASH, result);

	action->qid = FIELD_GET(GID_ENT_QID, result0);
	action->mid = FIELD_GET(GID_ENT_MID, result0);
	action->iqvalid = iqvalid;
	action->oqvalid = oqvalid;
	action->mvalid = mvalid;

	if (FIELD_GET(GID_ENT_RSLT1_LL_LENGTH, result1) == 1)
		/* Match is on first entry */
		handle_first_entry(rvu, bkt_id, match_link, rslt_link);
	else
		update_previous_link(rvu, prev_link, match_link, rslt_link);

	/* Clear matched entry */
	gid_entry0_w(0, 0, 0, 0, 0, 0);
	gid_entry1_w(match_link, 0, 0);

	mutex_lock(&rvu->rsrc_lock);
	rvu_free_rsrc(&rvu->hw->psw->gid_t, match_link);
	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}

static int psw_gid_insert(struct rvu *rvu, struct gid_key *key,
			  struct gid_action *action)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	u16 link, bkt_id, max_ll_depth;
	u64 result, result1, result0;
	u8 iqvalid, oqvalid, mvalid;
	u64 temp0, temp1, rslt_link;
	u64 reg;

	link = action->link;
	if (!lookup_gid_entry(rvu, key, &result, &result1, &result0)) {
		/* Bucket doesn't exist, insert entry to table */
		gid_entry0_w(link, action->mid, action->qid, action->mvalid,
			     action->iqvalid, action->oqvalid);
		gid_entry1_w(link, key->rid, key->epffunc);

		reg = FIELD_PREP(GID_BKT_BVALID, 1);
		reg |= FIELD_PREP(GID_BKT_BSTART, link);

		bkt_id = FIELD_GET(GID_BKT_RSLT_BHASH, result);
		rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_BUCKET(bkt_id), reg);
	} else {
		if (FIELD_GET(GID_ENT_RSLT1_MLL_ERR, result1)) {
			rvu_free_rsrc(&psw->gid_t, action->link);
			return PSW_AF_ERR_GID_MLL;
		}

		iqvalid = FIELD_GET(GID_ENT_IQVALID, result0);
		oqvalid = FIELD_GET(GID_ENT_OQVALID, result0);
		mvalid = FIELD_GET(GID_ENT_MVALID, result0);

		if (iqvalid || oqvalid || mvalid) {
			rvu_free_rsrc(&psw->gid_t, action->link);
			return PSW_AF_ERR_GID_EXIST;
		}

		reg = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_PARAM);
		max_ll_depth = FIELD_GET(GID_PARAM_LL_DEPTH, reg);
		if (FIELD_GET(GID_ENT_RSLT1_LL_LENGTH, result1) ==
		    max_ll_depth)  {
			reg = FIELD_PREP(GID_PARAM_LL_DEPTH, max_ll_depth + 1);
			rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_PARAM, reg);
		}
		gid_entry0_w(link, action->mid, action->qid, action->mvalid,
			     action->iqvalid, action->oqvalid);
		gid_entry1_w(link, key->rid, key->epffunc);

		rslt_link = FIELD_GET(GID_ENT_LINK, result0);
		temp0 = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY0(rslt_link));
		temp1 = rvu_read64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY1(rslt_link));

		temp0 &= ~GID_ENT_LINK;
		temp0 |= FIELD_PREP(GID_ENT_LINK, link);

		temp1 &= ~GID_ENT_WNUM;
		temp1 |= FIELD_PREP(GID_ENT_WNUM, rslt_link);

		rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY0_W, temp0);
		rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_ENTRY1_W, temp1);
	}

	return 0;
}

static int gid_insert(struct rvu *rvu, u16 epffunc, u16 rid, u16 gid, u16 qid,
		      u16 mid, u8 mvalid, u8 iqvalid, u8 oqvalid)
{
	struct gid_action action;
	struct gid_key key;

	key.rid = rid;
	key.epffunc = epffunc;
	action.link = gid;
	action.qid = qid;
	action.mid = mid;
	action.mvalid = mvalid;
	action.iqvalid = iqvalid;
	action.oqvalid = oqvalid;
	if (mvalid)
		rvu_write64(rvu, BLKADDR_PSW, PSW_AF_MSIX_VECX_EPF_FUNC(mid), epffunc);

	return psw_gid_insert(rvu, &key, &action);
}

static int gid_alloc_resources(struct rvu *rvu, u16 rid_base, int min_cnt,
			       int max_cnt, int inb_qs, int outb_qs,
			       u16 epffunc)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	u16 gid_idx, qid_idx, msid_idx, cnt;
	u8 iqvalid = 0, oqvalid = 0;
	struct gid_action action;
	u16 rid, gid, qid, mid;
	struct gid_key key;
	int ret;

	cnt = min_cnt;
	gid_idx = rvu_alloc_rsrc_contig(&psw->gid_t, cnt);
	qid_idx = rvu_alloc_rsrc_contig(&psw->qid_t, cnt);
	msid_idx = rvu_alloc_rsrc_contig(&psw->mid_t, cnt);

	for (rid = 0, gid = gid_idx, qid = qid_idx, mid = msid_idx; rid < min_cnt;
	     rid++, gid++, qid++, mid++) {
		ret = gid_insert(rvu, epffunc, rid + rid_base, gid, qid, mid, 1, 1, 1);
		if (ret)
			goto err;
	}
	cnt = 0;
	if (inb_qs != outb_qs) {
		cnt = abs(inb_qs - outb_qs);
		iqvalid = inb_qs > outb_qs ? 1 : 0;
		oqvalid = inb_qs > outb_qs ? 0 : 1;
	}
	gid_idx = rvu_alloc_rsrc_contig(&psw->gid_t, cnt);
	qid_idx = rvu_alloc_rsrc_contig(&psw->qid_t, cnt);
	msid_idx = rvu_alloc_rsrc_contig(&psw->mid_t, cnt);

	for (gid = gid_idx, qid = qid_idx, mid = msid_idx; rid < (cnt + min_cnt);
	     rid++, gid++, qid++, mid++) {
		ret = gid_insert(rvu, epffunc, rid + rid_base, gid, qid, mid, 1,
				 iqvalid, oqvalid);
		if (ret)
			goto err;
	}

	cnt = max_cnt - rid;
	gid_idx = rvu_alloc_rsrc_contig(&psw->gid_t, cnt);
	msid_idx = rvu_alloc_rsrc_contig(&psw->mid_t, cnt);

	for (gid = gid_idx, mid = msid_idx; rid < max_cnt; rid++, gid++, mid++) {
		ret = gid_insert(rvu, epffunc, rid + rid_base, gid, 0, mid, 1, 0, 0);
		if (ret)
			goto err;
	}
	return 0;

err:
	rid--;
	key.epffunc = epffunc;
	for (; rid >= 0; rid--) {
		key.rid = rid + rid_base;
		psw_gid_delete(rvu, &key, &action);

		mutex_lock(&rvu->rsrc_lock);
		if (action.iqvalid || action.oqvalid)
			rvu_free_rsrc(&psw->qid_t, action.qid);
		rvu_free_rsrc(&psw->mid_t, action.mid);

		mutex_unlock(&rvu->rsrc_lock);
	}
	mutex_lock(&rvu->rsrc_lock);
	rvu_free_rsrc_contig(&psw->gid_t, cnt, gid_idx);
	rvu_free_rsrc_contig(&psw->qid_t, cnt, qid_idx);
	rvu_free_rsrc_contig(&psw->mid_t, cnt, msid_idx);
	mutex_unlock(&rvu->rsrc_lock);

	return ret;
}

int rvu_mbox_handler_psw_fid_alloc_entry(struct rvu *rvu,
					 struct psw_fid_alloc_entry_req *req,
					 struct psw_fid_alloc_entry_rsp *rsp)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	int fid_idx, blkaddr = BLKADDR_PSW;
	u8 pf, epf;
	u64 reg;

	pf = rvu_get_pf(rvu->pdev, req->hdr.pcifunc);
	epf = psw->pf2epf_map[pf];

	fid_idx = rvu_alloc_rsrc(&psw->fid_t);
	if (fid_idx < 0)
		return PSW_AF_ERR_NOSPC;

	reg = FIELD_PREP(FID_LOG2STRIDE, req->log2stride);
	reg |= FIELD_PREP(FID_LOG2SIZE, req->log2size);
	reg |= FIELD_PREP(FID_OFFSET, req->offset);
	reg |= FIELD_PREP(FID_PSW_TYPE, req->psw_type);
	rvu_write64(rvu, blkaddr, PSW_AF_FID_IND(fid_idx), reg);

	reg = FIELD_PREP(FID_BASE_ADDR, req->base_addr);
	reg |= FIELD_PREP(FID_BASE_MASK, req->base_mask);
	rvu_write64(rvu, blkaddr, PSW_AF_FID_BASE(fid_idx), reg);

	reg = FIELD_PREP(FID_EPF_NUM, epf);
	reg |= FIELD_PREP(FID_EPF_MASK, psw->num_epfs - 1);
	reg |= FIELD_PREP(FID_ISEPF, req->isepf);
	if (req->evf_id)
		reg |= FIELD_PREP(FID_EVFM1_NUM, req->evf_id - 1);

	reg |= FIELD_PREP(FID_EVFM1_MASK, req->evfm1_mask);
	reg |= FIELD_PREP(FID_EBAR, req->bar);
	reg |= FIELD_PREP(FID_READ, req->read_en);
	reg |= FIELD_PREP(FID_READ_MASK, req->read_mask);
	reg |= FIELD_PREP(FID_VALID, 0x1);
	rvu_write64(rvu, blkaddr, PSW_AF_FID_ATTR(fid_idx), reg);

	rsp->fid_idx = fid_idx;

	return 0;
}

int rvu_mbox_handler_psw_fid_free_entry(struct rvu *rvu,
					struct psw_fid_free_entry_req *req,
					struct msg_rsp *rsp)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	int blkaddr = BLKADDR_PSW;

	rvu_write64(rvu, blkaddr, PSW_AF_FID_ATTR(req->fid_idx), 0x0ULL);
	rvu_free_rsrc(&psw->fid_t, req->fid_idx);

	return 0;
}

int rvu_mbox_handler_psw_gid_free(struct rvu *rvu,
				  struct psw_gid_free_req *req,
				  struct msg_rsp *rsp)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	u16 nb_rids = req->nb_rids, rid;
	struct gid_action action;
	struct gid_key key;
	u8 pf, epf, port;
	int ret;

	pf = rvu_get_pf(rvu->pdev, req->hdr.pcifunc);
	epf = psw->pf2epf_map[pf];
	port = PSW_PEM_ID(epf);
	epf = PSW_PEM_EPF(epf);
	key.epffunc = PSW_EPFFUNC(port, epf, req->evf_id);

	for (rid = req->rid_base; rid < nb_rids; rid++) {
		key.rid = rid;
		ret = psw_gid_delete(rvu, &key, &action);
		if (ret)
			return ret;

		mutex_lock(&rvu->rsrc_lock);
		if (action.iqvalid || action.oqvalid)
			rvu_free_rsrc(&psw->qid_t, action.qid);
		rvu_free_rsrc(&psw->mid_t, action.mid);

		mutex_unlock(&rvu->rsrc_lock);
	}

	return 0;
}

int rvu_mbox_handler_psw_gid_alloc(struct rvu *rvu,
				   struct psw_gid_alloc_req *req,
				   struct msg_rsp *rsp)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	u16 min_cnt, max_cnt, max_q_cnt;
	u16 outb_qs = req->nb_outb_qs;
	u16 inb_qs = req->nb_inb_qs;
	u16 nb_msid = req->nb_mid;
	u8 pf, epf, port;
	u16 epffunc;
	int ret;

	min_cnt = min(inb_qs, outb_qs);
	min_cnt = min(nb_msid, min_cnt);

	max_q_cnt = max(inb_qs, outb_qs);
	if (nb_msid < max_q_cnt)
		return PSW_AF_ERR_PARAM;
	max_cnt = max(nb_msid, max_q_cnt);
	if (max_cnt > PSW_MAX_RID_CNT_PER_FUNC)
		return PSW_AF_ERR_PARAM;

	pf = rvu_get_pf(rvu->pdev, req->hdr.pcifunc);
	epf = psw->pf2epf_map[pf];
	port = PSW_PEM_ID(epf);
	epf = PSW_PEM_EPF(epf);
	epffunc = PSW_EPFFUNC(port, epf, req->evf_id);

	mutex_lock(&rvu->rsrc_lock);
	if (!rvu_rsrc_check_contig(&psw->gid_t, max_cnt))
		return PSW_AF_ERR_NOSPC;

	if (!rvu_rsrc_check_contig(&psw->qid_t, max_q_cnt))
		return PSW_AF_ERR_NOSPC;

	if (!rvu_rsrc_check_contig(&psw->mid_t, max_cnt))
		return PSW_AF_ERR_NOSPC;

	ret = gid_alloc_resources(rvu, req->rid_base, min_cnt, max_cnt, inb_qs,
				  outb_qs, epffunc);

	mutex_unlock(&rvu->rsrc_lock);

	return ret;
}

int rvu_mbox_handler_psw_caps_get(struct rvu *rvu, struct msg_req *req,
				  struct psw_caps_get_rsp *rsp)
{
	struct psw_rsrc *psw = rvu->hw->psw;
	int blkaddr = BLKADDR_PSW, psw_type;
	u8 pf;

	pf = rvu_get_pf(rvu->pdev, req->hdr.pcifunc);
	rsp->epf = psw->pf2epf_map[pf];
	rsp->const0 = psw->const0;
	rsp->const1 = psw->const1;
	rsp->const2 = psw->const2;
	for (psw_type = 0; psw_type < PSW_TYPE_COUNT; psw_type++)
		rsp->fid_type_const[psw_type] = rvu_read64(rvu, blkaddr,
							   PSW_AF_FID_TYPEX_CONST(psw_type));

	return 0;
}

int rvu_mbox_handler_psw_msix_offset(struct rvu *rvu, struct msg_req *req,
				     struct psw_msix_offset_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int blkaddr = BLKADDR_PSW;
	struct rvu_pfvf *pfvf;
	int lf, slot;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	if (!pfvf->msix.bmap)
		return 0;

	rsp->pswlfs = pfvf->pswlfs;
	for (slot = 0; slot < rsp->pswlfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, slot);
		rsp->pswlf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, blkaddr, lf);
	}

	return 0;
}

int rvu_mbox_handler_psw_free_rsrc_cnt(struct rvu *rvu, struct msg_req *req,
				       struct psw_free_rsrcs_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int blkaddr = BLKADDR_PSW;
	struct rvu_block *block;

	mutex_lock(&rvu->rsrc_lock);

	block = &hw->block[blkaddr];
	rsp->psw = rvu_rsrc_free_count(&block->lf);

	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}

static int psw_lf_free(struct rvu *rvu, u16 pcifunc)
{
	int num_lfs, pswlf, slot, ret;
	int blkaddr = BLKADDR_PSW;
	struct rvu_block *block;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc), blkaddr);
	if (!num_lfs)
		return 0;

	for (slot = 0; slot < num_lfs; slot++) {
		pswlf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (pswlf < 0)
			return PSW_AF_ERR_LF_INVALID;

		/* Reset LF */
		ret = rvu_lf_reset(rvu, block, pswlf);
		if (ret) {
			dev_err(rvu->dev, "Failed to reset blkaddr %d LF%d\n",
				block->addr, pswlf);
		}
	}

	return 0;
}

int rvu_mbox_handler_psw_detach_resources(struct rvu *rvu,
					  struct psw_rsrc_detach_req *detach,
					  struct msg_rsp *rsp)
{
	u16 pcifunc = detach->hdr.pcifunc;

	psw_lf_free(rvu, pcifunc);

	mutex_lock(&rvu->rsrc_lock);

	rvu_detach_block(rvu, pcifunc, BLKTYPE_PSW);

	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}

int rvu_mbox_handler_psw_attach_resources(struct rvu *rvu,
					  struct psw_rsrc_attach_req *attach,
					  struct msg_rsp *rsp)
{
	u16 pcifunc = attach->hdr.pcifunc;
	struct rvu_hwinfo *hw = rvu->hw;
	int blkaddr = BLKADDR_PSW;
	struct rvu_block *block;
	struct rvu_pfvf *pfvf;
	int ret, lf;
	u16 slot;
	u64 cfg;

	if (!attach->pswlfs)
		return 0;

	block = &hw->block[blkaddr];
	pfvf = rvu_get_pfvf(rvu, pcifunc);

	mutex_lock(&rvu->rsrc_lock);

	/* If first request, detach all existing attached resources */
	if (!attach->modify)
		rvu_detach_block(rvu, pcifunc, BLKTYPE_PSW);

	/* Check if the request can be accommodated */
	ret = rvu_psw_check_rsrc_availability(rvu, attach, pcifunc, blkaddr);
	if (ret)
		goto exit;

	if (attach->modify)
		rvu_detach_block(rvu, pcifunc, BLKTYPE_PSW);

	for (slot = 0; slot < attach->pswlfs; slot++) {
		/* Allocate the resource */
		lf = rvu_alloc_rsrc(&block->lf);
		if (lf < 0)
			goto exit;

		cfg = (1ULL << 63) | (pcifunc << 8) | slot;
		rvu_write64(rvu, blkaddr,
			    block->lfcfg_reg | (lf << block->lfshift), cfg);
		rvu_update_rsrc_map(rvu, pfvf, block, pcifunc, lf, true);

		/* Set start MSIX vector for this LF within this PF/VF */
		rvu_set_msix_offset(rvu, pfvf, block, lf);
	}

exit:
	mutex_unlock(&rvu->rsrc_lock);
	return ret;
}

static void rvu_psw_unregister_interrupts_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	struct rvu_hwinfo *hw;
	u16 i, nvecs;
	int off;
	u64 reg;

	(void)data;

	reg = rvu_read64(rvu, blkaddr, PSW_PRIV_AF_INT_CFG);
	off = reg & 0x7FF;
	if (!off) {
		dev_warn(rvu->dev,
			 "Failed to get PSW_AF_INT vector offsets\n");
		return;
	}
	nvecs = FIELD_GET(GENMASK_ULL(23, 12), reg);

	hw = rvu->hw;
	block = &hw->block[blkaddr];

	rvu_write64(rvu, blkaddr, PSW_AF_APINOTIF_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, PSW_AF_GEN_INT_ENA_W1C, 0xFFFF);
	rvu_write64(rvu, blkaddr, PSW_AF_RAS_INT_ENA_W1C, 0x1FF);
	rvu_write64(rvu, blkaddr, PSW_AF_RVU_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, PSW_AF_ECC_INT_ENA_W1C,
		    INTR_MASK(PSW_ECC_INT_BITS));

	for (i = 0; i < nvecs; i++) {
		if (rvu->irq_allocated[off + i]) {
			free_irq(pci_irq_vector(rvu->pdev, off + i), block);
			rvu->irq_allocated[off + i] = false;
		}
	}
}

static int rvu_psw_register_interrupts_block(struct rvu_block *block, void *data)
{
	int api_notif_int_vec, gen_int_vec, ras_int_vec;
	struct rvu *rvu = block->rvu;
	int rvu_int_vec, ecc_int_vec;
	int blkaddr = block->addr;
	u16 max_evfs;
	int off, ret;

	max_evfs = rvu->hw->psw->const0 & 0xFFFF;
	off = rvu_read64(rvu, blkaddr, PSW_PRIV_AF_INT_CFG) & 0x7FF;
	if (!off) {
		dev_warn(rvu->dev,
			 "Failed to get PSW_AF_INT vector offsets\n");
		return 0;
	}

	api_notif_int_vec = off + max_evfs + 1;
	ret = psw_do_register_interrupt(block, api_notif_int_vec,
					psw_api_notif_intr_handler,
					"PSWAF API NOTIF");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, PSW_AF_APINOTIF_INT_ENA_W1S, 0x1);

	gen_int_vec = api_notif_int_vec + 1;
	ret = psw_do_register_interrupt(block, gen_int_vec,
					psw_gen_intr_handler, "PSWAF GEN");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, PSW_AF_GEN_INT_ENA_W1S, 0xFFFF);

	ras_int_vec = gen_int_vec + 1;
	ret = psw_do_register_interrupt(block, ras_int_vec,
					psw_ras_intr_handler, "PSWAF RAS");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, PSW_AF_RAS_INT_ENA_W1S, 0x1FF);

	rvu_int_vec = ras_int_vec + 1;
	ret = psw_do_register_interrupt(block, rvu_int_vec,
					psw_rvu_intr_handler, "PSWAF RVU");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, PSW_AF_RVU_INT_ENA_W1S, 0x1);

	ecc_int_vec = rvu_int_vec + 1;
	ret = psw_do_register_interrupt(block, ecc_int_vec,
					psw_ecc_intr_handler, "PSWAF ECC");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, PSW_AF_ECC_INT_ENA_W1S,
		    INTR_MASK(PSW_ECC_INT_BITS));

	return 0;
err:
	rvu_psw_unregister_interrupts_block(block, data);

	return ret;
}

static void rvu_psw_freemem_block(struct rvu_block *block, void *data)
{
	(void)data;

	rvu_free_bitmap(&block->lf);
}

static int rvu_setup_psw_hw_resource_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 cfg;
	int ret;

	cfg = rvu_read64(rvu, blkaddr, PSW_AF_CONST2);
	block->lf.max = (cfg >> 40) & 0xFF;
	block->type = BLKTYPE_PSW;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = PSW_AF_RVU_LF_CFG_DEBUG;
	block->lfcfg_reg = PSW_PRIV_LFX_CFG;
	block->msixcfg_reg = PSW_PRIV_LFX_INT_CFG;
	block->lfreset_reg = PSW_AF_LF_RST;
	sprintf(block->name, "PSW");

	ret = rvu_alloc_bitmap(&block->lf);
	if (ret)
		return ret;

	/* Allocate memory for block LF/slot to pcifunc mapping info */
	block->fn_map =
		devm_kcalloc(rvu->dev, block->lf.max, sizeof(u16), GFP_KERNEL);
	if (!block->fn_map) {
		ret = -ENOMEM;
		goto free_bmap;
	}
	rvu_reset_blk_lfcfg(rvu, block);

	rvu_scan_block(rvu, block);

	return 0;

free_bmap:
	rvu_free_bitmap(&block->lf);

	return ret;
}

static int psw_gid_setup(struct rvu *rvu, struct psw_rsrc *psw, int blkaddr)
{
	int ret;
	u64 reg;

	psw->gid_t.max = FIELD_GET(CONST1_MAX_GID, psw->const1);

	ret = rvu_alloc_bitmap(&psw->gid_t);
	if (ret)
		return ret;

	psw->qid_t.max = PSW_MAX_QUEUES;
	ret = rvu_alloc_bitmap(&psw->qid_t);
	if (ret)
		goto gid_t_free;

	psw->mid_t.max = psw->gid_t.max;
	ret = rvu_alloc_bitmap(&psw->mid_t);
	if (ret)
		goto qid_t_free;

	reg = FIELD_PREP(GID_PARAM_LL_DEPTH, 5);
	rvu_write64(rvu, BLKADDR_PSW, PSW_AF_GID_PARAM, reg);

	return 0;

qid_t_free:
	kfree(psw->qid_t.bmap);
gid_t_free:
	kfree(psw->gid_t.bmap);
	return ret;
}

static int rvu_psw_init_block(struct rvu_block *block, void *data)
{
	struct psw_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	struct rvu_hwinfo *hw;
	struct psw_rsrc *psw;
	u16 pf_id, epf_id;
	u8 *pf2epf_map;
	u16 max_epfs;
	u64 cfg;
	int ret;

	if (!data)
		return -EINVAL;

	hw = rvu->hw;
	hw->psw = &drvdata->rsrc;
	psw = hw->psw;
	pf2epf_map = devm_kcalloc(rvu->dev, hw->total_pfs, sizeof(uint8_t),
				  GFP_KERNEL);
	if (!pf2epf_map)
		return -ENOMEM;
	memset(pf2epf_map, 0xFF, hw->total_pfs * sizeof(uint8_t));

	psw->const0 = rvu_read64(rvu, blkaddr, PSW_AF_CONST0);
	psw->const1 = rvu_read64(rvu, blkaddr, PSW_AF_CONST1);
	psw->const2 = rvu_read64(rvu, blkaddr, PSW_AF_CONST2);
	max_epfs = FIELD_GET(CONST_MAX_EPFS, psw->const0);

	for (pf_id = 0, epf_id = 0; pf_id < hw->total_pfs && epf_id < max_epfs; pf_id++) {
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf_id));
		if (!(cfg & BIT_ULL(20)))
			continue;

		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_ID_CFG(pf_id));
		if ((cfg & 0xFF) == PCI_DEVID_PSW_PF) {
			pf2epf_map[pf_id] = epf_id;
			epf_id++;
			dev_info(rvu->dev, "pf2epf_map[%u]: %u\n", pf_id, pf2epf_map[pf_id]);
		}
	}
	psw->num_epfs = epf_id;
	psw->pf2epf_map = pf2epf_map;

	ret = psw_gid_setup(rvu, psw, BLKADDR_PSW);
	if (ret)
		return ret;

	psw->fid_t.max = FIELD_GET(GENMASK_ULL(31, 16), psw->const1);
	ret = rvu_alloc_bitmap(&psw->fid_t);
	if (ret)
		goto gid_free;

	return 0;

gid_free:
	kfree(psw->gid_t.bmap);
	kfree(psw->qid_t.bmap);
	kfree(psw->mid_t.bmap);

	return ret;
}

static void *rvu_psw_probe(struct rvu *rvu, int blkaddr)
{
	struct psw_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_PSW:
		data = devm_kzalloc(rvu->dev, sizeof(struct psw_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		data->res_idx = res_idx++;
		/* Due to HW errata for PSW, SW asserts all of the bits of PSW_AF_CLK_EN_PART0/
		 * PSW_AF_CLK_EN_PART1 prior writing to PSW_AF_BLK_RST[RST].
		 */
		rvu_write64(rvu, blkaddr, PSW_AF_CLK_EN_PART0, 0x3f);
		rvu_write64(rvu, blkaddr, PSW_AF_CLK_EN_PART1, 0x1ff);
		rvu_eblock_reset(rvu, blkaddr, PSW_AF_BLK_RST);
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_psw_remove(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	struct psw_rsrc *psw;

	psw = rvu->hw->psw;

	kfree(psw->fid_t.bmap);
	kfree(psw->gid_t.bmap);
	kfree(psw->qid_t.bmap);
	kfree(psw->mid_t.bmap);
	devm_kfree(block->rvu->dev, data);
}

static int rvu_psw_mbox_handler(struct otx2_mbox *mbox, int devid,
				struct mbox_msghdr *req)
{
	struct rvu *rvu = pci_get_drvdata(mbox->pdev);
	int _id = req->id;

	switch (_id) {
	#define M(_name, _id, _fn_name, _req_type, _rsp_type)		\
	{								\
	case _id: {							\
		struct _rsp_type *rsp;					\
		int err;						\
									\
		rsp = (struct _rsp_type *)otx2_mbox_alloc_msg(		\
			mbox, devid,					\
			sizeof(struct _rsp_type));			\
		if (rsp) {						\
			rsp->hdr.id = _id;				\
			rsp->hdr.sig = OTX2_MBOX_RSP_SIG;		\
			rsp->hdr.pcifunc = req->pcifunc;		\
			rsp->hdr.rc = 0;				\
		}							\
									\
		err = rvu_mbox_handler_ ## _fn_name(rvu,		\
						    (struct _req_type *)req, \
						    rsp);		\
		if (rsp && err)						\
			rsp->hdr.rc = err;				\
									\
		trace_otx2_msg_process(mbox->pdev, _id, err, req->pcifunc); \
		return rsp ? err : -ENOMEM;				\
	}								\
	}
		MBOX_EBLOCK_PSW_MESSAGES

	default :
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}
}

struct mbox_op psw_mbox_op = {
	.start = 0x1200,
	.end = 0x13FF,
	.handler = rvu_psw_mbox_handler,
};

static struct rvu_eblock_driver_ops psw_ops = {
	.probe	= rvu_psw_probe,
	.remove	= rvu_psw_remove,
	.init	= rvu_psw_init_block,
	.setup	= rvu_setup_psw_hw_resource_block,
	.free	= rvu_psw_freemem_block,
	.register_interrupt = rvu_psw_register_interrupts_block,
	.unregister_interrupt = rvu_psw_unregister_interrupts_block,
	.mbox_op = &psw_mbox_op,
};

void psw_eb_module_init(void)
{
	rvu_eblock_register_driver(&psw_ops);
}

void psw_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&psw_ops);
}
