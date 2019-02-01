// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/types.h>

#include "rvu_struct.h"

#include "rvu_reg.h"
#include "rvu.h"

static void rvu_sso_hwgrp_config_thresh(struct rvu *rvu, int blkaddr, int lf)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u64 add, grp_thr, grp_rsvd;
	u64 reg;

	/* Configure IAQ Thresholds */
	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf));
	grp_rsvd = reg & SSO_HWGRP_IAQ_RSVD_THR_MASK;
	add = hw->sso.iaq_rsvd - grp_rsvd;

	grp_thr = hw->sso.iaq_rsvd & SSO_HWGRP_IAQ_RSVD_THR_MASK;
	grp_thr |= ((hw->sso.iaq_max & SSO_HWGRP_IAQ_MAX_THR_MASK) <<
		    SSO_HWGRP_IAQ_MAX_THR_SHIFT);

	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf), grp_thr);

	if (add)
		rvu_write64(rvu, blkaddr, SSO_AF_AW_ADD,
			    (add & SSO_AF_AW_ADD_RSVD_FREE_MASK) <<
			    SSO_AF_AW_ADD_RSVD_FREE_SHIFT);

	/* Configure TAQ Thresholds */
	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf));
	grp_rsvd = reg & SSO_HWGRP_TAQ_RSVD_THR_MASK;
	add = hw->sso.taq_rsvd - grp_rsvd;

	grp_thr = hw->sso.taq_rsvd & SSO_HWGRP_TAQ_RSVD_THR_MASK;
	grp_thr |= ((hw->sso.taq_max & SSO_HWGRP_TAQ_MAX_THR_MASK) <<
		    SSO_HWGRP_TAQ_MAX_THR_SHIFT);

	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf), grp_thr);

	if (add)
		rvu_write64(rvu, blkaddr, SSO_AF_TAQ_ADD,
			    (add & SSO_AF_TAQ_RSVD_FREE_MASK) <<
			    SSO_AF_TAQ_ADD_RSVD_FREE_SHIFT);
}

int rvu_sso_lf_teardown(struct rvu *rvu, int lf)
{
	int blkaddr, err;
	u64 reg, add;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	rvu_write64(rvu, blkaddr, SSO_AF_IU_ACCNTX_RST(lf), 0x1);

	err = rvu_poll_reg(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf),
			   SSO_HWGRP_AW_STS_NPA_FETCH, true);
	if (err) {
		dev_err(rvu->dev,
			"SSO_HWGRP(%d)_AW_STATUS[NPA_FETCH] not cleared", lf);
		return err;
	}

	/* Remove all pointers from XAQ, HRM 14.13.6 */
	rvu_write64(rvu, blkaddr, SSO_AF_ERR0_ENA_W1C, BIT_ULL(1));
	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_AW_CFG(lf));
	reg = (reg & ~SSO_HWGRP_AW_CFG_RWEN) | SSO_HWGRP_AW_CFG_XAQ_BYP_DIS;
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_CFG(lf), reg);

	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf));
	if (reg & SSO_HWGRP_AW_STS_TPTR_VLD) {
		/* aura will be torn down, no need to free the pointer. */
		rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf),
			    SSO_HWGRP_AW_STS_TPTR_VLD);
	}

	err = rvu_poll_reg(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf),
			   SSO_HWGRP_AW_STS_XAQ_BUFSC_MASK, true);
	if (err) {
		dev_warn(rvu->dev,
			 "SSO_HWGRP(%d)_AW_STATUS[XAQ_BUF_CACHED] not cleared",
			 lf);
		return err;
	}

	/* Re-enable error reporting once we're finished */
	rvu_write64(rvu, blkaddr, SSO_AF_ERR0_ENA_W1S, BIT_ULL(1));

	/* HRM 14.13.4 (13) */
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_CFG(lf),
		    SSO_HWGRP_AW_CFG_LDWB | SSO_HWGRP_AW_CFG_LDT |
		    SSO_HWGRP_AW_CFG_STT);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_XAQ_AURA(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_XAQX_GMCTL(lf), 0x0);
	reg = (SSO_HWGRP_PRI_AFF_MASK << SSO_HWGRP_PRI_AFF_SHIFT) |
	      (SSO_HWGRP_PRI_WGT_MASK << SSO_HWGRP_PRI_WGT_SHIFT) |
	      (0x1 << SSO_HWGRP_PRI_WGT_SHIFT);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_PRI(lf), reg);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_WS_PC(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_EXT_PC(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_WA_PC(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_TS_PC(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_DS_PC(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_XAQ_LIMIT(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_IU_ACCNT(lf), 0x0);

	/* The delta between the current and default thresholds
	 * need to be returned to the SSO
	 */
	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf)) &
		SSO_HWGRP_IAQ_RSVD_THR_MASK;
	add = SSO_HWGRP_IAQ_RSVD_THR - reg;
	reg = (SSO_HWGRP_IAQ_MAX_THR_MASK << SSO_HWGRP_IAQ_MAX_THR_SHIFT) |
	      SSO_HWGRP_IAQ_RSVD_THR;
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf), reg);

	if (add)
		rvu_write64(rvu, blkaddr, SSO_AF_AW_ADD,
			    (add & SSO_AF_AW_ADD_RSVD_FREE_MASK) <<
			    SSO_AF_AW_ADD_RSVD_FREE_SHIFT);

	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf)) &
		SSO_HWGRP_TAQ_RSVD_THR_MASK;
	add = SSO_HWGRP_TAQ_RSVD_THR - reg;
	reg = (SSO_HWGRP_TAQ_MAX_THR_MASK << SSO_HWGRP_TAQ_MAX_THR_SHIFT) |
	      SSO_HWGRP_TAQ_RSVD_THR;
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf), reg);
	if (add)
		rvu_write64(rvu, blkaddr, SSO_AF_TAQ_ADD,
			    (add & SSO_AF_TAQ_RSVD_FREE_MASK) <<
			    SSO_AF_TAQ_ADD_RSVD_FREE_SHIFT);

	rvu_write64(rvu, blkaddr, SSO_AF_XAQX_HEAD_PTR(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_XAQX_TAIL_PTR(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_XAQX_HEAD_NEXT(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_XAQX_TAIL_NEXT(lf), 0x0);

	return 0;
}

int rvu_ssow_lf_teardown(struct rvu *rvu, int lf)
{
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return SSOW_AF_ERR_LF_INVALID;

	/* set SAI_INVAL bit */
	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_INV(lf), 0x1);

	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_ARB(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_GMCTL(lf), 0x0);

	return 0;
}

int rvu_mbox_handler_sso_hw_setconfig(struct rvu *rvu,
				      struct sso_hw_setconfig *req,
				      struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int hwgrp, lf, err, blkaddr;
	u32 npa_aura_id;
	u64 reg;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	npa_aura_id = req->npa_aura_id;

	/* Check if requested 'SSOLF <=> NPALF' mapping is valid */
	if (req->npa_pf_func) {
		/* If default, use 'this' SSOLF's PFFUNC */
		if (req->npa_pf_func == RVU_DEFAULT_PF_FUNC)
			req->npa_pf_func = pcifunc;
		if (!is_pffunc_map_valid(rvu, req->npa_pf_func, BLKTYPE_NPA))
			return SSO_AF_INVAL_NPA_PF_FUNC;
	}

	/* Initialize XAQ ring */
	for (hwgrp = 0; hwgrp < req->hwgrps; hwgrp++) {
		lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, hwgrp);
		if (lf < 0)
			return SSO_AF_ERR_LF_INVALID;

		rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_XAQ_AURA(lf),
			    npa_aura_id);
		rvu_write64(rvu, blkaddr, SSO_AF_XAQX_GMCTL(lf),
			    req->npa_pf_func);

		/* enable XAQ */
		rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_CFG(lf), 0xF);

		/* Wait for ggrp to ack. */
		err = rvu_poll_reg(rvu, blkaddr,
				   SSO_AF_HWGRPX_AW_STATUS(lf),
				   SSO_HWGRP_AW_STS_INIT_STS, false);

		reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf));
		if (err || (reg & BIT_ULL(4)) || !(reg & BIT_ULL(8))) {
			dev_warn(rvu->dev, "SSO_HWGRP(%d) XAQ NPA pointer initialization failed",
				 lf);
			return -ENOMEM;
		}
	}

	return 0;
}

int rvu_mbox_handler_sso_grp_set_priority(struct rvu *rvu,
					  struct sso_grp_priority *req,
					  struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr;
	u64 regval;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	regval = (((u64)(req->weight & SSO_HWGRP_PRI_WGT_MASK)
		  << SSO_HWGRP_PRI_WGT_SHIFT) |
		  ((u64)(req->affinity & SSO_HWGRP_PRI_AFF_MASK)
		   << SSO_HWGRP_PRI_AFF_SHIFT) |
		  (req->priority & SSO_HWGRP_PRI_MASK));

	lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, req->grp);
	if (lf < 0)
		return SSO_AF_ERR_LF_INVALID;

	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_PRI(lf), regval);

	return 0;
}

int rvu_mbox_handler_sso_grp_get_priority(struct rvu *rvu,
					  struct sso_info_req *req,
					  struct sso_grp_priority *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr;
	u64 regval;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, req->grp);
	if (lf < 0)
		return SSO_AF_ERR_LF_INVALID;

	regval = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_PRI(lf));

	rsp->weight = (regval >> SSO_HWGRP_PRI_WGT_SHIFT)
			& SSO_HWGRP_PRI_WGT_MASK;
	rsp->affinity = (regval >> SSO_HWGRP_PRI_AFF_SHIFT)
			& SSO_HWGRP_PRI_AFF_MASK;
	rsp->priority = regval & SSO_HWGRP_PRI_MASK;

	return 0;
}

int rvu_mbox_handler_sso_grp_qos_config(struct rvu *rvu,
					struct sso_grp_qos_cfg *req,
					struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	u64 regval, grp_rsvd;
	int lf, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, req->grp);
	if (lf < 0)
		return SSO_AF_ERR_LF_INVALID;

	/* Check if GGRP has been active. */
	regval = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_WA_PC(lf));
	if (regval)
		return SSO_AF_ERR_GRP_EBUSY;

	/* Configure XAQ threhold */
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_XAQ_LIMIT(lf), req->xaq_limit);

	/* Configure TAQ threhold */
	regval = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf));
	grp_rsvd = regval & SSO_HWGRP_TAQ_RSVD_THR_MASK;
	if (req->taq_thr < grp_rsvd)
		req->taq_thr = grp_rsvd;

	regval = req->taq_thr & SSO_HWGRP_TAQ_MAX_THR_MASK;
	regval = (regval << SSO_HWGRP_TAQ_MAX_THR_SHIFT) | grp_rsvd;
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf), regval);

	/* Configure IAQ threhold */
	regval = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf));
	grp_rsvd = regval & SSO_HWGRP_IAQ_RSVD_THR_MASK;
	if (req->iaq_thr < grp_rsvd + 4)
		req->iaq_thr = grp_rsvd + 4;

	regval = req->iaq_thr & SSO_HWGRP_IAQ_MAX_THR_MASK;
	regval = (regval << SSO_HWGRP_IAQ_MAX_THR_SHIFT) | grp_rsvd;
	rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf), regval);

	return 0;
}

int rvu_mbox_handler_sso_grp_get_stats(struct rvu *rvu,
				       struct sso_info_req *req,
				       struct sso_grp_stats *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, req->grp);
	if (lf < 0)
		return SSO_AF_ERR_LF_INVALID;

	rsp->ws_pc = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_WS_PC(lf));
	rsp->ext_pc = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_EXT_PC(lf));
	rsp->wa_pc = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_WA_PC(lf));
	rsp->ts_pc = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_TS_PC(lf));
	rsp->ds_pc = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_DS_PC(lf));
	rsp->dq_pc = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_DQ_PC(lf));
	rsp->aw_status = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf));
	rsp->page_cnt = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_PAGE_CNT(lf));

	return 0;
}

int rvu_mbox_handler_sso_hws_get_stats(struct rvu *rvu,
				       struct sso_info_req *req,
				       struct sso_hws_stats *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr, ssow_blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	ssow_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSOW, pcifunc);
	if (ssow_blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	lf = rvu_get_lf(rvu, &hw->block[ssow_blkaddr], pcifunc, req->hws);
	if (lf < 0)
		return SSO_AF_ERR_LF_INVALID;

	rsp->arbitration = rvu_read64(rvu, blkaddr, SSO_AF_HWSX_ARB(lf));

	return 0;
}

int rvu_mbox_handler_sso_lf_alloc(struct rvu *rvu, struct sso_lf_alloc_req *req,
				  struct sso_lf_alloc_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int ssolf, uniq_ident, rc = 0;
	struct rvu_pfvf *pfvf;
	int hwgrp, blkaddr;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (pfvf->sso <= 0 || blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	if (!pfvf->sso_uniq_ident) {
		uniq_ident = rvu_alloc_rsrc(&hw->sso.pfvf_ident);
		if (uniq_ident < 0) {
			rc = SSO_AF_ERR_AF_LF_ALLOC;
			goto exit;
		}
		pfvf->sso_uniq_ident = uniq_ident;
	} else {
		uniq_ident = pfvf->sso_uniq_ident;
	}

	/* Set threshold for the In-Unit Accounting Index*/
	rvu_write64(rvu, blkaddr, SSO_AF_IU_ACCNTX_CFG(uniq_ident),
		    SSO_AF_HWGRP_IU_ACCNT_MAX_THR << 16);

	for (hwgrp = 0; hwgrp < req->hwgrps; hwgrp++) {
		ssolf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, hwgrp);
		if (ssolf < 0)
			return SSO_AF_ERR_LF_INVALID;

		/* All groups assigned to single SR-IOV function must be
		 * assigned same unique in-unit accounting index.
		 */
		rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_IU_ACCNT(ssolf),
			    0x10000 | uniq_ident);

		/* Assign unique tagspace */
		rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_TAGSPACE(ssolf),
			    uniq_ident);
	}

exit:
	rsp->xaq_buf_size = hw->sso.sso_xaq_buf_size;
	rsp->xaq_wq_entries = hw->sso.sso_xaq_num_works;
	rsp->in_unit_entries = hw->sso.sso_iue;
	rsp->hwgrps = hw->sso.sso_hwgrps;
	return rc;
}

int rvu_mbox_handler_sso_lf_free(struct rvu *rvu, struct sso_lf_free_req *req,
				 struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int hwgrp, lf, err, blkaddr;
	struct rvu_pfvf *pfvf;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	/* Perform reset of SSO HW GRPs */
	for (hwgrp = 0; hwgrp < req->hwgrps; hwgrp++) {
		lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, hwgrp);
		if (lf < 0)
			return SSO_AF_ERR_LF_INVALID;

		err = rvu_sso_lf_teardown(rvu, lf);
		if (err)
			return err;

		/* Reset this SSO LF */
		err = rvu_lf_reset(rvu, &hw->block[blkaddr], lf);
		if (err)
			dev_err(rvu->dev, "SSO%d free: failed to reset\n", lf);
		/* Reset the IAQ and TAQ thresholds */
		rvu_sso_hwgrp_config_thresh(rvu, blkaddr, lf);
	}

	if (pfvf->sso_uniq_ident) {
		rvu_free_rsrc(&hw->sso.pfvf_ident, pfvf->sso_uniq_ident);
		pfvf->sso_uniq_ident = 0;
	}

	return 0;
}

int rvu_mbox_handler_sso_ws_cache_inv(struct rvu *rvu, struct msg_req *req,
				      struct msg_rsp *rsp)
{
	int num_lfs, ssowlf, hws, blkaddr;
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSOW, pcifunc);
	if (blkaddr < 0)
		return SSOW_AF_ERR_LF_INVALID;

	block = &hw->block[blkaddr];

	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->type);
	if (!num_lfs)
		return SSOW_AF_ERR_LF_INVALID;

	/* SSO HWS invalidate registers are part of SSO AF */
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, pcifunc);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	for (hws = 0; hws < num_lfs; hws++) {
		ssowlf = rvu_get_lf(rvu, block, pcifunc, hws);
		if (ssowlf < 0)
			return SSOW_AF_ERR_LF_INVALID;

		/* Reset this SSO LF GWS cache */
		rvu_write64(rvu, blkaddr, SSO_AF_HWSX_INV(ssowlf), 1);
	}

	return 0;
}

int rvu_mbox_handler_ssow_lf_alloc(struct rvu *rvu,
				   struct ssow_lf_alloc_req *req,
				   struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_pfvf *pfvf;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	if (pfvf->ssow <= 0)
		return SSOW_AF_ERR_LF_INVALID;

	return 0;
}

int rvu_mbox_handler_ssow_lf_free(struct rvu *rvu,
				  struct ssow_lf_free_req *req,
				  struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int ssowlf, hws, err, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSOW, pcifunc);
	if (blkaddr < 0)
		return SSOW_AF_ERR_LF_INVALID;

	for (hws = 0; hws < req->hws; hws++) {
		ssowlf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, hws);
		if (ssowlf < 0)
			return SSOW_AF_ERR_LF_INVALID;

		err = rvu_ssow_lf_teardown(rvu, ssowlf);
		if (err)
			return err;

		/* Reset this SSO LF */
		err = rvu_lf_reset(rvu, &hw->block[blkaddr], ssowlf);
		if (err)
			dev_err(rvu->dev, "SSOW%d free: failed to reset\n",
				ssowlf);
	}

	return 0;
}

int rvu_sso_init(struct rvu *rvu)
{
	u64 iaq_free_cnt, iaq_rsvd, iaq_max, iaq_rsvd_cnt = 0;
	u64 taq_free_cnt, taq_rsvd, taq_max, taq_rsvd_cnt = 0;
	struct sso_rsrc *sso = &rvu->hw->sso;
	int blkaddr, hwgrp, grpmsk, hws, err;
	u64 reg;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return 0;

	reg = rvu_read64(rvu, blkaddr, SSO_AF_CONST);
	/* number of SSO hardware work slots */
	sso->sso_hws = (reg >> 56) & 0xFF;
	/* number of SSO hardware groups */
	sso->sso_hwgrps = (reg & 0xFFFF);
	/* number of SSO In-Unit entries */
	sso->sso_iue =  (reg >> 16) & 0xFFFF;

	reg = rvu_read64(rvu, blkaddr, SSO_AF_CONST1);
	/* number of work entries in external admission queue (XAQ) */
	sso->sso_xaq_num_works = (reg >> 16) & 0xFFFF;
	/* number of bytes in a XAQ buffer */
	sso->sso_xaq_buf_size = (reg & 0xFFFF);

	/* Configure IAQ entries */
	reg = rvu_read64(rvu, blkaddr, SSO_AF_AW_WE);
	iaq_free_cnt = reg & SSO_AF_IAQ_FREE_CNT_MASK;

	/* Give out half of buffers fairly, rest left floating */
	iaq_rsvd = iaq_free_cnt / sso->sso_hwgrps / 2;

	/* Enforce minimum per hardware requirements */
	if (iaq_rsvd < SSO_HWGRP_IAQ_RSVD_THR)
		iaq_rsvd = SSO_HWGRP_IAQ_RSVD_THR;
	/* To ensure full streaming performance should be at least 208. */
	iaq_max = iaq_rsvd + SSO_HWGRP_IAQ_MAX_THR_STRM_PERF;

	if (iaq_max >= (SSO_AF_IAQ_FREE_CNT_MAX + 1))
		iaq_max = SSO_AF_IAQ_FREE_CNT_MAX;

	/* Configure TAQ entries */
	reg = rvu_read64(rvu, blkaddr, SSO_AF_TAQ_CNT);
	taq_free_cnt = reg & SSO_AF_TAQ_FREE_CNT_MASK;

	/* Give out half of buffers fairly, rest left floating */
	taq_rsvd = taq_free_cnt / sso->sso_hwgrps / 2;

	/* Enforce minimum per hardware requirements */
	if (taq_rsvd < SSO_HWGRP_TAQ_RSVD_THR)
		taq_rsvd = SSO_HWGRP_TAQ_RSVD_THR;
	/* To ensure full streaming performance should be at least 16. */
	taq_max = taq_rsvd + SSO_HWGRP_TAQ_MAX_THR_STRM_PERF;

	if (taq_max >= (SSO_AF_TAQ_FREE_CNT_MAX + 1))
		taq_max = SSO_AF_TAQ_FREE_CNT_MAX;

	/* Save thresholds to reprogram HWGRPs on reset */
	sso->iaq_rsvd = iaq_rsvd;
	sso->iaq_max = iaq_max;
	sso->taq_rsvd = taq_rsvd;
	sso->taq_max = taq_max;

	for (hwgrp = 0; hwgrp < sso->sso_hwgrps; hwgrp++) {
		rvu_sso_hwgrp_config_thresh(rvu, blkaddr, hwgrp);
		iaq_rsvd_cnt += iaq_rsvd;
		taq_rsvd_cnt += taq_rsvd;
	}

	/* Verify SSO_AW_WE[RSVD_FREE], TAQ_CNT[RSVD_FREE] are greater than
	 * or equal to sum of IAQ[RSVD_THR], TAQ[RSRVD_THR] fields.
	 */
	reg = rvu_read64(rvu, blkaddr, SSO_AF_AW_WE);
	reg = (reg >> SSO_AF_IAQ_RSVD_FREE_SHIFT) & SSO_AF_IAQ_RSVD_FREE_MASK;
	if (reg < iaq_rsvd_cnt) {
		dev_warn(rvu->dev, "WARN: Wrong IAQ resource calculations %llx vs %llx\n",
			 reg, iaq_rsvd_cnt);
		rvu_write64(rvu, blkaddr, SSO_AF_AW_WE,
			    (iaq_rsvd_cnt & SSO_AF_IAQ_RSVD_FREE_MASK) <<
			    SSO_AF_IAQ_RSVD_FREE_SHIFT);
	}

	reg = rvu_read64(rvu, blkaddr, SSO_AF_TAQ_CNT);
	reg = (reg >> SSO_AF_TAQ_RSVD_FREE_SHIFT) & SSO_AF_TAQ_RSVD_FREE_MASK;
	if (reg < taq_rsvd_cnt) {
		dev_warn(rvu->dev, "WARN: Wrong TAQ resource calculations %llx vs %llx\n",
			 reg, taq_rsvd_cnt);
		rvu_write64(rvu, blkaddr, SSO_AF_TAQ_CNT,
			    (taq_rsvd_cnt & SSO_AF_TAQ_RSVD_FREE_MASK) <<
			    SSO_AF_TAQ_RSVD_FREE_SHIFT);
	}

	/* Unset the HWS Hardware Group Mask.
	 * The hardware group mask should be set by PF/VF
	 * using SSOW_LF_GWS_GRPMSK_CHG based on the LF allocations.
	 */
	for (grpmsk = 0; grpmsk < (sso->sso_hwgrps / 64); grpmsk++) {
		for (hws = 0; hws < sso->sso_hws; hws++) {
			rvu_write64(rvu, blkaddr,
				    SSO_AF_HWSX_SX_GRPMSKX(hws, 0, grpmsk),
				    0x0);
			rvu_write64(rvu, blkaddr,
				    SSO_AF_HWSX_SX_GRPMSKX(hws, 1, grpmsk),
				    0x0);
		}
	}

	/* Allocate SSO_AF_CONST::HWS + 1. As the total number of pf/vf are
	 * limited by the numeber of HWS available.
	 */
	sso->pfvf_ident.max = sso->sso_hws + 1;
	err = rvu_alloc_bitmap(&sso->pfvf_ident);
	if (err)
		return err;

	/* Reserve one bit so that identifier starts from 1 */
	rvu_alloc_rsrc(&sso->pfvf_ident);

	return 0;
}

void rvu_sso_freemem(struct rvu *rvu)
{
	struct sso_rsrc *sso = &rvu->hw->sso;

	kfree(sso->pfvf_ident.bmap);
}
