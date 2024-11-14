// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "struct.h"
#include "../rvu.h"

void cpt_cn20k_rxc_time_cfg(struct rvu *rvu, int blkaddr,
			    struct cpt_rxc_time_cfg_req *req,
			    struct cpt_rxc_time_cfg_req *save)
{
	u16 qid = req->queue_id;
	u64 dfrg_reg;

	if (save) {
		/* Save older config */
		dfrg_reg = rvu_read64(rvu, blkaddr, CPT_AF_RXC_QUEX_DFRG(qid));
		save->zombie_thres = FIELD_GET(RXC_ZOMBIE_THRES, dfrg_reg);
		save->zombie_limit = FIELD_GET(RXC_ZOMBIE_LIMIT, dfrg_reg);
		save->active_thres = FIELD_GET(RXC_ACTIVE_THRES, dfrg_reg);
		save->active_limit = FIELD_GET(RXC_ACTIVE_LIMIT, dfrg_reg);

		save->step = rvu_read64(rvu, blkaddr, CPT_AF_RXC_TIME_CFG);
	}

	dfrg_reg = FIELD_PREP(RXC_ZOMBIE_THRES, req->zombie_thres);
	dfrg_reg |= FIELD_PREP(RXC_ZOMBIE_LIMIT, req->zombie_limit);
	dfrg_reg |= FIELD_PREP(RXC_ACTIVE_THRES, req->active_thres);
	dfrg_reg |= FIELD_PREP(RXC_ACTIVE_LIMIT, req->active_limit);

	rvu_write64(rvu, blkaddr, CPT_AF_RXC_TIME_CFG, req->step);
	rvu_write64(rvu, blkaddr, CPT_AF_RXC_QUEX_DFRG(qid), dfrg_reg);
}

void cpt_cn20k_rxc_teardown(struct rvu *rvu, u16 pcifunc, int blkaddr)
{
	struct cpt_rxc_time_cfg_req req, prev;
	struct rvu_cpt *cpt = &rvu->cpt;
	int timeout = 2000, queue_idx;
	u64 reg;

	/* Set time limit to minimum values, so that rxc entries will be
	 * flushed out quickly.
	 */
	req.step = 1;
	req.zombie_thres = 1;
	req.zombie_limit = 1;
	req.active_thres = 1;
	req.active_limit = 1;

	for_each_set_bit(queue_idx, cpt->cpt_rx_queue_bitmap,
			 CPT_AF_MAX_RXC_QUEUES) {
		/* Skip queues that don't match the given pcifunc, unless
		 * it's queue 0.
		 */
		if (cpt->cptpfvf_map[queue_idx] != pcifunc && queue_idx)
			continue;

		req.queue_id = queue_idx;
		prev.queue_id = queue_idx;

		cpt_cn20k_rxc_time_cfg(rvu, blkaddr, &req, &prev);

		do {
			reg = rvu_read64(rvu, blkaddr,
					 CPT_AF_RXC_QUEX_ACTIVE_STS(queue_idx));
			udelay(1);
			if (FIELD_GET(RXC_ACTIVE_COUNT, reg))
				timeout--;
			else
				break;
		} while (timeout);

		if (timeout == 0)
			dev_warn(rvu->dev,
				 "Poll for RXC active count hits hard loop counter\n");

		timeout = 2000;
		do {
			reg = rvu_read64(rvu, blkaddr,
					 CPT_AF_RXC_QUEX_ZOMBIE_STS(queue_idx));
			udelay(1);
			if (FIELD_GET(RXC_ZOMBIE_COUNT, reg))
				timeout--;
			else
				break;
		} while (timeout);

		if (timeout == 0)
			dev_warn(rvu->dev,
				 "Poll for RXC zombie count hits hard loop counter\n");

		/* Restore config */
		cpt_cn20k_rxc_time_cfg(rvu, blkaddr, &prev, NULL);

		/* Reset CPT_AF_RXC_QUE(0..15)_X2P(0..1)_LINK_CFG to default */
		reg = rvu_read64(rvu, blkaddr,
				 CPT_AF_RXC_QUEX_X2PX_LINK_CFG(queue_idx, 0));
		if (reg != RXC_QUEX_X2PX_LINK_CFG_DEFAUT)
			rvu_write64(rvu, blkaddr,
				    CPT_AF_RXC_QUEX_X2PX_LINK_CFG(queue_idx, 0),
				    RXC_QUEX_X2PX_LINK_CFG_DEFAUT);

		reg = rvu_read64(rvu, blkaddr,
				 CPT_AF_RXC_QUEX_X2PX_LINK_CFG(queue_idx, 1));
		if (reg != RXC_QUEX_X2PX_LINK_CFG_DEFAUT)
			rvu_write64(rvu, blkaddr,
				    CPT_AF_RXC_QUEX_X2PX_LINK_CFG(queue_idx, 1),
				    RXC_QUEX_X2PX_LINK_CFG_DEFAUT);

		/* Free queue: clear bit and reset mapping */
		__clear_bit(queue_idx, cpt->cpt_rx_queue_bitmap);
		cpt->cptpfvf_map[queue_idx] = 0;
	}
}

static int cpt_rx_inline_queue_cfg(struct rvu *rvu, int blkaddr, u8 cptlf,
				   struct cpt_rx_inline_qcfg_req *req)
{
	u8 pri_mask = otx2_cpt_que_pri_mask(rvu);
	u16 sso_pf_func = req->sso_pf_func;
	u8 nix_queue;
	u64 val;

	val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf));
	if (req->enable && (val & BIT_ULL(16))) {
		/* IPSec inline outbound path is already enabled for a given
		 * CPT LF, HRM states that inline inbound & outbound paths
		 * must not be enabled at the same time for a given CPT LF
		 */
		return CPT_AF_ERR_INLINE_IPSEC_INB_ENA;
	}

	/* Check if requested 'CPTLF <=> SSOLF' mapping is valid */
	if (sso_pf_func && !is_pffunc_map_valid(rvu, sso_pf_func, BLKTYPE_SSO))
		return CPT_AF_ERR_SSO_PF_FUNC_INVALID;

	/* Check if requested 'CPTLF <=> NIXLF' mapping is valid */
	if (req->nix_pf_func) {
		if (!is_pffunc_map_valid(rvu, req->nix_pf_func,
					 BLKTYPE_NIX))
			return CPT_AF_ERR_NIX_PF_FUNC_INVALID;
	}

	if (req->eng_grpmsk == 0x0)
		return CPT_AF_ERR_GRP_INVALID;

	if (req->queue_pri > pri_mask)
		return CPT_AF_ERR_PRI_INVALID;

	if (req->ctx_ilen > CPT_AF_MAX_CTX_ILEN)
		return CPT_AF_ERR_CTX_ILEN_INVALID;

	nix_queue = req->rx_queue_id;
	/* Enable CPT LF for IPsec inline inbound operations */
	if (req->enable)
		val |= BIT_ULL(9);
	else
		val &= ~BIT_ULL(9);

	if (req->pf_func_ctx)
		val |= BIT_ULL(20);
	else
		val &= ~BIT_ULL(20);

	val &= ~CPT_AF_ENG_GRPMASK;
	val |= FIELD_PREP(CPT_AF_ENG_GRPMASK, req->eng_grpmsk);
	val &= ~pri_mask;
	val |= FIELD_PREP(CPT_AF_QUEUE_PRI, req->queue_pri);
	val &= ~CPT_AF_INFLIGHT_LIMIT;
	val |= FIELD_PREP(CPT_AF_INFLIGHT_LIMIT, req->inflight_limit);
	if (req->ctx_ilen) {
		val &= ~CPT_AF_CTX_ILEN;
		val |= FIELD_PREP(CPT_AF_CTX_ILEN, req->ctx_ilen);
	} else {
		val &= ~CPT_AF_CTX_ILEN;
		val |= FIELD_PREP(CPT_AF_CTX_ILEN, CPT_CTX_ILEN);
	}
	val &= ~CPT_AF_RXC_QUEUE;
	val |= FIELD_PREP(CPT_AF_RXC_QUEUE, nix_queue);
	val &= ~CPT_AF_NIX_QUEUE;
	val |= FIELD_PREP(CPT_AF_NIX_QUEUE, nix_queue);
	rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), val);

	val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf));
	if (sso_pf_func) {
		/* Set SSO, and NIX_PF_FUNC */
		val &= ~(CPT_AF_SSO_PF_FUNC | CPT_AF_NIX_PF_FUNC);
		val |= FIELD_PREP(CPT_AF_SSO_PF_FUNC, req->sso_pf_func);
		val |= FIELD_PREP(CPT_AF_NIX_PF_FUNC, req->nix_pf_func);
	}
	if (req->pf_func_ctx) {
		val &= ~CPT_AF_CTX_PF_FUNC;
		val |= FIELD_PREP(CPT_AF_CTX_PF_FUNC, req->ctx_pf_func);
	}
	rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf), val);

	/* Configure the X2P Link register with the cpt base channel number and
	 * range of channels it should propagate to X2P
	 */
	val = (ilog2(NIX_CHAN_CPT_X2P_MASK + 1) << 16);
	val |= (u64)rvu->hw->cpt_chan_base;
	/* There is 1:1 mapping between RX, and RXC Queues */
	rvu_write64(rvu, blkaddr,
		    CPT_AF_RXC_QUEX_X2PX_LINK_CFG(nix_queue, 0), val);
	rvu_write64(rvu, blkaddr,
		    CPT_AF_RXC_QUEX_X2PX_LINK_CFG(nix_queue, 1), val);

	return 0;
}

int rvu_mbox_handler_cpt_rx_inl_queue_cfg(struct rvu *rvu,
					  struct cpt_rx_inline_qcfg_req *req,
					  struct msg_rsp *rsp)
{
	struct rvu_cpt *cpt = &rvu->cpt;
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	int cptlf, blkaddr;
	u16 actual_slot;

	if (!is_cn20k(rvu->pdev)) {
		dev_err(rvu->dev, "Mbox support is only for cn20k\n");
		return -EOPNOTSUPP;
	}

	if (req->rx_queue_id >= CPT_AF_MAX_RXC_QUEUES)
		return CPT_AF_ERR_RXC_QUEUE_INVALID;

	if (cpt->cptpfvf_map[req->rx_queue_id] != req->hdr.pcifunc)
		return CPT_AF_ERR_QUEUE_PCIFUNC_MAP_INVALID;

	blkaddr = rvu_get_blkaddr_from_slot(rvu, BLKTYPE_CPT, pcifunc,
					    req->slot, &actual_slot);
	if (blkaddr < 0)
		return CPT_AF_ERR_LF_INVALID;

	block = &rvu->hw->block[blkaddr];

	cptlf = rvu_get_lf(rvu, block, pcifunc, actual_slot);
	if (cptlf < 0)
		return CPT_AF_ERR_LF_INVALID;

	return cpt_rx_inline_queue_cfg(rvu, blkaddr, cptlf, req);
}

int rvu_mbox_handler_cpt_rx_inline_qalloc(struct rvu *rvu,
					  struct msg_req *req,
					  struct cpt_rx_inline_qalloc_rsp *rsp)
{
	struct rvu_cpt *cpt = &rvu->cpt;

	int index = find_first_zero_bit(cpt->cpt_rx_queue_bitmap,
					CPT_AF_MAX_RXC_QUEUES);
	if (index >= CPT_AF_MAX_RXC_QUEUES)
		return CPT_AF_ERR_RXC_QUEUE_INVALID;

	/* Flag the queue ID as allocated */
	set_bit(index, cpt->cpt_rx_queue_bitmap);

	cpt->cptpfvf_map[index] = req->hdr.pcifunc;
	rsp->rx_queue_id = index;

	return 0;
}

static void cpt_rx_qid_init(struct rvu *rvu)
{
	struct rvu_cpt *cpt = &rvu->cpt;

	bitmap_zero(cpt->cpt_rx_queue_bitmap, CPT_AF_MAX_RXC_QUEUES);

	/* Queue 0 is reserved for Global LF, that is allocated via CPT
	 * PF, and can be used by RVU netdev.
	 */
	set_bit(0, cpt->cpt_rx_queue_bitmap);
}

void rvu_cn20k_cpt_init(struct rvu *rvu)
{
	cpt_rx_qid_init(rvu);
}
