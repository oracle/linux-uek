//SPDX-License-Identifier: GPL-2.0
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

#if defined(CONFIG_ARM64)
#define rvu_sso_store_pair(val0, val1, addr) ({				\
	__asm__ volatile("stp %x[x0], %x[x1], [%x[p1]]"			\
			 :						\
			 :						\
			 [x0]"r"(val0), [x1]"r"(val1), [p1]"r"(addr));	\
	})
#else
#define rvu_sso_store_pair(val0, val1, addr)				\
	do {								\
		u64 *addr1 = (void *)addr;				\
		*addr1 = val0;						\
		*(u64 *)(((u8 *)addr1) + 8) = val1;			\
	} while (0)
#endif

#define SSO_AF_INT_DIGEST_PRNT(reg)					\
	for (i = 0; i < block->lf.max / 64; i++) {			\
		reg0 = rvu_read64(rvu, blkaddr, reg##X(i));		\
		dev_err(rvu->dev, #reg "(%d) : 0x%llx", i, reg0);	\
		rvu_write64(rvu, blkaddr, reg##X(i), reg0);		\
	}

void rvu_sso_hwgrp_config_thresh(struct rvu *rvu, int blkaddr, int lf)
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

static void rvu_sso_enable_aw_src(struct rvu *rvu, int lf_cnt, int sub_blkaddr,
				  u64 addr, int *lf_arr, u16 pcifunc, u8 shift,
				  u8 addr_off)
{
	u64 reg;
	int lf;

	for (lf = 0; lf < lf_cnt; lf++) {
		reg = rvu_read64(rvu, sub_blkaddr, addr |
				 lf_arr[lf] << addr_off);

		reg |= ((u64)pcifunc << shift);
		rvu_write64(rvu, sub_blkaddr, addr |
				lf_arr[lf] << addr_off, reg);
	}
}

static int rvu_sso_disable_aw_src(struct rvu *rvu, int **lf_arr,
				  int sub_blkaddr, u8 shift, u8 addr_off,
				  u16 pcifunc, u64 addr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int lf_cnt = 0, lf;
	u64 reg;

	if (sub_blkaddr >= 0) {
		block = &hw->block[sub_blkaddr];
		*lf_arr = kmalloc(block->lf.max * sizeof(int), GFP_KERNEL);
		if (!*lf_arr)
			return 0;

		for (lf = 0; lf < block->lf.max; lf++) {
			reg = rvu_read64(rvu, sub_blkaddr,
					 addr | lf << addr_off);
			if (((reg >> shift) & 0xFFFFul) != pcifunc)
				continue;

			reg &= ~(0xFFFFul << shift);
			rvu_write64(rvu, sub_blkaddr, addr | lf << addr_off,
				    reg);
			(*lf_arr)[lf_cnt] = lf;
			lf_cnt++;
		}
	}

	return lf_cnt;
}

static void rvu_sso_ggrp_taq_flush(struct rvu *rvu, u16 pcifunc, int lf,
				   int slot, int ssow_lf, u64 blkaddr,
				   u64 ssow_blkaddr)
{
	int nix_lf_cnt, cpt_lf_cnt, tim_lf_cnt;
	int *nix_lf, *cpt_lf, *tim_lf;
	u64 reg, val;

	/* Disable add work. */
	rvu_write64(rvu, blkaddr, SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_QCTL),
		    0);

	/* Disable all sources of work. */
	nix_lf = NULL;
	nix_lf_cnt = rvu_sso_disable_aw_src(rvu, &nix_lf,
					    rvu_get_blkaddr(rvu, BLKTYPE_NIX,
							    pcifunc),
					    NIX_AF_LF_SSO_PF_FUNC_SHIFT,
					    NIX_AF_LF_CFG_SHIFT, pcifunc,
					    NIX_AF_LFX_CFG(0));

	cpt_lf = NULL;
	cpt_lf_cnt = rvu_sso_disable_aw_src(rvu, &cpt_lf,
					    rvu_get_blkaddr(rvu, BLKTYPE_CPT,
							    0),
					    CPT_AF_LF_SSO_PF_FUNC_SHIFT,
					    CPT_AF_LF_CTL2_SHIFT, pcifunc,
					    CPT_AF_LFX_CTL2(0));

	tim_lf = NULL;
	tim_lf_cnt = rvu_sso_disable_aw_src(rvu, &tim_lf,
					    rvu_get_blkaddr(rvu, BLKTYPE_TIM,
							    0),
					    TIM_AF_RING_SSO_PF_FUNC_SHIFT,
					    TIM_AF_RING_GMCTL_SHIFT, pcifunc,
					    TIM_AF_RINGX_GMCTL(0));

	/* ZIP and DPI blocks not yet implemented. */

	/* Enable add work. */
	rvu_write64(rvu, blkaddr, SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_QCTL),
		    0x1);

	/* Prepare WS for GW operations. */
	do {
		reg = rvu_read64(rvu, ssow_blkaddr,
				 SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_TAG));
	} while (reg & BIT_ULL(63));

	if (reg & BIT_ULL(62))
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_DESCHED),
			    0x0);
	else if (((reg >> 32) & SSO_TT_EMPTY) != SSO_TT_EMPTY)
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_SWTAG_FLUSH),
			    0x0);

	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_GWC_INVAL), 0x0);
	/* Drain TAQ. */
	val = slot;
	val |= BIT_ULL(18);
	val |= BIT_ULL(16);

	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf));
	while ((reg >> 48) & 0x7FF) {
		rvu_write64(rvu, blkaddr,
			    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_OP_ADD_WORK1),
			    0x1 << 3);
get_work:
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_GET_WORK),
			    val);
		do {
			reg = rvu_read64(rvu, ssow_blkaddr,
					 SSOW_AF_BAR2_ALIASX(0,
							     SSOW_LF_GWS_TAG));
		} while (reg & BIT_ULL(63));

		if (!rvu_read64(rvu, ssow_blkaddr,
				SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_WQP)))
			goto get_work;

		reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_TAQ_THR(lf));
	}

	reg = rvu_read64(rvu, ssow_blkaddr,
			 SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_TAG));
	if (((reg >> 32) & SSO_TT_EMPTY) != SSO_TT_EMPTY)
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_SWTAG_FLUSH),
			    0x0);

	/* Disable add work. */
	rvu_write64(rvu, blkaddr, SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_QCTL),
		    0x0);

	/* restore all sources of work. */
	rvu_sso_enable_aw_src(rvu, nix_lf_cnt, rvu_get_blkaddr(rvu, BLKTYPE_NIX,
							       pcifunc),
			      NIX_AF_LFX_CFG(0), nix_lf, pcifunc,
			      NIX_AF_LF_SSO_PF_FUNC_SHIFT,
			      NIX_AF_LF_CFG_SHIFT);
	rvu_sso_enable_aw_src(rvu, cpt_lf_cnt, rvu_get_blkaddr(rvu, BLKTYPE_CPT,
							       0),
			      CPT_AF_LFX_CTL2(0), cpt_lf, pcifunc,
			      CPT_AF_LF_SSO_PF_FUNC_SHIFT,
			      CPT_AF_LF_CTL2_SHIFT);
	rvu_sso_enable_aw_src(rvu, tim_lf_cnt, rvu_get_blkaddr(rvu, BLKTYPE_TIM,
							       0),
			      TIM_AF_RINGX_GMCTL(0), tim_lf, pcifunc,
			      TIM_AF_RING_SSO_PF_FUNC_SHIFT,
			      TIM_AF_RING_GMCTL_SHIFT);

	kfree(nix_lf);
	kfree(cpt_lf);
	kfree(tim_lf);
}

int rvu_sso_lf_teardown(struct rvu *rvu, u16 pcifunc, int lf, int slot)
{
	int ssow_lf, iue, blkaddr, ssow_blkaddr, err;
	struct sso_rsrc *sso = &rvu->hw->sso;
	struct rvu_hwinfo *hw = rvu->hw;
	u64 aq_cnt, ds_cnt, cq_ds_cnt;
	u64 reg, add, wqp, val;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return SSO_AF_ERR_LF_INVALID;

	/* Enable BAR2 ALIAS for this pcifunc. */
	reg = BIT_ULL(16) | pcifunc;
	rvu_write64(rvu, blkaddr, SSO_AF_BAR2_SEL, reg);

	rvu_write64(rvu, blkaddr,
		    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_INT_THR), 0x0);
	rvu_write64(rvu, blkaddr,
		    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_AQ_THR),
		    SSO_LF_GGRP_AQ_THR_MASK);

	rvu_write64(rvu, blkaddr,
		    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_INT),
		    SSO_LF_GGRP_INT_MASK);
	rvu_write64(rvu, blkaddr,
		    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_INT_ENA_W1C),
		    SSO_LF_GGRP_INT_MASK);

	ssow_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSOW, 0);
	if (ssow_blkaddr < 0)
		goto af_cleanup;
	/* Check if LF is in slot 0, if not no HWS are attached. */
	ssow_lf = rvu_get_lf(rvu, &hw->block[ssow_blkaddr], pcifunc, 0);
	if (ssow_lf < 0)
		goto af_cleanup;

	rvu_write64(rvu, ssow_blkaddr, SSOW_AF_BAR2_SEL, reg);

	/* Ignore all interrupts */
	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_INT_ENA_W1C),
		    SSOW_LF_GWS_INT_MASK);
	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_INT),
		    SSOW_LF_GWS_INT_MASK);

	/* Prepare WS for GW operations. */
	rvu_poll_reg(rvu, ssow_blkaddr, SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_TAG),
		     BIT_ULL(63), true);

	reg = rvu_read64(rvu, ssow_blkaddr,
			 SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_TAG));
	if (reg & BIT_ULL(62))
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_DESCHED), 0);
	else if (((reg >> 32) & SSO_TT_EMPTY) != SSO_TT_EMPTY)
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_SWTAG_FLUSH),
			    0);

	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_GWC_INVAL), 0);

	/* Disable add work. */
	rvu_write64(rvu, blkaddr, SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_QCTL),
		    0x0);

	/* HRM 14.13.4 (4) */
	/* Clean up nscheduled IENT let the work flow. */
	for (iue = 0; iue < sso->sso_iue; iue++) {
		reg = rvu_read64(rvu, blkaddr, SSO_AF_IENTX_GRP(iue));
		if (SSO_AF_HWGRPX_IUEX_NOSCHED(lf, reg)) {
			wqp = rvu_read64(rvu, blkaddr, SSO_AF_IENTX_WQP(iue));
			rvu_sso_store_pair(wqp, iue, rvu->afreg_base +
					   ((ssow_blkaddr << 28) |
					    SSOW_AF_BAR2_ALIASX(0,
						  SSOW_LF_GWS_OP_CLR_NSCHED0)));
		}
	}

	/* HRM 14.13.4 (6) */
	/* Drain all the work using grouped gw. */
	aq_cnt = rvu_read64(rvu, blkaddr,
			    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_AQ_CNT));
	ds_cnt = rvu_read64(rvu, blkaddr,
			    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_MISC_CNT));
	cq_ds_cnt = rvu_read64(rvu, blkaddr,
			       SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_INT_CNT));
	cq_ds_cnt &= SSO_LF_GGRP_INT_CNT_MASK;

	val  = slot;		/* GGRP ID */
	val |= BIT_ULL(18);	/* Grouped */
	val |= BIT_ULL(16);	/* WAIT */

	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_NW_TIM),
		    SSOW_LF_GWS_MAX_NW_TIM);

	while (aq_cnt || cq_ds_cnt || ds_cnt) {
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_GET_WORK),
			    val);
		do {
			reg = rvu_read64(rvu, ssow_blkaddr,
					 SSOW_AF_BAR2_ALIASX(0,
							     SSOW_LF_GWS_TAG));
		} while (reg & BIT_ULL(63));
		if (((reg >> 32) & SSO_TT_EMPTY) != SSO_TT_EMPTY)
			rvu_write64(rvu, ssow_blkaddr,
				    SSOW_AF_BAR2_ALIASX(0,
						SSOW_LF_GWS_OP_SWTAG_FLUSH),
				    0x0);
		aq_cnt = rvu_read64(rvu, blkaddr,
				    SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_AQ_CNT)
				    );
		ds_cnt = rvu_read64(rvu, blkaddr,
				    SSO_AF_BAR2_ALIASX(slot,
						       SSO_LF_GGRP_MISC_CNT));
		cq_ds_cnt = rvu_read64(rvu, blkaddr,
				       SSO_AF_BAR2_ALIASX(slot,
							  SSO_LF_GGRP_INT_CNT));
		/* Extract cq and ds count */
		cq_ds_cnt &= SSO_LF_GGRP_INT_CNT_MASK;
	}

	/* Due to the Errata 35432, SSO doesn't release the partially consumed
	 * TAQ buffer used by HWGRP when HWGRP is reset. Use SW routine to
	 * drain it manually.
	 */
	if (is_rvu_96xx_B0(rvu))
		rvu_sso_ggrp_taq_flush(rvu, pcifunc, lf, slot, ssow_lf, blkaddr,
				       ssow_blkaddr);

	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_NW_TIM), 0x0);

	/* HRM 14.13.4 (7) */
	reg = rvu_read64(rvu, blkaddr,
			 SSO_AF_BAR2_ALIASX(slot, SSO_LF_GGRP_XAQ_CNT))
		& SSO_LF_GGRP_XAQ_CNT_MASK;
	if (reg != 0)
		dev_warn(rvu->dev,
			 "SSO_LF[%d]_GGRP_XAQ_CNT is %lld expected 0", lf, reg);

	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_PAGE_CNT(lf))
		& SSO_AF_HWGRP_PAGE_CNT_MASK;
	if (reg != 0)
		dev_warn(rvu->dev,
			 "SSO_AF_HWGRP[%d]_PAGE_CNT is %lld expected 0", lf,
			 reg);

	reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_IAQ_THR(lf))
		>> SSO_HWGRP_IAQ_GRP_CNT_SHIFT;
	reg &= SSO_HWGRP_IAQ_GRP_CNT_MASK;
	if (reg != 0)
		dev_warn(rvu->dev,
			 "SSO_AF_HWGRP[%d]_IAQ_THR is %lld expected 0", lf,
			 reg);
	rvu_write64(rvu, ssow_blkaddr, SSOW_AF_BAR2_SEL, 0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_INV(ssow_lf), 0x1);

af_cleanup:
	reg = rvu_read64(rvu, blkaddr, SSO_AF_UNMAP_INFO);
	if ((reg & 0xFFF) == pcifunc)
		rvu_write64(rvu, blkaddr, SSO_AF_ERR0, SSO_AF_ERR0_MASK);

	reg = rvu_read64(rvu, blkaddr, SSO_AF_UNMAP_INFO2);
	if ((reg & 0xFFF) == pcifunc)
		rvu_write64(rvu, blkaddr, SSO_AF_ERR2, SSO_AF_ERR2_MASK);

	rvu_write64(rvu, blkaddr, SSO_AF_POISONX(lf / 64), lf % 64);
	rvu_write64(rvu, blkaddr, SSO_AF_IU_ACCNTX_RST(lf), 0x1);

	err = rvu_poll_reg(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf),
			   SSO_HWGRP_AW_STS_NPA_FETCH, true);
	if (err)
		dev_warn(rvu->dev,
			 "SSO_HWGRP(%d)_AW_STATUS[NPA_FETCH] not cleared", lf);

	/* Remove all pointers from XAQ, HRM 14.13.6 */
	rvu_write64(rvu, blkaddr, SSO_AF_ERR0_ENA_W1C, ~0ULL);
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

	rvu_write64(rvu, blkaddr, SSO_AF_ERR0, ~0ULL);
	/* Re-enable error reporting once we're finished */
	rvu_write64(rvu, blkaddr, SSO_AF_ERR0_ENA_W1S, ~0ULL);

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

	rvu_write64(rvu, blkaddr, SSO_AF_BAR2_SEL, 0);

	return 0;
}

int rvu_ssow_lf_teardown(struct rvu *rvu, u16 pcifunc, int lf, int slot)
{
	int blkaddr, ssow_blkaddr;
	u64 reg;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return SSOW_AF_ERR_LF_INVALID;

	ssow_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSOW, 0);
	if (ssow_blkaddr < 0)
		return SSOW_AF_ERR_LF_INVALID;

	/* Enable BAR2 alias access. */
	reg = BIT_ULL(16) | pcifunc;
	rvu_write64(rvu, ssow_blkaddr, SSOW_AF_BAR2_SEL, reg);

	/* Ignore all interrupts */
	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_INT_ENA_W1C),
		    SSOW_LF_GWS_INT_MASK);
	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_INT),
		    SSOW_LF_GWS_INT_MASK);

	/* HRM 14.13.4 (3) */
	/* Wait till waitw/desched completes. */
	rvu_poll_reg(rvu, ssow_blkaddr,
		     SSOW_AF_BAR2_ALIASX(slot, SSOW_LF_GWS_PENDSTATE),
		     BIT_ULL(63) | BIT_ULL(58), true);

	reg = rvu_read64(rvu, ssow_blkaddr,
			 SSOW_AF_BAR2_ALIASX(slot, SSOW_LF_GWS_TAG));
	/* Switch Tag Pending */
	if (reg & BIT_ULL(62))
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(slot, SSOW_LF_GWS_OP_DESCHED),
			    0x0);
	/* Tag Type != EMPTY use swtag_flush to release tag-chain. */
	else if (((reg >> 32) & SSO_TT_EMPTY) != SSO_TT_EMPTY)
		rvu_write64(rvu, ssow_blkaddr,
			    SSOW_AF_BAR2_ALIASX(slot,
						SSOW_LF_GWS_OP_SWTAG_FLUSH),
			    0x0);

	/* Wait for desched to complete. */
	rvu_poll_reg(rvu, ssow_blkaddr,
		     SSOW_AF_BAR2_ALIASX(slot, SSOW_LF_GWS_PENDSTATE),
		     BIT_ULL(58), true);

	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_NW_TIM), 0x0);
	rvu_write64(rvu, ssow_blkaddr,
		    SSOW_AF_BAR2_ALIASX(0, SSOW_LF_GWS_OP_GWC_INVAL), 0x0);

	/* set SAI_INVAL bit */
	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_INV(lf), 0x1);
	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_ARB(lf), 0x0);
	rvu_write64(rvu, blkaddr, SSO_AF_HWSX_GMCTL(lf), 0x0);

	rvu_write64(rvu, ssow_blkaddr, SSOW_AF_BAR2_SEL, 0x0);

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

		reg = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_AW_STATUS(lf));
		if (reg & SSO_HWGRP_AW_STS_XAQ_BUFSC_MASK || reg & BIT_ULL(3)) {
			reg = rvu_read64(rvu, blkaddr,
					 SSO_AF_HWGRPX_AW_CFG(lf));
			reg = (reg & ~SSO_HWGRP_AW_CFG_RWEN) |
			       SSO_HWGRP_AW_CFG_XAQ_BYP_DIS;
			rvu_write64(rvu, blkaddr, SSO_AF_HWGRPX_AW_CFG(lf),
				    reg);

			reg = rvu_read64(rvu, blkaddr,
					 SSO_AF_HWGRPX_AW_STATUS(lf));
			if (reg & SSO_HWGRP_AW_STS_TPTR_VLD) {
				rvu_poll_reg(rvu, blkaddr,
					     SSO_AF_HWGRPX_AW_STATUS(lf),
					     SSO_HWGRP_AW_STS_NPA_FETCH, true);

				rvu_write64(rvu, blkaddr,
					    SSO_AF_HWGRPX_AW_STATUS(lf),
					    SSO_HWGRP_AW_STS_TPTR_VLD);
			}

			if (rvu_poll_reg(rvu, blkaddr,
					 SSO_AF_HWGRPX_AW_STATUS(lf),
					 SSO_HWGRP_AW_STS_XAQ_BUFSC_MASK, true))
				dev_warn(rvu->dev,
					 "SSO_HWGRP(%d)_AW_STATUS[XAQ_BUF_CACHED] not cleared",
					 lf);
		}

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

		err = rvu_sso_lf_teardown(rvu, pcifunc, lf, hwgrp);
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
					block->addr);
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

		err = rvu_ssow_lf_teardown(rvu, pcifunc, ssowlf, hws);
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

static int rvu_sso_do_register_interrupt(struct rvu *rvu, int irq_offs,
					 irq_handler_t handler,
					 const char *name)
{
	int ret = 0;

	ret = request_irq(pci_irq_vector(rvu->pdev, irq_offs), handler, 0,
			  name, rvu);
	if (ret) {
		dev_err(rvu->dev, "SSOAF: %s irq registration failed", name);
		goto err;
	}

	WARN_ON(rvu->irq_allocated[irq_offs]);
	rvu->irq_allocated[irq_offs] = true;
err:
	return ret;
}

static irqreturn_t rvu_sso_af_err0_intr_handler(int irq, void *ptr)
{
	struct rvu *rvu = (struct rvu *)ptr;
	struct rvu_block *block;
	int i, blkaddr;
	u64 reg, reg0;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	block = &rvu->hw->block[blkaddr];
	reg = rvu_read64(rvu, blkaddr, SSO_AF_ERR0);
	dev_err(rvu->dev, "Received SSO_AF_ERR0 irq : 0x%llx", reg);

	if (reg & BIT_ULL(15)) {
		dev_err(rvu->dev, "Received Bad-fill-packet NCB error");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_POISON)
	}

	if (reg & BIT_ULL(14)) {
		dev_err(rvu->dev, "An FLR was initiated, but SSO_LF_GGRP_AQ_CNT[AQ_CNT] != 0");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_FLR_AQ_DIGEST)
	}

	if (reg & BIT_ULL(13)) {
		dev_err(rvu->dev, "Add work dropped due to XAQ pointers not yet initialized.");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_XAQDIS_DIGEST)
	}

	if (reg & (0xF << 9)) {
		dev_err(rvu->dev, "PF_FUNC mapping error.");
		dev_err(rvu->dev, "SSO_AF_UNMAP_INFO : 0x%llx",
			rvu_read64(rvu, blkaddr, SSO_AF_UNMAP_INFO));
	}

	if (reg & BIT_ULL(8)) {
		dev_err(rvu->dev, "Add work dropped due to QTL being disabled, 0x0");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_QCTLDIS_DIGEST)
	}

	if (reg & BIT_ULL(7)) {
		dev_err(rvu->dev, "Add work dropped due to WQP being 0x0");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_WQP0_DIGEST)
	}

	if (reg & BIT_ULL(6))
		dev_err(rvu->dev, "Add work dropped due to 64 bit write");

	if (reg & BIT_ULL(5))
		dev_err(rvu->dev, "Set when received add work with tag type is specified as EMPTY");

	if (reg & BIT_ULL(4)) {
		dev_err(rvu->dev, "Add work to disabled hardware group. An ADDWQ was received and dropped to a hardware group with SSO_AF_HWGRP(0..255)_IAQ_THR[RSVD_THR] = 0.");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_GRPDIS_DIGEST)
	}

	if (reg & BIT_ULL(3)) {
		dev_err(rvu->dev, "Bad-fill-packet NCB error");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_BFPN_DIGEST)
	}

	if (reg & BIT_ULL(2)) {
		dev_err(rvu->dev, "Bad-fill-packet error.");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_BFP_DIGEST)
	}

	if (reg & BIT_ULL(1)) {
		dev_err(rvu->dev, "The NPA returned an error indication");
		SSO_AF_INT_DIGEST_PRNT(SSO_AF_NPA_DIGEST)
	}

	rvu_write64(rvu, blkaddr, SSO_AF_ERR0, reg);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_sso_af_err2_intr_handler(int irq, void *ptr)
{
	struct rvu *rvu = (struct rvu *)ptr;
	int blkaddr;
	u64 reg;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	reg = rvu_read64(rvu, blkaddr, SSO_AF_ERR2);
	dev_err(rvu->dev, "received SSO_AF_ERR2 irq : 0x%llx", reg);
	rvu_write64(rvu, blkaddr, SSO_AF_ERR2, reg);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_sso_af_ras_intr_handler(int irq, void *ptr)
{
	struct rvu *rvu = (struct rvu *)ptr;
	struct rvu_block *block;
	int i, blkaddr;
	u64 reg, reg0;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	block = &rvu->hw->block[blkaddr];

	reg = rvu_read64(rvu, blkaddr, SSO_AF_RAS);
	dev_err(rvu->dev, "received SSO_AF_RAS irq : 0x%llx", reg);
	rvu_write64(rvu, blkaddr, SSO_AF_RAS, reg);
	SSO_AF_INT_DIGEST_PRNT(SSO_AF_POISON)

	return IRQ_HANDLED;
}

void rvu_sso_unregister_interrupts(struct rvu *rvu)
{
	int i, blkaddr, offs;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return;

	offs = rvu_read64(rvu, blkaddr, SSO_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs)
		return;

	rvu_write64(rvu, blkaddr, SSO_AF_RAS_ENA_W1C, ~0ULL);
	rvu_write64(rvu, blkaddr, SSO_AF_ERR2_ENA_W1C, ~0ULL);
	rvu_write64(rvu, blkaddr, SSO_AF_ERR0_ENA_W1C, ~0ULL);

	for (i = 0; i < SSO_AF_INT_VEC_CNT; i++)
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), rvu);
			rvu->irq_allocated[offs + i] = false;
		}
}

int rvu_sso_register_interrupts(struct rvu *rvu)
{
	int blkaddr, offs, ret = 0;

	if (!is_block_implemented(rvu->hw, BLKADDR_SSO))
		return 0;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return blkaddr;

	offs = rvu_read64(rvu, blkaddr, SSO_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get SSO_AF_INT vector offsets\n");
		return 0;
	}

	ret = rvu_sso_do_register_interrupt(rvu, offs + SSO_AF_INT_VEC_ERR0,
					    rvu_sso_af_err0_intr_handler,
					    "SSO_AF_ERR0");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, SSO_AF_ERR0_ENA_W1S, ~0ULL);

	ret = rvu_sso_do_register_interrupt(rvu, offs + SSO_AF_INT_VEC_ERR2,
					    rvu_sso_af_err2_intr_handler,
					    "SSO_AF_ERR2");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, SSO_AF_ERR2_ENA_W1S, ~0ULL);

	ret = rvu_sso_do_register_interrupt(rvu, offs + SSO_AF_INT_VEC_RAS,
					    rvu_sso_af_ras_intr_handler,
					    "SSO_AF_RAS");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, SSO_AF_RAS_ENA_W1S, ~0ULL);

	return 0;
err:
	rvu_sso_unregister_interrupts(rvu);
	return ret;
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
				   SSO_AF_HWSX_SX_GRPMSKX(hws, 0, grpmsk), 0x0);
			rvu_write64(rvu, blkaddr,
				   SSO_AF_HWSX_SX_GRPMSKX(hws, 1, grpmsk), 0x0);
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
