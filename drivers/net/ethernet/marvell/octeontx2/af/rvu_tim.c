// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell.
 *
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/types.h>
#include <linux/bitfield.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "rvu.h"

#define TIM_CHUNKSIZE_MULTIPLE	(16)
#define TIM_CHUNKSIZE_MIN	(TIM_CHUNKSIZE_MULTIPLE * 0x2)
#define TIM_CHUNKSIZE_MAX	(TIM_CHUNKSIZE_MULTIPLE * 0x1FFF)

static inline u64 get_tenns_clk(void)
{
	u64 tsc = 0;

#if defined(CONFIG_ARM64)
	asm volatile("mrs %0, cntfrq_el0" : "=r" (tsc));
#endif
	return tsc;
}

static inline int tim_block_cn10k_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int lf, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, 0);
	if (blkaddr < 0)
		return blkaddr;
	hw->tim.ring_intvls = kmalloc_array(hw->block[blkaddr].lf.max,
					    sizeof(enum tim_ring_interval),
					    GFP_KERNEL);
	if (!hw->tim.ring_intvls)
		return -ENOMEM;

	for (lf = 0; lf < hw->block[blkaddr].lf.max; lf++)
		hw->tim.ring_intvls[lf] = TIM_INTERVAL_INVAL;
	hw->tim.rings_per_intvl[TIM_INTERVAL_1US] = 0;
	hw->tim.rings_per_intvl[TIM_INTERVAL_10US] = 0;
	hw->tim.rings_per_intvl[TIM_INTERVAL_1MS] = 0;

	return 0;
}

static inline void tim_cn10k_clear_intvl(struct rvu *rvu, int lf)
{
	struct tim_rsrc *tim = &rvu->hw->tim;

	if (tim->ring_intvls[lf] != TIM_INTERVAL_INVAL) {
		tim->rings_per_intvl[tim->ring_intvls[lf]]--;
		tim->ring_intvls[lf] = TIM_INTERVAL_INVAL;
	}
}

static inline void tim_cn10k_record_intvl(struct rvu *rvu, int lf,
					  u64 intervalns)
{
	struct tim_rsrc *tim = &rvu->hw->tim;
	enum tim_ring_interval intvl;

	tim_cn10k_clear_intvl(rvu, lf);

	if (intervalns < (u64)1E4)
		intvl = TIM_INTERVAL_1US;
	else if (intervalns < (u64)1E6)
		intvl = TIM_INTERVAL_10US;
	else
		intvl = TIM_INTERVAL_1MS;

	tim->ring_intvls[lf] = intvl;
	tim->rings_per_intvl[tim->ring_intvls[lf]]++;
}

static inline int tim_get_min_intvl(struct rvu *rvu, u8 clocksource,
				    u64 clockfreq, u64 *intvl_ns,
				    u64 *intvl_cyc)
{
	struct tim_rsrc *tim = &rvu->hw->tim;
	int intvl;

	if (is_rvu_otx2(rvu)) {
		switch (clocksource) {
		case TIM_CLK_SRCS_TENNS:
			intvl = 200;
			break;
		case TIM_CLK_SRCS_GPIO:
			intvl = 256;
			break;
		case TIM_CLK_SRCS_GTI:
		case TIM_CLK_SRCS_PTP:
			intvl = 300;
			break;
		default:
			return TIM_AF_INVALID_CLOCK_SOURCE;
		}

		*intvl_cyc = (u64)intvl;
	} else {
		if (tim->rings_per_intvl[TIM_INTERVAL_1US] < 8)
			intvl = (u64)1E3;
		else if (tim->rings_per_intvl[TIM_INTERVAL_10US] < 8)
			intvl = (u64)1E4;
		else
			intvl = (u64)1E6;

		*intvl_cyc = (u64)DIV_ROUND_UP(clockfreq * (intvl), (u64)1E9);
	}

	*intvl_ns = (u64)DIV_ROUND_UP((*intvl_cyc) * (u64)1E9, clockfreq);

	return 0;
}

static int rvu_tim_disable_lf(struct rvu *rvu, int lf, int blkaddr)
{
	u64 regval;

	if (!is_rvu_otx2(rvu))
		tim_cn10k_clear_intvl(rvu, lf);

	regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
	if ((regval & TIM_AF_RINGX_CTL1_ENA) == 0)
		return TIM_AF_RING_ALREADY_DISABLED;

	/* Clear TIM_AF_RING(0..255)_CTL1[ENA]. */
	regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
	regval &= ~TIM_AF_RINGX_CTL1_ENA;
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf), regval);

	/*
	 * Poll until the corresponding ring’s
	 * TIM_AF_RING(0..255)_CTL1[RCF_BUSY] is clear.
	 */
	rvu_poll_reg(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf),
			TIM_AF_RINGX_CTL1_RCF_BUSY, true);

	return 0;
}

int rvu_mbox_handler_tim_get_min_intvl(struct rvu *rvu,
				       struct tim_intvl_req *req,
				       struct tim_intvl_rsp *rsp)
{
	if (!req->clockfreq)
		return TIM_AF_INVALID_CLOCK_SOURCE;

	return tim_get_min_intvl(rvu, req->clocksource, req->clockfreq,
				 &rsp->intvl_ns, &rsp->intvl_cyc);
}

int rvu_mbox_handler_tim_lf_alloc(struct rvu *rvu,
				  struct tim_lf_alloc_req *req,
				  struct tim_lf_alloc_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr;
	u64 regval;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
	if (blkaddr < 0)
		return TIM_AF_LF_INVALID;

	lf = rvu_get_lf(rvu, &rvu->hw->block[blkaddr], pcifunc, req->ring);
	if (lf < 0)
		return TIM_AF_LF_INVALID;

	/* Check if requested 'TIMLF <=> NPALF' mapping is valid */
	if (req->npa_pf_func) {
		/* If default, use 'this' TIMLF's PFFUNC */
		if (req->npa_pf_func == RVU_DEFAULT_PF_FUNC)
			req->npa_pf_func = pcifunc;
		if (!is_pffunc_map_valid(rvu, req->npa_pf_func, BLKTYPE_NPA))
			return TIM_AF_INVAL_NPA_PF_FUNC;
	}

	/* Check if requested 'TIMLF <=> SSOLF' mapping is valid */
	if (req->sso_pf_func) {
		/* If default, use 'this' SSOLF's PFFUNC */
		if (req->sso_pf_func == RVU_DEFAULT_PF_FUNC)
			req->sso_pf_func = pcifunc;
		if (!is_pffunc_map_valid(rvu, req->sso_pf_func, BLKTYPE_SSO))
			return TIM_AF_INVAL_SSO_PF_FUNC;
	}

	regval = (((u64)req->npa_pf_func) << 16) |
		 ((u64)req->sso_pf_func);
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_GMCTL(lf), regval);

	rsp->tenns_clk = get_tenns_clk();

	return 0;
}

int rvu_mbox_handler_tim_lf_free(struct rvu *rvu,
				 struct tim_ring_req *req,
				 struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
	if (blkaddr < 0)
		return TIM_AF_LF_INVALID;

	lf = rvu_get_lf(rvu, &rvu->hw->block[blkaddr], pcifunc, req->ring);
	if (lf < 0)
		return TIM_AF_LF_INVALID;

	rvu_tim_lf_teardown(rvu, pcifunc, lf, req->ring);

	return 0;
}

int rvu_mbox_handler_tim_config_ring(struct rvu *rvu,
				     struct tim_config_req *req,
				     struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	u64 intvl_cyc, intvl_ns;
	int lf, blkaddr;
	u64 regval;
	int rc;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
	if (blkaddr < 0)
		return TIM_AF_LF_INVALID;

	lf = rvu_get_lf(rvu, &rvu->hw->block[blkaddr], pcifunc, req->ring);
	if (lf < 0)
		return TIM_AF_LF_INVALID;

	/* Check the inputs. */
	/* bigendian can only be 1 or 0. */
	if (req->bigendian & ~1)
		return TIM_AF_INVALID_BIG_ENDIAN_VALUE;

	/* enableperiodic can only be 1 or 0. */
	if (req->enableperiodic & ~1)
		return TIM_AF_INVALID_ENABLE_PERIODIC;

	/* enabledontfreebuffer can only be 1 or 0. */
	if (req->enabledontfreebuffer & ~1)
		return TIM_AF_INVALID_ENABLE_DONTFREE;

	/*
	 * enabledontfreebuffer needs to be true if enableperiodic
	 * is enabled.
	 */
	if (req->enableperiodic && !req->enabledontfreebuffer)
		return TIM_AF_ENA_DONTFRE_NSET_PERIODIC;


	/* bucketsize needs to between 2 and 2M (1<<20). */
	if (req->bucketsize < 2 || req->bucketsize > 1<<20)
		return TIM_AF_INVALID_BSIZE;

	if (req->chunksize % TIM_CHUNKSIZE_MULTIPLE)
		return TIM_AF_CSIZE_NOT_ALIGNED;

	if (req->chunksize < TIM_CHUNKSIZE_MIN)
		return TIM_AF_CSIZE_TOO_SMALL;

	if (req->chunksize > TIM_CHUNKSIZE_MAX)
		return TIM_AF_CSIZE_TOO_BIG;

	rc = tim_get_min_intvl(rvu, req->clocksource, req->clockfreq,
			       &intvl_ns, &intvl_cyc);
	if (rc)
		return rc;

	if (req->interval < intvl_cyc || req->intervalns < intvl_ns)
		return TIM_AF_INTERVAL_TOO_SMALL;

	/* Configure edge of GPIO clock source */
	if (req->clocksource == TIM_CLK_SRCS_GPIO &&
	    req->gpioedge < TIM_GPIO_INVALID) {
		regval = rvu_read64(rvu, blkaddr, TIM_AF_FLAGS_REG);
		if (FIELD_GET(TIM_AF_FLAGS_REG_GPIO_EDGE_MASK, regval) ==
		    TIM_GPIO_NO_EDGE && req->gpioedge == TIM_GPIO_NO_EDGE)
			return TIM_AF_GPIO_CLK_SRC_NOT_ENABLED;
		if (req->gpioedge != TIM_GPIO_NO_EDGE && req->gpioedge !=
		    FIELD_GET(TIM_AF_FLAGS_REG_GPIO_EDGE_MASK, regval)) {
			dev_info(rvu->dev,
				 "Change edge of GPIO input to %d from %lld.\n",
				 (int)req->gpioedge,
				 FIELD_GET(TIM_AF_FLAGS_REG_GPIO_EDGE_MASK,
					   regval));
			regval &= ~TIM_AF_FLAGS_REG_GPIO_EDGE_MASK;
			regval |= FIELD_PREP(TIM_AF_FLAGS_REG_GPIO_EDGE_MASK,
					     req->gpioedge);
			rvu_write64(rvu, blkaddr, TIM_AF_FLAGS_REG, regval);
		}
	}

	if (!is_rvu_otx2(rvu))
		tim_cn10k_record_intvl(rvu, lf, req->intervalns);

	/* CTL0 */
	/* EXPIRE_OFFSET = 0 and is set correctly when enabling. */
	regval = req->interval;
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL0(lf), regval);

	/* CTL1 */
	regval = (((u64)req->bigendian) << 53) |
		 (1ull << 48) | /* LOCK_EN */
		 (((u64)req->enableperiodic) << 45) |
		 (((u64)(req->enableperiodic ^ 1)) << 44) | /* ENA_LDWB */
		 (((u64)req->enabledontfreebuffer) << 43) |
		 (u64)(req->bucketsize - 1);
	if (is_rvu_otx2(rvu))
		regval |= (((u64)req->clocksource) << 51);
	else
		regval |= (((u64)req->clocksource) << 40);

	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf), regval);

	/* CTL2 */
	regval = ((u64)req->chunksize / TIM_CHUNKSIZE_MULTIPLE) << 40;
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL2(lf), regval);

	return 0;
}

static inline int tim_get_free_running_counter_offset(u64 *clk_src)
{
	switch (*clk_src) {
	case TIM_CLK_SRCS_TENNS:
		*clk_src = TIM_AF_FR_RN_TENNS;
		break;
	case TIM_CLK_SRCS_GPIO:
		*clk_src = TIM_AF_FR_RN_GPIOS;
		break;
	case TIM_CLK_SRCS_GTI:
		*clk_src = TIM_AF_FR_RN_GTI;
		break;
	case TIM_CLK_SRCS_PTP:
		*clk_src = TIM_AF_FR_RN_PTP;
		break;
	case TIM_CLK_SRCS_SYNCE:
		*clk_src = TIM_AF_FR_RN_SYNCE;
		break;
	case TIM_CLK_SRCS_BTS:
		*clk_src = TIM_AF_FR_RN_BTS;
		break;
	default:
		return TIM_AF_INVALID_CLOCK_SOURCE;
	}

	return 0;
}

int rvu_mbox_handler_tim_enable_ring(struct rvu *rvu,
				     struct tim_ring_req *req,
				     struct tim_enable_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	u64 start_cyc, end_cyc, low;
	u64 regval, clk_src;
	u32 expiry, intvl;
	int retries, ret;
	int lf, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
	if (blkaddr < 0)
		return TIM_AF_LF_INVALID;

	lf = rvu_get_lf(rvu, &rvu->hw->block[blkaddr], pcifunc, req->ring);
	if (lf < 0)
		return TIM_AF_LF_INVALID;

	/* Error out if the ring is already running. */
	regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
	if (regval & TIM_AF_RINGX_CTL1_ENA)
		return TIM_AF_RING_STILL_RUNNING;

	/* Enable, the ring. */
	regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
	/* Get the clock source. */
	if (is_rvu_otx2(rvu))
		clk_src = (regval >> 51) & 0x3;
	else
		clk_src = (regval >> 40) & 0x7;

	ret = tim_get_free_running_counter_offset(&clk_src);
	if (ret)
		return ret;

	retries = 10;
	do {
		regval |= TIM_AF_RINGX_CTL1_ENA;
		regval &= ~GENMASK_ULL(39, 20);
		/* Make sure that below reads don't get hoisted out. */
		mb();
		start_cyc = rvu_read64(rvu, blkaddr, clk_src);
		rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf), regval);
		regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL0(lf));
		end_cyc = rvu_read64(rvu, blkaddr, clk_src);
		/* Make sure that above reads and writes complete. */
		mb();
		low = end_cyc & GENMASK_ULL(31, 0);
		start_cyc >>= 32;
		end_cyc >>= 32;
		if (start_cyc - end_cyc) {
			regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
			regval &= ~TIM_AF_RINGX_CTL1_ENA;
			rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf), regval);
			regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL0(lf));
			rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL0(lf),
				    regval & GENMASK_ULL(31, 0));
			regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
		}
	} while ((start_cyc - end_cyc) && retries--);

	if (!retries && (start_cyc - end_cyc))
		return TIM_AF_LF_START_SYNC_FAIL;

	expiry = regval >> 32;
	intvl = regval & GENMASK_ULL(31, 0);
	rsp->timestarted = (start_cyc << 32) | expiry;
	if (low > expiry)
		rsp->timestarted += BIT_ULL(32);
	rsp->timestarted -= intvl;
	rsp->currentbucket = 0;

	return 0;
}

int rvu_mbox_handler_tim_disable_ring(struct rvu *rvu,
				      struct tim_ring_req *req,
				      struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
	if (blkaddr < 0)
		return TIM_AF_LF_INVALID;

	lf = rvu_get_lf(rvu, &rvu->hw->block[blkaddr], pcifunc, req->ring);
	if (lf < 0)
		return TIM_AF_LF_INVALID;

	return rvu_tim_disable_lf(rvu, lf, blkaddr);
}

int rvu_tim_lf_teardown(struct rvu *rvu, u16 pcifunc, int lf, int slot)
{
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
	if (blkaddr < 0)
		return TIM_AF_LF_INVALID;

	/* Ensure TIM ring is disabled prior to clearing the mapping */
	rvu_tim_disable_lf(rvu, lf, blkaddr);

	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_GMCTL(lf), 0);

	return 0;
}

#define FOR_EACH_TIM_LF(lf)	\
for (lf = 0; lf < hw->block[BLKTYPE_TIM].lf.max; lf++)

int rvu_tim_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int lf, blkaddr, rc = 0;
	u8 gpio_edge;
	u64 regval;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, 0);
	if (blkaddr < 0)
		return 0;

	if (!is_rvu_otx2(rvu))
		rc = tim_block_cn10k_init(rvu);

	regval = rvu_read64(rvu, blkaddr, TIM_AF_FLAGS_REG);

	/* Disable the TIM block, if not already disabled. */
	if (regval & TIM_AF_FLAGS_REG_ENA_TIM) {
		/* Disable each ring(lf). */
		FOR_EACH_TIM_LF(lf) {
			regval = rvu_read64(rvu, blkaddr,
					    TIM_AF_RINGX_CTL1(lf));
			if (!(regval & TIM_AF_RINGX_CTL1_ENA))
				continue;

			rvu_tim_disable_lf(rvu, lf, blkaddr);
		}

		/* Disable the TIM block. */
		regval = rvu_read64(rvu, blkaddr, TIM_AF_FLAGS_REG);
		regval &= ~TIM_AF_FLAGS_REG_ENA_TIM;
		rvu_write64(rvu, blkaddr, TIM_AF_FLAGS_REG, regval);
	}

	/* Reset each LF. */
	FOR_EACH_TIM_LF(lf) {
		rvu_lf_reset(rvu, &hw->block[BLKTYPE_TIM], lf);
	}

	/* Reset the TIM block; getting a clean slate. */
	rvu_write64(rvu, blkaddr, TIM_AF_BLK_RST, 0x1);
	rvu_poll_reg(rvu, blkaddr, TIM_AF_BLK_RST, BIT_ULL(63), true);

	gpio_edge = TIM_GPIO_NO_EDGE;

	/* Enable TIM block. */
	regval = FIELD_PREP(TIM_AF_FLAGS_REG_GPIO_EDGE_MASK, gpio_edge) |
		 BIT_ULL(2) | /* RESET */
		 BIT_ULL(0); /* ENA_TIM */
	rvu_write64(rvu, blkaddr, TIM_AF_FLAGS_REG, regval);

	if(is_rvu_otx2(rvu))
		rvu_tim_hw_fixes(rvu, blkaddr);

	return rc;
}
