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
#include <linux/bitfield.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "rvu.h"

#define TIM_CHUNKSIZE_MULTIPLE	(16)
#define TIM_CHUNKSIZE_MIN	(TIM_CHUNKSIZE_MULTIPLE * 0x2)
#define TIM_CHUNKSIZE_MAX	(TIM_CHUNKSIZE_MULTIPLE * 0x1FFF)

static inline u64 get_tenns_tsc(void)
{
	u64 tsc;

#if defined(CONFIG_ARM64)
	asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
#endif
	return tsc;
}

static inline u64 get_tenns_clk(void)
{
	u64 tsc;

#if defined(CONFIG_ARM64)
	asm volatile("mrs %0, cntfrq_el0" : "=r" (tsc));
#endif
	return tsc;
}

static int rvu_tim_disable_lf(struct rvu *rvu, int lf, int blkaddr)
{
	u64 regval;

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
	int lf, blkaddr;
	u32 intervalmin;
	u64 regval;

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

	switch (req->clocksource) {
	case TIM_CLK_SRCS_TENNS:
		intervalmin = 256;
		break;
	case TIM_CLK_SRCS_GPIO:
		intervalmin = 256;
		break;
	case TIM_CLK_SRCS_GTI:
	case TIM_CLK_SRCS_PTP:
		intervalmin = 300;
		break;
	default:
		return TIM_AF_INVALID_CLOCK_SOURCE;
	}

	if (req->interval < intervalmin)
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

	/* CTL0 */
	/* EXPIRE_OFFSET = 0 and is set correctly when enabling. */
	regval = req->interval;
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL0(lf), regval);

	/* CTL1 */
	regval = (((u64)req->bigendian) << 53) |
		 (((u64)req->clocksource) << 51) |
		 (1ull << 48) | /* LOCK_EN */
		 (((u64)req->enableperiodic) << 45) |
		 (((u64)(req->enableperiodic ^ 1)) << 44) | /* ENA_LDWB */
		 (((u64)req->enabledontfreebuffer) << 43) |
		 (u64)(req->bucketsize - 1);
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf), regval);

	/* CTL2 */
	regval = ((u64)req->chunksize / TIM_CHUNKSIZE_MULTIPLE) << 40;
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL2(lf), regval);

	return 0;
}

int rvu_mbox_handler_tim_enable_ring(struct rvu *rvu,
				     struct tim_ring_req *req,
				     struct tim_enable_rsp *rsp)
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

	/* Error out if the ring is already running. */
	regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
	if (regval & TIM_AF_RINGX_CTL1_ENA)
		return TIM_AF_RING_STILL_RUNNING;

	/* Enable, the ring. */
	regval = rvu_read64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf));
	regval |= TIM_AF_RINGX_CTL1_ENA;
	rvu_write64(rvu, blkaddr, TIM_AF_RINGX_CTL1(lf), regval);

	rsp->timestarted = get_tenns_tsc();
	rsp->currentbucket = (regval >> 20) & 0xfffff;

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
	int lf, blkaddr;
	u8 gpio_edge;
	u64 regval;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, 0);
	if (blkaddr < 0)
		return 0;

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

	return 0;
}
