// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "common.h"
#include "mbox.h"
#include "rvu.h"
#include "cgx.h"
#include "rvu_fixes.h"

#define OTX2_MAX_CQ_CNT 64

struct nix_tx_stall {
	struct rvu *rvu;
	int blkaddr;
	int smq_count;
	int tl4_count;
	int tl3_count;
	int tl2_count;
	int sq_count;
	u16 *smq_tl2_map;
	u16 *tl4_tl2_map;
	u16 *tl3_tl2_map;
	u16 *tl2_tl1_map;
	u16 *sq_smq_map;
#define LINK_TYPE_SHIFT	7
#define EXPR_LINK(map)	(map & (1 << LINK_TYPE_SHIFT))
#define LINK_CHAN_SHIFT	8
#define	LINK_CHAN(map)	(map >> LINK_CHAN_SHIFT)
	u16  *tl2_link_map;
	u8  *nixlf_tl2_count;
	u64 *nixlf_poll_count;
	u64 *nixlf_stall_count;
	u64 *nlink_credits;		 /* Normal link credits */
	u64 poll_cntr;
	u64 stalled_cntr;
	int pse_link_bp_level;
	bool txsch_config_changed;
	struct mutex txsch_lock; /* To sync Tx SCHQ config update and poll */
	struct task_struct *poll_thread; /* Tx stall condition polling thread */
};

/* Tranmsit stall hw issue's workaround reads loads of registers
 * at frequent intervals, having barrier for every register access
 * will increase the cycles spent in stall detection. Hence using
 * relaxed counterparts.
 */
static inline void rvu_wr64(struct rvu *rvu, u64 block, u64 offset, u64 val)
{
	writeq_relaxed(val, rvu->afreg_base + ((block << 28) | offset));
}

static inline u64 rvu_rd64(struct rvu *rvu, u64 block, u64 offset)
{
	return readq_relaxed(rvu->afreg_base + ((block << 28) | offset));
}

/**
 * rvu_usleep_interruptible - sleep waiting for signals
 * @usecs: Time in microseconds to sleep for
 *
 * A replica of msleep_interruptable to reduce tx stall
 * poll interval.
 */
static unsigned long rvu_usleep_interruptible(unsigned int usecs)
{
	unsigned long timeout = usecs_to_jiffies(usecs) + 1;

	while (timeout && !signal_pending(current))
		timeout = schedule_timeout_interruptible(timeout);
	return jiffies_to_usecs(timeout);
}

void rvu_nix_txsch_lock(struct nix_hw *nix_hw)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;

	if (tx_stall)
		mutex_lock(&tx_stall->txsch_lock);
}

void rvu_nix_txsch_unlock(struct nix_hw *nix_hw)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;

	if (tx_stall)
		mutex_unlock(&tx_stall->txsch_lock);
}

void rvu_nix_txsch_config_changed(struct nix_hw *nix_hw)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;

	if (tx_stall)
		tx_stall->txsch_config_changed = true;
}

void rvu_nix_update_link_credits(struct rvu *rvu, int blkaddr,
				 int link, u64 ncredits)
{
	struct nix_tx_stall *tx_stall;
	struct nix_hw *nix_hw;

	nix_hw = get_nix_hw(rvu->hw, blkaddr);
	if (!nix_hw)
		return;

	tx_stall = nix_hw->tx_stall;
	if (!tx_stall)
		return;

	rvu_nix_txsch_lock(nix_hw);
	tx_stall->nlink_credits[link] = ncredits;
	rvu_nix_txsch_unlock(nix_hw);
}

void rvu_nix_update_sq_smq_mapping(struct rvu *rvu, int blkaddr, int nixlf,
				   u16 sq, u16 smq)
{
	struct nix_tx_stall *tx_stall;
	struct nix_hw *nix_hw;
	int sq_count;

	nix_hw = get_nix_hw(rvu->hw, blkaddr);
	if (!nix_hw)
		return;

	tx_stall = nix_hw->tx_stall;
	if (!tx_stall)
		return;

	sq_count = tx_stall->sq_count;

	rvu_nix_txsch_lock(nix_hw);
	tx_stall->sq_smq_map[nixlf * sq_count + sq] = smq;
	rvu_nix_txsch_unlock(nix_hw);
}

static void rvu_nix_scan_link_credits(struct rvu *rvu, int blkaddr,
				      struct nix_tx_stall *tx_stall)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u64 credits;
	int link;

	for (link = 0; link < (hw->cgx_links + hw->lbk_links); link++) {
		credits = rvu_rd64(rvu, blkaddr,
				   NIX_AF_TX_LINKX_NORM_CREDIT(link));
		tx_stall->nlink_credits[link] = credits;
	}
}

static void rvu_nix_scan_tl2_link_mapping(struct rvu *rvu,
					  struct nix_tx_stall *tx_stall,
					  int blkaddr, int tl2, int smq)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int link, chan;
	u64 link_cfg;

	for (link = 0; link < (hw->cgx_links + hw->lbk_links); link++) {
		link_cfg = rvu_rd64(rvu, blkaddr,
				    NIX_AF_TL3_TL2X_LINKX_CFG(tl2, link));
		if (!(link_cfg & BIT_ULL(12)))
			continue;

		/* Get channel of the LINK to which this TL2 is transmitting */
		chan = link_cfg & 0x3F;
		tx_stall->tl2_link_map[tl2] = chan << LINK_CHAN_SHIFT;

		/* Save link info */
		tx_stall->tl2_link_map[tl2] |= (link & 0x7F);

		/* Workaround assumes TL2 transmits to only one link.
		 * So assume the first link enabled is the only one.
		 */
		break;
	}
}

static bool is_sq_alloacted(struct rvu *rvu, struct rvu_pfvf *pfvf,
			    int blkaddr, int sq)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct admin_queue *aq;

	block = &hw->block[blkaddr];
	aq = block->aq;
	spin_lock(&aq->lock);
	if (test_bit(sq, pfvf->sq_bmap)) {
		spin_unlock(&aq->lock);
		return true;
	}
	spin_unlock(&aq->lock);
	return false;
}

static bool is_schq_allocated(struct rvu *rvu, struct nix_hw *nix_hw,
			      int lvl, int schq)
{
	struct nix_txsch *txsch = &nix_hw->txsch[lvl];

	mutex_lock(&rvu->rsrc_lock);
	if (test_bit(schq, txsch->schq.bmap)) {
		mutex_unlock(&rvu->rsrc_lock);
		return true;
	}
	mutex_unlock(&rvu->rsrc_lock);
	return false;
}

static bool is_sw_xoff_set(struct rvu *rvu, int blkaddr, int lvl, int schq)
{
	u64 cfg, swxoff_reg = 0x00;

	switch (lvl) {
	case NIX_TXSCH_LVL_MDQ:
		swxoff_reg = NIX_AF_MDQX_SW_XOFF(schq);
		break;
	case NIX_TXSCH_LVL_TL4:
		swxoff_reg = NIX_AF_TL4X_SW_XOFF(schq);
		break;
	case NIX_TXSCH_LVL_TL3:
		swxoff_reg = NIX_AF_TL3X_SW_XOFF(schq);
		break;
	case NIX_TXSCH_LVL_TL2:
		swxoff_reg = NIX_AF_TL2X_SW_XOFF(schq);
		break;
	case NIX_TXSCH_LVL_TL1:
		swxoff_reg = NIX_AF_TL1X_SW_XOFF(schq);
		break;
	}
	if (!swxoff_reg)
		return false;

	cfg = rvu_rd64(rvu, blkaddr, swxoff_reg);
	if (cfg & BIT_ULL(0))
		return true;

	return false;
}

static void rvu_nix_scan_txsch_hierarchy(struct rvu *rvu,
					 struct nix_hw *nix_hw, int blkaddr)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;
	struct rvu_hwinfo *hw = rvu->hw;
	struct nix_txsch *tl2_txsch;
	struct rvu_block *block;
	int tl4, tl3, tl2, tl1;
	int lf, smq, size;
	u16 pcifunc;
	u64 cfg;

	/* Clear previous mappings */
	size = sizeof(u16);
	memset(tx_stall->smq_tl2_map, U16_MAX, tx_stall->smq_count * size);
	memset(tx_stall->tl4_tl2_map, U16_MAX, tx_stall->tl4_count * size);
	memset(tx_stall->tl3_tl2_map, U16_MAX, tx_stall->tl3_count * size);
	memset(tx_stall->tl2_tl1_map, U16_MAX, tx_stall->tl2_count * size);
	memset(tx_stall->tl2_link_map, U16_MAX, tx_stall->tl2_count * size);

	for (smq = 0; smq < tx_stall->smq_count; smq++) {
		/* Skip SMQ if it's not assigned to any */
		if (!is_schq_allocated(rvu, nix_hw, NIX_TXSCH_LVL_SMQ, smq))
			continue;

		/* If SW_XOFF is set, ignore the scheduler queue */
		cfg = rvu_rd64(rvu, blkaddr, NIX_AF_SMQX_CFG(smq));
		if (cfg & BIT_ULL(50))
			continue;
		if (is_sw_xoff_set(rvu, blkaddr, NIX_TXSCH_LVL_MDQ, smq))
			continue;

		cfg = rvu_rd64(rvu, blkaddr, NIX_AF_MDQX_PARENT(smq));
		tl4 = (cfg >> 16) & 0x1FF;
		if (is_sw_xoff_set(rvu, blkaddr, NIX_TXSCH_LVL_TL4, tl4))
			continue;

		cfg = rvu_rd64(rvu, blkaddr, NIX_AF_TL4X_PARENT(tl4));
		tl3 = (cfg >> 16) & 0x1FF;
		if (is_sw_xoff_set(rvu, blkaddr, NIX_TXSCH_LVL_TL3, tl3))
			continue;

		cfg = rvu_rd64(rvu, blkaddr, NIX_AF_TL3X_PARENT(tl3));
		tl2 = (cfg >> 16) & 0x1FF;
		if (is_sw_xoff_set(rvu, blkaddr, NIX_TXSCH_LVL_TL2, tl2))
			continue;

		cfg = rvu_rd64(rvu, blkaddr, NIX_AF_TL2X_PARENT(tl2));
		tl1 = (cfg >> 16) & 0x1FF;
		if (is_sw_xoff_set(rvu, blkaddr, NIX_TXSCH_LVL_TL1, tl1))
			continue;

		tx_stall->smq_tl2_map[smq] = tl2;
		tx_stall->tl4_tl2_map[tl4] = tl2;
		tx_stall->tl3_tl2_map[tl3] = tl2;
		tx_stall->tl2_tl1_map[tl2] = tl1;
		rvu_nix_scan_tl2_link_mapping(rvu, tx_stall, blkaddr, tl2, smq);
	}

	/* Get count of TL2s attached to each NIXLF */
	tl2_txsch = &nix_hw->txsch[NIX_TXSCH_LVL_TL2];
	block = &hw->block[blkaddr];
	memset(tx_stall->nixlf_tl2_count, 0, block->lf.max * sizeof(u8));
	for (lf = 0; lf < block->lf.max; lf++) {
		mutex_lock(&rvu->rsrc_lock);
		if (!test_bit(lf, block->lf.bmap)) {
			mutex_unlock(&rvu->rsrc_lock);
			continue;
		}
		pcifunc = block->fn_map[lf];
		mutex_unlock(&rvu->rsrc_lock);

		for (tl2 = 0; tl2 < tx_stall->tl2_count; tl2++) {
			if (!is_schq_allocated(rvu, nix_hw,
					       NIX_TXSCH_LVL_TL2, tl2))
				continue;
			if (pcifunc == TXSCH_MAP_FUNC(tl2_txsch->pfvf_map[tl2]))
				tx_stall->nixlf_tl2_count[lf]++;
		}
	}
}

#define TX_OCTS 4
#define RVU_AF_BAR2_SEL			(0x9000000ull)
#define RVU_AF_BAR2_ALIASX(a, b)	(0x9100000ull | a << 12 | b)
#define	NIX_LF_SQ_OP_OCTS		(0xa10)

static bool is_sq_stalled(struct rvu *rvu, struct nix_hw *nix_hw, int smq)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;
	u64 btx_octs, atx_octs, cfg, incr;
	int sq_count = tx_stall->sq_count;
	struct rvu_hwinfo *hw = rvu->hw;
	int blkaddr = tx_stall->blkaddr;
	struct nix_txsch *smq_txsch;
	struct rvu_pfvf *pfvf;
	atomic64_t *ptr;
	int nixlf, sq;
	u16 pcifunc;

	smq_txsch = &nix_hw->txsch[NIX_TXSCH_LVL_SMQ];
	pcifunc = TXSCH_MAP_FUNC(smq_txsch->pfvf_map[smq]);
	nixlf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, 0);
	if (nixlf < 0)
		return false;

	/* If a NIXLF is transmitting pkts via only one TL2, then checking
	 * global NIXLF TX stats is sufficient.
	 */

	if (tx_stall->nixlf_tl2_count[nixlf] != 1)
		goto poll_sq_stats;

	tx_stall->nixlf_poll_count[nixlf]++;
	btx_octs = rvu_rd64(rvu, blkaddr, NIX_AF_LFX_TX_STATX(nixlf, TX_OCTS));
	usleep_range(50, 60);
	atx_octs = rvu_rd64(rvu, blkaddr, NIX_AF_LFX_TX_STATX(nixlf, TX_OCTS));
	if (btx_octs == atx_octs) {
		tx_stall->nixlf_stall_count[nixlf]++;
		return true;
	}
	return false;

poll_sq_stats:
	if (!tx_stall->nixlf_tl2_count[nixlf])
		return false;

	pfvf = rvu_get_pfvf(rvu, pcifunc);

	/* Enable BAR2 register access from AF BAR2 alias registers*/
	cfg = BIT_ULL(16) | pcifunc;
	rvu_wr64(rvu, blkaddr, RVU_AF_BAR2_SEL, cfg);

	for (sq = 0; sq < pfvf->sq_ctx->qsize; sq++) {
		if (!is_sq_alloacted(rvu, pfvf, blkaddr, sq))
			continue;

		rvu_nix_txsch_lock(nix_hw);
		if (tx_stall->sq_smq_map[nixlf * sq_count + sq] != smq) {
			rvu_nix_txsch_unlock(nix_hw);
			continue;
		}
		rvu_nix_txsch_unlock(nix_hw);

		incr = (u64)sq << 32;
		ptr = (__force atomic64_t *)(rvu->afreg_base + ((blkaddr << 28)
			| RVU_AF_BAR2_ALIASX(nixlf, NIX_LF_SQ_OP_OCTS)));

		btx_octs = atomic64_fetch_add_relaxed(incr, ptr);
		usleep_range(50, 60);
		atx_octs = atomic64_fetch_add_relaxed(incr, ptr);
		/* If atleast one SQ is transmitting pkts then SMQ is
		 * not stalled.
		 */
		if (btx_octs != atx_octs)
			return false;
	}
	tx_stall->nixlf_stall_count[nixlf]++;

	return true;
}

static bool rvu_nix_check_smq_stall(struct rvu *rvu, struct nix_hw *nix_hw,
				    int tl2)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;
	int blkaddr = tx_stall->blkaddr;
	u64 mdesc_cnt;
	int smq;

	for (smq = 0; smq < tx_stall->smq_count; smq++) {
		if (tx_stall->smq_tl2_map[smq] != tl2)
			continue;

		mdesc_cnt = rvu_rd64(rvu, blkaddr, NIX_AF_SMQX_STATUS(smq));
		if (!(mdesc_cnt & 0x7F))
			continue;
		if (is_sq_stalled(rvu, nix_hw, smq))
			return true;
	}
	return false;
}

static bool is_cgx_idle(u64 status, u8 link_map)
{
	if (EXPR_LINK(link_map))
		return status & CGXX_CMRX_TX_LMAC_E_IDLE;
	return status & CGXX_CMRX_TX_LMAC_IDLE;
}

static bool rvu_cgx_tx_idle(struct rvu *rvu, struct nix_hw *nix_hw,
			    struct nix_txsch *tl2_txsch, int tl2)
{
	unsigned long timeout = jiffies + usecs_to_jiffies(20);
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;
	u16 pcifunc, link_map;
	u8 cgx_id, lmac_id;
	u64 status;
	void *cgxd;
	int pf;

	pcifunc = TXSCH_MAP_FUNC(tl2_txsch->pfvf_map[tl2]);
	pf = rvu_get_pf(pcifunc);
	if (!is_pf_cgxmapped(rvu, pf))
		return false;

	rvu_get_cgx_lmac_id(rvu->pf2cgxlmac_map[pf], &cgx_id, &lmac_id);
	cgxd = rvu_cgx_pdata(cgx_id, rvu);
	if (!cgxd)
		return false;

	link_map = tx_stall->tl2_link_map[tl2];

	/* Wait for LMAC TX_IDLE */
	while (time_before(jiffies, timeout)) {
		status = cgx_get_lmac_tx_fifo_status(cgxd, lmac_id);
		if (is_cgx_idle(status, link_map))
			return true;
		usleep_range(1, 2);
	}
	return false;
}

static void rvu_nix_restore_tx(struct rvu *rvu, struct nix_hw *nix_hw,
			       int blkaddr, int tl2)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;
	struct nix_txsch *tl2_txsch;
	int tl, link;

	link = tx_stall->tl2_link_map[tl2] & 0x7F;

	tx_stall->stalled_cntr++;

	tl2_txsch = &nix_hw->txsch[NIX_TXSCH_LVL_TL2];
	rvu_nix_txsch_lock(nix_hw);

	/* Set SW_XOFF for every TL2 queue which transmits to
	 * the associated link.
	 */
	for (tl = 0; tl < tx_stall->tl2_count; tl++) {
		if ((tx_stall->tl2_link_map[tl] & 0x7F) != link)
			continue;
		/* Full workaround is implemented assuming fixed 1:1
		 * TL3:TL2 mapping, ie TL3 and TL2 index can be used
		 * interchangeably. Hence except in this API, no other
		 * place we check for PSE backpressure level configured
		 * in NIX_AF_PSE_CHANNEL_LEVEL reg.
		 */
		if (tx_stall->pse_link_bp_level == NIX_TXSCH_LVL_TL2)
			rvu_wr64(rvu, blkaddr,
				 NIX_AF_TL2X_SW_XOFF(tl), BIT_ULL(0));
		else
			rvu_wr64(rvu, blkaddr,
				 NIX_AF_TL3X_SW_XOFF(tl), BIT_ULL(0));
	}
	usleep_range(20, 25);

	/* Wait for LMAC TX_IDLE */
	if (link < rvu->hw->cgx_links) {
		if (!rvu_cgx_tx_idle(rvu, nix_hw, tl2_txsch, tl2))
			goto clear_sw_xoff;
	}

	/* Restore link credits */
	rvu_wr64(rvu, blkaddr, NIX_AF_TX_LINKX_NORM_CREDIT(link),
		 tx_stall->nlink_credits[link]);

	/* Toggle SW_XOFF of every scheduler queue at every level
	 * which points to this TL2.
	 */
	for (tl = 0; tl < tx_stall->smq_count; tl++) {
		if (tx_stall->smq_tl2_map[tl] != tl2)
			continue;
		rvu_wr64(rvu, blkaddr, NIX_AF_MDQX_SW_XOFF(tl), BIT_ULL(0));
		rvu_wr64(rvu, blkaddr, NIX_AF_MDQX_SW_XOFF(tl), 0x00);
	}

	for (tl = 0; tl < tx_stall->tl4_count; tl++) {
		if (tx_stall->tl4_tl2_map[tl] != tl2)
			continue;
		rvu_wr64(rvu, blkaddr, NIX_AF_TL4X_SW_XOFF(tl), BIT_ULL(0));
		rvu_wr64(rvu, blkaddr, NIX_AF_TL4X_SW_XOFF(tl), 0x00);
	}

	for (tl = 0; tl < tx_stall->tl3_count; tl++) {
		if (tx_stall->tl3_tl2_map[tl] != tl2)
			continue;
		if (tx_stall->pse_link_bp_level == NIX_TXSCH_LVL_TL2) {
			rvu_wr64(rvu, blkaddr,
				 NIX_AF_TL3X_SW_XOFF(tl), BIT_ULL(0));
			rvu_wr64(rvu, blkaddr, NIX_AF_TL3X_SW_XOFF(tl), 0x00);
		} else {
			/* TL3 and TL2 indices used by this NIXLF are same */
			rvu_wr64(rvu, blkaddr,
				 NIX_AF_TL2X_SW_XOFF(tl), BIT_ULL(0));
			rvu_wr64(rvu, blkaddr, NIX_AF_TL2X_SW_XOFF(tl), 0x00);
		}
	}

clear_sw_xoff:
	/* Clear SW_XOFF of all TL2 queues, which are set above */
	for (tl = 0; tl < tx_stall->tl2_count; tl++) {
		if ((tx_stall->tl2_link_map[tl] & 0x7F) != link)
			continue;
		if (tx_stall->pse_link_bp_level == NIX_TXSCH_LVL_TL2)
			rvu_wr64(rvu, blkaddr, NIX_AF_TL2X_SW_XOFF(tl), 0x00);
		else
			rvu_wr64(rvu, blkaddr, NIX_AF_TL3X_SW_XOFF(tl), 0x00);
	}
	rvu_nix_txsch_unlock(nix_hw);
}

static bool is_link_backpressured(struct nix_tx_stall *tx_stall,
				  struct nix_hw *nix_hw,
				  int blkaddr, int tl2)
{
	struct rvu *rvu = tx_stall->rvu;
	struct nix_txsch *tl2_txsch;
	int pkt_cnt, unit_cnt;
	int link, chan;
	u64 cfg;

	/* Skip uninitialized ones */
	if (tx_stall->tl2_link_map[tl2] == U16_MAX)
		return true;

	link = tx_stall->tl2_link_map[tl2] & 0x7F;
	chan = LINK_CHAN(tx_stall->tl2_link_map[tl2]);

	cfg = rvu_rd64(rvu, blkaddr, NIX_AF_TX_LINKX_HW_XOFF(link));
	if (cfg & BIT_ULL(chan))
		return true;

	/* Skip below checks for LBK links */
	if (link >= rvu->hw->cgx_links)
		return false;

	cfg = rvu_rd64(rvu, blkaddr, NIX_AF_TX_LINKX_NORM_CREDIT(link));

	/* Check if current credits or pkt count is -ve or simply
	 * morethan what is configured.
	 */
	pkt_cnt = (cfg >> 2) & 0x3FF;
	unit_cnt = (cfg >> 12) & 0xFFFFF;
	if (pkt_cnt > ((tx_stall->nlink_credits[link] >> 2) & 0x3FF) ||
	    unit_cnt > ((tx_stall->nlink_credits[link] >> 12) & 0xFFFFF)) {
		return false;
	}

	tl2_txsch = &nix_hw->txsch[NIX_TXSCH_LVL_TL2];
	if (rvu_cgx_tx_idle(rvu, nix_hw, tl2_txsch, tl2))
		return false;

	return true;
}

static int rvu_nix_poll_for_tx_stall(void *arg)
{
	struct nix_tx_stall *tx_stall = arg;
	struct rvu *rvu = tx_stall->rvu;
	int blkaddr = tx_stall->blkaddr;
	struct nix_hw *nix_hw;
	int tl2;

	nix_hw = get_nix_hw(rvu->hw, blkaddr);
	if (!nix_hw)
		return -EINVAL;

	while (!kthread_should_stop()) {
		for (tl2 = 0; tl2 < tx_stall->tl2_count; tl2++) {
			/* Skip TL2 if it's not assigned to any */
			if (!is_schq_allocated(rvu, nix_hw,
					       NIX_TXSCH_LVL_TL2, tl2))
				continue;

			tx_stall->poll_cntr++;

			if (tx_stall->txsch_config_changed) {
				rvu_nix_txsch_lock(nix_hw);
				rvu_nix_scan_txsch_hierarchy(rvu, nix_hw,
							     blkaddr);
				tx_stall->txsch_config_changed = false;
				rvu_nix_txsch_unlock(nix_hw);
			}

			rvu_nix_txsch_lock(nix_hw);
			if (is_link_backpressured(tx_stall, nix_hw,
						  blkaddr, tl2)) {
				rvu_nix_txsch_unlock(nix_hw);
				continue;
			}
			rvu_nix_txsch_unlock(nix_hw);

			if (!rvu_nix_check_smq_stall(rvu, nix_hw, tl2))
				continue;

			rvu_nix_restore_tx(rvu, nix_hw, blkaddr, tl2);
		}
		rvu_usleep_interruptible(250);
	}

	return 0;
}

static int rvu_nix_init_tl_map(struct rvu *rvu, struct nix_hw *nix_hw, int lvl)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;
	struct nix_txsch *txsch;
	u16 *tl_map;

	txsch = &nix_hw->txsch[lvl];
	tl_map = devm_kcalloc(rvu->dev, txsch->schq.max,
			      sizeof(u16), GFP_KERNEL);
	if (!tl_map)
		return -ENOMEM;

	switch (lvl) {
	case NIX_TXSCH_LVL_SMQ:
		tx_stall->smq_count = txsch->schq.max;
		tx_stall->smq_tl2_map = tl_map;
		break;
	case NIX_TXSCH_LVL_TL4:
		tx_stall->tl4_count = txsch->schq.max;
		tx_stall->tl4_tl2_map = tl_map;
		break;
	case NIX_TXSCH_LVL_TL3:
		tx_stall->tl3_count = txsch->schq.max;
		tx_stall->tl3_tl2_map = tl_map;
		break;
	case NIX_TXSCH_LVL_TL2:
		tx_stall->tl2_count = txsch->schq.max;
		tx_stall->tl2_tl1_map = tl_map;
		break;
	}
	memset(tl_map, U16_MAX, txsch->schq.max * sizeof(u16));
	return 0;
}

static int rvu_nix_tx_stall_workaround_init(struct rvu *rvu,
					    struct nix_hw *nix_hw, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct nix_tx_stall *tx_stall;
	struct rvu_block *block;
	int links, err;

	if (!hw->cap.nix_fixed_txschq_mapping)
		return 0;

	tx_stall = devm_kzalloc(rvu->dev,
				sizeof(struct nix_tx_stall), GFP_KERNEL);
	if (!tx_stall)
		return -ENOMEM;

	tx_stall->blkaddr = blkaddr;
	tx_stall->rvu = rvu;
	nix_hw->tx_stall = tx_stall;

	/* Get the level at which link/chan will assert backpressure */
	if (rvu_read64(rvu, blkaddr, NIX_AF_PSE_CHANNEL_LEVEL))
		tx_stall->pse_link_bp_level = NIX_TXSCH_LVL_TL3;
	else
		tx_stall->pse_link_bp_level = NIX_TXSCH_LVL_TL2;

	mutex_init(&tx_stall->txsch_lock);

	/* Alloc memory for saving SMQ/TL4/TL3/TL1 to TL2 mapping */
	err = rvu_nix_init_tl_map(rvu, nix_hw, NIX_TXSCH_LVL_SMQ);
	if (err)
		return err;
	err = rvu_nix_init_tl_map(rvu, nix_hw, NIX_TXSCH_LVL_TL4);
	if (err)
		return err;
	err = rvu_nix_init_tl_map(rvu, nix_hw, NIX_TXSCH_LVL_TL3);
	if (err)
		return err;
	err = rvu_nix_init_tl_map(rvu, nix_hw, NIX_TXSCH_LVL_TL2);
	if (err)
		return err;

	block = &hw->block[blkaddr];
	tx_stall->sq_count = min_t(int, num_online_cpus(), OTX2_MAX_CQ_CNT);

	/* SMQs to nixlf SQ mapping info */
	tx_stall->sq_smq_map = devm_kcalloc(rvu->dev,
					    block->lf.max * tx_stall->sq_count,
					    sizeof(u16), GFP_KERNEL);
	if (!tx_stall->sq_smq_map)
		return -ENOMEM;
	memset(tx_stall->sq_smq_map, U16_MAX,
	       block->lf.max * tx_stall->sq_count * sizeof(u16));

	/* TL2 to transmit link mapping info */
	tx_stall->tl2_link_map = devm_kcalloc(rvu->dev, tx_stall->tl2_count,
					      sizeof(u16), GFP_KERNEL);
	if (!tx_stall->tl2_link_map)
		return -ENOMEM;
	memset(tx_stall->tl2_link_map, U16_MAX,
	       tx_stall->tl2_count * sizeof(u16));

	/* Number of Tl2s attached to NIXLF */
	tx_stall->nixlf_tl2_count = devm_kcalloc(rvu->dev, block->lf.max,
						 sizeof(u8), GFP_KERNEL);
	if (!tx_stall->nixlf_tl2_count)
		return -ENOMEM;
	memset(tx_stall->nixlf_tl2_count, 0, block->lf.max * sizeof(u8));

	/* Per NIXLF poll and stall counters */
	tx_stall->nixlf_poll_count = devm_kcalloc(rvu->dev, block->lf.max,
						  sizeof(u64), GFP_KERNEL);
	if (!tx_stall->nixlf_poll_count)
		return -ENOMEM;
	memset(tx_stall->nixlf_poll_count, 0, block->lf.max * sizeof(u64));

	tx_stall->nixlf_stall_count = devm_kcalloc(rvu->dev, block->lf.max,
						   sizeof(u64), GFP_KERNEL);
	if (!tx_stall->nixlf_stall_count)
		return -ENOMEM;
	memset(tx_stall->nixlf_stall_count, 0, block->lf.max * sizeof(u64));

	/* For saving HW link's transmit credits config */
	links = rvu->hw->cgx_links + rvu->hw->lbk_links;
	tx_stall->nlink_credits = devm_kcalloc(rvu->dev, links,
					       sizeof(u64), GFP_KERNEL);
	if (!tx_stall->nlink_credits)
		return -ENOMEM;
	rvu_nix_scan_link_credits(rvu, blkaddr, tx_stall);

	tx_stall->poll_thread = kthread_create(rvu_nix_poll_for_tx_stall,
					       (void *)tx_stall,
					       "nix_tx_stall_polling_kthread");
	if (IS_ERR(tx_stall->poll_thread))
		return PTR_ERR(tx_stall->poll_thread);

	kthread_bind(tx_stall->poll_thread, cpumask_first(cpu_online_mask));
	wake_up_process(tx_stall->poll_thread);
	return 0;
}

static void rvu_nix_tx_stall_workaround_exit(struct rvu *rvu,
					     struct nix_hw *nix_hw)
{
	struct nix_tx_stall *tx_stall = nix_hw->tx_stall;

	if (!tx_stall)
		return;

	if (tx_stall->poll_thread)
		kthread_stop(tx_stall->poll_thread);
	mutex_destroy(&tx_stall->txsch_lock);
}

ssize_t rvu_nix_get_tx_stall_counters(struct nix_hw *nix_hw,
				      char __user *buffer, loff_t *ppos)
{
	struct rvu *rvu = nix_hw->rvu;
	struct rvu_hwinfo *hw;
	struct nix_tx_stall *tx_stall;
	struct rvu_block *block;
	int blkaddr, len, lf;
	char kbuf[2048];

	hw = rvu->hw;
	if (*ppos)
		return 0;

	blkaddr = nix_hw->blkaddr;

	tx_stall = nix_hw->tx_stall;
	if (!tx_stall)
		return -EFAULT;

	len = snprintf(kbuf, sizeof(kbuf), "\n  NIX transmit stall stats\n");
	len += snprintf(kbuf + len, sizeof(kbuf),
			"\t\tPolled: \t\t%lld\n", tx_stall->poll_cntr);
	len += snprintf(kbuf + len, sizeof(kbuf),
			"\t\tTx stall detected: \t%lld\n\n",
			tx_stall->stalled_cntr);

	block = &hw->block[blkaddr];
	mutex_lock(&rvu->rsrc_lock);
	for (lf = 0; lf < block->lf.max; lf++) {
		if (!test_bit(lf, block->lf.bmap))
			continue;
		len += snprintf(kbuf + len, sizeof(kbuf),
				"\t\tNIXLF%d   Polled: %lld \tStalled: %lld\n",
				lf, tx_stall->nixlf_poll_count[lf],
				tx_stall->nixlf_stall_count[lf]);
	}
	mutex_unlock(&rvu->rsrc_lock);

	if (len > 0) {
		if (copy_to_user(buffer, kbuf, len))
			return -EFAULT;
	}

	*ppos += len;
	return len;
}

static void rvu_nix_enable_internal_bp(struct rvu *rvu, int blkaddr)
{
	/* An issue exists in A0 silicon whereby, NIX CQ may reach in CQ full
	 * state followed by CQ hang on CQM query response from stale
	 * CQ context. To avoid such condition, enable internal backpressure
	 * with BP_TEST registers.
	 */
	if (is_rvu_96xx_A0(rvu)) {
		/* Enable internal backpressure on pipe_stg0 */
		rvu_write64(rvu, blkaddr, NIX_AF_RQM_BP_TEST,
			    BIT_ULL(51) | BIT_ULL(23) | BIT_ULL(22) | 0x100ULL);
		/* Enable internal backpressure on cqm query request */
		rvu_write64(rvu, blkaddr, NIX_AF_CQM_BP_TEST,
			    BIT_ULL(43) | BIT_ULL(23) | BIT_ULL(22) | 0x100ULL);
	}
}

int rvu_nix_fixes_init(struct rvu *rvu, struct nix_hw *nix_hw, int blkaddr)
{
	int err;
	u64 cfg;


	/* As per a HW errata in 96xx A0 silicon, NIX may corrupt
	 * internal state when conditional clocks are turned off.
	 * Hence enable them.
	 */
	if (is_rvu_96xx_A0(rvu))
		rvu_write64(rvu, blkaddr, NIX_AF_CFG,
			    rvu_read64(rvu, blkaddr, NIX_AF_CFG) | 0x5EULL);
	if (!is_rvu_post_96xx_C0(rvu))
		rvu_write64(rvu, blkaddr, NIX_AF_CFG,
			    rvu_read64(rvu, blkaddr, NIX_AF_CFG) | 0x40ULL);

	/* Set chan/link to backpressure TL3 instead of TL2 */
	rvu_write64(rvu, blkaddr, NIX_AF_PSE_CHANNEL_LEVEL, 0x01);

	/* Disable SQ manager's sticky mode operation (set TM6 = 0, TM11 = 0)
	 * This sticky mode is known to cause SQ stalls when multiple
	 * SQs are mapped to same SMQ and transmitting pkts simultaneously.
	 * NIX PSE may dead lock when therea are any sticky to non-sticky
	 * transmission. Hence disable it (TM5 = 0).
	 */
	cfg = rvu_read64(rvu, blkaddr, NIX_AF_SQM_DBG_CTL_STATUS);
	cfg &= ~(BIT_ULL(15) | BIT_ULL(14) | BIT_ULL(23));
	/* NIX may drop credits when condition clocks are turned off.
	 * Hence enable control flow clk (set TM9 = 1).
	 */
	cfg |= BIT_ULL(21);
	rvu_write64(rvu, blkaddr, NIX_AF_SQM_DBG_CTL_STATUS, cfg);

	rvu_nix_enable_internal_bp(rvu, blkaddr);

	if (!is_rvu_96xx_A0(rvu))
		return 0;

	err = rvu_nix_tx_stall_workaround_init(rvu, nix_hw, blkaddr);
	if (err)
		return err;

	return 0;
}

void rvu_nix_fixes_exit(struct rvu *rvu, struct nix_hw *nix_hw)
{
	if (!is_rvu_96xx_A0(rvu))
		return;

	rvu_nix_tx_stall_workaround_exit(rvu, nix_hw);
}

int rvu_tim_lookup_rsrc(struct rvu *rvu, struct rvu_block *block,
			u16 pcifunc, int slot)
{
	int lf, blkaddr;
	u64 val;

	/* Due to a HW issue LF_CFG_DEBUG register cannot be used to
	 * find PF_FUNC <=> LF mapping, hence scan through LFX_CFG
	 * registers to find mapped LF for a given PF_FUNC.
	 */
	if (is_rvu_96xx_B0(rvu)) {
		blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
		if (blkaddr < 0)
			return TIM_AF_LF_INVALID;

		for (lf = 0; lf < block->lf.max; lf++) {
			val = rvu_read64(rvu, block->addr, block->lfcfg_reg |
					 (lf << block->lfshift));
			if ((((val >> 8) & 0xffff) == pcifunc) &&
			    (val & 0xff) == slot)
				return lf;
		}
		return -1;
	}

	val = ((u64)pcifunc << 24) | (slot << 16) | (1ULL << 13);
	rvu_write64(rvu, block->addr, block->lookup_reg, val);

	/* Wait for the lookup to finish */
	while (rvu_read64(rvu, block->addr, block->lookup_reg) & (1ULL << 13))
		;

	val = rvu_read64(rvu, block->addr, block->lookup_reg);

	/* Check LF valid bit */
	if (!(val & (1ULL << 12)))
		return -1;

	return (val & 0xFFF);
}

int rvu_npc_get_tx_nibble_cfg(struct rvu *rvu, u64 nibble_ena)
{
	/* Due to a HW issue in these silicon versions, parse nibble enable
	 * configuration has to be identical for both Rx and Tx interfaces.
	 */
	if (is_rvu_96xx_B0(rvu))
		return nibble_ena;
	return 0;
}

bool is_parse_nibble_config_valid(struct rvu *rvu,
				  struct npc_mcam_kex *mcam_kex)
{
	if (!is_rvu_96xx_B0(rvu))
		return true;

	/* Due to a HW issue in above silicon versions, parse nibble enable
	 * configuration has to be identical for both Rx and Tx interfaces.
	 */
	if (mcam_kex->keyx_cfg[NIX_INTF_RX] != mcam_kex->keyx_cfg[NIX_INTF_TX])
		return false;
	return true;
}

void __weak otx2smqvf_xmit(void)
{
	/* Nothing to do */
}

void rvu_smqvf_xmit(struct rvu *rvu)
{
	if (is_rvu_95xx_A0(rvu) || is_rvu_96xx_A0(rvu)) {
		usleep_range(50, 60);
		otx2smqvf_xmit();
	}
}
