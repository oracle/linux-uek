// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/jiffies.h>

#include "cgx.h"
#include "rvu.h"
#include "rvu_reg.h"
#include "ptp.h"
#include "mcs.h"

#include "rvu_trace.h"
#include "rvu_npc_hash.h"

#define DRV_NAME	"rvu_af"
#define DRV_STRING      "Marvell RVU Admin Function Driver"

static void rvu_set_msix_offset(struct rvu *rvu, struct rvu_pfvf *pfvf,
				struct rvu_block *block, int lf);
static void rvu_clear_msix_offset(struct rvu *rvu, struct rvu_pfvf *pfvf,
				  struct rvu_block *block, int lf);
static void __rvu_flr_handler(struct rvu *rvu, u16 pcifunc);

static int rvu_mbox_init(struct rvu *rvu, struct mbox_wq_info *mw,
			 int type, int num,
			 void (mbox_handler)(struct work_struct *),
			 void (mbox_up_handler)(struct work_struct *));
enum {
	TYPE_AFVF,
	TYPE_AFPF,
};

/* Supported devices */
static const struct pci_device_id rvu_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_RVU_AF) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Marvell.");
MODULE_DESCRIPTION(DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_DEVICE_TABLE(pci, rvu_id_table);

static char *mkex_profile; /* MKEX profile name */
module_param(mkex_profile, charp, 0000);
MODULE_PARM_DESC(mkex_profile, "MKEX profile name string");

static char *kpu_profile; /* KPU profile name */
module_param(kpu_profile, charp, 0000);
MODULE_PARM_DESC(kpu_profile, "KPU profile name string");

static int max_vfs = -1;
module_param(max_vfs, int, 0444);
MODULE_PARM_DESC(max_vfs,
		 "Reduce the number of VFs initialized by the driver");

static void rvu_setup_hw_capabilities(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;

	hw->cap.nix_tx_aggr_lvl = NIX_TXSCH_LVL_TL1;
	hw->cap.nix_fixed_txschq_mapping = false;
	hw->cap.nix_shaping = true;
	hw->cap.nix_tx_link_bp = true;
	hw->cap.nix_rx_multicast = true;
	hw->cap.nix_shaper_toggle_wait = false;
	hw->cap.npc_hash_extract = false;
	hw->cap.npc_exact_match_enabled = false;
	hw->rvu = rvu;

	if (is_rvu_pre_96xx_C0(rvu)) {
		hw->cap.nix_fixed_txschq_mapping = true;
		hw->cap.nix_txsch_per_cgx_lmac = 4;
		hw->cap.nix_txsch_per_lbk_lmac = 132;
		hw->cap.nix_txsch_per_sdp_lmac = 76;
		hw->cap.nix_shaping = false;
		hw->cap.nix_tx_link_bp = false;
		if (is_rvu_96xx_A0(rvu) || is_rvu_95xx_A0(rvu))
			hw->cap.nix_rx_multicast = false;
	}
	if (!is_rvu_pre_96xx_C0(rvu))
		hw->cap.nix_shaper_toggle_wait = true;

	if (!is_rvu_otx2(rvu))
		hw->cap.per_pf_mbox_regs = true;

	if (is_rvu_npc_hash_extract_en(rvu))
		hw->cap.npc_hash_extract = true;

	if (is_rvu_nix_spi_to_sa_en(rvu))
		hw->cap.spi_to_sas = 0x2000;
}

/* Poll a RVU block's register 'offset', for a 'zero'
 * or 'nonzero' at bits specified by 'mask'
 */
int rvu_poll_reg(struct rvu *rvu, u64 block, u64 offset, u64 mask, bool zero)
{
	unsigned long timeout = jiffies + usecs_to_jiffies(20000);
	bool twice = false;
	void __iomem *reg;
	u64 reg_val;

	reg = rvu->afreg_base + ((block << 28) | offset);
again:
	reg_val = readq(reg);
	if (zero && !(reg_val & mask))
		return 0;
	if (!zero && (reg_val & mask))
		return 0;
	if (time_before(jiffies, timeout)) {
		usleep_range(1, 5);
		goto again;
	}
	/* In scenarios where CPU is scheduled out before checking
	 * 'time_before' (above) and gets scheduled in such that
	 * jiffies are beyond timeout value, then check again if HW is
	 * done with the operation in the meantime.
	 */
	if (!twice) {
		twice = true;
		goto again;
	}
	return -EBUSY;
}

int rvu_alloc_rsrc(struct rsrc_bmap *rsrc)
{
	int id;

	if (!rsrc->bmap)
		return -EINVAL;

	id = find_first_zero_bit(rsrc->bmap, rsrc->max);
	if (id >= rsrc->max)
		return -ENOSPC;

	__set_bit(id, rsrc->bmap);

	return id;
}

int rvu_alloc_rsrc_contig(struct rsrc_bmap *rsrc, int nrsrc)
{
	int start;

	if (!rsrc->bmap)
		return -EINVAL;

	start = bitmap_find_next_zero_area(rsrc->bmap, rsrc->max, 0, nrsrc, 0);
	if (start >= rsrc->max)
		return -ENOSPC;

	bitmap_set(rsrc->bmap, start, nrsrc);
	return start;
}

static void rvu_free_rsrc_contig(struct rsrc_bmap *rsrc, int nrsrc, int start)
{
	if (!rsrc->bmap)
		return;
	if (start >= rsrc->max)
		return;

	bitmap_clear(rsrc->bmap, start, nrsrc);
}

bool rvu_rsrc_check_contig(struct rsrc_bmap *rsrc, int nrsrc)
{
	int start;

	if (!rsrc->bmap)
		return false;

	start = bitmap_find_next_zero_area(rsrc->bmap, rsrc->max, 0, nrsrc, 0);
	if (start >= rsrc->max)
		return false;

	return true;
}

void rvu_free_rsrc(struct rsrc_bmap *rsrc, int id)
{
	if (!rsrc->bmap)
		return;

	__clear_bit(id, rsrc->bmap);
}

int rvu_rsrc_free_count(struct rsrc_bmap *rsrc)
{
	int used;

	if (!rsrc->bmap)
		return 0;

	used = bitmap_weight(rsrc->bmap, rsrc->max);
	return (rsrc->max - used);
}

bool is_rsrc_free(struct rsrc_bmap *rsrc, int id)
{
	if (!rsrc->bmap)
		return false;

	return !test_bit(id, rsrc->bmap);
}

int rvu_alloc_bitmap(struct rsrc_bmap *rsrc)
{
	rsrc->bmap = kcalloc(BITS_TO_LONGS(rsrc->max),
			     sizeof(long), GFP_KERNEL);
	if (!rsrc->bmap)
		return -ENOMEM;
	return 0;
}

void rvu_free_bitmap(struct rsrc_bmap *rsrc)
{
	kfree(rsrc->bmap);
}

/* Get block LF's HW index from a PF_FUNC's block slot number */
int rvu_get_lf(struct rvu *rvu, struct rvu_block *block, u16 pcifunc, u16 slot)
{
	u16 match = 0;
	int lf;

	mutex_lock(&rvu->rsrc_lock);
	for (lf = 0; lf < block->lf.max; lf++) {
		if (block->fn_map[lf] == pcifunc) {
			if (slot == match) {
				mutex_unlock(&rvu->rsrc_lock);
				return lf;
			}
			match++;
		}
	}
	mutex_unlock(&rvu->rsrc_lock);
	return -ENODEV;
}

/* Convert BLOCK_TYPE_E to a BLOCK_ADDR_E.
 * Some silicon variants of OcteonTX2 supports
 * multiple blocks of same type.
 *
 * @pcifunc has to be zero when no LF is yet attached.
 *
 * For a pcifunc if LFs are attached from multiple blocks of same type, then
 * return blkaddr of first encountered block.
 */
int rvu_get_blkaddr(struct rvu *rvu, int blktype, u16 pcifunc)
{
	int devnum, blkaddr = -ENODEV;
	u64 cfg, reg;
	bool is_pf;

	switch (blktype) {
	case BLKTYPE_NPC:
		blkaddr = BLKADDR_NPC;
		goto exit;
	case BLKTYPE_NPA:
		blkaddr = BLKADDR_NPA;
		goto exit;
	case BLKTYPE_NIX:
		/* For now assume NIX0 */
		if (!pcifunc) {
			blkaddr = BLKADDR_NIX0;
			goto exit;
		}
		break;
	case BLKTYPE_SSO:
		blkaddr = BLKADDR_SSO;
		goto exit;
	case BLKTYPE_SSOW:
		blkaddr = BLKADDR_SSOW;
		goto exit;
	case BLKTYPE_TIM:
		blkaddr = BLKADDR_TIM;
		goto exit;
	case BLKTYPE_CPT:
		/* For now assume CPT0 */
		if (!pcifunc) {
			blkaddr = BLKADDR_CPT0;
			goto exit;
		}
		break;
	case BLKTYPE_REE:
		if (!pcifunc) {
			blkaddr = BLKADDR_REE0;
			goto exit;
		}
		break;
	}

	/* Check if this is a RVU PF or VF */
	if (pcifunc & RVU_PFVF_FUNC_MASK) {
		is_pf = false;
		devnum = rvu_get_hwvf(rvu, pcifunc);
	} else {
		is_pf = true;
		devnum = rvu_get_pf(pcifunc);
	}

	/* Check if the 'pcifunc' has a NIX LF from 'BLKADDR_NIX0' or
	 * 'BLKADDR_NIX1'.
	 */
	if (blktype == BLKTYPE_NIX) {
		reg = is_pf ? RVU_PRIV_PFX_NIXX_CFG(0) :
			RVU_PRIV_HWVFX_NIXX_CFG(0);
		cfg = rvu_read64(rvu, BLKADDR_RVUM, reg | (devnum << 16));
		if (cfg) {
			blkaddr = BLKADDR_NIX0;
			goto exit;
		}

		reg = is_pf ? RVU_PRIV_PFX_NIXX_CFG(1) :
			RVU_PRIV_HWVFX_NIXX_CFG(1);
		cfg = rvu_read64(rvu, BLKADDR_RVUM, reg | (devnum << 16));
		if (cfg)
			blkaddr = BLKADDR_NIX1;
	}

	if (blktype == BLKTYPE_CPT) {
		reg = is_pf ? RVU_PRIV_PFX_CPTX_CFG(0) :
			RVU_PRIV_HWVFX_CPTX_CFG(0);
		cfg = rvu_read64(rvu, BLKADDR_RVUM, reg | (devnum << 16));
		if (cfg) {
			blkaddr = BLKADDR_CPT0;
			goto exit;
		}

		reg = is_pf ? RVU_PRIV_PFX_CPTX_CFG(1) :
			RVU_PRIV_HWVFX_CPTX_CFG(1);
		cfg = rvu_read64(rvu, BLKADDR_RVUM, reg | (devnum << 16));
		if (cfg)
			blkaddr = BLKADDR_CPT1;
	}

	/* Check if the 'pcifunc' has a REE LF from 'BLKADDR_REE0' or
	 * 'BLKADDR_REE1'. If pcifunc has REE LFs from both then only
	 * BLKADDR_REE0 is returned.
	 */
	if (blktype == BLKTYPE_REE) {
		reg = is_pf ? RVU_PRIV_PFX_REEX_CFG(0) :
			RVU_PRIV_HWVFX_REEX_CFG(0);
		cfg = rvu_read64(rvu, BLKADDR_RVUM, reg | (devnum << 16));
		if (cfg) {
			blkaddr = BLKADDR_REE0;
			goto exit;
		}

		reg = is_pf ? RVU_PRIV_PFX_REEX_CFG(1) :
			RVU_PRIV_HWVFX_REEX_CFG(1);
		cfg = rvu_read64(rvu, BLKADDR_RVUM, reg | (devnum << 16));
		if (cfg)
			blkaddr = BLKADDR_REE1;
	}

exit:
	if (is_block_implemented(rvu->hw, blkaddr))
		return blkaddr;
	return -ENODEV;
}

static void rvu_update_rsrc_map(struct rvu *rvu, struct rvu_pfvf *pfvf,
				struct rvu_block *block, u16 pcifunc,
				u16 lf, bool attach)
{
	int devnum, num_lfs = 0;
	bool is_pf;
	u64 reg;

	if (lf >= block->lf.max) {
		dev_err(&rvu->pdev->dev,
			"%s: FATAL: LF %d is >= %s's max lfs i.e %d\n",
			__func__, lf, block->name, block->lf.max);
		return;
	}

	/* Check if this is for a RVU PF or VF */
	if (pcifunc & RVU_PFVF_FUNC_MASK) {
		is_pf = false;
		devnum = rvu_get_hwvf(rvu, pcifunc);
	} else {
		is_pf = true;
		devnum = rvu_get_pf(pcifunc);
	}

	block->fn_map[lf] = attach ? pcifunc : 0;

	switch (block->addr) {
	case BLKADDR_NPA:
		pfvf->npalf = attach ? true : false;
		num_lfs = pfvf->npalf;
		break;
	case BLKADDR_NIX0:
	case BLKADDR_NIX1:
		pfvf->nixlf = attach ? true : false;
		num_lfs = pfvf->nixlf;
		break;
	case BLKADDR_SSO:
		attach ? pfvf->sso++ : pfvf->sso--;
		num_lfs = pfvf->sso;
		break;
	case BLKADDR_SSOW:
		attach ? pfvf->ssow++ : pfvf->ssow--;
		num_lfs = pfvf->ssow;
		break;
	case BLKADDR_TIM:
		attach ? pfvf->timlfs++ : pfvf->timlfs--;
		num_lfs = pfvf->timlfs;
		break;
	case BLKADDR_CPT0:
		attach ? pfvf->cptlfs++ : pfvf->cptlfs--;
		num_lfs = pfvf->cptlfs;
		break;
	case BLKADDR_CPT1:
		attach ? pfvf->cpt1_lfs++ : pfvf->cpt1_lfs--;
		num_lfs = pfvf->cpt1_lfs;
		break;
	case BLKADDR_REE0:
		attach ? pfvf->ree0_lfs++ : pfvf->ree0_lfs--;
		num_lfs = pfvf->ree0_lfs;
		break;
	case BLKADDR_REE1:
		attach ? pfvf->ree1_lfs++ : pfvf->ree1_lfs--;
		num_lfs = pfvf->ree1_lfs;
		break;
	}

	reg = is_pf ? block->pf_lfcnt_reg : block->vf_lfcnt_reg;
	rvu_write64(rvu, BLKADDR_RVUM, reg | (devnum << 16), num_lfs);
}

inline int rvu_get_pf(u16 pcifunc)
{
	return (pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;
}

void rvu_get_pf_numvfs(struct rvu *rvu, int pf, int *numvfs, int *hwvf)
{
	u64 cfg;

	/* Get numVFs attached to this PF and first HWVF */
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));
	*numvfs = (cfg >> 12) & 0xFF;
	*hwvf = cfg & 0xFFF;
}

int rvu_get_hwvf(struct rvu *rvu, int pcifunc)
{
	int pf, func;
	u64 cfg;

	pf = rvu_get_pf(pcifunc);
	func = pcifunc & RVU_PFVF_FUNC_MASK;

	/* Get first HWVF attached to this PF */
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));

	return ((cfg & 0xFFF) + func - 1);
}

struct rvu_pfvf *rvu_get_pfvf(struct rvu *rvu, int pcifunc)
{
	/* Check if it is a PF or VF */
	if (pcifunc & RVU_PFVF_FUNC_MASK)
		return &rvu->hwvf[rvu_get_hwvf(rvu, pcifunc)];
	else
		return &rvu->pf[rvu_get_pf(pcifunc)];
}

static bool is_pf_func_valid(struct rvu *rvu, u16 pcifunc)
{
	int pf, vf, nvfs;
	u64 cfg;

	pf = rvu_get_pf(pcifunc);
	if (pf >= rvu->hw->total_pfs)
		return false;

	if (!(pcifunc & RVU_PFVF_FUNC_MASK))
		return true;

	/* Check if VF is within number of VFs attached to this PF */
	vf = (pcifunc & RVU_PFVF_FUNC_MASK) - 1;
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));
	nvfs = (cfg >> 12) & 0xFF;
	if (vf >= nvfs)
		return false;

	return true;
}

bool is_block_implemented(struct rvu_hwinfo *hw, int blkaddr)
{
	struct rvu_block *block;

	if (blkaddr < BLKADDR_RVUM || blkaddr >= BLK_COUNT)
		return false;

	block = &hw->block[blkaddr];
	return block->implemented;
}

static void rvu_check_block_implemented(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int blkid;
	u64 cfg;

	/* For each block check if 'implemented' bit is set */
	for (blkid = 0; blkid < BLK_COUNT; blkid++) {
		block = &hw->block[blkid];
		cfg = rvupf_read64(rvu, RVU_PF_BLOCK_ADDRX_DISC(blkid));
		if (cfg & BIT_ULL(11))
			block->implemented = true;
	}
}

static void rvu_setup_rvum_blk_revid(struct rvu *rvu)
{
	rvu_write64(rvu, BLKADDR_RVUM,
		    RVU_PRIV_BLOCK_TYPEX_REV(BLKTYPE_RVUM),
		    RVU_BLK_RVUM_REVID);
}

static void rvu_clear_rvum_blk_revid(struct rvu *rvu)
{
	rvu_write64(rvu, BLKADDR_RVUM,
		    RVU_PRIV_BLOCK_TYPEX_REV(BLKTYPE_RVUM), 0x00);
}

int rvu_lf_reset(struct rvu *rvu, struct rvu_block *block, int lf)
{
	int err;

	if (!block->implemented)
		return 0;

	rvu_write64(rvu, block->addr, block->lfreset_reg, lf | BIT_ULL(12));
	err = rvu_poll_reg(rvu, block->addr, block->lfreset_reg, BIT_ULL(12),
			   true);
	return err;
}

static void rvu_block_reset(struct rvu *rvu, int blkaddr, u64 rst_reg)
{
	struct rvu_block *block = &rvu->hw->block[blkaddr];
	int err;

	if (!block->implemented)
		return;

	rvu_write64(rvu, blkaddr, rst_reg, BIT_ULL(0));
	err = rvu_poll_reg(rvu, blkaddr, rst_reg, BIT_ULL(63), true);
	if (err) {
		dev_err(rvu->dev, "HW block:%d reset timeout retrying again\n", blkaddr);
		while (rvu_poll_reg(rvu, blkaddr, rst_reg, BIT_ULL(63), true) == -EBUSY)
			;
	}
}

static void rvu_reset_all_blocks(struct rvu *rvu)
{
	/* Do a HW reset of all RVU blocks */
	rvu_block_reset(rvu, BLKADDR_NPA, NPA_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NIX0, NIX_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NIX1, NIX_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NPC, NPC_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_SSO, SSO_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_TIM, TIM_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_CPT0, CPT_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_CPT1, CPT_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NDC_NIX0_RX, NDC_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NDC_NIX0_TX, NDC_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NDC_NIX1_RX, NDC_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NDC_NIX1_TX, NDC_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_NDC_NPA0, NDC_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_REE0, REE_AF_BLK_RST);
	rvu_block_reset(rvu, BLKADDR_REE1, REE_AF_BLK_RST);
}

static void rvu_scan_block(struct rvu *rvu, struct rvu_block *block)
{
	struct rvu_pfvf *pfvf;
	u64 cfg;
	int lf;

	for (lf = 0; lf < block->lf.max; lf++) {
		cfg = rvu_read64(rvu, block->addr,
				 block->lfcfg_reg | (lf << block->lfshift));
		if (!(cfg & BIT_ULL(63)))
			continue;

		/* Set this resource as being used */
		__set_bit(lf, block->lf.bmap);

		/* Get, to whom this LF is attached */
		pfvf = rvu_get_pfvf(rvu, (cfg >> 8) & 0xFFFF);
		rvu_update_rsrc_map(rvu, pfvf, block,
				    (cfg >> 8) & 0xFFFF, lf, true);

		/* Set start MSIX vector for this LF within this PF/VF */
		rvu_set_msix_offset(rvu, pfvf, block, lf);
	}
}

static void rvu_check_min_msix_vec(struct rvu *rvu, int nvecs, int pf, int vf)
{
	int min_vecs;

	if (!vf)
		goto check_pf;

	if (!nvecs) {
		dev_warn(rvu->dev,
			 "PF%d:VF%d is configured with zero msix vectors, %d\n",
			 pf, vf - 1, nvecs);
	}
	return;

check_pf:
	if (pf == 0)
		min_vecs = RVU_AF_INT_VEC_CNT + RVU_PF_INT_VEC_CNT;
	else
		min_vecs = RVU_PF_INT_VEC_CNT;

	if (!(nvecs < min_vecs))
		return;
	dev_warn(rvu->dev,
		 "PF%d is configured with too few vectors, %d, min is %d\n",
		 pf, nvecs, min_vecs);
}

static int rvu_setup_msix_resources(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int pf, vf, numvfs, hwvf, err;
	int nvecs, offset, max_msix;
	struct rvu_pfvf *pfvf;
	u64 cfg, phy_addr;
	dma_addr_t iova;

	for (pf = 0; pf < hw->total_pfs; pf++) {
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));
		/* If PF is not enabled, nothing to do */
		if (!((cfg >> 20) & 0x01))
			continue;

		rvu_get_pf_numvfs(rvu, pf, &numvfs, &hwvf);

		pfvf = &rvu->pf[pf];
		/* Get num of MSIX vectors attached to this PF */
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_MSIX_CFG(pf));
		pfvf->msix.max = ((cfg >> 32) & 0xFFF) + 1;
		rvu_check_min_msix_vec(rvu, pfvf->msix.max, pf, 0);

		/* Alloc msix bitmap for this PF */
		err = rvu_alloc_bitmap(&pfvf->msix);
		if (err)
			return err;

		/* Allocate memory for MSIX vector to RVU block LF mapping */
		pfvf->msix_lfmap = devm_kcalloc(rvu->dev, pfvf->msix.max,
						sizeof(u16), GFP_KERNEL);
		if (!pfvf->msix_lfmap)
			return -ENOMEM;

		/* For PF0 (AF) firmware will set msix vector offsets for
		 * AF, block AF and PF0_INT vectors, so jump to VFs.
		 */
		if (!pf)
			goto setup_vfmsix;

		/* Set MSIX offset for PF's 'RVU_PF_INT_VEC' vectors.
		 * These are allocated on driver init and never freed,
		 * so no need to set 'msix_lfmap' for these.
		 */
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_INT_CFG(pf));
		nvecs = (cfg >> 12) & 0xFF;
		cfg &= ~0x7FFULL;
		offset = rvu_alloc_rsrc_contig(&pfvf->msix, nvecs);
		rvu_write64(rvu, BLKADDR_RVUM,
			    RVU_PRIV_PFX_INT_CFG(pf), cfg | offset);
setup_vfmsix:
		/* Alloc msix bitmap for VFs */
		for (vf = 0; vf < numvfs; vf++) {
			pfvf =  &rvu->hwvf[hwvf + vf];
			/* Get num of MSIX vectors attached to this VF */
			cfg = rvu_read64(rvu, BLKADDR_RVUM,
					 RVU_PRIV_PFX_MSIX_CFG(pf));
			pfvf->msix.max = (cfg & 0xFFF) + 1;
			rvu_check_min_msix_vec(rvu, pfvf->msix.max, pf, vf + 1);

			/* Alloc msix bitmap for this VF */
			err = rvu_alloc_bitmap(&pfvf->msix);
			if (err)
				return err;

			pfvf->msix_lfmap =
				devm_kcalloc(rvu->dev, pfvf->msix.max,
					     sizeof(u16), GFP_KERNEL);
			if (!pfvf->msix_lfmap)
				return -ENOMEM;

			/* Set MSIX offset for HWVF's 'RVU_VF_INT_VEC' vectors.
			 * These are allocated on driver init and never freed,
			 * so no need to set 'msix_lfmap' for these.
			 */
			cfg = rvu_read64(rvu, BLKADDR_RVUM,
					 RVU_PRIV_HWVFX_INT_CFG(hwvf + vf));
			nvecs = (cfg >> 12) & 0xFF;
			cfg &= ~0x7FFULL;
			offset = rvu_alloc_rsrc_contig(&pfvf->msix, nvecs);
			rvu_write64(rvu, BLKADDR_RVUM,
				    RVU_PRIV_HWVFX_INT_CFG(hwvf + vf),
				    cfg | offset);
		}
	}

	/* HW interprets RVU_AF_MSIXTR_BASE address as an IOVA, hence
	 * create an IOMMU mapping for the physical address configured by
	 * firmware and reconfig RVU_AF_MSIXTR_BASE with IOVA.
	 */
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_CONST);
	max_msix = cfg & 0xFFFFF;
	if (rvu->fwdata && rvu->fwdata->msixtr_base)
		phy_addr = rvu->fwdata->msixtr_base;
	else
		phy_addr = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_MSIXTR_BASE);
	iova = dma_map_resource(rvu->dev, phy_addr,
				max_msix * PCI_MSIX_ENTRY_SIZE,
				DMA_BIDIRECTIONAL, 0);

	if (dma_mapping_error(rvu->dev, iova))
		return -ENOMEM;

	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_MSIXTR_BASE, (u64)iova);
	rvu->msix_base_iova = iova;
	rvu->msixtr_base_phy = phy_addr;

	return 0;
}

static void rvu_reset_msix(struct rvu *rvu)
{
	/* Restore msixtr base register */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_MSIXTR_BASE,
		    rvu->msixtr_base_phy);
}

static void rvu_free_hw_resources(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct rvu_pfvf  *pfvf;
	int id, max_msix;
	u64 cfg;

	rvu_npa_freemem(rvu);
	rvu_npc_freemem(rvu);
	rvu_nix_freemem(rvu);
	rvu_sso_freemem(rvu);
	rvu_ree_freemem(rvu);

	/* Free block LF bitmaps */
	for (id = 0; id < BLK_COUNT; id++) {
		block = &hw->block[id];
		kfree(block->lf.bmap);
	}

	/* Free MSIX bitmaps */
	for (id = 0; id < hw->total_pfs; id++) {
		pfvf = &rvu->pf[id];
		kfree(pfvf->msix.bmap);
	}

	for (id = 0; id < hw->total_vfs; id++) {
		pfvf = &rvu->hwvf[id];
		kfree(pfvf->msix.bmap);
	}

	/* Unmap MSIX vector base IOVA mapping */
	if (!rvu->msix_base_iova)
		return;
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_CONST);
	max_msix = cfg & 0xFFFFF;
	dma_unmap_resource(rvu->dev, rvu->msix_base_iova,
			   max_msix * PCI_MSIX_ENTRY_SIZE,
			   DMA_BIDIRECTIONAL, 0);

	rvu_reset_msix(rvu);
	mutex_destroy(&rvu->rsrc_lock);
	mutex_destroy(&rvu->alias_lock);
}

static void rvu_setup_pfvf_macaddress(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int pf, vf, numvfs, hwvf;
	struct rvu_pfvf *pfvf;
	u64 *mac;

	for (pf = 0; pf < hw->total_pfs; pf++) {
		/* For PF0(AF), Assign MAC address to only VFs (LBKVFs) */
		if (!pf)
			goto lbkvf;

		if (!is_pf_cgxmapped(rvu, pf))
			continue;
		/* Assign MAC address to PF */
		pfvf = &rvu->pf[pf];
		if (rvu->fwdata && pf < PF_MACNUM_MAX) {
			mac = &rvu->fwdata->pf_macs[pf];
			if (*mac)
				u64_to_ether_addr(*mac, pfvf->mac_addr);
			else
				eth_random_addr(pfvf->mac_addr);
		} else {
			eth_random_addr(pfvf->mac_addr);
		}
		ether_addr_copy(pfvf->default_mac, pfvf->mac_addr);

lbkvf:
		/* Assign MAC address to VFs*/
		rvu_get_pf_numvfs(rvu, pf, &numvfs, &hwvf);
		for (vf = 0; vf < numvfs; vf++, hwvf++) {
			pfvf = &rvu->hwvf[hwvf];
			if (rvu->fwdata && hwvf < VF_MACNUM_MAX) {
				mac = &rvu->fwdata->vf_macs[hwvf];
				if (*mac)
					u64_to_ether_addr(*mac, pfvf->mac_addr);
				else
					eth_random_addr(pfvf->mac_addr);
			} else {
				eth_random_addr(pfvf->mac_addr);
			}
			ether_addr_copy(pfvf->default_mac, pfvf->mac_addr);
		}
	}
}

static void rvu_setup_pfvf_aggr_lvl_rr_prio(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_pfvf *pfvf;
	int pf;

	for (pf = 0; pf < hw->total_pfs; pf++) {
		pfvf = &rvu->pf[pf];
		pfvf->tl1_rr_prio = TXSCH_TL1_DFLT_RR_PRIO;
	}
}

static int rvu_fwdata_init(struct rvu *rvu)
{
	u64 fwdbase;
	int err;

	/* Get firmware data base address */
	err = cgx_get_fwdata_base(&fwdbase);
	if (err)
		goto fail;
	rvu->fwdata = ioremap_wc(fwdbase, sizeof(struct rvu_fwdata));
	if (!rvu->fwdata)
		goto fail;
	if (!is_rvu_fwdata_valid(rvu)) {
		dev_err(rvu->dev,
			"Mismatch in 'fwdata' struct btw kernel and firmware\n");
		iounmap(rvu->fwdata);
		rvu->fwdata = NULL;
		return -EINVAL;
	}
	return 0;
fail:
	dev_info(rvu->dev, "Unable to fetch 'fwdata' from firmware\n");
	return -EIO;
}

static void rvu_fwdata_exit(struct rvu *rvu)
{
	if (rvu->fwdata)
		iounmap(rvu->fwdata);
}

static int rvu_setup_nix_hw_resource(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int blkid;
	u64 cfg;

	/* Init NIX LF's bitmap */
	block = &hw->block[blkaddr];
	if (!block->implemented)
		return 0;
	blkid = (blkaddr == BLKADDR_NIX0) ? 0 : 1;
	cfg = rvu_read64(rvu, blkaddr, NIX_AF_CONST2);
	block->lf.max = cfg & 0xFFF;
	block->addr = blkaddr;
	block->type = BLKTYPE_NIX;
	block->lfshift = 8;
	block->lookup_reg = NIX_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_NIXX_CFG(blkid);
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_NIXX_CFG(blkid);
	block->lfcfg_reg = NIX_PRIV_LFX_CFG;
	block->msixcfg_reg = NIX_PRIV_LFX_INT_CFG;
	block->lfreset_reg = NIX_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "NIX%d", blkid);
	rvu->nix_blkaddr[blkid] = blkaddr;
	return rvu_alloc_bitmap(&block->lf);
}

static int rvu_setup_cpt_hw_resource(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int blkid;
	u64 cfg;

	/* Init CPT LF's bitmap */
	block = &hw->block[blkaddr];
	if (!block->implemented)
		return 0;
	blkid = (blkaddr == BLKADDR_CPT0) ? 0 : 1;
	cfg = rvu_read64(rvu, blkaddr, CPT_AF_CONSTANTS0);
	block->lf.max = cfg & 0xFF;
	block->addr = blkaddr;
	block->type = BLKTYPE_CPT;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = CPT_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_CPTX_CFG(blkid);
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_CPTX_CFG(blkid);
	block->lfcfg_reg = CPT_PRIV_LFX_CFG;
	block->msixcfg_reg = CPT_PRIV_LFX_INT_CFG;
	block->lfreset_reg = CPT_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "CPT%d", blkid);
	return rvu_alloc_bitmap(&block->lf);
}

static int rvu_setup_ree_hw_resource(struct rvu *rvu, int blkaddr, int blkid)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int err;
	u64 cfg;

	/* Init REE LF's bitmap */
	block = &hw->block[blkaddr];
	if (!block->implemented)
		return 0;
	cfg = rvu_read64(rvu, blkaddr, REE_AF_CONSTANTS);
	block->lf.max = cfg & 0xFF;
	block->addr = blkaddr;
	block->type = BLKTYPE_REE;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = REE_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_REEX_CFG(blkid);
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_REEX_CFG(blkid);
	block->lfcfg_reg = REE_PRIV_LFX_CFG;
	block->msixcfg_reg = REE_PRIV_LFX_INT_CFG;
	block->lfreset_reg = REE_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "REE%d", blkid);
	err = rvu_alloc_bitmap(&block->lf);
	if (err)
		return err;
	return 0;
}

static void rvu_get_lbk_bufsize(struct rvu *rvu)
{
	struct pci_dev *pdev = NULL;
	void __iomem *base;
	u64 lbk_const;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
			      PCI_DEVID_OCTEONTX2_LBK, pdev);
	if (!pdev)
		return;

	base = pci_ioremap_bar(pdev, 0);
	if (!base)
		goto err_put;

	lbk_const = readq(base + LBK_CONST);

	/* cache fifo size */
	rvu->hw->lbk_bufsize = FIELD_GET(LBK_CONST_BUF_SIZE, lbk_const);

	iounmap(base);
err_put:
	pci_dev_put(pdev);
}

/* Function to perform operations (read/write) on lmtst map table */
static int rvu_setup_hw_resources(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int blkid, err;
	u64 cfg;

	/* Get HW supported max RVU PF & VF count */
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_CONST);
	hw->total_pfs = (cfg >> 32) & 0xFF;
	hw->total_vfs = (cfg >> 20) & 0xFFF;
	hw->max_vfs_per_pf = (cfg >> 40) & 0xFF;

	if (!is_rvu_otx2(rvu))
		rvu_apr_block_cn10k_init(rvu);

	/* Init NPA LF's bitmap */
	block = &hw->block[BLKADDR_NPA];
	if (!block->implemented)
		goto nix;
	cfg = rvu_read64(rvu, BLKADDR_NPA, NPA_AF_CONST);
	block->lf.max = (cfg >> 16) & 0xFFF;
	block->addr = BLKADDR_NPA;
	block->type = BLKTYPE_NPA;
	block->lfshift = 8;
	block->lookup_reg = NPA_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_NPA_CFG;
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_NPA_CFG;
	block->lfcfg_reg = NPA_PRIV_LFX_CFG;
	block->msixcfg_reg = NPA_PRIV_LFX_INT_CFG;
	block->lfreset_reg = NPA_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "NPA");
	err = rvu_alloc_bitmap(&block->lf);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate NPA LF bitmap\n", __func__);
		return err;
	}

nix:
	err = rvu_setup_nix_hw_resource(rvu, BLKADDR_NIX0);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate NIX0 LFs bitmap\n", __func__);
		return err;
	}

	err = rvu_setup_nix_hw_resource(rvu, BLKADDR_NIX1);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate NIX1 LFs bitmap\n", __func__);
		return err;
	}

	/* Init SSO group's bitmap */
	block = &hw->block[BLKADDR_SSO];
	if (!block->implemented)
		goto ssow;
	cfg = rvu_read64(rvu, BLKADDR_SSO, SSO_AF_CONST);
	block->lf.max = cfg & 0xFFFF;
	block->addr = BLKADDR_SSO;
	block->type = BLKTYPE_SSO;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = SSO_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_SSO_CFG;
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_SSO_CFG;
	block->lfcfg_reg = SSO_PRIV_LFX_HWGRP_CFG;
	block->msixcfg_reg = SSO_PRIV_LFX_HWGRP_INT_CFG;
	block->lfreset_reg = SSO_AF_LF_HWGRP_RST;
	block->rvu = rvu;
	sprintf(block->name, "SSO GROUP");
	err = rvu_alloc_bitmap(&block->lf);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate SSO LF bitmap\n", __func__);
		return err;
	}

ssow:
	/* Init SSO workslot's bitmap */
	block = &hw->block[BLKADDR_SSOW];
	if (!block->implemented)
		goto tim;
	block->lf.max = (cfg >> 56) & 0xFF;
	block->addr = BLKADDR_SSOW;
	block->type = BLKTYPE_SSOW;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = SSOW_AF_RVU_LF_HWS_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_SSOW_CFG;
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_SSOW_CFG;
	block->lfcfg_reg = SSOW_PRIV_LFX_HWS_CFG;
	block->msixcfg_reg = SSOW_PRIV_LFX_HWS_INT_CFG;
	block->lfreset_reg = SSOW_AF_LF_HWS_RST;
	block->rvu = rvu;
	sprintf(block->name, "SSOWS");
	err = rvu_alloc_bitmap(&block->lf);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate SSOW LF bitmap\n", __func__);
		return err;
	}

tim:
	/* Init TIM LF's bitmap */
	block = &hw->block[BLKADDR_TIM];
	if (!block->implemented)
		goto cpt;
	cfg = rvu_read64(rvu, BLKADDR_TIM, TIM_AF_CONST);
	block->lf.max = cfg & 0xFFFF;
	block->addr = BLKADDR_TIM;
	block->type = BLKTYPE_TIM;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = TIM_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = RVU_PRIV_PFX_TIM_CFG;
	block->vf_lfcnt_reg = RVU_PRIV_HWVFX_TIM_CFG;
	block->lfcfg_reg = TIM_PRIV_LFX_CFG;
	block->msixcfg_reg = TIM_PRIV_LFX_INT_CFG;
	block->lfreset_reg = TIM_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "TIM");
	err = rvu_alloc_bitmap(&block->lf);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate TIM LF bitmap\n", __func__);
		return err;
	}

cpt:
	err = rvu_setup_cpt_hw_resource(rvu, BLKADDR_CPT0);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate CPT0 LF bitmap\n", __func__);
		return err;
	}
	err = rvu_setup_cpt_hw_resource(rvu, BLKADDR_CPT1);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to allocate CPT1 LF bitmap\n", __func__);
		return err;
	}

	/* REE */
	err = rvu_setup_ree_hw_resource(rvu, BLKADDR_REE0, 0);
	if (err)
		return err;
	err = rvu_setup_ree_hw_resource(rvu, BLKADDR_REE1, 1);
	if (err)
		return err;

	/* Allocate memory for PFVF data */
	rvu->pf = devm_kcalloc(rvu->dev, hw->total_pfs,
			       sizeof(struct rvu_pfvf), GFP_KERNEL);
	if (!rvu->pf) {
		dev_err(rvu->dev,
			"%s: Failed to allocate memory for PF's rvu_pfvf struct\n", __func__);
		return -ENOMEM;
	}

	rvu->hwvf = devm_kcalloc(rvu->dev, hw->total_vfs,
				 sizeof(struct rvu_pfvf), GFP_KERNEL);
	if (!rvu->hwvf) {
		dev_err(rvu->dev,
			"%s: Failed to allocate memory for VF's rvu_pfvf struct\n", __func__);
		return -ENOMEM;
	}

	mutex_init(&rvu->rsrc_lock);
	mutex_init(&rvu->alias_lock);

	rvu_fwdata_init(rvu);

	err = rvu_setup_msix_resources(rvu);
	if (err) {
		dev_err(rvu->dev,
			"%s: Failed to setup MSIX resources\n", __func__);
		return err;
	}

	for (blkid = 0; blkid < BLK_COUNT; blkid++) {
		block = &hw->block[blkid];
		if (!block->lf.bmap)
			continue;

		/* Allocate memory for block LF/slot to pcifunc mapping info */
		block->fn_map = devm_kcalloc(rvu->dev, block->lf.max,
					     sizeof(u16), GFP_KERNEL);
		if (!block->fn_map) {
			err = -ENOMEM;
			goto msix_err;
		}

		/* Scan all blocks to check if low level firmware has
		 * already provisioned any of the resources to a PF/VF.
		 */
		rvu_scan_block(rvu, block);
	}

	err = rvu_set_channels_base(rvu);
	if (err)
		goto msix_err;

	err = rvu_npc_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize npc\n", __func__);
		goto npc_err;
	}

	err = rvu_cgx_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize cgx\n", __func__);
		goto cgx_err;
	}

	err = rvu_npc_exact_init(rvu);
	if (err) {
		dev_err(rvu->dev, "failed to initialize exact match table\n");
		return err;
	}

	/* Assign MACs for CGX mapped functions */
	rvu_setup_pfvf_macaddress(rvu);

	/* Assign aggr level RR Priority */
	rvu_setup_pfvf_aggr_lvl_rr_prio(rvu);

	err = rvu_npa_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize npa\n", __func__);
		goto npa_err;
	}

	rvu_get_lbk_bufsize(rvu);

	err = rvu_nix_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize nix\n", __func__);
		goto nix_err;
	}

	err = rvu_sso_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize sso\n", __func__);
		goto sso_err;
	}

	err = rvu_tim_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize tim\n", __func__);
		goto sso_err;
	}

	err = rvu_sdp_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize sdp\n", __func__);
		goto sso_err;
	}

	err = rvu_ree_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize ree\n", __func__);
		goto sso_err;
	}

	err = rvu_cpt_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize cpt\n", __func__);
		goto sso_err;
	}

	rvu_program_channels(rvu);

	err = rvu_mcs_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s: Failed to initialize mcs\n", __func__);
		goto sso_err;
	}

	return 0;

sso_err:
	rvu_sso_freemem(rvu);
nix_err:
	rvu_nix_freemem(rvu);
npa_err:
	rvu_npa_freemem(rvu);
cgx_err:
	rvu_cgx_exit(rvu);
npc_err:
	rvu_npc_freemem(rvu);
	rvu_fwdata_exit(rvu);
msix_err:
	rvu_reset_msix(rvu);
	return err;
}

/* NPA and NIX admin queue APIs */
void rvu_aq_free(struct rvu *rvu, struct admin_queue *aq)
{
	if (!aq)
		return;

	qmem_free(rvu->dev, aq->inst);
	qmem_free(rvu->dev, aq->res);
	devm_kfree(rvu->dev, aq);
}

int rvu_aq_alloc(struct rvu *rvu, struct admin_queue **ad_queue,
		 int qsize, int inst_size, int res_size)
{
	struct admin_queue *aq;
	int err;

	*ad_queue = devm_kzalloc(rvu->dev, sizeof(*aq), GFP_KERNEL);
	if (!*ad_queue)
		return -ENOMEM;
	aq = *ad_queue;

	/* Alloc memory for instructions i.e AQ */
	err = qmem_alloc(rvu->dev, &aq->inst, qsize, inst_size);
	if (err) {
		devm_kfree(rvu->dev, aq);
		return err;
	}

	/* Alloc memory for results */
	err = qmem_alloc(rvu->dev, &aq->res, qsize, res_size);
	if (err) {
		rvu_aq_free(rvu, aq);
		return err;
	}

	spin_lock_init(&aq->lock);
	return 0;
}

int rvu_mbox_handler_ready(struct rvu *rvu, struct msg_req *req,
			   struct ready_msg_rsp *rsp)
{
	if (rvu->fwdata) {
		rsp->rclk_freq = rvu->fwdata->rclk;
		rsp->sclk_freq = rvu->fwdata->sclk;
	}
	return 0;
}

/* Get current count of a RVU block's LF/slots
 * provisioned to a given RVU func.
 */
u16 rvu_get_rsrc_mapcount(struct rvu_pfvf *pfvf, int blkaddr)
{
	switch (blkaddr) {
	case BLKADDR_NPA:
		return pfvf->npalf ? 1 : 0;
	case BLKADDR_NIX0:
	case BLKADDR_NIX1:
		return pfvf->nixlf ? 1 : 0;
	case BLKADDR_SSO:
		return pfvf->sso;
	case BLKADDR_SSOW:
		return pfvf->ssow;
	case BLKADDR_TIM:
		return pfvf->timlfs;
	case BLKADDR_CPT0:
		return pfvf->cptlfs;
	case BLKADDR_CPT1:
		return pfvf->cpt1_lfs;
	case BLKADDR_REE0:
		return pfvf->ree0_lfs;
	case BLKADDR_REE1:
		return pfvf->ree1_lfs;
	}
	return 0;
}

/* Return true if LFs of block type are attached to pcifunc */
static bool is_blktype_attached(struct rvu_pfvf *pfvf, int blktype)
{
	switch (blktype) {
	case BLKTYPE_NPA:
		return pfvf->npalf ? 1 : 0;
	case BLKTYPE_NIX:
		return pfvf->nixlf ? 1 : 0;
	case BLKTYPE_SSO:
		return !!pfvf->sso;
	case BLKTYPE_SSOW:
		return !!pfvf->ssow;
	case BLKTYPE_TIM:
		return !!pfvf->timlfs;
	case BLKTYPE_CPT:
		return pfvf->cptlfs || pfvf->cpt1_lfs;
	case BLKTYPE_REE:
		return pfvf->ree0_lfs || pfvf->ree1_lfs;
	}

	return false;
}

bool is_pffunc_map_valid(struct rvu *rvu, u16 pcifunc, int blktype)
{
	struct rvu_pfvf *pfvf;

	if (!is_pf_func_valid(rvu, pcifunc))
		return false;

	pfvf = rvu_get_pfvf(rvu, pcifunc);

	/* Check if this PFFUNC has a LF of type blktype attached */
	if (blktype != BLKTYPE_SSO && !is_blktype_attached(pfvf, blktype))
		return false;

	return true;
}

static int rvu_lookup_rsrc(struct rvu *rvu, struct rvu_block *block,
			   int pcifunc, int slot)
{
	u64 val;

	if (block->type == BLKTYPE_TIM)
		return rvu_tim_lookup_rsrc(rvu, block, pcifunc, slot);

	val = ((u64)pcifunc << 24) | (slot << 16) | (1ULL << 13);
	rvu_write64(rvu, block->addr, block->lookup_reg, val);
	/* Wait for the lookup to finish */
	/* TODO: put some timeout here */
	while (rvu_read64(rvu, block->addr, block->lookup_reg) & (1ULL << 13))
		;

	val = rvu_read64(rvu, block->addr, block->lookup_reg);

	/* Check LF valid bit */
	if (!(val & (1ULL << 12)))
		return -1;

	return (val & 0xFFF);
}

int rvu_get_blkaddr_from_slot(struct rvu *rvu, int blktype, u16 pcifunc,
			      u16 global_slot, u16 *slot_in_block)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	int numlfs, total_lfs = 0, nr_blocks = 0;
	int i, num_blkaddr[BLK_COUNT] = { 0 };
	struct rvu_block *block;
	int blkaddr = -ENODEV;
	u16 start_slot;

	if (!is_blktype_attached(pfvf, blktype))
		return -ENODEV;

	/* Get all the block addresses from which LFs are attached to
	 * the given pcifunc in num_blkaddr[].
	 */
	for (blkaddr = BLKADDR_RVUM; blkaddr < BLK_COUNT; blkaddr++) {
		block = &rvu->hw->block[blkaddr];
		if (block->type != blktype)
			continue;
		if (!is_block_implemented(rvu->hw, blkaddr))
			continue;

		numlfs = rvu_get_rsrc_mapcount(pfvf, blkaddr);
		if (numlfs) {
			total_lfs += numlfs;
			num_blkaddr[nr_blocks] = blkaddr;
			nr_blocks++;
		}
	}

	if (global_slot >= total_lfs)
		return -ENODEV;

	/* Based on the given global slot number retrieve the
	 * correct block address out of all attached block
	 * addresses and slot number in that block.
	 */
	total_lfs = 0;
	blkaddr = -ENODEV;
	for (i = 0; i < nr_blocks; i++) {
		numlfs = rvu_get_rsrc_mapcount(pfvf, num_blkaddr[i]);
		total_lfs += numlfs;
		if (global_slot < total_lfs) {
			blkaddr = num_blkaddr[i];
			start_slot = total_lfs - numlfs;
			*slot_in_block = global_slot - start_slot;
			break;
		}
	}

	return blkaddr;
}

static void rvu_detach_block(struct rvu *rvu, int pcifunc, int blktype)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int slot, lf, num_lfs;
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, blktype, pcifunc);
	if (blkaddr < 0)
		return;

	if (blktype == BLKTYPE_NIX)
		rvu_nix_reset_mac(pfvf, pcifunc);

	block = &hw->block[blkaddr];

	num_lfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
	if (!num_lfs)
		return;

	for (slot = 0; slot < num_lfs; slot++) {
		lf = rvu_lookup_rsrc(rvu, block, pcifunc, slot);
		if (lf < 0) /* This should never happen */
			continue;

		/* Disable the LF */
		rvu_write64(rvu, blkaddr, block->lfcfg_reg |
			    (lf << block->lfshift), 0x00ULL);

		/* Update SW maintained mapping info as well */
		rvu_update_rsrc_map(rvu, pfvf, block,
				    pcifunc, lf, false);

		/* Free the resource */
		rvu_free_rsrc(&block->lf, lf);

		/* Clear MSIX vector offset for this LF */
		rvu_clear_msix_offset(rvu, pfvf, block, lf);
	}
}

static int rvu_detach_rsrcs(struct rvu *rvu, struct rsrc_detach *detach,
			    u16 pcifunc)
{
	struct rvu_hwinfo *hw = rvu->hw;
	bool detach_all = true;
	struct rvu_block *block;
	int blkid;

	mutex_lock(&rvu->rsrc_lock);

	/* Check for partial resource detach */
	if (detach && detach->partial)
		detach_all = false;

	/* Check for RVU block's LFs attached to this func,
	 * if so, detach them.
	 */
	for (blkid = 0; blkid < BLK_COUNT; blkid++) {
		block = &hw->block[blkid];
		if (!block->lf.bmap)
			continue;
		if (!detach_all && detach) {
			if (blkid == BLKADDR_NPA && !detach->npalf)
				continue;
			else if ((blkid == BLKADDR_NIX0) && !detach->nixlf)
				continue;
			else if ((blkid == BLKADDR_NIX1) && !detach->nixlf)
				continue;
			else if ((blkid == BLKADDR_SSO) && !detach->sso)
				continue;
			else if ((blkid == BLKADDR_SSOW) && !detach->ssow)
				continue;
			else if ((blkid == BLKADDR_TIM) && !detach->timlfs)
				continue;
			else if ((blkid == BLKADDR_CPT0) && !detach->cptlfs)
				continue;
			else if ((blkid == BLKADDR_CPT1) && !detach->cptlfs)
				continue;
			else if ((blkid == BLKADDR_REE0) && !detach->reelfs)
				continue;
			else if ((blkid == BLKADDR_REE1) && !detach->reelfs)
				continue;
		}
		rvu_detach_block(rvu, pcifunc, block->type);
	}

	mutex_unlock(&rvu->rsrc_lock);
	return 0;
}

int rvu_mbox_handler_detach_resources(struct rvu *rvu,
				      struct rsrc_detach *detach,
				      struct msg_rsp *rsp)
{
	return rvu_detach_rsrcs(rvu, detach, detach->hdr.pcifunc);
}

int rvu_get_nix_blkaddr(struct rvu *rvu, u16 pcifunc)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	int blkaddr = BLKADDR_NIX0, vf;
	struct rvu_pfvf *pf;

	pf = rvu_get_pfvf(rvu, pcifunc & ~RVU_PFVF_FUNC_MASK);

	/* All CGX mapped PFs are set with assigned NIX block during init */
	if (is_pf_cgxmapped(rvu, rvu_get_pf(pcifunc))) {
		blkaddr = pf->nix_blkaddr;
	} else if (is_afvf(pcifunc)) {
		vf = pcifunc - 1;
		/* Assign NIX based on VF number. All even numbered VFs get
		 * NIX0 and odd numbered gets NIX1
		 */
		blkaddr = (vf & 1) ? BLKADDR_NIX1 : BLKADDR_NIX0;
		/* NIX1 is not present on all silicons */
		if (!is_block_implemented(rvu->hw, BLKADDR_NIX1))
			blkaddr = BLKADDR_NIX0;
	}

	/* if SDP1 then the blkaddr is NIX1 */
	if (is_sdp_pfvf(pcifunc) && pf->sdp_info->node_id == 1)
		blkaddr = BLKADDR_NIX1;

	switch (blkaddr) {
	case BLKADDR_NIX1:
		pfvf->nix_blkaddr = BLKADDR_NIX1;
		pfvf->nix_rx_intf = NIX_INTFX_RX(1);
		pfvf->nix_tx_intf = NIX_INTFX_TX(1);
		break;
	case BLKADDR_NIX0:
	default:
		pfvf->nix_blkaddr = BLKADDR_NIX0;
		pfvf->nix_rx_intf = NIX_INTFX_RX(0);
		pfvf->nix_tx_intf = NIX_INTFX_TX(0);
		break;
	}

	return pfvf->nix_blkaddr;
}

static int rvu_get_attach_blkaddr(struct rvu *rvu, int blktype,
				  u16 pcifunc, struct rsrc_attach *attach)
{
	int blkaddr;

	switch (blktype) {
	case BLKTYPE_NIX:
		blkaddr = rvu_get_nix_blkaddr(rvu, pcifunc);
		break;
	case BLKTYPE_CPT:
		if (attach->hdr.ver < RVU_MULTI_BLK_VER)
			return rvu_get_blkaddr(rvu, blktype, 0);
		blkaddr = attach->cpt_blkaddr ? attach->cpt_blkaddr :
			  BLKADDR_CPT0;
		if (blkaddr != BLKADDR_CPT0 && blkaddr != BLKADDR_CPT1)
			return -ENODEV;
		break;
	case BLKTYPE_REE:
		blkaddr = attach->ree_blkaddr ? attach->ree_blkaddr :
			  BLKADDR_REE0;
		if (blkaddr != BLKADDR_REE0 && blkaddr != BLKADDR_REE1)
			return -ENODEV;
		break;
	default:
		return rvu_get_blkaddr(rvu, blktype, 0);
	}

	if (is_block_implemented(rvu->hw, blkaddr))
		return blkaddr;

	return -ENODEV;
}

static void rvu_attach_block(struct rvu *rvu, int pcifunc, int blktype,
			     int num_lfs, struct rsrc_attach *attach)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int slot, lf;
	int blkaddr;
	u64 cfg;

	if (!num_lfs)
		return;

	blkaddr = rvu_get_attach_blkaddr(rvu, blktype, pcifunc, attach);
	if (blkaddr < 0)
		return;

	block = &hw->block[blkaddr];
	if (!block->lf.bmap)
		return;

	for (slot = 0; slot < num_lfs; slot++) {
		/* Allocate the resource */
		lf = rvu_alloc_rsrc(&block->lf);
		if (lf < 0)
			return;

		cfg = (1ULL << 63) | (pcifunc << 8) | slot;
		rvu_write64(rvu, blkaddr, block->lfcfg_reg |
			    (lf << block->lfshift), cfg);
		rvu_update_rsrc_map(rvu, pfvf, block,
				    pcifunc, lf, true);

		/* Set start MSIX vector for this LF within this PF/VF */
		rvu_set_msix_offset(rvu, pfvf, block, lf);
	}
}

static int rvu_check_rsrc_availability(struct rvu *rvu,
				       struct rsrc_attach *req, u16 pcifunc)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	int free_lfs, mappedlfs, blkaddr;
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int ret;

	ret = rvu_check_rsrc_policy(rvu, req, pcifunc);
	if (ret) {
		dev_err(rvu->dev, "Func 0x%x: Resource policy check failed\n",
			pcifunc);
		return ret;
	}

	/* Only one NPA LF can be attached */
	if (req->npalf && !is_blktype_attached(pfvf, BLKTYPE_NPA)) {
		block = &hw->block[BLKADDR_NPA];
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (!free_lfs)
			goto fail;
	} else if (req->npalf) {
		dev_err(&rvu->pdev->dev,
			"Func 0x%x: Invalid req, already has NPA\n",
			 pcifunc);
		return -EINVAL;
	}

	/* Only one NIX LF can be attached */
	if (req->nixlf && !is_blktype_attached(pfvf, BLKTYPE_NIX)) {
		blkaddr = rvu_get_attach_blkaddr(rvu, BLKTYPE_NIX,
						 pcifunc, req);
		if (blkaddr < 0)
			return blkaddr;
		block = &hw->block[blkaddr];
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (!free_lfs)
			goto fail;
	} else if (req->nixlf) {
		dev_err(&rvu->pdev->dev,
			"Func 0x%x: Invalid req, already has NIX\n",
			pcifunc);
		return -EINVAL;
	}

	if (req->sso) {
		block = &hw->block[BLKADDR_SSO];
		/* Is request within limits ? */
		if (req->sso > block->lf.max) {
			dev_err(&rvu->pdev->dev,
				"Func 0x%x: Invalid SSO req, %d > max %d\n",
				 pcifunc, req->sso, block->lf.max);
			return -EINVAL;
		}
		mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
		free_lfs = rvu_rsrc_free_count(&block->lf);
		/* Check if additional resources are available */
		if (req->sso > mappedlfs &&
		    ((req->sso - mappedlfs) > free_lfs))
			goto fail;
	}

	if (req->ssow) {
		block = &hw->block[BLKADDR_SSOW];
		if (req->ssow > block->lf.max) {
			dev_err(&rvu->pdev->dev,
				"Func 0x%x: Invalid SSOW req, %d > max %d\n",
				 pcifunc, req->ssow, block->lf.max);
			return -EINVAL;
		}
		mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (req->ssow > mappedlfs &&
		    ((req->ssow - mappedlfs) > free_lfs))
			goto fail;
	}

	if (req->timlfs) {
		block = &hw->block[BLKADDR_TIM];
		if (req->timlfs > block->lf.max) {
			dev_err(&rvu->pdev->dev,
				"Func 0x%x: Invalid TIMLF req, %d > max %d\n",
				 pcifunc, req->timlfs, block->lf.max);
			return -EINVAL;
		}
		mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (req->timlfs > mappedlfs &&
		    ((req->timlfs - mappedlfs) > free_lfs))
			goto fail;
	}

	if (req->cptlfs) {
		blkaddr = rvu_get_attach_blkaddr(rvu, BLKTYPE_CPT,
						 pcifunc, req);
		if (blkaddr < 0)
			return blkaddr;
		block = &hw->block[blkaddr];
		if (req->cptlfs > block->lf.max) {
			dev_err(&rvu->pdev->dev,
				"Func 0x%x: Invalid CPTLF req, %d > max %d\n",
				 pcifunc, req->cptlfs, block->lf.max);
			return -EINVAL;
		}
		mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (req->cptlfs > mappedlfs &&
		    ((req->cptlfs - mappedlfs) > free_lfs))
			goto fail;
	}

	if (req->hdr.ver >= RVU_MULTI_BLK_VER && req->reelfs) {
		blkaddr = rvu_get_attach_blkaddr(rvu, BLKTYPE_REE,
						 pcifunc, req);
		if (blkaddr < 0)
			return blkaddr;
		block = &hw->block[blkaddr];
		if (req->reelfs > block->lf.max) {
			dev_err(&rvu->pdev->dev,
				"Func 0x%x: Invalid REELF req, %d > max %d\n",
				 pcifunc, req->reelfs, block->lf.max);
			return -EINVAL;
		}
		mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (req->reelfs > mappedlfs &&
		    ((req->reelfs - mappedlfs) > free_lfs))
			goto fail;
	}

	return 0;

fail:
	dev_info(rvu->dev, "Request for %s failed\n", block->name);
	return -ENOSPC;
}

static bool rvu_attach_from_same_block(struct rvu *rvu, int blktype,
				       struct rsrc_attach *attach)
{
	int blkaddr, num_lfs;

	blkaddr = rvu_get_attach_blkaddr(rvu, blktype,
					 attach->hdr.pcifunc, attach);
	if (blkaddr < 0)
		return false;

	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, attach->hdr.pcifunc),
					blkaddr);
	/* Requester already has LFs from given block ? */
	return !!num_lfs;
}

int rvu_mbox_handler_attach_resources(struct rvu *rvu,
				      struct rsrc_attach *attach,
				      struct msg_rsp *rsp)
{
	u16 pcifunc = attach->hdr.pcifunc;
	int err;

	/* If first request, detach all existing attached resources */
	if (!attach->modify)
		rvu_detach_rsrcs(rvu, NULL, pcifunc);

	mutex_lock(&rvu->rsrc_lock);

	/* Check if the request can be accommodated */
	err = rvu_check_rsrc_availability(rvu, attach, pcifunc);
	if (err)
		goto exit;

	/* Now attach the requested resources */
	if (attach->nixlf)
		rvu_attach_block(rvu, pcifunc, BLKTYPE_NIX, 1, attach);

	if (attach->npalf)
		rvu_attach_block(rvu, pcifunc, BLKTYPE_NPA, 1, attach);

	if (attach->sso) {
		/* RVU func doesn't know which exact LF or slot is attached
		 * to it, it always sees as slot 0,1,2. So for a 'modify'
		 * request, simply detach all existing attached LFs/slots
		 * and attach a fresh.
		 */
		if (attach->modify)
			rvu_detach_block(rvu, pcifunc, BLKTYPE_SSO);
		rvu_attach_block(rvu, pcifunc, BLKTYPE_SSO,
				 attach->sso, attach);
	}

	if (attach->ssow) {
		if (attach->modify)
			rvu_detach_block(rvu, pcifunc, BLKTYPE_SSOW);
		rvu_attach_block(rvu, pcifunc, BLKTYPE_SSOW,
				 attach->ssow, attach);
	}

	if (attach->timlfs) {
		if (attach->modify)
			rvu_detach_block(rvu, pcifunc, BLKTYPE_TIM);
		rvu_attach_block(rvu, pcifunc, BLKTYPE_TIM,
				 attach->timlfs, attach);
	}

	if (attach->cptlfs) {
		if (attach->modify &&
		    rvu_attach_from_same_block(rvu, BLKTYPE_CPT, attach))
			rvu_detach_block(rvu, pcifunc, BLKTYPE_CPT);
		rvu_attach_block(rvu, pcifunc, BLKTYPE_CPT,
				 attach->cptlfs, attach);
	}

	if (attach->hdr.ver >= RVU_MULTI_BLK_VER && attach->reelfs) {
		if (attach->modify &&
		    rvu_attach_from_same_block(rvu, BLKTYPE_REE, attach))
			rvu_detach_block(rvu, pcifunc, BLKTYPE_REE);
		rvu_attach_block(rvu, pcifunc, BLKTYPE_REE,
				 attach->reelfs, attach);
	}

exit:
	mutex_unlock(&rvu->rsrc_lock);
	return err;
}

static u16 rvu_get_msix_offset(struct rvu *rvu, struct rvu_pfvf *pfvf,
			       int blkaddr, int lf)
{
	u16 vec;

	if (lf < 0)
		return MSIX_VECTOR_INVALID;

	for (vec = 0; vec < pfvf->msix.max; vec++) {
		if (pfvf->msix_lfmap[vec] == MSIX_BLKLF(blkaddr, lf))
			return vec;
	}
	return MSIX_VECTOR_INVALID;
}

static void rvu_set_msix_offset(struct rvu *rvu, struct rvu_pfvf *pfvf,
				struct rvu_block *block, int lf)
{
	u16 nvecs, vec, offset;
	u64 cfg;

	cfg = rvu_read64(rvu, block->addr, block->msixcfg_reg |
			 (lf << block->lfshift));
	nvecs = (cfg >> 12) & 0xFF;

	/* Check and alloc MSIX vectors, must be contiguous */
	if (!rvu_rsrc_check_contig(&pfvf->msix, nvecs))
		return;

	offset = rvu_alloc_rsrc_contig(&pfvf->msix, nvecs);

	/* Config MSIX offset in LF */
	rvu_write64(rvu, block->addr, block->msixcfg_reg |
		    (lf << block->lfshift), (cfg & ~0x7FFULL) | offset);

	/* Update the bitmap as well */
	for (vec = 0; vec < nvecs; vec++)
		pfvf->msix_lfmap[offset + vec] = MSIX_BLKLF(block->addr, lf);
}

static void rvu_clear_msix_offset(struct rvu *rvu, struct rvu_pfvf *pfvf,
				  struct rvu_block *block, int lf)
{
	u16 nvecs, vec, offset;
	u64 cfg;

	cfg = rvu_read64(rvu, block->addr, block->msixcfg_reg |
			 (lf << block->lfshift));
	nvecs = (cfg >> 12) & 0xFF;

	/* Clear MSIX offset in LF */
	rvu_write64(rvu, block->addr, block->msixcfg_reg |
		    (lf << block->lfshift), cfg & ~0x7FFULL);

	offset = rvu_get_msix_offset(rvu, pfvf, block->addr, lf);
	if (offset == MSIX_VECTOR_INVALID)
		return;

	/* Update the mapping */
	for (vec = 0; vec < nvecs; vec++)
		pfvf->msix_lfmap[offset + vec] = 0;

	/* Free the same in MSIX bitmap */
	rvu_free_rsrc_contig(&pfvf->msix, nvecs, offset);
}

int rvu_mbox_handler_msix_offset(struct rvu *rvu, struct msg_req *req,
				 struct msix_offset_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_pfvf *pfvf;
	int lf, slot, blkaddr;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	if (!pfvf->msix.bmap)
		return 0;

	/* Set MSIX offsets for each block's LFs attached to this PF/VF */
	lf = rvu_get_lf(rvu, &hw->block[BLKADDR_NPA], pcifunc, 0);
	rsp->npa_msixoff = rvu_get_msix_offset(rvu, pfvf, BLKADDR_NPA, lf);

	/* Get BLKADDR from which LFs are attached to pcifunc */
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	if (blkaddr < 0) {
		rsp->nix_msixoff = MSIX_VECTOR_INVALID;
	} else {
		lf = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, 0);
		rsp->nix_msixoff = rvu_get_msix_offset(rvu, pfvf, blkaddr, lf);
	}

	rsp->sso = pfvf->sso;
	for (slot = 0; slot < rsp->sso; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_SSO], pcifunc, slot);
		rsp->sso_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_SSO, lf);
	}

	rsp->ssow = pfvf->ssow;
	for (slot = 0; slot < rsp->ssow; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_SSOW], pcifunc, slot);
		rsp->ssow_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_SSOW, lf);
	}

	rsp->timlfs = pfvf->timlfs;
	for (slot = 0; slot < rsp->timlfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_TIM], pcifunc, slot);
		rsp->timlf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_TIM, lf);
	}

	rsp->cptlfs = pfvf->cptlfs;
	for (slot = 0; slot < rsp->cptlfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_CPT0], pcifunc, slot);
		rsp->cptlf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_CPT0, lf);
	}

	rsp->cpt1_lfs = pfvf->cpt1_lfs;
	for (slot = 0; slot < rsp->cpt1_lfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_CPT1], pcifunc, slot);
		rsp->cpt1_lf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_CPT1, lf);
	}

	rsp->ree0_lfs = pfvf->ree0_lfs;
	for (slot = 0; slot < rsp->ree0_lfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_REE0], pcifunc, slot);
		rsp->ree0_lf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_REE0, lf);
	}

	rsp->ree1_lfs = pfvf->ree1_lfs;
	for (slot = 0; slot < rsp->ree1_lfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_REE1], pcifunc, slot);
		rsp->ree1_lf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_REE1, lf);
	}

	return 0;
}

int rvu_mbox_handler_vf_flr(struct rvu *rvu, struct msg_req *req,
			    struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	u16 vf, numvfs;
	u64 cfg;

	vf = pcifunc & RVU_PFVF_FUNC_MASK;
	cfg = rvu_read64(rvu, BLKADDR_RVUM,
			 RVU_PRIV_PFX_CFG(rvu_get_pf(pcifunc)));
	numvfs = (cfg >> 12) & 0xFF;

	if (vf && vf <= numvfs)
		__rvu_flr_handler(rvu, pcifunc);
	else
		return RVU_INVALID_VF_ID;

	return 0;
}

int rvu_ndc_sync(struct rvu *rvu, int lfblkaddr, int lfidx, u64 lfoffset)
{
	/* Sync cached info for this LF in NDC to LLC/DRAM */
	rvu_write64(rvu, lfblkaddr, lfoffset, BIT_ULL(12) | lfidx);
	return rvu_poll_reg(rvu, lfblkaddr, lfoffset, BIT_ULL(12), true);
}

int rvu_mbox_handler_get_hw_cap(struct rvu *rvu, struct msg_req *req,
				struct get_hw_cap_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;

	rsp->nix_fixed_txschq_mapping = hw->cap.nix_fixed_txschq_mapping;
	rsp->nix_shaping = hw->cap.nix_shaping;
	rsp->npc_hash_extract = hw->cap.npc_hash_extract;

	return 0;
}

int rvu_mbox_handler_ndc_sync_op(struct rvu *rvu,
				 struct ndc_sync_op *req,
				 struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int err, lfidx, lfblkaddr;

	if (req->npa_lf_sync) {
		/* Get NPA LF data */
		lfblkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPA, pcifunc);
		if (lfblkaddr < 0)
			return NPA_AF_ERR_AF_LF_INVALID;

		lfidx = rvu_get_lf(rvu, &hw->block[lfblkaddr], pcifunc, 0);
		if (lfidx < 0)
			return NPA_AF_ERR_AF_LF_INVALID;

		/* Sync NPA NDC */
		err = rvu_ndc_sync(rvu, lfblkaddr,
				   lfidx, NPA_AF_NDC_SYNC);
		if (err)
			dev_err(rvu->dev,
				"NDC-NPA sync failed for LF %u\n", lfidx);
	}

	if (!req->nix_lf_tx_sync && !req->nix_lf_rx_sync)
		return 0;

	/* Get NIX LF data */
	lfblkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	if (lfblkaddr < 0)
		return NIX_AF_ERR_AF_LF_INVALID;

	lfidx = rvu_get_lf(rvu, &hw->block[lfblkaddr], pcifunc, 0);
	if (lfidx < 0)
		return NIX_AF_ERR_AF_LF_INVALID;

	if (req->nix_lf_tx_sync) {
		/* Sync NIX TX NDC */
		err = rvu_ndc_sync(rvu, lfblkaddr,
				   lfidx, NIX_AF_NDC_TX_SYNC);
		if (err)
			dev_err(rvu->dev,
				"NDC-NIX-TX sync fail for LF %u\n", lfidx);
	}

	if (req->nix_lf_rx_sync) {
		/* Sync NIX RX NDC */
		err = rvu_ndc_sync(rvu, lfblkaddr,
				   lfidx, NIX_AF_NDC_RX_SYNC);
		if (err)
			dev_err(rvu->dev,
				"NDC-NIX-RX sync failed for LF %u\n", lfidx);
	}

	return 0;
}

int rvu_mbox_handler_set_vf_perm(struct rvu *rvu, struct set_vf_perm *req,
				 struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_pfvf *pfvf;
	int blkaddr, nixlf;
	u16 target;

	/* Only PF can add VF permissions */
	if ((pcifunc & RVU_PFVF_FUNC_MASK) || is_afvf(pcifunc))
		return -EOPNOTSUPP;

	target = (pcifunc & ~RVU_PFVF_FUNC_MASK) | (req->vf + 1);
	pfvf = rvu_get_pfvf(rvu, target);

	if (req->flags & RESET_VF_PERM) {
		pfvf->flags &= RVU_CLEAR_VF_PERM;
	} else if (test_bit(PF_SET_VF_TRUSTED, &pfvf->flags) ^
		 (req->flags & VF_TRUSTED)) {
		change_bit(PF_SET_VF_TRUSTED, &pfvf->flags);
		/* disable multicast and promisc entries */
		if (!test_bit(PF_SET_VF_TRUSTED, &pfvf->flags)) {
			blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, target);
			if (blkaddr < 0)
				return 0;
			nixlf = rvu_get_lf(rvu, &hw->block[blkaddr],
					   target, 0);
			if (nixlf < 0)
				return 0;
			npc_enadis_default_mce_entry(rvu, target, nixlf,
						     NIXLF_ALLMULTI_ENTRY,
						     false);
			npc_enadis_default_mce_entry(rvu, target, nixlf,
						     NIXLF_PROMISC_ENTRY,
						     false);
		}
	}

	return 0;
}

static int rvu_process_mbox_msg(struct otx2_mbox *mbox, int devid,
				struct mbox_msghdr *req)
{
	struct rvu *rvu = pci_get_drvdata(mbox->pdev);

	/* Check if valid, if not reply with a invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG)
		goto bad_message;

	switch (req->id) {
#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
	case _id: {							\
		struct _rsp_type *rsp;					\
		int err;						\
									\
		rsp = (struct _rsp_type *)otx2_mbox_alloc_msg(		\
			mbox, devid,					\
			sizeof(struct _rsp_type));			\
		/* some handlers should complete even if reply */	\
		/* could not be allocated */				\
		if (!rsp &&						\
		    _id != MBOX_MSG_DETACH_RESOURCES &&			\
		    _id != MBOX_MSG_NIX_TXSCH_FREE &&			\
		    _id != MBOX_MSG_VF_FLR)				\
			return -ENOMEM;					\
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
		trace_otx2_msg_process(mbox->pdev, _id, err);		\
		return rsp ? err : -ENOMEM;				\
	}
MBOX_MESSAGES
MBOX_MCS_FIPS_MESSAGES
#undef M

bad_message:
	default:
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}
}

static void __rvu_mbox_handler(struct rvu_work *mwork, int type)
{
	struct rvu *rvu = mwork->rvu;
	int offset, err, id, devid;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	struct mbox_wq_info *mw;
	struct otx2_mbox *mbox;

	switch (type) {
	case TYPE_AFPF:
		mw = &rvu->afpf_wq_info;
		break;
	case TYPE_AFVF:
		mw = &rvu->afvf_wq_info;
		break;
	default:
		return;
	}

	devid = mwork - mw->mbox_wrk;
	mbox = &mw->mbox;
	mdev = &mbox->dev[devid];

	/* Process received mbox messages */
	req_hdr = mdev->mbase + mbox->rx_start;
	if (mw->mbox_wrk[devid].num_msgs == 0)
		return;

	offset = mbox->rx_start + ALIGN(sizeof(*req_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < mw->mbox_wrk[devid].num_msgs; id++) {
		msg = mdev->mbase + offset;

		/* Set which PF/VF sent this message based on mbox IRQ */
		switch (type) {
		case TYPE_AFPF:
			msg->pcifunc &=
				~(RVU_PFVF_PF_MASK << RVU_PFVF_PF_SHIFT);
			msg->pcifunc |= (devid << RVU_PFVF_PF_SHIFT);
			break;
		case TYPE_AFVF:
			msg->pcifunc &=
				~(RVU_PFVF_FUNC_MASK << RVU_PFVF_FUNC_SHIFT);
			msg->pcifunc |= (devid << RVU_PFVF_FUNC_SHIFT) + 1;
			break;
		}

		err = rvu_process_mbox_msg(mbox, devid, msg);
		if (!err) {
			offset = mbox->rx_start + msg->next_msgoff;
			continue;
		}

		if (msg->pcifunc & RVU_PFVF_FUNC_MASK)
			dev_warn(rvu->dev, "Error %d when processing message %s (0x%x) from PF%d:VF%d\n",
				 err, otx2_mbox_id2name(msg->id),
				 msg->id, rvu_get_pf(msg->pcifunc),
				 (msg->pcifunc & RVU_PFVF_FUNC_MASK) - 1);
		else
			dev_warn(rvu->dev, "Error %d when processing message %s (0x%x) from PF%d\n",
				 err, otx2_mbox_id2name(msg->id),
				 msg->id, devid);
	}
	mw->mbox_wrk[devid].num_msgs = 0;

	/* Send mbox responses to VF/PF */
	otx2_mbox_msg_send(mbox, devid);
}

static inline void rvu_afpf_mbox_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);

	__rvu_mbox_handler(mwork, TYPE_AFPF);
}

static inline void rvu_afvf_mbox_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);

	__rvu_mbox_handler(mwork, TYPE_AFVF);
}

static void __rvu_mbox_up_handler(struct rvu_work *mwork, int type)
{
	struct rvu *rvu = mwork->rvu;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	struct mbox_wq_info *mw;
	struct otx2_mbox *mbox;
	int offset, id, devid;

	switch (type) {
	case TYPE_AFPF:
		mw = &rvu->afpf_wq_info;
		break;
	case TYPE_AFVF:
		mw = &rvu->afvf_wq_info;
		break;
	default:
		return;
	}

	devid = mwork - mw->mbox_wrk_up;
	mbox = &mw->mbox_up;
	mdev = &mbox->dev[devid];

	rsp_hdr = mdev->mbase + mbox->rx_start;
	if (mw->mbox_wrk_up[devid].up_num_msgs == 0) {
		dev_warn(rvu->dev, "mbox up handler: num_msgs = 0\n");
		return;
	}

	offset = mbox->rx_start + ALIGN(sizeof(*rsp_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < mw->mbox_wrk_up[devid].up_num_msgs; id++) {
		msg = mdev->mbase + offset;

		if (msg->id >= MBOX_MSG_MAX) {
			dev_err(rvu->dev,
				"Mbox msg with unknown ID 0x%x\n", msg->id);
			goto end;
		}

		if (msg->sig != OTX2_MBOX_RSP_SIG) {
			dev_err(rvu->dev,
				"Mbox msg with wrong signature %x, ID 0x%x\n",
				msg->sig, msg->id);
			goto end;
		}

		switch (msg->id) {
		case MBOX_MSG_CGX_LINK_EVENT:
			break;
		default:
			if (msg->rc)
				dev_err(rvu->dev,
					"Mbox msg response has err %d, ID 0x%x\n",
					msg->rc, msg->id);
			break;
		}
end:
		offset = mbox->rx_start + msg->next_msgoff;
		mdev->msgs_acked++;
	}
	mw->mbox_wrk_up[devid].up_num_msgs = 0;

	otx2_mbox_reset(mbox, devid);
}

static inline void rvu_afpf_mbox_up_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);

	__rvu_mbox_up_handler(mwork, TYPE_AFPF);
}

static inline void rvu_afvf_mbox_up_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);

	__rvu_mbox_up_handler(mwork, TYPE_AFVF);
}

static int rvu_get_mbox_regions(struct rvu *rvu, void **mbox_addr,
				int num, int type, unsigned long *pf_bmap)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int region;
	u64 bar4;

	/* For cn10k platform VF mailbox regions of a PF follows after the
	 * PF <-> AF mailbox region. Whereas for Octeontx2 it is read from
	 * RVU_PF_VF_BAR4_ADDR register.
	 */
	if (type == TYPE_AFVF) {
		for (region = 0; region < num; region++) {
			if (!test_bit(region, pf_bmap))
				continue;

			if (hw->cap.per_pf_mbox_regs) {
				bar4 = rvu_read64(rvu, BLKADDR_RVUM,
						  RVU_AF_PFX_BAR4_ADDR(0)) +
						  MBOX_SIZE;
				bar4 += region * MBOX_SIZE;
			} else {
				bar4 = rvupf_read64(rvu, RVU_PF_VF_BAR4_ADDR);
				bar4 += region * MBOX_SIZE;
			}
			mbox_addr[region] = (void *)ioremap_wc(bar4, MBOX_SIZE);
			if (!mbox_addr[region])
				goto error;
		}
		return 0;
	}

	/* For cn10k platform AF <-> PF mailbox region of a PF is read from per
	 * PF registers. Whereas for Octeontx2 it is read from
	 * RVU_AF_PF_BAR4_ADDR register.
	 */
	for (region = 0; region < num; region++) {
		if (!test_bit(region, pf_bmap))
			continue;

		if (hw->cap.per_pf_mbox_regs) {
			bar4 = rvu_read64(rvu, BLKADDR_RVUM,
					  RVU_AF_PFX_BAR4_ADDR(region));
		} else {
			bar4 = rvu_read64(rvu, BLKADDR_RVUM,
					  RVU_AF_PF_BAR4_ADDR);
			bar4 += region * MBOX_SIZE;
		}
		mbox_addr[region] = (void *)ioremap_wc(bar4, MBOX_SIZE);
		if (!mbox_addr[region])
			goto error;
	}
	return 0;

error:
	while (region--)
		iounmap((void __iomem *)mbox_addr[region]);
	return -ENOMEM;
}

static int rvu_mbox_init(struct rvu *rvu, struct mbox_wq_info *mw,
			 int type, int num,
			 void (mbox_handler)(struct work_struct *),
			 void (mbox_up_handler)(struct work_struct *))
{
	int err = -EINVAL, i, dir, dir_up;
	void __iomem *reg_base;
	struct rvu_work *mwork;
	unsigned long *pf_bmap;
	void **mbox_regions;
	const char *name;
	u64 cfg;

	pf_bmap = devm_kcalloc(rvu->dev, BITS_TO_LONGS(num), sizeof(long), GFP_KERNEL);
	if (!pf_bmap)
		return -ENOMEM;

	/* RVU VFs */
	if (type == TYPE_AFVF)
		bitmap_set(pf_bmap, 0, num);

	if (type == TYPE_AFPF) {
		/* Mark enabled PFs in bitmap */
		for (i = 0; i < num; i++) {
			cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(i));
			if (cfg & BIT_ULL(20))
				set_bit(i, pf_bmap);
		}
	}

	mbox_regions = kcalloc(num, sizeof(void *), GFP_KERNEL);
	if (!mbox_regions)
		return -ENOMEM;

	switch (type) {
	case TYPE_AFPF:
		name = "rvu_afpf_mailbox";
		dir = MBOX_DIR_AFPF;
		dir_up = MBOX_DIR_AFPF_UP;
		reg_base = rvu->afreg_base;
		err = rvu_get_mbox_regions(rvu, mbox_regions, num, TYPE_AFPF, pf_bmap);
		if (err)
			goto free_regions;
		break;
	case TYPE_AFVF:
		name = "rvu_afvf_mailbox";
		dir = MBOX_DIR_PFVF;
		dir_up = MBOX_DIR_PFVF_UP;
		reg_base = rvu->pfreg_base;
		err = rvu_get_mbox_regions(rvu, mbox_regions, num, TYPE_AFVF, pf_bmap);
		if (err)
			goto free_regions;
		break;
	default:
		return err;
	}

	mw->mbox_wq = alloc_workqueue(name,
				      WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM,
				      num);
	if (!mw->mbox_wq) {
		err = -ENOMEM;
		goto unmap_regions;
	}

	mw->mbox_wrk = devm_kcalloc(rvu->dev, num,
				    sizeof(struct rvu_work), GFP_KERNEL);
	if (!mw->mbox_wrk) {
		err = -ENOMEM;
		goto exit;
	}

	mw->mbox_wrk_up = devm_kcalloc(rvu->dev, num,
				       sizeof(struct rvu_work), GFP_KERNEL);
	if (!mw->mbox_wrk_up) {
		err = -ENOMEM;
		goto exit;
	}

	err = otx2_mbox_regions_init(&mw->mbox, mbox_regions, rvu->pdev,
				     reg_base, dir, num, pf_bmap);
	if (err)
		goto exit;

	err = otx2_mbox_regions_init(&mw->mbox_up, mbox_regions, rvu->pdev,
				     reg_base, dir_up, num, pf_bmap);
	if (err)
		goto exit;

	for (i = 0; i < num; i++) {
		if (!test_bit(i, pf_bmap))
			continue;

		mwork = &mw->mbox_wrk[i];
		mwork->rvu = rvu;
		INIT_WORK(&mwork->work, mbox_handler);

		mwork = &mw->mbox_wrk_up[i];
		mwork->rvu = rvu;
		INIT_WORK(&mwork->work, mbox_up_handler);
	}
	kfree(mbox_regions);
	return 0;

exit:
	destroy_workqueue(mw->mbox_wq);
unmap_regions:
	while (num--)
		iounmap((void __iomem *)mbox_regions[num]);
free_regions:
	kfree(mbox_regions);
	return err;
}

static void rvu_mbox_destroy(struct mbox_wq_info *mw)
{
	struct otx2_mbox *mbox = &mw->mbox;
	struct otx2_mbox_dev *mdev;
	int devid;

	if (mw->mbox_wq) {
		flush_workqueue(mw->mbox_wq);
		destroy_workqueue(mw->mbox_wq);
		mw->mbox_wq = NULL;
	}

	for (devid = 0; devid < mbox->ndevs; devid++) {
		mdev = &mbox->dev[devid];
		if (mdev->hwbase)
			iounmap((void __iomem *)mdev->hwbase);
	}

	otx2_mbox_destroy(&mw->mbox);
	otx2_mbox_destroy(&mw->mbox_up);
}

static void rvu_queue_work(struct mbox_wq_info *mw, int first,
			   int mdevs, u64 intr)
{
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;
	int i;

	for (i = first; i < mdevs; i++) {
		/* start from 0 */
		if (!(intr & BIT_ULL(i - first)))
			continue;

		mbox = &mw->mbox;
		mdev = &mbox->dev[i];
		hdr = mdev->mbase + mbox->rx_start;

		/*The hdr->num_msgs is set to zero immediately in the interrupt
		 * handler to  ensure that it holds a correct value next time
		 * when the interrupt handler is called.
		 * pf->mbox.num_msgs holds the data for use in pfaf_mbox_handler
		 * pf>mbox.up_num_msgs holds the data for use in
		 * pfaf_mbox_up_handler.
		 */

		if (hdr->num_msgs) {
			mw->mbox_wrk[i].num_msgs = hdr->num_msgs;
			hdr->num_msgs = 0;
			queue_work(mw->mbox_wq, &mw->mbox_wrk[i].work);
		}
		mbox = &mw->mbox_up;
		mdev = &mbox->dev[i];
		hdr = mdev->mbase + mbox->rx_start;
		if (hdr->num_msgs) {
			mw->mbox_wrk_up[i].up_num_msgs = hdr->num_msgs;
			hdr->num_msgs = 0;
			queue_work(mw->mbox_wq, &mw->mbox_wrk_up[i].work);
		}
	}
}

static irqreturn_t rvu_mbox_pf_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	u64 intr;

	intr = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFAF_MBOX_INT);
	/* Clear interrupts */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFAF_MBOX_INT, intr);
	if (intr)
		trace_otx2_msg_interrupt(rvu->pdev, "PF(s) to AF", intr);

	/* Sync with mbox memory region */
	rmb();

	rvu_queue_work(&rvu->afpf_wq_info, 0, rvu->hw->total_pfs, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_mbox_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	int vfs = rvu->vfs;
	u64 intr;

	/* Sync with mbox memory region */
	rmb();

	/* Handle VF interrupts */
	if (vfs > 64) {
		intr = rvupf_read64(rvu, RVU_PF_VFPF_MBOX_INTX(1));
		rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INTX(1), intr);

		rvu_queue_work(&rvu->afvf_wq_info, 64, vfs, intr);
		vfs = 64;
	}

	intr = rvupf_read64(rvu, RVU_PF_VFPF_MBOX_INTX(0));
	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INTX(0), intr);
	if (intr)
		trace_otx2_msg_interrupt(rvu->pdev, "VF(s) to AF", intr);

	rvu_queue_work(&rvu->afvf_wq_info, 0, vfs, intr);

	return IRQ_HANDLED;
}

static void rvu_enable_mbox_intr(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;

	/* Clear spurious irqs, if any */
	rvu_write64(rvu, BLKADDR_RVUM,
		    RVU_AF_PFAF_MBOX_INT, INTR_MASK(hw->total_pfs));

	/* Enable mailbox interrupt for all PFs except PF0 i.e AF itself */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFAF_MBOX_INT_ENA_W1S,
		    INTR_MASK(hw->total_pfs) & ~1ULL);
}

static void rvu_npa_lf_mapped_nix_lf_teardown(struct rvu *rvu, u16 pcifunc)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *nix_block;
	struct rsrc_detach detach;
	u16 nix_pcifunc;
	int blkaddr, lf;
	u64 regval;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	if (blkaddr < 0)
		return;

	nix_block = &hw->block[blkaddr];
	for (lf = 0; lf < nix_block->lf.max; lf++) {
		/* Loop through all the NIX LFs and check if the NPA lf is
		 * being used based on pcifunc.
		 */
		regval = rvu_read64(rvu, blkaddr, NIX_AF_LFX_CFG(lf));
		if ((regval & 0xFFFF) != pcifunc)
			continue;

		nix_pcifunc = nix_block->fn_map[lf];

		/* Skip NIX LF attached to the pcifunc as it is already
		 * quiesced.
		 */
		if (nix_pcifunc == pcifunc)
			continue;

		detach.partial = true;
		detach.nixlf   = true;
		/* Teardown the NIX LF. */
		rvu_nix_lf_teardown(rvu, nix_pcifunc, blkaddr, lf);
		rvu_lf_reset(rvu, nix_block, lf);
		/* Detach the NIX LF. */
		rvu_detach_rsrcs(rvu, &detach, nix_pcifunc);
	}
}

static void rvu_npa_lf_mapped_sso_lf_teardown(struct rvu *rvu, u16 pcifunc)
{
	int npa_blkaddr, blkaddr, lf, retry;
	u16 sso_pcifunc, match_cnt = 0;
	struct rvu_block *sso_block;
	struct rsrc_detach detach;
	unsigned long drain_tmo;
	u16 *pcifunc_arr;
	u64 regval;

	pcifunc_arr = kcalloc(rvu->hw->total_pfs + rvu->hw->total_vfs,
			      sizeof(*pcifunc_arr), GFP_KERNEL);
	if (!pcifunc_arr)
		return;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SSO, 0);
	if (blkaddr < 0)
		return;

	npa_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPA, 0);
	if (blkaddr < 0)
		return;

	regval = BIT_ULL(16) | pcifunc;
	rvu_bar2_sel_write64(rvu, npa_blkaddr, NPA_AF_BAR2_SEL, regval);

	sso_block = &rvu->hw->block[blkaddr];
	retry = 0;
	drain_tmo = jiffies + msecs_to_jiffies(SSO_FLUSH_TMO_MAX);
	for (lf = 0; lf < sso_block->lf.max || retry; lf++) {
		if (lf == sso_block->lf.max) {
			if (time_after(jiffies, drain_tmo)) {
				dev_err(rvu->dev, "Failed to drain SSO queues\n");
				break;
			}

			lf = 0;
			retry = 0;
		}
		regval = rvu_read64(rvu, blkaddr, SSO_AF_XAQX_GMCTL(lf));
		if ((regval & 0xFFFF) != pcifunc)
			continue;

		sso_pcifunc = sso_block->fn_map[lf];
		regval = rvu_read64(rvu, blkaddr, sso_block->lfcfg_reg |
				    (lf << sso_block->lfshift));
		if (rvu_sso_lf_drain_queues(rvu, sso_pcifunc, lf,
					    regval & 0xF) == -EAGAIN) {
			retry = 1;
			continue;
		}

		regval = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_XAQ_AURA(lf));
		rvu_sso_deinit_xaq_aura(rvu, blkaddr, npa_blkaddr, regval, lf);
	}

	for (lf = 0; lf < sso_block->lf.max; lf++) {
		regval = rvu_read64(rvu, blkaddr, SSO_AF_XAQX_GMCTL(lf));
		if ((regval & 0xFFFF) != pcifunc)
			continue;

		regval = rvu_read64(rvu, blkaddr, SSO_AF_HWGRPX_XAQ_AURA(lf));
		if (rvu_sso_poll_aura_cnt(rvu, npa_blkaddr, regval))
			dev_err(rvu->dev,
				"[%d]Failed to free XAQs to aura[%lld]\n",
				__LINE__, regval);

		rvu_sso_xaq_aura_write(rvu, lf, 0);
		rvu_write64(rvu, blkaddr, SSO_AF_XAQX_GMCTL(lf), 0);
	}

	for (lf = 0; lf < sso_block->lf.max; lf++) {
		regval = rvu_read64(rvu, blkaddr, SSO_AF_XAQX_GMCTL(lf));
		if ((regval & 0xFFFF) != pcifunc)
			continue;

		sso_pcifunc = sso_block->fn_map[lf];
		regval = rvu_read64(rvu, blkaddr, sso_block->lfcfg_reg |
				    (lf << sso_block->lfshift));
		/* Save SSO PF_FUNC info to detach all LFs of that PF_FUNC at
		 * once later.
		 */
		rvu_sso_lf_teardown(rvu, sso_pcifunc, lf, regval & 0xF);
		rvu_lf_reset(rvu, sso_block, lf);
		pcifunc_arr[match_cnt] = sso_pcifunc;
		match_cnt++;
	}
	rvu_bar2_sel_write64(rvu, npa_blkaddr, NPA_AF_BAR2_SEL, 0);

	detach.partial = true;
	detach.sso   = true;

	for (sso_pcifunc = 0; sso_pcifunc < match_cnt; sso_pcifunc++)
		rvu_detach_rsrcs(rvu, &detach, pcifunc_arr[sso_pcifunc]);
	kfree(pcifunc_arr);
}

static void rvu_blklf_teardown(struct rvu *rvu, u16 pcifunc, u8 blkaddr)
{
	struct rvu_block *block;
	unsigned long drain_tmo;
	int slot, lf, num_lfs;
	int err, retry;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->addr);
	if (!num_lfs)
		return;

	if (block->addr == BLKADDR_SSO) {
		retry = 0;
		drain_tmo = jiffies + msecs_to_jiffies(SSO_FLUSH_TMO_MAX);
		for (slot = 0; slot < num_lfs || retry; slot++) {
			if (slot == num_lfs) {
				if (time_after(jiffies, drain_tmo)) {
					dev_err(rvu->dev,
						"Failed to drain SSO queues\n");
					break;
				}

				slot = 0;
				retry = 0;
			}
			lf = rvu_get_lf(rvu, block, pcifunc, slot);
			if (lf < 0)
				continue;
			if (rvu_sso_lf_drain_queues(rvu, pcifunc, lf, slot) ==
			    -EAGAIN)
				retry = 1;
		}
		rvu_sso_cleanup_xaq_aura(rvu, pcifunc, num_lfs);
	}

	for (slot = 0; slot < num_lfs; slot++) {
		lf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (lf < 0)
			continue;

		/* Cleanup LF and reset it */
		if (block->addr == BLKADDR_NIX0 || block->addr == BLKADDR_NIX1)
			rvu_nix_lf_teardown(rvu, pcifunc, block->addr, lf);
		else if (block->addr == BLKADDR_NPA) {
			rvu_npa_lf_mapped_nix_lf_teardown(rvu, pcifunc);
			rvu_npa_lf_mapped_sso_lf_teardown(rvu, pcifunc);
			rvu_npa_lf_teardown(rvu, pcifunc, lf);
		} else if (block->addr == BLKADDR_SSO)
			rvu_sso_lf_teardown(rvu, pcifunc, lf, slot);
		else if (block->addr == BLKADDR_SSOW)
			rvu_ssow_lf_teardown(rvu, pcifunc, lf, slot);
		else if (block->addr == BLKADDR_TIM)
			rvu_tim_lf_teardown(rvu, pcifunc, lf, slot);
		else if ((block->addr == BLKADDR_CPT0) ||
			 (block->addr == BLKADDR_CPT1))
			rvu_cpt_lf_teardown(rvu, pcifunc, block->addr, lf,
					    slot);

		err = rvu_lf_reset(rvu, block, lf);
		if (err) {
			dev_err(rvu->dev, "Failed to reset blkaddr %d LF%d\n",
				block->addr, lf);
		}

		if (block->addr == BLKADDR_SSO)
			rvu_sso_hwgrp_config_thresh(rvu, block->addr, lf, NULL);
	}
}

static void rvu_sso_pfvf_rst(struct rvu *rvu, u16 pcifunc)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	struct rvu_hwinfo *hw = rvu->hw;

	if (pfvf->sso_uniq_ident) {
		rvu_free_rsrc(&hw->sso.pfvf_ident, pfvf->sso_uniq_ident);
		pfvf->sso_uniq_ident = 0;
	}
}

static void __rvu_flr_handler(struct rvu *rvu, u16 pcifunc)
{
	if (rvu_npc_exact_has_match_table(rvu))
		rvu_npc_exact_reset(rvu, pcifunc);

	mutex_lock(&rvu->flr_lock);
	/* Reset order should reflect inter-block dependencies:
	 * 1. Reset any packet/work sources (NIX, CPT, TIM)
	 * 2. Flush and reset SSO/SSOW
	 * 3. Cleanup pools (NPA)
	 */

	/* Free allocated BPIDs */
	rvu_nix_flr_free_bpids(rvu, pcifunc);

	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_NIX0);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_NIX1);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_CPT0);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_CPT1);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_REE0);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_REE1);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_TIM);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_SSOW);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_SSO);
	rvu_blklf_teardown(rvu, pcifunc, BLKADDR_NPA);
	rvu_reset_lmt_map_tbl(rvu, pcifunc);
	rvu_detach_rsrcs(rvu, NULL, pcifunc);
	rvu_sso_pfvf_rst(rvu, pcifunc);

	/* In scenarios where PF/VF drivers detach NIXLF without freeing MCAM
	 * entries, check and free the MCAM entries explicitly to avoid leak.
	 * Since LF is detached use LF number as -1.
	 */
	rvu_npc_free_mcam_entries(rvu, pcifunc, -1);
	rvu_mac_reset(rvu, pcifunc);

	/* MCS flr handler */
	if (rvu->mcs_blk_cnt)
		rvu_mcs_flr_handler(rvu, pcifunc);

	mutex_unlock(&rvu->flr_lock);
}

static void rvu_afvf_flr_handler(struct rvu *rvu, int vf)
{
	int reg = 0;

	/* pcifunc = 0(PF0) | (vf + 1) */
	__rvu_flr_handler(rvu, vf + 1);

	if (vf >= 64) {
		reg = 1;
		vf = vf - 64;
	}

	/* Signal FLR finish and enable IRQ */
	rvupf_write64(rvu, RVU_PF_VFTRPENDX(reg), BIT_ULL(vf));
	rvupf_write64(rvu, RVU_PF_VFFLR_INT_ENA_W1SX(reg), BIT_ULL(vf));
}

static void rvu_flr_handler(struct work_struct *work)
{
	struct rvu_work *flrwork = container_of(work, struct rvu_work, work);
	struct rvu *rvu = flrwork->rvu;
	u16 pcifunc, numvfs, vf;
	u64 cfg;
	int pf;

	pf = flrwork - rvu->flr_wrk;
	if (pf >= rvu->hw->total_pfs) {
		rvu_afvf_flr_handler(rvu, pf - rvu->hw->total_pfs);
		return;
	}

	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));
	numvfs = (cfg >> 12) & 0xFF;
	pcifunc  = pf << RVU_PFVF_PF_SHIFT;

	for (vf = 0; vf < numvfs; vf++)
		__rvu_flr_handler(rvu, (pcifunc | (vf + 1)));

	__rvu_flr_handler(rvu, pcifunc);

	/* Signal FLR finish */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFTRPEND, BIT_ULL(pf));

	/* Enable interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1S,  BIT_ULL(pf));
}

static void rvu_afvf_queue_flr_work(struct rvu *rvu, int start_vf, int numvfs)
{
	int dev, vf, reg = 0;
	u64 intr;

	if (start_vf >= 64)
		reg = 1;

	intr = rvupf_read64(rvu, RVU_PF_VFFLR_INTX(reg));
	if (!intr)
		return;

	for (vf = 0; vf < numvfs; vf++) {
		if (!(intr & BIT_ULL(vf)))
			continue;
		/* Clear and disable the interrupt */
		rvupf_write64(rvu, RVU_PF_VFFLR_INTX(reg), BIT_ULL(vf));
		rvupf_write64(rvu, RVU_PF_VFFLR_INT_ENA_W1CX(reg), BIT_ULL(vf));

		dev = vf + start_vf + rvu->hw->total_pfs;
		queue_work(rvu->flr_wq, &rvu->flr_wrk[dev].work);
	}
}

static irqreturn_t rvu_flr_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	u64 intr;
	u8  pf;

	intr = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT);
	if (!intr)
		goto afvf_flr;

	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		if (intr & (1ULL << pf)) {
			/* clear interrupt */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT,
				    BIT_ULL(pf));
			/* Disable the interrupt */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1C,
				    BIT_ULL(pf));
			/* PF is already dead do only AF related operations */
			queue_work(rvu->flr_wq, &rvu->flr_wrk[pf].work);
		}
	}

afvf_flr:
	rvu_afvf_queue_flr_work(rvu, 0, 64);
	if (rvu->vfs > 64)
		rvu_afvf_queue_flr_work(rvu, 64, rvu->vfs - 64);

	return IRQ_HANDLED;
}

static void rvu_me_handle_vfset(struct rvu *rvu, int idx, u64 intr)
{
	int vf;

	/* Nothing to be done here other than clearing the
	 * TRPEND bit.
	 */
	for (vf = 0; vf < 64; vf++) {
		if (intr & (1ULL << vf)) {
			/* clear the trpend due to ME(master enable) */
			rvupf_write64(rvu, RVU_PF_VFTRPENDX(idx), BIT_ULL(vf));
			/* clear interrupt */
			rvupf_write64(rvu, RVU_PF_VFME_INTX(idx), BIT_ULL(vf));
		}
	}
}

/* Handles ME interrupts from VFs of AF */
static irqreturn_t rvu_me_vf_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	int vfset;
	u64 intr;

	intr = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT);

	for (vfset = 0; vfset <= 1; vfset++) {
		intr = rvupf_read64(rvu, RVU_PF_VFME_INTX(vfset));
		if (intr)
			rvu_me_handle_vfset(rvu, vfset, intr);
	}

	return IRQ_HANDLED;
}

/* Handles ME interrupts from PFs */
static irqreturn_t rvu_me_pf_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	u64 intr;
	u8  pf;

	intr = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT);

	/* Nothing to be done here other than clearing the
	 * TRPEND bit.
	 */
	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		if (intr & (1ULL << pf)) {
			/* clear the trpend due to ME(master enable) */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFTRPEND,
				    BIT_ULL(pf));
			/* clear interrupt */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT,
				    BIT_ULL(pf));
		}
	}

	return IRQ_HANDLED;
}

static void rvu_unregister_interrupts(struct rvu *rvu)
{
	int irq;

	rvu_sso_unregister_interrupts(rvu);
	rvu_cpt_unregister_interrupts(rvu);
	rvu_ree_unregister_interrupts(rvu);

	/* Disable the Mbox interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFAF_MBOX_INT_ENA_W1C,
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);

	/* Disable the PF FLR interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1C,
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);

	/* Disable the PF ME interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT_ENA_W1C,
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);

	for (irq = 0; irq < rvu->num_vec; irq++) {
		if (rvu->irq_allocated[irq]) {
			free_irq(pci_irq_vector(rvu->pdev, irq), rvu);
			rvu->irq_allocated[irq] = false;
		}
	}

	pci_free_irq_vectors(rvu->pdev);
	rvu->num_vec = 0;
}

static int rvu_afvf_msix_vectors_num_ok(struct rvu *rvu)
{
	struct rvu_pfvf *pfvf = &rvu->pf[0];
	int offset;

	pfvf = &rvu->pf[0];
	offset = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_INT_CFG(0)) & 0x3ff;

	/* Make sure there are enough MSIX vectors configured so that
	 * VF interrupts can be handled. Offset equal to zero means
	 * that PF vectors are not configured and overlapping AF vectors.
	 */
	return (pfvf->msix.max >= RVU_AF_INT_VEC_CNT + RVU_PF_INT_VEC_CNT) &&
	       offset;
}

static int rvu_register_interrupts(struct rvu *rvu)
{
	int ret, offset, pf_vec_start;

	rvu->num_vec = pci_msix_vec_count(rvu->pdev);

	rvu->irq_name = devm_kmalloc_array(rvu->dev, rvu->num_vec,
					   NAME_SIZE, GFP_KERNEL);
	if (!rvu->irq_name)
		return -ENOMEM;

	rvu->irq_allocated = devm_kcalloc(rvu->dev, rvu->num_vec,
					  sizeof(bool), GFP_KERNEL);
	if (!rvu->irq_allocated)
		return -ENOMEM;

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(rvu->pdev, rvu->num_vec,
				    rvu->num_vec, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(rvu->dev,
			"RVUAF: Request for %d msix vectors failed, ret %d\n",
			rvu->num_vec, ret);
		return ret;
	}

	/* Register mailbox interrupt handler */
	sprintf(&rvu->irq_name[RVU_AF_INT_VEC_MBOX * NAME_SIZE], "RVUAF Mbox");
	ret = request_irq(pci_irq_vector(rvu->pdev, RVU_AF_INT_VEC_MBOX),
			  rvu_mbox_pf_intr_handler, 0,
			  &rvu->irq_name[RVU_AF_INT_VEC_MBOX * NAME_SIZE], rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for mbox irq\n");
		goto fail;
	}

	rvu->irq_allocated[RVU_AF_INT_VEC_MBOX] = true;

	/* Enable mailbox interrupts from all PFs */
	rvu_enable_mbox_intr(rvu);

	/* Register FLR interrupt handler */
	sprintf(&rvu->irq_name[RVU_AF_INT_VEC_PFFLR * NAME_SIZE],
		"RVUAF FLR");
	ret = request_irq(pci_irq_vector(rvu->pdev, RVU_AF_INT_VEC_PFFLR),
			  rvu_flr_intr_handler, 0,
			  &rvu->irq_name[RVU_AF_INT_VEC_PFFLR * NAME_SIZE],
			  rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for FLR\n");
		goto fail;
	}
	rvu->irq_allocated[RVU_AF_INT_VEC_PFFLR] = true;

	/* Enable FLR interrupt for all PFs*/
	rvu_write64(rvu, BLKADDR_RVUM,
		    RVU_AF_PFFLR_INT, INTR_MASK(rvu->hw->total_pfs));

	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1S,
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);

	/* Register ME interrupt handler */
	sprintf(&rvu->irq_name[RVU_AF_INT_VEC_PFME * NAME_SIZE],
		"RVUAF ME");
	ret = request_irq(pci_irq_vector(rvu->pdev, RVU_AF_INT_VEC_PFME),
			  rvu_me_pf_intr_handler, 0,
			  &rvu->irq_name[RVU_AF_INT_VEC_PFME * NAME_SIZE],
			  rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for ME\n");
	}
	rvu->irq_allocated[RVU_AF_INT_VEC_PFME] = true;

	/* Clear TRPEND bit for all PF */
	rvu_write64(rvu, BLKADDR_RVUM,
		    RVU_AF_PFTRPEND, INTR_MASK(rvu->hw->total_pfs));
	/* Enable ME interrupt for all PFs*/
	rvu_write64(rvu, BLKADDR_RVUM,
		    RVU_AF_PFME_INT, INTR_MASK(rvu->hw->total_pfs));

	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT_ENA_W1S,
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);

	if (!rvu_afvf_msix_vectors_num_ok(rvu))
		return 0;

	/* Get PF MSIX vectors offset. */
	pf_vec_start = rvu_read64(rvu, BLKADDR_RVUM,
				  RVU_PRIV_PFX_INT_CFG(0)) & 0x3ff;

	/* Register MBOX0 interrupt. */
	offset = pf_vec_start + RVU_PF_INT_VEC_VFPF_MBOX0;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "RVUAFVF Mbox0");
	ret = request_irq(pci_irq_vector(rvu->pdev, offset),
			  rvu_mbox_intr_handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE],
			  rvu);
	if (ret)
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for Mbox0\n");

	rvu->irq_allocated[offset] = true;

	/* Register MBOX1 interrupt. MBOX1 IRQ number follows MBOX0 so
	 * simply increment current offset by 1.
	 */
	offset = pf_vec_start + RVU_PF_INT_VEC_VFPF_MBOX1;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "RVUAFVF Mbox1");
	ret = request_irq(pci_irq_vector(rvu->pdev, offset),
			  rvu_mbox_intr_handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE],
			  rvu);
	if (ret)
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for Mbox1\n");

	rvu->irq_allocated[offset] = true;

	/* Register FLR interrupt handler for AF's VFs */
	offset = pf_vec_start + RVU_PF_INT_VEC_VFFLR0;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "RVUAFVF FLR0");
	ret = request_irq(pci_irq_vector(rvu->pdev, offset),
			  rvu_flr_intr_handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for RVUAFVF FLR0\n");
		goto fail;
	}
	rvu->irq_allocated[offset] = true;

	offset = pf_vec_start + RVU_PF_INT_VEC_VFFLR1;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "RVUAFVF FLR1");
	ret = request_irq(pci_irq_vector(rvu->pdev, offset),
			  rvu_flr_intr_handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for RVUAFVF FLR1\n");
		goto fail;
	}
	rvu->irq_allocated[offset] = true;

	/* Register ME interrupt handler for AF's VFs */
	offset = pf_vec_start + RVU_PF_INT_VEC_VFME0;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "RVUAFVF ME0");
	ret = request_irq(pci_irq_vector(rvu->pdev, offset),
			  rvu_me_vf_intr_handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for RVUAFVF ME0\n");
		goto fail;
	}
	rvu->irq_allocated[offset] = true;

	offset = pf_vec_start + RVU_PF_INT_VEC_VFME1;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "RVUAFVF ME1");
	ret = request_irq(pci_irq_vector(rvu->pdev, offset),
			  rvu_me_vf_intr_handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for RVUAFVF ME1\n");
		goto fail;
	}
	rvu->irq_allocated[offset] = true;

	ret = rvu_sso_register_interrupts(rvu);
	if (ret)
		goto fail;

	ret = rvu_cpt_register_interrupts(rvu);
	if (ret)
		goto fail;

	ret = rvu_ree_register_interrupts(rvu);
	if (ret)
		goto fail;

	return 0;
fail:
	rvu_unregister_interrupts(rvu);
	return ret;
}

static void rvu_flr_wq_destroy(struct rvu *rvu)
{
	if (rvu->flr_wq) {
		flush_workqueue(rvu->flr_wq);
		destroy_workqueue(rvu->flr_wq);
		rvu->flr_wq = NULL;
	}
}

static int rvu_flr_init(struct rvu *rvu)
{
	int dev, num_devs;
	u64 cfg;
	int pf;

	/* Enable FLR for all PFs*/
	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));
		rvu_write64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf),
			    cfg | BIT_ULL(22));
	}

	rvu->flr_wq = alloc_workqueue("rvu_afpf_flr",
				      WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM,
				       1);
	if (!rvu->flr_wq)
		return -ENOMEM;

	num_devs = rvu->hw->total_pfs + pci_sriov_get_totalvfs(rvu->pdev);
	rvu->flr_wrk = devm_kcalloc(rvu->dev, num_devs,
				    sizeof(struct rvu_work), GFP_KERNEL);
	if (!rvu->flr_wrk) {
		destroy_workqueue(rvu->flr_wq);
		return -ENOMEM;
	}

	for (dev = 0; dev < num_devs; dev++) {
		rvu->flr_wrk[dev].rvu = rvu;
		INIT_WORK(&rvu->flr_wrk[dev].work, rvu_flr_handler);
	}

	mutex_init(&rvu->flr_lock);

	return 0;
}

static void rvu_disable_afvf_intr(struct rvu *rvu)
{
	int vfs = rvu->vfs;

	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0), INTR_MASK(vfs));
	rvupf_write64(rvu, RVU_PF_VFFLR_INT_ENA_W1CX(0), INTR_MASK(vfs));
	rvupf_write64(rvu, RVU_PF_VFME_INT_ENA_W1CX(0), INTR_MASK(vfs));
	if (vfs <= 64)
		return;

	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INT_ENA_W1CX(1),
		      INTR_MASK(vfs - 64));
	rvupf_write64(rvu, RVU_PF_VFFLR_INT_ENA_W1CX(1), INTR_MASK(vfs - 64));
	rvupf_write64(rvu, RVU_PF_VFME_INT_ENA_W1CX(1), INTR_MASK(vfs - 64));
}

static void rvu_enable_afvf_intr(struct rvu *rvu)
{
	int vfs = rvu->vfs;

	/* Clear any pending interrupts and enable AF VF interrupts for
	 * the first 64 VFs.
	 */
	/* Mbox */
	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INTX(0), INTR_MASK(vfs));
	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0), INTR_MASK(vfs));

	/* FLR */
	rvupf_write64(rvu, RVU_PF_VFFLR_INTX(0), INTR_MASK(vfs));
	rvupf_write64(rvu, RVU_PF_VFFLR_INT_ENA_W1SX(0), INTR_MASK(vfs));
	rvupf_write64(rvu, RVU_PF_VFME_INT_ENA_W1SX(0), INTR_MASK(vfs));

	/* Same for remaining VFs, if any. */
	if (vfs <= 64)
		return;

	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INTX(1), INTR_MASK(vfs - 64));
	rvupf_write64(rvu, RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
		      INTR_MASK(vfs - 64));

	rvupf_write64(rvu, RVU_PF_VFFLR_INTX(1), INTR_MASK(vfs - 64));
	rvupf_write64(rvu, RVU_PF_VFFLR_INT_ENA_W1SX(1), INTR_MASK(vfs - 64));
	rvupf_write64(rvu, RVU_PF_VFME_INT_ENA_W1SX(1), INTR_MASK(vfs - 64));
}

int rvu_get_num_lbk_chans(void)
{
	struct pci_dev *pdev;
	void __iomem *base;
	int ret = -EIO;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_LBK,
			      NULL);
	if (!pdev)
		goto err;

	base = pci_ioremap_bar(pdev, 0);
	if (!base)
		goto err_put;

	/* Read number of available LBK channels from LBK(0)_CONST register. */
	ret = (readq(base + 0x10) >> 32) & 0xffff;
	iounmap(base);
err_put:
	pci_dev_put(pdev);
err:
	return ret;
}

static int rvu_enable_sriov(struct rvu *rvu)
{
	struct pci_dev *pdev = rvu->pdev;
	int err, chans, vfs;

	if (!rvu_afvf_msix_vectors_num_ok(rvu)) {
		dev_warn(&pdev->dev,
			 "Skipping SRIOV enablement since not enough IRQs are available\n");
		return 0;
	}

	chans = rvu_get_num_lbk_chans();
	if (chans < 0)
		return chans;

	vfs = pci_sriov_get_totalvfs(pdev);

	/* Clamp vfs to max_vfs iff set */
	if (max_vfs >= 0 && vfs > max_vfs)
		vfs = max_vfs;

	/* Limit VFs in case we have more VFs than LBK channels available. */
	if (vfs > chans)
		vfs = chans;

	if (!vfs)
		return 0;

	/* LBK channel number 63 is used for switching packets between
	 * CGX mapped VFs. Hence limit LBK pairs till 62 only.
	 */
	if (vfs > 62)
		vfs = 62;

	/* Save VFs number for reference in VF interrupts handlers.
	 * Since interrupts might start arriving during SRIOV enablement
	 * ordinary API cannot be used to get number of enabled VFs.
	 */
	rvu->vfs = vfs;

	err = rvu_mbox_init(rvu, &rvu->afvf_wq_info, TYPE_AFVF, vfs,
			    rvu_afvf_mbox_handler, rvu_afvf_mbox_up_handler);
	if (err)
		return err;

	rvu_enable_afvf_intr(rvu);
	/* Make sure IRQs are enabled before SRIOV. */
	mb();

	err = pci_enable_sriov(pdev, vfs);
	if (err) {
		rvu_disable_afvf_intr(rvu);
		rvu_mbox_destroy(&rvu->afvf_wq_info);
		return err;
	}

	return 0;
}

static void rvu_disable_sriov(struct rvu *rvu)
{
	rvu_disable_afvf_intr(rvu);
	rvu_mbox_destroy(&rvu->afvf_wq_info);
	pci_disable_sriov(rvu->pdev);
}

static void rvu_update_module_params(struct rvu *rvu)
{
	const char *default_pfl_name = "default";

	strscpy(rvu->mkex_pfl_name,
		mkex_profile ? mkex_profile : default_pfl_name, MKEX_NAME_LEN);
	strscpy(rvu->kpu_pfl_name,
		kpu_profile ? kpu_profile : default_pfl_name, KPU_NAME_LEN);
}

static int rvu_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct rvu *rvu;
	int    err;

	rvu = devm_kzalloc(dev, sizeof(*rvu), GFP_KERNEL);
	if (!rvu)
		return -ENOMEM;

	rvu->hw = devm_kzalloc(dev, sizeof(struct rvu_hwinfo), GFP_KERNEL);
	if (!rvu->hw) {
		devm_kfree(dev, rvu);
		return -ENOMEM;
	}

	pci_set_drvdata(pdev, rvu);
	rvu->pdev = pdev;
	rvu->dev = &pdev->dev;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto err_freemem;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "DMA mask config failed, abort\n");
		goto err_release_regions;
	}

	pci_set_master(pdev);
	rvu->ptp = ptp_get();
	if (IS_ERR(rvu->ptp)) {
		err = PTR_ERR(rvu->ptp);
		if (err == -EPROBE_DEFER) {
			dev_err(dev,
				"PTP driver not loaded, deferring probe\n");
			goto err_release_regions;
		}
		rvu->ptp = NULL;
	}

	/* Map Admin function CSRs */
	rvu->afreg_base = pcim_iomap(pdev, PCI_AF_REG_BAR_NUM, 0);
	rvu->pfreg_base = pcim_iomap(pdev, PCI_PF_REG_BAR_NUM, 0);
	if (!rvu->afreg_base || !rvu->pfreg_base) {
		dev_err(dev, "Unable to map admin function CSRs, aborting\n");
		err = -ENOMEM;
		goto err_put_ptp;
	}

	/* Store module params in rvu structure */
	rvu_update_module_params(rvu);

	/* Check which blocks the HW supports */
	rvu_check_block_implemented(rvu);

	rvu_reset_all_blocks(rvu);

	rvu_setup_hw_capabilities(rvu);

	err = rvu_setup_hw_resources(rvu);
	if (err)
		goto err_put_ptp;

	/* Init mailbox btw AF and PFs */
	err = rvu_mbox_init(rvu, &rvu->afpf_wq_info, TYPE_AFPF,
			    rvu->hw->total_pfs, rvu_afpf_mbox_handler,
			    rvu_afpf_mbox_up_handler);
	if (err) {
		dev_err(dev, "%s: Failed to initialize mbox\n", __func__);
		goto err_hwsetup;
	}

	err = rvu_flr_init(rvu);
	if (err) {
		dev_err(dev, "%s: Failed to initialize flr\n", __func__);
		goto err_mbox;
	}

	err = rvu_register_interrupts(rvu);
	if (err) {
		dev_err(dev, "%s: Failed to register interrupts\n", __func__);
		goto err_flr;
	}

	err = rvu_register_dl(rvu);
	if (err) {
		dev_err(dev, "%s: Failed to register devlink\n", __func__);
		goto err_irq;
	}

	rvu_setup_rvum_blk_revid(rvu);

	err = rvu_policy_init(rvu);
	if (err)
		goto err_dl;

	/* Enable AF's VFs (if any) */
	err = rvu_enable_sriov(rvu);
	if (err) {
		dev_err(dev, "%s: Failed to enable sriov\n", __func__);
		goto err_policy;
	}

	/* Initialize debugfs */
	rvu_dbg_init(rvu);

	mutex_init(&rvu->rswitch.switch_lock);

	if (rvu->fwdata)
		ptp_start(rvu->ptp, rvu->fwdata->sclk, rvu->fwdata->ptp_ext_clk_rate,
			  rvu->fwdata->ptp_ext_tstamp);

	return 0;

err_policy:
	rvu_policy_destroy(rvu);
err_dl:
	rvu_unregister_dl(rvu);
err_irq:
	rvu_unregister_interrupts(rvu);
err_flr:
	rvu_flr_wq_destroy(rvu);
err_mbox:
	rvu_mbox_destroy(&rvu->afpf_wq_info);
err_hwsetup:
	rvu_cgx_exit(rvu);
	rvu_fwdata_exit(rvu);
	rvu_mcs_exit(rvu);
	rvu_reset_all_blocks(rvu);
	rvu_free_hw_resources(rvu);
	rvu_clear_rvum_blk_revid(rvu);
err_put_ptp:
	ptp_put(rvu->ptp);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
err_freemem:
	pci_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, rvu->hw);
	devm_kfree(dev, rvu);
	return err;
}

static void rvu_remove(struct pci_dev *pdev)
{
	struct rvu *rvu = pci_get_drvdata(pdev);

	rvu_dbg_exit(rvu);
	rvu_policy_destroy(rvu);
	rvu_unregister_interrupts(rvu);
	rvu_unregister_dl(rvu);
	rvu_flr_wq_destroy(rvu);
	rvu_cgx_exit(rvu);
	rvu_fwdata_exit(rvu);
	rvu_mcs_exit(rvu);
	rvu_mbox_destroy(&rvu->afpf_wq_info);
	rvu_disable_sriov(rvu);
	rvu_reset_all_blocks(rvu);
	rvu_free_hw_resources(rvu);
	rvu_clear_rvum_blk_revid(rvu);
	ptp_put(rvu->ptp);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	devm_kfree(&pdev->dev, rvu->hw);
	devm_kfree(&pdev->dev, rvu);
}

static struct pci_driver rvu_driver = {
	.name = DRV_NAME,
	.id_table = rvu_id_table,
	.probe = rvu_probe,
	.remove = rvu_remove,
};

static int __init rvu_init_module(void)
{
	int err;

	pr_info("%s: %s\n", DRV_NAME, DRV_STRING);

	err = pci_register_driver(&cgx_driver);
	if (err < 0)
		return err;

	err = pci_register_driver(&ptp_driver);
	if (err < 0)
		goto ptp_err;

	err = pci_register_driver(&mcs_driver);
	if (err < 0)
		goto mcs_err;

	err =  pci_register_driver(&rvu_driver);
	if (err < 0)
		goto rvu_err;

	return 0;
rvu_err:
	pci_unregister_driver(&mcs_driver);
mcs_err:
	pci_unregister_driver(&ptp_driver);
ptp_err:
	pci_unregister_driver(&cgx_driver);

	return err;
}

static void __exit rvu_cleanup_module(void)
{
	pci_unregister_driver(&rvu_driver);
	pci_unregister_driver(&mcs_driver);
	pci_unregister_driver(&ptp_driver);
	pci_unregister_driver(&cgx_driver);
}

module_init(rvu_init_module);
module_exit(rvu_cleanup_module);
