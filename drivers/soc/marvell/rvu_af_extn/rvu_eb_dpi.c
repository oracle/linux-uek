// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/pci.h>
#include "mbox.h"
#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eblock.h"
#include "rvu_trace.h"
#include "rvu_dpi_mbox.h"

/* Maximum number of DPI blocks */
#define MAX_DPI_BLKS		2

/* DPI_ENGX_BUF 8 KB FIFO for 0,1,2,3 engines, 16KB for 4,5
 * need to check for 6,7!!
 */
static unsigned long eng_fifo_buf = 0x101008080808;

#define DPI_MAX_ENGINES	6

#define DPI_ENG_BUF_BLKS(x)			((x) & 0x1fULL)
#define DPI_ENG_BUF_GET_BLKS(x)			((x) & 0x1fULL)
#define DPI_DMA_CONTROL_DMA_ENB(x)              (((x) & 0x3fULL) << 48)
#define DPI_CTL_EN                              (0x1ULL)

#define DPI_EBUS_MRRS_MIN			128
#define DPI_EBUS_MRRS_MAX			1024
#define DPI_EBUS_MPS_MIN			128
#define DPI_EBUS_MPS_MAX			1024
#define DPI_EBUS_MAX_PORTS			2
#define DPI_EBUS_PORTX_CFG_MRRS(x)		(((x) & 0x7) << 0)
#define DPI_EBUS_PORTX_CFG_MPS(x)		(((x) & 0x7) << 4)

#define RL_PERIOD 8
#define RL_BURST_TH 64
#define RL_TOKEN 8
#define SDP_RL_PERIOD 8
#define SDP_RL_BURST_TH 64
#define SDP_RL_TOKEN 8
#define BPHY_RL_PERIOD 8
#define BPHY_RL_BURST_TH 64
#define BPHY_RL_TOKEN 8
#define PSW_RL_PERIOD 8
#define PSW_RL_BURST_TH 64
#define PSW_RL_TOKEN 8

#define DPI_DMA_CONTROL_O_MODE			(0x1ULL << 14)
#define DPI_DMA_CONTROL_O_NS			(0x1ULL << 17)
#define DPI_DMA_CONTROL_O_RO			(0x1ULL << 18)
#define DPI_DMA_CONTROL_LDWB			(0x1ULL << 32)
#define DPI_DMA_CONTROL_WQECSMODE1		(0x1ULL << 37)
#define DPI_DMA_CONTROL_ZBWCSEN			(0x1ULL << 39)
#define DPI_DMA_CONTROL_WQECSOFF(offset)	(((u64)offset) << 40)
#define DPI_DMA_CONTROL_WQECSDIS		(0x1ULL << 47)
#define DPI_DMA_CONTROL_UIO_DIS			(0x1ULL << 55)
#define DPI_DMA_CONTROL_PKT_EN			(0x1ULL << 56)
#define DPI_DMA_CONTROL_PORT1_EN		(0x1ULL << 57)
#define DPI_DMA_CONTROL_FFP_DIS			(0x1ULL << 59)

#define DPI_WPORT				(0x1ULL << 4)
#define DPI_RPORT				(0x1ULL << 0)

struct dpi_drvdata {
	int res_idx;
};

static int dpi_dma_engine_get_num(void)
{
	return DPI_MAX_ENGINES;
}

static int validate_and_get_dpi_blkaddr(int req_blkaddr)
{
	int blkaddr;

	blkaddr = req_blkaddr ? req_blkaddr : BLKADDR_DPI0;
	if (blkaddr != BLKADDR_DPI0 && blkaddr != BLKADDR_DPI1)
		return -EINVAL;

	return blkaddr;
}

static void dpi_lf_disable_iqueue(struct rvu *rvu, int blkaddr, int slot)
{
	/* Disable instructions enqueuing */
	rvupf_write64(rvu, DPI_LF_RINGX_CFG(blkaddr, 0), 0);
	rvupf_write64(rvu, DPI_LF_RINGX_CFG(blkaddr, 1), 0);
}

int rvu_dpi_lf_teardown(struct rvu *rvu, u16 pcifunc, int blkaddr, int lf,
			int slot)
{
	mutex_lock(&rvu->dpi_rsrc_lock);

	dpi_lf_disable_iqueue(rvu, blkaddr, slot);

	mutex_unlock(&rvu->dpi_rsrc_lock);

	return 0;
}

static int dpi_lf_free(struct rvu *rvu, struct msg_req *req, int blkaddr)
{
	u16 pcifunc = req->hdr.pcifunc;
	int num_lfs, dpilf, slot, err;
	struct rvu_block *block;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->addr);
	if (!num_lfs)
		return 0;

	for (slot = 0; slot < num_lfs; slot++) {
		dpilf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (dpilf < 0)
			return DPI_AF_ERR_LF_INVALID;

		/* Perform teardown */
		rvu_dpi_lf_teardown(rvu, pcifunc, blkaddr, dpilf, slot);

		/* Reset LF */
		err = rvu_lf_reset(rvu, block, dpilf);
		if (err) {
			dev_err(rvu->dev, "Failed to reset blkaddr %d LF%d\n",
				block->addr, dpilf);
		}
	}

	return 0;
}

int rvu_mbox_handler_dpi_lf_ring_cfg(struct rvu *rvu,
				     struct dpi_lf_ring_cfg_req *req,
				     struct msg_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	u64 cfg;
	int lf;

	cfg = ((u64)req->err_rsp_en << 36) | ((u64)(req->xtype & 0x7) << 12);
	cfg |= ((u64)(req->pri & 0x3) << 8);

	if (req->xtype == OUTBOUND  || req->xtype == EXTERNAL)
		cfg |= (DPI_WPORT |  DPI_RPORT);

	lf = rvu_get_lf(rvu, &hw->block[req->dpi_blkaddr], pcifunc,
			req->lf_slot);

	rvu_write64(rvu, req->dpi_blkaddr,
		    DPI_AF_LFX_RINGX_CFG(lf, req->ring_idx), cfg);

	return 0;
}

int rvu_mbox_handler_dpi_lf_free(struct rvu *rvu, struct msg_req *req,
				 struct msg_rsp *rsp)
{
	int ret;

	ret = dpi_lf_free(rvu, req, BLKADDR_DPI0);
	if (ret)
		return ret;

	if (is_block_implemented(rvu->hw, BLKADDR_DPI1))
		ret = dpi_lf_free(rvu, req, BLKADDR_DPI1);

	return ret;
}

int rvu_mbox_handler_dpi_free_rsrc_cnt(struct rvu *rvu,
				       struct msg_req *req,
				       struct dpi_free_rsrcs_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;

	mutex_lock(&rvu->dpi_rsrc_lock);

	block = &hw->block[BLKADDR_DPI0];
	rsp->dpi = rvu_rsrc_free_count(&block->lf);

	block = &hw->block[BLKADDR_DPI1];
	rsp->dpi1 = rvu_rsrc_free_count(&block->lf);

	mutex_unlock(&rvu->dpi_rsrc_lock);

	return 0;
}

static int rvu_dpi_get_attach_blkaddr(struct rvu *rvu, int blktype,
				      u16 pcifunc,
				      struct dpi_rsrc_attach_req *attach)
{
	int blkaddr;

	switch (blktype) {
	case BLKTYPE_DPI:
		if (attach->hdr.ver < RVU_MULTI_BLK_VER)
			return rvu_get_blkaddr(rvu, blktype, 0);
		blkaddr = attach->dpi_blkaddr ? attach->dpi_blkaddr :
			  BLKADDR_DPI0;
		if (blkaddr != BLKADDR_DPI0 && blkaddr != BLKADDR_DPI1)
			return -ENODEV;
		break;
	default:
		return rvu_get_blkaddr(rvu, blktype, 0);
	}

	if (is_block_implemented(rvu->hw, blkaddr))
		return blkaddr;

	return -ENODEV;
}

static int rvu_dpi_check_rsrc_availability(struct rvu *rvu,
					   struct dpi_rsrc_attach_req *req,
					   u16 pcifunc)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	int free_lfs, mappedlfs, blkaddr;
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;

	if (req->dpilfs) {
		blkaddr = rvu_dpi_get_attach_blkaddr(rvu, BLKTYPE_DPI,
						     pcifunc, req);
		if (blkaddr < 0)
			return blkaddr;

		block = &hw->block[blkaddr];
		if (req->dpi_lfs > block->lf.max) {
			dev_err(&rvu->pdev->dev,
				"Func 0x%x: Invalid DPILF req, %d > max %d\n",
				 pcifunc, req->dpilfs, block->lf.max);
			return -EINVAL;
		}
		mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
		free_lfs = rvu_rsrc_free_count(&block->lf);
		if (req->dpilfs > mappedlfs &&
		    ((req->dpilfs - mappedlfs) > free_lfs))
			goto fail;
	}

	return 0;

fail:
	dev_info(rvu->dev, "Request for %s failed\n", block->name);
	return -ENOSPC;
}

static bool rvu_attach_from_same_block(struct rvu *rvu, int blktype,
				       struct dpi_rsrc_attach_req *attach)
{
	int blkaddr, num_lfs;

	blkaddr = rvu_dpi_get_attach_blkaddr(rvu, blktype,
					     attach->hdr.pcifunc, attach);
	if (blkaddr < 0)
		return false;

	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, attach->hdr.pcifunc),
					blkaddr);
	/* Requester already has LFs from given block ? */
	return !!num_lfs;
}

static int dpi_detach_rsrcs(struct rvu *rvu, struct dpi_rsrc_detach_req *detach,
			    u16 pcifunc)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	bool detach_all = true;
	struct msg_req req;
	int blkid;

	mutex_lock(&rvu->dpi_rsrc_lock);

	/* Check for partial resource detach */
	if (detach && detach->partial)
		detach_all = false;

	/* Check for RVU block's LFs attached to this func,
	 * if so, detach them.
	 */
	for (blkid = BLKADDR_DPI0; blkid <= BLKADDR_DPI1; blkid++) {
		block = &hw->block[blkid];
		if (!block->lf.bmap)
			continue;
		if (!detach_all && detach) {
			if (blkid == BLKADDR_DPI0 && !detach->dpilfs)
				continue;
			else if ((blkid == BLKADDR_DPI1) && !detach->dpi1_lfs)
				continue;
		}

		rvu_detach_block(rvu, pcifunc, block->type);

		req.hdr.pcifunc = detach->hdr.pcifunc;
		dpi_lf_free(rvu, &req, blkid);
	}

	mutex_unlock(&rvu->dpi_rsrc_lock);
	return 0;
}

int rvu_mbox_handler_dpi_detach_resources(struct rvu *rvu,
					  struct dpi_rsrc_detach_req *detach,
					  struct msg_rsp *rsp)
{
	return dpi_detach_rsrcs(rvu, detach, detach->hdr.pcifunc);
}

static void rvu_dpi_attach_block(struct rvu *rvu, int pcifunc, int blktype,
				 int num_lfs,
				 struct dpi_rsrc_attach_req *attach)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int slot, lf;
	int blkaddr;
	u64 cfg;

	if (!num_lfs)
		return;

	blkaddr = rvu_dpi_get_attach_blkaddr(rvu, blktype, pcifunc, attach);
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

int rvu_mbox_handler_dpi_attach_resources(struct rvu *rvu,
					  struct dpi_rsrc_attach_req *attach,
					  struct msg_rsp *rsp)
{
	u16 pcifunc = attach->hdr.pcifunc;
	int err;

	if (!attach->dpilfs)
		return 0;

	/* If first request, detach all existing attached resources */
	if (!attach->modify)
		dpi_detach_rsrcs(rvu, NULL, pcifunc);

	mutex_lock(&rvu->dpi_rsrc_lock);

	/* Check if the request can be accommodated */
	err = rvu_dpi_check_rsrc_availability(rvu, attach, pcifunc);
	if (err)
		goto exit;

	if (attach->dpilfs) {
		if (attach->modify &&
		    rvu_attach_from_same_block(rvu, BLKTYPE_DPI, attach))
			rvu_detach_block(rvu, pcifunc, BLKTYPE_DPI);
		rvu_dpi_attach_block(rvu, pcifunc, BLKTYPE_DPI,
				     attach->dpi_lfs, attach);
	}

exit:
	mutex_unlock(&rvu->dpi_rsrc_lock);
	return err;
}

int rvu_mbox_handler_dpi_lf_chan_cfg(struct rvu *rvu,
				     struct dpi_lf_chan_cfg_req *req,
				     struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	u64 val = 0;
	int dpilf;

	block = &rvu->hw->block[req->dpi_blkaddr];

	dpilf = rvu_get_lf(rvu, block, pcifunc, req->lf_slot);
	if (dpilf < 0)
		return DPI_AF_ERR_LF_INVALID;

	val = rvu_read64(rvu, req->dpi_blkaddr, DPI_AF_CHAN_LFX_CFG(dpilf));
	if (val & BIT_ULL(63))
		return DPI_AF_ERR_PARAM;

	/* Default chan config when DPI_AF_CHAN_LF()_CFG[ENA] is zero */
	rvu_write64(rvu, req->dpi_blkaddr, DPI_AF_LFX_RINGX_CHAN_CFG(dpilf, 0),
		    req->def_config);

	return 0;
}

int rvu_mbox_handler_dpi_lf_pf_func_cfg(struct rvu *rvu,
					struct dpi_lf_pf_func_cfg_req *req,
					struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	int dpilf, blkaddr;
	int num_lfs;
	u64 val;

	blkaddr = validate_and_get_dpi_blkaddr(req->dpi_blkaddr);
	if (blkaddr < 0)
		return blkaddr;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->addr);
	if (!num_lfs)
		return DPI_AF_ERR_LF_INVALID;

	dpilf = rvu_get_lf(rvu, block, pcifunc, req->lf_slot);
	if (dpilf < 0)
		return DPI_AF_ERR_LF_INVALID;

	/* Set DPI LF NPA_PF_FUNC and SSO_PF_FUNC.
	 */
	val = rvu_read64(rvu, blkaddr, DPI_AF_LFX_PF_VF_CFG(dpilf));
	val &= ~(GENMASK_ULL(31, 16) | GENMASK_ULL(15, 0));
	val |= ((u64)req->npa_pf_func << 16 |
		(u64)req->sso_pf_func);
	rvu_write64(rvu, blkaddr, DPI_AF_LFX_PF_VF_CFG(dpilf), val);

	return 0;
}

static void rvu_dpi_unregister_interrupts_block(struct rvu_block *block,
						void *data)
{
	(void)block;
	(void)data;
}

static int rvu_dpi_register_interrupts_block(struct rvu_block *block,
					     void *data)
{
	(void)block;
	(void)data;

	return 0;
}

static int dpi_exit(struct rvu *rvu)
{
	int engine = 0, port, blkaddr;
	u64 val = 0ULL;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_DPI, 0);

		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_BUF(engine), val);
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_CFG(engine), 0x0ULL);
	}

	rvu_write64(rvu, blkaddr, DPI_AF_DMA_CONTROL, val);
	rvu_write64(rvu, blkaddr, DPI_AF_CTL, ~DPI_CTL_EN);

	for (port = 0; port < DPI_EBUS_MAX_PORTS; port++) {
		val = rvu_read64(rvu, blkaddr,
				 DPI_AF_EBUS_PORTX_CFG(port));
		val &= ~DPI_EBUS_PORTX_CFG_MRRS(0x7);
		val &= ~DPI_EBUS_PORTX_CFG_MPS(0x7);
		rvu_write64(rvu, blkaddr,
			    DPI_AF_EBUS_PORTX_CFG(port), val);
	}
	return 0;
}

static int rvu_dpi_init_block(struct rvu_block *block, void *data)
{
	int engine, blkaddr, port = 0, mrrs, mps, blkid;
	u8 *eng_buf = (u8 *)&eng_fifo_buf;
	struct dpi_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	u8 mrrs_val, mps_val;
	u64 val;

	if (!data)
		return -EINVAL;

	blkid = drvdata->res_idx;
	blkaddr = blkid ? BLKADDR_DPI1 : BLKADDR_DPI0;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		val = DPI_ENG_BUF_BLKS(eng_buf[engine & 0x7]);
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_BUF(engine), val);

		/* Here qmap for the engines are set to 0.
		 * No dpi queues are mapped to engines.
		 * When a VF is initialised corresponding bit
		 * in the qmap will be set for all engines.
		 */
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_CFG(engine), 0x0ULL);
	}

	/* Channel Table Cache Hash type.
	 * 0x0 - RND - Random spreading (Preferred)
	 * 0x1 - REM - Simple Remainder
	 * 0x2 - XOR1 - channel ^ channel_table
	 * 0x3 - XOR2 - More complex xor
	 */
	rvu_write64(rvu, blkaddr, DPI_AF_CHAN_HSEL, 0ULL);

	val = 0ULL;
	val =  (DPI_DMA_CONTROL_ZBWCSEN | DPI_DMA_CONTROL_PKT_EN |
		DPI_DMA_CONTROL_LDWB | DPI_DMA_CONTROL_O_MODE);

	val |= DPI_DMA_CONTROL_DMA_ENB(0x3fULL);

	rvu_write64(rvu, blkaddr, DPI_AF_DMA_CONTROL, val);
	rvu_write64(rvu, blkaddr, DPI_AF_CTL, DPI_CTL_EN);

	/* Set max outstanding read and load requests */
	val = (DPI_RD_FIFO_MAX_TH << 16) | DPI_NCB_MAX_MOLR;
	rvu_write64(rvu, blkaddr, DPI_AF_NCB_CFG, val);

	/* Configure MPS and MRRS for DPI */
	mrrs = DPI_EBUS_MRRS_MIN;
	mrrs_val = fls(mrrs) - 8;

	mps = DPI_EBUS_MPS_MIN;
	mps_val = fls(mps) - 8;

	for (port = 0; port < DPI_EBUS_MAX_PORTS; port++) {
		val = rvu_read64(rvu, blkaddr,
				 DPI_AF_EBUS_PORTX_CFG(port));
		val &= ~(DPI_EBUS_PORTX_CFG_MRRS(0x7) |
			 DPI_EBUS_PORTX_CFG_MPS(0x7));
		val |= (DPI_EBUS_PORTX_CFG_MPS(mps_val) |
			DPI_EBUS_PORTX_CFG_MRRS(mrrs_val));
		/* EXACT_RD_DIS, MOLR, MPS_LIM, MRRS */
		val |= (DPI_EBUS_MAX_MOLR << 8) | BIT_ULL(7) | BIT_ULL(20);
		rvu_write64(rvu, blkaddr,
			    DPI_AF_EBUS_PORTX_CFG(port), val);
	}

	/* Need to re-config DPI_AF_ENG_BUF_TH_LIMIT if required, reset values
	 * [LIMIT], [HITH_LIMIT], [HITH], [MEDTH_LIMIT],
	 * [MEDTH], [LOTH_LIMIT], and [LOTH] being used
	 */

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		val = BIT_ULL(63) | (RL_PERIOD < 32) | (RL_BURST_TH << 16) |
			RL_TOKEN;
		/* Disable rate limit initially */
		val = 0;
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_RATE_CTRL(engine), val);
	}

	val = BIT_ULL(63) | (SDP_RL_PERIOD < 32) | (SDP_RL_BURST_TH << 16) |
		SDP_RL_TOKEN;
	/* Disable rate limit initially */
	val = 0;
	rvu_write64(rvu, blkaddr, DPI_AF_SDP_OPKT_RATE_CTRL, val);
	rvu_write64(rvu, blkaddr, DPI_AF_SDP_OPKT_RATE_CTRL, val);

	val = BIT_ULL(63) | (BPHY_RL_PERIOD < 32) | (BPHY_RL_BURST_TH << 16) |
		BPHY_RL_TOKEN;
	/* Disable rate limit initially */
	val = 0;
	rvu_write64(rvu, blkaddr, DPI_AF_BPHYX_OPKT_RATE_CTRL(0), val);
	rvu_write64(rvu, blkaddr, DPI_AF_BPHYX_OPKT_RATE_CTRL(1), val);

	val = BIT_ULL(63) | (PSW_RL_PERIOD < 32) | (PSW_RL_BURST_TH << 16) |
		PSW_RL_TOKEN;
	/* Disable rate limit initially */
	val = 0;
	rvu_write64(rvu, blkaddr, DPI_AF_PSWX_OPKT_RATE_CTRL(0), val);
	rvu_write64(rvu, blkaddr, DPI_AF_PSWX_OPKT_RATE_CTRL(1), val);

	mutex_init(&rvu->dpi_rsrc_lock);

	return 0;
}

static void rvu_dpi_freemem_block(struct rvu_block *block, void *data)
{
	(void)block;
	(void)data;

	/* Free up resources related to DPI channel tables etc.. */
}

static int rvu_setup_dpi_hw_resource(struct rvu_block *block, void *data)
{
	struct dpi_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	struct rvu_hwinfo *hw = rvu->hw;
	int blkid, err, blkaddr;
	u64 cfg;

	blkid = drvdata->res_idx;
	blkaddr = blkid ? BLKADDR_DPI1 : BLKADDR_DPI0;
	block = &hw->block[blkaddr];

	/* Init DPI LF's bitmap */
	if (!block->implemented)
		return 0;
	cfg = rvu_read64(rvu, blkaddr, DPI_AF_CONST);
	block->lf.max = cfg & 0xFFF;
	block->addr = blkaddr;
	block->type = BLKTYPE_DPI;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = DPI_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = DPI_AF_CONST;
	block->vf_lfcnt_reg = DPI_AF_CONST;
	block->lfcfg_reg = DPI_PRIV_LFX_CFG;
	block->msixcfg_reg = DPI_PRIV_LFX_INT_CFG(0);
	block->lfreset_reg = DPI_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "DPI%d", blkid);
	err = rvu_alloc_bitmap(&block->lf);
	if (err)
		return err;

	/* Allocate memory for block LF/slot to pcifunc mapping info */
	block->fn_map =
		devm_kcalloc(rvu->dev, block->lf.max, sizeof(u16), GFP_KERNEL);
	if (!block->fn_map) {
		err = -ENOMEM;
		goto free_bmap;
	}

	rvu_reset_blk_lfcfg(rvu, block);

	rvu_scan_block(rvu, block);

	return 0;

free_bmap:
	rvu_free_bitmap(&block->lf);

	return err;
}

static int rvu_dpi_mbox_handler(struct otx2_mbox *mbox, int devid,
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
		MBOX_EBLOCK_DPI_MESSAGES

	default :
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}
}

static void *rvu_dpi_probe(struct rvu *rvu, int blkaddr)
{
	struct dpi_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_DPI0:
	case BLKADDR_DPI1:
		data = devm_kzalloc(rvu->dev, sizeof(struct dpi_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		data->res_idx = res_idx++;
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_dpi_remove(struct rvu_block *hwblock, void *data)
{
	dpi_exit(hwblock->rvu);
	devm_kfree(hwblock->rvu->dev, data);
}

struct mbox_op dpi_mbox_op = {
	.start = 0xC000,
	.end = 0xCFFF,
	.handler = rvu_dpi_mbox_handler,
};

static struct rvu_eblock_driver_ops dpi_ops = {
	.probe	= rvu_dpi_probe,
	.remove	= rvu_dpi_remove,
	.init	= rvu_dpi_init_block,
	.setup	= rvu_setup_dpi_hw_resource,
	.free	= rvu_dpi_freemem_block,
	.register_interrupt = rvu_dpi_register_interrupts_block,
	.unregister_interrupt = rvu_dpi_unregister_interrupts_block,
	.mbox_op = &dpi_mbox_op,
};

void dpi_eb_module_init(void)
{
	rvu_eblock_register_driver(&dpi_ops);
}

void dpi_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&dpi_ops);
}
