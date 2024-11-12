// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU AF ML extension
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eb_ml.h"
#include "rvu_eblock.h"
#include "rvu_eblock_reg.h"
#include "rvu_ml_mbox.h"
#include "rvu_trace.h"

static const char *ml_irq_name[MAX_ML_BLOCKS][ML_AF_INT_VEC_CNT] = {
	{ "ML0_AF_CORE_INT_LO", "ML0_AF_CORE_INT_HI", "ML0_AF_WRAP_ERR_INT",
	  "ML0_AF_RVU_INT" },
};

struct ml_drvdata {
	int res_idx;
};

static void rvu_ml_unregister_interrupts_block(struct rvu_block *block,
					       void *data);

static int get_ml_pf_num(struct rvu *rvu)
{
	int i, ml_pf_num = -1;
	u64 id_cfg, cfg;
	u8 pf_devid;

	pf_devid = PCI_DEVID_CN20K_ML_PF & 0xFF;
	for (i = 0; i < rvu->hw->total_pfs; i++) {
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(i));
		if (!(cfg & BIT_ULL(20)))
			continue;

		id_cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_ID_CFG(i));
		if ((id_cfg & 0xFF) == pf_devid) {
			ml_pf_num = i;
			break;
		}
	}

	return ml_pf_num;
}

static bool is_ml_pf(struct rvu *rvu, u16 pcifunc)
{
	if (rvu_get_pf(rvu->pdev, pcifunc) != rvu->ml_pf_num)
		return false;

	if (pcifunc & RVU_PFVF_FUNC_MASK)
		return false;

	return true;
}

static bool is_ml_vf(struct rvu *rvu, u16 pcifunc)
{
	if (rvu_get_pf(rvu->pdev, pcifunc) != rvu->ml_pf_num)
		return false;

	if (!(pcifunc & RVU_PFVF_FUNC_MASK))
		return false;

	return true;
}

static bool is_ml_af_reg(u64 offset)
{
	u16 i;

	switch (offset) {
	case ML_AF_CFG:
	case ML_AF_MLR_BASE:
	case ML_AF_JOB_MGR_CTRL:
	case ML_AF_CORE_INT_LO:
	case ML_AF_CORE_INT_LO_ENA_W1C:
	case ML_AF_CORE_INT_LO_ENA_W1S:
	case ML_AF_CORE_INT_HI:
	case ML_AF_CORE_INT_HI_ENA_W1C:
	case ML_AF_CORE_INT_HI_ENA_W1S:
	case ML_AF_WRAP_ERR_INT:
	case ML_AF_WRAP_ERR_INT_ENA_W1C:
	case ML_AF_WRAP_ERR_INT_ENA_W1S:
	case ML_PRIV_AF_CFG:
	case ML_PRIV_AF_INT_CFG:
	case ML_AF_RVU_INT:
	case ML_AF_RVU_INT_ENA_W1S:
	case ML_AF_RVU_INT_ENA_W1C:
	case ML_AF_LF_RST:
	case ML_AF_RVU_LF_CFG_DEBUG:
	case ML_AF_CONST:
	case ML_AF_MLR_SIZE:
		return true;
	}

	for (i = 0; i < 2; i++) {
		if (offset == ML_AF_AXI_BRIDGE_CTRLX(i))
			return true;
	}

	for (i = 0; i < ML_SCRATCH_NR; i++) {
		if (offset == ML_AF_SCRATCHX(i))
			return true;
	}

	for (i = 0; i < ML_ANBX_NR; i++) {
		if (offset == ML_AF_ANBX_BACKP_DISABLE(i))
			return true;
	}

	for (i = 0; i < ML_ANBX_NR; i++) {
		if (offset == ML_AF_ANBX_NCBI_P_OVR(i))
			return true;
	}

	for (i = 0; i < ML_ANBX_NR; i++) {
		if (offset == ML_AF_ANBX_NCBI_NP_OVR(i))
			return true;
	}

	return false;
}

int rvu_ml_lf_teardown(struct rvu *rvu, u16 pcifunc, int lf, int slot)
{
	u64 reg;
	u8 pid;

	if (!is_block_implemented(rvu->hw, BLKADDR_ML))
		return 0;

	/* Disable queuing requests to all partitions */
	for (pid = 0; pid < ML_MAX_PARTITIONS; pid++) {
		reg = rvu_read64(rvu, BLKADDR_ML, ML_AF_PIDX_LF_ALLOW(pid));
		reg &= ~BIT(lf);
		rvu_write64(rvu, BLKADDR_ML, ML_AF_PIDX_LF_ALLOW(pid), reg);
	}

	/* Wait for LF jobs to finish */
	rvu_poll_reg(rvu, BLKADDR_ML, ML_AF_LFX_JOB_IN_JMGR(lf),
		     GENMASK_ULL(6, 0), true);

	/* Reset LF */
	reg = BIT(12) | ((u64)lf & 0x1F);
	rvu_write64(rvu, BLKADDR_ML, ML_AF_LF_RST, reg);

	/* Clear LF MLR BASE */
	rvu_write64(rvu, BLKADDR_ML, ML_AF_LFX_MLR_BASE(lf), 0);

	return 0;
}

int rvu_mbox_handler_ml_rd_wr_register(struct rvu *rvu,
				       struct ml_rd_wr_reg_msg *req,
				       struct ml_rd_wr_reg_msg *rsp)
{
	if (!is_block_implemented(rvu->hw, BLKADDR_ML))
		return ML_AF_ERR_BLOCK_NOT_IMPLEMENTED;

	/* This message is accepted only if sent from ML PF/VF */
	if (!is_ml_pf(rvu, req->hdr.pcifunc) &&
	    !is_ml_vf(rvu, req->hdr.pcifunc))
		return ML_AF_ERR_ACCESS_DENIED;

	if (!is_ml_af_reg(req->reg_offset))
		return ML_AF_ERR_REG_INVALID;

	rsp->reg_offset = req->reg_offset;
	rsp->ret_val = req->ret_val;
	rsp->is_write = req->is_write;

	if (req->is_write)
		rvu_write64(rvu, BLKADDR_ML, req->reg_offset, req->val);
	else
		rsp->val = rvu_read64(rvu, BLKADDR_ML, req->reg_offset);

	return 0;
}

int rvu_mbox_handler_ml_caps_get(struct rvu *rvu, struct msg_req *req,
				 struct ml_caps_rsp_msg *rsp)
{
	if (!is_block_implemented(rvu->hw, BLKADDR_ML))
		return ML_AF_ERR_BLOCK_NOT_IMPLEMENTED;

	rsp->ml_af_const = rvu_read64(rvu, BLKADDR_ML, ML_AF_CONST);

	return 0;
}

int rvu_mbox_handler_ml_free_rsrc_cnt(struct rvu *rvu, struct msg_req *req,
				      struct ml_free_rsrcs_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;

	mutex_lock(&rvu->rsrc_lock);

	block = &hw->block[BLKADDR_ML];
	rsp->ml = rvu_rsrc_free_count(&block->lf);

	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}

int rvu_mbox_handler_ml_attach_resources(struct rvu *rvu,
					 struct ml_rsrc_attach *attach,
					 struct msg_rsp *rsp)
{
	u16 pcifunc = attach->hdr.pcifunc;
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	int free_lfs, mappedlfs;
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int slot, lf;
	u64 cfg;

	if (!attach->mllfs)
		return 0;

	/* If first request, detach all existing attached resources */
	if (!attach->modify)
		rvu_detach_block(rvu, pcifunc, BLKTYPE_ML);

	mutex_lock(&rvu->rsrc_lock);

	block = &hw->block[BLKADDR_ML];
	if (!block->lf.bmap)
		goto exit;

	if (attach->mllfs > block->lf.max) {
		dev_err(&rvu->pdev->dev,
			"Func 0x%x: Invalid MLLF req, %d > max %d\n", pcifunc,
			attach->mllfs, block->lf.max);
		return -EINVAL;
	}

	mappedlfs = rvu_get_rsrc_mapcount(pfvf, block->addr);
	free_lfs = rvu_rsrc_free_count(&block->lf);
	if (attach->mllfs > mappedlfs &&
	    ((attach->mllfs - mappedlfs) > free_lfs))
		goto fail;

	if (attach->modify && !!mappedlfs)
		rvu_detach_block(rvu, pcifunc, BLKTYPE_ML);

	for (slot = 0; slot < attach->mllfs; slot++) {
		/* Allocate the resource */
		lf = rvu_alloc_rsrc(&block->lf);
		if (lf < 0)
			return 0;

		cfg = (1ULL << 63) | (pcifunc << 8) | slot;
		rvu_write64(rvu, BLKADDR_ML,
			    block->lfcfg_reg | (lf << block->lfshift), cfg);
		rvu_update_rsrc_map(rvu, pfvf, block, pcifunc, lf, true);

		/* Set start MSIX vector for this LF within this PF/VF */
		rvu_set_msix_offset(rvu, pfvf, block, lf);
	}

exit:
	mutex_unlock(&rvu->rsrc_lock);

	return 0;

fail:
	mutex_unlock(&rvu->rsrc_lock);
	dev_info(rvu->dev, "Request for %s failed\n", block->name);

	return -ENOSPC;
}

int rvu_mbox_handler_ml_detach_resources(struct rvu *rvu, struct msg_req *req,
					 struct msg_rsp *rsp)
{
	mutex_lock(&rvu->rsrc_lock);

	rvu_detach_block(rvu, req->hdr.pcifunc, BLKTYPE_ML);

	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}

int rvu_mbox_handler_ml_msix_offset(struct rvu *rvu, struct msg_req *req,
				    struct ml_msix_offset_rsp *rsp)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_pfvf *pfvf;
	int lf, slot;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	if (!pfvf->msix.bmap)
		return 0;

	rsp->mllfs = pfvf->mllfs;
	for (slot = 0; slot < rsp->mllfs; slot++) {
		lf = rvu_get_lf(rvu, &hw->block[BLKADDR_ML], pcifunc, slot);
		rsp->mllf_msixoff[slot] =
			rvu_get_msix_offset(rvu, pfvf, BLKADDR_ML, lf);
	}

	return 0;
}

int rvu_mbox_handler_ml_lf_alloc(struct rvu *rvu, struct ml_lf_alloc_req *req,
				 struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	int mllf;
	int num_lfs, slot;
	u64 val;

	if (!is_block_implemented(rvu->hw, BLKADDR_ML))
		return ML_AF_ERR_BLOCK_NOT_IMPLEMENTED;

	block = &rvu->hw->block[BLKADDR_ML];
	num_lfs =
		rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc), block->addr);
	if (!num_lfs)
		return ML_AF_ERR_LF_INVALID;

	/* Check if requested 'MLLF <=> SSOLF' mapping is valid */
	if (req->sso_pf_func) {
		/* If default, use 'this' MLLF's PFFUNC */
		if (req->sso_pf_func == RVU_DEFAULT_PF_FUNC)
			req->sso_pf_func = pcifunc;
		if (!is_pffunc_map_valid(rvu, req->sso_pf_func, BLKTYPE_SSO))
			return ML_AF_ERR_SSO_PF_FUNC_INVALID;
	}

	for (slot = 0; slot < num_lfs; slot++) {
		mllf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (mllf < 0)
			return ML_AF_ERR_LF_INVALID;

		/* Set ML LF SSO_PF_FUNC. */
		val = rvu_read64(rvu, BLKADDR_ML, ML_AF_LFX_GMCTL(mllf));
		val &= ~GENMASK_ULL(15, 0);
		val |= (u64)req->sso_pf_func;
		rvu_write64(rvu, BLKADDR_ML, ML_AF_LFX_GMCTL(mllf), val);
	}

	return 0;
}

int rvu_mbox_handler_ml_lf_free(struct rvu *rvu, struct msg_req *req,
				struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	int num_lfs, mllf, slot, err;
	struct rvu_block *block;

	if (!is_block_implemented(rvu->hw, BLKADDR_ML))
		return ML_AF_ERR_BLOCK_NOT_IMPLEMENTED;

	block = &rvu->hw->block[BLKADDR_ML];
	num_lfs =
		rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc), block->addr);
	if (!num_lfs)
		return 0;

	for (slot = 0; slot < num_lfs; slot++) {
		mllf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (mllf < 0)
			return ML_AF_ERR_LF_INVALID;

		/* Perform teardown */
		rvu_ml_lf_teardown(rvu, pcifunc, mllf, slot);

		/* Reset LF */
		err = rvu_lf_reset(rvu, block, mllf);
		if (err) {
			dev_err(rvu->dev, "Failed to reset blkaddr %d LF%d\n",
				block->addr, mllf);
		}
	}

	return 0;
}

int rvu_mbox_handler_ml_lf_set_pid(struct rvu *rvu,
				   struct ml_lf_set_pid_req *req,
				   struct msg_rsp *rsp)
{
	u64 regval;
	u16 pid;

	if (!is_block_implemented(rvu->hw, BLKADDR_ML))
		return ML_AF_ERR_BLOCK_NOT_IMPLEMENTED;

	/* This message is accepted only if sent from ML PF/VF */
	if (!is_ml_pf(rvu, req->hdr.pcifunc) &&
	    !is_ml_vf(rvu, req->hdr.pcifunc))
		return ML_AF_ERR_ACCESS_DENIED;

	for (pid = 0; pid < ML_MAX_PARTITIONS; pid++) {
		if (!(req->pid_mask & BIT(pid)))
			continue;

		regval = rvu_read64(rvu, BLKADDR_ML, ML_AF_PIDX_LF_ALLOW(pid));
		regval |= BIT(req->lf_id);
		rvu_write64(rvu, BLKADDR_ML, ML_AF_PIDX_LF_ALLOW(pid), regval);
	}

	return 0;
}

static int rvu_ml_mbox_handler(struct otx2_mbox *mbox, int devid,
			       struct mbox_msghdr *req)
{
	struct rvu *rvu = pci_get_drvdata(mbox->pdev);
	int _id = req->id;

	switch (_id) {
#define M(_name, _id, _fn_name, _req_type, _rsp_type)                       \
	{                                                                   \
	case _id: {                                                         \
		struct _rsp_type *rsp;                                      \
		int err;                                                    \
									    \
		rsp = (struct _rsp_type *)otx2_mbox_alloc_msg(              \
			mbox, devid, sizeof(struct _rsp_type));             \
		if (rsp) {                                                  \
			rsp->hdr.id = _id;                                  \
			rsp->hdr.sig = OTX2_MBOX_RSP_SIG;                   \
			rsp->hdr.pcifunc = req->pcifunc;                    \
			rsp->hdr.rc = 0;                                    \
		}                                                           \
									    \
		err = rvu_mbox_handler_##_fn_name(                          \
			rvu, (struct _req_type *)req, rsp);                 \
		if (rsp && err)                                             \
			rsp->hdr.rc = err;                                  \
									    \
		trace_otx2_msg_process(mbox->pdev, _id, err, req->pcifunc); \
		return rsp ? err : -ENOMEM;                                 \
	}                                                                   \
	}
		MBOX_EBLOCK_ML_MESSAGES

	default :
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}
}

static void *rvu_ml_probe(struct rvu *rvu, int blkaddr)
{
	struct ml_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_ML:
		data = devm_kzalloc(rvu->dev, sizeof(struct ml_drvdata),
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

static void rvu_ml_remove(struct rvu_block *hwblock, void *data)
{
	devm_kfree(hwblock->rvu->dev, data);
}

static int rvu_ml_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	u16 pid;

	(void)data;

	/* Retrieve ML PF number */
	rvu->ml_pf_num = get_ml_pf_num(rvu);

	/* Configure ML_PRIV_AF_CFG register */
	rvu_write64(rvu, block->addr, ML_PRIV_AF_CFG, (rvu->ml_pf_num & 0x2F));

	/* Reset LF and PID map */
	for (pid = 0; pid < ML_MAX_PARTITIONS; pid++)
		rvu_write64(rvu, block->addr, ML_AF_PIDX_LF_ALLOW(pid), 0x0);

	return 0;
}

static int rvu_ml_setup_hw_resource(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	struct rvu_hwinfo *hw = rvu->hw;
	u64 cfg;
	int err;

	block = &hw->block[BLKADDR_ML];
	if (!block->implemented)
		return 0;

	cfg = rvu_read64(rvu, block->addr, ML_AF_CONST);
	block->lf.max = cfg & 0xFF;
	block->type = BLKTYPE_ML;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = ML_AF_RVU_LF_CFG_DEBUG;
	block->lfcfg_reg = ML_PRIV_LFX_CFG;
	block->msixcfg_reg = ML_PRIV_LFX_INT_CFG;
	block->lfreset_reg = ML_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "ML");

	err = rvu_alloc_bitmap(&block->lf);
	if (err) {
		dev_err(rvu->dev, "Failed to allocate ML LF bitmap\n");
		return err;
	}
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

static void rvu_ml_freemem_block(struct rvu_block *block, void *data)
{
	(void)data;

	rvu_free_bitmap(&block->lf);
}

static irqreturn_t rvu_ml_af_core_int_lo_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_CORE_INT_LO);
	if (intr & ML_AF_CORE_INT_LO_INT_LO)
		dev_err_ratelimited(rvu->dev,
				    "ML: Low priority interrupt from MLIP\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_LO, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_ml_af_core_int_hi_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_CORE_INT_HI);
	if (intr & ML_AF_CORE_INT_HI_INT_HI)
		dev_err_ratelimited(rvu->dev,
				    "ML: High priority interrupt from MLIP\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_HI, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_ml_af_wrap_err_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_WRAP_ERR_INT);
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P0_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 0 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P1_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 1 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P2_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 2 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P3_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 3 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_RADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC read request address out of bound\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_WADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC write request address out of bound.\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_NCB_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC read response error from NCB bus.\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_NCB_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC write response error from NCB bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_CSR_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC read response error from CSR bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_CSR_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC write response error from CSR bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_RADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA read request address out of bound\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_WADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA write request address out of bound\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_NCB_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA read response error from NCB bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_NCB_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA write response error from NCB bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_CSR_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA read response error from CSR bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_CSR_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA write response error from CSR bus\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_WRAP_ERR_INT, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_ml_af_rvu_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_RVU_INT);
	if (intr & ML_AF_RVU_INT_UNMAPPED_SLOT)
		dev_err_ratelimited(rvu->dev, "ML: Unmapped slot\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_RVU_INT, intr);

	return IRQ_HANDLED;
}

static int rvu_ml_af_request_irq(struct rvu_block *block, int offset,
				 irq_handler_t handler, const char *name)
{
	int ret = 0;
	struct rvu *rvu = block->rvu;

	WARN_ON(rvu->irq_allocated[offset]);
	rvu->irq_allocated[offset] = false;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "%s", name);
	ret = request_irq(pci_irq_vector(rvu->pdev, offset), handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], block);
	if (ret)
		dev_warn(block->rvu->dev, "Failed to register %s irq\n", name);
	else
		rvu->irq_allocated[offset] = true;

	return rvu->irq_allocated[offset];
}

static int rvu_ml_register_interrupts_block(struct rvu_block *block, void *data)
{
	struct ml_drvdata *drvdata = data;
	int offs, blkid, blkaddr, ret = 0;
	struct rvu *rvu = block->rvu;

	blkid = drvdata->res_idx;
	blkaddr = block->addr;

	/* Read interrupt vector */
	offs = rvu_read64(rvu, blkaddr, ML_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev, "Failed to get ML_AF_INT vector offsets");
		return 0;
	}

	/* Register and enable CORE_INT_LO interrupt */
	ret = rvu_ml_af_request_irq(
		block, offs + ML_AF_INT_VEC_CORE_INT_LO,
		rvu_ml_af_core_int_lo_intr_handler,
		ml_irq_name[blkid][ML_AF_INT_VEC_CORE_INT_LO]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_LO_ENA_W1S, ~0ULL);

	/* Register and enable CORE_INT_HI interrupt */
	ret = rvu_ml_af_request_irq(
		block, offs + ML_AF_INT_VEC_CORE_INT_HI,
		rvu_ml_af_core_int_hi_intr_handler,
		ml_irq_name[blkid][ML_AF_INT_VEC_CORE_INT_HI]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_HI_ENA_W1S, ~0ULL);

	/* Register and enable WRAP_ERR_INT interrupt */
	ret = rvu_ml_af_request_irq(
		block, offs + ML_AF_INT_VEC_WRAP_ERR_INT,
		rvu_ml_af_wrap_err_intr_handler,
		ml_irq_name[blkid][ML_AF_INT_VEC_WRAP_ERR_INT]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_WRAP_ERR_INT_ENA_W1S, ~0ULL);

	/* Register and enable RVU interrupt */
	ret = rvu_ml_af_request_irq(block, offs + ML_AF_INT_VEC_RVU_INT,
				    rvu_ml_af_rvu_intr_handler,
				    ml_irq_name[blkid][ML_AF_INT_VEC_RVU_INT]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_RVU_INT_ENA_W1S, ~0ULL);

	return 0;
err:
	rvu_ml_unregister_interrupts_block(block, data);

	return ret;
}

static void rvu_ml_unregister_interrupts_block(struct rvu_block *block,
					       void *data)
{
	int i, offs, blkaddr;
	struct rvu *rvu = block->rvu;

	blkaddr = block->addr;

	offs = rvu_read64(rvu, blkaddr, ML_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev, "Failed to get ML_AF_INT vector offsets");
		return;
	}

	/* Disable all ML AF interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_LO_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_HI_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, ML_AF_WRAP_ERR_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, ML_AF_RVU_INT_ENA_W1C, 0x1);

	for (i = 0; i < ML_AF_INT_VEC_CNT; i++) {
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), block);
			rvu->irq_allocated[offs + i] = false;
		}
	}
}

struct mbox_op ml_mbox_op = {
	.start = 0xB000,
	.end = 0xB0FF,
	.handler = rvu_ml_mbox_handler,
};

static struct rvu_eblock_driver_ops ml_ops = {
	.probe = rvu_ml_probe,
	.remove = rvu_ml_remove,
	.init = rvu_ml_init_block,
	.setup = rvu_ml_setup_hw_resource,
	.free = rvu_ml_freemem_block,
	.register_interrupt = rvu_ml_register_interrupts_block,
	.unregister_interrupt = rvu_ml_unregister_interrupts_block,
	.mbox_op = &ml_mbox_op,
};

void ml_eb_module_init(void)
{
	rvu_eblock_register_driver(&ml_ops);
}

void ml_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&ml_ops);
}
