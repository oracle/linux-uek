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
#define CONST_MAX_EPFS  GENMASK_ULL(63, 48)

struct psw_rsrc {
	u8 *pf2epf_map;
	u64 const0;
	u64 const1;
	u64 const2;
	u8 num_epfs;
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

	return 0;
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

static void rvu_psw_remove(struct rvu_block *hwblock, void *data)
{
	devm_kfree(hwblock->rvu->dev, data);
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
