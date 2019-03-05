// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/pci.h>
#include "rvu_struct.h"
#include "rvu_reg.h"
#include "mbox.h"
#include "rvu.h"

/* CPT PF device id */
#define	PCI_DEVID_OTX2_CPT_PF	0xA0FD

/* Maximum supported microcode groups */
#define CPT_MAX_ENGINE_GROUPS	8

/* Invalid engine group */
#define INVALID_ENGINE_GRP	0xFF

/* Number of engine group for symmetric crypto */
static int crypto_eng_grp = INVALID_ENGINE_GRP;

/* CPT PF number */
static int cpt_pf_num = -1;

/* Fault interrupts names */
static const char *cpt_flt_irq_name[2] = { "CPTAF FLT0", "CPTAF FLT1" };

static irqreturn_t rvu_cpt_af_flr_intr_handler(int irq, void *ptr)
{
	struct rvu *rvu = (struct rvu *) ptr;
	u64 reg0, reg1;
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	reg0 = rvu_read64(rvu, blkaddr, CPT_AF_FLTX_INT(0));
	reg1 = rvu_read64(rvu, blkaddr, CPT_AF_FLTX_INT(1));
	dev_err(rvu->dev, "Received CPTAF FLT irq : 0x%llx, 0x%llx",
		reg0, reg1);

	rvu_write64(rvu, blkaddr, CPT_AF_FLTX_INT(0), reg0);
	rvu_write64(rvu, blkaddr, CPT_AF_FLTX_INT(1), reg1);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_cpt_af_rvu_intr_handler(int irq, void *ptr)
{
	struct rvu *rvu = (struct rvu *) ptr;
	int blkaddr;
	u64 reg;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	reg = rvu_read64(rvu, blkaddr, CPT_AF_RVU_INT);
	dev_err(rvu->dev, "Received CPTAF RVU irq : 0x%llx", reg);

	rvu_write64(rvu, blkaddr, CPT_AF_RVU_INT, reg);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_cpt_af_ras_intr_handler(int irq, void *ptr)
{
	struct rvu *rvu = (struct rvu *) ptr;
	int blkaddr;
	u64 reg;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	reg = rvu_read64(rvu, blkaddr, CPT_AF_RAS_INT);
	dev_err(rvu->dev, "Received CPTAF RAS irq : 0x%llx", reg);

	rvu_write64(rvu, blkaddr, CPT_AF_RAS_INT, reg);
	return IRQ_HANDLED;
}

static int rvu_cpt_do_register_interrupt(struct rvu *rvu, int irq_offs,
					 irq_handler_t handler,
					 const char *name)
{
	int ret = 0;

	ret = request_irq(pci_irq_vector(rvu->pdev, irq_offs), handler, 0,
			  name, rvu);
	if (ret) {
		dev_err(rvu->dev, "RVUAF: %s irq registration failed", name);
		goto err;
	}

	WARN_ON(rvu->irq_allocated[irq_offs]);
	rvu->irq_allocated[irq_offs] = true;
err:
	return ret;
}

void rvu_cpt_unregister_interrupts(struct rvu *rvu)
{
	int blkaddr, i, offs;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return;

	offs = rvu_read64(rvu, blkaddr, CPT_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get CPT_AF_INT vector offsets\n");
		return;
	}

	/* Disable all CPT AF interrupts */
	for (i = 0; i < 2; i++)
		rvu_write64(rvu, blkaddr, CPT_AF_FLTX_INT_ENA_W1C(i), 0x1);
	rvu_write64(rvu, blkaddr, CPT_AF_RVU_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, CPT_AF_RAS_INT_ENA_W1C, 0x1);

	for (i = 0; i < CPT_AF_INT_VEC_CNT; i++)
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), rvu);
			rvu->irq_allocated[offs + i] = false;
		}
}

static bool is_cpt_pf(u16 pcifunc)
{
	if (rvu_get_pf(pcifunc) != cpt_pf_num)
		return false;
	if (pcifunc & RVU_PFVF_FUNC_MASK)
		return false;

	return true;
}

static bool is_cpt_vf(u16 pcifunc)
{
	if (rvu_get_pf(pcifunc) != cpt_pf_num)
		return false;
	if (!(pcifunc & RVU_PFVF_FUNC_MASK))
		return false;

	return true;
}

int rvu_cpt_init(struct rvu *rvu)
{
	struct pci_dev *pdev;
	int i;

	for (i = 0; i < rvu->hw->total_pfs; i++) {
		pdev = pci_get_domain_bus_and_slot(
				pci_domain_nr(rvu->pdev->bus), i + 1, 0);
		if (!pdev)
			continue;

		if (pdev->device == PCI_DEVID_OTX2_CPT_PF) {
			cpt_pf_num = i;
			put_device(&pdev->dev);
			break;
		}

		put_device(&pdev->dev);
	}

	return 0;
}

int rvu_cpt_register_interrupts(struct rvu *rvu)
{

	int i, offs, blkaddr, ret = 0;

	if (!is_block_implemented(rvu->hw, BLKADDR_CPT0))
		return 0;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return blkaddr;

	offs = rvu_read64(rvu, blkaddr, CPT_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get CPT_AF_INT vector offsets\n");
		return 0;
	}

	for (i = CPT_AF_INT_VEC_FLT0; i < CPT_AF_INT_VEC_RVU; i++) {
		ret = rvu_cpt_do_register_interrupt(rvu, offs + i,
						    rvu_cpt_af_flr_intr_handler,
						    cpt_flt_irq_name[i]);
		if (ret)
			goto err;
		rvu_write64(rvu, blkaddr, CPT_AF_FLTX_INT_ENA_W1S(i), 0x1);
	}

	ret = rvu_cpt_do_register_interrupt(rvu, offs + CPT_AF_INT_VEC_RVU,
					    rvu_cpt_af_rvu_intr_handler,
					    "CPTAF RVU");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, CPT_AF_RVU_INT_ENA_W1S, 0x1);

	ret = rvu_cpt_do_register_interrupt(rvu, offs + CPT_AF_INT_VEC_RAS,
					    rvu_cpt_af_ras_intr_handler,
					    "CPTAF RAS");
	if (ret)
		goto err;
	rvu_write64(rvu, blkaddr, CPT_AF_RAS_INT_ENA_W1S, 0x1);

	return 0;
err:
	rvu_cpt_unregister_interrupts(rvu);
	return ret;
}

int rvu_mbox_handler_cpt_lf_alloc(struct rvu *rvu,
				  struct cpt_lf_alloc_req_msg *req,
				  struct cpt_lf_alloc_rsp_msg *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	int num_lfs, slot, grp_mask;
	struct rvu_block *block;
	int cptlf, blkaddr;
	u64 val;

	if (crypto_eng_grp == INVALID_ENGINE_GRP)
		return CPT_AF_ERR_GRP_INVALID;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, pcifunc);
	if (blkaddr < 0)
		return blkaddr;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->type);
	if (!num_lfs)
		return CPT_AF_ERR_LF_INVALID;

	/* Check if requested 'CPTLF <=> NIXLF' mapping is valid */
	if (req->nix_pf_func) {
		/* If default, use 'this' CPTLF's PFFUNC */
		if (req->nix_pf_func == RVU_DEFAULT_PF_FUNC)
			req->nix_pf_func = pcifunc;
		if (!is_pffunc_map_valid(rvu, req->nix_pf_func, BLKTYPE_NIX))
			return CPT_AF_ERR_NIX_PF_FUNC_INVALID;
	}

	/* Check if requested 'CPTLF <=> SSOLF' mapping is valid */
	if (req->sso_pf_func) {
		/* If default, use 'this' CPTLF's PFFUNC */
		if (req->sso_pf_func == RVU_DEFAULT_PF_FUNC)
			req->sso_pf_func = pcifunc;
		if (!is_pffunc_map_valid(rvu, req->sso_pf_func, BLKTYPE_SSO))
			return CPT_AF_ERR_SSO_PF_FUNC_INVALID;
	}

	for (slot = 0; slot < num_lfs; slot++) {
		cptlf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (cptlf < 0)
			return CPT_AF_ERR_LF_INVALID;

		/* Set CPT LF group and priority */
		grp_mask = 1 << crypto_eng_grp;
		val = (u64) grp_mask << 48 | 1;
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), val);

		/* Set CPT LF NIX_PF_FUNC and SSO_PF_FUNC */
		val = (u64) req->nix_pf_func << 48 |
		      (u64) req->sso_pf_func << 32;
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf), val);
	}

	rsp->crypto_eng_grp = crypto_eng_grp;
	return 0;
}

int rvu_mbox_handler_cpt_lf_free(struct rvu *rvu, struct msg_req *req,
				 struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	int cptlf, blkaddr;
	int num_lfs, slot;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, pcifunc);
	if (blkaddr < 0)
		return blkaddr;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->type);
	if (!num_lfs)
		return CPT_AF_ERR_LF_INVALID;

	for (slot = 0; slot < num_lfs; slot++) {
		cptlf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (cptlf < 0)
			return CPT_AF_ERR_LF_INVALID;

		/* Reset CPT LF group and priority */
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), 0x0);
		/* Reset CPT LF NIX_PF_FUNC and SSO_PF_FUNC */
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf), 0x0);
	}

	return 0;
}

int rvu_mbox_handler_cpt_set_crypto_grp(struct rvu *rvu,
					struct cpt_set_crypto_grp_req_msg *req,
					struct cpt_set_crypto_grp_req_msg *rsp)
{
	/* This message is accepted only if sent from CPT PF */
	if (!is_cpt_pf(req->hdr.pcifunc))
		return CPT_AF_ERR_ACCESS_DENIED;

	rsp->crypto_eng_grp = req->crypto_eng_grp;

	if (req->crypto_eng_grp != INVALID_ENGINE_GRP &&
	    req->crypto_eng_grp >= CPT_MAX_ENGINE_GROUPS)
		return CPT_AF_ERR_GRP_INVALID;

	crypto_eng_grp = req->crypto_eng_grp;
	return 0;
}

int rvu_mbox_handler_cpt_rd_wr_register(struct rvu *rvu,
					struct cpt_rd_wr_reg_msg *req,
					struct cpt_rd_wr_reg_msg *rsp)
{
	int blkaddr, num_lfs, offs, lf;
	struct rvu_block *block;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return blkaddr;

	/* This message is accepted only if sent from CPT PF/VF */
	if (!is_cpt_pf(req->hdr.pcifunc) &&
	    !is_cpt_vf(req->hdr.pcifunc))
		return CPT_AF_ERR_ACCESS_DENIED;

	rsp->reg_offset = req->reg_offset;
	rsp->ret_val = req->ret_val;
	rsp->is_write = req->is_write;

	if (req->hdr.pcifunc & RVU_PFVF_FUNC_MASK) {
		/* Registers that can be accessed from VF */
		switch (req->reg_offset & 0xFF000) {
		case CPT_AF_LFX_CTL(0):
			offs = req->reg_offset & 0xFFF;
			if (offs % 8)
				goto error;
			lf = offs >> 3;
		break;

		default:
			goto error;
		}

		block = &rvu->hw->block[blkaddr];
		num_lfs = rvu_get_rsrc_mapcount(
					rvu_get_pfvf(rvu, req->hdr.pcifunc),
					block->type);
		if (lf >= num_lfs)
			/* Slot is not valid for that VF */
			goto error;

		/* Need to translate CPT LF slot to global number because
		 * VFs use local numbering from 0 to number of LFs - 1
		 */
		lf = rvu_get_lf(rvu, &rvu->hw->block[blkaddr],
				req->hdr.pcifunc, lf);
		if (lf < 0)
			goto error;

		req->reg_offset &= 0xFF000;
		req->reg_offset += lf << 3;
		rsp->reg_offset = req->reg_offset;
	} else {
		/* Registers that can be accessed from PF */
		switch (req->reg_offset & 0xFF000) {
		case CPT_AF_PF_FUNC:
		case CPT_AF_BLK_RST:
		case CPT_AF_CONSTANTS1:
			if (req->reg_offset & 0xFFF)
				goto error;
		break;

		case CPT_AF_EXEX_STS(0):
		case CPT_AF_EXEX_CTL(0):
		case CPT_AF_EXEX_CTL2(0):
		case CPT_AF_EXEX_UCODE_BASE(0):
			offs = req->reg_offset & 0xFFF;
			if ((offs % 8) || (offs >> 3) > 127)
				goto error;
		break;

		default:
			goto error;
		}
	}

	if (req->is_write)
		rvu_write64(rvu, blkaddr, req->reg_offset, req->val);
	else
		rsp->val = rvu_read64(rvu, blkaddr, req->reg_offset);

	return 0;
error:
	/* Access to register denied */
	return CPT_AF_ERR_ACCESS_DENIED;
}
