// SPDX-License-Identifier: GPL-2.0-only
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2020 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/pci.h>
#include "rvu_struct.h"
#include "rvu_reg.h"
#include "mbox.h"
#include "rvu.h"

/* CPT PF device id */
#define	PCI_DEVID_OTX2_CPT_PF	0xA0FD
#define	PCI_DEVID_OTX2_CPT10_PF	0xA0F2

/* Length of initial context fetch in 128 byte words */
#define CPT_CTX_ILEN    2

#define cpt_get_eng_sts(e_min, e_max, rsp, etype)                   \
({                                                                  \
	u64 free_sts = 0, busy_sts = 0;                             \
	typeof(rsp) _rsp = rsp;                                     \
	u32 e, i;                                                   \
								    \
	for (e = (e_min), i = 0; e < (e_max); e++, i++) {           \
		reg = rvu_read64(rvu, blkaddr, CPT_AF_EXEX_STS(e)); \
		if (reg & 0x1)                                      \
			busy_sts |= 1ULL << i;                      \
								    \
		if (reg & 0x2)                                      \
			free_sts |= 1ULL << i;                      \
	}                                                           \
	(_rsp)->busy_sts_##etype = busy_sts;                        \
	(_rsp)->free_sts_##etype = free_sts;                        \
})

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
	dev_err_ratelimited(rvu->dev, "Received CPTAF FLT irq : 0x%llx, 0x%llx",
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
	dev_err_ratelimited(rvu->dev, "Received CPTAF RVU irq : 0x%llx", reg);

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
	dev_err_ratelimited(rvu->dev, "Received CPTAF RAS irq : 0x%llx", reg);

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

static bool is_cpt_blkaddr(int blkaddr)
{
	if (blkaddr != BLKADDR_CPT0 && blkaddr != BLKADDR_CPT1)
		return false;

	return true;
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

		if (pdev->device == PCI_DEVID_OTX2_CPT_PF ||
		    pdev->device == PCI_DEVID_OTX2_CPT10_PF) {
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
				  struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	int cptlf, blkaddr;
	int num_lfs, slot;
	u64 val;

	blkaddr = req->blkaddr ? req->blkaddr : BLKADDR_CPT0;
	if (!is_cpt_blkaddr(blkaddr))
		return -EINVAL;

	if (req->eng_grpmsk == 0x0)
		return CPT_AF_ERR_GRP_INVALID;

	block = &rvu->hw->block[blkaddr];
	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->addr);
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
		val = (u64)req->eng_grpmsk << 48 | 1;
		/* Configure initial context push length */
		val |= (CPT_CTX_ILEN << 17);
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), val);

		/* Set CPT LF NIX_PF_FUNC and SSO_PF_FUNC. EXE_LDWB is set
		 * on reset.
		 */
		val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf));
		val &= ~(GENMASK_ULL(63, 48) | GENMASK_ULL(47, 32));
		val |= ((u64)req->nix_pf_func << 48 |
			(u64)req->sso_pf_func << 32);
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf), val);
	}
	return 0;
}

static int cpt_lf_free(struct rvu *rvu, struct msg_req *req, int blkaddr)
{
	u16 pcifunc = req->hdr.pcifunc;
	int num_lfs, cptlf, slot, err;
	struct rvu_block *block;

	block = &rvu->hw->block[blkaddr];

	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					block->addr);
	if (!num_lfs)
		return 0;

	for (slot = 0; slot < num_lfs; slot++) {
		cptlf = rvu_get_lf(rvu, block, pcifunc, slot);
		if (cptlf < 0)
			return CPT_AF_ERR_LF_INVALID;

		/* Perform teardown */
		rvu_cpt_lf_teardown(rvu, pcifunc, blkaddr, cptlf, slot);

		/* Reset LF */
		err = rvu_lf_reset(rvu, block, cptlf);
		if (err) {
			dev_err(rvu->dev, "Failed to reset blkaddr %d LF%d\n",
				block->addr, cptlf);
		}
	}

	return 0;
}

int rvu_mbox_handler_cpt_lf_free(struct rvu *rvu, struct msg_req *req,
				 struct msg_rsp *rsp)
{
	int ret;

	ret = cpt_lf_free(rvu, req, BLKADDR_CPT0);
	if (ret)
		return ret;

	if (is_block_implemented(rvu->hw, BLKADDR_CPT1))
		ret = cpt_lf_free(rvu, req, BLKADDR_CPT1);

	return ret;
}

static int cpt_inline_ipsec_cfg_inbound(struct rvu *rvu, int blkaddr, u8 cptlf,
					struct cpt_inline_ipsec_cfg_msg *req)
{
	u16 sso_pf_func = req->sso_pf_func;
	u8 nix_sel;
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

	nix_sel = (blkaddr == BLKADDR_CPT1) ? 1 : 0;
	/* Set PF_FUNC_INST */
	if (req->enable)
		val |= BIT_ULL(9);
	else
		val &= ~BIT_ULL(9);

	val |= (u64)nix_sel << 8;
	rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), val);

	if (sso_pf_func) {
		/* Set SSO_PF_FUNC */
		val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf));
		val |= (u64)sso_pf_func << 32;
		val |= (u64)req->nix_pf_func << 48;
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf), val);
	}
	if (req->sso_pf_func_ovrd)
		/* Set SSO_PF_FUNC_OVRD for inline IPSec */
		rvu_write64(rvu, blkaddr, CPT_AF_ECO, 0x1);

	/* Configure the X2P Link register with the cpt base channel number and
	 * range of channels it should propagate to X2P
	 */
	if (!is_rvu_otx2(rvu)) {
		val = (ilog2(NIX_CHAN_CPT_X2P_MASK + 1) << 16);
		val |= rvu->hw->cpt_chan_base;

		rvu_write64(rvu, blkaddr, CPT_AF_X2PX_LINK_CFG(0), val);
		rvu_write64(rvu, blkaddr, CPT_AF_X2PX_LINK_CFG(1), val);
	}

	return 0;
}

static int cpt_inline_ipsec_cfg_outbound(struct rvu *rvu, int blkaddr, u8 cptlf,
					 struct cpt_inline_ipsec_cfg_msg *req)
{
	u16 nix_pf_func = req->nix_pf_func;
	int nix_blkaddr;
	u8 nix_sel;
	u64 val;

	val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf));
	if (req->enable && (val & BIT_ULL(9))) {
		/* IPSec inline inbound path is already enabled for a given
		 * CPT LF, HRM states that inline inbound & outbound paths
		 * must not be enabled at the same time for a given CPT LF
		 */
		return CPT_AF_ERR_INLINE_IPSEC_OUT_ENA;
	}

	/* Check if requested 'CPTLF <=> NIXLF' mapping is valid */
	if (nix_pf_func && !is_pffunc_map_valid(rvu, nix_pf_func, BLKTYPE_NIX))
		return CPT_AF_ERR_NIX_PF_FUNC_INVALID;

	/* Set PF_FUNC_INST */
	if (req->enable)
		val |= BIT_ULL(16);
	else
		val &= ~BIT_ULL(16);
	rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), val);

	if (nix_pf_func) {
		/* Set NIX_PF_FUNC */
		val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf));
		val |= (u64)nix_pf_func << 48;
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL2(cptlf), val);

		nix_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, nix_pf_func);
		nix_sel = (nix_blkaddr == BLKADDR_NIX0) ? 0 : 1;

		val = rvu_read64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf));
		val |= (u64)nix_sel << 8;
		rvu_write64(rvu, blkaddr, CPT_AF_LFX_CTL(cptlf), val);
	}

	return 0;
}

int rvu_mbox_handler_cpt_inline_ipsec_cfg(struct rvu *rvu,
					  struct cpt_inline_ipsec_cfg_msg *req,
					  struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct rvu_block *block;
	int cptlf, blkaddr, ret;
	u16 actual_slot;

	blkaddr = rvu_get_blkaddr_from_slot(rvu, BLKTYPE_CPT, pcifunc,
					    req->slot, &actual_slot);
	if (blkaddr < 0)
		return CPT_AF_ERR_LF_INVALID;

	block = &rvu->hw->block[blkaddr];

	cptlf = rvu_get_lf(rvu, block, pcifunc, actual_slot);
	if (cptlf < 0)
		return CPT_AF_ERR_LF_INVALID;

	switch (req->dir) {
	case CPT_INLINE_INBOUND:
		ret = cpt_inline_ipsec_cfg_inbound(rvu, blkaddr, cptlf, req);
		break;

	case CPT_INLINE_OUTBOUND:
		ret = cpt_inline_ipsec_cfg_outbound(rvu, blkaddr, cptlf, req);
		break;

	default:
		return CPT_AF_ERR_PARAM;
	}

	return ret;
}

int rvu_mbox_handler_cpt_rd_wr_register(struct rvu *rvu,
					struct cpt_rd_wr_reg_msg *req,
					struct cpt_rd_wr_reg_msg *rsp)
{
	int blkaddr, num_lfs, offs, lf;
	struct rvu_block *block;

	blkaddr = req->blkaddr ? req->blkaddr : BLKADDR_CPT0;
	if (!is_cpt_blkaddr(blkaddr))
		return -EINVAL;

	/* This message is accepted only if sent from CPT PF/VF */
	if (!is_cpt_pf(req->hdr.pcifunc) &&
	    !is_cpt_vf(req->hdr.pcifunc))
		return CPT_AF_ERR_ACCESS_DENIED;

	rsp->reg_offset = req->reg_offset;
	rsp->ret_val = req->ret_val;
	rsp->is_write = req->is_write;

	/* Registers that can be accessed from PF/VF */
	if ((req->reg_offset & 0xFF000) ==  CPT_AF_LFX_CTL(0) ||
	    (req->reg_offset & 0xFF000) ==  CPT_AF_LFX_CTL2(0)) {
		offs = req->reg_offset & 0xFFF;
		if (offs % 8)
			goto error;
		lf = offs >> 3;
		block = &rvu->hw->block[blkaddr];
		num_lfs = rvu_get_rsrc_mapcount(
				rvu_get_pfvf(rvu, req->hdr.pcifunc),
				block->addr);
		if (lf >= num_lfs)
			/* Slot is not valid for that PF/VF */
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
	} else if (!(req->hdr.pcifunc & RVU_PFVF_FUNC_MASK)) {
		/* Registers that can be accessed from PF */
		switch (req->reg_offset & 0xFF000) {
		case CPT_AF_DIAG:
		case CPT_AF_CTL:
		case CPT_AF_PF_FUNC:
		case CPT_AF_BLK_RST:
		case CPT_AF_CONSTANTS1:
		case CPT_AF_CTX_FLUSH_TIMER:
			if (req->reg_offset & 0xFFF)
				goto error;
			break;

		case CPT_AF_EXEX_STS(0):
		case CPT_AF_EXEX_CTL(0):
		case CPT_AF_EXEX_CTL2(0):
		case CPT_AF_EXEX_UCODE_BASE(0):
			offs = req->reg_offset & 0xFFF;
			if (offs % 8)
				goto error;
			break;
		default:
			goto error;
		}
	} else {
		goto error;
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

static void get_ctx_pc(struct rvu *rvu, struct cpt_sts_rsp *rsp, int blkaddr)
{
	rsp->ctx_mis_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_MIS_PC);
	rsp->ctx_hit_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_HIT_PC);
	rsp->ctx_aop_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_AOP_PC);
	rsp->ctx_aop_lat_pc = rvu_read64(rvu, blkaddr,
					 CPT_AF_CTX_AOP_LATENCY_PC);
	rsp->ctx_ifetch_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_IFETCH_PC);
	rsp->ctx_ifetch_lat_pc = rvu_read64(rvu, blkaddr,
					    CPT_AF_CTX_IFETCH_LATENCY_PC);
	rsp->ctx_ffetch_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_FFETCH_PC);
	rsp->ctx_ffetch_lat_pc = rvu_read64(rvu, blkaddr,
					    CPT_AF_CTX_FFETCH_LATENCY_PC);
	rsp->ctx_wback_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_FFETCH_PC);
	rsp->ctx_wback_lat_pc = rvu_read64(rvu, blkaddr,
					   CPT_AF_CTX_FFETCH_LATENCY_PC);
	rsp->ctx_psh_pc = rvu_read64(rvu, blkaddr, CPT_AF_CTX_FFETCH_PC);
	rsp->ctx_psh_lat_pc = rvu_read64(rvu, blkaddr,
					 CPT_AF_CTX_FFETCH_LATENCY_PC);
	rsp->ctx_err = rvu_read64(rvu, blkaddr, CPT_AF_CTX_ERR);
	rsp->ctx_enc_id = rvu_read64(rvu, blkaddr, CPT_AF_CTX_ENC_ID);
	rsp->ctx_flush_timer = rvu_read64(rvu, blkaddr, CPT_AF_CTX_FLUSH_TIMER);

	rsp->rxc_time = rvu_read64(rvu, blkaddr, CPT_AF_RXC_TIME);
	rsp->rxc_time_cfg = rvu_read64(rvu, blkaddr, CPT_AF_RXC_TIME_CFG);
	rsp->rxc_active_sts = rvu_read64(rvu, blkaddr, CPT_AF_RXC_ACTIVE_STS);
	rsp->rxc_zombie_sts = rvu_read64(rvu, blkaddr, CPT_AF_RXC_ZOMBIE_STS);
	rsp->rxc_dfrg = rvu_read64(rvu, blkaddr, CPT_AF_RXC_DFRG);
	rsp->x2p_link_cfg0 = rvu_read64(rvu, blkaddr, CPT_AF_X2PX_LINK_CFG(0));
	rsp->x2p_link_cfg1 = rvu_read64(rvu, blkaddr, CPT_AF_X2PX_LINK_CFG(1));
}

static void get_eng_sts(struct rvu *rvu, struct cpt_sts_rsp *rsp, int blkaddr)
{
	u16 max_ses, max_ies, max_aes;
	u32 e_min = 0, e_max = 0;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, CPT_AF_CONSTANTS1);
	max_ses = reg & 0xffff;
	max_ies = (reg >> 16) & 0xffff;
	max_aes = (reg >> 32) & 0xffff;

	/* Get AE status */
	e_min = max_ses + max_ies;
	e_max = max_ses + max_ies + max_aes;
	cpt_get_eng_sts(e_min, e_max, rsp, ae);
	/* Get SE status */
	e_min = 0;
	e_max = max_ses;
	cpt_get_eng_sts(e_min, e_max, rsp, se);
	/* Get IE status */
	e_min = max_ses;
	e_max = max_ses + max_ies;
	cpt_get_eng_sts(e_min, e_max, rsp, ie);
}

int rvu_mbox_handler_cpt_sts(struct rvu *rvu, struct cpt_sts_req *req,
			     struct cpt_sts_rsp *rsp)
{
	int blkaddr;

	blkaddr = req->blkaddr ? req->blkaddr : BLKADDR_CPT0;
	if (!is_cpt_blkaddr(blkaddr))
		return -EINVAL;

	/* This message is accepted only if sent from CPT PF/VF */
	if (!is_cpt_pf(req->hdr.pcifunc) &&
	    !is_cpt_vf(req->hdr.pcifunc))
		return CPT_AF_ERR_ACCESS_DENIED;

	if (!is_rvu_otx2(rvu))
		get_ctx_pc(rvu, rsp, blkaddr);

	/* Get CPT engines status */
	get_eng_sts(rvu, rsp, blkaddr);

	/* Read CPT instruction PC registers */
	rsp->inst_req_pc = rvu_read64(rvu, blkaddr, CPT_AF_INST_REQ_PC);
	rsp->inst_lat_pc = rvu_read64(rvu, blkaddr, CPT_AF_INST_LATENCY_PC);
	rsp->rd_req_pc = rvu_read64(rvu, blkaddr, CPT_AF_RD_REQ_PC);
	rsp->rd_lat_pc = rvu_read64(rvu, blkaddr, CPT_AF_RD_LATENCY_PC);
	rsp->rd_uc_pc = rvu_read64(rvu, blkaddr, CPT_AF_RD_UC_PC);
	rsp->active_cycles_pc = rvu_read64(rvu, blkaddr,
					   CPT_AF_ACTIVE_CYCLES_PC);
	rsp->exe_err_info = rvu_read64(rvu, blkaddr, CPT_AF_EXE_ERR_INFO);
	rsp->cptclk_cnt = rvu_read64(rvu, blkaddr, CPT_AF_CPTCLK_CNT);
	rsp->diag = rvu_read64(rvu, blkaddr, CPT_AF_DIAG);

	return 0;
}

#define RXC_ZOMBIE_THRES  GENMASK_ULL(59, 48)
#define RXC_ZOMBIE_LIMIT  GENMASK_ULL(43, 32)
#define RXC_ACTIVE_THRES  GENMASK_ULL(27, 16)
#define RXC_ACTIVE_LIMIT  GENMASK_ULL(11, 0)
#define RXC_ACTIVE_COUNT  GENMASK_ULL(60, 48)
#define RXC_ZOMBIE_COUNT  GENMASK_ULL(60, 48)

static void cpt_rxc_time_cfg(struct rvu *rvu, struct cpt_rxc_time_cfg_req *req,
			     int blkaddr, struct cpt_rxc_time_cfg_req *save)
{
	u64 dfrg_reg;

	if (save) {
		/* Save older config */
		dfrg_reg = rvu_read64(rvu, blkaddr, CPT_AF_RXC_DFRG);
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
	rvu_write64(rvu, blkaddr, CPT_AF_RXC_DFRG, dfrg_reg);
}

int rvu_mbox_handler_cpt_rxc_time_cfg(struct rvu *rvu,
				      struct cpt_rxc_time_cfg_req *req,
				      struct msg_rsp *rsp)
{
	int blkaddr;

	blkaddr = req->blkaddr ? req->blkaddr : BLKADDR_CPT0;
	if (!is_cpt_blkaddr(blkaddr))
		return -EINVAL;

	/* This message is accepted only if sent from CPT PF/VF */
	if (!is_cpt_pf(req->hdr.pcifunc) &&
	    !is_cpt_vf(req->hdr.pcifunc))
		return CPT_AF_ERR_ACCESS_DENIED;

	cpt_rxc_time_cfg(rvu, req, blkaddr, NULL);

	return 0;
}

int rvu_mbox_handler_cpt_ctx_cache_sync(struct rvu *rvu, struct msg_req *req,
					struct msg_rsp *rsp)
{
	return rvu_cpt_ctx_flush(rvu, req->hdr.pcifunc);
}

static void cpt_rxc_teardown(struct rvu *rvu, int blkaddr)
{
	struct cpt_rxc_time_cfg_req req, prev;
	int timeout = 2000;
	u64 reg;

	if (is_rvu_otx2(rvu))
		return;

	/* Set time limit to minimum values, so that rxc entries will be
	 * flushed out quickly.
	 */
	req.step = 1;
	req.zombie_thres = 1;
	req.zombie_limit = 1;
	req.active_thres = 1;
	req.active_limit = 1;

	cpt_rxc_time_cfg(rvu, &req, blkaddr, &prev);

	do {
		reg = rvu_read64(rvu, blkaddr, CPT_AF_RXC_ACTIVE_STS);
		udelay(1);
		if (FIELD_GET(RXC_ACTIVE_COUNT, reg))
			timeout--;
		else
			break;
	} while (timeout);

	if (timeout == 0)
		dev_warn(rvu->dev, "Poll for RXC active count hits hard loop counter\n");

	timeout = 2000;
	do {
		reg = rvu_read64(rvu, blkaddr, CPT_AF_RXC_ZOMBIE_STS);
		udelay(1);
		if (FIELD_GET(RXC_ZOMBIE_COUNT, reg))
			timeout--;
		else
			break;
	} while (timeout);

	if (timeout == 0)
		dev_warn(rvu->dev, "Poll for RXC zombie count hits hard loop counter\n");

	/* Restore config */
	cpt_rxc_time_cfg(rvu, &prev, blkaddr, NULL);
}

static void cpt_lf_disable_iqueue(struct rvu *rvu, int blkaddr, int slot)
{
	u64 inprog, grp_ptr;
	int i = 0;

	/* Disable instructions enqueuing */
	rvu_write64(rvu, blkaddr, CPT_AF_BAR2_ALIASX(slot, CPT_LF_CTL), 0x0);

	/* Disable executions in the LF's queue */
	inprog = rvu_read64(rvu, blkaddr,
			    CPT_AF_BAR2_ALIASX(slot, CPT_LF_INPROG));
	inprog &= ~BIT_ULL(16);
	rvu_write64(rvu, blkaddr,
		    CPT_AF_BAR2_ALIASX(slot, CPT_LF_INPROG), inprog);

	/* Wait for CPT queue to become execution-quiescent */
	do {
		inprog = rvu_read64(rvu, blkaddr,
				    CPT_AF_BAR2_ALIASX(slot, CPT_LF_INPROG));
		/* Check for partial entries (GRB_PARTIAL) */
		if (inprog & BIT_ULL(31))
			i = 0;
		else
			i++;

		grp_ptr = rvu_read64(rvu, blkaddr,
				     CPT_AF_BAR2_ALIASX(slot,
							CPT_LF_Q_GRP_PTR));
	} while ((i < 10) && (((grp_ptr >> 32) & 0x7FFF) !=
				(grp_ptr & 0x7FFF)));

	i = 0;
	do {
		inprog = rvu_read64(rvu, blkaddr,
				    CPT_AF_BAR2_ALIASX(slot, CPT_LF_INPROG));
		/* GWB writes groups of 40. So below formula is used for
		 * knowing that no more instructions will be scheduled
		 * (INFLIGHT == 0) && (GWB < 40) && (GRB == 0 OR 40)
		 */
		if (((inprog & 0x1FF) == 0) &&
		    (((inprog >> 40) & 0xFF) < 40) &&
		    ((((inprog >> 32) & 0xFF) == 0) ||
		    (((inprog >> 32) & 0xFF) == 40)))
			i++;
		else
			i = 0;
	} while (i < 10);
}

int rvu_cpt_lf_teardown(struct rvu *rvu, u16 pcifunc, int blkaddr, int lf, int slot)
{
	u64 reg;

	if (is_cpt_pf(pcifunc) || is_cpt_vf(pcifunc))
		cpt_rxc_teardown(rvu, blkaddr);

	/* Enable BAR2 ALIAS for this pcifunc. */
	reg = BIT_ULL(16) | pcifunc;
	rvu_write64(rvu, blkaddr, CPT_AF_BAR2_SEL, reg);

	cpt_lf_disable_iqueue(rvu, blkaddr, slot);

	/* Set group drop to help clear out hardware */
	reg = rvu_read64(rvu, blkaddr, CPT_AF_BAR2_ALIASX(slot, CPT_LF_INPROG));
	reg |= BIT_ULL(17);
	rvu_write64(rvu, blkaddr, CPT_AF_BAR2_ALIASX(slot, CPT_LF_INPROG), reg);

	rvu_write64(rvu, blkaddr, CPT_AF_BAR2_SEL, 0);

	return 0;
}

#define CPT_RES_LEN    16
#define CPT_SE_IE_EGRP 1ULL

static int cpt_inline_inb_lf_cmd_send(struct rvu *rvu, int blkaddr,
				      int nix_blkaddr)
{
	struct cpt_inst_lmtst_req *req;
	dma_addr_t res_daddr;
	int timeout = 3000;
	u8 cpt_idx;
	u64 *inst;
	u16 *res;
	int rc;

	res = kzalloc(CPT_RES_LEN, GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	res_daddr = dma_map_single(rvu->dev, res, CPT_RES_LEN,
				   DMA_BIDIRECTIONAL);
	if (dma_mapping_error(rvu->dev, res_daddr)) {
		dev_err(rvu->dev, "DMA mapping failed for CPT result\n");
		rc = -EFAULT;
		goto res_free;
	}
	*res = 0xFFFF;

	/* Send mbox message to CPT PF */
	req = (struct cpt_inst_lmtst_req *)
	       otx2_mbox_alloc_msg_rsp(&rvu->afpf_wq_info.mbox_up,
				       cpt_pf_num, sizeof(*req),
				       sizeof(struct msg_rsp));
	if (!req) {
		rc = -ENOMEM;
		goto res_daddr_unmap;
	}
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.id = MBOX_MSG_CPT_INST_LMTST;

	inst = req->inst;
	/* Prepare CPT_INST_S */
	inst[0] = 0;
	inst[1] = res_daddr;
	/* AF PF FUNC */
	inst[2] = 0;
	/* Set QORD */
	inst[3] = 1;
	inst[4] = 0;
	inst[5] = 0;
	inst[6] = 0;
	/* Set EGRP */
	inst[7] = CPT_SE_IE_EGRP << 61;

	/* Subtract 1 from the NIX-CPT credit count to preserve
	 * credit counts.
	 */
	cpt_idx = (blkaddr == BLKADDR_CPT0) ? 0 : 1;
	rvu_write64(rvu, nix_blkaddr, NIX_AF_RX_CPTX_CREDIT(cpt_idx),
		    BIT_ULL(22) - 1);

	otx2_mbox_msg_send(&rvu->afpf_wq_info.mbox_up, cpt_pf_num);
	rc = otx2_mbox_wait_for_rsp(&rvu->afpf_wq_info.mbox_up, cpt_pf_num);
	if (rc)
		dev_warn(rvu->dev, "notification to pf %d failed\n",
			 cpt_pf_num);
	/* Wait for CPT instruction to be completed */
	do {
		mdelay(1);
		if (*res == 0xFFFF)
			timeout--;
		else
			break;
	} while (timeout);

	if (timeout == 0)
		dev_warn(rvu->dev, "Poll for result hits hard loop counter\n");

res_daddr_unmap:
	dma_unmap_single(rvu->dev, res_daddr, CPT_RES_LEN, DMA_BIDIRECTIONAL);
res_free:
	kfree(res);

	return 0;
}

#define CTX_CAM_PF_FUNC   GENMASK_ULL(61, 46)
#define CTX_CAM_CPTR      GENMASK_ULL(45, 0)

int rvu_cpt_ctx_flush(struct rvu *rvu, u16 pcifunc)
{
	int nix_blkaddr, blkaddr;
	u16 max_ctx_entries, i;
	int slot = 0, num_lfs;
	u64 reg, cam_data;
	int rc;

	nix_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	if (nix_blkaddr < 0)
		return -EINVAL;

	if (is_rvu_otx2(rvu))
		return 0;

	blkaddr = (nix_blkaddr == BLKADDR_NIX1) ? BLKADDR_CPT1 : BLKADDR_CPT0;

	/* Submit CPT_INST_S to track when all packets have been
	 * flushed through for the NIX PF FUNC in inline inbound case.
	 */
	rc = cpt_inline_inb_lf_cmd_send(rvu, blkaddr, nix_blkaddr);
	if (rc)
		return rc;

	/* Wait for rxc entries to be flushed out */
	cpt_rxc_teardown(rvu, blkaddr);

	reg = rvu_read64(rvu, blkaddr, CPT_AF_CONSTANTS0);
	max_ctx_entries = (reg >> 48) & 0xFFF;

	mutex_lock(&rvu->rsrc_lock);

	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, pcifunc),
					blkaddr);
	if (num_lfs == 0) {
		dev_warn(rvu->dev, "CPT LF is not configured\n");
		goto unlock;
	}

	/* Enable BAR2 ALIAS for this pcifunc. */
	reg = BIT_ULL(16) | pcifunc;
	rvu_write64(rvu, blkaddr, CPT_AF_BAR2_SEL, reg);

	for (i = 0; i < max_ctx_entries; i++) {
		cam_data = rvu_read64(rvu, blkaddr, CPT_AF_CTX_CAM_DATA(i));

		if ((FIELD_GET(CTX_CAM_PF_FUNC, cam_data) == pcifunc) &&
		    FIELD_GET(CTX_CAM_CPTR, cam_data)) {
			reg = BIT_ULL(46) | FIELD_GET(CTX_CAM_CPTR, cam_data);
			rvu_write64(rvu, blkaddr,
				    CPT_AF_BAR2_ALIASX(slot, CPT_LF_CTX_FLUSH),
				    reg);
		}
	}
	rvu_write64(rvu, blkaddr, CPT_AF_BAR2_SEL, 0);

unlock:
	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}
