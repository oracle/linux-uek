// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "cn20k/api.h"
#include "struct.h"
#include "../rvu.h"

int rvu_mbox_handler_npa_cn20k_aq_enq(struct rvu *rvu,
				      struct npa_cn20k_aq_enq_req *req,
				      struct npa_cn20k_aq_enq_rsp *rsp)
{
	return rvu_npa_aq_enq_inst(rvu, (struct npa_aq_enq_req *)req,
				   (struct npa_aq_enq_rsp *)rsp);
}
EXPORT_SYMBOL(rvu_mbox_handler_npa_cn20k_aq_enq);

int rvu_npa_halo_hwctx_disable(struct npa_aq_enq_req *req)
{
	struct npa_cn20k_aq_enq_req *hreq;

	hreq = (struct npa_cn20k_aq_enq_req *)req;

	hreq->halo.bp_ena_0 = 0;
	hreq->halo.bp_ena_1 = 0;
	hreq->halo.bp_ena_2 = 0;
	hreq->halo.bp_ena_3 = 0;
	hreq->halo.bp_ena_4 = 0;
	hreq->halo.bp_ena_5 = 0;
	hreq->halo.bp_ena_6 = 0;
	hreq->halo.bp_ena_7 = 0;

	hreq->halo_mask.bp_ena_0 = 1;
	hreq->halo_mask.bp_ena_1 = 1;
	hreq->halo_mask.bp_ena_2 = 1;
	hreq->halo_mask.bp_ena_3 = 1;
	hreq->halo_mask.bp_ena_4 = 1;
	hreq->halo_mask.bp_ena_5 = 1;
	hreq->halo_mask.bp_ena_6 = 1;
	hreq->halo_mask.bp_ena_7 = 1;

	return 0;
}

int npa_cn20k_dpc_alloc(struct rvu *rvu, struct npa_cn20k_dpc_alloc_req *req,
			struct npa_cn20k_dpc_alloc_rsp *rsp)

{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int i, lf, blkaddr, ridx;
	struct rvu_block *block;
	struct rvu_pfvf *pfvf;
	u64 val, lfmask;

	pfvf = rvu_get_pfvf(rvu, pcifunc);

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPA, 0);
	if (!pfvf->npalf || blkaddr < 0)
		return NPA_AF_ERR_AF_LF_INVALID;

	block = &hw->block[blkaddr];
	lf = rvu_get_lf(rvu, block, pcifunc, 0);
	if (lf < 0)
		return NPA_AF_ERR_AF_LF_INVALID;

	/* allocate a new counter */
	i = rvu_alloc_rsrc(&rvu->npa_dpc);
	if (i < 0)
		return i;
	rsp->cntr_id = i;

	/* DPC counter config */
	rvu_write64(rvu, blkaddr, NPA_AF_DPCX_CFG(i), req->dpc_conf);

	ridx = lf % 32; /* 0 to 31 lfs -> idx 0, 32 - 63 lfs -> idx 1 */
	lfmask = BIT_ULL(ridx ? lf - 32 : lf);

	/* Map LF to this counter */
	val = rvu_read64(rvu, blkaddr, NPA_AF_DPCX_LF_ENAX(i, ridx));
	val |= lfmask;
	rvu_write64(rvu, blkaddr, NPA_AF_DPCX_LF_ENAX(i, ridx), val);

	/* Give permission for LF access */
	val = rvu_read64(rvu, blkaddr, NPA_AF_DPC_PERMITX(i, ridx));
	val |= lfmask;
	rvu_write64(rvu, blkaddr, NPA_AF_DPC_PERMITX(i, ridx), val);

	return 0;
}

int rvu_mbox_handler_npa_cn20k_dpc_alloc(struct rvu *rvu,
					 struct npa_cn20k_dpc_alloc_req *req,
					 struct npa_cn20k_dpc_alloc_rsp *rsp)
{
	return npa_cn20k_dpc_alloc(rvu, req, rsp);
}

int npa_cn20k_dpc_free(struct rvu *rvu, struct npa_cn20k_dpc_free_req *req)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int cntr, lf, blkaddr, ridx;
	struct rvu_block *block;
	struct rvu_pfvf *pfvf;
	u64 val, lfmask;

	pfvf = rvu_get_pfvf(rvu, pcifunc);

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPA, 0);
	if (!pfvf->npalf || blkaddr < 0)
		return NPA_AF_ERR_AF_LF_INVALID;

	block = &hw->block[blkaddr];
	lf = rvu_get_lf(rvu, block, pcifunc, 0);
	if (lf < 0)
		return NPA_AF_ERR_AF_LF_INVALID;

	ridx = lf % NPA_DPC_LFS_PER_REG; /* LFs 0 to 63 -> 0, 64 to 127 -> 1 */
	lfmask = BIT_ULL(ridx ? lf - NPA_DPC_LFS_PER_REG : lf);
	cntr = req->cntr_id;

	/* Unmap LF for this counter */
	val = rvu_read64(rvu, blkaddr, NPA_AF_DPCX_LF_ENAX(cntr, ridx));
	if (!(val & lfmask)) /* Verify if this LF really owns this */
		return NPA_AF_ERR_AF_LF_INVALID;
	val &= ~lfmask;
	rvu_write64(rvu, blkaddr, NPA_AF_DPCX_LF_ENAX(cntr, ridx), val);

	/* Revert permission */
	val = rvu_read64(rvu, blkaddr, NPA_AF_DPC_PERMITX(cntr, ridx));
	val &= ~lfmask;
	rvu_write64(rvu, blkaddr, NPA_AF_DPC_PERMITX(cntr, ridx), val);

	/* Free this counter */
	rvu_free_rsrc(&rvu->npa_dpc, req->cntr_id);

	return 0;
}

void npa_cn20k_dpc_free_all(struct rvu *rvu, u16 pcifunc)
{
	struct npa_cn20k_dpc_free_req req;
	int i;

	req.hdr.pcifunc = pcifunc;
	for (i = 0; i < NPA_DPC_MAX; i++) {
		req.cntr_id = i;
		npa_cn20k_dpc_free(rvu, &req);
	}
}

int rvu_mbox_handler_npa_cn20k_dpc_free(struct rvu *rvu,
					struct npa_cn20k_dpc_free_req *req,
					struct msg_rsp *rsp)
{
	return npa_cn20k_dpc_free(rvu, req);
}
