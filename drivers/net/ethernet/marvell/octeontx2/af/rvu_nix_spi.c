// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include "rvu.h"

static bool nix_spi_to_sa_index_check_duplicate(struct rvu *rvu,
						struct nix_spi_to_sa_add_req *req,
						struct nix_spi_to_sa_add_rsp *rsp,
						int blkaddr, int16_t index, u8 way,
						bool *is_valid, int lfidx)
{
	u32 spi_index;
	u16 match_id;
	bool valid;
	u8 lfid;
	u64 wkey;

	wkey = rvu_read64(rvu, blkaddr, NIX_AF_SPI_TO_SA_KEYX_WAYX(index, way));
	spi_index = (wkey & 0xFFFFFFFF);
	match_id = ((wkey >> 32) & 0xFFFF);
	lfid = ((wkey >> 48) & 0x7f);
	valid = ((wkey >> 55) & 0x1);

	*is_valid = valid;
	if (!valid)
		return 0;

	if (req->spi_index == spi_index && req->match_id == match_id &&
	    lfidx == lfid) {
		rsp->hash_index = index;
		rsp->way = way;
		rsp->is_duplicate = true;
		return 1;
	}
	return 0;
}

static void  nix_spi_to_sa_index_table_update(struct rvu *rvu,
					      struct nix_spi_to_sa_add_req *req,
					      struct nix_spi_to_sa_add_rsp *rsp,
					      int blkaddr, int16_t index, u8 way,
					      int lfidx)
{
	u64 wvalue;
	u64 wkey;

	wkey = (req->spi_index | ((u64)req->match_id << 32) |
		(((u64)lfidx) << 48) | ((u64)req->valid << 55));
	rvu_write64(rvu, blkaddr, NIX_AF_SPI_TO_SA_KEYX_WAYX(index, way),
		    wkey);
	wvalue = (req->sa_index & 0xFFFFFFFF);
	rvu_write64(rvu, blkaddr, NIX_AF_SPI_TO_SA_VALUEX_WAYX(index, way),
		    wvalue);
	rsp->hash_index = index;
	rsp->way = way;
	rsp->is_duplicate = false;
}

int rvu_mbox_handler_nix_spi_to_sa_delete(struct rvu *rvu,
					  struct nix_spi_to_sa_delete_req *req,
					  struct msg_rsp *rsp)
{
	struct rvu_pfvf *pfvf, *parent_pf;
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	int lfidx, lfid;
	int blkaddr;
	u64 wvalue;
	u64 wkey;
	int ret = 0;

	if (!hw->cap.spi_to_sas)
		return NIX_AF_ERR_PARAM;

	if (!is_nixlf_attached(rvu, pcifunc)) {
		ret = NIX_AF_ERR_AF_LF_INVALID;
		goto exit;
	}

	parent_pf = &rvu->pf[rvu_get_pf(pcifunc)];
	pfvf = rvu_get_pfvf(rvu, pcifunc);
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	lfidx = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, 0);
	if (lfidx < 0) {
		ret = NIX_AF_ERR_AF_LF_INVALID;
		goto exit;
	}

	mutex_lock(&rvu->rsrc_lock);

	wkey = rvu_read64(rvu, blkaddr,
			  NIX_AF_SPI_TO_SA_KEYX_WAYX(req->hash_index,
						     req->way));
	lfid = ((wkey >> 48) & 0x7f);
	if (lfid != lfidx) {
		ret = NIX_AF_ERR_AF_LF_INVALID;
		goto unlock;
	}

	wkey = 0;
	rvu_write64(rvu, blkaddr,
		    NIX_AF_SPI_TO_SA_KEYX_WAYX(req->hash_index, req->way),
		    wkey);
	wvalue = 0;
	rvu_write64(rvu, blkaddr,
		    NIX_AF_SPI_TO_SA_VALUEX_WAYX(req->hash_index, req->way),
		    wvalue);
unlock:
	mutex_unlock(&rvu->rsrc_lock);
exit:
	return ret;
}

int rvu_mbox_handler_nix_spi_to_sa_add(struct rvu *rvu,
				       struct nix_spi_to_sa_add_req *req,
				       struct nix_spi_to_sa_add_rsp *rsp)
{
	u16 way0_index, way1_index, way2_index, way3_index;
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc = req->hdr.pcifunc;
	bool way0, way1, way2, way3;
	int ret = 0;
	int blkaddr;
	int lfidx;
	u64 value;
	u64 key;

	if (!hw->cap.spi_to_sas)
		return NIX_AF_ERR_PARAM;

	if (!is_nixlf_attached(rvu, pcifunc)) {
		ret = NIX_AF_ERR_AF_LF_INVALID;
		goto exit;
	}

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	lfidx = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, 0);
	if (lfidx < 0) {
		ret = NIX_AF_ERR_AF_LF_INVALID;
		goto exit;
	}

	mutex_lock(&rvu->rsrc_lock);

	key = (((u64)lfidx << 48) | ((u64)req->match_id << 32) | req->spi_index);
	rvu_write64(rvu, blkaddr, NIX_AF_SPI_TO_SA_HASH_KEY, key);
	value = rvu_read64(rvu, blkaddr, NIX_AF_SPI_TO_SA_HASH_VALUE);
	way0_index = (value & 0x7ff);
	way1_index = ((value >> 16) & 0x7ff);
	way2_index = ((value >> 32) & 0x7ff);
	way3_index = ((value >> 48) & 0x7ff);

	/* Check for duplicate entry */
	if (nix_spi_to_sa_index_check_duplicate(rvu, req, rsp, blkaddr,
						way0_index, 0, &way0, lfidx) ||
	    nix_spi_to_sa_index_check_duplicate(rvu, req, rsp, blkaddr,
						way1_index, 1, &way1, lfidx) ||
	    nix_spi_to_sa_index_check_duplicate(rvu, req, rsp, blkaddr,
						way2_index, 2, &way2, lfidx) ||
	    nix_spi_to_sa_index_check_duplicate(rvu, req, rsp, blkaddr,
						way3_index, 3, &way3, lfidx)) {
		ret = 0;
		goto unlock;
	}

	/* If not present, update first available way with index */
	if (!way0)
		nix_spi_to_sa_index_table_update(rvu, req, rsp, blkaddr,
						 way0_index, 0, lfidx);
	else if (!way1)
		nix_spi_to_sa_index_table_update(rvu, req, rsp, blkaddr,
						 way1_index, 1, lfidx);
	else if (!way2)
		nix_spi_to_sa_index_table_update(rvu, req, rsp, blkaddr,
						 way2_index, 2, lfidx);
	else if (!way3)
		nix_spi_to_sa_index_table_update(rvu, req, rsp, blkaddr,
						 way3_index, 3, lfidx);
unlock:
	mutex_unlock(&rvu->rsrc_lock);
exit:
	return ret;
}

int rvu_nix_free_spi_to_sa_table(struct rvu *rvu, uint16_t pcifunc)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int index, way;
	int lfidx, lfid;
	int blkaddr;
	u64  value;
	u64 key;

	if (!hw->cap.spi_to_sas)
		return 0;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, pcifunc);
	lfidx = rvu_get_lf(rvu, &hw->block[blkaddr], pcifunc, 0);
	if (lfidx < 0)
		return NIX_AF_ERR_AF_LF_INVALID;

	mutex_lock(&rvu->rsrc_lock);
	for (index = 0; index < hw->cap.spi_to_sas / 4; index++) {
		for (way = 0; way < 4; way++) {
			key = rvu_read64(rvu, blkaddr,
					 NIX_AF_SPI_TO_SA_KEYX_WAYX(index,
								    way));
			lfid = ((key >> 48) & 0x7f);
			if (lfid == lfidx) {
				key = 0;
				rvu_write64(rvu, blkaddr,
					    NIX_AF_SPI_TO_SA_KEYX_WAYX(index,
								       way),
					    key);
				value = 0;
				rvu_write64(rvu, blkaddr,
					    NIX_AF_SPI_TO_SA_VALUEX_WAYX(index,
									 way),
					    value);
			}
		}
	}
	mutex_unlock(&rvu->rsrc_lock);

	return 0;
}
