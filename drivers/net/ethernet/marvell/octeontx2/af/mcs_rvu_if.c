// SPDX-License-Identifier: GPL-2.0
/* Marvell CN10K MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "mcs.h"
#include "rvu.h"

int rvu_mbox_handler_mcs_free_resources(struct rvu *rvu,
					struct mcs_free_rsrc_req *req,
					struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct mcs_rsrc_map *map;
	struct mcs *mcs;
	int rc;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return -EINVAL;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX)
		map = &mcs->rx;
	else
		map = &mcs->tx;

	mutex_lock(&rvu->rsrc_lock);
	/* Free all the cam resources mapped to PF/VF */
	if (req->all) {
		rc = mcs_free_all_rsrc(mcs, req->dir, pcifunc);
		goto exit;
	}

	switch (req->rsrc_type) {
	case MCS_RSRC_TYPE_FLOWID:
		rc = mcs_free_rsrc(&map->flow_ids, map->flowid2pf_map, req->rsrc_id, pcifunc);
		break;
	case MCS_RSRC_TYPE_SECY:
		rc =  mcs_free_rsrc(&map->secy, map->secy2pf_map, req->rsrc_id, pcifunc);
		break;
	case MCS_RSRC_TYPE_SC:
		rc = mcs_free_rsrc(&map->sc, map->sc2pf_map, req->rsrc_id, pcifunc);
		break;
	case MCS_RSRC_TYPE_SA:
		rc = mcs_free_rsrc(&map->sa, map->sa2pf_map, req->rsrc_id, pcifunc);
		break;
	}
exit:
	mutex_unlock(&rvu->rsrc_lock);
	return rc;
}

int rvu_mbox_handler_mcs_alloc_resources(struct rvu *rvu,
					 struct mcs_alloc_rsrc_req *req,
					 struct mcs_alloc_rsrc_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	struct mcs_rsrc_map *map;
	struct mcs *mcs;
	int rsrc_id, i;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return -EINVAL;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX)
		map = &mcs->rx;
	else
		map = &mcs->tx;

	mutex_lock(&rvu->rsrc_lock);

	if (req->all) {
		rsrc_id = mcs_alloc_all_rsrc(mcs, &rsp->flow_ids[0],
					     &rsp->secy_ids[0],
					     &rsp->sc_ids[0],
					     &rsp->sa_ids[0],
					     pcifunc, req->dir);
		if (rsrc_id < 0)
			goto exit;
	}

	switch (req->rsrc_type) {
	case MCS_RSRC_TYPE_FLOWID:
		for (i = 0; i < req->rsrc_cnt; i++) {
			rsrc_id = mcs_alloc_rsrc(&map->flow_ids, map->flowid2pf_map, pcifunc);
			if (rsrc_id < 0)
				goto exit;
			rsp->flow_ids[i] = rsrc_id;
			rsp->rsrc_cnt++;
		}
		break;
	case MCS_RSRC_TYPE_SECY:
		for (i = 0; i < req->rsrc_cnt; i++) {
			rsrc_id = mcs_alloc_rsrc(&map->secy, map->secy2pf_map, pcifunc);
			if (rsrc_id < 0)
				goto exit;
			rsp->secy_ids[i] = rsrc_id;
			rsp->rsrc_cnt++;
		}
		break;
	case MCS_RSRC_TYPE_SC:
		for (i = 0; i < req->rsrc_cnt; i++) {
			rsrc_id = mcs_alloc_rsrc(&map->sc, map->sc2pf_map, pcifunc);
			if (rsrc_id < 0)
				goto exit;
			rsp->sc_ids[i] = rsrc_id;
			rsp->rsrc_cnt++;
		}
		break;
	case MCS_RSRC_TYPE_SA:
		for (i = 0; i < req->rsrc_cnt; i++) {
			rsrc_id = mcs_alloc_rsrc(&map->sa, map->sa2pf_map, pcifunc);
			if (rsrc_id < 0)
				goto exit;
			rsp->sa_ids[i] = rsrc_id;
			rsp->rsrc_cnt++;
		}
		break;
	}

	rsp->rsrc_type = req->rsrc_type;
	rsp->dir = req->dir;
	rsp->mcs_id = req->mcs_id;
	rsp->all = req->all;

	mutex_unlock(&rvu->rsrc_lock);
	return 0;
exit:
	dev_err(rvu->dev, "Failed to allocate the mcs resources for PCIFUNC:%d\n", pcifunc);
	mutex_unlock(&rvu->rsrc_lock);
	return rsrc_id;
}

int rvu_mcs_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;

	rvu->mcs_blk_cnt = mcs_get_blkcnt();

	if (!rvu->mcs_blk_cnt)
		return 0;

	return mcs_set_lmac_channels(hw->cgx_chan_base);
}
