// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include "rvu.h"
#include "rvu_eblock.h"
#include "rvu_eb_sdp.h"
#include "rvu_trace.h"

#define SDP_R_MAP_VF_MASK		GENMASK_ULL(7, 0)
#define SDP_R_MAP_EPF_MASK		GENMASK_ULL(11, 8)
#define SDP_R_MAP_VRING_MASK		GENMASK_ULL(18, 12)
#define SDP_R_MAP_VLD_MASK		BIT_ULL(19)
#define SDP_R_MAP_VFRSID_MASK		GENMASK_ULL(37, 30)
#define SDP_R_MAP_CHAN_MASK		GENMASK_ULL(46, 38)

#define SDP_MAC_CHAN_MAP_RING_MASK	GENMASK_ULL(9, 1)
#define SDP_MAC_CHAN_MAP_VLD_MASK	BIT_ULL(0)

#define SDP_AF_CONST_RINGS		GENMASK_ULL(31, 16)

#define SDP_EVF_RSRCID_MAX		256

struct sdp_drvdata sdp_data; /*global struct to hold mbox_wqs */
struct sdp_irq_data epf_cookie[SDP_MAX_EPF];

#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct rvu *rvu, int devid)		\
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&rvu->afvf_wq_info.mbox_up, devid, sizeof(struct _req_type), \
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	trace_otx2_msg_alloc(rvu->pdev, _id, sizeof(*req), 0);		\
	return req;							\
}

MBOX_EBLOCK_UP_SDP_MESSAGES
#undef M

/* Given a host pcifunc returns host VF number + 1 */
static u16 get_sdp_evf(u16 host_pcifunc)
{
	return (host_pcifunc & RVU_PFVF_FUNC_MASK);
}

/* Given a host pcifunc returns host PF number */
static u16 get_sdp_epf(u16 host_pcifunc)
{
	return (host_pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;
}

/* Given a host pcifunc returns corresponding RVU pcifunc */
static u16 cn20k_get_rvu_pcifunc(struct rvu *rvu, u16 host_pcifunc)
{
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	u8 host_pf, host_vf, rvu_pf;
	u16 rvu_pcifunc;

	host_vf = host_pcifunc & RVU_PFVF_FUNC_MASK;
	host_pf = (host_pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;

	rvu_pf = sdp->host2rvupf[host_pf];
	/* Form RVU pcifunc */
	rvu_pcifunc = (rvu_pf & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT;
	/* Host PF's IO are handled by first VFs of PF. Hence on RVU side
	 * PFs are only to receive message from AF and forward to VFs.
	 */
	rvu_pcifunc |= (host_vf + 1);

	return rvu_pcifunc;
}

static int cn20k_create_host2rvupf_mapping(struct rvu *rvu, u8 *nr_sdp_pfs)
{
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	struct pci_dev *pdev = NULL;
	u8 sdp_pfs = 0;

	while (true) {
		pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
				      PCI_DEVID_OCTEONTX2_GEN_PF, pdev);
		if (!pdev)
			return 0;

		if (sdp_pfs >= MAX_EPFS) {
			dev_err(rvu->dev, "SDP RVU PFs exceeded MAX EPFs\n");
			pci_dev_put(pdev);
			return -EINVAL;
		}

		/* save Host PFs to RVU PFs mapping */
		sdp->host2rvupf[sdp_pfs] = pdev->bus->number - 1;
		sdp_pfs++;
	}

	if (nr_sdp_pfs)
		*nr_sdp_pfs = sdp_pfs;

	return 0;
}

static void cn20k_sdp_events_task(struct work_struct *work)
{
	struct sdp_config *pf_sdp_cfg, *target_sdp_cfg;
	struct sdp_vf_msg *msg, *tmp;
	struct sdp_rings_cfg *req;
	struct rvu_pfvf *pfvf;
	struct rvu *rvu;
	u64 flags;
	int pfid;
	u16 ring;
	int vf;

	pf_sdp_cfg = container_of(work, struct sdp_config, dwork.work);
	rvu = pf_sdp_cfg->rvu;
	pfid = pf_sdp_cfg->rvu_pf_num;

	mutex_lock(&rvu->mbox_lock);

	list_for_each_entry_safe(msg, tmp, &pf_sdp_cfg->msg_list, list) {
		switch (msg->id) {
		case MBOX_MSG_SDP_RINGS_UPDATE:
			req = otx2_mbox_alloc_msg_sdp_rings_update(rvu, pfid);
			if (!req) {
				dev_err(rvu->dev, "No memory to send %s msg\n",
					otx2_mbox_id2name(msg->id));
				continue;
			}

			/* Set VF bitmap so gen PF driver can fwd to its VFs */
			vf = (msg->target_pcifunc & RVU_PFVF_FUNC_MASK) - 1;
			vf < 64 ? set_bit(vf, &req->vf_bmap1) :
				  set_bit(vf - 64, &req->vf_bmap2);

			flags = msg->flags;
			if (flags & SDP_RING_F_FREE) {
				req->flags = SDP_RING_F_FREE;
				break;
			}

			/* ALLOC RINGS */
			pfvf = rvu_get_pfvf(rvu, msg->target_pcifunc);
			target_sdp_cfg = &pfvf->sdp_cfg;
			req->flags = SDP_RING_F_ALLOC;
			req->nr_rings = target_sdp_cfg->nr_rings;
			for (ring = 0; ring < target_sdp_cfg->nr_rings; ring++)
				req->sq2chan_map[ring] = target_sdp_cfg->channels[ring];
			break;
		default:
			break;
		}

		otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, pfid);
		otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, pfid);

		list_del(&msg->list);
		kfree(msg);
	}

	mutex_unlock(&rvu->mbox_lock);
}

static int cn20k_sdp_send_ring_msg(struct rvu *rvu, u16 target,
				   u16 msg_id, u64 flags)
{
	struct sdp_config *sdp_pf_cfg;
	struct sdp_vf_msg *msg;
	struct rvu_pfvf *pf;

	msg = kzalloc(sizeof(struct sdp_vf_msg), GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	/* Get the PF's pfvf of target to send message since
	 * AF can only send to PFs but not to a PF's VF.
	 */
	pf = rvu_get_pfvf(rvu, target & ~RVU_PFVF_FUNC_MASK);
	sdp_pf_cfg = &pf->sdp_cfg;

	INIT_LIST_HEAD(&msg->list);
	msg->id = msg_id;
	msg->flags = flags;
	msg->target_pcifunc = target;

	list_add_tail(&msg->list, &sdp_pf_cfg->msg_list);

	schedule_delayed_work(&sdp_pf_cfg->dwork, msecs_to_jiffies(50));

	return 0;
}

static int cn20k_sdp_rings_init(struct rvu *rvu)
{
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	struct sdp_config *sdp_cfg;
	struct rvu_pfvf *pfvf;
	int ring, err, pf;
	u16 rvu_pcifunc;
	u16 max_rings;
	int vf_rid;
	u8 sdp_pfs;
	u64 cfg;

	if (!is_cn20k(rvu->pdev))
		return 0;

	err = cn20k_create_host2rvupf_mapping(rvu, &sdp_pfs);
	if (err)
		return err;

	sdp->vf_rsrc_map = kcalloc(SDP_EVF_RSRCID_MAX, sizeof(u16), GFP_KERNEL);
	if (!sdp->vf_rsrc_map)
		return  -ENOMEM;

	cfg = rvu_read64(rvu, BLKADDR_SDP, SDP_AF_CONST);
	max_rings = FIELD_GET(SDP_AF_CONST_RINGS, cfg);

	sdp->fn_map = kcalloc(max_rings, sizeof(u16), GFP_KERNEL);
	if (!sdp->fn_map) {
		err =  -ENOMEM;
		goto free_vf_rsrc_map;
	}


	mutex_init(&sdp->cfg_lock);

	sdp->rings.max = max_rings;
	err = rvu_alloc_bitmap(&sdp->rings);
	if (err)
		goto free_fn_map;

	sdp->vf_rids.max = SDP_EVF_RSRCID_MAX;
	err = rvu_alloc_bitmap(&sdp->vf_rids);
	if (err)
		goto free_rings_bmap;

	for (vf_rid = 0; vf_rid < sdp->vf_rids.max; vf_rid++)
		sdp->vf_rsrc_map[vf_rid] = 0xFFFF;

	for (ring = 0; ring < sdp->rings.max; ring++)
		sdp->fn_map[ring] = 0xFFFF;

	for (pf = 0; pf < sdp_pfs; pf++) {
		rvu_pcifunc = (sdp->host2rvupf[pf] & RVU_PFVF_PF_MASK) <<
			      RVU_PFVF_PF_SHIFT;
		pfvf = rvu_get_pfvf(rvu, rvu_pcifunc);
		sdp_cfg = &pfvf->sdp_cfg;

		INIT_DELAYED_WORK(&sdp_cfg->dwork, cn20k_sdp_events_task);
		INIT_LIST_HEAD(&sdp_cfg->msg_list);
		sdp_cfg->rvu = rvu;
		sdp_cfg->rvu_pf_num = sdp->host2rvupf[pf];
	}

	return 0;

free_rings_bmap:
	rvu_free_bitmap(&sdp->rings);
free_fn_map:
	kfree(sdp->fn_map);
free_vf_rsrc_map:
	kfree(sdp->vf_rsrc_map);
	return err;
}

static int cn20k_sdp_mcam_alloc(struct rvu *rvu, u16 pcifunc,
				u16 channel, int *rx_entry)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, pcifunc);
	struct npc_mcam_alloc_entry_req entry_req = { 0 };
	struct npc_mcam_alloc_entry_rsp entry_rsp = { 0 };
	struct npc_mcam_free_entry_req free_req = { 0 };
	struct npc_install_flow_req req = { 0 };
	struct npc_install_flow_rsp rsp = { 0 };
	struct msg_rsp free_rsp = { 0 };
	int rc;

	/* Try to allocate a MCAM entry */
	entry_req.hdr.pcifunc = 0;
	entry_req.count = 1;
	entry_req.kw_type = NPC_MCAM_KEY_X2;

	rc = rvu_mbox_handler_npc_mcam_alloc_entry(rvu,
						   &entry_req, &entry_rsp);
	if (rc)
		return rc;

	if (entry_rsp.count != entry_req.count)
		return NPC_MCAM_ALLOC_FAILED;

	/* TODO: Ensure valid NIXLF and NPALF are attached */
	req.hdr.pcifunc = 0; /* AF is requester */
	req.vf = pcifunc;
	req.channel = channel;
	req.chan_mask = 0xFFFUL;
	req.intf = pfvf->nix_rx_intf;
	req.op = NIX_RX_ACTION_DEFAULT;
	req.entry = entry_rsp.entry_list[0];
	req.set_cntr = 1;

	rc = rvu_mbox_handler_npc_install_flow(rvu, &req, &rsp);
	if (rc)
		goto free_entries;

	if (rx_entry)
		*rx_entry = entry_rsp.entry_list[0];

	return 0;

free_entries:
	free_req.entry = entry_rsp.entry_list[0];
	rvu_mbox_handler_npc_mcam_free_entry(rvu, &free_req, &free_rsp);

	return rc;
}

static int cn20k_sdp_get_vfrid(struct rvu *rvu, u16 host_pcifunc)
{
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	int rid;

	/* Allocate a new VF_RSRC_ID */
	rid = rvu_alloc_rsrc(&sdp->vf_rids);
	if (rid >= 0)
		sdp->vf_rsrc_map[rid] = host_pcifunc;

	return rid;
}

int rvu_mbox_handler_sdp_rings_alloc(struct rvu *rvu,
				     struct sdp_rings_alloc_req *req,
				     struct sdp_rings_alloc_rsp *rsp)
{
	u16 rvu_pcifunc = cn20k_get_rvu_pcifunc(rvu, req->hdr.pcifunc);
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, rvu_pcifunc);
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	u16 host_pcifunc = req->hdr.pcifunc;
	int qcount = num_online_cpus();
	struct sdp_config *sdp_cfg;
	int ring, rx_entry, slot;
	int vf_rid, err;
	u16 host_vf;
	u64 cfg;

	host_vf = get_sdp_evf(host_pcifunc);
	sdp_cfg = &pfvf->sdp_cfg;

	if (!req->nr_rings)
		return 0;

	if (req->nr_rings > qcount) {
		dev_err(rvu->dev,
			"Could not allocate queues more than active cpus(%d)",
			qcount);
		return -EINVAL;
	}

	if (sdp_cfg->nr_rings) {
		dev_err(rvu->dev,
			"Rings already allocated, free existing rings and try");
		return -EINVAL;
	}

	mutex_lock(&sdp->cfg_lock);

	/* In case of host VF get VF resource id of it */
	if (host_vf) {
		vf_rid = cn20k_sdp_get_vfrid(rvu, host_pcifunc);
		if (vf_rid < 0) {
			dev_err(rvu->dev, "VF resource id allocation failed\n");
			mutex_unlock(&sdp->cfg_lock);
			return vf_rid;
		}
	}

	for (slot = 0; slot < req->nr_rings; slot++) {
		ring = rvu_alloc_rsrc(&sdp->rings);
		if (ring < 0)
			/* Unable to allocate all the rings requested */
			break;

		err = cn20k_sdp_mcam_alloc(rvu, rvu_pcifunc,
					   pfvf->rx_chan_base + ring, &rx_entry);
		if (err) {
			/* Unable to allocate mcam entry for ring */
			dev_err(rvu->dev,
				"%d Allocating mcam entries for ring %d failed\n",
				err, slot);
			rvu_free_rsrc(&sdp->rings, ring);
			break;
		}

		sdp_cfg->mcam_rx_entries[slot] = rx_entry;

		cfg = FIELD_PREP(SDP_R_MAP_VF_MASK, get_sdp_evf(host_pcifunc));
		cfg |= FIELD_PREP(SDP_R_MAP_EPF_MASK, get_sdp_epf(host_pcifunc));
		cfg |= FIELD_PREP(SDP_R_MAP_VRING_MASK, slot);
		/* Use hardware ring number as channel number */
		cfg |= FIELD_PREP(SDP_R_MAP_CHAN_MASK, ring);
		cfg |= FIELD_PREP(SDP_R_MAP_VLD_MASK, 1);
		if (host_vf)
			cfg |= FIELD_PREP(SDP_R_MAP_VFRSID_MASK, vf_rid);

		rvu_write64(rvu, BLKADDR_SDP, SDP_AF_RX_EPF_VF_MAP(ring), cfg);

		/* Use hardware ring number as channel number */
		cfg = FIELD_PREP(SDP_MAC_CHAN_MAP_RING_MASK, ring);
		cfg |= FIELD_PREP(SDP_MAC_CHAN_MAP_VLD_MASK, 1);
		rvu_write64(rvu, BLKADDR_SDP, SDP_AF_MAC_CHANX_RING_MAP(ring),
			    cfg);

		sdp_cfg->hw_ring_map[slot] = ring;
		/* TX and RX channels are same */
		sdp_cfg->channels[slot] = pfvf->rx_chan_base + ring;
		sdp_cfg->nr_rings++;
		rsp->count++;

		sdp->fn_map[ring] = host_pcifunc;
	}

	if (rsp->count) {
		cn20k_sdp_send_ring_msg(rvu, rvu_pcifunc, MBOX_MSG_SDP_RINGS_UPDATE,
					SDP_RING_F_ALLOC);
	} else if (host_vf) { /* None of rings configuration is successful */
		rvu_free_rsrc(&sdp->vf_rids, vf_rid);
		sdp->vf_rsrc_map[vf_rid] = 0xFFFF;
	}

	mutex_unlock(&sdp->cfg_lock);

	return 0;
}

static void _rvu_sdp_ring_free(struct rvu *rvu,
			       struct sdp_config *sdp_cfg,
			       u16 ring)
{
	struct npc_mcam_free_entry_req free_req = { 0 };
	struct npc_delete_flow_req del_req = { 0 };
	struct npc_delete_flow_rsp del_rsp = { 0 };
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	struct msg_rsp rsp = { 0 };
	int hw_ring;
	u64 cfg;

	hw_ring = sdp_cfg->hw_ring_map[ring];

	cfg = rvu_read64(rvu, BLKADDR_SDP,
			 SDP_AF_RX_EPF_VF_MAP(hw_ring));
	cfg &= ~SDP_R_MAP_VLD_MASK;
	rvu_write64(rvu, BLKADDR_SDP,
		    SDP_AF_RX_EPF_VF_MAP(hw_ring), cfg);

	cfg = rvu_read64(rvu, BLKADDR_SDP,
			 SDP_AF_MAC_CHANX_RING_MAP(hw_ring));
	cfg &= ~SDP_MAC_CHAN_MAP_VLD_MASK;
	rvu_write64(rvu, BLKADDR_SDP,
		    SDP_AF_MAC_CHANX_RING_MAP(hw_ring), cfg);

	del_req.entry = sdp_cfg->mcam_rx_entries[ring];
	rvu_mbox_handler_npc_delete_flow(rvu, &del_req, &del_rsp);

	free_req.entry = sdp_cfg->mcam_rx_entries[ring];
	rvu_mbox_handler_npc_mcam_free_entry(rvu, &free_req, &rsp);

	rvu_free_rsrc(&sdp->rings, hw_ring);
	sdp_cfg->nr_rings--;
	sdp->fn_map[hw_ring] = 0xFFFF;
}

int rvu_mbox_handler_sdp_rings_free(struct rvu *rvu,
				    struct sdp_rings_free_req *req,
				    struct msg_rsp *rsp)
{
	u16 rvu_pcifunc = cn20k_get_rvu_pcifunc(rvu, req->hdr.pcifunc);
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, rvu_pcifunc);
	struct sdp_rsrc *sdp = &rvu->hw->sdp;
	u16 nr_rings, host_pcifunc, host_vf;
	struct sdp_config *sdp_cfg;
	int rid, rc = 0;
	u16 slot;

	host_pcifunc = req->hdr.pcifunc;
	host_vf = get_sdp_evf(host_pcifunc);

	sdp_cfg = &pfvf->sdp_cfg;
	if (!sdp_cfg->nr_rings) {
		dev_err(rvu->dev, "No rings allocated\n");
		return -ENODEV;
	}

	mutex_lock(&sdp->cfg_lock);

	nr_rings = sdp_cfg->nr_rings;
	for (slot = 0; slot < nr_rings; slot++)
		_rvu_sdp_ring_free(rvu, sdp_cfg, slot);

	if (host_vf) {
		for (rid = 0; rid < sdp->vf_rids.max; rid++) {
			if (sdp->vf_rsrc_map[rid] == host_pcifunc)
				break;
		}

		if (rid < sdp->vf_rids.max) {
			rvu_free_rsrc(&sdp->vf_rids, rid);
			sdp->vf_rsrc_map[rid] = 0xFFFF;
		} else {
			dev_err(rvu->dev, "VF resource id for EVF:%d not found",
				host_vf - 1);
			rc = -EINVAL;
		}
	}

	cn20k_sdp_send_ring_msg(rvu, rvu_pcifunc, MBOX_MSG_SDP_RINGS_UPDATE,
				SDP_RING_F_FREE);

	mutex_unlock(&sdp->cfg_lock);

	return rc;
}

int rvu_mbox_handler_sdp_rings_default(struct rvu *rvu,
				       struct msg_req *req,
				       struct sdp_rings_default_rsp *rsp)
{
	rsp->default_nr_rings = num_online_cpus();

	return 0;
}
/* SDP Mbox handler */
static int sdp_process_mbox_msg(struct otx2_mbox *mbox, int devid,
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
		MBOX_EBLOCK_SDP_MESSAGES

	default :
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}
}

/*Duplicate mbox APIs */
static void __sdp_mbox_up_handler(struct rvu_work *mwork, int type)
{
	struct rvu *rvu = mwork->rvu;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	struct mbox_wq_info *mw;
	struct otx2_mbox *mbox;
	int offset, id, devid;

	switch (type) {
	case TYPE_AFEPF:
		mw = &sdp_data.afepf_wq_info;
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

static void __sdp_mbox_handler(struct rvu_work *mwork, int type, bool poll)
{
	struct rvu *rvu = mwork->rvu;
	int offset, err, id, devid;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	struct mbox_wq_info *mw;
	struct otx2_mbox *mbox;

	switch (type) {
	case TYPE_AFEPF:
		mw = &sdp_data.afepf_wq_info;
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
		case TYPE_AFEPF:
			msg->pcifunc &=
				~(RVU_PFVF_PF_MASK << RVU_PFVF_PF_SHIFT);
			msg->pcifunc |= (devid << RVU_PFVF_PF_SHIFT);
			break;
		}

		err = sdp_process_mbox_msg(mbox, devid, msg);
		if (!err) {
			offset = mbox->rx_start + msg->next_msgoff;
			continue;
		}

		if (msg->pcifunc & RVU_PFVF_FUNC_MASK)
			dev_warn(rvu->dev, "Error %d when processing message %s (0x%x) from EPF%d:VF%d\n",
				 err, otx2_mbox_id2name(msg->id),
				 msg->id, rvu_get_pf(msg->pcifunc),
				 (msg->pcifunc & RVU_PFVF_FUNC_MASK) - 1);
		else
			dev_warn(rvu->dev, "Error %d when processing message %s (0x%x) from EPF%d\n",
				 err, otx2_mbox_id2name(msg->id),
				 msg->id, devid);
	}

	mw->mbox_wrk[devid].num_msgs = 0;

	if (!is_cn20k(mbox->pdev) && poll)
		otx2_mbox_wait_for_zero(mbox, devid);

	/* Send mbox responses to VF/PF */
	otx2_mbox_msg_send(mbox, devid);
}

/* Each PEM supports upto 8 EPFs
 * SCRATCH(0) contains start address of mbox region of PEM0
 */
static int sdp_get_mbox_regions(struct rvu *rvu, void **mbox_addr,
				int num, int type, unsigned long *pf_bmap,
				int blkaddr)
{
	int region;
	u64 bar;

	bar = rvu_read64(rvu, blkaddr, SDP_AF_EPFX_SCRATCH(0));
	if (!bar) {
		dev_warn(rvu->dev,
			 "PEM BAR Mbox region not configured\n");
		goto error;
	}

	if (type == TYPE_AFEPF) {
		for (region = 0; region < num; region++) {
			if (!test_bit(region, pf_bmap))
				continue;

			bar += region * MBOX_SIZE;
			mbox_addr[region] = (void *)ioremap_wc(bar, MBOX_SIZE);

			if (!mbox_addr[region])
				goto error;
		}
	}
	return 0;

error:
	return -ENOMEM;
}

static int sdp_mbox_init(struct rvu *rvu, struct mbox_wq_info *mw,
			 int type, int num, int blkaddr,
			 void (mbox_handler)(struct work_struct *),
			 void (mbox_up_handler)(struct work_struct *))
{
	int err = -EINVAL, i, dir, dir_up;
	void __iomem *reg_base;
	struct rvu_work *mwork;
	unsigned long *pf_bmap;
	void **mbox_regions;
	const char *name;

	pf_bmap = bitmap_zalloc(num, GFP_KERNEL);
	if (!pf_bmap)
		return -ENOMEM;

	if (type == TYPE_AFEPF)
		*pf_bmap = GENMASK(num - 1, 0);

	mutex_init(&rvu->mbox_lock);

	mbox_regions = kcalloc(num, sizeof(void *), GFP_KERNEL);
	if (!mbox_regions) {
		err = -ENOMEM;
		goto free_bitmap;
	}

	switch (type) {
	case TYPE_AFEPF:
		name = "rvu_afepf_mailbox";
		dir = MBOX_DIR_AFEPF;
		dir_up = MBOX_DIR_AFEPF_UP;
		reg_base = rvu->afreg_base;
		err = sdp_get_mbox_regions(rvu, mbox_regions, num, TYPE_AFEPF,
					   pf_bmap, blkaddr);
		if (err)
			goto free_regions;
		break;
	default:
		goto free_regions;
	}

	mw->mbox_wq = alloc_workqueue(name,
				      WQ_HIGHPRI | WQ_MEM_RECLAIM,
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
	return 0;

exit:
	destroy_workqueue(mw->mbox_wq);
unmap_regions:
	while (num--)
		iounmap((void __iomem *)mbox_regions[num]);
free_regions:
	kfree(mbox_regions);
free_bitmap:
	bitmap_free(pf_bmap);
	return err;
}

static irqreturn_t rvu_mbox_epf_intr_handler(int irq, void *cookie)
{
	struct sdp_irq_data *epf_cookie = cookie;
	struct rvu *rvu = epf_cookie->block->rvu;
	int epf_id = epf_cookie->pf_data;
	u64 epf_intr;

	epf_intr = rvu_read64(rvu, BLKADDR_SDP, SDP_AF_AP_EPFX_MBOX_LINT(epf_id));
	/* Clear interrupts */
	rvu_write64(rvu, BLKADDR_SDP, SDP_AF_AP_EPFX_MBOX_LINT(epf_id), epf_intr);
	if (epf_intr)
		trace_otx2_msg_interrupt(rvu->pdev, "EPF(s) to AF", epf_intr);

	/* Sync with mbox memory region */
	rmb();

	rvu_queue_work(&sdp_data.afepf_wq_info, 0, SDP_MAX_EPF, BIT(epf_id));
	return IRQ_HANDLED;
}

static void rvu_sdp_unregister_interrupts_block(struct rvu_block *block,
						void *data)
{
	int i, offs, blkaddr;
	struct rvu *rvu = block->rvu;

	blkaddr = block->addr;

	offs = rvu_read64(rvu, blkaddr, SDP_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get SDP_AF_INT vector offsets");
		return;
	}

	for (i = 0; i < SDP_MBOX_VEC_CNT; i++) {
		rvu_write64(rvu, blkaddr, SDP_AF_AP_EPFX_MBOX_LINT_ENA_W1S(i), 0x1);
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), block);
			rvu->irq_allocated[offs + i] = false;
		}
	}
}

static int rvu_sdp_af_request_irq(struct sdp_irq_data *epf_cookie,
				  int offset, irq_handler_t handler,
				  const char *name)
{
	struct rvu *rvu = epf_cookie->block->rvu;
	int ret = 0;

	WARN_ON(rvu->irq_allocated[offset]);
	rvu->irq_allocated[offset] = false;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "%s", name);
	ret = request_irq(pci_irq_vector(rvu->pdev, offset), handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], epf_cookie);
	if (ret)
		dev_warn(rvu->dev, "Failed to register %s irq\n", name);
	else
		rvu->irq_allocated[offset] = true;

	return rvu->irq_allocated[offset];
}

static int rvu_sdp_register_interrupts_block(struct rvu_block *block,
					     void *data)
{
	int offs, blkaddr, ret = 0, epf;
	struct rvu *rvu = block->rvu;

	blkaddr = block->addr;

	/* Read interrupt vector */
	offs = rvu_read64(rvu, blkaddr, SDP_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get SDP_AF_INT vector offsets");
		return 0;
	}
	/* Register and enable mbox interrupt */
	for (epf = 0; epf < SDP_MBOX_VEC_CNT; epf++) {
		epf_cookie[epf].block = block;
		epf_cookie[epf].pf_data = epf;
		sprintf(epf_cookie[epf].irq_name, "epf%d_intr_handler", epf);
		ret = rvu_sdp_af_request_irq(&epf_cookie[epf], offs + SDP_MBOX_LINT_EPF_0 + epf,
					     rvu_mbox_epf_intr_handler, epf_cookie[epf].irq_name);
		if (!ret)
			goto err;

		rvu_write64(rvu, block->addr, SDP_AF_AP_EPFX_MBOX_LINT_ENA_W1S(epf), ~0ULL);
	}

	return 0;
err:
	rvu_sdp_unregister_interrupts_block(block, data);
	return ret;
}

static inline void rvu_afepf_mbox_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);
	struct rvu *rvu = mwork->rvu;

	mutex_lock(&rvu->mbox_lock);
	__sdp_mbox_handler(mwork, TYPE_AFEPF, true);
	mutex_unlock(&rvu->mbox_lock);
}

static inline void rvu_afepf_mbox_up_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);

	__sdp_mbox_up_handler(mwork, TYPE_AFEPF);
}

int rvu_mbox_handler_sdp_read_const(struct rvu *rvu,
				    struct msg_req *req,
				    struct sdp_rsp_const *rsp)
{
	u64 sdp_const;
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SDP, req->hdr.pcifunc);
	if (blkaddr < 0)
		return -ENODEV;

	sdp_const = rvu_read64(rvu, blkaddr, SDP_AF_CONST);
	rsp->fifo_sz = sdp_const & 0xffff;
	rsp->rings  = FIELD_GET(SDP_NUMBER_OF_RINGS_IMPL, sdp_const);
	return 0;
}

static int rvu_sdp_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	int  num_chan;
	int blkaddr;
	u64 regval;
	int err;

	/* Channel Configuration */
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	num_chan = rvu_read64(rvu, blkaddr, NIX_AF_CONST1) & 0XFFFUL;
	regval = rvu->hw->sdp_chan_base;
	regval |= ilog2(num_chan) << 16;
	rvu_write64(rvu, block->addr, SDP_AF_LINK_CFG, regval);

	/* BPFLR_D disable clearing BP in FLR */
	regval = rvu_read64(rvu, block->addr, SDP_AF_GBL_CONTROL);
	regval |= (1 << 2);
	rvu_write64(rvu, block->addr, SDP_AF_GBL_CONTROL, regval);

	err = cn20k_sdp_rings_init(rvu);
	if (err) {
		dev_err(rvu->dev, "Rings initialization failed(%d)\n", err);
		return err;
	}

	err = sdp_mbox_init(rvu, &sdp_data.afepf_wq_info, TYPE_AFEPF,
			    SDP_MAX_EPF, block->addr, rvu_afepf_mbox_handler,
			    rvu_afepf_mbox_up_handler);

	/* Now that mbox frame work setup, allow access from EPF */
	if (!err)
		rvu_write64(rvu, block->addr, SDP_AF_ACCESS_CTL, 0xDF);
	return err;
}

static int rvu_setup_sdp_hw_resource(struct rvu_block *block, void *data)
{
	block->type = BLKTYPE_SDP;
	block->addr = BLKADDR_SDP;
	sprintf(block->name, "SDP");
	return 0;
}

static void *rvu_sdp_probe(struct rvu *rvu, int blkaddr)
{
	struct sdp_drvdata *data;

	switch (blkaddr) {
	case BLKADDR_SDP:
		data = devm_kzalloc(rvu->dev, sizeof(struct sdp_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_sdp_remove(struct rvu_block *hwblock, void *data)
{
	devm_kfree(hwblock->rvu->dev, data);
}

static void rvu_sdp_free(struct rvu_block *block, void *data)
{
	//nothing
}

static struct rvu_eblock_driver_ops sdp_ops = {
	.probe	= rvu_sdp_probe,
	.remove	= rvu_sdp_remove,
	.init	= rvu_sdp_init_block,
	.setup	= rvu_setup_sdp_hw_resource,
	.register_interrupt = rvu_sdp_register_interrupts_block,
	.unregister_interrupt = rvu_sdp_unregister_interrupts_block,
	.free    = rvu_sdp_free,
};

void sdp_eb_module_init(void)
{
	rvu_eblock_register_driver(&sdp_ops);
}

void sdp_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&sdp_ops);
}
