// SPDX-License-Identifier: GPL-2.0
/* OcteonTX2 SDP driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_struct.h"
#include "sdp.h"

#define DRV_NAME	"octeontx2-sdp"
#define DRV_VERSION	"1.1"

#define PCI_DEVID_OCTEONTX2_SDP_PF	0xA0F6
#define PCI_DEVID_OCTEONTX2_SDP_VF	0xA0F7

/* PCI BAR nos */
#define PCI_AF_REG_BAR_NUM	0
#define PCI_CFG_REG_BAR_NUM	2
#define MBOX_BAR_NUM		4

#define SDP_PPAIR_THOLD 0x400

/* Supported devices */
static const struct pci_device_id rvu_sdp_id_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_SDP_PF)},
	{0} /* end of table */
};

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 SDP PF Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, rvu_sdp_id_table);

/* All PF devices found are stored here */
static spinlock_t sdp_lst_lock;
LIST_HEAD(sdp_dev_lst_head);
static int sdp_sriov_configure(struct pci_dev *pdev, int num_vfs);

static inline bool is_otx3_sdp(struct sdp_dev *sdp)
{
	if (sdp->pdev->subsystem_device >= PCI_SUBSYS_DEVID_CN10K_A)
		return 1;

	return 0;
}

static void
sdp_write64(struct sdp_dev *rvu, u64 b, u64 s, u64 o, u64 v)
{
	writeq(v, rvu->bar2 + ((b << 20) | (s << 12) | o));
}

static u64 sdp_read64(struct sdp_dev *rvu, u64 b, u64 s, u64 o)
{
	return readq(rvu->bar2 + ((b << 20) | (s << 12) | o));
}

static void enable_af_mbox_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;

	sdp = pci_get_drvdata(pdev);
	/* Clear interrupt if any */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);

	/* Now Enable AF-PF interrupt */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1S, 0x1ULL);
}

static void disable_af_mbox_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;

	sdp = pci_get_drvdata(pdev);
	/* Clear interrupt if any */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);

	/* Now Disable AF-PF interrupt */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1C, 0x1ULL);
}

static int
forward_to_mbox(struct sdp_dev *sdp, struct otx2_mbox *mbox, int devid,
		struct mbox_msghdr *req, int size, const char *mstr)
{
	struct mbox_msghdr *msg;
	int res = 0;

	msg = otx2_mbox_alloc_msg(mbox, devid, size);
	if (msg == NULL)
		return -ENOMEM;

	memcpy((uint8_t *)msg + sizeof(struct mbox_msghdr),
	       (uint8_t *)req + sizeof(struct mbox_msghdr), size);
	msg->id = req->id;
	msg->pcifunc = req->pcifunc;
	msg->sig = req->sig;
	msg->ver = req->ver;

	otx2_mbox_msg_send(mbox, devid);
	res = otx2_mbox_wait_for_rsp(mbox, devid);
	if (res == -EIO) {
		dev_err(&sdp->pdev->dev, "RVU %s MBOX timeout.\n", mstr);
		goto err;
	} else if (res) {
		dev_err(&sdp->pdev->dev,
			"RVU %s MBOX error: %d.\n", mstr, res);
		res = -EFAULT;
		goto err;
	}

	return 0;
err:
	return res;
}

static int
handle_af_req(struct sdp_dev *sdp, struct rvu_vf *vf, struct mbox_msghdr *req,
	      int size)
{
	/* We expect a request here */
	if (req->sig != OTX2_MBOX_REQ_SIG) {
		dev_err(&sdp->pdev->dev,
			"UP MBOX msg with wrong signature %x, ID 0x%x\n",
			req->sig, req->id);
		return -EINVAL;
	}

	/* If handling notifs in PF is required,add a switch-case here. */
	return forward_to_mbox(sdp, &sdp->pfvf_mbox_up, vf->vf_id, req, size,
			       "VF");
}


static void sdp_afpf_mbox_handler_up(struct work_struct *work)
{
	struct sdp_dev *sdp = container_of(work, struct sdp_dev, mbox_wrk_up);
	struct otx2_mbox *mbox = &sdp->afpf_mbox_up;
	struct otx2_mbox_dev *mdev = mbox->dev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	int offset, id, err;
	struct rvu_vf *vf;

	/* sync with mbox memory region */
	smp_rmb();

	/* Process received mbox messages */
	req_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	offset = ALIGN(sizeof(*req_hdr), MBOX_MSG_ALIGN);
	for (id = 0; id < req_hdr->num_msgs; id++) {
		msg = (struct mbox_msghdr *)(mdev->mbase + mbox->rx_start +
					     offset);

		if ((msg->pcifunc >> RVU_PFVF_PF_SHIFT) != sdp->pf ||
		    (msg->pcifunc & RVU_PFVF_FUNC_MASK) <= sdp->num_vfs)
			err = -EINVAL;
		else {
			vf = &sdp->vf_info[msg->pcifunc & RVU_PFVF_FUNC_MASK];
			err = handle_af_req(sdp, vf, msg,
					    msg->next_msgoff - offset);
		}
		if (err)
			otx2_reply_invalid_msg(mbox, 0, msg->pcifunc, msg->id);
		offset = msg->next_msgoff;
	}

	otx2_mbox_msg_send(mbox, 0);
}

static void sdp_afpf_mbox_handler(struct work_struct *work)
{
	struct nix_lf_alloc_rsp *alloc_rsp;
	struct otx2_mbox *af_mbx, *vf_mbx;
	struct mbox_msghdr *msg, *fwd;
	struct free_rsrcs_rsp *rsp;
	int offset, i, vf_id, size;
	struct mbox_hdr *rsp_hdr;
	struct sdp_dev *sdp;
	struct rvu_vf *vf;

	/* Read latest mbox data */
	smp_rmb();

	sdp = container_of(work, struct sdp_dev, mbox_wrk);
	af_mbx = &sdp->afpf_mbox;
	vf_mbx = &sdp->pfvf_mbox;
	rsp_hdr = (struct mbox_hdr *)(af_mbx->dev->mbase + af_mbx->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;
	offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);

	for (i = 0; i < rsp_hdr->num_msgs; i++) {
		msg = (struct mbox_msghdr *)(af_mbx->dev->mbase +
					     af_mbx->rx_start + offset);
		size = msg->next_msgoff - offset;

		if (msg->id >= MBOX_MSG_MAX) {
			dev_err(&sdp->pdev->dev,
				"MBOX msg with unknown ID 0x%x\n", msg->id);
			goto end;
		}

		if (msg->sig != OTX2_MBOX_RSP_SIG) {
			dev_err(&sdp->pdev->dev,
				"MBOX msg with wrong signature %x, ID 0x%x\n",
				msg->sig, msg->id);
			goto end;
		}

		vf_id = (msg->pcifunc & RVU_PFVF_FUNC_MASK);

		if (msg->id == MBOX_MSG_NIX_LF_ALLOC) {
			alloc_rsp = (struct nix_lf_alloc_rsp *)msg;
			if (vf_id == 1)
				alloc_rsp->rx_chan_cnt = sdp->info.vf_rings[0];
			else
				alloc_rsp->rx_chan_cnt = sdp->info.vf_rings[1];
			alloc_rsp->tx_chan_cnt = alloc_rsp->rx_chan_cnt;
		}

		if (vf_id > 0) {
			if (vf_id > sdp->num_vfs) {
				dev_err(&sdp->pdev->dev,
					"MBOX msg to unknown VF: %d >= %d\n",
					vf_id, sdp->num_vfs);
				goto end;
			}
			vf = &sdp->vf_info[vf_id - 1];
			/* Ignore stale responses and VFs in FLR. */
			if (!vf->in_use || vf->got_flr)
				goto end;
			fwd = otx2_mbox_alloc_msg(vf_mbx, vf_id - 1, size);
			if (!fwd) {
				dev_err(&sdp->pdev->dev,
					"Forwarding to VF%d failed.\n", vf_id);
				goto end;
			}
			memcpy((uint8_t *)fwd + sizeof(struct mbox_msghdr),
			       (uint8_t *)msg + sizeof(struct mbox_msghdr),
			       size);
			fwd->id = msg->id;
			fwd->pcifunc = msg->pcifunc;
			fwd->sig = msg->sig;
			fwd->ver = msg->ver;
			fwd->rc = msg->rc;
		} else {
			if (msg->ver < OTX2_MBOX_VERSION) {
				dev_err(&sdp->pdev->dev,
					"MBOX msg with version %04x != %04x\n",
					msg->ver, OTX2_MBOX_VERSION);
				goto end;
			}

			switch (msg->id) {
			case MBOX_MSG_READY:
				sdp->pf = (msg->pcifunc >> RVU_PFVF_PF_SHIFT) &
					 RVU_PFVF_PF_MASK;
				break;
			case MBOX_MSG_FREE_RSRC_CNT:
				rsp = (struct free_rsrcs_rsp *)msg;
				memcpy(&sdp->limits, msg, sizeof(*rsp));
				break;
			case MBOX_MSG_SET_SDP_CHAN_INFO:
				/* Nothing to do */
				break;
			case MBOX_MSG_GET_SDP_CHAN_INFO:
				/* Nothing to do */
				break;
			default:
				dev_err(&sdp->pdev->dev,
					"Unsupported msg %d received.\n",
					msg->id);
				break;
			}
		}
end:
		offset = msg->next_msgoff;
		af_mbx->dev->msgs_acked++;
	}
	otx2_mbox_reset(af_mbx, 0);
}

static int
reply_free_rsrc_cnt(struct sdp_dev *sdp, struct rvu_vf *vf,
		    struct mbox_msghdr *req, int size)
{
	struct free_rsrcs_rsp *rsp;

	rsp = (struct free_rsrcs_rsp *)otx2_mbox_alloc_msg(&sdp->pfvf_mbox,
							   vf->vf_id,
							   sizeof(*rsp));
	if (rsp == NULL)
		return -ENOMEM;

	rsp->hdr.id = MBOX_MSG_FREE_RSRC_CNT;
	rsp->hdr.pcifunc = req->pcifunc;
	rsp->hdr.sig = OTX2_MBOX_RSP_SIG;
	return 0;
}

static int
handle_vf_req(struct sdp_dev *sdp, struct rvu_vf *vf, struct mbox_msghdr *req,
	      int size)
{
	int err = 0, chan_idx, chan_diff, reg_off = 0, vf_id;
	uint64_t en_bp;
	u16 chan_base;
	u8 chan_cnt;

	/* Check if valid, if not reply with a invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG) {
		dev_err(&sdp->pdev->dev,
			"VF MBOX msg with wrong signature %x, ID 0x%x\n",
			req->sig, req->id);
		return -EINVAL;
	}

	switch (req->id) {
	case MBOX_MSG_READY:
		if (req->ver < OTX2_MBOX_VERSION) {
			dev_err(&sdp->pdev->dev,
				"VF MBOX msg with version %04x != %04x\n",
				req->ver, OTX2_MBOX_VERSION);
			return -EINVAL;
		}
		vf->in_use = true;
		err = forward_to_mbox(sdp, &sdp->afpf_mbox, 0, req, size, "AF");
		break;
	case MBOX_MSG_FREE_RSRC_CNT:
		if (req->ver < OTX2_MBOX_VERSION) {
			dev_err(&sdp->pdev->dev,
				"VF MBOX msg with version %04x != %04x\n",
				req->ver, OTX2_MBOX_VERSION);
			return -EINVAL;
		}
		err = reply_free_rsrc_cnt(sdp, vf, req, size);
		break;
	case MBOX_MSG_ATTACH_RESOURCES:
		if (req->ver < OTX2_MBOX_VERSION) {
			dev_err(&sdp->pdev->dev,
				"VF MBOX msg with version %04x != %04x\n",
				req->ver, OTX2_MBOX_VERSION);
			return -EINVAL;
		}
		err = forward_to_mbox(sdp, &sdp->afpf_mbox, 0, req, size, "AF");
		break;
	case MBOX_MSG_NIX_LF_ALLOC:
		chan_base = sdp->chan_base + sdp->info.num_pf_rings;
		for (vf_id = 0; vf_id < vf->vf_id; vf_id++)
			chan_base += sdp->info.vf_rings[vf_id];
		chan_cnt = sdp->info.vf_rings[vf->vf_id];
		for (chan_idx = 0; chan_idx < chan_cnt; chan_idx++) {
			chan_diff = chan_base + chan_idx - sdp->chan_base;
			reg_off = 0;
			while (chan_diff > 63) {
				reg_off += 1;
				chan_diff -= 64;
			}

			en_bp = readq(sdp->sdp_base +
				      SDPX_OUT_BP_ENX_W1S(reg_off));
			en_bp |= (1ULL << chan_diff);
			writeq(en_bp, sdp->sdp_base +
			       SDPX_OUT_BP_ENX_W1S(reg_off));
		}
		/* Fall through */
	default:
		err = forward_to_mbox(sdp, &sdp->afpf_mbox, 0, req, size, "AF");
		break;
	}

	return err;
}

static int send_flr_msg(struct otx2_mbox *mbox, int dev_id, int pcifunc)
{
	struct msg_req *req;

	req = (struct msg_req *)
		otx2_mbox_alloc_msg(mbox, dev_id, sizeof(*req));
	if (req == NULL)
		return -ENOMEM;

	req->hdr.pcifunc = pcifunc;
	req->hdr.id = MBOX_MSG_VF_FLR;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;

	otx2_mbox_msg_send(mbox, 0);

	return 0;
}

static void sdp_send_flr_msg(struct sdp_dev *sdp, struct rvu_vf *vf)
{
	int res, pcifunc;

	pcifunc = (vf->sdp->pf << RVU_PFVF_PF_SHIFT) |
		((vf->vf_id + 1) & RVU_PFVF_FUNC_MASK);

	if (send_flr_msg(&sdp->afpf_mbox, 0, pcifunc) != 0) {
		dev_err(&sdp->pdev->dev, "Sending FLR to AF failed\n");
		return;
	}

	res = otx2_mbox_wait_for_rsp(&sdp->afpf_mbox, 0);
	if (res == -EIO) {
		dev_err(&sdp->pdev->dev, "RVU AF MBOX timeout.\n");
	} else if (res) {
		dev_err(&sdp->pdev->dev,
			"RVU MBOX error: %d.\n", res);
	}
}

static void sdp_send_flr_to_dpi(struct sdp_dev *sdp)
{
	/* TODO: DPI VF's needs to be handled */
}

static void sdp_pfvf_flr_handler(struct work_struct *work)
{
	struct rvu_vf *vf = container_of(work, struct rvu_vf, pfvf_flr_work);
	struct sdp_dev *sdp = vf->sdp;
	struct otx2_mbox *mbox;

	mbox = &sdp->pfvf_mbox;

	sdp_send_flr_to_dpi(sdp);
	sdp_send_flr_msg(sdp, vf);

	/* Disable interrupts from AF and wait for any pending
	 * responses to be handled for this VF and then reset the
	 * mailbox
	 */
	disable_af_mbox_int(sdp->pdev);
	flush_workqueue(sdp->afpf_mbox_wq);
	otx2_mbox_reset(mbox, vf->vf_id);
	vf->in_use = false;
	vf->got_flr = false;
	enable_af_mbox_int(sdp->pdev);
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(vf->vf_id / 64),
		   BIT_ULL(vf->intr_idx));
}

static void sdp_pfvf_mbox_handler_up(struct work_struct *work)
{
	struct otx2_mbox *af_mbx, *vf_mbx;
	struct mbox_msghdr *msg, *fwd;
	struct mbox_hdr *rsp_hdr;
	struct sdp_dev *sdp;
	int offset, i, size;
	struct rvu_vf *vf;

	/* Read latest mbox data */
	smp_rmb();

	vf = container_of(work, struct rvu_vf, mbox_wrk_up);
	sdp = vf->sdp;
	af_mbx = &sdp->afpf_mbox;
	vf_mbx = &sdp->pfvf_mbox;
	rsp_hdr = (struct mbox_hdr *)(vf_mbx->dev[vf->vf_id].mbase +
				      vf_mbx->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;
	offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);

	for (i = 0; i < rsp_hdr->num_msgs; i++) {
		msg = (struct mbox_msghdr *)(vf_mbx->dev->mbase +
					     vf_mbx->rx_start + offset);
		size = msg->next_msgoff - offset;

		if (msg->sig != OTX2_MBOX_RSP_SIG) {
			dev_err(&sdp->pdev->dev,
				"UP MBOX msg with wrong signature %x, ID 0x%x\n",
				msg->sig, msg->id);
			goto end;
		}

		/* override message value with actual values */
		msg->pcifunc = (sdp->pf << RVU_PFVF_PF_SHIFT) | vf->vf_id;

		fwd = otx2_mbox_alloc_msg(af_mbx, 0, size);
		if (!fwd) {
			dev_err(&sdp->pdev->dev,
				"UP Forwarding from VF%d to AF failed.\n",
				vf->vf_id);
			goto end;
		}
		memcpy((uint8_t *)fwd + sizeof(struct mbox_msghdr),
			(uint8_t *)msg + sizeof(struct mbox_msghdr),
			size);
		fwd->id = msg->id;
		fwd->pcifunc = msg->pcifunc;
		fwd->sig = msg->sig;
		fwd->ver = msg->ver;
		fwd->rc = msg->rc;
end:
		offset = msg->next_msgoff;
		vf_mbx->dev->msgs_acked++;
	}
	otx2_mbox_reset(vf_mbx, vf->vf_id);
}

static void sdp_pfvf_mbox_handler(struct work_struct *work)
{
	struct rvu_vf *vf = container_of(work, struct rvu_vf, mbox_wrk);
	struct sdp_dev *sdp = vf->sdp;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	struct otx2_mbox *mbox;
	int offset, id, err;

	mbox = &sdp->pfvf_mbox;
	mdev = &mbox->dev[vf->vf_id];

	/* sync with mbox memory region */
	smp_rmb();

	/* Process received mbox messages */
	req_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	offset = ALIGN(sizeof(*req_hdr), MBOX_MSG_ALIGN);
	for (id = 0; id < req_hdr->num_msgs; id++) {
		msg = (struct mbox_msghdr *)(mdev->mbase + mbox->rx_start +
					     offset);

		/* Set which VF sent this message based on mbox IRQ */
		msg->pcifunc = ((u16)sdp->pf << RVU_PFVF_PF_SHIFT) |
				((vf->vf_id + 1) & RVU_PFVF_FUNC_MASK);
		err = handle_vf_req(sdp, vf, msg, msg->next_msgoff - offset);
		if (err)
			otx2_reply_invalid_msg(mbox, vf->vf_id, msg->pcifunc,
					       msg->id);
		offset = msg->next_msgoff;
	}
	/* Send mbox responses to VF */
	if (mdev->num_msgs)
		otx2_mbox_msg_send(mbox, vf->vf_id);
}

static irqreturn_t sdp_af_pf_mbox_intr(int irq, void *arg)
{
	struct sdp_dev *sdp = (struct sdp_dev *)arg;
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;

	/* Read latest mbox data */
	smp_rmb();

	mbox = &sdp->afpf_mbox;
	mdev = &mbox->dev[0];
	hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	/* Handle PF => AF channel response */
	if (hdr->num_msgs)
		queue_work(sdp->afpf_mbox_wq, &sdp->mbox_wrk);

	mbox = &sdp->afpf_mbox_up;
	mdev = &mbox->dev[0];
	hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	/* Handle AF => PF request */
	if (hdr->num_msgs)
		queue_work(sdp->afpf_mbox_wq, &sdp->mbox_wrk_up);

	/* Clear and ack the interrupt */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);

	return IRQ_HANDLED;
}

static void __handle_vf_flr(struct sdp_dev *sdp, struct rvu_vf *vf_ptr)
{
	if (vf_ptr->in_use) {
		/* Using the same MBOX workqueue here, so that we can
		 * synchronize with other VF->PF messages being forwarded to
		 * AF
		 */
		vf_ptr->got_flr = true;
		queue_work(sdp->pfvf_mbox_wq, &vf_ptr->pfvf_flr_work);
	} else
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			   RVU_PF_VFTRPENDX(vf_ptr->vf_id / 64),
			   BIT_ULL(vf_ptr->intr_idx));
}

static irqreturn_t sdp_pf_vf_flr_intr(int irq, void *arg)
{
	struct sdp_dev *sdp = (struct sdp_dev *)arg;
	struct rvu_vf *vf_ptr;
	int vf, i;
	u64 intr;

	/* Check which VF FLR has been raised and process accordingly */
	for (i = 0; i < 2; i++) {
		/* Read the interrupt bits */
		intr = sdp_read64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(i));

		for (vf = i * 64; vf < sdp->num_vfs; vf++) {
			vf_ptr = &sdp->vf_info[vf];
			if (intr & (1ULL << vf_ptr->intr_idx)) {
				/* Clear the interrupts */
				sdp_write64(sdp, BLKADDR_RVUM, 0,
					   RVU_PF_VFFLR_INTX(i),
					   BIT_ULL(vf_ptr->intr_idx));
				__handle_vf_flr(sdp, vf_ptr);
			}
		}
	}

	return IRQ_HANDLED;
}

static irqreturn_t sdp_pf_vf_mbox_intr(int irq, void *arg)
{
	struct sdp_dev *sdp = (struct sdp_dev *)arg;
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;
	struct rvu_vf *vf;
	int i, vfi;
	u64 intr;

	/* Check which VF has raised an interrupt and schedule corresponding
	 * workq to process the MBOX
	 */
	for (i = 0; i < 2; i++) {
		/* Read the interrupt bits */
		intr = sdp_read64(sdp, BLKADDR_RVUM, 0,
				  RVU_PF_VFPF_MBOX_INTX(i));

		for (vfi = i * 64; vfi < sdp->num_vfs; vfi++) {
			vf = &sdp->vf_info[vfi];
			if ((intr & (1ULL << vf->intr_idx)) == 0)
				continue;
			mbox = &sdp->pfvf_mbox;
			mdev = &mbox->dev[vf->vf_id];
			hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
			/* Handle VF => PF channel request */
			if (hdr->num_msgs)
				queue_work(sdp->pfvf_mbox_wq, &vf->mbox_wrk);

			mbox = &sdp->pfvf_mbox_up;
			mdev = &mbox->dev[vf->vf_id];
			hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
			/* Handle PF => VF channel response */
			if (hdr->num_msgs)
				queue_work(sdp->pfvf_mbox_wq, &vf->mbox_wrk_up);
			/* Clear the interrupt */
			sdp_write64(sdp, BLKADDR_RVUM, 0,
				   RVU_PF_VFPF_MBOX_INTX(i),
				   BIT_ULL(vf->intr_idx));
		}
	}

	return IRQ_HANDLED;
}

static int sdp_register_flr_irq(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int err, vec, i;

	sdp = pci_get_drvdata(pdev);

	/* Register for VF FLR interrupts
	 * There are 2 vectors starting at index 0x0
	 */
	for (vec = RVU_PF_INT_VEC_VFFLR0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFFLR1; i++) {
		sprintf(&sdp->irq_names[(vec + i) * NAME_SIZE],
			"SDP_PF%02d_VF_FLR%d", pdev->bus->number, i);
		err = request_irq(pci_irq_vector(pdev, vec + i),
				  sdp_pf_vf_flr_intr, 0,
				  &sdp->irq_names[(vec + i) * NAME_SIZE], sdp);
		if (err) {
			dev_err(&pdev->dev,
				"request_irq() failed for PFVF FLR intr %d\n",
				vec);
			goto reg_fail;
		}
		sdp->irq_allocated[vec + i] = true;
	}

	return 0;

reg_fail:

	return err;
}

static void sdp_free_flr_irq(struct pci_dev *pdev)
{
	(void) pdev;
	/* Nothing here but will free workqueues */
}

static int sdp_alloc_irqs(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int err;

	sdp = pci_get_drvdata(pdev);

	/* Get number of MSIX vector count and allocate vectors first */
	sdp->msix_count = pci_msix_vec_count(pdev);

	err = pci_alloc_irq_vectors(pdev, sdp->msix_count, sdp->msix_count,
				    PCI_IRQ_MSIX);

	if (err < 0) {
		dev_err(&pdev->dev, "pci_alloc_irq_vectors() failed %d\n", err);
		return err;
	}

	sdp->irq_names = kmalloc_array(sdp->msix_count, NAME_SIZE, GFP_KERNEL);
	if (!sdp->irq_names) {
		err = -ENOMEM;
		goto err_irq_names;
	}

	sdp->irq_allocated = kcalloc(sdp->msix_count, sizeof(bool), GFP_KERNEL);
	if (!sdp->irq_allocated) {
		err = -ENOMEM;
		goto err_irq_allocated;
	}

	return 0;

err_irq_allocated:
	kfree(sdp->irq_names);
	sdp->irq_names = NULL;
err_irq_names:
	pci_free_irq_vectors(pdev);
	sdp->msix_count = 0;

	return err;
}

static void sdp_free_irqs(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int irq;

	sdp = pci_get_drvdata(pdev);
	for (irq = 0; irq < sdp->msix_count; irq++) {
		if (sdp->irq_allocated[irq])
			free_irq(pci_irq_vector(sdp->pdev, irq), sdp);
	}

	pci_free_irq_vectors(pdev);

	kfree(sdp->irq_names);
	kfree(sdp->irq_allocated);
}

static int sdp_register_mbox_irq(struct pci_dev *pdev)
{
	int err, vec = RVU_PF_INT_VEC_VFPF_MBOX0, i;
	struct sdp_dev *sdp;

	sdp = pci_get_drvdata(pdev);

	/* Register PF-AF interrupt handler */
	sprintf(&sdp->irq_names[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE],
		"PF%02d_AF_MBOX_IRQ", pdev->devfn);
	err = request_irq(pci_irq_vector(pdev, RVU_PF_INT_VEC_AFPF_MBOX),
			  sdp_af_pf_mbox_intr, 0,
			  &sdp->irq_names[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE],
			  sdp);
	if (err) {
		dev_err(&pdev->dev,
			"request_irq() failed for AF_PF MSIX vector\n");
		return err;
	}
	sdp->irq_allocated[RVU_PF_INT_VEC_AFPF_MBOX] = true;

	err = otx2_mbox_init(&sdp->afpf_mbox, sdp->af_mbx_base, pdev, sdp->bar2,
			     MBOX_DIR_PFAF, 1);
	if (err) {
		dev_err(&pdev->dev, "Failed to initialize PF/AF MBOX\n");
		goto error;
	}
	err = otx2_mbox_init(&sdp->afpf_mbox_up, sdp->af_mbx_base, pdev,
			     sdp->bar2, MBOX_DIR_PFAF_UP, 1);
	if (err) {
		dev_err(&pdev->dev, "Failed to initialize PF/AF UP MBOX\n");
		goto error;
	}

	/* Register for PF-VF mailbox interrupts
	 * There are 2 vectors starting at index 0x4
	 */
	for (vec = RVU_PF_INT_VEC_VFPF_MBOX0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFPF_MBOX1; i++) {
		sprintf(&sdp->irq_names[(vec + i) * NAME_SIZE],
			"PF%02d_VF_MBOX_IRQ%d", pdev->devfn, i);
		err = request_irq(pci_irq_vector(pdev, vec + i),
				  sdp_pf_vf_mbox_intr, 0,
				  &sdp->irq_names[(vec + i) * NAME_SIZE], sdp);
		if (err) {
			dev_err(&pdev->dev,
				"request_irq() failed for PFVF Mbox intr %d\n",
				vec + i);
			goto error;
		}
		sdp->irq_allocated[vec + i] = true;
	}

	sdp->afpf_mbox_wq = alloc_workqueue(
	    "sdp_pfaf_mailbox", WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 1);
	if (!sdp->afpf_mbox_wq)
		goto error;

	INIT_WORK(&sdp->mbox_wrk, sdp_afpf_mbox_handler);
	INIT_WORK(&sdp->mbox_wrk_up, sdp_afpf_mbox_handler_up);

	return err;

error:
	if (sdp->afpf_mbox_up.dev != NULL)
		otx2_mbox_destroy(&sdp->afpf_mbox_up);
	if (sdp->afpf_mbox.dev != NULL)
		otx2_mbox_destroy(&sdp->afpf_mbox);

	return err;
}

static int sdp_get_pcifunc(struct sdp_dev *sdp)
{
	struct msg_req *ready_req;
	int res = 0;

	ready_req = (struct msg_req *)
		otx2_mbox_alloc_msg_rsp(&sdp->afpf_mbox, 0, sizeof(ready_req),
					sizeof(struct ready_msg_rsp));
	if (ready_req == NULL) {
		dev_err(&sdp->pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	ready_req->hdr.id = MBOX_MSG_READY;
	ready_req->hdr.sig = OTX2_MBOX_REQ_SIG;
	otx2_mbox_msg_send(&sdp->afpf_mbox, 0);
	res = otx2_mbox_wait_for_rsp(&sdp->afpf_mbox, 0);
	if (res == -EIO) {
		dev_err(&sdp->pdev->dev, "RVU AF MBOX timeout.\n");
	} else if (res) {
		dev_err(&sdp->pdev->dev, "RVU MBOX error: %d.\n", res);
		res = -EFAULT;
	}
	return res;
}

static int sdp_get_available_rsrcs(struct sdp_dev *sdp)
{
	struct mbox_msghdr *rsrc_req;
	int res = 0;

	rsrc_req = otx2_mbox_alloc_msg(&sdp->afpf_mbox, 0, sizeof(*rsrc_req));
	if (rsrc_req == NULL) {
		dev_err(&sdp->pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}
	rsrc_req->id = MBOX_MSG_FREE_RSRC_CNT;
	rsrc_req->sig = OTX2_MBOX_REQ_SIG;
	rsrc_req->pcifunc = RVU_PFFUNC(sdp->pf, 0);
	otx2_mbox_msg_send(&sdp->afpf_mbox, 0);
	res = otx2_mbox_wait_for_rsp(&sdp->afpf_mbox, 0);
	if (res == -EIO) {
		dev_err(&sdp->pdev->dev, "RVU AF MBOX timeout.\n");
	} else if (res) {
		dev_err(&sdp->pdev->dev,
			"RVU MBOX error: %d.\n", res);
		res = -EFAULT;
	}
	return res;
}

static void sdp_afpf_mbox_term(struct pci_dev *pdev)
{
	struct sdp_dev *sdp = pci_get_drvdata(pdev);

	destroy_workqueue(sdp->afpf_mbox_wq);
	otx2_mbox_destroy(&sdp->afpf_mbox);
	otx2_mbox_destroy(&sdp->afpf_mbox_up);
}

static int sdp_check_pf_usable(struct sdp_dev *sdp)
{
	u64 rev;

	rev = sdp_read64(sdp, BLKADDR_RVUM, 0,
			RVU_PF_BLOCK_ADDRX_DISC(BLKADDR_RVUM));
	rev = (rev >> 12) & 0xFF;
	/* Check if AF has setup revision for RVUM block,
	 * otherwise this driver probe should be deferred
	 * until AF driver comes up.
	 */
	if (!rev) {
		dev_warn(&sdp->pdev->dev,
			 "AF is not initialized, deferring probe\n");
		return -EPROBE_DEFER;
	}
	return 0;
}

static int sdp_parse_rinfo(struct pci_dev *pdev,
			   struct sdp_node_info *info)
{
	u32 vf_ring_cnts, vf_rings;
	struct device_node *dev;
	struct device *sdev;
	const void *ptr;
	int len, vfid;

	sdev = &pdev->dev;
	dev = of_find_node_by_name(NULL, "rvu-sdp");
	if (dev == NULL) {
		dev_err(sdev, "can't find FDT dev %s\n", "rvu-sdp");
		return -EINVAL;
	}

	ptr = of_get_property(dev, "num-rvu-vfs", &len);
	if (ptr == NULL) {
		dev_err(sdev, "SDP DTS: Failed to get num-rvu-vfs\n");
		return -EINVAL;
	}

	if (len != sizeof(u32)) {
		dev_err(sdev, "SDP DTS: Wrong field length: num-rvu-vfs\n");
		return -EINVAL;
	}
	info->max_vfs =  be32_to_cpup((u32 *)ptr);

	if (info->max_vfs > pci_sriov_get_totalvfs(pdev)) {
		dev_err(sdev, "SDP DTS: Invalid field value: num-rvu-vfs\n");
		return -EINVAL;
	}

	ptr = of_get_property(dev, "num-pf-rings", &len);
	if (ptr == NULL) {
		dev_err(sdev, "SDP DTS: Failed to get num-pf-rings\n");
		return -EINVAL;
	}
	if (len != sizeof(u32)) {
		dev_err(sdev, "SDP DTS: Wrong field length: num-pf-rings\n");
		return -EINVAL;
	}
	info->num_pf_rings = be32_to_cpup((u32 *)ptr);

	ptr = of_get_property(dev, "pf-srn", &len);
	if (ptr == NULL) {
		dev_err(sdev, "SDP DTS: Failed to get pf-srn\n");
		return -EINVAL;
	}
	if (len != sizeof(u32)) {
		dev_err(sdev, "SDP DTS: Wrong field length: pf-srn\n");
		return -EINVAL;
	}
	info->pf_srn = be32_to_cpup((u32 *)ptr);

	ptr = of_get_property(dev, "num-vf-rings", &len);
	if (ptr == NULL) {
		dev_err(sdev, "SDP DTS: Failed to get num-vf-rings\n");
		return -EINVAL;
	}

	vf_ring_cnts = len / sizeof(u32);
	if (vf_ring_cnts > info->max_vfs) {
		dev_err(sdev, "SDP DTS: Wrong field length: num-vf-rings\n");
		return -EINVAL;
	}

	for (vfid = 0; vfid < info->max_vfs; vfid++) {
		if (vfid < vf_ring_cnts) {
			if (of_property_read_u32_index(dev, "num-vf-rings",
					vfid, &vf_rings)) {
				dev_err(sdev, "SDP DTS: Failed to get vf ring count\n");
				return -EINVAL;
			}
			info->vf_rings[vfid] = vf_rings;
		} else {
			/*
			 * Rest of the VFs use the same last ring count
			 * specified
			 */
			info->vf_rings[vfid] = info->vf_rings[vf_ring_cnts - 1];
		}
	}
	dev_info(sdev, "pf start ring number:%d num_pf_rings:%d max_vfs:%d vf_ring_cnts:%d\n",
		 info->pf_srn, info->num_pf_rings, info->max_vfs, vf_ring_cnts);

	return 0;
}

static ssize_t sdp_vf0_rings_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct pci_dev *pdev;
	struct sdp_dev *sdp;

	pdev = to_pci_dev(dev);
	sdp = pci_get_drvdata(pdev);
	return sprintf(buf, "%d", sdp->info.vf_rings[0]);
}
static DEVICE_ATTR_RO(sdp_vf0_rings);

static ssize_t sdp_vfx_rings_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct pci_dev *pdev;
	struct sdp_dev *sdp;

	pdev = to_pci_dev(dev);
	sdp = pci_get_drvdata(pdev);
	return sprintf(buf, "%d", sdp->info.vf_rings[1]);
}
static DEVICE_ATTR_RO(sdp_vfx_rings);

static struct attribute *sdp_ring_attrs[] = {
	&dev_attr_sdp_vf0_rings.attr,
	&dev_attr_sdp_vfx_rings.attr,
	NULL
};

static struct attribute_group sdp_ring_attr_group = {
	.name = "sdp_ring_attr",
	.attrs = sdp_ring_attrs,
};

static int sdp_sysfs_init(struct device *dev)
{
	int ret;

	ret = sysfs_create_group(&dev->kobj, &sdp_ring_attr_group);
	if (ret < 0) {
		dev_err(dev, " create_domain sysfs failed\n");
		return ret;
	}

	return 0;
}

static void sdp_sysfs_remove(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &sdp_ring_attr_group);
}

static int get_chan_info(struct sdp_dev *sdp)
{
	struct sdp_get_chan_info_msg *rsp;
	struct msg_req *req;
	int res = 0;

	req = (struct msg_req *) otx2_mbox_alloc_msg(&sdp->afpf_mbox, 0, sizeof(*req));
	if (req == NULL) {
		dev_err(&sdp->pdev->dev, "RVU Mbox failed to alloc\n");
		return -EFAULT;
	}
	req->hdr.id = MBOX_MSG_GET_SDP_CHAN_INFO;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = RVU_PFFUNC(sdp->pf, 0);

	otx2_mbox_msg_send(&sdp->afpf_mbox, 0);
	res = otx2_mbox_wait_for_rsp(&sdp->afpf_mbox, 0);
	if (res == -EIO)
		dev_err(&sdp->pdev->dev, "RVU AF Mbox timeout\n");
	else if (res) {
		dev_err(&sdp->pdev->dev, "RVU Mbox error: %d\n", res);
		res = -EFAULT;
	}
	rsp = (struct sdp_get_chan_info_msg *)otx2_mbox_get_rsp(&sdp->afpf_mbox, 0,
								&req->hdr);
	sdp->chan_base = rsp->chan_base;
	sdp->num_chan = rsp->num_chan;

	return res;
}
static int send_chan_info(struct sdp_dev *sdp, struct sdp_node_info *info)
{
	struct sdp_chan_info_msg *cinfo;
	int res = 0;

	cinfo = (struct sdp_chan_info_msg *)
		otx2_mbox_alloc_msg(&sdp->afpf_mbox, 0, sizeof(*cinfo));
	if (cinfo == NULL) {
		dev_err(&sdp->pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}
	cinfo->hdr.id = MBOX_MSG_SET_SDP_CHAN_INFO;
	cinfo->hdr.sig = OTX2_MBOX_REQ_SIG;
	cinfo->hdr.pcifunc = RVU_PFFUNC(sdp->pf, 0);

	memcpy(&cinfo->info, info, sizeof(struct sdp_node_info));
	otx2_mbox_msg_send(&sdp->afpf_mbox, 0);
	res = otx2_mbox_wait_for_rsp(&sdp->afpf_mbox, 0);
	if (res == -EIO) {
		dev_err(&sdp->pdev->dev, "RVU AF MBOX timeout.\n");
	} else if (res) {
		dev_err(&sdp->pdev->dev, "RVU MBOX error: %d.\n", res);
		res = -EFAULT;
	}

	return res;
}

static void program_sdp_rinfo(struct sdp_dev *sdp)
{
	u32 rppf, rpvf, numvf, pf_srn, npfs, npfs_per_pem, epf_srn;
	void __iomem *addr;
	u32 mac, mac_mask;
	u64 cfg, val, pkg_ver;
	u64 ep_pem, valid_ep_pem_mask, npem, epf_base;
	u32 vf, ring, epf, epvf;

	/* TODO npfs should be obtained from dts */
	npfs_per_pem = NUM_PFS_PER_PEM;

	/* PF doesn't have any rings */
	rppf = sdp->info.vf_rings[0];
	rpvf = sdp->info.vf_rings[1];
	numvf = sdp->info.max_vfs - 1;

	pf_srn = sdp->info.pf_srn;

	dev_info(&sdp->pdev->dev, "rppf:%u rpvf:%u numvf:%u pf_srn:%u\n", rppf,
		 rpvf, numvf, pf_srn);

	mac_mask = MAC_MASK_96XX;
	switch (sdp->pdev->subsystem_device) {
	case PCI_SUBSYS_DEVID_96XX:
		valid_ep_pem_mask = VALID_EP_PEMS_MASK_96XX;
		addr = ioremap(GPIO_PKG_VER, 8);
		pkg_ver = readq(addr);
		iounmap(addr);
		if (pkg_ver == CN93XXN_PKG)
			valid_ep_pem_mask = VALID_EP_PEMS_MASK_93XX;
		break;
	case PCI_SUBSYS_DEVID_95XXO:
	case PCI_SUBSYS_DEVID_95XXN:
		valid_ep_pem_mask = VALID_EP_PEMS_MASK_95XX;
		break;
	case PCI_SUBSYS_DEVID_98XX:
		if (sdp->info.node_id == 0)
			valid_ep_pem_mask = VALID_EP_PEMS_MASK_98XX_SDP0;
		else
			valid_ep_pem_mask = VALID_EP_PEMS_MASK_98XX_SDP1;
		mac_mask = MAC_MASK_98XX;
		break;
	case PCI_SUBSYS_DEVID_CN10K_A:
	case PCI_SUBSYS_DEVID_CNF10K_A:
	case PCI_SUBSYS_DEVID_CNF10K_B:
		valid_ep_pem_mask = VALID_EP_PEMS_MASK_106XX;
		mac_mask = MAC_MASK_CN10K;
		break;
	default:
		dev_err(&sdp->pdev->dev,
			"Failed to set SDP ring info: unsupported platform\n");
		break;
	}
	sdp->valid_ep_pem_mask = valid_ep_pem_mask;
	sdp->mac_mask = mac_mask;
	npem = 0;
	epf_srn = 0;

	for (ep_pem = 0; ep_pem < MAX_PEMS; ep_pem++) {
		if (!(valid_ep_pem_mask & (1ul << ep_pem)))
			continue;
		addr  = ioremap(PEMX_CFG(ep_pem), 8);
		cfg = readq(addr);
		iounmap(addr);
		if ((!((cfg >> PEMX_CFG_LANES_BIT_POS) &
		       PEMX_CFG_LANES_BIT_MASK)) ||
		    ((cfg >> PEMX_CFG_HOSTMD_BIT_POS) &
		     PEMX_CFG_HOSTMD_BIT_MASK))
			continue;
		/* found the PEM in endpoint mode */
		epf_base = 0;
		if (sdp->pdev->subsystem_device !=
		    PCI_SUBSYS_DEVID_98XX)
			val = (((u64)rppf << RPPF_BIT_96XX) |
			       ((u64)pf_srn << PF_SRN_BIT_96XX) |
			       ((u64)npfs_per_pem << NPFS_BIT_96XX));
		else
			val = (((u64)rppf << RPPF_BIT_98XX) |
			       ((u64)pf_srn << PF_SRN_BIT_98XX) |
			       ((u64)npfs_per_pem << NPFS_BIT_98XX));
		mac = ep_pem & mac_mask;
		writeq(val, sdp->sdp_base + SDPX_MACX_PF_RING_CTL(mac));

		epf_srn = npfs_per_pem * rppf;
		for (npfs = 0; npfs < npfs_per_pem; npfs++) {
			val = (((u64)numvf << RINFO_NUMVF_BIT) |
			       ((u64)rpvf << RINFO_RPVF_BIT) |
			       ((u64)(epf_srn) << RINFO_SRN_BIT));
			writeq(val,
			       sdp->sdp_base +
			       SDPX_EPFX_RINFO((epf_base +
						(npem * MAX_PFS_PER_PEM))));
			epf_srn += numvf * rpvf;
			epf_base++;
		}
		npem++;
	}
}

static void set_firmware_ready(struct sdp_dev *sdp)
{
	u32 npfs, npfs_per_pem;
	void __iomem *addr;
	u64 ep_pem, val;
	u64 cfg;

	/* TODO: add support for 10K model */
	/* TODO npfs should be obtained from dts */
	npfs_per_pem = NUM_PFS_PER_PEM;
	for (ep_pem = 0; ep_pem < MAX_PEMS; ep_pem++) {
		if (!(sdp->valid_ep_pem_mask & (1ul << ep_pem)))
			continue;
		addr  = ioremap(PEMX_CFG(ep_pem), 8);
		cfg = readq(addr);
		iounmap(addr);
		if ((!((cfg >> PEMX_CFG_LANES_BIT_POS) &
		       PEMX_CFG_LANES_BIT_MASK)) ||
		    ((cfg >> PEMX_CFG_HOSTMD_BIT_POS) &
		     PEMX_CFG_HOSTMD_BIT_MASK))
			continue;
		/* found the PEM in endpoint mode */
		for (npfs = 0; npfs < npfs_per_pem; npfs++) {
			addr  = ioremap(PEMX_CFG_WR(ep_pem), 8);
			val = ((FW_STATUS_READY << PEMX_CFG_WR_DATA) |
			       (npfs << PEMX_CFG_WR_PF) |
			       (1 << 15) |
			       (PCIEEP_VSECST_CTL << PEMX_CFG_WR_REG));
			writeq(val, addr);
		}
	}
}

static int sdp_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	uint64_t inst, sdp_gbl_ctl;
	struct sdp_dev *sdp;
	uint64_t regval;
	int err;

	sdp = devm_kzalloc(dev, sizeof(struct sdp_dev), GFP_KERNEL);
	if (sdp == NULL)
		return -ENOMEM;

	sdp->pdev = pdev;
	pci_set_drvdata(pdev, sdp);

	mutex_init(&sdp->lock);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto enable_failed;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto map_failed;
	}

	if (pci_sriov_get_totalvfs(pdev) <= 0) {
		err = -ENODEV;
		goto set_mask_failed;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to set DMA mask\n");
		goto set_mask_failed;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to set DMA mask\n");
		goto set_mask_failed;
	}

	pci_set_master(pdev);

	/* CSR Space mapping */
	sdp->bar2 = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM,
			       pci_resource_len(pdev, PCI_CFG_REG_BAR_NUM));
	if (!sdp->bar2) {
		dev_err(&pdev->dev, "Unable to map BAR2\n");
		err = -ENODEV;
		goto set_mask_failed;
	}

	err = sdp_check_pf_usable(sdp);
	if (err)
		goto pf_unusable;

	/* Map SDP register area */
	/* right now only 2 SDP blocks are supported */
	inst = list_empty(&sdp_dev_lst_head) ? 0 : 1;
	sdp->sdp_base = ioremap(SDP_BASE(inst), SDP_REG_SIZE);
	if (!sdp->sdp_base) {
		dev_err(&pdev->dev, "Unable to map SDP CSR space\n");
		err = -ENODEV;
		goto pf_unusable;
	}
	/* Map PF-AF mailbox memory */
	sdp->af_mbx_base = ioremap_wc(pci_resource_start(pdev, MBOX_BAR_NUM),
				     pci_resource_len(pdev, MBOX_BAR_NUM));
	if (!sdp->af_mbx_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		err = -ENODEV;
		goto pf_unusable;
	}

	/* Request IRQ for PF-VF mailbox here - TBD: check if this can be moved
	 * to sriov enable function
	 */
	if (sdp_alloc_irqs(pdev)) {
		dev_err(&pdev->dev,
			"Unable to allocate MSIX Interrupt vectors\n");
		err = -ENODEV;
		goto alloc_irqs_failed;
	}

	if (sdp_register_mbox_irq(pdev) != 0) {
		dev_err(&pdev->dev,
			"Unable to allocate MBOX Interrupt vectors\n");
		err = -ENODEV;
		goto reg_mbox_irq_failed;
	}

	if (sdp_register_flr_irq(pdev) != 0) {
		dev_err(&pdev->dev,
			"Unable to allocate FLR Interrupt vectors\n");
		err = -ENODEV;
		goto reg_flr_irq_failed;
	}

	enable_af_mbox_int(pdev);

	if (sdp_get_pcifunc(sdp)) {
		dev_err(&pdev->dev,
			"Failed to retrieve pcifunc from AF\n");
		err = -ENODEV;
		goto get_pcifunc_failed;
	}

	err = get_chan_info(sdp);
	if (err) {
		dev_err(&pdev->dev, "SDP get channel info failed\n");
		goto get_chan_info_failed;
	}

	dev_info(&sdp->pdev->dev, "SDP chan base: 0x%x, num chan: 0x%x\n",
		 sdp->chan_base, sdp->num_chan);

	/* From cn10k onwards the SDP channel configuration is programmable */
	if (pdev->subsystem_device >= PCI_SUBSYS_DEVID_CN10K_A) {
		regval = sdp->chan_base;
		regval |= ilog2(sdp->num_chan) << 16;
		writeq(regval, sdp->sdp_base + SDPX_LINK_CFG);
	}

	err = sdp_parse_rinfo(pdev, &sdp->info);
	if (err) {
		err = -EINVAL;
		goto get_rinfo_failed;
	}

	/* To differentiate a PF between SDP0 or SDP1 we make use of the
	 * revision ID field in the config space. The revision is filled
	 * by the firmware. The lower 4 bits field is used here.
	 * 0 means SDP0
	 * 1 means SDP1
	 */
	if (pdev->revision & 0x0F)
		sdp->info.node_id = 1;
	else
		sdp->info.node_id = 0;


	/*
	 * For 98xx there are 2xSDPs so start the PF ring from 128 for SDP1
	 * SDP0 has PCI revid 0 and SDP1 has PCI revid 1
	 */
	sdp->info.pf_srn = (pdev->revision & 0x0F) ? 128 : sdp->info.pf_srn;

	err = send_chan_info(sdp, &sdp->info);
	if (err) {
		err = -EINVAL;
		goto get_rinfo_failed;
	}

	program_sdp_rinfo(sdp);

	/* Water mark for backpressuring NIX Tx when enabled */
	if (pdev->subsystem_device >= PCI_SUBSYS_DEVID_CN10K_A)
		writeq(SDP_PPAIR_THOLD, sdp->sdp_base + SDPX_OUT_WMARK);
	sdp_gbl_ctl = readq(sdp->sdp_base + SDPX_GBL_CONTROL);
	sdp_gbl_ctl |= (1 << 2); /* BPFLR_D disable clearing BP in FLR */
	writeq(sdp_gbl_ctl, sdp->sdp_base + SDPX_GBL_CONTROL);

	/* Add to global list of PFs found */
	err = sdp_sysfs_init(&sdp->pdev->dev);
	if (err != 0) {
		err = -ENODEV;
		dev_info(&sdp->pdev->dev, "Sysfs init failed\n");
	}
	sdp_sriov_configure(sdp->pdev, sdp->info.max_vfs);
	set_firmware_ready(sdp);

	spin_lock(&sdp_lst_lock);
	list_add(&sdp->list, &sdp_dev_lst_head);
	spin_unlock(&sdp_lst_lock);

	return 0;

get_chan_info_failed:
get_rinfo_failed:
get_pcifunc_failed:
	disable_af_mbox_int(pdev);
	sdp_free_flr_irq(pdev);
reg_flr_irq_failed:
	sdp_afpf_mbox_term(pdev);
reg_mbox_irq_failed:
	sdp_free_irqs(pdev);
alloc_irqs_failed:
	iounmap(sdp->af_mbx_base);
pf_unusable:
	pcim_iounmap(pdev, sdp->bar2);
set_mask_failed:
	pci_release_regions(pdev);
map_failed:
	pci_disable_device(pdev);
enable_failed:
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, sdp);
	return err;
}

static void enable_vf_flr_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits, idx;

	sdp = pci_get_drvdata(pdev);

	/* Clear any pending interrupts */
	for (idx = 0; idx  < 2; idx++) {
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(idx),
			    ~0x0ULL);
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(idx),
			    ~0x0ULL);
	}

	/* Enable for FLR interrupts for VFs */
	if (sdp->num_vfs > 64) {
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(0),
			    GENMASK_ULL(63, 0));
		ena_bits = (sdp->num_vfs - 64) - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(1),
			   GENMASK_ULL(ena_bits, 0));
	} else {
		ena_bits = sdp->num_vfs - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(0),
			    GENMASK_ULL(ena_bits, 0));
	}
}

static void disable_vf_flr_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits, idx;

	sdp = pci_get_drvdata(pdev);

	/* Clear any pending interrupts */
	for (idx = 0; idx  < 2; idx++) {
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(idx),
			    ~0x0ULL);
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(idx),
			    ~0x0ULL);
	}

	/* Disable the FLR interrupts for VFs */
	if (sdp->num_vfs > 64) {
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(0),
			    GENMASK_ULL(63, 0));
		ena_bits = (sdp->num_vfs - 64) - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(1),
			   GENMASK_ULL(ena_bits, 0));
	} else {
		ena_bits = sdp->num_vfs - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(0),
			    GENMASK_ULL(ena_bits, 0));
	}
}

static void enable_vf_mbox_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits, idx;

	sdp = pci_get_drvdata(pdev);

	/* Clear any pending interrupts */
	for (idx = 0; idx < 2; idx++) {
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(idx),
			    ~0x0ULL);
	}

	/* Enable VF MBOX interrupts */
	if (sdp->num_vfs > 64) {
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0),
			    GENMASK_ULL(63, 0));
		ena_bits = (sdp->num_vfs - 64) - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			   RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
			   GENMASK_ULL(ena_bits, 0));
	} else {
		ena_bits = sdp->num_vfs - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0),
			    GENMASK_ULL(ena_bits, 0));
	}
}

static void disable_vf_mbox_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits, idx;

	sdp = pci_get_drvdata(pdev);

	/* Clear any pending interrupts */
	for (idx = 0; idx < 2; idx++) {
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(idx),
			    ~0x0ULL);
	}

	/* Disable the MBOX interrupts for VFs */
	if (sdp->num_vfs > 64) {
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0),
			    GENMASK_ULL(63, 0));
		ena_bits = (sdp->num_vfs - 64) - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			   RVU_PF_VFPF_MBOX_INT_ENA_W1CX(1),
			   GENMASK_ULL(ena_bits, 0));
	} else {
		ena_bits = sdp->num_vfs - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			   RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0),
			   GENMASK_ULL(ena_bits, 0));
	}
}

static int __sriov_disable(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;

	sdp = pci_get_drvdata(pdev);
	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev, "Disabing VFs while VFs are assigned\n");
		dev_err(&pdev->dev, "VFs will not be freed\n");
		return -EPERM;
	}

	disable_vf_flr_int(pdev);
	disable_vf_mbox_int(pdev);

	if (sdp->pfvf_mbox_wq) {
		destroy_workqueue(sdp->pfvf_mbox_wq);
		sdp->pfvf_mbox_wq = NULL;
	}
	if (sdp->pfvf_mbx_base) {
		iounmap(sdp->pfvf_mbx_base);
		sdp->pfvf_mbx_base = NULL;
	}

	otx2_mbox_destroy(&sdp->pfvf_mbox);
	otx2_mbox_destroy(&sdp->pfvf_mbox_up);

	pci_disable_sriov(pdev);

	kfree(sdp->vf_info);
	sdp->vf_info = NULL;

	return 0;
}

static int __sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	struct rvu_vf *vf_ptr;
	int curr_vfs, vf = 0;
	struct sdp_dev *sdp;
	u64 pf_vf_mbox_base;
	int err;

	curr_vfs = pci_num_vf(pdev);
	if (!curr_vfs && !num_vfs)
		return -EINVAL;

	if (curr_vfs) {
		dev_err(
		    &pdev->dev,
		    "Virtual Functions are already enabled on this device\n");
		return -EINVAL;
	}
	if (num_vfs > SDP_MAX_VFS)
		num_vfs = SDP_MAX_VFS;

	sdp = pci_get_drvdata(pdev);

	if (sdp_get_available_rsrcs(sdp)) {
		dev_err(&pdev->dev, "Failed to get resource limits.\n");
		return -EFAULT;
	}

	sdp->vf_info = kcalloc(num_vfs, sizeof(struct rvu_vf), GFP_KERNEL);
	if (sdp->vf_info == NULL)
		return -ENOMEM;

	sdp->num_vfs = num_vfs;

	/* Map PF-VF mailbox memory.
	 * On CN10K platform, PF <-> VF mailbox region follows after
	 * PF <-> AF mailbox region.
	 */
	if (pdev->subsystem_device == PCI_SUBSYS_DEVID_CN10K_A)
		pf_vf_mbox_base = pci_resource_start(pdev, PCI_MBOX_BAR_NUM) + MBOX_SIZE;
	else
		pf_vf_mbox_base = readq((void __iomem *)((u64)sdp->bar2 +
							 RVU_PF_VF_BAR4_ADDR));

	if (!pf_vf_mbox_base) {
		dev_err(&pdev->dev, "PF-VF Mailbox address not configured\n");
		err = -ENOMEM;
		goto err_mbox_mem_map;
	}
	sdp->pfvf_mbx_base = ioremap_wc(pf_vf_mbox_base, MBOX_SIZE * num_vfs);
	if (!sdp->pfvf_mbx_base) {
		dev_err(&pdev->dev,
			"Mapping of PF-VF mailbox address failed\n");
		err = -ENOMEM;
		goto err_mbox_mem_map;
	}
	err = otx2_mbox_init(&sdp->pfvf_mbox, sdp->pfvf_mbx_base, pdev,
			     sdp->bar2, MBOX_DIR_PFVF, num_vfs);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to initialize PF/VF MBOX for %d VFs\n",
			num_vfs);
		goto err_mbox_init;
	}

	err = otx2_mbox_init(&sdp->pfvf_mbox_up, sdp->pfvf_mbx_base, pdev,
			     sdp->bar2, MBOX_DIR_PFVF_UP, num_vfs);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to initialize PF/VF MBOX UP for %d VFs\n",
			num_vfs);
		goto err_mbox_up_init;
	}

	/* Allocate a single workqueue for VF/PF mailbox because access to
	 * AF/PF mailbox has to be synchronized.
	 */
	sdp->pfvf_mbox_wq =
		alloc_workqueue("sdp_pfvf_mailbox",
				WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 1);
	if (sdp->pfvf_mbox_wq == NULL) {
		dev_err(&pdev->dev,
			"Workqueue allocation failed for PF-VF MBOX\n");
		err = -ENOMEM;
		goto err_workqueue_alloc;
	}

	for (vf = 0; vf < num_vfs; vf++) {
		vf_ptr = &sdp->vf_info[vf];
		vf_ptr->vf_id = vf;
		vf_ptr->sdp = (void *)sdp;
		vf_ptr->intr_idx = vf % 64;
		INIT_WORK(&vf_ptr->mbox_wrk, sdp_pfvf_mbox_handler);
		INIT_WORK(&vf_ptr->mbox_wrk_up, sdp_pfvf_mbox_handler_up);
		INIT_WORK(&vf_ptr->pfvf_flr_work, sdp_pfvf_flr_handler);
	}

	enable_vf_mbox_int(pdev);
	enable_vf_flr_int(pdev);

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable to SRIOV VFs: %d\n", err);
		goto err_enable_sriov;
	}

	return num_vfs;

err_enable_sriov:
	disable_vf_flr_int(pdev);
	disable_vf_mbox_int(pdev);
err_workqueue_alloc:
	destroy_workqueue(sdp->pfvf_mbox_wq);
	if (sdp->pfvf_mbox_up.dev != NULL)
		otx2_mbox_destroy(&sdp->pfvf_mbox_up);
err_mbox_up_init:
	if (sdp->pfvf_mbox.dev != NULL)
		otx2_mbox_destroy(&sdp->pfvf_mbox);
err_mbox_init:
	iounmap(sdp->pfvf_mbx_base);
err_mbox_mem_map:
	kfree(sdp->vf_info);

	return err;
}

static int sdp_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return __sriov_disable(pdev);
	else
		return __sriov_enable(pdev, num_vfs);
}

static void sdp_remove(struct pci_dev *pdev)
{
	struct sdp_dev *sdp = pci_get_drvdata(pdev);


	spin_lock(&sdp_lst_lock);
	list_del(&sdp->list);
	spin_unlock(&sdp_lst_lock);

	sdp_sysfs_remove(&pdev->dev);

	if (sdp->num_vfs)
		__sriov_disable(pdev);

	disable_af_mbox_int(pdev);
	sdp_free_flr_irq(pdev);
	sdp_afpf_mbox_term(pdev);
	sdp_free_irqs(pdev);

	if (sdp->af_mbx_base)
		iounmap(sdp->af_mbx_base);
	if (sdp->bar2)
		pcim_iounmap(pdev, sdp->bar2);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	devm_kfree(&pdev->dev, sdp);
}

static struct pci_driver sdp_driver = {
	.name = DRV_NAME,
	.id_table = rvu_sdp_id_table,
	.probe = sdp_probe,
	.remove = sdp_remove,
	.sriov_configure = sdp_sriov_configure,
};

static int __init otx2_sdp_init_module(void)
{
	pr_info("%s\n", DRV_NAME);

	spin_lock_init(&sdp_lst_lock);
	return pci_register_driver(&sdp_driver);
}

static void __exit otx2_sdp_exit_module(void)
{
	pci_unregister_driver(&sdp_driver);
}

module_init(otx2_sdp_init_module);
module_exit(otx2_sdp_exit_module);
