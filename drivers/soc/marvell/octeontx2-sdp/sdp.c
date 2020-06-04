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

#define FW_TO_HOST 0x2
#define HOST_TO_FW 0x1

union ring {
	u64 u;
	struct {
		u64 dir:2;
		u64 rpvf:4;
		u64 rppf:6;
		u64 numvf:8;
		u64 rsvd:16;
		u64 raz:28;
	} s;
};

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
struct host_hs_work {
	struct delayed_work sdp_work;
	struct workqueue_struct *sdp_host_handshake;
	struct sdp_dev *sdp;
};
struct host_hs_work hs_work;
static int sdp_sriov_configure(struct pci_dev *pdev, int num_vfs);

static u32 num_vf0_rings, num_vfx_rings, max_vfs;
static u32 neg_vf0_rings, neg_vfx_rings, neg_vf;

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
check_attach_rsrcs_req(struct sdp_dev *sdp, struct rvu_vf *vf,
		       struct mbox_msghdr *req, int size)
{
	struct rsrc_attach *rsrc_req;

	rsrc_req = (struct rsrc_attach *)req;
	return forward_to_mbox(sdp, &sdp->afpf_mbox, 0, req, size, "AF");
}

static int
handle_vf_req(struct sdp_dev *sdp, struct rvu_vf *vf, struct mbox_msghdr *req,
	      int size)
{
	int err = 0;

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
		err = check_attach_rsrcs_req(sdp, vf, req, size);
		break;
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
			"PF%02d_VF_FLR_IRQ%d", pdev->devfn, i);
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

	flush_workqueue(sdp->afpf_mbox_wq);
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

static int sdp_parse_rinfo(void)
{
	struct device_node *dev;
	const void *ptr;
	int len;

	dev = of_find_node_by_name(NULL, "rvu-sdp");
	if (dev == NULL) {
		pr_info("can't find FDT dev %s\n", "rvu-sdp");
		return -1;
	}

	ptr = of_get_property(dev, "num-vf0-rings", &len);
	if (ptr == NULL) {
		pr_info("Error: Failed to get property\n");
		return -1;
	}

	if (len == 4) {
		num_vf0_rings = be32_to_cpup((u32 *)ptr);
	} else {
		pr_info("SDP DTSi info: Wrong field length\n");
		return -1;
	}

	ptr = of_get_property(dev, "num-vfx-rings", &len);
	if (ptr == NULL) {
		pr_info("Error: Failed to get property\n");
		return -1;
	}

	if (len == 4) {
		num_vfx_rings = be32_to_cpup((u32 *)ptr);
	} else {
		pr_info("SDP DTSi info: Wrong field length\n");
		return -1;
	}

	ptr = of_get_property(dev, "num-rvu-vfs", &len);
	if (ptr == NULL) {
		pr_info("Error: Failed to get property\n");
		return -1;
	}

	if (len == 4) {
		max_vfs = be32_to_cpup((u32 *)ptr);
	} else {
		pr_info("SDP DTSi info: Wrong field length\n");
		return -1;
	}

	return 0;
}

static ssize_t sdp_vf0_rings_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%d", neg_vf0_rings);
}
static DEVICE_ATTR_RO(sdp_vf0_rings);

static ssize_t sdp_vfx_rings_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%d", neg_vfx_rings);
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

int sdp_sysfs_init(struct device *dev)
{
	int ret;

	ret = sysfs_create_group(&dev->kobj, &sdp_ring_attr_group);
	if (ret < 0) {
		dev_err(dev, " create_domain sysfs failed\n");
		return ret;
	}

	return 0;
}

void sdp_sysfs_remove(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &sdp_ring_attr_group);
}

static void sdp_host_handshake_fn(struct work_struct *wrk)
{
	struct host_hs_work *container_work;
	union ring host_rinfo;
	struct sdp_dev *sdp;
	int err;

	container_work = container_of(wrk, struct host_hs_work, sdp_work.work);
	sdp = container_work->sdp;
	host_rinfo.u = readq(sdp->sdp_base + SDPX_RINGX_IN_PKT_CNT(0));
	if (host_rinfo.s.dir == HOST_TO_FW) {
		neg_vf0_rings = host_rinfo.s.rppf;
		neg_vfx_rings = host_rinfo.s.rpvf;
		neg_vf = host_rinfo.s.numvf;
		dev_info(&sdp->pdev->dev, "Negotiated VF0 rings:%d VFx rings%d VFs:%d\n",
			 neg_vf0_rings, neg_vfx_rings, neg_vf);
		host_rinfo.s.dir = FW_TO_HOST;
		writeq(host_rinfo.u,
			       sdp->sdp_base + SDPX_RINGX_IN_PKT_CNT(0));

		err = sdp_sysfs_init(&sdp->pdev->dev);
		if (err != 0) {
			err = -ENODEV;
			dev_info(&sdp->pdev->dev, "Sysfs init failed\n");
		}
		sdp_sriov_configure(sdp->pdev, neg_vf + 1);

		return;
	}

	queue_delayed_work(container_work->sdp_host_handshake,
			   &container_work->sdp_work,  HZ * 1);
}

static int sdp_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct sdp_dev *sdp;
	union ring fw_rinfo;
	int err;
	uint64_t inst;

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

	err = sdp_parse_rinfo();
	if (err) {
		err = -EINVAL;
		goto get_rinfo_failed;
	}

	fw_rinfo.u = 0;
	fw_rinfo.s.dir = FW_TO_HOST;
	fw_rinfo.s.rppf = num_vf0_rings;
	fw_rinfo.s.rpvf = num_vfx_rings;
	fw_rinfo.s.numvf = max_vfs-1;

	dev_info(&pdev->dev, "Ring info 0x%llx\n", fw_rinfo.u);
	writeq(fw_rinfo.u, sdp->sdp_base + SDPX_RINGX_IN_PKT_CNT(0));

	hs_work.sdp = sdp;
	hs_work.sdp_host_handshake = alloc_workqueue("sdp_epmode_fw_hs",
						     WQ_MEM_RECLAIM, 0);
	INIT_DELAYED_WORK(&hs_work.sdp_work, sdp_host_handshake_fn);
	queue_delayed_work(hs_work.sdp_host_handshake, &hs_work.sdp_work, 0);

	/* Add to global list of PFs found */
	spin_lock(&sdp_lst_lock);
	list_add(&sdp->list, &sdp_dev_lst_head);
	spin_unlock(&sdp_lst_lock);

	return 0;

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
	int ena_bits;

	sdp = pci_get_drvdata(pdev);
	/* Clear any pending interrupts */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0), ~0x0ULL);
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0), ~0x0ULL);

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1), ~0x0ULL);
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1),
			    ~0x0ULL);
	}

	/* Enable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((sdp->num_vfs - 1) % 64);
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(0),
		   GENMASK_ULL(ena_bits, 0));

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = sdp->num_vfs - 64 - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(1),
			   GENMASK_ULL(ena_bits, 0));
	}
}

static void disable_vf_flr_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits;
	u64 intr;

	sdp = pci_get_drvdata(pdev);
	/* clear any pending interrupt */

	intr = sdp_read64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0));
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0), intr);
	intr = sdp_read64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0));
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0), intr);

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		intr = sdp_read64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1));
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1), intr);
		intr = sdp_read64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1));
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1), intr);
	}

	/* Disable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((sdp->num_vfs - 1) % 64);

	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(0),
		   GENMASK_ULL(ena_bits, 0));

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = sdp->num_vfs - 64 - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(1),
			   GENMASK_ULL(ena_bits, 0));
	}
}

static void enable_vf_mbox_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits;

	sdp = pci_get_drvdata(pdev);
	/* Clear any pending interrupts */
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0), ~0x0ULL);

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(1),
			   ~0x0ULL);
	}

	/* Enable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((sdp->num_vfs - 1) % 64);
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0),
		   GENMASK_ULL(ena_bits, 0));

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = sdp->num_vfs - 64 - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			   RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
			   GENMASK_ULL(ena_bits, 0));
	}
}

static void disable_vf_mbox_int(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int ena_bits;
	u64 intr;

	sdp = pci_get_drvdata(pdev);
	/* clear any pending interrupt */

	intr = sdp_read64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0));
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0), intr);

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		intr = sdp_read64(sdp, BLKADDR_RVUM, 0,
				  RVU_PF_VFPF_MBOX_INTX(1));
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INTX(1), intr);
	}

	/* Disable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((sdp->num_vfs - 1) % 64);
	sdp_write64(sdp, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0),
			GENMASK_ULL(ena_bits, 0));

	if (sdp->num_vfs > 64) { /* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = sdp->num_vfs - 64 - 1;
		sdp_write64(sdp, BLKADDR_RVUM, 0,
			   RVU_PF_VFPF_MBOX_INT_ENA_W1CX(1),
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
		flush_workqueue(sdp->pfvf_mbox_wq);
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

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable to SRIOV VFs: %d\n", err);
		goto err_enable_sriov;
	}

	sdp->num_vfs = num_vfs;

	/* Map PF-VF mailbox memory */
	pf_vf_mbox_base = (u64)sdp->bar2 + RVU_PF_VF_BAR4_ADDR;
	pf_vf_mbox_base = readq((void __iomem *)(unsigned long)pf_vf_mbox_base);
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
	return num_vfs;

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
	pci_disable_sriov(pdev);
err_enable_sriov:
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

	flush_workqueue(hs_work.sdp_host_handshake);
	destroy_workqueue(hs_work.sdp_host_handshake);

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
