// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 NPA driver
 *
 * Copyright (C) 2020 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/of.h>
#include <linux/if_vlan.h>
#include <linux/mutex.h>
#include <net/ip.h>
#include <linux/iommu.h>
#include "rvu_reg.h"
#include "mbox.h"
#include "npa.h"
#include "npa_api.h"

#define DRV_NAME "octeontx2-npapf"
#define DRV_VERSION "1.0"
#define DRV_STRING "Marvell OcteonTX2 NPA Physical Function Driver"
#define PCI_DEVID_OCTEONTX2_RVU_NPA_PF 0xA0FB

/* Supported devices */
static const struct pci_device_id otx2_npa_pf_id_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_RVU_NPA_PF)},
	{0,}			/* end of table */
};

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION(DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, otx2_npa_pf_id_table);

/* All PF devices found are stored here */
static spinlock_t npa_lst_lock;
LIST_HEAD(npa_dev_lst_head);
static DECLARE_BITMAP(pf_bmp, NPA_MAX_PFS);
static struct npa_dev_t *gnpa_pf_dev[NPA_MAX_PFS] = { NULL };

static void npa_write64(struct npa_dev_t *rvu, u64 b, u64 s, u64 o, u64 v)
{
	writeq_relaxed(v,
		       rvu->mmio[NPA_REG_BASE].hw_addr +
		       ((b << 20) | (s << 12) | o));
}

static u64 npa_read64(struct npa_dev_t *rvu, u64 b, u64 s, u64 o)
{
	return readq_relaxed(rvu->mmio[NPA_REG_BASE].hw_addr +
			     ((b << 20) | (s << 12) | o));
}

static int
forward_to_mbox(struct npa_dev_t *npa, struct otx2_mbox *mbox, int devid,
		struct mbox_msghdr *req, int size, const char *mstr)
{
	struct mbox_msghdr *msg;
	int res = 0;

	msg = otx2_mbox_alloc_msg(mbox, devid, size);
	if (msg == NULL)
		return -ENOMEM;

	memcpy((uint8_t *) msg + sizeof(struct mbox_msghdr),
	       (uint8_t *) req + sizeof(struct mbox_msghdr), size);
	msg->id = req->id;
	msg->pcifunc = req->pcifunc;
	msg->sig = req->sig;
	msg->ver = req->ver;
	msg->rc = req->rc;

	otx2_mbox_msg_send(mbox, devid);
	res = otx2_mbox_wait_for_rsp(mbox, devid);
	if (res == -EIO) {
		dev_err(&npa->pdev->dev, "RVU %s MBOX timeout.\n", mstr);
		goto err;
	} else if (res) {
		dev_err(&npa->pdev->dev, "RVU %s MBOX error: %d.\n", mstr, res);
		res = -EFAULT;
		goto err;
	}

	return 0;
err:
	return res;
}

static int
handle_af_req(struct npa_dev_t *npa, struct rvu_vf *vf, struct mbox_msghdr *req,
	      int size)
{
	/* We expect a request here */
	if (req->sig != OTX2_MBOX_REQ_SIG) {
		dev_err(&npa->pdev->dev,
			"UP MBOX msg with wrong signature %x, ID 0x%x\n",
			req->sig, req->id);
		return -EINVAL;
	}

	/* If handling notifs in PF is required,add a switch-case here. */
	return forward_to_mbox(npa, &npa->pfvf_mbox_up, vf->vf_id, req, size,
			       "VF");
}

static void npa_afpf_mbox_up_handler(struct work_struct *work)
{
	/* TODO: List MBOX uphandler operations */
	struct npa_dev_t *npa_pf_dev;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	struct otx2_mbox *mbox;
	int offset, id, err;
	struct rvu_vf *vf;
	u16 vf_id;

	npa_pf_dev = container_of(work, struct npa_dev_t, mbox_wrk_up);
	mbox = &npa_pf_dev->afpf_mbox_up;
	mdev = &mbox->dev[0];
	/* sync with mbox memory region */
	smp_rmb();

	/* Process received mbox messages */
	req_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	offset = ALIGN(sizeof(*req_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < req_hdr->num_msgs; id++) {
		msg = (struct mbox_msghdr *)(mdev->mbase + mbox->rx_start +
					     offset);

		if ((msg->pcifunc >> RVU_PFVF_PF_SHIFT) !=
		    (npa_pf_dev->pcifunc >> RVU_PFVF_PF_SHIFT)
		    || (msg->pcifunc & RVU_PFVF_FUNC_MASK) <=
		    npa_pf_dev->num_vfs)
			err = -EINVAL;
		else {
			vf_id = msg->pcifunc & RVU_PFVF_FUNC_MASK;
			vf = &npa_pf_dev->vf_info[vf_id];
			err =
			    handle_af_req(npa_pf_dev, vf, msg,
					  msg->next_msgoff - offset);
		}

		if (err)
			otx2_reply_invalid_msg(mbox, 0, msg->pcifunc, msg->id);
		offset = msg->next_msgoff;
	}

	otx2_mbox_msg_send(mbox, 0);
}

static void npa_mbox_handler_msix_offset(struct npa_dev_t *pfvf,
					 struct msix_offset_rsp *rsp)
{
	pfvf->npa_msixoff = rsp->npa_msixoff;
}

static void npa_mbox_handler_lf_alloc(struct npa_dev_t *pfvf,
				      struct npa_lf_alloc_rsp *rsp)
{
	pfvf->stack_pg_ptrs = rsp->stack_pg_ptrs;
	pfvf->stack_pg_bytes = rsp->stack_pg_bytes;
}

static irqreturn_t otx2_afpf_mbox_intr_handler(int irq, void *pf_irq)
{
	struct npa_dev_t *npa_pf_dev = (struct npa_dev_t *)pf_irq;
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;

	/* Read latest mbox data */
	smp_rmb();

	mbox = &npa_pf_dev->afpf_mbox;
	mdev = &mbox->dev[0];
	hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	/* Handle PF => AF channel response */
	if (hdr->num_msgs)
		queue_work(npa_pf_dev->afpf_mbox_wq, &npa_pf_dev->mbox_wrk);

	mbox = &npa_pf_dev->afpf_mbox_up;
	mdev = &mbox->dev[0];
	hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	/* Handle AF => PF request */
	if (hdr->num_msgs)
		queue_work(npa_pf_dev->afpf_mbox_wq, &npa_pf_dev->mbox_wrk_up);

	/* Clear the IRQ */
	npa_write64(npa_pf_dev, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);

	return IRQ_HANDLED;
}

static inline void otx2_enable_afpf_mbox_intr(struct npa_dev_t *npa)
{
	/* Enable mailbox interrupt for msgs coming from AF.
	 * First clear to avoid spurious interrupts, if any.
	 */
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_INT, BIT_ULL(0));
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1S, BIT_ULL(0));
}

static inline void otx2_disable_afpf_mbox_intr(struct npa_dev_t *npa)
{
	/* Clear interrupt if any */
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_INT, BIT_ULL(0));
	/* Disable AF => PF mailbox IRQ */
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1C, BIT_ULL(0));
}

static int otx2_alloc_afpf_mbox_intr(struct npa_dev_t *npa)
{
	struct pci_dev *pdev;
	int err;

	pdev = npa->pdev;
	/* Register PF-AF interrupt handler */
	sprintf(&npa->irq_names[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE],
		"PF%02d_AF_MBOX_IRQ", pdev->devfn);
	err =
	    request_irq(pci_irq_vector
			(npa->pdev, RVU_PF_INT_VEC_AFPF_MBOX),
			otx2_afpf_mbox_intr_handler, 0,
			&npa->irq_names[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE],
			npa);
	if (err) {
		dev_err(&npa->pdev->dev,
			"RVUPF: IRQ registration failed for PFAF mbox irq\n");
		return err;
	}

	otx2_enable_afpf_mbox_intr(npa);

	return 0;
}

static void otx2_free_afpf_mbox_intr(struct npa_dev_t *npa)
{
	int vector = pci_irq_vector(npa->pdev, RVU_PF_INT_VEC_AFPF_MBOX);

	otx2_disable_afpf_mbox_intr(npa);
	free_irq(vector, npa);
}

static void otx2_process_afpf_mbox_msg(struct npa_dev_t *npa_pf_dev,
				       struct mbox_msghdr *msg, int size)
{
	struct otx2_mbox *vf_mbx;
	struct mbox_msghdr *fwd;
	struct device *dev;
	struct rvu_vf *vf;
	int vf_id;

	dev = &npa_pf_dev->pdev->dev;
	if (msg->id >= MBOX_MSG_MAX) {
		dev_err(dev, "Mbox msg with unknown ID 0x%x\n", msg->id);
		return;
	}

	if (msg->sig != OTX2_MBOX_RSP_SIG) {
		dev_err(dev,
			"Mbox msg with wrong signature %x, ID 0x%x\n",
			msg->sig, msg->id);
		return;
	}

	/* message response heading VF */
	vf_id = msg->pcifunc & RVU_PFVF_FUNC_MASK;
	vf_mbx = &npa_pf_dev->pfvf_mbox;

	if (vf_id > 0) {
		if (vf_id > npa_pf_dev->num_vfs) {
			dev_err(&npa_pf_dev->pdev->dev,
				"MBOX msg to unknown VF: %d >= %d\n",
				vf_id, npa_pf_dev->num_vfs);
			return;
		}
		vf = &npa_pf_dev->vf_info[vf_id - 1];
		/* Ignore stale responses and VFs in FLR. */
		if (!vf->in_use || vf->got_flr)
			return;
		fwd = otx2_mbox_alloc_msg(vf_mbx, vf_id - 1, size);
		if (!fwd) {
			dev_err(&npa_pf_dev->pdev->dev,
				"Forwarding to VF%d failed.\n", vf_id);
			return;
		}
		memcpy((uint8_t *) fwd + sizeof(struct mbox_msghdr),
		       (uint8_t *) msg + sizeof(struct mbox_msghdr), size);
		fwd->id = msg->id;
		fwd->pcifunc = msg->pcifunc;
		fwd->sig = msg->sig;
		fwd->ver = msg->ver;
		fwd->rc = msg->rc;
	} else {
		switch (msg->id) {
		case MBOX_MSG_READY:
			npa_pf_dev->pcifunc = msg->pcifunc;
			break;
		case MBOX_MSG_MSIX_OFFSET:
			npa_mbox_handler_msix_offset(npa_pf_dev,
						     (struct msix_offset_rsp *)
						     msg);
			break;
		case MBOX_MSG_NPA_LF_ALLOC:
			npa_mbox_handler_lf_alloc(npa_pf_dev,
						  (struct npa_lf_alloc_rsp *)
						  msg);
			break;
		default:
			if (msg->rc)
				dev_err(&npa_pf_dev->pdev->dev,
					"Mbox msg response has err %d, ID 0x%x\n",
					msg->rc, msg->id);
			break;
		}
	}
}

static void npa_afpf_mbox_handler(struct work_struct *work)
{
	struct npa_dev_t *npa_pf_dev;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	struct otx2_mbox *mbox;
	int offset, id, size;

	npa_pf_dev = container_of(work, struct npa_dev_t, mbox_wrk);
	mbox = &npa_pf_dev->afpf_mbox;
	mdev = &mbox->dev[0];
	rsp_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;

	offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);
	for (id = 0; id < rsp_hdr->num_msgs; id++) {
		msg = (struct mbox_msghdr *)(mdev->mbase + mbox->rx_start + offset);
		size = msg->next_msgoff - offset;
		otx2_process_afpf_mbox_msg(npa_pf_dev, msg, size);
		offset = msg->next_msgoff;
		mdev->msgs_acked++;
	}

	otx2_mbox_reset(mbox, 0);
}

static int
reply_free_rsrc_cnt(struct npa_dev_t *npa, struct rvu_vf *vf,
		    struct mbox_msghdr *req, int size)
{
	struct free_rsrcs_rsp *rsp;

	rsp = (struct free_rsrcs_rsp *)otx2_mbox_alloc_msg(&npa->pfvf_mbox,
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
handle_vf_req(struct npa_dev_t *npa, struct rvu_vf *vf, struct mbox_msghdr *req,
	      int size)
{
	int err = 0;

	/* Check if valid, if not reply with a invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG) {
		dev_err(&npa->pdev->dev,
			"VF MBOX msg with wrong signature %x, ID 0x%x\n",
			req->sig, req->id);
		return -EINVAL;
	}

	if (req->ver < OTX2_MBOX_VERSION) {
		dev_err(&npa->pdev->dev,
			"VF MBOX msg with version %04x != %04x\n",
			req->ver, OTX2_MBOX_VERSION);
		return -EINVAL;
	}
	switch (req->id) {
	case MBOX_MSG_READY:
		vf->in_use = true;
		err = forward_to_mbox(npa, &npa->afpf_mbox, 0, req, size, "AF");
		break;
	case MBOX_MSG_FREE_RSRC_CNT:
		err = reply_free_rsrc_cnt(npa, vf, req, size);
		break;
	default:
		err = forward_to_mbox(npa, &npa->afpf_mbox, 0, req, size, "AF");
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

static void npa_send_flr_msg(struct npa_dev_t *npa, struct rvu_vf *vf)
{
	int res, pcifunc;

	pcifunc = vf->npa->pcifunc | ((vf->vf_id + 1) & RVU_PFVF_FUNC_MASK);

	if (send_flr_msg(&npa->afpf_mbox, 0, pcifunc) != 0) {
		dev_err(&npa->pdev->dev, "Sending FLR to AF failed\n");
		return;
	}

	res = otx2_mbox_wait_for_rsp(&npa->afpf_mbox, 0);
	if (res == -EIO)
		dev_err(&npa->pdev->dev, "RVU AF MBOX timeout.\n");
	else if (res)
		dev_err(&npa->pdev->dev, "RVU MBOX error: %d.\n", res);
}

static void npa_pfvf_flr_handler(struct work_struct *work)
{
	struct rvu_vf *vf = container_of(work, struct rvu_vf, pfvf_flr_work);
	struct npa_dev_t *npa = vf->npa;
	struct otx2_mbox *mbox;

	mbox = &npa->pfvf_mbox;

	npa_send_flr_msg(npa, vf);

	/* Disable interrupts from AF and wait for any pending
	 * responses to be handled for this VF and then reset the
	 * mailbox
	 */
	otx2_disable_afpf_mbox_intr(npa);
	flush_workqueue(npa->afpf_mbox_wq);
	otx2_mbox_reset(mbox, vf->vf_id);
	vf->in_use = false;
	vf->got_flr = false;
	otx2_enable_afpf_mbox_intr(npa);
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(vf->vf_id / 64),
		    BIT_ULL(vf->intr_idx));
}

static void npa_pfvf_mbox_handler_up(struct work_struct *work)
{
	struct otx2_mbox *af_mbx, *vf_mbx;
	struct mbox_msghdr *msg, *fwd;
	struct mbox_hdr *rsp_hdr;
	struct npa_dev_t *npa;
	int offset, i, size;
	struct rvu_vf *vf;

	/* Read latest mbox data */
	smp_rmb();

	vf = container_of(work, struct rvu_vf, mbox_wrk_up);
	npa = vf->npa;
	af_mbx = &npa->afpf_mbox;
	vf_mbx = &npa->pfvf_mbox;
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
			dev_err(&npa->pdev->dev,
				"UP MBOX msg with wrong signature %x, ID 0x%x\n",
				msg->sig, msg->id);
			goto end;
		}

		/* override message value with actual values */
		msg->pcifunc = npa->pcifunc | vf->vf_id;

		fwd = otx2_mbox_alloc_msg(af_mbx, 0, size);
		if (!fwd) {
			dev_err(&npa->pdev->dev,
				"UP Forwarding from VF%d to AF failed.\n",
				vf->vf_id);
			goto end;
		}
		memcpy((uint8_t *) fwd + sizeof(struct mbox_msghdr),
		       (uint8_t *) msg + sizeof(struct mbox_msghdr), size);
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

static void npa_pfvf_mbox_handler(struct work_struct *work)
{
	struct rvu_vf *vf = container_of(work, struct rvu_vf, mbox_wrk);
	struct npa_dev_t *npa = vf->npa;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	struct otx2_mbox *mbox;
	int offset, id, err;

	mbox = &npa->pfvf_mbox;
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
		msg->pcifunc =
		    npa->pcifunc | ((vf->vf_id + 1) & RVU_PFVF_FUNC_MASK);
		err = handle_vf_req(npa, vf, msg, msg->next_msgoff - offset);
		if (err)
			otx2_reply_invalid_msg(mbox, vf->vf_id, msg->pcifunc,
					       msg->id);
		offset = msg->next_msgoff;
	}
	/* Send mbox responses to VF */
	if (mdev->num_msgs)
		otx2_mbox_msg_send(mbox, vf->vf_id);
}

static int npa_afpf_mbox_init(struct npa_dev_t *npa_pf_dev)
{
	struct pci_dev *pdev;
	int err;

	pdev = npa_pf_dev->pdev;
	npa_pf_dev->afpf_mbox_wq = alloc_workqueue("otx2_npa_pfaf_mailbox",
						   WQ_UNBOUND | WQ_HIGHPRI |
						   WQ_MEM_RECLAIM, 1);
	if (!npa_pf_dev->afpf_mbox_wq)
		return -ENOMEM;

	err =
	    otx2_mbox_init(&npa_pf_dev->afpf_mbox,
			   npa_pf_dev->mmio[AFPF_MBOX_BASE].hw_addr, pdev,
			   npa_pf_dev->mmio[NPA_REG_BASE].hw_addr,
			   MBOX_DIR_PFAF, 1);
	if (err) {
		dev_err(&pdev->dev, "mbox init for pfaf failed\n");
		goto destroy_mbox_wq;
	}

	err =
	    otx2_mbox_init(&npa_pf_dev->afpf_mbox_up,
			   npa_pf_dev->mmio[AFPF_MBOX_BASE].hw_addr, pdev,
			   npa_pf_dev->mmio[NPA_REG_BASE].hw_addr,
			   MBOX_DIR_PFAF_UP, 1);
	if (err) {
		dev_err(&pdev->dev, "mbox init for pfaf up failed\n");
		goto destroy_mbox_afpf;
	}

	INIT_WORK(&npa_pf_dev->mbox_wrk, npa_afpf_mbox_handler);
	INIT_WORK(&npa_pf_dev->mbox_wrk_up, npa_afpf_mbox_up_handler);
	mutex_init(&npa_pf_dev->lock);
	return 0;

destroy_mbox_wq:
	destroy_workqueue(npa_pf_dev->afpf_mbox_wq);
destroy_mbox_afpf:
	otx2_mbox_destroy(&npa_pf_dev->afpf_mbox);

	return err;
}

static void __handle_vf_flr(struct npa_dev_t *npa, struct rvu_vf *vf_ptr)
{
	if (vf_ptr->in_use) {
		/* Using the same MBOX workqueue here, so that we can
		 * synchronize with other VF->PF messages being forwarded to
		 * AF
		 */
		vf_ptr->got_flr = true;
		queue_work(npa->pfvf_mbox_wq, &vf_ptr->pfvf_flr_work);
	} else
		npa_write64(npa, BLKADDR_RVUM, 0,
			    RVU_PF_VFTRPENDX(vf_ptr->vf_id / 64),
			    BIT_ULL(vf_ptr->intr_idx));
}

static irqreturn_t npa_pf_vf_flr_intr(int irq, void *pf_irq)
{
	struct npa_dev_t *npa = (struct npa_dev_t *)pf_irq;
	struct rvu_vf *vf_ptr;
	int vec, vf, i;
	u64 intr;

	/* Check which VF FLR has been raised and process accordingly */
	for (vec = RVU_PF_INT_VEC_VFFLR0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFFLR1; i++) {
		/* Read the interrupt bits */
		intr = npa_read64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(i));

		for (vf = i * 64; vf < npa->num_vfs; vf++) {
			vf_ptr = &npa->vf_info[vf];
			if (intr & (1ULL << vf_ptr->intr_idx)) {
				/* Clear the interrupts */
				npa_write64(npa, BLKADDR_RVUM, 0,
					    RVU_PF_VFFLR_INTX(i),
					    BIT_ULL(vf_ptr->intr_idx));
				__handle_vf_flr(npa, vf_ptr);
			}
		}
	}

	return IRQ_HANDLED;
}

static irqreturn_t otx2_pfvf_mbox_intr_handler(int irq, void *pf_irq)
{
	struct npa_dev_t *npa = (struct npa_dev_t *)pf_irq;
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;
	struct rvu_vf *vf;
	int i, vfi, vec;
	u64 intr;

	/* Check which VF has raised an interrupt and schedule corresponding
	 * workq to process the MBOX
	 */
	for (vec = RVU_PF_INT_VEC_VFPF_MBOX0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFPF_MBOX1; i++) {
		/* Read the interrupt bits */
		intr = npa_read64(npa, BLKADDR_RVUM, 0,
				  RVU_PF_VFPF_MBOX_INTX(i));

		for (vfi = i * 64; vfi < npa->num_vfs; vfi++) {
			vf = &npa->vf_info[vfi];
			if ((intr & (1ULL << vf->intr_idx)) == 0)
				continue;
			mbox = &npa->pfvf_mbox;
			mdev = &mbox->dev[vf->vf_id];
			hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
			/* Handle VF => PF channel request */
			if (hdr->num_msgs)
				queue_work(npa->pfvf_mbox_wq, &vf->mbox_wrk);

			mbox = &npa->pfvf_mbox_up;
			mdev = &mbox->dev[vf->vf_id];
			hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
			/* Handle PF => VF channel response */
			if (hdr->num_msgs)
				queue_work(npa->pfvf_mbox_wq, &vf->mbox_wrk_up);
			/* Clear the interrupt */
			npa_write64(npa, BLKADDR_RVUM, 0,
				    RVU_PF_VFPF_MBOX_INTX(i),
				    BIT_ULL(vf->intr_idx));
		}
	}
	return IRQ_HANDLED;
}

static void free_ptrs(struct otx2_npa_pool *pool, struct device *owner)
{
	struct iommu_domain *iommu_domain;
	struct page *list_page;
	struct ptr_pair *list;
	u64 *next_ptr;
	int i, cnt;

	iommu_domain = iommu_get_domain_for_dev(owner);
	list_page = pool->ptr_list_start;
	while (pool->ptr_pair_cnt) {
		list = page_to_virt(list_page);
		if (pool->ptr_pair_cnt > pool->ptr_pairs_per_page)
			cnt = pool->ptr_pairs_per_page;
		else
			cnt = pool->ptr_pair_cnt;
		for (i = 0; i < cnt; i++) {
			if (iommu_domain
			    && (iommu_domain->type != IOMMU_DOMAIN_IDENTITY))
				dma_unmap_page_attrs(owner, list->iova,
						     pool->rbsize,
						     DMA_TO_DEVICE,
						     DMA_ATTR_SKIP_CPU_SYNC);
			__free_pages(list->page, pool->rbpage_order);
			list++;
		}
		next_ptr = (u64 *) list;
		__free_page(list_page);
		list_page = (struct page *)*next_ptr;
		pool->ptr_pair_cnt -= cnt;
	}
}

static int record_ptrs(struct otx2_npa_pool *pool, dma_addr_t iova)
{
	struct page *ptr_list_page;
	struct ptr_pair *pair;
	u64 *next_ptr;

	if (pool->ptr_list
	    && (pool->ptr_pairs_in_page < pool->ptr_pairs_per_page))
		goto store_ptrs;

	ptr_list_page = alloc_page(GFP_KERNEL | __GFP_COMP | __GFP_NOWARN);
	if (unlikely(!ptr_list_page))
		return -ENOMEM;

	if (!pool->ptr_list_start)
		pool->ptr_list_start = ptr_list_page;

	if (pool->ptr_list) {
		next_ptr = (u64 *) pool->ptr_list;
		*next_ptr = (u64) ptr_list_page;
	}
	pool->ptr_list = page_to_virt(ptr_list_page);
	pool->ptr_pairs_in_page = 0;

store_ptrs:
	pair = (struct ptr_pair *)pool->ptr_list;
	pair->page = pool->page;
	pair->iova = iova;
	pool->ptr_list += sizeof(struct ptr_pair);
	pool->ptr_pairs_in_page += 1;
	pool->ptr_pair_cnt += 1;

	return 0;
}

static dma_addr_t otx2_alloc_npa_buf(struct npa_dev_t *pfvf,
				     struct otx2_npa_pool *pool, gfp_t gfp,
				     struct device *owner)
{
	dma_addr_t iova;
	struct iommu_domain *iommu_domain;

	/* Check if request can be accommodated in previous allocated page */
	if (pool->page && ((pool->page_offset + pool->rbsize) <= PAGE_SIZE)) {
		page_ref_inc(pool->page);
		goto ret;
	}

	/* Allocate a new page */
	pool->page = alloc_pages(gfp | __GFP_COMP | __GFP_NOWARN,
				 pool->rbpage_order);
	if (unlikely(!pool->page))
		return -ENOMEM;
	pool->page_offset = 0;
ret:
	iommu_domain = iommu_get_domain_for_dev(owner);
	if (iommu_domain && (iommu_domain->type == IOMMU_DOMAIN_IDENTITY)) {
		iova = page_to_phys(pool->page) + pool->page_offset;
	} else {
		iova = dma_map_page_attrs(owner, pool->page, pool->page_offset,
					  pool->rbsize, DMA_TO_DEVICE,
					  DMA_ATTR_SKIP_CPU_SYNC);
		if (unlikely(dma_mapping_error(owner, iova)))
			iova = (dma_addr_t) NULL;
	}

	if (!iova) {
		if (!pool->page_offset)
			__free_pages(pool->page, pool->rbpage_order);
		pool->page = NULL;
		return -ENOMEM;
	}

	record_ptrs(pool, iova);
	pool->page_offset += pool->rbsize;
	return iova;
}

static inline int npa_sync_mbox_msg(struct otx2_mbox *mbox)
{
	int err;

	if (!otx2_mbox_nonempty(mbox, 0))
		return 0;
	otx2_mbox_msg_send(mbox, 0);
	err = otx2_mbox_wait_for_rsp(mbox, 0);
	if (err)
		return err;

	return otx2_mbox_check_rsp_msgs(mbox, 0);
}

static int otx2_npa_aura_init(struct npa_dev_t *npa, int aura_id,
			      int pool_id, int numptrs)
{
	struct npa_aq_enq_req *aq;
	struct otx2_npa_pool *pool;
	struct device *dev;
	int err;

	pool = npa->pools[aura_id];
	dev = &npa->pdev->dev;

	/* Allocate memory for HW to update Aura count.
	 * Alloc one cache line, so that it fits all FC_STYPE modes.
	 */
	if (!pool->fc_addr) {
		err = qmem_alloc(dev, &pool->fc_addr, 1, OTX2_ALIGN);
		if (err)
			return err;
	}

	/* Initialize this aura's context via AF */
	aq = otx2_af_mbox_alloc_msg_npa_aq_enq(&npa->afpf_mbox);
	if (!aq) {
		/* Shared mbox memory buffer is full, flush it and retry */
		err = npa_sync_mbox_msg(&npa->afpf_mbox);
		if (err)
			return err;
		aq = otx2_af_mbox_alloc_msg_npa_aq_enq(&npa->afpf_mbox);
		if (!aq)
			return -ENOMEM;
	}

	aq->aura_id = aura_id;
	/* Will be filled by AF with correct pool context address */
	aq->aura.pool_addr = pool_id;
	aq->aura.pool_caching = 1;
	aq->aura.shift = ilog2(numptrs) - 8;
	aq->aura.count = numptrs;
	aq->aura.limit = numptrs;
	aq->aura.avg_level = NPA_AURA_AVG_LVL;
	aq->aura.ena = 1;
	aq->aura.fc_ena = 1;
	aq->aura.fc_addr = pool->fc_addr->iova;
	aq->aura.fc_hyst_bits = 0;	/* Store count on all updates */

	/* Fill AQ info */
	aq->ctype = NPA_AQ_CTYPE_AURA;
	aq->op = NPA_AQ_INSTOP_INIT;

	return 0;
}

static int otx2_npa_pool_init(struct npa_dev_t *pfvf, u16 pool_id,
			      int stack_pages, int numptrs, int buf_size)
{
	struct npa_aq_enq_req *aq;
	struct otx2_npa_pool *pool;
	struct device *dev;
	int err;

	dev = &pfvf->pdev->dev;
	pool = pfvf->pools[pool_id];

	/* Alloc memory for stack which is used to store buffer pointers */
	err = qmem_alloc(dev, &pool->stack, stack_pages, pfvf->stack_pg_bytes);
	if (err)
		return err;

	pool->rbsize = buf_size;
	pool->rbpage_order = get_order(buf_size);

	/* Initialize this pool's context via AF */
	aq = otx2_af_mbox_alloc_msg_npa_aq_enq(&pfvf->afpf_mbox);
	if (!aq) {
		/* Shared mbox memory buffer is full, flush it and retry */
		err = npa_sync_mbox_msg(&pfvf->afpf_mbox);
		if (err) {
			qmem_free(dev, pool->stack);
			return err;
		}
		aq = otx2_af_mbox_alloc_msg_npa_aq_enq(&pfvf->afpf_mbox);
		if (!aq) {
			qmem_free(dev, pool->stack);
			return -ENOMEM;
		}
	}

	aq->aura_id = pool_id;
	aq->pool.stack_base = pool->stack->iova;
	aq->pool.stack_caching = 1;
	aq->pool.ena = 1;
	aq->pool.buf_size = buf_size / 128;
	aq->pool.stack_max_pages = stack_pages;
	aq->pool.shift = ilog2(numptrs) - 8;
	aq->pool.ptr_start = 0;
	aq->pool.ptr_end = ~0ULL;

	/* Fill AQ info */
	aq->ctype = NPA_AQ_CTYPE_POOL;
	aq->op = NPA_AQ_INSTOP_INIT;

	return 0;
}

u64 npa_alloc_buf(u32 aura)
{
	union aura_handle ah;
	struct npa_dev_t *npa_pf_dev;

	ah.handle = aura;
	npa_pf_dev = gnpa_pf_dev[ah.s.pf_id];
	return otx2_atomic64_add((u64) ah.s.aura | BIT_ULL(63),
				 npa_pf_dev->alloc_reg_ptr);
}
EXPORT_SYMBOL(npa_alloc_buf);

u16 npa_pf_func(u32 aura)
{
	union aura_handle ah;
	struct npa_dev_t *npa_pf_dev;

	ah.handle = aura;
	npa_pf_dev = gnpa_pf_dev[ah.s.pf_id];
	return npa_pf_dev->pcifunc;
}
EXPORT_SYMBOL(npa_pf_func);

void npa_free_buf(u32 aura, u64 buf)
{
	union aura_handle ah;
	struct npa_dev_t *npa_pf_dev;

	ah.handle = aura;
	npa_pf_dev = gnpa_pf_dev[ah.s.pf_id];
	otx2_write128((u64) buf, (u64) ah.s.aura | BIT_ULL(63),
		      npa_pf_dev->free_reg_addr);
}
EXPORT_SYMBOL(npa_free_buf);

static void npa_set_reg_ptrs(struct npa_dev_t *npa_pf_dev)
{
	void __iomem *reg_addr = npa_pf_dev->mmio[NPA_REG_BASE].hw_addr;
	u64 offset = NPA_LF_AURA_OP_ALLOCX(0);

	offset &= ~(RVU_FUNC_BLKADDR_MASK << RVU_FUNC_BLKADDR_SHIFT);
	offset |= (BLKADDR_NPA << RVU_FUNC_BLKADDR_SHIFT);
	npa_pf_dev->alloc_reg_ptr = (u64 *) (reg_addr + offset);

	offset = NPA_LF_AURA_OP_FREE0;
	offset &= ~(RVU_FUNC_BLKADDR_MASK << RVU_FUNC_BLKADDR_SHIFT);
	offset |= (BLKADDR_NPA << RVU_FUNC_BLKADDR_SHIFT);
	npa_pf_dev->free_reg_addr = (reg_addr + offset);
}

static int npa_lf_alloc(struct npa_dev_t *pfvf)
{
	struct npa_lf_alloc_req *npalf;
	int err, aura_cnt;

	npalf = otx2_af_mbox_alloc_msg_npa_lf_alloc(&pfvf->afpf_mbox);
	if (!npalf)
		return -ENOMEM;

	/* Set aura and pool counts */
	npalf->nr_pools = NPA_MAX_AURAS;
	aura_cnt = ilog2(roundup_pow_of_two(npalf->nr_pools));
	npalf->aura_sz = (aura_cnt >= ilog2(128)) ? (aura_cnt - 6) : 1;

	err = npa_sync_mbox_msg(&pfvf->afpf_mbox);
	if (err)
		return err;

	return 0;
}

static int otx2_npa_aura_pool_init(struct npa_dev_t *npa, int num_ptrs,
				   int buf_size, int aura_id, u32 *handle,
				   struct device *owner)
{
	struct otx2_npa_pool *pool;
	union aura_handle ah;
	struct device *dev;
	int stack_pages;
	int err, ptr;
	s64 bufptr;

	mutex_lock(&npa->lock);
	if (!npa->alloc_reg_ptr) {
		npa_lf_alloc(npa);
		npa_set_reg_ptrs(npa);
	}
	mutex_unlock(&npa->lock);

	dev = &npa->pdev->dev;
	pool = devm_kzalloc(dev, sizeof(struct otx2_npa_pool), GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	pool->ptr_list = NULL;
	pool->ptr_pairs_in_page = 0;
	pool->ptr_pairs_per_page =
	    (PAGE_SIZE - sizeof(u64)) / sizeof(struct ptr_pair);
	pool->ptr_list_start = NULL;
	pool->ptr_pair_cnt = 0;

	npa->pools[aura_id] = pool;
	/* Initialize aura context */
	err = otx2_npa_aura_init(npa, aura_id, aura_id, num_ptrs);
	if (err)
		goto pool_init_fail;

	stack_pages =
	    (num_ptrs + npa->stack_pg_ptrs - 1) / npa->stack_pg_ptrs;
	err =
	    otx2_npa_pool_init(npa, aura_id, stack_pages, num_ptrs,
			       buf_size);
	if (err)
		goto pool_init_fail;

	/* Flush accumulated messages */
	err = npa_sync_mbox_msg(&npa->afpf_mbox);
	if (err)
		goto pool_init_fail;

	/* Allocate pointers and free them to aura/pool */
	for (ptr = 0; ptr < num_ptrs; ptr++) {
		bufptr = otx2_alloc_npa_buf(npa, pool, GFP_KERNEL, owner);
		if (bufptr <= 0)
			return bufptr;
		/* Free buffer to Aura */
		otx2_write128((u64) bufptr, (u64) aura_id | BIT_ULL(63),
			      npa->free_reg_addr);
	}
	ah.s.aura = aura_id;
	ah.s.pf_id = npa->pf_id;
	/* Report the handle to caller */
	*handle = ah.handle;
	return 0;

pool_init_fail:
	otx2_mbox_reset(&npa->afpf_mbox, 0);
	qmem_free(dev, pool->stack);
	qmem_free(dev, pool->fc_addr);
	devm_kfree(dev, pool);
	return err;
}

int npa_aura_pool_init(int pool_size, int buf_size, u32 *aura_handle,
		       struct device *owner)
{
	struct npa_dev_t *npa_pf;
	int aura_id;
	bool set;
	int i;

	for_each_set_bit(i, pf_bmp, NPA_MAX_PFS) {
		npa_pf = gnpa_pf_dev[i];
		set = true;
		while (set) {
			aura_id =
			    find_first_zero_bit(npa_pf->aura_bmp,
						NPA_MAX_AURAS);
			if (aura_id < NPA_MAX_AURAS)
				set =
				    test_and_set_bit(aura_id, npa_pf->aura_bmp);
			else
				break;
		}
		if (!set)
			break;
	}

	if (set) {
		dev_err(owner, "Max aura limit reached\n");
		return -ENOMEM;
	}

	return otx2_npa_aura_pool_init(npa_pf, pool_size, buf_size, aura_id,
				       aura_handle, owner);
}
EXPORT_SYMBOL(npa_aura_pool_init);

static int npa_lf_aura_pool_fini(struct npa_dev_t *npa, u16 aura_id)
{
	struct npa_aq_enq_req *aura_req, *pool_req;
	struct ndc_sync_op *ndc_req;
	struct otx2_mbox *mbox;
	int rc;

	mbox = &npa->afpf_mbox;
	/* Procedure for disabling an aura/pool */
	usleep_range(10, 11);

	/* TODO: Need to know why? */
	otx2_atomic64_add((u64) aura_id | BIT_ULL(63), npa->alloc_reg_ptr);

	pool_req = otx2_af_mbox_alloc_msg_npa_aq_enq(mbox);
	pool_req->aura_id = aura_id;
	pool_req->ctype = NPA_AQ_CTYPE_POOL;
	pool_req->op = NPA_AQ_INSTOP_WRITE;
	pool_req->pool.ena = 0;
	pool_req->pool_mask.ena = ~pool_req->pool_mask.ena;

	aura_req = otx2_af_mbox_alloc_msg_npa_aq_enq(mbox);
	aura_req->aura_id = aura_id;
	aura_req->ctype = NPA_AQ_CTYPE_AURA;
	aura_req->op = NPA_AQ_INSTOP_WRITE;
	aura_req->aura.ena = 0;
	aura_req->aura_mask.ena = ~aura_req->aura_mask.ena;

	rc = npa_sync_mbox_msg(&npa->afpf_mbox);
	if (rc) {
		dev_err(&npa->pdev->dev, "Aura pool finish failed\n");
		return rc;
	}

	/* Sync NDC-NPA for LF */
	ndc_req = otx2_af_mbox_alloc_msg_ndc_sync_op(mbox);
	ndc_req->npa_lf_sync = 1;

	rc = npa_sync_mbox_msg(&npa->afpf_mbox);
	if (rc) {
		dev_err(&npa->pdev->dev, "Error on NDC-NPA LF sync.\n");
		return rc;
	}
	return 0;
}

int npa_aura_pool_fini(const u32 aura_handle, struct device *owner)
{
	struct npa_dev_t *npa;
	union aura_handle ah;
	u16 aura_id, pf_id;

	ah.handle = aura_handle;
	aura_id = ah.s.aura;
	pf_id = ah.s.pf_id;
	npa = gnpa_pf_dev[pf_id];
	if (!test_bit(aura_id, npa->aura_bmp)) {
		dev_info(&npa->pdev->dev, "Pool not active\n");
		return 0;
	}

	npa_lf_aura_pool_fini(npa, aura_id);
	qmem_free(&npa->pdev->dev, npa->pools[aura_id]->stack);
	qmem_free(&npa->pdev->dev, npa->pools[aura_id]->fc_addr);
	free_ptrs(npa->pools[aura_id], owner);
	devm_kfree(&npa->pdev->dev, npa->pools[aura_id]);

	clear_bit(aura_id, npa->aura_bmp);

	return 0;
}
EXPORT_SYMBOL(npa_aura_pool_fini);

static int npa_check_pf_usable(struct npa_dev_t *npa)
{
	u64 rev;

	rev = npa_read64(npa, BLKADDR_RVUM, 0,
			 RVU_PF_BLOCK_ADDRX_DISC(BLKADDR_RVUM));
	rev = (rev >> 12) & 0xFF;
	/* Check if AF has setup revision for RVUM block,
	 * otherwise this driver probe should be deferred
	 * until AF driver comes up.
	 */
	if (!rev) {
		dev_warn(&npa->pdev->dev,
			 "AF is not initialized, deferring probe\n");
		return -EPROBE_DEFER;
	}
	return 0;
}

static int npa_register_mbox_intr(struct npa_dev_t *npa_pf_dev, bool probe_af)
{
	struct msg_req *req;
	struct rsrc_attach *attach;
	struct msg_req *msix;
	int err;

	/* Request and enable AF=>PF mailbox interrupt handler */
	otx2_alloc_afpf_mbox_intr(npa_pf_dev);

	if (!probe_af)
		return 0;

	/* Check mailbox communication with AF */
	req = otx2_af_mbox_alloc_msg_ready(&npa_pf_dev->afpf_mbox);
	if (!req) {
		otx2_disable_afpf_mbox_intr(npa_pf_dev);
		err = -ENOMEM;
		goto err_free_intr;
	}

	err = npa_sync_mbox_msg(&npa_pf_dev->afpf_mbox);
	if (err) {
		dev_warn(&npa_pf_dev->pdev->dev,
			 "AF not responding to mailbox, deferring probe\n");
		err = -EPROBE_DEFER;
		goto err_free_intr;
	}

	mutex_lock(&npa_pf_dev->lock);
	/* Get memory to put this msg */
	attach =
	    otx2_af_mbox_alloc_msg_attach_resources(&npa_pf_dev->afpf_mbox);
	if (!attach) {
		mutex_unlock(&npa_pf_dev->lock);
		err = -ENOMEM;
		goto err_free_intr;
	}

	attach->npalf = true;
	/* Send attach request to AF */
	err = npa_sync_mbox_msg(&npa_pf_dev->afpf_mbox);
	if (err) {
		mutex_unlock(&npa_pf_dev->lock);
		goto err_free_intr;
	}

	/* Get NPA MSIX vector offsets */
	msix = otx2_af_mbox_alloc_msg_msix_offset(&npa_pf_dev->afpf_mbox);
	if (!msix) {
		mutex_unlock(&npa_pf_dev->lock);
		err = -ENOMEM;
		goto err_free_intr;
	}

	err = npa_sync_mbox_msg(&npa_pf_dev->afpf_mbox);
	if (err) {
		mutex_unlock(&npa_pf_dev->lock);
		goto err_free_intr;
	}

	mutex_unlock(&npa_pf_dev->lock);

	return 0;

err_free_intr:
	otx2_free_afpf_mbox_intr(npa_pf_dev);
	return err;
}

static void npa_afpf_mbox_destroy(struct npa_dev_t *npa_pf_dev)
{

	if (npa_pf_dev->afpf_mbox_wq) {
		flush_workqueue(npa_pf_dev->afpf_mbox_wq);
		destroy_workqueue(npa_pf_dev->afpf_mbox_wq);
		npa_pf_dev->afpf_mbox_wq = NULL;
	}

	otx2_mbox_destroy(&npa_pf_dev->afpf_mbox);
	otx2_mbox_destroy(&npa_pf_dev->afpf_mbox_up);
}

static int otx2_npa_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct npa_dev_t *npa;
	int err, pos;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		return err;
	}

	if (pci_request_regions(pdev, DRV_NAME)) {
		dev_err(&pdev->dev, "pci_request_regions failed\n");
		goto err_disable_device;
	}

	pci_set_master(pdev);

	npa = vzalloc(sizeof(struct npa_dev_t));
	if (npa == NULL)
		goto err_release_regions;

	pci_set_drvdata(pdev, npa);
	npa->pdev = pdev;

	npa->mmio[NPA_REG_BASE].start = pci_resource_start(pdev, REG_BAR_NUM);
	npa->mmio[NPA_REG_BASE].len = pci_resource_len(pdev, REG_BAR_NUM);
	npa->mmio[NPA_REG_BASE].hw_addr =
	    ioremap_wc(npa->mmio[NPA_REG_BASE].start,
		       npa->mmio[NPA_REG_BASE].len);
	npa->mmio[NPA_REG_BASE].mapped_len = npa->mmio[NPA_REG_BASE].len;
	dev_info(&pdev->dev, "REG BAR %p\n", npa->mmio[NPA_REG_BASE].hw_addr);

	npa->mmio[AFPF_MBOX_BASE].start =
	    pci_resource_start(pdev, MBOX_BAR_NUM);
	npa->mmio[AFPF_MBOX_BASE].len = pci_resource_len(pdev, MBOX_BAR_NUM);
	npa->mmio[AFPF_MBOX_BASE].hw_addr =
	    ioremap_wc(npa->mmio[AFPF_MBOX_BASE].start,
		       npa->mmio[AFPF_MBOX_BASE].len);
	npa->mmio[AFPF_MBOX_BASE].mapped_len = npa->mmio[AFPF_MBOX_BASE].len;
	dev_info(&pdev->dev, "MBOX BAR %p\n",
		 npa->mmio[AFPF_MBOX_BASE].hw_addr);

	err = npa_check_pf_usable(npa);
	if (err)
		goto err_free_privdev;

	npa->num_vec = pci_msix_vec_count(pdev);
	err = pci_alloc_irq_vectors(pdev, npa->num_vec,
				    npa->num_vec, PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(&pdev->dev, "%s: Failed to alloc %d IRQ vectors\n",
			__func__, npa->num_vec);
		goto err_free_privdev;
	}

	npa->irq_names = kmalloc_array(npa->num_vec, NAME_SIZE, GFP_KERNEL);
	if (!npa->irq_names) {
		err = -ENOMEM;
		goto err_free_irq_vectors;
	}

	err = npa_afpf_mbox_init(npa);
	if (err) {
		dev_err(&pdev->dev, "Mbox init failed\n");
		goto err_free_irq_names;
	}

	/* Register mailbox interrupt */
	err = npa_register_mbox_intr(npa, true);
	if (err) {
		dev_err(&pdev->dev, "Registering MBOX interrupt failed\n");
		goto err_mbox_destroy;
	}

	spin_lock(&npa_lst_lock);
	pos = find_first_zero_bit(pf_bmp, NPA_MAX_PFS);
	if (pos < NPA_MAX_PFS) {
		set_bit(pos, pf_bmp);
		npa->pf_id = pos;
		gnpa_pf_dev[pos] = npa;
	}
	spin_unlock(&npa_lst_lock);

	return 0;
err_mbox_destroy:
	npa_afpf_mbox_destroy(npa);
err_free_irq_names:
	kfree(npa->irq_names);
err_free_irq_vectors:
	pci_free_irq_vectors(npa->pdev);
err_free_privdev:
	iounmap(npa->mmio[NPA_REG_BASE].hw_addr);
	iounmap(npa->mmio[AFPF_MBOX_BASE].hw_addr);
	pci_set_drvdata(pdev, NULL);
	vfree(npa);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	return err;
}

static void npa_disable_vf_flr_int(struct npa_dev_t *npa)
{
	struct pci_dev *pdev;
	int ena_bits, vec, i;
	u64 intr;

	pdev = npa->pdev;
	/* clear any pending interrupt */

	intr = npa_read64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0));
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0), intr);
	intr = npa_read64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0));
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0), intr);

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		intr = npa_read64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1));
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1), intr);
		intr = npa_read64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1));
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1), intr);
	}

	/* Disable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((npa->num_vfs - 1) % 64);

	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(0),
		    GENMASK_ULL(ena_bits, 0));

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = npa->num_vfs - 64 - 1;
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1CX(1),
			    GENMASK_ULL(ena_bits, 0));
	}

	for (vec = RVU_PF_INT_VEC_VFFLR0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFFLR1; i++)
		free_irq(pci_irq_vector(pdev, vec + i), npa);
}

static int npa_enable_vf_flr_int(struct npa_dev_t *npa)
{
	struct pci_dev *pdev;
	int err, vec, i;
	int ena_bits;

	pdev = npa->pdev;

	/* Register for VF FLR interrupts
	 * There are 2 vectors starting at index 0x0
	 */
	for (vec = RVU_PF_INT_VEC_VFFLR0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFFLR1; i++) {
		sprintf(&npa->irq_names[(vec + i) * NAME_SIZE],
			"PF%02d_VF_FLR_IRQ%d", pdev->devfn, i);
		err = request_irq(pci_irq_vector(pdev, vec + i),
				  npa_pf_vf_flr_intr, 0,
				  &npa->irq_names[(vec + i) * NAME_SIZE], npa);
		if (err) {
			dev_err(&pdev->dev,
				"request_irq() failed for PFVF FLR intr %d\n",
				vec);
			return err;
		}
	}

	/* Clear any pending interrupts */
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0), ~0x0ULL);
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0), ~0x0ULL);

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1), ~0x0ULL);
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1),
			    ~0x0ULL);
	}

	/* Enable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((npa->num_vfs - 1) % 64);
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(0),
		    GENMASK_ULL(ena_bits, 0));

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = npa->num_vfs - 64 - 1;
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INT_ENA_W1SX(1),
			    GENMASK_ULL(ena_bits, 0));
	}
	return 0;
}

static int npa_enable_pfvf_mbox_intr(struct npa_dev_t *npa)
{
	int ena_bits, vec, err, i;
	struct pci_dev *pdev;

	/* Register for PF-VF mailbox interrupts
	 * There are 2 vectors starting at index 0x4
	 */
	pdev = npa->pdev;
	for (vec = RVU_PF_INT_VEC_VFPF_MBOX0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFPF_MBOX1; i++) {
		sprintf(&npa->irq_names[(vec + i) * NAME_SIZE],
			"PF%02d_VF_MBOX_IRQ%d", pdev->devfn, i);
		err = request_irq(pci_irq_vector(pdev, vec + i),
				  otx2_pfvf_mbox_intr_handler, 0,
				  &npa->irq_names[(vec + i) * NAME_SIZE], npa);
		if (err) {
			dev_err(&pdev->dev,
				"request_irq() failed for PFVF Mbox intr %d\n",
				vec + i);
			return err;
		}
	}

	/* Clear any pending interrupts */
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0), ~0x0ULL);

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(1),
			    ~0x0ULL);
	}

	/* Enable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((npa->num_vfs - 1) % 64);
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0),
		    GENMASK_ULL(ena_bits, 0));

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = npa->num_vfs - 64 - 1;
		npa_write64(npa, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
			    GENMASK_ULL(ena_bits, 0));
	}

	return 0;
}

static void npa_disable_pfvf_mbox_intr(struct npa_dev_t *npa)
{
	struct pci_dev *pdev;
	int ena_bits, vec, i;
	u64 intr;

	intr = npa_read64(npa, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0));
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0), intr);

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		intr = npa_read64(npa, BLKADDR_RVUM, 0,
				  RVU_PF_VFPF_MBOX_INTX(1));
		npa_write64(npa, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INTX(1), intr);
	}

	/* Disable for first 64 VFs here - upto number of VFs enabled */
	ena_bits = ((npa->num_vfs - 1) % 64);
	npa_write64(npa, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0),
		    GENMASK_ULL(ena_bits, 0));

	if (npa->num_vfs > 64) {	/* For VF 64 to 127(MAX) */
		/* Enable for VF interrupts for VFs 64  to 128 */
		ena_bits = npa->num_vfs - 64 - 1;
		npa_write64(npa, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INT_ENA_W1CX(1),
			    GENMASK_ULL(ena_bits, 0));
	}

	pdev = npa->pdev;
	for (vec = RVU_PF_INT_VEC_VFPF_MBOX0, i = 0;
	     vec + i <= RVU_PF_INT_VEC_VFPF_MBOX1; i++)
		free_irq(pci_irq_vector(pdev, vec + i), npa);
}

static int otx2_npa_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	struct rvu_vf *vf_ptr;
	struct npa_dev_t *npa;
	u64 pf_vf_mbox_base;
	int err, vf;

	npa = pci_get_drvdata(pdev);

	npa->vf_info = kcalloc(num_vfs, sizeof(struct rvu_vf), GFP_KERNEL);
	if (npa->vf_info == NULL)
		return -ENOMEM;

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable to SRIOV VFs: %d\n", err);
		goto err_enable_sriov;
	}

	npa->num_vfs = num_vfs;

	/* Map PF-VF mailbox memory */
	pf_vf_mbox_base =
	    (u64) npa->mmio[NPA_REG_BASE].hw_addr + RVU_PF_VF_BAR4_ADDR;
	pf_vf_mbox_base = readq((void __iomem *)(unsigned long)pf_vf_mbox_base);
	if (!pf_vf_mbox_base) {
		dev_err(&pdev->dev, "PF-VF Mailbox address not configured\n");
		err = -ENOMEM;
		goto err_mbox_mem_map;
	}
	npa->mmio[PFVF_MBOX_BASE].hw_addr =
	    ioremap_wc(pf_vf_mbox_base, MBOX_SIZE * num_vfs);
	if (!npa->mmio[PFVF_MBOX_BASE].hw_addr) {
		dev_err(&pdev->dev,
			"Mapping of PF-VF mailbox address failed\n");
		err = -ENOMEM;
		goto err_mbox_mem_map;
	}
	err =
	    otx2_mbox_init(&npa->pfvf_mbox, npa->mmio[PFVF_MBOX_BASE].hw_addr,
			   pdev, npa->mmio[NPA_REG_BASE].hw_addr, MBOX_DIR_PFVF,
			   num_vfs);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to initialize PF/VF MBOX for %d VFs\n",
			num_vfs);
		goto err_mbox_init;
	}
	err =
	    otx2_mbox_init(&npa->pfvf_mbox_up,
			   npa->mmio[PFVF_MBOX_BASE].hw_addr, pdev,
			   npa->mmio[NPA_REG_BASE].hw_addr, MBOX_DIR_PFVF_UP,
			   num_vfs);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to initialize PF/VF MBOX UP for %d VFs\n",
			num_vfs);
		goto err_mbox_up_init;
	}

	/* Allocate a single workqueue for VF/PF mailbox because access to
	 * AF/PF mailbox has to be synchronized.
	 */
	npa->pfvf_mbox_wq =
	    alloc_workqueue("npa_pfvf_mailbox",
			    WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 1);
	if (npa->pfvf_mbox_wq == NULL) {
		dev_err(&pdev->dev,
			"Workqueue allocation failed for PF-VF MBOX\n");
		err = -ENOMEM;
		goto err_workqueue_alloc;
	}

	for (vf = 0; vf < num_vfs; vf++) {
		vf_ptr = &npa->vf_info[vf];
		vf_ptr->vf_id = vf;
		vf_ptr->npa = (void *)npa;
		vf_ptr->intr_idx = vf % 64;
		INIT_WORK(&vf_ptr->mbox_wrk, npa_pfvf_mbox_handler);
		INIT_WORK(&vf_ptr->mbox_wrk_up, npa_pfvf_mbox_handler_up);
		INIT_WORK(&vf_ptr->pfvf_flr_work, npa_pfvf_flr_handler);
	}

	err = npa_enable_pfvf_mbox_intr(npa);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to initialize PF/VF MBOX intr for %d VFs\n",
			num_vfs);
		goto err_pfvf_mbox_intr;
	}
	err = npa_enable_vf_flr_int(npa);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to initialize PF/VF MBOX intr for %d VFs\n",
			num_vfs);
		goto err_vf_flr_intr;
	}
	return num_vfs;

err_vf_flr_intr:
	npa_disable_pfvf_mbox_intr(npa);
err_pfvf_mbox_intr:
	destroy_workqueue(npa->pfvf_mbox_wq);
err_workqueue_alloc:
	if (npa->pfvf_mbox_up.dev != NULL)
		otx2_mbox_destroy(&npa->pfvf_mbox_up);
err_mbox_up_init:
	if (npa->pfvf_mbox.dev != NULL)
		otx2_mbox_destroy(&npa->pfvf_mbox);
err_mbox_init:
	iounmap(npa->mmio[PFVF_MBOX_BASE].hw_addr);
err_mbox_mem_map:
	pci_disable_sriov(pdev);
err_enable_sriov:
	kfree(npa->vf_info);

	return err;
}

static int otx2_npa_sriov_disable(struct pci_dev *pdev)
{
	struct npa_dev_t *npa;

	npa = pci_get_drvdata(pdev);
	npa_disable_vf_flr_int(npa);
	npa_disable_pfvf_mbox_intr(npa);

	if (npa->pfvf_mbox_wq) {
		flush_workqueue(npa->pfvf_mbox_wq);
		destroy_workqueue(npa->pfvf_mbox_wq);
		npa->pfvf_mbox_wq = NULL;
	}

	if (npa->mmio[PFVF_MBOX_BASE].hw_addr)
		iounmap(npa->mmio[PFVF_MBOX_BASE].hw_addr);

	otx2_mbox_destroy(&npa->pfvf_mbox);
	otx2_mbox_destroy(&npa->pfvf_mbox_up);

	pci_disable_sriov(pdev);

	kfree(npa->vf_info);
	npa->vf_info = NULL;

	return 0;
}

static int otx2_npa_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return otx2_npa_sriov_disable(pdev);
	else
		return otx2_npa_sriov_enable(pdev, num_vfs);
}

static void otx2_npa_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct npa_dev_t *npa;
	struct msg_req *req;
	int err;

	npa = pci_get_drvdata(pdev);

	if (npa->num_vfs)
		otx2_npa_sriov_disable(pdev);

	req = otx2_af_mbox_alloc_msg_npa_lf_free(&npa->afpf_mbox);
	if (!req)
		dev_err(dev, "Failed to allocate npa lf free req\n");
	err = npa_sync_mbox_msg(&npa->afpf_mbox);
	if (err)
		dev_err(dev, "Failed to free lf\n");

	otx2_af_mbox_alloc_msg_detach_resources(&npa->afpf_mbox);
	err = npa_sync_mbox_msg(&npa->afpf_mbox);
	if (err)
		dev_err(dev, "Failed to detach resources\n");

	otx2_free_afpf_mbox_intr(npa);
	npa_afpf_mbox_destroy(npa);

	kfree(npa->irq_names);

	spin_lock(&npa_lst_lock);
	gnpa_pf_dev[npa->pf_id] = NULL;
	clear_bit(npa->pf_id, pf_bmp);
	spin_unlock(&npa_lst_lock);

	pci_free_irq_vectors(pdev);
	/* Unmap regions */
	iounmap(npa->mmio[NPA_REG_BASE].hw_addr);
	iounmap(npa->mmio[AFPF_MBOX_BASE].hw_addr);
	pci_set_drvdata(pdev, NULL);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	vfree(npa);
}

static struct pci_driver otx2_pf_driver = {
	.name = DRV_NAME,
	.id_table = otx2_npa_pf_id_table,
	.probe = otx2_npa_probe,
	.shutdown = otx2_npa_remove,
	.remove = otx2_npa_remove,
	.sriov_configure = otx2_npa_sriov_configure
};

static int __init otx2_npa_rvupf_init_module(void)
{
	pr_info("%s: %s\n", DRV_NAME, DRV_STRING);

	spin_lock_init(&npa_lst_lock);
	return pci_register_driver(&otx2_pf_driver);
}

static void __exit otx2_npa_rvupf_cleanup_module(void)
{
	pci_unregister_driver(&otx2_pf_driver);
}

module_init(otx2_npa_rvupf_init_module);
module_exit(otx2_npa_rvupf_cleanup_module);
