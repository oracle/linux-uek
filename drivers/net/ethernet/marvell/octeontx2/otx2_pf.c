// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Physcial Function ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
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
#include <net/ip.h>
#include <linux/iommu.h>

#include "otx2_reg.h"
#include "otx2_common.h"
#include "otx2_txrx.h"
#include "otx2_struct.h"

#define DRV_NAME	"octeontx2-nicpf"
#define DRV_STRING	"Marvell OcteonTX2 NIC Physical Function Driver"
#define DRV_VERSION	"1.0"

/* Supported devices */
static const struct pci_device_id otx2_pf_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_RVU_PF) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION(DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, otx2_pf_id_table);

static void otx2_process_pfaf_mbox_msg(struct otx2_nic *pf,
				       struct mbox_msghdr *msg)
{
	if (msg->id >= MBOX_MSG_MAX) {
		dev_err(pf->dev,
			"Mbox msg with unknown ID 0x%x\n", msg->id);
		return;
	}

	if (msg->sig != OTX2_MBOX_RSP_SIG) {
		dev_err(pf->dev,
			"Mbox msg with wrong signature %x, ID 0x%x\n",
			 msg->sig, msg->id);
		return;
	}

	switch (msg->id) {
	case MBOX_MSG_READY:
		pf->pcifunc = msg->pcifunc;
		break;
	case MBOX_MSG_MSIX_OFFSET:
		mbox_handler_MSIX_OFFSET(pf, (struct msix_offset_rsp *)msg);
		break;
	case MBOX_MSG_NPA_LF_ALLOC:
		mbox_handler_NPA_LF_ALLOC(pf, (struct npa_lf_alloc_rsp *)msg);
		break;
	case MBOX_MSG_NIX_LF_ALLOC:
		mbox_handler_NIX_LF_ALLOC(pf, (struct nix_lf_alloc_rsp *)msg);
		break;
	case MBOX_MSG_NIX_TXSCH_ALLOC:
		mbox_handler_NIX_TXSCH_ALLOC(pf,
					     (struct nix_txsch_alloc_rsp *)msg);
		break;
	case MBOX_MSG_CGX_STATS:
		mbox_handler_CGX_STATS(pf, (struct cgx_stats_rsp *)msg);
		break;
	default:
		if (msg->rc)
			dev_err(pf->dev,
				"Mbox msg response has err %d, ID 0x%x\n",
				msg->rc, msg->id);
		break;
	}
}

static void otx2_pfaf_mbox_handler(struct work_struct *work)
{
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	struct otx2_mbox *mbox;
	struct mbox *af_mbox;
	int offset, id;

	af_mbox = container_of(work, struct mbox, mbox_wrk);
	mbox = &af_mbox->mbox;
	mdev = &mbox->dev[0];
	rsp_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;
	offset = mbox->rx_start + ALIGN(sizeof(*rsp_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < rsp_hdr->num_msgs; id++) {
		msg = (struct mbox_msghdr *)(mdev->mbase + offset);
		otx2_process_pfaf_mbox_msg(af_mbox->pfvf, msg);
		offset = mbox->rx_start + msg->next_msgoff;
		mdev->msgs_acked++;
	}

	otx2_mbox_reset(mbox, 0);

	/* Clear the IRQ */
	smp_wmb();
	otx2_write64(af_mbox->pfvf, RVU_PF_INT, BIT_ULL(0));
}

static int otx2_mbox_up_handler_CGX_LINK_EVENT(struct otx2_nic *pf,
					       struct cgx_link_info_msg *msg,
					       struct msg_rsp *rsp)
{
	struct cgx_link_user_info *linfo = &msg->link_info;
	struct net_device *netdev = pf->netdev;

	pr_info("%s NIC Link is %s\n",
		netdev->name, linfo->link_up ? "UP" : "DOWN");
	if (linfo->link_up) {
		netif_carrier_on(netdev);
		netif_tx_start_all_queues(netdev);
	} else {
		netif_tx_stop_all_queues(netdev);
		netif_carrier_off(netdev);
	}
	return 0;
}

static int otx2_process_mbox_msg_up(struct otx2_nic *pf,
				    struct mbox_msghdr *req)
{
	/* Check if valid, if not reply with a invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG) {
		otx2_reply_invalid_msg(&pf->mbox.mbox_up, 0, 0, req->id);
		return -ENODEV;
	}

	switch (req->id) {
#define M(_name, _id, _req_type, _rsp_type)				\
	case _id: {							\
		struct _rsp_type *rsp;					\
		int err;						\
									\
		rsp = (struct _rsp_type *)otx2_mbox_alloc_msg(		\
			&pf->mbox.mbox_up, 0,				\
			sizeof(struct _rsp_type));			\
		if (!rsp)						\
			return -ENOMEM;					\
									\
		rsp->hdr.id = _id;					\
		rsp->hdr.sig = OTX2_MBOX_RSP_SIG;			\
		rsp->hdr.pcifunc = 0;					\
		rsp->hdr.rc = 0;					\
									\
		err = otx2_mbox_up_handler_ ## _name(			\
			pf, (struct _req_type *)req, rsp);		\
		return err;						\
	}
MBOX_UP_CGX_MESSAGES
#undef M
		break;
	default:
		otx2_reply_invalid_msg(&pf->mbox.mbox_up, 0, 0, req->id);
		return -ENODEV;
	}
	return 0;
}

static void otx2_pfaf_mbox_up_handler(struct work_struct *work)
{
	struct mbox *af_mbox = container_of(work, struct mbox, mbox_up_wrk);
	struct otx2_mbox *mbox = &af_mbox->mbox_up;
	struct otx2_nic *pf = af_mbox->pfvf;
	struct otx2_mbox_dev *mdev = &mbox->dev[0];
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	int offset, id;
	int err;

	rsp_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;

	offset = mbox->rx_start + ALIGN(sizeof(*rsp_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < rsp_hdr->num_msgs; id++) {
		msg = (struct mbox_msghdr *)(mdev->mbase + offset);

		err = otx2_process_mbox_msg_up(pf, msg);
		if (err) {
			dev_warn(pf->dev, "Error %d when processing message %s from AF\n",
				 err, otx2_mbox_id2name(msg->id));
		}
		offset = mbox->rx_start + msg->next_msgoff;
	}

	otx2_mbox_msg_send(mbox, 0);
}

static irqreturn_t otx2_pfaf_mbox_intr_handler(int irq, void *pf_irq)
{
	struct otx2_nic *pf = (struct otx2_nic *)pf_irq;
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;

	/* Read latest mbox data */
	smp_rmb();

	/* Check for AF => PF response messages */
	mbox = &pf->mbox.mbox;
	mdev = &mbox->dev[0];
	hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	if (hdr->num_msgs)
		queue_work(pf->mbox_wq, &pf->mbox.mbox_wrk);

	/* Check for AF => PF notification messages */
	mbox = &pf->mbox.mbox_up;
	mdev = &mbox->dev[0];
	hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	if (hdr->num_msgs)
		queue_work(pf->mbox_wq, &pf->mbox.mbox_up_wrk);

	/* Clear the IRQ */
	otx2_write64(pf, RVU_PF_INT, BIT_ULL(0));

	return IRQ_HANDLED;
}

static int otx2_register_mbox_intr(struct otx2_nic *pf)
{
	struct otx2_hw *hw = &pf->hw;
	struct msg_req *req;
	char *irq_name;
	int err;

	/* Register mailbox interrupt handler */
	irq_name = &hw->irq_name[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE];
	snprintf(irq_name, NAME_SIZE, "RVUPFAF Mbox");
	err = request_irq(pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_AFPF_MBOX),
			  otx2_pfaf_mbox_intr_handler, 0, irq_name, pf);
	if (err) {
		dev_err(pf->dev,
			"RVUPF: IRQ registration failed for PFAF mbox irq\n");
		return err;
	}

	/* Enable mailbox interrupt for msgs coming from AF.
	 * First clear to avoid spurious interrupts, if any.
	 */
	otx2_write64(pf, RVU_PF_INT, BIT_ULL(0));
	otx2_write64(pf, RVU_PF_INT_ENA_W1S, BIT_ULL(0));

	/* Check mailbox communication with AF */
	req = otx2_mbox_alloc_msg_READY(&pf->mbox);
	if (!req)
		return -ENOMEM;

	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		dev_warn(pf->dev,
			 "AF not responding to mailbox, deferring probe\n");
		return -EPROBE_DEFER;
	}
	return 0;
}

static void otx2_disable_mbox_intr(struct otx2_nic *pf)
{
	int vector = pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_AFPF_MBOX);

	/* Disable AF => PF mailbox IRQ */
	otx2_write64(pf, RVU_PF_INT_ENA_W1C, BIT_ULL(0));
	free_irq(vector, pf);
}

static void otx2_pfaf_mbox_destroy(struct otx2_nic *pf)
{
	struct mbox *mbox = &pf->mbox;

	if (pf->mbox_wq) {
		flush_workqueue(pf->mbox_wq);
		destroy_workqueue(pf->mbox_wq);
		pf->mbox_wq = NULL;
	}

	if (mbox->mbox.hwbase)
		iounmap((void __iomem *)mbox->mbox.hwbase);

	otx2_mbox_destroy(&mbox->mbox);
	otx2_mbox_destroy(&mbox->mbox_up);
}

static int otx2_pfaf_mbox_init(struct otx2_nic *pf)
{
	struct mbox *mbox = &pf->mbox;
	void __iomem *hwbase;
	int err;

	mbox->pfvf = pf;
	pf->mbox_wq = alloc_workqueue("otx2_pfaf_mailbox",
				      WQ_UNBOUND | WQ_HIGHPRI |
				      WQ_MEM_RECLAIM, 1);
	if (!pf->mbox_wq)
		return -ENOMEM;

	/* Mailbox is a reserved memory (in RAM) region shared between
	 * admin function (i.e AF) and this PF, shouldn't be mapped as
	 * device memory to allow unaligned accesses.
	 */
	hwbase = ioremap_wc(pci_resource_start(pf->pdev, PCI_MBOX_BAR_NUM),
			    pci_resource_len(pf->pdev, PCI_MBOX_BAR_NUM));
	if (!hwbase) {
		dev_err(pf->dev, "Unable to map PFAF mailbox region\n");
		err = -ENOMEM;
		goto exit;
	}

	err = otx2_mbox_init(&mbox->mbox, hwbase, pf->pdev, pf->reg_base,
			     MBOX_DIR_PFAF, 1);
	if (err)
		goto exit;

	err = otx2_mbox_init(&mbox->mbox_up, hwbase, pf->pdev, pf->reg_base,
			     MBOX_DIR_PFAF_UP, 1);
	if (err)
		goto exit;

	INIT_WORK(&mbox->mbox_wrk, otx2_pfaf_mbox_handler);
	INIT_WORK(&mbox->mbox_up_wrk, otx2_pfaf_mbox_up_handler);

	return 0;
exit:
	destroy_workqueue(pf->mbox_wq);
	return err;
}

static int otx2_cgx_config_linkevents(struct otx2_nic *pf, bool enable)
{
	struct msg_req *msg;

	if (enable)
		msg = otx2_mbox_alloc_msg_CGX_START_LINKEVENTS(&pf->mbox);
	else
		msg = otx2_mbox_alloc_msg_CGX_STOP_LINKEVENTS(&pf->mbox);

	if (!msg)
		return -ENOMEM;

	return otx2_sync_mbox_msg(&pf->mbox);
}

static int otx2_cgx_config_loopback(struct otx2_nic *pf, bool enable)
{
	struct msg_req *msg;

	if (enable)
		msg = otx2_mbox_alloc_msg_CGX_INTLBK_ENABLE(&pf->mbox);
	else
		msg = otx2_mbox_alloc_msg_CGX_INTLBK_DISABLE(&pf->mbox);

	if (!msg)
		return -ENOMEM;

	return otx2_sync_mbox_msg(&pf->mbox);
}

static int otx2_enable_rxvlan(struct otx2_nic *pf, bool enable)
{
	struct nix_vtag_config *req;
	struct mbox_msghdr *rsp_hdr;
	int err;

	req = otx2_mbox_alloc_msg_NIX_VTAG_CFG(&pf->mbox);
	if (!req)
		return -ENOMEM;

	req->vtag_size = 0;
	req->cfg_type = 1;
	/* must be set to zero */
	req->rx.vtag_type = 0;
	req->rx.strip_vtag = enable;
	req->rx.capture_vtag = enable;

	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err)
		return err;

	rsp_hdr = otx2_mbox_get_rsp(&pf->mbox.mbox, 0, &req->hdr);
	if (IS_ERR(rsp_hdr))
		return PTR_ERR(rsp_hdr);

	return rsp_hdr->rc;
}

int otx2_set_real_num_queues(struct net_device *netdev,
			     int tx_queues, int rx_queues)
{
	int err;

	err = netif_set_real_num_tx_queues(netdev, tx_queues);
	if (err) {
		netdev_err(netdev,
			   "Failed to set no of Tx queues: %d\n", tx_queues);
		return err;
	}

	err = netif_set_real_num_rx_queues(netdev, rx_queues);
	if (err)
		netdev_err(netdev,
			   "Failed to set no of Rx queues: %d\n", rx_queues);
	return err;
}
EXPORT_SYMBOL(otx2_set_real_num_queues);

static void otx2_alloc_rxvlan(struct otx2_nic *pf)
{
	netdev_features_t old, wanted = NETIF_F_HW_VLAN_STAG_RX |
					NETIF_F_HW_VLAN_CTAG_RX;
	struct mbox_msghdr *rsp_hdr;
	struct msg_req *req;
	int err;

	req = otx2_mbox_alloc_msg_NIX_RXVLAN_ALLOC(&pf->mbox);
	if (!req)
		return;

	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err)
		return;

	rsp_hdr = otx2_mbox_get_rsp(&pf->mbox.mbox, 0, &req->hdr);
	if (IS_ERR(rsp_hdr))
		return;

	old = pf->netdev->hw_features;
	if (rsp_hdr->rc) {
		/* in case of failure during rxvlan allocation
		 * features must be updated accordingly
		 */
		dev_info(pf->dev,
			 "Disabling RX VLAN offload due to non-availability of MCAM space\n");
		pf->netdev->hw_features &= ~wanted;
		pf->netdev->features &= ~wanted;
	} else if (!(pf->netdev->hw_features & wanted)) {
		/* we are recovering from the previous failure */
		pf->netdev->hw_features |= wanted;
		err = otx2_enable_rxvlan(pf, true);
		if (!err)
			pf->netdev->features |= wanted;
	} else if (pf->netdev->features & wanted) {
		/* interface is going up */
		err = otx2_enable_rxvlan(pf, true);
		if (err) {
			pf->netdev->features &= ~wanted;
			netdev_features_change(pf->netdev);
		}
	}

	if (old != pf->netdev->hw_features)
		netdev_features_change(pf->netdev);
}

static irqreturn_t otx2_q_intr_handler(int irq, void *data)
{
	struct otx2_nic *pf = data;
	atomic64_t *ptr;
	u64 qidx = 0;
	u64 val;

	/* CQ */
	for (qidx = 0; qidx < pf->qset.cq_cnt; qidx++) {
		ptr = pf->reg_base + NIX_LF_CQ_OP_INT;
		val = atomic64_fetch_add_relaxed((qidx << 32) |
						 NIX_CQERRINT_BITS, ptr);

		if (!(val & (NIX_CQERRINT_BITS | BIT_ULL(42))))
			continue;

		if (val & BIT_ULL(42)) {
			dev_err(pf->dev, "CQ%lld: error reading NIX_LF_CQ_OP_INT\n",
				qidx);
		} else {
			if (val & BIT_ULL(NIX_CQERRINT_DOOR_ERR))
				dev_err(pf->dev, "CQ%lld: Doorbell error",
					qidx);
			if (val & BIT_ULL(NIX_CQERRINT_WR_FULL))
				dev_err(pf->dev, "CQ%lld: Write full. A CQE to be added has been dropped because the CQ is full",
					qidx);
			if (val & BIT_ULL(NIX_CQERRINT_CQE_FAULT))
				dev_err(pf->dev, "CQ%lld: Memory fault on CQE write to LLC/DRAM",
					qidx);
		}

		schedule_work(&pf->reset_task);
	}

	/* RQ */
	for (qidx = 0; qidx < pf->hw.rx_queues; qidx++) {
		ptr = pf->reg_base + NIX_LF_RQ_OP_INT;
		val = atomic64_fetch_add_relaxed((qidx << 32) | NIX_RQINT_BITS,
						 ptr);
		if (!(val & (NIX_RQINT_BITS | BIT_ULL(42))))
			continue;

		if (val & BIT_ULL(42)) {
			dev_err(pf->dev, "RQ%lld: error reading NIX_LF_RQ_OP_INT\n",
				qidx);
			schedule_work(&pf->reset_task);
		} else {
			if (val & BIT_ULL(NIX_RQINT_DROP))
				this_cpu_inc(pf->hw.pcpu_stats->rq_drops);
			if (val & BIT_ULL(NIX_RQINT_RED))
				this_cpu_inc(pf->hw.pcpu_stats->rq_red_drops);
		}
	}

	/* SQ */
	for (qidx = 0; qidx < pf->hw.tx_queues; qidx++) {
		ptr = pf->reg_base + NIX_LF_SQ_OP_INT;
		val = atomic64_fetch_add_relaxed((qidx << 32) | NIX_SQINT_BITS,
						 ptr);
		if (!(val & (NIX_SQINT_BITS | BIT_ULL(42))))
			continue;

		if (val & BIT_ULL(42)) {
			dev_err(pf->dev, "SQ%lld: error reading NIX_LF_SQ_OP_INT\n",
				qidx);
		} else {
			if (val & BIT_ULL(NIX_SQINT_LMT_ERR))
				dev_err(pf->dev, "SQ%lld: LMT store error",
					qidx);
			if (val & BIT_ULL(NIX_SQINT_MNQ_ERR))
				dev_err(pf->dev, "SQ%lld: Meta-descriptor enqueue error",
					qidx);
			if (val & BIT_ULL(NIX_SQINT_SEND_ERR))
				dev_err(pf->dev, "SQ%lld: Send error", qidx);
			if (val & BIT_ULL(NIX_SQINT_SQB_ALLOC_FAIL))
				dev_err(pf->dev, "SQ%lld: SQB allocation failed",
					qidx);
		}

		schedule_work(&pf->reset_task);
	}

	return IRQ_HANDLED;
}

static irqreturn_t otx2_cq_intr_handler(int irq, void *cq_irq)
{
	struct otx2_cq_poll *cq_poll = (struct otx2_cq_poll *)cq_irq;
	struct otx2_nic *pf = (struct otx2_nic *)cq_poll->dev;
	int qidx = cq_poll->cint_idx;

	/* Disable interrupts.
	 *
	 * Completion interrupts behave in a level-triggered interrupt
	 * fashion, and hence have to be cleared only after it is serviced.
	 */
	otx2_write64(pf, NIX_LF_CINTX_ENA_W1C(qidx), BIT_ULL(0));

	/* Schedule NAPI */
	napi_schedule_irqoff(&cq_poll->napi);

	return IRQ_HANDLED;
}

static void otx2_disable_napi(struct otx2_nic *pf)
{
	struct otx2_qset *qset = &pf->qset;
	struct otx2_cq_poll *cq_poll;
	int qidx;

	for (qidx = 0; qidx < pf->hw.cint_cnt; qidx++) {
		cq_poll = &qset->napi[qidx];
		napi_disable(&cq_poll->napi);
		netif_napi_del(&cq_poll->napi);
	}
}

static int otx2_init_hw_resources(struct otx2_nic *pf)
{
	struct otx2_hw *hw = &pf->hw;
	int err, lvl;

	/* Set required NPA LF's pool counts
	 * Auras and Pools are used in a 1:1 mapping,
	 * so, aura count = pool count.
	 */
	hw->rqpool_cnt = hw->rx_queues;
	hw->sqpool_cnt = hw->tx_queues;
	hw->pool_cnt = hw->rqpool_cnt + hw->sqpool_cnt;

	/* NPA init */
	err = otx2_config_npa(pf);
	if (err)
		return err;

	/* NIX init */
	err = otx2_config_nix(pf);
	if (err)
		return err;

	/* Init Auras and pools used by NIX RQ, for free buffer ptrs */
	err = otx2_rq_aura_pool_init(pf);
	if (err)
		return err;

	/* Init Auras and pools used by NIX SQ, for queueing SQEs */
	err = otx2_sq_aura_pool_init(pf);
	if (err)
		return err;

	err = otx2_txsch_alloc(pf);
	if (err)
		return err;

	err = otx2_config_nix_queues(pf);
	if (err)
		return err;

	for (lvl = 0; lvl < NIX_TXSCH_LVL_CNT; lvl++) {
		err = otx2_txschq_config(pf, lvl);
		if (err)
			return err;
	}

	return 0;
}

static void otx2_free_hw_resources(struct otx2_nic *pf)
{
	struct otx2_qset *qset = &pf->qset;
	struct mbox *mbox = &pf->mbox;
	struct otx2_snd_queue *sq;
	struct otx2_cq_queue *cq;
	int err, qidx, cqe_count;
	struct msg_req *req;

	/* Stop transmission */
	err = otx2_txschq_stop(pf);
	if (err)
		dev_err(pf->dev, "RVUPF: Failed to stop/free TX schedulers\n");

	/* Disable SQs */
	otx2_ctx_disable(mbox, NIX_AQ_CTYPE_SQ, false);
	for (qidx = 0; qidx < pf->hw.tx_queues; qidx++) {
		sq = &qset->sq[qidx];
		qmem_free(pf->dev, sq->sqe);
		if (!pf->hw.hw_tso)
			qmem_free(pf->dev, sq->tso_hdrs);
		kfree(sq->sg);
	}

	/* Free SQB pointers */
	otx2_free_aura_ptr(pf, AURA_NIX_SQ);

	/* Disable RQs */
	otx2_ctx_disable(mbox, NIX_AQ_CTYPE_RQ, false);

	/*Dequeue all CQEs */
	for (qidx = 0; qidx < qset->cq_cnt; qidx++) {
		cq = &qset->cq[qidx];
		cqe_count = otx2_read64(pf, NIX_LF_CINTX_CNT(cq->cint_idx));
		cqe_count &= 0xFFFFFFFF;
		if (cqe_count)
			otx2_napi_handler(cq, pf, cqe_count);
	}

	/* Free RQ buffer pointers*/
	otx2_free_aura_ptr(pf, AURA_NIX_RQ);

	/* Disable CQs*/
	otx2_ctx_disable(mbox, NIX_AQ_CTYPE_CQ, false);
	for (qidx = 0; qidx < qset->cq_cnt; qidx++) {
		cq = &qset->cq[qidx];
		qmem_free(pf->dev, cq->cqe);
	}

	/* Reset NIX LF */
	req = otx2_mbox_alloc_msg_NIX_LF_FREE(mbox);
	if (req)
		WARN_ON(otx2_sync_mbox_msg(mbox));

	/* Disable NPA Pool and Aura hw context */
	otx2_ctx_disable(mbox, NPA_AQ_CTYPE_POOL, true);
	otx2_ctx_disable(mbox, NPA_AQ_CTYPE_AURA, true);
	otx2_aura_pool_free(pf);

	/* Reset NPA LF */
	req = otx2_mbox_alloc_msg_NPA_LF_FREE(mbox);
	if (req)
		WARN_ON(otx2_sync_mbox_msg(mbox));
}

static netdev_tx_t otx2_xmit(struct sk_buff *skb, struct net_device *netdev)

{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct otx2_snd_queue *sq;
	int qidx = skb_get_queue_mapping(skb);
	struct netdev_queue *txq = netdev_get_tx_queue(netdev, qidx);

	/* Check for minimum packet length */
	if (skb->len <= ETH_HLEN) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	sq = &pf->qset.sq[qidx];

	if (!netif_tx_queue_stopped(txq) &&
	    !otx2_sq_append_skb(netdev, sq, skb, qidx)) {
		netif_tx_stop_queue(txq);

		/* Barrier, for stop_queue to be visible on other cpus */
		smp_mb();
		if ((sq->num_sqbs - *sq->aura_fc_addr) > 1)
			netif_tx_start_queue(txq);
		else
			netdev_warn(netdev,
				    "%s: No free SQE/SQB, stopping SQ%d\n",
				     netdev->name, qidx);

		return NETDEV_TX_BUSY;
	}

	return NETDEV_TX_OK;
}

int otx2_open(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct otx2_cq_poll *cq_poll = NULL;
	struct otx2_qset *qset = &pf->qset;
	int err = 0, qidx, vec, cpu;
	char *irq_name;

	/* Clear percpu stats */
	for_each_possible_cpu(cpu)
		memset(per_cpu_ptr(pf->hw.pcpu_stats, cpu), 0,
		       sizeof(struct otx2_pcpu_stats));

	netif_carrier_off(netdev);

	pf->qset.cq_cnt = pf->hw.rx_queues + pf->hw.tx_queues;
	/* RQ and SQs are mapped to different CQs,
	 * so find out max CQ IRQs (i.e CINTs) needed.
	 */
	pf->hw.cint_cnt = max(pf->hw.rx_queues, pf->hw.tx_queues);
	qset->napi = kcalloc(pf->hw.cint_cnt, sizeof(*cq_poll), GFP_KERNEL);
	if (!qset->napi)
		return -ENOMEM;

	/* CQ size of RQ */
	qset->rqe_cnt = qset->rqe_cnt ? qset->rqe_cnt : Q_COUNT(Q_SIZE_1K);
	/* CQ size of SQ */
	qset->sqe_cnt = qset->sqe_cnt ? qset->sqe_cnt : Q_COUNT(Q_SIZE_4K);

	err = -ENOMEM;
	qset->cq = kcalloc(pf->qset.cq_cnt,
			   sizeof(struct otx2_cq_queue), GFP_KERNEL);
	if (!qset->cq)
		goto err_free_mem;

	qset->sq = kcalloc(pf->hw.tx_queues,
			   sizeof(struct otx2_snd_queue), GFP_KERNEL);
	if (!qset->sq)
		goto err_free_mem;

	qset->rq = kcalloc(pf->hw.rx_queues,
			   sizeof(struct otx2_rcv_queue), GFP_KERNEL);
	if (!qset->rq)
		goto err_free_mem;

	err = otx2_init_hw_resources(pf);
	if (err)
		goto err_free_mem;

	/* Register NAPI handler */
	for (qidx = 0; qidx < pf->hw.cint_cnt; qidx++) {
		cq_poll = &qset->napi[qidx];
		cq_poll->cint_idx = qidx;
		/* RQ0 & SQ0 are mapped to CINT0 and so on..
		 * 'cq_ids[0]' points to RQ's CQ and
		 * 'cq_ids[1]' points to SQ's CQ and
		 */
		cq_poll->cq_ids[0] =
			(qidx <  pf->hw.rx_queues) ? qidx : CINT_INVALID_CQ;
		cq_poll->cq_ids[1] = (qidx < pf->hw.tx_queues) ?
				      qidx + pf->hw.rx_queues : CINT_INVALID_CQ;
		cq_poll->dev = (void *)pf;
		netif_napi_add(netdev, &cq_poll->napi,
			       otx2_poll, NAPI_POLL_WEIGHT);
		napi_enable(&cq_poll->napi);
	}

	/* Check if MAC address from AF is valid or else set a random MAC */
	if (is_zero_ether_addr(netdev->dev_addr)) {
		eth_hw_addr_random(netdev);
		err = otx2_hw_set_mac_addr(pf, netdev);
		if (err)
			goto err_disable_napi;
	}

	/* Set default MTU in HW */
	err = otx2_hw_set_mtu(pf, netdev->mtu);
	if (err)
		goto err_disable_napi;

	/* Initialize RSS */
	err = otx2_rss_init(pf);
	if (err)
		goto err_disable_napi;

	/* Register Queue IRQ handlers */
	vec = pf->hw.nix_msixoff + NIX_LF_QINT_VEC_START;
	irq_name = &pf->hw.irq_name[vec * NAME_SIZE];

	snprintf(irq_name, NAME_SIZE, "%s-qerr", pf->netdev->name);

	err = request_irq(pci_irq_vector(pf->pdev, vec),
			  otx2_q_intr_handler, 0, irq_name, pf);
	if (err) {
		dev_err(pf->dev,
			"RVUPF%d: IRQ registration failed for QERR\n",
			rvu_get_pf(pf->pcifunc));
		goto err_disable_napi;
	}

	/* Enable QINT IRQ */
	otx2_write64(pf, NIX_LF_QINTX_ENA_W1S(0), BIT_ULL(0));

	/* Register CQ IRQ handlers */
	vec = pf->hw.nix_msixoff + NIX_LF_CINT_VEC_START;
	for (qidx = 0; qidx < pf->hw.cint_cnt; qidx++) {
		irq_name = &pf->hw.irq_name[vec * NAME_SIZE];

		snprintf(irq_name, NAME_SIZE, "%s-rxtx-%d", pf->netdev->name,
			 qidx);

		err = request_irq(pci_irq_vector(pf->pdev, vec),
				  otx2_cq_intr_handler, 0, irq_name,
				  &qset->napi[qidx]);
		if (err) {
			dev_err(pf->dev,
				"RVUPF%d: IRQ registration failed for CQ%d\n",
				rvu_get_pf(pf->pcifunc), qidx);
			goto err_free_cints;
		}
		vec++;

		/* Configure CQE interrupt coalescing parameters */
		otx2_write64(pf, NIX_LF_CINTX_WAIT(qidx),
			     ((u64)pf->cq_time_wait << 48) |
			     pf->cq_ecount_wait);

		/* Enable CQ IRQ */
		otx2_write64(pf, NIX_LF_CINTX_INT(qidx), BIT_ULL(0));
		otx2_write64(pf, NIX_LF_CINTX_ENA_W1S(qidx), BIT_ULL(0));
	}

	otx2_set_cints_affinity(pf);

	err = otx2_rxtx_enable(pf, true);
	if (err)
		goto err_free_cints;

	pf->intf_down = false;

	/* Enable link notifications */
	otx2_cgx_config_linkevents(pf, true);

	/* Alloc rxvlan entry in MCAM for PFs only */
	if (!(pf->pcifunc & RVU_PFVF_FUNC_MASK))
		otx2_alloc_rxvlan(pf);

	return 0;

err_free_cints:
	otx2_free_cints(pf, qidx);
	vec = pci_irq_vector(pf->pdev,
			     pf->hw.nix_msixoff + NIX_LF_QINT_VEC_START);
	otx2_write64(pf, NIX_LF_QINTX_ENA_W1C(0), BIT_ULL(0));
	synchronize_irq(vec);
	free_irq(vec, pf);
err_disable_napi:
	otx2_disable_napi(pf);
	otx2_free_hw_resources(pf);
err_free_mem:
	kfree(qset->sq);
	kfree(qset->cq);
	kfree(qset->napi);
	return err;
}
EXPORT_SYMBOL(otx2_open);

int otx2_stop(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct otx2_cq_poll *cq_poll = NULL;
	struct otx2_qset *qset = &pf->qset;
	int qidx, vec;

	/* First stop packet Rx/Tx */
	otx2_rxtx_enable(pf, false);

	/* Disable link notifications */
	otx2_cgx_config_linkevents(pf, false);

	pf->intf_down = true;
	/* 'intf_down' may be checked on any cpu */
	smp_wmb();

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	/* Cleanup Queue IRQ */
	vec = pci_irq_vector(pf->pdev,
			     pf->hw.nix_msixoff + NIX_LF_QINT_VEC_START);
	otx2_write64(pf, NIX_LF_QINTX_ENA_W1C(0), BIT_ULL(0));
	synchronize_irq(vec);
	free_irq(vec, pf);

	/* Cleanup CQ NAPI and IRQ */
	vec = pf->hw.nix_msixoff + NIX_LF_CINT_VEC_START;
	for (qidx = 0; qidx < pf->hw.cint_cnt; qidx++) {
		/* Disable interrupt */
		otx2_write64(pf, NIX_LF_CINTX_ENA_W1C(qidx), BIT_ULL(0));

		synchronize_irq(pci_irq_vector(pf->pdev, vec));

		cq_poll = &qset->napi[qidx];
		napi_synchronize(&cq_poll->napi);
		vec++;
	}

	netif_tx_disable(netdev);
	otx2_free_hw_resources(pf);
	otx2_free_cints(pf, pf->hw.cint_cnt);

	otx2_disable_napi(pf);

	for (qidx = 0; qidx < netdev->num_tx_queues; qidx++)
		netdev_tx_reset_queue(netdev_get_tx_queue(netdev, qidx));

	kfree(qset->sq);
	kfree(qset->cq);
	kfree(qset->napi);
	memset(qset, 0, sizeof(*qset));
	return 0;
}
EXPORT_SYMBOL(otx2_stop);

static netdev_features_t otx2_fix_features(struct net_device *dev,
					   netdev_features_t features)
{
	if (features & NETIF_F_HW_VLAN_CTAG_RX)
		features |= NETIF_F_HW_VLAN_STAG_RX;
	else
		features &= ~NETIF_F_HW_VLAN_STAG_RX;

	return features;
}

static void otx2_set_rx_mode(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct nix_rx_mode *req;

	if (!(netdev->flags & IFF_UP))
		return;

	req = otx2_mbox_alloc_msg_NIX_SET_RX_MODE(&pf->mbox);
	if (!req)
		return;

	req->mode = NIX_RX_MODE_UCAST;

	/* We don't support MAC address filtering yet */
	if (netdev->flags & IFF_PROMISC)
		req->mode |= NIX_RX_MODE_PROMISC;
	else if (netdev->flags & IFF_ALLMULTI)
		req->mode |= NIX_RX_MODE_ALLMULTI;

	otx2_sync_mbox_msg_busy_poll(&pf->mbox);
}

static void otx2_reset_task(struct work_struct *work)
{
	struct otx2_nic *pf = container_of(work, struct otx2_nic, reset_task);

	if (!netif_running(pf->netdev))
		return;

	otx2_stop(pf->netdev);
	pf->reset_count++;
	otx2_open(pf->netdev);
	netif_trans_update(pf->netdev);
}

static int otx2_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	netdev_features_t changed = features ^ netdev->features;

	if ((changed & NETIF_F_LOOPBACK) && netif_running(netdev))
		return otx2_cgx_config_loopback(pf,
						features & NETIF_F_LOOPBACK);

	if ((changed & NETIF_F_HW_VLAN_CTAG_RX) && netif_running(netdev))
		return otx2_enable_rxvlan(pf,
					  features & NETIF_F_HW_VLAN_CTAG_RX);

	return 0;
}

static const struct net_device_ops otx2_netdev_ops = {
	.ndo_open		= otx2_open,
	.ndo_stop		= otx2_stop,
	.ndo_start_xmit		= otx2_xmit,
	.ndo_fix_features	= otx2_fix_features,
	.ndo_set_mac_address    = otx2_set_mac_address,
	.ndo_change_mtu         = otx2_change_mtu,
	.ndo_set_rx_mode        = otx2_set_rx_mode,
	.ndo_get_stats64	= otx2_get_stats64,
	.ndo_set_features	= otx2_set_features,
	.ndo_tx_timeout         = otx2_tx_timeout,
};

static int otx2_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct otx2_nic *pf;
	struct otx2_hw *hw;
	int    err, qcount;
	int    num_vec = pci_msix_vec_count(pdev);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		return err;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to set DMA mask\n");
		goto err_release_regions;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to set consistent DMA mask\n");
		goto err_release_regions;
	}

	pci_set_master(pdev);

	/* Set number of queues */
	qcount = min_t(int, num_online_cpus(), OTX2_MAX_CQ_CNT);

	netdev = alloc_etherdev_mqs(sizeof(*pf), qcount, qcount);
	if (!netdev) {
		err = -ENOMEM;
		goto err_release_regions;
	}

	pci_set_drvdata(pdev, netdev);
	SET_NETDEV_DEV(netdev, &pdev->dev);
	pf = netdev_priv(netdev);
	pf->netdev = netdev;
	pf->pdev = pdev;
	pf->dev = dev;
	hw = &pf->hw;
	hw->pdev = pdev;
	hw->rx_queues = qcount;
	hw->tx_queues = qcount;
	hw->max_queues = qcount;

	hw->irq_name = devm_kmalloc_array(&hw->pdev->dev, num_vec, NAME_SIZE,
					  GFP_KERNEL);
	if (!hw->irq_name)
		goto err_free_netdev;

	hw->affinity_mask = devm_kcalloc(&hw->pdev->dev, num_vec,
					 sizeof(cpumask_var_t), GFP_KERNEL);
	if (!hw->affinity_mask)
		goto err_free_netdev;

	err = pci_alloc_irq_vectors(hw->pdev, num_vec, num_vec, PCI_IRQ_MSIX);
	if (err < 0)
		goto err_free_netdev;

	hw->pcpu_stats = netdev_alloc_pcpu_stats(struct otx2_pcpu_stats);
	if (!hw->pcpu_stats) {
		err = -ENOMEM;
		goto err_free_irq_vectors;
	}

	/* Map CSRs */
	pf->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!pf->reg_base) {
		dev_err(dev, "Unable to map physical function CSRs, aborting\n");
		err = -ENOMEM;
		goto err_free_pcpu_stats;
	}

	/* Init PF <=> AF mailbox stuff */
	err = otx2_pfaf_mbox_init(pf);
	if (err)
		goto err_free_pcpu_stats;

	/* Register mailbox interrupt */
	err = otx2_register_mbox_intr(pf);
	if (err)
		goto err_mbox_destroy;

	/* Request AF to attach NPA and NIX LFs to this PF.
	 * NIX and NPA LFs are needed for this PF to function as a NIC.
	 */
	err = otx2_attach_npa_nix(pf);
	if (err)
		goto err_disable_mbox_intr;

	err = otx2_set_real_num_queues(netdev, hw->tx_queues, hw->rx_queues);
	if (err)
		goto err_detach_rsrc;

	if (!is_9xxx_pass1_silicon(pdev))
		hw->hw_tso = true;

	pf->cq_time_wait = CQ_TIMER_THRESH_DEFAULT;
	pf->cq_ecount_wait = CQ_CQE_THRESH_DEFAULT;

	/* NPA's pool is a stack to which SW frees buffer pointers via Aura.
	 * HW allocates buffer pointer from stack and uses it for DMA'ing
	 * ingress packet. In some scenarios HW can free back allocated buffer
	 * pointers to pool. This makes it impossible for SW to maintain a
	 * parallel list where physical addresses of buffer pointers (IOVAs)
	 * given to HW can be saved for later reference.
	 *
	 * So the only way to convert Rx packet's buffer address is to use
	 * IOMMU's iova_to_phys() handler which translates the address by
	 * walking through the translation tables.
	 *
	 * So check if device is binded to IOMMU, otherwise translation is
	 * not needed.
	 */
	pf->iommu_domain = iommu_get_domain_for_dev(dev);

	netdev->hw_features = (NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
			       NETIF_F_IPV6_CSUM | NETIF_F_RXHASH |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_TSO6 |
			       NETIF_F_HW_VLAN_STAG_RX |
			       NETIF_F_HW_VLAN_CTAG_RX);
	netdev->features |= netdev->hw_features;
	netdev->hw_features |= NETIF_F_LOOPBACK;

	netdev->gso_max_segs = OTX2_MAX_GSO_SEGS;

	netdev->netdev_ops = &otx2_netdev_ops;

	/* MTU range: 68 - 9190 */
	netdev->min_mtu = OTX2_MIN_MTU;
	netdev->max_mtu = OTX2_MAX_MTU;

	INIT_WORK(&pf->reset_task, otx2_reset_task);

	err = register_netdev(netdev);
	if (err) {
		dev_err(dev, "Failed to register netdevice\n");
		goto err_detach_rsrc;
	}

	otx2_set_ethtool_ops(netdev);
	return 0;

err_detach_rsrc:
	otx2_detach_resources(&pf->mbox);
err_disable_mbox_intr:
	otx2_disable_mbox_intr(pf);
err_mbox_destroy:
	otx2_pfaf_mbox_destroy(pf);
err_free_pcpu_stats:
	free_percpu(hw->pcpu_stats);
err_free_irq_vectors:
	pci_free_irq_vectors(hw->pdev);
err_free_netdev:
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);
err_release_regions:
	pci_release_regions(pdev);
	return err;
}

static void otx2_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct otx2_nic *pf;
	struct otx2_hw *hw;

	if (!netdev)
		return;

	pf = netdev_priv(netdev);
	hw = &pf->hw;
	unregister_netdev(netdev);

	otx2_disable_mbox_intr(pf);

	otx2_detach_resources(&pf->mbox);
	otx2_pfaf_mbox_destroy(pf);
	free_percpu(hw->pcpu_stats);
	pci_free_irq_vectors(pf->pdev);
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);

	pci_release_regions(pdev);
}

static struct pci_driver otx2_pf_driver = {
	.name = DRV_NAME,
	.id_table = otx2_pf_id_table,
	.probe = otx2_probe,
	.remove = otx2_remove,
};

static int __init otx2_rvupf_init_module(void)
{
	pr_info("%s: %s\n", DRV_NAME, DRV_STRING);

	return pci_register_driver(&otx2_pf_driver);
}

static void __exit otx2_rvupf_cleanup_module(void)
{
	pci_unregister_driver(&otx2_pf_driver);
}

module_init(otx2_rvupf_init_module);
module_exit(otx2_rvupf_cleanup_module);
