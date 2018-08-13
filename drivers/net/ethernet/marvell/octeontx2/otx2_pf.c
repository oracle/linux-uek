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

	/* Clear the IRQ */
	otx2_write64(pf, RVU_PF_INT, BIT_ULL(0));

	return IRQ_HANDLED;
}

static int otx2_register_mbox_intr(struct otx2_nic *pf)
{
	struct otx2_hw *hw = &pf->hw;
	int err;

	/* Skip if MSIX is already initialized */
	if (hw->num_vec)
		return 0;

	/* Enable MSI-X */
	err = otx2_enable_msix(hw);
	if (err)
		return err;

	/* Register mailbox interrupt handler */
	sprintf(&hw->irq_name[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE],
		"RVUPFAF Mbox");
	err = request_irq(pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_AFPF_MBOX),
			  otx2_pfaf_mbox_intr_handler, 0,
			  &hw->irq_name[RVU_PF_INT_VEC_AFPF_MBOX * NAME_SIZE],
			  pf);
	if (err) {
		dev_err(pf->dev,
			"RVUPF: IRQ registration failed for PFAF mbox irq\n");
		return err;
	}

	hw->irq_allocated[RVU_PF_INT_VEC_AFPF_MBOX] = true;

	/* Enable mailbox interrupt for msgs coming from AF.
	 * First clear to avoid spurious interrupts, if any.
	 */
	otx2_write64(pf, RVU_PF_INT, BIT_ULL(0));
	otx2_write64(pf, RVU_PF_INT_ENA_W1S, BIT_ULL(0));

	/* Check mailbox communication with AF */
	otx2_mbox_alloc_msg_READY(&pf->mbox);
	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		dev_warn(pf->dev,
			 "AF not responding to mailbox, deferring probe\n");
		return err;
	}
	return 0;
}

static void otx2_disable_mbox_intr(struct otx2_nic *pf)
{
	/* Disable AF => PF mailbox IRQ */
	otx2_write64(pf, RVU_PF_INT_ENA_W1C, BIT_ULL(0));
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

	INIT_WORK(&mbox->mbox_wrk, otx2_pfaf_mbox_handler);

	return 0;
exit:
	destroy_workqueue(pf->mbox_wq);
	return err;
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

static int otx2_set_real_num_queues(struct net_device *netdev,
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
	int err, lvl;

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

	/* Initialize RSS */
	err = otx2_rss_init(pf);
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
		kfree(sq->sg);
	}

	/* Free SQB pointers */
	otx2_free_aura_ptr(pf, NIX_AQ_CTYPE_SQ);

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
	otx2_free_aura_ptr(pf, NIX_AQ_CTYPE_RQ);

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

static int otx2_open(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct otx2_cq_poll *cq_poll = NULL;
	struct otx2_qset *qset = &pf->qset;
	int err = 0, qidx, vec;

	netif_carrier_off(netdev);

	err = otx2_register_mbox_intr(pf);
	if (err)
		return err;

	pf->qset.cq_cnt = pf->hw.rx_queues + pf->hw.tx_queues;
	/* RQ and SQs are mapped to different CQs,
	 * so find out max CQ IRQs (i.e CINTs) needed.
	 */
	pf->hw.cint_cnt = max(pf->hw.rx_queues, pf->hw.tx_queues);
	qset->napi = kcalloc(pf->hw.cint_cnt, sizeof(*cq_poll), GFP_KERNEL);
	if (!qset->napi)
		return -ENOMEM;

	qset->cq = kcalloc(pf->qset.cq_cnt,
			   sizeof(struct otx2_cq_queue), GFP_KERNEL);
	if (!qset->cq)
		goto freemem;

	qset->sq = kcalloc(pf->hw.tx_queues,
			   sizeof(struct otx2_snd_queue), GFP_KERNEL);
	if (!qset->sq)
		goto freemem;

	err = otx2_init_hw_resources(pf);
	if (err)
		goto freemem;

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
			goto cleanup;
	}

	/* Sync new MAC address to AF, if a change is pending */
	if (pf->set_mac_pending) {
		err = otx2_hw_set_mac_addr(pf, netdev);
		if (err)
			goto cleanup;
		pf->set_mac_pending = false;
	}

	/* Set default MTU in HW */
	err = otx2_hw_set_mtu(pf, netdev->mtu);
	if (err)
		goto cleanup;

	/* Register CQ IRQ handlers */
	vec = pf->hw.nix_msixoff + NIX_LF_CINT_VEC_START;
	for (qidx = 0; qidx < pf->hw.cint_cnt; qidx++) {
		sprintf(&pf->hw.irq_name[vec * NAME_SIZE], "%s-rxtx-%d",
			pf->netdev->name, qidx);

		err = request_irq(pci_irq_vector(pf->pdev, vec),
				  otx2_cq_intr_handler, 0,
				  &pf->hw.irq_name[vec * NAME_SIZE],
				  &qset->napi[qidx]);
		if (err) {
			dev_err(pf->dev,
				"RVUPF%d: IRQ registration failed for CQ%d\n",
				rvu_get_pf(pf->pcifunc), qidx);
			goto cleanup;
		}
		pf->hw.irq_allocated[vec] = true;
		vec++;

		/* Configure CQE interrupt coalescing parameters.
		 * Set ECOUNT_WAIT and QCOUNT_WAIT to non-zero values.
		 * TODO: Add timer expiry coalescing as well,
		 * for now trigger a IRQ when CQE count >= 1.
		 */
		otx2_write64(pf, NIX_LF_CINTX_WAIT(qidx), 0x00);

		/* Enable CQ IRQ */
		otx2_write64(pf, NIX_LF_CINTX_INT(qidx), BIT_ULL(0));
		otx2_write64(pf, NIX_LF_CINTX_ENA_W1S(qidx), BIT_ULL(0));
	}

	otx2_set_irq_affinity(pf);

	err = otx2_rxtx_enable(pf, true);
	if (err)
		goto cleanup;

	pf->intf_down = false;
	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);

	return 0;

cleanup:
	otx2_disable_napi(pf);
	otx2_disable_msix(pf);
freemem:
	kfree(qset->sq);
	kfree(qset->cq);
	kfree(qset->napi);
	return err;
}

static int otx2_stop(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct otx2_cq_poll *cq_poll = NULL;
	struct otx2_qset *qset = &pf->qset;
	int qidx, vec;

	/* First stop packet Rx/Tx at CGX */
	otx2_rxtx_enable(pf, false);

	pf->intf_down = true;
	/* 'intf_down' may be checked on any cpu */
	smp_wmb();

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

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
	otx2_disable_msix(pf);

	otx2_disable_napi(pf);

	for (qidx = 0; qidx < netdev->num_tx_queues; qidx++)
		netdev_tx_reset_queue(netdev_get_tx_queue(netdev, qidx));

	kfree(qset->sq);
	kfree(qset->cq);
	kfree(qset->napi);
	memset(qset, 0, sizeof(*qset));
	return 0;
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
	return 0;
}

static const struct net_device_ops otx2_netdev_ops = {
	.ndo_open		= otx2_open,
	.ndo_stop		= otx2_stop,
	.ndo_start_xmit		= otx2_xmit,
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

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
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
	hw->rqpool_cnt = qcount;

	/* Map CSRs */
	pf->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!pf->reg_base) {
		dev_err(dev, "Unable to map physical function CSRs, aborting\n");
		err = -ENOMEM;
		goto err_free_netdev;
	}

	/* Init PF <=> AF mailbox stuff */
	err = otx2_pfaf_mbox_init(pf);
	if (err)
		goto err_free_netdev;

	/* Register mailbox interrupt */
	err = otx2_register_mbox_intr(pf);
	if (err)
		goto err_irq;

	/* Request AF to attach NPA and NIX LFs to this PF.
	 * NIX and NPA LFs are needed for this PF to function as a NIC.
	 */
	err = otx2_attach_npa_nix(pf);
	if (err)
		goto err_irq;

	err = otx2_set_real_num_queues(netdev, hw->tx_queues, hw->rx_queues);
	if (err)
		goto err_detach_rsrc;

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
			       NETIF_F_TSO | NETIF_F_TSO6);
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

	return 0;

err_detach_rsrc:
	otx2_detach_resources(&pf->mbox);
err_irq:
	otx2_disable_msix(pf);
	otx2_pfaf_mbox_destroy(pf);
err_free_netdev:
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	return err;
}

static void otx2_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct otx2_nic *pf;

	if (!netdev)
		return;

	pf = netdev_priv(netdev);
	unregister_netdev(netdev);

	otx2_disable_mbox_intr(pf);
	otx2_disable_msix(pf);
	otx2_detach_resources(&pf->mbox);
	otx2_pfaf_mbox_destroy(pf);

	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
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
