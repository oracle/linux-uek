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

#include "otx2_reg.h"
#include "otx2_common.h"

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

static void otx2_disable_mbox_intr(struct otx2_nic *pf)
{
	int vector = pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_AFPF_MBOX);

	/* Disable AF => PF mailbox IRQ */
	otx2_write64(pf, RVU_PF_INT_ENA_W1C, BIT_ULL(0));
	free_irq(vector, pf);
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
	req = otx2_mbox_alloc_msg_ready(&pf->mbox);
	if (!req) {
		otx2_disable_mbox_intr(pf);
		return -ENOMEM;
	}
	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		dev_warn(pf->dev,
			 "AF not responding to mailbox, deferring probe\n");
		otx2_disable_mbox_intr(pf);
		return -EPROBE_DEFER;
	}

	return 0;
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

static int otx2_open(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	int err = 0;

	netif_carrier_off(netdev);

	err = otx2_register_mbox_intr(pf);
	if (err)
		return err;

	return 0;
}

static int otx2_stop(struct net_device *netdev)
{
	return 0;
}

static const struct net_device_ops otx2_netdev_ops = {
	.ndo_open		= otx2_open,
	.ndo_stop		= otx2_stop,
};

static int otx2_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct otx2_nic *pf;
	struct otx2_hw *hw;
	int err, qcount;
	int num_vec;

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
	qcount = num_online_cpus();

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

	num_vec = pci_msix_vec_count(pdev);
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

	/* Map CSRs */
	pf->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!pf->reg_base) {
		dev_err(dev, "Unable to map physical function CSRs, aborting\n");
		err = -ENOMEM;
		goto err_free_irq_vectors;
	}

	/* Init PF <=> AF mailbox stuff */
	err = otx2_pfaf_mbox_init(pf);
	if (err)
		goto err_free_irq_vectors;

	/* Register mailbox interrupt */
	err = otx2_register_mbox_intr(pf);
	if (err)
		goto err_mbox_destroy;

	err = otx2_set_real_num_queues(netdev, hw->tx_queues, hw->rx_queues);
	if (err)
		goto err_disable_mbox_intr;

	netdev->netdev_ops = &otx2_netdev_ops;
	err = register_netdev(netdev);
	if (err) {
		dev_err(dev, "Failed to register netdevice\n");
		goto err_disable_mbox_intr;
	}

	return 0;

err_disable_mbox_intr:
	otx2_disable_mbox_intr(pf);
err_mbox_destroy:
	otx2_pfaf_mbox_destroy(pf);
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

	if (!netdev)
		return;

	pf = netdev_priv(netdev);
	unregister_netdev(netdev);

	otx2_disable_mbox_intr(pf);
	otx2_pfaf_mbox_destroy(pf);

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
