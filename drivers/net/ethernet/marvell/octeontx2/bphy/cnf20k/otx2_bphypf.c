// SPDX-License-Identifier: GPL-2.0
/* Marvell BPHY RVU PF Ethernet driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/of.h>
#include <linux/if_vlan.h>
#include <linux/iommu.h>
#include <net/ip.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/bitfield.h>

#include "otx2_reg.h"
#include "otx2_common.h"
#include "otx2_txrx.h"
#include "otx2_struct.h"
#include "otx2_ptp.h"
#include "cn10k.h"
#include "qos.h"
#include <rvu_trace.h>
#include "otx2_bphypf.h"
#include <rvu_cplt_mbox.h>

#define DRV_NAME	"rvu_bphy_nicpf"
#define DRV_STRING	"Marvell BPHY RVU PF Ethernet Driver"

/* Supported devices */
static const struct pci_device_id otx2_bphypf_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_RVU_BPHY_NIX_PF) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION(DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_DEVICE_TABLE(pci, otx2_bphypf_id_table);

enum {
	TYPE_PFAF,
	TYPE_PFVF,
};

static int otx2_bphypf_config_hw_tx_tstamp(struct otx2_nic *pfvf, bool enable);
static int otx2_bphypf_config_hw_rx_tstamp(struct otx2_nic *pfvf, bool enable);

static int otx2_bphypf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	bool if_up = netif_running(netdev);
	int err = 0;

	if (pf->xdp_prog && new_mtu > MAX_XDP_MTU) {
		netdev_warn(netdev, "Jumbo frames not yet supported with XDP, current MTU %d.\n",
			    netdev->mtu);
		return -EINVAL;
	}
	if (if_up)
		otx2_stop(netdev);

	netdev_info(netdev, "Changing MTU from %d to %d\n",
		    netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	if (if_up)
		err = otx2_open(netdev);

	return err;
}

static void __maybe_unused otx2_disable_flr_me_intr(struct otx2_nic *pf)
{
	int irq, vfs = pf->total_vfs;

	/* Disable VFs ME interrupts */
	otx2_write64(pf, RVU_PF_VFME_INT_ENA_W1CX(0), INTR_MASK(vfs));
	irq = pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFME0);
	free_irq(irq, pf);

	/* Disable VFs FLR interrupts */
	otx2_write64(pf, RVU_PF_VFFLR_INT_ENA_W1CX(0), INTR_MASK(vfs));
	irq = pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFFLR0);
	free_irq(irq, pf);

	if (vfs <= 64)
		return;

	otx2_write64(pf, RVU_PF_VFME_INT_ENA_W1CX(1), INTR_MASK(vfs - 64));
	irq = pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFME1);
	free_irq(irq, pf);

	otx2_write64(pf, RVU_PF_VFFLR_INT_ENA_W1CX(1), INTR_MASK(vfs - 64));
	irq = pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFFLR1);
	free_irq(irq, pf);
}

static void __maybe_unused otx2_flr_wq_destroy(struct otx2_nic *pf)
{
	if (!pf->flr_wq)
		return;
	destroy_workqueue(pf->flr_wq);
	pf->flr_wq = NULL;
	devm_kfree(pf->dev, pf->flr_wrk);
}

static void otx2_flr_handler(struct work_struct *work)
{
	struct flr_work *flrwork = container_of(work, struct flr_work, work);
	struct otx2_nic *pf = flrwork->pf;
	struct mbox *mbox = &pf->mbox;
	struct msg_req *req;
	int vf, reg = 0;

	vf = flrwork - pf->flr_wrk;

	mutex_lock(&mbox->lock);
	req = otx2_mbox_alloc_msg_vf_flr(mbox);
	if (!req) {
		mutex_unlock(&mbox->lock);
		return;
	}
	req->hdr.pcifunc &= RVU_PFVF_FUNC_MASK;
	req->hdr.pcifunc |= (vf + 1) & RVU_PFVF_FUNC_MASK;

	if (!otx2_sync_mbox_msg(&pf->mbox)) {
		if (vf >= 64) {
			reg = 1;
			vf = vf - 64;
		}
		/* clear transcation pending bit */
		otx2_write64(pf, RVU_PF_VFTRPENDX(reg), BIT_ULL(vf));
		otx2_write64(pf, RVU_PF_VFFLR_INT_ENA_W1SX(reg), BIT_ULL(vf));
	}

	mutex_unlock(&mbox->lock);
}

static irqreturn_t otx2_pf_flr_intr_handler(int irq, void *pf_irq)
{
	struct otx2_nic *pf = (struct otx2_nic *)pf_irq;
	int reg, dev, vf, start_vf, num_reg = 1;
	u64 intr;

	if (pf->total_vfs > 64)
		num_reg = 2;

	for (reg = 0; reg < num_reg; reg++) {
		intr = otx2_read64(pf, RVU_PF_VFFLR_INTX(reg));
		if (!intr)
			continue;
		start_vf = 64 * reg;
		for (vf = 0; vf < 64; vf++) {
			if (!(intr & BIT_ULL(vf)))
				continue;
			dev = vf + start_vf;
			queue_work(pf->flr_wq, &pf->flr_wrk[dev].work);
			/* Clear interrupt */
			otx2_write64(pf, RVU_PF_VFFLR_INTX(reg), BIT_ULL(vf));
			/* Disable the interrupt */
			otx2_write64(pf, RVU_PF_VFFLR_INT_ENA_W1CX(reg),
				     BIT_ULL(vf));
		}
	}
	return IRQ_HANDLED;
}

static irqreturn_t otx2_pf_me_intr_handler(int irq, void *pf_irq)
{
	struct otx2_nic *pf = (struct otx2_nic *)pf_irq;
	int vf, reg, num_reg = 1;
	u64 intr;

	if (pf->total_vfs > 64)
		num_reg = 2;

	for (reg = 0; reg < num_reg; reg++) {
		intr = otx2_read64(pf, RVU_PF_VFME_INTX(reg));
		if (!intr)
			continue;
		for (vf = 0; vf < 64; vf++) {
			if (!(intr & BIT_ULL(vf)))
				continue;
			/* clear trpend bit */
			otx2_write64(pf, RVU_PF_VFTRPENDX(reg), BIT_ULL(vf));
			/* clear interrupt */
			otx2_write64(pf, RVU_PF_VFME_INTX(reg), BIT_ULL(vf));
		}
	}
	return IRQ_HANDLED;
}

static int __maybe_unused otx2_register_flr_me_intr(struct otx2_nic *pf,
						    int numvfs)
{
	struct otx2_hw *hw = &pf->hw;
	char *irq_name;
	int ret;

	/* Register ME interrupt handler*/
	irq_name = &hw->irq_name[RVU_PF_INT_VEC_VFME0 * NAME_SIZE];
	snprintf(irq_name, NAME_SIZE, "RVUPF%d_ME0", rvu_get_pf(pf->pdev,
								pf->pcifunc));
	ret = request_irq(pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFME0),
			  otx2_pf_me_intr_handler, 0, irq_name, pf);
	if (ret) {
		dev_err(pf->dev,
			"RVUPF: IRQ registration failed for ME0\n");
	}

	/* Register FLR interrupt handler */
	irq_name = &hw->irq_name[RVU_PF_INT_VEC_VFFLR0 * NAME_SIZE];
	snprintf(irq_name, NAME_SIZE, "RVUPF%d_FLR0", rvu_get_pf(pf->pdev,
								 pf->pcifunc));
	ret = request_irq(pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFFLR0),
			  otx2_pf_flr_intr_handler, 0, irq_name, pf);
	if (ret) {
		dev_err(pf->dev,
			"RVUPF: IRQ registration failed for FLR0\n");
		return ret;
	}

	if (numvfs > 64) {
		irq_name = &hw->irq_name[RVU_PF_INT_VEC_VFME1 * NAME_SIZE];
		snprintf(irq_name, NAME_SIZE, "RVUPF%d_ME1",
			 rvu_get_pf(pf->pdev, pf->pcifunc));
		ret = request_irq(pci_irq_vector
				  (pf->pdev, RVU_PF_INT_VEC_VFME1),
				  otx2_pf_me_intr_handler, 0, irq_name, pf);
		if (ret) {
			dev_err(pf->dev,
				"RVUPF: IRQ registration failed for ME1\n");
		}
		irq_name = &hw->irq_name[RVU_PF_INT_VEC_VFFLR1 * NAME_SIZE];
		snprintf(irq_name, NAME_SIZE, "RVUPF%d_FLR1",
			 rvu_get_pf(pf->pdev, pf->pcifunc));
		ret = request_irq(pci_irq_vector
				  (pf->pdev, RVU_PF_INT_VEC_VFFLR1),
				  otx2_pf_flr_intr_handler, 0, irq_name, pf);
		if (ret) {
			dev_err(pf->dev,
				"RVUPF: IRQ registration failed for FLR1\n");
			return ret;
		}
	}

	/* Enable ME interrupt for all VFs*/
	otx2_write64(pf, RVU_PF_VFME_INTX(0), INTR_MASK(numvfs));
	otx2_write64(pf, RVU_PF_VFME_INT_ENA_W1SX(0), INTR_MASK(numvfs));

	/* Enable FLR interrupt for all VFs*/
	otx2_write64(pf, RVU_PF_VFFLR_INTX(0), INTR_MASK(numvfs));
	otx2_write64(pf, RVU_PF_VFFLR_INT_ENA_W1SX(0), INTR_MASK(numvfs));

	if (numvfs > 64) {
		numvfs -= 64;

		otx2_write64(pf, RVU_PF_VFME_INTX(1), INTR_MASK(numvfs));
		otx2_write64(pf, RVU_PF_VFME_INT_ENA_W1SX(1),
			     INTR_MASK(numvfs));

		otx2_write64(pf, RVU_PF_VFFLR_INTX(1), INTR_MASK(numvfs));
		otx2_write64(pf, RVU_PF_VFFLR_INT_ENA_W1SX(1),
			     INTR_MASK(numvfs));
	}
	return 0;
}

static int __maybe_unused otx2_pf_flr_init(struct otx2_nic *pf, int num_vfs)
{
	int vf;

	pf->flr_wq = alloc_ordered_workqueue("otx2_pf_flr_wq", WQ_HIGHPRI);
	if (!pf->flr_wq)
		return -ENOMEM;

	pf->flr_wrk = devm_kcalloc(pf->dev, num_vfs,
				   sizeof(struct flr_work), GFP_KERNEL);
	if (!pf->flr_wrk) {
		destroy_workqueue(pf->flr_wq);
		return -ENOMEM;
	}

	for (vf = 0; vf < num_vfs; vf++) {
		pf->flr_wrk[vf].pf = pf;
		INIT_WORK(&pf->flr_wrk[vf].work, otx2_flr_handler);
	}

	return 0;
}

static void otx2_bphypf_queue_vf_work(struct mbox *mw,
				      struct workqueue_struct *mbox_wq,
				      int first, int mdevs, u64 intr)
{
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *mbox;
	struct mbox_hdr *hdr;
	int i;

	for (i = first; i < mdevs; i++) {
		/* start from 0 */
		if (!(intr & BIT_ULL(i - first)))
			continue;

		mbox = &mw->mbox;
		mdev = &mbox->dev[i];
		hdr = mdev->mbase + mbox->rx_start;
		/* The hdr->num_msgs is set to zero immediately in the interrupt
		 * handler to ensure that it holds a correct value next time
		 * when the interrupt handler is called. pf->mw[i].num_msgs
		 * holds the data for use in otx2_pfvf_mbox_handler and
		 * pf->mw[i].up_num_msgs holds the data for use in
		 * otx2_pfvf_mbox_up_handler.
		 */
		if (hdr->num_msgs) {
			mw[i].num_msgs = hdr->num_msgs;
			hdr->num_msgs = 0;
			queue_work(mbox_wq, &mw[i].mbox_wrk);
		}

		mbox = &mw->mbox_up;
		mdev = &mbox->dev[i];
		hdr = mdev->mbase + mbox->rx_start;
		if (hdr->num_msgs) {
			mw[i].up_num_msgs = hdr->num_msgs;
			hdr->num_msgs = 0;
			queue_work(mbox_wq, &mw[i].mbox_up_wrk);
		}
	}
}

static void otx2_forward_msg_pfvf(struct otx2_mbox_dev *mdev,
				  struct otx2_mbox *pfvf_mbox, void *bbuf_base,
				  int devid)
{
	struct otx2_mbox_dev *src_mdev = mdev;
	int offset;

	/* Msgs are already copied, trigger VF's mbox irq */
	smp_wmb();

	otx2_mbox_wait_for_zero(pfvf_mbox, devid);

	offset = pfvf_mbox->trigger | (devid << pfvf_mbox->tr_shift);
	writeq(MBOX_DOWN_MSG, (void __iomem *)pfvf_mbox->reg_base + offset);

	/* Restore VF's mbox bounce buffer region address */
	src_mdev->mbase = bbuf_base;
}

static int __maybe_unused otx2_forward_vf_mbox_msgs(struct otx2_nic *pf,
						    struct otx2_mbox *src_mbox,
						    int dir, int vf,
						    int num_msgs)
{
	struct otx2_mbox_dev *src_mdev, *dst_mdev;
	struct mbox_hdr *mbox_hdr;
	struct mbox_hdr *req_hdr;
	struct mbox *dst_mbox;
	int dst_size, err;

	if (dir == MBOX_DIR_PFAF) {
		/* Set VF's mailbox memory as PF's bounce buffer memory, so
		 * that explicit copying of VF's msgs to PF=>AF mbox region
		 * and AF=>PF responses to VF's mbox region can be avoided.
		 */
		src_mdev = &src_mbox->dev[vf];
		mbox_hdr = src_mbox->hwbase +
				src_mbox->rx_start + (vf * MBOX_SIZE);

		dst_mbox = &pf->mbox;
		dst_size = dst_mbox->mbox.tx_size -
				ALIGN(sizeof(*mbox_hdr), MBOX_MSG_ALIGN);
		/* Check if msgs fit into destination area and has valid size */
		if (mbox_hdr->msg_size > dst_size || !mbox_hdr->msg_size)
			return -EINVAL;

		dst_mdev = &dst_mbox->mbox.dev[0];

		mutex_lock(&pf->mbox.lock);
		dst_mdev->mbase = src_mdev->mbase;
		dst_mdev->msg_size = mbox_hdr->msg_size;
		dst_mdev->num_msgs = num_msgs;
		err = otx2_sync_mbox_msg(dst_mbox);
		/* Error code -EIO indicate there is a communication failure
		 * to the AF. Rest of the error codes indicate that AF processed
		 * VF messages and set the error codes in response messages
		 * (if any) so simply forward responses to VF.
		 */
		if (err == -EIO) {
			dev_warn(pf->dev,
				 "AF not responding to VF%d messages\n", vf);
			/* restore PF mbase and exit */
			dst_mdev->mbase = pf->mbox.bbuf_base;
			mutex_unlock(&pf->mbox.lock);
			return err;
		}
		/* At this point, all the VF messages sent to AF are acked
		 * with proper responses and responses are copied to VF
		 * mailbox hence raise interrupt to VF.
		 */
		req_hdr = (struct mbox_hdr *)(dst_mdev->mbase +
					      dst_mbox->mbox.rx_start);
		req_hdr->num_msgs = num_msgs;

		otx2_forward_msg_pfvf(dst_mdev, &pf->mbox_pfvf[0].mbox,
				      pf->mbox.bbuf_base, vf);
		mutex_unlock(&pf->mbox.lock);
	} else if (dir == MBOX_DIR_PFVF_UP) {
		src_mdev = &src_mbox->dev[0];
		mbox_hdr = src_mbox->hwbase + src_mbox->rx_start;
		req_hdr = (struct mbox_hdr *)(src_mdev->mbase +
					      src_mbox->rx_start);
		req_hdr->num_msgs = num_msgs;

		dst_mbox = &pf->mbox_pfvf[0];
		dst_size = dst_mbox->mbox_up.tx_size -
				ALIGN(sizeof(*mbox_hdr), MBOX_MSG_ALIGN);
		/* Check if msgs fit into destination area */
		if (mbox_hdr->msg_size > dst_size)
			return -EINVAL;

		dst_mdev = &dst_mbox->mbox_up.dev[vf];
		dst_mdev->mbase = src_mdev->mbase;
		dst_mdev->msg_size = mbox_hdr->msg_size;
		dst_mdev->num_msgs = mbox_hdr->num_msgs;
		err = otx2_sync_mbox_up_msg(dst_mbox, vf);
		if (err) {
			dev_warn(pf->dev,
				 "VF%d is not responding to mailbox\n", vf);
			return err;
		}
	} else if (dir == MBOX_DIR_VFPF_UP) {
		req_hdr = (struct mbox_hdr *)(src_mbox->dev[0].mbase +
					      src_mbox->rx_start);
		req_hdr->num_msgs = num_msgs;
		otx2_forward_msg_pfvf(&pf->mbox_pfvf->mbox_up.dev[vf],
				      &pf->mbox.mbox_up,
				      pf->mbox_pfvf[vf].bbuf_base,
				      0);
	}

	return 0;
}

static irqreturn_t bphy_pfvf_mbox_intr_handler(int irq, void *pf_irq)
{
	struct otx2_nic *pf = (struct otx2_nic *)(pf_irq);
	int vfs = pf->total_vfs;
	struct mbox *mbox;
	u64 intr;

	mbox = pf->mbox_pfvf;
	/* Handle VF interrupts */
	if (vfs > 64) {
		intr = otx2_read64(pf, RVU_PF_VFPF_MBOX_INTX(1));
		otx2_write64(pf, RVU_PF_VFPF_MBOX_INTX(1), intr);
		otx2_bphypf_queue_vf_work(mbox, pf->mbox_pfvf_wq, 64, vfs,
					  intr);
		if (intr)
			trace_otx2_msg_interrupt(mbox->mbox.pdev,
						 "VF(s) to PF", intr);
		vfs = 64;
	}

	intr = otx2_read64(pf, RVU_PF_VFPF_MBOX_INTX(0));
	otx2_write64(pf, RVU_PF_VFPF_MBOX_INTX(0), intr);

	otx2_bphypf_queue_vf_work(mbox, pf->mbox_pfvf_wq, 0, vfs, intr);

	if (intr)
		trace_otx2_msg_interrupt(mbox->mbox.pdev, "VF(s) to PF", intr);

	return IRQ_HANDLED;
}

static void __maybe_unused *cn20k_pfvf_mbox_alloc(struct otx2_nic *pf,
						  int numvfs)
{
	struct qmem *mbox_addr;
	int err;

	err = qmem_alloc(&pf->pdev->dev, &mbox_addr, numvfs, MBOX_SIZE);
	if (err) {
		dev_err(pf->dev, "qmem alloc fail\n");
		return ERR_PTR(-ENOMEM);
	}

	otx2_write64(pf, RVU_PF_VF_MBOX_ADDR, (u64)mbox_addr->iova);
	pf->pfvf_mbox_addr = mbox_addr;

	return mbox_addr->base;
}

static void otx2_enable_pfvf_mbox_intr(struct otx2_nic *pf, int numvfs)
{
	/* Clear PF <=> VF mailbox IRQ */
	otx2_write64(pf, RVU_PF_VFPF_MBOX_INTX(0), ~0ull);
	otx2_write64(pf, RVU_PF_VFPF_MBOX_INTX(1), ~0ull);

	/* Enable PF <=> VF mailbox IRQ */
	otx2_write64(pf, RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0), INTR_MASK(numvfs));
	if (numvfs > 64) {
		numvfs -= 64;
		otx2_write64(pf, RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
			     INTR_MASK(numvfs));
	}
}

static int __maybe_unused otx2_register_pfvf_mbox_intr(struct otx2_nic *pf,
						       int numvfs)
{
	struct otx2_hw *hw = &pf->hw;
	char *irq_name;
	int err;

	if (is_cn20k(pf->pdev))
		return cn20k_register_pfvf_mbox_intr(pf, numvfs);

	/* Register MBOX0 interrupt handler */
	irq_name = &hw->irq_name[RVU_PF_INT_VEC_VFPF_MBOX0 * NAME_SIZE];
	if (pf->pcifunc)
		snprintf(irq_name, NAME_SIZE,
			 "RVUPF%d_VF Mbox0", rvu_get_pf(pf->pdev, pf->pcifunc));
	else
		snprintf(irq_name, NAME_SIZE, "RVUPF_VF Mbox0");
	err = request_irq(pci_irq_vector(pf->pdev, RVU_PF_INT_VEC_VFPF_MBOX0),
			  bphy_pfvf_mbox_intr_handler, 0, irq_name, pf);
	if (err) {
		dev_err(pf->dev,
			"RVUPF: IRQ registration failed for PFVF mbox0 irq\n");
		return err;
	}

	if (numvfs > 64) {
		/* Register MBOX1 interrupt handler */
		irq_name = &hw->irq_name[RVU_PF_INT_VEC_VFPF_MBOX1 * NAME_SIZE];
		if (pf->pcifunc)
			snprintf(irq_name, NAME_SIZE,
				 "RVUPF%d_VF Mbox1", rvu_get_pf(pf->pdev,
								pf->pcifunc));
		else
			snprintf(irq_name, NAME_SIZE, "RVUPF_VF Mbox1");
		err = request_irq(pci_irq_vector(pf->pdev,
						 RVU_PF_INT_VEC_VFPF_MBOX1),
						 bphy_pfvf_mbox_intr_handler,
						 0, irq_name, pf);
		if (err) {
			dev_err(pf->dev,
				"RVUPF: IRQ registration failed for PFVF mbox1 irq\n");
			return err;
		}
	}

	otx2_enable_pfvf_mbox_intr(pf, numvfs);

	return 0;
}

static void __maybe_unused otx2_process_pfaf_mbox_msg(struct otx2_nic *pf,
						      struct mbox_msghdr *msg)
{
	int devid;

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

	/* message response heading VF */
	devid = msg->pcifunc & RVU_PFVF_FUNC_MASK;
	if (devid) {
		struct otx2_vf_config *config = &pf->vf_configs[devid - 1];
		struct delayed_work *dwork;

		switch (msg->id) {
		case MBOX_MSG_NIX_LF_START_RX:
			config->intf_down = false;
			dwork = &config->link_event_work;
			schedule_delayed_work(dwork, msecs_to_jiffies(100));
			break;
		case MBOX_MSG_NIX_LF_STOP_RX:
			config->intf_down = true;
			break;
		}

		return;
	}

	switch (msg->id) {
	case MBOX_MSG_READY:
		pf->pcifunc = msg->pcifunc;
		break;
	case MBOX_MSG_MSIX_OFFSET:
		mbox_handler_msix_offset(pf, (struct msix_offset_rsp *)msg);
		break;
	case MBOX_MSG_NPA_LF_ALLOC:
		mbox_handler_npa_lf_alloc(pf, (struct npa_lf_alloc_rsp *)msg);
		break;
	case MBOX_MSG_NIX_LF_ALLOC:
		mbox_handler_nix_lf_alloc(pf, (struct nix_lf_alloc_rsp *)msg);
		break;
	case MBOX_MSG_NIX_BP_ENABLE:
		mbox_handler_nix_bp_enable(pf, (struct nix_bp_cfg_rsp *)msg);
		break;
	case MBOX_MSG_CGX_STATS:
		mbox_handler_cgx_stats(pf, (struct cgx_stats_rsp *)msg);
		break;
	case MBOX_MSG_CGX_FEC_STATS:
		mbox_handler_cgx_fec_stats(pf, (struct cgx_fec_stats_rsp *)msg);
		break;
	default:
		if (msg->rc)
			dev_err(pf->dev,
				"Mbox msg response has err %d, ID 0x%x\n",
				msg->rc, msg->id);
		break;
	}
}

static void __maybe_unused otx2_bphypf_handle_link_event(struct otx2_nic *pf)
{
	struct cgx_link_user_info *linfo = &pf->linfo;
	struct net_device *netdev = pf->netdev;

	if (pf->flags & OTX2_FLAG_PORT_UP)
		return;

	pr_info("%s NIC Link is %s %d Mbps %s duplex\n", netdev->name,
		linfo->link_up ? "UP" : "DOWN", linfo->speed,
		linfo->full_duplex ? "Full" : "Half");
	if (linfo->link_up) {
		netif_carrier_on(netdev);
		netif_tx_start_all_queues(netdev);
	} else {
		netif_carrier_off(netdev);
		netif_tx_stop_all_queues(netdev);
	}
}

static int __maybe_unused otx2_process_mbox_msg_up(struct otx2_nic *pf,
						   struct mbox_msghdr *req)
{
	/* Check if valid, if not reply with a invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG) {
		otx2_reply_invalid_msg(&pf->mbox.mbox_up, 0, 0, req->id);
		return -ENODEV;
	}

	switch (req->id) {
#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
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
		err = otx2_mbox_up_handler_ ## _fn_name(		\
			pf, (struct _req_type *)req, rsp);		\
		return err;						\
	}
MBOX_UP_CGX_MESSAGES
MBOX_UP_MCS_MESSAGES
#undef M
		break;
	default:
		otx2_reply_invalid_msg(&pf->mbox.mbox_up, 0, 0, req->id);
		return -ENODEV;
	}
	return 0;
}

static int otx2_cgx_config_linkevents(struct otx2_nic *pf, bool enable)
{
	struct msg_req *msg;
	int err;

	mutex_lock(&pf->mbox.lock);
	if (enable)
		msg = otx2_mbox_alloc_msg_cgx_start_linkevents(&pf->mbox);
	else
		msg = otx2_mbox_alloc_msg_cgx_stop_linkevents(&pf->mbox);

	if (!msg) {
		mutex_unlock(&pf->mbox.lock);
		return -ENOMEM;
	}

	err = otx2_sync_mbox_msg(&pf->mbox);
	mutex_unlock(&pf->mbox.lock);
	return err;
}

static int otx2_cgx_config_loopback(struct otx2_nic *pf, bool enable)
{
	struct msg_req *msg;
	int err;

	if (enable && !bitmap_empty(pf->flow_cfg->dmacflt_bmap,
				    pf->flow_cfg->dmacflt_max_flows))
		netdev_warn(pf->netdev,
			    "CGX/RPM internal loopback might not work as DMAC filters are active\n");

	mutex_lock(&pf->mbox.lock);
	if (enable)
		msg = otx2_mbox_alloc_msg_cgx_intlbk_enable(&pf->mbox);
	else
		msg = otx2_mbox_alloc_msg_cgx_intlbk_disable(&pf->mbox);

	if (!msg) {
		mutex_unlock(&pf->mbox.lock);
		return -ENOMEM;
	}

	err = otx2_sync_mbox_msg(&pf->mbox);
	mutex_unlock(&pf->mbox.lock);
	return err;
}

static char *nix_sqoperr_e_str[NIX_SQOPERR_MAX] = {
	"NIX_SQOPERR_OOR",
	"NIX_SQOPERR_CTX_FAULT",
	"NIX_SQOPERR_CTX_POISON",
	"NIX_SQOPERR_DISABLED",
	"NIX_SQOPERR_SIZE_ERR",
	"NIX_SQOPERR_OFLOW",
	"NIX_SQOPERR_SQB_NULL",
	"NIX_SQOPERR_SQB_FAULT",
	"NIX_SQOPERR_SQE_SZ_ZERO",
};

static char *nix_mnqerr_e_str[NIX_MNQERR_MAX] = {
	"NIX_MNQERR_SQ_CTX_FAULT",
	"NIX_MNQERR_SQ_CTX_POISON",
	"NIX_MNQERR_SQB_FAULT",
	"NIX_MNQERR_SQB_POISON",
	"NIX_MNQERR_TOTAL_ERR",
	"NIX_MNQERR_LSO_ERR",
	"NIX_MNQERR_CQ_QUERY_ERR",
	"NIX_MNQERR_MAX_SQE_SIZE_ERR",
	"NIX_MNQERR_MAXLEN_ERR",
	"NIX_MNQERR_SQE_SIZEM1_ZERO",
};

static char *nix_snd_status_e_str[NIX_SND_STATUS_MAX] =  {
	[NIX_SND_STATUS_GOOD] = "NIX_SND_STATUS_GOOD",
	[NIX_SND_STATUS_SQ_CTX_FAULT] = "NIX_SND_STATUS_SQ_CTX_FAULT",
	[NIX_SND_STATUS_SQ_CTX_POISON] = "NIX_SND_STATUS_SQ_CTX_POISON",
	[NIX_SND_STATUS_SQB_FAULT] = "NIX_SND_STATUS_SQB_FAULT",
	[NIX_SND_STATUS_SQB_POISON] = "NIX_SND_STATUS_SQB_POISON",
	[NIX_SND_STATUS_HDR_ERR] = "NIX_SND_STATUS_HDR_ERR",
	[NIX_SND_STATUS_EXT_ERR] = "NIX_SND_STATUS_EXT_ERR",
	[NIX_SND_STATUS_JUMP_FAULT] = "NIX_SND_STATUS_JUMP_FAULT",
	[NIX_SND_STATUS_JUMP_POISON] = "NIX_SND_STATUS_JUMP_POISON",
	[NIX_SND_STATUS_CRC_ERR] = "NIX_SND_STATUS_CRC_ERR",
	[NIX_SND_STATUS_IMM_ERR] = "NIX_SND_STATUS_IMM_ERR",
	[NIX_SND_STATUS_SG_ERR] = "NIX_SND_STATUS_SG_ERR",
	[NIX_SND_STATUS_MEM_ERR] = "NIX_SND_STATUS_MEM_ERR",
	[NIX_SND_STATUS_INVALID_SUBDC] = "NIX_SND_STATUS_INVALID_SUBDC",
	[NIX_SND_STATUS_SUBDC_ORDER_ERR] = "NIX_SND_STATUS_SUBDC_ORDER_ERR",
	[NIX_SND_STATUS_DATA_FAULT] = "NIX_SND_STATUS_DATA_FAULT",
	[NIX_SND_STATUS_DATA_POISON] = "NIX_SND_STATUS_DATA_POISON",
	[NIX_SND_STATUS_NPC_DROP_ACTION] = "NIX_SND_STATUS_NPC_DROP_ACTION",
	[NIX_SND_STATUS_LOCK_VIOL] = "NIX_SND_STATUS_LOCK_VIOL",
	[NIX_SND_STATUS_NPC_UCAST_CHAN_ERR] = "NIX_SND_STAT_NPC_UCAST_CHAN_ERR",
	[NIX_SND_STATUS_NPC_MCAST_CHAN_ERR] = "NIX_SND_STAT_NPC_MCAST_CHAN_ERR",
	[NIX_SND_STATUS_NPC_MCAST_ABORT] = "NIX_SND_STATUS_NPC_MCAST_ABORT",
	[NIX_SND_STATUS_NPC_VTAG_PTR_ERR] = "NIX_SND_STATUS_NPC_VTAG_PTR_ERR",
	[NIX_SND_STATUS_NPC_VTAG_SIZE_ERR] = "NIX_SND_STATUS_NPC_VTAG_SIZE_ERR",
	[NIX_SND_STATUS_SEND_MEM_FAULT] = "NIX_SND_STATUS_SEND_MEM_FAULT",
	[NIX_SND_STATUS_SEND_STATS_ERR] = "NIX_SND_STATUS_SEND_STATS_ERR",
};

static irqreturn_t __maybe_unused otx2_q_intr_handler(int irq, void *data)
{
	struct otx2_nic *pf = data;
	struct otx2_snd_queue *sq;
	u64 val, *ptr;
	u64 qidx = 0;

	/* CQ */
	for (qidx = 0; qidx < pf->qset.cq_cnt; qidx++) {
		ptr = otx2_get_regaddr(pf, NIX_LF_CQ_OP_INT);
		val = otx2_atomic64_add((qidx << 44), ptr);

		otx2_write64(pf, NIX_LF_CQ_OP_INT, (qidx << 44) |
			     (val & NIX_CQERRINT_BITS));
		if (!(val & (NIX_CQERRINT_BITS | BIT_ULL(42))))
			continue;

		if (val & BIT_ULL(42)) {
			netdev_err(pf->netdev,
				   "CQ%lld: error reading NIX_LF_CQ_OP_INT, NIX_LF_ERR_INT 0x%llx\n",
				   qidx, otx2_read64(pf, NIX_LF_ERR_INT));
		} else {
			if (val & BIT_ULL(NIX_CQERRINT_DOOR_ERR))
				netdev_err(pf->netdev, "CQ%lld: Doorbell error",
					   qidx);
			if (val & BIT_ULL(NIX_CQERRINT_CQE_FAULT))
				netdev_err(pf->netdev,
					   "CQ%lld: Memory fault on CQE write to LLC/DRAM",
					   qidx);
		}

		schedule_work(&pf->reset_task);
	}

	/* SQ */
	for (qidx = 0; qidx < otx2_get_total_tx_queues(pf); qidx++) {
		u64 sq_op_err_dbg, mnq_err_dbg, snd_err_dbg;
		u8 sq_op_err_code, mnq_err_code, snd_err_code;

		sq = &pf->qset.sq[qidx];
		if (!sq->sqb_ptrs)
			continue;

		/* Below debug registers captures first errors corresponding to
		 * those registers. We don't have to check against SQ qid as
		 * these are fatal errors.
		 */

		ptr = otx2_get_regaddr(pf, NIX_LF_SQ_OP_INT);
		val = otx2_atomic64_add((qidx << 44), ptr);
		otx2_write64(pf, NIX_LF_SQ_OP_INT, (qidx << 44) |
			     (val & NIX_SQINT_BITS));

		if (val & BIT_ULL(42)) {
			netdev_err(pf->netdev,
				   "SQ%lld: error reading NIX_LF_SQ_OP_INT, NIX_LF_ERR_INT 0x%llx\n",
				   qidx, otx2_read64(pf, NIX_LF_ERR_INT));
			goto done;
		}

		sq_op_err_dbg = otx2_read64(pf, NIX_LF_SQ_OP_ERR_DBG);
		if (!(sq_op_err_dbg & BIT(44)))
			goto chk_mnq_err_dbg;

		sq_op_err_code = FIELD_GET(GENMASK(7, 0), sq_op_err_dbg);
		netdev_err(pf->netdev,
			   "SQ%lld: NIX_LF_SQ_OP_ERR_DBG(0x%llx)  err=%s(%#x)\n",
			   qidx, sq_op_err_dbg,
			   nix_sqoperr_e_str[sq_op_err_code],
			   sq_op_err_code);

		otx2_write64(pf, NIX_LF_SQ_OP_ERR_DBG, BIT_ULL(44));

		if (sq_op_err_code == NIX_SQOPERR_SQB_NULL)
			goto chk_mnq_err_dbg;

		/* Err is not NIX_SQOPERR_SQB_NULL, call aq function to read
		 * SQ structure.
		 * TODO: But we are in irq context. How to call mbox functions
		 * which does sleep
		 */

chk_mnq_err_dbg:
		mnq_err_dbg = otx2_read64(pf, NIX_LF_MNQ_ERR_DBG);
		if (!(mnq_err_dbg & BIT(44)))
			goto chk_snd_err_dbg;

		mnq_err_code = FIELD_GET(GENMASK(7, 0), mnq_err_dbg);
		netdev_err(pf->netdev,
			   "SQ%lld: NIX_LF_MNQ_ERR_DBG(0x%llx)  err=%s(%#x)\n",
			   qidx, mnq_err_dbg,  nix_mnqerr_e_str[mnq_err_code],
			   mnq_err_code);
		otx2_write64(pf, NIX_LF_MNQ_ERR_DBG, BIT_ULL(44));

chk_snd_err_dbg:
		snd_err_dbg = otx2_read64(pf, NIX_LF_SEND_ERR_DBG);
		if (snd_err_dbg & BIT(44)) {
			snd_err_code = FIELD_GET(GENMASK(7, 0), snd_err_dbg);
			netdev_err(pf->netdev,
				   "SQ%lld: NIX_LF_SND_ERR_DBG:0x%llx err=%s(%#x)\n",
				   qidx, snd_err_dbg,
				   nix_snd_status_e_str[snd_err_code],
				   snd_err_code);
			otx2_write64(pf, NIX_LF_SEND_ERR_DBG, BIT_ULL(44));
		}

done:
		/* Print values and reset */
		if (val & BIT_ULL(NIX_SQINT_SQB_ALLOC_FAIL))
			netdev_err(pf->netdev, "SQ%lld: SQB allocation failed",
				   qidx);

		schedule_work(&pf->reset_task);
	}

	return IRQ_HANDLED;
}

static bool otx2_promisc_use_mce_list(struct otx2_nic *pfvf)
{
	int vf;

	/* The AF driver will determine whether to allow the VF netdev or not */
	if (is_otx2_vf(pfvf->pcifunc))
		return true;

	/* check if there are any trusted VFs associated with the PF netdev */
	for (vf = 0; vf < pci_num_vf(pfvf->pdev); vf++)
		if (pfvf->vf_configs[vf].trusted)
			return true;
	return false;
}

static void otx2_bphypf_do_set_rx_mode(struct work_struct *work)
{
	struct otx2_nic *pf = container_of(work, struct otx2_nic, rx_mode_work);
	struct net_device *netdev = pf->netdev;
	struct nix_rx_mode *req;
	bool promisc = false;

	if (!(netdev->flags & IFF_UP))
		return;

	if ((netdev->flags & IFF_PROMISC) ||
	    (netdev_uc_count(netdev) > pf->flow_cfg->ucast_flt_cnt)) {
		promisc = true;
	}

	/* Write unicast address to mcam entries or del from mcam */
	if (!promisc && netdev->priv_flags & IFF_UNICAST_FLT)
		__dev_uc_sync(netdev, otx2_add_macfilter, otx2_del_macfilter);

	mutex_lock(&pf->mbox.lock);
	req = otx2_mbox_alloc_msg_nix_set_rx_mode(&pf->mbox);
	if (!req) {
		mutex_unlock(&pf->mbox.lock);
		return;
	}

	req->mode = NIX_RX_MODE_UCAST;

	if (promisc)
		req->mode |= NIX_RX_MODE_PROMISC;
	if (netdev->flags & (IFF_ALLMULTI | IFF_MULTICAST))
		req->mode |= NIX_RX_MODE_ALLMULTI;

	if (otx2_promisc_use_mce_list(pf))
		req->mode |= NIX_RX_MODE_USE_MCE;

	otx2_sync_mbox_msg(&pf->mbox);
	mutex_unlock(&pf->mbox.lock);
}

static netdev_tx_t otx2_bphypf_xmit(struct sk_buff *skb,
				    struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	int qidx = skb_get_queue_mapping(skb);
	struct otx2_snd_queue *sq;
	struct netdev_queue *txq;
	int sq_idx;

	/* XDP SQs are not mapped with TXQs
	 * advance qid to derive correct sq mapped with QOS
	 */
	sq_idx = (qidx >= pf->hw.tx_queues) ? (qidx + pf->hw.xdp_queues) : qidx;

	/* Check for minimum and maximum packet length */
	if (skb->len <= ETH_HLEN ||
	    (!skb_shinfo(skb)->gso_size && skb->len > pf->tx_max_pktlen)) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	sq = &pf->qset.sq[sq_idx];
	txq = netdev_get_tx_queue(netdev, qidx);

	if (!otx2_sq_append_skb(pf, txq, sq, skb, qidx)) {
		netif_tx_stop_queue(txq);

		/* Check again, in case SQBs got freed up */
		smp_mb();
		if (((sq->num_sqbs - *sq->aura_fc_addr) * sq->sqe_per_sqb)
							> sq->sqe_thresh)
			netif_tx_wake_queue(txq);

		return NETDEV_TX_BUSY;
	}

	return NETDEV_TX_OK;
}

static netdev_features_t otx2_fix_features(struct net_device *dev,
					   netdev_features_t features)
{
	if (features & NETIF_F_HW_VLAN_CTAG_RX)
		features |= NETIF_F_HW_VLAN_STAG_RX;
	else
		features &= ~NETIF_F_HW_VLAN_STAG_RX;

	return features;
}

static void otx2_bphypf_set_rx_mode(struct net_device *netdev)
{
	struct otx2_nic *pf = netdev_priv(netdev);

	queue_work(pf->otx2_wq, &pf->rx_mode_work);
}

static int otx2_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	netdev_features_t changed = features ^ netdev->features;
	struct otx2_nic *pf = netdev_priv(netdev);

	if ((changed & NETIF_F_LOOPBACK) && netif_running(netdev))
		return otx2_cgx_config_loopback(pf,
						features & NETIF_F_LOOPBACK);

	if ((changed & NETIF_F_HW_VLAN_CTAG_RX) && netif_running(netdev))
		return otx2_enable_rxvlan(pf,
					  features & NETIF_F_HW_VLAN_CTAG_RX);

	return otx2_handle_ntuple_tc_features(netdev, features);
}

static void otx2_bphypf_reset_task(struct work_struct *work)
{
	struct otx2_nic *pf = container_of(work, struct otx2_nic, reset_task);

	if (!netif_running(pf->netdev))
		return;

	rtnl_lock();
	otx2_stop(pf->netdev);
	pf->reset_count++;
	otx2_open(pf->netdev);
	netif_trans_update(pf->netdev);
	rtnl_unlock();
}

static int otx2_bphypf_config_hw_rx_tstamp(struct otx2_nic *pfvf, bool enable)
{
	struct msg_req *req;
	int err;

	if (pfvf->flags & OTX2_FLAG_RX_TSTAMP_ENABLED && enable)
		return 0;

	mutex_lock(&pfvf->mbox.lock);
	if (enable)
		req = otx2_mbox_alloc_msg_cgx_ptp_rx_enable(&pfvf->mbox);
	else
		req = otx2_mbox_alloc_msg_cgx_ptp_rx_disable(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return -ENOMEM;
	}

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err) {
		mutex_unlock(&pfvf->mbox.lock);
		return err;
	}

	mutex_unlock(&pfvf->mbox.lock);
	if (enable)
		pfvf->flags |= OTX2_FLAG_RX_TSTAMP_ENABLED;
	else
		pfvf->flags &= ~OTX2_FLAG_RX_TSTAMP_ENABLED;
	return 0;
}

static int otx2_bphypf_config_hw_tx_tstamp(struct otx2_nic *pfvf, bool enable)
{
	struct msg_req *req;
	int err;

	if (pfvf->flags & OTX2_FLAG_TX_TSTAMP_ENABLED && enable)
		return 0;

	mutex_lock(&pfvf->mbox.lock);
	if (enable)
		req = otx2_mbox_alloc_msg_nix_lf_ptp_tx_enable(&pfvf->mbox);
	else
		req = otx2_mbox_alloc_msg_nix_lf_ptp_tx_disable(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return -ENOMEM;
	}

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err) {
		mutex_unlock(&pfvf->mbox.lock);
		return err;
	}

	mutex_unlock(&pfvf->mbox.lock);
	if (enable)
		pfvf->flags |= OTX2_FLAG_TX_TSTAMP_ENABLED;
	else
		pfvf->flags &= ~OTX2_FLAG_TX_TSTAMP_ENABLED;
	return 0;
}

static const struct net_device_ops otx2_bphypf_netdev_ops = {
	.ndo_open		= otx2_open,
	.ndo_stop		= otx2_stop,
	.ndo_start_xmit		= otx2_bphypf_xmit,
	.ndo_select_queue	= otx2_select_queue,
	.ndo_fix_features	= otx2_fix_features,
	.ndo_set_mac_address    = otx2_set_mac_address,
	.ndo_change_mtu		= otx2_bphypf_change_mtu,
	.ndo_set_rx_mode	= otx2_bphypf_set_rx_mode,
	.ndo_set_features	= otx2_set_features,
	.ndo_tx_timeout		= otx2_tx_timeout,
	.ndo_get_stats64	= otx2_get_stats64,
	.ndo_setup_tc		= otx2_setup_tc,
	.ndo_hwtstamp_get	= otx2_config_hwtstamp_get,
	.ndo_hwtstamp_set	= otx2_config_hwtstamp_set,
};

static int otx2_bphypf_wq_init(struct otx2_nic *pf)
{
	pf->otx2_wq = create_singlethread_workqueue("otx2_bphypf_wq");
	if (!pf->otx2_wq)
		return -ENOMEM;

	INIT_WORK(&pf->rx_mode_work, otx2_bphypf_do_set_rx_mode);
	INIT_WORK(&pf->reset_task, otx2_bphypf_reset_task);
	return 0;
}

static int otx2_bphypf_probe(struct pci_dev *pdev,
			     const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	int err, qcount, qos_txqs;
	struct net_device *netdev;
	struct otx2_nic *pf;
	struct otx2_hw *hw;

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

	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "DMA mask config failed, abort\n");
		goto err_release_regions;
	}

	pci_set_master(pdev);

	/* Set number of queues */
	qcount = min_t(int, num_online_cpus(), OTX2_MAX_CQ_CNT);
	qos_txqs = min_t(int, qcount, OTX2_QOS_MAX_LEAF_NODES);

	netdev = alloc_etherdev_mqs(sizeof(*pf), qcount + qos_txqs, qcount);
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
	pf->flags |= OTX2_FLAG_INTF_DOWN;

	hw = &pf->hw;
	hw->pdev = pdev;
	hw->rx_queues = qcount;
	hw->tx_queues = qcount;
	hw->non_qos_queues = qcount;
	hw->max_queues = qcount;
	hw->rbuf_len = OTX2_DEFAULT_RBUF_LEN;
	/* Use CQE of 128 byte descriptor size by default */
	hw->xqe_size = 128;

	pf->af_xdp_zc_qidx = bitmap_zalloc(qcount, GFP_KERNEL);
	if (!pf->af_xdp_zc_qidx)
		goto err_free_netdev;

	err = otx2_init_rsrc(pdev, pf);
	if (err)
		goto err_free_netdev;

	err = otx2_set_real_num_queues(netdev, hw->tx_queues, hw->rx_queues);
	if (err)
		goto err_detach_rsrc;

	/* Assign default mac address */
	otx2_get_mac_from_af(netdev);

	/* Don't check for error.  Proceed without ptp */
	otx2_ptp_init(pf);

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
	 */
	pf->iommu_domain = iommu_get_domain_for_dev(dev);
	if (pf->iommu_domain)
		pf->iommu_domain_type =
			((struct iommu_domain *)pf->iommu_domain)->type;

	netdev->hw_features = (NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
			       NETIF_F_IPV6_CSUM | NETIF_F_RXHASH |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_TSO6 |
			       NETIF_F_GSO_UDP_L4);
	netdev->features |= netdev->hw_features;

	err = otx2_mcam_flow_init(pf);
	if (err)
		goto err_ptp_destroy;

	otx2_set_hw_capabilities(pf);

	err = cn10k_mcs_init(pf);
	if (err)
		goto err_del_mcam_entries;

	if (pf->flags & OTX2_FLAG_NTUPLE_SUPPORT)
		netdev->hw_features |= NETIF_F_NTUPLE;

	if (pf->flags & OTX2_FLAG_UCAST_FLTR_SUPPORT)
		netdev->priv_flags |= IFF_UNICAST_FLT;

	/* Support TSO on tag interface */
	netdev->vlan_features |= netdev->features;
	netdev->hw_features  |= NETIF_F_HW_VLAN_CTAG_TX |
				NETIF_F_HW_VLAN_STAG_TX;
	if (pf->flags & OTX2_FLAG_RX_VLAN_SUPPORT)
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX |
				       NETIF_F_HW_VLAN_STAG_RX;
	netdev->features |= netdev->hw_features;

	/* HW supports tc offload but mutually exclusive with n-tuple filters */
	if (pf->flags & OTX2_FLAG_TC_FLOWER_SUPPORT)
		netdev->hw_features |= NETIF_F_HW_TC;

	netdev->hw_features |= NETIF_F_LOOPBACK | NETIF_F_RXALL;

	netif_set_tso_max_segs(netdev, OTX2_MAX_GSO_SEGS);
	netdev->watchdog_timeo = OTX2_TX_TIMEOUT;

	netdev->netdev_ops = &otx2_bphypf_netdev_ops;

	netdev->min_mtu = OTX2_MIN_MTU;
	netdev->max_mtu = otx2_get_max_mtu(pf);
	hw->max_mtu = netdev->max_mtu;

	err = register_netdev(netdev);
	if (err) {
		dev_err(dev, "Failed to register netdevice\n");
		goto err_mcs_free;
	}

	err = otx2_bphypf_wq_init(pf);
	if (err)
		goto err_unreg_netdev;

	/* FIXME: use nicpf specific ethtool_ops */
	otx2_bphypf_set_ethtool_ops(netdev);

	err = otx2_init_tc(pf);
	if (err)
		goto err_mcam_flow_del;

	err = otx2_register_dl(pf);
	if (err)
		goto err_shutdown_tc;

	/* Enable link notifications */
	otx2_cgx_config_linkevents(pf, true);

	/* Set interface mode as Default */
	pf->ethtool_flags |= OTX2_PRIV_FLAG_DEF_MODE;

#ifdef CONFIG_DCB
	err = otx2_dcbnl_set_ops(netdev);
	if (err)
		goto err_pf_sriov_init;
#endif

	otx2_qos_init(pf, qos_txqs);

	return 0;

err_pf_sriov_init:
	otx2_shutdown_tc(pf);
err_shutdown_tc:
	otx2_shutdown_tc(pf);
err_mcam_flow_del:
	otx2_mcam_flow_del(pf);
err_unreg_netdev:
	unregister_netdev(netdev);
err_mcs_free:
	cn10k_mcs_free(pf);
err_del_mcam_entries:
	otx2_mcam_flow_del(pf);
err_ptp_destroy:
	otx2_ptp_destroy(pf);
err_detach_rsrc:
	if (pf->hw.lmt_info)
		free_percpu(pf->hw.lmt_info);
	if (test_bit(CN10K_LMTST, &pf->hw.cap_flag))
		qmem_free(pf->dev, pf->dync_lmt);
	otx2_detach_resources(&pf->mbox);
	otx2_disable_mbox_intr(pf);
	otx2_pfaf_mbox_destroy(pf);
	pci_free_irq_vectors(hw->pdev);
err_free_netdev:
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);
err_release_regions:
	pci_release_regions(pdev);
	return err;
}

static void otx2_bphypf_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct otx2_nic *pf;

	if (!netdev)
		return;

	pf = netdev_priv(netdev);

	pf->flags |= OTX2_FLAG_PF_SHUTDOWN;

	if (pf->flags & OTX2_FLAG_TX_TSTAMP_ENABLED)
		otx2_bphypf_config_hw_tx_tstamp(pf, false);
	if (pf->flags & OTX2_FLAG_RX_TSTAMP_ENABLED)
		otx2_bphypf_config_hw_rx_tstamp(pf, false);

	/* Disable 802.3x pause frames */
	if (pf->flags & OTX2_FLAG_RX_PAUSE_ENABLED ||
	    (pf->flags & OTX2_FLAG_TX_PAUSE_ENABLED)) {
		pf->flags &= ~OTX2_FLAG_RX_PAUSE_ENABLED;
		pf->flags &= ~OTX2_FLAG_TX_PAUSE_ENABLED;
		otx2_config_pause_frm(pf);
	}

#ifdef CONFIG_DCB
	/* Disable PFC config */
	if (pf->pfc_en) {
		pf->pfc_en = 0;
		otx2_config_priority_flow_ctrl(pf);
	}
#endif
	otx2_bphypf_set_npc_parse_mode(pf, true);
	cancel_work_sync(&pf->reset_task);

	/* Disable link notifications */
	otx2_cgx_config_linkevents(pf, false);

	otx2_unregister_dl(pf);
	unregister_netdev(netdev);
	cn10k_mcs_free(pf);
	otx2_ptp_destroy(pf);
	if (pf->otx2_wq)
		destroy_workqueue(pf->otx2_wq);

	otx2_mcam_flow_del(pf);
	otx2_shutdown_tc(pf);
	otx2_shutdown_qos(pf);
	otx2_detach_resources(&pf->mbox);
	if (pf->hw.lmt_info)
		free_percpu(pf->hw.lmt_info);
	if (test_bit(CN10K_LMTST, &pf->hw.cap_flag))
		qmem_free(pf->dev, pf->dync_lmt);
	otx2_disable_mbox_intr(pf);
	otx2_pfaf_mbox_destroy(pf);
	pci_free_irq_vectors(pf->pdev);
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);

	pci_release_regions(pdev);
}

static struct pci_driver otx2_bphypf_driver = {
	.name = DRV_NAME,
	.id_table = otx2_bphypf_id_table,
	.probe = otx2_bphypf_probe,
	.shutdown = otx2_bphypf_remove,
	.remove = otx2_bphypf_remove,
};

static int __init otx2_bphypf_init_module(void)
{
	pr_info("%s: %s\n", DRV_NAME, DRV_STRING);

	return pci_register_driver(&otx2_bphypf_driver);
}

static void __exit otx2_bphypf_cleanup_module(void)
{
	pci_unregister_driver(&otx2_bphypf_driver);
}

module_init(otx2_bphypf_init_module);
module_exit(otx2_bphypf_cleanup_module);
