// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/pci.h>

#include "otx2_reg.h"
#include "otx2_common.h"
#include "otx2_struct.h"

int otx2_config_nix(struct otx2_nic *pfvf)
{
	struct nix_lf_alloc_req  *nixlf;

	pfvf->qset.xqe_size = NIX_XQESZ_W16 ? 128 : 512;

	/* Get memory to put this msg */
	nixlf = otx2_mbox_alloc_msg_NIX_LF_ALLOC(&pfvf->mbox);
	if (!nixlf)
		return -ENOMEM;

	/* Set RQ/SQ/CQ counts */
	nixlf->rq_cnt = pfvf->hw.rx_queues;
	nixlf->sq_cnt = pfvf->hw.tx_queues;
	nixlf->cq_cnt = pfvf->qset.cq_cnt;
	nixlf->xqe_sz = NIX_XQESZ_W16;
	/* We don't know absolute NPA LF idx attached.
	 * AF will replace 'RVU_DEFAULT_PF_FUNC' with
	 * NPA LF attached to this RVU PF/VF.
	 */
	nixlf->npa_func = RVU_DEFAULT_PF_FUNC;
	/* Disable alignment pad, enable L2 length check,
	 * enable L4 TCP/UDP checksum verification.
	 */
	nixlf->rx_cfg = BIT_ULL(33) | BIT_ULL(35) | BIT_ULL(37);

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

int otx2_config_npa(struct otx2_nic *pfvf)
{
	struct otx2_qset *qset = &pfvf->qset;
	struct npa_lf_alloc_req  *npalf;
	struct otx2_hw *hw = &pfvf->hw;
	int aura_cnt;

	/* Pool - Stack of free buffer pointers
	 * Aura - Alloc/frees pointers from/to pool for NIX DMA.
	 */

	/* Rx and Tx queues will have their own aura & pool in a 1:1 config */
	hw->pool_cnt = hw->rx_queues + hw->tx_queues;

	qset->pool = devm_kzalloc(pfvf->dev, sizeof(struct otx2_pool) *
				  hw->pool_cnt, GFP_KERNEL);
	if (!qset->pool)
		return -ENOMEM;

	/* Get memory to put this msg */
	npalf = otx2_mbox_alloc_msg_NPA_LF_ALLOC(&pfvf->mbox);
	if (!npalf)
		return -ENOMEM;

	/* Set aura and pool counts */
	npalf->nr_pools = hw->pool_cnt;
	aura_cnt = ilog2(roundup_pow_of_two(hw->pool_cnt));
	npalf->aura_sz = (aura_cnt >= ilog2(128)) ? (aura_cnt - 6) : 1;

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

int otx2_detach_resources(struct mbox *mbox)
{
	struct rsrc_detach *detach;

	detach = otx2_mbox_alloc_msg_DETACH_RESOURCES(mbox);
	if (!detach)
		return -ENOMEM;

	/* detach all */
	detach->partial = false;

	/* Send detach request to AF */
	otx2_mbox_msg_send(&mbox->mbox, 0);
	return 0;
}

int otx2_attach_npa_nix(struct otx2_nic *pfvf)
{
	struct rsrc_attach *attach;
	struct msg_req *msix;
	int err;

	/* Get memory to put this msg */
	attach = otx2_mbox_alloc_msg_ATTACH_RESOURCES(&pfvf->mbox);
	if (!attach)
		return -ENOMEM;

	attach->npalf = true;
	attach->nixlf = true;

	/* Send attach request to AF */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		return err;

	/* Get NPA and NIX MSIX vector offsets */
	msix = otx2_mbox_alloc_msg_MSIX_OFFSET(&pfvf->mbox);
	if (!msix)
		return -ENOMEM;

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		return err;

	if (pfvf->hw.npa_msixoff == MSIX_VECTOR_INVALID ||
	    pfvf->hw.nix_msixoff == MSIX_VECTOR_INVALID) {
		dev_err(pfvf->dev,
			"RVUPF: Invalid MSIX vector offset for NPA/NIX\n");
		return -EINVAL;
	}
	return 0;
}

/* Mbox message handlers */
void mbox_handler_NPA_LF_ALLOC(struct otx2_nic *pfvf,
			       struct npa_lf_alloc_rsp *rsp)
{
	pfvf->hw.stack_pg_ptrs = rsp->stack_pg_ptrs;
	pfvf->hw.stack_pg_bytes = rsp->stack_pg_bytes;
}

void mbox_handler_NIX_LF_ALLOC(struct otx2_nic *pfvf,
			       struct nix_lf_alloc_rsp *rsp)
{
	pfvf->hw.sqb_size = rsp->sqb_size;
	pfvf->rx_chan_base = rsp->rx_chan_base;
	pfvf->tx_chan_base = rsp->tx_chan_base;
	ether_addr_copy(pfvf->netdev->dev_addr, rsp->mac_addr);
}

void mbox_handler_MSIX_OFFSET(struct otx2_nic *pfvf,
			      struct msix_offset_rsp *rsp)
{
	pfvf->hw.npa_msixoff = rsp->npa_msixoff;
	pfvf->hw.nix_msixoff = rsp->nix_msixoff;
}

void otx2_disable_msix(struct otx2_nic *pfvf)
{
	struct otx2_hw *hw = &pfvf->hw;
	int irq;

	if (!hw->irq_allocated)
		goto freemem;

	/* Free all registered IRQ handlers */
	for (irq = 0; irq < hw->num_vec; irq++) {
		if (!hw->irq_allocated[irq])
			continue;
		free_irq(pci_irq_vector(hw->pdev, irq), pfvf);
	}

	pci_free_irq_vectors(hw->pdev);

freemem:
	hw->num_vec = 0;
	kfree(hw->irq_allocated);
	kfree(hw->irq_name);
	hw->irq_allocated = NULL;
	hw->irq_name = NULL;
}

int otx2_enable_msix(struct otx2_hw *hw)
{
	int ret;

	hw->num_vec = pci_msix_vec_count(hw->pdev);

	hw->irq_name = kmalloc_array(hw->num_vec, NAME_SIZE, GFP_KERNEL);
	if (!hw->irq_name)
		return -ENOMEM;

	hw->irq_allocated = kcalloc(hw->num_vec, sizeof(bool), GFP_KERNEL);
	if (!hw->irq_allocated) {
		kfree(hw->irq_name);
		return -ENOMEM;
	}

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(hw->pdev, hw->num_vec, hw->num_vec,
				    PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&hw->pdev->dev,
			"Request for #%d msix vectors failed, ret %d\n",
			hw->num_vec, ret);
		kfree(hw->irq_allocated);
		kfree(hw->irq_name);
	}

	return 0;
}
