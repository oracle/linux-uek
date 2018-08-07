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
