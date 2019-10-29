// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/pci.h>
#include "rvu.h"

/* SDP PF device id */
#define PCI_DEVID_OTX2_SDP_PF   0xA0F6

/* SDP PF number */
static int sdp_pf_num = -1;

bool is_sdp_pf(u16 pcifunc)
{
	if (rvu_get_pf(pcifunc) != sdp_pf_num)
		return false;
	if (pcifunc & RVU_PFVF_FUNC_MASK)
		return false;

	return true;
}

int rvu_sdp_init(struct rvu *rvu)
{
	struct pci_dev *pdev;
	int i;

	for (i = 0; i < rvu->hw->total_pfs; i++) {
		pdev = pci_get_domain_bus_and_slot(
				pci_domain_nr(rvu->pdev->bus), i + 1, 0);
		if (!pdev)
			continue;

		if (pdev->device == PCI_DEVID_OTX2_SDP_PF) {
			sdp_pf_num = i;
			put_device(&pdev->dev);
			break;
		}

		put_device(&pdev->dev);
	}

	return 0;
}
