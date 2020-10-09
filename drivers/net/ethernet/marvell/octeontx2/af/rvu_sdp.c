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

/* Maximum SDP blocks in a chip */
#define MAX_SDP		2

/* SDP PF number */
static int sdp_pf_num[MAX_SDP] = {-1, -1};

bool is_sdp_pf(u16 pcifunc)
{
	u16 pf = rvu_get_pf(pcifunc);
	u32 found = 0, i = 0;

	while (i < MAX_SDP) {
		if (pf == sdp_pf_num[i])
			found = 1;
		i++;
	}

	if (!found)
		return false;

	if (pcifunc & RVU_PFVF_FUNC_MASK)
		return false;

	return true;
}

int rvu_sdp_init(struct rvu *rvu)
{
	struct pci_dev *pdev = NULL;
	struct rvu_pfvf *pfvf;
	u32 i = 0;

	while ((i < MAX_SDP) && (pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
						       PCI_DEVID_OTX2_SDP_PF,
						       pdev)) != NULL) {
		/* The RVU PF number is one less than bus number */
		sdp_pf_num[i] = pdev->bus->number - 1;
		pfvf = &rvu->pf[sdp_pf_num[i]];
		/* To differentiate a PF between SDP0 or SDP1 we make use of the
		 * revision ID field in the config space. The revision is filled
		 * by the firmware.
		 * 0 means SDP0
		 * 1 means SDP1
		 */
		if (pdev->revision) {
			pfvf->is_sdp0 = 0;
			pfvf->is_sdp1 = 1;
		} else {
			pfvf->is_sdp0 = 1;
			pfvf->is_sdp1 = 0;
		}

		dev_info(rvu->dev, "SDP PF number:%d\n", sdp_pf_num[i]);

		put_device(&pdev->dev);
		i++;
	}

	return 0;
}
