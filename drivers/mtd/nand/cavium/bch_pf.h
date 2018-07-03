/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __BCHPF_H
#define __BCHPF_H

#include "bch_common.h"

#define	BCH_MSIX_VECTORS 1

struct bch_device;

struct bch_device {
	struct list_head list;
	u8 max_vfs; /* Maximum Virtual Functions supported */
	u8 vfs_enabled; /* Number of enabled VFs */
	u8 vfs_in_use; /* Number of VFs in use */
	u32 flags; /* Flags to hold device status bits */

	void __iomem *reg_base; /* Register start address */
	struct pci_dev *pdev; /* pci device handle */
};

#endif /* __BCHPF_H */
