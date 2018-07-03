#include <linux/mtd/mtd.h>
/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __BCH_COMMON_H
#define __BCH_COMMON_H

#include <asm/byteorder.h>
#include <linux/delay.h>
#include <linux/pci.h>

#include "bch_regs.h"

/* Device ID */
#define BCH_PCI_PF_DEVICE_ID 0xa043
#define BCH_PCI_VF_DEVICE_ID 0xa044

#define BCH_81XX_PCI_PF_SUBSYS_ID 0xa243
#define BCH_81XX_PCI_VF_SUBSYS_ID 0xa244
#define BCH_83XX_PCI_PF_SUBSYS_ID 0xa343
#define BCH_83XX_PCI_VF_SUBSYS_ID 0xa344

/* flags to indicate the features supported */
#define BCH_FLAG_SRIOV_ENABLED BIT(1)

/*
 * BCH Registers map for 81xx
 */

/* PF registers */
#define BCH_CTL			0x0ull
#define BCH_ERR_CFG		0x10ull
#define BCH_BIST_RESULT		0x80ull
#define BCH_ERR_INT		0x88ull
#define BCH_ERR_INT_W1S		0x90ull
#define BCH_ERR_INT_ENA_W1C	0xA0ull
#define BCH_ERR_INT_ENA_W1S	0xA8ull

/* VF registers */
#define BCH_VQX_CTL(z)		0x0ull
#define BCH_VQX_CMD_BUF(z)	0x8ull
#define BCH_VQX_CMD_PTR(z)	0x20ull
#define BCH_VQX_DOORBELL(z)	0x800ull

#endif /* __BCH_COMMON_H */
