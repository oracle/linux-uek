/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 RVU Resource Manager driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __OTXRMCMD_H__
#define __OTXRMCMD_H__

#include <linux/ioctl.h>

#define VERPACK(_mj, _mn, _rl) ((_mj) << 16 | (_mn) << 8 | (_rl))
#define VERMAJ(_v) ((_v) >> 16)
#define VERMIN(_v) (((_v) >> 8) & 0xFF)

#define OTXRM_VERSION VERPACK(1, 0, 0)
#define OTXRM_DRVNAME "/dev/otxrm"

/* MEM */
struct otx_mem {
	uint64_t pa; /* Phys.base address */
	uint64_t nbytes; /* Number of bytes to read */
	uint8_t  *buf; /* Buffer address for return memory values */
} __packed;

/* OTXRM IOCTL commands/messages */
#define IOC_TYPE	110

#define IOC_MEMREAD     _IOWR(IOC_TYPE, 1, struct otx_mem *)

#endif /* __OTXRMCMD_H__ */
