/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT8X_COMMON_H
#define __CPT8X_COMMON_H

#include <linux/types.h>
#include <linux/delay.h>
#include <linux/device.h>

/* Maximum number of AE and SE VFs */
#define CPT_8X_MAX_VFS_NUM	64

/* Flags to indicate the features supported */
#define CPT_FLAG_SRIOV_ENABLED BIT(1)
#define CPT_FLAG_VF_DRIVER BIT(2)
#define CPT_FLAG_DEVICE_READY BIT(3)

#define cpt_sriov_enabled(cpt) ((cpt)->flags & CPT_FLAG_SRIOV_ENABLED)
#define cpt_vf_driver(cpt) ((cpt)->flags & CPT_FLAG_VF_DRIVER)
#define cpt_device_ready(cpt) ((cpt)->flags & CPT_FLAG_DEVICE_READY)

#define CPT_MBOX_MSG_TIMEOUT 2000
#define CPT_MAX_MBOX_DATA_STR_SIZE 64

/* VF-PF message opcodes */
enum cpt_mbox_opcode {
	CPT_MSG_VF_UP = 1,
	CPT_MSG_VF_DOWN,
	CPT_MSG_READY,
	CPT_MSG_QLEN,
	CPT_MSG_QBIND_GRP,
	CPT_MSG_VQ_PRIORITY,
	CPT_MSG_PF_TYPE,
	CPT_MSG_ACK,
	CPT_MSG_NACK
};

/* CPT mailbox structure */
struct cpt_mbox {
	u64 msg; /* Message type MBOX[0] */
	u64 data;/* Data         MBOX[1] */
};

#endif /* __CPT8X_COMMON_H */
