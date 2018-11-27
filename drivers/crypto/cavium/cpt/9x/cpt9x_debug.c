// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt9x_mbox_common.h"

static char *get_opcode_str(int msg_opcode)
{
	char *str = "Unknown";

	switch (msg_opcode) {
	case MBOX_MSG_READY:
		str = "READY";
	break;

	case MBOX_MSG_FREE_RSRC_CNT:
		str = "FREE_RSRC_CNT";
	break;

	case MBOX_MSG_ATTACH_RESOURCES:
		str = "ATTACH_RESOURCES";
	break;

	case MBOX_MSG_DETACH_RESOURCES:
		str = "DETACH_RESOURCES";
	break;

	case MBOX_MSG_MSIX_OFFSET:
		str = "MSIX_OFFSET";
	break;

	case MBOX_MSG_CPT_RD_WR_REGISTER:
		str = "RD_WR_REGISTER";
	break;
	}

	return str;
}

void dump_mbox_msg(struct device *dev, struct mbox_msghdr *msg, int size)
{
	char *opcode_str;
	u16 pf_id, vf_id;

	opcode_str = get_opcode_str(msg->id);
	pf_id = (msg->pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;
	vf_id = (msg->pcifunc >> RVU_PFVF_FUNC_SHIFT) & RVU_PFVF_FUNC_MASK;

	dev_info(dev, "Receive %s opcode (PF%d/VF%d), size %d, rc %d",
		 opcode_str, pf_id, vf_id, size, msg->rc);
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 2, msg, size,
		       false);
}
