// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/device.h>
#include "cpt8x_common.h"

#define MAX_RAW_DATA_STR_SIZE	64

static char *get_opcode_str(int msg_opcode)
{
	char *str = "Unknown";

	switch (msg_opcode) {
	case CPT_MSG_VF_UP:
		str = "UP";
	break;

	case CPT_MSG_VF_DOWN:
		str = "DOWN";
	break;

	case CPT_MSG_READY:
		str = "READY";
	break;

	case CPT_MSG_QLEN:
		str = "QLEN";
	break;

	case CPT_MSG_QBIND_GRP:
		str = "QBIND_GRP";
	break;

	case CPT_MSG_VQ_PRIORITY:
		str = "VQ_PRIORITY";
	break;

	case CPT_MSG_PF_TYPE:
		str = "PF_TYPE";
	break;

	case CPT_MSG_ACK:
		str = "ACK";
	break;

	case CPT_MSG_NACK:
		str = "NACK";
	break;
	}

	return str;
}

void dump_mbox_msg(struct device *dev, struct cpt_mbox *mbox_msg, int vf_id)
{
	char raw_data_str[MAX_RAW_DATA_STR_SIZE];
	char *opcode_str;

	opcode_str = get_opcode_str(mbox_msg->msg);
	hex_dump_to_buffer(mbox_msg, sizeof(struct cpt_mbox), 16, 8,
			   raw_data_str, MAX_RAW_DATA_STR_SIZE, false);
	if (vf_id >= 0)
		dev_info(dev, "Receive from VF%d %s opcode raw_data %s",
			 vf_id, opcode_str, raw_data_str);
	else
		dev_info(dev, "Receive from PF %s opcode raw_data %s",
			 opcode_str, raw_data_str);
}
