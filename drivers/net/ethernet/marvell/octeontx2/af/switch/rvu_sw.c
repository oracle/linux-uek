// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>
#include "rvu.h"
#include "rvu_sw.h"
#include "rvu_sw_l2.h"

u32 rvu_sw_port_id(struct rvu *rvu, u16 pcifunc)
{
	u16 port_id;
	u16 rep_id;

	rep_id  = rvu_rep_get_vlan_id(rvu, pcifunc);

	port_id = FIELD_PREP(GENMASK_ULL(31, 16), rep_id) |
		  FIELD_PREP(GENMASK_ULL(15, 0), pcifunc);

	return port_id;
}

int rvu_mbox_handler_swdev2af_notify(struct rvu *rvu,
				     struct swdev2af_notify_req *req,
				     struct msg_rsp *rsp)
{
	int rc = 0;

	switch (req->msg_type) {
	case SWDEV2AF_MSG_TYPE_FW_STATUS:
		rc = rvu_sw_l2_init_offl_wq(rvu, req->pcifunc, req->fw_up);
		break;

	case SWDEV2AF_MSG_TYPE_REFRESH_FDB:
		rc = rvu_sw_l2_fdb_list_entry_add(rvu, req->pcifunc, req->mac);
		break;
	}

	return rc;
}
