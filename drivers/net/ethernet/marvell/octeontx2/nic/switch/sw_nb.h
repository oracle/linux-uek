/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#ifndef SW_NB_H_
#define SW_NB_H_

enum {
	OTX2_DEV_UP = 1,
	OTX2_DEV_DOWN,
	OTX2_DEV_CHANGE,
	OTX2_NEIGH_UPDATE,
	OTX2_FIB_ENTRY_REPLACE,
	OTX2_FIB_ENTRY_ADD,
	OTX2_FIB_ENTRY_DEL,
	OTX2_FIB_ENTRY_APPEND,
	OTX2_CMD_MAX,
};

int sw_nb_register(void);
int sw_nb_unregister(void);

int otx2_mbox_up_handler_af2pf_fdb_refresh(struct otx2_nic *pf,
					   struct af2pf_fdb_refresh_req *req,
					   struct msg_rsp *rsp);

const char *sw_nb_get_cmd2str(int cmd);
#endif // SW_NB_H__
