/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#ifndef SW_NB_H_
#define SW_NB_H_

int sw_nb_register(void);
int sw_nb_unregister(void);

int otx2_mbox_up_handler_af2pf_fdb_refresh(struct otx2_nic *pf,
					   struct af2pf_fdb_refresh_req *req,
					   struct msg_rsp *rsp);

#endif // SW_NB_H__
