// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_REQUEST_MANAGER_H
#define __CPT9X_REQUEST_MANAGER_H

void cpt9x_post_process(struct cptlf_wqe *wqe);
struct reqmgr_ops cpt9x_get_reqmgr_ops(void);
int cpt9x_do_request(struct pci_dev *pdev, struct cpt_request_info *req,
		     int cpu_num);
void cpt9x_send_cmd(union cpt_inst_s *cptinst, u32 insts_num, void *obj);
void cpt9x_send_cmds_in_batch(union cpt_inst_s *cptinst, u32 num, void *obj);
void cpt9x_send_cmds_for_speed_test(union cpt_inst_s *cptinst, u32 num,
				    void *obj);

#endif /* __CPT9X_REQUEST_MANAGER_H */
