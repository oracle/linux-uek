/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT8X_REQUEST_MANAGER_H
#define __CPT8X_REQUEST_MANAGER_H

void cpt8x_post_process(struct cptvf_wqe *wqe);
struct reqmgr_ops cpt8x_get_reqmgr_ops(void);
void cpt8x_send_cmds_in_batch(union cpt_inst_s *cptinst, u32 num, void *obj);
#endif /* __CPT8X_REQUEST_MANAGER_H */
