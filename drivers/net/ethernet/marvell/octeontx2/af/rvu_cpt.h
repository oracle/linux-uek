/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef RVU_CPT_H
#define RVU_CPT_H

#define CPT_AF_MAX_RXC_QUEUES 16

struct rvu_cpt {
	/* PCIFUNC to CPT RX Queue map */
	u16                     cptpfvf_map[CPT_AF_MAX_RXC_QUEUES];
	DECLARE_BITMAP(cpt_rx_queue_bitmap, CPT_AF_MAX_RXC_QUEUES);
};

void rvu_cn20k_cpt_init(struct rvu *rvu);

#endif /* RVU_CPT_H */
