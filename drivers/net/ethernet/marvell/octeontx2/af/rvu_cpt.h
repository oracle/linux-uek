/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef RVU_CPT_H
#define RVU_CPT_H

#define CPT_AF_MAX_RXC_QUEUES	16
#define CPT_AF_MAX_CTX_ILEN	GENMASK(2, 0)
#define CPT_AF_NIX_QUEUE	GENMASK_ULL(8, 5)
#define CPT_AF_RXC_QUEUE	GENMASK_ULL(15, 13)
#define CPT_AF_ENG_GRPMASK	GENMASK(55, 48)
#define CPT_AF_QUEUE_PRI	GENMASK(2, 0)
#define CPT_AF_CTX_ILEN		GENMASK(19, 17)
#define CPT_AF_INFLIGHT_LIMIT	GENMASK(47, 40)
#define CPT_AF_CTX_PF_FUNC	GENMASK(31, 16)
#define CPT_AF_SSO_PF_FUNC	GENMASK(47, 32)
#define CPT_AF_NIX_PF_FUNC	GENMASK(63, 48)

/* Length of initial context fetch in 128 byte words */
#define CPT_CTX_ILEN    1ULL

struct rvu_cpt {
	/* PCIFUNC to CPT RX Queue map */
	u16                     cptpfvf_map[CPT_AF_MAX_RXC_QUEUES];
	DECLARE_BITMAP(cpt_rx_queue_bitmap, CPT_AF_MAX_RXC_QUEUES);
};

void rvu_cn20k_cpt_init(struct rvu *rvu);
int otx2_cpt_que_pri_mask(struct rvu *rvu);

#endif /* RVU_CPT_H */
