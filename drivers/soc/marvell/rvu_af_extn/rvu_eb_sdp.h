/* SPDX-License-Identifier: GPL-2.0
 * Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef __RVU_EB_SDP_H__
#define __RVU_EB_SDP_H__

/* SDP CSR */
#define SDP_AF_GBL_CONTROL		           (0x4090000)
#define SDP_AF_LINK_CFG		                   (0x4090100)

struct sdp_drvdata {
	struct mbox_wq_info	afepf_wq_info;
};

#endif /* __RVU_EB_SDP_H__ */
