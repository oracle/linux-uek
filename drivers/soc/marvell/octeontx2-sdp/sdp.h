/* SPDX-License-Identifier: GPL-2.0
 * OcteonTX2 SDP driver
 *
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef SDP_H_
#define SDP_H_

#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include "mbox.h"

#define RVU_PFVF_PF_SHIFT	10
#define RVU_PFVF_PF_MASK	0x3F
#define RVU_PFVF_FUNC_SHIFT	0
#define RVU_PFVF_FUNC_MASK	0x3FF

#define RVU_PFFUNC(pf, func)	\
	((((pf) & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT) | \
	(((func) & RVU_PFVF_FUNC_MASK) << RVU_PFVF_FUNC_SHIFT))

#define SDP_BASE(a)		(0x86E080000000ull | a << 36)
#define SDP_REG_SIZE		0x42000000

#define SDPX_OUT_BP_ENX_W1S(a)  (0x80280ull | a << 4)
#define SDPX_GBL_CONTROL	(0x40080200ull)

struct sdp_dev {
	struct list_head	list;
	struct mutex		lock;
	struct pci_dev		*pdev;
	void __iomem		*sdp_base;
	void __iomem		*bar2;
	void __iomem		*af_mbx_base;
	void __iomem		*pfvf_mbx_base;
#define SDP_VF_ENABLED 0x1
	u32			flags;
	u32			num_vfs;
	u16			chan_base;
	u16			num_chan;
	bool			*irq_allocated;
	char			*irq_names;
	int			msix_count;
	int			pf;
	u8			valid_ep_pem_mask;
	u8			mac_mask;
	struct otx2_mbox	pfvf_mbox; /* MBOXes for VF => PF channel */
	struct otx2_mbox	pfvf_mbox_up; /* MBOXes for PF => VF channel */
	struct otx2_mbox	afpf_mbox; /* MBOX for PF => AF channel */
	struct otx2_mbox	afpf_mbox_up; /* MBOX for AF => PF channel */
	struct work_struct	mbox_wrk;
	struct work_struct	mbox_wrk_up;
	struct workqueue_struct	*afpf_mbox_wq; /* MBOX handler */
	struct workqueue_struct	*pfvf_mbox_wq; /* VF MBOX handler */
	struct sdp_node_info info;
	struct rvu_vf		*vf_info;
	struct free_rsrcs_rsp	limits; /* Maximum limits for all VFs */
};

struct rvu_vf {
	struct work_struct	mbox_wrk;
	struct work_struct	mbox_wrk_up;
	struct work_struct	pfvf_flr_work;
	struct device_attribute in_use_attr;
	struct pci_dev		*pdev;
	struct kobject		*limits_kobj;
	/* pointer to PF struct this PF belongs to */
	struct sdp_dev		*sdp;
	int			vf_id;
	int			intr_idx; /* vf_id%64 actually */
	bool			in_use;
	bool			got_flr;
};

#endif
