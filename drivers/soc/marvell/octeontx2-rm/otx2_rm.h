// SPDX-License-Identifier: GPL-2.0
/* OcteonTX2 RVU Resource Manager driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef RM_H_
#define RM_H_

#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include "mbox.h"
#include "quota.h"

#define MAX_DOM_VFS		8
#define RM_MAX_VFS		128
/* 12 CGX PFs + max HWVFs - VFs used for domains */
#define RM_MAX_PORTS		(12 + 256 - MAX_DOM_VFS)
#define NAME_SIZE		32
#define RM_MAX_CPT_VFS		1

#define RVU_PFVF_PF_SHIFT	10
#define RVU_PFVF_PF_MASK	0x3F
#define RVU_PFVF_FUNC_SHIFT	0
#define RVU_PFVF_FUNC_MASK	0x3FF

#define RVU_PFFUNC(pf, func)	\
	((((pf) & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT) | \
	(((func) & RVU_PFVF_FUNC_MASK) << RVU_PFVF_FUNC_SHIFT))

/* PCI device IDs */
#define PCI_DEVID_OCTEONTX2_RVU_PF		0xA063
#define PCI_DEVID_OCTEONTX2_PASS1_RVU_PF	0x0063 /* Errata */
#define PCI_DEVID_OCTEONTX2_RVU_AFVF		0xA0F8
#define PCI_DEVID_OCTEONTX2_PASS1_RVU_AFVF	0x00F8
#define	PCI_DEVID_OCTEONTX2_RVU_VF		0xA064
#define	PCI_DEVID_OCTEONTX2_PASS1_RVU_VF	0xA064

struct rm_dev;

struct rvu_vf {
	struct work_struct	mbox_wrk;
	struct work_struct	mbox_wrk_up;
	struct work_struct	pfvf_flr_work;
	struct device_attribute in_use_attr;
	struct pci_dev		*pdev;
	struct kobject		*limits_kobj;
	/* pointer to PF struct this PF belongs to */
	struct rm_dev		*rm;
	int			vf_id;
	int			intr_idx; /* vf_id%64 actually */
	bool			in_use;
	bool			got_flr;
};

struct rvu_limits {
	struct quotas	*sso;
	struct quotas	*ssow;
	struct quotas	*npa;
	struct quotas	*tim;
};

struct rm_dev {
	struct list_head	list;
	struct mutex		lock;
	struct pci_dev		*pdev;
	void __iomem		*bar2;
	void __iomem		*af_mbx_base;
	void __iomem		*pfvf_mbx_base;
#define RM_VF_ENABLED 0x1
	u32			flags;
	u32			num_vfs;
	bool			*irq_allocated;
	char			*irq_names;
	int			msix_count;
	int			pf;

	struct otx2_mbox	pfvf_mbox; /* MBOXes for VF => PF channel */
	struct otx2_mbox	pfvf_mbox_up; /* MBOXes for PF => VF channel */
	struct otx2_mbox	afpf_mbox; /* MBOX for PF => AF channel */
	struct otx2_mbox	afpf_mbox_up; /* MBOX for AF => PF channel */
	struct work_struct	mbox_wrk;
	struct work_struct	mbox_wrk_up;
	struct workqueue_struct	*afpf_mbox_wq; /* MBOX handler */
	struct workqueue_struct	*pfvf_mbox_wq; /* VF MBOX handler */
	struct rvu_vf		*vf_info;
	struct free_rsrcs_rsp	limits; /* Maximum limits for all VFs */
	struct rvu_limits	vf_limits; /* Limits for each VF */
};

#endif /* RM_H_ */
