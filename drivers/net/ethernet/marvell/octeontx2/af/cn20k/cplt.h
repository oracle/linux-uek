/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef CPLT_H
#define CPLT_H

bool is_pf_cgxcpltmapped(struct rvu *rvu, u8 pf);
bool is_pf_cpltmapped(struct rvu *rvu, u8 pf);

static inline bool is_cnf20ka(struct pci_dev *pdev)
{
	return ((pdev->subsystem_device & 0xFFFF) == 0xC320);
}

struct rvu_cplt_rpm {
#define PF_CPLTMAP_BASE		34 /* CPLT PF starts from 34 */
	u16			cplt_mapped_vfs; /* maximum CPLT mapped VFs */
	u8			cplt_mapped_pfs;
	u8			cplt_cnt_max;	 /* CPLT port count max */
	u16			*pf2cpltlmac_map; /* pf to cplt_lmac map */
	u64			*cpltlmac2pf_map; /* bitmap of mapped pfs for
						   * every CPLT lmac port
						   */
	unsigned long		cplt_pf_notify_bmap; /* Flags for PF notify */
	unsigned long		lmac_bmap;
	struct			work_struct cplt_evh_work;
	struct			workqueue_struct *cplt_evh_wq;
	spinlock_t		cplt_evq_lock; /* cplt event queue lock */
	struct list_head	cplt_evq_head; /* cplt event queue head */
	struct mutex		cplt_cfg_lock; /* serialize cplt config */
	struct rvu		*rvu;
	bool			ready;
};

#endif /* CPLT_H */
