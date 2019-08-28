// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt9x_mbox_common.h"
#include "cpt_reqmgr.h"
#include "cpt9x_reqmgr.h"
#include "cpt_algs.h"

static int cpt9x_get_kcrypto_eng_grp_num(struct pci_dev *pdev)
{
	struct cptlfs_info *lfs = get_lfs_info(pdev);

	return lfs->kcrypto_eng_grp_num;
}

int cpt9x_do_request(struct pci_dev *pdev, struct cpt_request_info *req,
		     int cpu_num)
{
	struct cptlfs_info *lfs = get_lfs_info(pdev);

	return process_request(pdev, &lfs->ops, req, &lfs->lf[cpu_num].pqueue,
			       &lfs->lf[cpu_num]);
}

struct algs_ops cpt9x_get_algs_ops(void)
{
	struct algs_ops ops;

	ops.cpt_do_request = cpt9x_do_request;
	ops.cpt_get_kcrypto_eng_grp_num = cpt9x_get_kcrypto_eng_grp_num;

	return ops;
}
