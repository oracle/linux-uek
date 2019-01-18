// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt8x_vf.h"
#include "cpt_algs.h"

static int cpt8x_do_request(struct pci_dev *pdev, struct cpt_request_info *req,
			    int cpu_num)
{
	struct cpt_vf *cptvf = pci_get_drvdata(pdev);

	if (!cpt_device_ready(cptvf)) {
		dev_err(&pdev->dev, "CPT Device is not ready");
		return -ENODEV;
	}

	if ((cptvf->vftype == SE_TYPES) && (!req->ctrl.s.se_req)) {
		dev_err(&pdev->dev, "CPTVF-%d of SE TYPE got AE request",
			cptvf->vfid);
		return -EINVAL;
	} else if ((cptvf->vftype == AE_TYPES) && (req->ctrl.s.se_req)) {
		dev_err(&pdev->dev, "CPTVF-%d of AE TYPE got SE request",
			cptvf->vfid);
		return -EINVAL;
	}

	return process_request(pdev, &cptvf->ops, req,
			       &cptvf->pqinfo.queue[0], cptvf);
}

static int cpt8x_get_kcrypto_eng_grp_num(struct pci_dev *pdev)
{
	return 0;
}

struct algs_ops cpt8x_get_algs_ops(void)
{
	struct algs_ops ops;

	ops.cpt_do_request = cpt8x_do_request;
	ops.cpt_get_kcrypto_eng_grp_num = cpt8x_get_kcrypto_eng_grp_num;

	return ops;
}
