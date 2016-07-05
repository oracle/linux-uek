/*
 * Copyright (c) 2012, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_vf.c: SR/IOV support functions
 */
#include "sif_dev.h"
#include "sif_vf.h"

int sif_vf_enable(struct pci_dev *dev, int num_vfs)
{
	struct sif_dev *sdev = pci_get_drvdata(dev);
	int ret = 0;

	if (sdev->is_vf)
		return 0;
	if (sdev->fw_vfs < 0) {
		struct psif_epsc_csr_req req;
		struct psif_epsc_csr_rsp rsp;
		/* Ask the EPSC how many VFs that are enabled */
		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_QUERY;
		req.u.query.data.op = EPSC_QUERY_NUM_UF;
		ret = sif_epsc_wr(sdev, &req, &rsp);
		if (ret) {
			sif_log(sdev, SIF_INFO,
				"Request to the EPSC for number of VFs configured failed with %d", ret);
			return ret;
		}
		sdev->fw_vfs = rsp.data - 1;
		sif_log(sdev, SIF_INFO, "Firmware supports %d VFs", sdev->fw_vfs);
	}

	if (num_vfs > sdev->fw_vfs) {
		sif_log(sdev, SIF_INFO, "Requested %d vfs - limited by firmware to %d",
			num_vfs, sdev->fw_vfs);
		num_vfs = sdev->fw_vfs;
	}
	if (num_vfs) {
		ret = pci_enable_sriov(dev, num_vfs);
		if (ret < 0) {
			sif_log(sdev, SIF_INFO, "Failed (status %d) to enable %d VFs",
				ret, num_vfs);
			goto sriov_failed;
		}
		sif_log(sdev, SIF_INFO, "Enabled %d VFs", num_vfs);
		sdev->num_vfs = num_vfs;
	} else
		pci_disable_sriov(sdev->pdev);
	return num_vfs;
sriov_failed:
	return ret;
}


void sif_vf_disable(struct sif_dev *sdev)
{
	if (sdev->num_vfs) {
		pci_disable_sriov(sdev->pdev);
		sdev->num_vfs = 0;
	}
}
