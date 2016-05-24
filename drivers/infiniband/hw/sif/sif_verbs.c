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
 * sif_verbs.c: IB verbs API extensions specific to PSIF
 */

#include <linux/module.h>
#include "sif_verbs.h"
#include "sif_dev.h"
#include "sif_epsc.h"
#include "psif_hw_data.h"
#include "psif_hw_csr.h"

/* Set/get the 48 bit ethernet mac address for a port */
int sif_get_mac(struct ib_device *dev, u8 port, u16 uf, u64 *address)
{
	int ret = 0;
	struct sif_dev *sdev = to_sdev(dev);
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;

	if (port > 2)
		return -ENODEV;

	memset(&req, 0, sizeof(req));

	req.opcode = EPSC_QUERY;
	req.uf = uf;
	req.u.query.info.op = EPSC_QUERY_VPD_MAC;
	req.u.query.info.index = port;
	req.u.query.data.op = EPSC_QUERY_BLANK; /* Single query */

	ret = sif_epsc_wr(sdev, &req, &cqe);
	if (ret) {
		*address = 0;
		sif_log(sdev, SIF_INFO, "Failed with status %d", ret);
	} else {
		*address = cqe.info;
	}
	return ret;
}
EXPORT_SYMBOL(sif_get_mac);

int sif_set_mac(struct ib_device *dev, u8 port, u16 uf, u64 address)
{
	int ret = 0;
	struct sif_dev *sdev = to_sdev(dev);
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;

	if (port > 2)
		return -ENODEV;

	memset(&req, 0, sizeof(req));

	req.opcode = EPSC_SET_EOIB_MAC;
	req.uf = uf;
	req.u.set_eoib_mac.port = port;
	req.u.set_eoib_mac.mac = address;
	req.u.set_eoib_mac.index = 1; /* */

	ret = sif_epsc_wr(sdev, &req, &cqe);
	if (ret)
		sif_log(sdev, SIF_INFO, "Failed with status %d", ret);
	return ret;
}
EXPORT_SYMBOL(sif_set_mac);
