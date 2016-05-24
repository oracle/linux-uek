/*
 * Copyright (c) 2014, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_xrc.c: Implementation of XRC related functions
 */

#include <linux/idr.h>
#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_pd.h"
#include "sif_xrc.h"
#include "sif_idr.h"


int sif_init_xrcd(struct sif_dev *sdev)
{
	sif_idr_init(&sdev->xrcd_refs, 1, SIF_MAX_XRCD_INDEX);
	return 0;
}


void sif_deinit_xrcd(struct sif_dev *sdev)
{
	/* Nothing to do yet  */
}


struct ib_xrcd *sif_alloc_xrcd(struct ib_device *device,
				struct ib_ucontext *ucontext,
				struct ib_udata *udata)
{
	struct sif_dev *sdev = to_sdev(device);
	struct sif_xrcd *xrcd;
	int ret = -ENOMEM;

	xrcd = kzalloc(sizeof(struct sif_xrcd), GFP_KERNEL);
	if (!xrcd)
		goto err_res_xrcd;

	ret = sif_idr_alloc(&sdev->xrcd_refs, xrcd, GFP_KERNEL);
	if (ret < 0) {
		sif_log(sdev, SIF_XRC, "idr_alloc failed with %d", ret);
		goto err_idr_alloc;
	}
	xrcd->index = ret;
	xrcd->pd = alloc_pd(sdev);
	if (!xrcd->pd) {
		ret = -ENOMEM;
		sif_log(sdev, SIF_XRC, "alloc_pd failed with %d", ret);
		goto err_alloc_pd;
	}
	xrcd->pd->ibpd.device = &sdev->ib_dev;
	xrcd->pd->xrcd = xrcd;
	sif_log(sdev, SIF_XRC, "index %d (pd %d)", xrcd->index, xrcd->pd->idx);
	return &xrcd->ib_xrcd;

err_alloc_pd:
	sif_idr_remove(&sdev->xrcd_refs, xrcd->index);
err_idr_alloc:
	kfree(xrcd);
err_res_xrcd:
	return ERR_PTR(ret);
}

int sif_dealloc_xrcd(struct ib_xrcd *ib_xrcd)
{
	struct sif_dev *sdev = to_sdev(ib_xrcd->device);
	struct sif_xrcd *xrcd = to_sxrcd(ib_xrcd);

	sif_log(sdev, SIF_XRC, "index %d", xrcd->index);

	dealloc_pd(xrcd->pd);
	sif_idr_remove(&sdev->xrcd_refs, xrcd->index);
	kfree(xrcd);
	return 0;
}
