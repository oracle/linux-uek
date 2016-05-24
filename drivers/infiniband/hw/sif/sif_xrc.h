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
 * sif_xrc.h: XRC related functions
 */

#ifndef __SIF_XRC_H
#define __SIF_XRC_H

/* SIF supports a 24 bit XRCD domain index: */
#define SIF_MAX_XRCD_INDEX ((1 << 24) - 1)

struct sif_xrcd {
	struct ib_xrcd ib_xrcd;
	int index;
	struct sif_pd *pd;
};

static inline struct sif_xrcd *to_sxrcd(struct ib_xrcd *ibxrcd)
{
	return container_of(ibxrcd, struct sif_xrcd, ib_xrcd);
}

int sif_init_xrcd(struct sif_dev *sdev);
void sif_deinit_xrcd(struct sif_dev *sdev);

struct ib_xrcd *sif_alloc_xrcd(struct ib_device *device,
				struct ib_ucontext *ucontext,
				struct ib_udata *udata);
int sif_dealloc_xrcd(struct ib_xrcd *xrcd);

#endif
