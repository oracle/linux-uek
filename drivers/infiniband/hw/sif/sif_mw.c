/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_mw.c: Implementation of memory windows for SIF
 */

#include <rdma/ib_verbs.h>
#include "sif_mw.h"
#include "sif_dev.h"

struct ib_mw *sif_alloc_mw(struct ib_pd *ibpd)
{
	sif_logi(ibpd->device, SIF_INFO, "Not implemented");
	return ERR_PTR(-EOPNOTSUPP);
}

int sif_dealloc_mw(struct ib_mw *ibmw)
{
	sif_logi(ibmw->device, SIF_INFO, "Not implemented");
	return -EOPNOTSUPP;
}
