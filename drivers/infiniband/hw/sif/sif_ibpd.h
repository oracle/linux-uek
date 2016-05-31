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
 * sif_ibpd.h: External interface to (IB) protection domains for SIF
 */

#ifndef __SIF_IBPD_H
#define __SIF_IBPD_H

struct ib_pd *sif_alloc_pd(struct ib_device *ibdev,
			   struct ib_ucontext *ibucontext,
			   struct ib_udata *udata);

int sif_dealloc_pd(struct ib_pd *ibpd);

struct ib_shpd *sif_alloc_shpd(struct ib_device *ibdev,
				struct ib_pd *ibpd,
				struct ib_udata *udata);

struct ib_pd *sif_share_pd(struct ib_device *ibdev,
			struct ib_ucontext *context,
			struct ib_udata *udata,
			struct ib_shpd *shpd);

int sif_remove_shpd(struct ib_device *ibdev,
		struct ib_shpd *shpd,
		int atinit);

#endif
