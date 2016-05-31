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
 * sif_fmr.h: Interface to internal IB Fast Memory Registration (FMR)
 *   logic for SIF
 */

#ifndef __SIF_FMR_H
#define __SIF_FMR_H

struct sif_fmr {
	struct ib_fmr ibfmr;
	struct sif_mr *mr;
};

static inline struct sif_fmr *to_sfmr(struct ib_fmr *ibfmr)
{
	return container_of(ibfmr, struct sif_fmr, ibfmr);
}

struct ib_fmr *sif_alloc_fmr(struct ib_pd *ibpd,
			     int mr_access_flags, struct ib_fmr_attr *fmr_attr);
int sif_map_phys_fmr(struct ib_fmr *ibfmr,
		     u64 *page_list, int list_len, u64 iova);

int sif_unmap_phys_fmr(struct ib_fmr *ibfmr);
int sif_unmap_phys_fmr_list(struct list_head *fmr_list);

int sif_dealloc_fmr(struct ib_fmr *ibfmr);

#endif
