/*
 * Copyright (c) 2013, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_spt.h: Experimental (still unsafe)
 *   implementation of direct use of the operating system's
 *   page tables (shared page tables)
 */

#ifndef _SIF_SPT_H
#define _SIF_SPT_H

struct sif_dev;
struct sif_mmu_ctx;


#define PSIF_TABLE_PTR_SHIFT 52
#define PSIF_TABLE_PTR_SIZE (_AC(1, UL) << PSIF_TABLE_PTR_SHIFT)
#define PSIF_TABLE_PTR_MASK (~(PSIF_TABLE_PTR_SIZE-1))

int sif_spt_map_gva_ctx(struct sif_dev *sdev,
				struct sif_mmu_ctx *ctx,
				struct sif_mem *mem,
				bool write);

void sif_spt_unmap_gva_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx);

#endif
