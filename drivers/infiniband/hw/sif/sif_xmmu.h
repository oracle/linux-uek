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
 * sif_xmmu.h: Implementation of special MMU mappings.
 */

#ifndef _SIF_XMMU_H
#define _SIF_XMMU_H
struct sif_dev;
struct sif_mmu_ctx;

/* Implementation of a mapping of a virtual address space onto a single page
 * with minimal use of page table memory (workaround for #1931 + test support)
 */
int sif_zero_map_gva_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write);

void sif_zero_unmap_gva_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx);

#endif
