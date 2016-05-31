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
 * sif_xmmu.c: Implementation of special MMU mappings.
 */

#include "sif_mmu.h"
#include "sif_spt.h"
#include "sif_xmmu.h"
#include "sif_dev.h"
#include "sif_dma.h"
#include "sif_mem.h"
#include "sif_pt.h"
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/highmem.h>
#include <linux/kgdb.h>

int sif_zero_map_gva_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write)
{
	int i, ret;
	u32 map_cnt; /* Number of overlapping maps of the same physical region */
	u64 phys_size = ctx->phys_sz = mem->size; /* Tyically smaller than ctx->size */
	u64 phys_pages;
	u64 start = ctx->base;
	struct sif_pt *pt;
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;
	struct scatterlist *sg = sif_mem_get_sgl(mem);

	if (!phys_size || phys_size & ~PAGE_MASK) {
		sif_log(sdev, SIF_INFO, "Invalid phys_length specified (0x%llx)", phys_size);
		return -EINVAL;
	}

	map_cnt = ctx->size / phys_size;
	phys_pages = phys_size >> sdev->mi.page_shift;

	if (phys_pages > sdev->mi.ptes_per_page) {
		sif_log(sdev, SIF_INFO,
			"Illegal phys_length specified (0x%llx) max %u pages supported",
			phys_size, sdev->mi.ptes_per_page);
		return -EINVAL;
	}
	if (map_cnt * phys_size != ctx->size) {
		sif_log(sdev, SIF_INFO,
			"Illegal virtual/phys length specified (0x%llx/0x%llx) must be a multiple",
			ctx->size, phys_size);
		return -EINVAL;
	}

	pt = sif_pt_create_empty(sdev, start, mem->mem_type);
	if (!pt)
		return -ENOMEM;

	ctx->pt = pt;
	hw_ctx->wr_access = write;
	hw_ctx->translation_type = MMU_GVA2GPA_MODE;
	hw_ctx->page_size = PAGE_SIZE_IA32E_4KB;

	for (i = 0; i < map_cnt; i++) {
		ret = sif_pt_extend(pt, sg, start, phys_size);
		if (ret < 0)
			goto extend_failed;
		start += phys_size;
	}
	return 0;

extend_failed:
	for (; i >= 0; i--) {
		start -= phys_size;
		sif_pt_free_part(pt, start, phys_size);
	}
	return ret;
}

void sif_zero_unmap_gva_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx)
{
	int i;
	u64 start = ctx->base;
	u64 phys_size = ctx->phys_sz;
	u32 map_cnt = ctx->size / phys_size;

	for (i = 0; i < map_cnt; i++) {
		sif_pt_free_part(ctx->pt, start, phys_size);
		start += phys_size;
	}
	sif_unmap_gva_ctx(sdev, ctx);
}
