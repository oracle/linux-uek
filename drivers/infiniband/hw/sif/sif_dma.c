/*
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_dma.c: DMA memory mapping
 */
#include <linux/version.h>
#include "sif_dma.h"
#include "sif_dev.h"
#include "psif_hw_data.h"

struct page *sif_alloc_pages(struct sif_dev *sdev, gfp_t gfp_mask, unsigned int order)
{
#ifdef CONFIG_NUMA
	if (sdev->pdev->dev.numa_node >= 0) {
		struct page *page = alloc_pages_node(sdev->pdev->dev.numa_node, gfp_mask, order);

		if (page)
			return page;

		sif_logi(&sdev->ib_dev, SIF_INFO, "Warning: unable to allocate order %d, on numa node %d",
			 order, sdev->pdev->dev.numa_node);
	}
#endif
	return alloc_pages(gfp_mask, order);
}




/* allocate/release aligned memory */
void *sif_dma_alloc_aligned(struct ib_device *dev, size_t size,
			dma_addr_t *dma_handle, gfp_t flag,
			enum dma_data_direction dir)
{
	dma_addr_t ioaddr;
	int ret;
	void *cpu_addr;
	struct sif_dev *sdev = to_sdev(dev);
	struct page *page = sif_alloc_pages(sdev, flag, get_order(size));

	if (!page)
		return NULL;

	cpu_addr = page_address(page);
	ioaddr = (dma_addr_t) ib_dma_map_single(dev, cpu_addr, size, dir);
	ret = dma_mapping_error(dev->dma_device, ioaddr);
	if (ret) {
		sif_logi(dev, SIF_DMA, "DMA mapping %p sz %lx %sfailed",
			cpu_addr, size, (dir == DMA_TO_DEVICE ? "read only " : ""));
		free_pages((unsigned long)cpu_addr, get_order(size));
		return NULL;
	}
	*dma_handle = ioaddr;
	return cpu_addr;
}

void sif_dma_free_aligned(struct ib_device *dev, size_t size,
			void *cpu_addr, u64 dma_handle,
			enum dma_data_direction dir)
{
	ib_dma_unmap_single(dev, dma_handle, size, dir);
	free_pages((unsigned long)cpu_addr, get_order(size));
}


void *sif_dma_alloc_readonly(struct ib_device *dev, size_t size,
			dma_addr_t *dma_handle, gfp_t flag)
{
	return sif_dma_alloc_aligned(dev, size, dma_handle, flag, DMA_TO_DEVICE);
}

void sif_dma_free_readonly(struct ib_device *dev, size_t size,
			void *cpu_addr, dma_addr_t dma_handle)
{
	sif_dma_free_aligned(dev, size, cpu_addr, dma_handle, DMA_TO_DEVICE);
}
