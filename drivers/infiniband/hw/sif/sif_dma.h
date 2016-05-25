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
 * sif_dma.h: DMA memory mapping
 */

#ifndef __SIF_DMA_H
#define __SIF_DMA_H

#include <rdma/ib_verbs.h>

struct sif_dev;

struct page *sif_alloc_pages(struct sif_dev *sdev, gfp_t gfp_mask, unsigned int order);

void *sif_dma_alloc_coherent(struct ib_device *dev, size_t size,
			     u64 *dma_handle, gfp_t flag);
void sif_dma_free_coherent(struct ib_device *dev, size_t size,
			   void *cpu_addr, u64 dma_handle);

/* allocate/release readonly (and noncoherent?) memory */
void *sif_dma_alloc_readonly(struct ib_device *dev, size_t size,
			dma_addr_t *dma_handle, gfp_t flag);

void sif_dma_free_readonly(struct ib_device *dev, size_t size,
			void *cpu_addr, dma_addr_t dma_handle);

/* Allocate/release memory that is naturally aligned according to size,
 * eg. 2M gets 2M aligned etc:
 */
void *sif_dma_alloc_aligned(struct ib_device *dev, size_t size,
			dma_addr_t *dma_handle, gfp_t flag,
			enum dma_data_direction dir);

void sif_dma_free_aligned(struct ib_device *dev, size_t size,
			void *cpu_addr, u64 dma_handle,
			enum dma_data_direction dir);


struct sif_table;

/* Largest single dma alloc we can get
 * - if larger need, switch to vmalloc:
 */
#define SIF_MAX_CONT (PAGE_SIZE << (MAX_ORDER - 1))

#endif
