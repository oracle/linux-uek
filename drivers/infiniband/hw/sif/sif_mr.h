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
 * sif_mr.h: Interface to internal IB memory registration logic for SIF
 */

#ifndef __SIF_MR_H
#define __SIF_MR_H
#include "sif_mmu.h"

struct ib_umem;
struct sif_mem;

struct sif_mr {
	struct ib_mr ibmr;
	int index;
	struct sif_mem *mem;
	struct sif_mmu_ctx mmu_ctx;
};

static inline struct sif_mr *to_smr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct sif_mr, ibmr);
}

struct ib_mr *sif_get_dma_mr(struct ib_pd *ibpd, int mr_access_flags);
struct sif_mr *sif_alloc_invalid_mr(struct sif_pd *pd);
struct ib_mr *sif_reg_phys_mr(struct ib_pd *ibpd,
			      struct ib_phys_buf *phys_buf_array,
			      int num_phys_buf, int mr_access_flags,
			      u64 *iova_start);

struct ib_mr *sif_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
			      u64 virt_addr, int mr_access_flags,
			      struct ib_udata *udata);

int sif_dereg_mr(struct ib_mr *ibmr);

struct ib_mr *sif_alloc_fast_reg_mr(struct ib_pd *ibpd, int max_page_list_len);
struct ib_fast_reg_page_list *sif_alloc_fast_reg_page_list(struct ib_device
							   *ibdev,
							   int page_list_len);

void sif_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list);
int sif_rereg_phys_mr(struct ib_mr *ibmr,
		      int mr_rereg_mask,
		      struct ib_pd *ibpd,
		      struct ib_phys_buf *phys_buf_array,
		      int num_phys_buf, int mr_access_flags, u64 *iova_start);

/* Deallocate MR - assumes ownership of mr->mem and deletes that as well.
 * To be used with high level mr allocation operations that create their own
 * sif_mem object:
 */
void sif_dealloc_mr(struct sif_dev *sdev, struct sif_mr *mr);

struct sif_dev;
struct seq_file;
struct sif_pd;
enum psif_mmu_translation;

/* Line printer for debugfs file */
void sif_dfs_print_key(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

/* Internal mr allocation/deallocation functions:
 * Allocate an IB MR for the memory object @mem
 * If length == 0, allocate an invalid map.
 * The mr does not own the @mem object
 */
struct sif_mr *alloc_mr(struct sif_dev *sdev, struct sif_pd *pd,
			struct sif_mem *mem, u64 map_start, int acc_fl);
struct sif_mr *create_dma_mr(struct sif_pd *pd, int acc_fl);

void dealloc_mr(struct sif_dev *sdev, struct sif_mr *mr);


/* API to allocate/release a key for TLB invalidation only
 * Note that 0 is considered an invalid key!
 */
u32 allocate_invalidate_key(struct sif_mmu_ctx *ctx);

/* Release and invalidate a previously allocated TLB invalidation key */
void release_invalidate_key(struct sif_dev *sdev, u32 lkey);


#endif
