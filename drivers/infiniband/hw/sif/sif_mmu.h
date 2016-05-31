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
 * sif_mmu.h: API for management of sif's on-chip mmu.
 */

#ifndef _SIF_MMU_H
#define _SIF_MMU_H

#include <rdma/ib_verbs.h>
#include "psif_hw_data.h"
#include "sif_user.h"

struct sif_mem;
struct psif_mmu_cntx;
struct sif_dev;

enum wr_mode {
	PCM_POST,	/* Post WR without requesting send completion */
	PCM_POST_COMPL, /* Post WR requesting send completion but do not wait(poll) for it */
	PCM_WAIT	/* Post WR requesting send completion and wait(poll) for it to arrive */
};

enum post_mode {
	PM_WRITE,	/* Write the WR into the SQ but don't trigger any posting */
	PM_DOORBELL,	/* Post request and trigger doorbell (send queue mode) */
	PM_CB,		/* "Normal" collect buffer mode */
};

/* The driver's representation of an MMU context:
 * The key is the only means for referring the MMU context wrt invalidation
 * (TLB_INVALIDATE) but this is only necessary to do for GVA2GPA contexts
 * [TBD: with level > 0 (?)]
 */

struct sif_mmu_ctx {
	u64 base;   /* Start of mapping (byte resolution) */
	u64 size;   /* Size of mapping (byte resolution) */
	u32 lkey;   /* Key to use for invalidation - only valid if nonzero */
	enum sif_mem_type mt;  /* Logical type of mapping */
	enum psif_mmu_translation type; /* Defined in psif_hw_data */
	struct psif_mmu_cntx mctx;   /* host order version of MMU context populated by sif_map_ctx */
	struct sif_pt *pt;  /* sif page table this mmu context points into (only GVA2GPA types) */
	off_t uv2dma;  /* For bypass: user_va + uv2dma = actual dma_addr */
	u64 phys_sz;   /* Only used by SIFMT_ZERO mappings */
};


/* Prepare a new mmu context
 *  ctx points to storage for this mmu context
 *  mem points to a DMA mapped memory object to map
 *
 *  - prepare any page tables needed for dma
 *    and/or allocate private structures
 *  - fill in information for hw in ctx->hw_ctx
 *
 * NB! hw_ctx is assumed to be set to values for
 *    MMU_PASS_THROUGH (all null bytes) by default
 *
 * Return 0 upon success or -errno
 */
int sif_map_ctx(struct sif_dev *sdev,
		struct sif_mmu_ctx *ctx,
		struct sif_mem *mem,
		u64 virt_base, u64 size,
		bool write);

/* Release any resources associated with
 *  the mmu context c. This will typically be
 *  any driver managed page tables and any I/O mappings
 *  (pinning) of page table memory
 */
void sif_unmap_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *c);

/* Populate/invalidate a pte range in an already existing context's page table
 * Only GVA2GPA memory types supports this:
 *  page_list should contain the corresponding list of dma_addresses to map:
 */
int sif_map_ctx_part(struct sif_dev *sdev,
		struct sif_mmu_ctx *c,
		struct sif_mem *mem,
		u64 virt_base, u64 size);

int sif_unmap_gva_ctx_part(struct sif_dev *sdev, struct sif_mmu_ctx *c,
			u64 virt_base, u64 size);

/* Remap an existing context to a new memory object
 * (of the same size)
 */
int sif_map_fmr_ctx(struct sif_dev *sdev,
		struct sif_mmu_ctx *c,
		struct sif_mem *mem);

void sif_unmap_fmr_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx, enum wr_mode mode);

/*** internal mmu code - used by sif_xmmu.h ***/

void sif_unmap_gva_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx);

const char *sif_mem_type_str(enum sif_mem_type mem_type);

void set_ctx(struct sif_dev *sdev,
	struct sif_mmu_ctx *ctx,
	enum psif_table_level level,
	u64 val);

/* Return an mmu context in passthrough mode */
struct psif_mmu_cntx sif_mmu_ctx_passthrough(bool write);

/* The I/O side virtual address as seen from sif */
static inline u64 sif_mmu_vaddr(struct sif_mmu_ctx *ctx, off_t offset)
{
	return ctx->base + offset;
}

/* Post a command to flush the TLBs PTE cache.
 * If @ptw_cache is set, also flush the PTW cache.
 */
int sif_post_flush_tlb(struct sif_dev *sdev, bool ptw_cache);

/* Wait for a previously posted flush_tlb to complete */
int sif_complete_flush_tlb(struct sif_dev *sdev);

/* Flush the TLB and wait for the flush to complete */
static inline int sif_flush_tlb(struct sif_dev *sdev)
{
	int ret = sif_post_flush_tlb(sdev, true);

	if (ret)
		return ret;
	return sif_complete_flush_tlb(sdev);
}

#endif
