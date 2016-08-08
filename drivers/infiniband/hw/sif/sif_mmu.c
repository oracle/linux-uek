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
 * sif_mmu.c: main entry points and initialization
 */

#include "sif_mmu.h"
#include "sif_dev.h"
#include "sif_base.h"
#include "sif_dma.h"
#include "sif_hwi.h"
#include "sif_mem.h"
#include "sif_spt.h"
#include "sif_xmmu.h"
#include "sif_pt.h"
#include "sif_mr.h"
#include "sif_query.h"

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/highmem.h>
#include <linux/kref.h>
#include <linux/version.h>
#include <rdma/ib_umem.h>
#include "psif_hw_setget.h"
#include "sif_defs.h"

static int sif_map_gva_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write);

static int sif_map_bypass_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write);

static int sif_map_cs_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			bool write);

#ifndef __sparc__
/* Special handling for PHYS memory types which don't have any sg list: */
static int sif_map_special_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write);
#endif

static int sif_mmu_invalidate_tlb(struct sif_dev *sdev, struct sif_mmu_ctx *ctx, enum wr_mode mode);

void set_ctx(struct sif_dev *sdev,
	struct sif_mmu_ctx *ctx,
	enum psif_table_level level,
	u64 val)
{
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;

	val &= ~PSIF_TABLE_PTR_MASK;
	hw_ctx->table_ptr = ((val) >> PT_PAGE_SHIFT);
	hw_ctx->table_level = level;
	sif_log(sdev, SIF_MMU, "%p ptr 0x%08llx level %d", hw_ctx, val, level);
}



int sif_map_ctx(struct sif_dev *sdev,
		struct sif_mmu_ctx *ctx,
		struct sif_mem *mem,
		u64 virt_base, u64 size, bool write)
{
	/* hw_ctx entry assumed to be set up in pass through
	 * prior to the call (all null bytes)
	 */
	ctx->type = MMU_GVA2GPA_MODE;
	ctx->base = virt_base;
	ctx->size = size;
	ctx->mt = mem->mem_type;

	switch (mem->mem_type) {
	case SIFMT_BYPASS:
	case SIFMT_BYPASS_RO:
	case SIFMT_NOMEM:
		return sif_map_bypass_ctx(sdev, ctx, mem, write);
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
	case SIFMT_2M:
	case SIFMT_4K:
		return sif_map_gva_ctx(sdev, ctx, mem, write);
	case SIFMT_CS:
		return sif_map_cs_ctx(sdev, ctx, write);
	case SIFMT_ZERO:
		return sif_zero_map_gva_ctx(sdev, ctx, mem, write);
	case SIFMT_PTONLY:
		return 0; /* Nothing to map yet */
#ifndef __sparc__
	case SIFMT_PHYS:
		return sif_map_special_ctx(sdev, ctx, mem, write);
	case SIFMT_UMEM_SPT:
		return sif_spt_map_gva_ctx(sdev, ctx, mem, write);
#endif
	default:
		sif_log(sdev, SIF_INFO, "Unimplemented mem_type %d %s",
			mem->mem_type, sif_mem_type_str(mem->mem_type));
		return -EOPNOTSUPP;
	}
	return -EINVAL;
}

void sif_unmap_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx)
{
	switch (ctx->mt) {
	case SIFMT_BYPASS:
	case SIFMT_BYPASS_RO:
	case SIFMT_NOMEM:
		break;
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
	case SIFMT_PHYS:
	case SIFMT_FMR:
	case SIFMT_2M:
	case SIFMT_4K:
	case SIFMT_CS:
	case SIFMT_PTONLY:
		sif_unmap_gva_ctx(sdev, ctx);
		break;
#ifndef __sparc__
	case SIFMT_ZERO:
		sif_zero_unmap_gva_ctx(sdev, ctx);
		break;
	case SIFMT_UMEM_SPT:
		sif_spt_unmap_gva_ctx(sdev, ctx);
		break;
#endif
	default:
		sif_log(sdev, SIF_INFO, "Unimplemented mem type %d, ctx at %p", ctx->mt, ctx);
		BUG(); /* Should not happen - throwing the cards */
	}
}

static size_t num_pages(u64 base, u64 size, u32 page_shift)
{
	size_t pg_sz = 1 << page_shift;

	return aligned_size(base, size, pg_sz) >> page_shift;
}

/* May return -1 or a valid enum value for psif_page_size */
static int hw_leaf_page_sz(struct sif_dev *sdev, u32 page_shift)
{
	/* Page size not supported by device configuration */
	if (sdev->mi.page_shift > page_shift) {
		sif_log(sdev, SIF_INFO,
			"Cannot support page shift %d - min.page shift supported in this configuration is %d",
			page_shift, sdev->mi.page_shift);
		return -1;
	}

	switch (sdev->mi.page_shift) {
	case 12: /* Device configured for Intel page sizes */
		if (page_shift < 21)
			return PAGE_SIZE_IA32E_4KB;
		if (page_shift < 30)
			return PAGE_SIZE_IA32E_2MB;
		return PAGE_SIZE_IA32E_1GB;
	case 13: /* Device configured for Sparc page sizes */
		if (page_shift < 16)
			return PAGE_SIZE_S64_8KB;
		if (page_shift < 19)
			return PAGE_SIZE_S64_64KB;
		if (page_shift < 22)
			return PAGE_SIZE_S64_512KB;
		if (page_shift < 25)
			return PAGE_SIZE_S64_4MB;
		if (page_shift < 28)
			return PAGE_SIZE_S64_32MB;
		if (page_shift < 34)
			return PAGE_SIZE_S64_2GB;
		return PAGE_SIZE_S64_16GB;
	}
	sif_log(sdev, SIF_INFO, "Cannot support page shift %d", page_shift);
	return -1;
}


static inline enum psif_table_level hw_leaf_level(enum psif_page_size pg_sz)
{
	switch (pg_sz) {
	case PAGE_SIZE_IA32E_2MB:
	case PAGE_SIZE_S64_4MB:
		return PAGE_LEVEL1;
	case PAGE_SIZE_IA32E_1GB:
	case PAGE_SIZE_S64_2GB:
		return PAGE_LEVEL2;
	default:
		return PAGE_LEVEL0;
	}
}


static int sif_map_bypass_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write)
{
	u64 addr = 0;
	int ret = 0;

	ctx->type = MMU_PASS_THROUGH0;

	if (mem->mem_type == SIFMT_NOMEM)
		ctx->mt = SIFMT_BYPASS;
	if (write)
		ctx->mctx.wr_access = 1;

	if (mem->m.u.umem) {
		addr = sif_mem_dma_if_cont(mem);
		if (IS_ERR((void *)addr))
			return PTR_ERR((void *)addr);
	} else if (mem->mem_type != SIFMT_NOMEM)
		addr = sif_mem_dma(mem, 0);

	if (mem->mem_type == SIFMT_BYPASS || mem->mem_type == SIFMT_BYPASS_RO)
		ctx->uv2dma = addr - ctx->base;
	ctx->base = addr;
	return ret;
}


static int sif_map_gva_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write)
{
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;
	bool multipage;
	u64 page_size;
	u64 page_mask;
	enum psif_table_level leaf_level;
	u64 aligned_base;
	u64 aligned_sz;
	u32 page_shift = sif_mem_page_shift(mem);
	u8 pt_leaf_level = 0;
	u8 pt_pte_extent = 1;
	u64 dma_addr;

	/* Adjust to a supported page shift */
	int ret = find_optimal_leaf_level(sdev, page_shift,
					ctx->base, sif_mem_dma(mem, 0), ctx->size,
					&pt_leaf_level, &pt_pte_extent);
	if (ret)
		return ret;

	page_shift = sdev->mi.page_shift + pt_leaf_level * sdev->mi.level_shift;
	page_size = 1ULL << page_shift;
	page_mask = ~(page_size - 1);

	hw_ctx->wr_access = write;
	hw_ctx->translation_type = MMU_GVA2GPA_MODE;
	hw_ctx->page_size = hw_leaf_page_sz(sdev, page_shift);

	aligned_base = ctx->base & page_mask;
	aligned_sz = aligned_size(ctx->base, ctx->size, page_size);
	multipage = sdev->single_pte_pt || aligned_sz > page_size;
	leaf_level = hw_leaf_level(hw_ctx->page_size);
	dma_addr = sif_mem_dma(mem, 0);

	sif_log(sdev, SIF_MMU_V, "base 0x%llx dma base 0x%llx size 0x%llx page shift %d size %s",
		ctx->base, dma_addr, ctx->size, page_shift,
		string_enum_psif_page_size(hw_ctx->page_size));

	if (multipage) {
		ctx->pt = sif_pt_create(sdev, sif_mem_get_sgl(mem),
					ctx->base, ctx->size, page_shift, false, false);
		if (!ctx->pt)
			return -ENOMEM;
		set_ctx(sdev, ctx, sif_pt_root_table_level(ctx->pt), sif_pt_dma_root(ctx->pt));
	} else {
		dma_addr_t aligned_dma_addr = dma_addr & ~((1 << page_shift) - 1);

		set_ctx(sdev, ctx, leaf_level, aligned_dma_addr);
	}
	return 0;
}


static int sif_map_cs_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			bool write)
{
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;

	hw_ctx->wr_access = write;
	hw_ctx->translation_type = MMU_GVA2GPA_MODE;
	hw_ctx->page_size = PAGE_SIZE_IA32E_4KB;

	/* Just create a page table with an empty top level page */
	ctx->pt = sif_pt_create_empty(sdev, ctx->base, SIFMT_CS);
	if (!ctx->pt)
		return -ENOMEM;
	set_ctx(sdev, ctx, sif_pt_root_table_level(ctx->pt), sif_pt_dma_root(ctx->pt));
	return 0;
}

#ifndef __sparc__
static int sif_map_special_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write)
{
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;
	bool multipage = aligned_size(ctx->base, ctx->size, PAGE_SIZE) > PAGE_SIZE;

	sif_log(sdev, SIF_MMU_V, "base 0x%llx size 0x%llx", ctx->base, ctx->size);

	hw_ctx->page_size = PAGE_SIZE_IA32E_4KB;
	hw_ctx->wr_access = write;
	hw_ctx->translation_type = MMU_GVA2GPA_MODE;

	if (multipage) {
		ctx->pt = sif_pt_create_for_mem(mem, ctx->base, 12, true, true);
		if (!ctx->pt)
			return -ENOMEM;
		set_ctx(sdev, ctx, sif_pt_root_table_level(ctx->pt), sif_pt_dma_root(ctx->pt));
	} else
		set_ctx(sdev, ctx, PAGE_LEVEL0, sif_mem_dma(mem, 0));
	return 0;
}
#endif

/* map an existing context to a new memory object
 * Reuse key, page table and mmu context if possible
 */
int sif_map_fmr_ctx(struct sif_dev *sdev,
		struct sif_mmu_ctx *ctx,
		struct sif_mem *mem)
{
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;
	struct psif_key *key = get_key(sdev, ctx->lkey);
	bool multipage;
	u64 vstart = (u64)mem->vmap_base;
	u64 page_size;
	u64 page_mask;
	enum psif_table_level leaf_level;
	u64 aligned_base;
	u64 aligned_sz;
	u32 page_shift = sif_mem_page_shift(mem);
	u8 pt_leaf_level = 0;
	u8 pt_pte_extent = 1;
	int ret;

	/* Adjust to a supported page shift */
	ret = find_optimal_leaf_level(sdev, page_shift,
				vstart, sif_mem_dma(mem, 0), mem->size,
				&pt_leaf_level, &pt_pte_extent);
	if (ret)
		return ret;

	page_shift = sdev->mi.page_shift + pt_leaf_level * sdev->mi.level_shift;
	page_size = 1ULL << page_shift;
	page_mask = ~(page_size - 1);

	hw_ctx->wr_access = true;
	hw_ctx->translation_type = MMU_GVA2GPA_MODE;
	hw_ctx->page_size = hw_leaf_page_sz(sdev, page_shift);

	aligned_base = ctx->base & page_mask;
	aligned_sz = aligned_size(vstart, mem->size, page_size);
	multipage = sdev->single_pte_pt || aligned_sz > page_size;
	leaf_level = hw_leaf_level(hw_ctx->page_size);

	/* Now page sizes may have changed too, if so we cannot reuse the page table, delete it: */
	if (ctx->pt && page_shift != ctx->pt->page_shift) {
		sif_pt_free(ctx->pt);
		ctx->pt = NULL;
	}

	/* For FMRs we reuse the mmu context and modify the existing key */
	ctx->base = (u64)mem->vmap_base;
	ctx->size = mem->size;

	set_psif_key__base_addr(key, ctx->base);
	set_psif_key__lkey_state(key, PSIF_DMA_KEY_VALID);
	set_psif_key__rkey_state(key, PSIF_DMA_KEY_VALID);
	set_psif_key__length(key, mem->size);

	sif_log(sdev, SIF_FMR, "key %d: base now at %llx  (sz %llx - mem sz %llx)",
		ctx->lkey, ctx->base, ctx->size, mem->size);

	/* We have two cases:
	 * 1) a single page pointer: Pointer must be set to new address - keep page size and everything
	 * 2) a page table of any depth:
	 *    appropriate ptes must be set to refer to new pages
	 */
	if (!multipage) {
		dma_addr_t dma_addr = sif_mem_dma(mem, 0);
		dma_addr_t aligned_dma_addr = dma_addr & ~((1 << page_shift) - 1);

		set_ctx(sdev, ctx, leaf_level, aligned_dma_addr);
	} else if (!ctx->pt) {
		ctx->pt = sif_pt_create_for_mem(mem, ctx->base, page_shift, true, false);
		if (!ctx->pt)
			return -ENOMEM;
		set_ctx(sdev, ctx, sif_pt_root_table_level(ctx->pt), sif_pt_dma_root(ctx->pt));
	} else {
		sif_pt_remap_for_mem(ctx->pt, mem, page_shift, ctx->base);
		/* Only the level of the top node may have changed, the page is
		 * guaranteed to be the same, but the previous use could
		 * have been a single page - just set it every time for now:
		 */
		set_ctx(sdev, ctx, sif_pt_root_table_level(ctx->pt), sif_pt_dma_root(ctx->pt));
	}
	/* Update the used network endian context */
	set_psif_key__mmu_context(key, *((u64 *)&ctx->mctx));
	return 0;
}

void sif_unmap_gva_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx)
{
	/* TLB invalidate is not available at teardown, instead we
	 * invalidate the whole MMU as a final operation before taking down the
	 * communication with the EPSC.
	 */
	if (likely(sdev->registered) && ctx->pt && !sif_feature(disable_invalidate_tlb))
		sif_mmu_invalidate_tlb(sdev, ctx, PCM_WAIT);
	if (ctx->pt)
		sif_pt_free(ctx->pt);
}


void sif_unmap_fmr_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx, enum wr_mode mode)
{
	sif_log(sdev, SIF_FMR, "key %d", ctx->lkey);
	if (!sif_feature(disable_invalidate_tlb))
		sif_mmu_invalidate_tlb(sdev, ctx, mode);
}


static int sif_mmu_invalidate_tlb_partial(struct sif_dev *sdev, struct sif_mmu_ctx *ctx,
				u64 start, u64 len, enum wr_mode mode)
{
	struct psif_wr wr;
	int ncompleted;
	int ret = 0;
	u32 lkey = ctx->lkey;
	u32 npages;
	u32 shift;
	u32 sq_entry_idx;
	int pqp_sq_idx;
	struct sif_sq *sq;
	struct sif_pqp *pqp;
	struct psif_cq_entry *cqe;
	DECLARE_SIF_CQE_POLL(sdev, lcqe);

	pqp = lcqe.pqp;

	if (!lkey) {
		lkey = allocate_invalidate_key(ctx);
		if (!lkey) {
			sif_log(sdev, SIF_INFO,
				"Failed to allocate a TLB invalidation key!");
			return -ENOMEM;
		}
	}

	/* Do no invalidate TLB if page table is NULL.
	 * However, if mode == PCM_WAIT, need to generate
	 * a completion to itself to ensure that all the
	 * previous posted invalidate TLB pqp operations
	 * have completed.
	 *
	 * This is mainly to cater for invalidating the TLB of a
	 * list of fmr ctx. This is done here within the function as
	 * the generated completion needs to know the selected
	 * pqp. The caller sif_unmap_phys_fmr_list doesn't
	 * know the pqp until DECLARE_SIF_CQE_POLL.
	 * In a scenario for invalidating TLB for a ctx,
	 * the ctx->pt is checked before calling this function
	 * so that no additional completion will be generated.
	 * e.g in sif_unmap_gva_ctx.
	 */
	if (unlikely(!ctx->pt))  {
		if (mode == PCM_WAIT) {
			ret = gen_pqp_cqe(&lcqe);
			if (ret < 0) {
				sif_log(sdev, SIF_INFO,
					"cqe %p gen_pqp_cqe returned %d",
					&lcqe, ret);
				return ret;
			}
			ret = poll_cq_waitfor(&lcqe);
			if (ret < 0) {
				sif_log(sdev, SIF_INFO,
					"cqe %p poll_cq_waitfor returned %d",
					&lcqe, ret);
			}
		}
		return ret;
	}

	memset(&wr, 0, sizeof(struct psif_wr));
	wr.op = PSIF_WR_INVALIDATE_TLB;
	wr.details.su.key = lkey;

	shift = sif_pt_page_shift(ctx->pt);
	npages = num_pages(ctx->base, len, shift);

	while (npages) {
		/* TLB invalidate only uses the lower 16 bits of the length field */
		u32 n = min_t(u32, npages, 0xffff);

		wr.details.su.addr = start;
		wr.details.su.length = n;
		npages -= n;
		if (npages > 0) {
			int sts = sif_pqp_post_send(sdev, &wr, NULL);

			if (sts) {
				sif_log(sdev, SIF_INFO,
					"Partial invalidate TLB for key %d, base %llx, length %x failed, sts %d",
					lkey, start, n << shift, sts);
				return sts;
			}
		} else
			break;
		/* reset checksum for the next calculation */
		wr.checksum = 0;
		start += n << shift;
	}

	/* We can allow async post only if we do not depend on deleting the key after
	 * the request has completed:
	 */
	if (mode != PCM_WAIT && ctx->lkey) {
		wr.completion = (mode == PCM_POST) ? 0 : 1;
		return sif_pqp_post_send(sdev, &wr, NULL);
	}

	wr.completion = 1;

	sif_log(sdev, SIF_PQP, "Invalidate TLB for key %d, base %llx, length %x",
		lkey, start, wr.details.su.length << shift);

	ncompleted = sif_pqp_poll_wr(sdev, &wr, &lcqe);

	if (ncompleted < 0) {
		sif_log(sdev, SIF_INFO, "%s completion for pqp request",
			(ncompleted ? "Error" : "No"));
		ret = ncompleted;
		goto out;
	}

	/* Note that we operate on 3 different indices here! */
	cqe = &lcqe.cqe;
	pqp_sq_idx = pqp->qp->qp_idx;
	sq = get_sif_sq(sdev, pqp_sq_idx);

	/* sq_id.sq_seq_num contains the send queue sequence number for this completion
	 * and by this driver's definition the index into the send queue will
	 * be this number modulo the length of the send queue:
	 */
	sq_entry_idx = cqe->wc_id.sq_id.sq_seq_num & sq->mask;

	if (cqe->status != PSIF_WC_STATUS_SUCCESS) {
		sif_log(sdev, SIF_INFO,
			"base %llx, length %x: failed with status %s(%d) for cq_seq %d",
			start, wr.details.su.length << shift,
			string_enum_psif_wc_status(cqe->status), cqe->status, cqe->seq_num);
		sif_logs(SIF_INFO, write_struct_psif_cq_entry(NULL, 0, cqe));
		ret = -EIO;
		atomic_inc(&pqp->cq->error_cnt);
		goto out;
	}

	sif_log(sdev, SIF_PQP, "cq_seq %d sq_seq %d, sq_entry_idx %d",
		cqe->seq_num, cqe->wc_id.sq_id.sq_seq_num, sq_entry_idx);
out:
	if (!ctx->lkey)
		release_invalidate_key(sdev, lkey);
	return ret;
}


static int sif_mmu_invalidate_tlb(struct sif_dev *sdev, struct sif_mmu_ctx *ctx, enum wr_mode mode)
{
	return sif_mmu_invalidate_tlb_partial(sdev, ctx, ctx->base, ctx->size, mode);
}


/* extend an mmu context with DMA addresses from @mem.
 * Only GVA2GPA memory types supports this:
 */
int sif_map_ctx_part(struct sif_dev *sdev,
		struct sif_mmu_ctx *ctx,
		struct sif_mem *mem,
		u64 virt_base, u64 size)
{
	int ret;

	if (ctx->type != MMU_GVA2GPA_MODE)
		return -EINVAL;

	ret = sif_pt_extend(ctx->pt, sif_mem_get_sgl(mem), virt_base, size);
	if (ret >= 0 && ctx->mt == SIFMT_CS && ctx->pt->vsize == size)
		set_ctx(sdev, ctx, sif_pt_root_table_level(ctx->pt), sif_pt_dma_root(ctx->pt));
	return ret;
}


/* invalidate a pte range in an already existing context's page table
 * Only GVA2GPA memory types supports this:
 */

int sif_unmap_gva_ctx_part(struct sif_dev *sdev, struct sif_mmu_ctx *ctx,
			u64 virt_base, u64 size)
{
	int ret = sif_pt_free_part(ctx->pt, virt_base, size);

	if (ret < 0)
		return ret;

	if (unlikely(!sdev->registered)) {
		/* TLB invalidate is not available at teardown */
		return 0;
	}

	/* Invalidate this range of the page table with PSIF - assume async call is ok */
	return sif_mmu_invalidate_tlb_partial(sdev, ctx, virt_base, size, PCM_POST);
}



const char *sif_mem_type_str(enum sif_mem_type mem_type)
{
	switch (mem_type) {
	case SIFMT_BYPASS:
		return "SIFMT_BYPASS";
	case SIFMT_UMEM:
		return "SIFMT_UMEM";
	case SIFMT_UMEM_RO:
		return "SIFMT_UMEM_RO";
	case SIFMT_BYPASS_RO:
		return "SIFMT_BYPASS_RO";
	case SIFMT_UMEM_SPT:
		return "SIFMT_UMEM_SPT";
	case SIFMT_2M:
		return "SIFMT_2M";
	case SIFMT_4K:
		return "SIFMT_4K";
	case SIFMT_CS:
		return "SIFMT_CS";
	case SIFMT_ZERO:
		return "SIFMT_ZERO";
	case SIFMT_PHYS:
		return "SIFMT_PHYS";
	case SIFMT_FMR:
		return "SIFMT_FMR";
	case SIFMT_NOMEM:
		return "SIFMT_NOMEM";
	case SIFMT_PTONLY:
		return "SIFMT_PTONLY";
	case SIFMT_MAX:
		return "SIFMT_MAX";
	default:
		break;
	}
	return "(undefined sif_mem_type)";
}


struct psif_mmu_cntx sif_mmu_ctx_passthrough(bool write)
{
	struct psif_mmu_cntx ctx = { .wr_access = 1 };
	return ctx;
}


#define TSU_MMU_FLUSH_CACHES_ADDR   0x00200003L

/* Post a command to flush the TLBs PTE cache.
 * If @ptw_cache is set, also flush the PTW cache.
 */
int sif_post_flush_tlb(struct sif_dev *sdev, bool ptw_cache)
{
	int ret;

	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 100)) {
		struct psif_epsc_csr_rsp resp;
		struct psif_epsc_csr_req req;

		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_FLUSH_CACHES;
		req.u.flush_caches.flush_mmu_caches.flush_mmu_cache = 1;
		if (ptw_cache)
			req.u.flush_caches.flush_mmu_caches.flush_ptw_cache = 1;
		ret = sif_epsc_wr_poll(sdev, &req, &resp);
	} else {
		int bits = (ptw_cache ? 0x3 : 0x1);

		ret = sif_write_global_csr(sdev, TSU_MMU_FLUSH_CACHES_ADDR, bits);
	}
	if (ret) {
		sif_log(sdev, SIF_INFO,
			"clearing MMU cache failed with error %d ", ret);
	}
	return ret;
}


/* Wait for a previously posted flush_tlb to complete */
int sif_complete_flush_tlb(struct sif_dev *sdev)
{
	ulong start_time = jiffies;
	ulong timeout = sdev->min_resp_ticks * 4;
	ulong timeout_time = start_time + timeout;
	u64 val;
	int cnt = 0;
	int ret;
	int ms;

	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 100)) {
		/* For API ver. >= 100, we already wait for completion in mailbox operation */
		return 0;
	}
	do {
		val = sif_read_global_csr(sdev, TSU_MMU_FLUSH_CACHES_ADDR);
		cnt++;
	} while (val != -1LL && (val & 0x4) != 0x4 && time_is_after_jiffies(timeout_time));
	if (val == -1LL)
		sif_log(sdev, SIF_INFO, "CSR error waiting for mmu cache flush to finish");
	if (time_is_before_jiffies(timeout_time)) {
		sif_log(sdev, SIF_INFO, "timeout waiting for mmu cache flush to finish, val = %lld",
			val);
		return -ETIMEDOUT;
	}
	ret = sif_write_global_csr(sdev, TSU_MMU_FLUSH_CACHES_ADDR, 0x0);
	ms = jiffies_to_msecs(jiffies - start_time);
	if (ret)
		sif_log(sdev, SIF_INFO, "failed to turn off mmu cache flush mode in %d ms", ms);
	else
		sif_log(sdev, SIF_INFO_V, "flushing completed in %d ms, cnt %d",
			ms, cnt);
	return ret;
}
