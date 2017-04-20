/*
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Vinay Shaw <vinay.shaw@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_spt.c: Experimental implementation of shared use of the OS's page tables.
 *   Default is to use private page tables - shared page tables can be enabled using
 *   a vendor flag. This implementation assumes that physical addresses and DMA addresses
 *   are 1-1, which might not in general be the case if going through an IOMMU.
 */

#include "sif_mmu.h"
#include "sif_dev.h"
#include "sif_base.h"
#include "sif_dma.h"
#include "sif_hwi.h"
#include "sif_spt.h"

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/highmem.h>
#include <rdma/ib_umem.h>


#define PMD_ALIGN(addr)   ALIGN(addr, PMD_SIZE)
#define PUD_ALIGN(addr)   ALIGN(addr, PUD_SIZE)
#define PGDIR_ALIGN(addr) ALIGN(addr, PGDIR_SIZE)


static void set_ctx_w_page(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			enum psif_table_level level,
			enum psif_page_size pg_sz, u64 val)
{
	struct psif_mmu_cntx *hw_ctx = &ctx->mctx;

	hw_ctx->page_size = pg_sz;
	hw_ctx->table_ptr = ((val) >> PAGE_SHIFT) & ~PSIF_TABLE_PTR_MASK;
	hw_ctx->table_level = level;
	sif_log(sdev, SIF_MMU, "pte 0x%08llx level %d", val, level);
}


static int sif_set_mmu_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *sctx,
			struct sif_mem *mem, bool write);

int sif_spt_map_gva_ctx(struct sif_dev *sdev,
			struct sif_mmu_ctx *ctx,
			struct sif_mem *mem,
			bool write)
{
	int ret;

	if (!(mem->mem_type == SIFMT_UMEM) || !mem->m.u.umem) {
		sif_log(sdev, SIF_MMU, "Only implemented for user space mappings!");
		return -EINVAL;
	}

	ret = sif_set_mmu_ctx(sdev, ctx, mem, write);
	if (ret)
		goto mmctx_failed;
	return 0;

mmctx_failed:
	return ret;
}


static int sif_set_mmu_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *ctx,
			struct sif_mem *mem, bool write)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	u64 start = ctx->base;
	u64 len = ctx->size;
	struct psif_mmu_cntx *pctx = &ctx->mctx;
	int npgds, npuds, npmds, nptes;
	int ret = 0;

	sif_log(sdev, SIF_MMU, "start 0x%llx len 0x%llx", start, len);

	if (len == 0)
		goto err;

	pgd = pgd_offset(mem->m.u.umem->mm, start);
	if (pgd_none(*pgd))
		goto err;

	ctx->pt = (void *)pgd; /* Misuse pt to save the pointer to avoid going via mm at dealloc time */
	ctx->mt = SIFMT_ZERO;

	p4d = p4d_offset(pgd, start);
	if (p4d_none(*p4d))
		goto err;

	pud = pud_offset(p4d, start);
	if (pud_none(*pud))
		goto err;

	pctx->wr_access = write;
	pctx->translation_type = MMU_GVA2GPA_MODE;

	npgds = PGDIR_ALIGN(len + (start & ~PGDIR_MASK)) >> PGDIR_SHIFT;
	npuds = PUD_ALIGN(len + (start & ~PUD_MASK)) >> PUD_SHIFT;

#ifndef __aarch64__
	if (pud_large(*pud)) {
		ptep = (pte_t *) pud;
		pte = *ptep;

		if (!pte_present(pte)) {
			sif_log(sdev, SIF_MMU,
				"Page not present, bugging out..");
			BUG();
			goto err;
		}

		if (npuds == 1) {
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL2, PAGE_SIZE_IA32E_1GB,
				pte_val(pte));
		} else if (npgds == 1)
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL3, PAGE_SIZE_IA32E_1GB,
				pgd_val(*pgd));
#ifdef CONFIG_X86
		else
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL4, PAGE_SIZE_IA32E_1GB,
				read_cr3());
#endif
		goto out;
	}
#endif /* !__aarch64__ */

	pmd = pmd_offset(pud, start);
	if (pmd_none(*pmd))
		goto err;

	npmds = PMD_ALIGN(len + (start & ~PMD_MASK)) >> PMD_SHIFT;

#ifndef __aarch64__
	if (pmd_large(*pmd)) {
		ptep = (pte_t *) pmd;
		pte = *ptep;

		if (!pte_present(pte)) {
			sif_log(sdev, SIF_MMU,
				"Page not present, bugging out..");
			BUG();
			goto err;
		}

		if (npmds == 1) {
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL1, PAGE_SIZE_IA32E_2MB,
				pte_val(pte));
		} else if (npuds == 1)
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL2, PAGE_SIZE_IA32E_2MB,
				pud_val(*pud));
		else if (npgds == 1)
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL3, PAGE_SIZE_IA32E_2MB,
				pgd_val(*pgd));
#ifdef CONFIG_X86
		else
			set_ctx_w_page(sdev, ctx, PAGE_LEVEL4, PAGE_SIZE_IA32E_2MB,
				read_cr3());
#endif
		goto out;
	}
#endif /* !__aarch64__ */

	ptep = pte_offset_map(pmd, start);
	pte = *ptep;
	if (!pte_present(pte)) {
		sif_log(sdev, SIF_MMU, "Page not present, bugging out..");
		BUG();
		goto err;
	}

	nptes = PAGE_ALIGN(len + (start & ~PAGE_MASK)) >> PAGE_SHIFT;
	if (nptes == 1) {
		set_ctx_w_page(sdev, ctx, PAGE_LEVEL0, PAGE_SIZE_IA32E_4KB, pte_val(pte));
	} else if (npmds == 1) {
		set_ctx_w_page(sdev, ctx, PAGE_LEVEL1, PAGE_SIZE_IA32E_4KB, pmd_val(*pmd));
	} else if (npuds == 1) {
		set_ctx_w_page(sdev, ctx, PAGE_LEVEL2, PAGE_SIZE_IA32E_4KB, pud_val(*pud));
	} else if (npgds == 1) {
		set_ctx_w_page(sdev, ctx, PAGE_LEVEL3, PAGE_SIZE_IA32E_4KB, pgd_val(*pgd));
#ifdef CONFIG_X86
	} else {
		set_ctx_w_page(sdev, ctx, PAGE_LEVEL4, PAGE_SIZE_IA32E_4KB, read_cr3());
#endif
	}
	goto out;
err:
	sif_log(sdev, SIF_MMU, "Error in setting mmu context");
	ret = -1;
out:
	return ret;
}

void sif_spt_unmap_gva_ctx(struct sif_dev *sdev, struct sif_mmu_ctx *sctx)
{
	u64 start = sctx->base;
	u64 len = sctx->size;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	int npgds, npuds, npmds, nptes;

	sif_log(sdev, SIF_MMU, "start 0x%llx len 0x%llx", start, len);

	if (len == 0)
		goto err;

	pgd = (pgd_t *)sctx->pt;
	if (pgd_none(*pgd))
		goto err;

	if (pgd_none(*pgd)) {
		sif_log(sdev, SIF_MMU, "Table entry(pgd) already freed");
		goto out;
	}

	p4d = p4d_offset(pgd, start);
	if (p4d_none(*p4d)) {
		sif_log(sdev, SIF_MMU, "Table entry(p4d) already freed");
		goto out;
	}

	pud = pud_offset(p4d, start);
	if (pud_none(*pud)) {
		sif_log(sdev, SIF_MMU, "Table entry(pud) already freed");
		goto out;
	}

	npgds = PGDIR_ALIGN(len + (start & ~PGDIR_MASK)) >> PGDIR_SHIFT;
	npuds = PUD_ALIGN(len + (start & ~PUD_MASK)) >> PUD_SHIFT;

#ifndef __aarch64__
	if (pud_large(*pud)) {
		ptep = (pte_t *) pud;
		pte = *ptep;

		if (!pte_present(pte)) {
			sif_log(sdev, SIF_MMU,
				"Page not present, bugging out..");
			BUG();
			goto err;
		}
		goto out;
	}
#endif /* !__aarch64__ */

	pmd = pmd_offset(pud, start);
	if (pmd_none(*pmd)) {
		sif_log(sdev, SIF_MMU, "Table entry(pmd) already freed");
		goto out;
	}

	npmds = PMD_ALIGN(len + (start & ~PMD_MASK)) >> PMD_SHIFT;

#ifndef __aarch64__
	if (pmd_large(*pmd)) {
		ptep = (pte_t *) pmd;
		pte = *ptep;

		if (!pte_present(pte)) {
			sif_log(sdev, SIF_MMU,
				"Page not present, bugging out..");
			BUG();
			goto err;
		}
		goto out;
	}
#endif /* !__aarch64__ */

	ptep = pte_offset_map(pmd, start);
	pte = *ptep;
	if (!pte_present(pte)) {
		sif_log(sdev, SIF_MMU, "Page not present, bugging out..");
		BUG();
		goto err;
	}

	nptes = PAGE_ALIGN(len + (start & ~PAGE_MASK)) >> PAGE_SHIFT;

	goto out;
err:
	sif_log(sdev, SIF_MMU, "Error releasing mmu context");
out:
	return;
}

