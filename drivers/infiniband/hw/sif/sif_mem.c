/*
 * Copyright (c) 2014, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_mem.c: SIF table memory and page table management
 */

#include <linux/scatterlist.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <rdma/ib_umem.h>
#include "sif_dev.h"
#include "sif_mem.h"
#include "sif_dma.h"
#include "sif_pt.h"

/* Defined below */
static int sif_mem_fixup_dma(struct scatterlist *sg);

/* Initialization of global per device info */
void sif_mem_init(struct sif_dev *sdev)
{
	struct sif_mem_info *mi = &sdev->mi;

	if (sif_feature(toggle_page_size)) {
		mi->page_shift = PAGE_SHIFT == 12 ? 13 : 12;
		mi->page_size = PAGE_SIZE == 0x1000 ? 0x2000 : 0x1000;
	} else {
		mi->page_shift = PAGE_SHIFT;
		mi->page_size = PAGE_SIZE;
	}
	mi->level_shift = 9;
	mi->max_shift = mi->page_shift + mi->level_shift * PT_LEVELS;
	mi->ptes_per_page = 1 << mi->level_shift;
	mi->page_mask = ~(mi->page_size - 1);
}

/* Some utilities */

inline size_t mem_type_to_page_shift(struct sif_dev *sdev, enum sif_mem_type mem_type)
{
	switch (mem_type) {
	case SIFMT_2M:
		return sdev->mi.page_shift + sdev->mi.level_shift;
	default:
		return sdev->mi.page_shift;
	}
}


static u32 sif_mem_fmr_max_page_shift(struct sif_mem *mem)
{
	struct sif_dev *sdev = mem->sdev;
	u32 max_shift = sdev->mi.max_shift;
	u64 end = 0;
	u32 bits = sizeof(dma_addr_t) << 3;
	int i;
	u64 incr = 1 << mem->m.fmr.page_shift;

	BUG_ON(mem->mem_type != SIFMT_FMR);

	for (i = 0; i < mem->m.fmr.page_list_len; i++) {
		u64 next_addr = mem->m.fmr.page_list[i];

		if (end && end != next_addr) {
			unsigned long border = end | next_addr;
			u32 shift = find_first_bit(&border, bits);

			if (shift < max_shift) {
				sif_log(sdev, SIF_MEM_V,
					"%4d: start 0x%llx, sz 0x%llx, prev.end 0x%llx shift %d -> %d",
					i, next_addr, incr, end, max_shift, shift);
				max_shift = shift;
				if (max_shift == mem->m.fmr.page_shift) /* No point in continuing */
					break;
			}
		}
		end = next_addr + incr;
	}
	sif_log(sdev, SIF_MEM_SG, "found max shift %d from inspecting %d sges", max_shift, i);
	return max_shift;
}


/* Calculate the max.possible page_shift for this memory
 * based on alignment of the DMA
 */
static u32 sif_mem_max_page_shift(struct sif_mem *mem)
{
	struct sif_dev *sdev = mem->sdev;
	u32 max_shift = sdev->mi.max_shift;
	u64 end = 0;
	u32 bits = sizeof(dma_addr_t) << 3;
	u32 sg_cnt = 0;

	struct scatterlist *sg = sif_mem_get_sgl(mem);

	if (!sg)
		return sdev->mi.page_shift;
	for (; sg; sg = sg_next(sg)) {
		u64 dma_start = sg_dma_address(sg);

		sg_cnt++;
#ifdef __sparc__
		/* TBD: Fix bug in umem:
		 * SG lists are not always properly terminated
		 */
		if (!sg_dma_len(sg))
			break;
#endif
		if (end && end != dma_start) {
			unsigned long border = end | dma_start;
			u32 shift = find_first_bit(&border, bits);

			if (shift < max_shift) {
				sif_log(sdev, SIF_MEM_V,
					"%4d: start 0x%llx, sz %x, prev.end 0x%llx shift %d -> %d",
					sg_cnt, dma_start, sg_dma_len(sg), end, max_shift, shift);
				max_shift = shift;
				if (max_shift == sdev->mi.page_shift) /* No point in continuing */
					break;
				/* BUG_ON(max_shift < sdev->mi.page_shift); */
				if (max_shift < sdev->mi.page_shift) {
					sif_log(sdev, SIF_INFO,
						"Failed to find a valid page shift: max_shift %d sdev->mi.page_shift %d",
						max_shift, sdev->mi.page_shift);
					return max_shift;
				}
			}
		}
		end = sg_dma_address(sg) + sg_dma_len(sg);
	}
	sif_log(sdev, SIF_MEM_SG, "found max shift %d from inspecting %d sges", max_shift, sg_cnt);
	return max_shift;
}

/* External observer:
 * Return the largest page size (represented by page shift bits) usable for this memory
 */
u32 sif_mem_page_shift(struct sif_mem *mem)
{
	/* If a maximum has been calculated, use it: */
	if (mem->max_page_shift)
		return mem->max_page_shift;
	return mem_type_to_page_shift(mem->sdev, mem->mem_type);
}

static struct scatterlist *sg_alloc_list(struct sif_dev *sdev, unsigned int nelems, gfp_t flag)
{
	struct scatterlist *sg = sif_kmalloc(sdev, sizeof(struct scatterlist) * nelems, flag);

	if (sg) {
		sif_log0(SIF_MMU, "start at %p, %d elems allocated", sg, nelems);
		sg_init_table(sg, nelems);
	}
	return sg;
}


/* API for managing a sif_kmem object */

/** Allocate a set of pages of size (1 << page_shift).
 * Prepare for scatterlist(s) of fixed length @sg_size (in number of elements)
 * and allocate an initial @sz bytes (must be multiple of  1 << page_shift)
 * @sz must be less than what fits within the initial scatterlist.
 * If sg_size is 0, figure out the optimal sg_size.
 */
int sif_kmem_init(struct sif_dev *sdev, struct sif_kmem *kmem, size_t sg_size, size_t sz,
		u32 page_shift, gfp_t flag, enum dma_data_direction dir)
{
	int ret;

	memset(kmem, 0, sizeof(*kmem));
	kmem->page_shift = page_shift;

	if (!sg_size)
		sg_size = sz >> page_shift;
	kmem->sg_size = sg_size;
	kmem->dir = dir;
	kmem->sg_max = 0; /* Indicates an empty list with no end mark set yet */

	if (sz == 0)
		return 0;

	ret = sif_kmem_extend(sdev, kmem, sz, flag);
	if (ret < 0)
		return ret;

	return 0;
}


static void sif_kmem_free_pages(struct sif_kmem *kmem, struct scatterlist *sg, u32 nelems)
{
	int i;
	int order = kmem->page_shift - PAGE_SHIFT;

	for (i = 0; i < nelems; i++) {
		__free_pages(sg_page(sg), order);
		sg = sg_next(sg);
	}
}


static void sif_kmem_free_sgls(struct sif_kmem *kmem, struct scatterlist *sgl, u32 nlists)
{
	for (; nlists > 0; nlists--) {
		struct scatterlist *nsgl = sg_chain_ptr(&sgl[kmem->sg_size]);

		kfree(sgl);
		sgl = nsgl;
	}
}

/* Find the @n'th scatterlist array within kmem */
static struct scatterlist *sif_kmem_find_sg_head_idx(struct sif_kmem *kmem, u32 n)
{
	int i = 0;
	struct scatterlist *sgl = kmem->sg;

	for (; n > i; i++)
		sgl = sg_chain_ptr(&sgl[kmem->sg_size]);
	return sgl;
}


/* Find the scatterlist element with index idx within kmem */
struct scatterlist *sif_kmem_find_sg_idx(struct sif_kmem *kmem, u32 idx)
{
	struct scatterlist *sgl;
	int n = idx / kmem->sg_size;

	sgl = sif_kmem_find_sg_head_idx(kmem, n);
	return &sgl[idx % kmem->sg_size];
}


void sif_kmem_free(struct sif_dev *sdev, struct sif_kmem *kmem)
{
	int npages = kmem->sg_max - kmem->sg_start;
	struct scatterlist *sg = sif_kmem_find_sg_idx(kmem, kmem->sg_start);

	ib_dma_unmap_sg(&sdev->ib_dev, sg, npages, kmem->dir);

	sif_kmem_free_pages(kmem, sg, npages);
	sif_kmem_free_sgls(kmem, sg, kmem->nlists);
	kmem->sg = NULL;
}


/* Extend a kmem object by allocating more sg entries if necessary, then
 * allocate pages and dma map them. The invariant upon exit is that
 * all allocated pages are dma mapped, which means that we must
 * clean up pages that did not get mapped, if mapping fails midway:
 */

int sif_kmem_extend(struct sif_dev *sdev, struct sif_kmem *kmem, size_t sz, gfp_t flag)
{
	u32 i;
	int ret;
	int order;
	struct page *page;
	struct scatterlist *sg;
	struct scatterlist *sg_prev = NULL;
	struct scatterlist *sg_start = NULL;
	size_t page_size = 1UL << kmem->page_shift;
	u64 page_mask = page_size - 1;
	u32 sg_size = (sz + page_mask) >> kmem->page_shift;

	u32 nl = kmem->nlists;
	long free_sg = nl * kmem->sg_size - kmem->sg_max;

	sif_log(sdev, SIF_MEM, "enter, kmem at %p, sz 0x%lx", kmem, sz);

	/* Make room in sg list */
	for (; free_sg < sg_size; free_sg += kmem->sg_size) {
		sg = sg_alloc_list(sdev, kmem->sg_size + 1, flag);
		if (!sg) {
			ret = -ENOMEM;
			goto failed;
		}
		if (kmem->last_sg)
			sg_chain(kmem->last_sg, kmem->sg_size + 1, sg);
		else
			kmem->sg = sg;
		kmem->last_sg = sg;
		kmem->nlists++;
	}

	/* The end mark is always in the last used element, not the first available one
	 * which sg_max points to:
	 */
	if (kmem->sg_max) {
		sg_prev = sif_kmem_find_sg_idx(kmem, kmem->sg_max - 1);
		sg_unmark_end(sg_prev);
		sg = sg_next(sg_prev);
	} else
		sg = sif_kmem_find_sg_idx(kmem, 0);

	sg_start = sg;
	order = kmem->page_shift - PAGE_SHIFT;

	/* Allocate the new memory */
	for (i = 0; i < sg_size; i++) {
		sif_log(sdev, SIF_MEM_V, "i = %d, sg %p", i, sg);
		page = sif_alloc_pages(sdev, flag | __GFP_ZERO, order);
		if (!page) {
			ret = -ENOMEM;
			sg_size = i;
			sg_mark_end(sg);
			goto map_failed;
		}
		BUG_ON(!sg);
		sg_set_page(sg, page, page_size, 0);
		sg_prev = sg;
		sg = sg_next(sg);
	}
	sg_mark_end(sg_prev);

	ret = ib_dma_map_sg(&sdev->ib_dev, sg_start, sg_size, kmem->dir);
	if (ret < 0) {
		sif_log(sdev, SIF_INFO, "ib_dma_map_sg failed with %d", ret);
		ret = -EFAULT;
		goto map_failed;
	}

	sif_logs(SIF_PT_VV, sif_dump_sg(sg_start));

	/* TBD: Remove this when issues with wrong alignments of DMA addresses
	 * has been resolved (both Sparc and OVM, see Orabug: 21690736
	 * For 2M seg_size, check that all DMA addresses are 2M aligned:
	 */
	if (page_size >= PMD_SIZE) {
		for (sg = sg_start, i = 0; sg != NULL; sg = sg_next(sg), i++) {
			if (sg_dma_address(sg) & ~PMD_MASK) {
				sif_log(sdev, SIF_INFO,
					"**** Orabug: 21690736 - aligned PA maps to unaligned IOVA: i = %d, pa %llx dma %pad",
					i,
					(u64)sg_phys(sg), &sg_dma_address(sg));
				ret = -EIO;
				goto map_failed;
			}
			sif_log(sdev, SIF_MEM_V, "i = %d, pa %llx dma %pad", i,
				(u64)sg_phys(sg), &sg_dma_address(sg));
		}
	}

	/* To enable direct lookup, we rely on the s/g list not being
	 * collapsed by dma mapping. This holds on x86 but eg. on sparc we see
	 * collapsed lists where the IOMMU delivers the whole DMA range in a single entry
	 * at the start. Handle this case too by rewriting the DMA list
	 * to comply with our needs, otherwise fail (and dump the sg list to the trace buffer
	 * for analysis):
	 */
	if (sg_size != ret) {
		if (ret == 1) {
			sif_log(sdev, SIF_MEM, "Fixing up collapsed sg list (%d/%d)",
				ret, sg_size);
			ret = sif_mem_fixup_dma(sg_start);
			if (ret)
				goto map_failed;
			sif_logs(SIF_PT_VV, sif_dump_sg(sg_start));
		} else {
			/* This should not happen, but sanity check it anyway */
			sif_log(sdev, SIF_INFO,
				"** Detected unhandled layout of s/g list (%d/%d) **",
				ret, sg_size);
			ret = -EPROTOTYPE;
			goto map_failed;
		}
	}
	i = kmem->sg_max;
	kmem->sg_max += ret;
	kmem->size += sz;
	return i;
map_failed:
	sif_dump_sg(sg_start);
	if (sg_size)
		sif_kmem_free_pages(kmem, sg_start, sg_size);
failed:
	return ret;
}


/* Map a part of the @kmem object given by @offset, @size to the user space
 * vm context given in @vma. The part must be page aligned and page sized:
 */

static int sif_kmem_vma_map_part(struct sif_dev *sdev, struct sif_kmem *kmem, struct vm_area_struct *vma,
			off_t start_off, size_t size)
{
	off_t sg_index = start_off >> kmem->page_shift;
	u64 page_size = 1 << kmem->page_shift;
	u64 page_mask = (page_size - 1);
	off_t off = start_off & page_mask; /* start offset within mem page */
	off_t sz = min_t(off_t, size, page_size - off);
	struct scatterlist *sg;
	dma_addr_t pfn, sg_phy;
	u64 start = vma->vm_start;
	u64 rem = size;
	int ret;

	BUG_ON(off & ~PAGE_MASK);

	sg = sif_kmem_find_sg_idx(kmem, sg_index);

	sif_log(sdev, SIF_MMAP, "size %lx, off %lx start sg idx: %ld",
		size, off, sg_index);

	for (; rem > 0; sg = sg_next(sg)) {
		sg_phy = sg_phys(sg);
		pfn = (sg_phy + off) >> PAGE_SHIFT;
		sif_log(sdev, SIF_MMAP, "pfn %pad, sz %lx sg_phys %pad off %lx",
			&pfn, sz, &sg_phy, off);
		ret = remap_pfn_range(vma, start, pfn, sz, vma->vm_page_prot);
		if (ret)
			return ret;
		rem -= sz;
		start += sz;
		sz = min(rem, page_size);
		off = 0;
	}
	return 0;
}


static int sif_vma_map_sg_part(struct sif_dev *sdev, struct scatterlist *sg,
			struct vm_area_struct *vma, off_t start_off, size_t size)
{
	u64 start = vma->vm_start;
	off_t off = start_off;
	dma_addr_t pfn, sg_phy;
	off_t rem = size;
	off_t sz;
	int ret;

	BUG_ON(off & ~PAGE_MASK);

	sif_log(sdev, SIF_MMAP, "size %lx, off %lx",
		size, start_off);

	while (off > sg->length) {
		off -= sg->length;
		sg = sg_next(sg);
	}
	sz = min_t(off_t, rem, sg->length - off);

	for (;;) {
		sg_phy = sg_phys(sg);
		pfn = (sg_phy + off) >> PAGE_SHIFT;
		sif_log(sdev, SIF_MMAP, "pfn %pad, sz %lx sg_phys %pad off %lx",
			&pfn, sz, &sg_phy, off);
		ret = remap_pfn_range(vma, start, pfn, sz, vma->vm_page_prot);
		if (ret)
			return ret;
		rem -= sz;
		start += sz;
		off = 0;
		if (rem <= 0)
			break;
		sg = sg_next(sg);
		sz = min_t(off_t, rem, sg->length);
	}
	return 0;
}


/* Remove a set of sg entries from the list starting at page index sg_idx
 * and unlink from the linked list.
 *
 * We have to make sure we maintain consistency for index lookups,
 * so no scatterlist vectors can be deleted from the middle of the list,
 * only head and tail removal is allowed,
 * and if we remove scatterlists from the head of the list, we must update the offset.
 */

int sif_kmem_shrink(struct sif_dev *sdev, struct sif_kmem *kmem, int sg_idx, size_t size)
{
	/* TBD: Implement this! */
	return -EOPNOTSUPP;
}


/************************************
 * API for managing different higher level (scatter) memory segment abstractions
 * used by SIF:
 */

/* Set up a sif_mem structure for handling a memory
 * segment of initial size @size.
 */
struct sif_mem *sif_mem_create(struct sif_dev *sdev, size_t sg_size,
			size_t size, enum sif_mem_type mem_type,
			gfp_t flag, enum dma_data_direction dir)
{
	int ret;
	u32 page_shift = mem_type_to_page_shift(sdev, mem_type);
	struct sif_mem *mem = kzalloc(sizeof(*mem), flag);

	if (!mem)
		return NULL;

	BUG_ON(mem_type != SIFMT_2M && mem_type != SIFMT_4K);


	ret = sif_kmem_init(sdev, &mem->m.km, sg_size,
			size, page_shift, flag, dir);
	if (ret)
		goto failed;

	mem->sdev = sdev;
	mem->size = size;
	mem->mem_type = mem_type;
	mem->max_page_shift = 0;
	return mem;
failed:
	kfree(mem);
	return NULL;
}

/* Create a sif_mem object from an umem object (User level memory)
 * The sif_mem object resumes ownership of the umem:
 */
struct sif_mem *sif_mem_create_umem(struct sif_dev *sdev,
				struct ib_umem *umem,
				enum sif_mem_type mem_type,
				gfp_t flag, enum dma_data_direction dir)
{
	struct sif_mem *mem;
	u64 dma_addr;

	if (mem_type != SIFMT_BYPASS && !umem) {
		sif_log(sdev, SIF_INFO, "Invalid umem setup");
		return NULL;
	}
	mem = kzalloc(sizeof(*mem), flag);
	if (!mem)
		return NULL;

	BUG_ON(!umem);
	BUG_ON(mem_type != SIFMT_UMEM &&
		mem_type != SIFMT_UMEM_RO &&
		mem_type != SIFMT_BYPASS);

	mem->sdev = sdev;
	mem->m.u.umem = umem;
	mem->size = umem->length;
	mem->mem_type = mem_type;

	/* See commit eeb8461e - sg chain safe impl of umem in 3.15 */
	mem->m.u.sg = umem->sg_head.sgl;
	mem->m.u.start_offset = umem->address & ~PAGE_MASK;
	mem->vmap_base = (void *)umem->address;
	mem->max_page_shift = sif_mem_max_page_shift(mem);
	dma_addr = sg_dma_address(mem->m.u.sg);
	sif_log(sdev, SIF_MEM, "vaddr %p, sg dma start 0x%llx, umem start_offset %llx",
		mem->vmap_base, dma_addr, mem->m.u.start_offset);
	if (umem->nmap < umem->npages) {
		int ret;

		sif_log(sdev, SIF_MEM, "Fixing up collapsed sg list (%d/%d)",
			umem->nmap, umem->npages);
		sif_logs(SIF_MEM, sif_dump_sg(mem->m.u.sg));
		ret = sif_mem_fixup_dma(mem->m.u.sg);
		if (ret) {
			sif_log(sdev, SIF_INFO, "sg list fixup failed");
			sif_dump_sg(mem->m.u.sg);
			kfree(mem);
			return NULL;
		}
	}
	sif_logs(SIF_PT_VV, sif_dump_sg(mem->m.u.sg));
	return mem;
}


/* Create a sif_mem object from a phys array of length @num_phys
 * The phys array is owned by caller:
 */
struct sif_mem *sif_mem_create_phys(struct sif_dev *sdev, void *kvaddr,
				struct ib_phys_buf *phys_buf, int num_phys,
				gfp_t flag)
{
	int i;
	u64 size = 0;
	struct sif_mem *mem = kzalloc(sizeof(*mem), flag);

	if (!mem)
		return NULL;

	mem->sdev = sdev;
	mem->m.phys.phys_buf = phys_buf;
	mem->m.phys.phys_buf_len = num_phys;
	for (i = 0; i < num_phys; i++) {
		sif_log(sdev, SIF_MMU_V, "phys_buf addr 0x%llx size 0x%llx",
			phys_buf[i].addr, phys_buf[i].size);
		size += phys_buf[i].size;
	}
	/* TBD: We could calculate this above but phys_mr is scheduled to be removed */
	mem->max_page_shift = 0;
	mem->vmap_base = kvaddr;
	mem->size = size;
	mem->mem_type = SIFMT_PHYS;
	return mem;
}

struct sif_mem *sif_mem_create_fmr(struct sif_dev *sdev, size_t max_pages, u32 page_shift,
				gfp_t flag)
{
	size_t size = max_pages << page_shift;
	struct sif_mem *mem = sif_mem_create_ref(sdev, SIFMT_PTONLY, 0, size, flag);

	if (mem)
		mem->m.fmr.page_shift = page_shift;
	sif_log(sdev, SIF_FMR, "page_shift %d, size 0x%lx", page_shift, size);
	return mem;
}

/* Create a sif_mem object from a memory pointer array of length @num_pages
 * The memory pointer array is owned by caller:
 */
int sif_mem_map_fmr(struct sif_mem *mem, u64 iova,
		u64 *page_list, int num_pages)
{
	u64 actual_size = num_pages << mem->m.fmr.page_shift;

	if (iova & (mem->m.fmr.page_shift - 1)) {
		sif_log(mem->sdev, SIF_INFO, "Misaligned FMR start - iova 0x%llx", iova);
		return -EINVAL;
	}
	if (actual_size > mem->size) {
		/* This is really now an artificial limit for us, except for performance */
		sif_log(mem->sdev, SIF_INFO, "Attempt to map 0x%llx bytes, max for this FMR is 0x%llx",
			actual_size, mem->size);
		return -ENOMEM;
	}
	mem->vmap_base = (void *)iova;
	mem->m.fmr.page_list = page_list;
	mem->m.fmr.page_list_len = num_pages;
	mem->mem_type = SIFMT_FMR;

	/* We save the max mem size to be able to restore it later */
	mem->m.fmr.max_size = mem->size;
	mem->size = actual_size;
	mem->max_page_shift = sif_mem_fmr_max_page_shift(mem);
	return 0;
}

void sif_mem_unmap_fmr(struct sif_mem *mem)
{
	mem->vmap_base = NULL;
	mem->size = mem->m.fmr.max_size;
	mem->m.fmr.page_list = NULL;
	mem->m.fmr.page_list_len = 0;
	mem->mem_type = SIFMT_PTONLY;
}

/* Create a sif_mem object mapped dma contiguous, suitable for
 * BYPASS mapping (size constraints..)
 */
struct sif_mem *sif_mem_create_dmacont(struct sif_dev *sdev, size_t size,
				gfp_t flag, enum dma_data_direction dir)
{
	struct sif_mem *mem = kzalloc(sizeof(*mem), flag);
	dma_addr_t dma_handle;
	struct scatterlist *sg;

	if (!mem)
		return NULL;

	/* The __GFP_DMA32 bit is not supported by page_alloc in all kernels */
	if (unlikely(flag & __GFP_DMA32)) {
		u64 dma_addr;

		mem->vmap_base = ib_dma_alloc_coherent(&sdev->ib_dev, size,
				&dma_addr, flag);
		dma_handle = dma_addr;
		mem->m.u.flags = SMF_DMA32;
	} else
		mem->vmap_base = sif_dma_alloc_aligned(&sdev->ib_dev, size, &dma_handle,
						       flag, dir);
	if (!mem->vmap_base)
		goto dma_alloc_failed;
	mem->sdev = sdev;
	mem->mem_type = SIFMT_BYPASS;
	mem->max_page_shift = sdev->mi.max_shift;
	mem->size = size;
	mem->m.u.dir = dir;
	mem->m.u.umem = NULL;
	sg = mem->m.u.sg = &mem->m.u.sg0;
	sg_init_one(sg, mem->vmap_base, mem->size);
	sg->dma_address = dma_handle;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	sg->dma_length = mem->size;
#endif
	return mem;
dma_alloc_failed:
	kfree(mem);
	return NULL;
}


/* Create a sif_mem object with no own memory backing - to use for CB, SQ_CMPL and
 * kernel full passthrough cases to have a "shallow" mem object:
 */
struct sif_mem *sif_mem_create_ref(struct sif_dev *sdev, enum sif_mem_type mem_type,
				u64 sif_vaddr, size_t size, gfp_t flag)
{
	struct sif_mem *mem = kzalloc(sizeof(*mem), flag);

	if (!mem)
		return NULL;

	BUG_ON(mem_type != SIFMT_PTONLY && mem_type != SIFMT_NOMEM && mem_type != SIFMT_CS);

	mem->sdev = sdev;
	mem->mem_type = mem_type;
	mem->vmap_base = (void *)sif_vaddr;
	mem->size = size;
	mem->max_page_shift = 0;
	return mem;
}


/* Free a sif_mem previously created with sif_mem_create */
int sif_mem_free(struct sif_mem *mem)
{
	switch (mem->mem_type) {
	case SIFMT_2M:
	case SIFMT_4K:
		sif_kmem_free(mem->sdev, &mem->m.km);
		break;
	case SIFMT_BYPASS:
		/* BYPASS mode can be used from kernel or user space
		 * If umem is set, it is a user space mapping:
		 */
		if (!mem->m.u.umem) {
			if (mem->m.u.flags & SMF_DMA32)
				ib_dma_free_coherent(&mem->sdev->ib_dev, mem->size,
						mem->vmap_base, sif_mem_dma(mem, 0));
			else
				sif_dma_free_aligned(&mem->sdev->ib_dev, mem->size,
						mem->vmap_base, sif_mem_dma(mem, 0), mem->m.u.dir);
		}
		/* Deliberate fall-through */
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
		if (mem->m.u.umem)
			ib_umem_release(mem->m.u.umem);
		break;
	default:
		break; /* Nothing extra to do */
	}
	kfree(mem);
	return 0;
}


/* Allocate some (more) memory for this sif_mem
 * Return a pointer to the start of that memory and increase ref.cnt for the sif_mem
 */
int sif_mem_extend(struct sif_mem *mem, size_t size, gfp_t flag)
{
	int sg_idx;

	if (mem->mem_type != SIFMT_2M && mem->mem_type != SIFMT_4K)
		return -EINVAL;

	sg_idx = sif_kmem_extend(mem->sdev, &mem->m.km, size, flag);
	mem->size = mem->m.km.size;
	return sg_idx;
}

/* Free a subrange of this memory object starting at @sg and dereference the
 * sif_mem object. Assumes there is no other references to this subrange:
 */
int sif_mem_shrink(struct sif_mem *mem, int sg_idx, size_t size)
{
	int ret;

	if (mem->mem_type != SIFMT_2M && mem->mem_type != SIFMT_4K)
		return -EINVAL;

	ret = sif_kmem_shrink(mem->sdev, &mem->m.km, sg_idx, size);
	mem->size = mem->m.km.size;
	return ret;
}


bool sif_mem_has_umem(struct sif_mem *mem)
{
	switch (mem->mem_type) {
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
	case SIFMT_BYPASS:
		return mem->m.u.umem != NULL;
	default:
		break;
	}
	return false;
}


/* Find kernel virtual address at @offset within map */
void *sif_mem_kaddr(struct sif_mem *mem, off_t offset)
{
	switch (mem->mem_type) {
	case SIFMT_2M:
	case SIFMT_4K:
	{
		off_t off = offset & ((1 << mem->m.km.page_shift) - 1);
		u32 i = offset >> mem->m.km.page_shift;
		struct scatterlist *sg = sif_kmem_find_sg_idx(&mem->m.km, i);

		return sg_virt(sg) + off;
	}
	case SIFMT_BYPASS:
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
	case SIFMT_NOMEM:
	case SIFMT_PHYS:
	case SIFMT_FMR:
		return mem->vmap_base + offset;
	default:
		break;
	}

	sif_log(mem->sdev, SIF_INFO, "Not implemented for type %d",
		mem->mem_type);
	return NULL;
}

/* Find DMA address at @offset within map */
dma_addr_t sif_mem_dma(struct sif_mem *mem, off_t offset)
{
	switch (mem->mem_type) {
	case SIFMT_PTONLY:
		return offset;
	case SIFMT_2M:
	case SIFMT_4K:
	{
		off_t off = offset & ((1 << mem->m.km.page_shift) - 1);
		u32 i = offset >> mem->m.km.page_shift;
		struct scatterlist *sg = sif_kmem_find_sg_idx(&mem->m.km, i);

		return sg_dma_address(sg) + off;
	}
	case SIFMT_BYPASS:
		return sg_dma_address(mem->m.u.sg) + offset;
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
	{
		struct scatterlist *sg = mem->m.u.sg;
		/* umem objects have page aligned sg lists but may start at an offset */
		offset += mem->m.u.start_offset;
		while (sg && offset >= sg->length) {
			offset -= sg->length;
			sg = sg_next(sg);
		}
		return sg_dma_address(sg) + offset;
	}
	case SIFMT_PHYS:
	{
		struct ib_phys_buf *pb = mem->m.phys.phys_buf;

		while (offset >= pb->size) {
			offset -= pb->size;
			pb++;
		}
		return pb->addr + offset;
	}
	case SIFMT_FMR:
	{
		u32 pageno = offset >> mem->m.fmr.page_shift;
		off_t off = offset & ((1 << mem->m.fmr.page_shift) - 1);

		return mem->m.fmr.page_list[pageno] + off;
	}
	default:
		break;
	}

	sif_log(mem->sdev, SIF_INFO, "Not implemented for type %d",
		mem->mem_type);
	BUG();
	return 0ull;
}


struct scatterlist *sif_mem_get_sgl(struct sif_mem *mem)
{
	switch (mem->mem_type) {
	case SIFMT_UMEM:
	case SIFMT_UMEM_RO:
	case SIFMT_BYPASS:
		return mem->m.u.sg;
	case SIFMT_2M:
	case SIFMT_4K:
		return mem->m.km.sg;
	default:
		sif_log(mem->sdev, SIF_INFO, "unsupported memory type %d", mem->mem_type);
		break;
	}
	return NULL;
}


/* If map is continuous, get start of dma mapping
 * otherwise return an error pointer:
 */
dma_addr_t sif_mem_dma_if_cont(struct sif_mem *mem)
{
	struct scatterlist *sg;
	size_t sz = 1 << sif_mem_max_page_shift(mem);

	if (sz < mem->size) {
		sif_log(mem->sdev, SIF_INFO,
			"size: %lld - max possible page sz %ld: mmu bypass not possible",
			mem->size, sz);
		return (u64)ERR_PTR(-EPERM);
	}
	sg = sif_mem_get_sgl(mem);
	if (unlikely(!sg))
		return (u64)ERR_PTR(-EINVAL);
	return sg_dma_address(sg);
}


int sif_mem_vma_map_part(struct sif_mem *mem, struct vm_area_struct *vma,
			off_t start_off, size_t size)
{
	switch (mem->mem_type) {
	case SIFMT_2M:
	case SIFMT_4K:
		return sif_kmem_vma_map_part(mem->sdev, &mem->m.km, vma, start_off, size);
	case SIFMT_BYPASS:
	case SIFMT_BYPASS_RO:
		return sif_vma_map_sg_part(mem->sdev, mem->m.u.sg, vma, start_off, size);
	default:
		sif_log(mem->sdev, SIF_INFO, "not implemented for mem.type %d", mem->mem_type);
		return -EOPNOTSUPP;
	}
}


/* Map the memory referenced by @mem to the user space vma */
int sif_mem_vma_map(struct sif_mem *mem, struct vm_area_struct *vma)
{
	return sif_mem_vma_map_part(mem, vma, 0, mem->size);
}

/* sif_mem iterator support (mainly for the types that do not expose a scatterlist) */

int sif_mem_iter_init(struct sif_mem *mem, struct sif_mem_iter *it)
{
	it->mem = mem;
	switch (mem->mem_type) {
	case SIFMT_PHYS:
	case SIFMT_FMR:
	case SIFMT_PTONLY:
		it->phys.i = 0;
		break;
	default:
		it->sg = sif_mem_get_sgl(mem);
		if (!it->sg)
			return -EINVAL;
	}
	it->offset = 0;
	return 0;
}


int sif_mem_iter_advance(struct sif_mem_iter *it, u64 incr)
{
	switch (it->mem->mem_type) {
	case SIFMT_PHYS:
	{
		long left = it->mem->m.phys.phys_buf[it->phys.i].size - it->offset;

		if (left > incr)
			it->offset += incr;
		else {
			it->offset = incr - left;
			it->phys.i++;
		}
		if (it->phys.i >= it->mem->m.phys.phys_buf_len)
			return -ENOMEM;
		return 0;
	}
	case SIFMT_FMR:
	{
		long page_size = 1 << it->mem->m.fmr.page_shift;
		long left = page_size - it->offset;

		if (left > incr)
			it->offset += incr;
		else {
			it->offset = incr - left;
			it->phys.i++;
		}
		if (it->phys.i >= it->mem->m.fmr.page_list_len)
			return -ENOMEM;
		return 0;
	}
	case SIFMT_PTONLY:
		it->offset += incr;
		if (it->offset >= it->mem->size)
			return -ENOMEM;
		return 0;
	default:
		it->offset += incr;
		while (it->offset >= it->sg->length) {
			it->offset = it->offset - it->sg->length;
			it->sg = sg_next(it->sg);
		}
		if (it->sg)
			return 0;
		else
			return -ENOMEM;
	}
}

dma_addr_t sif_mem_iter_dma(struct sif_mem_iter *it)
{
	switch (it->mem->mem_type) {
	case SIFMT_PHYS:
		return it->mem->m.phys.phys_buf[it->phys.i].addr + it->offset;
	case SIFMT_FMR:
		return it->mem->m.fmr.page_list[it->phys.i] + it->offset;
	case SIFMT_PTONLY:
		return 0; /* For future fmr use: populate with empty ptes to be filled later */
	default:
		return sg_dma_address(it->sg) + it->offset;
	}
}


/* DMA is mapped continuously and the map is reflected in a "collapsed" sg list for DMA,
 * The rest of the list is still valid for the pa/va part - we need to loop through and
 * make it consistent for our usage:
 */
static int sif_mem_fixup_dma(struct scatterlist *sg)
{
	struct scatterlist *from_sg = sg;
	struct scatterlist *last_sg = sg;
	dma_addr_t dma_addr = sg_dma_address(from_sg);
	size_t dma_size = sg_dma_len(sg);
	size_t sg_len = sg->length; /* Save the "homogeneous" length */

	while (sg) {
		if (dma_size < sg->length)
			return -EINVAL;  /* should not happen */

		if (sg->dma_address && sg->dma_address != (dma_addr_t)-1) {
			/* This entry is part of the collapsed list
			 * must keep address and dma_length until we have "consumed" it,
			 * Since all lengths are homogeneous in the resulting list we
			 * can temporarily "misuse" the length field in this entry to
			 * store the new dma_address, and just leave the dma_length
			 * for later consumption:
			 */
			sg->length = sg->dma_address;
		} else
			sg->dma_length = sg_len;

		sg->dma_address = dma_addr;
		dma_addr += sg_len;
		dma_size -= sg_len;
		last_sg = sg;
		sg = sg_next(sg);

		if (!dma_size) {
			/* Clean up our "temporary store" (see below comment) */
			from_sg->length = from_sg->dma_length = sg_len;
			from_sg = sg_next(from_sg);
			dma_addr = from_sg->length; /* from temp store */
			dma_size = sg_dma_len(from_sg);
		}
	}
	return 0;
}

/* A utility for dumping an sg list to the trace buffer */
void sif_dump_sg(struct scatterlist *sgl)
{
	struct scatterlist *sg = sgl;
	int cnt = 0;

	trace_printk(" **** sg dump - start at %p ****\n", sg);
	trace_printk("%16s: %16s %8s %16s %16s %8s %8s %4s\n",
		"sg", "dma", "dmalen", "pa", "kva", "length", "offset", "end mark");
	while (sg) {
		u64 dma_addr = sg_dma_address(sg);
		u64 pa = sg_phys(sg);

		trace_printk("%p: %#16llx %#8x %#16llx %p %#8x %#8x %4s\n",
			sg, dma_addr, sg_dma_len(sg), pa,
			sg_virt(sg), sg->length, sg->offset,
			(sg_is_last(sg) ? "[last]" : ""));
		sg = sg_next(sg);
		cnt++;
	}
	trace_printk(" **** tot.%d elements ****\n", cnt);
}
