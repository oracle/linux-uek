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
 * sif_pt.c: SIF (private) page table management
 */

#include <linux/mm.h>
#include <linux/kref.h>
#include <linux/seq_file.h>
#include "sif_dev.h"
#include "sif_mr.h"
#include "sif_mem.h"
#include "sif_pt.h"
#include "sif_base.h"

/* A kmem_cache to allocate the nodes in the rb_trees */
static struct kmem_cache *pt_page_cache;

static inline void *sif_pt_cache_alloc(struct sif_dev *sdev, gfp_t flags)
{
#ifdef CONFIG_NUMA
	void *n;

	n = kmem_cache_alloc_node(pt_page_cache, flags, sdev->pdev->dev.numa_node);
	if (n)
		return n;

	sif_log(sdev, SIF_INFO, "Warning: unable to allocate mem on numa node %d",
		sdev->pdev->dev.numa_node);
#endif
	return kmem_cache_alloc(pt_page_cache, flags);
}


/* Declared below */
static int init_top(struct sif_pt *pt, u64 vstart, int npages);


int sif_pt_init(void)
{
	pt_page_cache = KMEM_CACHE(sif_pt_page, 0);
	if (!pt_page_cache)
		return -ENOMEM;
	return 0;
}

void sif_pt_exit(void)
{
	kmem_cache_destroy(pt_page_cache);
}

/* some utilities: */

/* Find the optimal page size (represented by the leaf level)
 * to use based on device capabilities, configuration and a max_shift
 * value (typically based on continuousness of memory.
 * The result is adjusted with the address pair of a corresponding virtual
 * address and dma address to ensure that it is possible to create a mapping at that
 * level. pte_ext_shift is set to the number bits to shift increment between
 * each valid pte (For the odd sized leaf pages)
 * Assumes vaddr and dma_add.
 */
int find_optimal_leaf_level(struct sif_dev *sdev, u32 max_shift,
			u64 vaddr, u64 dma_addr, u64 size,
			u8 *leaf_level, u8 *pte_ext_shift)
{
	u32 shift, adj_page_shift, page_shift;
	unsigned long smallest_misalign;
	u32 bits = sizeof(dma_addr_t) << 3;

	/* Page size not supported by device configuration
	 * TBD: Remove (Should not happen unless a programming error)
	 */
	if (sdev->mi.page_shift > max_shift) {
		sif_log(sdev, SIF_INFO,
			"Failed to find a valid leaf level (page_shift %d, max_shift %d)",
			sdev->mi.page_shift, max_shift);
		return -EINVAL;
	}

	*leaf_level = 0;
	*pte_ext_shift = 0;
	shift = sdev->mi.page_shift;

	switch (shift) {
	case 12:
		/* Device configured for Intel page sizes:
		 * In x86 mode for PSIF 2.1 only 4K base page size is supported
		 */
		if (max_shift < 21)
			break;
		*leaf_level = 1;
		if (max_shift < 30)
			break;
		*leaf_level = 2;
		break;
	case 13: /* Device configured for Sparc page sizes */
		if (max_shift < 16)
			break;
		*pte_ext_shift = 3; /* 64K base page - only populate every 8th leaf entry */
		if (max_shift < 19)
			break;
		*pte_ext_shift = 6;  /* 512K base page - only populate every 64th leaf entry */
		if (max_shift < 22)
			break;
		*leaf_level = 1;
		*pte_ext_shift = 0;
		if (max_shift < 25)
			break;
		*pte_ext_shift = 3; /* Fits 32M pages at level 1 - every 8th 4M entry */
		if (max_shift < 28)
			break;
		*pte_ext_shift = 6; /* Fits 256M pages at level 1 - every 64th 4M entry */
		if (max_shift < 31)
			break;
		*leaf_level = 2;
		*pte_ext_shift = 0; /* Fits 2GB pages at level 2 */
		if (max_shift < 34)
			break;
		*pte_ext_shift = 3; /* Fits 16GB pages at level 2 - every 8th 2GB entry */
		if (max_shift < 37)
			break;
		break;
	default:
		BUG();
	}
	if (*leaf_level) {
		page_shift = shift + (*leaf_level * sdev->mi.level_shift);
		smallest_misalign = (dma_addr ^ vaddr) & ((1 << page_shift) - 1);
		if (smallest_misalign & ~PAGE_MASK) {
			sif_log(sdev, SIF_INFO,
				"Failed to create page table: misaligned VA/DMA (0x%lx) dma 0x%llx vaddr 0x%llx",
				smallest_misalign, dma_addr, vaddr);
			return -EINVAL;
		}

		if (smallest_misalign) {
			adj_page_shift = find_first_bit(&smallest_misalign, bits);
			*leaf_level = (adj_page_shift - shift) / sdev->mi.level_shift;
			sif_log(sdev, SIF_PT,
				"misaligned VA/DMA adj: leaf_level %d, page_shift %d, smallest_misalign 0x%lx, adj_page_shift %d",
				*leaf_level,
				page_shift, smallest_misalign, adj_page_shift);
			page_shift = adj_page_shift;
		}
		/* TBD: Remove - just for debugging */
		if (*leaf_level > 3) {
			sif_log(sdev, SIF_INFO,
				"haywire leaf level %d - should not be possible - setting safe value 0",
				*leaf_level);
			*leaf_level = 0;
			return -EINVAL;
		}
		if (*leaf_level) {
			/* Check if we can do equally well with a lower level pointer */
			int size_order = order_base_2(size);
			int size_shift = page_shift - size_order;

			if (size_shift < 0)
				goto out;
			sif_log(sdev, SIF_PT, "order %d page_shift %d size_shift %d",
				size_order, page_shift, size_shift);
			if (size_shift > 0) {
				u32 new_leaf_level =
					((page_shift - size_shift + sdev->mi.level_shift - 1 - shift)
						/ sdev->mi.level_shift);
				sif_log(sdev, SIF_PT, "new_leaf_level %d", new_leaf_level);
				if (new_leaf_level < *leaf_level) {
					*leaf_level = new_leaf_level;
					sif_log(sdev, SIF_PT,
						"size_shift %d, size adjusted leaf_level %d",
						size_shift, *leaf_level);
				}
			}
		}
	}
out:
	sif_log(sdev, SIF_PT, "shift %d leaf_level %d", shift, *leaf_level);
	return 0;
}

/* Find the aligned size of a region within a certain page alignment size
 * (eg. the number of pages of size @alignment needed to address (start,len))
 */
u64 aligned_size(u64 start, u64 len, u64 alignment)
{
	u64 mask = alignment - 1;
	u64 aligned_start = start & ~mask;
	u64 aligned_end = (start + len + mask) & ~mask;

	return aligned_end - aligned_start;
}

/* Find the union of the two ranges including non-overlapped parts */
static u64 merge_ranges(u64 start1, u64 size1, u64 start2, u64 size2, u64 *new_size)
{
	u64 new_start = min(start1, start2);
	u64 new_end = max(start1 + size1, start2 + size2);
	*new_size = new_end - new_start;
	return new_start;
}

static u32 level_to_pageshift(struct sif_pt *pt, int level)
{
	struct sif_mem_info *mi = &pt->sdev->mi;

	level++;
	if (level < 0 || level > 4)
		sif_log(pt->sdev, SIF_INFO, "level %d", level);
	BUG_ON(level < 0 || level > 4);
	return mi->page_shift + mi->level_shift * level;
}

static u64 level_to_pagesize(struct sif_pt *pt, int level)
{
	return (1ull << level_to_pageshift(pt, level));
}

static u64 level_to_pagemask(struct sif_pt *pt, int level)
{
	return (level_to_pagesize(pt, level) - 1);
}


u32 sif_pt_page_shift(struct sif_pt *pt)
{
	return level_to_pageshift(pt, pt->leaf_level - 1);
}

/* Find the required page table memory need in number of
 * pt->page_table_page sized pages
 * If pt->fixed_top, calculate space for a final page for each of the levels
 * even if only one entry is necessary.
 *
 * NB! Sets pt->top_level as a side effect
 */
static u32 table_mem_need(struct sif_pt *pt, u64 vstart, u64 mapsize)
{
	u64 aligned_size_pte;
	u64 aligned_size_pmd;
	u64 aligned_size_pud;
	u64 aligned_size_pgd;
	u64 aligned_size_pml4;
	u64 psz;
	int nptes, npmds, npuds, npgds, pte_pages;
	int pshift;
	/* If we need to guarantee that the top node remains the same, we must build
	 * a max level page table
	 */
	int single = pt->fixed_top ? 1 : 0;
	struct sif_dev *sdev = pt->sdev;

	/* Determine what setup to use for the kmem object based on the initial mapsize:
	 * We use 4K pages for now, and set sg_size to the number of pages needed to
	 * support mapsize + the full chain of pages if we need a 4-level table:
	 */
	psz = sdev->mi.page_size;
	aligned_size_pte = aligned_size(vstart, mapsize, psz);
	psz <<= sdev->mi.level_shift;
	aligned_size_pmd = aligned_size(vstart, mapsize, psz);
	psz <<= sdev->mi.level_shift;
	aligned_size_pud = aligned_size(vstart, mapsize, psz);
	psz <<= sdev->mi.level_shift;
	aligned_size_pgd = aligned_size(vstart, mapsize, psz);
	psz <<= sdev->mi.level_shift;
	aligned_size_pml4 = aligned_size(vstart, mapsize, psz);

	sif_log(pt->sdev, SIF_MMU, "aligned lengths: pte %llx pmd %llx pud %llx pgd %llx pml4 %llx",
		aligned_size_pte, aligned_size_pmd, aligned_size_pud,
		aligned_size_pgd, aligned_size_pml4);

	pshift = sdev->mi.page_shift + sdev->mi.level_shift;
	nptes = aligned_size_pmd >> pshift;
	pshift += sdev->mi.level_shift;
	npmds = nptes > 1 ? aligned_size_pud >> pshift : single;
	pshift += sdev->mi.level_shift;
	npuds = npmds > 1 ? aligned_size_pgd >> pshift : single;
	pshift += sdev->mi.level_shift;
	npgds = npuds > 1 ? aligned_size_pml4 >> pshift : single;

	pte_pages = pt->leaf_level ? 0 : nptes;

	sif_log(pt->sdev, SIF_MMU, "npgds %d, npuds %d, npmds: %d, pte_pages %d",
		npgds, npuds, npmds, pte_pages);

	pt->top_level = single ? 3 : (npgds ? 3 : (npuds ? 2 : (npmds ? 1 : 0)));
	return pte_pages + npmds + npuds + npgds;
}

/* Find page table entry index for the pte referring
 * the page starting at vaddr at level @level
 */
static inline int sif_pte_index(struct sif_dev *sdev, u64 vaddr, u64 page_shift)
{
	return (vaddr >> page_shift) & (sdev->mi.ptes_per_page - 1);
}




static void pt_free_page(struct sif_pt *pt, struct sif_pt_page *n)
{
	list_add_tail(&n->list, &pt->freelist);
	n->parent = NULL;
	n->vaddr = 0;
}


/* Destructor callback for kref */
static void sif_pt_release(struct kref *kref)
{
	struct sif_pt *pt = container_of(kref, struct sif_pt, refcnt);
	struct list_head *np;
	struct list_head *npp;
	struct sif_pt_page *n;

	sif_log(pt->sdev, SIF_MMU_V, "at %p", pt);

	if (pt->top)
		pt_free_page(pt, pt->top);

	/* Actual cleanup */
	list_for_each_safe(np, npp, &pt->freelist) {
		n = list_entry(np, struct sif_pt_page, list);
		kfree(n);
	}
	if (pt->m.sg_size)
		sif_kmem_free(pt->sdev, &pt->m);
	kfree(pt);
}


/* Create a sif_page_table object and if mapsize > 0,
 * map the range starting at @sg to a map with start at virtual
 * address @vstart and size @mapsize and the number of bits to use in each page
 * in page_shift. The object can later be resized using sif_pt_extend/sif_pt_shrink:
 * Set @modifiable to allow the table to be extended and shrinked
 * Set @fixed_top to have pt guarantee that the top node remains constant
 * in which case it will always be a level 4 tree.
 */
struct sif_pt *sif_pt_create(struct sif_dev *sdev, struct scatterlist *sg,
			u64 vstart, size_t size, u32 page_shift,
			bool modifiable, bool fixed_top)
{
	int ret = 0;
	int i;
	dma_addr_t dma_start = sg ? sg_dma_address(sg) : 0;
	struct sif_pt *pt = sif_kmalloc(sdev, sizeof(*pt), GFP_KERNEL | __GFP_ZERO);

	if (!pt)
		return NULL;

	/* sub-page misalignment in vstart must correspond with
	 * misalignment in dma address but sg entries are page aligned:
	 */
	dma_start += vstart & ~PAGE_MASK;

	sif_log(sdev, SIF_MMU, "vstart %llx, size %lx, page_shift %d%s", vstart, size,
		page_shift, (modifiable ? " (modifiable)" : ""));
	pt->sdev = sdev;
	pt->fixed_top = fixed_top;
	pt->modifiable = modifiable;

	ret = find_optimal_leaf_level(sdev, page_shift,
				vstart, dma_start, size,
				&pt->leaf_level, &pt->pte_ext_shift);
	if (ret)
		goto extend_failed;

	pt->page_shift = sdev->mi.page_shift + pt->leaf_level * sdev->mi.level_shift;
	pt->ptes_per_page = 1 << sdev->mi.level_shift;

	for (i = 0; i < PT_LEVELS; i++)
		pt->pmd[i] = RB_ROOT;
	kref_init(&pt->refcnt);
	mutex_init(&pt->lock);
	INIT_LIST_HEAD(&pt->freelist);

	ret = sif_pt_extend(pt, sg, vstart, size);
	if (ret < 0)
		goto extend_failed;
	return pt;

extend_failed:
	kfree(pt);
	return NULL;
}


struct sif_pt *sif_pt_create_for_mem(struct sif_mem *mem,
				u64 vstart, u32 page_shift, bool modifiable, bool fixed_top)
{
	int ret = 0;
	int i;
	struct sif_dev *sdev = mem->sdev;
	struct sif_pt *pt = sif_kmalloc(sdev, sizeof(*pt), GFP_KERNEL | __GFP_ZERO);
	size_t size = mem->size;

	if (!pt)
		return NULL;

	sif_log(sdev, SIF_MMU, "vstart %llx, size %lx, page_shift %d%s", vstart, size,
		page_shift, (modifiable ? " (modifiable)" : ""));
	pt->sdev = sdev;
	pt->fixed_top = fixed_top;
	pt->modifiable = modifiable;
	ret = find_optimal_leaf_level(sdev, page_shift,
				vstart, sif_mem_dma(mem, 0), size,
				&pt->leaf_level, &pt->pte_ext_shift);
	if (ret)
		goto extend_failed;

	pt->page_shift = sdev->mi.page_shift + pt->leaf_level * sdev->mi.level_shift;
	pt->ptes_per_page = 1 << sdev->mi.level_shift;

	for (i = 0; i < PT_LEVELS; i++)
		pt->pmd[i] = RB_ROOT;
	kref_init(&pt->refcnt);
	mutex_init(&pt->lock);
	INIT_LIST_HEAD(&pt->freelist);

	ret = sif_pt_extend_with_mem(pt, mem, vstart);
	if (ret < 0)
		goto extend_failed;
	return pt;

extend_failed:
	kfree(pt);
	return NULL;
}


/* Create an empty, extendable sif page table object */
struct sif_pt *sif_pt_create_empty(struct sif_dev *sdev, u64 vstart, enum sif_mem_type map_mt)
{
	u32 page_shift = sdev->mi.page_shift;
	struct sif_pt *pt;
	int ret;

	if (map_mt == SIFMT_2M)
		page_shift += sdev->mi.level_shift;

	pt = sif_pt_create(sdev, NULL, vstart, 0, page_shift, true, map_mt == SIFMT_CS);
	if (!pt)
		return NULL;

	if (map_mt == SIFMT_CS) {
		/* Allocate an empty top page table page to get an address to send to PSIF: */
		pt->top_level = 3;
		ret = init_top(pt, 0, 1);
		if (ret) {
			sif_kmem_free(pt->sdev, &pt->m);
			return NULL;
		}
	}
	return pt;
}


/* DMA address of root pointer of page table */
dma_addr_t sif_pt_dma_root(struct sif_pt *pt)
{
	return pt->top ? sg_dma_address(pt->top->page) : 0;
}

/* SIF level of root pointer */
u8 sif_pt_root_table_level(struct sif_pt *pt)
{
	return pt->top_level + 1;
}


/* Create sif_pt_page objects for @npages new pages for the page list in @sgl
 * and insert them into the freelist:
 */
static int add_pages_to_freelist(struct sif_pt *pt, struct scatterlist *sgl, int npages)
{
	struct scatterlist *sg;
	struct sif_pt_page *n;
	int i;

	for_each_sg(sgl, sg, npages, i) {
		n = sif_pt_cache_alloc(pt->sdev, GFP_KERNEL | __GFP_ZERO);
		if (!n)
			return -ENOMEM;
		sif_log(pt->sdev, SIF_MMU_V, "i = %d: sg %p", i, sg);
		n->page = sg;
		list_add_tail(&n->list, &pt->freelist);
	}
	return 0;
}


/* TBD: Consider allocating more than a single page at a time from @m object
 * as sif_kmem_find_sg_list is O(n) where n is the number of sg arrays in @m.
 */
static struct sif_pt_page *pt_alloc_page(struct sif_pt *pt, u64 vaddr)
{
	int ret;
	struct scatterlist *sg;
	struct sif_pt_page *n;

	if (list_empty(&pt->freelist)) {
		ret = sif_kmem_extend(pt->sdev, &pt->m, PAGE_SIZE, GFP_KERNEL);
		if (ret < 0)
			goto failed;
		sg = sif_kmem_find_sg_idx(&pt->m, ret);
		ret = add_pages_to_freelist(pt, sg, 1);
		if (ret < 0)
			goto failed;
	}

	n = list_first_entry(&pt->freelist, struct sif_pt_page, list);
	list_del(&n->list);
	n->vaddr = vaddr;
	return n;
failed:
	return ERR_PTR(ret);
}



static struct sif_pt_page *replace_top(struct sif_pt *pt, u64 vaddr)
{
	/* insert a new top node, put the old one into the
	 * empty rbtree for this level, and link the old top node from
	 * the new top:
	 */
	u64 aligned_vaddr, top_pagesize;
	u64 pt_shift, ptv;
	u64 *pmd;
	int i;
	struct sif_pt_page *ep;
	struct sif_dev *sdev = pt->sdev;

	if (pt->top->usecnt == 1) {
		/* Top node not used, just reuse with different va */
		pt->top->vaddr = vaddr;
		return pt->top;
	}

	pt->top->usecnt--;
	/* Loop until we have a top node that spans vaddr */
	do {
		int level = pt->top_level;
		struct rb_root *root = &pt->pmd[level];
		struct rb_node **np = &root->rb_node;

		top_pagesize = level_to_pagesize(pt, ++pt->top_level);
		aligned_vaddr = pt->top->vaddr & ~(top_pagesize - 1);

		rb_link_node(&pt->top->node, NULL, np);
		rb_insert_color(&pt->top->node, root);
		ep = pt->top;
		pt->top = pt_alloc_page(pt, aligned_vaddr);
		if (IS_ERR(pt->top)) {
			ep = pt->top;
			pt->top = NULL;
			return ep;
		}

		ep->parent = pt->top;
		pmd = sg_virt(pt->top->page);
		pt_shift = level_to_pageshift(pt, level);
		i = sif_pte_index(sdev, ep->vaddr, pt_shift);
		ptv = sg_dma_address(ep->page) | PT_PAGE_PRESENT;
		sif_log(sdev, SIF_MMU_V, "level %d: pmd[%d](%p) = %llx", level, i, &pmd[i], ptv);
		BUG_ON(pmd[i] != 0);
		pmd[i] = ptv;
		pt->top->usecnt++;

		sif_log(sdev, SIF_MMU,
			"New top node at dma addr %pad level %d - aligned at %llx, page sz. %llx",
			&sg_dma_address(pt->top->page), pt->top_level, aligned_vaddr, top_pagesize);
	} while (vaddr < aligned_vaddr || vaddr >= aligned_vaddr + top_pagesize);

	return NULL;
}



/* Find the page table page at level whose first entry references the sif virtual address @vaddr
 * @vaddr assumed to be aligned to the appropriate alignment for the level.
 * If the page does not exist, allocate a new one and add it:
 */
static struct sif_pt_page *find_insert_page(struct sif_pt *pt, u8 level, u64 vaddr)
{
	struct rb_root *root = &pt->pmd[level];
	struct rb_node **np = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sif_pt_page *ep;
	struct sif_dev *sdev = pt->sdev;

	sif_log(sdev, SIF_MMU, "level %d vaddr %llx", level, vaddr);
	if (level == pt->top_level) {
		if (likely(vaddr == pt->top->vaddr))
			return pt->top;

		/* (possibly recursively) build up a new top node that spans both
		 * the old tree and the new subtree:
		 */
		ep = replace_top(pt, vaddr);
		if (ep)
			return ep;
	}

	while (*np) {
		ep = container_of(*np, struct sif_pt_page, node);
		parent = *np;
		if (vaddr < ep->vaddr)
			np = &((*np)->rb_left);
		else if (vaddr > ep->vaddr)
			np = &((*np)->rb_right);
		else {
			sif_log(sdev, SIF_PT,
				"Level %d: Found page at vaddr %llx with dma addr %pad",
				level, ep->vaddr, &sg_dma_address(ep->page));
			return ep;
		}
	}

	/* Allocate and insert a new node into the tree */
	ep = pt_alloc_page(pt, vaddr);
	if (IS_ERR(ep))
		return ep;

	sif_log(sdev, SIF_PT, "Allocated new pt page for vaddr %llx with dma addr %pad",
		vaddr, &sg_dma_address(ep->page));

	rb_link_node(&ep->node, parent, np);
	rb_insert_color(&ep->node, root);
	return ep;
}


/* Find an element in the tree for the given level, return NULL if it does not
 * exist:
 */
static struct sif_pt_page *find_page(struct sif_pt *pt, u8 level, u64 vaddr)
{
	struct rb_root *root;
	struct rb_node *n;
	struct rb_node *parent = NULL;
	struct sif_pt_page *ep;

	if (level == pt->top_level)
		return pt->top;

	root = &pt->pmd[level];
	n = root->rb_node;

	sif_log(pt->sdev, SIF_MMU_V, "level %d vaddr %llx", level, vaddr);
	while (n) {
		ep = container_of(n, struct sif_pt_page, node);
		parent = n;
		if (vaddr < ep->vaddr)
			n = n->rb_left;
		else if (vaddr > ep->vaddr)
			n = n->rb_right;
		else
			return ep;
	}
	return NULL;
}


static inline struct sif_pt_page *next_page(struct sif_pt_page *p)
{
	struct rb_node *node = rb_next(&p->node);

	if (node)
		return container_of(node, struct sif_pt_page, node);
	else
		return NULL;
}

static inline struct sif_pt_page *prev_page(struct sif_pt_page *p)
{
	struct rb_node *node = rb_prev(&p->node);

	if (node)
		return container_of(node, struct sif_pt_page, node);
	else
		return NULL;
}

static inline struct sif_pt_page *first_page(struct sif_pt *pt, int level)
{
	struct rb_node *node = rb_first(&pt->pmd[level]);

	if (node)
		return container_of(node, struct sif_pt_page, node);
	else
		return NULL;
}

static inline struct sif_pt_page *last_page(struct sif_pt *pt, int level)
{
	struct rb_node *node = rb_last(&pt->pmd[level]);

	if (node)
		return container_of(node, struct sif_pt_page, node);
	else
		return NULL;
}


/* Create the page table tree from the given vaddr upwards, until
 * we reach an existsting node or find the top node. Update use counts on the
 * involved nodes:
 */
static struct sif_pt_page *find_next(struct sif_pt *pt, u8 level, u64 vaddr)
{
	u64 vaddr_up = 0;
	struct sif_pt_page *pt_page_start = find_insert_page(pt, level, vaddr);
	struct sif_pt_page *pt_page;
	struct sif_pt_page *pt_parent;
	struct sif_dev *sdev = pt->sdev;
	int i;

	if (pt_page_start == pt->top || IS_ERR(pt_page_start))
		return pt_page_start;

	sif_log(sdev, SIF_MMU_V, "level %d vaddr %llx", level, vaddr);

	pt_page = pt_page_start;
	for (;;) {
		u64 pt_shift, ptv;
		u64 *pmd;

		pt_shift = level_to_pageshift(pt, level);
		pt_parent = pt_page->parent;
		level++;
		if (pt_parent) {
			/* We found an existing node - rest of the tree upwards is ok */
			break;
		}
		vaddr_up = vaddr & ~level_to_pagemask(pt, level);
		if (level == pt->top_level && vaddr_up == pt->top->vaddr) {
			sif_log(sdev, SIF_PT, "found top at level %d", level);
			pt_parent = pt->top;
		} else {
			sif_log(sdev, SIF_PT, "searching at level %d/%d from vaddr %llx",
				level, pt->top_level, vaddr_up);
			pt_parent = find_insert_page(pt, level, vaddr_up);
		}

		if (IS_ERR(pt_parent))
			return pt_parent;

		pt_page->parent = pt_parent;

		/* Set page pointer in parent */
		pmd = sg_virt(pt_parent->page);
		i = sif_pte_index(sdev, vaddr, pt_shift);
		ptv = sg_dma_address(pt_page->page) | PT_PAGE_PRESENT;
		sif_log(sdev, SIF_MMU_V, "level %d: pmd[%d](%p) = %llx", level, i, &pmd[i], ptv);
		WARN_ON(pmd[i] != 0);
		pmd[i] = ptv;

		pt_parent->usecnt++;
		if (pt_parent == pt->top || pt_parent->usecnt > 1)
			break;
		pt_page = pt_parent;
		vaddr = vaddr_up;
	}
	return pt_page_start;
}


static int populate_pt(struct sif_pt *pt, struct scatterlist *sg,
		u64 vstart, size_t size)
{
	int level = pt->leaf_level;
	u64 va, vend, incr;
	u64 pt_shift = level_to_pageshift(pt, level-1); /* page shift for the level below us */
	u64 page_flags = PT_PAGE_PRESENT;
	struct sif_dev *sdev = pt->sdev;
	u64 small_page_misalign;
	u64 large_page_misalign = 0;
	off_t sg_offset; /* Running page aligned offset within the current sg */

	/* If level > 0 we must set the PS bit to indicate that this is a leaf node
	 * We also have two levels of alignment to consider:
	 */
	if (level > 0) {
		small_page_misalign = vstart & level_to_pagemask(pt, level - 2);
		large_page_misalign = (vstart & level_to_pagemask(pt, level - 1)) - small_page_misalign;
		page_flags |= PT_PAGE_PS;
	} else
		small_page_misalign = (vstart & level_to_pagemask(pt, level - 1));


	/* Populate the table at level @level - assuming no overlap */
	vend = vstart + size;
	va = vstart & ~level_to_pagemask(pt, level - 1);

	/* Depending on alignment we might need to point to a DMA address
	 * way ahead of the first sg, but aligned to the first small page size:
	 */
	sg_offset = -large_page_misalign;
	incr = level_to_pagesize(pt, level - 1) << pt->pte_ext_shift;

	sif_log(sdev, SIF_PT,
		"level %d mis (0x%llx,0x%llx) vstart %llx -> %llx size %lx pte_ext_shift %d, incr 0x%llx sg_offset %#lx",
		level, small_page_misalign, large_page_misalign, vstart, va, size,
		pt->pte_ext_shift, incr, sg_offset);

	while (va < vend) {
		struct sif_pt_page *pt_page;
		u64 *pmd;
		int i;
		u64 va_up = va & ~level_to_pagemask(pt, level);

		pt_page = find_next(pt, level, va_up);
		if (IS_ERR(pt_page))
			return PTR_ERR(pt_page);

		pmd = sg_virt(pt_page->page);
		i = sif_pte_index(sdev, va, pt_shift);
		for (; i < sdev->mi.ptes_per_page && va < vend; i++) {
			u64 ptv;

			if (!sg) {
				sif_log(sdev, SIF_INFO,
					"##### pt at %p: level %d: failed to find next sg at va %llx (vstart,size) = (%llx,%lx))",
					pt, level, va, vstart, size);
				return -EIO;
			}
			ptv = (sg_dma_address(sg) + sg_offset) | page_flags;
			WARN_ON(pmd[i] != 0);
			sif_log(sdev, SIF_PT_V, "va %llx: level %d: pmd[%d](%p) = %llx",
				va, level, i, &pmd[i], ptv);
			pmd[i] = ptv;
			pt_page->usecnt++;
			va += incr;
			sg_offset += incr;
			/* At this point size might be the end aligned size at this level so
			 * make sure to terminate at the end of the sg list:
			 */
			while (sg && sg_offset >= sg_dma_len(sg)) {
				if (incr > sdev->mi.page_size)
					sif_log(sdev, SIF_PT_VV,
						"sg_offset %#lx sg->length %x sg_dma_len(sg) %x",
						sg_offset, sg->length, sg_dma_len(sg));
				sg_offset -= sg_dma_len(sg);
				sg = sg_next(sg);
			}
			/* Note that we must handle both small incr in large pages and opposite! */
			if (unlikely(sg_offset && sg_offset < incr))
				return 0; /* We're done - vend in the middle of a higher level page */
		}
	}

	return 0;
}


/* sif_mem iterator based page table population - needed for special types */
static int populate_pt_from_mem(struct sif_pt *pt, struct sif_mem *mem, u64 vstart, bool fast_path)
{
	u8 level = pt->leaf_level;
	u64 va, vend, incr;
	u64 pt_shift = level_to_pageshift(pt, level-1); /* page shift for the level below us */
	u64 page_flags = PT_PAGE_PRESENT;
	struct sif_mem_iter mi;
	struct sif_dev *sdev = pt->sdev;
	u64 small_page_misalign;
	u64 large_page_misalign = 0;
	off_t sg_offset; /* Running page aligned offset within the current sg */

	/* If level > 0 we must set the PS bit to indicate that this is a leaf node
	 * We also have two levels of alignment to consider:
	 */
	if (level > 0) {
		small_page_misalign = vstart & level_to_pagemask(pt, level - 2);
		large_page_misalign = (vstart & level_to_pagemask(pt, level - 1)) - small_page_misalign;
		page_flags |= PT_PAGE_PS;
	} else
		small_page_misalign = (vstart & level_to_pagemask(pt, level - 1));

	/* Populate the table at level @level - assuming no overlap */
	vend = vstart + mem->size;
	va = vstart & ~level_to_pagemask(pt, level - 1);

	/* Depending on alignment we might need to point to a DMA address
	 * way ahead of the first sg, but aligned to the first small page size:
	 */
	sg_offset = -large_page_misalign;
	incr = level_to_pagesize(pt, level - 1) << pt->pte_ext_shift;
	sif_mem_iter_init(mem, &mi);

	sif_log(sdev, SIF_PT,
		"level %d mis (0x%llx,0x%llx) vstart %llx -> %llx size %llx pte_ext_shift %d, incr 0x%llx sg_offset %#lx",
		level, small_page_misalign, large_page_misalign, vstart, va, mem->size,
		pt->pte_ext_shift, incr, sg_offset);

	while (va < vend) {
		struct sif_pt_page *pt_page;
		u64 *pmd;
		int i;
		u64 va_up = va & ~level_to_pagemask(pt, level);

		pt_page = find_next(pt, level, va_up);
		if (IS_ERR(pt_page))
			return PTR_ERR(pt_page);

		pmd = sg_virt(pt_page->page);
		i = sif_pte_index(sdev, va, pt_shift);
		for (; i < sdev->mi.ptes_per_page && va < vend; i++) {
			u64 ptv;

			ptv = (sif_mem_iter_dma(&mi) + sg_offset) | page_flags;
			BUG_ON(!(ptv & ~0x81));
			sif_log(sdev, SIF_PT_V, "level %d: pmd[%d](%p) = %llx", level, i, &pmd[i], ptv);
			pmd[i] = ptv;
			if (!fast_path)
				pt_page->usecnt++;
			va += incr;
			sg_offset += incr;
			if (va < vend) {
				int ret = sif_mem_iter_advance(&mi, sg_offset);

				if (ret) {
					sif_log(sdev, SIF_MMU_V, "No page for vaddr %llx", va);
					return ret;
				}
				sg_offset = 0;
			}
		}
	}

	return 0;
}


/* (safe) observe leaf node of page table at @vaddr */
int sif_pt_entry(struct sif_pt *pt, u64 vaddr, dma_addr_t *entry, dma_addr_t *val)
{
	int ret = 0;
	struct sif_pt_page *p;
	struct sif_dev *sdev = pt->sdev;
	u64 *pmd;
	u64 pt_shift;
	u64 va_up;
	u8 level;
	int i, ip;

	mutex_lock(&pt->lock);
	level = pt->leaf_level;
	va_up = vaddr & ~level_to_pagemask(pt, level);
	pt_shift = level_to_pageshift(pt, level-1);
	p = find_page(pt, level, va_up);
	if (p) {
		pmd = sg_virt(p->page);
		i = sif_pte_index(sdev, vaddr, pt_shift);
		*val = pmd[i];
		pmd = sg_virt(p->parent->page);
		ip = sif_pte_index(sdev, va_up, level_to_pageshift(pt, level));
		*entry = pmd[ip];
		sif_log(sdev, SIF_MMU_V,
			"Page at vaddr %llx, lookup vaddr %llx at index %d: entry(idx = %d): %pad, value: %pad",
			va_up, vaddr, i, ip, entry, val);
	} else {
		sif_log(sdev, SIF_MMU_V, "Page at vaddr %llx not found", va_up);
		ret = -EINVAL;
	}
	mutex_unlock(&pt->lock);
	return ret;
}


/* Remove a reference to the given remove_addr from page @p,
 * if refcnt == 0, return page to freelist
 * and (if at leaf level) return the next page in the rb_tree, otherwise return
 * the same page.
 *
 */
static struct sif_pt_page *remove_page_ref(struct sif_pt *pt, struct sif_pt_page *p,
					u64 remove_addr, u8 level)
{
	struct sif_pt_page *np = p;
	u64 *pmd = sg_virt(p->page);
	int index = sif_pte_index(pt->sdev, remove_addr, level_to_pageshift(pt, level-1));
	u64 dma_addr = sg_dma_address(p->page);

	BUG_ON(p->usecnt < 1);
	pmd[index] = 0;

	p->usecnt--;
	sif_log(pt->sdev, SIF_PT_VV,
		"level %d: index = %d ps = %d, page - dma at 0x%llx - use count %d",
		level, index, level_to_pageshift(pt, level-1), dma_addr, p->usecnt);
	if (!p->usecnt) {
		if (p->parent)
			remove_page_ref(pt, p->parent, p->vaddr, level + 1);
		else
			BUG_ON(p != pt->top);
		if (level == pt->leaf_level)
			np = next_page(p);
		if (pt->top != p) /* We dont use the rbtree for the top node */
			rb_erase(&p->node, &pt->pmd[level]);
		else
			pt->top = NULL; /* So we can check if removal is needed in sif_pt_release() */
		pt_free_page(pt, p);
	}
	return np;
}

/* size of each sg list used to maintain page table pages
 * when fixed_top is set (currently only used by the sq_cmpl table)
 * We want it reasonably large as we index in constant time into the list
 * but use a linear scan to navigate the chain of lists
 */
#define FIXED_TOP_SG_SIZE 0x1000

static int init_top(struct sif_pt *pt, u64 vstart, int npages)
{
	u64 aligned_vaddr = vstart & ~(level_to_pagesize(pt, pt->top_level) - 1);
	int ret;
	size_t sg_size = pt->fixed_top ? FIXED_TOP_SG_SIZE : max(npages, 1);

	/* Single pte table necessary for WA for Bug #4096 */
	if (pt->top_level < pt->leaf_level) {
		sif_log(pt->sdev, SIF_PT_V, "Adjusting top level %d -> %d",
			pt->top_level, pt->leaf_level);
		pt->top_level = pt->leaf_level;
	}

	ret = sif_kmem_init(pt->sdev, &pt->m, sg_size, (u64)npages << PAGE_SHIFT,
			PAGE_SHIFT, GFP_KERNEL, DMA_TO_DEVICE);
	if (ret < 0)
		return ret;

	if (add_pages_to_freelist(pt, pt->m.sg, pt->m.sg_max))
		return ret;

	/* Create the top node of the page table: */
	pt->top = pt_alloc_page(pt, aligned_vaddr);
	if (unlikely(IS_ERR(pt->top))) {
		int ret = PTR_ERR(pt->top);

		pt->top = NULL;
		return ret;
	}
	sif_log(pt->sdev, SIF_PT_V,
		"Created top node at kva %p, dma addr %pad level %d for vstart %llx - aligned at %llx",
		sg_virt(pt->top->page), &sg_dma_address(pt->top->page),
		pt->top_level, vstart, aligned_vaddr);

	if (pt->modifiable) {
		/* avoid that this node gets freed if all mappings are removed */
		pt->top->usecnt++;
	}
	return 0;
}


inline void reinit_top(struct sif_pt *pt, u64 vstart)
{
	u64 aligned_vaddr = vstart & ~(level_to_pagesize(pt, pt->top_level) - 1);

	sif_log(pt->sdev, SIF_PT_V,
		"Reused top node at dma addr %pad level %d for vstart %llx - aligned at %llx",
		&sg_dma_address(pt->top->page), pt->top_level, vstart, aligned_vaddr);
	pt->top->vaddr = aligned_vaddr;
}


static u64 recalc_vstart(struct sif_pt *pt)
{
	struct sif_dev *sdev = pt->sdev;
	struct sif_pt_page *p = first_page(pt, pt->leaf_level);
	u64 page_shift = level_to_pageshift(pt, pt->leaf_level - 1);
	int i;

	if (p) {
		u64 *pmd = sg_virt(p->page);

		for (i = 0; i < sdev->mi.ptes_per_page; i++)
			if (pmd[i]) {
				u64 nvaddr = p->vaddr + (i << page_shift);
				u64 delta_sz = nvaddr - pt->vstart;

				sif_log(sdev, SIF_PT_V, "vstart %llx -> %llx (vsize %llx -> %llx)",
					pt->vstart, nvaddr, pt->vsize, pt->vsize - delta_sz);
				pt->vsize -= delta_sz;
				return nvaddr;
			}
	}
	pt->vsize = 0;
	pt->vstart = 0;
	return 0;
}

static u64 recalc_size(struct sif_pt *pt)
{
	struct sif_dev *sdev = pt->sdev;
	struct sif_pt_page *p = last_page(pt, pt->leaf_level);
	u64 page_shift = level_to_pageshift(pt, pt->leaf_level - 1);
	int i;

	if (p) {
		u64 *pmd = sg_virt(p->page);

		for (i = sdev->mi.ptes_per_page - 1; i >= 0; i--)
			if (pmd[i]) {
				u64 nend = p->vaddr + ((i+1) << page_shift);
				u64 nvsize = nend - pt->vstart;

				sif_log(sdev, SIF_MMU_V, "vstart at %llx, size %llx -> %llx",
					pt->vstart, pt->vsize, nvsize);
				return nvsize;
			}
	}
	pt->vsize = 0;
	pt->vstart = 0;
	return 0;
}



/* Extend a page table at DMA address @vstart with the list starting at @sg with size @size */
int sif_pt_extend(struct sif_pt *pt, struct scatterlist *sg, u64 vstart, size_t size)
{
	int ret = 0;
	u32 npages;
	u64 page_mask = level_to_pagesize(pt, pt->leaf_level - 1) - 1;
	u64 new_start;
	u64 new_size;

	if (!size)
		return 0;

	sif_log(pt->sdev, SIF_MMU, "** vstart %llx size %lx page size %llx leaf_level %d **",
		vstart, size, page_mask + 1, pt->leaf_level);
	mutex_lock(&pt->lock);

	/* Calculate a good size of each sg table in the kmem object: */
	if (!pt->top) {
		/* This is a blank pt - allocate and set up the initial structures */
		npages = table_mem_need(pt, vstart, size);

		ret = init_top(pt, vstart, npages);
		if (ret)
			goto kmem_ext_failed;

		new_start = vstart;
		new_size = size;
	} else if (pt->vsize == 0) {
		new_start = vstart;
		new_size = size;
		reinit_top(pt, vstart);
	} else {
		if (!pt->modifiable) {
			sif_log(pt->sdev, SIF_INFO, "error: Attempt to modify an unmodifiable page table");
			return -EINVAL;
		}
		new_start = merge_ranges(pt->vstart, pt->vsize, vstart, size, &new_size);
		sif_log(pt->sdev, SIF_MMU_V, "new_start %llx new_size %llx **",
			new_start, new_size);
	}

	kref_get(&pt->refcnt);

	ret = populate_pt(pt, sg, vstart, size);
	if (ret)
		goto populate_failed;

	/* sync the whole table memory to make sure the changes are reflected:
	 * TBD: Optimize to only sync the parts that have actually been modified.
	 * With this code we will potentially sync a long page freelist as well:
	 */
	dma_sync_sg_for_device(pt->sdev->ib_dev.dma_device, pt->m.sg, pt->m.sg_max, DMA_TO_DEVICE);

	pt->vstart = new_start;
	pt->vsize = new_size;
	mutex_unlock(&pt->lock);
	return ret;
populate_failed:
	kref_put(&pt->refcnt, sif_pt_release);
kmem_ext_failed:
	sif_kmem_free(pt->sdev, &pt->m);
	mutex_unlock(&pt->lock);
	return ret;
}



/* Extend a page table at DMA address @vstart with the contents of @mem */
int sif_pt_extend_with_mem(struct sif_pt *pt, struct sif_mem *mem, u64 vstart)
{
	int ret = 0;
	u32 npages;
	u64 page_mask = level_to_pagesize(pt, pt->leaf_level - 1) - 1;
	u64 new_start;
	u64 new_size;
	size_t size = mem->size;

	if (!size)
		return 0;

	sif_log(pt->sdev, SIF_MMU, "** vstart %llx size %lx page size %llx leaf level %d **",
		vstart, size, page_mask + 1, pt->leaf_level);
	mutex_lock(&pt->lock);

	/* Calculate a good size of each sg table in the kmem object: */
	if (!pt->top) {
		/* This is a blank pt - allocate and set up the initial structures */
		npages = table_mem_need(pt, vstart, size);

		ret = init_top(pt, vstart, npages);
		if (ret)
			goto kmem_ext_failed;

		new_start = vstart;
		new_size = size;
	} else if (!pt->modifiable) {
		sif_log(pt->sdev, SIF_INFO, "error: Attempt to modify an unmodifiable page table");
		return -EINVAL;
	} else if (pt->vsize == 0) {
		new_start = vstart;
		new_size = size;
		reinit_top(pt, vstart);
	} else {
		new_start = merge_ranges(pt->vstart, pt->vsize, vstart, size, &new_size);
		sif_log(pt->sdev, SIF_MMU_V, "new_start %llx new_size %llx **",
			new_start, new_size);
	}

	kref_get(&pt->refcnt);

	ret = populate_pt_from_mem(pt, mem, vstart, false);

	/* sync the whole table memory to make sure the changes are reflected:
	 * TBD: Optimize to only sync the parts that have actually been modified.
	 * With this code we will potentially sync a long page freelist as well:
	 */
	dma_sync_sg_for_device(pt->sdev->ib_dev.dma_device, pt->m.sg, pt->m.sg_max, DMA_TO_DEVICE);

	pt->vstart = new_start;
	pt->vsize = new_size;
	mutex_unlock(&pt->lock);
	return ret;

kmem_ext_failed:
	sif_kmem_free(pt->sdev, &pt->m);
	mutex_unlock(&pt->lock);
	return ret;
}


/* Shrink a page table to no longer contain DMA address start @sg and size @size */
int sif_pt_free_part(struct sif_pt *pt, u64 vstart, size_t size)
{
	struct sif_pt_page *p;
	int level = pt->leaf_level;
	u64 va = vstart & ~level_to_pagemask(pt, level - 1);
	u64 va_up = va & ~level_to_pagemask(pt, level);
	u64 vend = vstart + size;
	u64 page_size;
	int ret = 0;

	sif_log(pt->sdev, SIF_PT_V, "** vstart %llx -> %llx, size %lx **", vstart, va, size);

	page_size = level_to_pagesize(pt, level - 1);
	mutex_lock(&pt->lock);
	p = find_page(pt, level, va_up);
	if (!p) {
		sif_log(pt->sdev, SIF_INFO, "vaddr %llx not found at level %d",
			va_up, level);
		ret = -EINVAL; /* va not mapped */
		goto failed;
	}

	while (va < vend && p) {
		p = remove_page_ref(pt, p, va, level);
		if (!p)
			break;
		if (va < p->vaddr)
			va = p->vaddr;
		else
			va += page_size;
	}
	if (vstart == pt->vstart) {
		pt->vsize -= size;
		pt->vstart += size;
		if (size == pt->vsize)
			pt->vstart = pt->vsize = 0;
		else
			pt->vstart = recalc_vstart(pt);
	}
	if (vend == pt->vstart + pt->vsize) {
		pt->vsize -= size;
		if (size == pt->vsize)
			pt->vstart = pt->vsize = 0;
		else
			pt->vsize = recalc_size(pt);
	}

	/* sync the whole table memory to make sure the changes are reflected:
	 * TBD: Optimize to only sync the parts that have actually been modified.
	 * With this code we will potentially sync a long page freelist as well:
	 */
	dma_sync_sg_for_device(pt->sdev->ib_dev.dma_device, pt->m.sg, pt->m.sg_max, DMA_TO_DEVICE);

	mutex_unlock(&pt->lock);
	return kref_put(&pt->refcnt, sif_pt_release);

failed:
	mutex_unlock(&pt->lock);
	return ret;
}

/* Free remaining mappings */
int sif_pt_free(struct sif_pt *pt)
{
	int ret = 0;

	if (pt->vsize) {
		int ref = atomic_read(&pt->refcnt.refcount);

		if (ref == 2)
			ret = sif_pt_free_part(pt, pt->vstart, pt->vsize);
		else {
			sif_log(pt->sdev, SIF_MMU_V, "failed - vstart %llx, sz %llx, refcnt %d",
				pt->vstart, pt->vsize, ref);
			return -EBUSY;
		}
	}
	if (!ret) {
		sif_log(pt->sdev, SIF_MMU_V, "refcnt %d", atomic_read(&pt->refcnt.refcount) - 1);
		ret = kref_put(&pt->refcnt, sif_pt_release);
		if (!ret)
			return -EBUSY;
		ret = 0;
	}
	return ret;
}



/* Remap the (remappable) page table to be used starting at vstart for the range of mem */
int sif_pt_remap_for_mem(struct sif_pt *pt, struct sif_mem *mem, u32 page_shift,
			u64 vstart)
{
	/* We optimize the case where @vstart is aligned in a way that allows
	 * the page table to be reused directly. For now we just handle the case where
	 * the old and new vaddr and the size is the same, which is the case for RDS,
	 * our main use case for FMR at this stage.
	 * For all other cases, we just do a full cycle of free/extend_with_mem:
	 */
	int ret = 0;

	if (pt->vstart != vstart || pt->vsize != mem->size || pt->page_shift != page_shift) {
		ret = sif_pt_free_part(pt, pt->vstart, pt->vsize);
		if (ret)
			return ret;
		ret = sif_pt_extend_with_mem(pt, mem, vstart);
		return ret;
	}

	sif_log(pt->sdev, SIF_MMU_V, "** vstart %llx size %llx **", vstart, mem->size);
	mutex_lock(&pt->lock);

	/* Fast path: Repopulate ptes directly - all ref.cnts are kept as is: */

	ret = populate_pt_from_mem(pt, mem, vstart, true);

	/* sync the whole table memory to make sure the changes are reflected:
	 * TBD: Optimize to only sync the parts that have actually been modified.
	 * With this code we will potentially sync a long page freelist as well:
	 */
	if (!ret)
		dma_sync_sg_for_device(pt->sdev->ib_dev.dma_device, pt->m.sg, pt->m.sg_max, DMA_TO_DEVICE);
	mutex_unlock(&pt->lock);
	return ret;
}


/* Called from debugfs key file - caller assumes this function will
 * finish the line in the file:
 */
void sif_pt_dfs_print(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	/* First figure out if a pt object exists for this key,
	 * we only care about MR keys here yet:
	 */
	struct sif_pt *pt;
	struct sif_mr *mr = safe_get_sif_mr(sdev, pos);

	pt = mr ? mr->mmu_ctx.pt : NULL;
	if (!pt) {
		seq_puts(s, "\n");
		return;
	}

	seq_printf(s, "  %3d %3d %4lld\n",
		pt->top_level, pt->leaf_level, pt->m.size >> pt->m.page_shift);
}
