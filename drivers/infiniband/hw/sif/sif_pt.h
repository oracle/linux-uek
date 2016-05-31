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
 * sif_pt.h: SIF (private) page table management.
 *   API for managing a sif specific page table which can be referenced from
 *   multiple MMU contexts.
 */

#ifndef _SIF_PT_H
#define _SIF_PT_H
#include <linux/rbtree.h>
#include <linux/list.h>
#include "sif_mem.h"

struct seq_file;

/* rb_tree entries to track virtual addresses
 * in this page table.
 */
struct sif_pt_page {
	struct rb_node node;		/* Linkage for pt->pmd */
	struct list_head list;		/* Linkage for freelist */
	struct scatterlist *page;	/* Pointer to info on the used page within pt->m */
	struct sif_pt_page *parent;	/* Pointer to the parent page in the page table */
	u64 vaddr;			/* Virtual address mapped by the page table page */
	u32 usecnt;			/* Number of entries in use in the referred pt page */
};


/* Number of page table page levels we support:
 * This level uses 0 = pte pages, 1 = pmd pages, 2 = pud pages, 3 = pgdir pages
 * This equals psif_table_level - 1 as we do not represent the pages themselves.
 *
 * Example: Corresponding page_shift will then eg be 12 (4K pages) for level -1 and 21 (2M)
 * for level 1 for the default x86 case. For Sparc, several level 0 page sizes are
 * supported, which gives multiple alternatives for the lowest level.
 */
#define PT_LEVELS 4

/* Lower bits with special meaning
 * from the Intel page table spec
 */
#define PT_PAGE_PRESENT	0x1 /* Page is present */
#define PT_PAGE_PS     0x80 /* If set (at level >= 0) page is a leaf pointer even at level > 0 */
#define PT_PAGE_SHIFT    12 /* Number of insignificant bits in a sif page table pointer */

/* SIF driver representation of a generic
 * driver maintained page table.
 *
 * Note that the base leaf page size is
 * based on the "theoretical" smallest page, eg with 2M pages it will be 4K = shift 12.
 * Whether that size is actually used is then determined by leaf_level.
 */
struct sif_pt {
	struct sif_dev *sdev;	/* Device this mapping is valid for */
	bool fixed_top;         /* If set, pt guarantees that the top node remains constant */
	bool modifiable;	/* Set if this page table should support modification */
	u8 top_level;		/* Page table level of top node, 0 means no table */
	u8 leaf_level;		/* Page table level of leaf node */
	u8 pte_ext_shift;	/* Only populate every (1 << pte_ext_shift) pte */
	u16 ptes_per_page;	/* #ptes per page table page - also defines size of the pt page */
	u32 page_shift;		/* Base leaf page shift in use for this table */
	u64 vstart;		/* Start of the mapping in VA as seen from SIF */
	u64 vsize;		/* Extent of the mapping (including any holes) */
	struct sif_pt_page *top;/* Top level page table page exposed to sif */
	struct mutex lock;	/* Protects modifications to the page table data structure */
	struct kref refcnt;	/* Keep track of users of this page table */
	struct sif_kmem m;	/* DMA mapped store for page table memory */
	struct rb_root pmd[PT_LEVELS];/* Pr.level lookup table from offset to page table page */
	struct list_head freelist; /* list of DMA mapped pt pages not currently in use */
};


/* Called from sif_init/exit to set up/clean up global data structures */
int sif_pt_init(void);
void sif_pt_exit(void);

/* Called from debugfs key file */
void sif_pt_dfs_print(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

/* Create a referenced sif page table object with an empty top level page */
struct sif_pt *sif_pt_create_empty(struct sif_dev *sdev, u64 vstart, enum sif_mem_type map_mt);

/* Create a sif page table object of size @mapsize using memory referenced by @sg
 * with SIF virtual address starting at @vstart, which must be aligned at a page
 * size boundary compatible with page sizes used by the memory type used by the backing store
 * @map_mt. Assuming sg is a valid (possibly chained) scatterlist long enough to provide
 * backing for @mapsize.
 * Set @modifiable to allow the table to be extended and shrinked
 * Set @fixed_top to have pt guarantee that the top node remains constant
 * in which case it will always be a level 4 tree.
 */
struct sif_pt *sif_pt_create(struct sif_dev *sdev, struct scatterlist *sg,
			u64 vstart, size_t mapsize,
			u32 page_shift, bool modifiable, bool fixed_top);

/* Create a sif page table from a mem object:
 * Set @fixed_top to prepare for a table where the top node is fixed:
 * (will always be a level 4 tree)
 */
struct sif_pt *sif_pt_create_for_mem(struct sif_mem *mem, u64 vstart,
				u32 page_shift, bool modifiable, bool fixed_top);

/* Remap the (remappable) page table to be used starting at vstart for the range of mem
 * eg. replace the current mapping with a new one, preserving the top node
 * (but possibly reuse at a different level!)
 */
int sif_pt_remap_for_mem(struct sif_pt *pt, struct sif_mem *mem,
			u32 page_shift, u64 vstart);

/* Extend a page table at DMA address @vstart with the list starting at @sg with size @size */
int sif_pt_extend(struct sif_pt *pt, struct scatterlist *sg, u64 vstart, size_t size);

/* Extend a page table at DMA address @vstart with the contents of @mem */
int sif_pt_extend_with_mem(struct sif_pt *pt, struct sif_mem *mem, u64 vstart);

/* DMA address of root pointer of page table */
dma_addr_t sif_pt_dma_root(struct sif_pt *pt);

/* SIF level of root pointer */
u8 sif_pt_root_table_level(struct sif_pt *pt);

/* Leaf page shift (number of bits within page) of this page table */
u32 sif_pt_page_shift(struct sif_pt *pt);

/* Observe leaf node of page table at @vaddr */
int sif_pt_entry(struct sif_pt *pt, u64 vaddr, dma_addr_t *entry, dma_addr_t *val);

/* free a part of the page table and dereference */
int sif_pt_free_part(struct sif_pt *pt, u64 vstart, size_t size);

/* Free this page table. If more than one reference has been created (using sif_pt_extend)
 * return -EBUSY, e.g. this call can be used parenthetic with sif_pt_create, but not if
 * mapping has been referenced more than once, in which case sif_pt_free_part must be called
 * with identical start, size as with extend to clean up properly before a final sif_pt_free:
 */
int sif_pt_free(struct sif_pt *pt);

/* Div. utilities: */

/* Find the aligned size of a region within a certain page alignment size
 * (eg. the number of pages of size @alignment needed to address (start,len))
 */
u64 aligned_size(u64 start, u64 len, u64 alignment);

/* Find the optimal page size (represented by leaf level)
 * to use based on device capabilities, configuration and a max_shift
 * value (typically based on continuousness of memory:
 * The result is adjusted with the address pair of a corresponding virtual
 * address and dma address to ensure that it is possible to create a mapping at that
 * level. pte_extent is set to the number bits to shift increment between
 * each valid pte (For the odd sized leaf pages)
 */
int find_optimal_leaf_level(struct sif_dev *sdev, u32 max_shift,
			u64 vaddr, u64 dma_addr, u64 size,
			u8 *leaf_level,	u8 *pte_ext_shift);

#endif
