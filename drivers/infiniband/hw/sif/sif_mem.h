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
 * sif_mem.h: A common interface for all memory used by
 *  SIF for queue, table and page table management
 */

#ifndef _SIF_MEM_H
#define _SIF_MEM_H
#include <rdma/ib_verbs.h>
#include "sif_user.h"

/* We need to support 4 interfaces to memory; abbreviated umem, fmr,
 * phys and kmem below, to be compatible with the different ways we are called.
 * This is due to be cleaned up in the core IB stack,
 * by allowing the use of scatterlists for all types of s/g memory
 * provided to rdma devices.
 */

/* Allocation of table and queue memory:
 * The Linux buddy allocator should guarantee us lots of up to 4M I/O contiguous
 * memory segments through alloc_pages provided the system has enough memory.
 * Assume that we get at least 4M standalone and any number of (aligned) 2M entries after that
 *
 * This way we allocate contiguous memory and use bypass/passthrough mapping if
 * alloc_sz <= 4M, and revert to GVA2GPA if needs are larger, but allocate in 2M blocks
 * and use PSIF 2M pages for this.
 */

struct ib_umem;
struct sif_dev;

/* Per device memory configuration info
 * embedded in sif_dev:
 */
struct sif_mem_info {
	u8 page_shift;   /* number of bits within the smallest SIF level 0 page (depends on config) */
	u8 level_shift;  /* number of bits to shift to the next level in the page table  */
	u8 max_shift;    /* Highest number of bits within the highest level page */
	u32 ptes_per_page; /* Page table entries per page table page */
	u64 page_size;   /* size of a SIF level 0 page (as configured) */
	u64 page_mask;   /* All bits beyond page_shift set */
};

/* Valid for SIFMT_2M, SIFMT_4K and SIFMT_BYPASS_RO:
 * Represented as a pool of equally sized pages.
 * Allows direct page offset lookup from the kernel side.
 * All pages are the same size.
 * To maintain offset indexes, interior pages cannot be removed.
 * sg_start will be > 0 if there are empty entries at the start, allowing
 * indexes to remain valid if entries are deleted from the head
 */
struct sif_kmem {
	u64 size;	 /* Size of the mapped memory of this kmem */
	u32 page_shift;  /* Represents page size of each scatter element */
	u32 sg_size;     /* Allocated number of (usable!) elements in (each) scatter list */
	u32 sg_start;    /* Current start offset into the sg list */
	u32 sg_max;      /* Last entry in use + 1 (<= sg_size * nlists) */
	u32 nlists;      /* Number of (sg_size+1'd) sg lists linked through sg */
	enum dma_data_direction dir;  /* DMA direction used for dma mapping */
	struct scatterlist *sg; /* Pointer to start of scatterlist array */
	struct scatterlist *last_sg; /* The start of the last list array in the sg list linkage */
};

/* Valid for SIFMT_FMR (when called from ib_map_phys_fmr) */
struct sif_mem_fmr {
	u64 *page_list;  /* Array of dma addresses of buffers */
	u32 page_list_len; /* length of page_list array */
	u32 page_shift;  /* Represents page size of each scatter element */
	u64 max_size;    /* Saved maximal size of the FMR as supplied during creation */
};

/* Valid for SIFMT_PHYS (when called from ib_reg_phys_mr)
 * It is called "phys" but should have been called "dma" as it is used
 * with dma addresses in at least 1 of the 2 use cases in the kernel...
 * not important to support this API, but keep for completeness:
 */
struct sif_mem_phys {
	struct ib_phys_buf *phys_buf;  /* Array of dma address/size pairs of buffers */
	u64 phys_buf_len; /* length of phys_buf array */
};

/* Flag values so far only used by 'flags' in sif_mem_umem: */
enum sif_mem_flags {
	SMF_DMA32 = 0x1    /* Set if this memory is allocated from the DMA32 space */
};

/* Memory types mapped from user space:
 * Valid for SIFMT_UMEM, SIFMT_UMEM_RO, SIFMT_BYPASS:
 */
struct sif_mem_umem {
	struct ib_umem *umem; /* User memory, NULL if this is a kernel bypass mapping */
	struct scatterlist *sg; /* A pointer to a valid scatterlist (user and kernel) */
	u64 start_offset;     /* Stored misalignment according to the scatter element size */
	enum dma_data_direction dir;  /* DMA direction used for dma mapping */
	u32 flags;
	struct scatterlist sg0; /* Inline storage for bypass mode */
};


/* The generic sif s/g memory representation
 *
 */
struct sif_mem {
	struct sif_dev *sdev;
	enum sif_mem_type mem_type; /* Logical type of mapping */
	u16 max_page_shift; /* 0: unknown, >= 0: Largest page size that can be mapped cont. */
	u64 size;         /* Size of mapping */
	void *vmap_base;  /* Kernel address of the start of a vmap cont.mapping, if any */
	union {
		struct sif_mem_umem u;     /* SIFMT_{UMEM*,BYPASS} */
		struct sif_kmem km;        /* SIFMT_{2M,CS,4K} */
		struct sif_mem_fmr fmr;    /* SIFMT_FMR */
		struct sif_mem_phys phys;  /* SIFMT_PHYS */
	} m;
};


/* Initialization of global per device info - called from sif_hwi.c */
void sif_mem_init(struct sif_dev *sdev);

/* API for managing a sif_kmem object */

/* Allocate a memory object of size @size and populate an sg list
 * with it:
 */
int sif_kmem_init(struct sif_dev *sdev, struct sif_kmem *kmem, size_t sg_size, size_t size,
		u32 page_shift, gfp_t flag, enum dma_data_direction dir);

/* sg unmap and free the memory referenced by mem */
void sif_kmem_free(struct sif_dev *sdev, struct sif_kmem *mem);

/* Extend the kmem object with a total size of @size - return sg_index of the first
 * allocated element:
 */
int sif_kmem_extend(struct sif_dev *sdev, struct sif_kmem *kmem,
				size_t size, gfp_t flag);
int sif_kmem_shrink(struct sif_dev *sdev, struct sif_kmem *mem, int sg_idx, size_t size);

/* Find the scatterlist element with index idx within kmem */
struct scatterlist *sif_kmem_find_sg_idx(struct sif_kmem *kmem, u32 idx);

/************************************
 * API for managing different higher level (scatter) memory segment abstractions
 * used by SIF:
 */

/* Set up a sif_mem structure for handling a memory
 * segment of initial size @size.
 */
struct sif_mem *sif_mem_create(struct sif_dev *sdev, size_t sg_size, size_t size,
			enum sif_mem_type mem_type,
			gfp_t flag,
			enum dma_data_direction dir);

/* Create a sif_mem object from an umem object (User level memory)
 * The sif_mem object resumes ownership of the umem:
 */
struct sif_mem *sif_mem_create_umem(struct sif_dev *sdev,
				struct ib_umem *umem,
				enum sif_mem_type mem_type,
				gfp_t flag, enum dma_data_direction dir);

/* Create a sif_mem object from a phys array of length @num_phys
 * The phys array is owned by caller:
 */
struct sif_mem *sif_mem_create_phys(struct sif_dev *sdev, void *iova_start,
				struct ib_phys_buf *phys, int num_phys,
				gfp_t flag);

/* Create a sif_mem object from a memory pointer array of length @num_pages
 * The memory pointer array is owned by caller:
 */
struct sif_mem *sif_mem_create_fmr(struct sif_dev *sdev, size_t size, u32 page_shift,
				gfp_t flag);

/* Create a sif_mem object with no own memory backing - to use for CB, SQ_CMPL and
 * kernel full passthrough cases to have a "shallow" mem object:
 */
struct sif_mem *sif_mem_create_ref(struct sif_dev *sdev, enum sif_mem_type mem_type,
				u64 sif_vaddr, size_t size, gfp_t flag);

/* Create an aligned sif_mem object mapped coherent dma contiguous, suitable for
 * BYPASS mapping (size constraints..)
 */
struct sif_mem *sif_mem_create_dmacont(struct sif_dev *sdev, size_t size, gfp_t flag,
				enum dma_data_direction dir);

/* Free a sif_mem previously created with sif_mem_create */
int sif_mem_free(struct sif_mem *mem);

/* Map a previously created sif_mem ref object from a memory pointer array of length @num_pages
 * The memory pointer array is owned by caller:
 * Returns -ENOMEM if the sif_mem ref object does not have a sufficiently large size.
 */
int sif_mem_map_fmr(struct sif_mem *mem, u64 iova,
		u64 *page_list, int num_pages);

/* Unmap and reset a mem object previously set up with sif_mem_map_fmr */
void sif_mem_unmap_fmr(struct sif_mem *mem);

/* Allocate some (more) memory for this sif_mem
 * Return an s/g index (page offset to the start of that memory
 * or -errval if an error.
 */
int sif_mem_extend(struct sif_mem *mem, size_t size, gfp_t flag);

/* Free a subrange of this memory object starting at @sg_idx and dereference the
 * sif_mem object. Assumes there is no other references to this subrange, and that
 * this subrange corresponds exactly to a prior allocation with either create or extend above
 * returns 0 upon success or a negative errno if failure:
 */
int sif_mem_shrink(struct sif_mem *mem, int sg_idx, size_t size);

/* Returns true if this memory is represented internally by an umem object */
bool sif_mem_has_umem(struct sif_mem *mem);

/* Return the largest page size (represented by page shift bits) usable for this memory */
u32 sif_mem_page_shift(struct sif_mem *mem);

/* Find kernel virtual address at @offset within map */
void *sif_mem_kaddr(struct sif_mem *mem, off_t offset);

/* Find dma address at @offset within map */
dma_addr_t sif_mem_dma(struct sif_mem *mem, off_t offset);

/* If map is continuous, get start of dma mapping
 * otherwise return an error pointer:
 */
dma_addr_t sif_mem_dma_if_cont(struct sif_mem *mem);

/* Return the start of the s/g list for this mem object */
struct scatterlist *sif_mem_get_sgl(struct sif_mem *mem);

/* Map a part of the @mem object given by @offset, @size to the user space
 * vm context given in @vma. The part must be page aligned and page sized:
 */

int sif_mem_vma_map_part(struct sif_mem *mem, struct vm_area_struct *vma,
			off_t start_off, size_t size);

/* Map the memory referenced by @mem to the user space vma */
int sif_mem_vma_map(struct sif_mem *mem, struct vm_area_struct *vma);


/* sif_mem iterator (mainly for the types that do not expose a scatterlist) */
struct sif_mem_iter {
	struct sif_mem *mem;
	union {
		struct {
			int i;  /* Index used by SIFMT_PHYS and SIFMT_FMR */
		} phys;
		struct scatterlist *sg; /* Used by scatterlist based types */
	};
	size_t offset;  /* Current offset within element */
};

int sif_mem_iter_init(struct sif_mem *mem, struct sif_mem_iter *it);
int sif_mem_iter_advance(struct sif_mem_iter *it, u64 incr);
dma_addr_t sif_mem_iter_dma(struct sif_mem_iter *mi);

/* A utility for dumping an sg list to the trace buffer */
void sif_dump_sg(struct scatterlist *sgl);

#endif
