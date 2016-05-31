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
 * sif_user.h: This file defines sif specific verbs extension request/response.
 */

#ifndef _SIF_USER_H
#define _SIF_USER_H

/* Binary interface control:
 *   Major version difference indicate backward incompatible changes
 *   Minor version difference indicate that only a common subset of
 *   features are available.
 *
 */
#define SIF_UVERBS_ABI_MAJOR_VERSION    3
#define SIF_UVERBS_ABI_MINOR_VERSION    4

#define SIF_UVERBS_VERSION(x, y) ((x) << 8 | (y))

#define SIF_UVERBS_ABI_VERSION \
	SIF_UVERBS_VERSION(SIF_UVERBS_ABI_MAJOR_VERSION, SIF_UVERBS_ABI_MINOR_VERSION)

/*
 * Bit 5 is not used by the PSIF_WC_OPCODE_FOO_BAR enums. Hence, using
 * it to indicate if QP has been destroyed before the CQE has been
 * polled
 */
#define SIF_WC_QP_DESTROYED (1<<5)

/*
 * This struct will be amended to an un-polled cqe, in case the QP has
 * been destroyed before the CQEs are polled. The information is
 * needed in order to handle flushing of SRQs and generation of Last
 * WQE Reached event.
 *
 * The information amended to the CQE is _only_ valid if the CQE has
 * been marked with SIF_WC_QP_DESTROYED.
 */
struct sif_post_mortem_qp_info_in_cqe {
	bool was_srq;
	int srq_idx;
	int qpn; /* Could be useful for de-bugging/logging */
};


#ifndef _SIF_H
/* These definitions must be kept in sync with
 * the ones in libsif's sif.h
 */
enum sif_vendor_flags {
	MMU_special   =  0x1,   /* Use special mmu setup in associated mappings
				 * NB! Modifies input to ibv_reg_mr!
				 */
	SQ_mode       =  0x2,   /* Trigger send queue mode instead of using VCBs */
	proxy_mode    =  0x4,   /* Enable EPS-A proxying - requires the eps_a field to be set */
	SVF_kernel_mode =  0x8, /* Enable kernel mode - default is direct user mode */
	tsu_qosl      = 0x10,   /* Value to use for the qosl bit in the qp state */
	no_checksum   = 0x20,   /* No csum for qp, wqe.wr.csum = qp.magic */
	dynamic_mtu   = 0x40,   /* dynamic MTU - use 256B instead of the path MTU */
};

enum sif_mem_type {
	SIFMT_BYPASS,    /* Use MMU bypass in associated mmu contexts */
	SIFMT_UMEM,      /* Normal default umem based user level mapping */
	SIFMT_UMEM_SPT,  /* Mapping of user memory based on the process' own page table */
	SIFMT_CS,        /* A large (sparsely populated) SIF only vaddr mapping (used for SQ CMPL) */
	SIFMT_ZERO,      /* Special mapping of a vaddr range to a single page (see #1931) */
	SIFMT_BYPASS_RO, /* MMU bypass mapped read only for device (requires IOMMU enabled) */
	SIFMT_UMEM_RO,   /* GVA2GPA mapped read only for device (requires IOMMU enabled) */
	SIFMT_PHYS,      /* Use GVA2GPA but input is based on a phys_buf array instead of umem */
	SIFMT_FMR,       /* Use GVA2GPA but input is based on a page address array instead of umem */
	SIFMT_2M,        /* sif_kmem based 2M page allocation */
	SIFMT_NOMEM,     /* Bypass mode - special kernel mappings with no memory allocated */
	SIFMT_4K,        /* sif_kmem based 4K page allocation */
	SIFMT_PTONLY,    /* No memory allocated but full page table needed (FMR init) */
	SIFMT_MAX
};

enum sif_proxy_type {
	SIFPX_OFF, /* Default value - no proxying */
	SIFPX_EPSA_1,
	SIFPX_EPSA_2,
	SIFPX_EPSA_3,
	SIFPX_EPSA_4
};

enum sif_flush_type {
	NO_FLUSH,
	FLUSH_SQ,
	FLUSH_RQ
};
#endif

/* These should be multiple of 64 bytes and densely packed: */

struct sif_get_context_ext {
	__u32 abi_version;  /* Let the driver know which version we are */
	__u32 reserved;
};

struct sif_get_context_resp_ext {
	__u32 sq_sw_ext_sz;	   /* Distance in bytes between descriptor elements */
	__u32 rq_ext_sz;
	__u32 cq_ext_sz;
	__u32 sq_entry_per_block;  /* Number of entries per block of descriptors */
	__u32 rq_entry_per_block;
	__u32 cq_entry_per_block;
	__u32 sq_hw_ext_sz;	   /* Dist between sq hw descriptor elms, from >= v.3.3 */
	__u32 reserved;
};

struct sif_alloc_pd_resp_ext {
	__u32 cb_idx;  /* The virtual collect buffer to use by this protection domain */
	__u32 reserved;
};

/* TBD: We must filter this structure before we go upstream */
struct sif_share_pd_resp_ext {
	__u32 cb_idx;  /* The virtual collect buffer to use by this shared protection domain */
	__u32 reserved;
};

struct sif_create_cq_ext {
	enum sif_vendor_flags flags;
	enum sif_proxy_type proxy;
};

struct sif_create_cq_resp_ext {
	__u32 cq_idx;
	__u32 reserved;
};

struct sif_create_qp_ext {
	enum sif_vendor_flags flags;
	enum sif_proxy_type proxy;
};

struct sif_create_qp_resp_ext {
	__u32 qp_idx;
	__u32 rq_idx;
	__u32 magic;
	__u32 sq_extent;
	__u32 rq_extent;
	__u32 sq_sgl_offset;
	__u32 sq_mr_idx;
	__u32 reserved;
	__u64 sq_dma_handle;
};

struct sif_modify_qp_ext {
	enum sif_flush_type flush;
	__u32 reserved;
};

struct sif_reg_mr_ext {
	enum sif_vendor_flags flags;
	enum sif_mem_type mem_type;
	__u64 map_length;  /* Used by gva_type SIFGT_ZERO - indicates psif vmap length */
	__u64 phys_length; /* Used by gva_type SIFGT_ZERO - indicates valid memory length */
};

struct sif_reg_mr_resp_ext {
	__u64 uv2dma;  /* Used to support bypass mode */
};

struct sif_create_srq_ext {
	enum sif_vendor_flags flags;
	__u32 res1;
};

struct sif_create_srq_resp_ext {
	__u32 index;
	__u32 extent;
};

struct sif_create_ah_resp_ext {
	__u32 index;
	__u32 reserved;
};

/* mmap offset encoding */

enum sif_mmap_cmd {
	SIF_MAP_NONE,	/* No mapping */
	SIF_MAP_CB,	/* Map a collect buffer - cb index as argument */
	SIF_MAP_SQ,	/* Map an SQ,RQ or CQ (entries) - queue index as argument */
	SIF_MAP_RQ,
	SIF_MAP_CQ,
	SIF_MAP_SQ_SW,	/* Map a block of SQ,RQ or CQ software descriptors - block index as argument */
	SIF_MAP_RQ_SW,
	SIF_MAP_CQ_SW,
	/* These are safe to map read-only (so far only sq_hw in use) */
	SIF_MAP_QP,	/* Map a block of qp descriptors - block index as argument */
	SIF_MAP_SQ_HW,	/* Map a block of SQ,RQ or CQ hardware descriptors - block index as argument */
	SIF_MAP_RQ_HW,
	SIF_MAP_CQ_HW,
	SIF_MAP_MAX
};


#define SIF_MCMD_SHIFT (PAGE_SHIFT + 32)

static inline __u64 mmap_set_cmd(enum sif_mmap_cmd cmd, __u32 index)
{
	return ((__u64)cmd << SIF_MCMD_SHIFT) | ((__u64)index << PAGE_SHIFT);
}

static inline void mmap_get_cmd(__u64 offset, enum sif_mmap_cmd *cmdp, __u32 *idxp)
{
	*cmdp = (enum sif_mmap_cmd)((offset >> SIF_MCMD_SHIFT) & 0xff);
	*idxp = (offset >> PAGE_SHIFT) & 0xffffffff;
}

#endif
