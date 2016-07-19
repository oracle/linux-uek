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
 * sif_base.c: Basic hardware setup of SIF
 */
#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_X86
#include <asm/cacheflush.h>
#endif
#include "sif_base.h"
#include "sif_hwi.h"
#include "sif_mmu.h"
#include "sif_dma.h"
#include "psif_hw_csr.h"
#include "sif_epsc.h"
#include "sif_query.h"
#include "sif_defs.h"

/* Pretty printers for debugfs defined here: */
#include "sif_qp.h"
#include "sif_sq.h"
#include "sif_ah.h"
#include "sif_mr.h"
#include "sif_eq.h"
#include "sif_cq.h"

static int sif_init_bitmap(struct sif_table *table);
static void sif_free_bitmap(struct sif_table *table);

#define psif_xrq_sw psif_rq_sw

/* fallback cases for special entries below */
static uint dummy_bw_cb_size = 16383;
static uint dummy_lat_cb_size = 1;

/* Macro for generating parameter values for queues
 * They are all read only after driver load
 */

#define add_qsz_parameter(type, hwtype, initsize) \
uint sif_##type##_size = initsize;\
module_param_named(type##_size, sif_##type##_size, uint, S_IRUGO);\
MODULE_PARM_DESC(type##_size, "Size of the " #type " descriptor table")


/* These are the queue size parameters we support
 *  e.g. for instance qp_size=2048 or ah_size=100
 * (all sizes will be rounded up to a power of two value)
 */
add_qsz_parameter(mr, key, 4194304);
add_qsz_parameter(epsc, epsc_csr_req, 2048);
add_qsz_parameter(qp, qp, 1048576);
add_qsz_parameter(rq, rq_hw, 1048576);
add_qsz_parameter(cq, cq_hw, 524288);
add_qsz_parameter(ah, ah, 262144);
add_qsz_parameter(sq_ring, sq_ring, 262144);
add_qsz_parameter(sq_tvl, sq_tvl, 128);

/* These sizes must be equal to QP size */
#define sif_sq_rspq_size sif_qp_size
#define sif_rqsp_size sif_qp_size
#define sif_atsp_size sif_qp_size

/* These can be set from the command line - no parameter needed */
static uint sif_epsa0_size = 64;
static uint sif_epsa1_size = 64;
static uint sif_epsa2_size = 64;
static uint sif_epsa3_size = 64;

/* This defines how small the smallest (sw) pointers can get.
 * If set to <= 8, 512 sw descriptors will fit in one page.
 * This gives the smallest amount of internal overhead in each software descriptor
 * but will yield a much larger block size which will require a larger amount of
 * entries from both software and hardware descriptors to be reserved for each
 * protection domain:
 */
uint sif_min_extent = 128;
module_param_named(min_extent, sif_min_extent, uint, S_IRUGO);
MODULE_PARM_DESC(min_extent, "The smallest entry size to use for descriptors");

/* These vars defines a minimal value for the number of extra eq entries
 * to allocate. The driver will only update the EQ_SW_INDEX pointer
 * when necessary. Necessary is defined by the absolute requirement that
 * there must at any time be enough space in the event queue to store all possible
 * sets of events occuring simultaenously. During setup, the driver will allocate
 * enough entries to have at least @epsc_eq_headroom extra entries such that EQ_SW_INDEX
 * need not be updated more often than for every @epsc_eq_headroom event:
 */
uint sif_epsc_eq_headroom = 64;
module_param_named(epsc_eq_headroom, sif_epsc_eq_headroom, uint, S_IRUGO);
MODULE_PARM_DESC(epsc_eq_headroom, "Minimal amount of extra headroom in the EPSC event queue");

uint sif_tsu_eq_headroom = 64;
module_param_named(tsu_eq_headroom, sif_tsu_eq_headroom, uint, S_IRUGO);
MODULE_PARM_DESC(tsu_eq_headroom, "Minimal amount of extra headroom in TSU event queue 0");


/* sif_table_layout is a static struct used to organize
 * base pointer size/layout data in a way that allows
 * them to be configured by iteration:
 */

struct sif_table_layout {
	off_t off; /* Off. to corr. psif_base_addr within psif_csr */
	const char *name; /* Corresponding to enum name */
	const char *desc; /* Textual table desc (for logging) */
	uint *e_cnt_ref; /* Driver parameter ref for no.of entries to allocate */
	u32 entry_sz;  /* Real size of entries in this table */
	u32 ext;       /* Actual extent of (stride between) entries in this table */
	sif_dfs_printer dfs_printer; /* entry printing in debugfs */
	enum sif_tab_type xref;  /* -1: No xref, else xref bitmap (read only) */
	bool wr_access;  /* Whether or not PSIF should have write access */
	bool drv_ref;    /* Keep track of driver structs via separate pointer array */
};

/* Composition of static entries into the base_layout table below:
 *
 * This setup defines the memory layout of descriptors and inlined
 * driver data structures.
 *
 * add_layout  :  base layout of descriptors with no inlined struct and no debugfs print
 *  - a version: Include separate array of pointers to driver struct
 * add_x_layout: layout with alternative type to define extent (inlined driver struct)
 *  - p version: provide a printer function for debugfs
 *  - d version: default naming of printer function
 *  - r version: "cross reference" the bitmap of another map - no separate allocation
 */

#define add_xpr_layout(type, ec, _desc, _e_type, _dfs_printer, _xref, _wr_acc, _drv_ref) { \
	.off = offsetof(struct psif_csr_be, base_addr_##type),\
	.name = #type,\
	.desc = _desc,\
	.e_cnt_ref = &sif_##ec##_size,\
	.entry_sz = sizeof(struct _e_type),\
	.ext = roundup_pow_of_two(sizeof(struct _e_type)),\
	.dfs_printer = _dfs_printer,\
	.xref = _xref, \
	.wr_access = _wr_acc, \
	.drv_ref = _drv_ref, \
}

#define add_xp_layout(type, ec, _desc, _e_type, _dfs_printer, _wr_acc) \
	add_xpr_layout(type, ec, _desc, _e_type, _dfs_printer, -1, _wr_acc, false)

#define add_x_layout(type, ec, _desc, _e_type, _wr_acc) \
	add_xp_layout(type, ec, _desc, _e_type, NULL, _wr_acc)

#define add_xd_layout(type, ec, _desc, _e_type, _wr_acc)	\
	add_xp_layout(type, ec, _desc, _e_type, sif_dfs_print_##type, _wr_acc)

#define add_xdr_layout(type, ec, _desc, _e_type, _xref, _wr_acc)	\
	add_xpr_layout(type, ec, _desc, _e_type, sif_dfs_print_##type, _xref, _wr_acc, false)

#define add_layout(type, ec, _desc, _wr_acc) \
	add_x_layout(type, ec, _desc, psif_##type, _wr_acc)

#define add_a_layout(type, ec, _desc, _wr_acc) \
	add_xpr_layout(type, ec, _desc, psif_##type, sif_dfs_print_##type, -1, _wr_acc, true)

#define add_r_layout(type, ec, _desc, _xref, _wr_acc) \
	add_xpr_layout(type, ec, _desc, sif_##type, NULL, _xref, _wr_acc, false)

#define add_d_layout(type, ec, _desc, _wr_acc) \
	add_xp_layout(type, ec, _desc, psif_##type, sif_dfs_print_##type, _wr_acc)

/* For use with eps req */
#define add_e_req_layout(type, _suff) { \
	.off = 0, \
	.name = #type "_csr_req", \
	.desc = "EPS" #_suff " Request queue", \
	.e_cnt_ref = &sif_##type##_size, \
	.entry_sz = sizeof(struct psif_epsc_csr_req),\
	.ext = roundup_pow_of_two(sizeof(struct psif_epsc_csr_req)), \
	.dfs_printer = sif_dfs_print_##type, \
	.xref = -1, \
	.wr_access = false, \
	.drv_ref = false, \
}

/* For use with eps rsp */
#define add_e_rsp_layout(type, _suff) { \
	.off = 0, \
	.name = #type "_csr_rsp", \
	.desc = "EPS" #_suff " Response queue", \
	.e_cnt_ref = &sif_##type##_size, \
	.entry_sz = sizeof(struct psif_epsc_csr_rsp),\
	.ext = roundup_pow_of_two(sizeof(struct psif_epsc_csr_rsp)), \
	.dfs_printer = NULL, \
	.xref = type##_csr_rsp, \
	.wr_access = true,\
	.drv_ref = false,\
}


/* This array is indexed by the sif_tab_type enum
 * NB! If you change anything here (including order)
 * remember to update
 * - enum sif_tab_type in sif_dev.h
 * - define_funcs call list in sif_base.h
 */

static struct sif_table_layout base_layout[] = {
	add_e_req_layout(epsc, C),
	add_e_rsp_layout(epsc, C),
	add_a_layout(key,   mr, "Key validation", false),
	add_xd_layout(qp, qp, "QP descriptor", sif_qp, true),
	add_layout(rqsp, rqsp, "RQ scratch pad", true),
	add_layout(atsp, atsp, "Atomic replay data", true),
	add_xd_layout(ah,    ah, "Address handle", sif_ah, false),
	add_xd_layout(cq_hw, cq, "Compl.desc (hw)", sif_cq, true),
	add_r_layout(cq_sw, cq, "Compl.desc (sw)", cq_hw, false),
	add_xd_layout(rq_hw, rq, "Recv.queue (hw)", sif_rq, true),
	add_r_layout(rq_sw, rq, "Recv.queue (sw)", rq_hw, false),
	add_xdr_layout(sq_hw, qp, "Send queue (hw)", sif_sq, qp, true),
	add_r_layout(sq_sw, qp, "Send queue (sw)", qp, false),
	{
		/* Special handling of the completion block's
		 * special send queue address map - see #944
		 */
		.off = offsetof(struct psif_csr_be, base_addr_sq_cmpl),
		.name = "sq_cmpl",
		.desc = "cq: SQ addr.map",
		.e_cnt_ref = &sif_qp_size,
		.entry_sz = 0, /* Calculated later */
		.ext = 0, /* Calculated later */
		.dfs_printer = sif_dfs_print_sq_cmpl,
		.xref = qp, /* Reference QP to have flat setup (used by dfs only) */
		.wr_access = false,
		.drv_ref = false,
	},
	add_layout(sq_ring, sq_ring, "SQS Ring buffer", true),
	add_layout(sq_tvl, sq_tvl, "SQS Resp.queue TVL", true),
	add_layout(sq_rspq, sq_rspq, "SQS Resp.queue", true),
	{
		/* Special handling of collect buffer entries */
		.off = 0,
		.name = "bw_cb",
		.desc = "High bandwith collect buffer",
		.e_cnt_ref = &dummy_bw_cb_size,
		.entry_sz = sizeof(struct psif_cb),
		.ext = 4096,
		.dfs_printer = NULL,
		.xref = -1,
		.wr_access = false,
		.drv_ref = false,
	},
	{
		/* Special handling of collect buffer entries */
		.off = 0,
		.name = "lat_cb",
		.desc = "Low latency collect buffer",
		.e_cnt_ref = &dummy_lat_cb_size,
		.entry_sz = sizeof(struct psif_cb),
		.ext = 4096,
		.dfs_printer = NULL,
		.xref = -1,
		.wr_access = false,
		.drv_ref = false,
	},
	add_e_req_layout(epsa0, A-0),
	add_e_rsp_layout(epsa0, A-0),
	add_e_req_layout(epsa1, A-1),
	add_e_rsp_layout(epsa1, A-1),
	add_e_req_layout(epsa2, A-2),
	add_e_rsp_layout(epsa2, A-2),
	add_e_req_layout(epsa3, A-3),
	add_e_rsp_layout(epsa3, A-3)
};


const char *sif_table_name(enum sif_tab_type type)
{
	return base_layout[type].name;
}


static bool is_eps_req(enum sif_tab_type type)
{
	switch (type) {
	case epsc_csr_req:
	case epsa0_csr_req:
	case epsa1_csr_req:
	case epsa2_csr_req:
	case epsa3_csr_req:
		return true;
	default:
		break;
	}
	return false;
}


static bool is_eps_rsp(enum sif_tab_type type)
{
	switch (type) {
	case epsc_csr_rsp:
	case epsa0_csr_rsp:
	case epsa1_csr_rsp:
	case epsa2_csr_rsp:
	case epsa3_csr_rsp:
		return true;
	default:
		break;
	}
	return false;
}


sif_dfs_printer sif_table_dfs_printer(enum sif_tab_type type)
{
	/* At this point we have one common implementation: */
	return base_layout[type].dfs_printer;
}


static enum sif_tab_type get_sw_type(enum sif_tab_type type)
{
	switch (type) {
	case cq_hw:
		return cq_sw;
	case rq_hw:
		return rq_sw;
	case qp:
	case sq_hw:
		return sq_sw;
	default:
		break;
	}
	return (enum sif_tab_type)0;
}

static enum sif_tab_type get_hw_type(enum sif_tab_type type)
{
	switch (type) {
	case cq_sw:
		return cq_hw;
	case rq_sw:
		return rq_hw;
	case sq_sw:
		return sq_hw;
	default:
		break;
	}
	return (enum sif_tab_type)0;
}

static bool is_sw_type(enum sif_tab_type type)
{
	switch (type) {
	case cq_sw:
	case rq_sw:
	case sq_sw:
		return true;
	default:
		break;
	}
	return false;
}


/* The user mapped types we need to adjust extent for
 * based on min_extent
 * qp is exempt from this list as it is not mapped to
 * user space although part of two-level alloc:
 */
static bool is_user_mapped_type(enum sif_tab_type type)
{
	switch (type) {
	case cq_sw:
	case rq_sw:
	case sq_sw:
	case cq_hw:
	case rq_hw:
	case sq_hw:
		return true;
	default:
		break;
	}
	return false;
}


static int init_blocks(struct sif_dev *sdev, enum sif_tab_type type)
{
	struct sif_table *tp = &sdev->ba[type];
	enum sif_tab_type sw_type;
	size_t sw_eb; /* sw type's required minimal entries per block */

	if (is_sw_type(type)) {
		/* Pick up block settings from the hw type which has already been initialized */
		enum sif_tab_type hw_type = get_hw_type(type);
		struct sif_table *tph = &sdev->ba[hw_type];

		tp->entry_per_block = tph->entry_per_block;
		tp->block_ext = tph->block_ext;
		tp->block_cnt = tph->block_cnt;
		tp->block = tph->block;
		return 0;
	}

	sw_type = get_sw_type(type);
	/* Only the tables with a software type requires 2-level alloc */
	if (sw_type)
		sw_eb = PAGE_SIZE / base_layout[sw_type].ext;
	else
		return 0;

	if (type == qp) {
		/* Only relate to sq_hw and sq_sw
		 * (which hasn't been setup yet) for block size calc
		 */
		tp->entry_per_block = max(sw_eb, PAGE_SIZE / base_layout[sq_hw].ext);
	} else {
		/* blocks must fill a page of the smallest of the sw and hw pointer */
		tp->entry_per_block = max(sw_eb, PAGE_SIZE / tp->ext_sz);
	}
	tp->block_cnt = tp->entry_cnt / tp->entry_per_block;

	if (tp->entry_per_block > 1) {
		/* Allocate an 8 byte aligned/end aligned room for the local bitmap
		 * right after the block struct:
		 */
		int bitmap_bytes = (((tp->entry_per_block + 7) >> 3) + 7) & ~7;

		sif_log(sdev, SIF_INIT,
			"%s uses two-level alloc: entry_per_block %d, block_cnt %d bitmap_bytes %d",
			sif_table_name(type), tp->entry_per_block, tp->block_cnt,
				bitmap_bytes);

		tp->block_ext = sizeof(struct sif_table_block) + bitmap_bytes;

		if (unlikely(type == sq_hw)) /* Uses QP bitmap */
			tp->block = sdev->ba[qp].block;
		else {
			/* Zero-initialize the block struct - real initialize
			 * upon first allocation
			 */
			tp->block = kzalloc(tp->block_ext * tp->block_cnt, GFP_KERNEL);
		}
		if (!tp->block)
			return -ENOMEM;
	}

	if (tp->alloc_rr) {
		size_t i;
		/* Make sure we start at index 0 for readability + reserve QP 0 */
		for (i = 0; i < tp->block_cnt; i++) {
			struct sif_table_block *b = sif_get_block(tp, i);

			b->last_used = tp->entry_per_block - 1;
		}
	}
	return 0;
}


static void deinit_blocks(struct sif_dev *sdev, enum sif_tab_type type)
{
	struct sif_table *tp = &sdev->ba[type];

	if (tp->block) {
		/* SQ uses QP bitmap and sw types refs the corresponding hw type */
		if (likely(type != sq_hw && !is_sw_type(type)))
			kfree(tp->block);
		tp->block = NULL;
	}
}


/* Set up the memory mapped table type given by @type
 * with SIF based on information in the base_layout table.
 */
int sif_table_init(struct sif_dev *sdev, enum sif_tab_type type)
{
	struct sif_table *tp = &sdev->ba[type];
	int extent;  /* As log2 */
	int ret = 0;
	struct psif_epsc_csr_req req; /* local epsc wr copy */
	struct psif_epsc_csr_rsp resp;
	u64 alloc_sz;
	u32 cfg_sz;

	memset(tp, 0, sizeof(*tp));
	tp->type = type;
	tp->sdev = sdev;
	cfg_sz = (u32)(*base_layout[type].e_cnt_ref);
	if (cfg_sz & 0x80000000 || cfg_sz == 0) {
		sif_log(sdev, SIF_INFO, "%s(%u): table size %#x out of bounds",
			base_layout[type].desc, type, cfg_sz);
		return -EINVAL;
	}

	/* Only 2^n sized number of entries allowed: */
	tp->entry_cnt = roundup_pow_of_two(cfg_sz);
	tp->ext_sz = base_layout[type].ext;
	tp->table_sz = (size_t)tp->ext_sz * tp->entry_cnt;

	/* Set aside room for a sif_epsc_data struct at the end of
	 * the eps completion vectors so they can use the same mmu context in psif:
	 */
	alloc_sz = (is_eps_rsp_tab(type) ?
		tp->table_sz + sizeof(struct sif_epsc_data) + sif_eps_log_size :
		tp->table_sz);

	if (unlikely(type == sq_cmpl))
		sif_sq_cmpl_setup(tp);
	else if (unlikely(is_cb_table(type)))
		sif_cb_table_init(sdev, type);
	else
		sif_alloc_table(tp, alloc_sz);

	if (!tp->mem) {
		sif_log(sdev, SIF_INFO,
			"Failed to allocate 0x%lx bytes of memory for the %s table",
			tp->table_sz, base_layout[type].desc);
		return -ENOMEM;
	}

	extent = order_base_2(tp->ext_sz);

	if (type == ah) /* Address handles can be allocated from intr.context */
		tp->from_interrupt = true;

	/* Allocate descriptors in a round robin fashion */
	tp->alloc_rr = is_cb_table(type) ?
		sif_feature(alloc_cb_round_robin) : !sif_feature(disable_alloc_round_robin);

	/* single level defaults - then check for 2-level setup.. */
	tp->block_cnt = tp->entry_cnt;
	tp->entry_per_block = 1;

	/* Enable one or two-level allocation */
	if (!sif_feature(flat_alloc))
		ret = init_blocks(sdev, type);

	if (ret)
		goto err_init_blocks;

	if (tp->alloc_rr)
		tp->last_used = tp->block_cnt - 1; /* Next will be the first entry */

	sif_log(sdev, SIF_INIT,	"%s(%d): entry cnt %d, entry sz %d, ext sz %d, extent %d, [%s]",
		base_layout[type].desc, type, tp->entry_cnt, base_layout[type].entry_sz, tp->ext_sz,
		extent, (base_layout[type].wr_access ? "writable" : "readonly"));
	sif_log(sdev, SIF_INIT,	" - table sz 0x%lx %s sif_base 0x%llx csr off 0x%lx",
		tp->table_sz, sif_mem_type_str(tp->mem->mem_type),
		tp->sif_base, base_layout[type].off);

	/* If xref is set to something other than -1 it means
	 * this table is not being allocated from individually, and thus
	 * need no bitmap, but rather is implicitly allocated from the referenced
	 * table entry (which must be lower in enum value to ensure that it is
	 * already allocated!)
	 * Also a table that references another this way is not allowed to allocate
	 * any indices..
	 */
	if (base_layout[type].xref != -1)
		tp->bitmap = sdev->ba[base_layout[type].xref].bitmap;
	else if (sif_init_bitmap(tp) != 0) {
		ret = -ENOMEM;
		goto err_init_bitmap;
	}

	spin_lock_init(&tp->lock);

	if (is_cb_table(type))
		return 0; /* No base addr setup for CBs */

	/* Base address setup - inform the EPS */
	memset(&req, 0, sizeof(req));

	if (is_eps_req(type)) {
		/* Both req and rsp gets posted when rsp is set up */
		ret = 0;
	} else if (is_eps_rsp(type)) {
		/* req,rsp and eq setup taken care of here: */
		ret = sif_eps_init(sdev, type);
		if (ret)
			goto err_map_ctx; /* No context mapped in this case */
	} else {
		req.opcode = EPSC_SET_BASEADDR;
		req.u.base_addr.address = tp->sif_base;
		req.u.base_addr.num_entries = tp->entry_cnt;
		req.u.base_addr.extent_log2 = extent;
		ret = sif_map_ctx(sdev, &tp->mmu_ctx, tp->mem,
				tp->sif_base, tp->table_sz,
				base_layout[type].wr_access);
		if (ret) {
			sif_log(sdev, SIF_INFO, "Failed to set up mmu context for %s",
				base_layout[type].desc);
			goto err_map_ctx;
		}
		req.addr = base_layout[type].off;

		/* Fill in the mmu context from sif_map_ctx before submitting to the EPSC */
		req.u.base_addr.mmu_context = tp->mmu_ctx.mctx;

		ret = sif_epsc_wr_poll(sdev, &req, &resp);
		if (ret)
			goto err_epsc_comm;
	}
	return 0;


err_epsc_comm:
	sif_unmap_ctx(sdev, &tp->mmu_ctx);
err_map_ctx:
	if (base_layout[type].xref == -1)
		sif_free_bitmap(tp);
err_init_bitmap:
	deinit_blocks(sdev, type);
err_init_blocks:
	sif_free_table(tp);
	tp->mem = NULL;
	return ret;
}

static void sif_table_deinit(struct sif_dev *sdev, enum sif_tab_type type)
{
	struct sif_table *tp = &sdev->ba[type];

	if (tp->mem) {
		if (is_eps_rsp(type))
			sif_eps_deinit(sdev, type);
		sif_unmap_ctx(sdev, &tp->mmu_ctx);
		if (base_layout[type].xref == -1)
			sif_free_bitmap(tp);
		deinit_blocks(sdev, type);
		sif_free_table(tp);
		tp->mem = NULL;
	}
}


static void sif_base_deinit_partly(struct sif_dev *sdev, int level)
{
	int i;

	for (i = level - 1; i >= 0; i--)
		sif_table_deinit(sdev, i);
}


int sif_base_init(struct sif_dev *sdev)
{
	/* Setting up base registers */
	int ret = 0;
	int i;

	/* extent less than 8 bytes not supported by hw */
	if (sif_min_extent < 8)
		sif_min_extent = 8;
	else
		sif_min_extent = roundup_pow_of_two(sif_min_extent);

	if (!sif_feature(flat_alloc) && sif_min_extent > 2048) {
		sif_log(sdev, SIF_INFO,
			"cap'ing min_extent to 2048 - largest supported with two -level alloc");
		sif_min_extent = 2048;
	}

	/* Update sw table extents with min_extent: */
	for (i = 0; i < sif_tab_init_max; i++)
		if (is_user_mapped_type(i) && base_layout[i].ext < sif_min_extent)
			base_layout[i].ext = sif_min_extent;

	for (i = 0; i < sif_tab_init_max; i++) {
		ret = sif_table_init(sdev, i);
		/* Allow some base address setup calls to fail.
		 * This should allow us to work around some cases very old firmware
		 * just to perform firmware flash upgrade:
		 */
		if (ret) {
			sif_log(sdev, SIF_INFO, "table init failed for the \"%s\" table",
				sif_table_name(i));
			if (i <= epsc_csr_rsp || i == qp || i == key)
				goto bi_failed;
		}
	}

	/* We rely upon 0-initialized table structs for the EPS-A entries as well */
	for (i = sif_tab_init_max; i < sif_tab_max; i++) {
		struct sif_table *tp = &sdev->ba[i];

		memset(tp, 0, sizeof(*tp));
	}

	/* Init complete */
	return 0;

bi_failed:
	sif_base_deinit_partly(sdev, i);
	return ret;
}


void sif_base_deinit(struct sif_dev *sdev)
{
	sif_base_deinit_partly(sdev, sif_tab_max);
}


/* Send a base addr request to a given EPSA with address information for @type */
int sif_table_update(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		enum sif_tab_type type)
{
	int ret;
	struct sif_table *tp = &sdev->ba[type];
	struct psif_epsc_csr_req req; /* local epsc wr copy */
	struct psif_epsc_csr_rsp resp;
	int extent = order_base_2(tp->ext_sz);

	/* GVA2GPA not supported by EPSes in rev2: */
	if (PSIF_REVISION(sdev) <= 2 && tp->mem->mem_type != SIFMT_BYPASS)
		return -EOPNOTSUPP;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_SET_BASEADDR;
	req.u.base_addr.address = tp->sif_base;
	req.u.base_addr.num_entries = tp->entry_cnt;
	req.u.base_addr.extent_log2 = extent;
	req.u.base_addr.mmu_context = tp->mmu_ctx.mctx;
	req.addr = base_layout[type].off; /* This is the type of request */

	ret = sif_eps_wr(sdev, eps_num, &req, &resp);
	return ret;
}


/* Write an invalidate request to the pqp.
 * using the given modes. Note that if @lcqe is set, wr_mode must be
 * set to PCM_WAIT, to avoid the cqe from living beyond it's caller's scope!
 */
int sif_write_invalidate(struct sif_pqp *pqp, enum sif_tab_type type, int index,
			struct sif_cqe *lcqe, enum wr_mode wr_mode, enum post_mode p_mode)
{
	struct psif_wr wr;
	enum psif_wr_type inv_op;
	int ncompleted;
	u32 sq_entry_idx;
	int pqp_sq_idx;
	struct sif_sq *sq;
	struct psif_cq_entry *cqe;
	bool self_destruct;
	bool dyn_lcqe = false;
	struct sif_dev *sdev = to_sdev(pqp->qp->ibqp.device);

	self_destruct = (type == cq_hw) && (index == pqp->cq->index);

	/* Figure out if an invalidate request is necessary */
	inv_op = sif_invalidate_opcode(type);
	BUG_ON(inv_op == -1);
	BUG_ON(lcqe && wr_mode != PCM_WAIT);
	if (inv_op == -1)
		return -ENODEV;

	sif_log(sdev, SIF_PQP, "sending inv.req. type %s (0x%x) target queue index %d",
		sif_table_name(type), inv_op, index);

	memset(&wr, 0, sizeof(struct psif_wr));
	/* For this table type we need to send an explicit
	 * invalidate work request
	 */
	wr.op = inv_op;
	switch (inv_op) {
	case PSIF_WR_INVALIDATE_RKEY:
	case PSIF_WR_INVALIDATE_LKEY:
	case PSIF_WR_INVALIDATE_BOTH_KEYS:
		wr.details.su.key = index;
		break;
	case PSIF_WR_INVALIDATE_RQ:
		wr.details.su.u2.rq_id = index;
		break;
	case PSIF_WR_INVALIDATE_XRCSRQ:
		wr.details.su.u2.xrq_id = index;
		break;
	case PSIF_WR_INVALIDATE_CQ:
		wr.details.su.u2.cq_id = index;
		break;
	case PSIF_WR_INVALIDATE_SGL_CACHE:
		wr.details.su.u2.target_qp = index;
		break;
	default:
		/* Should never get here */
		return -ENODEV;
	}

	if (self_destruct) {
		/* A self destruct does not receive any completion
		 * instead we must poll for descriptor write-back
		 */
		int ret = 0;
		int sts = sif_pqp_post_send(sdev, &wr, NULL);

		if (sts) {
			sif_log(sdev, SIF_INFO,
				"Posted self-destruct request on cq %d failed, sts %d",
				index, sts);
		}

		sif_log(sdev, SIF_INFO_V, "Posted self-destruct request on cq %d", index);
		ret = poll_wait_for_cq_writeback(sdev, pqp->cq);
		return ret;
	}

	if (wr_mode != PCM_WAIT) {
		int sts;

		wr.completion = (wr_mode == PCM_POST) ? 0 : 1;
		sts = sif_pqp_write_send(pqp, &wr, NULL, p_mode);
		if (sts != -EAGAIN)
			return sts;
		/* In the EAGAIN case, post a new (synchronous) request with completion
		 * to be able to use the quota beyond lowpri_lim.
		 * Note that here lcqe is NULL so we need to dynamically allocate and initialize
		 * one:
		 */
		BUG_ON(lcqe);
		sif_log(sdev, SIF_INFO_V, "pqp %d: async post made sync due to almost full PQP",
			index);
		lcqe = kzalloc(sizeof(*lcqe), GFP_KERNEL);
		if (!lcqe)
			return -ENOMEM;
		/* See DECLARE_SIF_CQE_POLL */
		lcqe->cqe.status = PSIF_WC_STATUS_FIELD_MAX;
		lcqe->pqp = get_pqp(sdev);
		dyn_lcqe = true;
	}

	wr.completion = 1;
	ncompleted = sif_pqp_poll_wr(sdev, &wr, lcqe);

	if (ncompleted < 0) {
		sif_log(sdev, SIF_INFO, "pqp request failed with errno %d", ncompleted);
		return ncompleted;
	}

	if (dyn_lcqe) {
		kfree(lcqe);
		return 0;
	}

	/* Note that we operate on 3 different indices here! */
	cqe = &lcqe->cqe;
	pqp_sq_idx = pqp->qp->qp_idx;
	sq = get_sif_sq(sdev, pqp_sq_idx);

	/* sq_id.sq_seq_num contains the send queue sequence number for this completion
	 * and by this driver's definition the index into the send queue will
	 * be this number modulo the length of the send queue:
	 */
	sq_entry_idx = cqe->wc_id.sq_id.sq_seq_num & sq->mask;

	if (cqe->status != PSIF_WC_STATUS_SUCCESS) {
		sif_log(sdev, SIF_INFO,	"failed with status %s(%d) for cq_seq %d",
			string_enum_psif_wc_status(cqe->status), cqe->status, cqe->seq_num);
		sif_logs(SIF_INFO, write_struct_psif_cq_entry(NULL, 0, cqe));
		atomic_inc(&pqp->cq->error_cnt);
		return -EIO;
	}

	sif_log(sdev, SIF_PQP, "cq_seq %d sq_seq %d, sq_entry_idx %d",
		cqe->seq_num, cqe->wc_id.sq_id.sq_seq_num, sq_entry_idx);

	return ncompleted < 0 ? ncompleted : 0;
}

int sif_invalidate(struct sif_dev *sdev, enum sif_tab_type type, int index,
		enum wr_mode wr_mode)
{
	struct sif_cqe *cqe = NULL;
	DECLARE_SIF_CQE_POLL(sdev, lcqe);
	struct sif_pqp *pqp = lcqe.pqp;

	if (unlikely(!pqp))
		return 0; /* Failed before any PQPs were set up */

	if (wr_mode == PCM_WAIT)
		cqe = &lcqe;
	return sif_write_invalidate(pqp, type, index, cqe, wr_mode, PM_CB);
}

#define table_lock(table, flags) \
	do {\
		if (unlikely(table->from_interrupt))	\
			spin_lock_irqsave(&table->lock, flags); \
		else						\
			spin_lock(&table->lock); \
	} while (0)


#define table_unlock(table, flags) \
	do {				     \
		if (unlikely(table->from_interrupt))	     \
			spin_unlock_irqrestore(&table->lock, flags);	\
		else	\
			spin_unlock(&table->lock);	\
	} while (0)


/* 1st level bitmap index allocation scheme */
static int sif_init_bitmap(struct sif_table *table)
{
	/* Allocate 1 bit for each block of entries */
	size_t bsz = max(sizeof(ulong), table->block_cnt / sizeof(ulong));

	if (bsz > SIF_MAX_CONT)
		table->bitmap = vzalloc(bsz);
	else
		table->bitmap = kzalloc(bsz, GFP_KERNEL);
	if (!table->bitmap) {
		sif_log0(SIF_INIT,
			 "Failed to allocate 0x%lx bytes of alloc.bitmap", bsz);
		return -ENOMEM;
	}
	return 0;
}

int sif_alloc_index(struct sif_dev *sdev, enum sif_tab_type type)
{
	int index;
	int next = 0;
	struct sif_table *table = &sdev->ba[type];
	unsigned long flags = 0;

	table_lock(table, flags);
	if (table->alloc_rr)
		next = (table->last_used + 1) & (table->block_cnt - 1);

	index = find_next_zero_bit(table->bitmap, table->block_cnt, next);
	if (table->alloc_rr && index >= table->block_cnt)
		index = find_next_zero_bit(table->bitmap, table->block_cnt, 0);
	if (index < table->block_cnt) {
		set_bit(index, table->bitmap);
		if (table->alloc_rr)
			table->last_used = index;
	} else
		index = -1;
	table_unlock(table, flags);
	sif_log(sdev, SIF_IDX, "%s[%d] (entries per block %d)", sif_table_name(type), index,
		table->entry_per_block);
	return index;
}

void sif_free_index(struct sif_dev *sdev, enum sif_tab_type type, int index)
{
	struct sif_table *table = &sdev->ba[type];
	size_t ext_sz = table->ext_sz;
	char *desc = sif_mem_kaddr(table->mem, index * ext_sz);
	unsigned long flags = 0;

	if (!test_bit(index, table->bitmap)) {
		/* This should not happen - inconsistency somewhere */
		sif_log(sdev, SIF_INFO, "XZW: index %d, table type %d/%d was not marked as used!",
			index, type, sif_tab_init_max);
		BUG();
		return;
	}


	if (table->entry_per_block == 1) {
		/* Clean descriptor entry for reuse:
		 * note that we clean the whole extent here which
		 * includes all of sif_##type for inlined types:
		 */
		if (table->type == rq_hw) /* only zero out driver data structure */
			memset(desc + sizeof(struct psif_rq_hw), 0, ext_sz - sizeof(struct psif_rq_hw));
		else if (!is_cb_table(table->type) && table->type != qp && table->type != cq_hw)
			memset(desc, 0, ext_sz);
	}

	table_lock(table, flags);
	clear_bit(index, table->bitmap);
	table_unlock(table, flags);
	sif_log(sdev, SIF_IDX, "%s[%d]", sif_table_name(type), index);
}


bool sif_index_used(struct sif_table *table, int index)
{
	if (unlikely(index < 0 || index >= table->entry_cnt))
		return NULL;
	return test_bit(index, table->bitmap);
}


u32 sif_entries_used(struct sif_table *table)
{
	int bits_used = 0;
	int i = 0;
	unsigned long flags = 0;

	table_lock(table, flags);
	if (table->entry_per_block == 1)
		bits_used = bitmap_weight(table->bitmap, table->block_cnt);
	else
		for (;;) {
			i = sif_next_used(table, i);
			if (i < 0)
				break;
			bits_used++;
			i++;
		}

	table_unlock(table, flags);
	return bits_used;
}

static void sif_free_bitmap(struct sif_table *table)
{
	if (table->bitmap) {
		size_t bsz = table->block_cnt / sizeof(ulong);

		if (bsz > SIF_MAX_CONT)
			vfree(table->bitmap);
		else
			kfree(table->bitmap);
		table->bitmap = NULL;
	}
}


/* This function is used to traverse tables for the debugfs file system.
 * @index is the descriptor index (not block index) so in case of
 * two-level allocation (table->entry_per_block > 1)
 * a two-level traversal is needed here:
 */
int sif_next_used(struct sif_table *table, int index)
{
	ulong *map = NULL;
	int blk_idx, new_blk_idx, epb, old_idx;
	struct sif_table_block *b;

	/* This is a queue - no bitmap */
	if (unlikely(table->type == epsc_csr_req))
		return sif_eps_next_used(table, index);

	/* TBD: Quick hack for now - the bitmap reference stuff does not work
	 * properly with two-level alloc:
	 */
	if (unlikely(table->type == sq_cmpl))
		table = &table->sdev->ba[qp];

	map = table->bitmap;
	if (!map)
		return -1;

	if (table->entry_per_block == 1) {
		index = find_next_bit(map, table->block_cnt, index);
		if (index < table->block_cnt)
			return index;
		else
			return -1;
	}
	old_idx = index;

	/* Two level allocation */
	epb = table->entry_per_block;
	blk_idx = index / epb;
next_block:
	index = index % epb;
	new_blk_idx = find_next_bit(map, table->block_cnt, blk_idx);
	if (new_blk_idx >= table->block_cnt)
		return -1;
	if (new_blk_idx != blk_idx)
		index = 0;

	b = sif_get_block(table, new_blk_idx);
	index =  find_next_bit(b->bitmap, epb, index);
	if (index >= epb) {
		blk_idx++;
		goto next_block;
	}
	index += b->offset;
	return index;
}

static int sif_alloc_sg_table(struct sif_table *tp, size_t size)
{
	struct sif_dev *sdev = tp->sdev;
	size_t sg_size = size >> PMD_SHIFT;
	enum sif_mem_type memtype = sif_feature(no_huge_pages) ? SIFMT_4K : SIFMT_2M;

	tp->mem = sif_mem_create(sdev, sg_size, size, memtype,
				GFP_KERNEL, DMA_BIDIRECTIONAL);
	if (!tp->mem)
		return -ENOMEM;
	return 0;
}

int sif_alloc_table(struct sif_table *tp, size_t size)
{
	struct sif_dev *sdev = tp->sdev;
	int ret;

	/* TBD: handle eqs in a better way */
	if (!tp->is_eq && base_layout[tp->type].drv_ref) {
		size_t ref_tbl_sz = sizeof(void *) *  tp->entry_cnt;

		tp->drv_ref = vzalloc(ref_tbl_sz);
		if (!tp->drv_ref) {
			sif_log(sdev, SIF_INFO, "unable to allocate %ld bytes of ref.table for table %s",
				ref_tbl_sz, sif_table_name(tp->type));
			return -ENOMEM;
		}
	}

	/* The sqs ring buffer must be phys.cont to avoid PCIe deadlocks (#3477)
	 * and do not need to be zero initialized, its written by HW and read by HW
	 */
	if (size <= SIF_MAX_CONT || (tp->type == sq_ring && !tp->is_eq)) {
		gfp_t flags = GFP_KERNEL;

		if (tp->type != sq_ring)
			flags |= __GFP_ZERO;

		tp->mem = sif_mem_create_dmacont(sdev, size, flags, DMA_BIDIRECTIONAL);
		if (!tp->mem) {
			ret = -ENOMEM;
			goto t_alloc_failed;
		}
		tp->sif_base = sif_mem_dma(tp->mem, 0);
		if (tp->type == sq_ring) {
			/* Avoid deadlocks on PCIe (#3484) */
			tp->mmu_ctx.mctx.ro = 1;
			tp->mmu_ctx.mctx.ns = 1;

			/*
			 * BZ #3618: Make sure no dirty cache lines
			 * exists, which might be flushed out and
			 * overwrite the ring-buffer, after it has
			 * been written by PSIF
			 */
#ifdef CONFIG_X86
			clflush_cache_range(tp->mem->vmap_base, size);
#else
			sif_log(sdev, SIF_INFO, "Warning: implement flush cache for this architecture");
#endif
		}
		return 0;
	}

	ret = sif_alloc_sg_table(tp, size);
	if (ret)
		goto t_alloc_failed;

	/* Use some easily identifiable (nonzero) high virtual address range on the sif side */
	tp->sif_base = tp->is_eq ?
		SIF_BASE_ADDR_EQ_START(tp->index) :
		SIF_BASE_ADDR_START(tp->type);
	return 0;

t_alloc_failed:
	if (tp->drv_ref) {
		vfree(tp->drv_ref);
		tp->drv_ref = NULL;
	}
	return ret;
}


void sif_free_table(struct sif_table *tp)
{
	sif_mem_free(tp->mem);
	tp->mem = NULL;

	if (tp->drv_ref) {
		vfree(tp->drv_ref);
		tp->drv_ref = NULL;
	}
}
