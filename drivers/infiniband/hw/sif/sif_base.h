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
 * sif_base.h: Basic hardware setup of SIF
 */

#ifndef __SIF_BASE_H
#define __SIF_BASE_H
#include "sif_dev.h"
#include "sif_debug.h"
#include "sif_pd.h"
#include "sif_qp.h"
#include "sif_cq.h"
#include "sif_ah.h"
#include "sif_int_user.h"

/* Establish contact with the EPS and initialize the base descriptor setup */
int sif_base_init(struct sif_dev *sdev);

void sif_base_deinit(struct sif_dev *sdev);

int sif_alloc_index(struct sif_dev *sdev, enum sif_tab_type type);
void sif_free_index(struct sif_dev *sdev, enum sif_tab_type type, int index);
u32 sif_entries_used(struct sif_table *table);

bool sif_index_used(struct sif_table *table, int index);

/* Find next used entry, starting at (and including) index
 */
int sif_next_used(struct sif_table *table, int index);

int sif_invalidate(struct sif_dev *sdev, enum sif_tab_type type, int index, enum wr_mode mode);

int sif_write_invalidate(struct sif_pqp *pqp, enum sif_tab_type type, int index,
			 struct sif_cqe *lcqe, enum wr_mode wr_mode, enum post_mode p_mode);

#define sif_define_funcs(type) \
static inline int sif_invalidate_##type(struct sif_dev *sdev, int index, \
					enum wr_mode mode)\
{ \
		return sif_invalidate(sdev, type, index, mode); \
} \
static inline u32 sif_##type##_usage(struct sif_dev *sdev)\
{\
	return sif_entries_used(&sdev->ba[type]); \
} \
static inline struct psif_##type *get_##type(struct sif_dev *sdev, int index)\
{ \
	return (struct psif_##type *)(sif_mem_kaddr(sdev->ba[type].mem, \
				index * sdev->ba[type].ext_sz)); \
} \
static inline void sif_clear_##type(struct sif_dev *sdev, int index)\
{ \
	struct psif_##type *p = get_##type(sdev, index);\
	memset(p, 0, sizeof(*p));\
}


#define sif_def_pd_index_alloc(type)\
static inline int sif_alloc_##type##_idx(struct sif_pd *pd)\
{ \
	return sif_pd_alloc_index(pd, type);	\
} \
static inline void sif_free_##type##_idx(struct sif_pd *pd, int index)\
{ \
	sif_pd_free_index(pd, type, index);	\
}

#define sif_def_global_index_alloc(type)\
static inline int sif_alloc_##type##_idx(struct sif_dev *sdev)\
{ \
	return sif_alloc_index(sdev, type);	\
} \
static inline void sif_free_##type##_idx(struct sif_dev *sdev, int index)\
{ \
	sif_free_index(sdev, type, index); \
}

const char *sif_table_name(enum sif_tab_type type);

/* Exposed to sif_epsc only! */

/* Set up the table type @type and send a base addr request to the EPSC */
int sif_table_init(struct sif_dev *sdev, enum sif_tab_type type);

/* Send a base addr request to a given EPSA with address information for @type */
int sif_table_update(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		enum sif_tab_type type);

sif_dfs_printer sif_table_dfs_printer(enum sif_tab_type type);

#define psif_bw_cb psif_cb __iomem
#define psif_lat_cb psif_cb __iomem

sif_define_funcs(key)
sif_define_funcs(qp)
sif_define_funcs(cq_hw)
sif_define_funcs(cq_sw)
sif_define_funcs(ah)
sif_define_funcs(rq_sw)
sif_define_funcs(rq_hw)
sif_define_funcs(sq_sw)
sif_define_funcs(sq_hw)
sif_define_funcs(sq_rspq)
sif_define_funcs(bw_cb)
sif_define_funcs(lat_cb)

/* These descriptors use 2-level alloc,
 * 2nd level resource management is done by the protection domain.
 * The purpose of this is that elements that fits within the same page will always be
 * owned by the same protection domain, to avoid that an ill-behaved application
 * may accidentially modify the descriptors of an unrelated application.
 * Changes in allocation levels here must be accompanied by changes in init_blocks
 * in sif_base.c and type changes sdev <-> pd in the index allocation functions.
 */
sif_def_pd_index_alloc(qp)
sif_def_pd_index_alloc(rq_hw)
sif_def_pd_index_alloc(sq_hw)
sif_def_pd_index_alloc(cq_hw)

/* These use global, single level alloc.
 * CBs are unproblematic since they each occupy a full page.
 * The rest is only used from kernel space
 */

sif_def_global_index_alloc(key)
sif_def_global_index_alloc(ah)
sif_def_global_index_alloc(bw_cb)
sif_def_global_index_alloc(lat_cb)

/* Lookup functions for sif structs inlined with hw descs */
#define sif_define_lookup_funcs(type, hwtype)\
static inline struct sif_##type *get_sif_##type(struct sif_dev *sdev, int idx)\
{ \
	return container_of(get_##hwtype(sdev, idx),\
		struct sif_##type, d);\
} \
static inline struct sif_##type *safe_get_sif_##type(struct sif_dev *sdev, int idx)\
{ \
	struct sif_table *tp = &sdev->ba[hwtype];\
	if (unlikely(idx < 0 || idx >= tp->entry_cnt)) \
		return NULL;\
	if (!sif_pd_index_used(tp, idx))\
		return NULL;\
	return get_sif_##type(sdev, idx);\
} \
extern uint sif_##type##_size

sif_define_lookup_funcs(rq, rq_hw);
sif_define_lookup_funcs(rq_sw, rq_sw);
sif_define_lookup_funcs(sq, sq_hw);
sif_define_lookup_funcs(sq_sw, sq_sw);
sif_define_lookup_funcs(cq, cq_hw);
sif_define_lookup_funcs(cq_sw, cq_sw);
sif_define_lookup_funcs(qp, qp);
sif_define_lookup_funcs(ah, ah);

/* Lookup functions for sif structs accessed via the
 * "side-array" table->drv_ref
 */
#define sif_def_ref_lookup_funcs(type, hwtype) \
static inline struct sif_##type *get_sif_##type(struct sif_dev *sdev, int idx) \
{ \
	return ((struct sif_##type **)sdev->ba[hwtype].drv_ref)[idx];	\
} \
static inline void set_sif_##type(struct sif_dev *sdev, int idx, struct sif_##type *v)  \
{ \
	((struct sif_##type **)sdev->ba[hwtype].drv_ref)[idx] = v; \
} \
static inline struct psif_##hwtype *safe_get_##hwtype(struct sif_dev *sdev, int idx)\
{ \
	struct sif_table *tp = &sdev->ba[hwtype];  \
	if (!sif_index_used(tp, idx)) \
		return NULL;\
	return get_##hwtype(sdev, idx);\
} \
static inline struct sif_##type *safe_get_sif_##type(struct sif_dev *sdev, int idx)\
{ \
	struct sif_table *tp = &sdev->ba[hwtype];  \
	if (!sif_index_used(tp, idx)) \
		return NULL;\
	return get_sif_##type(sdev, idx);\
} \
extern uint sif_##type##_size

sif_def_ref_lookup_funcs(mr, key);

static inline struct sif_table_block *sif_get_block(struct sif_table *tp, int index)
{
	return (struct sif_table_block *)(tp->block + tp->block_ext * index);
}

extern uint sif_xrq_size;
extern uint sif_epsc_size;
extern uint sif_epsc_eq_headroom;
extern uint sif_tsu_eq_headroom;
extern uint sif_sq_ring_size;
extern uint sif_sq_tvl_size;
extern uint sif_min_extent;

/* Multi-strategy allocation of table memory */
int sif_alloc_table(struct sif_table *tp, size_t size);

void sif_free_table(struct sif_table *tp);

#endif
