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
 * sif_fmr.c: Implementation of fast memory registration for SIF
 */

#include <rdma/ib_verbs.h>
#include <linux/slab.h>
#include "sif_fmr.h"
#include "sif_dev.h"
#include "sif_defs.h"
#include "sif_mr.h"
#include "sif_base.h"
#include "psif_hw_setget.h"

struct ib_fmr *sif_alloc_fmr(struct ib_pd *ibpd,
			     int mr_access_flags, struct ib_fmr_attr *fmr_attr)
{
	struct sif_dev *sdev = to_sdev(ibpd->device);
	struct sif_pd *pd = to_spd(ibpd);
	struct sif_fmr *fmr = kmalloc(sizeof(struct sif_fmr), GFP_KERNEL);
	struct sif_mem *mem;
	struct ib_fmr *ibfmr;
	void *ret;

	if (!fmr) {
		sif_log(sdev, SIF_INFO, "Unable to allocate memory for the fmr");
		return ERR_PTR(-ENOMEM);
	}

	mem = sif_mem_create_fmr(sdev, fmr_attr->max_pages, fmr_attr->page_shift, GFP_KERNEL);
	if (!mem) {
		ret = ERR_PTR(-ENOMEM);
		goto mem_create_failed;
	}

	memset(fmr, 0, sizeof(struct sif_fmr));
	fmr->mr = alloc_mr(sdev, pd, mem, 0,
			IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE |
			IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC);
	if (IS_ERR(fmr->mr)) {
		ret = fmr->mr;
		goto mr_alloc_failed;
	}

	ibfmr = &fmr->ibfmr;
	ibfmr->lkey = fmr->mr->index;
	ibfmr->rkey = fmr->mr->index;

	sif_log(sdev, SIF_FMR, "max_pages %d, page_shift %d, max_maps %d",
		fmr_attr->max_pages, fmr_attr->page_shift, fmr_attr->max_maps);
	return &fmr->ibfmr;

mr_alloc_failed:
	sif_mem_free(mem);
mem_create_failed:
	kfree(fmr);
	return ret;
}


int sif_map_phys_fmr(struct ib_fmr *ibfmr,
		     u64 *page_list, int list_len, u64 iova)
{
	struct sif_dev *sdev = to_sdev(ibfmr->device);
	struct sif_fmr *fmr = to_sfmr(ibfmr);
	struct sif_mem *mem = fmr->mr->mem;
	int ret = 0;

	if (mem->mem_type != SIFMT_PTONLY) {
		sif_log(sdev, SIF_FMR, "Attempt to map an already mapped fmr - must unmap first");
		ret = sif_unmap_phys_fmr(ibfmr);
		if (ret)
			return ret;
	}

	ret = sif_mem_map_fmr(mem, iova, page_list, list_len);
	if (ret)
		return ret;

	ret = sif_map_fmr_ctx(sdev, &fmr->mr->mmu_ctx, mem);
	return ret;
}


int sif_unmap_phys_fmr(struct ib_fmr *ibfmr)
{
	struct sif_fmr *fmr = to_sfmr(ibfmr);
	struct sif_dev *sdev = to_sdev(ibfmr->device);
	struct sif_mmu_ctx *ctx = &fmr->mr->mmu_ctx;
	int index = fmr->mr->index;
	struct psif_key *key = get_key(sdev, index);

	/* See sif_mr.c for details on invalidation of DMA validation keys */

	/* First set key to a state where memory accesses are invalid: */
	set_psif_key__lkey_state(key, PSIF_DMA_KEY_MMU_VALID);
	set_psif_key__rkey_state(key, PSIF_DMA_KEY_MMU_VALID);
	sif_invalidate_key(sdev, index, PCM_WAIT);

	/* Synchronous TLB invalidation to avoid invalidating the key too early: */
	sif_unmap_fmr_ctx(sdev, ctx, PCM_WAIT);

	/* Invalidate the keys */
	set_psif_key__lkey_state(key, PSIF_DMA_KEY_INVALID);
	set_psif_key__rkey_state(key, PSIF_DMA_KEY_INVALID);
	sif_invalidate_key(sdev, index, PCM_WAIT);

	/* TBD: We could add code here to nil the ptes
	 * for debugging purposes, for now they are left behind..
	 * (can leave stale PTE data behind, but never for pages we allow access to)
	 */

	/* Reset the memory object - remove stale refs to pages
	 * (for sanity checking purposes, could be eliminated)
	 */
	sif_mem_unmap_fmr(fmr->mr->mem);
	return 0;
}


static int invalidate_fmr_key(struct sif_st_pqp *spqp, struct ib_fmr *ibfmr,
		enum psif_dma_vt_key_states state, enum wr_mode mode)
{
	struct sif_fmr *fmr = to_sfmr(ibfmr);
	struct sif_dev *sdev = to_sdev(ibfmr->device);
	int index = fmr->mr->index;
	struct psif_key *key = get_key(sdev, index);

	set_psif_key__lkey_state(key, state);
	set_psif_key__rkey_state(key, state);
	if (spqp)
		return sif_inv_key_update_st(spqp, index, mode);
	else
		return sif_invalidate_key(sdev, index, mode);
}


int sif_unmap_phys_fmr_list(struct list_head *fmr_list)
{
	struct ib_fmr *ib_fmr;
	struct sif_dev *sdev = NULL;
	enum wr_mode mode;
	int ret;
	int cnt = 0;
	bool flush_all = false;
	struct sif_st_pqp *spqp = NULL;
	u16 ms = 0;
	ulong start_time = jiffies;

	if (!list_empty(fmr_list)) {
		ib_fmr = list_first_entry(fmr_list, struct ib_fmr, list);
		sdev = to_sdev(ib_fmr->device);
	} else
		return 0;

	if (!sif_feature(disable_stencil_invalidate)) {
		spqp = sif_alloc_ki_spqp(sdev);
		if (!spqp)
			sif_log(sdev, SIF_PQPT,
				"All %u configured stencil pqps busy, consider increasing ki_spqp_size",
				sdev->ki_spqp.pool_sz);
	}

	/* Check if we should do a brute force whole MMU caches flush */
	list_for_each_entry(ib_fmr, fmr_list, list) {
		cnt++;
		if (cnt >= sif_fmr_cache_flush_threshold) {
			flush_all = true;
			goto key_to_invalid;
		}
	}

	cnt = 0;
	list_for_each_entry(ib_fmr, fmr_list, list) {
		mode = list_is_last(&ib_fmr->list, fmr_list) ? PCM_WAIT
			: (!(cnt & 0x1f) ? PCM_POST_COMPL : PCM_POST);
		ret = invalidate_fmr_key(spqp, ib_fmr, PSIF_DMA_KEY_MMU_VALID, mode);
		if (ret)
			goto out;
		cnt++;
	}
	sif_log(sdev, SIF_FMR, "done with %d invalidates to MMU_VALID", cnt);

	cnt = 0;
	list_for_each_entry(ib_fmr, fmr_list, list) {
		mode = list_is_last(&ib_fmr->list, fmr_list) ? PCM_WAIT
			: (!(cnt & 0x1f) ? PCM_POST_COMPL : PCM_POST);
		sif_unmap_fmr_ctx(to_sdev(ib_fmr->device),
				&(to_sfmr(ib_fmr))->mr->mmu_ctx, mode);
		cnt++;
	}
	sif_log(sdev, SIF_FMR, "done with %d unmap_fmr_ctxs", cnt);
key_to_invalid:
	cnt = 0;

	list_for_each_entry(ib_fmr, fmr_list, list) {
		mode = list_is_last(&ib_fmr->list, fmr_list) ? PCM_WAIT
			: (!(cnt & 0x1f) ? PCM_POST_COMPL : PCM_POST);
		ret = invalidate_fmr_key(spqp, ib_fmr, PSIF_DMA_KEY_INVALID, mode);
		if (ret)
			goto out;
		cnt++;
	}
	sif_log(sdev, SIF_FMR, "done invalidating %d fmr keys%s",
		cnt, (spqp ? " (stencil)" : ""));

	if (flush_all) {
		ret = sif_post_flush_tlb(sdev, true);
		if (ret)
			goto out;
		ret = sif_complete_flush_tlb(sdev);
		if (ret)
			goto out;
	}

	cnt = 0;
	list_for_each_entry(ib_fmr, fmr_list, list) {
		sif_mem_unmap_fmr((to_sfmr(ib_fmr))->mr->mem);
		cnt++;
	}
	ms = jiffies_to_msecs(jiffies - start_time);
	sif_log_rlim(sdev, SIF_PERF_V, "done unmapping %d fmrs in %u ms", cnt, ms);
out:
	if (spqp)
		sif_release_ki_spqp(spqp);

	return ret;
}


int sif_dealloc_fmr(struct ib_fmr *ibfmr)
{
	struct sif_dev *sdev = to_sdev(ibfmr->device);
	struct sif_fmr *fmr = to_sfmr(ibfmr);

	if (fmr->mr->mem->mem_type != SIFMT_PTONLY) {
		sif_log(sdev, SIF_FMR, "Attempt to deallocate a mapped fmr (key %d) - must unmap first",
			fmr->mr->index);
		return -EBUSY;
	}
	sif_dealloc_mr(sdev, fmr->mr);
	kfree(fmr);
	return 0;
}
