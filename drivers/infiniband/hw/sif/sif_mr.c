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
 * sif_mr.c: Implementation of memory regions support for SIF
 */

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>

#include "sif_dev.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include "sif_defs.h"
#include "sif_base.h"
#include "sif_mr.h"
#include "sif_pd.h"
#include "sif_mmu.h"
#include "sif_pt.h"
#include "sif_user.h"
#include <linux/seq_file.h>
#include "sif_user.h"

struct sif_mr *sif_alloc_invalid_mr(struct sif_pd *pd)
{
	struct sif_dev *sdev = to_sdev(pd->ibpd.device);
	u64 bad_addr = (~0ull) ^ (PAGE_SIZE-1);
	struct sif_mem *mem =
		sif_mem_create_ref(sdev, SIFMT_NOMEM, bad_addr, 0, GFP_KERNEL);
	if (!mem)
		return ERR_PTR(-ENOMEM);

	return alloc_mr(sdev, pd, mem, 0, 0);
}

struct sif_mr *create_dma_mr(struct sif_pd *pd, int acc_fl)
{
	/* Use a common MR (in bypass mode)
	 * covering the whole memory space (for each pd which needs it)
	 */
	struct sif_dev *sdev = to_sdev(pd->ibpd.device);
	struct sif_mr *mr;
	struct sif_mem *mem =
		sif_mem_create_ref(sdev, SIFMT_NOMEM, 0ull, (~0ull) ^ (PAGE_SIZE-1), GFP_KERNEL);
	if (!mem)
		return ERR_PTR(-ENOMEM);

	mr = alloc_mr(sdev, pd, mem, 0, acc_fl);
	if (IS_ERR(mr))
		goto alloc_mr_failed;
	return mr;

alloc_mr_failed:
	sif_mem_free(mem);
	return mr;
}


struct ib_mr *sif_get_dma_mr(struct ib_pd *ibpd, int acc_fl)
{
	struct sif_mr *mr = create_dma_mr(to_spd(ibpd), acc_fl);

	return mr ? &mr->ibmr : NULL;
}


struct ib_mr *sif_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
			      u64 virt_addr, int acc_fl,
			      struct ib_udata *udata)
{
	enum sif_mem_type mem_type = SIFMT_UMEM;
	struct sif_dev *sdev = to_sdev(ibpd->device);
	struct sif_mr *mr;
	void *ret;
	struct ib_umem *umem;
	struct sif_mem *mem;
	ulong user_flags = 0;
	u64 map_length = 0;
	u64 phys_length = 0;
	u64 umem_length = length;
	enum dma_data_direction dma_dir = DMA_BIDIRECTIONAL;
	DEFINE_DMA_ATTRS(attrs);

	if (udata) {
		struct sif_reg_mr_ext cmd;
		int rv;

		rv = ib_copy_from_udata(&cmd, udata, sizeof(cmd));
		if (rv)
			return ERR_PTR(-EFAULT);
		user_flags = cmd.flags;
		if (sif_vendor_enable(MMU_special, user_flags)) {
			mem_type =
				sdev->mt_override == SIFMT_UMEM ? cmd.mem_type : sdev->mt_override;
			map_length = cmd.map_length;
			phys_length = cmd.phys_length;
			if (mem_type == SIFMT_BYPASS_RO || mem_type == SIFMT_UMEM_RO)
				dma_dir = DMA_TO_DEVICE;
			if (mem_type == SIFMT_CS)
				umem_length = phys_length;
		}
	}

	sif_log(sdev, SIF_MR, "start 0x%llx len 0x%llx virt_addr 0x%llx flags 0x%lx",
		start, length, virt_addr, user_flags);

	/* Pin user memory */
	umem = ib_umem_get_attrs(ibpd->uobject->context, start, umem_length, acc_fl,
				dma_dir, &attrs);

	if (IS_ERR(umem)) {
		int ev = PTR_ERR(umem);

		ret = (void *)umem;
		sif_log(sdev, SIF_MR,
			"#### Failed to get umem [err %d] (start %llx length %llx vaddr %llx, udata at %p)",
			ev, start, length, virt_addr, udata);
		return ret;
	}

	if (map_length) {
		if (map_length < length) {
			sif_log(sdev, SIF_INFO, "illegal map_length 0x%llx - must be > length 0x%llx",
				map_length, length);
			return ERR_PTR(-EINVAL);
		}
		length = map_length;
	}

	mem = sif_mem_create_umem(sdev, umem, mem_type, GFP_KERNEL, dma_dir);
	if (!mem) {
		mr = (void *)ERR_PTR(-ENOMEM);
		goto err_create_mem;
	}

	mr = alloc_mr(sdev, to_spd(ibpd), mem, start, acc_fl);
	if (IS_ERR(mr))
		goto err_mmu_ctx;

	if (udata) {
		struct sif_reg_mr_resp_ext resp;
		int rv;

		memset(&resp, 0, sizeof(resp));
		resp.uv2dma = mr->mmu_ctx.uv2dma;
		rv = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (rv) {
			/* Exit here as ib_umem_release is implicit via dealloc_mr */
			dealloc_mr(sdev, mr);
			return ERR_PTR(-EFAULT);
		}
	}

	sif_log(sdev, SIF_MR, "Exit: ibmr 0x%p - uv2dma %lx", &mr->ibmr, mr->mmu_ctx.uv2dma);
	return &mr->ibmr;

err_mmu_ctx:
	sif_mem_free(mem); /* owns and frees the umem as well */
	return (void *)mr;
err_create_mem:
	ib_umem_release(umem);
	return (void *)mr;
}

struct ib_mr *sif_reg_phys_mr(struct ib_pd *ibpd,
			      struct ib_phys_buf *phys_buf_array,
			      int num_phys_buf,
			      int acc_fl, u64 *iova_start)
{
	struct sif_dev *sdev = to_sdev(ibpd->device);
	struct sif_mr *mr;
	struct sif_mem *mem;

	if ((num_phys_buf <= 0) || !phys_buf_array) {
		sif_log(sdev, SIF_INFO, "input error: num_phys_buf 0%x phys_buf_array %p",
			num_phys_buf, phys_buf_array);
		mr = ERR_PTR(-EINVAL);
		goto param_err;
	}

	sif_log(sdev, SIF_MR, " num_phys_buf %d, flags 0x%x, iova_start %p",
		num_phys_buf, acc_fl, iova_start);

	mem = sif_mem_create_phys(sdev, iova_start, phys_buf_array, num_phys_buf,
				GFP_KERNEL);
	if (!mem) {
		sif_log(sdev, SIF_INFO, "Failed to create mem object (ENOMEM)");
		mr = ERR_PTR(-ENOMEM);
		goto param_err;
	}

	mr = alloc_mr(sdev, to_spd(ibpd), mem, (u64)iova_start, acc_fl);
	if (IS_ERR(mr))
		goto alloc_mr_failed;

	return &mr->ibmr;
alloc_mr_failed:
	sif_mem_free(mem);
param_err:
	return (void *)mr;
}

int sif_rereg_phys_mr(struct ib_mr *ibmr, int mr_rereg_mask,
		      struct ib_pd *ibpd,
		      struct ib_phys_buf *phys_buf_array, int num_phys_buf,
		      int mr_access_flags, u64 *iova_start)
{
	struct sif_dev *sdev = to_sdev(ibpd->device);

	sif_log(sdev, SIF_INFO, "Not implemented");
	return -EOPNOTSUPP;
}



struct sif_mr *alloc_mr(struct sif_dev *sdev, struct sif_pd *pd,
			struct sif_mem *mem, u64 map_start, int acc_fl)
{
	struct sif_mr *mr;
	volatile struct psif_key *key;
	struct psif_key lkey;
	bool write;
	int index;
	int ret = 0;
	u64 length = mem ? mem->size : ((~0ull) ^ (PAGE_SIZE-1));

	index = sif_alloc_key_idx(sdev);
	if (index < 0) {
		sif_log(sdev, SIF_MR, "Failed to allocate key idx");
		ret = -ENOMEM;
		goto err_reg_mr;
	}

	mr = kzalloc(sizeof(struct sif_mr), GFP_KERNEL);
	if (!mr) {
		sif_log(sdev, SIF_MR, "Failed to allocate memory for sif_mr");
		ret = -ENOMEM;
		goto err_mr_alloc;
	}

	memset(mr, 0, sizeof(struct sif_mr));
	memset(&lkey, 0, sizeof(struct psif_key));
	mr->index = index;
	mr->mem = mem;
	set_sif_mr(sdev, index, mr);
	key = get_key(sdev, index);

	if (length) {
		/* MR will always have L/R keys associated with them.*/
		lkey.lkey_state = PSIF_DMA_KEY_VALID;
		lkey.rkey_state = PSIF_DMA_KEY_VALID;
	} else {
		/* Allocation is for a special invalid key */
		lkey.lkey_state = PSIF_DMA_KEY_INVALID;
		lkey.rkey_state = PSIF_DMA_KEY_INVALID;
	}

	/* Access flags */
	lkey.local_access_rd = 1;
	if (acc_fl & IB_ACCESS_LOCAL_WRITE)
		lkey.local_access_wr = 1;
	if (acc_fl & IB_ACCESS_REMOTE_READ)
		lkey.remote_access_rd = 1;
	if (acc_fl & IB_ACCESS_REMOTE_WRITE)
		lkey.remote_access_wr = 1;
	if (acc_fl & IB_ACCESS_REMOTE_ATOMIC)
		lkey.remote_access_atomic = 1;
	/* TBD: IB_ACCESS_MW_BIND (what to do with that?)
	 *  and also conditonal_wr
	 */

	write = (lkey.local_access_wr ? 1:0) || (lkey.remote_access_wr ? 1:0);

	lkey.pd = pd->idx;

	ret = sif_map_ctx(sdev, &mr->mmu_ctx, mem, map_start, length, write);
	if (ret)
		goto err_map_ctx;

	mr->mmu_ctx.lkey = index;
	if (length)
		lkey.base_addr = mr->mmu_ctx.base;
	else
		lkey.base_addr = (u64)-1LL;
	lkey.length = mr->mmu_ctx.size;
	lkey.mmu_context = mr->mmu_ctx.mctx;

	sif_logs(SIF_DUMP, write_struct_psif_key(NULL, 0, &lkey));

	/* Write to HW descriptor */
	copy_conv_to_hw(key, &lkey, sizeof(lkey));

	mr->ibmr.lkey = mr->ibmr.rkey = mr->index;

	sif_log(sdev, SIF_MR, "type %s - key %d (pd %d) - success",
		sif_mem_type_str(mem->mem_type),
		mr->index, pd->idx);
	return mr;
err_map_ctx:
	kfree(mr);
	set_sif_mr(sdev, index, NULL);
err_mr_alloc:
	sif_clear_key(sdev, index);
	sif_free_key_idx(sdev, index);
err_reg_mr:
	sif_log(sdev, SIF_MR, "Exit: failed with status %d", ret);
	return ERR_PTR(ret);
}

/* If the MMU is involved (not pass-through mode)
 * PSIF MR deregistration is asyncronous and five-step (see #2002):
 *  1) Invalidate associated dma validation entry but first
 *     make sure it is in the special MMU_VALID state which does not
 *     allow uses of it from IB but allows it to be used for invalidation
 *     operations. The invalidate req causes a flush of the entry in
 *     VAL's cache.
 *  2) Invalidate MMU context (TLB_INVALIDATE)
 *     This will lead to a fetch of the key again, this time with
 *     state == MMU_VALID.
 *  3) Issue another key invalidate
 *  4) NIL validation entry - make valid = 0
 *  5) Unpin/release memory associated with it
 */

void dealloc_mr(struct sif_dev *sdev, struct sif_mr *mr)
{
	int index = mr->index;
	int sts;
	struct psif_key *key = get_key(sdev, index);
	bool need_5_step = mr->mmu_ctx.type == MMU_GVA2GPA_MODE;

	/* We do not invalidate the invalid key at index 0 */
	bool do_invalidate_key = index != 0 && !sif_feature(disable_invalidate_key);

	if (do_invalidate_key) {
		if (need_5_step) {
			set_psif_key__lkey_state(key, PSIF_DMA_KEY_MMU_VALID);
			set_psif_key__rkey_state(key, PSIF_DMA_KEY_MMU_VALID);
		} else {
			set_psif_key__lkey_state(key, PSIF_DMA_KEY_INVALID);
			set_psif_key__rkey_state(key, PSIF_DMA_KEY_INVALID);
		}

		/* Flush this DMA validation entry */
		sts = sif_invalidate_key(sdev, index, PCM_WAIT);
		if (sts) {
			sif_log(sdev, SIF_INFO,
				"Invalidate key failed");
		}
	}

	/* Invalidate and unmap MMU context */
	sif_unmap_ctx(sdev, &mr->mmu_ctx);

	if (need_5_step && do_invalidate_key) {
		set_psif_key__lkey_state(key, PSIF_DMA_KEY_INVALID);
		set_psif_key__rkey_state(key, PSIF_DMA_KEY_INVALID);

		/* Flush this DMA validation entry - the final operation, must be synchronous: */
		sts = sif_invalidate_key(sdev, index, PCM_WAIT);
		if (sts) {
			sif_log(sdev, SIF_INFO,
				"Invalidate key failed");
		}
	}

	kfree(mr);
	set_sif_mr(sdev, index, NULL);

	if (!sif_feature(disable_invalidate_key)) {
		/* Release memory associated with this key */
		sif_clear_key(sdev, index);
		sif_free_key_idx(sdev, index);
	}
}


void sif_dealloc_mr(struct sif_dev *sdev, struct sif_mr *mr)
{
	struct sif_mem *mem = mr->mem;

	dealloc_mr(sdev, mr);
	sif_mem_free(mem);
}


int sif_dereg_mr(struct ib_mr *ibmr)
{
	struct sif_mr *mr = to_smr(ibmr);
	struct sif_dev *sdev = to_sdev(ibmr->device);
	int index = mr->ibmr.lkey;

	sif_logi(ibmr->device, SIF_MR, "Enter: mr 0x%p key 0x%x", mr,
		 index);

	sif_dealloc_mr(sdev, mr);
	sif_log(sdev, SIF_MR, "Exit: success");
	return 0;
}

/* Line printer for debugfs file */
void sif_dfs_print_key(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	struct psif_key *key;
	struct psif_key lkey;
	const char *typestr;
	char l_state, r_state;

	if (unlikely(pos < 0)) {
		seq_printf(s, "# %61s State %s\n", "", "Page table info");
		seq_printf(s, "# Index %18s %18s %16s   LR   %s\n",
			"Base address(hex)", "Length(hex)", "MMU ctx type", " top leaf pages");
		return;
	}

	key = get_key(sdev, pos);
	copy_conv_to_sw(&lkey, key, sizeof(struct psif_key));
	typestr = string_enum_psif_mmu_translation(lkey.mmu_context.translation_type) + 4;
	l_state = string_enum_psif_dma_vt_key_states(lkey.lkey_state)[13];
	r_state = string_enum_psif_dma_vt_key_states(lkey.rkey_state)[13];

	seq_printf(s, "%7lld %18llx %18llx %16s   %c%c  ", pos, lkey.base_addr, lkey.length,
		typestr, l_state, r_state);
	sif_pt_dfs_print(s, sdev, pos);
}


/* API to allocate/release a key for TLB invalidation only
 * Note that 0 is considered an invalid key!
 */
u32 allocate_invalidate_key(struct sif_mmu_ctx *ctx)
{
	/* This call is only meaningful for contexts with a valid page table: */
	struct sif_dev *sdev = ctx->pt->sdev;
	int index;
	struct psif_key lkey;
	volatile struct psif_key *key;

	index = sif_alloc_key_idx(sdev);
	if (index < 0)
		return 0;

	key = get_key(sdev, index);
	memset(&lkey, 0, sizeof(struct psif_key));
	lkey.lkey_state = PSIF_DMA_KEY_MMU_VALID;
	lkey.rkey_state = PSIF_DMA_KEY_MMU_VALID;
	lkey.base_addr = ctx->base;
	lkey.length = ctx->size;
	lkey.mmu_context = ctx->mctx;

	/* Write to HW descriptor */
	copy_conv_to_hw(key, &lkey, sizeof(lkey));
	return (u32)index;
}

/* Release and invalidate a previously allocated TLB invalidation key */
void release_invalidate_key(struct sif_dev *sdev, u32 index)
{
	int sts;
	struct psif_key *key = get_key(sdev, index);

	set_psif_key__lkey_state(key, PSIF_DMA_KEY_INVALID);
	set_psif_key__rkey_state(key, PSIF_DMA_KEY_INVALID);

	/* Flush this DMA validation entry - we do not really depend on the result
	 * so safe to make it asynchronous:
	 */
	sts = sif_invalidate_key(sdev, index, PCM_POST);
	if (sts)
		sif_log(sdev, SIF_INFO,
			"Invalidate key failed");

	/* Release memory associated with this key */
	sif_clear_key(sdev, index);
	sif_free_key_idx(sdev, index);
}
