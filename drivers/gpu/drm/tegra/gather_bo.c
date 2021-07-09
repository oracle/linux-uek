// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 NVIDIA Corporation */

#include <linux/scatterlist.h>
#include <linux/slab.h>

#include "gather_bo.h"

static struct host1x_bo *gather_bo_get(struct host1x_bo *host_bo)
{
	struct gather_bo *bo = container_of(host_bo, struct gather_bo, base);

	kref_get(&bo->ref);

	return host_bo;
}

static void gather_bo_release(struct kref *ref)
{
	struct gather_bo *bo = container_of(ref, struct gather_bo, ref);

	kfree(bo->gather_data);
	kfree(bo);
}

void gather_bo_put(struct host1x_bo *host_bo)
{
	struct gather_bo *bo = container_of(host_bo, struct gather_bo, base);

	kref_put(&bo->ref, gather_bo_release);
}

static struct sg_table *
gather_bo_pin(struct device *dev, struct host1x_bo *host_bo, dma_addr_t *phys)
{
	struct gather_bo *bo = container_of(host_bo, struct gather_bo, base);
	struct sg_table *sgt;
	int err;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	err = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (err) {
		kfree(sgt);
		return ERR_PTR(err);
	}

	sg_init_one(sgt->sgl, bo->gather_data, bo->gather_data_words*4);

	return sgt;
}

static void gather_bo_unpin(struct device *dev, struct sg_table *sgt)
{
	if (sgt) {
		sg_free_table(sgt);
		kfree(sgt);
	}
}

static void *gather_bo_mmap(struct host1x_bo *host_bo)
{
	struct gather_bo *bo = container_of(host_bo, struct gather_bo, base);

	return bo->gather_data;
}

static void gather_bo_munmap(struct host1x_bo *host_bo, void *addr)
{
}

const struct host1x_bo_ops gather_bo_ops = {
	.get = gather_bo_get,
	.put = gather_bo_put,
	.pin = gather_bo_pin,
	.unpin = gather_bo_unpin,
	.mmap = gather_bo_mmap,
	.munmap = gather_bo_munmap,
};
