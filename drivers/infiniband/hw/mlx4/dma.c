#include <linux/types.h>
#include <rdma/ib_verbs.h>

#if defined(__sparc__) && defined(__arch64__)
/*
 * sparc platform dma mapping for mlx4
 *
 * sparc platform require weak order dma mapping as default mapping type.
 * only cq must have strict memory dma mapping. most of the ulps just call
 * ib_dma_map_single/sg w/o the needed DMA_ATTR_WEAK_ORDERING attribute.
 * as result the ib performance on sparc platforms is very poor. using the
 * dma mapping callbacks in ib_dma_xxx functions can solve this issue w/o
 * the need to modify all the ulps.
 *
 * we pick the right dma api by the below order:
 * 1. include/asm-generic/dma-mapping-common.h
 * 2. include/linux/dma-mapping.h
 *
 * NOTE! - call to ib_dma_xxx api will cause endless recursion!
 */

static int
sparc_dma_mapping_error(struct ib_device *dev, u64 dma_addr)
{
	return dma_mapping_error(dev->dma_device, dma_addr);
}

static u64
sparc_dma_map_single(struct ib_device *dev, void *ptr, size_t size,
		     enum dma_data_direction direction)
{
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
	return dma_map_single_attrs(dev->dma_device, ptr, size, direction,
				    &attrs);
}

static void
sparc_dma_unmap_single(struct ib_device *dev, u64 addr, size_t size,
		       enum dma_data_direction direction)
{
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
	return dma_unmap_single_attrs(dev->dma_device, addr, size, direction,
				      &attrs);
}

static u64
sparc_dma_map_page(struct ib_device *dev, struct page *page,
		   unsigned long offset, size_t size,
		   enum dma_data_direction direction)
{
	const struct dma_map_ops *ops = get_dma_ops(dev->dma_device);
	dma_addr_t addr;
	DEFINE_DMA_ATTRS(attrs);

	kmemcheck_mark_initialized(page_address(page) + offset, size);
	BUG_ON(!valid_dma_direction(direction));
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
	addr = ops->map_page(dev->dma_device, page, offset, size, direction,
		&attrs);

	debug_dma_map_page(dev->dma_device, page, offset, size, direction,
			   addr, false);

	return addr;
}

static void
sparc_dma_unmap_page(struct ib_device *dev, u64 addr, size_t size,
		     enum dma_data_direction direction)
{
	const struct dma_map_ops *ops = get_dma_ops(dev->dma_device);
	DEFINE_DMA_ATTRS(attrs);

	BUG_ON(!valid_dma_direction(direction));
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
	if (ops->unmap_page)
		ops->unmap_page(dev->dma_device, addr, size, direction,
			&attrs);

	debug_dma_unmap_page(dev->dma_device, addr, size, direction, false);
}

static int
sparc_dma_map_sg(struct ib_device *dev, struct scatterlist *sg, int nents,
		 enum dma_data_direction direction)
{
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
	return dma_map_sg_attrs(dev->dma_device, sg, nents, direction, &attrs);
}

static void
sparc_dma_unmap_sg(struct ib_device *dev, struct scatterlist *sg, int nents,
		   enum dma_data_direction direction)
{
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
	dma_unmap_sg_attrs(dev->dma_device, sg, nents, direction, &attrs);
}

static u64
sparc_dma_map_single_attrs(struct ib_device *dev, void *ptr, size_t size,
			   enum dma_data_direction direction,
			   struct dma_attrs *attrs)
{
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, attrs);
	return dma_map_single_attrs(dev->dma_device, ptr, size, direction,
				    attrs);
}

static void
sparc_dma_unmap_single_attrs(struct ib_device *dev, u64 addr, size_t size,
		       enum dma_data_direction direction,
		       struct dma_attrs *attrs)
{
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, attrs);
	dma_unmap_single_attrs(dev->dma_device, addr, size, direction, attrs);
}

static int
sparc_dma_map_sg_attrs(struct ib_device *dev, struct scatterlist *sg, int nents,
		 enum dma_data_direction direction, struct dma_attrs *attrs)
{
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, attrs);
	return dma_map_sg_attrs(dev->dma_device, sg, nents, direction, attrs);
}

static void
sparc_dma_unmap_sg_attrs(struct ib_device *dev, struct scatterlist *sg,
			 int nents, enum dma_data_direction direction,
			 struct dma_attrs *attrs)
{
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, attrs);
	dma_unmap_sg_attrs(dev->dma_device, sg, nents, direction, attrs);
}

static void
sparc_dma_sync_single_for_cpu(struct ib_device *dev, u64 dma_handle,
			      size_t size, enum dma_data_direction dir)
{
	dma_sync_single_for_cpu(dev->dma_device, dma_handle, size, dir);
}

static void
sparc_dma_sync_single_for_device(struct ib_device *dev, u64 dma_handle,
				 size_t size, enum dma_data_direction dir)
{
	dma_sync_single_for_device(dev->dma_device, dma_handle, size, dir);
}

static void *
sparc_dma_alloc_coherent(struct ib_device *dev, size_t size,
			 u64 *dma_handle, gfp_t flag)
{
	dma_addr_t handle;
	void *ret;

	ret = dma_alloc_coherent(dev->dma_device, size, &handle, flag);
	*dma_handle = handle;

	return ret;
}

static void
sparc_dma_free_coherent(struct ib_device *dev, size_t size, void *cpu_addr,
			u64 dma_handle)
{
	dma_free_coherent(dev->dma_device, size,
				 cpu_addr, (dma_addr_t) dma_handle);
}

static struct ib_dma_mapping_ops sparc_dma_mapping_ops = {
	.mapping_error = sparc_dma_mapping_error,
	.map_single = sparc_dma_map_single,
	.unmap_single = sparc_dma_unmap_single,
	.map_page = sparc_dma_map_page,
	.unmap_page = sparc_dma_unmap_page,
	.map_sg = sparc_dma_map_sg,
	.unmap_sg = sparc_dma_unmap_sg,
	.map_single_attrs = sparc_dma_map_single_attrs,
	.unmap_single_attrs = sparc_dma_unmap_single_attrs,
	.map_sg_attrs = sparc_dma_map_sg_attrs,
	.unmap_sg_attrs = sparc_dma_unmap_sg_attrs,
	.sync_single_for_cpu = sparc_dma_sync_single_for_cpu,
	.sync_single_for_device = sparc_dma_sync_single_for_device,
	.alloc_coherent = sparc_dma_alloc_coherent,
	.free_coherent = sparc_dma_free_coherent,

};
#endif /* if defined(__sparc__) && defined(__arch64__) */

void
mlx4_register_dma_ops(struct ib_device *ib_dev)
{
#if defined(__sparc__) && defined(__arch64__)
	ib_dev->dma_ops = &sparc_dma_mapping_ops;
#else
	ib_dev->dma_ops = NULL;
#endif
}
