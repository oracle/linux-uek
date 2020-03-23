// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2016-2019 Intel Corporation. All rights reserved. */
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/pfn_t.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include "dax-private.h"
#include "bus.h"

static int dax_kmem_range(struct dev_dax *dev_dax, int i, struct range *r)
{
	struct dev_dax_range *dax_range = &dev_dax->ranges[i];
	struct range *range = &dax_range->range;

	/* memory-block align the hotplug range */
	r->start = ALIGN(range->start, memory_block_size_bytes());
	r->end = ALIGN_DOWN(range->end + 1, memory_block_size_bytes()) - 1;
	if (r->start >= r->end) {
		r->start = range->start;
		r->end = range->end;
		return -ENOSPC;
	}
	return 0;
}

int dev_dax_kmem_probe(struct dev_dax *dev_dax)
{
	int numa_node = dev_dax->target_node;
	struct device *dev = &dev_dax->dev;
	int i, mapped = 0;

	/*
	 * Ensure good NUMA information for the persistent memory.
	 * Without this check, there is a risk that slow memory
	 * could be mixed in a node with faster memory, causing
	 * unavoidable performance issues.
	 */
	if (numa_node < 0) {
		dev_warn(dev, "rejecting DAX region with invalid node: %d\n",
				numa_node);
		return -EINVAL;
	}

	for (i = 0; i < dev_dax->nr_range; i++) {
		char *new_res_name;
		struct resource *res;
		struct range range;
		int rc;

		rc = dax_kmem_range(dev_dax, i, &range);
		if (rc) {
			dev_info(dev, "mapping%d: %#llx-%#llx too small after alignment\n",
					i, range.start, range.end);
			continue;
		}

		new_res_name = kstrdup(dev_name(dev), GFP_KERNEL);
		if (!new_res_name)
			return -ENOMEM;

		res = request_mem_region(range.start, range_len(&range),
				new_res_name);
		if (!res) {
			dev_warn(dev, "mapping%d: %#llx-%#llx could not reserve region\n",
					i, range.start, range.end);
			kfree(new_res_name);
			/*
			 * Once some memory has been onlined we can't
			 * assume that it can be un-onlined safely.
			 */
			if (mapped)
				continue;
			return -EBUSY;
		}

		/* Temporarily clear busy to allow add_memory() to claim it */
		res->flags &= ~IORESOURCE_BUSY;
		rc = add_memory(numa_node, range.start, range_len(&range));
		res->flags |= IORESOURCE_BUSY;
		if (rc) {
			dev_warn(dev, "mapping%d: %#llx-%#llx memory add failed\n",
					i, range.start, range.end);
			release_mem_region(range.start, range_len(&range));
			kfree(new_res_name);
			if (mapped)
				continue;
			return rc;
		}
		dev_dax->ranges[i].dax_kmem_name = new_res_name;
		mapped++;
	}

	return 0;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
static void dax_kmem_release(struct dev_dax *dev_dax)
{
	int i;

	/*
	 * We have one shot for removing memory, if some memory blocks were not
	 * offline prior to calling this function remove_memory() will fail, and
	 * there is no way to hotremove this memory until reboot because device
	 * unbind will proceed regardless of the remove_memory result.
	 */
	for (i = 0; i < dev_dax->nr_range; i++) {
		const char *res_name = dev_dax->ranges[i].dax_kmem_name;
		struct range range;
		int rc;

		rc = dax_kmem_range(dev_dax, i, &range);
		if (rc)
			continue;

		rc = remove_memory(dev_dax->target_node, range.start,
				range_len(&range));
		if (rc == 0) {
			release_mem_region(range.start, range_len(&range));
			kfree(res_name);
			dev_dax->ranges[i].dax_kmem_name = NULL;
			continue;
		}
		dev_err(&dev_dax->dev,
			"mapping%d: %#llx-%#llx cannot be hotremoved until the next reboot\n",
				i, range.start, range.end);
	}
}
#else
static void dax_kmem_release(struct dev_dax *dev_dax)
{
	/*
	 * Without hotremove purposely leak the request_mem_region() for
	 * the device-dax range attempts. The removal of the device from
	 * the driver always succeeds, but the region is permanently
	 * pinned as reserved by the unreleased request_mem_region().
	 */
}
#endif /* CONFIG_MEMORY_HOTREMOVE */

static int dev_dax_kmem_remove(struct dev_dax *dev_dax)
{
	dax_kmem_release(dev_dax);
	return 0;
}

static struct dax_device_driver device_dax_kmem_driver = {
	.probe = dev_dax_kmem_probe,
	.remove = dev_dax_kmem_remove,
};

static int __init dax_kmem_init(void)
{
	return dax_driver_register(&device_dax_kmem_driver);
}

static void __exit dax_kmem_exit(void)
{
	dax_driver_unregister(&device_dax_kmem_driver);
}

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
module_init(dax_kmem_init);
module_exit(dax_kmem_exit);
MODULE_ALIAS_DAX_DEVICE(0);
