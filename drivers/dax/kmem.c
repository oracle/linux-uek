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

static struct range dax_kmem_range(struct dev_dax *dev_dax)
{
	struct range range;

	/* memory-block align the hotplug range */
	range.start = ALIGN(dev_dax->range.start, memory_block_size_bytes());
	range.end = ALIGN_DOWN(dev_dax->range.end + 1,
			memory_block_size_bytes()) - 1;
	return range;
}

int dev_dax_kmem_probe(struct device *dev)
{
	struct dev_dax *dev_dax = to_dev_dax(dev);
	struct range range = dax_kmem_range(dev_dax);
	int numa_node = dev_dax->target_node;
	struct resource *res;
	char *new_res_name;
	int rc;

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

	new_res_name = kstrdup(dev_name(dev), GFP_KERNEL);
	if (!new_res_name)
		return -ENOMEM;

	res = request_mem_region(range.start, range_len(&range), new_res_name);
	if (!res) {
		dev_warn(dev, "could not reserve region [%#llx-%#llx]\n",
				range.start, range.end);
		return -EBUSY;
	}

	/* Temporarily clear busy to allow add_memory() to claim it */
	res->flags &= ~IORESOURCE_BUSY;
	rc = add_memory(numa_node, range.start, range_len(&range));
	res->flags |= IORESOURCE_BUSY;
	if (rc) {
		release_mem_region(range.start, range_len(&range));
		kfree(new_res_name);
		return rc;
	}
	dev_dax->dax_kmem_name = new_res_name;

	return 0;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
static void dax_kmem_release(struct dev_dax *dev_dax)
{
	const char *res_name = dev_dax->dax_kmem_name;
	struct range range = dax_kmem_range(dev_dax);
	int rc;

	/*
	 * We have one shot for removing memory, if some memory blocks were not
	 * offline prior to calling this function remove_memory() will fail, and
	 * there is no way to hotremove this memory until reboot because device
	 * unbind will proceed regardless of the remove_memory result.
	 */
	rc = remove_memory(dev_dax->target_node, range.start, range_len(&range));
	if (rc == 0) {
		release_mem_region(range.start, range_len(&range));
		kfree(res_name);
		dev_dax->dax_kmem_name = NULL;
		return;
	}
	dev_err(&dev_dax->dev, "%#llx-%#llx cannot be hotremoved until the next reboot\n",
			range.start, range.end);
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

static int dev_dax_kmem_remove(struct device *dev)
{
	dax_kmem_release(to_dev_dax(dev));
	return 0;
}

static struct dax_device_driver device_dax_kmem_driver = {
	.drv = {
		.probe = dev_dax_kmem_probe,
		.remove = dev_dax_kmem_remove,
	},
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
