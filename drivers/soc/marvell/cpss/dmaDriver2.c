/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the two
license alternatives that you have not elected to use and (iii) preserve the
Marvell copyright notice above.


********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
********************************************************************************
* @file dmaDriver.c
*
* @brief Kernel module to map DMA memory to userspace
*
* @author Yuval Shaia <yshaia@marvell.com>
*
* Usage:
*	u32 offset, dma;
*	int fd, flags;
*	void *virt;
*
*	fd = open("/dev/mvdma", O_RDWR);
*	flags = global ? (1 << 24) : 0;
*	flags |= other_options;
*	offset = flags | domain << 16 | bus << 8 | dev << 3 | func;
*	lseek(fd, offset, 0);
*	virt = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
*		    idx * PAGE_SIZE);
*	read(fd, &dma, sizeof(dma));
*	close(fd);
*
*	The 'offset' argument to mmap sys-call is used as an indication to which
*	buffer to attach or to allocate new one. A value between 0 to 'n - 1',
*	where n is the number of buffers already allocated will cause the driver
*	to remap to the requested buffer.
*	A value of 'n' will cause the driver to allocate new buffer.
*
* For PCI platforms:
*	The 'offset' argument to lseek sys-call is used to configure the
*	PCI device and options.
*		25 - 31: Reserved
*		24     : Global Indication
*		16 - 23: Domain
*		8  - 15: Bus
*		3  - 7 : Device
*		0  - 2 : Function
*
* For non-PCI platforms:
*	The driver support allocation from a pre-reserved memory area described
*	in device tree.
*	The following is an example of reservation of 16m in device tree.
*
*	reserved-memory {
*		prestera_rsvd: buffer@2M {
*			compatible = "shared-dma-pool";
*			no-map;
*			reg = <0x0 0x10000 0x0 0x1000000>;
*		};
*	};
*
*	mvdma {
*		compatible = "marvell,mv_dma";
*		memory-region = <&prestera_rsvd>;
*		status = "okay";
*	};
*
* 	Note #1:
*	The lower 24 bits in offset argument to to lseek sys-call shold be
*	0xFFFFFF. The rest are used, the same as with PCI platform, to pass
*	flags to driver. Please note that 'Global Indication' in this case is
*	irrelevant and all allocations are for global use.
*
*	Note #2:
*	While the declaration of mvdma section is mandatory for non-PCI device,
*	the reserved-memory is not. In such case, the allocation will be done
*	from the global CMA pool.
*
*******************************************************************************/

#define MV_DRV_NAME "mvdma"

#include "mvDriverTemplate.h"

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/debugfs.h>
#include <linux/sched.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,14,79))
#if defined(CONFIG_OF)
#include <linux/platform_device.h>
#define SUPPORT_PLATFORM_DEVICE
#endif
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,19,8))
#include <linux/of_reserved_mem.h>
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)) || !defined(SUPPORT_PLATFORM_DEVICE)
#define MMAP_USE_REMAP_PFN_RANGE
#endif

#define MV_DMA_ALLOC_FLAGS GFP_DMA32 | GFP_NOFS

/* DMA mapping */
struct dma_mapping {
	struct list_head list; /* To maintain list of mappings */
	void *virt;
	dma_addr_t dma;
#ifdef MMAP_USE_REMAP_PFN_RANGE
	phys_addr_t phys;
#endif
	size_t size;
	long long unsigned int uvirt; /* debugfs: Save userspace virt address */
};

/* DMA mappings of device */
struct dev_mappings {
	struct list_head global_dev_mappings; /* Me on global_dev_mappings */
	struct device *dev;
	bool global;
	struct list_head mappings; /* List of dma_mapping */
	unsigned long list_count;
	struct dma_mapping *last_mapping;
};

struct file_desc {
	struct list_head list;
	struct file *filep;
	int pid;
};

/* Character device context */
static struct mvchrdev_ctx *mvdma_ctx;

/* Global driver list of dev_mappings */
struct list_head global_dev_mappings;
/* dev_mappings of the one platform device */
struct dev_mappings *platform_dev_mappings;
/* Global list of opened files (for debugfs) */
struct list_head opened_files; /* List of file_desc (for debugfs) */
/* debugfs dir and mmaps file */
struct dentry *debugfs_dir, *debugfs_mmaps;

/* Add filep to opened_files */
static void mvdma_add_open_file(struct file *file)
{
	struct file_desc *filed;

	filed = kzalloc(sizeof(*filed), GFP_KERNEL);
	if (!filed) {
		dev_err(mvdma_ctx->dev, "Fail to allocate file context\n");
		return;
	}

	filed->pid = current->pid;
	filed->filep = file;

	list_add(&filed->list, &(opened_files));
}

/* Remove filep from opened_files */
static void mvdma_remove_open_file(struct file *file)
{
	struct file_desc *filed;
	struct list_head *p;

	list_for_each(p, &opened_files) {
		filed = list_entry(p, struct file_desc, list);
		if (filed->filep == file) {
			list_del(p);
			kfree(filed);
			return;
		}
	}
}

/* Free DMA mapping */
static void mvdma_free_dma_mapping(struct device *dev,
				   struct dma_mapping *mapping)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,39)
	phys_addr_t p;
#endif

	BUG_ON(!mapping->dma);

	dev_dbg(dev, "dma_free_coherent size %ld, virt %p, dma 0x%llx",
		mapping->size, mapping->virt, (unsigned long long)mapping->dma);

	/*
	 * Kernel 6.x BUGs when reserved memory marked pages are returned.
         * Do not free reserved memory for this kernel:
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,39)
	for (p = mapping->dma;
	     p < (mapping->dma + mapping->size);
	     p += PAGE_SIZE)
		if (PageReserved((struct page *)phys_to_page(p))) {
			dev_err(dev, "Reserved memory@%llx, cannot free!\n",
				mapping->dma);
			return;
		}
#endif

	dma_free_coherent(dev, mapping->size, mapping->virt, mapping->dma);
}

static u64 mvdma_reminder(u64 dividend, u64 divisor)
{
	u64 remainder;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
		remainder = ((u32)dividend % (u32)divisor);
#else
		div64_u64_rem(dividend, divisor, &remainder);
#endif

	return remainder;
}

/* Alloc DMA mapping */
static struct dma_mapping *mvdma_alloc_dma_mapping(struct device *dev,
						   unsigned long size)
{
	struct dma_mapping *mapping;

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping) {
		dev_err(dev, "Fail to allocate memory for dma mapping\n");
		return NULL;
	}

	mapping->size = size;
	mapping->virt = dma_alloc_coherent(dev, size, &mapping->dma,
					   MV_DMA_ALLOC_FLAGS);
	if (!mapping->virt) {
		dev_err(dev, "Failed coherent DMA allocation, fallback to CMA\n");
		/*
		 * Looks like reserved memory release is not returned
		 * to the reserved memory area. If coherent allocation
		 * fails, release device tree reserved memory settings
		 * and try to allocate from CMA:
		 */
		of_reserved_mem_device_release(dev);
		mapping->virt = dma_alloc_coherent(dev, size, &mapping->dma,
						   MV_DMA_ALLOC_FLAGS);
		if (!mapping->virt) {
			dev_err(dev, "Failed coherent DMA allocation, both reserved and CMA!\n");
			goto err_free_mapping_msg;
		}
	}

	/* Make sure address is aligned with the size */
	if (mvdma_reminder(mapping->dma, mapping->size)) {
		struct dma_mapping m_1;

		dev_info(dev, "Coherent memory %llx,%lx is not aligned, adjusting\n",
			mapping->dma, mapping->size);

		/* Reserve dummy place */
		m_1.size = mapping->size - mvdma_reminder(mapping->dma,
							  mapping->size);
		mvdma_free_dma_mapping(dev, mapping);
		m_1.virt = dma_alloc_coherent(dev, m_1.size, &(m_1.dma),
					      MV_DMA_ALLOC_FLAGS);
		if (!m_1.virt)
			goto err_free_mapping;

		dev_dbg(dev, "aligner allocated: %llx, %lx\n", m_1.dma, m_1.size);
		/* Remap, this time we should be aligned */
		mapping->virt = dma_alloc_coherent(dev, size, &mapping->dma,
						   MV_DMA_ALLOC_FLAGS);
		mvdma_free_dma_mapping(dev, &m_1);
		if (!mapping->virt)
			goto err_free_mapping_msg;

		/* Let's again make sure address is aligned with the size */
		if (mvdma_reminder(mapping->dma, mapping->size)) {
			dev_err(dev,
				"Fail to allocate aligned coherent memory of size %ld\n",
				size);
			goto err_free_mapping;
		}
	}
		dev_dbg(dev, "Coherent memory %llx, %lx is aligned:\n",
			mapping->dma, mapping->size);

#ifdef MMAP_USE_REMAP_PFN_RANGE
#if defined(CONFIG_X86) || defined(CONFIG_MIPS)
	mapping->phys = dma_to_phys(dev, mapping->dma);
#else
	mapping->phys = (phys_addr_t)mapping->dma;
#endif
	dev_dbg(dev, "phys=0x%llx\n", (unsigned long long)mapping->phys);
#endif

	return mapping;

err_free_mapping_msg:
	dev_err(dev, "Fail to allocate coherent memory of size %ld\n", size);

err_free_mapping:
	kfree(mapping);
	return NULL;
}

static struct dev_mappings *mvdma_alloc_dev_mappings(struct device *dev,
						     bool global)
{
	struct dev_mappings *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return NULL;

	INIT_LIST_HEAD(&m->mappings);

	m->dev = dev;
	m->global = global;

	return m;
}

/* Find dev_mappings object in the global list devices mappings */
static struct dev_mappings *mvdma_find_global_dev_mappings(struct device *dev)
{
	struct dev_mappings *dev_mappings;
	struct list_head *p;

	list_for_each(p, &(global_dev_mappings)) {
		dev_mappings = list_entry(p, struct dev_mappings,
					  global_dev_mappings);
		if (dev_mappings->dev == dev)
			return dev_mappings;
	}

	return NULL;
}

/* Free all mappings of a device */
static void mvdma_free_dev_mappings(struct dev_mappings *dev_mappings)
{
	struct dma_mapping *mapping;
	struct list_head *p, *q;

	dev_dbg(mvdma_ctx->dev, "Freeing device mappings\n");

	list_for_each_safe(p, q, &(dev_mappings->mappings)) {
		mapping = list_entry(p, struct dma_mapping, list);
		mvdma_free_dma_mapping(dev_mappings->dev, mapping);
		list_del(p);
		kfree(mapping);
	}
}

/* Free global list devices mappings (called on driver exit) */
static void mvdma_free_global_devs_mappings(void)
{
	struct dev_mappings *dev_mappings;
	struct list_head *p, *q;

	dev_dbg(mvdma_ctx->dev, "Freeing global mappings\n");

	list_for_each_safe(p, q, &(global_dev_mappings)) {
		dev_mappings = list_entry(p, struct dev_mappings,
					  global_dev_mappings);
		mvdma_free_dev_mappings(dev_mappings);
		list_del(p);
		kfree(dev_mappings);
	}
}

static void mvdma_dev_add_mapping(struct dev_mappings *dev,
				  struct dma_mapping *dma)
{
	list_add_tail(&dma->list, &dev->mappings);
	dev->list_count++;
}

static struct dma_mapping *mvdma_dev_get_mapping(struct dev_mappings *dev,
						 unsigned long offset)
{
	struct list_head *p;

	/* Convert to 1-based */
	offset += 1;

	list_for_each(p, &(dev->mappings)) {
		struct dma_mapping *dma_mapping;

		dma_mapping = list_entry(p, struct dma_mapping, list);
		offset--;
		if (!offset)
			return dma_mapping;
	}

	return NULL;
}

static int mvdma_dma_configure(struct device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	int (*dma_configure)(struct device *dev);
	int ret;

	/*
	 * The new DMA framework, that was added in 4.11 (compared to * 4.4),
	 * does not initiate each PCI dev as DMA-enabled by default
	 * (dev->dma_ops is set to dummy_dma_ops), so need to  set the PP to be
	 * DMA enabled. This can be done through DTS, but it is not a solution
	 * for Intel CPUs, hance need to use * HACK to call dma_configure, which
	 * is not exported by the * kernel
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	dma_configure = dev->bus->dma_configure;
#else
	dma_configure = (void*)(unsigned long)
		kallsyms_lookup_name("dma_configure");
#endif

	if (!dma_configure) {
		dev_err(dev, "Fail to resolve dma_configure\n");
		return -ENXIO;
	}

	ret = dma_configure(dev);
	if (ret) {
		dev_err(dev, "dma_configure failed %d\n", ret);
		return -EFAULT;
	}
#endif

	return 0;
}

static int mvdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct dev_mappings *dev_mappings;
	struct dma_mapping *dma_mapping;
	unsigned long size;
	int rc;

	dev_mappings = (struct dev_mappings *)file->private_data;
	if (!dev_mappings) {
		dev_err(mvdma_ctx->dev, "mmap with no lseek, aborting\n");
		return -EIO;
	}

	size = vma->vm_end - vma->vm_start;

	dev_dbg(dev_mappings->dev,
		"Task %d triggers mmap, vm_start 0x%llx, vm_size %ld, offset %ld\n",
		current->pid, (long long unsigned int)vma->vm_start, size,
		vma->vm_pgoff);

	dev_mappings->last_mapping = NULL;

	/* Gaps are not allowed */
	if (vma->vm_pgoff > dev_mappings->list_count) {
		dev_err(mvdma_ctx->dev,
			"Fail to map to offset %ld (max %ld)\n",
			vma->vm_pgoff, dev_mappings->list_count);
		return -EIO;
	}

	dma_mapping = mvdma_dev_get_mapping(dev_mappings, vma->vm_pgoff);
	if (!dma_mapping) {
		mvdma_dma_configure(dev_mappings->dev);
		dma_mapping = mvdma_alloc_dma_mapping(dev_mappings->dev, size);
		if (!dma_mapping)
			return -EIO;

		dma_mapping->uvirt = vma->vm_start;
		mvdma_dev_add_mapping(dev_mappings, dma_mapping);
	}

	/* Save last mapping for later call to 'read()' */
	dev_mappings->last_mapping = dma_mapping;

	dev_dbg(mvdma_ctx->dev, "DMA block size %ld, virt %p, dma 0x%llx\n",
		dma_mapping->size, dma_mapping->virt,
		(unsigned long long)dma_mapping->dma);

	/* Map to the process's virtual address */
#ifdef MMAP_USE_REMAP_PFN_RANGE
	/* VM_IO for I/O memory */
	vma->vm_flags |= VM_IO;
	vma->vm_pgoff = dma_mapping->phys >> PAGE_SHIFT;

	/* If need to disable caching on mapped memory */
	/* vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot); */

	/* TODO: check if write combine support is needed ? */
	/* vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot); */

	rc = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			     dma_mapping->size, vma->vm_page_prot);
	if (rc) {
		dev_err(dev_mappings->dev, "remap_pfn_range failed\n");
		return -ENXIO;
	}

	dev_dbg(mvdma_ctx->dev, "remap_pfn_range vm_pgoff 0x%lx succeeds\n",
		vma->vm_pgoff);
#else /* MMAP_USE_REMAP_PFN_RANGE */
	vma->vm_pgoff = 0;
	rc = dma_mmap_coherent(dev_mappings->dev, vma, dma_mapping->virt,
			       dma_mapping->dma, dma_mapping->size);
	if (rc) {
		dev_err(mvdma_ctx->dev, "dma_mmap_coherent() failed\n");
		return -ENXIO;
	}
	dev_dbg(mvdma_ctx->dev, "dma_mmap_coherent succeeds\n");
#endif /* MMAP_USE_REMAP_PFN_RANGE */

	return 0;
}

static ssize_t mvdma_read(struct file *file, char *buf, size_t siz, loff_t *off)
{
	struct dev_mappings *dev_mappings;
	unsigned long long dma;
#if defined(CONFIG_CPU_BIG_ENDIAN)
	u32 *pdma = (u32 *)&dma;
#endif

	dev_mappings = (struct dev_mappings *)file->private_data;
	if (!dev_mappings) {
		dev_err(mvdma_ctx->dev, "read with no mmap, aborting\n");
		return -EIO;
	}

	if (!dev_mappings->last_mapping)
		return -EINVAL;

	if (siz < sizeof(dma))
		return -EINVAL;

	dma = (unsigned long long)dev_mappings->last_mapping->dma;

	/* Make sure userspace will receive lower bytes first */
#if !defined(CONFIG_CPU_BIG_ENDIAN)
	if (copy_to_user(buf, &dma, sizeof(dma)))
		return -EFAULT;
#else
	if (copy_to_user(buf, &pdma[0], 4))
		return -EFAULT;
	if (copy_to_user(buf + 4, &pdma[1], 4))
		return -EFAULT;
#endif

	return sizeof(dma);
}

static int mvdma_open(struct inode *inode, struct file *file)
{
	dev_dbg(mvdma_ctx->dev, "Task %d open file\n", current->pid);

	file->private_data = NULL;

	mvdma_add_open_file(file);

	return 0;
}

static loff_t mvdma_lseek(struct file *file, loff_t off, int unused)
{
	struct dev_mappings *dev_mappings = NULL;
	unsigned int domain, bus, slot, func;
	struct pci_dev *pdev = NULL;
	int global;

	/**
	 * Caller may wish to switch to different device, let's dispose the
	 * current one before
	 */
	if (file->private_data) {
		dev_mappings = (struct dev_mappings *)file->private_data;
		if (!dev_mappings->global)
			mvdma_free_dev_mappings(dev_mappings);
		file->private_data = NULL;

		/* A way to let process shutdown gracefully */
		if ((off & 0x0000FFFF) == 0x0000FFFF)
			return 0;
	}

	/* Device tree reservation? */
	if ((off & 0x0000FFFF) == 0x0000FFFF) {
plat_dev_alloc:
		/*
		 * Below logic is workaround for a case where PP is a platform device & is not
		 * connected over PCIe, DTS does not contain compatible = "marvell,mv_dma"
		 * entry and kernel does not support mapping of reserved memory through DTS
		 *
		 */
		if (!platform_dev_mappings) {

			platform_dev_mappings = mvdma_alloc_dev_mappings(NULL, true);
			if (!platform_dev_mappings) {
				dev_err(mvdma_ctx->dev,
					"Fail to allocate dev_mappings for platform device\n");
				return -ENOMEM;
			} else {
				dev_dbg(mvdma_ctx->dev,
					"dev_mappings for platform device allocated\n");
			}
		}

		dev_dbg(mvdma_ctx->dev, "Using platform device\n");

		file->private_data = platform_dev_mappings;

		return 0;
	}

	global = ((off >> 24) & 0x1);
	domain = (off >> 16) & 0xFF;
	bus = (off >> 8) & 0xFF;
	slot = (off >> 3) & 0x1F;
	func = off & 0x07;

	pdev = pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(slot, func));
	if (!pdev) {
		dev_err(mvdma_ctx->dev, "Fail to find PCI device %d:%d.%d.%d\n",
			domain, bus, slot, func);
		return -EINVAL;
	}
	/* TODO: Release pdev when no longer need (pci_dev_put) */

	/* Workaround for CPSS-15827, fall back to DT reserved memory allocation
	 * in case CMA allocation fails
	 */
	{
		void *v;
		dma_addr_t d;
		v = dma_alloc_coherent(&pdev->dev, 0x200000, &d, MV_DMA_ALLOC_FLAGS);
		if (v) {
			dma_free_coherent(&pdev->dev, 0x200000, v, d);
		} else {
			dev_warn(mvdma_ctx->dev,
				 "Fail to allocate from CMA, switching to platform device\n");
			pci_dev_put(pdev);
			goto plat_dev_alloc;
		}
	}
	/* End of workaround */

	if (global) {
		dev_mappings = mvdma_find_global_dev_mappings(&(pdev->dev));
		if (!dev_mappings) {
			dev_mappings = mvdma_alloc_dev_mappings(&(pdev->dev),
								global);
			list_add(&dev_mappings->global_dev_mappings,
				&(global_dev_mappings));
		}
	} else {
		dev_mappings = mvdma_alloc_dev_mappings(&(pdev->dev), global);
	}

	file->private_data = dev_mappings;

	dev_dbg(mvdma_ctx->dev, "Using PCI device %s\n",
		dev_mappings->dev->kobj.name);

	return 0;
}

static int mvdma_release(struct inode *inode, struct file *file)
{
	struct dev_mappings *dev_mappings;

	dev_dbg(mvdma_ctx->dev, "Task %d close file\n", current->pid);

	if (file->private_data) {
		dev_mappings = (struct dev_mappings *)file->private_data;
		if (!dev_mappings->global)
			mvdma_free_dev_mappings(dev_mappings);
		file->private_data = NULL;
	}
	mvdma_remove_open_file(file);

	return 0;
}

#if defined(SUPPORT_PLATFORM_DEVICE)
static int mvdma_pdriver_probe(struct platform_device *pdev)
{
	int rc;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,19,8))
	rc = of_reserved_mem_device_init(&pdev->dev);
	if (rc)
		dev_warn(&pdev->dev,
			 "Missing memory-region, defaulting to CMA\n");
#endif
	platform_dev_mappings = mvdma_alloc_dev_mappings(&pdev->dev, true);
	if (!platform_dev_mappings) {
		dev_err(mvdma_ctx->dev,
			"Fail to allocate dev_mappings for platform device\n");
		return -ENOMEM;
	}
	list_add(&platform_dev_mappings->global_dev_mappings,
		&(global_dev_mappings));

	dev_info(&pdev->dev, "Platform device driver registered\n");

	return 0;
};

static int mvdma_pdriver_remove(struct platform_device *pdev)
{
	BUG_ON(!platform_dev_mappings);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,19,8))
	of_reserved_mem_device_release(&pdev->dev);
#endif
	return 0;
}

static const struct of_device_id mvdma_of_match_ids[] = {
	 { .compatible = "marvell,mv_dma", },
	{}
};

static struct platform_driver mvdma_platform_driver = {
	.probe		= mvdma_pdriver_probe,
	.remove		= mvdma_pdriver_remove,
	.driver		= {
		.name	= MV_DRV_NAME,
		.of_match_table = mvdma_of_match_ids,
	},
};
#endif

static struct file_operations mvdma_fops = {
	.mmap	= mvdma_mmap,
	.read	= mvdma_read,
	.open	= mvdma_open,
	.llseek	= mvdma_lseek,
	.release= mvdma_release,
};

void mvdma2_exit(void)
{
	mvchrdev_cleanup(mvdma_ctx);

#if defined(SUPPORT_PLATFORM_DEVICE)
	platform_driver_unregister(&mvdma_platform_driver);
#endif

	debugfs_remove(debugfs_mmaps);
	debugfs_remove(debugfs_dir);

	of_reserved_mem_device_release(mvdma_ctx->dev);
	mvdma_free_global_devs_mappings();
}

static void mvdma_debugfs_print_mappings(struct seq_file *m,
					 struct list_head *head)
{
	struct dma_mapping *dma_mapping;
	struct list_head *p;

#ifdef MMAP_USE_REMAP_PFN_RANGE
	seq_printf(m, "\t\t%-20s %-20s %-20s %-20s %-20s\n", "uvirt", "kvirt", "dma",
		   "phys", "size");
#else
	seq_printf(m, "\t\t%-20s %-20s %-20s %-20s\n", "uvirt", "kvirt", "dma", "size");
#endif
	list_for_each(p, head) {
		dma_mapping = list_entry(p, struct dma_mapping, list);
#ifdef MMAP_USE_REMAP_PFN_RANGE
		seq_printf(m, "\t\t%-20llx %-20p %-20llx %-20lx %-20lx\n",
			   dma_mapping->uvirt, dma_mapping->virt,
			   dma_mapping->dma, dma_mapping->phys,
			   dma_mapping->size);
#else
		seq_printf(m, "\t\t%-20llx %-20p %-20llx %-20lx\n",
			   dma_mapping->uvirt, dma_mapping->virt,
			   dma_mapping->dma, dma_mapping->size);
#endif
	}
}

static void mvdma_debugfs_print_attached_files(struct seq_file *m,
					       struct dev_mappings *dm)
{
	struct file_desc *filed;
	struct list_head *p;

	seq_printf(m, "\t\t%-10s %-20s\n", "pid", "filep");
	list_for_each(p, &opened_files) {
		filed = list_entry(p, struct file_desc, list);
		if (filed->filep->private_data == dm)
			seq_printf(m, "\t\t%-10d %-20p\n", filed->pid, filed->filep);
	}
}

static void mvdma_debugfs_print_private_files(struct seq_file *m)
{
	struct dev_mappings *dev_mappings;
	struct file_desc *filed;
	struct list_head *p;

	seq_printf(m, "privates\n");
	list_for_each(p, &opened_files) {
		filed = list_entry(p, struct file_desc, list);
		dev_mappings = (struct dev_mappings *)
					filed->filep->private_data;
		if (dev_mappings && !dev_mappings->global) {
			seq_printf(m, "\tdev %s, pid %d, filep %p\n",
				   dev_name(dev_mappings->dev),
				   filed->pid, filed->filep);
			mvdma_debugfs_print_mappings(m,
						     &(dev_mappings->mappings));
		}
	}
}

static void mvdma_debugfs_print_globals(struct seq_file *m)
{
	struct dev_mappings *dev_mappings;
	struct list_head *p;

	seq_printf(m, "globals\n");
	list_for_each(p, &(global_dev_mappings)) {
		dev_mappings = list_entry(p, struct dev_mappings,
					  global_dev_mappings);
		seq_printf(m, "\tdev %s\n", dev_name(dev_mappings->dev));
		mvdma_debugfs_print_mappings(m, &(dev_mappings->mappings));
		mvdma_debugfs_print_attached_files(m, dev_mappings);
	}
}

static int mvdma_debugfs_show(struct seq_file *m, void *v)
{

	mvdma_debugfs_print_globals(m);
	seq_puts(m, "\n");
	mvdma_debugfs_print_private_files(m);

	return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0))
#define DEFINE_SHOW_ATTRIBUTE(__name)						\
	static int __name ## _open(struct inode *inode, struct file *file)	\
{										\
	return single_open(file, __name ## _show, inode->i_private);		\
}										\
										\
static const struct file_operations __name ## _fops = {				\
	.owner		= THIS_MODULE,						\
	.open		= __name ## _open,					\
	.read		= seq_read,						\
	.llseek		= seq_lseek,						\
	.release	= single_release,					\
}
#endif

DEFINE_SHOW_ATTRIBUTE(mvdma_debugfs);

int mvdma2_init(void)
{
#if defined(SUPPORT_PLATFORM_DEVICE)
	int rc;
#endif //SUPPORT_PLATFORM_DEVICE

	mvdma_ctx = mvchrdev_init(MV_DRV_NAME, &mvdma_fops);
	if (!mvdma_ctx)
		return -EIO;

	INIT_LIST_HEAD(&global_dev_mappings);
	INIT_LIST_HEAD(&opened_files);
#if defined(CONFIG_DEBUG_FS)
	debugfs_dir = debugfs_create_dir(MV_DRV_NAME, NULL);
	if (IS_ERR(debugfs_dir)) {
		dev_err(mvdma_ctx->dev, "Fail to create debugfs directory\n");
		goto err_mvchrdev;
	}

	debugfs_mmaps = debugfs_create_file("mmaps", 0444, debugfs_dir, NULL,
					    &mvdma_debugfs_fops);
	if (IS_ERR(debugfs_mmaps)) {
		dev_err(mvdma_ctx->dev, "Fail to create debugfs mmaps file\n");
		goto err_dbgfs_dir;
	}
#endif //CONFIG_DEBUG_FS
#if defined(SUPPORT_PLATFORM_DEVICE)
	rc = platform_driver_register(&mvdma_platform_driver);
	if (rc) {
		dev_err(mvdma_ctx->dev, "Fail to register platform driver\n");
		goto err_dbgfs_mmap;
	} else {
		dev_dbg(mvdma_ctx->dev, "Registered platform driver\n");
	}
#endif //SUPPORT_PLATFORM_DEVICE

	return 0;

#if defined(SUPPORT_PLATFORM_DEVICE)
err_dbgfs_mmap:
#if defined(CONFIG_DEBUG_FS)
	debugfs_remove(debugfs_mmaps);
#endif //CONFIG_DEBUG_FS
#endif //SUPPORT_PLATFORM_DEVICE

#if defined(CONFIG_DEBUG_FS)
err_dbgfs_dir:
	debugfs_remove(debugfs_dir);

err_mvchrdev:
#endif //CONFIG_DEBUG_FS
	mvchrdev_cleanup(mvdma_ctx);

	return -EIO;
}
