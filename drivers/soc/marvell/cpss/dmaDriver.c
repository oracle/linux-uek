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
* dmaDriver.c
*
* DESCRIPTION:
*	mvDmaDrv - driver to map DMA memory to userspace
*	Usage:
*		fd = open("/dev/mvDmaDrv",O_RDWR);
*		mmap(,size, ..,fd,0) will allocate DMA block and map it
*		...
*		read(fd,uint64_t*,8) will read DMA address
*		close(fd) will unmap and free DMA block
*
*	Additional features used by linuxNokernelModule driver:
*		1. When virtual address == LINUX_VMA_DMABASE (defined below)
*		   then allocate a single DMA block which will be mapped to all
*		   applications to the same virtual address
*		2. Select PCI device for allocation:
*			lseek(fd,
*			      ((domain<<16)&0xffff0000) |
*			      ((bus<<8)   &0x0000ff00)  |
*			      ((dev<<3)   &0x000000f8)  |
*			      ((func)     &0x00000007))
*		   This should allow IOMMU transactions from PCI device to
*		   system memory
*
*	Please note:
*		On Intel CPU it may require 'intel_iommu=off' kernel option
*
*
*	Following is an example of pre-allocation in device-tree.
*
*	reserved-memory {
*		prestera_rsvd: buffer@0M {
*			compatible = "shared-dma-pool";
*			no-map;
*			reg = <0x0 0x10000 0x0 0x1000000>;
*		};
*	};
*
*	mvdma {
*		compatible = "marvell,mvdma";
*		memory-region = <&prestera_rsvd>;
*		status = "okay";
*	};
*
* DEPENDENCIES:
*	$Revision: 31 $
*
*******************************************************************************/
#define MV_DRV_NAME     "mvDmaDrv"
#define MV_DRV_MAJOR	244
#define MV_DRV_MINOR	3
#define MV_DRV_FOPS	mvDmaDrv_fops
#define MV_DRV_POSTINIT	mvDmaDrv_postInitDrv
#define MV_DRV_RELEASE	mvDmaDrv_releaseDrv

#include "mvDriverTemplate.h"

#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/kallsyms.h>
#include <linux/platform_device.h>
#include <linux/of_reserved_mem.h>

#ifdef MTS_BUILD
#define LINUX_VMA_DMABASE 0x19000000UL
#endif

#ifndef LINUX_VMA_DMABASE
#if defined(CONFIG_X86_64)
#define LINUX_VMA_DMABASE 0x1fc00000UL
#elif defined(CONFIG_X86) || defined(CONFIG_ARCH_MULTI_V7) || defined(CONFIG_ARM64)
#define LINUX_VMA_DMABASE 0x60000000UL
#endif /* CONFIG_X86 || CONFIG_ARCH_MULTI_V7 || CONFIG_ARM64 */
#ifdef CONFIG_MIPS
#define LINUX_VMA_DMABASE 0x2c800000UL
#endif /* CONFIG_MIPS */
#endif /* CONFIG_X86_64 */
#ifndef LINUX_VMA_DMABASE
#define LINUX_VMA_DMABASE 0x19000000UL
#endif /* LINUX_VMA_DMABASE */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
#define MMAP_USE_REMAP_PFN_RANGE
#endif

#define MV_DMA_ALLOC_FLAGS GFP_DMA32 | GFP_NOFS

/* Did we successfully registered as platform driver? zero means yes */
static u8 platdrv_registered;
static struct device *platdrv_dev;

struct dma_mapping {
	void *virt;
	dma_addr_t dma;
#ifdef MMAP_USE_REMAP_PFN_RANGE
	phys_addr_t phys;
#endif
	size_t size;
	struct device *dev;
};

static struct dma_mapping *shared_dmaBlock;

static void free_dma_block(struct dma_mapping *m)
{
	if (!m->dma)
		return;

	printk(KERN_INFO "%s: dma_free_coherent(%p, 0x%lx, %p, 0x%llx)\n",
	       MV_DRV_NAME, m->dev ? m->dev : mvDrv_device,
	       (unsigned long)m->size, m->virt, (unsigned long long)m->dma);

	dma_free_coherent(m->dev ? m->dev : mvDrv_device, m->size, m->virt,
			  m->dma);
}


static int mvDmaDrv_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct dma_mapping *m = (struct dma_mapping *)file->private_data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	int (*dma_configure)(struct device *dev);
	int ret;
#endif

	if (!m->dev && !platdrv_dev) {
		printk(KERN_ERR "%s: Nither PCI, nor Platform device is registered, cannot mmap\n",
		       MV_DRV_NAME);
		return -EIO;
	}

	if (!m->dev && platdrv_dev)
		m->dev = platdrv_dev;

	dev_info(m->dev, "%s(file=%p) data=%p LINUX_VMA_DMABASE=0x%lx\n",
		 __func__, file, m, LINUX_VMA_DMABASE);

	if (m->dma && vma->vm_start != LINUX_VMA_DMABASE)
		return -ENXIO;

	if (vma->vm_start == LINUX_VMA_DMABASE && shared_dmaBlock) {
		dev_dbg(m->dev, "SHM mode\n");
		if (m != shared_dmaBlock) {
			dev_dbg(m->dev,
				"SHM mode, new client instance, redirecting to pre-allocated block\n");
			kfree(m);
			file->private_data = shared_dmaBlock;
		}
		m = shared_dmaBlock;
	} else {
		if (vma->vm_start == LINUX_VMA_DMABASE) {
			dev_dbg(m->dev, "SHM mode, first client instance\n");
			shared_dmaBlock = m;
		}

		/* don't config dma_ops in case of no-dev, or for platdrv_dev */
		if (m->dev && !platdrv_dev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
		/* The new DMA framework, that was added in 4.11 (compared to
 		 * 4.4), does not initiate each PCI dev as DMA-enabled by
 		 * default (dev->dma_ops is set to dummy_dma_ops), so need to
 		 * set the PP to be DMA enabled. This can be done through DTS,
 		 * but it is not a solution for Intel CPUs, hance need to use
 		 * HACK to call dma_configure, which is not exported by the
 		 * kernel
		 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
			dma_configure = m->dev->bus->dma_configure;
#else
			dma_configure = (void*)(unsigned long)
					kallsyms_lookup_name("dma_configure");
#endif

			if (!dma_configure) {
				dev_err(m->dev,
					"Fail to resolve dma_configure\n");
				return -ENXIO;
			}

			ret = dma_configure(m->dev);
			if (ret) {
				dev_err(m->dev,
					"dma_configure failed %d\n", ret);
				return -EFAULT;
			}
#endif

			dev_info(m->dev, "allocating for device %p %s\n",
				 m->dev, m->dev->kobj.name);
		}

		m->size = (size_t)(vma->vm_end - vma->vm_start);

		m->virt = dma_alloc_coherent(m->dev, m->size, &(m->dma),
					     MV_DMA_ALLOC_FLAGS);
		if (!m->virt) {
			dev_err(m->dev,
				"dma_alloc_coherent failed to allocate 0%x bytes\n",
				(unsigned)m->size);
			return -ENXIO;
		}

		/* If allocated physical address (m->dma) is not aligned with
		   size, which is a Prestera req, for example 0xb0500000 not
		   aligned with 0x200000 do:
		   1. Free DMA
		   2. Alloc (PHY mod size) up to alignment - 0x100000 in our
		      case
		   3. Alloc original size (0x200000)
		   4. free (2)
		   5. Check if aligned */
		if (m->dma % m->size) {
			struct dma_mapping m_1 = *m;
			m_1.size = m->size - ( m->dma % m->size );

			dev_info(m->dev,
				"dma_alloc_coherent is not aligned. Reallocating\n");
			free_dma_block(m);

			m_1.virt = dma_alloc_coherent(m_1.dev, m_1.size,
						      &(m_1.dma),
						      MV_DMA_ALLOC_FLAGS);
			if (!m_1.virt) {
				dev_err(m->dev,
					"dma_alloc_coherent failed to allocate 0%x bytes\n",
					(unsigned) m_1.size);
				return -ENXIO;
			}

			m->virt = dma_alloc_coherent(m->dev, m->size, &(m->dma),
						     MV_DMA_ALLOC_FLAGS);
			free_dma_block(&m_1);
			if (!m->virt) {
				dev_err(m->dev,
					"dma_alloc_coherent failed to allocate 0%x bytes\n",
					(unsigned)m->size);
				return -ENXIO;
			}

			if (m->dma % m->size) {
				dev_err(m->dev,
					"dma_alloc_coherent failed to allocate aligned size of 0x%x for phys0x%lx\n",
					(unsigned)m->size,
					(unsigned long)m->dma);
				free_dma_block(m);
				return -ENXIO;
			}
		}

		dev_info(m->dev, "dma_alloc_coherent virt=%p dma=0x%llx\n",
			 m->virt, (unsigned long long)m->dma);

#ifdef MMAP_USE_REMAP_PFN_RANGE
#if defined(CONFIG_X86) || defined(CONFIG_MIPS)
		m->phys = dma_to_phys(m->dev, m->dma);
#else
		m->phys = (phys_addr_t)m->dma;
#endif
		dev_info(m->dev, "m->phys=0x%llx\n",
			 (unsigned long long)m->phys);
#endif
	}

#ifdef MMAP_USE_REMAP_PFN_RANGE
	/* VM_IO for I/O memory */
	vma->vm_flags |= VM_IO;
	vma->vm_pgoff = m->phys >> PAGE_SHIFT;

	/* If need to disable caching on mapped memory */
	/* vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot); */

	/* TODO: check if write combine support is needed ? */
	/* vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot); */

	dev_info(m->dev,
		 "remap_pfn_range(phys=0x%llx vm_start=0x%llx, vm_pgoff=0x%llx, vm_size=0x%lx)\n",
		 (unsigned long long)m->phys, (unsigned long long)vma->vm_start,
		 (unsigned long long)vma->vm_pgoff, (unsigned long)m->size);

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, m->size,
			    vma->vm_page_prot)) {
		dev_err(m->dev, "remap_pfn_range failed\n");
		return -ENXIO;
	}
#else /* MMAP_USE_REMAP_PFN_RANGE */
	dev_info(m->dev, "dma_mmap_coherent(vma=0x%llx, c=%p, dma=0x%llx, size=0x%llx)\n",
		(unsigned long long)vma->vm_start, m->virt,
		(unsigned long long)m->dma, (unsigned long long)m->size);
	if (dma_mmap_coherent(m->dev, vma, m->virt, m->dma, m->size)) {
		dev_info(m->dev, "dma_mmap_coherent() failed\n");
		return -ENXIO;
	}
#endif /* MMAP_USE_REMAP_PFN_RANGE */

	return 0;
}

static ssize_t mvDmaDrv_read(struct file *f, char *buf, size_t siz, loff_t *off)
{
	struct dma_mapping *m = (struct dma_mapping *)f->private_data;
	unsigned long long dma;

	if (!m)
		return -EFAULT;

	if (siz < sizeof(dma))
		return -EINVAL;

	dma = (unsigned long long)m->dma;

	if (copy_to_user(buf, &dma, sizeof(dma)))
		return -EFAULT;

	return sizeof(dma);
}

static int mvDmaDrv_open(struct inode *inode, struct file *file)
{
	struct dma_mapping *m;

	m = kzalloc(sizeof(struct dma_mapping), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	file->private_data = m;

	printk("%s: %s(file=%p) data=%p\n", MV_DRV_NAME, __func__, file, m);

	return 0;
}

static loff_t mvDmaDrv_lseek(struct file *file, loff_t off, int unused)
{
	struct dma_mapping *m = (struct dma_mapping *)file->private_data;
	struct pci_dev *pdev;
	int domain = (off >> 16) & 0xffff;
	unsigned int bus = (off >> 8) & 0xff;
	unsigned int devfn = PCI_DEVFN(((off >> 3) & 0x1f), (off & 0x07));

	if (!m)
		return -EFAULT;

	if (platdrv_dev) /* device-tree reservation */
		return 0;

	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (pdev) {
		m->dev = &(pdev->dev);
		printk("%s: Using PCI device %s\n", MV_DRV_NAME,
		       m->dev->kobj.name);
	}

	return 0;
}

static int mvDmaDrv_release(struct inode *inode, struct file *file)
{
	struct dma_mapping *m = (struct dma_mapping *)file->private_data;

	printk("%s: %s(file=%p) data=%p\n", MV_DRV_NAME, __func__, file, m);

	if (m != shared_dmaBlock) {
		free_dma_block(m);
		kfree(m);
	}

	return 0;
}

static int mvdmadrv_pdriver_probe(struct platform_device *pdev)
{
	int err;

	err = of_reserved_mem_device_init(&pdev->dev);
	if (err) {
		dev_err(&pdev->dev, "Could not get reserved memory\n");
		return -ENOMEM;
	}

	platdrv_dev = &pdev->dev;

	printk("%s: Using platform device %s\n", MV_DRV_NAME, pdev->name);

	return 0;
};

static int mvdmadrv_pdriver_remove(struct platform_device *pdev)
{
	BUG_ON(!platdrv_registered);

	of_reserved_mem_device_release(&pdev->dev);

	return 0;
}

static const struct of_device_id mvdmadrv_of_match_ids[] = {
	 { .compatible = "marvell,mv_dma", },
};

static struct platform_driver mvdmadrv_platform_driver = {
	.probe		= mvdmadrv_pdriver_probe,
	.remove		= mvdmadrv_pdriver_remove,
	.driver		= {
		.name	= MV_DRV_NAME,
		.of_match_table = mvdmadrv_of_match_ids,
	},
};

static struct file_operations mvDmaDrv_fops = {
	.mmap	= mvDmaDrv_mmap,
	.read	= mvDmaDrv_read,
	.open	= mvDmaDrv_open,
	.llseek	= mvDmaDrv_lseek,
	.release= mvDmaDrv_release /* A.K.A close */
};

static void mvDmaDrv_releaseDrv(void)
{
	if (platdrv_registered)
		platform_driver_unregister(&mvdmadrv_platform_driver);

	if (shared_dmaBlock) {
		free_dma_block(shared_dmaBlock);
		kfree(shared_dmaBlock);
	}
}
static void mvDmaDrv_postInitDrv(void)
{
	int err;

	err = platform_driver_register(&mvdmadrv_platform_driver);
	if (err)
		printk(KERN_ERR "%s: Fail to register platform driver\n",
		       MV_DRV_NAME);
	else
		platdrv_registered = 1;

	printk(KERN_DEBUG "%s: major=%d minor=%d\n", MV_DRV_NAME, major, minor);
}
