/*
 * Copyright (c) 2012 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/balloon.h>
#include "fmr_api.h"
#include "xen_fmr.h"

/* #define STUB_IB_CORE_DRIVER */

MODULE_AUTHOR("Yuval Shaia <yuval.shaia@oracle.com>");
MODULE_DESCRIPTION("XEN FMR API - Backend");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

/* Flags to indicate no xenbus operation until registration completed */
int			m_registered_to_xenbus;
/* Will be use to make sure all Devices were cleaned */
struct ref_count	m_dev_ref_count;
/* Will be use to make sure all VFs were cleaned */
struct ref_count	m_vf_ref_count;
/* Will be use to make sure all mapped pages were unmapped */
struct ref_count	m_map_ref_count;

/**
 * PPF Context initiated in init(), used in map() destroyed in term()
 */
struct xen_master_ppf_ctx {
	struct pci_dev			*pci_dev;
} xen_master_ppf_ctx;

/**
 * reset page count in struct page
 */
void reset_grant_page(struct page *page)
{
	init_page_count(page);
	reset_page_mapcount(page);
}

/**
 * VF Context initiated in add_function(), used in map() destroyed in del_function()
 */
struct xen_master_vf_ctx {
	struct xen_master_ppf_ctx	*ppf_ctx;
} xen_master_vf_ctx;

/**
 * VPM Context initiated in map(), used and destroyed in unmap()
 */
struct xen_master_vpm_ctx {
	dma_addr_t			dma_addr;
	struct page			*pagevec[1]; /* size is always 1 */
	grant_handle_t			handle;
	struct xen_master_vf_ctx	*vf_ctx;
} xen_master_vpm_ctx;

/**
 * Utility to unmap and free page
 */
int mlx_xen_fmr_unmap_page(grant_handle_t handle, struct page **pagevec,
			   int free_page_ind)
{
	int				retval;
	struct gnttab_unmap_grant_ref	unmap_ops;
	struct page			*page;
	phys_addr_t			kaddr;
	unsigned long			pfn;

	page = pagevec[0];
	pfn = page_to_pfn(page);
	kaddr = (phys_addr_t)pfn_to_kaddr(pfn);

	DPRINTK("xen_fmr_master: Unmapping kaddr=%llx, handle=%d\n",
		(unsigned long long)kaddr, handle);

	gnttab_set_unmap_op(&unmap_ops, kaddr, GNTMAP_host_map, handle);
	retval = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
					   &unmap_ops, 1);
	if (retval) {
		printk(KERN_ERR "xen_fmr_master: Fail to unmap err=%d\n",
		       retval);
		return -EINVAL;
	} else if (unmap_ops.status != GNTST_okay) {
		printk(KERN_ERR "xen_fmr_master: Fail to unmap status=%d,"
		       " kaddr=%llx, handle=%d\n", unmap_ops.status,
		       (unsigned long long)kaddr, handle);
		retval = -EFAULT;
	}

	reset_grant_page(page);

	if (free_page_ind) {
		set_phys_to_machine(pfn, INVALID_P2M_ENTRY);
		clear_bit(PG_pinned, &(page->flags));
		free_xenballooned_pages(1, pagevec);
	}

	return retval;
}

/**
 * Called by each HCA device on load
 */
int mlx_xen_fmr_icm_master_init(struct pci_dev *ppf, void **ppf_ctx)
{
	struct xen_master_ppf_ctx	*my_ppf_ctx;

	/* Validate ppf context */
	if (unlikely(ppf == 0))
		printk(KERN_ERR "xen_fmr_master: Warning, got empty"
		       " PPF in icm_master_init\n");

	/* Create and initialize device context */
	my_ppf_ctx = (struct xen_master_ppf_ctx *)
			kmalloc(sizeof(struct xen_master_ppf_ctx), GFP_KERNEL);
	if (my_ppf_ctx == NULL) {
		printk(KERN_ERR "xen_fmr_master: Fail to allocate memory"
		       " for device context\n");
		return -EFAULT;
	}
	my_ppf_ctx->pci_dev = ppf;
	*ppf_ctx = my_ppf_ctx;

	ref_count_inc(&m_dev_ref_count);

	printk(KERN_INFO "xen_fmr_master: FMR-ICM Master Initialized"
	       " for device %d\n", (ppf != 0) ? ppf->devfn : 0);

	return 0;
}

/**
 * Called each time a new vf registers to ppf
 */
int mlx_xen_fmr_icm_master_add_function(void *ppf_ctx,
					struct pci_dev *vf,
					u8 *fmr_info,
					void **vf_ctx)
{
	struct xen_master_vf_ctx	*my_vf_ctx;

	*vf_ctx = 0;

	/* Validate PPF context */
	if (unlikely(ppf_ctx == 0)) {
		printk(KERN_ERR "xen_fmr_master: Error, Got empty PPF context"
		       " in add_function\n");
		return -EFAULT;
	}

	/* Create and initialize VF context */
	my_vf_ctx = kmalloc(sizeof(struct xen_master_vf_ctx), GFP_KERNEL);
	if (my_vf_ctx == NULL) {
		printk("xen_fmr_master: Fail to allocate memory"
		       " for VF context\n");
		return -EFAULT;
	}
	my_vf_ctx->ppf_ctx = (struct xen_master_ppf_ctx *)ppf_ctx;
	*vf_ctx = my_vf_ctx;

	ref_count_inc(&m_vf_ref_count);

	printk(KERN_INFO "xen_fmr_master: FMR-ICM Master Initialized"
	       " for virtual function %d\n",
	       my_vf_ctx->ppf_ctx->pci_dev->devfn);

	return 0;
}

/**
 * Called each time a vf unregisters from ppf
 */
int mlx_xen_fmr_icm_master_del_function(void *vf_ctx)
{
	struct xen_master_vf_ctx	*my_vf_ctx;

	/* Validate VF context */
	if (unlikely(vf_ctx == 0)) {
		printk(KERN_ERR "xen_fmr_master: Error, Got empty VF context"
		       " in del_function\n");
		return -EFAULT;
	}
	my_vf_ctx = (struct xen_master_vf_ctx *)vf_ctx;

	printk(KERN_INFO "xen_fmr_master: FMR-ICM Master terminate virtual"
	       " function %d\n", my_vf_ctx->ppf_ctx->pci_dev->devfn);

	kfree(vf_ctx);

	ref_count_dec(&m_vf_ref_count);

	return 0;
}

/**
 * Map pages using info from vpm and returns ctx handle
 */
dma_addr_t mlx_xen_fmr_icm_master_dma_map(void *vf_ctx, struct vpm *vpm_page,
					  void **vpm_ctx)
{
	struct xen_vpm			*xen_vpm;
	struct gnttab_map_grant_ref	mops;
	struct xen_master_vpm_ctx	*my_vpm_ctx;
	struct xen_master_vf_ctx	*my_vf_ctx;
	struct page			*page;
	dma_addr_t			dma_addr;
	void				*kaddr;

	*vpm_ctx	= NULL;
	page		= NULL;

	/* Validate VPM */
	if (unlikely(vpm_page == 0)) {
		printk(KERN_ERR "xen_fmr_master: Error,"
		       " Got empty VPM Page in dma_map\n");
		return 0;
	}
	xen_vpm = (struct xen_vpm *)(vpm_page);
	DPRINTK("xen_fmr_master: Mapping to page (dom_id=%d,"
		" addr_ref=%ld (0x%llx))\n",
		be16_to_cpu(xen_vpm->dom_id),
		addr_ref_be_to_cpu(xen_vpm->addr_ref),
		addr_ref_be_to_cpu(xen_vpm->addr_ref));

	/* Validate VF context */
	if (unlikely(vf_ctx == 0)) {
		printk(KERN_ERR "xen_fmr_master: Error,"
		       " Got empty VF context in dma_map\n");
		return 0;
	}
	my_vf_ctx = (struct xen_master_vf_ctx *)vf_ctx;

	my_vpm_ctx = (struct xen_master_vpm_ctx *)
			kzalloc(sizeof(xen_master_vpm_ctx), GFP_KERNEL);
	if (!my_vpm_ctx) {
		printk(KERN_ERR "xen_fmr_master: Error,"
                " Failed to allocate vpm context\n");
		return 0;
	}
	/*
	* If slave run in domU then we have to map to addr_ref
	* otherwize addr_ref is the page address
	*/
	if (xen_vpm->dom_id) {
		/* Allocate virtual memory area */
		alloc_xenballooned_pages(1, my_vpm_ctx->pagevec, true);
		if (my_vpm_ctx->pagevec[0] == NULL) {
			printk(KERN_ERR "xen_fmr_master:"
			       " Fail allocate virtual area\n");
			kfree(my_vpm_ctx);
			return 0;
		}
		page = my_vpm_ctx->pagevec[0];
		set_bit(PG_pinned, &(page->flags));
		kaddr = pfn_to_kaddr(page_to_pfn(page));

		/* Map to the shared page */
		gnttab_set_map_op(&mops,
				  (unsigned long)kaddr,
				  GNTMAP_host_map,
				  addr_ref_be_to_cpu(xen_vpm->addr_ref),
				  be16_to_cpu(xen_vpm->dom_id));
		if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
					      &mops, 1)) {
			printk(KERN_ERR "xen_fmr_master: Fail to map to page,"
			       " status=%d gref=0x%lx va=0x%lx\n", mops.status,
			       (unsigned long)addr_ref_be_to_cpu(xen_vpm->addr_ref),
			       (unsigned long)be64_to_cpu(xen_vpm->vpm.va));
			clear_bit(PG_pinned, &(page->flags));
			free_xenballooned_pages(1, my_vpm_ctx->pagevec);
			kfree(my_vpm_ctx);
			return 0;
		}
		DPRINTK("xen_fmr_master: kaddr=%lx, pfn=0x%lx, mfn=0x%lx,"
			" bus_addr=0x%lx\n",
			(unsigned long)kaddr,
			page_to_pfn(page),
			pfn_to_mfn(page_to_pfn(page)),
			(unsigned long)mops.dev_bus_addr);
		set_phys_to_machine(page_to_pfn(page),
				    FOREIGN_FRAME(mops.dev_bus_addr >>
						  PAGE_SHIFT));

		DPRINTK("xen_fmr_master: kaddr=%llx, pfn=0x%lx, mfn=0x%lx,"
			" bus_addr=0x%llx\n",
			(unsigned long long)kaddr,
			page_to_pfn(page),
			pfn_to_mfn(page_to_pfn(page)),
			FOREIGN_FRAME(mops.dev_bus_addr >> PAGE_SHIFT));
		/* SetPageReserved(page); */
	} else {
		kaddr = (void *)addr_ref_be_to_cpu(xen_vpm->addr_ref);
		mops.handle = 0;
	}

#ifndef STUB_IB_CORE_DRIVER
	/* Map DMA */
	dma_addr = dma_map_single(&(my_vf_ctx->ppf_ctx->pci_dev->dev),
				  kaddr,
				  PAGE_SIZE,
				  DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&(my_vf_ctx->ppf_ctx->pci_dev->dev), dma_addr)) {
		printk(KERN_ERR "xen_fmr_master: Fail in map address"
		       " (0x%llx) for DMA\n",
		       (unsigned long long)kaddr);
		mlx_xen_fmr_unmap_page(mops.handle, my_vpm_ctx->pagevec, 1);
		kfree(my_vpm_ctx);
		return 0;
	}
#else
	/* This will be used only on testings where we are not
	    connected to real driver */
	DPRINTK("xen_fmr_master: Fake device\n");
	dma_addr = (dma_addr_t)kaddr;
#endif

	/* Save context to unmap */
	my_vpm_ctx->dma_addr = dma_addr;
	my_vpm_ctx->handle	= mops.handle;
	my_vpm_ctx->vf_ctx	= vf_ctx;
	*vpm_ctx = my_vpm_ctx;

	ref_count_inc(&m_map_ref_count);

	DPRINTK("xen_fmr_master: Mapped kaddr=0x%llx, dma_addr=0x%llx,"
		" handle=%d\n",
	       (unsigned long long)kaddr,
	       (unsigned long long)my_vpm_ctx->dma_addr,
	       my_vpm_ctx->handle);


	return dma_addr;
}

/**
 * Unmap page based on ctx
 */
int mlx_xen_fmr_icm_master_dma_unmap(void *vpm_ctx)
{
	struct xen_master_vpm_ctx	*my_vpm_ctx;
	int				err = 0;

	/* Validate VPM context */
	if (unlikely(vpm_ctx == 0)) {
		printk(KERN_ERR "xen_fmr_master: Error,"
		       " Got empty VPMF context in dma_unmap\n");
		return -EFAULT;
	}
	my_vpm_ctx = (struct xen_master_vpm_ctx *)vpm_ctx;

#ifndef STUB_IB_CORE_DRIVER
	/* Unmap DMA - bus is set to zero in driver stub */
	dma_unmap_single(&(my_vpm_ctx->vf_ctx->ppf_ctx->pci_dev->dev),
			 my_vpm_ctx->dma_addr,
			 PAGE_SIZE,
			 DMA_BIDIRECTIONAL);
#endif

	/* Unmap the page only if we mapped it */
	if (my_vpm_ctx->handle) {
		if (mlx_xen_fmr_unmap_page(my_vpm_ctx->handle,
					   my_vpm_ctx->pagevec, 1) != 0) {
			DPRINTK("xen_fmr_master: Fail to unmap %d\n",
				my_vpm_ctx->handle);
			err = -EFAULT;
		}
	}
	kfree(vpm_ctx);

	ref_count_dec(&m_map_ref_count);

	DPRINTK("xen_fmr_master: Unmapped from addr\n");

	return err;
}

/**
 * Called by each HCA before unload
 */
void mlx_xen_fmr_icm_master_term(void *ppf_ctx)
{
	struct xen_master_ppf_ctx	*my_ppf_ctx;

	/* Validate ppf context */
	if (unlikely(ppf_ctx == 0)) {
		printk(KERN_ERR "xen_fmr_master: Error,"
		       " got empty PPF in icm_master_init\n");
		return;
	}

	my_ppf_ctx = (struct xen_master_ppf_ctx *)ppf_ctx;

	printk(KERN_INFO "xen_fmr_master: FMR-ICM Master"
	       " terminated for device %d\n",
	       my_ppf_ctx->pci_dev->devfn);

	kfree(ppf_ctx);

	ref_count_dec(&m_dev_ref_count);
}

static struct mlx4_icm_master icm_master = {
	.protocol	= FMR_PROTOCOL_XEN,
	.vpm_info_size	= XEN_VPM_SZ,
	.fmr_info_size	= 0,
	.log_page_size	= PAGE_SHIFT,
	.init		= mlx_xen_fmr_icm_master_init,
	.add_function	= mlx_xen_fmr_icm_master_add_function,
	.del_function	= mlx_xen_fmr_icm_master_del_function,
	.dma_map	= mlx_xen_fmr_icm_master_dma_map,
	.dma_unmap	= mlx_xen_fmr_icm_master_dma_unmap,
	.term		= mlx_xen_fmr_icm_master_term
};

/**
 *
 */
static int mlx4_xen_fmr_back_remove(struct xenbus_device *dev)
{
	if (!m_registered_to_xenbus)
		return 0;

	return 0;
}

/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and switch to InitWait.
 */
static int mlx4_xen_fmr_back_probe(struct xenbus_device *dev,
				   const struct xenbus_device_id *id)
{
	if (!m_registered_to_xenbus)
		return 0;

	return 0;
}

/**
 *
 */
static void mlx4_xen_fmr_frontend_changed(struct xenbus_device *dev,
					  enum xenbus_state frontend_state)
{
	if (!m_registered_to_xenbus)
		return;

	DPRINTK("xen_fmr_master: Domain %d change state to %s\n",
		dev->otherend_id, xenbus_strstate(frontend_state));
	DPRINTK("xen_fmr_master: My state is %s\n",
		xenbus_strstate(dev->state));

	if (xenbus_printf(XBT_NIL, dev->nodename, "dom-id", "%d",
			  dev->otherend_id))
		printk(KERN_ERR "xen_fmr_master: Fail to write to xenbus\n");

	mlx4_xen_fmr_switch_state(dev, XenbusStateInitialising);
	mlx4_xen_fmr_switch_state(dev, XenbusStateInitWait);
}

/**
 *
 */
static const struct xenbus_device_id mlx_xen_fmr_back_ids[] = {
	{ XENBUS_DEVID },
	{ "" }
};
static DEFINE_XENBUS_DRIVER(mlx_xen_fmr_back, ,
	.probe			= mlx4_xen_fmr_back_probe,
	.remove			= mlx4_xen_fmr_back_remove,
	.otherend_changed	= mlx4_xen_fmr_frontend_changed
);

/**
 * Initialize module
 */
static int __init mlx4_xen_fmr_backend_init(void)
{
	if (!xen_domain())
		return -ENODEV;

	m_registered_to_xenbus = 0;

	DPRINTK(KERN_INFO "xen_fmr_master: Registering to XENBUS\n");

	if (xenbus_register_backend(&mlx_xen_fmr_back_driver)) {
		printk(KERN_ERR "xen_fmr_master:"
		       " Fail to register to XENBUS\n");
		return -ENODEV;
	}
	m_registered_to_xenbus = 1;

	ref_count_init(&m_dev_ref_count);
	ref_count_init(&m_vf_ref_count);
	ref_count_init(&m_map_ref_count);

	DPRINTK(KERN_INFO "xen_fmr_master: Registering to ICM\n");
	if (mlx4_reg_icm_master(&icm_master) != 0) {
		printk(KERN_ERR "xen_fmr_master: Fail to register to ICM\n");
		return -ENODEV;
	}

	printk(KERN_INFO "xen_fmr_master: Initialized\n");

	return 0;
}

/**
 * Terminate module
 */
static void __exit mlx4_xen_fmr_backend_exit(void)
{
	DPRINTK(KERN_INFO "xen_fmr_master: Going down\n");

	DPRINTK(KERN_INFO "xen_fmr_master: Unregistering from ICM\n");
	mlx4_unreg_icm_master(&icm_master);

	DPRINTK(KERN_INFO "xen_fmr_master: Verify sharings %d\n",
		m_map_ref_count.var);
	ref_count_wait_for_zero(&m_map_ref_count);
	DPRINTK(KERN_INFO "xen_fmr_master: Verify VFs %d\n",
		m_vf_ref_count.var);
	ref_count_wait_for_zero(&m_vf_ref_count);
	DPRINTK(KERN_INFO "xen_fmr_master: Verify Devices %d\n",
		m_dev_ref_count.var);
	ref_count_wait_for_zero(&m_dev_ref_count);

	DPRINTK(KERN_INFO "xen_fmr_master: Unregistering from XENBUS\n");
	xenbus_unregister_driver(&mlx_xen_fmr_back_driver);

	printk(KERN_INFO "xen_fmr_master: Terminated\n");
}

module_init(mlx4_xen_fmr_backend_init);
module_exit(mlx4_xen_fmr_backend_exit);
