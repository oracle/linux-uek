/*
 * Copyright (c) 2011 Daniel Kiper
 * Copyright (c) 2012 Daniel Kiper, Oracle Corporation
 *
 * kexec/kdump implementation for Xen was written by Daniel Kiper.
 * Initial work on it was sponsored by Google under Google Summer
 * of Code 2011 program and Citrix. Konrad Rzeszutek Wilk from Oracle
 * was the mentor for this project.
 *
 * Some ideas are taken from:
 *   - native kexec/kdump implementation,
 *   - kexec/kdump implementation for Xen Linux Kernel Ver. 2.6.18,
 *   - PV-GRUB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <xen/xen.h>
#include <xen/xen-ops.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/kexec.h>
#include <asm/xen/page.h>

#define __ma(vaddr)	(virt_to_machine(vaddr).maddr)

static struct page *kimage_alloc_pages(gfp_t gfp_mask,
					unsigned int order,
					unsigned long limit)
{
	struct page *pages;
	unsigned int address_bits, i;

	pages = alloc_pages(gfp_mask, order);

	if (!pages)
		return NULL;

	address_bits = (limit == ULONG_MAX) ? BITS_PER_LONG : ilog2(limit);

	/* Relocate set of pages below given limit. */
	if (xen_create_contiguous_region((unsigned long)page_address(pages),
							order, address_bits)) {
		__free_pages(pages, order);
		return NULL;
	}

	BUG_ON(PagePrivate(pages));

	pages->mapping = NULL;
	set_page_private(pages, order);

	for (i = 0; i < (1 << order); ++i)
		SetPageReserved(pages + i);

	return pages;
}

static void kimage_free_pages(struct page *page)
{
	unsigned int i, order;

	order = page_private(page);

	for (i = 0; i < (1 << order); ++i)
		ClearPageReserved(page + i);

	xen_destroy_contiguous_region((unsigned long)page_address(page), order);
	__free_pages(page, order);
}

static unsigned long xen_page_to_mfn(struct page *page)
{
	return pfn_to_mfn(page_to_pfn(page));
}

static struct page *xen_mfn_to_page(unsigned long mfn)
{
	return pfn_to_page(mfn_to_pfn(mfn));
}

static unsigned long xen_virt_to_machine(volatile void *address)
{
	return virt_to_machine(address).maddr;
}

static void *xen_machine_to_virt(unsigned long address)
{
	return phys_to_virt(machine_to_phys(XMADDR(address)).paddr);
}

static void *alloc_pgtable_page(struct kimage *image)
{
	struct page *page;

	page = kimage_alloc_control_pages(image, 0);

	if (!page || !page_address(page))
		return NULL;

	memset(page_address(page), 0, PAGE_SIZE);

	return page_address(page);
}

static int alloc_transition_pgtable(struct kimage *image)
{
	image->arch.pgd = alloc_pgtable_page(image);

	if (!image->arch.pgd)
		return -ENOMEM;

	image->arch.pmd0 = alloc_pgtable_page(image);

	if (!image->arch.pmd0)
		return -ENOMEM;

	image->arch.pmd1 = alloc_pgtable_page(image);

	if (!image->arch.pmd1)
		return -ENOMEM;

	image->arch.pte0 = alloc_pgtable_page(image);

	if (!image->arch.pte0)
		return -ENOMEM;

	image->arch.pte1 = alloc_pgtable_page(image);

	if (!image->arch.pte1)
		return -ENOMEM;

	return 0;
}

static int machine_xen_kexec_prepare(struct kimage *image)
{
#ifdef CONFIG_KEXEC_JUMP
	if (image->preserve_context) {
		pr_info_once("kexec: Context preservation is not "
				"supported in Xen domains.\n");
		return -ENOSYS;
	}
#endif

	return alloc_transition_pgtable(image);
}

static int machine_xen_kexec_load(struct kimage *image)
{
	void *control_page;
	struct xen_kexec_load xkl = {};

	/* Image is unloaded, nothing to do. */
	if (!image)
		return 0;

	control_page = page_address(image->control_code_page);
	memcpy(control_page, xen_relocate_kernel, xen_kexec_control_code_size);

	xkl.type = image->type;
	xkl.image.page_list[XK_MA_CONTROL_PAGE] = __ma(control_page);
	xkl.image.page_list[XK_MA_TABLE_PAGE] = 0; /* Unused. */
	xkl.image.page_list[XK_MA_PGD_PAGE] = __ma(image->arch.pgd);
	xkl.image.page_list[XK_MA_PUD0_PAGE] = 0; /* Unused. */
	xkl.image.page_list[XK_MA_PUD1_PAGE] = 0; /* Unused. */
	xkl.image.page_list[XK_MA_PMD0_PAGE] = __ma(image->arch.pmd0);
	xkl.image.page_list[XK_MA_PMD1_PAGE] = __ma(image->arch.pmd1);
	xkl.image.page_list[XK_MA_PTE0_PAGE] = __ma(image->arch.pte0);
	xkl.image.page_list[XK_MA_PTE1_PAGE] = __ma(image->arch.pte1);
	xkl.image.indirection_page = image->head;
	xkl.image.start_address = image->start;

	return HYPERVISOR_kexec_op(KEXEC_CMD_kexec_load, &xkl);
}

static void machine_xen_kexec_cleanup(struct kimage *image)
{
}

static void machine_xen_kexec_unload(struct kimage *image)
{
	int rc;
	struct xen_kexec_load xkl = {};

	if (!image)
		return;

	xkl.type = image->type;
	rc = HYPERVISOR_kexec_op(KEXEC_CMD_kexec_unload, &xkl);

	WARN(rc, "kexec: %s: HYPERVISOR_kexec_op(): %i\n", __func__, rc);
}

static void machine_xen_kexec_shutdown(void)
{
}

static void machine_xen_kexec(struct kimage *image)
{
	int rc;
	struct xen_kexec_exec xke = {};

	xke.type = image->type;
	rc = HYPERVISOR_kexec_op(KEXEC_CMD_kexec, &xke);

	pr_emerg("kexec: %s: HYPERVISOR_kexec_op(): %i\n", __func__, rc);
	BUG();
}

void __init xen_init_kexec_ops(void)
{
	if (!xen_initial_domain())
		return;

	kexec_ops.crash_alloc_temp_store = true;
	kexec_ops.kimage_alloc_pages = kimage_alloc_pages;
	kexec_ops.kimage_free_pages = kimage_free_pages;
	kexec_ops.page_to_pfn = xen_page_to_mfn;
	kexec_ops.pfn_to_page = xen_mfn_to_page;
	kexec_ops.virt_to_phys = xen_virt_to_machine;
	kexec_ops.phys_to_virt = xen_machine_to_virt;
	kexec_ops.machine_kexec_prepare = machine_xen_kexec_prepare;
	kexec_ops.machine_kexec_load = machine_xen_kexec_load;
	kexec_ops.machine_kexec_cleanup = machine_xen_kexec_cleanup;
	kexec_ops.machine_kexec_unload = machine_xen_kexec_unload;
	kexec_ops.machine_kexec_shutdown = machine_xen_kexec_shutdown;
	kexec_ops.machine_kexec = machine_xen_kexec;
}
