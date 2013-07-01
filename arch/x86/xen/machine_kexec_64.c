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

#include <xen/interface/memory.h>
#include <xen/xen.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/kexec.h>
#include <asm/xen/page.h>

#define __ma(vaddr)	(virt_to_machine(vaddr).maddr)

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

static void init_level2_page(pmd_t *pmd, unsigned long addr)
{
	unsigned long end_addr = addr + PUD_SIZE;

	while (addr < end_addr) {
		native_set_pmd(pmd++, native_make_pmd(addr | __PAGE_KERNEL_LARGE_EXEC));
		addr += PMD_SIZE;
	}
}

static int init_level3_page(struct kimage *image, pud_t *pud,
				unsigned long addr, unsigned long last_addr)
{
	pmd_t *pmd;
	struct page *page;
	unsigned long end_addr = addr + PGDIR_SIZE;

	while ((addr < last_addr) && (addr < end_addr)) {
		page = kimage_alloc_control_pages(image, 0);

		if (!page)
			return -ENOMEM;

		pmd = page_address(page);
		init_level2_page(pmd, addr);
		native_set_pud(pud++, native_make_pud(__ma(pmd) | _KERNPG_TABLE));
		addr += PUD_SIZE;
	}

	/* Clear the unused entries. */
	while (addr < end_addr) {
		native_pud_clear(pud++);
		addr += PUD_SIZE;
	}

	return 0;
}


static int init_level4_page(struct kimage *image, pgd_t *pgd,
				unsigned long addr, unsigned long last_addr)
{
	int rc;
	pud_t *pud;
	struct page *page;
	unsigned long end_addr = addr + PTRS_PER_PGD * PGDIR_SIZE;

	while ((addr < last_addr) && (addr < end_addr)) {
		page = kimage_alloc_control_pages(image, 0);

		if (!page)
			return -ENOMEM;

		pud = page_address(page);
		rc = init_level3_page(image, pud, addr, last_addr);

		if (rc)
			return rc;

		native_set_pgd(pgd++, native_make_pgd(__ma(pud) | _KERNPG_TABLE));
		addr += PGDIR_SIZE;
	}

	/* Clear the unused entries. */
	while (addr < end_addr) {
		native_pgd_clear(pgd++);
		addr += PGDIR_SIZE;
	}

	return 0;
}

static void free_transition_pgtable(struct kimage *image)
{
	free_page((unsigned long)image->arch.pgd);
	free_page((unsigned long)image->arch.pud0);
	free_page((unsigned long)image->arch.pud1);
	free_page((unsigned long)image->arch.pmd0);
	free_page((unsigned long)image->arch.pmd1);
	free_page((unsigned long)image->arch.pte0);
	free_page((unsigned long)image->arch.pte1);
}

static int alloc_transition_pgtable(struct kimage *image)
{
	image->arch.pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pgd)
		goto err;

	image->arch.pud0 = (pud_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pud0)
		goto err;

	image->arch.pud1 = (pud_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pud1)
		goto err;

	image->arch.pmd0 = (pmd_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pmd0)
		goto err;

	image->arch.pmd1 = (pmd_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pmd1)
		goto err;

	image->arch.pte0 = (pte_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pte0)
		goto err;

	image->arch.pte1 = (pte_t *)get_zeroed_page(GFP_KERNEL);

	if (!image->arch.pte1)
		goto err;

	return 0;

err:
	free_transition_pgtable(image);

	return -ENOMEM;
}

static int init_pgtable(struct kimage *image, pgd_t *pgd)
{
	int rc;
	unsigned long max_mfn;

	max_mfn = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);

	rc = init_level4_page(image, pgd, 0, PFN_PHYS(max_mfn));

	if (rc)
		return rc;

	return alloc_transition_pgtable(image);
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

	return init_pgtable(image, page_address(image->control_code_page));
}

static int machine_xen_kexec_load(struct kimage *image)
{
	void *control_page, *table_page;
	struct xen_kexec_load xkl = {};

	/* Image is unloaded, nothing to do. */
	if (!image)
		return 0;

	table_page = page_address(image->control_code_page);
	control_page = table_page + PAGE_SIZE;

	memcpy(control_page, xen_relocate_kernel, xen_kexec_control_code_size);

	xkl.type = image->type;
	xkl.image.page_list[XK_MA_CONTROL_PAGE] = __ma(control_page);
	xkl.image.page_list[XK_MA_TABLE_PAGE] = __ma(table_page);
	xkl.image.page_list[XK_MA_PGD_PAGE] = __ma(image->arch.pgd);
	xkl.image.page_list[XK_MA_PUD0_PAGE] = __ma(image->arch.pud0);
	xkl.image.page_list[XK_MA_PUD1_PAGE] = __ma(image->arch.pud1);
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
	free_transition_pgtable(image);
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
