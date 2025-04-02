// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018-2022, Pensando Systems Inc.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/sort.h>
#include <linux/pfn_t.h>
#include <dt-bindings/soc/pensando,capmem.h>
#include "capmem_dev.h"

#define CREATE_TRACE_POINTS
#include "cap_tracepoint.h"

#define CAPMEM_REGION_ALIGN		PMD_SIZE

/* page entry size for vm->huge_fault() */
enum page_entry_size {
	PE_SIZE_PTE = 0,
	PE_SIZE_PMD,
	PE_SIZE_PUD,
};

/*
 * Memory range information provided by U-Boot on the kernel commandline:
 * Syntax:
 *	start-end:type[,start-end:type]
 *	    start:  hex start address (no 0x prefix)
 *	    end:    hex end address (inclusive)
 *	    type:   address space type: coherent | noncoherent
 * Eg:
 *	capmem=c0000000-c3f00000:coherent,c8000000-13fffffff:noncoherent
 *
 * Only address ranges specified are allowed to be mapped.
 */
static char *ranges;
#ifdef MODULE
module_param(ranges, charp, 0);
#else
static int __init capmem_setup(char *s)
{
	ranges = s;
	return 0;
}
__setup("capmem=", capmem_setup);
#endif

static struct capmem_range mem_range[CAPMEM_MAX_RANGES];
static int nmem_ranges;

static int capmem_add_range(uint64_t start, uint64_t len, int type)
{
	struct capmem_range *p = &mem_range[nmem_ranges];

	if (nmem_ranges == CAPMEM_MAX_RANGES)
		return -ENOMEM;
	p->start = start;
	p->len = len;
	p->type = type;
	++nmem_ranges;
	return 0;
}

#ifdef CONFIG_PENSANDO_SOC_CAPMEM_HUGEPAGE
static vm_fault_t cap_mem_pte_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	phys_addr_t phys;
	pgoff_t pgoff;
	vm_fault_t rc;

	trace_cap_mem_pte_fault(vma, vmf);

	pgoff = vmf->pgoff;
	phys = PFN_PHYS(pgoff);

	trace_cap_mem_vmf_insert_pfn_pte(vma, vmf, phys);

	rc = vmf_insert_pfn(vma, vmf->address, PFN_DOWN(phys));
	if (rc == -ENOMEM)
		return VM_FAULT_OOM;
	if (rc < 0 && rc != -EBUSY)
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

static vm_fault_t cap_mem_pmd_fault(struct vm_fault *vmf)
{
	unsigned long pmd_addr = vmf->address & PMD_MASK;
	struct vm_area_struct *vma = vmf->vma;
	phys_addr_t phys;
	pgoff_t pgoff;
	pfn_t pfn;

	trace_cap_mem_pmd_fault(vma, vmf);

	if (pmd_addr < vma->vm_start || (pmd_addr + PMD_SIZE) > vma->vm_end)
		return VM_FAULT_FALLBACK;

	pgoff = linear_page_index(vma, pmd_addr);
	phys = PFN_PHYS(pgoff);

	if (!IS_ALIGNED(phys, PMD_SIZE))
		return VM_FAULT_FALLBACK;

	trace_cap_mem_vmf_insert_pfn_pmd(vma, vmf, phys);

	pfn = phys_to_pfn_t(phys, PFN_DEV|PFN_MAP);

	return vmf_insert_pfn_pmd(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static vm_fault_t cap_mem_pud_fault(struct vm_fault *vmf)
{
	unsigned long pud_addr = vmf->address & PUD_MASK;
	struct vm_area_struct *vma = vmf->vma;
	phys_addr_t phys;
	pgoff_t pgoff;
	pfn_t pfn;

	trace_cap_mem_pud_fault(vma, vmf);

	if (pud_addr < vma->vm_start || (pud_addr + PUD_SIZE) > vma->vm_end)
		return VM_FAULT_FALLBACK;

	pgoff = linear_page_index(vma, pud_addr);
	phys = PFN_PHYS(pgoff);

	if (!IS_ALIGNED(phys, PUD_SIZE))
		return VM_FAULT_FALLBACK;

	trace_cap_mem_vmf_insert_pfn_pud(vma, vmf, phys);

	pfn = phys_to_pfn_t(phys, PFN_DEV|PFN_MAP);

	return vmf_insert_pfn_pud(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
}
#else
static vm_fault_t cap_mem_pud_fault(struct vm_fault *vmf)
{
	return VM_FAULT_FALLBACK;
}
#endif /* !CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */

static vm_fault_t cap_mem_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	vm_fault_t rc;

	trace_cap_mem_fault_enter(vmf->vma, vmf);

	switch (pe_size) {
	case PE_SIZE_PTE:
		rc = cap_mem_pte_fault(vmf);
		break;
	case PE_SIZE_PMD:
		rc = cap_mem_pmd_fault(vmf);
		break;
	case PE_SIZE_PUD:
		rc = cap_mem_pud_fault(vmf);
		break;
	default:
		rc = VM_FAULT_SIGBUS;
	}

	trace_cap_mem_fault_exit(vmf->vma, vmf);

	return rc;
}

static vm_fault_t cap_mem_fault(struct vm_fault *vmf)
{
	return cap_mem_huge_fault(vmf, PE_SIZE_PTE);
}

static int cap_mem_may_split(struct vm_area_struct *vma, unsigned long addr)
{
	return -EINVAL;
}

static const struct vm_operations_struct cap_mem_vm_ops = {
	.fault = cap_mem_fault,
	.huge_fault = cap_mem_huge_fault,
	.may_split = cap_mem_may_split,
};

static unsigned long cap_mem_get_unmapped_area(struct file *filp,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	unsigned long off, len_align, addr_align, align;

	align = PAGE_SIZE;
	off = pgoff << PAGE_SHIFT;

	if (len >= PMD_SIZE && IS_ALIGNED(off, PMD_SIZE))
		align = PMD_SIZE;

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
	if (len >= PUD_SIZE && IS_ALIGNED(off, PUD_SIZE))
		align = PUD_SIZE;
#endif

	trace_cap_mem_get_unmapped_area_enter(addr, len, pgoff, align);

	if (align == PAGE_SIZE)
		goto out;

	len_align = len + align;

	addr = current->mm->get_unmapped_area(filp, addr, len_align, pgoff, flags);
	if (!IS_ERR_VALUE(addr)) {
		addr_align = round_up(addr, align);
		trace_cap_mem_get_unmapped_area_exit(addr_align, len_align, pgoff, align);
		return addr_align;
	}

out:
	addr = current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
	trace_cap_mem_get_unmapped_area_exit(addr, len, pgoff, align);
	return addr;
}
#endif

static int cap_mem_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	phys_addr_t p_start = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
	phys_addr_t p_end = p_start + size - 1;
	pgprot_t pgprot = vma->vm_page_prot;
	int i;

	// range cannot wrap
	if (p_end <= p_start)
		return -EINVAL;

	// must be MAP_SHARED
	if (!(vma->vm_flags & VM_MAYSHARE))
		return -EINVAL;

	// find permitted range
	for (i = 0; i < nmem_ranges; i++)
		if (p_start >= mem_range[i].start &&
		    p_end < (mem_range[i].start + mem_range[i].len))
			break;
	if (i == nmem_ranges)
		return -EPERM;

	switch (mem_range[i].type) {
	case CAPMEM_TYPE_DEVICE:
		/* register space must be device-mapped */
		pgprot = pgprot_device(pgprot);
		vm_flags_set(vma, VM_IO);
		break;

	case CAPMEM_TYPE_NONCOHERENT:
	case CAPMEM_TYPE_BYPASS:
		/*
		 * An inner shareable cached mapping on a noncoherence range
		 * is invalid, so only accept non-cached mapping requests.
		 */
		if (!(file->f_flags & O_SYNC))
			return -EINVAL;
		pgprot = pgprot_writecombine(pgprot);
		break;

	default:
		// CAPMEM_TYPE_COHERENT - default inner shareable mapping
		break;
	}

	/*
	 * Clear the RDONLY bit and set the DIRTY bit to bypass the
	 * kernel's clean/dirty page tracking, which uses a page fault on
	 * first write behavior, which is undesirable for performance.
	 */
	if (vma->vm_flags & VM_WRITE)
		pgprot = __pgprot_modify(pgprot, PTE_RDONLY, PTE_DIRTY);

	vma->vm_page_prot = pgprot;

#ifdef CONFIG_PENSANDO_SOC_CAPMEM_HUGEPAGE
	vma->vm_ops = &cap_mem_vm_ops;
	vm_flags_set(vma, VM_PFNMAP | VM_HUGEPAGE | VM_DONTEXPAND | VM_DONTDUMP);
#else
	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}
#endif

	return 0;
}

/*
 * Map a capmem range type to a legacy type for v1 commands
 */
static int compat_range_type(unsigned int cmd, int type)
{
	if (cmd == CAPMEM_GET_RANGES && type == CAPMEM_TYPE_BYPASS)
		return CAPMEM_TYPE_NONCOHERENT;
	else
		return type;
}

static long cap_mem_unlocked_ioctl(struct file *file,
		unsigned int cmd, unsigned long arg)
{
	void __user *p = (void __user *)arg;
	struct capmem_range __user *rp;
	struct capmem_ranges_args gr;
	struct capmem_range range;
	int i;

	switch (cmd) {
	case CAPMEM_GET_NRANGES:
		return put_user(nmem_ranges, (int __user *)p);

	case CAPMEM_GET_RANGES:
	case CAPMEM_GET_RANGES2:
		if (copy_from_user(&gr, p, sizeof(gr)))
			return -EFAULT;
		rp = (struct capmem_range __user *)gr.range;
		for (i = 0; i < gr.nranges; i++) {
			if (i >= nmem_ranges)
				return i;
			range = mem_range[i];
			range.type = compat_range_type(cmd, range.type);
			if (copy_to_user(rp, &range, sizeof(*rp)))
				return -EFAULT;
			++rp;
		}
		return i;

	default:
		return -ENOTTY;
	}
}

const struct file_operations cap_mem_fops = {
	.owner		= THIS_MODULE,
	.mmap		= cap_mem_mmap,
	.unlocked_ioctl	= cap_mem_unlocked_ioctl,
#ifdef CONFIG_PENSANDO_SOC_CAPMEM_HUGEPAGE
	.get_unmapped_area = cap_mem_get_unmapped_area,
#endif
};

static struct miscdevice cap_mem_dev = {
	MISC_DYNAMIC_MINOR,
	CAPMEM_NAME,
	&cap_mem_fops
};

static int __init parse_memory_ranges(struct platform_device *pdev, char *s)
{
	uint64_t start, end, len;
	char *p, *q;
	int r, type;

	if (!s)
		return 0;

	while ((p = strsep(&s, ",")) != NULL) {
		if (nmem_ranges == CAPMEM_MAX_RANGES) {
			dev_err(&pdev->dev, "too many ranges\n");
			return -ENODEV;
		}
		q = strchr(p, ':');
		if (!q)
			goto syntax;
		*q++ = '\0';
		if (sscanf(p, "%llx-%llx", &start, &end) != 2)
			goto syntax;
		if (end <= start)
			goto syntax;
		if (strcmp(q, "coherent") == 0)
			type = CAPMEM_TYPE_COHERENT;
		else if (strcmp(q, "noncoherent") == 0)
			type = CAPMEM_TYPE_NONCOHERENT;
		else
			goto syntax;
		len = end - start + 1;
		r = capmem_add_range(start, len, type);
		if (r)
			return r;
	}
	return 0;
syntax:
	dev_err(&pdev->dev, "invalid range syntax\n");
	return -EINVAL;
}

/*
 * Load ranges from the device-tree
 * Each range row comprises 5 words:
 *	<start_hi start_lo size_hi size_lo attr>
 *	attr is { unused:29, device:1, bypass:1, coherent:1 }
 */
static int load_of_ranges(struct platform_device *pdev, const char *pname)
{
	u32 entries[CAPMEM_MAX_RANGES][5];
	int r, n, i, type;
	u64 start, len;
	u32 attr;

	n = of_property_read_variable_u32_array(pdev->dev.of_node,
			pname, (u32 *)entries, 0,
			sizeof(entries) / sizeof(u32));
	if (n < 0)
		return -ENOENT;

	if (n % 5 != 0) {
		dev_err(&pdev->dev, "of %s invalid\n", pname);
		return -ENODEV;
	}
	n /= 5;
	for (i = 0; i < n; i++) {
		attr = entries[i][4];
		if (attr & DSC_MEM_ATTR_DEVICE)
			type = CAPMEM_TYPE_DEVICE;
		else if (attr & DSC_MEM_ATTR_BYPASS)
			type = CAPMEM_TYPE_BYPASS;
		else if (attr & DSC_MEM_ATTR_COHERENT)
			type = CAPMEM_TYPE_COHERENT;
		else
			type = CAPMEM_TYPE_NONCOHERENT;
		start = ((u64)entries[i][0] << 32) | entries[i][1];
		len   = ((u64)entries[i][2] << 32) | entries[i][3];
		r = capmem_add_range(start, len, type);
		if (r)
			return r;
	}
	return 0;
}

static int cmp_ranges(const void *a, const void *b)
{
	const struct capmem_range *r1 = a;
	const struct capmem_range *r2 = b;

	if (r1->start == r2->start)
		return 0;
	else
		return (r1->start < r2->start) ? -1 : 1;
}

static int capmem_probe(struct platform_device *pdev)
{
	int r;

	dev_info(&pdev->dev, "Loading capmem driver\n");

	/* load the fixed ranges from the device-tree */
	r = load_of_ranges(pdev, "pensando,capmem-fixed-ranges");
	if (r == -ENOENT)
		return r;

	/*
	 * load the ranges installed by u-boot; either in the device-tree
	 * or provided as a module parameter.
	 */
	r = load_of_ranges(pdev, "pensando,capmem-ranges");
	if (r == -ENOENT) {
		/* fallback to the capmem= variable */
		r = parse_memory_ranges(pdev, ranges);
		if (r)
			return r;
	}

	/*
	 * Sort ranges by ascending physical address.
	 */
	sort(mem_range, nmem_ranges, sizeof(mem_range[0]), cmp_ranges, NULL);

	return misc_register(&cap_mem_dev);
}

static void capmem_remove(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "Unloading capmem driver\n");
	misc_deregister(&cap_mem_dev);
}

static const struct of_device_id capmem_of_match[] = {
	{ .compatible = "pensando,capmem" },
	{ /* end of table */ }
};

static struct platform_driver capmem_driver = {
	.probe = capmem_probe,
	.remove = capmem_remove,
	.driver = {
		.name = "capmem",
		.owner = THIS_MODULE,
		.of_match_table = capmem_of_match,
	},
};

module_platform_driver(capmem_driver);
MODULE_DESCRIPTION("Pensando SoC Memory Driver");
MODULE_LICENSE("GPL");
