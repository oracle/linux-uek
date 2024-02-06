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

#define DSC_MEM_ATTR_COHERENT	0x1	// Memory range is coherent

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
		vma->vm_flags |= VM_IO;
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

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}

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
			sizeof (entries) / sizeof (u32));
	if (n < 0) {
		return -ENOENT;
	}
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

static int capmem_remove(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "Unloading capmem driver\n");
	misc_deregister(&cap_mem_dev);
	return 0;
}

static struct of_device_id capmem_of_match[] = {
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
