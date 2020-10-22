
/*
 * Copyright (c) 2018, Pensando Systems Inc.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include "capmem_dev.h"

#define PFX			CAPMEM_NAME ": "

/*
 * Memory range information provided by U-Boot
 * Syntax:
 *      start-end:type[,start-end:type]
 *          start:  hex start address (no 0x prefix)
 *          end:    hex end address (inclusive)
 *          type:   address space type: coherent | noncoherent
 * Eg:
 *      ranges=c0000000-c3f00000:coherent,c8000000-13fffffff:noncoherent
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
		break;

	case CAPMEM_TYPE_NONCOHERENT:
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

static long cap_mem_unlocked_ioctl(struct file *file,
		unsigned int cmd, unsigned long arg)
{
	void __user *p = (void __user *)arg;
	struct capmem_range __user *rp;
	struct capmem_ranges_args gr;
	int i;

	switch (cmd) {
	case CAPMEM_GET_NRANGES:
		return put_user(nmem_ranges, (int __user *)p);

	case CAPMEM_GET_RANGES:
		if (copy_from_user(&gr, p, sizeof (gr)))
			return -EFAULT;
		rp = (struct capmem_range __user *)gr.range;
		for (i = 0; i < gr.nranges; i++) {
			if (i >= nmem_ranges)
				return i;
			if (copy_to_user(rp, &mem_range[i], sizeof (*rp)))
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

static int __init parse_memory_ranges(char *s)
{
	uint64_t start, end, len;
	char *p, *q;
	int r, type;

	if (!s)
		return 0;

	while ((p = strsep(&s, ",")) != NULL) {
		if (nmem_ranges == CAPMEM_MAX_RANGES) {
			printk(KERN_ERR PFX "too many ranges\n");
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
	printk(KERN_ERR PFX "invalid range syntax\n");
	return -EINVAL;
}

/*
 * Device space is mapped out here.
 */
static const struct {
	uint64_t start;
	uint64_t len;
} init_device_ranges[] = {
	{ 0x00000000, 0x80000000 },
};

static int __init cap_mem_init(void)
{
	int i, r;

	printk(KERN_INFO PFX "capmem driver loading\n");
	for (i = 0; i < ARRAY_SIZE(init_device_ranges); i++) {
		capmem_add_range(init_device_ranges[i].start,
				 init_device_ranges[i].len,
				 CAPMEM_TYPE_DEVICE);
	}
	r = parse_memory_ranges(ranges);
	if (r)
		return r;
	return misc_register(&cap_mem_dev);
}

static void __exit cap_mem_cleanup(void)
{
	printk(KERN_INFO PFX "capmem driver unloading\n");
	misc_deregister(&cap_mem_dev);
}

module_init(cap_mem_init);
module_exit(cap_mem_cleanup);
MODULE_DESCRIPTION("Pensando SoC Memory Driver");
MODULE_LICENSE("GPL");
