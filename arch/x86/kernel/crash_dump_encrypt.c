// SPDX-License-Identifier: GPL-2.0
/*
 *	Memory preserving reboot related code.
 *
 *	Created by: Lianbo Jiang (lijiang@redhat.com)
 *	Copyright (C) RedHat Corporation, 2018. All rights reserved
 */

#include <linux/errno.h>
#include <linux/crash_dump.h>
#include <linux/uaccess.h>
#include <linux/io.h>

/**
 * copy_oldmem_page_encrypted - copy one page from "oldmem encrypted"
 * @pfn: page frame number to be copied
 * @buf: target memory address for the copy; this can be in kernel address
 *	space or user address space (see @userbuf)
 * @csize: number of bytes to copy
 * @offset: offset in bytes into the page (based on pfn) to begin the copy
 * @userbuf: if set, @buf is in user address space, use copy_to_user(),
 *	otherwise @buf is in kernel address space, use memcpy().
 *
 * Copy a page from "oldmem encrypted". For this page, there is no pte
 * mapped in the current kernel. We stitch up a pte, similar to
 * kmap_atomic.
 */

ssize_t copy_oldmem_page_encrypted(unsigned long pfn, char *buf,
		size_t csize, unsigned long offset, int userbuf)
{
	void  *vaddr;

	if (!csize)
		return 0;

	vaddr = (__force void *)ioremap_encrypted(pfn << PAGE_SHIFT,
						  PAGE_SIZE);
	if (!vaddr)
		return -ENOMEM;

	if (userbuf) {
		if (copy_to_user((void __user *)buf, vaddr + offset, csize)) {
			iounmap((void __iomem *)vaddr);
			return -EFAULT;
		}
	} else
		memcpy(buf, vaddr + offset, csize);

	set_iounmap_nonlazy();
	iounmap((void __iomem *)vaddr);
	return csize;
}
