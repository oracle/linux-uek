// SPDX-License-Identifier: GPL-2.0
#include <linux/highmem.h>
#include <linux/crash_dump.h>
#include <linux/errno.h>
#include <linux/io.h>
/**
 * copy_oldmem_page - copy one page from "oldmem"
 * @pfn: page frame number to be copied
 * @buf: target memory address for the copy; this can be in kernel address
 *	space or user address space (see @userbuf)
 * @csize: number of bytes to copy
 * @offset: offset in bytes into the page (based on pfn) to begin the copy
 * @userbuf: if set, @buf is in user address space, use copy_to_user(),
 *	otherwise @buf is in kernel address space, use memcpy().
 *
 * Copy a page from "oldmem". For this page, there is no pte mapped
 * in the current kernel.
 */
ssize_t copy_oldmem_page(unsigned long pfn, char *buf,
			 size_t csize, unsigned long offset, int userbuf)
{
	void  *vaddr;

	if (!csize)
		return 0;

	vaddr = ioremap(pfn << PAGE_SHIFT, PAGE_SIZE);

	if (!userbuf) {
		memcpy(buf, vaddr + offset, csize);
		iounmap(vaddr);
	} else {
		if (copy_to_user(buf, vaddr + offset, csize))
			csize = -EFAULT;
	}

	iounmap(vaddr);
	return csize;
}
