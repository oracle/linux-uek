/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Softare Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <asm/asi.h>
#include <asm/adi_64.h>
#include <asm/page.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include "adi.h"
#include "internal.h"

#define MAX_TAG_VERSION ((1 << adi_nbits()) - 1)

static inline void _membar_sync(void)
{
	asm volatile("membar #Sync\n\t");
}

static ssize_t _adi_tag_rw(char *vaddr, unsigned long voffset, ssize_t len,
			   char __user *buf, ssize_t pagesize, int write)
{
	ssize_t copied = 0;
	unsigned char tag;
	unsigned long adi_blksz = adi_blksize();

	if (!adi_blksz)
		return -ENOENT;

	while ((len > copied) && (voffset != pagesize)) {
		if (write) {
			if (copy_from_user(&tag, buf + copied, 1)) {
				copied = -EFAULT;
				break;
			}
			if (tag > MAX_TAG_VERSION) {
				copied = -EINVAL;
				break;
			}
			adi_set_version(vaddr + voffset, tag);
		} else {
			tag = adi_get_version(vaddr + voffset);
			if (copy_to_user(buf + copied, &tag, 1)) {
				copied = -EFAULT;
				break;
			}
		}

		voffset += adi_blksz;
		copied++;
	}
	return copied;
}

static ssize_t adi_tag_rw(struct mm_struct *mm, struct task_struct *task,
			  char __user *buf, size_t count,
			  unsigned long long addr, int write)
{
	unsigned long voffset, start, page_sz = 0;
	int res, locked, this_len = 0;
	struct vm_area_struct *vma;
	ssize_t copied = 0;
	struct page *page;
	char *vaddr;

	while (count) {
		down_read(&mm->mmap_sem);
		locked = 1;
		vma = find_vma(mm, addr);

		if (!vma) {
			up_read(&mm->mmap_sem);
			copied = -EFAULT;
			break;
		}

		if (!(vma->vm_flags & VM_SPARC_ADI)) {
			up_read(&mm->mmap_sem);
			copied =  -ENOMEM;
			break;
		}

		res = get_user_pages_locked(task, mm, addr, 1, write, 1, &page,
					    &locked);

		if (res != 1) {
			if (!copied)
				copied = -EIO;

			if (locked)
				up_read(&mm->mmap_sem);
			break;
		}

		page_sz = vma_kernel_pagesize(vma);
		start = round_down(addr, page_sz);
		voffset = addr - start;
		addr = start;
		vaddr = kmap(page);
		this_len = _adi_tag_rw(vaddr, voffset, count, buf, page_sz,
				       write);

		kunmap(page);
		put_page(page);

		if (locked)
			up_read(&mm->mmap_sem);

		if (this_len < 0) {
			copied = this_len;
			break;
		}

		addr += page_sz;
		copied += this_len;
		count -= this_len;
		buf += this_len;
	}

	if (write)
		_membar_sync();

	return copied;
}

static ssize_t proc_tag_rw(struct file *file, char __user *buf, size_t count,
			   loff_t *ppos, int write)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct mm_struct *mm = file->private_data;
	unsigned long long addr;
	ssize_t length;

	if (!adi_capable())
		return -EPERM;

	if (!mm)
		return 0;

	if (!atomic_inc_not_zero(&mm->mm_users))
		return 0;

	addr = adi_blksize() * (unsigned long long)*ppos;
	length = adi_tag_rw(mm, task, buf, count,  addr, write);

	mmput(mm);

	if (length > 0)
		*ppos += length;

	return length;
}

static ssize_t proc_tag_read(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos)
{
	return proc_tag_rw(file, buf, count, ppos, 0);
}

static ssize_t proc_tag_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	return proc_tag_rw(file, (char __user *)buf, count, ppos, 1);
}

static int proc_tag_open(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = proc_mem_open(inode, PTRACE_MODE_ATTACH);

	if (IS_ERR(mm))
		return PTR_ERR(mm);

	file->private_data = mm;
	file->f_mode |= FMODE_UNSIGNED_OFFSET;
	return 0;
}

static int proc_tag_release(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = file->private_data;

	if (mm)
		mmdrop(mm);
	return 0;
}

static const struct file_operations proc_tag_operations = {
	.llseek		= mem_lseek,
	.open		= proc_tag_open,
	.read		= proc_tag_read,
	.release	= proc_tag_release,
	.write		= proc_tag_write
};

static const struct pid_entry adi_dir_stuff[] = {
	REG("tags",	S_IRUSR | S_IWUSR, proc_tag_operations),
};

static int proc_adi_readdir(struct file *file, struct dir_context *ctx)
{
	return proc_pident_readdir(file, ctx, adi_dir_stuff,
				   ARRAY_SIZE(adi_dir_stuff));
}

const struct file_operations proc_adi_operations = {
	.read		= generic_read_dir,
	.iterate	= proc_adi_readdir,
	.llseek		= default_llseek,
};

static struct dentry *proc_adi_dir_lookup(struct inode *dir,
					  struct dentry *dentry,
					  unsigned int flags)
{
	return proc_pident_lookup(dir, dentry, adi_dir_stuff,
				  ARRAY_SIZE(adi_dir_stuff));
}

const struct inode_operations proc_adi_inode_operations = {
	.lookup		= proc_adi_dir_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};
