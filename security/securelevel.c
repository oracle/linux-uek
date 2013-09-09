/*
 *  securelevel.c - support for generic kernel lockdown
 *
 *  Copyright Nebula, Inc <matthew.garrett@nebula.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/uaccess.h>

static int securelevel;

static DEFINE_SPINLOCK(securelevel_lock);

#define MAX_SECURELEVEL 1

int get_securelevel(void)
{
	return securelevel;
}
EXPORT_SYMBOL(get_securelevel);

int set_securelevel(int new_securelevel)
{
	int ret = 0;

	spin_lock(&securelevel_lock);

	if ((securelevel == -1) || (new_securelevel < securelevel) ||
	    (new_securelevel > MAX_SECURELEVEL)) {
		ret = -EINVAL;
		goto out;
	}

	securelevel = new_securelevel;
out:
	spin_unlock(&securelevel_lock);
	return ret;
}
EXPORT_SYMBOL(set_securelevel);

static ssize_t securelevel_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, sizeof(tmpbuf), "%d", securelevel);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t securelevel_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char *page = NULL;
	ssize_t length;
	int new_securelevel;

	length = -ENOMEM;
	if (count >= PAGE_SIZE)
		goto out;

	length = -EINVAL;
	if (*ppos != 0)
		goto out;

	length = -ENOMEM;
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		goto out;

	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	length = -EINVAL;
	if (sscanf(page, "%d", &new_securelevel) != 1)
		goto out;

	length = set_securelevel(new_securelevel);
	if (length)
		goto out;

	length = count;
out:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations securelevel_fops = {
	.read 	= securelevel_read,
	.write 	= securelevel_write,
	.llseek	= generic_file_llseek,
};

static __init int setup_securelevel(void)
{
	struct dentry *securelevel_file;

	securelevel_file = securityfs_create_file("securelevel",
						  S_IWUSR | S_IRUGO,
						  NULL, NULL,
						  &securelevel_fops);

	if (IS_ERR(securelevel_file))
		return PTR_ERR(securelevel_file);

	return 0;
}
late_initcall(setup_securelevel);
