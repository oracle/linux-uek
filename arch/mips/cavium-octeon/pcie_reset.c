/*
 * Simple /proc interface to PCIe reset.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2017 Cavium, Inc.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include <asm/octeon/octeon.h>

static struct proc_dir_entry *proc_pcie_reset_entry;
void octeon_pcie_setup_port(unsigned int node, unsigned int port, bool do_register);

static ssize_t pcie_reset_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	if (count) {
		char c;
		int pem;
		int node;

		if (get_user(c, buf))
			return -EFAULT;
		pem = c - '0';
		if (pem < 0 || pem > 7)
			return -EINVAL;

		node = (pem >> 2) & 1;
		pem &= 3;
		octeon_pcie_setup_port(node, pem, false);
		pr_notice("pcie_reset %d:%d\n", node, pem);
	}
	return count;
}

static const struct file_operations pcie_reset_operations = {
	.write = pcie_reset_write,
	.llseek = noop_llseek,
};

/*
 * Module initialization
 */
static int __init pcie_reset_init(void)
{
	if (!octeon_has_feature(OCTEON_FEATURE_PCIE))
		return 0;

	pr_notice("/proc/pcie_reset: Interface loaded\n");

	proc_pcie_reset_entry = proc_create("pcie_reset", 0200, NULL,
					    &pcie_reset_operations);

	return 0;
}

/*
 * Module cleanup
 */
static void __exit pcie_reset_exit(void)
{
	if (proc_pcie_reset_entry)
		remove_proc_entry("pcie_reset", NULL);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Inc. <support@cavium.com>");
module_init(pcie_reset_init);
module_exit(pcie_reset_exit);
