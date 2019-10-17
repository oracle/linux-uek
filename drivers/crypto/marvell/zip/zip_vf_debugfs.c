// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "zip_vf_debugfs.h"

static struct zip_vf_registers regs[64] = {
	{"ZIP_VQ_ENA        ",  ZIP_VF_VQX_ENA},
	{"ZIP_VQ_DOORBELL   ",  ZIP_VF_VQX_DOORBELL},
	{"ZIP_VQ_SBUF_ADDR  ",  ZIP_VF_VQX_SBUF_ADDR},
	{"ZIP_VQ_DONE       ",  ZIP_VF_VQX_DONE},
	{ NULL, 0}
};

/* Displays ZIP device statistics */
static int zip_vf_show_stats(struct seq_file *s, void *unused)
{
	struct zip_vf_device *vf = NULL;
	struct zip_vf_stats *st;
	u64 avg_chunk, avg_cr;

	int i;

	for (i = 0; i < ZIP_MAX_VFS; i++) {
		vf = zip_vf_get_device_by_id(i);
		st  = &vf->stats;
		avg_chunk = (atomic64_read(&st->comp_in_bytes) /
			     atomic64_read(&st->comp_req_complete));
		avg_cr = (atomic64_read(&st->comp_in_bytes) /
			  atomic64_read(&st->comp_out_bytes));

		seq_printf(s,   "\n------ ZIP VF Device %d Statistics ------\n"
				"Compression Req Submitted	: \t%lld\n"
				"Compression Req Completed	: \t%lld\n"
				"Compress In Bytes		: \t%lld\n"
				"Compressed Out Bytes		: \t%lld\n"
				"Average Chunk size		: \t%llu\n"
				"Average Compression ratio	: \t%llu\n",
				i,
				(u64)atomic64_read(&st->comp_req_submit),
				(u64)atomic64_read(&st->comp_req_complete),
				(u64)atomic64_read(&st->comp_in_bytes),
				(u64)atomic64_read(&st->comp_out_bytes),
				avg_chunk,
				avg_cr);
	}
	return 0;
}

/* Clear ZIP device statistics */
static int zip_vf_clear_stats(struct seq_file *s, void *unused)
{
	struct zip_vf_device *vf = NULL;
	int i;

	for (i = 0; i < ZIP_MAX_VFS; i++) {
		vf = zip_vf_get_device_by_id(i);
		if (vf)
			memset(&vf->stats, 0, sizeof(struct zip_vf_stats));
	}

	return 0;
}

/* Prints Registers' contents */
static int zip_vf_print_regs(struct seq_file *s, void *unused)
{
	struct zip_vf_device *vf = NULL;
	u64 val;
	int i, index;

	for (index = 0; index < ZIP_MAX_VFS; index++) {
		vf = zip_vf_get_device_by_id(index);
		seq_printf(s, "\n------ ZIP VF %d Registers ------\n", index);

		i = 0;

		while (regs[i].reg_name) {
			val = zip_vf_reg_read(vf, regs[i].reg_offset);
			seq_printf(s, "%s: 0x%016llx\n", regs[i].reg_name, val);
			i++;
		}
	}
	return 0;
}

static int zip_vf_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, zip_vf_show_stats, NULL);
}

static const struct file_operations zip_vf_stats_fops = {
	.owner = THIS_MODULE,
	.open  = zip_vf_stats_open,
	.read  = seq_read,
};

static int zip_vf_clear_open(struct inode *inode, struct file *file)
{
	return single_open(file, zip_vf_clear_stats, NULL);
}

static const struct file_operations zip_vf_clear_fops = {
	.owner = THIS_MODULE,
	.open  = zip_vf_clear_open,
	.read  = seq_read,
};

static int zip_vf_regs_open(struct inode *inode, struct file *file)
{
	return single_open(file, zip_vf_print_regs, NULL);
}

static const struct file_operations zip_vf_regs_fops = {
	.owner = THIS_MODULE,
	.open  = zip_vf_regs_open,
	.read  = seq_read,
};

/* Root directory for octeontx zip debugfs entry */
static struct dentry *zip_vf_debugfs_root;

int __init zip_vf_debugfs_init(void)
{
	struct dentry *zip_vf_stats, *zip_vf_clear, *zip_vf_regs;

	if (!debugfs_initialized())
		return -ENODEV;

	zip_vf_debugfs_root = debugfs_create_dir(DRV_NAME, NULL);
	if (!zip_vf_debugfs_root)
		return -ENOMEM;

	/* Creating files for entries inside octeontx zip directory */
	zip_vf_stats = debugfs_create_file("zipvf_stats", 0444,
					zip_vf_debugfs_root,
					NULL, &zip_vf_stats_fops);
	if (!zip_vf_stats)
		goto failed_to_create;

	zip_vf_clear = debugfs_create_file("zipvf_stats_clear", 0444,
					zip_vf_debugfs_root,
					NULL, &zip_vf_clear_fops);
	if (!zip_vf_clear)
		goto failed_to_create;

	zip_vf_regs = debugfs_create_file("zipvf_registers", 0444,
				       zip_vf_debugfs_root,
				       NULL, &zip_vf_regs_fops);
	if (!zip_vf_regs)
		goto failed_to_create;

	return 0;

failed_to_create:
	debugfs_remove_recursive(zip_vf_debugfs_root);
	return -ENOENT;
}

void __exit zip_vf_debugfs_exit(void)
{
	debugfs_remove_recursive(zip_vf_debugfs_root);
}
