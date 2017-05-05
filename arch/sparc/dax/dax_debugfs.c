/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "dax_impl.h"
#include <linux/debugfs.h>

static struct dentry *dax_dbgfs;
static struct dentry *dax_output;

enum dax_dbfs_type {
	DAX_DBFS_MEM_USAGE,
	DAX_DBFS_ALLOC_COUNT,
};

static int debug_open(struct inode *inode, struct file *file);

static const struct file_operations debugfs_ops = {
	.open = debug_open,
	.release = single_release,
	.read = seq_read,
	.llseek = seq_lseek,
};

static int dax_debugfs_read(struct seq_file *s, void *data)
{
	switch ((long)s->private) {
	case DAX_DBFS_MEM_USAGE:
		seq_printf(s, "memory use (Kb): %d\n",
			   atomic_read(&dax_requested_mem));
		break;
	case DAX_DBFS_ALLOC_COUNT:
		seq_printf(s, "DAX alloc count: %d\n",
			   atomic_read(&dax_alloc_counter));
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, dax_debugfs_read, inode->i_private);
}

void dax_debugfs_init(void)
{
	dax_dbgfs = debugfs_create_dir("dax", NULL);
	if (dax_dbgfs == NULL) {
		dax_err("dax debugfs dir creation failed");
		return;
	}

	dax_output = debugfs_create_file("mem_usage", 0444, dax_dbgfs,
					 (void *)DAX_DBFS_MEM_USAGE,
					 &debugfs_ops);
	if (dax_output == NULL)
		dax_err("dax debugfs output file creation failed");

	dax_output = debugfs_create_file("alloc_count", 0444, dax_dbgfs,
					 (void *)DAX_DBFS_ALLOC_COUNT,
					 &debugfs_ops);
	if (dax_output == NULL)
		dax_err("dax debugfs output file creation failed");
}

void dax_debugfs_clean(void)
{
	if (dax_dbgfs != NULL)
		debugfs_remove_recursive(dax_dbgfs);
}
