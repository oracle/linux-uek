// SPDX-License-Identifier: GPL-2.0
/* Proc entry for board information
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/of.h>

#define OCTTX_NODE "octeontx_brd"

struct octeontx_info_mac_addr {
	union {
		u64 num;
		struct {
		u8 pad[2];
			u8 bytes[6];
		} s;
	};
};

struct octtx_brd_info {
	const char *board_revision;
	const char *board_serial;
	const char *board_model;
	const char *board_num_of_mac;
	int  dev_tree_parsed;
	struct octeontx_info_mac_addr mac_addr;
};

static struct proc_dir_entry *ent;
static struct octtx_brd_info brd;
static char null_string[5] = "NULL";

static int oct_brd_proc_show(struct seq_file *seq, void *v)
{
	if (!brd.dev_tree_parsed) {
		seq_puts(seq, "No board info available!\n");
		return -EPERM;
	}

	seq_printf(seq, "board_model: %s\n", brd.board_model);
	seq_printf(seq, "board_revision: %s\n", brd.board_revision);
	seq_printf(seq, "board_serial_number: %s\n", brd.board_serial);
	seq_printf(seq, "mac_addr_base: %pM\n", brd.mac_addr.s.bytes);
	seq_printf(seq, "mac_addr_count: %s\n", brd.board_num_of_mac);

	return  0;
}

static int oct_brd_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, oct_brd_proc_show, NULL);
}

static const struct file_operations oct_brd_fops = {
	.owner = THIS_MODULE,
	.open = oct_brd_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int octtx_info_init(void)
{
	int ret;
	const char *board_mac;
	struct device_node *np = NULL;
	struct octeontx_info_mac_addr mac_addr;

	if (!brd.dev_tree_parsed) {
		np = of_find_node_by_name(NULL, OCTTX_NODE);
		if (!np) {
			pr_err("No board info available!\n");
			return -ENODEV;
		}
		ret = of_property_read_string(np, "BOARD-MODEL",
						&brd.board_model);
		if (ret) {
			pr_warn("Board model not available\n");
			/* Default name is "NULL" */
			brd.board_model = null_string;
		}
		ret = of_property_read_string(np, "BOARD-REVISION",
						&brd.board_revision);
		if (ret) {
			pr_warn("Board revision not available\n");
			/* Default name is "NULL" */
			brd.board_revision = null_string;

		}
		ret = of_property_read_string(np, "BOARD-SERIAL",
						&brd.board_serial);
		if (ret) {
			pr_warn("Board serial not available\n");
			/* Default name is "NULL" */
			brd.board_serial = null_string;
		}
		ret = of_property_read_string(np, "BOARD-MAC-ADDRESS",
								&board_mac);
		if (ret) {
			pr_warn("Board mac address not available\n");
			brd.mac_addr.num = 0;
		} else {
			if (!kstrtoull(board_mac, 16, &mac_addr.num))
				brd.mac_addr.num = be64_to_cpu(mac_addr.num);
		}


		ret = of_property_read_string(np, "BOARD-MAC-ADDRESS-NUM",
							&brd.board_num_of_mac);
		if (ret) {
			pr_warn("Board mac address number not available\n");
			brd.board_num_of_mac = null_string;
		}

		brd.dev_tree_parsed = 1;
	}

	ent = proc_create("octtx_info", 0444, NULL, &oct_brd_fops);
	if (!ent) {
		pr_err("proc entry creation for octtx info failed\n");
		return -ENODEV;
	}

	return 0;
}

static void octtx_info_cleanup(void)
{
	proc_remove(ent);
}

module_init(octtx_info_init);
module_exit(octtx_info_cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("octeontx board info");
MODULE_AUTHOR("Sujeet Baranwal <sbaranwal@marvell.com>");
