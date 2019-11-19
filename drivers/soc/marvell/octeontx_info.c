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

#define MAC_ADDR_STR_LEN 18
#define OCTTX_NODE "octeontx_brd"

struct octtx_brd_info {
	const char *board_revision;
	const char *board_serial;
	const char *board_model;
	char board_mac[18];
	int  dev_tree_parsed;
};

static struct proc_dir_entry *ent;
static struct octtx_brd_info brd;

static char null_string[5] = "NULL";
static char expansion[MAC_ADDR_STR_LEN] = "00:00:00:00:00:00";

static void format_ethaddr(const char *macPtr, char *out)
{
	int r = 0, w = 0, len;

	/* Ignore 0x in the beginning */
	if (!strncmp(macPtr, "0x", 2))
		macPtr += 2;

	len = strlen(macPtr);

	while ((len - r) >= 2) {
		expansion[16 - w] = macPtr[len - 1 - r];
		expansion[16 - w - 1] = macPtr[len - 1 - r - 1];
		w += 3;
		r += 2;
	}

	/* if any char still left */
	if ((len - r) == 1)
		expansion[16 - w] = macPtr[len - 1 - r];

	memcpy(out, expansion, MAC_ADDR_STR_LEN);
}

static int oct_brd_proc_show(struct seq_file *seq, void *v)
{
	if (!brd.dev_tree_parsed) {
		seq_puts(seq, "No board info available!\n");
		return 0;
	}

	seq_printf(seq, "board_model: %s\n", brd.board_model);
	seq_printf(seq, "board_revision: %s\n", brd.board_revision);
	seq_printf(seq, "board_serial_number: %s\n", brd.board_serial);
	seq_printf(seq, "mac_addr_base: %s\n", brd.board_mac);

	return  0;
}

static int oct_brd_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, oct_brd_proc_show, NULL);
}

#ifdef CONFIG_PROC_FS
static const struct file_operations oct_brd_fops = {
	.owner = THIS_MODULE,
	.open = oct_brd_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static int octtx_info_init(void)
{
	int ret;
	const char *board_mac;
	struct device_node *np = NULL;

	if (!brd.dev_tree_parsed) {
		np = of_find_node_by_name(NULL, OCTTX_NODE);
		if (!np) {
			pr_err("No board info available!\n");
			return 0;
		}
		ret = of_property_read_string(np, "BOARD-MODEL",
						&brd.board_model);
		if (ret) {
			pr_err("Board model not available\n");
			/* Default name is "NULL" */
			brd.board_model = null_string;
		}
		ret = of_property_read_string(np, "BOARD-REVISION",
						&brd.board_revision);
		if (ret) {
			pr_err("Board revision not available\n");
			/* Default name is "NULL" */
			brd.board_revision = null_string;

		}
		ret = of_property_read_string(np, "BOARD-SERIAL",
						&brd.board_serial);
		if (ret) {
			pr_err("Board serial not available\n");
			/* Default name is "NULL" */
			brd.board_serial = null_string;
		}
		ret = of_property_read_string(np, "BOARD-MAC-ADDRESS",
								&board_mac);
		if (ret) {
			pr_err("Board mac address not available\n");
			/* Default name is "NULL" */
			strncpy(brd.board_mac, expansion,
						sizeof(brd.board_mac));
		} else
			format_ethaddr(board_mac, brd.board_mac);

		brd.dev_tree_parsed = 1;
	}

	ent = proc_create("octtx_info", 0660, NULL, &oct_brd_fops);
	if (ent == NULL)
		return -ENODEV;

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
