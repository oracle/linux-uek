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

static struct proc_dir_entry *ent;

static void format_ethaddr(const char *macPtr, char *out)
{
	char expansion[MAC_ADDR_STR_LEN] = "00:00:00:00:00:00";
	int r = 0, w = 0, len;

	/* Ignore 0x in the beginning */
	macPtr = macPtr + 2;

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
	struct device_node *np = NULL;
	const char *board_revision;
	const char *board_serial;
	const char *board_model;
	const char *board_mac;
	char mac_addr[18];

	np = of_find_node_by_name(NULL, OCTTX_NODE);
	if (!np) {
		seq_puts(seq, "No board info available!\n");
		return 0;
	}

	of_property_read_string(np, "BOARD-MODEL", &board_model);
	of_property_read_string(np, "BOARD-REVISION", &board_revision);
	of_property_read_string(np, "BOARD-SERIAL",  &board_serial);
	of_property_read_string(np, "BOARD-MAC-ADDRESS", &board_mac);

	format_ethaddr(board_mac, mac_addr);

	seq_printf(seq, "Board model: %s\n", board_model);
	seq_printf(seq, "Board revision: %s\n", board_revision);
	seq_printf(seq, "Board serial: %s\n", board_serial);
	seq_printf(seq, "Board MAC: %s\n", mac_addr);

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
	struct device_node *np = NULL;

	np = of_find_node_by_name(NULL, OCTTX_NODE);
	if (np)
		ent = proc_create("octtx_info", 0660, NULL, &oct_brd_fops);

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
