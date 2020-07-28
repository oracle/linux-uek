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
#include <linux/errno.h>
#include <linux/slab.h>

#define OCTTX_NODE	"octeontx_brd"
#define FW_LAYOUT_NODE	"firmware-layout"

struct octeontx_info_mac_addr {
	union {
		u64 num;
		struct {
		u8 pad[2];
			u8 bytes[6];
		} s;
	};
};

struct octtx_fw_info {
	const char *name;
	const char *version_string;
	u32 address;
	u32 max_size;
	u8 major_version;
	u8 minor_version;
	u8 revision_number;
	u8 revision_type;
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 minute;
	u16 flags;
	u32 customer_version;
	struct octtx_fw_info *next;
};

struct octtx_brd_info {
	const char *board_revision;
	const char *board_serial;
	const char *board_model;
	const char *board_num_of_mac;
	int  dev_tree_parsed;
	struct octeontx_info_mac_addr mac_addr;
	struct octtx_fw_info *fw_info;
};

static struct proc_dir_entry *ent;
static struct octtx_brd_info brd;
static char null_string[5] = "NULL";

static int oct_brd_proc_show(struct seq_file *seq, void *v)
{
	struct octtx_fw_info *fw_info = brd.fw_info;

	if (!brd.dev_tree_parsed) {
		seq_puts(seq, "No board info available!\n");
		return -EPERM;
	}

	seq_printf(seq, "board_model: %s\n", brd.board_model);
	seq_printf(seq, "board_revision: %s\n", brd.board_revision);
	seq_printf(seq, "board_serial_number: %s\n", brd.board_serial);
	seq_printf(seq, "mac_addr_base: %pM\n", brd.mac_addr.s.bytes);
	seq_printf(seq, "mac_addr_count: %s\n", brd.board_num_of_mac);

	while (fw_info) {
		seq_printf(seq, "firmware-file: %s\n", fw_info->name);
		seq_printf(seq, "  firmware-address:  0x%08x\n",
			   fw_info->address);
		seq_printf(seq, "  firmware-max-size: 0x%08x\n",
			   fw_info->max_size);
		seq_printf(seq, "  version-string:    %s\n",
			   fw_info->version_string);
		seq_printf(seq, "  version:           %02u.%02u.%02u\n",
			   fw_info->major_version, fw_info->minor_version,
			   fw_info->revision_number);
		seq_printf(seq, "  revision-type:     0x%x\n",
			   fw_info->revision_type);
		seq_printf(seq, "  date:              %04u-%02u-%02u\n",
			   fw_info->year, fw_info->month, fw_info->day);
		seq_printf(seq, "  time:              %02u:%02u\n",
			   fw_info->hour, fw_info->minute);
		seq_printf(seq, "  flags:             0x%04x\n",
			   fw_info->flags);
		seq_printf(seq, "  customer-version:  0x%08x\n",
			   fw_info->customer_version);
		fw_info = fw_info->next;
	}
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

static int octtx_parse_firmware_layout(struct device_node *parent)
{
	struct device_node *np = NULL;
	struct octtx_fw_info *fw_info, *last_fw_info = NULL;
	const char *version_string;
	const char *name;
	int ret;
	u32 ver_num;
	u32 date;
	u32 time;
	u32 flags;

	for_each_child_of_node(parent, np) {
		pr_debug("Getting firmware layout from node %s\n",
			of_node_full_name(np));
		ret = of_property_read_string(np, "description", &name);
		if (ret) {
			pr_warn("Could not obtain firmware file name\n");
			break;
		}
		pr_debug("Firmware file name: %s\n", name);

		/* We only care about entries with version info */
		ret = of_property_read_string(np, "version", &version_string);
		if (ret) {
			pr_debug("No version information found for %s\n", name);
			continue;
		}

		fw_info = kzalloc(sizeof(*fw_info), GFP_KERNEL);
		if (!fw_info) {
			pr_err("Out of memory for firmware info\n");
			return -ENOMEM;
		}

		fw_info->name = kstrdup(name, GFP_KERNEL);
		if (!fw_info->name) {
			pr_err("Out of memory\n");
			return -ENOMEM;
		}
		fw_info->version_string = kstrdup(version_string, GFP_KERNEL);
		if (!fw_info->version_string) {
			pr_err("Out of memory\n");
			return -ENOMEM;
		}

		ret = of_property_read_u32_index(np, "reg", 0,
						 &fw_info->address);
		if (ret) {
			pr_warn("Could not obtain firmware address for %s\n",
				fw_info->name);
			fw_info->address = (u32)-1;
			return -1;
		}

		ret = of_property_read_u32_index(np, "reg", 1,
						 &fw_info->max_size);
		if (ret) {
			pr_warn("Could not obtain firmware maximum size for %s\n",
				fw_info->name);
			fw_info->max_size = (u32)-1;
			return -1;
		}

		ret = of_property_read_u32(np, "revision", &ver_num);
		if (ret) {
			pr_warn("Could not obtain revision number for %s\n",
				fw_info->name);
		} else {
			fw_info->major_version = (ver_num >> 24) & 0xff;
			fw_info->minor_version = (ver_num >> 16) & 0xff;
			fw_info->revision_number = (ver_num >> 8) & 0xff;
			fw_info->revision_type = ver_num & 0xff;
		}

		ret = of_property_read_u32(np, "date", &date);
		if (ret) {
			pr_warn("Could not obtain date for %s\n",
				fw_info->name);
		} else {
			fw_info->year = (date >> 16) & 0xffff;
			fw_info->month = (date >> 8) & 0xff;
			fw_info->day = date & 0xff;
		}
		ret = of_property_read_u32(np, "time", &time);
		if (ret) {
			pr_warn("Could not obtain time for %s\n",
				fw_info->name);
		} else {
			fw_info->hour = (time >> 24) & 0xff;
			fw_info->minute = (time >> 16) & 0xff;
		}
		ret = of_property_read_u32(np, "flags", &flags);
		if (ret) {
			pr_warn("Could not obtain flags for %s\n",
				fw_info->name);
			fw_info->flags = 0;
		} else {
			fw_info->flags = flags & 0xFFFF;
		}
		ret = of_property_read_u32(np, "customer-version",
					   &fw_info->customer_version);
		if (ret) {
			pr_warn("Could not obtain customer version for %s\n",
				fw_info->name);
		}

		if (!brd.fw_info)
			brd.fw_info = fw_info;
		if (last_fw_info)
			last_fw_info->next = fw_info;
		last_fw_info = fw_info;
	}
	pr_debug("octtx_info parsing firmware done\n");
	return 0;
}

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

		np = of_find_node_by_name(np, FW_LAYOUT_NODE);
		if (np) {
			ret = octtx_parse_firmware_layout(np);
			if (ret)
				pr_err("Error parsing firmware-layout\n");
		}

		brd.dev_tree_parsed = 1;
	}

	ent = proc_create("octtx_info", 0444, NULL, &oct_brd_fops);
	if (!ent) {
		pr_err("proc entry creation for octtx info failed\n");
		return -ENODEV;
	}
	pr_info("Added /proc/octtx_info");

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
