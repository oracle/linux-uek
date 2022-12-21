// SPDX-License-Identifier: GPL-2.0
/* Proc entry for board information
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "octtx_info: " fmt

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/of.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <soc/marvell/octeontx/octeontx_smc.h>

#define OCTTX_NODE	"octeontx_brd"
#define FW_LAYOUT_NODE	"firmware-layout"
#define SOC_NODE	"soc"
#define MAX_MACS	32  // Please keep this in sync with EBF

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
	const char *board_num_of_mac_id;
	const char *reset_count_cold;
	const char *reset_count_warm;
	const char *reset_count_core_wdog;
	const char *reset_count_scp_wdog;
	const char *reset_count_mcp_wdog;
	const char *reset_count_ecp_wdog;
	int  dev_tree_parsed;
	int  use_mac_id;
	struct octeontx_info_mac_addr mac_addrs[MAX_MACS];
	struct octtx_fw_info *fw_info;
	const char *sdk_version;
};

static struct proc_dir_entry *ent;
static struct octtx_brd_info brd;
static const char null_string[5] = "NULL";

static int oct_brd_proc_show(struct seq_file *seq, void *v)
{
	struct octtx_fw_info *fw_info = brd.fw_info;
	struct octeontx_info_mac_addr *mac_addr;

	if (!brd.dev_tree_parsed) {
		seq_puts(seq, "No board info available!\n");
		return -EPERM;
	}

	seq_printf(seq, "board_model: %s\n", brd.board_model);
	seq_printf(seq, "board_revision: %s\n", brd.board_revision);
	seq_printf(seq, "board_serial_number: %s\n", brd.board_serial);
	seq_printf(seq, "SDK Version: %s\n", brd.sdk_version);
	if (!brd.use_mac_id) {
		mac_addr = &brd.mac_addrs[0];

		seq_printf(seq, "mac_addr_count: %s\n", brd.board_num_of_mac);
		seq_printf(seq, "mac_addr_base: %pM\n", mac_addr->s.bytes);
	} else {
		u32 u, num;

		if (brd.board_num_of_mac_id == null_string)
			seq_printf(seq, "mac_addr_count: %s\n",
				   brd.board_num_of_mac_id);

		if (!kstrtou32(brd.board_num_of_mac_id, 16, &num)) {
			seq_printf(seq, "mac_addr_count: %s\n",
				   brd.board_num_of_mac_id);

			for (u = 0; u < num; u++) {
				mac_addr = &brd.mac_addrs[u];

				seq_printf(seq, "board-mac-addr-id%d: %pM\n",
					   u, mac_addr->s.bytes);
			}
		}
	}

	if (is_soc_cn10kx()) {
		seq_printf(seq, "cold_reset_count: %s\n", brd.reset_count_cold);
		seq_printf(seq, "warm_reset_count: %s\n", brd.reset_count_warm);
		seq_printf(seq, "core_wdog_reset_count: %s\n",
			   brd.reset_count_core_wdog);
		seq_printf(seq, "scp_wdog_reset_count: %s\n",
			   brd.reset_count_scp_wdog);
		seq_printf(seq, "mcp_wdog_reset_count: %s\n",
			   brd.reset_count_mcp_wdog);
		seq_printf(seq, "ecp_wdog_reset_count: %s\n",
			   brd.reset_count_ecp_wdog);
	}

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

static const struct proc_ops oct_brd_fops = {
	.proc_open = oct_brd_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int octtx_parse_mac_info(struct device_node *node)
{
	const char *board_mac;
	struct octeontx_info_mac_addr mac_addr;
	int ret;
	u32 num, id_num, u;

	if (!node)
		return -EINVAL;

	/* Initialize variables */
	memset(brd.mac_addrs, 0, sizeof(brd.mac_addrs));
	brd.use_mac_id = 0;

	ret = of_property_read_string(node, "BOARD-MAC-ADDRESS-NUM",
				      &brd.board_num_of_mac);
	if (ret) {
		pr_warn("Board MAC address number not available\n");
		brd.board_num_of_mac = null_string;
		num = -1;
	} else {
		if (kstrtou32(brd.board_num_of_mac, 16, &num))
			pr_warn("Board MAC address number is not available\n");
	}

	ret = of_property_read_string(node, "BOARD-MAC-ADDRESS", &board_mac);
	if (ret) {
		pr_warn("Board MAC address not available\n");
		brd.mac_addrs[0].num = 0;
	} else {
		if (!kstrtoull(board_mac, 16, &mac_addr.num))
			brd.mac_addrs[0].num = be64_to_cpu(mac_addr.num);
	}

	/* This part is not mandatory */
	ret = of_property_read_string(node, "BOARD-MAC-ADDRESS-ID-NUM",
				      &brd.board_num_of_mac_id);
	if (ret) {
		brd.board_num_of_mac_id = null_string;
		id_num = -1;
	} else {
		if (kstrtou32(brd.board_num_of_mac_id, 16, &id_num))
			pr_warn("Board MAC addressess IDs number is not available\n");
	}

	if ((brd.board_num_of_mac_id != null_string) && (id_num > 0)) {
		for (u = 0; u < id_num; u++) {
			char prop_name[32] = { 0 };

			snprintf(prop_name, sizeof(prop_name),
				 "BOARD-MAC-ADDRESS-ID%u",
				 u);
			ret = of_property_read_string(node, prop_name,
						      &board_mac);
			if (ret) {
				brd.mac_addrs[u].num = 0;
			} else {
				if (!kstrtou64(board_mac, 16, &mac_addr.num))
					brd.mac_addrs[u].num = be64_to_cpu(mac_addr.num);
			}
		}

		brd.use_mac_id = 1;
	}

	return 0;
}

/** Reads reset counters information and store it in global board structure
 *
 * @param np	device tree node to parse
 *
 */
static void octtx_parse_reset_couters(struct device_node *np)
{
	int ret;

	ret = of_property_read_string(np, "RESET-COUNT-COLD",
					&brd.reset_count_cold);
	if (ret) {
		pr_warn("Cold reset count not available\n");
		/* Default name is "NULL" */
		brd.reset_count_cold = null_string;
	}

	ret = of_property_read_string(np, "RESET-COUNT-WARM",
					&brd.reset_count_warm);
	if (ret) {
		pr_warn("Warm reset count not available\n");
		/* Default name is "NULL" */
		brd.reset_count_warm = null_string;
	}

	ret = of_property_read_string(np, "RESET-COUNT-CORE-WDOG",
					&brd.reset_count_core_wdog);
	if (ret) {
		pr_warn("Core Watchdog reset count not available\n");
		/* Default name is "NULL" */
		brd.reset_count_core_wdog = null_string;
	}

	ret = of_property_read_string(np, "RESET-COUNT-SCP-WDOG",
					&brd.reset_count_scp_wdog);
	if (ret) {
		pr_warn("SCP Watchdog reset count not available\n");
		/* Default name is "NULL" */
		brd.reset_count_scp_wdog = null_string;
	}

	ret = of_property_read_string(np, "RESET-COUNT-MCP-WDOG",
					&brd.reset_count_mcp_wdog);
	if (ret) {
		pr_warn("MCP Watchdog reset count not available\n");
		/* Default name is "NULL" */
		brd.reset_count_mcp_wdog = null_string;
	}

	ret = of_property_read_string(np, "RESET-COUNT-ECP-WDOG",
					&brd.reset_count_ecp_wdog);
	if (ret) {
		pr_warn("ECP Watchdog reset count not available\n");
		/* Default name is "NULL" */
		brd.reset_count_ecp_wdog = null_string;
	}
}

static int octtx_parse_firmware_layout(struct device_node *parent)
{
	struct device_node *np = NULL;
	struct octtx_fw_info *fw_info = NULL, *last_fw_info = NULL;
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
			ret = -ENOMEM;
			goto bailout;
		}

		fw_info->name = kstrdup(name, GFP_KERNEL);
		if (!fw_info->name) {
			pr_err("Out of memory\n");
			ret = -ENOMEM;
			goto bailout;
		}
		fw_info->version_string = kstrdup(version_string, GFP_KERNEL);
		if (!fw_info->version_string) {
			pr_err("Out of memory\n");
			ret = -ENOMEM;
			goto bailout;
		}

		ret = of_property_read_u32_index(np, "reg", 0,
						 &fw_info->address);
		if (ret) {
			pr_warn("Could not obtain firmware address for %s\n",
				fw_info->name);
			fw_info->address = (u32)-1;
			ret = -EINVAL;
			goto bailout;
		}

		ret = of_property_read_u32_index(np, "reg", 1,
						 &fw_info->max_size);
		if (ret) {
			pr_warn("Could not obtain firmware maximum size for %s\n",
				fw_info->name);
			fw_info->max_size = (u32)-1;
			ret = -EINVAL;
			goto bailout;
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

bailout:
	if (fw_info) {
		kfree(fw_info->name);
		kfree(fw_info->version_string);
	}
	kfree(fw_info);

	return ret;
}

static int __init octtx_info_init(void)
{
	int ret;
	struct device_node *np = NULL;

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

		ret = octtx_parse_mac_info(np);
		if (ret) {
			pr_warn("Board MAC addess not available\n");
		}

		/* Parse elements related to CN10KX */
		if (is_soc_cn10kx()) {
			octtx_parse_reset_couters(np);

			np = of_find_node_by_name(np, FW_LAYOUT_NODE);
			if (np) {
				ret = octtx_parse_firmware_layout(np);
				if (ret)
					pr_err("Error parsing firmware-layout\n");
			}
		}

		/* Read SOC@0 node to get SDK Version */
		np = of_find_node_by_name(NULL, SOC_NODE);
		if (!np) {
			pr_err("soc node not available!\n");
			return -ENODEV;
		}
		ret = of_property_read_string(np, "sdk-version",
						&brd.sdk_version);
		if (ret) {
			pr_warn("SDK Version not available\n");
			/* Default name is "NULL" */
			brd.sdk_version = null_string;
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

static void  __exit octtx_info_cleanup(void)
{
	proc_remove(ent);
}

module_init(octtx_info_init);
module_exit(octtx_info_cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("octeontx board info");
MODULE_AUTHOR("Sujeet Baranwal <sbaranwal@marvell.com>");
