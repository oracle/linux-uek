// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Marvell
 *
 */

#include <linux/arm-smccc.h>
#include <soc/marvell/octeontx/octeontx_smc.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

/* Maximum number of MAC addressess to pass */
#define MAC_MGMT_MAX_MACS_NUM	32

/* Maximum mac data size */
#define MAC_MGMT_MAX_MAC_TEXT_SIZE	2048

/* Single entry description */
struct mac_info {
	u32	index;
	u32	reserved; /* Must be zero */
	union {
		u64	mac_addr;
		u8      bytes[8];
	} s;
};

/* SMC call number used to set MAC address */
#define PLAT_OCTEONTX_MAC_MGMT_SET_ADDR	0xc2000e10

/** Set MAC address given by user
 *
 * The call passes MAC address information to ATF for further processing.
 * Information contains index and MAC address itself. Data should be validated
 * before this call.
 *
 * @param minfo - MAC address information (index, value)
 *
 * @return 0 for success, error code otherwise
 *
 */
static int mac_mgmt_set_addr(struct mac_info *minfo)
{
	struct arm_smccc_res res;

	/* Pass validated data to ATF */
	arm_smccc_smc(PLAT_OCTEONTX_MAC_MGMT_SET_ADDR,
		      minfo->index, minfo->s.mac_addr, 0, 0, 0, 0, 0,
		      &res);
	if (res.a0)
		return -EINVAL;

	return 0;
}

/** Parse user input in text for to MAC information structure
 *
 * @param buffer - ASCII string containing user's input
 * @param n - size of the user's input
 * @param minfo - input/output value, contains MAC information. Updated only when call succeeded
 *
 * @return bytes parsed for success, error code otherwise
 *
 */
static ssize_t mac_mgmt_parse_buffer(const char *buffer, size_t n,
			    struct mac_info *minfo)
{
	u32 index;
	u64 mac_addr;
	int processed, ret;

	/* Data are in buffer, parse it */
	ret = sscanf(buffer, "%u %llx %n", &index, &mac_addr, &processed);
	if (ret <= 0)
		return -EINVAL;

	if (processed < 2)  /* Expect at least two characters in input */
		return -EINVAL;

	if (index > MAC_MGMT_MAX_MACS_NUM)
		return -EINVAL;

	if (!mac_addr)
		return -EINVAL;

	/* Store validated data */
	minfo->index = index;
	minfo->s.mac_addr = mac_addr & 0xffffffffffff;

	pr_debug("%s: Idx: %u, addr: %llx\n", __func__,
		 minfo->index, minfo->s.mac_addr);

	return n;
}

/** Process the write operations to debugfs.
 *
 * The call is supported by seq_file API form kernel
 *
 * @param filep - file pointer
 * @param buffer - user's input buffer
 * @param count - user's input buffer size
 * @param ppos - position in file
 *
 * @return bytes written for success, error code otherwise
 *
 */
static ssize_t mac_mgmt_write(struct file *filp, const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	struct mac_info minfo = { 0 };
	char *mac_text_data = NULL;
	size_t cnt;
	int ret, bytes;

	/* User should fit into MAC_MGMT_MAX_MAC_TEXT_SIZE - 1, otherwise truncate */
	cnt = (count >= MAC_MGMT_MAX_MAC_TEXT_SIZE - 1) ?
		(MAC_MGMT_MAX_MAC_TEXT_SIZE - 1) : count;

	/* Leave one byte for NULL termination */
	mac_text_data = kzalloc(cnt + 1, GFP_KERNEL);
	if (!mac_text_data)
		return -ENOMEM;

	if (copy_from_user(mac_text_data, buffer, cnt)) {
		ret = -EFAULT;
		goto done;
	}

	bytes = mac_mgmt_parse_buffer(mac_text_data, cnt, &minfo);
	if (bytes < 0) {
		pr_warn("%s: Invalid text format!\n", __func__);
		ret = bytes;
		goto done;
	}

	ret = mac_mgmt_set_addr(&minfo);
	if (!ret)
		pr_info("%s: MAC addresses has been updated, change takes effect after reboot\n",
			__func__);
done:
	kfree(mac_text_data);
	return ret ? ret : bytes;
}

/** Process the read operations from debugfs.
 *
 * The call is supported by seq_file API form kernel.
 * It provides usage information to user.
 *
 * @param s - seq_file file handle
 * @param unused - unused parameter
 *
 * @return 0 for success, error code otherwise
 *
 */
static int mac_mgmt_read(struct seq_file *s, void *unused)
{
	seq_printf(s, "Sets MAC address for available interface.\nFormat:\n"
		      "ID BOARD-MAC-ADDRESS\n\n");
	return 0;
}

/** Process the open call on debugfs.
 *
 * The call is supported by seq_file API form kernel.
 *
 * @param inode - inode representing debugfs entry
 * @param file - file structure related to debugfs entry
 *
 * @return 0 for success, error code otherwise
 *
 */
static int mac_mgmt_open(struct inode *inode, struct file *file)
{
	return single_open(file, mac_mgmt_read, inode->i_private);
}

static const struct file_operations mac_mgmt_fops = {
	.owner		= THIS_MODULE,
	.open		= mac_mgmt_open,
	.read		= seq_read,
	.write		= mac_mgmt_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* Handle to debugfs root directory created by the driver */
static struct dentry *mac_dbgfs_root;

/** Initialize debugfs entries for the driver
 *
 * @return 0 for success, error code otherwise
 *
 */
static int mac_mgmt_setup_debugfs(void)
{
	struct dentry *dbg_file;

	mac_dbgfs_root = debugfs_create_dir("mac_mgmt", NULL);
	if (IS_ERR(mac_dbgfs_root))
		return PTR_ERR(mac_dbgfs_root);

	dbg_file = debugfs_create_file("set_mac_addr", 0600, mac_dbgfs_root,
				       NULL, &mac_mgmt_fops);
	if (IS_ERR(dbg_file)) {
		debugfs_remove(mac_dbgfs_root);
		mac_dbgfs_root = NULL;
		return PTR_ERR(dbg_file);
	}

	return 0;
}

static int __init cn10k_mac_mgmt_init(void)
{
	int ret;

	ret = octeontx_soc_check_smc();
	if (ret != 2) {
		pr_info("%s: Not supported\n", __func__);
		return -EPERM;
	}

	ret = mac_mgmt_setup_debugfs();
	if (ret) {
		pr_err("%s: Can't create debugfs entries! (%d)\n",
			__func__, ret);
		return ret;
	}

	pr_info("Marvell CN10K MAC management\n");

	return 0;
}

static void __exit cn10k_mac_mgmt_exit(void)
{
	debugfs_remove_recursive(mac_dbgfs_root);
}

module_init(cn10k_mac_mgmt_init);
module_exit(cn10k_mac_mgmt_exit);

MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
MODULE_DESCRIPTION("MAC address management for Marvell CN10K");
MODULE_LICENSE("GPL");
