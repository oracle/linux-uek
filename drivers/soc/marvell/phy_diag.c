// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Marvell
 *
 */

#include <linux/arm-smccc.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/uaccess.h>

#define ARM_SMC_SVC_UID			0xc200ff01

#define PLAT_OCTEONTX_PHY_DBG_PRBS	0xc2000e00
#define PLAT_OCTEONTX_PHY_LOOPBACK	0xc2000e01
#define PLAT_OCTEONTX_PHY_GET_TEMP	0xc2000e02
#define PLAT_OCTEONTX_PHY_SERDES_CFG	0xc2000e03
#define PLAT_OCTEONTX_PHY_MDIO		0xc2000e04

#define MAX_ETH				10
#define MAX_LMAC_PER_ETH		4

#define DEFINE_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _read, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.write		= __name ## _write,				\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}

#define DEFINE_STR_2_ENUM_FUNC(_conv_arr)				\
static inline int _conv_arr ## _str2enum(const char *str)		\
{									\
	size_t idx;							\
	size_t len = ARRAY_SIZE(_conv_arr);				\
									\
	if (!str)							\
		return -1;						\
									\
	for (idx = 0; idx < len; idx++) {				\
		if (!strcmp(_conv_arr[idx].s, str))			\
			return _conv_arr[idx].e;			\
	}								\
									\
	return -1;							\
}

struct dentry *phy_dbgfs_root;

/* This is expected OcteonTX response for SVC UID command */
static const int octeontx_svc_uuid[] = {
	0x6ff498cf,
	0x5a4e9cfa,
	0x2f2a3aa4,
	0x5945b105,
};

#define CMD_SZ 64
char cmd_buf[CMD_SZ];

static struct {
	int eth;
	int lmac;
} phy_data;

enum phy_sgmii_vod {
	PHY_SGMII_VOD_14mV = 0,
	PHY_SGMII_VOD_112mV,
	PHY_SGMII_VOD_210mV,
	PHY_SGMII_VOD_308mV,
	PHY_SGMII_VOD_406mV,
	PHY_SGMII_VOD_504mV,
	PHY_SGMII_VOD_602mV,
	PHY_SGMII_VOD_700mV,

	PHY_SGMII_VOD_MAX
};

#define VOD(_val) {PHY_SGMII_VOD_ ## _val, #_val}
static struct {
	enum phy_sgmii_vod e;
	const char *s;
} sgmii_vod_values[] = {
	VOD(14mV),
	VOD(112mV),
	VOD(210mV),
	VOD(308mV),
	VOD(406mV),
	VOD(504mV),
	VOD(602mV),
	VOD(700mV),
};
DEFINE_STR_2_ENUM_FUNC(sgmii_vod_values)

enum phy_prbs_cmd {
	PHY_PRBS_START_CMD = 1,
	PHY_PRBS_STOP_CMD,
	PHY_PRBS_GET_DATA_CMD,
};

static struct {
	enum phy_prbs_cmd e;
	const char *s;
} prbs_cmds[] = {
	{PHY_PRBS_START_CMD, "start"},
	{PHY_PRBS_STOP_CMD, "stop"},
};
DEFINE_STR_2_ENUM_FUNC(prbs_cmds)


enum phy_prbs_side {
	PRBS_SIDE_LINE = 0,
	PRBS_SIDE_HOST,
};

static struct {
	enum phy_prbs_side e;
	const char *s;
} prbs_sides[] = {
	{PRBS_SIDE_LINE, "line"},
	{PRBS_SIDE_HOST, "host"},
};
DEFINE_STR_2_ENUM_FUNC(prbs_sides)


enum phy_prbs_type {
	PRBS_7 = 0,
	PRBS_23,
	PRBS_31,
	PRBS_1010,
};

static struct {
	enum phy_prbs_type e;
	const char *s;
} prbs_types[] = {
	{PRBS_7, "prbs_7"},
	{PRBS_23, "prbs_23"},
	{PRBS_31, "prbs_31"},
	{PRBS_1010, "prbs_1010"},
};
DEFINE_STR_2_ENUM_FUNC(prbs_types)


enum phy_mdio_optype {
	CLAUSE_22 = 0,
	CLAUSE_45,
};

static struct {
	enum phy_mdio_optype e;
	const char *s;
} mdio_optype[] = {
	{CLAUSE_22, "c22"},
	{CLAUSE_45, "c45"},
};
DEFINE_STR_2_ENUM_FUNC(mdio_optype)



static int copy_user_input(const char __user *buffer,
			size_t count, char *cmd_buf, size_t buf_sz)
{
	size_t cnt;

	cnt = (count >= buf_sz - 1) ? buf_sz - 1 : count;

	memset(cmd_buf, 0, buf_sz);
	if (copy_from_user(cmd_buf, buffer, cnt))
		return -EFAULT;

	cmd_buf[cnt] = '\0';
	return 0;
}


static int parse_phy_mdio_op_data(char *cmd, int write,
		int *clause, int *dev_page, int *reg, int *val)
{
	char *end;
	char *token;
	int optype;
	int devpage;

	end = skip_spaces(cmd);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	optype = mdio_optype_str2enum(token);
	if (optype == -1)
		return -EINVAL;

	*clause = optype;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	if (kstrtoint(token, 10, &devpage))
		return -EINVAL;

	if (devpage >= 0) {
		/* device addr or page nr are 5 bits */
		devpage &= 0x1f;
		*dev_page = devpage;
	} else if (devpage != -1) {
		return -EINVAL;
	}

	/* Cannot ignore devad when using clause 45 */
	if (devpage == -1 && optype == CLAUSE_45)
		return -EINVAL;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	if (kstrtouint(token, 16, reg))
		return -EINVAL;

	*reg &= (clause == CLAUSE_22) ? 0x1f : 0xffff;

	if (write) {
		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		if (kstrtouint(token, 16, val))
			return -EINVAL;

		*val &= 0xffff;
	}

	return 0;
}


static ssize_t phy_debug_read_reg_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int clause;
	int dev_page = (1 << 5);
	int reg;
	int val;
	int x1;
	int x2;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	if (parse_phy_mdio_op_data(cmd_buf, 0, &clause,
				&dev_page, &reg, &val)) {
		return -EINVAL;
	}

	x1 = (dev_page << 2) | (clause << 1) | 0;
	x2 = reg;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_MDIO, x1, x2,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("MDIO: Reading PHY register failed!\n");
		return count;
	}

	val = res.a1 & 0xffff;

	pr_info("MDIO: val=0x%x\n", val);

	return count;
}

static int phy_debug_read_reg_read(struct seq_file *s, void *unused)
{
	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_read_reg);

static ssize_t phy_debug_write_reg_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int clause;
	int dev_page = (1 << 5);
	int reg;
	int val;
	int x1;
	int x2;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	if (parse_phy_mdio_op_data(cmd_buf, 1, &clause,
				&dev_page, &reg, &val)) {
		return -EINVAL;
	}

	x1 = (dev_page << 2) | (clause << 1) | 1;
	x2 = (val << 16) | reg;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_MDIO, x1, x2,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0)
		pr_warn("MDIO: Writing PHY register failed!\n");

	return count;
}

static int phy_debug_write_reg_read(struct seq_file *s, void *unused)
{
	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_write_reg);

static ssize_t phy_debug_prbs_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *end;
	char *token;
	int cmd;
	int host;
	int type = 0;
	int cfg = 0;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	end = skip_spaces(cmd_buf);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	cmd = prbs_cmds_str2enum(token);
	if (cmd == -1)
		return -EINVAL;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	host = prbs_sides_str2enum(token);
	if (host == -1)
		return -EINVAL;

	if (cmd == PHY_PRBS_START_CMD) {
		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		type = prbs_types_str2enum(token);
		if (type == -1)
			return -EINVAL;
	}

	cfg |= (type << 2) | (1 << 1) | host;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_DBG_PRBS, cmd, cfg,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("Configuring PRBS failed!\n");
		return count;
	}

	if (cmd == PHY_PRBS_START_CMD) {
		pr_info("PRBS started: side=%s, type=%s\n",
			prbs_sides[host].s, prbs_types[type].s);
	} else {
		pr_info("PRBS stopped: side=%s\n",
			prbs_sides[host].s);
	}

	return count;
}

static int phy_debug_prbs_read(struct seq_file *s, void *unused)
{
	struct arm_smccc_res res;
	int cfg;
	int host_errors;
	int line_errors;

	cfg = 1;
	arm_smccc_smc(PLAT_OCTEONTX_PHY_DBG_PRBS, PHY_PRBS_GET_DATA_CMD, cfg,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	host_errors = res.a0;

	cfg = 0;
	arm_smccc_smc(PLAT_OCTEONTX_PHY_DBG_PRBS, PHY_PRBS_GET_DATA_CMD, cfg,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	line_errors = res.a0;

	seq_printf(s, "PRBS errors: host=%d line=%d\n", host_errors, line_errors);

	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_prbs);

static ssize_t phy_debug_loopback_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *token;
	unsigned int lpb_en;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	token = strim(skip_spaces(cmd_buf));
	if (!token)
		return -EINVAL;

	if (kstrtouint(token, 10, &lpb_en) || (lpb_en != 1 && lpb_en != 0))
		return -EINVAL;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_LOOPBACK, lpb_en,
		phy_data.eth, phy_data.lmac, 0, 0, 0, 0, &res);

	if (res.a0) {
		if (lpb_en)
			pr_warn("Enabling Line Loopback failed!\n");
		else
			pr_warn("Disabling Line Loopback failed!\n");

		return count;
	}

	pr_info("Line Loopback: enable=%d\n", lpb_en);

	return count;
}

static int phy_debug_loopback_read(struct seq_file *s, void *unused)
{
	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_loopback);

static int phy_debug_serdes_read(struct seq_file *s, void *unused)
{
	struct arm_smccc_res res;
	const char *vod_str;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_SERDES_CFG, 0, 0,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		seq_puts(s, "Reading SERDES config failed!\n");
		return 0;
	}

	vod_str = sgmii_vod_values[res.a1 & 0x7].s;
	seq_printf(s, "SERDES config: VOD=%s\n", vod_str);

	return 0;
}

static ssize_t phy_debug_serdes_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *token;
	int vod_val;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	token = strim(skip_spaces(cmd_buf));
	if (!token)
		return -EINVAL;

	vod_val = sgmii_vod_values_str2enum(token);
	if (vod_val == -1)
		return -EINVAL;

	vod_val &= 0x7;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_SERDES_CFG, 1, vod_val,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("Changing SERDES config failed!\n");
		return count;
	}

	pr_info("New SERDES config: VOD=%s\n", sgmii_vod_values[vod_val].s);

	return count;
}
DEFINE_ATTRIBUTE(phy_debug_serdes);

static int phy_debug_temp_show(struct seq_file *s, void *unused)
{
	struct arm_smccc_res res;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_GET_TEMP, phy_data.eth,
		      phy_data.lmac, 0, 0, 0, 0, 0, &res);

	if (res.a0)
		seq_puts(s, "Reading temperature failed!\n");
	else
		seq_printf(s, "Temperature: %ld\n", res.a1);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(phy_debug_temp);

static int parse_eth_lmac(char *cmd, int *eth, int *lmac)
{
	char *end;
	char *token;

	end = skip_spaces(cmd);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	if (kstrtouint(token, 10, eth) ||
		*eth >= MAX_ETH)
		return -EINVAL;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	if (kstrtouint(token, 10, lmac) ||
		*lmac >= MAX_LMAC_PER_ETH)
		return -EINVAL;

	return 0;
}

static int phy_debug_phy_read(struct seq_file *s, void *unused)
{
	seq_printf(s, "Selected PHY: @(eth=%d, lmac=%d)\n",
			phy_data.eth, phy_data.lmac);
	return 0;
}

static ssize_t phy_debug_phy_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	int eth;
	int lmac;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	if (parse_eth_lmac(cmd_buf, &eth, &lmac))
		return -EINVAL;

	phy_data.eth = eth;
	phy_data.lmac = lmac;

	pr_info("New PHY selected: @(eth=%d, lmac=%d)\n",
			phy_data.eth, phy_data.lmac);

	return count;
}
DEFINE_ATTRIBUTE(phy_debug_phy);

static int phy_dbg_setup_debugfs(void)
{
	struct dentry *dbg_file;

	phy_dbgfs_root = debugfs_create_dir("phy_diagnostics", NULL);

	dbg_file = debugfs_create_file("phy", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_phy_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("temperature", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_temp_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("serdes", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_serdes_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("line_loopback", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_loopback_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("prbs", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_prbs_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("write_reg", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_write_reg_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("read_reg", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_read_reg_fops);
	if (!dbg_file)
		goto create_failed;


	return 0;

create_failed:
	pr_err("Failed to create debugfs dir/file for octeontx_phy\n");
	debugfs_remove_recursive(phy_dbgfs_root);
	return -1;
}

static int __init phy_dbg_init(void)
{
	struct arm_smccc_res res;

	/*
	 * Compare response for standard SVC_UID commandi with OcteonTX UUID.
	 * Continue only if it is OcteonTX.
	 */
	arm_smccc_smc(ARM_SMC_SVC_UID, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != octeontx_svc_uuid[0] || res.a1 != octeontx_svc_uuid[1] ||
	    res.a2 != octeontx_svc_uuid[2] || res.a3 != octeontx_svc_uuid[3]) {
		pr_info("UIID SVC doesn't match OcteonTX. No serdes cmds.\n");
		return -1;
	}

	return phy_dbg_setup_debugfs();
}

static void __exit phy_dbg_exit(void)
{
	debugfs_remove_recursive(phy_dbgfs_root);
}

module_init(phy_dbg_init);
module_exit(phy_dbg_exit);

MODULE_AUTHOR("Damian Eppel <deppel@marvell.com>");
MODULE_DESCRIPTION("PHYs diagnostic commands for OcteonTX");
MODULE_LICENSE("GPL v2");
