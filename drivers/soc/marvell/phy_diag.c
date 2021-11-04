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
#include <soc/marvell/octeontx/octeontx_smc.h>


#define PLAT_OCTEONTX_PHY_DBG_PRBS	0xc2000e00
#define PLAT_OCTEONTX_PHY_LOOPBACK	0xc2000e01
#define PLAT_OCTEONTX_PHY_GET_TEMP	0xc2000e02
#define PLAT_OCTEONTX_PHY_SERDES_CFG	0xc2000e03
#define PLAT_OCTEONTX_PHY_MDIO		0xc2000e04
#define PLAT_OCTEONTX_PHY_EYE_CAPTURE	0xc2000e05
#define PLAT_OCTEONTX_PHY_PKT_GEN		0xc2000e06
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

enum phy_prbs_direction {
	PRBS_DIRECTION_TX = 1,
	PRBS_DIRECTION_RX,
	PRBS_DIRECTION_TX_RX,
};

static struct {
	enum phy_prbs_direction e;
	const char *s;
} prbs_directions[] = {
	{PRBS_DIRECTION_TX, "tx"},
	{PRBS_DIRECTION_RX, "rx"},
	{PRBS_DIRECTION_TX_RX, "tx-rx"},
};
DEFINE_STR_2_ENUM_FUNC(prbs_directions)


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

/* loopback definitions */
enum phy_loopback_cmd {
	PHY_LOOPBACK_START_CMD = 1,
	PHY_LOOPBACK_STOP_CMD,
};

static struct {
	enum phy_loopback_cmd e;
	const char *s;
} loopback_cmds[] = {
	{PHY_LOOPBACK_START_CMD, "start"},
	{PHY_LOOPBACK_STOP_CMD, "stop"},
};
DEFINE_STR_2_ENUM_FUNC(loopback_cmds)


enum phy_loopback_side {
	LOOPBACK_SIDE_LINE = 0,
	LOOPBACK_SIDE_HOST,
};

static struct {
	enum phy_loopback_side e;
	const char *s;
} loopback_sides[] = {
	{LOOPBACK_SIDE_LINE, "line"},
	{LOOPBACK_SIDE_HOST, "host"},
};
DEFINE_STR_2_ENUM_FUNC(loopback_sides)

enum phy_loopback_type {
	PCS_SHALLOW = 0,
	PCS_DEEP,
	PMA_DEEP,
};

static struct {
	enum phy_loopback_type e;
	const char *s;
} loopback_types[] = {
	{PCS_SHALLOW, "pcs_shallow"},
	{PCS_DEEP, "pcs_deep"},
	{PMA_DEEP, "pma_deep"},
};
DEFINE_STR_2_ENUM_FUNC(loopback_types)

/* eye capture definitions */
enum phy_eye_side {
	EYE_SIDE_LINE = 0,
	EYE_SIDE_HOST,
	EYE_SIDE_TEST_3,
	EYE_SIDE_TEST_4,
};

static struct {
	enum phy_eye_side e;
	const char *s;
} eye_sides[] = {
	{EYE_SIDE_LINE, "line"},
	{EYE_SIDE_HOST, "host"},
	{EYE_SIDE_TEST_3, "test_3"},
	{EYE_SIDE_TEST_4, "test_4"},
};
DEFINE_STR_2_ENUM_FUNC(eye_sides)

enum phy_eye_type {
	EYE_MEASURE = 0,
	EYE_PLOT,
};

static struct {
	enum phy_eye_type e;
	const char *s;
} eye_types[] = {
	{EYE_MEASURE, "measure"},
	{EYE_PLOT, "plot"},
};
DEFINE_STR_2_ENUM_FUNC(eye_types)

/* pktgen definitions */
enum phy_pktgen_cmd {
	PHY_PKTGEN_START_CMD = 1,
	PHY_PKTGEN_STOP_CMD,
	PHY_PKTGEN_SET_CMD,
	PHY_PKTGEN_GET_CMD
};

static struct {
	enum phy_pktgen_cmd e;
	const char *s;
} pktgen_cmds[] = {
	{PHY_PKTGEN_START_CMD, "start"},
	{PHY_PKTGEN_STOP_CMD, "stop"},
	{PHY_PKTGEN_SET_CMD, "set"},
};
DEFINE_STR_2_ENUM_FUNC(pktgen_cmds)

enum phy_pktgen_mode {
	PHY_PKTGEN_GENERATOR = 0,
	PHY_PKTGEN_CHECKER,
	PHY_PKTGEN_GEN_CHECK,
};

static struct {
	enum phy_pktgen_mode e;
	const char *s;
} pktgen_modes[] = {
	{PHY_PKTGEN_GENERATOR, "tx"},
	{PHY_PKTGEN_CHECKER, "rx"},
	{PHY_PKTGEN_GEN_CHECK, "tx-rx"},
};
DEFINE_STR_2_ENUM_FUNC(pktgen_modes)


enum phy_pktgen_side {
	PKTGEN_SIDE_LINE = 0,
	PKTGEN_SIDE_HOST,
};

static struct {
	enum phy_pktgen_side e;
	const char *s;
} pktgen_sides[] = {
	{PKTGEN_SIDE_LINE, "line"},
	{PKTGEN_SIDE_HOST, "host"},
};
DEFINE_STR_2_ENUM_FUNC(pktgen_sides)

enum phy_pktgen_type {
	PKTGEN_TYPE_SFD = 0,
	PKTGEN_TYPE_PATTERN_CTL,
	PKTGEN_TYPE_DIS_CRC,
	PKTGEN_TYPE_IN_PAYLOAD,
	PKTGEN_TYPE_FRAME_LEN_CTL,
	PKTGEN_TYPE_NUM_PACKETS,
	PKTGEN_TYPE_RANDOM_IPG,
	PKTGEN_TYPE_IPG_DURATION,
};

static struct {
	enum phy_pktgen_type e;
	const char *s;
} pktgen_types[] = {
	{PKTGEN_TYPE_SFD, "sfd"},
	{PKTGEN_TYPE_PATTERN_CTL, "pattern"},
	{PKTGEN_TYPE_DIS_CRC, "dis_crc"},
	{PKTGEN_TYPE_IN_PAYLOAD, "in_payload"},
	{PKTGEN_TYPE_FRAME_LEN_CTL, "frame_len"},
	{PKTGEN_TYPE_NUM_PACKETS, "num_packets"},
	{PKTGEN_TYPE_RANDOM_IPG, "random_ipg"},
	{PKTGEN_TYPE_IPG_DURATION, "ipg_duration"},
};
DEFINE_STR_2_ENUM_FUNC(pktgen_types)

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
	int direction;
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

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	direction = prbs_directions_str2enum(token);
	if (direction == -1)
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

	cfg |= (type << 3) | (direction << 1) | host;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_DBG_PRBS, cmd, cfg,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("Configuring PRBS failed!\n");
		return count;
	}

	if (cmd == PHY_PRBS_START_CMD) {
		pr_info("PRBS %s started: side=%s, type=%s\n",
			prbs_directions[direction-1].s, prbs_sides[host].s, prbs_types[type].s);
	} else
		pr_info("PRBS stopped\n");
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
	char *end;
	char *token;
	int cmd;
	int side;
	int type = 0;
	int cfg = 0;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	end = skip_spaces(cmd_buf);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	cmd = loopback_cmds_str2enum(token);
	if (cmd == -1)
		return -EINVAL;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	side = loopback_sides_str2enum(token);
	/* If no side is passed, assume line side as default */
	if (side == -1)
		side = LOOPBACK_SIDE_LINE;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	if (cmd == PHY_LOOPBACK_START_CMD) {

		type = loopback_types_str2enum(token);
		/* If not loopback type is passed, assume shallow loopback */
		if (type == -1)
			type = PCS_SHALLOW;
	}

	cfg |= (type << 2) | side;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_LOOPBACK, cmd, cfg,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		if (cmd == PHY_LOOPBACK_START_CMD)
			pr_warn("Enabling %s side %s Loopback failed!\n",
					loopback_sides[side].s, loopback_types[type].s);
		else
			pr_warn("Disabling %s side Loopback failed!\n",
					loopback_sides[side].s);

		return count;
	}
	if (cmd == PHY_LOOPBACK_START_CMD) {
		pr_info("Loopback %s side %s type started\n",
			loopback_sides[side].s, loopback_types[type].s);
	} else {
		pr_info("Loopback %s side type stopped\n",
			loopback_sides[side].s);
	}

	return count;
}

static int phy_debug_loopback_read(struct seq_file *s, void *unused)
{
	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_loopback);

/* Eye measurement */
static ssize_t phy_debug_eye_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *end;
	char *token;
	int type = 0, side = 0;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	end = skip_spaces(cmd_buf);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	side = eye_sides_str2enum(token);
	if (side == -1)
		return -EINVAL;

	end = skip_spaces(end);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	type = eye_types_str2enum(token);

	arm_smccc_smc(PLAT_OCTEONTX_PHY_EYE_CAPTURE, side, type,
		phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0)
		pr_warn("Eye %s side %s failed!\n", eye_sides[side].s, eye_types[type].s);
	else
		pr_info("Eye %s side %s success\n", eye_sides[side].s, eye_types[type].s);
	return count;
}

static int phy_debug_eye_read(struct seq_file *s, void *unused)
{
	return 0;
}

DEFINE_ATTRIBUTE(phy_debug_eye);

/* pktgen */
static ssize_t phy_debug_pktgen_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *end;
	char *token;
	int cmd;
	int mode;
	int type = 0;
	int value = 0;
	int side;
	int cfg = 0;

	if (copy_user_input(buffer, count, cmd_buf, CMD_SZ))
		return -EFAULT;

	end = skip_spaces(cmd_buf);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	cmd = pktgen_cmds_str2enum(token);
	if (cmd == -1)
		return -EINVAL;
	switch (cmd) {
	case PHY_PKTGEN_START_CMD:
	case PHY_PKTGEN_STOP_CMD:
		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;
		mode = pktgen_modes_str2enum(token);
		if (mode == -1)
			return -EINVAL;
		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;
		side = pktgen_sides_str2enum(token);
		if (side == -1)
			return -EINVAL;
		cfg = ((cmd & 0xff) << 8) | (mode & 0xff);
		pr_info("cmd=%d mode=%d side=%d cfg=0x%x\n", cmd, mode, side, cfg);

		arm_smccc_smc(PLAT_OCTEONTX_PHY_PKT_GEN, cfg, side,
				phy_data.eth, phy_data.lmac, 0, 0, 0, &res);
		break;
	case PHY_PKTGEN_SET_CMD:
		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;
		type = pktgen_types_str2enum(token);
		if (type == -1)
			return -EINVAL;
		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;
		if (kstrtouint(token, 0, &value))
			return -EINVAL;
		cfg = ((cmd & 0xff) << 8) | (type & 0xff);

		arm_smccc_smc(PLAT_OCTEONTX_PHY_PKT_GEN, cfg, value,
				phy_data.eth, phy_data.lmac, 0, 0, 0, &res);
		break;
	default:
		pr_warn("PKTGEN failed for invalid command %d!\n", cmd);
		return -EINVAL;
	}

	if (res.a0) {
		pr_warn("PKTGEN command failed!\n");
		return count;
	}

	pr_info("PKTGEN command success!\n");
	return count;
}

static int phy_debug_pktgen_read(struct seq_file *s, void *unused)
{
	struct arm_smccc_res res;
	int cmd;
	int cfg = 0;

	cmd = PHY_PKTGEN_GET_CMD;
	cfg = (cmd & 0xff) << 8;
	arm_smccc_smc(PLAT_OCTEONTX_PHY_PKT_GEN, cfg, 0,
				phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	seq_printf(s, "PKTGEN status: %ld\n", res.a0);

	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_pktgen);

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

	dbg_file = debugfs_create_file("loopback", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_loopback_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("prbs", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_prbs_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("eye", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_eye_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("pktgen", 0644, phy_dbgfs_root, NULL,
				    &phy_debug_pktgen_fops);
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
	if (octeontx_soc_check_smc() < 0) {
		pr_info("PHY diagnostics: Not supported\n");
		return -EPERM;
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
