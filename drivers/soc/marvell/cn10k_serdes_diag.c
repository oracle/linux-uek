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
#include <linux/of.h>
#include <soc/marvell/octeontx/octeontx_smc.h>

#define DRV_NAME "cn10k_serdes_diag"
#define OCTEONTX_SERDES_DBG_GET_MEM		0xc2000d04
#define PLAT_OCTEONTX_SERDES_DBG_RX_TUNING	0xc2000d05
#define PLAT_OCTEONTX_SERDES_DBG_TX_TUNING	0xc2000d06
#define PLAT_OCTEONTX_SERDES_DBG_LOOPBACK	0xc2000d07
#define PLAT_OCTEONTX_SERDES_DBG_PRBS		0xc2000d08

#define PORT_LANES_MAX 4

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

#define BUF_SZ 64
static struct dentry *serdes_dbgfs_root;
static char *serdes_tuning_shmem;
static char *prbs_shmem;

#define PRBS_PRMS_MAX 6
enum prbs_subcmd {
	PRBS_START,
	PRBS_SHOW,
	PRBS_CLEAR,
	PRBS_STOP
};

static struct {
	enum prbs_subcmd e;
	const char *s;
} prbs_subcmd[] = {
	{PRBS_START, "start"},
	{PRBS_SHOW, "show"},
	{PRBS_CLEAR, "clear"},
	{PRBS_STOP, "stop"},
};

DEFINE_STR_2_ENUM_FUNC(prbs_subcmd)

enum prbs_optcmd {
	PRBS_INJECT,
	PRBS_CHECKER,
	PRBS_GENERATOR,
	PRBS_BOTH,
};

static struct {
	enum prbs_optcmd e;
	const char *s;
} prbs_optcmd[] = {
	{PRBS_INJECT, "inject"},
	{PRBS_CHECKER, "check"},
	{PRBS_GENERATOR, "gen"},
	{PRBS_BOTH, "both"},
};

DEFINE_STR_2_ENUM_FUNC(prbs_optcmd)

enum prbs_pattern {
	PRBS_7 = 7,
	PRBS_9 = 9,
	PRBS_11 = 11,
	PRBS_15 = 15,
	PRBS_16 = 16,
	PRBS_23 = 23,
	PRBS_31 = 31,
	PRBS_32 = 32
};

struct prbs_error_stats {
	u64 total_bits;
	u64 error_bits;
};

struct prbs_cmd_params {
	int port;
	int lane_idx;
	int subcmd;
	int gen_check;
	int pattern;
	int inject_cnt;
};

#define LPBK_PRMS_MAX 2

enum lpbk_type {
	LPBK_TYPE_NONE = 0,
	LPBK_TYPE_NEA,
	LPBK_TYPE_NED,
	LPBK_TYPE_FED
};

static const char *const lpbk_type[] = {
	"No Loopback",
	"NEA",
	"NED",
	"FED"
};

struct lpbk_cmd_params {
	int port;
	int type;
};

#define TX_EQ_PRMS_MAX 12

enum tx_param {
	TX_PARAM_PRE3,
	TX_PARAM_PRE2,
	TX_PARAM_PRE1,
	TX_PARAM_MAIN,
	TX_PARAM_POST,
};

struct tx_eq_params {
	u16 pre3;
	u16 pre2;
	u16 pre1;
	u16 main;
	u16 post;
};

static struct {
	enum tx_param e;
	const char *s;
} tx_param[] = {
	{TX_PARAM_PRE3, "pre3"},
	{TX_PARAM_PRE2, "pre2"},
	{TX_PARAM_PRE1, "pre1"},
	{TX_PARAM_MAIN, "main"},
	{TX_PARAM_POST, "post"},
};

DEFINE_STR_2_ENUM_FUNC(tx_param)

static struct tx_eq_cmd_params {
	int port;
	int lane_idx;
	int update;
	u32 pre3_pre2;
	u32 pre1_main;
	u32 post_flags;
} tx_eq_cmd;

#define RX_EQ_PRMS_MAX 2

static struct rx_eq_cmd_params {
	int port;
	int lane_idx;
} rx_eq_cmd;

#define DFE_TAPS_NUM 24
#define CTLE_PARAMS_NUM 13

const char *dfe_taps_names[] = {
	"dfe_dc:\t\t",
	"dfe_vre:\t",
	"dfe_f0:\t\t",
	"dfe_f1:\t\t",
	"dfe_f2:\t\t",
	"dfe_f3:\t\t",
	"dfe_f4:\t\t",
	"dfe_f5:\t\t",
	"dfe_f6:\t\t",
	"dfe_f7:\t\t",
	"dfe_f8:\t\t",
	"dfe_f9:\t\t",
	"dfe_f10:\t",
	"dfe_f11:\t",
	"dfe_f12:\t",
	"dfe_f13:\t",
	"dfe_f14:\t",
	"dfe_f15:\t",
	"dfe_ff0:\t",
	"dfe_ff1:\t",
	"dfe_ff2:\t",
	"dfe_ff3:\t",
	"dfe_ff4:\t",
	"dfe_ff5:\t",
};

const char *ctle_params_names[] = {
	"ctle_current1_sel:\t",
	"ctle_rl1_sel:\t\t",
	"ctle_rl1_extra:\t\t",
	"ctle_res1_sel:\t\t",
	"ctle_cap1_sel:\t\t",
	"ctle_en_mid_freq:\t",
	"ctle_cs1_mid:\t\t",
	"ctle_rs1_mid:\t\t",
	"ctle_current2_sel:\t",
	"ctle_rl2_sel:\t\t",
	"ctle_rl2_tune_g:\t",
	"ctle_res2_sel:\t\t",
	"ctle_cap2_sel:\t\t",
};

struct rx_eq_params {
	s32 dfe_taps[DFE_TAPS_NUM];
	u32 ctle_params[CTLE_PARAMS_NUM];
};

static int copy_input_str(const char __user *buffer, size_t count,
			char *cmd_buf, size_t buf_sz)
{
	char *s;
	size_t cnt;

	cnt = (count >= buf_sz - 1) ? buf_sz - 1 : count;

	if (copy_from_user(cmd_buf, buffer, cnt))
		return -EFAULT;

	cmd_buf[cnt] = '\0';

	s = strchr(cmd_buf, '\n');
	if (s)
		*s = '\0';

	return 0;
}

static int tokenize_input(char *cmd_str, size_t *argc,
			const char *argv[], size_t tokens_max)
{
	char *token, *endp;
	int idx = 0;

	endp = strim(cmd_str);

	while (endp && idx < tokens_max) {
		endp = skip_spaces(endp);
		token = strsep(&endp, " \t");

		if (*token)
			argv[idx++] = token;
	}

	*argc = idx;
	return (idx == tokens_max && endp) ? -1 : 0;
}

static inline void get_gserm_data(int res, int *gserm_idx,
				int *mapping, int *lanes_num)
{
	*gserm_idx = (res >> 24) & 0xff;
	*mapping = (res >> 8) & 0xffff;
	*lanes_num = res & 0xff;
}

static int serdes_dbg_rx_eq_read(struct seq_file *s, void *unused)
{
	struct arm_smccc_res res;
	int x1, port, lane_idx, max_idx;
	struct rx_eq_params *rx_eq_params;
	int lanes_num, gserm_idx, mapping;

	seq_puts(s, "SerDes Rx Tuning Parameters:\n");
	seq_puts(s, "port#:\tlane#:\tgserm#:\tg-lane#:\n");

	port = rx_eq_cmd.port;
	lane_idx = rx_eq_cmd.lane_idx;

	x1 = (lane_idx << 8) | port;

	arm_smccc_smc(PLAT_OCTEONTX_SERDES_DBG_RX_TUNING, x1, 0,
		0, 0, 0, 0, 0, &res);
	if (res.a0) {
		pr_warn("Reading Rx Tuning parameters failed\n");
		return 0;
	}

	get_gserm_data(res.a2, &gserm_idx, &mapping, &lanes_num);
	rx_eq_params = (struct rx_eq_params *)serdes_tuning_shmem;

	if (lane_idx == 0xff) {
		lane_idx = 0;
		max_idx = lanes_num;
	} else {
		max_idx = lane_idx + 1;
	}

	for (; lane_idx < max_idx; lane_idx++) {
		int idx;
		int glane = (mapping >> 4 * lane_idx) & 0xf;

		seq_printf(s, "%d\t%d\t%d\t%d\n", port, lane_idx,
			gserm_idx, glane);

		for (idx = 0; idx < DFE_TAPS_NUM; idx++)
			seq_printf(s, "\t\t%s%d\n", dfe_taps_names[idx],
				rx_eq_params[lane_idx].dfe_taps[idx]);

		seq_puts(s, "\n");
		for (idx = 0; idx < CTLE_PARAMS_NUM; idx++)
			seq_printf(s, "\t\t%s%d\n", ctle_params_names[idx],
				rx_eq_params[lane_idx].ctle_params[idx]);
	}

	return 0;
}

static int parse_rx_eq_params(const char __user *buffer, size_t count,
				struct rx_eq_cmd_params *params)
{
	const char *argv[RX_EQ_PRMS_MAX] = {0};
	char cmd_buf[BUF_SZ];
	size_t argc;
	int port, lane_idx;

	if (copy_input_str(buffer, count, cmd_buf, BUF_SZ))
		return -EINVAL;

	if (tokenize_input(cmd_buf, &argc, argv, RX_EQ_PRMS_MAX))
		return -EINVAL;

	if (!argc)
		return -EINVAL;

	if (kstrtoint(argv[0], 10, &port))
		return -EINVAL;

	port &= 0xff;

	if (argc == 2) {
		if (kstrtoint(argv[1], 10, &lane_idx))
			return -EINVAL;
	} else {
		lane_idx = 0xff;
	}

	params->port = port;
	params->lane_idx = lane_idx;

	return 0;
}

static ssize_t serdes_dbg_rx_eq_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	int port, lane_idx;

	if (parse_rx_eq_params(buffer, count, &rx_eq_cmd))
		return -EINVAL;

	port = rx_eq_cmd.port;
	lane_idx = rx_eq_cmd.lane_idx;

	if (lane_idx == 0xff)
		pr_info("Rx Tuning: requested port=%d\n", port);
	else
		pr_info("Rx Tuning: requested port=%d, lane_idx=%d\n",
			port, lane_idx);

	return count;
}
DEFINE_ATTRIBUTE(serdes_dbg_rx_eq);

static int serdes_dbg_tx_eq_read(struct seq_file *s, void *unused)
{
	struct arm_smccc_res res;
	int x1, port, lane_idx, max_idx;
	struct tx_eq_params *tx_eq_params;
	int lanes_num, gserm_idx, mapping;

	port = tx_eq_cmd.port;
	lane_idx = tx_eq_cmd.lane_idx;

	x1 = (lane_idx << 8) | port;

	seq_puts(s, "SerDes Tx Tuning Parameters:\n");
	seq_puts(s, "port#:\tlane#:\tgserm#:\tg-lane#:"
			"\tpre3:\tpre2:\tpre1:\tmain:\tpost:\n");

	arm_smccc_smc(PLAT_OCTEONTX_SERDES_DBG_TX_TUNING, x1, 0,
		0, 0, 0, 0, 0, &res);
	if (res.a0) {
		pr_warn("Reading Tx Tuning parameters failed\n");
		return 0;
	}

	get_gserm_data(res.a2, &gserm_idx, &mapping, &lanes_num);
	tx_eq_params = (struct tx_eq_params *)serdes_tuning_shmem;

	if (lane_idx == 0xff) {
		lane_idx = 0;
		max_idx = lanes_num;
	} else {
		max_idx = lane_idx + 1;
	}

	for (; lane_idx < max_idx; lane_idx++) {
		int glane = (mapping >> 4 * lane_idx) & 0xf;

		seq_printf(s, "%d\t%d\t%d\t%d\t\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\n",
		       port, lane_idx,
		       gserm_idx, glane,
		       tx_eq_params[lane_idx].pre3,
		       tx_eq_params[lane_idx].pre2,
		       tx_eq_params[lane_idx].pre1,
		       tx_eq_params[lane_idx].main,
		       tx_eq_params[lane_idx].post);
	}

	return 0;
}

static int parse_tx_eq_params(const char __user *buffer, size_t count,
				struct tx_eq_cmd_params *params)
{
	const char *argv[TX_EQ_PRMS_MAX] = {0};
	char cmd_buf[BUF_SZ];
	size_t argc;
	int port, lane_idx, arg_idx;

	if (copy_input_str(buffer, count, cmd_buf, BUF_SZ))
		return -EINVAL;

	if (tokenize_input(cmd_buf, &argc, argv, TX_EQ_PRMS_MAX))
		return -EINVAL;

	if (!argc)
		return -EINVAL;

	if (kstrtoint(argv[0], 10, &port))
		return -EINVAL;

	port &= 0xff;

	if (argc > 1 && !kstrtoint(argv[1], 10, &lane_idx)) {
		arg_idx = 2;
	} else {
		lane_idx = 0xff;
		arg_idx = 1;
	}

	params->port = port;
	params->lane_idx = lane_idx;

	if (arg_idx == argc)
		return 0;

	params->update = 1;
	params->post_flags = 0;

	/* Next parameters are optional and they should come in pairs
	 * [name <value>], like: [pre1 <pre1>].
	 * The loop below is to parse each such pair.
	 */
	while (arg_idx < argc) {
		int param;
		int value;

		param = tx_param_str2enum(argv[arg_idx]);
		if (param == -1)
			return -EINVAL;

		arg_idx++;
		if (arg_idx == argc || kstrtoint(argv[arg_idx], 0, &value))
			return -EINVAL;

		value &= 0xffff;
		arg_idx++;

		switch (param) {
		case TX_PARAM_PRE3:
			params->pre3_pre2 |= value << 16;
			params->post_flags |= BIT(0);
			break;

		case TX_PARAM_PRE2:
			params->pre3_pre2 |= value;
			params->post_flags |= BIT(1);
			break;

		case TX_PARAM_PRE1:
			params->pre1_main |= value << 16;
			params->post_flags |= BIT(2);
			break;

		case TX_PARAM_MAIN:
			params->pre1_main |= value;
			params->post_flags |= BIT(3);
			break;

		case TX_PARAM_POST:
			params->post_flags |= value << 16;
			params->post_flags |= BIT(4);
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

static ssize_t serdes_dbg_tx_eq_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int port, lane_idx, max_idx;
	int lanes_num, gserm_idx, mapping;
	int x1, x2, x3, x4;

	if (parse_tx_eq_params(buffer, count, &tx_eq_cmd))
		return -EINVAL;

	port = tx_eq_cmd.port;
	lane_idx = tx_eq_cmd.lane_idx;

	if (!tx_eq_cmd.update) {
		if (lane_idx == 0xff)
			pr_info("Tx Tuning: requested port=%d\n", port);
		else
			pr_info("Tx Tuning: requested port=%d, lane_idx=%d\n",
				port, lane_idx);

		return count;
	}

	pr_info("SerDes Tx Tuning Parameters:\n");
	pr_info("port#:\tlane#:\tgserm#:\tg-lane#:\tstatus:\n");

	x1 = (lane_idx << 8) | port;
	x2 = tx_eq_cmd.pre3_pre2;
	x3 = tx_eq_cmd.pre1_main;
	x4 = tx_eq_cmd.post_flags;

	arm_smccc_smc(PLAT_OCTEONTX_SERDES_DBG_TX_TUNING, x1, x2,
		x3, x4, 0, 0, 0, &res);
	if (res.a0) {
		pr_warn("Writing Tx Tuning parameters failed\n");
		return count;
	}

	get_gserm_data(res.a2, &gserm_idx, &mapping, &lanes_num);
	tx_eq_cmd.update = 0;

	if (lane_idx == 0xff) {
		lane_idx = 0;
		max_idx = lanes_num;
	} else {
		max_idx = lane_idx + 1;
	}

	for (; lane_idx < max_idx; lane_idx++) {
		int glane = (mapping >> 4 * lane_idx) & 0xf;

		pr_info("%d\t%d\t%d\t%d\t\tUpdated\n",
			port, lane_idx,
			gserm_idx, glane);
	}

	return count;
}
DEFINE_ATTRIBUTE(serdes_dbg_tx_eq);

static int serdes_dbg_lpbk_read(struct seq_file *s, void *unused)
{
	return 0;
}

static int parse_lpbk_params(const char __user *buffer, size_t count,
				struct lpbk_cmd_params *params)
{
	const char *argv[LPBK_PRMS_MAX] = {0};
	char cmd_buf[BUF_SZ];
	size_t argc;
	int port, type;

	if (copy_input_str(buffer, count, cmd_buf, BUF_SZ))
		return -EINVAL;

	if (tokenize_input(cmd_buf, &argc, argv, LPBK_PRMS_MAX))
		return -EINVAL;

	if (argc < 2)
		return -EINVAL;

	if (kstrtoint(argv[0], 10, &port))
		return -EINVAL;

	port &= 0xff;

	if (kstrtoint(argv[1], 10, &type))
		return -EINVAL;

	/* Validate looback type against the list below */
	switch (type) {
	case LPBK_TYPE_NONE:
	case LPBK_TYPE_NEA:
	case LPBK_TYPE_NED:
	case LPBK_TYPE_FED:
		break;

	default:
		return -EINVAL;
	}

	params->port = port;
	params->type = type;
	return 0;
}

static ssize_t serdes_dbg_lpbk_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	int lane_idx;
	int lanes_num, gserm_idx, mapping;
	struct lpbk_cmd_params input;
	struct arm_smccc_res res;
	int x1, x2;

	if (parse_lpbk_params(buffer, count, &input))
		return -EINVAL;

	pr_info("Set SerDes Loopback:\n");
	pr_info("port#:\tlane#:\tgserm#:\tg-lane#:\ttype:\n");

	x1 = (0xff << 8) | input.port;
	x2 = input.type;

	arm_smccc_smc(PLAT_OCTEONTX_SERDES_DBG_LOOPBACK, x1, x2,
		0, 0, 0, 0, 0, &res);
	if (res.a0) {
		pr_warn("Setting SerDes Loopback failed\n");
		return count;
	}

	get_gserm_data(res.a1, &gserm_idx, &mapping, &lanes_num);

	for (lane_idx = 0; lane_idx < lanes_num; lane_idx++) {
		int glane = (mapping >> 4 * lane_idx) & 0xf;

		pr_info("%d\t%d\t%d\t%d\t\t%s\n",
			input.port, lane_idx,
			gserm_idx, glane,
			lpbk_type[input.type]);
	}

	return count;
}
DEFINE_ATTRIBUTE(serdes_dbg_lpbk);



static int serdes_dbg_prbs_read(struct seq_file *s, void *unused)
{
	return 0;
}

static int parse_prbs_params(const char __user *buffer, size_t count,
				struct prbs_cmd_params *params)
{
	const char *argv[PRBS_PRMS_MAX] = {0};
	char cmd_buf[BUF_SZ];
	size_t argc;
	int optcmd, arg_idx;

	if (copy_input_str(buffer, count, cmd_buf, BUF_SZ))
		return -EINVAL;

	if (tokenize_input(cmd_buf, &argc, argv, PRBS_PRMS_MAX))
		return -EINVAL;

	if (argc < 2)
		return -EINVAL;

	params->subcmd = prbs_subcmd_str2enum(argv[0]);
	if (params->subcmd == -1)
		return -EINVAL;

	if (kstrtoint(argv[1], 10, &params->port))
		return -EINVAL;

	params->port &= 0xff;

	/* If subcmd is not PRBS_START, then the parsing is done */
	if (params->subcmd != PRBS_START) {
		params->gen_check = 0x3;
		params->pattern = 0;
		params->inject_cnt = 0;
		return 0;
	}

	/* If it is PRBS_START command, yet another mandatory
	 * parameter is required: pattern
	 */
	if (argc < 3 || kstrtoint(argv[2], 10, &params->pattern))
		return -EINVAL;

	switch (params->pattern) {
	/* Validate pattern against the list below */
	case PRBS_7:
	case PRBS_9:
	case PRBS_11:
	case PRBS_15:
	case PRBS_16:
	case PRBS_23:
	case PRBS_31:
	case PRBS_32:
		break;

	default:
		return -EINVAL;
	}

	/* All other parameters are optional, thus enabled
	 * generator and checker by default and setting
	 * inject_cnt to zero just in case they are not
	 * provided.
	 */
	params->inject_cnt = 0;
	params->gen_check = PRBS_GENERATOR | PRBS_CHECKER;
	arg_idx = 3;

	while (arg_idx < argc) {
		optcmd = prbs_optcmd_str2enum(argv[arg_idx]);
		arg_idx++;

		switch (optcmd) {
		case PRBS_INJECT:
			if (arg_idx == argc || kstrtoint(argv[arg_idx], 10,
							&params->inject_cnt)) {
				return -EINVAL;
			}
			arg_idx++;
			break;

		case PRBS_GENERATOR:
			params->gen_check = PRBS_GENERATOR;
			break;

		case PRBS_CHECKER:
			params->gen_check = PRBS_CHECKER;
			break;

		case PRBS_BOTH:
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

static ssize_t serdes_dbg_prbs_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	int lane_idx;
	int lanes_num, gserm_idx, mapping;
	struct prbs_cmd_params input;
	struct arm_smccc_res res;
	int x1, x2, x3;

	if (parse_prbs_params(buffer, count, &input))
		return -EINVAL;

	x1 = (input.gen_check << 18) |
		(input.subcmd << 16) |
		(0xff << 8) | input.port;

	x2 = input.pattern;
	x3 = input.inject_cnt;

	arm_smccc_smc(PLAT_OCTEONTX_SERDES_DBG_PRBS, x1, x2,
		x3, 0, 0, 0, 0, &res);
	if (res.a0) {
		pr_warn("Setting SerDes PRBS failed\n");
		return count;
	}

	get_gserm_data(res.a2, &gserm_idx, &mapping, &lanes_num);

	pr_info("SerDes PRBS:\n");
	switch (input.subcmd) {
	case PRBS_START:
	{
		pr_info("port#:\tlane#:\tgserm#:\tg-lane#:\tpattern:"
					"\tgen/check:\tinject:\tcmd:\n");
		for (lane_idx = 0; lane_idx < lanes_num; lane_idx++) {
			int glane = (mapping >> 4 * lane_idx) & 0xf;

			pr_info("%d\t%d\t%d\t%d\t\t%d\t\t%s\t\t%d\t%s\n",
			       input.port,
			       lane_idx,
			       gserm_idx,
			       glane,
			       input.pattern,
			       prbs_optcmd[input.gen_check].s,
			       input.inject_cnt,
			       prbs_subcmd[input.subcmd].s);
		}
	}	break;

	case PRBS_SHOW:
	{
		struct prbs_error_stats *error_stats =
				(struct prbs_error_stats *)prbs_shmem;

		pr_info("port#:\tlane#:\tgserm#:\tg-lane#:"
				"\ttotal_bits:\terror_bits:\n");
		for (lane_idx = 0; lane_idx < lanes_num; lane_idx++) {
			int glane = (mapping >> 4 * lane_idx) & 0xf;

			pr_info("%d\t%d\t%d\t%d\t\t%llu\t\t%llu\n",
			       input.port,
			       lane_idx,
			       gserm_idx,
			       glane,
			       error_stats[lane_idx].total_bits,
			       error_stats[lane_idx].error_bits);
		}
	}	break;

	default:
		pr_info("port#:\tlane#:\tgserm#:\tg-lane#:\tcmd:\n");
		for (lane_idx = 0; lane_idx < lanes_num; lane_idx++) {
			int glane = (mapping >> 4 * lane_idx) & 0xf;

			pr_info("%d\t%d\t%d\t%d\t\t%s\n",
			       input.port, lane_idx,
			       gserm_idx, glane,
			       prbs_subcmd[input.subcmd].s);
		}
		break;
	}

	return count;
}
DEFINE_ATTRIBUTE(serdes_dbg_prbs);

static int serdes_dbg_setup_debugfs(void)
{
	struct dentry *dbg_file;

	serdes_dbgfs_root = debugfs_create_dir("serdes_diagnostics", NULL);

	dbg_file = debugfs_create_file("prbs", 0644, serdes_dbgfs_root, NULL,
				    &serdes_dbg_prbs_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("loopback", 0644, serdes_dbgfs_root, NULL,
				    &serdes_dbg_lpbk_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("rx_params", 0644, serdes_dbgfs_root, NULL,
				    &serdes_dbg_rx_eq_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("tx_params", 0644, serdes_dbgfs_root, NULL,
				    &serdes_dbg_tx_eq_fops);
	if (!dbg_file)
		goto create_failed;

	return 0;

create_failed:
	pr_err("Failed to create debugfs dir/file for serdes_diagnostics\n");
	debugfs_remove_recursive(serdes_dbgfs_root);
	return -1;
}

static int __init serdes_dbg_init(void)
{
	struct arm_smccc_res res;

	if (octeontx_soc_check_smc() != 2) {
		pr_info(DRV_NAME": Not supported\n");
		return -EPERM;
	}

	arm_smccc_smc(OCTEONTX_SERDES_DBG_GET_MEM, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_info(DRV_NAME
			": Firmware doesn't support serdes diagnostic cmds.\n");
		return -EPERM;
	}

	if (res.a0 != SMCCC_RET_SUCCESS)
		return -ENOMEM;

	serdes_tuning_shmem = ioremap_wc(res.a2,
		PORT_LANES_MAX * sizeof(struct rx_eq_params));

	if (!serdes_tuning_shmem)
		goto tuning_shmem_failed;

	prbs_shmem = ioremap_wc(res.a3,
		PORT_LANES_MAX * sizeof(struct prbs_error_stats));

	if (!prbs_shmem)
		goto prbs_shmem_failed;

	return serdes_dbg_setup_debugfs();

prbs_shmem_failed:
	iounmap(serdes_tuning_shmem);
tuning_shmem_failed:
	return -ENOMEM;
}

static void __exit serdes_dbg_exit(void)
{
	debugfs_remove_recursive(serdes_dbgfs_root);

	if (serdes_tuning_shmem)
		iounmap(serdes_tuning_shmem);

	if (prbs_shmem)
		iounmap(prbs_shmem);
}

module_init(serdes_dbg_init);
module_exit(serdes_dbg_exit);

MODULE_AUTHOR("Damian Eppel <deppel@marvell.com>");
MODULE_DESCRIPTION("SerDes diagnostic commands for CN10K");
MODULE_LICENSE("GPL v2");
