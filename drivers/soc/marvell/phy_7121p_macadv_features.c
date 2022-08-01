// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell
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

#define KEY_SIZE 256

#define PLAT_OCTEONTX_PHY_ADVANCE_CMDS		0xc2000b0b

#define MAX_ETH				10
#define MAX_LMAC_PER_ETH		4

int mac_debug;

#define MAC_ADV_DEBUG(fmt, arg...) \
				do { \
					if (mac_debug) \
						printk(fmt, ##arg); \
				} while (0)

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

struct dentry *phy_mac_adv_root;

#define CMD_SZ 64
char macadv_cmd_buf[CMD_SZ];

static struct {
	int eth;
	int lmac;
} phy_data;

/* MAC Advavce command definitions */
enum phy_mac_adv_cmd {

	PHY_MAC_ADV_MACSEC_SET_DA = 1,
	PHY_MAC_ADV_MACSEC_SET_KEY,
	PHY_MAC_ADV_MACSEC_ADD_POLICY,
	PHY_MAC_ADV_MACSEC_ADD_SA,
	PHY_MAC_ADV_MACSEC_ENABLE,
	PHY_MAC_ADV_MACSEC_BYPASS,
	PHY_MAC_ADV_MACSEC_TEST,
	PHY_MAC_ADV_MACSEC_PKT_TEST,
	PHY_MAC_ADV_MACSEC_GET_STATS,
	PHY_MAC_ADV_MAC_GET_STATS,
	PHY_MAC_ADV_MACSEC_GET,
	PHY_MAC_ADV_MACSEC_PTP,
	PHY_MAC_ADV_MACSEC_RE_KEY,
	PHY_MAC_ADV_MACSEC_MAX = 100,

	PHY_MAC_ADV_GEN_RCLK = 101,
	PHY_MAC_ADV_GEN_MAX = 200,
};

static struct {
	enum phy_mac_adv_cmd e;
	const char *s;
} mac_adv_macsec_cmds[] = {
	{PHY_MAC_ADV_MACSEC_SET_DA, "da"},
	{PHY_MAC_ADV_MACSEC_SET_KEY, "key"},
	{PHY_MAC_ADV_MACSEC_ENABLE, "enable"},
	{PHY_MAC_ADV_MACSEC_BYPASS, "bypass"},
	{PHY_MAC_ADV_MACSEC_TEST, "test"},
	{PHY_MAC_ADV_MACSEC_PKT_TEST, "pkttest"},
	{PHY_MAC_ADV_MACSEC_GET_STATS, "macsec_stats"},
	{PHY_MAC_ADV_MAC_GET_STATS, "mac_stats"},
	{PHY_MAC_ADV_MACSEC_PTP, "ptp_enable"},
	{PHY_MAC_ADV_MACSEC_RE_KEY, "rekey"},
};
DEFINE_STR_2_ENUM_FUNC(mac_adv_macsec_cmds)

static struct {
	enum phy_mac_adv_cmd e;
	const char *s;
} mac_adv_gen_cmds[] = {
	{PHY_MAC_ADV_GEN_RCLK, "rclk"},
};
DEFINE_STR_2_ENUM_FUNC(mac_adv_gen_cmds)

typedef enum {
	PIN_CLK_OUT_SE1 = 4,
	PIN_CLK_OUT_SE2 = 5,
	PIN_CLK_OUT_SE3 = 6,
	PIN_CLK_OUT_SE4 = 7,
} PHY_7121_RCLK_PIN_t;

static struct {
	PHY_7121_RCLK_PIN_t e;
	const char *s;
} rclk_pin[] = {
	{PIN_CLK_OUT_SE1, "se1"},
	{PIN_CLK_OUT_SE2, "se2"},
	{PIN_CLK_OUT_SE3, "se3"},
	{PIN_CLK_OUT_SE4, "se4"},
};
DEFINE_STR_2_ENUM_FUNC(rclk_pin)

typedef enum  PHY_7121_MACSEC_DIR {
	PHY_7121_MACSEC_INGRESS = 0,
	PHY_7121_MACSEC_EGRESS,
} PHY_7121_MACSEC_DIR_t;

static struct phy_mac_adv_macsec_dir {
	enum PHY_7121_MACSEC_DIR e;
	const char *s;
} macsec_dir[] = {
	{PHY_7121_MACSEC_INGRESS, "ingress"},
	{PHY_7121_MACSEC_EGRESS, "egress"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_dir)

typedef enum  PHY_7121_MACSEC_PKTTEST {
	PHY_7121_MACSEC_PKTTEST_START = 0,
	PHY_7121_MACSEC_PKTTEST_STOP,
	PHY_7121_MACSEC_PKTTEST_CHECK,
	PHY_7121_MACSEC_PKTTEST_COUNTERS,
	PHY_7121_MACSEC_PKTTEST_LPBK,
	PHY_7121_MACSEC_PKTTEST_GEN,
} PHY_7121_MACSEC_PKTTEST_t;

static struct phy_mac_adv_macsec_pkttest {
	enum PHY_7121_MACSEC_PKTTEST e;
	const char *s;
} macsec_pkttest[] = {
	{PHY_7121_MACSEC_PKTTEST_START, "start"},
	{PHY_7121_MACSEC_PKTTEST_STOP, "stop"},
	{PHY_7121_MACSEC_PKTTEST_CHECK, "check"},
	{PHY_7121_MACSEC_PKTTEST_COUNTERS, "counters"},
	{PHY_7121_MACSEC_PKTTEST_LPBK, "lpbk"},
	{PHY_7121_MACSEC_PKTTEST_GEN, "gen"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_pkttest)

typedef struct mac_da {
	PHY_7121_MACSEC_DIR_t dir;
	unsigned char  mac[6];
} mac_da_t;

#define MACSEC_KEY_SIZE 32

typedef struct key_sa {
	PHY_7121_MACSEC_DIR_t dir;
	unsigned char  key_size;
	unsigned char  key[MACSEC_KEY_SIZE];
	//unsigned char  key_ingress[MACSEC_KEY_SIZE];
	//unsigned char  key_egress[MACSEC_KEY_SIZE];
} key_sa_t;

typedef struct pkttest {
	PHY_7121_MACSEC_PKTTEST_t cmd;
} pkttest_t;

typedef struct phy_gen_rclk {
	int pin;
	int src_clk;
	int ratio;
} phy_gen_rclk_t;


typedef struct phy_7121_adv_cmds {
	int mac_adv_cmd;
	int cgx_id;
	int lmac_id;
	unsigned short  mdio_port;
	union {
		key_sa_t key;
		mac_da_t mac;
		pkttest_t pkttest_cmd;
		phy_gen_rclk_t gen_rclk;
	} data;
} phy_7121_adv_cmds_t;

/* Buffer Data */
struct memory_desc {
	void       *virt;
	dma_addr_t phys;
	uint64_t   size;
	char       pool_name[32];
};

#define BUF_DATA 0
#define BUF_COUNT 1
static struct memory_desc memdesc[BUF_COUNT] = {
	{0, 0, 1*128*1024,  "data buffer"},
};

static struct allocated_pages {
	struct page *p;
	int order;
} page_handler = {0};

static int alloc_buffers(struct memory_desc *memdesc, uint32_t required_buf)
{
	int i, required_mem = 0, page_order;
	void *page_addr;

	for (i = 0; i < BUF_COUNT; i++) {
		if (required_buf & 1<<i)
			required_mem += memdesc[i].size;
	}

	if (!required_mem)
		return 0;

	page_order = get_order(required_mem);
	page_handler.p = alloc_pages(GFP_KERNEL, page_order);
	if (!page_handler.p)
		return -ENOMEM;

	page_handler.order = page_order;
	page_addr = page_address(page_handler.p);
	memset(page_addr, 0x00, 1<<page_order);

	for (i = 0; i < BUF_COUNT; i++) {
		if (required_buf & 1<<i) {
			memdesc[i].virt = page_addr;
			memdesc[i].phys = virt_to_phys(page_addr);
			page_addr += memdesc[i].size;
		}
	}
	return 0;
}

static void free_buffers(void)
{
	int i;

	for (i = 0; i < BUF_COUNT; i++) {
		memdesc[i].phys = 0;
		memdesc[i].virt = 0;
	}

	if (page_handler.p) {
		__free_pages(page_handler.p, page_handler.order);
		page_handler.p = NULL;
		page_handler.order = 0;
	}
}

static void print_key(uint8_t *key_p, unsigned int count)
{
	int i;

	MAC_ADV_DEBUG("\n");
	for (i = 1; i <= count; i++) {
		MAC_ADV_DEBUG(" 0x%x ", key_p[i-1]);
		if (i%8 == 0)
			MAC_ADV_DEBUG("\n");
	}
}

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


static struct arm_smccc_res mrvl_exec_smc(uint64_t buf, uint64_t size)
{
	struct arm_smccc_res res;

	arm_smccc_smc(PLAT_OCTEONTX_PHY_ADVANCE_CMDS, buf, size,
			 phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	return res;
}

static ssize_t phy_debug_generic_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *end;
	char *token;
	int cmd;

	int pin;

	phy_7121_adv_cmds_t *mac_adv = (phy_7121_adv_cmds_t *)memdesc[BUF_DATA].virt;

	if (copy_user_input(buffer, count, macadv_cmd_buf, CMD_SZ))
		return -EFAULT;

	end = skip_spaces(macadv_cmd_buf);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	cmd = mac_adv_gen_cmds_str2enum(token);
	MAC_ADV_DEBUG("\n %s cmd %d", __func__, cmd);

	if (cmd == -1)
		return -EINVAL;

	memset(mac_adv, 0x00, sizeof(phy_7121_adv_cmds_t));

	mac_adv->cgx_id =  phy_data.eth;
	mac_adv->lmac_id =  phy_data.lmac;

	switch (cmd) {
	case PHY_MAC_ADV_GEN_RCLK:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_GEN_RCLK", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_GEN_RCLK;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		pin = rclk_pin_str2enum(token);
		if (pin == -1)
			return -EINVAL;
		mac_adv->data.gen_rclk.pin = pin;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		if (kstrtouint(token, 10, &mac_adv->data.gen_rclk.src_clk))
			return -EINVAL;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		if (kstrtouint(token, 10, &mac_adv->data.gen_rclk.ratio))
			return -EINVAL;
		break;

	default:
		pr_warn("MAC ADV failed for invalid command %d!\n", cmd);
		return -EINVAL;
	}

	arm_smccc_smc(PLAT_OCTEONTX_PHY_ADVANCE_CMDS,
			memdesc[BUF_DATA].phys, sizeof(phy_7121_adv_cmds_t),
			phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("MAC ADV  command failed count %d!\n", (int) count);
		return count;
	}

	pr_info("MAC ADV  command success count %x\n", (int)count);
	return count;
}

static int phy_debug_generic_read(struct seq_file *s, void *unused)
{
	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_generic);


static ssize_t phy_debug_mac_sec_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	char *end;
	char *token;
	int cmd;
	PHY_7121_MACSEC_DIR_t dir;
	PHY_7121_MACSEC_PKTTEST_t pkttest;

	phy_7121_adv_cmds_t *mac_adv = (phy_7121_adv_cmds_t *)memdesc[BUF_DATA].virt;

	if (copy_user_input(buffer, count, macadv_cmd_buf, CMD_SZ))
		return -EFAULT;

	end = skip_spaces(macadv_cmd_buf);
	token = strsep(&end, " \t\n");
	if (!token)
		return -EINVAL;

	cmd = mac_adv_macsec_cmds_str2enum(token);
	MAC_ADV_DEBUG("\n %s cmd %d", __func__, cmd);

	if (cmd == -1)
		return -EINVAL;

	memset(mac_adv, 0x00, sizeof(phy_7121_adv_cmds_t));

	mac_adv->cgx_id =  phy_data.eth;
	mac_adv->lmac_id =  phy_data.lmac;

	MAC_ADV_DEBUG(" mac_adv->cgx_id %d mac_adv->lmac_id %d\n",
					phy_data.eth, phy_data.lmac);

	switch (cmd) {
	case PHY_MAC_ADV_MACSEC_ENABLE:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ENABLE", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_ENABLE;
		break;

	case PHY_MAC_ADV_MACSEC_BYPASS:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_BYPASS", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_BYPASS;
		break;

	case PHY_MAC_ADV_MACSEC_TEST:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_TEST", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_TEST;
		break;

	case PHY_MAC_ADV_MACSEC_SET_DA:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_DA", __func__);

		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_SET_DA;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.mac.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_DA dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		sscanf(token, "%X:%X:%X:%X:%X:%X", (unsigned int *)&mac_adv->data.mac.mac[0],
						(unsigned int *)&mac_adv->data.mac.mac[1],
						(unsigned int *)&mac_adv->data.mac.mac[2],
						(unsigned int *)&mac_adv->data.mac.mac[3],
						(unsigned int *)&mac_adv->data.mac.mac[4],
						(unsigned int *)&mac_adv->data.mac.mac[5]);

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_DA"
			" mac_adv->data.mac.mac %s", __func__, (char *)mac_adv->data.mac.mac);

		if (mac_adv->data.mac.mac == 0)
			return -EINVAL;

		break;

	case PHY_MAC_ADV_MACSEC_SET_KEY:
		printk("\n %s PHY_MAC_ADV_MACSEC_SET_KEY", __func__);

		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_SET_KEY;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.key.dir = dir;

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_KEY dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		sscanf(token, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
					(unsigned int *)&mac_adv->data.key.key[0],
					(unsigned int *)&mac_adv->data.key.key[1],
					(unsigned int *)&mac_adv->data.key.key[2],
					(unsigned int *)&mac_adv->data.key.key[3],
					(unsigned int *)&mac_adv->data.key.key[4],
					(unsigned int *)&mac_adv->data.key.key[5],
					(unsigned int *)&mac_adv->data.key.key[6],
					(unsigned int *)&mac_adv->data.key.key[7],
					(unsigned int *)&mac_adv->data.key.key[8],
					(unsigned int *)&mac_adv->data.key.key[9],
					(unsigned int *)&mac_adv->data.key.key[10],
					(unsigned int *)&mac_adv->data.key.key[11],
					(unsigned int *)&mac_adv->data.key.key[12],
					(unsigned int *)&mac_adv->data.key.key[13],
					(unsigned int *)&mac_adv->data.key.key[14],
					(unsigned int *)&mac_adv->data.key.key[15]);

		mac_adv->data.key.key_size = strlen(token);

		if (strlen(token) != 47)
			printk("\nERROR Provide correct key(16) ");
		else
			mac_adv->data.key.key_size = 16;

		print_key(mac_adv->data.key.key, mac_adv->data.key.key_size);

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_KEY SIZE %d",
					__func__, mac_adv->data.key.key_size);

		break;

	case PHY_MAC_ADV_MACSEC_RE_KEY:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_RE_KEY", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_RE_KEY;
		break;

	case PHY_MAC_ADV_MACSEC_PKT_TEST:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_PKT_TEST", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_PKT_TEST;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_PKT_TEST token %s", __func__, token);

		pkttest = macsec_pkttest_str2enum(token);
		if (dir == -1)
			return -EINVAL;

		MAC_ADV_DEBUG("\n %s pkttest cmd %d", __func__, pkttest);
		mac_adv->data.pkttest_cmd.cmd = pkttest;
		MAC_ADV_DEBUG("\n %s mac_adv->data.pkttest_cmd.cmd %d", __func__, mac_adv->data.pkttest_cmd.cmd);

		break;
	case PHY_MAC_ADV_MACSEC_GET_STATS:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_GET_STATS", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_GET_STATS;
		break;
	case PHY_MAC_ADV_MAC_GET_STATS:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MAC_GET_STATS", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MAC_GET_STATS;
		break;
	case PHY_MAC_ADV_MACSEC_PTP:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_PTP", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_PTP;
		break;
	default:
		pr_warn("MAC ADV failed for invalid command %d!\n", cmd);
		return -EINVAL;
	}

	arm_smccc_smc(PLAT_OCTEONTX_PHY_ADVANCE_CMDS,
			memdesc[BUF_DATA].phys, sizeof(phy_7121_adv_cmds_t),
			phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("MAC ADV  command failed count %d!\n", (int) count);
		return count;
	}

	pr_info("MAC ADV  command success count %x\n", (int)count);
	return count;
}

static int phy_debug_mac_sec_read(struct seq_file *s, void *unused)
{
	phy_7121_adv_cmds_t *mac_adv = (phy_7121_adv_cmds_t *)memdesc[BUF_DATA].virt;

	mac_adv->mac_adv_cmd  = PHY_MAC_ADV_MACSEC_GET;

	mrvl_exec_smc(memdesc[BUF_DATA].phys,
			sizeof(phy_7121_adv_cmds_t));

	return 0;
}
DEFINE_ATTRIBUTE(phy_debug_mac_sec);

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

	if (copy_user_input(buffer, count, macadv_cmd_buf, CMD_SZ))
		return -EFAULT;

	if (parse_eth_lmac(macadv_cmd_buf, &eth, &lmac))
		return -EINVAL;

	phy_data.eth = eth;
	phy_data.lmac = lmac;

	pr_info("New PHY selected: @(eth=%d, lmac=%d)\n",
			phy_data.eth, phy_data.lmac);

	return count;
}
DEFINE_ATTRIBUTE(phy_debug_phy);

static int phy_mac_adv_setup_debugfs(void)
{
	struct dentry *dbg_file;

	phy_mac_adv_root = debugfs_create_dir("phy_7121p_macadv", NULL);

	dbg_file = debugfs_create_file("phy", 0644, phy_mac_adv_root, NULL,
				    &phy_debug_phy_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("macsec", 0644, phy_mac_adv_root, NULL,
				    &phy_debug_mac_sec_fops);
	if (!dbg_file)
		goto create_failed;

	dbg_file = debugfs_create_file("generic", 0644, phy_mac_adv_root, NULL,
				    &phy_debug_generic_fops);
	if (!dbg_file)
		goto create_failed;

	return 0;

create_failed:
	pr_err("Failed to create debugfs dir/file for octeontx_phy\n");
	debugfs_remove_recursive(phy_mac_adv_root);
	return -1;
}

static int __init phy_mac_adv_init(void)
{
	if (octeontx_soc_check_smc() < 0) {
		pr_info("PHY adv feature: Not supported\n");
		return -EPERM;
	}

	alloc_buffers(memdesc, 1<<BUF_DATA);

	mac_debug = 0;

	return phy_mac_adv_setup_debugfs();
}

static void __exit phy_mac_adv_exit(void)
{
	free_buffers();
	debugfs_remove_recursive(phy_mac_adv_root);
}

module_init(phy_mac_adv_init);
module_exit(phy_mac_adv_exit);

MODULE_AUTHOR("Narendra Hadke <nhadke@marvell.com>");
MODULE_DESCRIPTION("PHYs Advance Commands for OcteonTX");
MODULE_LICENSE("GPL v2");
