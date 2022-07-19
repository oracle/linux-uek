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


enum PHY_7121_MACSEC_DBG {
	PHY_7121_MACSEC_DBG_DISABLE = 0,
	PHY_7121_MACSEC_DBG_ENABLE,
};

enum PHY_7121_MACSEC_DBG mac_debug;

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
	PHY_MAC_ADV_MACSEC_SET_PKT_NUM,
	PHY_MAC_ADV_MACSEC_SET_SCI,
	PHY_MAC_ADV_MACSEC_ADD_VPORT,
	PHY_MAC_ADV_MACSEC_DEL_SA,
	PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA,
	PHY_MAC_ADV_MACSEC_DROPTYPE_SA,
	PHY_MAC_ADV_MACSEC_GET_MAC_ADDR,
	PHY_MAC_ADV_MACSEC_GET_SA_PARAMS,
	PHY_MAC_ADV_MACSEC_DBG,

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
	{PHY_MAC_ADV_MACSEC_SET_PKT_NUM, "pktnum"},
	{PHY_MAC_ADV_MACSEC_ADD_SA, "sa_add"},
	{PHY_MAC_ADV_MACSEC_SET_SCI, "sci"},
	{PHY_MAC_ADV_MACSEC_ADD_VPORT, "vport"},
	{PHY_MAC_ADV_MACSEC_DEL_SA, "sa_del"},
	{PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA, "sa_action"},
	{PHY_MAC_ADV_MACSEC_GET_MAC_ADDR, "get_mac"},
	{PHY_MAC_ADV_MACSEC_GET_SA_PARAMS, "get_sa_params"},
	{PHY_MAC_ADV_MACSEC_DBG, "macsec_dbg"},
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

enum  PHY_7121_MACSEC_DIR {
	PHY_7121_MACSEC_INGRESS = 0,
	PHY_7121_MACSEC_EGRESS,
};

static struct phy_mac_adv_macsec_dir {
	enum PHY_7121_MACSEC_DIR e;
	const char *s;
} macsec_dir[] = {
	{PHY_7121_MACSEC_INGRESS, "rx"},
	{PHY_7121_MACSEC_EGRESS, "tx"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_dir)

enum  PHY_7121_MACSEC_PKTTEST {
	PHY_7121_MACSEC_PKTTEST_START = 0,
	PHY_7121_MACSEC_PKTTEST_STOP,
	PHY_7121_MACSEC_PKTTEST_CHECK,
	PHY_7121_MACSEC_PKTTEST_COUNTERS,
	PHY_7121_MACSEC_PKTTEST_LPBK,
	PHY_7121_MACSEC_PKTTEST_GEN,
};

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

struct mac_da {
	enum PHY_7121_MACSEC_DIR dir;
	unsigned char  mac[6];
};

#define MACSEC_KEY_SIZE 16
#define MACSEC_SCI_SIZE 8

#define MAX_KEYS_PER_SA 2
#define MAX_SA_PER_PORT 4

enum PHY_7121_MACSEC_SA {
	PHY_7121_MACSEC_SA_0 = 0,
	PHY_7121_MACSEC_SA_1,
	PHY_7121_MACSEC_SA_2,
	PHY_7121_MACSEC_SA_3,
};

static struct phy_mac_adv_macsec_sa {
	enum PHY_7121_MACSEC_SA e;
	const char *s;
} macsec_sa[] = {
	{PHY_7121_MACSEC_SA_0, "sa_0"},
	{PHY_7121_MACSEC_SA_1, "sa_1"},
	{PHY_7121_MACSEC_SA_2, "sa_2"},
	{PHY_7121_MACSEC_SA_3, "sa_3"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_sa)


enum PHY_7121_MACSEC_VPORT {
	PHY_7121_MACSEC_VPORT_0 = 0,
	PHY_7121_MACSEC_VPORT_1,
};

static struct phy_mac_adv_macsec_vport {
	enum PHY_7121_MACSEC_VPORT e;
	const char *s;
} macsec_vport[] = {
	{PHY_7121_MACSEC_VPORT_0, "vport_0"},
	{PHY_7121_MACSEC_VPORT_1, "vport_1"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_vport)

struct macsec_vport_params {
	enum PHY_7121_MACSEC_VPORT  vport_num;
	enum PHY_7121_MACSEC_DIR dir;
	unsigned char mac[6];
};

enum PHY_7121_MACSEC_SA_ACTIONTYPE {
	SECY_SA_ACTION_BYPASS = 0,
	SECY_SA_ACTION_DROP,
	SECY_SA_ACTION_INGRESS,
	SECY_SA_ACTION_EGRESS,
	SECY_SA_ACTION_CRYPT_AUTH,
};

static struct phy_mac_adv_macsec_sa_actiontype {
	enum PHY_7121_MACSEC_SA_ACTIONTYPE e;
	const char *s;
} macsec_sa_actiontype[] = {
	{SECY_SA_ACTION_BYPASS, "bypass"},
	{SECY_SA_ACTION_DROP, "drop"},
	{SECY_SA_ACTION_INGRESS, "ingress"},
	{SECY_SA_ACTION_EGRESS, "egress"},
	{SECY_SA_ACTION_CRYPT_AUTH, "crypt_auth"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_sa_actiontype)

enum PHY_7121_MACSEC_SA_DROPTYPE {
	SECY_SA_DROP_CRC_ERROR = 0,
	SECY_SA_DROP_PKT_ERROR,
	SECY_SA_DROP_INTERNAL,
	SECY_SA_DROP_NONE
};

static struct phy_mac_adv_macsec_sa_droptype {
	enum PHY_7121_MACSEC_SA_DROPTYPE e;
	const char *s;
} macsec_sa_droptype[] = {
	{SECY_SA_DROP_CRC_ERROR, "crc_error"},
	{SECY_SA_DROP_PKT_ERROR, "pkt_error"},
	{SECY_SA_DROP_INTERNAL, "internal"},
	{SECY_SA_DROP_NONE, "none"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_sa_droptype)

static struct phy_mac_adv_macsec_dbg {
	enum PHY_7121_MACSEC_DBG e;
	const char *s;
} macsec_dbg[] = {
	{PHY_7121_MACSEC_DBG_DISABLE, "disable"},
	{PHY_7121_MACSEC_DBG_ENABLE, "enable"},
};
DEFINE_STR_2_ENUM_FUNC(macsec_dbg)

struct macsec_sa_params {
	enum PHY_7121_MACSEC_SA  sa_num;
	enum PHY_7121_MACSEC_DIR dir;
	uint32_t flags;
	bool is_actiontype;
	enum PHY_7121_MACSEC_SA_ACTIONTYPE actiontype;
	bool is_droptype;
	enum PHY_7121_MACSEC_SA_DROPTYPE droptype;
	bool is_key;
	unsigned char key[MACSEC_KEY_SIZE];
	unsigned int key_size;
	bool is_sci;
	unsigned char sci[MACSEC_SCI_SIZE];
	bool is_seq_no;
	uint32_t seq_num_lo;
	uint32_t seq_num_hi;
	bool is_ethertype;
	uint32_t ethertype;
};

typedef struct pkttest {
	enum PHY_7121_MACSEC_PKTTEST cmd;
} pkttest_t;

typedef struct phy_gen_rclk {
	int pin;
	int src_clk;
	int ratio;
} phy_gen_rclk_t;

#define MACSEC_ADV_CMD_VERS_MAJOR  0x0001
#define MACSEC_ADV_CMD_VERS_MINOR  0x0000
#define MACSEC_ADV_CMD_VERS  (MACSEC_ADV_CMD_VERS_MAJOR \
				| MACSEC_ADV_CMD_VERS_MINOR)

struct phy_7121_adv_cmds {
	int mac_adv_cmd_ver;
	int mac_adv_dbg;
	int mac_adv_cmd;
	int cgx_id;
	int lmac_id;
	unsigned short  mdio_port;
	union {
		struct macsec_sa_params sa_params;
		struct macsec_vport_params vport_params;
		struct pkttest pkttest_cmd;
		phy_gen_rclk_t gen_rclk;
	} data;
};

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
	for (i = 0; i < count; i++) {
		MAC_ADV_DEBUG(" 0x%x ", key_p[i]);
		if (i == 8)
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

	struct phy_7121_adv_cmds *mac_adv =
		(struct phy_7121_adv_cmds *)memdesc[BUF_DATA].virt;

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

	memset(mac_adv, 0x00, sizeof(struct phy_7121_adv_cmds));

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
			memdesc[BUF_DATA].phys, sizeof(struct phy_7121_adv_cmds),
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
	enum PHY_7121_MACSEC_DIR dir;
	enum PHY_7121_MACSEC_PKTTEST pkttest;
	enum PHY_7121_MACSEC_SA sa;
	enum PHY_7121_MACSEC_SA_ACTIONTYPE actiontype;
	enum PHY_7121_MACSEC_SA_DROPTYPE droptype;
	enum PHY_7121_MACSEC_DBG macsec_dbg;
	int status;

	struct phy_7121_adv_cmds *mac_adv = (struct phy_7121_adv_cmds *)memdesc[BUF_DATA].virt;

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

	memset(mac_adv, 0x00, sizeof(struct phy_7121_adv_cmds));

	mac_adv->mac_adv_cmd_ver = MACSEC_ADV_CMD_VERS;
	MAC_ADV_DEBUG("\n %s mac_adv->mac_adv_cmd_ver %x", __func__,
						mac_adv->mac_adv_cmd_ver);

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
		mac_adv->data.vport_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_DA dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		status = sscanf(token, "%X:%X:%X:%X:%X:%X",
					(unsigned int *)&mac_adv->data.vport_params.mac[0],
					(unsigned int *)&mac_adv->data.vport_params.mac[1],
					(unsigned int *)&mac_adv->data.vport_params.mac[2],
					(unsigned int *)&mac_adv->data.vport_params.mac[3],
					(unsigned int *)&mac_adv->data.vport_params.mac[4],
					(unsigned int *)&mac_adv->data.vport_params.mac[5]);
		if (status == -1) {
			pr_err("\n %s ERROR  mac address not provided", __func__);
			return -EINVAL;
		}

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_DA mac_adv->data.mac.mac %s",
				__func__, (char *)mac_adv->data.vport_params.mac);

		if (mac_adv->data.vport_params.mac == 0)
			return -EINVAL;

		break;

	case PHY_MAC_ADV_MACSEC_SET_KEY:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_KEY", __func__);

		memset(mac_adv->data.sa_params.key, 0, MACSEC_KEY_SIZE);

		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_SET_KEY;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_SET_KEY 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_KEY sa %d", __func__, sa);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_SET_KEY 3", __func__);
			return -EINVAL;
		}

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_KEY dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		MAC_ADV_DEBUG(" ++++++ %s", token);

		status = sscanf(token, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
					(unsigned int *)&mac_adv->data.sa_params.key[0],
					(unsigned int *)&mac_adv->data.sa_params.key[1],
					(unsigned int *)&mac_adv->data.sa_params.key[2],
					(unsigned int *)&mac_adv->data.sa_params.key[3],
					(unsigned int *)&mac_adv->data.sa_params.key[4],
					(unsigned int *)&mac_adv->data.sa_params.key[5],
					(unsigned int *)&mac_adv->data.sa_params.key[6],
					(unsigned int *)&mac_adv->data.sa_params.key[7],
					(unsigned int *)&mac_adv->data.sa_params.key[8],
					(unsigned int *)&mac_adv->data.sa_params.key[9],
					(unsigned int *)&mac_adv->data.sa_params.key[10],
					(unsigned int *)&mac_adv->data.sa_params.key[11],
					(unsigned int *)&mac_adv->data.sa_params.key[12],
					(unsigned int *)&mac_adv->data.sa_params.key[13],
					(unsigned int *)&mac_adv->data.sa_params.key[14],
					(unsigned int *)&mac_adv->data.sa_params.key[15]);

		if (status == -1) {
			pr_err("\n %s ERROR  sci not provided", __func__);
			return -EINVAL;
		}

		if (strlen(token) != 47) {
			pr_err("\nERROR Provide correct key(16) %d", (int)strlen(token));
			return -EINVAL;
		}

		mac_adv->data.sa_params.key_size = MACSEC_KEY_SIZE;

		print_key((unsigned  char *)mac_adv->data.sa_params.key,
						mac_adv->data.sa_params.key_size);

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_KEY SIZE %d",
					__func__, mac_adv->data.sa_params.key_size);

		mac_adv->data.sa_params.is_key = true;
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

	case PHY_MAC_ADV_MACSEC_SET_SCI:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_SCI", __func__);

		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_SET_SCI;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_SET_KEY 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_SCI dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		status = sscanf(token, "%X:%X:%X:%X:%X:%X:%X:%X",
						(unsigned int *)&mac_adv->data.sa_params.sci[0],
						(unsigned int *)&mac_adv->data.sa_params.sci[1],
						(unsigned int *)&mac_adv->data.sa_params.sci[2],
						(unsigned int *)&mac_adv->data.sa_params.sci[3],
						(unsigned int *)&mac_adv->data.sa_params.sci[4],
						(unsigned int *)&mac_adv->data.sa_params.sci[5],
						(unsigned int *)&mac_adv->data.sa_params.sci[6],
						(unsigned int *)&mac_adv->data.sa_params.sci[7]);

		if (status == -1) {
			pr_err("\n %s ERROR  sci not provided", __func__);
			return -EINVAL;
		}

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_SCI mac_adv->data.sci_id.sci %s",
						__func__, (char *)mac_adv->data.sa_params.sci);

		if (mac_adv->data.sa_params.sci == 0)
			return -EINVAL;

		mac_adv->data.sa_params.is_sci = true;

		break;

	case PHY_MAC_ADV_MACSEC_SET_PKT_NUM:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_PKT_NUM", __func__);

		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_SET_PKT_NUM;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_SET_KEY 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_PKT_NUM dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		status = sscanf(token, "%X:%X",
				(unsigned int *)&mac_adv->data.sa_params.seq_num_hi,
				(unsigned int *)&mac_adv->data.sa_params.seq_num_lo);
		if (status == -1) {
			pr_err("\n %s ERROR seq_num_lo not provided", __func__);
			return -EINVAL;
		}

		if (mac_adv->data.sa_params.seq_num_lo == -1)
			return -EINVAL;

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_PKT_NUM num.seq_num_lo %x",
				__func__, mac_adv->data.sa_params.seq_num_lo);

		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_SET_PKT_NUM seq_num_hi %x",
				__func__, mac_adv->data.sa_params.seq_num_hi);

		mac_adv->data.sa_params.is_seq_no = true;
		break;

	case PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA 1",
									__func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA sa %d",
								__func__, sa);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA dir %d",
								__func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		actiontype = macsec_sa_actiontype_str2enum(token);
		if (actiontype == -1)
			return -EINVAL;
		mac_adv->data.sa_params.actiontype = actiontype;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ACTIONTYPE_SA actiontype %d",
							__func__, actiontype);

		mac_adv->data.sa_params.is_actiontype = true;
		break;

	case PHY_MAC_ADV_MACSEC_DROPTYPE_SA:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DROPTYPE_SA", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_DROPTYPE_SA;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_DROPTYPE_SA 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DROPTYPE_SA sa %d", __func__, sa);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DROPTYPE_SA dir %d", __func__, dir);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		droptype = macsec_sa_droptype_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.droptype = droptype;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DROPTYPE_SA droptype %d",
								__func__, droptype);

		mac_adv->data.sa_params.is_droptype = true;
		break;

	case PHY_MAC_ADV_MACSEC_ADD_SA:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ADD_SA", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_ADD_SA;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_ADD_SA 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ADD_SA sa %d", __func__, sa);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_ADD_SA dir %d", __func__, dir);

		break;

	case PHY_MAC_ADV_MACSEC_DEL_SA:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DEL_SA", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_DEL_SA;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_DEL_SA 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DEL_SA sa %d", __func__, sa);

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token)
			return -EINVAL;

		dir = macsec_dir_str2enum(token);
		if (dir == -1)
			return -EINVAL;
		mac_adv->data.sa_params.dir = dir;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DEL_SA dir %d", __func__, dir);
		break;

	case PHY_MAC_ADV_MACSEC_GET_MAC_ADDR:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_GET_MAC_ADDR", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_GET_MAC_ADDR;
		break;

	case PHY_MAC_ADV_MACSEC_GET_SA_PARAMS:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_GET_SA_PARAMS", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_GET_SA_PARAMS;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_GET_SA_PARAMS 1", __func__);
			return -EINVAL;
		}

		sa = macsec_sa_str2enum(token);
		if (sa == -1)
			return -EINVAL;
		mac_adv->data.sa_params.sa_num = sa;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_GET_SA_PARAMS sa %d", __func__, sa);
		break;

	case PHY_MAC_ADV_MACSEC_DBG:
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DBG", __func__);
		mac_adv->mac_adv_cmd = PHY_MAC_ADV_MACSEC_DBG;

		end = skip_spaces(end);
		token = strsep(&end, " \t\n");
		if (!token) {
			pr_err("\n %s ERROR PHY_MAC_ADV_MACSEC_DBG 1", __func__);
			return -EINVAL;
		}

		mac_debug = macsec_dbg_str2enum(token);
		if (macsec_dbg == -1)
			return -EINVAL;
		mac_adv->mac_adv_dbg = mac_debug;
		MAC_ADV_DEBUG("\n %s PHY_MAC_ADV_MACSEC_DBG sa %d",
							__func__, macsec_dbg);
		break;

	default:
		pr_warn("MAC ADV failed for invalid command %d!\n", cmd);
		return -EINVAL;
	}

	arm_smccc_smc(PLAT_OCTEONTX_PHY_ADVANCE_CMDS,
			memdesc[BUF_DATA].phys, sizeof(struct phy_7121_adv_cmds),
			phy_data.eth, phy_data.lmac, 0, 0, 0, &res);

	if (res.a0) {
		pr_warn("MAC ADV  command failed count %d!\n", (int)count);
		return count;
	}

	pr_info("MAC ADV  command success count %d!\n", (int)count);
	return count;
}

static int phy_debug_mac_sec_read(struct seq_file *s, void *unused)
{
	struct phy_7121_adv_cmds *mac_adv = (struct phy_7121_adv_cmds *)memdesc[BUF_DATA].virt;

	mac_adv->mac_adv_cmd  = PHY_MAC_ADV_MACSEC_GET;

	mrvl_exec_smc(memdesc[BUF_DATA].phys,
			sizeof(struct phy_7121_adv_cmds));

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

	mac_debug = PHY_7121_MACSEC_DBG_DISABLE;

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
