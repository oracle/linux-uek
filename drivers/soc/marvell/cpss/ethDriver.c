/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the two
license alternatives that you have not elected to use and (iii) preserve the
Marvell copyright notice above.

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
*******************************************************************************/
/* Undef when testing done */
/* #define MVPPND_DEBUG_CONTROL_PATH */
/* #define MVPPND_DEBUG_REG */
/* #define MVPPND_DEBUG_DATA_PATH */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/if_vlan.h>
#ifdef MVPPND_DEBUG_DATA_PATH
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#endif
#include <linux/kthread.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,16,0)
#include <asm-generic/bitops/find.h>
#else
#include <linux/find.h>
#endif
#include "ethDriver.h"

/* #define DBG_DELAY */

#if defined(CONFIG_OF)
#define SUPPORT_PLATFORM_DEVICE
#endif

#ifdef SUPPORT_PLATFORM_DEVICE
#include <linux/of.h>
#include <linux/of_irq.h>
#endif

#define ETH_DRV_VER "1.03"

/* TODO List
- Complete queue initialization (i.e. when CPSS skip init our queues)
- Update "implementation" sections in the design document
*/

/* HW related constants */
#define PCI_DEVICE_ID_FALCON  0x8400
#define PCI_DEVICE_ID_AC5P    0x9400
#define PCI_DEVICE_ID_HARRIER 0x9041
#define PCI_DEVICE_ID_AC5X_1  0x9803
#define PCI_DEVICE_ID_AC5X_2  0x981f
#define PCI_DEVICE_ID_ALDRIN2 0xcc0f
#define PCI_DEVICE_ID_IML     0xa000
#define PCI_DEVICE_ID_AC5     0xb400
#define NUM_OF_TX_QUEUES NUM_OF_RX_QUEUES
#define NUM_OF_ATU_WINDOWS 8
#define NUM_OF_MG_WINDOWS 6
#define ATU_OFFS 0x1200 /* iATU offset in bar0 */
#define ATU_WIN_SIZE 0x000FFFFF

/* MG Registers */
#define REG_ADDR_BASE_FALCON		0x1D000000
#define REG_ADDR_BASE_AC5P		0x3C200000
#define REG_ADDR_BASE_AC5X		0x7F900000
#define REG_ADDR_BASE_AC5		0x0
#define REG_ADDR_BASE_MASK		ATU_WIN_SIZE /* To mask reg addr with */
#define REG_ADDR_BASE_MG_SHIFT		20 /* MG cluster ID bit in reg addr */
#define REG_ADDR_VENDOR			0x0050
#define REG_ADDR_DEVICE			0x004C
#define REG_ADDR_RX_FIRST_DESC		0x260C
#define REG_ADDR_RX_QUEUE_CMD		0x2680
#define REG_ADDR_TX_FIRST_DESC		0x26C0
#define REG_ADDR_TX_QUEUE_CMD		0x2868
#define REG_ADDR_MG_BASE_ADDR		0x020C
#define REG_ADDR_MG_SIZE		0x0210
#define REG_ADDR_MG_HA			0x023C
#define REG_ADDR_MG_CONTROL		0x0254
#define REG_ADDR_SDMA_CONF		0x2800
#define REG_ADDR_TX_MASK_0		0x2818
#define REG_ADDR_PG_CFG_QUEUE		0x28B0
#define REG_ADDR_PORT2_MASK_0		0x015C
#define REG_ADDR_RX_CAUSE_1		0x2890

static const long REG_ADDR_GLOBAL_MASK[] = {
	0x0034,
	0x0614
};

static const long REG_ADDR_RX_MASK[] = {
	0x2814,
	0x28A0
};

/* Array based registers index formulas */
enum {
	REG_ADDR_RX_FIRST_DESC_OFFSET_FORMULA	= 0x10,
	REG_ADDR_TX_FIRST_DESC_OFFSET_FORMULA	= 0x4,
	REG_ADDR_MG_BASE_ADDR_OFFSET_FORMULA	= 0x8,
	REG_ADDR_MG_SIZE_OFFSET_FORMULA		= 0x8,
	REG_ADDR_MG_HA_OFFSET_FORMULA		= 0x4,
	REG_ADDR_MG_CONTROL_OFFSET_FORMULA	= 0x4,
	REG_ADDR_PG_CFG_QUEUE_OFFSET_FORMULA	= 0x4,
};

/* TX descriptor status/command field bits */
enum {
	TX_CMD_BIT_OWN_SDMA	= (1 << 31),
	TX_CMD_BIT_FIRST	= (1 << 21),
	TX_CMD_BIT_LAST		= (1 << 20),
	TX_CMD_BIT_CRC		= (1 << 12),
};

/* RX descriptor status/command field bits */
enum {
	RX_CMD_BIT_OWN_SDMA	= (1 << 31),
	RX_CMD_BIT_CSUM		= (1 << 30),
	RX_CMD_BIT_LAST		= (1 << 26),
	RX_CMD_BIT_FIRST	= (1 << 27),
	RX_CMD_BIT_RES_ERR	= (1 << 28),
	RX_CMD_BIT_EN_INTR	= (1 << 29),
	RX_CMD_BIT_BUS_ERR	= (1 << 30),
};

/* Descriptor related macros */
#undef BIT_MASK
#define BIT_MASK(numOfBits) ((1ULL << numOfBits) - 1)
#define FIELD_MASK_NOT(offset, len) (~(BIT_MASK((len)) << (offset)))
#define U32_SET_FIELD(data, offset, length, val) \
	(data) = (((data) & FIELD_MASK_NOT((offset), (length))) | \
		  ((val) << (offset)))

#define TX_DESC_SET_BYTE_CNT(bc, val) \
	(U32_SET_FIELD(bc, 16, 14, val))

#define RX_DESC_SET_BYTE_CNT(bc, val) \
	bc = 0; \
	(U32_SET_FIELD(bc, 16, 14, val))

#define RX_DESC_GET_BYTE_CNT(bc) \
	((bc >> 16) & 0x3FFF)
#define RX_DESC_SET_BUFF_SIZE(bc, val) \
	bc = __builtin_bswap32(bc); \
	U32_SET_FIELD(bc, 0, 14, val); \
	bc = __builtin_bswap32(bc);

/* Configurable constants */
#define DRV_NAME "mvppnd_netdev"
#define MAX_NETDEVS (2 << 8)
#define DEF_ATU_WIN_AC5X 3

/* How long to wait for SDMA to take ownership of a descriptor */
static const unsigned long TX_WAIT_FOR_CPU_OWENERSHIP_USEC = 100000;
/* How many SKBs we allow to have in our TX ring */
static const unsigned long TX_QUEUE_SIZE = 10000;
static const u16 DEFAULT_NAPI_POLL_WEIGHT = NAPI_POLL_WEIGHT;
static const u8 MAX_EMPTY_NAPI_POLL = 20;
static const int RX_THREAD_UDELAY = 5000;
static const u16 DEFAULT_ATU_WIN = 5;
/* MG windows - one for coherent and max 2 for streaming, indexes below */
static const u8 DEFAULT_MG_WIN = 0xE;
static const u8 MG_WIN_COHERENT_IDX = 0;
static const u8 MG_WIN_STREAMING1_IDX = 1;
static const u8 MG_WIN_STREAMING2_IDX = 2;
static const u8 DEFAULT_TX_DSA[] = {0x50, 0x02, 0x10, 0x00, 0x88, 0x08, 0x40,
				    0x00, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				    0x0}; /* Forward */
/* TX ring size for MAC, DSA, head and all frags */
static const u16 TX_RING_SIZE = roundup_pow_of_two(MAX_FRAGS + 3);
static const u16 DEFAULT_RX_RING_SIZE = roundup_pow_of_two(128);
static const u32 DEFAULT_PKT_SZ = 2048; /* Multiplications of 8 */
static const u32 DEFAULT_TX_QUEUE = 4;
static const u32 DEFAULT_RX_QUEUES = 0xFF; /* default to max for better testing coverage */
static const u8 CRC_SIZE = 4;

static const u8 DEFAULT_MAC[] = {0x00, 0x50, 0x43, 0x0, 0x0, 0x0};
/* Default mask is each flow is port, ex. flow 1 is port #1 */
static const u8 DEFAULT_RX_DSA_MASK[] = {0x00, 0xF8, 0x00, 0x00, 0x00, 0x00,
					 0x0c, 0x00, 0x00, 0x30, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00};

static unsigned int last_poll_pkts, max_poll_pkts = 0;
static unsigned int last_budget_pkts, max_budget_pkts = 0;
static unsigned long no_skbs, tx_tout;
static unsigned long tx_busy_size, tx_busy_mem;

/* Defines slot for each statistics attribute in stats array */
enum mvppnd_stats {
	STATS_RX_PACKETS = 0,
	STATS_RX_PACKETS_RATE,
	STATS_RX_Q0_PACKETS,
	STATS_RX_Q1_PACKETS,
	STATS_RX_Q2_PACKETS,
	STATS_RX_Q3_PACKETS,
	STATS_RX_Q4_PACKETS,
	STATS_RX_Q5_PACKETS,
	STATS_RX_Q6_PACKETS,
	STATS_RX_Q7_PACKETS,
	STATS_TX_PACKETS,
	STATS_TX_IN_TRANSIT,
	STATS_INTERRUPTS,
	STATS_RX_TREE1_INTERRUPTS,
	STATS_NAPI_POLL_CALLS,
	STATS_NAPI_BURN_BUDGET,
	STATS_LAST = STATS_NAPI_BURN_BUDGET,
};

/* Description of each of the above statistics */
static const char *mvppnd_stats_descs[] = {
	"RX_PACKETS               ",
	"RX_PACKETS_RATE          ",
	"RX_Q0_PACKETS            ",
	"RX_Q1_PACKETS            ",
	"RX_Q2_PACKETS            ",
	"RX_Q3_PACKETS            ",
	"RX_Q4_PACKETS            ",
	"RX_Q5_PACKETS            ",
	"RX_Q6_PACKETS            ",
	"RX_Q7_PACKETS            ",
	"TX_PACKETS               ",
	"TX_IN_TRANSIT            ",
	"INTERRUPTS               ",
	"RX_TREE1_INTERRUPTS      ",
	"NAPI_POLL_CALLS          ",
	"NAPI_BURN_BUDGET         ",
};

struct mvppnd_hw_desc {
	volatile u32 cmd_sts;
	volatile u32 bc;
	volatile u32 buf_addr;
	volatile u32 next_desc_ptr;
};

struct mvppnd_dma_buf {
	void *virt;
	dma_addr_t dma;
	size_t size;
};

struct mvppnd_dma_block {
	struct mvppnd_dma_buf buf;
	size_t mark; /* pointer to free space in the block */
};

struct mvppnd_ring {
	struct mvppnd_hw_desc **descs; /* Array of hw_desc pointers */
	dma_addr_t ring_dma; /* dma address of the first descriptor */
	struct mvppnd_dma_sg_buf **buffs; /* Array of buffers */
	size_t descs_ptr; /* Index of the next desc  */
	size_t buffs_ptr; /* Index of the next buff */
};

/* Forward declaration b/c we need it in struct mvppnd_switch_flow */
struct mvppnd_dev;

struct mvppnd_128bit_var {
	u64 high, low;
};

/* netdev for each switch flow (ex each port has netdev) */
struct mvppnd_switch_flow {
	struct net_device *ndev;
	struct mvppnd_dev *ppdev;

	bool up;

	int flow_id;

	u8 config_tx_dsa[DSA_SIZE]; /* allow admin to modify TX dsa tag */
	u8 config_tx_dsa_size; /* To support all kinds of DSA */

	u8 rx_dsa_val[DSA_SIZE]; /* Along with mask will identify flow in RX */
	u8 rx_dsa_mask[DSA_SIZE];

	struct kobj_attribute attr_mac;
	struct kobj_attribute attr_tx_dsa;
	struct kobj_attribute attr_rx_dsa_val;
	struct kobj_attribute attr_rx_dsa_mask;
};

/* netdev for the entire switch */
struct mvppnd_switch_dev {
	/* 1-based, port 0 is main port on non-multi flows mode */
	struct mvppnd_switch_flow *flows[MAX_NETDEVS];
	DECLARE_BITMAP(flows_bitmap, MAX_NETDEVS);

	u32 flows_cnt;

	unsigned long stats[STATS_LAST + 1];
};

struct mvppnd_pci_dev {
	struct pci_dev *pdev;
	void __iomem *bar0; /* cnm */
	u8 mg_cluster; /* Define the prefix to use in an address, ex 1d10XXXX */
	int atu_win; /* iATU window number to use */
};

struct device_private_data {
	u32 mg_reg_base; /* mg 0 register base */
};

struct mvppnd_queue {
	struct mvppnd_ring ring;
};

struct mvppnd_dev {
	struct device *dev; /* Stores device for either pci or plat device */
	int irq;
	struct mvppnd_pci_dev pdev;
	struct mvppnd_switch_dev sdev;

	void __iomem *regs;
	u32 regs_offs; /* For PCI devices, offset in bar2 of our window */

	struct device_private_data *device_data;

	u8 mg_win[3]; /* 0 for coherent, 1 and 2 for streaming */

	bool going_down;

	/* For all coherent memory allocations (rings, data pointers etc) */
	struct mvppnd_dma_block coherent;

	int tx_queue_num; /* TX queue to post to */
	struct mvppnd_queue tx_queue;
	int tx_queue_size;
	atomic_t tx_skb_in_transit;
	struct workqueue_struct *tx_wq;
	struct mvppnd_dma_buf dsa;
	struct mvppnd_dma_buf mac;
	struct mvppnd_dma_buf tx_buffs;

	u32 rx_queues_mask; /* Used to set and clear RX interrupt mask */
	struct mutex rx_lock;
	size_t rx_rings_size[NUM_OF_RX_QUEUES];
	struct mvppnd_queue *rx_queues[NUM_OF_RX_QUEUES];
	size_t rx_queue_ptr; /* to resume RX work when budget is overrun */
	struct napi_struct napi;
	int napi_budget;

	struct task_struct *rx_thread;

	size_t max_pkt_sz; /* Maximum size of frame, set by sysfs */

	struct mvppnd_ops *ops; /* hook callback functions set */

#ifdef MVPPND_DEBUG_REG
	int print_packets_interval;
#endif

	/* sysfs attributes */
	struct kobj_attribute attr_tx_queue_size;
	struct kobj_attribute attr_rx_ring_size;
	struct kobj_attribute attr_napi_budget;
	struct kobj_attribute attr_max_pkt_sz;
	struct kobj_attribute attr_rx_queues;
	struct kobj_attribute attr_if_create;
	struct kobj_attribute attr_if_delete;
	struct kobj_attribute attr_tx_queue;
	struct kobj_attribute attr_atu_win;
	struct kobj_attribute attr_mg_win;
	struct kobj_attribute attr_mg;
#ifdef MVPPND_DEBUG_REG
	struct kobj_attribute attr_reg;
#endif
	struct kobj_attribute attr_driver_statistics;
};

struct mvppnd_skb_work {
	struct work_struct work;
	struct mvppnd_dev *ppdev;
	struct sk_buff *skb;
};

int mvppnd_create_netdev(struct mvppnd_dev *ppdev, const char *name, int port);
static void mvppnd_destroy_netdev(struct mvppnd_dev *ppdev, int flow_id);
netdev_tx_t mvppnd_start_xmit(struct sk_buff *skb, struct net_device *dev);

/* Did we successfully registered as platform driver? zero means yes */
#ifdef SUPPORT_PLATFORM_DEVICE
static u8 platdrv_registered;
#endif

struct device_private_data falcon_private_data = {REG_ADDR_BASE_FALCON};
struct device_private_data ac5p_private_data = {REG_ADDR_BASE_AC5P};
struct device_private_data ac5x_private_data = {REG_ADDR_BASE_AC5X};
struct device_private_data ac5_private_data = {REG_ADDR_BASE_AC5};

/*
 * netif_receive_skb_list() was only introduced in
 * kernel 4.19 . Make a naive implementation of
 * a function which can process a list of skb
 * and pass them into the stack. The sequencial
 * invocation of the same function repeatedly for
 * a list of buffers provides superior cache
 * performance
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0)
static void netif_receive_skb_list(struct list_head *head)
{
	struct sk_buff *skb, *next;

	list_for_each_entry_safe(skb, next, head, list) {
		list_del(&skb->list);
		skb->next = skb->prev = NULL;
		netif_receive_skb(skb);

	}
}
#endif

/*********** Driver statistics functions ***************/
static inline void mvppnd_inc_stat(struct mvppnd_dev *ppdev, u8 stat_idx,
				   unsigned long inc_by)
{
	ppdev->sdev.stats[stat_idx] += inc_by;
}
static inline void mvppnd_clear_stat(struct mvppnd_dev *ppdev, u8 stat_idx)
{
	ppdev->sdev.stats[stat_idx] = 0;
}

static inline const char *mvppnd_get_stat_desc(u8 stat_idx)
{
	return mvppnd_stats_descs[stat_idx];
}

static inline unsigned long mvppnd_get_stat(struct mvppnd_dev *ppdev,
					    u8 stat_idx,
					    unsigned long last_jiffies)
{
	static unsigned long last_rx_packets = 0;
	unsigned long diff;

	/* Some stats needs special care */
	if (stat_idx == STATS_RX_PACKETS_RATE) {
		diff = jiffies - last_jiffies;
		if (diff / HZ)
			ppdev->sdev.stats[STATS_RX_PACKETS_RATE] =
				(ppdev->sdev.stats[STATS_RX_PACKETS] -
				last_rx_packets) / (diff / HZ);
		last_rx_packets = ppdev->sdev.stats[STATS_RX_PACKETS];
	}

	return ppdev->sdev.stats[stat_idx];
}

/*********** registers related functions ***************/
static bool mvppnd_is_valid_atu_win(struct mvppnd_dev *ppdev)
{
	if (ppdev->pdev.atu_win == -1) {
		if (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2) {
			dev_err(&ppdev->pdev.pdev->dev,
				"Required atu_win configuration is missing\n");
			return false;
		} else {
			/* Not using ATU windows, we are ok */
			return true;
		}
	}

	if ((ppdev->pdev.atu_win * ATU_WIN_SIZE) >
	    pci_resource_len(ppdev->pdev.pdev, 2)) {
		dev_err(&ppdev->pdev.pdev->dev,
			"BAR2 size is too small (0x%llx), cannot use window #%d\n",
			pci_resource_len(ppdev->pdev.pdev, 2),
			ppdev->pdev.atu_win);
		return false;
	}

	return true;
}

/*
	Check existing CPSS oATU window entries
	If they cover the request oATU window mapping
	then return true

	Add second loop: If we identify overlapping start
	but different size, just increase the size, and
	return true
*/
static bool mvppnd_handle_covered_by_oATU(struct mvppnd_dev *ppdev,
				    u32 base_addr, u32 size)
{
	u32 i;
	u32 read_start, read_end, winx_offs;

	for (i = 0; i < ppdev->pdev.atu_win; i++)
	{
		/* Go to our window (oATU) */
		winx_offs = ATU_OFFS + i * 0x0200;

		read_start = ioread32(ppdev->pdev.bar0 + winx_offs + 0x8);
		read_end = ioread32(ppdev->pdev.bar0 + winx_offs + 0x10);

		if ( (read_start <= base_addr) &&
		     ( (read_end) >= (base_addr + size) ) )
			return true;
	}

	for (i = 0; i < ppdev->pdev.atu_win; i++)
	{
		/* Go to our window (oATU) */
		winx_offs = ATU_OFFS + i * 0x0200;

		read_start = ioread32(ppdev->pdev.bar0 + winx_offs + 0x8);
		read_end = ioread32(ppdev->pdev.bar0 + winx_offs + 0x10);
		/*
		 * if partial overlap at start, just increase current MG window
		 * to cover both original and newly requested window:
		 */
		if ( (read_start <= base_addr) &&
		     ( read_end > base_addr ) &&
		     ( read_end < (base_addr + size) ) ) {
			read_end = base_addr + size;
			dev_info(ppdev->dev, "Adjusting oATU window entry %d (%x) to end at %x\n",
				 i, read_start, read_end);
			iowrite32(read_end, ppdev->pdev.bar0 + winx_offs + 0x10);
			return true;
		}
	}

	return false;
}

static int mvppnd_setup_iatu_window(struct mvppnd_dev *ppdev, int mg_cluster)
{
	u32 reg_addr_base, winx_offs, winx_start;

	/* ATU windows are for SPI6 and above devices, skip in case this is not
	   our device */
	if (unlikely(ppdev->pdev.atu_win == -1))
		return 0;

	if (!mvppnd_is_valid_atu_win(ppdev))
		return -EINVAL;

	reg_addr_base = ppdev->device_data->mg_reg_base &
			(0xFFFFFFFF - ATU_WIN_SIZE);
	reg_addr_base = reg_addr_base | (mg_cluster << REG_ADDR_BASE_MG_SHIFT);

	/* Go to our window (0x0100 because we need only in bound) */
	winx_offs = ATU_OFFS + ppdev->pdev.atu_win * 0x0200 + 0x0100;

	winx_start = ioread32(ppdev->pdev.bar0 + winx_offs + 0x08);
	iowrite32(0, ppdev->pdev.bar0 + winx_offs + 0x0);
	iowrite32(0x80000000, ppdev->pdev.bar0 + winx_offs + 0x04);
	/* Start from bar2 phys addr, ignore the upper 32bits */
	winx_start = pci_resource_start(ppdev->pdev.pdev, 2) +
		     ppdev->pdev.atu_win * (ATU_WIN_SIZE + 1);
	iowrite32(winx_start, ppdev->pdev.bar0 + winx_offs + 0x08);
	iowrite32(winx_start + ATU_WIN_SIZE, ppdev->pdev.bar0 + winx_offs +
		  0x10);

	iowrite32(reg_addr_base, ppdev->pdev.bar0 + winx_offs + 0x14);

	ppdev->regs_offs = ppdev->pdev.atu_win * (ATU_WIN_SIZE + 1);

	return 0;
}

static int mvppnd_setup_oatu_window(struct mvppnd_dev *ppdev, u64 base,
				    u32 size)
{
	u32 winx_offs;

	/* ATU windows are for SPI6 and above devices, skip in case this is not
	   our device */
	if (unlikely(ppdev->pdev.atu_win == -1))
		return 0;

	if (!mvppnd_is_valid_atu_win(ppdev))
		return -EINVAL;

	/* Go to our window (oATU) */
	winx_offs = ATU_OFFS + ppdev->pdev.atu_win * 0x0200;

	iowrite32(0, ppdev->pdev.bar0 + winx_offs + 0x0);
	iowrite32(0x80000000, ppdev->pdev.bar0 + winx_offs + 0x4);
	iowrite32((base & 0xFFFFFFFF) | BIT(31), ppdev->pdev.bar0 + winx_offs + 0x8);
	iowrite32(0, ppdev->pdev.bar0 + winx_offs + 0xC);
	iowrite32(((base & 0xFFFFFFFF) | BIT(31)) + size, ppdev->pdev.bar0 + winx_offs + 0x10);
	iowrite32(base & 0xFFFFFFFF, ppdev->pdev.bar0 + winx_offs + 0x14);
	iowrite32(base >> 32, ppdev->pdev.bar0 + winx_offs + 0x18);

	return 0;
}

static inline u32 mvppnd_read_reg(struct mvppnd_dev *ppdev, u32 reg_addr)
{
	u32 reg_addr_offs = reg_addr & REG_ADDR_BASE_MASK;
	u32 val;

	val = ioread32(ppdev->regs + ppdev->regs_offs + reg_addr_offs);

	/*
	dev_info(ppdev->dev, "read : 0x%x=0x%x\n", reg_addr, val);
	*/

	return val;
}

static inline void mvppnd_write_reg(struct mvppnd_dev *ppdev, u32 reg_addr,
				    u32 val)
{
	u32 reg_addr_offs = reg_addr & REG_ADDR_BASE_MASK;

	/*
	dev_info(ppdev->dev, "write: 0x%x=0x%x\n", reg_addr, val);
	*/

	iowrite32(val, ppdev->regs + ppdev->regs_offs + reg_addr_offs);
}

static inline void mvppnd_edit_reg_or(struct mvppnd_dev *ppdev, u32 reg_addr,
				      u32 value)
{
	u32 v;

	v = mvppnd_read_reg(ppdev, reg_addr);
	v |= value;
	mvppnd_write_reg(ppdev, reg_addr, v);
}

/*********** SDMA Registers functions ******************/
static void mvppnd_update_interrupt_mask(struct mvppnd_dev *ppdev, u32 reg,
					 u32 mask, bool set)
{
	u32 reg_mask;

	/*
	dev_dbg(&ppdev->pdev->dev, "%s reg 0x%x mask 0x%x\n",
		set ? "set" : "clear", reg, mask);
	*/

	if (set) {
		mvppnd_edit_reg_or(ppdev, reg, mask);
	} else {
		reg_mask = mvppnd_read_reg(ppdev, reg);
		reg_mask &= ~mask;
		mvppnd_write_reg(ppdev, reg, reg_mask);
	}
}

/* Disable completion interrupts from our queues */
static inline void mvppnd_dis_rx_queues_intr(struct mvppnd_dev *ppdev, u8 tree)
{
	mvppnd_update_interrupt_mask(ppdev, REG_ADDR_RX_MASK[tree],
				     /* disable completion events */
				     ppdev->rx_queues_mask << 2 |
				     /* disable resource error events
				        (HW reached to CPU owned descriptor) */
				     ppdev->rx_queues_mask << 11,
				     false);
}

/* Enable completion interrupts from our queues */
static inline void mvppnd_en_rx_queues_intr(struct mvppnd_dev *ppdev, u8 tree)
{
	/* TODO: We should disable resource error events here, the same as
		 what we are doing in mvppnd_dis_rx_queues_intr */
	mvppnd_update_interrupt_mask(ppdev, REG_ADDR_RX_MASK[tree],
				     ppdev->rx_queues_mask << 2, true);
}

static inline void mvppnd_disable_tx_interrupts(struct mvppnd_dev *ppdev)
{
	/* Disable Tx Buffer Queue, Tx Error Queue and Tx End Queue */
	mvppnd_update_interrupt_mask(ppdev, REG_ADDR_TX_MASK_0,
				     (1 << (ppdev->tx_queue_num + 1)) |
				     (1 << (ppdev->tx_queue_num + 9)) |
				     (1 << (ppdev->tx_queue_num + 17)), false);
}

#if 0
/* Link tree 1 to cause 0 so any interrupts on tree1 will propagate to tree0 */

---> This part left for reference, delete when posting last commit

static int mvppnd_link_tree1_to_cause0(struct mvppnd_dev *ppdev)
{
	int rc;

	/* Enable RX on tree 1 */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_GLOBAL_MASK[1], 1 << 9);

	/* Enable port2 on tree 0 */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_GLOBAL_MASK[0], 1 << 17);

	/* Switch to MG 1 */
	rc = mvppnd_setup_iatu_window(ppdev, ppdev->pdev.mg_cluster + 4);
	if (rc)
		return -EIO;

	/* Enable port2 on tree 0 */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_GLOBAL_MASK[0], 1 << 17);

	/* Set bit 30 on port2 tree 0 */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_PORT2_MASK_0, 1 << 30);

	/* Back to MG 0 */
	rc = mvppnd_setup_iatu_window(ppdev, ppdev->pdev.mg_cluster);
	if (rc)
		return -EIO;

	/* Set bit 29 on port2 tree 0 */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_PORT2_MASK_0, 1 << 29);

	return 0;
}
#endif

/*********** MG windows functions **********************/
static void mvppnd_init_target_and_control(struct mvppnd_dev *ppdev,
					   u32 *target, u32 *control,
					   u32 base_addr, u32 size)
{
	/* Zero size means the caller wish to clear the window */
	if (!size) {
		*target = 0;
		*control = 0;
		return;
	}

	/* Internal device */
	if (!ppdev->pdev.pdev) {
		*target = 0xe02;
		*control = 0x6;
		return;
	}

	if (ppdev->pdev.pdev->device == PCI_DEVICE_ID_ALDRIN2) {
		*target = 0xe04;
		*control = 0x6;
		return;
	}

	/* All others - need to test */
	*target = 0xe03;
	*control = base_addr | BIT(31) | 0x0000000e;
}

/*
	Check existing CPSS MG window entries
	If they cover the request MG window mapping
	then return true

	Add second loop: If we identify overlapping start
	but different size, just increase the size, and
	return true
*/
static bool mvppnd_handle_covered_by_mg(struct mvppnd_dev *ppdev, u8 max_mg_win,
				    u32 base_addr, u32 size)
{
	u32 i;
	u32 read_base, read_size, control;

	for (i = 0; i < max_mg_win; i++)
	{
		read_base = mvppnd_read_reg(ppdev,
				REG_ADDR_MG_BASE_ADDR + i *
				REG_ADDR_MG_BASE_ADDR_OFFSET_FORMULA) & 0xFFFF0000;
		read_size = mvppnd_read_reg(ppdev,
				REG_ADDR_MG_SIZE + i *
				REG_ADDR_MG_SIZE_OFFSET_FORMULA) & 0xFFFF0000;
		control = mvppnd_read_reg(ppdev,
					  REG_ADDR_MG_CONTROL + i *
					  REG_ADDR_MG_CONTROL_OFFSET_FORMULA);

		if (control & 0x1)
			continue; /* MG window disabled, skip entry */

		if ( (read_base <= base_addr) &&
		     ( (read_base + read_size) >= (base_addr + size) ) )
			return true;
	}

	for (i = 0; i < max_mg_win; i++)
	{
		read_base = mvppnd_read_reg(ppdev,
				REG_ADDR_MG_BASE_ADDR + i *
				REG_ADDR_MG_BASE_ADDR_OFFSET_FORMULA) & 0xFFFF0000;
		read_size = mvppnd_read_reg(ppdev,
				REG_ADDR_MG_SIZE + i *
				REG_ADDR_MG_SIZE_OFFSET_FORMULA) & 0xFFFF0000;
		control = mvppnd_read_reg(ppdev,
					  REG_ADDR_MG_CONTROL + i *
					  REG_ADDR_MG_CONTROL_OFFSET_FORMULA);

		if (control & 0x1)
			continue; /* MG window disabled, skip entry */

		/*
		 * if partial overlap at start, just increase current MG window
		 * to cover both original and newly requested window:
		 */
		if ( (read_base <= base_addr) &&
		     ( (read_base + read_size) > base_addr ) &&
		     ( (read_base + read_size) < (base_addr + size) ) ) {
			read_size = base_addr + size - read_base;
			dev_info(ppdev->dev, "Adjusting MG window entry %d (%x) to size %x\n",
				 i, read_base, read_size);
			mvppnd_write_reg(ppdev, REG_ADDR_MG_SIZE + i *
					REG_ADDR_MG_SIZE_OFFSET_FORMULA, read_size);
			return true;
		}
	}

	return false;
}

static void mvppnd_setup_mg_window(struct mvppnd_dev *ppdev, u8 mg_win,
				   u64 base_addr, u32 size)
{
	u32 target, control;

	dev_dbg(ppdev->dev, "MG window %d: 0x%llx, %d\n", mg_win,
		base_addr, size);

	mvppnd_init_target_and_control(ppdev, &target, &control, base_addr,
				       size);

	/* Is oATU needed */
	if ((ppdev->pdev.pdev) &&
	    (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2) ) {
		/* only if we don't have overlapping mapping, then make a new one: */
		if (!mvppnd_handle_covered_by_oATU(ppdev, base_addr & 0xFFFFFFFF, size))
			mvppnd_setup_oatu_window(ppdev, base_addr, size);
	}

	if (mvppnd_handle_covered_by_mg(ppdev, NUM_OF_MG_WINDOWS, base_addr, size))
		return; /* if CPSS already mapped these addresses avoid making another overlapping mapping */

	mvppnd_write_reg(ppdev, REG_ADDR_MG_BASE_ADDR + mg_win *
			 REG_ADDR_MG_BASE_ADDR_OFFSET_FORMULA,
			 (base_addr & 0xFFFFFFFF) | target);
	mvppnd_write_reg(ppdev, REG_ADDR_MG_SIZE + mg_win *
			 REG_ADDR_MG_SIZE_OFFSET_FORMULA, size);
	mvppnd_write_reg(ppdev, REG_ADDR_MG_HA + mg_win *
			 REG_ADDR_MG_HA_OFFSET_FORMULA, 0);
	mvppnd_write_reg(ppdev, REG_ADDR_MG_CONTROL + mg_win *
			 REG_ADDR_MG_CONTROL_OFFSET_FORMULA, control);
}

/*********** some debug function ***********************/
#ifdef MVPPND_DEBUG_DATA_PATH
static void print_skb_hdr(struct mvppnd_dev *ppdev, const char *dir,
			  struct sk_buff *skb)
{
	char *data = skb->data;
	struct ethhdr *eth;

	dev_info(ppdev->dev, "--------- %s ---------\n", dir);
	dev_info(ppdev->dev, "skb_headlen %d\n", skb_headlen(skb));

	eth = (struct ethhdr *)data;
	dev_info(ppdev->dev, "----- mac header -----\n");
	dev_info(ppdev->dev, "src_mac %pM\n", eth->h_source);
	dev_info(ppdev->dev, "dst_mac %pM\n", eth->h_dest);
	/* https://en.wikipedia.org/wiki/EtherType */
	dev_info(ppdev->dev, "proto   0x%x\n",
		 be16_to_cpu(eth->h_proto));

	/* IPv4 */
	if (be16_to_cpu(eth->h_proto) == 0x0800) {
		struct iphdr *ipv4 =
			(struct iphdr *)(data + sizeof(struct ethhdr));
		dev_info(ppdev->dev, "----- ipv4 header -----\n");
		dev_info(ppdev->dev, "len   %d\n",
			 be16_to_cpu(ipv4->tot_len));
		dev_info(ppdev->dev, "proto 0x%x\n",
			 be16_to_cpu(ipv4->protocol));
		dev_info(ppdev->dev, "src_ip 0x%x\n",
			 be32_to_cpu(ipv4->saddr));
		dev_info(ppdev->dev, "dst_ip 0x%x\n",
			 be32_to_cpu(ipv4->daddr));
	}

	/* IPv6 */
	if (be16_to_cpu(eth->h_proto) == 0x86DD) {
		struct ipv6hdr *ipv6 =
			(struct ipv6hdr *)(data + sizeof(struct ethhdr));
		dev_info(ppdev->dev, "----- ipv6 header -----\n");
		dev_info(ppdev->dev, "src_ip %pI6\n",
			 ipv6->saddr.s6_addr);
		dev_info(ppdev->dev, "dst_ip %pI6\n",
			 ipv6->daddr.s6_addr);
	}
	dev_info(ppdev->dev, "----------------------\n");
}

static void print_frame(struct mvppnd_dev *ppdev, const char *data, size_t len,
			bool rx)
{
	char *b;
	int i;

	return;

	b = kmalloc(8196, GFP_KERNEL);

	b[0] = 0;
	dev_dbg(ppdev->dev, "----------------------------\n");
	dev_dbg(ppdev->dev, "%s: %ld bytes\n", rx ? "RX" : "TX",
		len);
	for (i = 0; i < len; i++) {
		if (rx && ((i == 12) || (i == 12 + 16)))
			sprintf(b, "%s\n", b);
		sprintf(b, "%s 0x%x", b, data[i]);
	}

	dev_dbg(ppdev->dev, "%s\n", b);
	dev_dbg(ppdev->dev, "----------------------------\n");

	kfree(b);
}

#else
#define print_skb_hdr(ppdev, dir, skb)
#define print_frame(ppdev, data, len, from_pp)
#endif

#ifdef MVPPND_DEBUG_REG
static void print_buff(const char *title, const unsigned char *buff,
		       size_t buff_len)
{
	int i;
	char *b;
	b = kmalloc(buff_len * 3 + 1, GFP_KERNEL);

	b[0] = 0;
	for (i = 0; i < buff_len; i++) {
		sprintf(b, "%s%.2x ", b, buff[i]);
	}
	printk("[%s %ld]: %s\n", title, buff_len, b);

	kfree(b);
}
#else
#define print_buff(title, buff, buff_len)
#endif

static void print_first_descs(struct mvppnd_dev *ppdev, const char *title,
			      u32 addr, int formula, int cnt)
{
	int i;

	return;

	dev_dbg(ppdev->dev, "%s\n", title);

	for (i = 0; i < cnt; i++)
		dev_dbg(ppdev->dev, "queue #%d desc ptr: 0x%x\n", i,
			mvppnd_read_reg(ppdev, addr + i * formula));

	dev_dbg(ppdev->dev, "end %s\n", title);
}

static void debug_print_some_registers(struct mvppnd_dev *ppdev)
{
	dev_dbg(ppdev->dev, "vendor: 0x%x\n",
		mvppnd_read_reg(ppdev, REG_ADDR_VENDOR));
	dev_dbg(ppdev->dev, "device: 0x%x\n",
		mvppnd_read_reg(ppdev, REG_ADDR_DEVICE));
	dev_dbg(ppdev->dev, "rxdesc: 0x%x\n",
		mvppnd_read_reg(ppdev, REG_ADDR_RX_FIRST_DESC));
	dev_dbg(ppdev->dev, "txdesc: 0x%x\n",
		mvppnd_read_reg(ppdev, REG_ADDR_TX_FIRST_DESC));

	print_first_descs(ppdev, "tx_queue", REG_ADDR_TX_FIRST_DESC,
			  REG_ADDR_TX_FIRST_DESC_OFFSET_FORMULA,
			  NUM_OF_TX_QUEUES);
}

/*********** queues related functions ******************/
static size_t mvppnd_num_of_rx_queues(struct mvppnd_dev *ppdev)
{
	size_t i, num_of_rx_queues = 0;

	for (i = 0; i < NUM_OF_RX_QUEUES; i++)
		num_of_rx_queues += ppdev->rx_queues[i] ? 1 : 0;

	return num_of_rx_queues;
}

static inline int cyclic_idx(int c, size_t s)
{
	if (c < 0)
		return s + c;

	return c & (s - 1); /* use bitwise AND as it is faster than modulo (division) */
}

static inline void cyclic_inc(size_t *c, size_t s)
{
	*c = (*c + 1) & (s - 1); /* use bitwise AND as it is faster than modulo (division) */
}

static int mvppnd_queue_enabled(struct mvppnd_dev *ppdev, u32 cmd_reg_addr,
				int queue)
{
	return (mvppnd_read_reg(ppdev, cmd_reg_addr) & (1 << queue));
}

static void mvppnd_enable_queue(struct mvppnd_dev *ppdev, u32 cmd_reg_addr,
				int queue)
{
	mvppnd_edit_reg_or(ppdev, cmd_reg_addr, 1 << queue);
}

static void mvppnd_disable_queue(struct mvppnd_dev *ppdev, u32 cmd_reg_addr,
				 int queue)
{
	mvppnd_edit_reg_or(ppdev, cmd_reg_addr, 1 << (queue + 8));
}

static u32 mvppnd_read_tx_first_desc(struct mvppnd_dev *ppdev, u8 queue)
{
	return mvppnd_read_reg(ppdev, REG_ADDR_TX_FIRST_DESC + queue *
			       REG_ADDR_TX_FIRST_DESC_OFFSET_FORMULA);
}

static void mvppnd_write_tx_first_desc(struct mvppnd_dev *ppdev, u32 val)
{
	mvppnd_disable_queue(ppdev, REG_ADDR_TX_QUEUE_CMD, ppdev->tx_queue_num);

	mvppnd_write_reg(ppdev, REG_ADDR_TX_FIRST_DESC + ppdev->tx_queue_num *
			 REG_ADDR_TX_FIRST_DESC_OFFSET_FORMULA, val);
}

static u32 mvppnd_read_rx_first_desc(struct mvppnd_dev *ppdev, u8 queue)
{
	return mvppnd_read_reg(ppdev, REG_ADDR_RX_FIRST_DESC + queue *
			       REG_ADDR_RX_FIRST_DESC_OFFSET_FORMULA);
}

static void mvppnd_write_rx_first_desc(struct mvppnd_dev *ppdev, u8 queue,
				       u32 val)
{
	/* When using more than one RX queue, after the SDMA places the first
	   packet in some rings, it store the old next-desc-ptr (the one which
	   CPSS puts originally) instead of the one specified as next-desc-ptr
	   of the current descriptor. It is like it has a cache and it fetch
	   the value from there.
	   By writing the first descriptor pointer twice to the register, it is
	   observed that the correct value is used, i.e the next-ptr and not
	   the CPSS value */

	mvppnd_disable_queue(ppdev, REG_ADDR_RX_QUEUE_CMD, queue);

	mvppnd_write_reg(ppdev, REG_ADDR_RX_FIRST_DESC + queue *
			 REG_ADDR_RX_FIRST_DESC_OFFSET_FORMULA, val);

	mvppnd_disable_queue(ppdev, REG_ADDR_RX_QUEUE_CMD, queue);

	mvppnd_write_reg(ppdev, REG_ADDR_RX_FIRST_DESC + queue *
			 REG_ADDR_RX_FIRST_DESC_OFFSET_FORMULA, val);
}

/*********** coherent memory block *********************/
/* We allocate one block for all dma services, then allocate from this block.
 * Allocation from the block cannot be undone, it is too complex and not needed
 * (unless the driver will be required to support run-time configuration
 * changes in the future)
 */
static int mvppnd_alloc_device_coherent(struct mvppnd_dev *ppdev)
{
	size_t i, rx_rings_total_size = 0;
	dma_addr_t d;
	size_t size, filler_size;
	void *v;

	ppdev->coherent.buf.size = 0;
	ppdev->coherent.mark = 0;

	for (i = 0; i < NUM_OF_RX_QUEUES; i++)
		if (ppdev->rx_queues[i])
			rx_rings_total_size += ppdev->rx_rings_size[i];

	/* RX queues */
	size = rx_rings_total_size * sizeof(struct mvppnd_hw_desc);
	ppdev->coherent.buf.size += max(size, PAGE_SIZE);

	/* One TX queue */
	size = TX_RING_SIZE * sizeof(struct mvppnd_hw_desc);
	ppdev->coherent.buf.size += max(size, PAGE_SIZE);

	/* Space for TX buffers (+1 for head) */
	size = TX_RING_SIZE * ppdev->max_pkt_sz;
	ppdev->coherent.buf.size += max(size, PAGE_SIZE);

	/* Space for two MACs (first descriptor) */
	size = ETH_ALEN * 2;
	ppdev->coherent.buf.size += max(size, PAGE_SIZE);

	/* Space for DSA (second descriptor) */
	size = DSA_SIZE;
	ppdev->coherent.buf.size += max(size, PAGE_SIZE);

	/* Space for RX buffers */
	size = rx_rings_total_size * ppdev->max_pkt_sz;
	ppdev->coherent.buf.size += max(size, PAGE_SIZE);

	/* Round to power of two */
	ppdev->coherent.buf.size = roundup_pow_of_two(ppdev->coherent.buf.size);

	ppdev->coherent.buf.virt = dma_alloc_coherent(ppdev->dev,
						      ppdev->coherent.buf.size,
						      &ppdev->coherent.buf.dma,
						      GFP_DMA32 | GFP_NOFS |
						      GFP_KERNEL);
	if (unlikely(!ppdev->coherent.buf.virt)) {
		dev_err(ppdev->dev,
			"Fail to allocate %ld bytes of coherent memory, masks %llx %llx\n",
			ppdev->coherent.buf.size, *ppdev->dev->dma_mask,
			ppdev->dev->coherent_dma_mask);
		return -ENOMEM;
	}

	/* Make sure address is aligned with the size */
	size = ppdev->coherent.buf.dma % ppdev->coherent.buf.size;
	if (size) {
		/*
		 * Allocate the difference between the requested
		 * size and the allocated address misalignment.
		 * This should make the next allocation start on the
		 * correct boundary:
		 */
		filler_size = ppdev->coherent.buf.size - size;
		dev_info(ppdev->dev,
			"Not aligned (0x%llx, 0x%lx), reallocating %lx\n",
			ppdev->coherent.buf.dma, ppdev->coherent.buf.size, filler_size);

		dma_free_coherent(ppdev->dev,
				  ppdev->coherent.buf.size,
				  ppdev->coherent.buf.virt,
				  ppdev->coherent.buf.dma);

		v = dma_alloc_coherent(ppdev->dev, filler_size, &d,
				       GFP_DMA32 | GFP_NOFS | GFP_KERNEL);
		ppdev->coherent.buf.virt =
			dma_alloc_coherent(ppdev->dev,
					   ppdev->coherent.buf.size,
					   &ppdev->coherent.buf.dma,
					   GFP_DMA32 | GFP_NOFS | GFP_KERNEL);
		if (unlikely(!ppdev->coherent.buf.virt)) {
			dev_err(ppdev->dev,
				"Fail to allocate %ld bytes of coherent memory, phys1 %llx phys2 %llx\n",
				ppdev->coherent.buf.size, d, ppdev->coherent.buf.dma);
			return -ENOMEM;
		}

		dma_free_coherent(ppdev->dev, filler_size, v, d);
	}

	if (ppdev->coherent.buf.dma % ppdev->coherent.buf.size) {
		dev_err(ppdev->dev,
			"Fail to allocate aligned coherent buffer, phys %llx filler %llx size %ld masks %llx %llx\n", ppdev->coherent.buf.dma, d,
			ppdev->coherent.buf.size, *ppdev->dev->dma_mask,
			ppdev->dev->coherent_dma_mask);
		return -ENOMEM;
	}

	dev_info(ppdev->dev,"coherent 0x%llx, %llx (0x%lx)\n",
		ppdev->coherent.buf.dma, ppdev->coherent.buf.dma +
		ppdev->coherent.buf.size, ppdev->coherent.buf.size);

	mvppnd_setup_mg_window(ppdev, ppdev->mg_win[MG_WIN_COHERENT_IDX],
			       ppdev->coherent.buf.dma,
			       (ppdev->coherent.buf.size - 1) & 0xFFFF0000);

	return 0;
}

static void mvppnd_free_device_coherent(struct mvppnd_dev *ppdev)
{
	if (!ppdev->coherent.buf.virt)
		return;

	dma_free_coherent(ppdev->dev, ppdev->coherent.buf.size,
			  ppdev->coherent.buf.virt, ppdev->coherent.buf.dma);

	ppdev->coherent.buf.virt = NULL;
}

static void *mvppnd_alloc_coherent(struct mvppnd_dev *ppdev, size_t size,
				   dma_addr_t *dma)
{
	void *free = ppdev->coherent.buf.virt + ppdev->coherent.mark;

	BUG_ON(ppdev->coherent.mark > ppdev->coherent.buf.size);

	*dma = ppdev->coherent.buf.dma + ppdev->coherent.mark;

	ppdev->coherent.mark += size;

	BUG_ON(!free);

	return free;
}

/*********** buf wrappers ******************************/
static int mvppnd_copy_skb_to_tx_buff(struct mvppnd_dev *ppdev,
				      struct sk_buff *skb,
				      struct mvppnd_dma_sg_buf *sgb)
{
	static const size_t PACKET_MIN_SIZE = ETH_ZLEN - ETH_ALEN * 2;
	int rc = 0;
	int i;

	if (unlikely((skb_shinfo(skb)->nr_frags > MAX_FRAGS)))
		return -EINVAL;

	skb_pull(skb, ETH_ALEN * 2); /* Skip src and dest macs */

	memset(ppdev->tx_buffs.virt, 0, PACKET_MIN_SIZE);
	memcpy(ppdev->tx_buffs.virt, skb->data, skb_headlen(skb));
	sgb->mappings[0] = ppdev->tx_buffs.dma;
	sgb->sizes[0] = max_t(unsigned int, skb_headlen(skb),
			      PACKET_MIN_SIZE);
	/* Frags starts from index 1 */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
		memcpy(ppdev->tx_buffs.virt + i * skb_frag_size(frag),
		       page_to_virt(skb_frag_page(frag)),
		       skb_frag_size(frag));
#else
		WARN_ONCE(1, "Older kernel, frags are not supported\n"
#endif
		sgb->mappings[i + 1] = ppdev->tx_buffs.dma + i *
				       skb_frag_size(frag);
		sgb->sizes[i + 1] = skb_frag_size(frag);
	}

	skb_push(skb, ETH_ALEN * 2); /* We are done, return to MAC header */
	return rc;
}

/*********** rings related functions *******************/
static void mvppnd_free_ring_dma(struct mvppnd_dev *ppdev,
				 struct mvppnd_ring *ring, size_t size)
{
	int i;

	if (!ring->buffs)
		return;

	for (i = 0; i < size; i++) {
		kfree(ring->buffs[i]);
		ring->buffs[i] = NULL;
	}

	kfree(ring->buffs);
	ring->buffs = NULL;

	kfree(ring->descs);
	ring->descs = NULL;

	ring->ring_dma = 0;
}

static int mvppnd_alloc_ring(struct mvppnd_dev *ppdev,
			     struct mvppnd_ring *ring, size_t size)
{
	int rc = 0;
	int i = 0;

	ring->descs = kmalloc_array(size, sizeof(ring->descs[0]), GFP_KERNEL);
	if (unlikely(!ring->descs))
		return -ENOMEM;

	/* TODO: Why i can't just do the next two allocs together? */
	ring->buffs = kmalloc_array(size, sizeof(ring->buffs[0]),
				    GFP_KERNEL);
	if (unlikely(!ring->buffs))
		goto free_descs;

	for (i = 0; i < size; i++) {
		ring->buffs[i] = kzalloc(sizeof(*ring->buffs[i]), GFP_KERNEL);
		if (unlikely(!ring->buffs[i]))
			goto free_buffs;
	}

	/* Allocate one big coherent and split it to all descs */
	ring->descs[0] = mvppnd_alloc_coherent(ppdev, sizeof(*ring->descs[0]) *
					       size, &ring->ring_dma);
	ring->descs[0]->next_desc_ptr = ring->ring_dma +
					sizeof(*ring->descs[0]);

	for (i = 1; i < size; i++) {
		ring->descs[i] = ring->descs[0] + i;
		ring->descs[i]->next_desc_ptr = ring->ring_dma + (i + 1) *
						sizeof(*ring->descs[0]);
		ring->descs[i]->cmd_sts = 0;
	}

	/* Close the ring */
	ring->descs[size - 1]->next_desc_ptr = ring->ring_dma;

	return 0;

free_buffs:
	for (i = 0; i < size; i++)
		kfree(ring->buffs[i]);
	kfree(ring->buffs);
	ring->buffs = NULL;

free_descs:
	kfree(ring->descs);
	ring->descs = NULL;

	return rc;
}

static int mvppnd_setup_tx_ring(struct mvppnd_dev *ppdev)
{
	int rc = 0;

	if (ppdev->tx_queue_num == -1)
		return -1;

	rc = mvppnd_alloc_ring(ppdev, &ppdev->tx_queue.ring, TX_RING_SIZE);
	if (rc)
		return rc;

	ppdev->tx_buffs.virt =
		mvppnd_alloc_coherent(ppdev, TX_RING_SIZE *
				      ppdev->max_pkt_sz, &ppdev->tx_buffs.dma);

	mvppnd_write_tx_first_desc(ppdev, ppdev->tx_queue.ring.ring_dma);

	return 0;
}

static void mvppnd_destroy_tx_ring(struct mvppnd_dev *ppdev)
{
	if (ppdev->tx_queue_num == -1)
		return;

	mvppnd_write_tx_first_desc(ppdev, 0);

	mvppnd_free_ring_dma(ppdev, &ppdev->tx_queue.ring, TX_RING_SIZE);
}

static void mvppnd_destroy_rx_rings(struct mvppnd_dev *ppdev)
{
	int i;

	for (i = 0; i < NUM_OF_RX_QUEUES; i++) {
		if (ppdev->rx_queues[i]) {
			mvppnd_write_rx_first_desc(ppdev, i, 0);
			mvppnd_free_ring_dma(ppdev, &ppdev->rx_queues[i]->ring,
					     ppdev->rx_rings_size[i]);
			kfree(ppdev->rx_queues[i]);
			ppdev->rx_queues[i] = NULL;
		}
	}
}

static int mvppnd_setup_rx_rings(struct mvppnd_dev *ppdev)
{
	struct mvppnd_ring *r;
	int i, j, rc = 0;

	if (!ppdev->mg_win[MG_WIN_STREAMING1_IDX]) {
		dev_err(ppdev->dev, "MG window is not set\n");
		return -EFAULT;
	}

	for (i = 0; i < NUM_OF_RX_QUEUES; i++) {
		if (!ppdev->rx_queues[i])
			continue;

		rc = mvppnd_alloc_ring(ppdev, &ppdev->rx_queues[i]->ring,
				       ppdev->rx_rings_size[i]);
		if (rc)
			goto destroy_rings;

		r = &ppdev->rx_queues[i]->ring;

		/* Populate ring with skbs */
		for (j = 0; j < ppdev->rx_rings_size[i]; j++) {
			struct mvppnd_dma_sg_buf *sgb = r->buffs[j];

			r->descs[j]->cmd_sts = RX_CMD_BIT_OWN_SDMA |
					       RX_CMD_BIT_EN_INTR;

			sgb->sizes[0] = ppdev->max_pkt_sz - DSA_SIZE;
			sgb->virt = mvppnd_alloc_coherent(ppdev, sgb->sizes[0],
							  &sgb->mappings[0]);

			r->descs[j]->buf_addr = sgb->mappings[0];
			RX_DESC_SET_BUFF_SIZE(r->descs[j]->bc, sgb->sizes[0]);
		}
		r->descs_ptr = 0;
		r->buffs_ptr = 0;

		mvppnd_write_rx_first_desc(ppdev, i, r->ring_dma);
	}

	/* recv boundaries */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_SDMA_CONF, 0x1);

	/* Enable queues */
	for (i = 0; i < NUM_OF_RX_QUEUES; i++)
		if (ppdev->rx_queues[i])
			mvppnd_enable_queue(ppdev, REG_ADDR_RX_QUEUE_CMD, i);
	/*
	 * AC5 in internal mode needs to be enabled twice for some reason,
	 * this should not have any adverse effect on other packet processors:
	 */
	for (i = 0; i < NUM_OF_RX_QUEUES; i++)
		if (ppdev->rx_queues[i])
			mvppnd_enable_queue(ppdev, REG_ADDR_RX_QUEUE_CMD, i);
	return 0;

destroy_rings:
	mvppnd_destroy_rx_rings(ppdev);

	return rc;
}

static void mvppnd_destroy_rings(struct mvppnd_dev *ppdev)
{
	mvppnd_destroy_rx_rings(ppdev);
	mvppnd_destroy_tx_ring(ppdev);
}

/*
 * This function is called by an external kernel module
 * to provide RX and TX callback hook functions.
 * If a previous registration of hooks were made,
 * this will override the previously registered hook
 * callback functions
 */
int mvppnd_register_hooks(struct net_device *ndev, struct mvppnd_ops *ops)
{
	struct mvppnd_switch_flow *flow;

	if (!ndev)
		return -EINVAL;

	flow = netdev_priv(ndev);

	flow->ppdev->ops = ops;

	return 0;
}
EXPORT_SYMBOL(mvppnd_register_hooks);

/*********** rx ****************************************/
#ifdef MVPPND_DEBUG_DATA_PATH
static void print_dsa(const char *netdev, const char *dir, u8 *dsa)
{
	char buf[1024];

	memset(buf, 0, sizeof(buf));
	snprintf(buf, PAGE_SIZE, "%s %s:", dir, netdev);
	snprintf(buf, PAGE_SIZE,
		 "%s %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
		 buf, dsa[0], dsa[1], dsa[2], dsa[3], dsa[4], dsa[5], dsa[6],
		 dsa[7], dsa[8], dsa[9], dsa[10], dsa[11], dsa[12], dsa[13],
		 dsa[14], dsa[15]);

	printk("%s\n", buf);
}
#else
#define print_dsa(netdev, dir, dsa)
#endif

static struct mvppnd_switch_flow *mvppnd_get_sw_flow(struct mvppnd_dev *ppdev,
						     u8 *dsa)
{
	struct mvppnd_128bit_var *v, *m, *d = (struct mvppnd_128bit_var *)dsa;
	u32 flows_cnt = ppdev->sdev.flows_cnt;
	struct mvppnd_switch_flow *flow;
	int i;

	flow = ppdev->sdev.flows[0]; /* Default to main netdev */

	for (i = 1; flows_cnt && (i < MAX_NETDEVS); i++) {
		if (!ppdev->sdev.flows[i])
			continue;

		flows_cnt--;

		if (!ppdev->sdev.flows[i]->up)
			continue;

		v = (struct mvppnd_128bit_var *)
			&(ppdev->sdev.flows[i]->rx_dsa_val);
		m = (struct mvppnd_128bit_var *)
			&(ppdev->sdev.flows[i]->rx_dsa_mask);

		if (v->high != (d->high & m->high))
			continue;

		if (v->low != (d->low & m->low))
			continue;

		flow = ppdev->sdev.flows[i];
		break;
	}

	return flow;
}

static u8 mvppnd_get_vlan_info(u8 *dsa, u16 *vlan)
{
	u8 istagged = (dsa[0] & 0x20) >> 5;
	*vlan = 0;

	if (istagged) {
		*vlan = (dsa[2] & 0x0f) << 8;
		*vlan |= (dsa[3] & 0xff);
	}

	return istagged;
}

static void mvppnd_process_rx_buff(struct mvppnd_dev *ppdev,
				   unsigned char *buff, u32 bc,
				   struct list_head *rx_list_ptr)
{
	struct mvppnd_switch_flow *flow;
	bool redirect_to_tx = false;
	struct net_device *ndev;
	struct vlan_ethhdr veth;
	char *skb_data, dsa[DSA_SIZE]; /* use dsa on stack - faster than dynamic allocation */
	struct sk_buff *skb;
	int rx_bytes;
	u8 istagged;
	u16 vlan;
	int rc;

	print_frame(ppdev, buff, RX_DESC_GET_BYTE_CNT(bc), true);

	rx_bytes = RX_DESC_GET_BYTE_CNT(bc) - CRC_SIZE;

	/*
	 * if RX callback hook exists, call it and according to the
	 * return value decide what needs to be done with the packet:
	 */
	if (ppdev->ops && ppdev->ops->process_rx) {
		rc = ppdev->ops->process_rx(ppdev->sdev.flows[0]->ndev, buff,
					    &rx_bytes, ppdev->max_pkt_sz);
		switch (rc) {
		case NF_DROP:
			ppdev->sdev.flows[0]->ndev->stats.rx_dropped++;
			return;
		case NF_ACCEPT:
			break;
		case NF_STOLEN:
			return;
		case NF_QUEUE:
			/*
			 * Continue but check again later, do TX instead of
			 * calling to netif_receive_skb
			 */
			redirect_to_tx = true;
			break;
		default:
			WARN_ONCE(1, "%s: Got invalid return value from process_rx\n",
				  DRV_NAME);
			ppdev->sdev.flows[0]->ndev->stats.rx_dropped++;
			return;
		};
	}

	/* Get vlan info from dsa */
	istagged = mvppnd_get_vlan_info(buff + ETH_ALEN * 2, &vlan);

	if (istagged) {
		rx_bytes = RX_DESC_GET_BYTE_CNT(bc) + VLAN_HLEN - CRC_SIZE;
	} else {
		rx_bytes = RX_DESC_GET_BYTE_CNT(bc) - CRC_SIZE;
	}

	flow = mvppnd_get_sw_flow(ppdev, buff + ETH_ALEN * 2);
	ndev = flow->ndev;

	print_dsa(ndev->name, "rx", buff + ETH_ALEN * 2);
	if ( (rx_bytes < DSA_SIZE) || (rx_bytes > ppdev->max_pkt_sz) ) {
		WARN_ONCE(1, "Received packet with illegal size %d!!!\n", rx_bytes);
		return;
	}

	skb = netdev_alloc_skb(ndev, rx_bytes);

	if (!skb) {
		ndev->stats.rx_dropped++;
		no_skbs++;
		return;
	}
	/* initialize skb closer to allocation when variables are cache hot: */
	/* Reserved place for DSA */
	skb_reserve(skb, DSA_SIZE);
	/* Bit 30 - csum validity */
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_HOST;

	/* Save dsa */
	memcpy(dsa, buff + ETH_ALEN * 2, DSA_SIZE);

	/* Delete DSA and move DA & SA in place */
	memmove(buff + DSA_SIZE, buff, ETH_ALEN * 2);
	buff += DSA_SIZE;

	/* Copy packet */
	if (istagged) {
		/* memcpy mac and protocol details to veth */
		memcpy(&veth, buff, ETH_HLEN);
		veth.h_vlan_encapsulated_proto = veth.h_vlan_proto;
		veth.h_vlan_proto = htons(ETH_P_8021Q);
		veth.h_vlan_TCI = htons(vlan);
		skb_data = skb_put(skb, rx_bytes - DSA_SIZE);
		/* copy eth hdr with vlan tag */
		memcpy(skb_data, &veth, VLAN_ETH_HLEN);
		/* copy rest of packet from buff */
		memcpy(skb_data + VLAN_ETH_HLEN, buff + ETH_HLEN, rx_bytes -
				DSA_SIZE - VLAN_ETH_HLEN);
	} else {
		skb_data = skb_put_data(skb, buff, rx_bytes - DSA_SIZE);
	}

	/* Copy DSA to the reserved place */
	memcpy(skb_data - DSA_SIZE, dsa, DSA_SIZE);

#ifdef MVPPND_DEBUG_REG
	/* Print packet for debug */
	if (ppdev->print_packets_interval &&
	    (!(ndev->stats.rx_packets % ppdev->print_packets_interval)))
		print_buff("rx", skb->data, skb->len);
#endif

	print_skb_hdr(ppdev, "rx", skb);

	skb->protocol = eth_type_trans(skb, skb->dev);

	if (unlikely(redirect_to_tx)) { /* redirect to tx is rarely used */
		mvppnd_start_xmit(skb, skb->dev);
		consume_skb(skb);
		ndev->stats.rx_packets++;
		ndev->stats.rx_bytes += rx_bytes;
	} else {
		list_add_tail(&skb->list, rx_list_ptr); /* add to list - caller will pass all buffer in one go to the kernel - faster */
		dev_dbg(ppdev->dev, "netif_receive_skb returns %d\n", rc);
		ndev->stats.rx_packets++;
		ndev->stats.rx_bytes += rx_bytes;
		print_frame(ppdev, skb->data, skb->len, true);
	}
}

static int mvppnd_process_rx_queue(struct mvppnd_dev *ppdev, int queue,
				   int budget,
				   struct list_head *rx_list_ptr)
{
	struct mvppnd_ring *r = &ppdev->rx_queues[queue]->ring;
	struct mvppnd_dma_sg_buf *buff;
	int done = 0;

	/* called only from NAPI poll context, hence no need for mutex */
	while (((r->descs[r->descs_ptr]->cmd_sts & RX_CMD_BIT_OWN_SDMA) !=
	       RX_CMD_BIT_OWN_SDMA) && (done < budget)) {

		/* TODO: Assumption now that each desc holds only *one* packet
			 so we expect bits last and first to be set.
			 Look for if there are other drivers that need to
			 compose several frags to one skb */

		/* TODO: Check resource error bit (28) */

		buff = r->buffs[r->buffs_ptr];

		/* Populate skb details and pass to network stack */
		mvppnd_process_rx_buff(ppdev, buff->virt,
				       r->descs[r->descs_ptr]->bc,
				       rx_list_ptr); /* add buffer to list, caller will pass entire list to kernel - faster */

		/* Pass ownership back to SDMA */
		r->descs[r->descs_ptr]->cmd_sts = RX_CMD_BIT_OWN_SDMA |
						  RX_CMD_BIT_EN_INTR;

		/* Goto next desc */
		cyclic_inc(&r->descs_ptr, ppdev->rx_rings_size[queue]);

		/* Goto next buff */
		cyclic_inc(&r->buffs_ptr, ppdev->rx_rings_size[queue]);

		done++;
	}

	/* return the number of processed frames */
	return done;
}

int mvppnd_poll(struct napi_struct *napi, int budget)
{
	struct mvppnd_dev *ppdev = container_of(napi, struct mvppnd_dev, napi);
	int done_queue, done_total = 0, queue_budget;
	unsigned num_rx_q_proc = 0, num_rx_q_nonempty = 0;
	struct list_head rx_list;
	size_t queue_idx = 0;

	while (!ppdev->rx_queues[queue_idx]) { /* skip unused queues */
		cyclic_inc(&queue_idx, NUM_OF_RX_QUEUES);
	}
	INIT_LIST_HEAD(&rx_list); /* list containing all received buffers for passing to kernel in one go - faster */

#ifdef DBG_BUDGET
	last_budget_pkts = budget;
	if (budget > max_budget_pkts)
		max_budget_pkts = budget; /* for debug telemetries only */
#endif

	/* dev_dbg(&ppdev->pdev->dev, "budget %d\n", budget); */
#ifdef DBG_DELAY
	pr_err("mvppnd_poll - NAPI poll\n");
#endif
	mvppnd_inc_stat(ppdev, STATS_NAPI_POLL_CALLS, 1);
	/*
	 * For now just give each queue 1/8 of the NAPI budget,
	 * but no less than one buffer.
	 * In the future we will create a sysfs interface which
	 * will allow the user to specify the exact weight to
	 * give each queue, which will determine how many buffer
	 * can be read in one go from the queue:
	 */
	queue_budget = budget >> 3;
	if (!queue_budget)
		queue_budget = 1;

	do {
		done_queue = mvppnd_process_rx_queue(ppdev, queue_idx,
						     queue_budget,
						     &rx_list);
		if (done_queue > 0)
			num_rx_q_nonempty++; /* record how many reads from queues yielded at least one buffer */
		num_rx_q_proc++; /* and how many reads were done at all */

		mvppnd_inc_stat(ppdev,
				STATS_RX_Q0_PACKETS + queue_idx,
				done_queue);

		done_total += done_queue;

		cyclic_inc(&queue_idx, NUM_OF_RX_QUEUES); /* move to next queue */
		while (!ppdev->rx_queues[queue_idx]) { /* skip unused queues */
			cyclic_inc(&queue_idx, NUM_OF_RX_QUEUES);
		}
		/*
		 * if we cycled through all of the queues
		 * and at least one queue yielded buffers,
		 * then do another round, as due to the weights
		 * used (fixed or in the future configurable)
		 * there could be still more buffers to be received.
		 * only once we exhausted all queues or our NAPI
		 * budget should we bail out:
		 */
		if ( (!queue_idx) && (num_rx_q_nonempty) ) {
			num_rx_q_nonempty = 0;
			num_rx_q_proc = 0;
		}

	} while ((done_total < budget) && /* look for packets as long as budget was not exhausted */
		 (num_rx_q_proc < NUM_OF_RX_QUEUES) ); /* and not all RX queues were exhausted */

	/* dev_dbg(&ppdev->pdev->dev, "done %d\n", done_total); */

	if (done_total < budget) { /* No more packets */
		dev_dbg(&ppdev->pdev.pdev->dev, "re-enable interrupts\n");
		napi_complete(napi);
		mvppnd_en_rx_queues_intr(ppdev, 1);
		/*
		 * Read Receive_SDMA_Interrupt_Cause1 to clear the register
		 */
		mvppnd_read_reg(ppdev, REG_ADDR_RX_CAUSE_1);
	} else {
		mvppnd_inc_stat(ppdev, STATS_NAPI_BURN_BUDGET, 1);
	}

	mvppnd_inc_stat(ppdev, STATS_RX_PACKETS, done_total);
	/*
	 * Read Receive_SDMA_Interrupt_Cause1 to clear the register
	 */
	mvppnd_read_reg(ppdev, REG_ADDR_RX_CAUSE_1);

	/* dev_dbg(&ppdev->pdev->dev, "done napi poll\n"); */
#ifdef DBG_DELAY
	pr_err("mvppnd_poll - NAPI poll - end\n");
#endif

	/*
	 * process skbs in a list. This is much more
	 * cache efficient as Linux kernel has a lot
	 * of function called, and this allows only
	 * the Linux kernel function to stay hot in
	 * the CPU cache, imrpvoing performance.
	 */
	netif_receive_skb_list(&rx_list);

#ifdef DBG_BUDGET
	last_poll_pkts = done_total;
	if (done_total > max_poll_pkts)
		max_poll_pkts = done_total; /* debug telemetries */
#endif

	return done_total;
}

/*********** sysfs *************************************/

static void mvppnd_print_ring(struct mvppnd_dev *ppdev,
			      struct mvppnd_ring *ring, size_t ring_size,
			      size_t curr_ptr)
{
	u32 dma;
	int i, j;

	for (j = curr_ptr; j < curr_ptr + 3; j++) {
		i = cyclic_idx(j, ring_size);
		if (i == 0)
			dma = ring->ring_dma;
		else
			dma = ring->descs[i - 1]->next_desc_ptr;

		dev_dbg(ppdev->dev,
			"\t[%d, 0x%x]: 0x%x, 0x%x, 0x%x, 0x%x\n",
			i, dma, ring->descs[i]->cmd_sts,
			__builtin_bswap32(ring->descs[i]->bc),
			ring->descs[i]->buf_addr,
			ring->descs[i]->next_desc_ptr);
	}
}

static ssize_t mvppnd_show_rx_queues(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_rx_queues);
	int i;

	strcpy(buf, "");

	for (i = 0; i < NUM_OF_RX_QUEUES; i++) {
		snprintf(buf, PAGE_SIZE, "%s[%c%d] 0x%x, %ld/%ld\n", buf,
			 ppdev->rx_queues[i] ? '*' : ' ', i,
			 mvppnd_read_rx_first_desc(ppdev, i),
			 ppdev->rx_queues[i] ?
			 ppdev->rx_queues[i]->ring.descs_ptr : -1,
			 ppdev->rx_queues[i] ?  ppdev->rx_rings_size[i] : -1);
		if (ppdev->rx_queues[i] && ppdev->rx_queues[i]->ring.descs)
			mvppnd_print_ring(ppdev, &ppdev->rx_queues[i]->ring,
					    ppdev->rx_rings_size[i],
					    ppdev->rx_queues[i]->ring.
					    descs_ptr);
	}

	return strlen(buf);
}

static void mvppnd_alloc_rx_queues(struct mvppnd_dev *ppdev)
{
	int i;

	for (i = 0; i < NUM_OF_RX_QUEUES; i++) {
		if (!test_bit(i, (unsigned long *)&ppdev->rx_queues_mask))
			continue;
		ppdev->rx_queues[i] = kmalloc(sizeof(*ppdev->rx_queues[i]),
				              GFP_KERNEL);
	}
}

static void mvppnd_free_rx_queues(struct mvppnd_dev *ppdev)
{
	int i;

	for (i = 0; i < NUM_OF_RX_QUEUES; i++) {
		kfree(ppdev->rx_queues[i]);
		ppdev->rx_queues[i] = NULL;
	}
}

static ssize_t mvppnd_store_rx_queues(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_rx_queues);
	unsigned long queues_bitmap;
	int rc;

	if ((ppdev->pdev.pdev) && (unlikely(ppdev->pdev.atu_win == -1)) &&
	    (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)) {
		dev_err(&ppdev->pdev.pdev->dev,
			"Required atu_win configuration is missing\n");
		return -ENOSYS;
	}

	rc = sscanf(buf, "0x%lx", &queues_bitmap);
	if (rc != 1) {
		dev_err(ppdev->dev,
			"Invalid input, expecting 0xlx\n");
		return -EINVAL;
	}

	/* Save for interrupt masking */
	ppdev->rx_queues_mask = queues_bitmap;

	return count;
}

static ssize_t mvppnd_show_tx_queue(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_tx_queue);
	int i;

	for (i = 0; i < NUM_OF_TX_QUEUES; i++) {
		snprintf(buf, PAGE_SIZE, "%s[%c%d] %d, 0x%x\n", buf,
			 (i == ppdev->tx_queue_num) ? '*' : ' ', i,
			 mvppnd_queue_enabled(ppdev, REG_ADDR_TX_QUEUE_CMD, i) ?
			 1 : 0, mvppnd_read_tx_first_desc(ppdev, i));
	}

	if (ppdev->tx_queue.ring.ring_dma) /* Ring is initialized? */
		mvppnd_print_ring(ppdev, &ppdev->tx_queue.ring, TX_RING_SIZE,
				  0);

	return strlen(buf);
}

static ssize_t mvppnd_store_tx_queue(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_tx_queue);
	if ((sscanf(buf, "%d", &ppdev->tx_queue_num) != 1) ||
	    (ppdev->tx_queue_num < -1) ||
	    (ppdev->tx_queue_num >= NUM_OF_TX_QUEUES)) {
		dev_err(ppdev->dev,
			"Invalid queue number %d\n", ppdev->tx_queue_num);
		ppdev->tx_queue_num = -1;
		return -EINVAL;
	}

	/* Verify that the requested queue is not used by Packet Generator */
	if (mvppnd_read_reg(ppdev, REG_ADDR_PG_CFG_QUEUE +
			    REG_ADDR_PG_CFG_QUEUE_OFFSET_FORMULA *
			    ppdev->tx_queue_num)) {
		dev_err(ppdev->dev,
			"Queue %d is used by Packet Generator\n",
			ppdev->tx_queue_num);
		ppdev->tx_queue_num = -1;
		return -EINVAL;
	}

	return count;
}

static ssize_t mvppnd_show_atu_win(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_atu_win);
	u32 addr;
	int i;

	snprintf(buf, PAGE_SIZE, "%s%-8s\t%-8s\t%-8s\t%-8s\t%-8s\t%-8s\t%-8s\n",
		 "                   ", "ctrl1", "ctrl2", "low-base",
		 "upper-base", "limit", "low-target", "upper-target");

	if (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2) {
		for (i = 0; i < NUM_OF_ATU_WINDOWS; i++) {
			addr = ATU_OFFS + i * 0x0200;
			snprintf(buf, PAGE_SIZE,
				"%s[%c%d] (0x%x) out: 0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\n",
				buf, (i == ppdev->pdev.atu_win ? '*' : ' '), i, addr,
				ioread32(ppdev->pdev.bar0 + addr + 0x0000),
				ioread32(ppdev->pdev.bar0 + addr + 0x0004),
				ioread32(ppdev->pdev.bar0 + addr + 0x0008),
				ioread32(ppdev->pdev.bar0 + addr + 0x000c),
				ioread32(ppdev->pdev.bar0 + addr + 0x0010),
				ioread32(ppdev->pdev.bar0 + addr + 0x0014),
				ioread32(ppdev->pdev.bar0 + addr + 0x0018));
			addr += 0x0100; /* Now inbound */
			snprintf(buf, PAGE_SIZE,
				"%s[%c%d] (0x%x) in : 0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\n",
				buf, (i == ppdev->pdev.atu_win ? '*' : ' '), i, addr,
				ioread32(ppdev->pdev.bar0 + addr + 0x0000),
				ioread32(ppdev->pdev.bar0 + addr + 0x0004),
				ioread32(ppdev->pdev.bar0 + addr + 0x0008),
				ioread32(ppdev->pdev.bar0 + addr + 0x000c),
				ioread32(ppdev->pdev.bar0 + addr + 0x0010),
				ioread32(ppdev->pdev.bar0 + addr + 0x0014),
				ioread32(ppdev->pdev.bar0 + addr + 0x0018));
		}
	}

	return strlen(buf);
}

static ssize_t mvppnd_store_atu_win(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_atu_win);
	int rc;

	rc = sscanf(buf, "%d", &ppdev->pdev.atu_win);
	if (rc != 1) {
		dev_err(ppdev->dev, "Invalid input\n");
		ppdev->pdev.atu_win = -1;
		return -EINVAL;
	}

	rc = mvppnd_setup_iatu_window(ppdev, ppdev->pdev.mg_cluster);
	if (rc)
		return rc;

	debug_print_some_registers(ppdev);

	return count;
}

static int mvppnd_is_our_win(struct mvppnd_dev *ppdev, u8 win)
{
	int i;

	for (i = 0; i < sizeof(ppdev->mg_win); i++)
		if (win == ppdev->mg_win[i])
			return true;

	return false;
}

static ssize_t mvppnd_show_mg_win(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_mg_win);
	int i;

	for (i = 0; i < NUM_OF_MG_WINDOWS; i++) {
		snprintf(buf, PAGE_SIZE,
			 "%s[%c%d] 0x%-8x\t0x%-8x\t0x%-8x\t0x%-8x\n", buf,
			 mvppnd_is_our_win(ppdev, i) ?  '*' : ' ', i,
			 mvppnd_read_reg(ppdev, REG_ADDR_MG_BASE_ADDR + i *
					 REG_ADDR_MG_BASE_ADDR_OFFSET_FORMULA),
			 mvppnd_read_reg(ppdev, REG_ADDR_MG_SIZE + i *
					 REG_ADDR_MG_SIZE_OFFSET_FORMULA),
			 mvppnd_read_reg(ppdev, REG_ADDR_MG_HA + i *
					 REG_ADDR_MG_HA_OFFSET_FORMULA),
			 mvppnd_read_reg(ppdev, REG_ADDR_MG_CONTROL + i *
					 REG_ADDR_MG_CONTROL_OFFSET_FORMULA));
	}

	return strlen(buf);
}

static void mvppnd_save_mg_wins(struct mvppnd_dev *ppdev, long bitmask)
{
	int i, j;

	memset(ppdev->mg_win, 0, sizeof(ppdev->mg_win));
	for (i = 0, j = 0; (i < NUM_OF_MG_WINDOWS) &&
	     (j < sizeof(ppdev->mg_win)) ; i++)
		if (test_bit(i, &bitmask))
			ppdev->mg_win[j++] = i;
}

static ssize_t mvppnd_store_mg_win(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_mg_win);
	int win_mask;

	if (sscanf(buf, "0x%x", &win_mask) != 1) {
		netdev_err(ppdev->sdev.flows[0]->ndev, "Invalid input\n");
		goto out;
	}

	mvppnd_save_mg_wins(ppdev, win_mask);
out:
	return count;
}

static ssize_t mvppnd_show_max_pkt_sz(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_max_pkt_sz);

	snprintf(buf, PAGE_SIZE, "%ld\n", ppdev->max_pkt_sz);

	return strlen(buf);
}

static ssize_t mvppnd_store_max_pkt_sz(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_max_pkt_sz);

	sscanf(buf, "%ld", &ppdev->max_pkt_sz);
	ppdev->max_pkt_sz = ((ppdev->max_pkt_sz / 8) + 1) * 8;

	ppdev->sdev.flows[0]->ndev->max_mtu = ppdev->max_pkt_sz - CRC_SIZE;

	return count;
}

static ssize_t mvppnd_show_mac(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_mac);

	snprintf(buf, PAGE_SIZE, "%pM\n", flow->ndev->dev_addr);

	return strlen(buf);
}

static ssize_t mvppnd_store_mac(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_mac);
	unsigned int mac[ETH_ALEN];
	int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	u8 mac_bytes[ETH_ALEN];
#endif

	sscanf(buf, "%x:%x:%x:%x:%x:%x\n", &mac[0], &mac[1], &mac[2], &mac[3],
	       &mac[4], &mac[5]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
	for (i = 0; i < ETH_ALEN; i++)
		flow->ndev->dev_addr[i] = mac[i];
#else
	for (i = 0; i < ETH_ALEN; i++)
		mac_bytes[i] = (u8)mac[i];
	dev_addr_mod(flow->ndev, 0, mac_bytes, ETH_ALEN);
#endif

	return count;
}

static ssize_t mvppnd_show_dsa(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_tx_dsa);
	unsigned int dsa[DSA_SIZE];
	int i;

	for (i = 0; i < DSA_SIZE; i++)
		dsa[i] = flow->config_tx_dsa[i];

	snprintf(buf, PAGE_SIZE,
		 "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n",
		 dsa[0], dsa[1], dsa[2], dsa[3], dsa[4], dsa[5], dsa[6], dsa[7],
		 dsa[8], dsa[9], dsa[10], dsa[11], dsa[12], dsa[13], dsa[14],
		 dsa[15]);
	snprintf(buf, PAGE_SIZE,
		 "%s%.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x\n",
		 buf, dsa[0], dsa[1], dsa[2], dsa[3], dsa[4], dsa[5], dsa[6],
		 dsa[7], dsa[8], dsa[9], dsa[10], dsa[11], dsa[12], dsa[13],
		 dsa[14], dsa[15]);
	snprintf(buf, PAGE_SIZE,
		 "%s%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
		 buf, dsa[0], dsa[1], dsa[2], dsa[3], dsa[4], dsa[5], dsa[6],
		 dsa[7], dsa[8], dsa[9], dsa[10], dsa[11], dsa[12], dsa[13],
		 dsa[14], dsa[15]);

	return strlen(buf);
}

static ssize_t mvppnd_store_dsa(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_tx_dsa);
	unsigned int dsa[DSA_SIZE];
	int i;

	i = sscanf(buf, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
		  &dsa[0], &dsa[1], &dsa[2], &dsa[3], &dsa[4], &dsa[5], &dsa[6],
		  &dsa[7], &dsa[8], &dsa[9], &dsa[10], &dsa[11], &dsa[12],
		  &dsa[13], &dsa[14], &dsa[15]);

	if (i > DSA_SIZE) {
		netdev_err(flow->ndev,
			   "Invalid input, expecting less than %d vytes\n",
			   DSA_SIZE);
		return -EINVAL;
	}

	flow->config_tx_dsa_size = i;

	memset(flow->config_tx_dsa, 0, sizeof(flow->config_tx_dsa));
	for (i = 0; i < DSA_SIZE; i++)
		if (i < flow->config_tx_dsa_size)
			flow->config_tx_dsa[i] = dsa[i];

	return count;
}

static ssize_t mvppnd_show_tx_queue_size(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_tx_queue_size);

	sprintf(buf, "%d\n", ppdev->tx_queue_size);

	return strlen(buf);
}

static ssize_t mvppnd_store_tx_queue_size(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_tx_queue_size);
	int rc;

	rc = sscanf(buf, "%d", &ppdev->tx_queue_size);
	if (rc != 1) {
		ppdev->tx_queue_size = TX_QUEUE_SIZE;
		return -EINVAL;
	}

	return count;
}

static ssize_t mvppnd_show_rx_ring_size(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_rx_ring_size);
	int i;

	strcpy(buf, "");

	for (i = 0; i < NUM_OF_RX_QUEUES; i++) {
		if (!ppdev->rx_queues[i])
			continue;

		sprintf(buf, "%s[%d] %ld\n", buf, i, ppdev->rx_rings_size[i]);
	}

	return strlen(buf);
}

static ssize_t mvppnd_store_rx_ring_size(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_rx_ring_size);
	size_t arg1, arg2, i;
	int rc;

	rc = sscanf(buf, "%ld %ld", &arg1, &arg2);
	switch (rc) {
	case 1:
		/* one arg, for backward compatibility - size of all */
		for (i = 0; i < NUM_OF_RX_QUEUES; i++)
			ppdev->rx_rings_size[i] =
				roundup_pow_of_two(arg1);
		break;
	case 2:
		if (arg1 > NUM_OF_RX_QUEUES) {
			dev_err(ppdev->dev, "Invalid input, expecting < %d\n",
				NUM_OF_RX_QUEUES);
			return -EINVAL;
		}
		ppdev->rx_rings_size[arg1] = roundup_pow_of_two(arg2);
		break;
	default:
		dev_err(ppdev->dev,
			"Invalid input, expecting one or two args\n");
		return -EINVAL;
	};

	return count;
}

static ssize_t mvppnd_show_napi_budget(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_napi_budget);

	sprintf(buf, "%d", ppdev->napi_budget);

	return strlen(buf);
}

static ssize_t mvppnd_store_napi_budget(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_napi_budget);
	int rc;

	rc = sscanf(buf, "%d", &ppdev->napi_budget);
	if (rc != 1) {
		dev_err(&ppdev->pdev.pdev->dev,
			"Invalid input, expecting napi budget\n");
		return -EINVAL;
	}

	return count;
}

static ssize_t mvppnd_show_driver_statistics(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_driver_statistics);
	static unsigned long last_jiffies;
	int i;
	char lstr[96];


	for (i = 0; i <= STATS_LAST; i++)
		sprintf(buf, "%s%s: %ld\n", buf, mvppnd_get_stat_desc(i),
			mvppnd_get_stat(ppdev, i, last_jiffies));
	last_jiffies = jiffies;
	/* debug counters - either last + max or incrementing counters: */
	/* how much budget did we get from the kernel */
	sprintf(lstr, "last budget packets: %d\n", last_budget_pkts);
	strcat(buf, lstr);
	sprintf(lstr, "max budget packets: %d\n", max_budget_pkts);
	strcat(buf, lstr);
	/* how many packets were polled in the NAPI poll handling: */
	sprintf(lstr, "last poll packets: %d\n", last_poll_pkts);
	strcat(buf, lstr);
	sprintf(lstr, "max poll packets: %d\n", max_poll_pkts);
	strcat(buf, lstr);
	sprintf(lstr, "Failure to allocate receive buffers: %ld\n", no_skbs); /* failure to allocate RX SKBs counter */
	strcat(buf, lstr);
	sprintf(lstr, "DMA TX timeout: %ld\n", tx_tout); /* SDMA TX timeout counter */
	strcat(buf, lstr);
	sprintf(lstr, "tx busy returned due to size queued: %ld\n", tx_busy_size); /* driver ndo tx handler returned busy because too many buffers were queued for transmission */
	strcat(buf, lstr);
	sprintf(lstr, "tx busy returned due to memory allocation failure: %ld\n", tx_busy_mem); /* driver ndo tx handler returned busy because no memory could be allocated for buffer */
	strcat(buf, lstr);

	return strlen(buf);
}

static ssize_t mvppnd_store_driver_statistics(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_driver_statistics);
	u32 entries_bitmask;
	int rc, i;

	last_poll_pkts = max_poll_pkts = 0; /* zero debug statistics */
	last_budget_pkts = max_budget_pkts = 0;

	rc = sscanf(buf, "0x%x", &entries_bitmask);
	if (rc != 1) {
		dev_err(ppdev->dev,
			"Invalid input, expecting 32 bit hex number\n");
		return -EINVAL;
	}

	for (i = 0; i <= STATS_LAST; i++) {
		if ((entries_bitmask & 0x00000001) == 0x00000001)
			mvppnd_clear_stat(ppdev, i);
		entries_bitmask = entries_bitmask >> 1;
	}

	return count;
}

static ssize_t mvppnd_store_if_create(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_if_create);
	char name[IFNAMSIZ];
	int rc, port;

	/*
	 * Port argument is optional, if set by the user then let
	 * mvppnd_create_netdev use it, otherwise pass -1 as indication to pick
	 * the next port.
	 * Set to -2 since convention for ports numbers is 1-based.
	 */
	port = -2;

	rc = sscanf(buf, "%s %d", name, &port);
	if ((rc != 1) && (rc != 2)) {
		dev_err(ppdev->dev,
			"Invalid input, expecting ifname [port]\n");
		return -EINVAL;
	}

	rc = mvppnd_create_netdev(ppdev, name, port + 1 /* 1 based */);
	if (rc < 0) {
		dev_err(ppdev->dev,
			"Fail to create netdev %s, aborting.\n", name);
		return -EINVAL;
	}

	return count;
}

static inline int mvppnd_get_flow_id(struct mvppnd_dev *ppdev,
				     const char *ifname)
{
	int i;

	/* 1 based as we will never look for 0 */
	for (i = 1; i < MAX_NETDEVS; i++)
		if ((ppdev->sdev.flows[i]) &&
		    (!strcmp(ifname, netdev_name(ppdev->sdev.flows[i]->ndev))))
			return i;

	dev_err(ppdev->dev, "Fail to find %s\n", ifname);
	return -ENOENT;
}

static ssize_t mvppnd_store_if_delete(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_if_delete);
	char name[IFNAMSIZ];
	int rc, flow_id;

	rc = sscanf(buf, "%s", name);
	if (rc != 1) {
		dev_err(ppdev->dev,
			"Invalid input, expecting ifname\n");
		return -EINVAL;
	}

	flow_id = mvppnd_get_flow_id(ppdev, name);
	if (flow_id < 0) {
		dev_err(ppdev->dev, "Fail to remove %s\n", name);
		return -EINVAL;
	}

	mvppnd_destroy_netdev(ppdev, flow_id);

	return count;
}

static ssize_t mvppnd_show_rx_dsa_mask(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_rx_dsa_mask);
	unsigned int dsa[DSA_SIZE];
	int i;

	for (i = 0; i < DSA_SIZE; i++)
		dsa[i] = flow->rx_dsa_mask[i];

	snprintf(buf, PAGE_SIZE,
		 "%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
		 dsa[0], dsa[1], dsa[2], dsa[3], dsa[4], dsa[5], dsa[6], dsa[7],
		 dsa[8], dsa[9], dsa[10], dsa[11], dsa[12], dsa[13], dsa[14],
		 dsa[15]);

	return strlen(buf);
}

static ssize_t mvppnd_store_rx_dsa_mask(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_rx_dsa_mask);
	unsigned int dsa[DSA_SIZE];
	int sz, i;

	sz = sscanf(buf, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
		    &dsa[0], &dsa[1], &dsa[2], &dsa[3], &dsa[4], &dsa[5],
		    &dsa[6], &dsa[7], &dsa[8], &dsa[9], &dsa[10], &dsa[11],
		    &dsa[12], &dsa[13], &dsa[14], &dsa[15]);
	if (sz > DSA_SIZE) {
		netdev_err(flow->ndev,
			   "Invalid input, expecting less than %d vytes\n",
			   DSA_SIZE);
		return -EINVAL;
	}

	if (sz != flow->config_tx_dsa_size) {
		netdev_warn(flow->ndev, "mask size != dsa size (%d, %d)\n",
			    sz, flow->config_tx_dsa_size);
	}

	for (i = 0; i < sz; i++)
		flow->rx_dsa_mask[i] = dsa[i];

	return count;
}

static ssize_t mvppnd_show_rx_dsa_val(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_rx_dsa_val);
	unsigned int dsa[DSA_SIZE];
	int i;

	for (i = 0; i < DSA_SIZE; i++)
		dsa[i] = flow->rx_dsa_val[i];

	snprintf(buf, PAGE_SIZE,
		 "%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
		 dsa[0], dsa[1], dsa[2], dsa[3], dsa[4], dsa[5], dsa[6], dsa[7],
		 dsa[8], dsa[9], dsa[10], dsa[11], dsa[12], dsa[13], dsa[14],
		 dsa[15]);

	return strlen(buf);
}

static ssize_t mvppnd_store_rx_dsa_val(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct mvppnd_switch_flow *flow =
		container_of(attr, struct mvppnd_switch_flow, attr_rx_dsa_val);
	unsigned int dsa[DSA_SIZE];
	int sz, i;

	sz = sscanf(buf, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
		    &dsa[0], &dsa[1], &dsa[2], &dsa[3], &dsa[4], &dsa[5],
		    &dsa[6], &dsa[7], &dsa[8], &dsa[9], &dsa[10], &dsa[11],
		    &dsa[12], &dsa[13], &dsa[14], &dsa[15]);

	if (sz > DSA_SIZE) {
		netdev_err(flow->ndev,
			   "Invalid input, expecting less than %d vytes\n",
			   DSA_SIZE);
		return -EINVAL;
	}

	if (sz != flow->config_tx_dsa_size) {
		netdev_warn(flow->ndev, "val size != dsa size (%d, %d)\n",
			    sz, flow->config_tx_dsa_size);
	}

	for (i = 0; i < sz; i++)
		flow->rx_dsa_val[i] = dsa[i];

	return count;
}

static ssize_t mvppnd_show_mg(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_mg);

	snprintf(buf, PAGE_SIZE, "%d\n", ppdev->pdev.mg_cluster);

	return strlen(buf);
}

static ssize_t mvppnd_store_mg(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_mg);
	int rc, mg_cluster;

	rc = sscanf(buf, "%d", &mg_cluster);
	if (rc != 1) {
		dev_err(ppdev->dev, "Invalid input\n");
		return -EINVAL;
	}

	ppdev->pdev.mg_cluster = mg_cluster;

	rc = mvppnd_setup_iatu_window(ppdev, ppdev->pdev.mg_cluster);
	if (rc)
		return rc;

	return count;
}

#ifdef MVPPND_DEBUG_REG
static ssize_t mvppnd_store_reg(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct mvppnd_dev *ppdev = container_of(attr, struct mvppnd_dev,
						attr_reg);
	int argc, cmd, arg1, arg2, arg3;

	argc = sscanf(buf, "0x%x 0x%x 0x%x 0x%x", &cmd, &arg1,&arg2, &arg3);

	switch (cmd) {
	case 0x1: /* oATU */
		if (argc != 4) {
			printk("Expecting 4 args (win, field, val)\n");
			return -EINVAL;
		}
		printk("win 0x%x, field 0x%x, val 0x%x\n", arg1, arg2,
		       arg3);
		iowrite32(arg3, ppdev->pdev.bar0 + ATU_OFFS + arg1 *
			  0x0200 + arg2);
		break;

	case 0x2: /* iATU */
		if (argc != 4) {
			printk("Expecting 4 args (win, field, val)\n");
			return -EINVAL;
		}
		printk("win 0x%x, field 0x%x, val 0x%x\n", arg1, arg2,
		       arg3);
		iowrite32(arg3, ppdev->pdev.bar0 + ATU_OFFS + arg1 *
			  0x0200 + arg2 + 0x100);
		break;

	case 0x3:
		if (argc != 2) {
			printk("Expecting 1 arg (print_packets_interval)\n");
			return -EINVAL;
		}
		ppdev->print_packets_interval = arg1;
		break;

	default:
		printk("Invalid command 0x%x\n", cmd);
		return -EINVAL;
	};

	return count;
}
#endif

static int mvppnd_sysfs_create_file(struct net_device *ndev,
				    struct kobj_attribute *attr,
				    const char *name, umode_t mode,
				    ssize_t (*show)(struct kobject *kobj,
						    struct kobj_attribute *attr,
						    char *buf),
				    ssize_t (*store)(struct kobject *kobj,
						     struct kobj_attribute *attr,
						     const char *buf,
						     size_t count))
{
	attr->attr.name = name;
	attr->attr.mode = mode;
	attr->show = show;
	attr->store = store;

	return sysfs_create_file(&ndev->dev.kobj, &attr->attr);
}

static int mvppnd_sysfs_create_files(struct mvppnd_dev *ppdev, int flow_id)
{
	struct mvppnd_switch_flow *flow = ppdev->sdev.flows[flow_id];
	int rc;

	rc = mvppnd_sysfs_create_file(flow->ndev, &flow->attr_mac, "mac",
				      S_IRUSR | S_IWUSR, mvppnd_show_mac,
				      mvppnd_store_mac);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create mac sysfs file\n");
		return rc;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &flow->attr_tx_dsa, "dsa",
				      S_IRUSR | S_IWUSR, mvppnd_show_dsa,
				      mvppnd_store_dsa);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create dsa sysfs file\n");
		goto remove_mac;
	}

	if (flow_id) {
		rc = mvppnd_sysfs_create_file(flow->ndev,
					      &flow->attr_rx_dsa_val,
					      "rx_dsa_val", S_IRUSR | S_IWUSR,
					      mvppnd_show_rx_dsa_val,
					      mvppnd_store_rx_dsa_val);
		if (rc) {
			dev_err(ppdev->dev,
				"Fail to create rx_dsa_val sysfs file\n");
			goto remove_dsa;
		}

		rc = mvppnd_sysfs_create_file(flow->ndev,
					      &flow->attr_rx_dsa_mask,
					      "rx_dsa_mask", S_IRUSR | S_IWUSR,
					      mvppnd_show_rx_dsa_mask,
					      mvppnd_store_rx_dsa_mask);
		if (rc) {
			dev_err(ppdev->dev,
				"Fail to create rx_dsa_mask sysfs file\n");
			goto remove_rx_dsa_val;
		}

		/* The next entries applies only to main device, exit here */
		return 0;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_rx_queues,
				      "rx_queues", S_IRUSR | S_IWUSR,
				      mvppnd_show_rx_queues,
				      mvppnd_store_rx_queues);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create rx_queues sysfs file\n");
		goto remove_rx_dsa_mask;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_tx_queue,
				      "tx_queue", S_IRUSR | S_IWUSR,
				      mvppnd_show_tx_queue,
				      mvppnd_store_tx_queue);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create tx_queue sysfs file\n");
		goto remove_rx_queue;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_mg_win, "mg_win",
				      S_IRUSR | S_IWUSR, mvppnd_show_mg_win,
				      mvppnd_store_mg_win);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create mg_win sysfs file\n");
		goto remove_tx_queue;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_max_pkt_sz,
				      "max_pkt_sz", S_IRUSR | S_IWUSR,
				      mvppnd_show_max_pkt_sz,
				      mvppnd_store_max_pkt_sz);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create max_pkt_sz sysfs file\n");
		goto remove_mg_win;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev,
				      &ppdev->attr_driver_statistics,
				      "driver_statistics", S_IRUSR | S_IWUSR,
				      mvppnd_show_driver_statistics,
				      mvppnd_store_driver_statistics);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create driver_statistics sysfs file\n");
		goto remove_max_pkt_sz;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_napi_budget,
				      "napi_budget", S_IRUSR | S_IWUSR,
				      mvppnd_show_napi_budget,
				      mvppnd_store_napi_budget);
	if (rc) {
		dev_err(&ppdev->pdev.pdev->dev,
			"Fail to create napi_budget sysfs file\n");
		goto remove_driver_statistics;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_rx_ring_size,
				      "rx_ring_size", S_IRUSR | S_IWUSR,
				      mvppnd_show_rx_ring_size,
				      mvppnd_store_rx_ring_size);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create rx_ring_size sysfs file\n");
		goto remove_napi_budget;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_if_create,
				      "if_create", S_IWUSR, NULL,
				      mvppnd_store_if_create);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create if_create sysfs file\n");
		goto remove_rx_ring_size;
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_if_delete,
				      "if_delete", S_IWUSR, NULL,
				      mvppnd_store_if_delete);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create if_delete sysfs file\n");
		goto remove_if_create;
	}

	if ((ppdev->pdev.pdev) &&
	    (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)) {
		rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_atu_win,
					      "atu_win", S_IRUSR | S_IWUSR,
					      mvppnd_show_atu_win,
					      mvppnd_store_atu_win);
		if (rc) {
			dev_err(ppdev->dev,
				"Fail to create atu_win sysfs file\n");
				goto remove_if_delete;
		}

		rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_mg,
					      "mg", S_IRUSR | S_IWUSR,
					      mvppnd_show_mg, mvppnd_store_mg);
		if (rc) {
			dev_err(ppdev->dev, "Fail to create mg sysfs file\n");
			goto remove_atu_win;
		}
	}

	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_tx_queue_size,
				      "tx_queue_size", S_IRUSR | S_IWUSR,
				      mvppnd_show_tx_queue_size,
				      mvppnd_store_tx_queue_size);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create tx_queue_size sysfs file\n");
		goto remove_mg;
	}

#ifdef MVPPND_DEBUG_REG
	rc = mvppnd_sysfs_create_file(flow->ndev, &ppdev->attr_reg,
				      "reg", S_IRUSR | S_IWUSR, NULL,
				      mvppnd_store_reg);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to create reg sysfs file\n");
		goto remove_tx_queue_size;
	}

	goto out;

remove_tx_queue_size:
	if (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &ppdev->attr_tx_queue_size.attr);
#else
	goto out;
#endif

remove_mg:
	if (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &ppdev->attr_mg.attr);
remove_atu_win:
	if (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &ppdev->attr_atu_win.attr);
remove_if_delete:
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_if_delete.attr);

remove_if_create:
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_if_create.attr);

remove_rx_ring_size:
	sysfs_remove_file(&flow->ndev->dev.kobj,
			  &ppdev->attr_rx_ring_size.attr);

remove_napi_budget:
	sysfs_remove_file(&flow->ndev->dev.kobj,
			  &ppdev->attr_napi_budget.attr);

remove_driver_statistics:
	sysfs_remove_file(&flow->ndev->dev.kobj,
			  &ppdev->attr_driver_statistics.attr);

remove_max_pkt_sz:
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_max_pkt_sz.attr);

remove_mg_win:
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_mg_win.attr);

remove_tx_queue:
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_tx_queue.attr);

remove_rx_queue:
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_rx_queues.attr);

remove_rx_dsa_mask:
	if (flow_id)
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &flow->attr_rx_dsa_mask.attr);

remove_rx_dsa_val:
	if (flow_id)
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &flow->attr_rx_dsa_val.attr);

remove_dsa:
	sysfs_remove_file(&flow->ndev->dev.kobj, &flow->attr_tx_dsa.attr);

remove_mac:
	sysfs_remove_file(&flow->ndev->dev.kobj, &flow->attr_mac.attr);

out:
	return rc;
}

static void mvppnd_sysfs_remove_files(struct mvppnd_dev *ppdev, int flow_id)
{
	struct mvppnd_switch_flow *flow = ppdev->sdev.flows[flow_id];

	sysfs_remove_file(&flow->ndev->dev.kobj, &flow->attr_tx_dsa.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj, &flow->attr_mac.attr);

	if (flow_id) {
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &flow->attr_rx_dsa_mask.attr);
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &flow->attr_rx_dsa_val.attr);
		return;
	}
#ifdef MVPPND_DEBUG_REG
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_reg.attr);
#endif
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_if_delete.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_if_create.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj,
			  &ppdev->attr_rx_ring_size.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj,
			  &ppdev->attr_napi_budget.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj,
			  &ppdev->attr_driver_statistics.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_max_pkt_sz.attr);
	if ((ppdev->pdev.pdev) &&
	    (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)) {
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &ppdev->attr_mg_win.attr);
		sysfs_remove_file(&flow->ndev->dev.kobj,
				  &ppdev->attr_atu_win.attr);
	}
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_tx_queue.attr);
	sysfs_remove_file(&flow->ndev->dev.kobj, &ppdev->attr_rx_queues.attr);
}

static void mvppnd_sysfs_set_mode(struct mvppnd_dev *ppdev, umode_t mode)
{
	struct kobject *kobj = &ppdev->sdev.flows[0]->ndev->dev.kobj;
	int rc = 0;

	rc += sysfs_chmod_file(kobj, &ppdev->attr_rx_ring_size.attr, mode);
	rc += sysfs_chmod_file(kobj, &ppdev->attr_max_pkt_sz.attr, mode);
	rc += sysfs_chmod_file(kobj, &ppdev->attr_tx_queue.attr, mode);
	rc += sysfs_chmod_file(kobj, &ppdev->attr_rx_queues.attr, mode);

	/*
	 * We could be called also when driver goes down where we need to
	 * un-register our netdev. During this un-registration the ndo_close is
	 * called which in turn calls us.
	 * The framework do not provides the information that the ndo_close was
	 * called as part of un-registration so we need to rely on ourselves -
	 * hence the ppdev->going_down.
	 */
	if (rc && !ppdev->going_down)
		dev_err(ppdev->dev,
			"Fail to change file attrs, driver is unstable now\n");
}

/*********** netdev utilities ******************************/
static void mvppnd_stop_all_netdevs(struct mvppnd_dev *ppdev, bool going_down)
{
	int i;

	for (i = 1; i < MAX_NETDEVS; i++)
		if (ppdev->sdev.flows[i]) {
			netif_stop_queue(ppdev->sdev.flows[i]->ndev);
			if (going_down) {
				clear_bit(__LINK_STATE_START,
					  &ppdev->sdev.flows[i]->ndev->state);
				ppdev->sdev.flows[i]->ndev->flags &= ~IFF_UP;
			}
		}
}

/*********** tx functions ******************************/
static int mvppnd_xmit_buf(struct mvppnd_dev *ppdev,
			   struct mvppnd_switch_flow *flow, const char *macs,
			   struct mvppnd_dma_sg_buf *sgb)
{
	bool sdma_took, wait_too_long;
	size_t wr_ptr, wr_ptr_first;
	size_t total_bytes = 0;
	u32 tmp_next_desc_ptr; /* TODO: Working in 'list' mode */
	unsigned long jiffs; /* Wait for SDMA to take the desc */
	int data_ptr;
	int ret;

	if (!sgb->mappings[0])
		return -EINVAL;

	wr_ptr = cyclic_idx(ppdev->tx_queue.ring.descs_ptr, TX_RING_SIZE);
	wr_ptr_first = wr_ptr;

	/* MAC */
	memcpy(ppdev->mac.virt, macs, ETH_ALEN * 2);
	ppdev->tx_queue.ring.descs[wr_ptr]->buf_addr = ppdev->mac.dma;
	TX_DESC_SET_BYTE_CNT(ppdev->tx_queue.ring.descs[wr_ptr]->bc,
			     ETH_ALEN * 2);
	total_bytes += ETH_ALEN * 2;
	/*
	dev_dbg(&ppdev->pdev->dev, "MACs: desc %d, len %d (%ld), ptr 0x%llx\n",
		wr_ptr, ETH_ALEN * 2, total_bytes, ppdev->mac.dma);
	*/
	cyclic_inc(&wr_ptr, TX_RING_SIZE);

	/* DSA */
	print_dsa(flow->ndev->name, "tx", (u8 *)flow->config_tx_dsa);
	memcpy(ppdev->dsa.virt, flow->config_tx_dsa, flow->config_tx_dsa_size);
	ppdev->tx_queue.ring.descs[wr_ptr]->buf_addr = ppdev->dsa.dma;
	TX_DESC_SET_BYTE_CNT(ppdev->tx_queue.ring.descs[wr_ptr]->bc,
			     flow->config_tx_dsa_size);
	ppdev->tx_queue.ring.descs[wr_ptr]->cmd_sts = TX_CMD_BIT_OWN_SDMA |
						      TX_CMD_BIT_CRC;
	/*
	dev_dbg(&ppdev->pdev->dev, "DSA : desc %d, len %d (%ld), ptr 0x%llx\n",
		wr_ptr, DSA_SIZE, total_bytes, ppdev->dsa.dma);
	*/
	total_bytes += flow->config_tx_dsa_size;
	cyclic_inc(&wr_ptr, TX_RING_SIZE);

	/* Data */
	data_ptr = 0;
	while (sgb->mappings[data_ptr]) {
		ppdev->tx_queue.ring.descs[wr_ptr]->buf_addr =
			sgb->mappings[data_ptr];
		sgb->sizes[data_ptr] += CRC_SIZE;
		TX_DESC_SET_BYTE_CNT(ppdev->tx_queue.ring.descs[wr_ptr]->bc,
				     sgb->sizes[data_ptr]);
		total_bytes += sgb->sizes[data_ptr];
		ppdev->tx_queue.ring.descs[wr_ptr]->cmd_sts =
			TX_CMD_BIT_OWN_SDMA | TX_CMD_BIT_CRC;
#ifdef MVPPND_DEBUG_DATA_PATH
		dev_info(ppdev->dev,
			"data: desc %ld, len %ld (%ld, %ld), ptr 0x%llx\n",
			wr_ptr, sgb->sizes[data_ptr],
			total_bytes - flow->config_tx_dsa_size, total_bytes,
			sgb->mappings[data_ptr]);
#endif

		data_ptr++;
		/* We have more? */
		if ((data_ptr < ARRAY_SIZE(sgb->mappings) - 1) &&
		     sgb->mappings[data_ptr])
			cyclic_inc(&wr_ptr, TX_RING_SIZE);
		else
			break;
	}

	/* Last descriptor - add last */
	ppdev->tx_queue.ring.descs[wr_ptr]->cmd_sts |= TX_CMD_BIT_LAST;
	/* TODO: For some reason ring does not work so for now let's use list */
	tmp_next_desc_ptr = ppdev->tx_queue.ring.descs[wr_ptr]->next_desc_ptr;
	ppdev->tx_queue.ring.descs[wr_ptr]->next_desc_ptr = 0;

	mvppnd_write_tx_first_desc(ppdev, ppdev->tx_queue.ring.ring_dma);

	/* We are ready, let's update the first descriptor - ownership, CRC &
	   first */
	ppdev->tx_queue.ring.descs[wr_ptr_first]->cmd_sts =
		TX_CMD_BIT_OWN_SDMA | TX_CMD_BIT_CRC | TX_CMD_BIT_FIRST;

	/* Flash descriptors before enabling the queue */
	mb();

	mvppnd_enable_queue(ppdev, REG_ADDR_TX_QUEUE_CMD, ppdev->tx_queue_num);

	jiffs = jiffies;
	do {
		sdma_took = ((ppdev->tx_queue.ring.descs[wr_ptr]->cmd_sts &
			     TX_CMD_BIT_OWN_SDMA) != TX_CMD_BIT_OWN_SDMA);
		wait_too_long = (jiffies_to_usecs(jiffies - jiffs) >
				 TX_WAIT_FOR_CPU_OWENERSHIP_USEC);
		mb();
	} while (!sdma_took && !wait_too_long);

	/* check again if buffer is still not free: */
	wait_too_long = ((ppdev->tx_queue.ring.descs[wr_ptr]->cmd_sts &
                             TX_CMD_BIT_OWN_SDMA) == TX_CMD_BIT_OWN_SDMA);

	/*
	dev_dbg(&ppdev->pdev->dev,
		"Took %d usec to SDMA to take the descriptor\n",
		jiffies_to_usecs(jiffies - jiffs));
	*/

	/* TODO: For some reason ring does not work so for now let's use list */
	ppdev->tx_queue.ring.descs_ptr = 0;
	ppdev->tx_queue.ring.descs[wr_ptr]->next_desc_ptr = tmp_next_desc_ptr;

	/* TODO: The ring thing */
	/* cyclic_inc(&wr_ptr, TX_RING_SIZE); */
	/* ppdev->tx_queue.ring.descs_ptr = wr_ptr; */

	if (wait_too_long) {
		ret = -EIO;
		tx_tout++; /* increment counter indicating SDMA TX timeout occured */
		pr_err("TX TOUT q %d first desc ptr %llx frst idx %lu bd sts %x addr %x wr idx %lu bd sts %x addr %x en_q %x vendor %x devid %x \n",
			ppdev->tx_queue_num,
			ppdev->tx_queue.ring.ring_dma,
			wr_ptr_first,
			ppdev->tx_queue.ring.descs[wr_ptr_first]->cmd_sts,
			ppdev->tx_queue.ring.descs[wr_ptr_first]->buf_addr,
			wr_ptr,
			ppdev->tx_queue.ring.descs[wr_ptr]->cmd_sts,
			ppdev->tx_queue.ring.descs[wr_ptr]->buf_addr,
			mvppnd_read_reg(ppdev, REG_ADDR_TX_QUEUE_CMD),
			mvppnd_read_reg(ppdev, REG_ADDR_VENDOR),
			mvppnd_read_reg(ppdev, REG_ADDR_DEVICE) );
		pr_err(
"rej %x LW %x NDP %x CTDP %x cur %x cfg %x glbl ctrl %x ext glbl ctrl %x lpbck %x\n",
			mvppnd_read_reg(ppdev, 0x28F4 ),
			mvppnd_read_reg(ppdev, 0x2604 + ppdev->tx_queue_num*0x10),
			mvppnd_read_reg(ppdev, 0x2608 + ppdev->tx_queue_num*0x10),
			mvppnd_read_reg(ppdev, 0x2684),
			mvppnd_read_reg(ppdev, 0x26C0 + ppdev->tx_queue_num*4),
			mvppnd_read_reg(ppdev, 0x2800),
			mvppnd_read_reg(ppdev, 0x58),
			mvppnd_read_reg(ppdev, 0x5C),
			mvppnd_read_reg(ppdev, 0x64)
								);
	}
	else
		ret = total_bytes - ETH_ALEN * 2 - flow->config_tx_dsa_size;

#ifdef MVPPND_DEBUG_DATA_PATH
	dev_info(ppdev->dev, "Total sent %d\n", ret);
#endif

	return ret;
}

static bool mvppnd_rings_empty(struct mvppnd_dev *ppdev)
{
	struct mvppnd_ring *r = NULL;
	u32 rxqs;

	for(rxqs = 0; rxqs< NUM_OF_RX_QUEUES; rxqs++) {
		if (ppdev->rx_queues[rxqs]) {
			r = &ppdev->rx_queues[rxqs]->ring;
			if((r->descs[r->descs_ptr]->cmd_sts &
			    RX_CMD_BIT_OWN_SDMA) != RX_CMD_BIT_OWN_SDMA)
				return false;
		}
	}

	return true;
}

/*
 * LIMITATION: CPSS and mvEthDrv.ko are the two software components which
 * access the interrupt tree on receiving an interrupt. When an event occurs,
 * corresponding bit in the leaf node is set, all related bits leading
 * up to the root are set accordingly and an interrupt is generated by the
 * switch
 *
 * Only when software processes and acknowledges the interrupt for e.g.
 * by reading the leaf node which is read-on-clear, all related bits leading
 * up to the root are cleared allowing next interrupt to be generated
 *
 * If a bit in MG0 Tree 0 Receive_SDMA_Interrupt_Cause1 is set indicating
 * packet received in RX-Q before CPSS processes and acknowledges an
 * interrupt meant for CPSS, RX-Q interrupt is not generated
 *
 * This is a race condition seen due to two software components accessing
 * the interrupt tree and processing the interrupts independently
 *
 * WORKAROUND:
 * 0x1D002890 = Receive SDMA Interrupt Cause1 (Receive_SDMA_Interrupt_Cause1)
 *
 * This is RX SDMA Int Cause register from MG0 Tree 1 which needs to be
 * read to clear the race condition and enable generation of next interrupt.
 * If mvEthDrv.ko misses the interrupt due to race condition leading to
 * Receive_SDMA_Interrupt_Cause1 remaining set, CPSS takes of reading it
 * clearing the race condition
 *
 * CPSS uses MG0 Tree 0 and mvEthDrv.ko uses MG0 Tree 1
 *
 * LIMITATION: Currently CPSS is configuring the interrupt tree in the switch to
 * connect only MG0 Tree 1 to MG0 Tree 0. Tree 1 of no other MG is configure
 * this way
 *
 * NOTE: We do connect Tree 1 of Tile 2 for devices with 4 tiles. Tile 2 is
 * connected by Tree 1
 */
static irqreturn_t mvppnd_isr(int irq, void *data)
{
	struct mvppnd_dev *ppdev = (struct mvppnd_dev *)data;

	mvppnd_inc_stat(ppdev, STATS_INTERRUPTS, 1);

	mvppnd_dis_rx_queues_intr(ppdev, 1);
	/*
	* Read Receive_SDMA_Interrupt_Cause1 to clear the register
	*/
	mvppnd_read_reg(ppdev, REG_ADDR_RX_CAUSE_1);

	/*
	 * As mentioned in the note above, Receive_SDMA_Interrupt_Cause1 is read
	 * from multiple places to address the race condition. At this point
	 * Receive_SDMA_Interrupt_Cause1 may or may not hold value indicating
	 * RX-Q interrupt. Hence instead of relying on
	 * Receive_SDMA_Interrupt_Cause1, if NAPI isn't scheduled, we check
	 * the RX-Q ownership bit to check if the ownership is with CPU and if
	 * it is, we schedule NAPI to read the packets
	 */
	if (!test_bit(NAPI_STATE_SCHED, &ppdev->napi.state) &&
	    !mvppnd_rings_empty(ppdev)) {
		mvppnd_inc_stat(ppdev, STATS_RX_TREE1_INTERRUPTS, 1);
		napi_schedule(&ppdev->napi);
	} else {
		mvppnd_en_rx_queues_intr(ppdev, 1);
		/*
		 * Read Receive_SDMA_Interrupt_Cause1 to clear the register
		 */
		mvppnd_read_reg(ppdev, REG_ADDR_RX_CAUSE_1);
	}

	return IRQ_HANDLED;
}

int mvppnd_emulate_rx(struct net_device *ndev, u8 *dsa, char *data,
		      size_t data_len, u8 queue)
{
	struct mvppnd_switch_flow *flow = netdev_priv(ndev);
	struct mvppnd_dev *ppdev = flow->ppdev;
	struct mvppnd_hw_desc *desc;
	unsigned int buff_size;
	unsigned char *buff;
	u32 rx_first_desc;

	if ((queue > NUM_OF_RX_QUEUES) || (queue < 0))
		return -EINVAL;

	rx_first_desc = mvppnd_read_rx_first_desc(ppdev, queue);
	desc = (struct mvppnd_hw_desc *)phys_to_virt(rx_first_desc);
	if ((desc->cmd_sts & RX_CMD_BIT_OWN_SDMA) != RX_CMD_BIT_OWN_SDMA)
		return 0; /* no place on ring - drop */

	buff = phys_to_virt(desc->buf_addr);

	buff_size = 0;

	memcpy(buff, data, ETH_ALEN * 2);
	buff += ETH_ALEN * 2;
	data += ETH_ALEN * 2;
	buff_size += ETH_ALEN * 2;

	memcpy(buff, dsa, DSA_SIZE);
	buff += DSA_SIZE;
	buff_size += DSA_SIZE;

	memcpy(buff, data, data_len - ETH_ALEN * 2);
	buff += (data_len - ETH_ALEN * 2);
	buff_size += (data_len - ETH_ALEN * 2);

	memset(buff, 0, CRC_SIZE);
	buff_size += CRC_SIZE;

	RX_DESC_SET_BYTE_CNT(desc->bc, buff_size);
	desc->cmd_sts &= 0x7FFFFFFF;

	mvppnd_write_rx_first_desc(ppdev, queue, desc->next_desc_ptr);

	mvppnd_isr(ppdev->irq, (void *)ppdev);

	return buff_size;
}
EXPORT_SYMBOL(mvppnd_emulate_rx);

static void mvppnd_transmit_skb(struct sk_buff *skb)
{
	struct mvppnd_switch_flow *flow = netdev_priv(skb->dev);
	struct mvppnd_dev *ppdev = flow->ppdev;
	struct mvppnd_dma_sg_buf sgb = {};
	int rc;

	/*
	dev_dbg(&ppdev->pdev->dev, "Got packet to transmit, len %d (head %d)\n",
		skb->len, skb_headlen(skb));
	*/
	print_frame(ppdev, skb->data, 100, false);
	print_skb_hdr(ppdev, "tx", skb);

	/*
	 * if TX callback hook exists, call it and according to the
	 * return value decide what needs to be done with the packet:
	 */
	if (ppdev->ops && ppdev->ops->process_tx) {
		rc = ppdev->ops->process_tx(flow->ndev, skb);
		switch (rc) {
		case NF_DROP:
			flow->ndev->stats.tx_dropped++;
			return;
		case NF_ACCEPT:
			break;
		case NF_STOLEN:
			return;
		default:
			WARN_ONCE(1, "%s: Got invalid return value from process_tx\n",
				  DRV_NAME);
			ppdev->sdev.flows[0]->ndev->stats.rx_dropped++;
			return;
		};
	}

	rc = mvppnd_copy_skb_to_tx_buff(ppdev, skb, &sgb);
	if (rc) {
		dev_dbg(ppdev->dev, "Fail to map skb %p\n",
			skb->data);
		return;
	}

	rc = mvppnd_xmit_buf(ppdev, flow, skb->data, &sgb);
	if (rc > 0) {
		mvppnd_inc_stat(ppdev, STATS_TX_PACKETS, 1);
		flow->ndev->stats.tx_packets++;
		flow->ndev->stats.tx_bytes += rc;
	} else {
		flow->ndev->stats.tx_dropped++;
	}
}

static void mvppnd_tx_work(struct work_struct *work)
{
	struct mvppnd_skb_work *skb_work = container_of(work,
							struct mvppnd_skb_work,
							work);
	struct net_device *dev = skb_work->skb->dev;
	struct mvppnd_switch_flow *flow = netdev_priv(dev);
	struct mvppnd_dev *ppdev = flow->ppdev;

	/* Interface might go down while this work was in the queue */
	if ((!flow->up) || (ppdev->tx_queue_num == -1) || (!netif_running(dev)))
		goto out;

	mvppnd_transmit_skb(skb_work->skb);

out:
	skb_unref(skb_work->skb);
	kfree_skb(skb_work->skb);
	kfree(work);
	atomic_dec(&ppdev->tx_skb_in_transit);
	ppdev->sdev.stats[STATS_TX_IN_TRANSIT] =
		atomic_read(&ppdev->tx_skb_in_transit);
}

static int rx_thread(void *data)
{
	struct mvppnd_dev *ppdev = (struct mvppnd_dev *)data;
#ifdef DBG_DELAY
	unsigned long j[4] = { 0, 0, 0, 0};
#endif

	while (!kthread_should_stop()) {

		if (!test_bit(NAPI_STATE_SCHED, &ppdev->napi.state) &&
		    !mvppnd_rings_empty(ppdev)) {
			napi_schedule(&ppdev->napi);
#ifdef DBG_DELAY
			pr_err("RX THRD SCHED NAPI i%lu : %lu %lu %lu %lu\n",
				i, j[0], j[1], j[2], j[3]);
#endif
			usleep_range(1, 2); /* trigger NAPI poll fast on NOHZ_FULL system, without HRTimer delay no interrupts will be generated ==> no softIRQ scheduled */
		}
		else
			msleep(4); /* msleep() so kernel will reschedule */
#ifdef DBG_DELAY
		j[i++] = jiffies;
		if (i >= 4)
			i = 0;
#endif
	}

	return 0;
}

void mvppnd_free_wq(struct mvppnd_dev *ppdev)
{
	if (ppdev->tx_wq) {
		mvppnd_stop_all_netdevs(ppdev, true); /* prevents new queuing */
		flush_workqueue(ppdev->tx_wq);
		drain_workqueue(ppdev->tx_wq);
		destroy_workqueue(ppdev->tx_wq);
		ppdev->tx_wq = NULL;
	}
}

/*********** netdev ops ********************************/
int mvppnd_open(struct net_device *dev)
{
	struct mvppnd_switch_flow *flow = netdev_priv(dev);
	struct mvppnd_dev *ppdev = flow->ppdev;
	int rc;

	if (flow->flow_id) {
		if (!ppdev->sdev.flows[0]->up) {
			netdev_err(dev, "%s interface is down\n",
				   ppdev->sdev.flows[0]->ndev->name);
			return -EPERM;
		}

		/* Nothing to be done for regular flows */
		goto out;
	}

	if (ppdev->tx_queue_num == -1) {
		netdev_err(dev,
			   "Can't open device while tx_queue is not set\n");
		return -EPERM;
	}

	if (!ppdev->max_pkt_sz) {
		netdev_err(dev,
			   "Can't open device while max_pkt_sz is not set\n");
		return -EPERM;
	}

	if ((ppdev->pdev.pdev) && (ppdev->pdev.atu_win == -1) &&
	    (ppdev->pdev.pdev->device != PCI_DEVICE_ID_ALDRIN2)) {
		netdev_err(dev,
			   "Can't open device while atu_win is not set\n");
		return -EPERM;
	}

	mvppnd_alloc_rx_queues(ppdev);

	if (!mvppnd_num_of_rx_queues(ppdev)) {
		netdev_err(dev,
			   "Can't open device while rx_queues is not set\n");
		return -EPERM;
	}

	rc = mvppnd_alloc_device_coherent(ppdev);
	if (rc < 0) {
		netdev_err(dev, "Fail to allocate coherent memory\n");
		return -ENOMEM;
	}

	rc = mvppnd_setup_rx_rings(ppdev);
	if (rc) {
		netdev_err(dev, "Fail to create rx rings\n");
		goto free_coherent;
	}

	rc = mvppnd_setup_tx_ring(ppdev);
	if (rc) {
		netdev_err(dev, "Fail to create tx ring %d\n",
			   ppdev->tx_queue_num);
		ppdev->tx_queue_num = -1;
		goto destroy_rx_rings;
	}

	ppdev->mac.virt = mvppnd_alloc_coherent(ppdev, ETH_ALEN * 2,
						&ppdev->mac.dma);
	ppdev->dsa.virt = mvppnd_alloc_coherent(ppdev, DSA_SIZE,
						&ppdev->dsa.dma);

	ppdev->tx_wq = create_workqueue("mvppnd_tx");
	if (!ppdev->tx_wq) {
		netdev_err(dev, "Fail to allocate TX work queue\n");
		goto destroy_tx_rings;
	}

	mvppnd_disable_tx_interrupts(ppdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,1,0)
	netif_napi_add(dev, &ppdev->napi, mvppnd_poll,
		       DEFAULT_NAPI_POLL_WEIGHT);
#else
	netif_napi_add_weight(dev, &ppdev->napi, mvppnd_poll,
		       DEFAULT_NAPI_POLL_WEIGHT);
#endif
	napi_enable(&ppdev->napi);

	mvppnd_sysfs_set_mode(ppdev, S_IRUGO);

	/* Disable our queues on tree 0 */
	mvppnd_dis_rx_queues_intr(ppdev, 0);

	rc = request_irq(ppdev->irq, mvppnd_isr, IRQF_SHARED, DRV_NAME, ppdev);
	if (rc < 0) {
		netdev_err(dev, "Fail to request IRQ %d\n", ppdev->irq);
		goto destroy_tx_wq;
	}

	napi_schedule(&ppdev->napi);

	/* Clear cause in tree 1 */
	while (mvppnd_read_reg(ppdev, REG_ADDR_RX_CAUSE_1));

	/* Enable RX bit in cause tree 1 */
	mvppnd_edit_reg_or(ppdev, REG_ADDR_GLOBAL_MASK[1], 1 << 9);

	/* Enable our queues on tree 1 */
	mvppnd_en_rx_queues_intr(ppdev, 1);

	/*
	 * For now no implenetation of separate interrupt-tree for devices other
	 * than Falcon in CPSS. Until then let's have dedicated thread to
	 * monitor RX rings
	 * Also poll for Falcon as a mitigation for missed interrupts.
	 */
	ppdev->rx_thread = kthread_run(rx_thread, (void *)ppdev,
				       "mvppnd_rx");
	if (!ppdev->rx_thread) {
		netdev_err(dev, "Fail to start RX thread\n");
		goto destroy_tx_wq;
	}

	debug_print_some_registers(ppdev);

out:
	flow->up = true;

	return 0;

destroy_tx_wq:
	destroy_workqueue(ppdev->tx_wq);

destroy_tx_rings:
	mvppnd_destroy_tx_ring(ppdev);
	ppdev->tx_wq = NULL;

destroy_rx_rings:
	mvppnd_destroy_rx_rings(ppdev);

free_coherent:
	mvppnd_free_device_coherent(ppdev);

	return -EIO;
}

int mvppnd_stop(struct net_device *dev)
{
	struct mvppnd_switch_flow *flow = netdev_priv(dev);
	struct mvppnd_dev *ppdev = flow->ppdev;
	int i;

	flow->up = false;

	if (flow->flow_id) /* Nothing to be done for regular flows */
		return 0;

	if (ppdev->rx_thread) {
		kthread_stop(ppdev->rx_thread);
		if (in_atomic())
			mdelay((RX_THREAD_UDELAY * 2)/1000);
		else
			msleep(10);
	}

	mvppnd_dis_rx_queues_intr(ppdev, 1);

	free_irq(ppdev->irq, ppdev);

	napi_disable(&ppdev->napi); /* must be called to stop a current napi poll midway processing */

	netif_napi_del(&ppdev->napi);

	mvppnd_free_wq(ppdev);

	/* Main interface is shutdown, close all sub interfaces */
	mvppnd_stop_all_netdevs(ppdev, true);

	mvppnd_destroy_rings(ppdev);

	mvppnd_free_device_coherent(ppdev);

	for (i = 0; i < sizeof(ppdev->mg_win); i++)
		if (ppdev->mg_win[i])
			mvppnd_setup_mg_window(ppdev, ppdev->mg_win[i], 0, 0);

	mvppnd_sysfs_set_mode(ppdev, S_IRUSR | S_IWUSR);

	mvppnd_free_rx_queues(ppdev);

	return 0;
}

netdev_tx_t mvppnd_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mvppnd_switch_flow *flow = netdev_priv(skb->dev);
	struct mvppnd_dev *ppdev = flow->ppdev;
	struct mvppnd_skb_work *skb_work;

	/* We are overun, return 'busy' to slow down */
	if (atomic_read(&ppdev->tx_skb_in_transit) > ppdev->tx_queue_size) {
		tx_busy_size++; /* increment telemetry for this condition */
		return NETDEV_TX_BUSY;
	}

	skb_work = kmalloc(sizeof(*skb_work), GFP_KERNEL);
	if (unlikely(!skb_work)) {
		tx_busy_mem++; /* increment telemetry for this condition */
		return NETDEV_TX_BUSY;
	}

	INIT_WORK(&skb_work->work, mvppnd_tx_work);
	skb_work->ppdev = ppdev;
	skb_work->skb = skb_get(skb);

	atomic_inc(&ppdev->tx_skb_in_transit);
	ppdev->sdev.stats[STATS_TX_IN_TRANSIT] =
		atomic_read(&ppdev->tx_skb_in_transit);

	/*
	 * Always schedule on CPU #0.
	 * If queue_work() is used, then kernel ends up
	 * queuing on the current CPU (core).
	 * this function (mvppnd_start_xmit() ) is called
	 * always on top of the caller stack of user-space
	 * (which called send()/sendto() to the kernel),
	 * hence the current CPU/core is determined by the
	 * CPU/core the user-space process sending is
	 * scheduled on. under load, the Linux kernel will
	 * reschedule this process to a different CPU/core
	 * runqueue. If The kernel ping-pongs the process
	 * between two cores/CPUs, using queue_work() will
	 * end up queuing TX packets on two different CPU's
	 * work-queues, which can run concurrenly, creating
	 * an unhandled race condition. queuing to CPU #0
	 * will ensure queuing is always done to the same
	 * workqueue thread, which always exists, preventing
	 * this race condition from occuring:
	 */
	queue_work_on(0, ppdev->tx_wq, &skb_work->work);

	return NETDEV_TX_OK;
}

static void mvppnd_net_mclist(struct net_device *dev)
{
	/*
	 * This callback is supposed to deal with mc filter.
	 * In rx path we always accept everything hardware gives us.
	 */
}

static const struct net_device_ops mvppnd_netdev_ops = {
	.ndo_open		= mvppnd_open,
	.ndo_stop		= mvppnd_stop,
	.ndo_start_xmit		= mvppnd_start_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_set_rx_mode	= mvppnd_net_mclist,
};

static void mvppnd_init_ppdev(struct mvppnd_dev *ppdev, struct pci_dev *pdev,
			      const struct pci_device_id *ent)
{
	int i;

	mutex_init(&ppdev->rx_lock);
	ppdev->tx_queue_num = DEFAULT_TX_QUEUE;
	ppdev->rx_queues_mask = DEFAULT_RX_QUEUES;

	if (pdev && pdev->device != PCI_DEVICE_ID_ALDRIN2)
		ppdev->pdev.atu_win = DEFAULT_ATU_WIN;
	else
		ppdev->pdev.atu_win = -1;

	if (ent)
		ppdev->device_data =
			(struct device_private_data *)(ent->driver_data);
	else
		/* Platform device, assuming AC5/X/ or IM */
		ppdev->device_data = &ac5x_private_data;

	ppdev->max_pkt_sz = DEFAULT_PKT_SZ;

	mvppnd_save_mg_wins(ppdev, DEFAULT_MG_WIN);

	ppdev->napi_budget = DEFAULT_NAPI_POLL_WEIGHT;

	for (i = 0; i < NUM_OF_RX_QUEUES; i++)
		ppdev->rx_rings_size[i] = DEFAULT_RX_RING_SIZE;

	ppdev->tx_queue_size = TX_QUEUE_SIZE;
	atomic_set(&ppdev->tx_skb_in_transit, 0);
}

static void mvppnd_clean_ppdev(struct mvppnd_dev *ppdev)
{
	mutex_destroy(&ppdev->rx_lock);
}

int mvppnd_create_netdev(struct mvppnd_dev *ppdev, const char *name, int port)
{
	struct mvppnd_switch_flow *flow;
	struct net_device *ndev;
	unsigned long flow_id;
	int rc;
	u8  u8_flow_id;

	if (port >= 0) {
		if ((port >= MAX_NETDEVS) ||
		    test_and_set_bit(port, ppdev->sdev.flows_bitmap))
			return -ENOMEM;
		flow_id = port;
	} else {
		flow_id = find_first_zero_bit(ppdev->sdev.flows_bitmap,
					      MAX_NETDEVS);
		if (flow_id >= MAX_NETDEVS) {
			dev_err(ppdev->dev,
				"Maximum %d devices are allowed\n",
				MAX_NETDEVS);
			return -ENOMEM;
		}
		set_bit(flow_id, ppdev->sdev.flows_bitmap);
	}
	BUG_ON(ppdev->sdev.flows[flow_id]);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	ndev = alloc_netdev_mqs(sizeof(*flow), name, NET_NAME_UNKNOWN,
				ether_setup, 1, 1);
#else
	ndev = alloc_netdev_mqs(sizeof(*flow), name, ether_setup, 1, 1);
#endif
	if (!ndev)
		return -ENOMEM;

	/* SET_NETDEV_DEV(ndev, ppdev->dev); */

	ndev->netdev_ops = &mvppnd_netdev_ops;

	rc = register_netdev(ndev);
	if (rc) {
		dev_err(ppdev->dev,
			"Fail to register net device (%d), aborting.\n", rc);
		goto free_netdev;
	}

	flow = netdev_priv(ndev);

	flow->ppdev = ppdev;
	flow->flow_id = flow_id;
	flow->ndev = ndev;
	/**
	 * Build default mask and val for the simple use where each flow
	 * represents a switch port
	 */
	memcpy(flow->rx_dsa_mask, DEFAULT_RX_DSA_MASK,
	       sizeof(DEFAULT_RX_DSA_MASK));
	flow->rx_dsa_val[1] = ((flow_id - 1) & 0x1f) << 3;
	flow->rx_dsa_val[6] = (((flow_id - 1) & 0x60) >> 5) << 2;
	flow->rx_dsa_val[9] = (((flow_id - 1) & 0x180) >> 7) << 4;

	ppdev->sdev.flows[flow_id] = flow;

	rc = mvppnd_sysfs_create_files(ppdev, flow_id);
	if (rc) {
		netdev_err(ndev, "Fail to create sysfs files, aborting.\n");
		goto unregister_netdev;
	}

	flow->config_tx_dsa_size = sizeof(DEFAULT_TX_DSA);
	memcpy(flow->config_tx_dsa, DEFAULT_TX_DSA,
	       flow->config_tx_dsa_size);

	if (!flow_id) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
		memcpy(ndev->dev_addr, DEFAULT_MAC, ETH_ALEN);
#else
		dev_addr_mod(ndev, 0, DEFAULT_MAC, ETH_ALEN);
#endif
	} else {
		/* MAC is based on port 0 MAC with last byte set to flow ID */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
		memcpy(ndev->dev_addr, ppdev->sdev.flows[0]->ndev->dev_addr,
		       ETH_ALEN);
		ndev->dev_addr[5] = flow_id;
#else
		dev_addr_mod(ndev, 0, ppdev->sdev.flows[0]->ndev->dev_addr,
		             ETH_ALEN);
		u8_flow_id = flow_id;
		dev_addr_mod(ndev, 5, &u8_flow_id, 1);
#endif
		flow->config_tx_dsa[1] = flow->rx_dsa_val[1];
		flow->config_tx_dsa[6] = flow->rx_dsa_val[6];
		flow->config_tx_dsa[9] = flow->rx_dsa_val[9];

		ppdev->sdev.flows_cnt++;
	}

	ndev->max_mtu = ppdev->max_pkt_sz - CRC_SIZE;

	ndev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	return flow_id;

unregister_netdev:
	unregister_netdev(ndev);

free_netdev:
	free_netdev(ndev);

	ppdev->sdev.flows[flow_id] = NULL;

	return -EIO;
}

static void mvppnd_destroy_netdev(struct mvppnd_dev *ppdev, int flow_id)
{
	struct mvppnd_switch_flow *flow = ppdev->sdev.flows[flow_id];

	BUG_ON(!flow);

	mvppnd_sysfs_remove_files(ppdev, flow_id);

	unregister_netdev(flow->ndev);

	free_netdev(flow->ndev);

	ppdev->sdev.flows[flow_id] = NULL;

	if (flow_id)
		ppdev->sdev.flows_cnt--;

	clear_bit(flow_id, ppdev->sdev.flows_bitmap);
}

static void mvppnd_destroy_netdevs(struct mvppnd_dev *ppdev)
{
	int i;

	mvppnd_free_wq(ppdev);
	for (i = 1; i < MAX_NETDEVS; i++)
		if (ppdev->sdev.flows[i])
			mvppnd_destroy_netdev(ppdev, i);

	mvppnd_destroy_netdev(ppdev, 0);
}

/*********** pci ops ***********************************/
static int mvppnd_map_bars_pci(struct mvppnd_dev *ppdev)
{
	ppdev->pdev.bar0 = pci_iomap(ppdev->pdev.pdev, 0, 0);
	if (!ppdev->pdev.bar0) {
		dev_err(&ppdev->pdev.pdev->dev,
			"Fail to remap to bar0, aborting.\n");
		return -ENOMEM;
	}
	dev_info(&ppdev->pdev.pdev->dev,
		 "bar0 phys 0x%llx, iomem %p, size %lld\n",
		 (u64) pci_resource_start(ppdev->pdev.pdev, 0),
		 ppdev->pdev.bar0,
		 (u64) pci_resource_len(ppdev->pdev.pdev, 0));

	ppdev->regs = pci_iomap(ppdev->pdev.pdev, 2, 0);
	if (!ppdev->regs) {
		dev_err(&ppdev->pdev.pdev->dev,
			"Fail to remap to bar2, aborting.\n");
		goto unmap_bar0;
	}
	dev_info(&ppdev->pdev.pdev->dev,
		 "bar2 phys 0x%llx, iomem %p, size %lld\n",
		 (u64) pci_resource_start(ppdev->pdev.pdev, 2),
		 ppdev->regs,
		 (u64) pci_resource_len(ppdev->pdev.pdev, 2));

	return 0;

unmap_bar0:
	iounmap(ppdev->pdev.bar0);

	return -ENOMEM;
}

static int mvppnd_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	struct mvppnd_dev *ppdev;
	int i, rc;

	dev_dbg(&pdev->dev, "bus: %d, vendor: 0x%04x, device: 0x%04x\n",
		pdev->bus->number, pdev->vendor, pdev->device);

	ppdev = kmalloc(sizeof(*ppdev), GFP_KERNEL | __GFP_ZERO);
	if (!ppdev) {
		dev_err(&pdev->dev, "Fail to allocate ppdev, aborting.\n");
		return -ENOMEM;
	}

	ppdev->dev = &pdev->dev;
	ppdev->pdev.pdev = pdev;

	mvppnd_init_ppdev(ppdev, pdev, ent);

	rc = mvppnd_create_netdev(ppdev, "mvpp%d", 0);
	BUG_ON(rc); /* we are the first so expecting bit #0 */
	if (rc < 0) {
		dev_err(&pdev->dev, "Fail to create netdev, aborting.\n");
		rc = -ENOMEM;
		goto free_ppdev;
	}

	pci_set_drvdata(pdev, ppdev);

	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Fail to enable PCI device, aborting.\n");
		rc = -ENOMEM;
		goto destroy_netdev;
	}

	for (i = 0; i < PCI_NUM_RESOURCES; i++)
		dev_dbg(&pdev->dev,
			"PCI BAR%d: %#lx %#llx %#llx %#llx\n", i,
			pci_resource_flags(pdev, i),
			(unsigned long long)pci_resource_start(pdev, i),
			(unsigned long long)pci_resource_end(pdev, i),
			(unsigned long long)pci_resource_len(pdev, i));

	/* Make sure that BAR0 and BAR2 are MMIO */
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM) ||
	    !(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Invalid PCI resource type, aborting.\n");
		goto disable_pci_device;
	}

	rc = pci_request_regions(pdev, DRV_NAME);
	if (rc) {
		dev_err(&pdev->dev, "Fail to request regions, aborting.\n");
		goto disable_pci_device;
	}

	/* We want 36 bit address space (32GB boards) */
	rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(36));
	if (rc) {
		dev_err(&pdev->dev, "Fail to set 36bit DMA mask\n");
		goto free_regions;
	}

	pci_set_master(pdev);

	ppdev->irq = ppdev->pdev.pdev->irq;

	/* Map to BARs */
	rc = mvppnd_map_bars_pci(ppdev);
	if (rc < 0)
		goto clear_pci_master;

	/*
	 * Use the default atu_win and mg setting, ignore warnings for now,
	 * trusting user to adjust before use
	 */
	mvppnd_setup_iatu_window(ppdev, ppdev->pdev.mg_cluster);

	/* TODO: for debug
	ppdev->pdev.atu_win = DEFAULT_ATU_WIN + 1;
	mvppnd_setup_iatu_window(ppdev, ppdev->pdev.mg_cluster + 4);
	ppdev->pdev.atu_win = DEFAULT_ATU_WIN;
	*/

	dev_info(&pdev->dev, "Probed to device\n");

	goto out;

clear_pci_master:
	pci_clear_master(pdev);

free_regions:
	pci_release_regions(pdev);

disable_pci_device:
	pci_disable_device(pdev);

destroy_netdev:
	mvppnd_destroy_netdev(ppdev, 0);

free_ppdev:
	kfree(ppdev);

out:
	return rc;
}

static void mvppnd_pci_remove(struct pci_dev *pdev)
{
	struct mvppnd_dev *ppdev = pci_get_drvdata(pdev);

	ppdev->going_down = true;

	/* TODO: Cleanup should be sensitive so it will verify that resource was
	 *       initialized in probe, i.e if probe did not failed
         */

	mvppnd_destroy_netdevs(ppdev);

	mvppnd_clean_ppdev(ppdev);

	if (ppdev->regs)
		iounmap(ppdev->regs);

	if (ppdev->pdev.bar0)
		iounmap(ppdev->pdev.bar0);

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	kfree(ppdev);

	dev_info(&pdev->dev, "Detached from device\n");
}

static const struct pci_device_id mvppnd_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_FALCON), 0, 0,
	  (kernel_ulong_t)&falcon_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_AC5P), 0, 0,
	  (kernel_ulong_t)&ac5p_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_HARRIER), 0, 0,
	  (kernel_ulong_t)&ac5p_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_AC5X_1), 0, 0,
	  (kernel_ulong_t)&ac5x_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_AC5X_2), 0, 0,
	  (kernel_ulong_t)&ac5x_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_IML), 0, 0,
	  (kernel_ulong_t)&ac5x_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_AC5), 0, 0,
	  (kernel_ulong_t)&ac5_private_data},
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, PCI_DEVICE_ID_ALDRIN2), 0, 0, 0},
	{ 0, 0, 0, 0, 0, 0, 0 }
};

MODULE_DEVICE_TABLE(pci, mvppnd_pci_tbl);

static struct pci_driver mvppnd_pci_driver = {
	.name		= DRV_NAME,
	.id_table	= mvppnd_pci_tbl,
	.probe		= mvppnd_pci_probe,
	.remove		= mvppnd_pci_remove,
	.shutdown	= mvppnd_pci_remove,
	.driver.pm	= NULL,
};

#ifdef SUPPORT_PLATFORM_DEVICE
static int mvppnd_get_irq_from_dt(void)
{
	struct device_node *node;
	int irq;

	node = of_find_node_by_path("/soc/prestera");
	if (!node)
		return -ENOENT;

	irq = irq_of_parse_and_map(node, 0);
	if (!irq)
		return -ENOENT;

	return irq;
}

static int mvppnd_pdriver_probe(struct platform_device *pdev)
{
	struct mvppnd_dev *ppdev;
	int rc;
	u32 devid;
	bool remap;

	dev_info(&pdev->dev, "Using platform device %s\n", pdev->name);

	/*
	 * Platform driver is for AC5/X. DDR start at 0x2_0000_0000,
	 * Hence 34 bit DMA mask is required:
	 */
	pdev->dev.coherent_dma_mask = DMA_BIT_MASK(34);
	pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;
	ppdev = kmalloc(sizeof(*ppdev), GFP_KERNEL | __GFP_ZERO);
	if (!ppdev) {
		dev_err(&pdev->dev, "Fail to allocate ppdev, aborting.\n");
		return -ENOMEM;
	}

	ppdev->dev = &pdev->dev;

	mvppnd_init_ppdev(ppdev, NULL, NULL);

	ppdev->irq = mvppnd_get_irq_from_dt();
	if (ppdev->irq == -ENOENT) {
		dev_err(&pdev->dev, "Fail to fetch IRQ from device-tree\n");
		rc = -ENOENT;
		goto free_ppdev;
	}

	rc = mvppnd_create_netdev(ppdev, "mvpp%d", 0);
	BUG_ON(rc); /* we are the first so expecting bit #0 */
	if (rc < 0) {
		dev_err(&pdev->dev, "Fail to create netdev, aborting.\n");
		rc = -ENOMEM;
		goto free_ppdev;
	}

	dev_set_drvdata(&pdev->dev, ppdev);

	do {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
		ppdev->regs = ioremap(ppdev->device_data->mg_reg_base,
#else
		ppdev->regs = ioremap_nocache(ppdev->device_data->mg_reg_base,
#endif
					      ATU_WIN_SIZE + 0x1);
		if (!ppdev->regs) {
			dev_err(ppdev->dev,
				"Fail to remap to MG space, aborting.\n");
			rc = -ENXIO;
			goto destroy_netdev;
		};

		/*
		 * AC5 has new style MG0 at address 0x7f900000 like AC5X,
		 * but this MG is not usable for SDMA.
		 * In order to get MG usuable for SDMA on AC5, we need to
		 * use the legacy MG at address zero.
		 * Hence, we need to unmap the previous mapping and remap
		 * again with the legacy MG.
		 * Note that for device ID functionality, MG0 at 0x7f90000
		 * is perfectly usable - only SDMA is not properly connected.
		 */
		devid = ioread32(ppdev->regs + REG_ADDR_DEVICE);
		if ( (((devid >> 4) & 0xff00) == (PCI_DEVICE_ID_AC5 & 0xff00)) &&
		     (ppdev->device_data->mg_reg_base != REG_ADDR_BASE_AC5) ) {
			iounmap(ppdev->regs);
			ppdev->device_data->mg_reg_base = REG_ADDR_BASE_AC5;
			remap = true;
		} else
			remap = false;
	} while (remap);

	dev_info(ppdev->dev,
		 "regs phys 0x%x, iomem %p, size %d\n",
		 ppdev->device_data->mg_reg_base, ppdev->regs,
		 ATU_WIN_SIZE + 0x1);

	dev_info(&pdev->dev, "Probed to device\n");

	goto out;

destroy_netdev:
	mvppnd_destroy_netdev(ppdev, 0);

free_ppdev:
	kfree(ppdev);
	return rc;

out:
	return 0;
};

static int mvppnd_pdriver_remove(struct platform_device *pdev)
{
	struct mvppnd_dev *ppdev;

	BUG_ON(!platdrv_registered);

	ppdev = (struct mvppnd_dev *)dev_get_drvdata(&pdev->dev);
	if (!ppdev)
		return 0;

	ppdev->going_down = true;

	mvppnd_destroy_netdevs(ppdev);

	mvppnd_clean_ppdev(ppdev);

	if (ppdev->regs)
		iounmap(ppdev->regs);

	kfree(ppdev);

	dev_info(&pdev->dev, "Detached from device\n");

	return 0;
}

static const struct of_device_id mvppnd_of_match_ids[] = {
	 { .compatible = "marvell,mvppnd", },
	{}
};

static struct platform_driver mvppnd_platform_driver = {
	.probe		= mvppnd_pdriver_probe,
	.remove		= mvppnd_pdriver_remove,
	.driver		= {
		.name		= DRV_NAME,
		.of_match_table = mvppnd_of_match_ids,
	},
};
#endif

/*********** module ************************************/
int mvppnd_init(void)
{
	int rc;

#ifdef SUPPORT_PLATFORM_DEVICE
	int err;

	err = platform_driver_register(&mvppnd_platform_driver);
	if (err)
		pr_err("%s: Fail to register platform driver\n", DRV_NAME);
	else
		platdrv_registered = 1;
#endif
	pr_info("Version: %s\n", ETH_DRV_VER);
	rc = pci_register_driver(&mvppnd_pci_driver);

	return rc;
}

void mvppnd_exit(void)
{
#ifdef SUPPORT_PLATFORM_DEVICE
	if (platdrv_registered)
		platform_driver_unregister(&mvppnd_platform_driver);
#endif
	pci_unregister_driver(&mvppnd_pci_driver);
}
