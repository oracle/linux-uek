/* bnx2.c: Broadcom NX2 network driver.
 *
 * Copyright (c) 2004-2012 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Michael Chan  (mchan@broadcom.com)
 */

#include <linux/version.h>
#include "bnx2_compat.h"

#if (LINUX_VERSION_CODE < 0x020612)
#include <linux/config.h>
#endif

#if (LINUX_VERSION_CODE < 0x020500)
#if defined(CONFIG_MODVERSIONS) && defined(MODULE) && ! defined(MODVERSIONS)
#define MODVERSIONS
#include <linux/modversions.h>
#endif
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#if (LINUX_VERSION_CODE >= 0x020600)
#include <linux/moduleparam.h>
#endif

#include <linux/stringify.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#if (LINUX_VERSION_CODE >= 0x020600)
#include <linux/dma-mapping.h>
#endif
#include <linux/bitops.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <linux/delay.h>
#include <asm/byteorder.h>
#include <asm/page.h>
#include <linux/time.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define BCM_VLAN 1
#endif

#ifdef NETIF_F_TSO
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#define BCM_TSO 1
#endif
#if (LINUX_VERSION_CODE >= 0x020600)
#include <linux/workqueue.h>
#endif
#ifndef BNX2_BOOT_DISK
#include <linux/crc32.h>
#endif
#include <linux/prefetch.h>
#include <linux/cache.h>
#include <linux/zlib.h>
#if (LINUX_VERSION_CODE >= 0x20617) && !defined(NETIF_F_MULTI_QUEUE)
#include <linux/log2.h>
#endif
#ifdef HAVE_AER
#include <linux/aer.h>
#endif

#if (LINUX_VERSION_CODE >= 0x020610)



#endif
#include "bnx2.h"
#include "bnx2_fw.h"
#include "bnx2_fw2.h"

#define DRV_MODULE_NAME		"bnx2"
#define DRV_MODULE_VERSION	"2.2.3e"
#define DRV_MODULE_RELDATE	"Aug 27, 2012"

#define RUN_AT(x) (jiffies + (x))

/* Time in jiffies before concluding the transmitter is hung. */
#if defined(__VMKLNX__)
/* On VMware ESX there is a possibility that that netdev watchdog thread
 * runs before the reset task if the machine is loaded.  If this occurs
 * too many times, these premature watchdog triggers will cause a PSOD
 * on a VMware ESX beta build */ 
#define TX_TIMEOUT  (20*HZ)
#else
#define TX_TIMEOUT  (5*HZ)
#endif /* defined(__VMKLNX__) */

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000)
#include "cnic_register.h"

static int bnx2_registered_cnic_adapter;
#endif /* defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000)*/

static char version[] __devinitdata =
	"Broadcom NetXtreme II Gigabit Ethernet Driver " DRV_MODULE_NAME " v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";

MODULE_AUTHOR("Michael Chan <mchan@broadcom.com>");
MODULE_DESCRIPTION("Broadcom NetXtreme II BCM5706/5708/5709/5716 Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

static int disable_msi = 0;

#if (LINUX_VERSION_CODE >= 0x20600)
module_param(disable_msi, int, 0);
MODULE_PARM_DESC(disable_msi, "Disable Message Signaled Interrupt (MSI)");
#endif

static int stop_on_tx_timeout = 0;

module_param(stop_on_tx_timeout, int, 0);
MODULE_PARM_DESC(stop_on_tx_timeout, "For debugging purposes, prevent a chip "
				     " reset when a tx timeout occurs");
#if defined(__VMKLNX__)
static int psod_on_tx_timeout;

module_param(psod_on_tx_timeout, int, 0);
MODULE_PARM_DESC(psod_on_tx_timeout, "For debugging purposes, crash the system "
				     " when a tx timeout occurs");

static int disable_msi_1shot = 0;
module_param(disable_msi_1shot, int, 0);
MODULE_PARM_DESC(disable_msi_1shot, "For debugging purposes, disable 1shot "
                                     " MSI mode if set to value of 1");
#if (VMWARE_ESX_DDK_VERSION >= 60000)
static int disable_fw_dmp;
module_param(disable_fw_dmp, int, 0);
MODULE_PARM_DESC(disable_fw_dmp, "For debugging purposes, disable firmware "
				 "dump feature when set to value of 1");
#endif
#endif

#define BNX2_MAX_NIC	32
#ifdef BNX2_ENABLE_NETQUEUE
#define BNX2_OPTION_UNSET   -1
#define BNX2_OPTION_ZERO	0

#define BNX2_NETQUEUE_ENABLED(bp) ((force_netq_param[bp->index] > 1) || \
				   (force_netq_param[bp->index] == \
						BNX2_OPTION_UNSET))
#define BNX2_NETQUEUE_DISABLED(bp) (force_netq_param[bp->index] == 0)

static int __devinitdata force_netq_param[BNX2_MAX_NIC+1] =
		{ [0 ... BNX2_MAX_NIC] = BNX2_OPTION_UNSET };

static unsigned int num_force_netq;
module_param_array_named(force_netq, force_netq_param, int,
			 &num_force_netq, 0);
MODULE_PARM_DESC(force_netq, "Option used for 5709/5716 only: "
			     "Enforce the number of NetQueues per port "
			     "(allowed values: -1 to 7 queues: "
			     "1-7 will force the number of NetQueues for the "
			     " given device, "
			     "0 to disable NetQueue, "
			     "-1 to use the default driver NetQueues value) "
			     "[Maximum supported NIC's = 32] "
			     "[example usage: force_net=-1,0,1,2: "
			     "This corresponds to the first 5709/5716 to use "
			     "the default number of NetQueues, "
			     "disable NetQueue on the second 5709/5716, "
			     "use 1 NetQueue on the third 5709/5716"
			     "use 2 NetQueues on the fourth 5709/5716]");
#endif /* BNX2_ENABLE_NETQUEUE */

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 60000)
#include <vmklinux_9/vmklinux_dump.h>
#define BNX2_DUMPNAME "bnx2_fwdmp"
static vmklnx_DumpFileHandle bnx2_fwdmp_dh;
static void *fwdmp_va_ptr;
static struct bnx2 *fwdmp_bp_ptr[BNX2_MAX_NIC];
static VMK_ReturnStatus bnx2_fwdmp_callback(void *cookie, vmk_Bool liveDump);
#endif

typedef enum {
	BCM5706 = 0,
	NC370T,
	NC370I,
	BCM5706S,
	NC370F,
	BCM5708,
	BCM5708S,
	BCM5709,
	BCM5709S,
	BCM5716,
	BCM5716S,
} board_t;

/* indexed by board_t, above */
static struct {
	char *name;
} board_info[] __devinitdata = {
	{ "Broadcom NetXtreme II BCM5706 1000Base-T" },
	{ "HP NC370T Multifunction Gigabit Server Adapter" },
	{ "HP NC370i Multifunction Gigabit Server Adapter" },
	{ "Broadcom NetXtreme II BCM5706 1000Base-SX" },
	{ "HP NC370F Multifunction Gigabit Server Adapter" },
	{ "Broadcom NetXtreme II BCM5708 1000Base-T" },
	{ "Broadcom NetXtreme II BCM5708 1000Base-SX" },
	{ "Broadcom NetXtreme II BCM5709 1000Base-T" },
	{ "Broadcom NetXtreme II BCM5709 1000Base-SX" },
	{ "Broadcom NetXtreme II BCM5716 1000Base-T" },
	{ "Broadcom NetXtreme II BCM5716 1000Base-SX" },
	};

static DEFINE_PCI_DEVICE_TABLE(bnx2_pci_tbl) = {
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706,
	  PCI_VENDOR_ID_HP, 0x3101, 0, 0, NC370T },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706,
	  PCI_VENDOR_ID_HP, 0x3106, 0, 0, NC370I },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5706 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5708,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5708 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706S,
	  PCI_VENDOR_ID_HP, 0x3102, 0, 0, NC370F },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706S,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5706S },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5708S,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5708S },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5709,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5709 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5709S,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5709S },
	{ PCI_VENDOR_ID_BROADCOM, 0x163b,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5716 },
	{ PCI_VENDOR_ID_BROADCOM, 0x163c,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, BCM5716S },
	{ 0, }
};

static const struct flash_spec flash_table[] =
{
#define BUFFERED_FLAGS		(BNX2_NV_BUFFERED | BNX2_NV_TRANSLATE)
#define NONBUFFERED_FLAGS	(BNX2_NV_WREN)
	/* Slow EEPROM */
	{0x00000000, 0x40830380, 0x009f0081, 0xa184a053, 0xaf000400,
	 BUFFERED_FLAGS, SEEPROM_PAGE_BITS, SEEPROM_PAGE_SIZE,
	 SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
	 "EEPROM - slow"},
	/* Expansion entry 0001 */
	{0x08000002, 0x4b808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 0001"},
	/* Saifun SA25F010 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x04000001, 0x47808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*2,
	 "Non-buffered flash (128kB)"},
	/* Saifun SA25F020 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x0c000003, 0x4f808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*4,
	 "Non-buffered flash (256kB)"},
	/* Expansion entry 0100 */
	{0x11000000, 0x53808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 0100"},
	/* Entry 0101: ST M45PE10 (non-buffered flash, TetonII B0) */
	{0x19000002, 0x5b808201, 0x000500db, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, ST_MICRO_FLASH_PAGE_BITS, ST_MICRO_FLASH_PAGE_SIZE,
	 ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*2,
	 "Entry 0101: ST M45PE10 (128kB non-bufferred)"},
	/* Entry 0110: ST M45PE20 (non-buffered flash)*/
	{0x15000001, 0x57808201, 0x000500db, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, ST_MICRO_FLASH_PAGE_BITS, ST_MICRO_FLASH_PAGE_SIZE,
	 ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*4,
	 "Entry 0110: ST M45PE20 (256kB non-bufferred)"},
	/* Saifun SA25F005 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x1d000003, 0x5f808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE,
	 "Non-buffered flash (64kB)"},
	/* Fast EEPROM */
	{0x22000000, 0x62808380, 0x009f0081, 0xa184a053, 0xaf000400,
	 BUFFERED_FLAGS, SEEPROM_PAGE_BITS, SEEPROM_PAGE_SIZE,
	 SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
	 "EEPROM - fast"},
	/* Expansion entry 1001 */
	{0x2a000002, 0x6b808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1001"},
	/* Expansion entry 1010 */
	{0x26000001, 0x67808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1010"},
	/* ATMEL AT45DB011B (buffered flash) */
	{0x2e000003, 0x6e808273, 0x00570081, 0x68848353, 0xaf000400,
	 BUFFERED_FLAGS, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE,
	 "Buffered flash (128kB)"},
	/* Expansion entry 1100 */
	{0x33000000, 0x73808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1100"},
	/* Expansion entry 1101 */
	{0x3b000002, 0x7b808201, 0x00050081, 0x03840253, 0xaf020406,
	 NONBUFFERED_FLAGS, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1101"},
	/* Ateml Expansion entry 1110 */
	{0x37000001, 0x76808273, 0x00570081, 0x68848353, 0xaf000400,
	 BUFFERED_FLAGS, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1110 (Atmel)"},
	/* ATMEL AT45DB021B (buffered flash) */
	{0x3f000003, 0x7e808273, 0x00570081, 0x68848353, 0xaf000400,
	 BUFFERED_FLAGS, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE*2,
	 "Buffered flash (256kB)"},
};

static const struct flash_spec flash_5709 = {
	.flags		= BNX2_NV_BUFFERED,
	.page_bits	= BCM5709_FLASH_PAGE_BITS,
	.page_size	= BCM5709_FLASH_PAGE_SIZE,
	.addr_mask	= BCM5709_FLASH_BYTE_ADDR_MASK,
	.total_size	= BUFFERED_FLASH_TOTAL_SIZE*2,
	.name		= "5709 Buffered flash (256kB)",
};

MODULE_DEVICE_TABLE(pci, bnx2_pci_tbl);

#if !defined(__VMKLNX__)
static void bnx2_init_napi(struct bnx2 *bp);
static void bnx2_del_napi(struct bnx2 *bp);
#else
static void __devinit bnx2_init_napi(struct bnx2 *bp);
static void __devexit bnx2_del_napi(struct bnx2 *bp);
#endif

static void bnx2_set_rx_ring_size(struct bnx2 *bp, u32 size);

#if defined(__VMKLNX__) 
static int
bnx2_tx_int(struct bnx2 *bp, struct bnx2_napi *bnapi, int budget,
	    int check_queue);
#endif /* defined(__VMKLNX__) */

#if defined(BNX2_ENABLE_NETQUEUE)
static int bnx2_netqueue_ops(vmknetddi_queueops_op_t op, void *args);
static void bnx2_stop_netqueue_hw(struct bnx2 *bp);
static void bnx2_start_netqueue_hw(struct bnx2 *bp);
static void bnx2_netqueue_service_bnx2_msix(struct bnx2_napi *bnapi);
static int bnx2_netqueue_is_avail(struct bnx2 *bp);
static void bnx2_close_netqueue_hw(struct bnx2 *bp);
static void bnx2_init_netqueue_hw(struct bnx2 *bp);
static int bnx2_open_netqueue_hw(struct bnx2 *bp);
static void bnx2_netqueue_flush_all(struct bnx2 *bp);
static int bnx2_netqueue_open_started(struct bnx2 *bp);

static inline u16 bnx2_get_hw_tx_cons(struct bnx2_napi *bnapi);
static inline u16 bnx2_get_hw_rx_cons(struct bnx2_napi *bnapi);

#ifdef BNX2_DEBUG
static u32 bnx2_read_ctx(struct bnx2 *bp, u32 offset);
#endif

#define TRUE 1
#define FALSE 0

#define for_each_nondefault_rx_queue(bp, var) \
				for (var = 1; var < bp->num_rx_rings; var++)
#define for_each_nondefault_tx_queue(bp, var) \
				for (var = 1; var < bp->num_tx_rings; var++)
#define is_multi(bp)		(bp->num_rx_ring > 1)
#endif /* defined(BNX2_ENABLE_NETQUEUE) */

#ifdef BNX2_BOOT_DISK
u32 ether_crc_le(size_t len, unsigned char const *p)
{
	u32 crc = ~0;
	int i;
#define CRCPOLY_LE 0xedb88320

	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}
#endif

static inline u32 bnx2_tx_avail(struct bnx2 *bp, struct bnx2_tx_ring_info *txr)
{
	u32 diff;

	/* Tell compiler to fetch tx_prod and tx_cons from memory. */
	barrier();

	/* The ring uses 256 indices for 255 entries, one of them
	 * needs to be skipped.
	 */
	diff = txr->tx_prod - txr->tx_cons;
	if (unlikely(diff >= TX_DESC_CNT)) {
		diff &= 0xffff;
		if (diff == TX_DESC_CNT)
			diff = MAX_TX_DESC_CNT;
	}
	return bp->tx_ring_size - diff;
}

static u32
bnx2_reg_rd_ind(struct bnx2 *bp, u32 offset)
{
	u32 val;

	spin_lock_bh(&bp->indirect_lock);
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW_ADDRESS, offset);
	val = REG_RD(bp, BNX2_PCICFG_REG_WINDOW);
	spin_unlock_bh(&bp->indirect_lock);
	return val;
}

static void
bnx2_reg_wr_ind(struct bnx2 *bp, u32 offset, u32 val)
{
	spin_lock_bh(&bp->indirect_lock);
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW_ADDRESS, offset);
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW, val);
	spin_unlock_bh(&bp->indirect_lock);
}

#if defined(__VMKLNX__)
static void
bnx2_reg_wr_ind_cfg(struct bnx2 *bp, u32 offset, u32 val)
{
	struct pci_dev *pdev = bp->pdev;

	spin_lock_bh(&bp->indirect_lock);
	pci_write_config_dword(pdev, BNX2_PCICFG_REG_WINDOW_ADDRESS, offset);
	pci_write_config_dword(pdev, BNX2_PCICFG_REG_WINDOW, val);
	spin_unlock_bh(&bp->indirect_lock);
}
#endif /* defined(__VMKLNX__) */

static void
bnx2_shmem_wr(struct bnx2 *bp, u32 offset, u32 val)
{
	bnx2_reg_wr_ind(bp, bp->shmem_base + offset, val);
}

static u32
bnx2_shmem_rd(struct bnx2 *bp, u32 offset)
{
	return bnx2_reg_rd_ind(bp, bp->shmem_base + offset);
}

static void
bnx2_ctx_wr(struct bnx2 *bp, u32 cid_addr, u32 offset, u32 val)
{
	offset += cid_addr;
	spin_lock_bh(&bp->indirect_lock);
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		int i;

		REG_WR(bp, BNX2_CTX_CTX_DATA, val);
		REG_WR(bp, BNX2_CTX_CTX_CTRL,
		       offset | BNX2_CTX_CTX_CTRL_WRITE_REQ);
		for (i = 0; i < 5; i++) {
			val = REG_RD(bp, BNX2_CTX_CTX_CTRL);
			if ((val & BNX2_CTX_CTX_CTRL_WRITE_REQ) == 0)
				break;
			udelay(5);
		}
	} else {
		REG_WR(bp, BNX2_CTX_DATA_ADR, offset);
		REG_WR(bp, BNX2_CTX_DATA, val);
	}
	spin_unlock_bh(&bp->indirect_lock);
}

#ifdef BCM_CNIC
static int
bnx2_drv_ctl(struct net_device *dev, struct drv_ctl_info *info)
{
	struct bnx2 *bp = netdev_priv(dev);
	struct drv_ctl_io *io = &info->data.io;

	switch (info->cmd) {
	case DRV_CTL_IO_WR_CMD:
		bnx2_reg_wr_ind(bp, io->offset, io->data);
		break;
	case DRV_CTL_IO_RD_CMD:
		io->data = bnx2_reg_rd_ind(bp, io->offset);
		break;
	case DRV_CTL_CTX_WR_CMD:
		bnx2_ctx_wr(bp, io->cid_addr, io->offset, io->data);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void bnx2_setup_cnic_irq_info(struct bnx2 *bp)
{
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0];
	int sb_id;

	if (bp->flags & BNX2_FLAG_USING_MSIX) {
		cp->drv_state |= CNIC_DRV_STATE_USING_MSIX;
		bnapi->cnic_present = 0;
		sb_id = bp->irq_nvecs;
		cp->irq_arr[0].irq_flags |= CNIC_IRQ_FL_MSIX;
	} else {
		cp->drv_state &= ~CNIC_DRV_STATE_USING_MSIX;
		bnapi->cnic_tag = bnapi->last_status_idx;
		bnapi->cnic_present = 1;
		sb_id = 0;
		cp->irq_arr[0].irq_flags &= ~CNIC_IRQ_FL_MSIX;
	}

	cp->irq_arr[0].vector = bp->irq_tbl[sb_id].vector;
	cp->irq_arr[0].status_blk = (void *)
		((unsigned long) bnapi->status_blk.msi +
		(BNX2_SBLK_MSIX_ALIGN_SIZE * sb_id));
	cp->irq_arr[0].status_blk_num = sb_id;
	cp->num_irq = 1;
}

static int bnx2_register_cnic(struct net_device *dev, struct cnic_ops *ops,
			      void *data)
{
	struct bnx2 *bp = netdev_priv(dev);
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	if (ops == NULL)
		return -EINVAL;

	if (cp->drv_state & CNIC_DRV_STATE_REGD)
		return -EBUSY;

	if (!bnx2_reg_rd_ind(bp, BNX2_FW_MAX_ISCSI_CONN))
		return -ENODEV;

	bp->cnic_data = data;
	rcu_assign_pointer(bp->cnic_ops, ops);

	cp->num_irq = 0;
	cp->drv_state = CNIC_DRV_STATE_REGD;

	bnx2_setup_cnic_irq_info(bp);

	return 0;
}

static int bnx2_unregister_cnic(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0];
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	mutex_lock(&bp->cnic_lock);
	cp->drv_state = 0;
	bnapi->cnic_present = 0;
	RCU_INIT_POINTER(bp->cnic_ops, NULL);
	mutex_unlock(&bp->cnic_lock);
	synchronize_rcu();
	return 0;
}

#if defined(BNX2_INBOX)
struct cnic_eth_dev *bnx2_cnic_probe(struct net_device *dev)
#else /* !defined(BNX2_INBOX) */
struct cnic_eth_dev *bnx2_cnic_probe2(struct net_device *dev)
#endif /* defined(BNX2_INBOX) */
{
	struct bnx2 *bp = netdev_priv(dev);
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	if (!cp->max_iscsi_conn)
		return NULL;

	cp->version = CNIC_ETH_DEV_VER;
	cp->drv_owner = THIS_MODULE;
	cp->chip_id = bp->chip_id;
	cp->pdev = bp->pdev;
	cp->io_base = bp->regview;
	cp->drv_ctl = bnx2_drv_ctl;
	cp->drv_register_cnic = bnx2_register_cnic;
	cp->drv_unregister_cnic = bnx2_unregister_cnic;

	return cp;
}
#if !(defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000))
#if defined(BNX2_INBOX)
EXPORT_SYMBOL(bnx2_cnic_probe);
#else /* !defined(BNX2_INBOX) */
EXPORT_SYMBOL(bnx2_cnic_probe2);
#endif /* defined(BNX2_INBOX) */
#endif

static void
bnx2_cnic_stop(struct bnx2 *bp)
{
	struct cnic_ops *c_ops;
	struct cnic_ctl_info info;

	mutex_lock(&bp->cnic_lock);
	c_ops = rcu_dereference_protected(bp->cnic_ops,
					  lockdep_is_held(&bp->cnic_lock));
	if (c_ops) {
		info.cmd = CNIC_CTL_STOP_CMD;

#if defined(__VMKLNX__)
		VMKAPI_MODULE_CALL_VOID(c_ops->cnic_owner->moduleID,
					c_ops->cnic_ctl, bp->cnic_data, &info);
#else
		c_ops->cnic_ctl(bp->cnic_data, &info);
#endif
	}
	mutex_unlock(&bp->cnic_lock);
}

static void
bnx2_cnic_start(struct bnx2 *bp)
{
	struct cnic_ops *c_ops;
	struct cnic_ctl_info info;

	mutex_lock(&bp->cnic_lock);
	c_ops = rcu_dereference_protected(bp->cnic_ops,
					  lockdep_is_held(&bp->cnic_lock));
	if (c_ops) {
		if (!(bp->flags & BNX2_FLAG_USING_MSIX)) {
			struct bnx2_napi *bnapi = &bp->bnx2_napi[0];

			bnapi->cnic_tag = bnapi->last_status_idx;
		}
		info.cmd = CNIC_CTL_START_CMD;
#if defined(__VMKLNX__)
		VMKAPI_MODULE_CALL_VOID(c_ops->cnic_owner->moduleID,
					c_ops->cnic_ctl, bp->cnic_data, &info);
#else
		c_ops->cnic_ctl(bp->cnic_data, &info);
#endif
	}
	mutex_unlock(&bp->cnic_lock);
}

#else

static void
bnx2_cnic_stop(struct bnx2 *bp)
{
}

static void
bnx2_cnic_start(struct bnx2 *bp)
{
}

#endif

static int
bnx2_read_phy(struct bnx2 *bp, u32 reg, u32 *val)
{
	u32 val1;
	int i, ret;

	if (bp->phy_flags & BNX2_PHY_FLAG_INT_MODE_AUTO_POLLING) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 &= ~BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	val1 = (bp->phy_addr << 21) | (reg << 16) |
		BNX2_EMAC_MDIO_COMM_COMMAND_READ | BNX2_EMAC_MDIO_COMM_DISEXT |
		BNX2_EMAC_MDIO_COMM_START_BUSY;
	REG_WR(bp, BNX2_EMAC_MDIO_COMM, val1);

	for (i = 0; i < 50; i++) {
		udelay(10);

		val1 = REG_RD(bp, BNX2_EMAC_MDIO_COMM);
		if (!(val1 & BNX2_EMAC_MDIO_COMM_START_BUSY)) {
			udelay(5);

			val1 = REG_RD(bp, BNX2_EMAC_MDIO_COMM);
			val1 &= BNX2_EMAC_MDIO_COMM_DATA;

			break;
		}
	}

	if (val1 & BNX2_EMAC_MDIO_COMM_START_BUSY) {
		*val = 0x0;
		ret = -EBUSY;
	}
	else {
		*val = val1;
		ret = 0;
	}

	if (bp->phy_flags & BNX2_PHY_FLAG_INT_MODE_AUTO_POLLING) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 |= BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	return ret;
}

static int
bnx2_write_phy(struct bnx2 *bp, u32 reg, u32 val)
{
	u32 val1;
	int i, ret;

	if (bp->phy_flags & BNX2_PHY_FLAG_INT_MODE_AUTO_POLLING) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 &= ~BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	val1 = (bp->phy_addr << 21) | (reg << 16) | val |
		BNX2_EMAC_MDIO_COMM_COMMAND_WRITE |
		BNX2_EMAC_MDIO_COMM_START_BUSY | BNX2_EMAC_MDIO_COMM_DISEXT;
	REG_WR(bp, BNX2_EMAC_MDIO_COMM, val1);

	for (i = 0; i < 50; i++) {
		udelay(10);

		val1 = REG_RD(bp, BNX2_EMAC_MDIO_COMM);
		if (!(val1 & BNX2_EMAC_MDIO_COMM_START_BUSY)) {
			udelay(5);
			break;
		}
	}

	if (val1 & BNX2_EMAC_MDIO_COMM_START_BUSY)
        	ret = -EBUSY;
	else
		ret = 0;

	if (bp->phy_flags & BNX2_PHY_FLAG_INT_MODE_AUTO_POLLING) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 |= BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	return ret;
}

static void
bnx2_disable_int(struct bnx2 *bp)
{
	int i;
	struct bnx2_napi *bnapi;

	for (i = 0; i < bp->irq_nvecs; i++) {
		bnapi = &bp->bnx2_napi[i];
		REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD, bnapi->int_num |
		       BNX2_PCICFG_INT_ACK_CMD_MASK_INT);
	}
	REG_RD(bp, BNX2_PCICFG_INT_ACK_CMD);
}

static void
bnx2_enable_int(struct bnx2 *bp)
{
	int i;
	struct bnx2_napi *bnapi;

	for (i = 0; i < bp->irq_nvecs; i++) {
		bnapi = &bp->bnx2_napi[i];

		REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD, bnapi->int_num |
		       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
		       BNX2_PCICFG_INT_ACK_CMD_MASK_INT |
		       bnapi->last_status_idx);

		REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD, bnapi->int_num |
		       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
		       bnapi->last_status_idx);
	}
	REG_WR(bp, BNX2_HC_COMMAND, bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW);
}

static void
bnx2_disable_int_sync(struct bnx2 *bp)
{
	int i;

	atomic_inc(&bp->intr_sem);
	if (!netif_running(bp->dev))
		return;

	bnx2_disable_int(bp);
	for (i = 0; i < bp->irq_nvecs; i++)
#if (LINUX_VERSION_CODE >= 0x2051c)
		synchronize_irq(bp->irq_tbl[i].vector);
#else
		synchronize_irq();
#endif
}

static void
bnx2_napi_disable(struct bnx2 *bp)
{
#ifdef BNX2_NEW_NAPI
	int i;

	for (i = 0; i < bp->irq_nvecs; i++)
		napi_disable(&bp->bnx2_napi[i].napi);
#else
	netif_poll_disable(bp->dev);
#endif
}

static void
bnx2_napi_enable(struct bnx2 *bp)
{
#ifdef BNX2_NEW_NAPI
	int i;

	for (i = 0; i < bp->irq_nvecs; i++)
		napi_enable(&bp->bnx2_napi[i].napi);
#else
	netif_poll_enable(bp->dev);
#endif
}

#if defined(BNX2_ENABLE_NETQUEUE)
static void
bnx2_netqueue_tx_flush_queue(struct bnx2_napi *bnapi,
			     struct bnx2_tx_ring_info *txr)
{
	struct bnx2 *bp = bnapi->bp;	

	rmb();
	if ((bnx2_get_hw_tx_cons(bnapi) != txr->hw_tx_cons) ||
	    (bnapi->tx_packets_sent != bnapi->tx_packets_processed)) {
		bnx2_tx_int(bp, bnapi, 100, 0);
		msleep(1);

		rmb();
	}
}


static void
bnx2_netqueue_tx_flush(struct bnx2 *bp)
{
	int i;
	struct bnx2_napi *bnapi;
        struct bnx2_tx_ring_info *txr;

	/*  Flush default ring */
	bnapi = &bp->bnx2_napi[0];
	txr = &bnapi->tx_ring;

	bnx2_netqueue_tx_flush_queue(bnapi, txr);
	netdev_info(bp->dev, "flushed default TX queue\n");

	/*  Flush NetQ rings */
	for_each_nondefault_tx_queue(bp, i) {
		bnapi = &bp->bnx2_napi[i];
		txr = &bnapi->tx_ring;

		rmb();

		bnx2_netqueue_tx_flush_queue(bnapi, txr);
		netdev_info(bp->dev, "flushed TX queue %d\n", i);
	}
}

static void
bnx2_netif_stop(struct bnx2 *bp, bool stop_cnic)
{
	if (stop_cnic)
		bnx2_cnic_stop(bp);
	if (netif_running(bp->dev)) {
		netif_tx_disable(bp->dev);
	}

	bnx2_disable_int_sync(bp);
	netif_carrier_off(bp->dev);	/* prevent tx timeout */

	/*  Give some settling time */
	msleep(250);

	if (netif_running(bp->dev)) {
		bnx2_napi_disable(bp);
	}

	rmb();

	if (bnx2_netqueue_open_started(bp))
		bnx2_netqueue_tx_flush(bp);
}

#else

static void
bnx2_netif_stop(struct bnx2 *bp, bool stop_cnic)
{
	if (stop_cnic)
		bnx2_cnic_stop(bp);
	if (netif_running(bp->dev)) {
		bnx2_napi_disable(bp);
		netif_tx_disable(bp->dev);
	}
	bnx2_disable_int_sync(bp);
	netif_carrier_off(bp->dev);	/* prevent tx timeout */
}

#endif

static void
bnx2_netif_start(struct bnx2 *bp, bool start_cnic)
{
	if (atomic_dec_and_test(&bp->intr_sem)) {
		if (netif_running(bp->dev)) {
			netif_tx_wake_all_queues(bp->dev);
			spin_lock_bh(&bp->phy_lock);
			if (bp->link_up)
				netif_carrier_on(bp->dev);
			spin_unlock_bh(&bp->phy_lock);
			bnx2_napi_enable(bp);
			bnx2_enable_int(bp);
			if (start_cnic)
				bnx2_cnic_start(bp);
		}
	}
}

static void
bnx2_free_tx_mem(struct bnx2 *bp)
{
	int i;

	for (i = 0; i < bp->num_tx_rings; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
		struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;

		if (txr->tx_desc_ring) {
#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_free_coherent(&bp->pdev->dev, TXBD_RING_SIZE,
					  txr->tx_desc_ring,
					  txr->tx_desc_mapping);
#else
			pci_free_consistent(bp->pdev, TXBD_RING_SIZE,
					    txr->tx_desc_ring,
					    txr->tx_desc_mapping);
#endif
			txr->tx_desc_ring = NULL;
		}
		kfree(txr->tx_buf_ring);
		txr->tx_buf_ring = NULL;
	}
}

static void
bnx2_free_rx_mem(struct bnx2 *bp)
{
	int i;

	for (i = 0; i < bp->num_rx_rings; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
		struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;
		int j;

		for (j = 0; j < bp->rx_max_ring; j++) {
			if (rxr->rx_desc_ring[j])
#if (LINUX_VERSION_CODE >= 0x02061b)
				dma_free_coherent(&bp->pdev->dev, RXBD_RING_SIZE,
						  rxr->rx_desc_ring[j],
						  rxr->rx_desc_mapping[j]);
#else
				pci_free_consistent(bp->pdev, RXBD_RING_SIZE,
						    rxr->rx_desc_ring[j],
						    rxr->rx_desc_mapping[j]);
#endif
			rxr->rx_desc_ring[j] = NULL;
		}
		vfree(rxr->rx_buf_ring);
		rxr->rx_buf_ring = NULL;

		for (j = 0; j < bp->rx_max_pg_ring; j++) {
			if (rxr->rx_pg_desc_ring[j])
#if (LINUX_VERSION_CODE >= 0x02061b)
				dma_free_coherent(&bp->pdev->dev, RXBD_RING_SIZE,
						  rxr->rx_pg_desc_ring[j],
						  rxr->rx_pg_desc_mapping[j]);
#else
				pci_free_consistent(bp->pdev, RXBD_RING_SIZE,
						    rxr->rx_pg_desc_ring[j],
						    rxr->rx_pg_desc_mapping[j]);
#endif
			rxr->rx_pg_desc_ring[j] = NULL;
		}
		vfree(rxr->rx_pg_ring);
		rxr->rx_pg_ring = NULL;
	}
}

static int
bnx2_alloc_tx_mem(struct bnx2 *bp)
{
	int i;

	for (i = 0; i < bp->num_tx_rings; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
		struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;

		txr->tx_buf_ring = kmalloc(SW_TXBD_RING_SIZE, GFP_KERNEL);
		if (txr->tx_buf_ring == NULL)
			return -ENOMEM;

		memset(txr->tx_buf_ring, 0, SW_TXBD_RING_SIZE);
		txr->tx_desc_ring =
#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_alloc_coherent(&bp->pdev->dev, TXBD_RING_SIZE,
					   &txr->tx_desc_mapping, GFP_KERNEL);
#else
			pci_alloc_consistent(bp->pdev, TXBD_RING_SIZE,
					     &txr->tx_desc_mapping);
#endif
		if (txr->tx_desc_ring == NULL)
			return -ENOMEM;
	}
	return 0;
}

static int
bnx2_alloc_rx_mem(struct bnx2 *bp)
{
	int i;

	for (i = 0; i < bp->num_rx_rings; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
		struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;
		int j;

		rxr->rx_buf_ring =
			vmalloc(SW_RXBD_RING_SIZE * bp->rx_max_ring);
		if (rxr->rx_buf_ring == NULL)
			return -ENOMEM;

		memset(rxr->rx_buf_ring, 0,
		       SW_RXBD_RING_SIZE * bp->rx_max_ring);

		for (j = 0; j < bp->rx_max_ring; j++) {
			rxr->rx_desc_ring[j] =
#if (LINUX_VERSION_CODE >= 0x02061b)
				dma_alloc_coherent(&bp->pdev->dev,
						   RXBD_RING_SIZE,
						   &rxr->rx_desc_mapping[j],
						   GFP_KERNEL);
#else
				pci_alloc_consistent(bp->pdev, RXBD_RING_SIZE,
						     &rxr->rx_desc_mapping[j]);
#endif
			if (rxr->rx_desc_ring[j] == NULL)
				return -ENOMEM;

		}

		if (bp->rx_pg_ring_size) {
			rxr->rx_pg_ring = vmalloc(SW_RXPG_RING_SIZE *
						  bp->rx_max_pg_ring);
			if (rxr->rx_pg_ring == NULL)
				return -ENOMEM;

			memset(rxr->rx_pg_ring, 0, SW_RXPG_RING_SIZE *
			       bp->rx_max_pg_ring);
		}

		for (j = 0; j < bp->rx_max_pg_ring; j++) {
			rxr->rx_pg_desc_ring[j] =
#if (LINUX_VERSION_CODE >= 0x02061b)
				dma_alloc_coherent(&bp->pdev->dev,
						   RXBD_RING_SIZE,
						   &rxr->rx_pg_desc_mapping[j],
						   GFP_KERNEL);
#else
				pci_alloc_consistent(bp->pdev, RXBD_RING_SIZE,
						&rxr->rx_pg_desc_mapping[j]);
#endif
			if (rxr->rx_pg_desc_ring[j] == NULL)
				return -ENOMEM;

		}
	}
	return 0;
}

static void
bnx2_free_mem(struct bnx2 *bp)
{
	int i;
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0];

	bnx2_free_tx_mem(bp);
	bnx2_free_rx_mem(bp);

	for (i = 0; i < bp->ctx_pages; i++) {
		if (bp->ctx_blk[i]) {
#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_free_coherent(&bp->pdev->dev, BCM_PAGE_SIZE,
					  bp->ctx_blk[i],
					  bp->ctx_blk_mapping[i]);
#else
			pci_free_consistent(bp->pdev, BCM_PAGE_SIZE,
					    bp->ctx_blk[i],
					    bp->ctx_blk_mapping[i]);
#endif
			bp->ctx_blk[i] = NULL;
		}
	}
	if (bnapi->status_blk.msi) {
#if (LINUX_VERSION_CODE >= 0x02061b)
		dma_free_coherent(&bp->pdev->dev, bp->status_stats_size,
				  bnapi->status_blk.msi,
				  bp->status_blk_mapping);
#else
		pci_free_consistent(bp->pdev, bp->status_stats_size,
				    bnapi->status_blk.msi,
				    bp->status_blk_mapping);
#endif
		bnapi->status_blk.msi = NULL;
		bp->stats_blk = NULL;
	}
}

static int
bnx2_alloc_mem(struct bnx2 *bp)
{
	int i, status_blk_size, err;
	struct bnx2_napi *bnapi;
	void *status_blk;

	/* Combine status and statistics blocks into one allocation. */
	status_blk_size = L1_CACHE_ALIGN(sizeof(struct status_block));
#ifdef CONFIG_PCI_MSI
	if (bp->flags & BNX2_FLAG_MSIX_CAP)
		status_blk_size = L1_CACHE_ALIGN(BNX2_MAX_MSIX_HW_VEC *
						 BNX2_SBLK_MSIX_ALIGN_SIZE);
#endif
	bp->status_stats_size = status_blk_size +
				sizeof(struct statistics_block);

#if (LINUX_VERSION_CODE >= 0x02061b)
	status_blk = dma_alloc_coherent(&bp->pdev->dev, bp->status_stats_size,
					&bp->status_blk_mapping, GFP_KERNEL);
#else
	status_blk = pci_alloc_consistent(bp->pdev, bp->status_stats_size,
					  &bp->status_blk_mapping);
#endif
	if (status_blk == NULL)
		goto alloc_mem_err;

	memset(status_blk, 0, bp->status_stats_size);

	bnapi = &bp->bnx2_napi[0];
	bnapi->status_blk.msi = status_blk;
	bnapi->hw_tx_cons_ptr =
		&bnapi->status_blk.msi->status_tx_quick_consumer_index0;
	bnapi->hw_rx_cons_ptr =
		&bnapi->status_blk.msi->status_rx_quick_consumer_index0;
	if (bp->flags & BNX2_FLAG_MSIX_CAP) {
		for (i = 1; i < bp->irq_nvecs; i++) {
			struct status_block_msix *sblk;

			bnapi = &bp->bnx2_napi[i];

			sblk = (status_blk + BNX2_SBLK_MSIX_ALIGN_SIZE * i);
			bnapi->status_blk.msix = sblk;
			bnapi->hw_tx_cons_ptr =
				&sblk->status_tx_quick_consumer_index;
			bnapi->hw_rx_cons_ptr =
				&sblk->status_rx_quick_consumer_index;
			bnapi->int_num = i << 24;
		}
	}

	bp->stats_blk = status_blk + status_blk_size;

	bp->stats_blk_mapping = bp->status_blk_mapping + status_blk_size;

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		/* NetQ uses CID 100, so we need 16K of context memory */
#if defined(BNX2_ENABLE_NETQUEUE)
		bp->ctx_pages = 0x4000 / BCM_PAGE_SIZE;
#else  /* !defined(__VMKLNX__) */
		bp->ctx_pages = 0x2000 / BCM_PAGE_SIZE;
#endif /* defined(__VMKLNX__) */
		if (bp->ctx_pages == 0)
			bp->ctx_pages = 1;
		for (i = 0; i < bp->ctx_pages; i++) {
#if (LINUX_VERSION_CODE >= 0x02061b)
			bp->ctx_blk[i] = dma_alloc_coherent(&bp->pdev->dev,
						BCM_PAGE_SIZE,
						&bp->ctx_blk_mapping[i],
						GFP_KERNEL);
#else
			bp->ctx_blk[i] = pci_alloc_consistent(bp->pdev,
						BCM_PAGE_SIZE,
						&bp->ctx_blk_mapping[i]);
#endif
			if (bp->ctx_blk[i] == NULL)
				goto alloc_mem_err;
		}
	}

	err = bnx2_alloc_rx_mem(bp);
	if (err)
		goto alloc_mem_err;

	err = bnx2_alloc_tx_mem(bp);
	if (err)
		goto alloc_mem_err;

	return 0;

alloc_mem_err:
	bnx2_free_mem(bp);
	return -ENOMEM;
}

static void
bnx2_report_fw_link(struct bnx2 *bp)
{
	u32 fw_link_status = 0;

	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
		return;

	if (bp->link_up) {
		u32 bmsr;

		switch (bp->line_speed) {
		case SPEED_10:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_10HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_10FULL;
			break;
		case SPEED_100:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_100HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_100FULL;
			break;
		case SPEED_1000:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_1000HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_1000FULL;
			break;
		case SPEED_2500:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_2500HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_2500FULL;
			break;
		}

		fw_link_status |= BNX2_LINK_STATUS_LINK_UP;

		if (bp->autoneg) {
			fw_link_status |= BNX2_LINK_STATUS_AN_ENABLED;

			bnx2_read_phy(bp, bp->mii_bmsr, &bmsr);
			bnx2_read_phy(bp, bp->mii_bmsr, &bmsr);

			if (!(bmsr & BMSR_ANEGCOMPLETE) ||
			    bp->phy_flags & BNX2_PHY_FLAG_PARALLEL_DETECT)
				fw_link_status |= BNX2_LINK_STATUS_PARALLEL_DET;
			else
				fw_link_status |= BNX2_LINK_STATUS_AN_COMPLETE;
		}
	}
	else
		fw_link_status = BNX2_LINK_STATUS_LINK_DOWN;

	bnx2_shmem_wr(bp, BNX2_LINK_STATUS, fw_link_status);
}

static char *
bnx2_xceiver_str(struct bnx2 *bp)
{
	return (bp->phy_port == PORT_FIBRE) ? "SerDes" :
		((bp->phy_flags & BNX2_PHY_FLAG_SERDES) ? "Remote Copper" :
		 "Copper");
}

static void
bnx2_report_link(struct bnx2 *bp)
{
	if (bp->link_up) {
		netif_carrier_on(bp->dev);
		netdev_info(bp->dev, "NIC %s Link is Up, %d Mbps %s duplex",
			    bnx2_xceiver_str(bp),
			    bp->line_speed,
			    bp->duplex == DUPLEX_FULL ? "full" : "half");

		if (bp->flow_ctrl) {
			if (bp->flow_ctrl & FLOW_CTRL_RX) {
				pr_cont(", receive ");
				if (bp->flow_ctrl & FLOW_CTRL_TX)
					pr_cont("& transmit ");
			}
			else {
				pr_cont(", transmit ");
			}
			pr_cont("flow control ON");
		}
		pr_cont("\n");
	} else {
		netif_carrier_off(bp->dev);
		netdev_err(bp->dev, "NIC %s Link is Down\n",
			   bnx2_xceiver_str(bp));
	}

	bnx2_report_fw_link(bp);
}

static void
bnx2_resolve_flow_ctrl(struct bnx2 *bp)
{
	u32 local_adv, remote_adv;

	bp->flow_ctrl = 0;
	if ((bp->autoneg & (AUTONEG_SPEED | AUTONEG_FLOW_CTRL)) !=
		(AUTONEG_SPEED | AUTONEG_FLOW_CTRL)) {

		if (bp->duplex == DUPLEX_FULL) {
			bp->flow_ctrl = bp->req_flow_ctrl;
		}
		return;
	}

	if (bp->duplex != DUPLEX_FULL) {
		return;
	}

	if ((bp->phy_flags & BNX2_PHY_FLAG_SERDES) &&
	    (CHIP_NUM(bp) == CHIP_NUM_5708)) {
		u32 val;

		bnx2_read_phy(bp, BCM5708S_1000X_STAT1, &val);
		if (val & BCM5708S_1000X_STAT1_TX_PAUSE)
			bp->flow_ctrl |= FLOW_CTRL_TX;
		if (val & BCM5708S_1000X_STAT1_RX_PAUSE)
			bp->flow_ctrl |= FLOW_CTRL_RX;
		return;
	}

	bnx2_read_phy(bp, bp->mii_adv, &local_adv);
	bnx2_read_phy(bp, bp->mii_lpa, &remote_adv);

	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		u32 new_local_adv = 0;
		u32 new_remote_adv = 0;

		if (local_adv & ADVERTISE_1000XPAUSE)
			new_local_adv |= ADVERTISE_PAUSE_CAP;
		if (local_adv & ADVERTISE_1000XPSE_ASYM)
			new_local_adv |= ADVERTISE_PAUSE_ASYM;
		if (remote_adv & ADVERTISE_1000XPAUSE)
			new_remote_adv |= ADVERTISE_PAUSE_CAP;
		if (remote_adv & ADVERTISE_1000XPSE_ASYM)
			new_remote_adv |= ADVERTISE_PAUSE_ASYM;

		local_adv = new_local_adv;
		remote_adv = new_remote_adv;
	}

	/* See Table 28B-3 of 802.3ab-1999 spec. */
	if (local_adv & ADVERTISE_PAUSE_CAP) {
		if(local_adv & ADVERTISE_PAUSE_ASYM) {
	                if (remote_adv & ADVERTISE_PAUSE_CAP) {
				bp->flow_ctrl = FLOW_CTRL_TX | FLOW_CTRL_RX;
			}
			else if (remote_adv & ADVERTISE_PAUSE_ASYM) {
				bp->flow_ctrl = FLOW_CTRL_RX;
			}
		}
		else {
			if (remote_adv & ADVERTISE_PAUSE_CAP) {
				bp->flow_ctrl = FLOW_CTRL_TX | FLOW_CTRL_RX;
			}
		}
	}
	else if (local_adv & ADVERTISE_PAUSE_ASYM) {
		if ((remote_adv & ADVERTISE_PAUSE_CAP) &&
			(remote_adv & ADVERTISE_PAUSE_ASYM)) {

			bp->flow_ctrl = FLOW_CTRL_TX;
		}
	}
}

static int
bnx2_5709s_linkup(struct bnx2 *bp)
{
	u32 val, speed;

	bp->link_up = 1;

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_GP_STATUS);
	bnx2_read_phy(bp, MII_BNX2_GP_TOP_AN_STATUS1, &val);
	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_COMBO_IEEEB0);

	if ((bp->autoneg & AUTONEG_SPEED) == 0) {
		bp->line_speed = bp->req_line_speed;
		bp->duplex = bp->req_duplex;
		return 0;
	}
	speed = val & MII_BNX2_GP_TOP_AN_SPEED_MSK;
	switch (speed) {
		case MII_BNX2_GP_TOP_AN_SPEED_10:
			bp->line_speed = SPEED_10;
			break;
		case MII_BNX2_GP_TOP_AN_SPEED_100:
			bp->line_speed = SPEED_100;
			break;
		case MII_BNX2_GP_TOP_AN_SPEED_1G:
		case MII_BNX2_GP_TOP_AN_SPEED_1GKV:
			bp->line_speed = SPEED_1000;
			break;
		case MII_BNX2_GP_TOP_AN_SPEED_2_5G:
			bp->line_speed = SPEED_2500;
			break;
	}
	if (val & MII_BNX2_GP_TOP_AN_FD)
		bp->duplex = DUPLEX_FULL;
	else
		bp->duplex = DUPLEX_HALF;
	return 0;
}

static int
bnx2_5708s_linkup(struct bnx2 *bp)
{
	u32 val;

	bp->link_up = 1;
	bnx2_read_phy(bp, BCM5708S_1000X_STAT1, &val);
	switch (val & BCM5708S_1000X_STAT1_SPEED_MASK) {
		case BCM5708S_1000X_STAT1_SPEED_10:
			bp->line_speed = SPEED_10;
			break;
		case BCM5708S_1000X_STAT1_SPEED_100:
			bp->line_speed = SPEED_100;
			break;
		case BCM5708S_1000X_STAT1_SPEED_1G:
			bp->line_speed = SPEED_1000;
			break;
		case BCM5708S_1000X_STAT1_SPEED_2G5:
			bp->line_speed = SPEED_2500;
			break;
	}
	if (val & BCM5708S_1000X_STAT1_FD)
		bp->duplex = DUPLEX_FULL;
	else
		bp->duplex = DUPLEX_HALF;

	return 0;
}

static int
bnx2_5706s_linkup(struct bnx2 *bp)
{
	u32 bmcr, local_adv, remote_adv, common;

	bp->link_up = 1;
	bp->line_speed = SPEED_1000;

	bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
	if (bmcr & BMCR_FULLDPLX) {
		bp->duplex = DUPLEX_FULL;
	}
	else {
		bp->duplex = DUPLEX_HALF;
	}

	if (!(bmcr & BMCR_ANENABLE)) {
		return 0;
	}

	bnx2_read_phy(bp, bp->mii_adv, &local_adv);
	bnx2_read_phy(bp, bp->mii_lpa, &remote_adv);

	common = local_adv & remote_adv;
	if (common & (ADVERTISE_1000XHALF | ADVERTISE_1000XFULL)) {

		if (common & ADVERTISE_1000XFULL) {
			bp->duplex = DUPLEX_FULL;
		}
		else {
			bp->duplex = DUPLEX_HALF;
		}
	}

	return 0;
}

static int
bnx2_copper_linkup(struct bnx2 *bp)
{
	u32 bmcr;

	bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
	if (bmcr & BMCR_ANENABLE) {
		u32 local_adv, remote_adv, common;

		bnx2_read_phy(bp, MII_CTRL1000, &local_adv);
		bnx2_read_phy(bp, MII_STAT1000, &remote_adv);

		common = local_adv & (remote_adv >> 2);
		if (common & ADVERTISE_1000FULL) {
			bp->line_speed = SPEED_1000;
			bp->duplex = DUPLEX_FULL;
		}
		else if (common & ADVERTISE_1000HALF) {
			bp->line_speed = SPEED_1000;
			bp->duplex = DUPLEX_HALF;
		}
		else {
			bnx2_read_phy(bp, bp->mii_adv, &local_adv);
			bnx2_read_phy(bp, bp->mii_lpa, &remote_adv);

			common = local_adv & remote_adv;
			if (common & ADVERTISE_100FULL) {
				bp->line_speed = SPEED_100;
				bp->duplex = DUPLEX_FULL;
			}
			else if (common & ADVERTISE_100HALF) {
				bp->line_speed = SPEED_100;
				bp->duplex = DUPLEX_HALF;
			}
			else if (common & ADVERTISE_10FULL) {
				bp->line_speed = SPEED_10;
				bp->duplex = DUPLEX_FULL;
			}
			else if (common & ADVERTISE_10HALF) {
				bp->line_speed = SPEED_10;
				bp->duplex = DUPLEX_HALF;
			}
			else {
				bp->line_speed = 0;
				bp->link_up = 0;
			}
		}
	}
	else {
		if (bmcr & BMCR_SPEED100) {
			bp->line_speed = SPEED_100;
		}
		else {
			bp->line_speed = SPEED_10;
		}
		if (bmcr & BMCR_FULLDPLX) {
			bp->duplex = DUPLEX_FULL;
		}
		else {
			bp->duplex = DUPLEX_HALF;
		}
	}

	return 0;
}

static void
bnx2_init_rx_context(struct bnx2 *bp, u32 cid)
{
	u32 val, rx_cid_addr = GET_CID_ADDR(cid);

	val = BNX2_L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE;
	val |= BNX2_L2CTX_CTX_TYPE_SIZE_L2;
	val |= 0x02 << 8;

	if (bp->flow_ctrl & FLOW_CTRL_TX)
		val |= BNX2_L2CTX_FLOW_CTRL_ENABLE;

	bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_CTX_TYPE, val);
}

static void
bnx2_init_all_rx_contexts(struct bnx2 *bp)
{
	int i;
	u32 cid;

	for (i = 0, cid = RX_CID; i < bp->num_rx_rings; i++, cid++) {
		if (i == 1)
			cid = RX_RSS_CID;
		bnx2_init_rx_context(bp, cid);
	}
}

static void
bnx2_set_mac_link(struct bnx2 *bp)
{
	u32 val;

	REG_WR(bp, BNX2_EMAC_TX_LENGTHS, 0x2620);
	if (bp->link_up && (bp->line_speed == SPEED_1000) &&
		(bp->duplex == DUPLEX_HALF)) {
		REG_WR(bp, BNX2_EMAC_TX_LENGTHS, 0x26ff);
	}

	/* Configure the EMAC mode register. */
	val = REG_RD(bp, BNX2_EMAC_MODE);

	val &= ~(BNX2_EMAC_MODE_PORT | BNX2_EMAC_MODE_HALF_DUPLEX |
		BNX2_EMAC_MODE_MAC_LOOP | BNX2_EMAC_MODE_FORCE_LINK |
		BNX2_EMAC_MODE_25G_MODE);

	if (bp->link_up) {
		switch (bp->line_speed) {
			case SPEED_10:
				if (CHIP_NUM(bp) != CHIP_NUM_5706) {
					val |= BNX2_EMAC_MODE_PORT_MII_10M;
					break;
				}
				/* fall through */
			case SPEED_100:
				val |= BNX2_EMAC_MODE_PORT_MII;
				break;
			case SPEED_2500:
				val |= BNX2_EMAC_MODE_25G_MODE;
				/* fall through */
			case SPEED_1000:
				val |= BNX2_EMAC_MODE_PORT_GMII;
				break;
		}
	}
	else {
		val |= BNX2_EMAC_MODE_PORT_GMII;
	}

	/* Set the MAC to operate in the appropriate duplex mode. */
	if (bp->duplex == DUPLEX_HALF)
		val |= BNX2_EMAC_MODE_HALF_DUPLEX;
	REG_WR(bp, BNX2_EMAC_MODE, val);

	/* Enable/disable rx PAUSE. */
	bp->rx_mode &= ~BNX2_EMAC_RX_MODE_FLOW_EN;

	if (bp->flow_ctrl & FLOW_CTRL_RX)
		bp->rx_mode |= BNX2_EMAC_RX_MODE_FLOW_EN;
	REG_WR(bp, BNX2_EMAC_RX_MODE, bp->rx_mode);

	/* Enable/disable tx PAUSE. */
	val = REG_RD(bp, BNX2_EMAC_TX_MODE);
	val &= ~BNX2_EMAC_TX_MODE_FLOW_EN;

	if (bp->flow_ctrl & FLOW_CTRL_TX)
		val |= BNX2_EMAC_TX_MODE_FLOW_EN;
	REG_WR(bp, BNX2_EMAC_TX_MODE, val);

	/* Acknowledge the interrupt. */
	REG_WR(bp, BNX2_EMAC_STATUS, BNX2_EMAC_STATUS_LINK_CHANGE);

	bnx2_init_all_rx_contexts(bp);
}

static void
bnx2_enable_bmsr1(struct bnx2 *bp)
{
	if ((bp->phy_flags & BNX2_PHY_FLAG_SERDES) &&
	    (CHIP_NUM(bp) == CHIP_NUM_5709))
		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_GP_STATUS);
}

static void
bnx2_disable_bmsr1(struct bnx2 *bp)
{
	if ((bp->phy_flags & BNX2_PHY_FLAG_SERDES) &&
	    (CHIP_NUM(bp) == CHIP_NUM_5709))
		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_COMBO_IEEEB0);
}

static int
bnx2_test_and_enable_2g5(struct bnx2 *bp)
{
	u32 up1;
	int ret = 1;

	if (!(bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE))
		return 0;

	if (bp->autoneg & AUTONEG_SPEED)
		bp->advertising |= ADVERTISED_2500baseX_Full;

	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_OVER1G);

	bnx2_read_phy(bp, bp->mii_up1, &up1);
	if (!(up1 & BCM5708S_UP1_2G5)) {
		up1 |= BCM5708S_UP1_2G5;
		bnx2_write_phy(bp, bp->mii_up1, up1);
		ret = 0;
	}

	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_COMBO_IEEEB0);

	return ret;
}

static int
bnx2_test_and_disable_2g5(struct bnx2 *bp)
{
	u32 up1;
	int ret = 0;

	if (!(bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE))
		return 0;

	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_OVER1G);

	bnx2_read_phy(bp, bp->mii_up1, &up1);
	if (up1 & BCM5708S_UP1_2G5) {
		up1 &= ~BCM5708S_UP1_2G5;
		bnx2_write_phy(bp, bp->mii_up1, up1);
		ret = 1;
	}

	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_COMBO_IEEEB0);

	return ret;
}

static void
bnx2_enable_forced_2g5(struct bnx2 *bp)
{
	u32 uninitialized_var(bmcr);
	int err;

	if (!(bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE))
		return;

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		u32 val;

		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_SERDES_DIG);
		if (!bnx2_read_phy(bp, MII_BNX2_SERDES_DIG_MISC1, &val)) {
			val &= ~MII_BNX2_SD_MISC1_FORCE_MSK;
			val |= MII_BNX2_SD_MISC1_FORCE |
				MII_BNX2_SD_MISC1_FORCE_2_5G;
			bnx2_write_phy(bp, MII_BNX2_SERDES_DIG_MISC1, val);
		}

		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_COMBO_IEEEB0);
		err = bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);

	} else if (CHIP_NUM(bp) == CHIP_NUM_5708) {
		err = bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
		if (!err)
			bmcr |= BCM5708S_BMCR_FORCE_2500;
	} else {
		return;
	}

	if (err)
		return;

	if (bp->autoneg & AUTONEG_SPEED) {
		bmcr &= ~BMCR_ANENABLE;
		if (bp->req_duplex == DUPLEX_FULL)
			bmcr |= BMCR_FULLDPLX;
	}
	bnx2_write_phy(bp, bp->mii_bmcr, bmcr);
}

static void
bnx2_disable_forced_2g5(struct bnx2 *bp)
{
	u32 uninitialized_var(bmcr);
	int err;

	if (!(bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE))
		return;

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		u32 val;

		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_SERDES_DIG);
		if (!bnx2_read_phy(bp, MII_BNX2_SERDES_DIG_MISC1, &val)) {
			val &= ~MII_BNX2_SD_MISC1_FORCE;
			bnx2_write_phy(bp, MII_BNX2_SERDES_DIG_MISC1, val);
		}

		bnx2_write_phy(bp, MII_BNX2_BLK_ADDR,
			       MII_BNX2_BLK_ADDR_COMBO_IEEEB0);
		err = bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);

	} else if (CHIP_NUM(bp) == CHIP_NUM_5708) {
		err = bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
		if (!err)
			bmcr &= ~BCM5708S_BMCR_FORCE_2500;
	} else {
		return;
	}

	if (err)
		return;

	if (bp->autoneg & AUTONEG_SPEED)
		bmcr |= BMCR_SPEED1000 | BMCR_ANENABLE | BMCR_ANRESTART;
	bnx2_write_phy(bp, bp->mii_bmcr, bmcr);
}

static void
bnx2_5706s_force_link_dn(struct bnx2 *bp, int start)
{
	u32 val;

	bnx2_write_phy(bp, MII_BNX2_DSP_ADDRESS, MII_EXPAND_SERDES_CTL);
	bnx2_read_phy(bp, MII_BNX2_DSP_RW_PORT, &val);
	if (start)
		bnx2_write_phy(bp, MII_BNX2_DSP_RW_PORT, val & 0xff0f);
	else
		bnx2_write_phy(bp, MII_BNX2_DSP_RW_PORT, val | 0xc0);
}

static int
bnx2_set_link(struct bnx2 *bp)
{
	u32 bmsr;
	u8 link_up;

	if (bp->loopback == MAC_LOOPBACK || bp->loopback == PHY_LOOPBACK) {
		bp->link_up = 1;
		return 0;
	}

	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
		return 0;

	link_up = bp->link_up;

	bnx2_enable_bmsr1(bp);
	bnx2_read_phy(bp, bp->mii_bmsr1, &bmsr);
	bnx2_read_phy(bp, bp->mii_bmsr1, &bmsr);
	bnx2_disable_bmsr1(bp);

	if ((bp->phy_flags & BNX2_PHY_FLAG_SERDES) &&
	    (CHIP_NUM(bp) == CHIP_NUM_5706)) {
		u32 val, an_dbg;

		if (bp->phy_flags & BNX2_PHY_FLAG_FORCED_DOWN) {
			bnx2_5706s_force_link_dn(bp, 0);
			bp->phy_flags &= ~BNX2_PHY_FLAG_FORCED_DOWN;
		}
		val = REG_RD(bp, BNX2_EMAC_STATUS);

		bnx2_write_phy(bp, MII_BNX2_MISC_SHADOW, MISC_SHDW_AN_DBG);
		bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &an_dbg);
		bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &an_dbg);

		if ((val & BNX2_EMAC_STATUS_LINK) &&
		    !(an_dbg & MISC_SHDW_AN_DBG_NOSYNC))
			bmsr |= BMSR_LSTATUS;
		else
			bmsr &= ~BMSR_LSTATUS;
	}

	if (bmsr & BMSR_LSTATUS) {
		bp->link_up = 1;

		if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
			if (CHIP_NUM(bp) == CHIP_NUM_5706)
				bnx2_5706s_linkup(bp);
			else if (CHIP_NUM(bp) == CHIP_NUM_5708)
				bnx2_5708s_linkup(bp);
			else if (CHIP_NUM(bp) == CHIP_NUM_5709)
				bnx2_5709s_linkup(bp);
		}
		else {
			bnx2_copper_linkup(bp);
		}
		bnx2_resolve_flow_ctrl(bp);
	}
	else {
		if ((bp->phy_flags & BNX2_PHY_FLAG_SERDES) &&
		    (bp->autoneg & AUTONEG_SPEED))
			bnx2_disable_forced_2g5(bp);

		if (bp->phy_flags & BNX2_PHY_FLAG_PARALLEL_DETECT) {
			u32 bmcr;

			bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
			bmcr |= BMCR_ANENABLE;
			bnx2_write_phy(bp, bp->mii_bmcr, bmcr);

			bp->phy_flags &= ~BNX2_PHY_FLAG_PARALLEL_DETECT;
		}
		bp->link_up = 0;
	}

	if (bp->link_up != link_up) {
		bnx2_report_link(bp);
	}

	bnx2_set_mac_link(bp);

	return 0;
}

static int
bnx2_reset_phy(struct bnx2 *bp)
{
	int i;
	u32 reg;

        bnx2_write_phy(bp, bp->mii_bmcr, BMCR_RESET);

#define PHY_RESET_MAX_WAIT 100
	for (i = 0; i < PHY_RESET_MAX_WAIT; i++) {
		udelay(10);

		bnx2_read_phy(bp, bp->mii_bmcr, &reg);
		if (!(reg & BMCR_RESET)) {
			udelay(20);
			break;
		}
	}
	if (i == PHY_RESET_MAX_WAIT) {
		return -EBUSY;
	}
	return 0;
}

static u32
bnx2_phy_get_pause_adv(struct bnx2 *bp)
{
	u32 adv = 0;

	if ((bp->req_flow_ctrl & (FLOW_CTRL_RX | FLOW_CTRL_TX)) ==
		(FLOW_CTRL_RX | FLOW_CTRL_TX)) {

		if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
			adv = ADVERTISE_1000XPAUSE;
		}
		else {
			adv = ADVERTISE_PAUSE_CAP;
		}
	}
	else if (bp->req_flow_ctrl & FLOW_CTRL_TX) {
		if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
			adv = ADVERTISE_1000XPSE_ASYM;
		}
		else {
			adv = ADVERTISE_PAUSE_ASYM;
		}
	}
	else if (bp->req_flow_ctrl & FLOW_CTRL_RX) {
		if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
			adv = ADVERTISE_1000XPAUSE | ADVERTISE_1000XPSE_ASYM;
		}
		else {
			adv = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
		}
	}
	return adv;
}

static int bnx2_fw_sync(struct bnx2 *, u32, int, int);

static int
bnx2_setup_remote_phy(struct bnx2 *bp, u8 port)
__releases(&bp->phy_lock)
__acquires(&bp->phy_lock)
{
	u32 speed_arg = 0, pause_adv;

	pause_adv = bnx2_phy_get_pause_adv(bp);

	if (bp->autoneg & AUTONEG_SPEED) {
		speed_arg |= BNX2_NETLINK_SET_LINK_ENABLE_AUTONEG;
		if (bp->advertising & ADVERTISED_10baseT_Half)
			speed_arg |= BNX2_NETLINK_SET_LINK_SPEED_10HALF;
		if (bp->advertising & ADVERTISED_10baseT_Full)
			speed_arg |= BNX2_NETLINK_SET_LINK_SPEED_10FULL;
		if (bp->advertising & ADVERTISED_100baseT_Half)
			speed_arg |= BNX2_NETLINK_SET_LINK_SPEED_100HALF;
		if (bp->advertising & ADVERTISED_100baseT_Full)
			speed_arg |= BNX2_NETLINK_SET_LINK_SPEED_100FULL;
		if (bp->advertising & ADVERTISED_1000baseT_Full)
			speed_arg |= BNX2_NETLINK_SET_LINK_SPEED_1GFULL;
		if (bp->advertising & ADVERTISED_2500baseX_Full)
			speed_arg |= BNX2_NETLINK_SET_LINK_SPEED_2G5FULL;
	} else {
		if (bp->req_line_speed == SPEED_2500)
			speed_arg = BNX2_NETLINK_SET_LINK_SPEED_2G5FULL;
		else if (bp->req_line_speed == SPEED_1000)
			speed_arg = BNX2_NETLINK_SET_LINK_SPEED_1GFULL;
		else if (bp->req_line_speed == SPEED_100) {
			if (bp->req_duplex == DUPLEX_FULL)
				speed_arg = BNX2_NETLINK_SET_LINK_SPEED_100FULL;
			else
				speed_arg = BNX2_NETLINK_SET_LINK_SPEED_100HALF;
		} else if (bp->req_line_speed == SPEED_10) {
			if (bp->req_duplex == DUPLEX_FULL)
				speed_arg = BNX2_NETLINK_SET_LINK_SPEED_10FULL;
			else
				speed_arg = BNX2_NETLINK_SET_LINK_SPEED_10HALF;
		}
	}

	if (pause_adv & (ADVERTISE_1000XPAUSE | ADVERTISE_PAUSE_CAP))
		speed_arg |= BNX2_NETLINK_SET_LINK_FC_SYM_PAUSE;
	if (pause_adv & (ADVERTISE_1000XPSE_ASYM | ADVERTISE_PAUSE_ASYM))
		speed_arg |= BNX2_NETLINK_SET_LINK_FC_ASYM_PAUSE;

	if (port == PORT_TP)
		speed_arg |= BNX2_NETLINK_SET_LINK_PHY_APP_REMOTE |
			     BNX2_NETLINK_SET_LINK_ETH_AT_WIRESPEED;

	bnx2_shmem_wr(bp, BNX2_DRV_MB_ARG0, speed_arg);

	spin_unlock_bh(&bp->phy_lock);
	bnx2_fw_sync(bp, BNX2_DRV_MSG_CODE_CMD_SET_LINK, 1, 0);
	spin_lock_bh(&bp->phy_lock);

	return 0;
}

static int
bnx2_setup_serdes_phy(struct bnx2 *bp, u8 port)
__releases(&bp->phy_lock)
__acquires(&bp->phy_lock)
{
	u32 adv, bmcr;
	u32 new_adv = 0;

	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
		return bnx2_setup_remote_phy(bp, port);

	if (!(bp->autoneg & AUTONEG_SPEED)) {
		u32 new_bmcr;
		int force_link_down = 0;

		if (bp->req_line_speed == SPEED_2500) {
			if (!bnx2_test_and_enable_2g5(bp))
				force_link_down = 1;
		} else if (bp->req_line_speed == SPEED_1000) {
			if (bnx2_test_and_disable_2g5(bp))
				force_link_down = 1;
		}
		bnx2_read_phy(bp, bp->mii_adv, &adv);
		adv &= ~(ADVERTISE_1000XFULL | ADVERTISE_1000XHALF);

		bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
		new_bmcr = bmcr & ~BMCR_ANENABLE;
		new_bmcr |= BMCR_SPEED1000;

		if (CHIP_NUM(bp) == CHIP_NUM_5709) {
			if (bp->req_line_speed == SPEED_2500)
				bnx2_enable_forced_2g5(bp);
			else if (bp->req_line_speed == SPEED_1000) {
				bnx2_disable_forced_2g5(bp);
				new_bmcr &= ~0x2000;
			}

		} else if (CHIP_NUM(bp) == CHIP_NUM_5708) {
			if (bp->req_line_speed == SPEED_2500)
				new_bmcr |= BCM5708S_BMCR_FORCE_2500;
			else
				new_bmcr = bmcr & ~BCM5708S_BMCR_FORCE_2500;
		}

		if (bp->req_duplex == DUPLEX_FULL) {
			adv |= ADVERTISE_1000XFULL;
			new_bmcr |= BMCR_FULLDPLX;
		}
		else {
			adv |= ADVERTISE_1000XHALF;
			new_bmcr &= ~BMCR_FULLDPLX;
		}
		if ((new_bmcr != bmcr) || (force_link_down)) {
			/* Force a link down visible on the other side */
			if (bp->link_up) {
				bnx2_write_phy(bp, bp->mii_adv, adv &
					       ~(ADVERTISE_1000XFULL |
						 ADVERTISE_1000XHALF));
				bnx2_write_phy(bp, bp->mii_bmcr, bmcr |
					BMCR_ANRESTART | BMCR_ANENABLE);

				bp->link_up = 0;
				netif_carrier_off(bp->dev);
				bnx2_write_phy(bp, bp->mii_bmcr, new_bmcr);
				bnx2_report_link(bp);
			}
			bnx2_write_phy(bp, bp->mii_adv, adv);
			bnx2_write_phy(bp, bp->mii_bmcr, new_bmcr);
		} else {
			bnx2_resolve_flow_ctrl(bp);
			bnx2_set_mac_link(bp);
		}
		return 0;
	}

	bnx2_test_and_enable_2g5(bp);

	if (bp->advertising & ADVERTISED_1000baseT_Full)
		new_adv |= ADVERTISE_1000XFULL;

	new_adv |= bnx2_phy_get_pause_adv(bp);

	bnx2_read_phy(bp, bp->mii_adv, &adv);
	bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);

	bp->serdes_an_pending = 0;
	if ((adv != new_adv) || ((bmcr & BMCR_ANENABLE) == 0)) {
		/* Force a link down visible on the other side */
		if (bp->link_up) {
			bnx2_write_phy(bp, bp->mii_bmcr, BMCR_LOOPBACK);
			spin_unlock_bh(&bp->phy_lock);
			bnx2_msleep(20);
			spin_lock_bh(&bp->phy_lock);
		}

		bnx2_write_phy(bp, bp->mii_adv, new_adv);
		bnx2_write_phy(bp, bp->mii_bmcr, bmcr | BMCR_ANRESTART |
			BMCR_ANENABLE);
		/* Speed up link-up time when the link partner
		 * does not autonegotiate which is very common
		 * in blade servers. Some blade servers use
		 * IPMI for kerboard input and it's important
		 * to minimize link disruptions. Autoneg. involves
		 * exchanging base pages plus 3 next pages and
		 * normally completes in about 120 msec.
		 */
		bp->current_interval = BNX2_SERDES_AN_TIMEOUT;
		bp->serdes_an_pending = 1;
		mod_timer(&bp->timer, jiffies + bp->current_interval);
	} else {
		bnx2_resolve_flow_ctrl(bp);
		bnx2_set_mac_link(bp);
	}

	return 0;
}

#define ETHTOOL_ALL_FIBRE_SPEED						\
	(bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE) ?			\
		(ADVERTISED_2500baseX_Full | ADVERTISED_1000baseT_Full) :\
		(ADVERTISED_1000baseT_Full)

#define ETHTOOL_ALL_COPPER_SPEED					\
	(ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |		\
	ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |		\
	ADVERTISED_1000baseT_Full)

#define PHY_ALL_10_100_SPEED (ADVERTISE_10HALF | ADVERTISE_10FULL | \
	ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_CSMA)

#define PHY_ALL_1000_SPEED (ADVERTISE_1000HALF | ADVERTISE_1000FULL)

static void
bnx2_set_default_remote_link(struct bnx2 *bp)
{
	u32 link;

	if (bp->phy_port == PORT_TP)
		link = bnx2_shmem_rd(bp, BNX2_RPHY_COPPER_LINK);
	else
		link = bnx2_shmem_rd(bp, BNX2_RPHY_SERDES_LINK);

	if (link & BNX2_NETLINK_SET_LINK_ENABLE_AUTONEG) {
		bp->req_line_speed = 0;
		bp->autoneg |= AUTONEG_SPEED;
		bp->advertising = ADVERTISED_Autoneg;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_10HALF)
			bp->advertising |= ADVERTISED_10baseT_Half;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_10FULL)
			bp->advertising |= ADVERTISED_10baseT_Full;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_100HALF)
			bp->advertising |= ADVERTISED_100baseT_Half;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_100FULL)
			bp->advertising |= ADVERTISED_100baseT_Full;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_1GFULL)
			bp->advertising |= ADVERTISED_1000baseT_Full;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_2G5FULL)
			bp->advertising |= ADVERTISED_2500baseX_Full;
	} else {
		bp->autoneg = 0;
		bp->advertising = 0;
		bp->req_duplex = DUPLEX_FULL;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_10) {
			bp->req_line_speed = SPEED_10;
			if (link & BNX2_NETLINK_SET_LINK_SPEED_10HALF)
				bp->req_duplex = DUPLEX_HALF;
		}
		if (link & BNX2_NETLINK_SET_LINK_SPEED_100) {
			bp->req_line_speed = SPEED_100;
			if (link & BNX2_NETLINK_SET_LINK_SPEED_100HALF)
				bp->req_duplex = DUPLEX_HALF;
		}
		if (link & BNX2_NETLINK_SET_LINK_SPEED_1GFULL)
			bp->req_line_speed = SPEED_1000;
		if (link & BNX2_NETLINK_SET_LINK_SPEED_2G5FULL)
			bp->req_line_speed = SPEED_2500;
	}
}

static void
bnx2_set_default_link(struct bnx2 *bp)
{
	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP) {
		bnx2_set_default_remote_link(bp);
		return;
	}

	bp->autoneg = AUTONEG_SPEED | AUTONEG_FLOW_CTRL;
	bp->req_line_speed = 0;
	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		u32 reg;

		bp->advertising = ETHTOOL_ALL_FIBRE_SPEED | ADVERTISED_Autoneg;

		reg = bnx2_shmem_rd(bp, BNX2_PORT_HW_CFG_CONFIG);
		reg &= BNX2_PORT_HW_CFG_CFG_DFLT_LINK_MASK;
		if (reg == BNX2_PORT_HW_CFG_CFG_DFLT_LINK_1G) {
			bp->autoneg = 0;
			bp->req_line_speed = bp->line_speed = SPEED_1000;
			bp->req_duplex = DUPLEX_FULL;
		}
	} else
		bp->advertising = ETHTOOL_ALL_COPPER_SPEED | ADVERTISED_Autoneg;
}

static void
bnx2_send_heart_beat(struct bnx2 *bp)
{
	u32 msg;
	u32 addr;

	spin_lock(&bp->indirect_lock);
	msg = (u32) (++bp->fw_drv_pulse_wr_seq & BNX2_DRV_PULSE_SEQ_MASK);
	addr = bp->shmem_base + BNX2_DRV_PULSE_MB;
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW_ADDRESS, addr);
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW, msg);
	spin_unlock(&bp->indirect_lock);
}

static void
bnx2_remote_phy_event(struct bnx2 *bp)
{
	u32 msg;
	u8 link_up = bp->link_up;
	u8 old_port;

	msg = bnx2_shmem_rd(bp, BNX2_LINK_STATUS);

	if (msg & BNX2_LINK_STATUS_HEART_BEAT_EXPIRED)
		bnx2_send_heart_beat(bp);

	msg &= ~BNX2_LINK_STATUS_HEART_BEAT_EXPIRED;

	if ((msg & BNX2_LINK_STATUS_LINK_UP) == BNX2_LINK_STATUS_LINK_DOWN)
		bp->link_up = 0;
	else {
		u32 speed;

		bp->link_up = 1;
		speed = msg & BNX2_LINK_STATUS_SPEED_MASK;
		bp->duplex = DUPLEX_FULL;
		switch (speed) {
			case BNX2_LINK_STATUS_10HALF:
				bp->duplex = DUPLEX_HALF;
				/* fall through */
			case BNX2_LINK_STATUS_10FULL:
				bp->line_speed = SPEED_10;
				break;
			case BNX2_LINK_STATUS_100HALF:
				bp->duplex = DUPLEX_HALF;
				/* fall through */
			case BNX2_LINK_STATUS_100BASE_T4:
				/* fall through */
			case BNX2_LINK_STATUS_100FULL:
				bp->line_speed = SPEED_100;
				break;
			case BNX2_LINK_STATUS_1000HALF:
				bp->duplex = DUPLEX_HALF;
				/* fall through */
			case BNX2_LINK_STATUS_1000FULL:
				bp->line_speed = SPEED_1000;
				break;
			case BNX2_LINK_STATUS_2500HALF:
				bp->duplex = DUPLEX_HALF;
				/* fall through */
			case BNX2_LINK_STATUS_2500FULL:
				bp->line_speed = SPEED_2500;
				break;
			default:
				bp->line_speed = 0;
				break;
		}

		bp->flow_ctrl = 0;
		if ((bp->autoneg & (AUTONEG_SPEED | AUTONEG_FLOW_CTRL)) !=
		    (AUTONEG_SPEED | AUTONEG_FLOW_CTRL)) {
			if (bp->duplex == DUPLEX_FULL)
				bp->flow_ctrl = bp->req_flow_ctrl;
		} else {
			if (msg & BNX2_LINK_STATUS_TX_FC_ENABLED)
				bp->flow_ctrl |= FLOW_CTRL_TX;
			if (msg & BNX2_LINK_STATUS_RX_FC_ENABLED)
				bp->flow_ctrl |= FLOW_CTRL_RX;
		}

		old_port = bp->phy_port;
		if (msg & BNX2_LINK_STATUS_SERDES_LINK)
			bp->phy_port = PORT_FIBRE;
		else
			bp->phy_port = PORT_TP;

		if (old_port != bp->phy_port)
			bnx2_set_default_link(bp);

	}
	if (bp->link_up != link_up)
		bnx2_report_link(bp);

	bnx2_set_mac_link(bp);
}

static int
bnx2_set_remote_link(struct bnx2 *bp)
{
	u32 evt_code;

	spin_lock(&bp->indirect_lock);
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW_ADDRESS,
	       bp->shmem_base + BNX2_FW_EVT_CODE_MB);
	evt_code = REG_RD(bp, BNX2_PCICFG_REG_WINDOW);
	spin_unlock(&bp->indirect_lock);
	switch (evt_code) {
		case BNX2_FW_EVT_CODE_LINK_EVENT:
			bnx2_remote_phy_event(bp);
			break;
		case BNX2_FW_EVT_CODE_SW_TIMER_EXPIRATION_EVENT:
		default:
			bnx2_send_heart_beat(bp);
			break;
	}
	return 0;
}

static int
bnx2_setup_copper_phy(struct bnx2 *bp)
__releases(&bp->phy_lock)
__acquires(&bp->phy_lock)
{
	u32 bmcr;
	u32 new_bmcr;

	bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);

	if (bp->autoneg & AUTONEG_SPEED) {
		u32 adv_reg, adv1000_reg;
		u32 new_adv = 0;
		u32 new_adv1000 = 0;

		bnx2_read_phy(bp, bp->mii_adv, &adv_reg);
		adv_reg &= (PHY_ALL_10_100_SPEED | ADVERTISE_PAUSE_CAP |
			ADVERTISE_PAUSE_ASYM);

		bnx2_read_phy(bp, MII_CTRL1000, &adv1000_reg);
		adv1000_reg &= PHY_ALL_1000_SPEED;

		new_adv = ethtool_adv_to_mii_adv_t(bp->advertising);
		new_adv |= ADVERTISE_CSMA;
		new_adv |= bnx2_phy_get_pause_adv(bp);

		new_adv1000 |= ethtool_adv_to_mii_ctrl1000_t(bp->advertising);
		if ((adv1000_reg != new_adv1000) ||
			(adv_reg != new_adv) ||
			((bmcr & BMCR_ANENABLE) == 0)) {

			bnx2_write_phy(bp, bp->mii_adv, new_adv);
			bnx2_write_phy(bp, MII_CTRL1000, new_adv1000);
			bnx2_write_phy(bp, bp->mii_bmcr, BMCR_ANRESTART |
				BMCR_ANENABLE);
		}
		else if (bp->link_up) {
			/* Flow ctrl may have changed from auto to forced */
			/* or vice-versa. */

			bnx2_resolve_flow_ctrl(bp);
			bnx2_set_mac_link(bp);
		}
		return 0;
	}

	new_bmcr = 0;
	if (bp->req_line_speed == SPEED_100) {
		new_bmcr |= BMCR_SPEED100;
	}
	if (bp->req_duplex == DUPLEX_FULL) {
		new_bmcr |= BMCR_FULLDPLX;
	}
	if (new_bmcr != bmcr) {
		u32 bmsr;

		bnx2_read_phy(bp, bp->mii_bmsr, &bmsr);
		bnx2_read_phy(bp, bp->mii_bmsr, &bmsr);

		if (bmsr & BMSR_LSTATUS) {
			/* Force link down */
			bnx2_write_phy(bp, bp->mii_bmcr, BMCR_LOOPBACK);
			spin_unlock_bh(&bp->phy_lock);
			bnx2_msleep(50);
			spin_lock_bh(&bp->phy_lock);

			bnx2_read_phy(bp, bp->mii_bmsr, &bmsr);
			bnx2_read_phy(bp, bp->mii_bmsr, &bmsr);
		}

		bnx2_write_phy(bp, bp->mii_bmcr, new_bmcr);

		/* Normally, the new speed is setup after the link has
		 * gone down and up again. In some cases, link will not go
		 * down so we need to set up the new speed here.
		 */
		if (bmsr & BMSR_LSTATUS) {
			bp->line_speed = bp->req_line_speed;
			bp->duplex = bp->req_duplex;
			bnx2_resolve_flow_ctrl(bp);
			bnx2_set_mac_link(bp);
		}
	} else {
		bnx2_resolve_flow_ctrl(bp);
		bnx2_set_mac_link(bp);
	}
	return 0;
}

static int
bnx2_setup_phy(struct bnx2 *bp, u8 port)
__releases(&bp->phy_lock)
__acquires(&bp->phy_lock)
{
	if (bp->loopback == MAC_LOOPBACK)
		return 0;

	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		return bnx2_setup_serdes_phy(bp, port);
	}
	else {
		return bnx2_setup_copper_phy(bp);
	}
}

static int
bnx2_init_5709s_phy(struct bnx2 *bp, int reset_phy)
{
	u32 val;

	bp->mii_bmcr = MII_BMCR + 0x10;
	bp->mii_bmsr = MII_BMSR + 0x10;
	bp->mii_bmsr1 = MII_BNX2_GP_TOP_AN_STATUS1;
	bp->mii_adv = MII_ADVERTISE + 0x10;
	bp->mii_lpa = MII_LPA + 0x10;
	bp->mii_up1 = MII_BNX2_OVER1G_UP1;

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_AER);
	bnx2_write_phy(bp, MII_BNX2_AER_AER, MII_BNX2_AER_AER_AN_MMD);

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_COMBO_IEEEB0);
	if (reset_phy)
		bnx2_reset_phy(bp);

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_SERDES_DIG);

	bnx2_read_phy(bp, MII_BNX2_SERDES_DIG_1000XCTL1, &val);
	val &= ~MII_BNX2_SD_1000XCTL1_AUTODET;
	val |= MII_BNX2_SD_1000XCTL1_FIBER;
	/* NEMO temp. FIX */
	if (bnx2_shmem_rd(bp, BNX2_SHARED_HW_CFG_CONFIG) & 0x80000000)
		val |= (1 << 3);
	bnx2_write_phy(bp, MII_BNX2_SERDES_DIG_1000XCTL1, val);

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_OVER1G);
	bnx2_read_phy(bp, MII_BNX2_OVER1G_UP1, &val);
	if (bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE)
		val |= BCM5708S_UP1_2G5;
	else
		val &= ~BCM5708S_UP1_2G5;
	bnx2_write_phy(bp, MII_BNX2_OVER1G_UP1, val);

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_BAM_NXTPG);
	bnx2_read_phy(bp, MII_BNX2_BAM_NXTPG_CTL, &val);
	val |= MII_BNX2_NXTPG_CTL_T2 | MII_BNX2_NXTPG_CTL_BAM;
	bnx2_write_phy(bp, MII_BNX2_BAM_NXTPG_CTL, val);

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_CL73_USERB0);

	val = MII_BNX2_CL73_BAM_EN | MII_BNX2_CL73_BAM_STA_MGR_EN |
	      MII_BNX2_CL73_BAM_NP_AFT_BP_EN;
	bnx2_write_phy(bp, MII_BNX2_CL73_BAM_CTL1, val);

	bnx2_write_phy(bp, MII_BNX2_BLK_ADDR, MII_BNX2_BLK_ADDR_COMBO_IEEEB0);

	return 0;
}

static int
bnx2_init_5708s_phy(struct bnx2 *bp, int reset_phy)
{
	u32 val;

	if (reset_phy)
		bnx2_reset_phy(bp);

	bp->mii_up1 = BCM5708S_UP1;

	bnx2_write_phy(bp, BCM5708S_BLK_ADDR, BCM5708S_BLK_ADDR_DIG3);
	bnx2_write_phy(bp, BCM5708S_DIG_3_0, BCM5708S_DIG_3_0_USE_IEEE);
	bnx2_write_phy(bp, BCM5708S_BLK_ADDR, BCM5708S_BLK_ADDR_DIG);

	bnx2_read_phy(bp, BCM5708S_1000X_CTL1, &val);
	val |= BCM5708S_1000X_CTL1_FIBER_MODE | BCM5708S_1000X_CTL1_AUTODET_EN;
	bnx2_write_phy(bp, BCM5708S_1000X_CTL1, val);

	bnx2_read_phy(bp, BCM5708S_1000X_CTL2, &val);
	val |= BCM5708S_1000X_CTL2_PLLEL_DET_EN;
	bnx2_write_phy(bp, BCM5708S_1000X_CTL2, val);

	if (bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE) {
		bnx2_read_phy(bp, BCM5708S_UP1, &val);
		val |= BCM5708S_UP1_2G5;
		bnx2_write_phy(bp, BCM5708S_UP1, val);
	}

	if ((CHIP_ID(bp) == CHIP_ID_5708_A0) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_B0) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_B1)) {
		/* increase tx signal amplitude */
		bnx2_write_phy(bp, BCM5708S_BLK_ADDR,
			       BCM5708S_BLK_ADDR_TX_MISC);
		bnx2_read_phy(bp, BCM5708S_TX_ACTL1, &val);
		val &= ~BCM5708S_TX_ACTL1_DRIVER_VCM;
		bnx2_write_phy(bp, BCM5708S_TX_ACTL1, val);
		bnx2_write_phy(bp, BCM5708S_BLK_ADDR, BCM5708S_BLK_ADDR_DIG);
	}

	val = bnx2_shmem_rd(bp, BNX2_PORT_HW_CFG_CONFIG) &
	      BNX2_PORT_HW_CFG_CFG_TXCTL3_MASK;

	if (val) {
		u32 is_backplane;

		is_backplane = bnx2_shmem_rd(bp, BNX2_SHARED_HW_CFG_CONFIG);
		if (is_backplane & BNX2_SHARED_HW_CFG_PHY_BACKPLANE) {
			bnx2_write_phy(bp, BCM5708S_BLK_ADDR,
				       BCM5708S_BLK_ADDR_TX_MISC);
			bnx2_write_phy(bp, BCM5708S_TX_ACTL3, val);
			bnx2_write_phy(bp, BCM5708S_BLK_ADDR,
				       BCM5708S_BLK_ADDR_DIG);
		}
	}
	return 0;
}

static int
bnx2_init_5706s_phy(struct bnx2 *bp, int reset_phy)
{
	if (reset_phy)
		bnx2_reset_phy(bp);

	bp->phy_flags &= ~BNX2_PHY_FLAG_PARALLEL_DETECT;

	if (CHIP_NUM(bp) == CHIP_NUM_5706)
        	REG_WR(bp, BNX2_MISC_GP_HW_CTL0, 0x300);

	if (bp->dev->mtu > 1500) {
		u32 val;

		/* Set extended packet length bit */
		bnx2_write_phy(bp, 0x18, 0x7);
		bnx2_read_phy(bp, 0x18, &val);
		bnx2_write_phy(bp, 0x18, (val & 0xfff8) | 0x4000);

		bnx2_write_phy(bp, 0x1c, 0x6c00);
		bnx2_read_phy(bp, 0x1c, &val);
		bnx2_write_phy(bp, 0x1c, (val & 0x3ff) | 0xec02);
	}
	else {
		u32 val;

		bnx2_write_phy(bp, 0x18, 0x7);
		bnx2_read_phy(bp, 0x18, &val);
		bnx2_write_phy(bp, 0x18, val & ~0x4007);

		bnx2_write_phy(bp, 0x1c, 0x6c00);
		bnx2_read_phy(bp, 0x1c, &val);
		bnx2_write_phy(bp, 0x1c, (val & 0x3fd) | 0xec00);
	}

	return 0;
}

static int
bnx2_init_copper_phy(struct bnx2 *bp, int reset_phy)
{
	u32 val;

	if (reset_phy)
		bnx2_reset_phy(bp);

	if (bp->phy_flags & BNX2_PHY_FLAG_CRC_FIX) {
		bnx2_write_phy(bp, 0x18, 0x0c00);
		bnx2_write_phy(bp, 0x17, 0x000a);
		bnx2_write_phy(bp, 0x15, 0x310b);
		bnx2_write_phy(bp, 0x17, 0x201f);
		bnx2_write_phy(bp, 0x15, 0x9506);
		bnx2_write_phy(bp, 0x17, 0x401f);
		bnx2_write_phy(bp, 0x15, 0x14e2);
		bnx2_write_phy(bp, 0x18, 0x0400);
	}

	if (bp->phy_flags & BNX2_PHY_FLAG_DIS_EARLY_DAC) {
		bnx2_write_phy(bp, MII_BNX2_DSP_ADDRESS,
			       MII_BNX2_DSP_EXPAND_REG | 0x8);
		bnx2_read_phy(bp, MII_BNX2_DSP_RW_PORT, &val);
		val &= ~(1 << 8);
		bnx2_write_phy(bp, MII_BNX2_DSP_RW_PORT, val);
	}

	if (bp->dev->mtu > 1500) {
		/* Set extended packet length bit */
		bnx2_write_phy(bp, 0x18, 0x7);
		bnx2_read_phy(bp, 0x18, &val);
		bnx2_write_phy(bp, 0x18, val | 0x4000);

		bnx2_read_phy(bp, 0x10, &val);
		bnx2_write_phy(bp, 0x10, val | 0x1);
	}
	else {
		bnx2_write_phy(bp, 0x18, 0x7);
		bnx2_read_phy(bp, 0x18, &val);
		bnx2_write_phy(bp, 0x18, val & ~0x4007);

		bnx2_read_phy(bp, 0x10, &val);
		bnx2_write_phy(bp, 0x10, val & ~0x1);
	}

	/* ethernet@wirespeed */
	bnx2_write_phy(bp, 0x18, 0x7007);
	bnx2_read_phy(bp, 0x18, &val);
	bnx2_write_phy(bp, 0x18, val | (1 << 15) | (1 << 4));
	return 0;
}


static int
bnx2_init_phy(struct bnx2 *bp, int reset_phy)
__releases(&bp->phy_lock)
__acquires(&bp->phy_lock)
{
	u32 val;
	int rc = 0;

	bp->phy_flags &= ~BNX2_PHY_FLAG_INT_MODE_MASK;
	bp->phy_flags |= BNX2_PHY_FLAG_INT_MODE_LINK_READY;

	bp->mii_bmcr = MII_BMCR;
	bp->mii_bmsr = MII_BMSR;
	bp->mii_bmsr1 = MII_BMSR;
	bp->mii_adv = MII_ADVERTISE;
	bp->mii_lpa = MII_LPA;

        REG_WR(bp, BNX2_EMAC_ATTENTION_ENA, BNX2_EMAC_ATTENTION_ENA_LINK);

	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
		goto setup_phy;

	bnx2_read_phy(bp, MII_PHYSID1, &val);
	bp->phy_id = val << 16;
	bnx2_read_phy(bp, MII_PHYSID2, &val);
	bp->phy_id |= val & 0xffff;

	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		if (CHIP_NUM(bp) == CHIP_NUM_5706)
			rc = bnx2_init_5706s_phy(bp, reset_phy);
		else if (CHIP_NUM(bp) == CHIP_NUM_5708)
			rc = bnx2_init_5708s_phy(bp, reset_phy);
		else if (CHIP_NUM(bp) == CHIP_NUM_5709)
			rc = bnx2_init_5709s_phy(bp, reset_phy);
	}
	else {
		rc = bnx2_init_copper_phy(bp, reset_phy);
	}

setup_phy:
	if (!rc)
		rc = bnx2_setup_phy(bp, bp->phy_port);

	return rc;
}

static int
bnx2_set_mac_loopback(struct bnx2 *bp)
{
	u32 mac_mode;

	mac_mode = REG_RD(bp, BNX2_EMAC_MODE);
	mac_mode &= ~BNX2_EMAC_MODE_PORT;
	mac_mode |= BNX2_EMAC_MODE_MAC_LOOP | BNX2_EMAC_MODE_FORCE_LINK;
	REG_WR(bp, BNX2_EMAC_MODE, mac_mode);
	bp->link_up = 1;
	return 0;
}

static int bnx2_test_link(struct bnx2 *);

static int
bnx2_set_phy_loopback(struct bnx2 *bp)
{
	u32 mac_mode;
	int rc, i;

	spin_lock_bh(&bp->phy_lock);
	rc = bnx2_write_phy(bp, bp->mii_bmcr, BMCR_LOOPBACK | BMCR_FULLDPLX |
			    BMCR_SPEED1000);
	spin_unlock_bh(&bp->phy_lock);
	if (rc)
		return rc;

	for (i = 0; i < 10; i++) {
		if (bnx2_test_link(bp) == 0)
			break;
		bnx2_msleep(100);
	}

	mac_mode = REG_RD(bp, BNX2_EMAC_MODE);
	mac_mode &= ~(BNX2_EMAC_MODE_PORT | BNX2_EMAC_MODE_HALF_DUPLEX |
		      BNX2_EMAC_MODE_MAC_LOOP | BNX2_EMAC_MODE_FORCE_LINK |
		      BNX2_EMAC_MODE_25G_MODE);

	mac_mode |= BNX2_EMAC_MODE_PORT_GMII;
	REG_WR(bp, BNX2_EMAC_MODE, mac_mode);
	bp->link_up = 1;
	return 0;
}

static void
bnx2_dump_mcp_state(struct bnx2 *bp)
{
	struct net_device *dev = bp->dev;
	u32 mcp_p0, mcp_p1;

	netdev_err(dev, "<--- start MCP states dump --->\n");
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		mcp_p0 = BNX2_MCP_STATE_P0;
		mcp_p1 = BNX2_MCP_STATE_P1;
	} else {
		mcp_p0 = BNX2_MCP_STATE_P0_5708;
		mcp_p1 = BNX2_MCP_STATE_P1_5708;
	}
	netdev_err(dev, "DEBUG: MCP_STATE_P0[%08x] MCP_STATE_P1[%08x]\n",
		   bnx2_reg_rd_ind(bp, mcp_p0), bnx2_reg_rd_ind(bp, mcp_p1));
	netdev_err(dev, "DEBUG: MCP mode[%08x] state[%08x] evt_mask[%08x]\n",
		   bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_MODE),
		   bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_STATE),
		   bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_EVENT_MASK));
	netdev_err(dev, "DEBUG: pc[%08x] pc[%08x] instr[%08x]\n",
		   bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_PROGRAM_COUNTER),
		   bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_PROGRAM_COUNTER),
		   bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_INSTRUCTION));
	netdev_err(dev, "DEBUG: shmem states:\n");
	netdev_err(dev, "DEBUG: drv_mb[%08x] fw_mb[%08x] link_status[%08x]",
		   bnx2_shmem_rd(bp, BNX2_DRV_MB),
		   bnx2_shmem_rd(bp, BNX2_FW_MB),
		   bnx2_shmem_rd(bp, BNX2_LINK_STATUS));
	pr_cont(" drv_pulse_mb[%08x]\n", bnx2_shmem_rd(bp, BNX2_DRV_PULSE_MB));
	netdev_err(dev, "DEBUG: dev_info_signature[%08x] reset_type[%08x]",
		   bnx2_shmem_rd(bp, BNX2_DEV_INFO_SIGNATURE),
		   bnx2_shmem_rd(bp, BNX2_BC_STATE_RESET_TYPE));
	pr_cont(" condition[%08x]\n",
		bnx2_shmem_rd(bp, BNX2_BC_STATE_CONDITION));
	DP_SHMEM_LINE(bp, BNX2_BC_STATE_RESET_TYPE);
	DP_SHMEM_LINE(bp, 0x3cc);
	DP_SHMEM_LINE(bp, 0x3dc);
	DP_SHMEM_LINE(bp, 0x3ec);
	netdev_err(dev, "DEBUG: 0x3fc[%08x]\n", bnx2_shmem_rd(bp, 0x3fc));
	netdev_err(dev, "<--- end MCP states dump --->\n");
}

static int
bnx2_fw_sync(struct bnx2 *bp, u32 msg_data, int ack, int silent)
{
	int i;
	u32 val;

	bp->fw_wr_seq++;
	msg_data |= bp->fw_wr_seq;

	bnx2_shmem_wr(bp, BNX2_DRV_MB, msg_data);

	if (!ack)
		return 0;

	/* wait for an acknowledgement. */
	for (i = 0; i < (BNX2_FW_ACK_TIME_OUT_MS / 10); i++) {
		bnx2_msleep(10);

		val = bnx2_shmem_rd(bp, BNX2_FW_MB);

		if ((val & BNX2_FW_MSG_ACK) == (msg_data & BNX2_DRV_MSG_SEQ))
			break;
	}
	if ((msg_data & BNX2_DRV_MSG_DATA) == BNX2_DRV_MSG_DATA_WAIT0)
		return 0;

	/* If we timed out, inform the firmware that this is the case. */
	if ((val & BNX2_FW_MSG_ACK) != (msg_data & BNX2_DRV_MSG_SEQ)) {
		msg_data &= ~BNX2_DRV_MSG_CODE;
		msg_data |= BNX2_DRV_MSG_CODE_FW_TIMEOUT;

		bnx2_shmem_wr(bp, BNX2_DRV_MB, msg_data);
		if (!silent) {
			pr_err("fw sync timeout, reset code = %x\n", msg_data);
			bnx2_dump_mcp_state(bp);
		}

		return -EBUSY;
	}

	if ((val & BNX2_FW_MSG_STATUS_MASK) != BNX2_FW_MSG_STATUS_OK)
		return -EIO;

	return 0;
}

static int
bnx2_init_5709_context(struct bnx2 *bp)
{
	int i, ret = 0;
	u32 val;

	val = BNX2_CTX_COMMAND_ENABLED | BNX2_CTX_COMMAND_MEM_INIT | (1 << 12);
	val |= (BCM_PAGE_BITS - 8) << 16;
	REG_WR(bp, BNX2_CTX_COMMAND, val);
	for (i = 0; i < 10; i++) {
		val = REG_RD(bp, BNX2_CTX_COMMAND);
		if (!(val & BNX2_CTX_COMMAND_MEM_INIT))
			break;
		udelay(2);
	}
	if (val & BNX2_CTX_COMMAND_MEM_INIT)
		return -EBUSY;

	for (i = 0; i < bp->ctx_pages; i++) {
		int j;

		if (bp->ctx_blk[i])
			memset(bp->ctx_blk[i], 0, BCM_PAGE_SIZE);
		else
			return -ENOMEM;

		REG_WR(bp, BNX2_CTX_HOST_PAGE_TBL_DATA0,
		       (bp->ctx_blk_mapping[i] & 0xffffffff) |
		       BNX2_CTX_HOST_PAGE_TBL_DATA0_VALID);
		REG_WR(bp, BNX2_CTX_HOST_PAGE_TBL_DATA1,
		       (u64) bp->ctx_blk_mapping[i] >> 32);
		REG_WR(bp, BNX2_CTX_HOST_PAGE_TBL_CTRL, i |
		       BNX2_CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ);
		for (j = 0; j < 10; j++) {

			val = REG_RD(bp, BNX2_CTX_HOST_PAGE_TBL_CTRL);
			if (!(val & BNX2_CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ))
				break;
			udelay(5);
		}
		if (val & BNX2_CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ) {
			ret = -EBUSY;
			break;
		}
	}
	return ret;
}

static void
bnx2_init_context(struct bnx2 *bp)
{
	u32 vcid;

	vcid = 96;
	while (vcid) {
		u32 vcid_addr, pcid_addr, offset;
		int i;

		vcid--;

		if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
			u32 new_vcid;

			vcid_addr = GET_PCID_ADDR(vcid);
			if (vcid & 0x8) {
				new_vcid = 0x60 + (vcid & 0xf0) + (vcid & 0x7);
			}
			else {
				new_vcid = vcid;
			}
			pcid_addr = GET_PCID_ADDR(new_vcid);
		}
		else {
	    		vcid_addr = GET_CID_ADDR(vcid);
			pcid_addr = vcid_addr;
		}

		for (i = 0; i < (CTX_SIZE / PHY_CTX_SIZE); i++) {
			vcid_addr += (i << PHY_CTX_SHIFT);
			pcid_addr += (i << PHY_CTX_SHIFT);

			REG_WR(bp, BNX2_CTX_VIRT_ADDR, vcid_addr);
			REG_WR(bp, BNX2_CTX_PAGE_TBL, pcid_addr);

			/* Zero out the context. */
			for (offset = 0; offset < PHY_CTX_SIZE; offset += 4)
				bnx2_ctx_wr(bp, vcid_addr, offset, 0);
		}
	}
}

static int
bnx2_alloc_bad_rbuf(struct bnx2 *bp)
{
	u16 *good_mbuf;
	u32 good_mbuf_cnt;
	u32 val;

	good_mbuf = kmalloc(512 * sizeof(u16), GFP_KERNEL);
	if (good_mbuf == NULL)
		return -ENOMEM;

	REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS,
		BNX2_MISC_ENABLE_SET_BITS_RX_MBUF_ENABLE);

	good_mbuf_cnt = 0;

	/* Allocate a bunch of mbufs and save the good ones in an array. */
	val = bnx2_reg_rd_ind(bp, BNX2_RBUF_STATUS1);
	while (val & BNX2_RBUF_STATUS1_FREE_COUNT) {
		bnx2_reg_wr_ind(bp, BNX2_RBUF_COMMAND,
				BNX2_RBUF_COMMAND_ALLOC_REQ);

		val = bnx2_reg_rd_ind(bp, BNX2_RBUF_FW_BUF_ALLOC);

		val &= BNX2_RBUF_FW_BUF_ALLOC_VALUE;

		/* The addresses with Bit 9 set are bad memory blocks. */
		if (!(val & (1 << 9))) {
			good_mbuf[good_mbuf_cnt] = (u16) val;
			good_mbuf_cnt++;
		}

		val = bnx2_reg_rd_ind(bp, BNX2_RBUF_STATUS1);
	}

	/* Free the good ones back to the mbuf pool thus discarding
	 * all the bad ones. */
	while (good_mbuf_cnt) {
		good_mbuf_cnt--;

		val = good_mbuf[good_mbuf_cnt];
		val = (val << 9) | val | 1;

		bnx2_reg_wr_ind(bp, BNX2_RBUF_FW_BUF_FREE, val);
	}
	kfree(good_mbuf);
	return 0;
}

static void
bnx2_set_mac_addr(struct bnx2 *bp, u8 *mac_addr, u32 pos)
{
	u32 val;

	val = (mac_addr[0] << 8) | mac_addr[1];

	REG_WR(bp, BNX2_EMAC_MAC_MATCH0 + (pos * 8), val);

	val = (mac_addr[2] << 24) | (mac_addr[3] << 16) |
		(mac_addr[4] << 8) | mac_addr[5];

	REG_WR(bp, BNX2_EMAC_MAC_MATCH1 + (pos * 8), val);
}

static inline int
bnx2_alloc_rx_page(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u16 index, gfp_t gfp)
{
	dma_addr_t mapping;
	struct sw_pg *rx_pg = &rxr->rx_pg_ring[index];
	struct rx_bd *rxbd =
		&rxr->rx_pg_desc_ring[RX_RING(index)][RX_IDX(index)];
	struct page *page = alloc_page(gfp);

	if (!page)
		return -ENOMEM;
#if (LINUX_VERSION_CODE >= 0x02061b)
	mapping = dma_map_page(&bp->pdev->dev, page, 0, PAGE_SIZE,
			       PCI_DMA_FROMDEVICE);
	if (dma_mapping_error(&bp->pdev->dev, mapping)) {
#else
	mapping = pci_map_page(bp->pdev, page, 0, PAGE_SIZE,
			       PCI_DMA_FROMDEVICE);
	if (pci_dma_mapping_error(mapping)) {
#endif
		__free_page(page);
		return -EIO;
	}

	rx_pg->page = page;
	dma_unmap_addr_set(rx_pg, mapping, mapping);
	rxbd->rx_bd_haddr_hi = (u64) mapping >> 32;
	rxbd->rx_bd_haddr_lo = (u64) mapping & 0xffffffff;
	return 0;
}

static void
bnx2_free_rx_page(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u16 index)
{
	struct sw_pg *rx_pg = &rxr->rx_pg_ring[index];
	struct page *page = rx_pg->page;

	if (!page)
		return;

#if (LINUX_VERSION_CODE >= 0x02061b)
	dma_unmap_page(&bp->pdev->dev, dma_unmap_addr(rx_pg, mapping),
		       PAGE_SIZE, PCI_DMA_FROMDEVICE);
#else
	pci_unmap_page(bp->pdev, dma_unmap_addr(rx_pg, mapping), PAGE_SIZE,
		       PCI_DMA_FROMDEVICE);
#endif

	__free_page(page);
	rx_pg->page = NULL;
}

static inline int
bnx2_alloc_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u16 index, gfp_t gfp)
{
	struct sk_buff *skb;
	struct sw_bd *rx_buf = &rxr->rx_buf_ring[index];
	dma_addr_t mapping;
	struct rx_bd *rxbd = &rxr->rx_desc_ring[RX_RING(index)][RX_IDX(index)];
	unsigned long align;

	skb = __netdev_alloc_skb(bp->dev, bp->rx_buf_size, gfp);
	if (skb == NULL) {
		return -ENOMEM;
	}

	if (unlikely((align = (unsigned long) skb->data & (BNX2_RX_ALIGN - 1))))
		skb_reserve(skb, BNX2_RX_ALIGN - align);

#if (LINUX_VERSION_CODE >= 0x02061b)
	mapping = dma_map_single(&bp->pdev->dev, skb->data, bp->rx_buf_use_size,
				 PCI_DMA_FROMDEVICE);
	if (dma_mapping_error(&bp->pdev->dev, mapping)) {
#else
	mapping = pci_map_single(bp->pdev, skb->data, bp->rx_buf_use_size,
		PCI_DMA_FROMDEVICE);
	if (pci_dma_mapping_error(mapping)) {
#endif
		dev_kfree_skb(skb);
		return -EIO;
	}

	rx_buf->skb = skb;
	rx_buf->desc = (struct l2_fhdr *) skb->data;
	dma_unmap_addr_set(rx_buf, mapping, mapping);

	rxbd->rx_bd_haddr_hi = (u64) mapping >> 32;
	rxbd->rx_bd_haddr_lo = (u64) mapping & 0xffffffff;

	rxr->rx_prod_bseq += bp->rx_buf_use_size;

	return 0;
}

static int
bnx2_phy_event_is_set(struct bnx2 *bp, struct bnx2_napi *bnapi, u32 event)
{
	struct status_block *sblk = bnapi->status_blk.msi;
	u32 new_link_state, old_link_state;
	int is_set = 1;

	new_link_state = sblk->status_attn_bits & event;
	old_link_state = sblk->status_attn_bits_ack & event;
	if (new_link_state != old_link_state) {
		if (new_link_state)
			REG_WR(bp, BNX2_PCICFG_STATUS_BIT_SET_CMD, event);
		else
			REG_WR(bp, BNX2_PCICFG_STATUS_BIT_CLEAR_CMD, event);
	} else
		is_set = 0;

	return is_set;
}

static void
bnx2_phy_int(struct bnx2 *bp, struct bnx2_napi *bnapi)
{
	spin_lock(&bp->phy_lock);

	if (bnx2_phy_event_is_set(bp, bnapi, STATUS_ATTN_BITS_LINK_STATE))
		bnx2_set_link(bp);
	if (bnx2_phy_event_is_set(bp, bnapi, STATUS_ATTN_BITS_TIMER_ABORT))
		bnx2_set_remote_link(bp);

	spin_unlock(&bp->phy_lock);

}

static inline u16
bnx2_get_hw_tx_cons(struct bnx2_napi *bnapi)
{
	u16 cons;

	/* Tell compiler that status block fields can change. */
	barrier();
	cons = *bnapi->hw_tx_cons_ptr;
	barrier();
	if (unlikely((cons & MAX_TX_DESC_CNT) == MAX_TX_DESC_CNT))
		cons++;
	return cons;
}

static int
#if defined(__VMKLNX__)
bnx2_tx_int(struct bnx2 *bp, struct bnx2_napi *bnapi, int budget,
	    int check_queue)
#else	    
bnx2_tx_int(struct bnx2 *bp, struct bnx2_napi *bnapi, int budget)
#endif
{
	struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;
	u16 hw_cons, sw_cons, sw_ring_cons;
#ifndef BCM_HAVE_MULTI_QUEUE
	int tx_pkt = 0;
#else
	int tx_pkt = 0, index;
	struct netdev_queue *txq;

	index = (bnapi - bp->bnx2_napi);
	txq = netdev_get_tx_queue(bp->dev, index);
#endif

	hw_cons = bnx2_get_hw_tx_cons(bnapi);
	sw_cons = txr->tx_cons;

	while (sw_cons != hw_cons) {
		struct sw_tx_bd *tx_buf;
		struct sk_buff *skb;
		int i, last;

		sw_ring_cons = TX_RING_IDX(sw_cons);

		tx_buf = &txr->tx_buf_ring[sw_ring_cons];
		skb = tx_buf->skb;

		/* prefetch skb_end_pointer() to speedup skb_shinfo(skb) */
		prefetch(&skb->end);

#ifdef BCM_TSO 
		/* partial BD completions possible with TSO packets */
		if (tx_buf->is_gso) {
			u16 last_idx, last_ring_idx;

			last_idx = sw_cons + tx_buf->nr_frags + 1;
			last_ring_idx = sw_ring_cons + tx_buf->nr_frags + 1;
			if (unlikely(last_ring_idx >= MAX_TX_DESC_CNT)) {
				last_idx++;
			}
			if (((s16) ((s16) last_idx - (s16) hw_cons)) > 0) {
				break;
			}
		}
#endif
#if (LINUX_VERSION_CODE >= 0x02061b)
		dma_unmap_single(&bp->pdev->dev, dma_unmap_addr(tx_buf, mapping),
			skb_headlen(skb), PCI_DMA_TODEVICE);
#else
		pci_unmap_single(bp->pdev, dma_unmap_addr(tx_buf, mapping),
			skb_headlen(skb), PCI_DMA_TODEVICE);
#endif

		tx_buf->skb = NULL;
		last = tx_buf->nr_frags;

		for (i = 0; i < last; i++) {
			sw_cons = NEXT_TX_BD(sw_cons);

#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_unmap_page(&bp->pdev->dev,
#else
			pci_unmap_page(bp->pdev,
#endif
				dma_unmap_addr(
					&txr->tx_buf_ring[TX_RING_IDX(sw_cons)],
					mapping),
				skb_frag_size(&skb_shinfo(skb)->frags[i]),
				PCI_DMA_TODEVICE);
		}

		sw_cons = NEXT_TX_BD(sw_cons);

		dev_kfree_skb(skb);
#if defined(BNX2_ENABLE_NETQUEUE)
		bnapi->stats.tx_packets++;
		bnapi->stats.tx_bytes += skb->len;
		bnapi->tx_packets_processed++;
		wmb();
#endif
		tx_pkt++;
		if (tx_pkt == budget)
			break;

		if (hw_cons == sw_cons)
			hw_cons = bnx2_get_hw_tx_cons(bnapi);
	}

	txr->hw_tx_cons = hw_cons;
	txr->tx_cons = sw_cons;

	/* Need to make the tx_cons update visible to bnx2_start_xmit()
	 * before checking for netif_tx_queue_stopped().  Without the
	 * memory barrier, there is a small possibility that bnx2_start_xmit()
	 * will miss it and cause the queue to be stopped forever.
	 */
	smp_mb();

#if defined(BNX2_ENABLE_NETQUEUE)
	if ((!check_queue) || (bp->netq_state & BNX2_NETQ_SUSPENDED))
		return tx_pkt;
#endif		

#ifndef BCM_HAVE_MULTI_QUEUE
	if (unlikely(netif_queue_stopped(bp->dev)) &&
		     (bnx2_tx_avail(bp, txr) > bp->tx_wake_thresh)) {
		netif_tx_lock(bp->dev);
		if ((netif_queue_stopped(bp->dev)) &&
		    (bnx2_tx_avail(bp, txr) > bp->tx_wake_thresh))
			netif_wake_queue(bp->dev);
		netif_tx_unlock(bp->dev);
	}
#else
	if (unlikely(netif_tx_queue_stopped(txq)) &&
		     (bnx2_tx_avail(bp, txr) > bp->tx_wake_thresh)) {
		__netif_tx_lock(txq, smp_processor_id());
		if ((netif_tx_queue_stopped(txq)) &&
		    (bnx2_tx_avail(bp, txr) > bp->tx_wake_thresh))
			netif_tx_wake_queue(txq);
		__netif_tx_unlock(txq);
	}
#endif
	return tx_pkt;
}

static void
bnx2_reuse_rx_skb_pages(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr,
			struct sk_buff *skb, int count)
{
	struct sw_pg *cons_rx_pg, *prod_rx_pg;
	struct rx_bd *cons_bd, *prod_bd;
	int i;
	u16 hw_prod, prod;
	u16 cons = rxr->rx_pg_cons;

	cons_rx_pg = &rxr->rx_pg_ring[cons];

	/* The caller was unable to allocate a new page to replace the
	 * last one in the frags array, so we need to recycle that page
	 * and then free the skb.
	 */
	if (skb) {
		struct page *page;
		struct skb_shared_info *shinfo;

		shinfo = skb_shinfo(skb);
		shinfo->nr_frags--;
		page = shinfo->frags[shinfo->nr_frags].page;
		shinfo->frags[shinfo->nr_frags].page = NULL;

		cons_rx_pg->page = page;
		dev_kfree_skb(skb);
	}

	hw_prod = rxr->rx_pg_prod;

	for (i = 0; i < count; i++) {
		prod = RX_PG_RING_IDX(hw_prod);

		prod_rx_pg = &rxr->rx_pg_ring[prod];
		cons_rx_pg = &rxr->rx_pg_ring[cons];
		cons_bd = &rxr->rx_pg_desc_ring[RX_RING(cons)][RX_IDX(cons)];
		prod_bd = &rxr->rx_pg_desc_ring[RX_RING(prod)][RX_IDX(prod)];

		if (prod != cons) {
			prod_rx_pg->page = cons_rx_pg->page;
			cons_rx_pg->page = NULL;
			dma_unmap_addr_set(prod_rx_pg, mapping,
				dma_unmap_addr(cons_rx_pg, mapping));

			prod_bd->rx_bd_haddr_hi = cons_bd->rx_bd_haddr_hi;
			prod_bd->rx_bd_haddr_lo = cons_bd->rx_bd_haddr_lo;

		}
		cons = RX_PG_RING_IDX(NEXT_RX_BD(cons));
		hw_prod = NEXT_RX_BD(hw_prod);
	}
	rxr->rx_pg_prod = hw_prod;
	rxr->rx_pg_cons = cons;
}

static inline void
bnx2_reuse_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr,
		  struct sk_buff *skb, u16 cons, u16 prod)
{
	struct sw_bd *cons_rx_buf, *prod_rx_buf;
	struct rx_bd *cons_bd, *prod_bd;

	cons_rx_buf = &rxr->rx_buf_ring[cons];
	prod_rx_buf = &rxr->rx_buf_ring[prod];

#if (LINUX_VERSION_CODE >= 0x02061b)
	dma_sync_single_for_device(&bp->pdev->dev,
#else
	pci_dma_sync_single_for_device(bp->pdev,
#endif
 		dma_unmap_addr(cons_rx_buf, mapping),
 		BNX2_RX_OFFSET + BNX2_RX_COPY_THRESH, PCI_DMA_FROMDEVICE);

	rxr->rx_prod_bseq += bp->rx_buf_use_size;

	prod_rx_buf->skb = skb;
	prod_rx_buf->desc = (struct l2_fhdr *) skb->data;

	if (cons == prod)
		return;

	dma_unmap_addr_set(prod_rx_buf, mapping,
			dma_unmap_addr(cons_rx_buf, mapping));

	cons_bd = &rxr->rx_desc_ring[RX_RING(cons)][RX_IDX(cons)];
	prod_bd = &rxr->rx_desc_ring[RX_RING(prod)][RX_IDX(prod)];
	prod_bd->rx_bd_haddr_hi = cons_bd->rx_bd_haddr_hi;
	prod_bd->rx_bd_haddr_lo = cons_bd->rx_bd_haddr_lo;
}

static int
bnx2_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, struct sk_buff *skb,
	    unsigned int len, unsigned int hdr_len, dma_addr_t dma_addr,
	    u32 ring_idx)
{
	int err;
	u16 prod = ring_idx & 0xffff;

	err = bnx2_alloc_rx_skb(bp, rxr, prod, GFP_ATOMIC);
	if (unlikely(err)) {
		bnx2_reuse_rx_skb(bp, rxr, skb, (u16) (ring_idx >> 16), prod);
		if (hdr_len) {
			unsigned int raw_len = len + 4;
			int pages = PAGE_ALIGN(raw_len - hdr_len) >> PAGE_SHIFT;

			bnx2_reuse_rx_skb_pages(bp, rxr, NULL, pages);
		}
		return err;
	}

	skb_reserve(skb, BNX2_RX_OFFSET);
#if (LINUX_VERSION_CODE >= 0x02061b)
	dma_unmap_single(&bp->pdev->dev, dma_addr, bp->rx_buf_use_size,
			 PCI_DMA_FROMDEVICE);
#else
	pci_unmap_single(bp->pdev, dma_addr, bp->rx_buf_use_size,
			 PCI_DMA_FROMDEVICE);
#endif

	if (hdr_len == 0) {
		skb_put(skb, len);
		return 0;
	} else {
		unsigned int i, frag_len, frag_size, pages;
		struct sw_pg *rx_pg;
		u16 pg_cons = rxr->rx_pg_cons;
		u16 pg_prod = rxr->rx_pg_prod;

		frag_size = len + 4 - hdr_len;
		pages = PAGE_ALIGN(frag_size) >> PAGE_SHIFT;
		skb_put(skb, hdr_len);

		for (i = 0; i < pages; i++) {
			dma_addr_t mapping_old;

			frag_len = min(frag_size, (unsigned int) PAGE_SIZE);
			if (unlikely(frag_len <= 4)) {
				unsigned int tail = 4 - frag_len;

				rxr->rx_pg_cons = pg_cons;
				rxr->rx_pg_prod = pg_prod;
				bnx2_reuse_rx_skb_pages(bp, rxr, NULL,
							pages - i);
				skb->len -= tail;
				if (i == 0) {
					skb->tail -= tail;
				} else {
					skb_frag_t *frag =
						&skb_shinfo(skb)->frags[i - 1];
					skb_frag_size_sub(frag, tail);
					skb->data_len -= tail;
				}
				return 0;
			}
			rx_pg = &rxr->rx_pg_ring[pg_cons];

			/* Don't unmap yet.  If we're unable to allocate a new
			 * page, we need to recycle the page and the DMA addr.
			 */
			mapping_old = dma_unmap_addr(rx_pg, mapping);
			if (i == pages - 1)
				frag_len -= 4;

			bnx2_skb_fill_page_desc(skb, i, rx_pg->page, 0,
						frag_len);
			rx_pg->page = NULL;

			err = bnx2_alloc_rx_page(bp, rxr,
						 RX_PG_RING_IDX(pg_prod),
						 GFP_ATOMIC);
			if (unlikely(err)) {
				rxr->rx_pg_cons = pg_cons;
				rxr->rx_pg_prod = pg_prod;
				bnx2_reuse_rx_skb_pages(bp, rxr, skb,
							pages - i);
				return err;
			}

#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_unmap_page(&bp->pdev->dev, mapping_old,
 				       PAGE_SIZE, PCI_DMA_FROMDEVICE);
#else
			pci_unmap_page(bp->pdev, mapping_old,
				       PAGE_SIZE, PCI_DMA_FROMDEVICE);
#endif

			frag_size -= frag_len;
			skb->data_len += frag_len;
			skb->truesize += PAGE_SIZE;
			skb->len += frag_len;

			pg_prod = NEXT_RX_BD(pg_prod);
			pg_cons = RX_PG_RING_IDX(NEXT_RX_BD(pg_cons));
		}
		rxr->rx_pg_prod = pg_prod;
		rxr->rx_pg_cons = pg_cons;
	}
	return 0;
}

static inline u16
bnx2_get_hw_rx_cons(struct bnx2_napi *bnapi)
{
	u16 cons;

	/* Tell compiler that status block fields can change. */
	barrier();
	cons = *bnapi->hw_rx_cons_ptr;
	barrier();
	if (unlikely((cons & MAX_RX_DESC_CNT) == MAX_RX_DESC_CNT))
		cons++;
	return cons;
}

static int
bnx2_rx_int(struct bnx2 *bp, struct bnx2_napi *bnapi, int budget)
{
	struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;
	u16 hw_cons, sw_cons, sw_ring_cons, sw_prod, sw_ring_prod;
	struct l2_fhdr *rx_hdr;
	int rx_pkt = 0, pg_ring_used = 0;
#if defined(BNX2_ENABLE_NETQUEUE)
	int index = (bnapi - bp->bnx2_napi);
#endif

	hw_cons = bnx2_get_hw_rx_cons(bnapi);
	sw_cons = rxr->rx_cons;
	sw_prod = rxr->rx_prod;

	/* Memory barrier necessary as speculative reads of the rx
	 * buffer can be ahead of the index in the status block
	 */
	rmb();
	while (sw_cons != hw_cons) {
		unsigned int len, hdr_len;
		u32 status;
		struct sw_bd *rx_buf, *next_rx_buf;
		struct sk_buff *skb;
		dma_addr_t dma_addr;
		u16 vtag = 0;
		int hw_vlan __maybe_unused = 0;

		sw_ring_cons = RX_RING_IDX(sw_cons);
		sw_ring_prod = RX_RING_IDX(sw_prod);

		rx_buf = &rxr->rx_buf_ring[sw_ring_cons];
		skb = rx_buf->skb;
		prefetchw(skb);

		next_rx_buf =
			&rxr->rx_buf_ring[RX_RING_IDX(NEXT_RX_BD(sw_cons))];
		prefetch(next_rx_buf->desc);

		rx_buf->skb = NULL;

		dma_addr = dma_unmap_addr(rx_buf, mapping);

#if (LINUX_VERSION_CODE >= 0x02061b)
		dma_sync_single_for_cpu(&bp->pdev->dev, dma_addr,
#else
		pci_dma_sync_single_for_cpu(bp->pdev, dma_addr,
#endif
			BNX2_RX_OFFSET + BNX2_RX_COPY_THRESH,
			PCI_DMA_FROMDEVICE);

		rx_hdr = rx_buf->desc;
		len = rx_hdr->l2_fhdr_pkt_len;
		status = rx_hdr->l2_fhdr_status;

		hdr_len = 0;
		if (status & L2_FHDR_STATUS_SPLIT) {
			hdr_len = rx_hdr->l2_fhdr_ip_xsum;
			pg_ring_used = 1;
		} else if (len > bp->rx_jumbo_thresh) {
			hdr_len = bp->rx_jumbo_thresh;
			pg_ring_used = 1;
		}

		if (unlikely(status & (L2_FHDR_ERRORS_BAD_CRC |
				       L2_FHDR_ERRORS_PHY_DECODE |
				       L2_FHDR_ERRORS_ALIGNMENT |
				       L2_FHDR_ERRORS_TOO_SHORT |
				       L2_FHDR_ERRORS_GIANT_FRAME))) {

#if defined(BNX2_ENABLE_NETQUEUE)
			bnapi->stats.rx_errors++;

			if (status & L2_FHDR_ERRORS_BAD_CRC)
				bnapi->stats.rx_crc_errors++;

			if (status &
			     (L2_FHDR_ERRORS_TOO_SHORT |
			      L2_FHDR_ERRORS_GIANT_FRAME))
				bnapi->stats.rx_frame_errors++;
#endif

			bnx2_reuse_rx_skb(bp, rxr, skb, sw_ring_cons,
					  sw_ring_prod);
			if (pg_ring_used) {
				int pages;

				pages = PAGE_ALIGN(len - hdr_len) >> PAGE_SHIFT;

				bnx2_reuse_rx_skb_pages(bp, rxr, NULL, pages);
			}
			goto next_rx;
		}

		len -= 4;

		if (len <= bp->rx_copy_thresh) {
			struct sk_buff *new_skb;

			new_skb = netdev_alloc_skb(bp->dev, len + 6);
			if (new_skb == NULL) {
				bnx2_reuse_rx_skb(bp, rxr, skb, sw_ring_cons,
						  sw_ring_prod);
				goto next_rx;
			}

			/* aligned copy */
#if (LINUX_VERSION_CODE >= 0x20616)
			skb_copy_from_linear_data_offset(skb,
							 BNX2_RX_OFFSET - 6,
				      new_skb->data, len + 6);
#else
			memcpy(new_skb->data, skb->data + BNX2_RX_OFFSET - 6,
			       len + 6);
#endif

			skb_reserve(new_skb, 6);
			skb_put(new_skb, len);

			bnx2_reuse_rx_skb(bp, rxr, skb,
				sw_ring_cons, sw_ring_prod);

			skb = new_skb;
		} else if (unlikely(bnx2_rx_skb(bp, rxr, skb, len, hdr_len,
			   dma_addr, (sw_ring_cons << 16) | sw_ring_prod)))
			goto next_rx;

		if ((status & L2_FHDR_STATUS_L2_VLAN_TAG) &&
		    !(bp->rx_mode & BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG)) {
			vtag = rx_hdr->l2_fhdr_vlan_tag;
#ifdef BCM_VLAN
			if (bp->vlgrp)
				hw_vlan = 1;
			else
#endif
			{
				struct vlan_ethhdr *ve = (struct vlan_ethhdr *)
					__skb_push(skb, 4);

				bcm_memmove(ve, skb->data + 4, ETH_ALEN * 2);
				ve->h_vlan_proto = htons(ETH_P_8021Q);
				ve->h_vlan_TCI = htons(vtag);
				len += 4;
			}
		}

		skb->protocol = eth_type_trans(skb, bp->dev);

		if ((len > (bp->dev->mtu + ETH_HLEN)) &&
			(ntohs(skb->protocol) != 0x8100)) {

			dev_kfree_skb(skb);
			goto next_rx;

		}

		skb->ip_summed = CHECKSUM_NONE;
		if (bp->rx_csum &&
			(status & (L2_FHDR_STATUS_TCP_SEGMENT |
			L2_FHDR_STATUS_UDP_DATAGRAM))) {

			if (likely((status & (L2_FHDR_ERRORS_TCP_XSUM |
					      L2_FHDR_ERRORS_UDP_XSUM)) == 0))
				skb->ip_summed = CHECKSUM_UNNECESSARY;
		}
#ifdef NETIF_F_RXHASH
		if ((bp->dev->features & NETIF_F_RXHASH) &&
		    ((status & L2_FHDR_STATUS_USE_RXHASH) ==
		     L2_FHDR_STATUS_USE_RXHASH))
			skb->rxhash = rx_hdr->l2_fhdr_hash;
#endif

		skb_record_rx_queue(skb, bnapi - &bp->bnx2_napi[0]);

#if defined(BNX2_ENABLE_NETQUEUE)
		vmknetddi_queueops_set_skb_queueid(skb,
				VMKNETDDI_QUEUEOPS_MK_RX_QUEUEID(index));
#endif

#if defined(NETIF_F_GRO) && defined(BNX2_NEW_NAPI)
#ifdef BCM_VLAN
		if (hw_vlan)
			vlan_gro_receive(&bnapi->napi, bp->vlgrp, vtag, skb);
		else
#endif
			napi_gro_receive(&bnapi->napi, skb);
#else
#ifdef BCM_VLAN
		if (hw_vlan)
			vlan_hwaccel_receive_skb(skb, bp->vlgrp, vtag);
		else
#endif
			netif_receive_skb(skb);
#endif

#if (LINUX_VERSION_CODE < 0x02061b) || defined(__VMKLNX__)
		bp->dev->last_rx = jiffies;
#endif
		rx_pkt++;

#if defined(BNX2_ENABLE_NETQUEUE)
		/*  Update queue specific stats */
		bnapi->stats.rx_packets++;
		bnapi->stats.rx_bytes += len;
#endif

next_rx:
		sw_cons = NEXT_RX_BD(sw_cons);
		sw_prod = NEXT_RX_BD(sw_prod);

		if ((rx_pkt == budget))
			break;

		/* Refresh hw_cons to see if there is new work */
		if (sw_cons == hw_cons) {
			hw_cons = bnx2_get_hw_rx_cons(bnapi);
			rmb();
		}
	}
	rxr->rx_cons = sw_cons;
	rxr->rx_prod = sw_prod;

	if (pg_ring_used)
		REG_WR16(bp, rxr->rx_pg_bidx_addr, rxr->rx_pg_prod);

	REG_WR16(bp, rxr->rx_bidx_addr, sw_prod);

	REG_WR(bp, rxr->rx_bseq_addr, rxr->rx_prod_bseq);

	mmiowb();

	return rx_pkt;

}

#ifdef CONFIG_PCI_MSI
/* MSI ISR - The only difference between this and the INTx ISR
 * is that the MSI interrupt is always serviced.
 */
static irqreturn_t
#if (LINUX_VERSION_CODE >= 0x20613) || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
bnx2_msi(int irq, void *dev_instance)
#else
bnx2_msi(int irq, void *dev_instance, struct pt_regs *regs)
#endif
{
	struct bnx2_napi *bnapi = dev_instance;
	struct bnx2 *bp = bnapi->bp;

	prefetch(bnapi->status_blk.msi);
	REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
#if defined(__VMKLNX__)
		bnapi->int_num |
#endif
		BNX2_PCICFG_INT_ACK_CMD_USE_INT_HC_PARAM |
		BNX2_PCICFG_INT_ACK_CMD_MASK_INT);

	/* Return here if interrupt is disabled. */
	if (unlikely(atomic_read(&bp->intr_sem) != 0))
		return IRQ_HANDLED;

#ifdef BNX2_NEW_NAPI
	napi_schedule(&bnapi->napi);
#else
	netif_rx_schedule(bp->dev);
#endif

	return IRQ_HANDLED;
}

static irqreturn_t
#if (LINUX_VERSION_CODE >= 0x20613) || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
bnx2_msi_1shot(int irq, void *dev_instance)
#else
bnx2_msi_1shot(int irq, void *dev_instance, struct pt_regs *regs)
#endif
{
	struct bnx2_napi *bnapi = dev_instance;
	struct bnx2 *bp = bnapi->bp;

	prefetch(bnapi->status_blk.msi);

	/* Return here if interrupt is disabled. */
	if (unlikely(atomic_read(&bp->intr_sem) != 0))
		return IRQ_HANDLED;

#ifdef BNX2_NEW_NAPI
	napi_schedule(&bnapi->napi);
#else
	netif_rx_schedule(bp->dev);
#endif

	return IRQ_HANDLED;
}
#endif

static irqreturn_t
#if (LINUX_VERSION_CODE >= 0x20613) || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
bnx2_interrupt(int irq, void *dev_instance)
#else
bnx2_interrupt(int irq, void *dev_instance, struct pt_regs *regs)
#endif
{
	struct bnx2_napi *bnapi = dev_instance;
	struct bnx2 *bp = bnapi->bp;
	struct status_block *sblk = bnapi->status_blk.msi;

	/* When using INTx, it is possible for the interrupt to arrive
	 * at the CPU before the status block posted prior to the
	 * interrupt. Reading a register will flush the status block.
	 * When using MSI, the MSI message will always complete after
	 * the status block write.
	 */
	if ((sblk->status_idx == bnapi->last_status_idx) &&
	    (REG_RD(bp, BNX2_PCICFG_MISC_STATUS) &
	     BNX2_PCICFG_MISC_STATUS_INTA_VALUE))
		return IRQ_NONE;

	REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
		BNX2_PCICFG_INT_ACK_CMD_USE_INT_HC_PARAM |
		BNX2_PCICFG_INT_ACK_CMD_MASK_INT);

	/* Read back to deassert IRQ immediately to avoid too many
	 * spurious interrupts.
	 */
	REG_RD(bp, BNX2_PCICFG_INT_ACK_CMD);

	/* Return here if interrupt is shared and is disabled. */
	if (unlikely(atomic_read(&bp->intr_sem) != 0))
		return IRQ_HANDLED;

#ifdef BNX2_NEW_NAPI
	if (napi_schedule_prep(&bnapi->napi)) {
		bnapi->last_status_idx = sblk->status_idx;
		__napi_schedule(&bnapi->napi);
	}
#else
	if (netif_rx_schedule_prep(bp->dev)) {
		bnapi->last_status_idx = sblk->status_idx;
		__netif_rx_schedule(bp->dev);
	}
#endif

	return IRQ_HANDLED;
}

static inline int
bnx2_has_fast_work(struct bnx2_napi *bnapi)
{
	struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;
	struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;

	if ((bnx2_get_hw_rx_cons(bnapi) != rxr->rx_cons) ||
	    (bnx2_get_hw_tx_cons(bnapi) != txr->hw_tx_cons))
		return 1;
	return 0;
}

#define STATUS_ATTN_EVENTS	(STATUS_ATTN_BITS_LINK_STATE | \
				 STATUS_ATTN_BITS_TIMER_ABORT)

static inline int
bnx2_has_work(struct bnx2_napi *bnapi)
{
	struct status_block *sblk = bnapi->status_blk.msi;

	if (bnx2_has_fast_work(bnapi))
		return 1;

#ifdef BCM_CNIC
	if (bnapi->cnic_present && (bnapi->cnic_tag != sblk->status_idx))
		return 1;
#endif

	if ((sblk->status_attn_bits & STATUS_ATTN_EVENTS) !=
	    (sblk->status_attn_bits_ack & STATUS_ATTN_EVENTS))
		return 1;

	return 0;
}

#ifdef CONFIG_PCI_MSI
static void
bnx2_chk_missed_msi(struct bnx2 *bp)
{
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0];
	u32 msi_ctrl;

	if (bnx2_has_work(bnapi)) {
		msi_ctrl = REG_RD(bp, BNX2_PCICFG_MSI_CONTROL);
		if (!(msi_ctrl & BNX2_PCICFG_MSI_CONTROL_ENABLE))
			return;

		if (bnapi->last_status_idx == bp->idle_chk_status_idx) {
			REG_WR(bp, BNX2_PCICFG_MSI_CONTROL, msi_ctrl &
			       ~BNX2_PCICFG_MSI_CONTROL_ENABLE);
			REG_WR(bp, BNX2_PCICFG_MSI_CONTROL, msi_ctrl);
#if (LINUX_VERSION_CODE >= 0x20613) || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
			bnx2_msi(bp->irq_tbl[0].vector, bnapi);
#else
			bnx2_msi(bp->irq_tbl[0].vector, bnapi, NULL);
#endif
		}
	}

	bp->idle_chk_status_idx = bnapi->last_status_idx;
}
#endif

#ifdef BCM_CNIC
static void bnx2_poll_cnic(struct bnx2 *bp, struct bnx2_napi *bnapi)
{
	struct cnic_ops *c_ops;

	if (!bnapi->cnic_present)
		return;

	rcu_read_lock();
	c_ops = rcu_dereference(bp->cnic_ops);
	if (c_ops)
		bnapi->cnic_tag = c_ops->cnic_handler(bp->cnic_data,
						      bnapi->status_blk.msi);
	rcu_read_unlock();
}
#endif

#ifdef BNX2_NEW_NAPI
static void bnx2_poll_link(struct bnx2 *bp, struct bnx2_napi *bnapi)
{
	struct status_block *sblk = bnapi->status_blk.msi;
	u32 status_attn_bits = sblk->status_attn_bits;
	u32 status_attn_bits_ack = sblk->status_attn_bits_ack;

	if ((status_attn_bits & STATUS_ATTN_EVENTS) !=
	    (status_attn_bits_ack & STATUS_ATTN_EVENTS)) {

		bnx2_phy_int(bp, bnapi);

		/* This is needed to take care of transient status
		 * during link changes.
		 */
		REG_WR(bp, BNX2_HC_COMMAND,
		       bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);
		REG_RD(bp, BNX2_HC_COMMAND);
	}
}

static int bnx2_poll_work(struct bnx2 *bp, struct bnx2_napi *bnapi,
			  int work_done, int budget)
{
	struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;
	struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;

	if (bnx2_get_hw_tx_cons(bnapi) != txr->hw_tx_cons)
#if defined(__VMKLNX__)
		bnx2_tx_int(bp, bnapi, 0, 1);
#else
		bnx2_tx_int(bp, bnapi, 0);
#endif

	if (bnx2_get_hw_rx_cons(bnapi) != rxr->rx_cons)
		work_done += bnx2_rx_int(bp, bnapi, budget - work_done);

#if defined(__VMKLNX__)
	wmb();
#endif
	return work_done;
}

static int bnx2_poll_msix(struct napi_struct *napi, int budget)
{
	struct bnx2_napi *bnapi = container_of(napi, struct bnx2_napi, napi);
	struct bnx2 *bp = bnapi->bp;
	int work_done = 0;
	struct status_block_msix *sblk = bnapi->status_blk.msix;

	while (1) {
		work_done = bnx2_poll_work(bp, bnapi, work_done, budget);
		if (unlikely(work_done >= budget))
			break;

		bnapi->last_status_idx = sblk->status_idx;
		/* status idx must be read before checking for more work. */
		rmb();
		if (likely(!bnx2_has_fast_work(bnapi))) {

			napi_complete(napi);
			REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD, bnapi->int_num |
			       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
			       bnapi->last_status_idx);
			break;
		}
	}
	return work_done;
}

static int bnx2_poll(struct napi_struct *napi, int budget)
{
	struct bnx2_napi *bnapi = container_of(napi, struct bnx2_napi, napi);
	struct bnx2 *bp = bnapi->bp;
	int work_done = 0;
	struct status_block *sblk = bnapi->status_blk.msi;

	while (1) {
		bnx2_poll_link(bp, bnapi);

		work_done = bnx2_poll_work(bp, bnapi, work_done, budget);

#if defined(BNX2_ENABLE_NETQUEUE)
		if (bnx2_netqueue_is_avail(bp) &&
		    (bp->netq_state & BNX2_NETQ_HW_STARTED))
			bnx2_netqueue_service_bnx2_msix(bnapi);
#endif

#ifdef BCM_CNIC
		bnx2_poll_cnic(bp, bnapi);
#endif

		/* bnapi->last_status_idx is used below to tell the hw how
		 * much work has been processed, so we must read it before
		 * checking for more work.
		 */
		bnapi->last_status_idx = sblk->status_idx;

		if (unlikely(work_done >= budget))
			break;

		rmb();
		if (likely(!bnx2_has_work(bnapi))) {
			napi_complete(napi);
			if (likely(bp->flags & BNX2_FLAG_USING_MSI_OR_MSIX)) {
				REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
				       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
				       bnapi->last_status_idx);
				break;
			}
			REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
			       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
			       BNX2_PCICFG_INT_ACK_CMD_MASK_INT |
			       bnapi->last_status_idx);

			REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
			       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
			       bnapi->last_status_idx);
			break;
		}
	}

	return work_done;
}

#else

static int
bnx2_poll(struct net_device *dev, int *budget)
{
	struct bnx2 *bp = netdev_priv(dev);
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0];
	struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;
	struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;
	struct status_block *sblk = bnapi->status_blk.msi;
	u32 status_attn_bits = sblk->status_attn_bits;
	u32 status_attn_bits_ack = sblk->status_attn_bits_ack;

	if ((status_attn_bits & STATUS_ATTN_EVENTS) !=
	    (status_attn_bits_ack & STATUS_ATTN_EVENTS)) {

		bnx2_phy_int(bp, bnapi);

		/* This is needed to take care of transient status
		 * during link changes.
		 */
		REG_WR(bp, BNX2_HC_COMMAND,
		       bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);
		REG_RD(bp, BNX2_HC_COMMAND);
	}

	if (bnx2_get_hw_tx_cons(bnapi) != txr->hw_tx_cons)
#if defined(__VMKLNX__)
		bnx2_tx_int(bp, bnapi, 0, 1);
#else
		bnx2_tx_int(bp, bnapi, 0);
#endif

	if (bnx2_get_hw_rx_cons(bnapi) != rxr->rx_cons) {
		int orig_budget = *budget;
		int work_done;

		if (orig_budget > dev->quota)
			orig_budget = dev->quota;

		work_done = bnx2_rx_int(bp, bnapi, orig_budget);
		*budget -= work_done;
		dev->quota -= work_done;
	}

#ifdef BCM_CNIC
	bnx2_poll_cnic(bp, bnapi);
#endif

	bnapi->last_status_idx = sblk->status_idx;
	rmb();

	if (!bnx2_has_work(bnapi)) {
		netif_rx_complete(dev);
		if (likely(bp->flags & BNX2_FLAG_USING_MSI_OR_MSIX)) {
			REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
			       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
			       bnapi->last_status_idx);
			return 0;
		}
		REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
		       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
		       BNX2_PCICFG_INT_ACK_CMD_MASK_INT |
		       bnapi->last_status_idx);

		REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
		       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
		       bnapi->last_status_idx);
		return 0;
	}

	return 1;
}
#endif

/* Called with rtnl_lock from vlan functions and also netif_tx_lock
 * from set_multicast.
 */
static void
bnx2_set_rx_mode(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);
	u32 rx_mode, sort_mode;
#ifdef BCM_HAVE_SET_RX_MODE
#if (LINUX_VERSION_CODE >= 0x2061f)
	struct netdev_hw_addr *ha;
#else
	struct dev_addr_list *uc_ptr;
#endif
#endif
	int i;

	if (!netif_running(dev))
		return;

	spin_lock_bh(&bp->phy_lock);

	rx_mode = bp->rx_mode & ~(BNX2_EMAC_RX_MODE_PROMISCUOUS |
				  BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG);
	sort_mode = 1 | BNX2_RPM_SORT_USER0_BC_EN;
#ifdef BCM_VLAN
	if (!bp->vlgrp && (bp->flags & BNX2_FLAG_CAN_KEEP_VLAN))
		rx_mode |= BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG;
#else
	if (bp->flags & BNX2_FLAG_CAN_KEEP_VLAN)
		rx_mode |= BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG;
#endif
	if (dev->flags & IFF_PROMISC) {
		/* Promiscuous mode. */
		rx_mode |= BNX2_EMAC_RX_MODE_PROMISCUOUS;
		sort_mode |= BNX2_RPM_SORT_USER0_PROM_EN |
			     BNX2_RPM_SORT_USER0_PROM_VLAN;
	}
	else if (dev->flags & IFF_ALLMULTI) {
		for (i = 0; i < NUM_MC_HASH_REGISTERS; i++) {
			REG_WR(bp, BNX2_EMAC_MULTICAST_HASH0 + (i * 4),
			       0xffffffff);
        	}
		sort_mode |= BNX2_RPM_SORT_USER0_MC_EN;
	}
	else {
		/* Accept one or more multicast(s). */
#ifndef BCM_NEW_NETDEV_HW_ADDR
		struct dev_mc_list *mclist;
#endif
		u32 mc_filter[NUM_MC_HASH_REGISTERS];
		u32 regidx;
		u32 bit;
		u32 crc;

		memset(mc_filter, 0, 4 * NUM_MC_HASH_REGISTERS);

#ifdef BCM_NEW_NETDEV_HW_ADDR
		netdev_for_each_mc_addr(ha, dev) {
			crc = ether_crc_le(ETH_ALEN, ha->addr);
#else
		netdev_for_each_mc_addr(mclist, dev) {
			crc = ether_crc_le(ETH_ALEN, mclist->dmi_addr);
#endif
			bit = crc & 0xff;
			regidx = (bit & 0xe0) >> 5;
			bit &= 0x1f;
			mc_filter[regidx] |= (1 << bit);
		}

		for (i = 0; i < NUM_MC_HASH_REGISTERS; i++) {
			REG_WR(bp, BNX2_EMAC_MULTICAST_HASH0 + (i * 4),
			       mc_filter[i]);
		}

		sort_mode |= BNX2_RPM_SORT_USER0_MC_HSH_EN;
	}

#ifdef BCM_HAVE_SET_RX_MODE
	if (netdev_uc_count(dev) > BNX2_MAX_UNICAST_ADDRESSES) {
		rx_mode |= BNX2_EMAC_RX_MODE_PROMISCUOUS;
		sort_mode |= BNX2_RPM_SORT_USER0_PROM_EN |
			     BNX2_RPM_SORT_USER0_PROM_VLAN;
	} else if (!(dev->flags & IFF_PROMISC)) {
#if (LINUX_VERSION_CODE < 0x2061f)
		uc_ptr = dev->uc_list;

		/* Add all entries into to the match filter list */
		for (i = 0; i < dev->uc_count; i++) {
			bnx2_set_mac_addr(bp, uc_ptr->da_addr,
					  i + BNX2_START_UNICAST_ADDRESS_INDEX);
			sort_mode |= (1 <<
				      (i + BNX2_START_UNICAST_ADDRESS_INDEX));
			uc_ptr = uc_ptr->next;
		}
#else
		i = 0;
		netdev_for_each_uc_addr(ha, dev) {
			bnx2_set_mac_addr(bp, ha->addr,
					  i + BNX2_START_UNICAST_ADDRESS_INDEX);
			sort_mode |= (1 <<
				      (i + BNX2_START_UNICAST_ADDRESS_INDEX));
			i++;
		}
#endif
	}
#endif

	if (rx_mode != bp->rx_mode) {
		bp->rx_mode = rx_mode;
		REG_WR(bp, BNX2_EMAC_RX_MODE, rx_mode);
	}

	REG_WR(bp, BNX2_RPM_SORT_USER0, 0x0);
	REG_WR(bp, BNX2_RPM_SORT_USER0, sort_mode);
	REG_WR(bp, BNX2_RPM_SORT_USER0, sort_mode | BNX2_RPM_SORT_USER0_ENA);

	spin_unlock_bh(&bp->phy_lock);
}

#define FW_BUF_SIZE	0x10000

static int
bnx2_gunzip_init(struct bnx2 *bp)
{
	if ((bp->gunzip_buf = vmalloc(FW_BUF_SIZE)) == NULL)
		goto gunzip_nomem1;

	if ((bp->strm = kmalloc(sizeof(*bp->strm), GFP_KERNEL)) == NULL)
		goto gunzip_nomem2;

	bp->strm->workspace = kmalloc(zlib_inflate_workspacesize(), GFP_KERNEL);
	if (bp->strm->workspace == NULL)
		goto gunzip_nomem3;

	return 0;

gunzip_nomem3:
	kfree(bp->strm);
	bp->strm = NULL;

gunzip_nomem2:
	vfree(bp->gunzip_buf);
	bp->gunzip_buf = NULL;

gunzip_nomem1:
	netdev_err(bp->dev, "Cannot allocate firmware buffer for "
			    "uncompression.\n");
	return -ENOMEM;
}

static void
bnx2_gunzip_end(struct bnx2 *bp)
{
	kfree(bp->strm->workspace);

	kfree(bp->strm);
	bp->strm = NULL;

	if (bp->gunzip_buf) {
		vfree(bp->gunzip_buf);
		bp->gunzip_buf = NULL;
	}
}

static int
bnx2_gunzip(struct bnx2 *bp, const u8 *zbuf,
	    int len, void **outbuf, int *outlen)
{
	int rc;

	bp->strm->next_in = zbuf;
	bp->strm->avail_in = len;
	bp->strm->next_out = bp->gunzip_buf;
	bp->strm->avail_out = FW_BUF_SIZE;

	rc = zlib_inflateInit2(bp->strm, -MAX_WBITS);
	if (rc != Z_OK)
		return rc;

	rc = zlib_inflate(bp->strm, Z_FINISH);

	*outlen = FW_BUF_SIZE - bp->strm->avail_out;
	*outbuf = bp->gunzip_buf;

	if ((rc != Z_OK) && (rc != Z_STREAM_END))
		netdev_err(bp->dev, "Firmware decompression error: %s\n",
			   bp->strm->msg);

	zlib_inflateEnd(bp->strm);

	if (rc == Z_STREAM_END)
		return 0;

	return rc;
}

#if defined(__VMKLNX__)
struct bnx2_cpus_scratch_debug {
	u32	offset;		/*  Scratch pad offset to firmware version */
	char 	*name;		/*  Name of the CPU */
};

#define BNX2_SCRATCH_FW_VERSION_OFFSET		0x10
#define BNX2_TPAT_SCRATCH_FW_VERSION_OFFSET	0x410

static void
bnx2_print_fw_versions(struct bnx2 *bp)
{
	/*  Array of the firmware offset's + CPU strings */
	const struct bnx2_cpus_scratch_debug cpus_scratch[] = {
		{ .offset = BNX2_TXP_SCRATCH + BNX2_SCRATCH_FW_VERSION_OFFSET,
		  .name   = "TXP" },
		{ .offset = BNX2_TPAT_SCRATCH +
			    BNX2_TPAT_SCRATCH_FW_VERSION_OFFSET,
		  .name   = "TPAT" },
		{ .offset = BNX2_RXP_SCRATCH + BNX2_SCRATCH_FW_VERSION_OFFSET,
		  .name   = "RXP" },
		{ .offset = BNX2_COM_SCRATCH + BNX2_SCRATCH_FW_VERSION_OFFSET,
		  .name   = "COM" },
		{ .offset = BNX2_CP_SCRATCH + BNX2_SCRATCH_FW_VERSION_OFFSET,
		  .name   = "CP" },
		/* There is no versioning for MCP firmware */
	};
	int i;

	netdev_info(bp->dev, "CPU fw versions: ");
	for (i = 0; i < ARRAY_SIZE(cpus_scratch); i++) {
		/*  The FW versions are 11 bytes long + 1 extra byte for
		 *  the NULL termination */
		char version[12];
		int j;

		/*  Copy 4 bytes at a time */
		for (j = 0; j < sizeof(version); j += 4) {
			u32 val;

			val = bnx2_reg_rd_ind(bp, cpus_scratch[i].offset + j);
			val = be32_to_cpu(val);
			memcpy(&version[j], &val, sizeof(val));
		}

		/*  Force a NULL terminiated string */
		version[11] = '\0';

		printk("%s: '%s' ", cpus_scratch[i].name, version);
	}
	printk("\n");
}
#endif

static u32
rv2p_fw_fixup(u32 rv2p_proc, int idx, u32 loc, u32 rv2p_code)
{
	switch (idx) {
	case RV2P_P1_FIXUP_PAGE_SIZE_IDX:
		rv2p_code &= ~RV2P_BD_PAGE_SIZE_MSK;
		rv2p_code |= RV2P_BD_PAGE_SIZE;
		break;
	}
	return rv2p_code;
}

static void
load_rv2p_fw(struct bnx2 *bp, __le32 *rv2p_code, u32 rv2p_code_len,
	u32 rv2p_proc, u32 fixup_loc)
{
	__le32 *rv2p_code_start = rv2p_code;
	int i;
	u32 val, cmd, addr;

	if (rv2p_proc == RV2P_PROC1) {
		cmd = BNX2_RV2P_PROC1_ADDR_CMD_RDWR;
		addr = BNX2_RV2P_PROC1_ADDR_CMD;
	} else {
		cmd = BNX2_RV2P_PROC2_ADDR_CMD_RDWR;
		addr = BNX2_RV2P_PROC2_ADDR_CMD;
	}

	for (i = 0; i < rv2p_code_len; i += 8) {
		REG_WR(bp, BNX2_RV2P_INSTR_HIGH, le32_to_cpu(*rv2p_code));
		rv2p_code++;
		REG_WR(bp, BNX2_RV2P_INSTR_LOW, le32_to_cpu(*rv2p_code));
		rv2p_code++;

		val = (i / 8) | cmd;
		REG_WR(bp, addr, val);
	}

	rv2p_code = rv2p_code_start;
	if (fixup_loc && ((fixup_loc * 4) < rv2p_code_len)) {
		u32 code;

		code = le32_to_cpu(*(rv2p_code + fixup_loc - 1));
		REG_WR(bp, BNX2_RV2P_INSTR_HIGH, code);
		code = le32_to_cpu(*(rv2p_code + fixup_loc));
		code = rv2p_fw_fixup(rv2p_proc, 0, fixup_loc, code);
		REG_WR(bp, BNX2_RV2P_INSTR_LOW, code);

		val = (fixup_loc / 2) | cmd;
		REG_WR(bp, addr, val);
	}

	/* Reset the processor, un-stall is done later. */
	if (rv2p_proc == RV2P_PROC1) {
		REG_WR(bp, BNX2_RV2P_COMMAND, BNX2_RV2P_COMMAND_PROC1_RESET);
	}
	else {
		REG_WR(bp, BNX2_RV2P_COMMAND, BNX2_RV2P_COMMAND_PROC2_RESET);
	}
}

static int
load_cpu_fw(struct bnx2 *bp, const struct cpu_reg *cpu_reg, struct fw_info *fw)
{
	u32 offset;
	u32 val;
	int rc;

	/* Halt the CPU. */
	val = bnx2_reg_rd_ind(bp, cpu_reg->mode);
	val |= cpu_reg->mode_value_halt;
	bnx2_reg_wr_ind(bp, cpu_reg->mode, val);
	bnx2_reg_wr_ind(bp, cpu_reg->state, cpu_reg->state_value_clear);

	/* Load the Text area. */
	offset = cpu_reg->spad_base + (fw->text_addr - cpu_reg->mips_view_base);

	if (fw->gz_text) {
		u32 text_len;
		void *text;

		rc = bnx2_gunzip(bp, fw->gz_text, fw->gz_text_len, &text,
				 &text_len);
		if (rc)
			return rc;

		fw->text = text;
	}
	if (fw->text) {
		int j;
		for (j = 0; j < (fw->text_len / 4); j++, offset += 4) {
			bnx2_reg_wr_ind(bp, offset, le32_to_cpu(fw->text[j]));
	        }
	}

	/* Load the Data area. */
	offset = cpu_reg->spad_base + (fw->data_addr - cpu_reg->mips_view_base);
	if (fw->data) {
		int j;

		for (j = 0; j < (fw->data_len / 4); j++, offset += 4) {
			bnx2_reg_wr_ind(bp, offset, fw->data[j]);
		}
	}

	/* Load the SBSS area. */
	offset = cpu_reg->spad_base + (fw->sbss_addr - cpu_reg->mips_view_base);
	if (fw->sbss_len) {
		int j;

		for (j = 0; j < (fw->sbss_len / 4); j++, offset += 4) {
			bnx2_reg_wr_ind(bp, offset, 0);
		}
	}

	/* Load the BSS area. */
	offset = cpu_reg->spad_base + (fw->bss_addr - cpu_reg->mips_view_base);
	if (fw->bss_len) {
		int j;

		for (j = 0; j < (fw->bss_len/4); j++, offset += 4) {
			bnx2_reg_wr_ind(bp, offset, 0);
		}
	}

	/* Load the Read-Only area. */
	offset = cpu_reg->spad_base +
		(fw->rodata_addr - cpu_reg->mips_view_base);
	if (fw->rodata) {
		int j;

		for (j = 0; j < (fw->rodata_len / 4); j++, offset += 4) {
			bnx2_reg_wr_ind(bp, offset, fw->rodata[j]);
		}
	}

	/* Clear the pre-fetch instruction. */
	bnx2_reg_wr_ind(bp, cpu_reg->inst, 0);
	bnx2_reg_wr_ind(bp, cpu_reg->pc, fw->start_addr);

	/* Start the CPU. */
	val = bnx2_reg_rd_ind(bp, cpu_reg->mode);
	val &= ~cpu_reg->mode_value_halt;
	bnx2_reg_wr_ind(bp, cpu_reg->state, cpu_reg->state_value_clear);
	bnx2_reg_wr_ind(bp, cpu_reg->mode, val);

	return 0;
}

static int
bnx2_init_cpus(struct bnx2 *bp)
{
	struct fw_info *fw;
	int rc = 0, rv2p_len;
	void *text;
	const void *rv2p;
	u32 text_len, fixup_loc;

	if ((rc = bnx2_gunzip_init(bp)) != 0)
		return rc;

	/* Initialize the RV2P processor. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		if ((CHIP_ID(bp) == CHIP_ID_5709_A0) ||
		    (CHIP_ID(bp) == CHIP_ID_5709_A1)) {
			rv2p = bnx2_xi90_rv2p_proc1;
			rv2p_len = sizeof(bnx2_xi90_rv2p_proc1);
			fixup_loc = XI90_RV2P_PROC1_MAX_BD_PAGE_LOC;
		} else {
			rv2p = bnx2_xi_rv2p_proc1;
			rv2p_len = sizeof(bnx2_xi_rv2p_proc1);
			fixup_loc = XI_RV2P_PROC1_MAX_BD_PAGE_LOC;
		}
	} else {
		rv2p = bnx2_rv2p_proc1;
		rv2p_len = sizeof(bnx2_rv2p_proc1);
		fixup_loc = RV2P_PROC1_MAX_BD_PAGE_LOC;
	}
	rc = bnx2_gunzip(bp, rv2p, rv2p_len, &text, &text_len);
	if (rc)
		goto init_cpu_err;

	load_rv2p_fw(bp, text, text_len, RV2P_PROC1, fixup_loc);

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		if ((CHIP_ID(bp) == CHIP_ID_5709_A0) ||
		    (CHIP_ID(bp) == CHIP_ID_5709_A1)) {
			rv2p = bnx2_xi90_rv2p_proc2;
			rv2p_len = sizeof(bnx2_xi90_rv2p_proc2);
			fixup_loc = XI90_RV2P_PROC2_MAX_BD_PAGE_LOC;
		} else {
			rv2p = bnx2_xi_rv2p_proc2;
			rv2p_len = sizeof(bnx2_xi_rv2p_proc2);
			fixup_loc = XI_RV2P_PROC2_MAX_BD_PAGE_LOC;
		}
	} else {
		rv2p = bnx2_rv2p_proc2;
		rv2p_len = sizeof(bnx2_rv2p_proc2);
		fixup_loc = RV2P_PROC2_MAX_BD_PAGE_LOC;
	}
	rc = bnx2_gunzip(bp, rv2p, rv2p_len, &text, &text_len);
	if (rc)
		goto init_cpu_err;

	load_rv2p_fw(bp, text, text_len, RV2P_PROC2, fixup_loc);

	/* Initialize the RX Processor. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		fw = &bnx2_rxp_fw_09;
	else
		fw = &bnx2_rxp_fw_06;

	rc = load_cpu_fw(bp, &cpu_reg_rxp, fw);
	if (rc)
		goto init_cpu_err;

	/* Initialize the TX Processor. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		fw = &bnx2_txp_fw_09;
	else
		fw = &bnx2_txp_fw_06;

	rc = load_cpu_fw(bp, &cpu_reg_txp, fw);
	if (rc)
		goto init_cpu_err;

	/* Initialize the TX Patch-up Processor. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		fw = &bnx2_tpat_fw_09;
	else
		fw = &bnx2_tpat_fw_06;

	rc = load_cpu_fw(bp, &cpu_reg_tpat, fw);
	if (rc)
		goto init_cpu_err;

	/* Initialize the Completion Processor. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		fw = &bnx2_com_fw_09;
	else
		fw = &bnx2_com_fw_06;

	rc = load_cpu_fw(bp, &cpu_reg_com, fw);
	if (rc)
		goto init_cpu_err;

	/* Initialize the Command Processor. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		fw = &bnx2_cp_fw_09;
	else
		fw = &bnx2_cp_fw_06;

	rc = load_cpu_fw(bp, &cpu_reg_cp, fw);
	if (rc)
		goto init_cpu_err;

#if defined(__VMKLNX__)
	bnx2_print_fw_versions(bp);
#endif

init_cpu_err:
	bnx2_gunzip_end(bp);
	return rc;
}

static int
bnx2_set_power_state(struct bnx2 *bp, pci_power_t state)
{
	u16 pmcsr;

	pci_read_config_word(bp->pdev, bp->pm_cap + PCI_PM_CTRL, &pmcsr);

	switch (state) {
	case PCI_D0: {
		u32 val;

		pci_write_config_word(bp->pdev, bp->pm_cap + PCI_PM_CTRL,
			(pmcsr & ~PCI_PM_CTRL_STATE_MASK) |
			PCI_PM_CTRL_PME_STATUS);

		if (pmcsr & PCI_PM_CTRL_STATE_MASK)
			/* delay required during transition out of D3hot */
			bnx2_msleep(20);

		val = REG_RD(bp, BNX2_EMAC_MODE);
		val |= BNX2_EMAC_MODE_MPKT_RCVD | BNX2_EMAC_MODE_ACPI_RCVD;
		val &= ~BNX2_EMAC_MODE_MPKT;
		REG_WR(bp, BNX2_EMAC_MODE, val);

		val = REG_RD(bp, BNX2_RPM_CONFIG);
		val &= ~BNX2_RPM_CONFIG_ACPI_ENA;
		REG_WR(bp, BNX2_RPM_CONFIG, val);
		break;
	}
	case PCI_D3hot: {
		int i;
		u32 val, wol_msg;

		if (bp->wol) {
			u32 advertising;
			u8 autoneg;

			autoneg = bp->autoneg;
			advertising = bp->advertising;

			if (bp->phy_port == PORT_TP) {
				bp->autoneg = AUTONEG_SPEED;
				bp->advertising = ADVERTISED_10baseT_Half |
					ADVERTISED_10baseT_Full |
					ADVERTISED_100baseT_Half |
					ADVERTISED_100baseT_Full |
					ADVERTISED_Autoneg;
			}

			spin_lock_bh(&bp->phy_lock);
			bnx2_setup_phy(bp, bp->phy_port);
			spin_unlock_bh(&bp->phy_lock);

			bp->autoneg = autoneg;
			bp->advertising = advertising;

			bnx2_set_mac_addr(bp, bp->dev->dev_addr, 0);

			val = REG_RD(bp, BNX2_EMAC_MODE);

			/* Enable port mode. */
			val &= ~BNX2_EMAC_MODE_PORT;
			val |= BNX2_EMAC_MODE_MPKT_RCVD |
			       BNX2_EMAC_MODE_ACPI_RCVD |
			       BNX2_EMAC_MODE_MPKT;
			if (bp->phy_port == PORT_TP)
				val |= BNX2_EMAC_MODE_PORT_MII;
			else {
				val |= BNX2_EMAC_MODE_PORT_GMII;
				if (bp->line_speed == SPEED_2500)
					val |= BNX2_EMAC_MODE_25G_MODE;
			}

			REG_WR(bp, BNX2_EMAC_MODE, val);

			/* receive all multicast */
			for (i = 0; i < NUM_MC_HASH_REGISTERS; i++) {
				REG_WR(bp, BNX2_EMAC_MULTICAST_HASH0 + (i * 4),
				       0xffffffff);
			}
			REG_WR(bp, BNX2_EMAC_RX_MODE,
			       BNX2_EMAC_RX_MODE_SORT_MODE);

			val = 1 | BNX2_RPM_SORT_USER0_BC_EN |
			      BNX2_RPM_SORT_USER0_MC_EN;
			REG_WR(bp, BNX2_RPM_SORT_USER0, 0x0);
			REG_WR(bp, BNX2_RPM_SORT_USER0, val);
			REG_WR(bp, BNX2_RPM_SORT_USER0, val |
			       BNX2_RPM_SORT_USER0_ENA);

			/* Need to enable EMAC and RPM for WOL. */
			REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS,
			       BNX2_MISC_ENABLE_SET_BITS_RX_PARSER_MAC_ENABLE |
			       BNX2_MISC_ENABLE_SET_BITS_TX_HEADER_Q_ENABLE |
			       BNX2_MISC_ENABLE_SET_BITS_EMAC_ENABLE);

			val = REG_RD(bp, BNX2_RPM_CONFIG);
			val &= ~BNX2_RPM_CONFIG_ACPI_ENA;
			REG_WR(bp, BNX2_RPM_CONFIG, val);

			wol_msg = BNX2_DRV_MSG_CODE_SUSPEND_WOL;
		}
		else {
			wol_msg = BNX2_DRV_MSG_CODE_SUSPEND_NO_WOL;
		}

		if (!(bp->flags & BNX2_FLAG_NO_WOL))
			bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT3 | wol_msg,
				     1, 0);

		pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
		if ((CHIP_ID(bp) == CHIP_ID_5706_A0) ||
		    (CHIP_ID(bp) == CHIP_ID_5706_A1)) {

			if (bp->wol)
				pmcsr |= 3;
		}
		else {
			pmcsr |= 3;
		}
		if (bp->wol) {
			pmcsr |= PCI_PM_CTRL_PME_ENABLE;
		}
		pci_write_config_word(bp->pdev, bp->pm_cap + PCI_PM_CTRL,
				      pmcsr);

		/* No more memory access after this point until
		 * device is brought back to D0.
		 */
		udelay(50);
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static int
bnx2_acquire_nvram_lock(struct bnx2 *bp)
{
	u32 val;
	int j;

	/* Request access to the flash interface. */
	REG_WR(bp, BNX2_NVM_SW_ARB, BNX2_NVM_SW_ARB_ARB_REQ_SET2);
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		val = REG_RD(bp, BNX2_NVM_SW_ARB);
		if (val & BNX2_NVM_SW_ARB_ARB_ARB2)
			break;

		udelay(5);
	}

	if (j >= NVRAM_TIMEOUT_COUNT)
		return -EBUSY;

	return 0;
}

static int
bnx2_release_nvram_lock(struct bnx2 *bp)
{
	int j;
	u32 val;

	/* Relinquish nvram interface. */
	REG_WR(bp, BNX2_NVM_SW_ARB, BNX2_NVM_SW_ARB_ARB_REQ_CLR2);

	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		val = REG_RD(bp, BNX2_NVM_SW_ARB);
		if (!(val & BNX2_NVM_SW_ARB_ARB_ARB2))
			break;

		udelay(5);
	}

	if (j >= NVRAM_TIMEOUT_COUNT)
		return -EBUSY;

	return 0;
}


static int
bnx2_enable_nvram_write(struct bnx2 *bp)
{
	u32 val;

	val = REG_RD(bp, BNX2_MISC_CFG);
	REG_WR(bp, BNX2_MISC_CFG, val | BNX2_MISC_CFG_NVM_WR_EN_PCI);

	if (bp->flash_info->flags & BNX2_NV_WREN) {
		int j;

		REG_WR(bp, BNX2_NVM_COMMAND, BNX2_NVM_COMMAND_DONE);
		REG_WR(bp, BNX2_NVM_COMMAND,
		       BNX2_NVM_COMMAND_WREN | BNX2_NVM_COMMAND_DOIT);

		for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
			udelay(5);

			val = REG_RD(bp, BNX2_NVM_COMMAND);
			if (val & BNX2_NVM_COMMAND_DONE)
				break;
		}

		if (j >= NVRAM_TIMEOUT_COUNT)
			return -EBUSY;
	}
	return 0;
}

static void
bnx2_disable_nvram_write(struct bnx2 *bp)
{
	u32 val;

	val = REG_RD(bp, BNX2_MISC_CFG);
	REG_WR(bp, BNX2_MISC_CFG, val & ~BNX2_MISC_CFG_NVM_WR_EN);
}


static void
bnx2_enable_nvram_access(struct bnx2 *bp)
{
	u32 val;

	val = REG_RD(bp, BNX2_NVM_ACCESS_ENABLE);
	/* Enable both bits, even on read. */
	REG_WR(bp, BNX2_NVM_ACCESS_ENABLE,
	       val | BNX2_NVM_ACCESS_ENABLE_EN | BNX2_NVM_ACCESS_ENABLE_WR_EN);
}

static void
bnx2_disable_nvram_access(struct bnx2 *bp)
{
	u32 val;

	val = REG_RD(bp, BNX2_NVM_ACCESS_ENABLE);
	/* Disable both bits, even after read. */
	REG_WR(bp, BNX2_NVM_ACCESS_ENABLE,
		val & ~(BNX2_NVM_ACCESS_ENABLE_EN |
			BNX2_NVM_ACCESS_ENABLE_WR_EN));
}

static int
bnx2_nvram_erase_page(struct bnx2 *bp, u32 offset)
{
	u32 cmd;
	int j;

	if (bp->flash_info->flags & BNX2_NV_BUFFERED)
		/* Buffered flash, no erase needed */
		return 0;

	/* Build an erase command */
	cmd = BNX2_NVM_COMMAND_ERASE | BNX2_NVM_COMMAND_WR |
	      BNX2_NVM_COMMAND_DOIT;

	/* Need to clear DONE bit separately. */
	REG_WR(bp, BNX2_NVM_COMMAND, BNX2_NVM_COMMAND_DONE);

	/* Address of the NVRAM to read from. */
	REG_WR(bp, BNX2_NVM_ADDR, offset & BNX2_NVM_ADDR_NVM_ADDR_VALUE);

	/* Issue an erase command. */
	REG_WR(bp, BNX2_NVM_COMMAND, cmd);

	/* Wait for completion. */
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		u32 val;

		udelay(5);

		val = REG_RD(bp, BNX2_NVM_COMMAND);
		if (val & BNX2_NVM_COMMAND_DONE)
			break;
	}

	if (j >= NVRAM_TIMEOUT_COUNT)
		return -EBUSY;

	return 0;
}

static int
bnx2_nvram_read_dword(struct bnx2 *bp, u32 offset, u8 *ret_val, u32 cmd_flags)
{
	u32 cmd;
	int j;

	/* Build the command word. */
	cmd = BNX2_NVM_COMMAND_DOIT | cmd_flags;

	/* Calculate an offset of a buffered flash, not needed for 5709. */
	if (bp->flash_info->flags & BNX2_NV_TRANSLATE) {
		offset = ((offset / bp->flash_info->page_size) <<
			   bp->flash_info->page_bits) +
			  (offset % bp->flash_info->page_size);
	}

	/* Need to clear DONE bit separately. */
	REG_WR(bp, BNX2_NVM_COMMAND, BNX2_NVM_COMMAND_DONE);

	/* Address of the NVRAM to read from. */
	REG_WR(bp, BNX2_NVM_ADDR, offset & BNX2_NVM_ADDR_NVM_ADDR_VALUE);

	/* Issue a read command. */
	REG_WR(bp, BNX2_NVM_COMMAND, cmd);

	/* Wait for completion. */
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		u32 val;

		udelay(5);

		val = REG_RD(bp, BNX2_NVM_COMMAND);
		if (val & BNX2_NVM_COMMAND_DONE) {
			__be32 v = cpu_to_be32(REG_RD(bp, BNX2_NVM_READ));
			memcpy(ret_val, &v, 4);
			break;
		}
	}
	if (j >= NVRAM_TIMEOUT_COUNT)
		return -EBUSY;

	return 0;
}


static int
bnx2_nvram_write_dword(struct bnx2 *bp, u32 offset, u8 *val, u32 cmd_flags)
{
	u32 cmd;
	__be32 val32;
	int j;

	/* Build the command word. */
	cmd = BNX2_NVM_COMMAND_DOIT | BNX2_NVM_COMMAND_WR | cmd_flags;

	/* Calculate an offset of a buffered flash, not needed for 5709. */
	if (bp->flash_info->flags & BNX2_NV_TRANSLATE) {
		offset = ((offset / bp->flash_info->page_size) <<
			  bp->flash_info->page_bits) +
			 (offset % bp->flash_info->page_size);
	}

	/* Need to clear DONE bit separately. */
	REG_WR(bp, BNX2_NVM_COMMAND, BNX2_NVM_COMMAND_DONE);

	memcpy(&val32, val, 4);

	/* Write the data. */
	REG_WR(bp, BNX2_NVM_WRITE, be32_to_cpu(val32));

	/* Address of the NVRAM to write to. */
	REG_WR(bp, BNX2_NVM_ADDR, offset & BNX2_NVM_ADDR_NVM_ADDR_VALUE);

	/* Issue the write command. */
	REG_WR(bp, BNX2_NVM_COMMAND, cmd);

	/* Wait for completion. */
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		udelay(5);

		if (REG_RD(bp, BNX2_NVM_COMMAND) & BNX2_NVM_COMMAND_DONE)
			break;
	}
	if (j >= NVRAM_TIMEOUT_COUNT)
		return -EBUSY;

	return 0;
}

static int
bnx2_init_nvram(struct bnx2 *bp)
{
	u32 val;
	int j, entry_count, rc = 0;
	const struct flash_spec *flash;

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		bp->flash_info = &flash_5709;
		goto get_flash_size;
	}

	/* Determine the selected interface. */
	val = REG_RD(bp, BNX2_NVM_CFG1);

	entry_count = ARRAY_SIZE(flash_table);

	if (val & 0x40000000) {

		/* Flash interface has been reconfigured */
		for (j = 0, flash = &flash_table[0]; j < entry_count;
		     j++, flash++) {
			if ((val & FLASH_BACKUP_STRAP_MASK) ==
			    (flash->config1 & FLASH_BACKUP_STRAP_MASK)) {
				bp->flash_info = flash;
				break;
			}
		}
	}
	else {
		u32 mask;
		/* Not yet been reconfigured */

		if (val & (1 << 23))
			mask = FLASH_BACKUP_STRAP_MASK;
		else
			mask = FLASH_STRAP_MASK;

		for (j = 0, flash = &flash_table[0]; j < entry_count;
			j++, flash++) {

			if ((val & mask) == (flash->strapping & mask)) {
				bp->flash_info = flash;

				/* Request access to the flash interface. */
				if ((rc = bnx2_acquire_nvram_lock(bp)) != 0)
					return rc;

				/* Enable access to flash interface */
				bnx2_enable_nvram_access(bp);

				/* Reconfigure the flash interface */
				REG_WR(bp, BNX2_NVM_CFG1, flash->config1);
				REG_WR(bp, BNX2_NVM_CFG2, flash->config2);
				REG_WR(bp, BNX2_NVM_CFG3, flash->config3);
				REG_WR(bp, BNX2_NVM_WRITE1, flash->write1);

				/* Disable access to flash interface */
				bnx2_disable_nvram_access(bp);
				bnx2_release_nvram_lock(bp);

				break;
			}
		}
	} /* if (val & 0x40000000) */

	if (j == entry_count) {
		bp->flash_info = NULL;
		pr_alert("Unknown flash/EEPROM type\n");
		return -ENODEV;
	}

get_flash_size:
	val = bnx2_shmem_rd(bp, BNX2_SHARED_HW_CFG_CONFIG2);
	val &= BNX2_SHARED_HW_CFG2_NVM_SIZE_MASK;
	if (val)
		bp->flash_size = val;
	else
		bp->flash_size = bp->flash_info->total_size;

	return rc;
}

static int
bnx2_nvram_read(struct bnx2 *bp, u32 offset, u8 *ret_buf,
		int buf_size)
{
	int rc = 0;
	u32 cmd_flags, offset32, len32, extra;

	if (buf_size == 0)
		return 0;

	/* Request access to the flash interface. */
	if ((rc = bnx2_acquire_nvram_lock(bp)) != 0)
		return rc;

	/* Enable access to flash interface */
	bnx2_enable_nvram_access(bp);

	len32 = buf_size;
	offset32 = offset;
	extra = 0;

	cmd_flags = 0;

	if (offset32 & 3) {
		u8 buf[4];
		u32 pre_len;

		offset32 &= ~3;
		pre_len = 4 - (offset & 3);

		if (pre_len >= len32) {
			pre_len = len32;
			cmd_flags = BNX2_NVM_COMMAND_FIRST |
				    BNX2_NVM_COMMAND_LAST;
		}
		else {
			cmd_flags = BNX2_NVM_COMMAND_FIRST;
		}

		rc = bnx2_nvram_read_dword(bp, offset32, buf, cmd_flags);

		if (rc)
			return rc;

		memcpy(ret_buf, buf + (offset & 3), pre_len);

		offset32 += 4;
		ret_buf += pre_len;
		len32 -= pre_len;
	}
	if (len32 & 3) {
		extra = 4 - (len32 & 3);
		len32 = (len32 + 4) & ~3;
	}

	if (len32 == 4) {
		u8 buf[4];

		if (cmd_flags)
			cmd_flags = BNX2_NVM_COMMAND_LAST;
		else
			cmd_flags = BNX2_NVM_COMMAND_FIRST |
				    BNX2_NVM_COMMAND_LAST;

		rc = bnx2_nvram_read_dword(bp, offset32, buf, cmd_flags);

		memcpy(ret_buf, buf, 4 - extra);
	}
	else if (len32 > 0) {
		u8 buf[4];

		/* Read the first word. */
		if (cmd_flags)
			cmd_flags = 0;
		else
			cmd_flags = BNX2_NVM_COMMAND_FIRST;

		rc = bnx2_nvram_read_dword(bp, offset32, ret_buf, cmd_flags);

		/* Advance to the next dword. */
		offset32 += 4;
		ret_buf += 4;
		len32 -= 4;

		while (len32 > 4 && rc == 0) {
			rc = bnx2_nvram_read_dword(bp, offset32, ret_buf, 0);

			/* Advance to the next dword. */
			offset32 += 4;
			ret_buf += 4;
			len32 -= 4;
		}

		if (rc)
			return rc;

		cmd_flags = BNX2_NVM_COMMAND_LAST;
		rc = bnx2_nvram_read_dword(bp, offset32, buf, cmd_flags);

		memcpy(ret_buf, buf, 4 - extra);
	}

	/* Disable access to flash interface */
	bnx2_disable_nvram_access(bp);

	bnx2_release_nvram_lock(bp);

	return rc;
}

static int
bnx2_nvram_write(struct bnx2 *bp, u32 offset, u8 *data_buf,
		int buf_size)
{
	u32 written, offset32, len32;
	u8 *buf, start[4], end[4], *align_buf = NULL, *flash_buffer = NULL;
	int rc = 0;
	int align_start, align_end;

	buf = data_buf;
	offset32 = offset;
	len32 = buf_size;
	align_start = align_end = 0;

	if ((align_start = (offset32 & 3))) {
		offset32 &= ~3;
		len32 += align_start;
		if (len32 < 4)
			len32 = 4;
		if ((rc = bnx2_nvram_read(bp, offset32, start, 4)))
			return rc;
	}

	if (len32 & 3) {
		align_end = 4 - (len32 & 3);
		len32 += align_end;
		if ((rc = bnx2_nvram_read(bp, offset32 + len32 - 4, end, 4)))
			return rc;
	}

	if (align_start || align_end) {
		align_buf = kmalloc(len32, GFP_KERNEL);
		if (align_buf == NULL)
			return -ENOMEM;
		if (align_start) {
			memcpy(align_buf, start, 4);
		}
		if (align_end) {
			memcpy(align_buf + len32 - 4, end, 4);
		}
		memcpy(align_buf + align_start, data_buf, buf_size);
		buf = align_buf;
	}

	if (!(bp->flash_info->flags & BNX2_NV_BUFFERED)) {
		flash_buffer = kmalloc(264, GFP_KERNEL);
		if (flash_buffer == NULL) {
			rc = -ENOMEM;
			goto nvram_write_end;
		}
	}

	written = 0;
	while ((written < len32) && (rc == 0)) {
		u32 page_start, page_end, data_start, data_end;
		u32 addr, cmd_flags;
		int i;

	        /* Find the page_start addr */
		page_start = offset32 + written;
		page_start -= (page_start % bp->flash_info->page_size);
		/* Find the page_end addr */
		page_end = page_start + bp->flash_info->page_size;
		/* Find the data_start addr */
		data_start = (written == 0) ? offset32 : page_start;
		/* Find the data_end addr */
		data_end = (page_end > offset32 + len32) ?
			(offset32 + len32) : page_end;

		/* Request access to the flash interface. */
		if ((rc = bnx2_acquire_nvram_lock(bp)) != 0)
			goto nvram_write_end;

		/* Enable access to flash interface */
		bnx2_enable_nvram_access(bp);

		cmd_flags = BNX2_NVM_COMMAND_FIRST;
		if (!(bp->flash_info->flags & BNX2_NV_BUFFERED)) {
			int j;

			/* Read the whole page into the buffer
			 * (non-buffer flash only) */
			for (j = 0; j < bp->flash_info->page_size; j += 4) {
				if (j == (bp->flash_info->page_size - 4)) {
					cmd_flags |= BNX2_NVM_COMMAND_LAST;
				}
				rc = bnx2_nvram_read_dword(bp,
					page_start + j,
					&flash_buffer[j],
					cmd_flags);

				if (rc)
					goto nvram_write_end;

				cmd_flags = 0;
			}
		}

		/* Enable writes to flash interface (unlock write-protect) */
		if ((rc = bnx2_enable_nvram_write(bp)) != 0)
			goto nvram_write_end;

		/* Loop to write back the buffer data from page_start to
		 * data_start */
		i = 0;
		if (!(bp->flash_info->flags & BNX2_NV_BUFFERED)) {
			/* Erase the page */
			if ((rc = bnx2_nvram_erase_page(bp, page_start)) != 0)
				goto nvram_write_end;

			/* Re-enable the write again for the actual write */
			bnx2_enable_nvram_write(bp);

			for (addr = page_start; addr < data_start;
				addr += 4, i += 4) {

				rc = bnx2_nvram_write_dword(bp, addr,
					&flash_buffer[i], cmd_flags);

				if (rc != 0)
					goto nvram_write_end;

				cmd_flags = 0;
			}
		}

		/* Loop to write the new data from data_start to data_end */
		for (addr = data_start; addr < data_end; addr += 4, i += 4) {
			if ((addr == page_end - 4) ||
				((bp->flash_info->flags & BNX2_NV_BUFFERED) &&
				 (addr == data_end - 4))) {

				cmd_flags |= BNX2_NVM_COMMAND_LAST;
			}
			rc = bnx2_nvram_write_dword(bp, addr, buf,
				cmd_flags);

			if (rc != 0)
				goto nvram_write_end;

			cmd_flags = 0;
			buf += 4;
		}

		/* Loop to write back the buffer data from data_end
		 * to page_end */
		if (!(bp->flash_info->flags & BNX2_NV_BUFFERED)) {
			for (addr = data_end; addr < page_end;
				addr += 4, i += 4) {

				if (addr == page_end-4) {
					cmd_flags = BNX2_NVM_COMMAND_LAST;
                		}
				rc = bnx2_nvram_write_dword(bp, addr,
					&flash_buffer[i], cmd_flags);

				if (rc != 0)
					goto nvram_write_end;

				cmd_flags = 0;
			}
		}

		/* Disable writes to flash interface (lock write-protect) */
		bnx2_disable_nvram_write(bp);

		/* Disable access to flash interface */
		bnx2_disable_nvram_access(bp);
		bnx2_release_nvram_lock(bp);

		/* Increment written */
		written += data_end - data_start;
	}

nvram_write_end:
	kfree(flash_buffer);
	kfree(align_buf);
	return rc;
}

static void
bnx2_init_fw_cap(struct bnx2 *bp)
{
	u32 val, sig = 0;

	bp->phy_flags &= ~BNX2_PHY_FLAG_REMOTE_PHY_CAP;
	bp->flags &= ~BNX2_FLAG_CAN_KEEP_VLAN;

	if (!(bp->flags & BNX2_FLAG_ASF_ENABLE))
		bp->flags |= BNX2_FLAG_CAN_KEEP_VLAN;

	val = bnx2_shmem_rd(bp, BNX2_FW_CAP_MB);
	if ((val & BNX2_FW_CAP_SIGNATURE_MASK) != BNX2_FW_CAP_SIGNATURE)
		return;

	if ((val & BNX2_FW_CAP_CAN_KEEP_VLAN) == BNX2_FW_CAP_CAN_KEEP_VLAN) {
		bp->flags |= BNX2_FLAG_CAN_KEEP_VLAN;
		sig |= BNX2_DRV_ACK_CAP_SIGNATURE | BNX2_FW_CAP_CAN_KEEP_VLAN;
	}

	if ((bp->phy_flags & BNX2_PHY_FLAG_SERDES) &&
	    (val & BNX2_FW_CAP_REMOTE_PHY_CAPABLE)) {
		u32 link;

		bp->phy_flags |= BNX2_PHY_FLAG_REMOTE_PHY_CAP;

		link = bnx2_shmem_rd(bp, BNX2_LINK_STATUS);
		if (link & BNX2_LINK_STATUS_SERDES_LINK)
			bp->phy_port = PORT_FIBRE;
		else
			bp->phy_port = PORT_TP;

		sig |= BNX2_DRV_ACK_CAP_SIGNATURE |
		       BNX2_FW_CAP_REMOTE_PHY_CAPABLE;
	}

	if (netif_running(bp->dev) && sig)
		bnx2_shmem_wr(bp, BNX2_DRV_ACK_CAP_MB, sig);
}

#if defined(__VMKLNX__)
static void
bnx2_setup_msix_tbl_cfg(struct bnx2 *bp)
{
	bnx2_reg_wr_ind_cfg(bp, BNX2_PCI_GRC_WINDOW_ADDR,
			    BNX2_PCI_GRC_WINDOW_ADDR_SEP_WIN);

	bnx2_reg_wr_ind_cfg(bp, BNX2_PCI_GRC_WINDOW2_ADDR,
			    BNX2_MSIX_TABLE_ADDR);
	bnx2_reg_wr_ind_cfg(bp, BNX2_PCI_GRC_WINDOW3_ADDR, BNX2_MSIX_PBA_ADDR);
}
#endif /* defined(__VMKLNX__) */

static void
bnx2_setup_msix_tbl(struct bnx2 *bp)
{
	REG_WR(bp, BNX2_PCI_GRC_WINDOW_ADDR, BNX2_PCI_GRC_WINDOW_ADDR_SEP_WIN);

	REG_WR(bp, BNX2_PCI_GRC_WINDOW2_ADDR, BNX2_MSIX_TABLE_ADDR);
	REG_WR(bp, BNX2_PCI_GRC_WINDOW3_ADDR, BNX2_MSIX_PBA_ADDR);
}

static int
bnx2_reset_chip(struct bnx2 *bp, u32 reset_code)
{
	u32 val;
	int i, rc = 0;
	u8 old_port;

	/* Wait for the current PCI transaction to complete before
	 * issuing a reset. */
	if ((CHIP_NUM(bp) == CHIP_NUM_5706) ||
	    (CHIP_NUM(bp) == CHIP_NUM_5708)) {
		REG_WR(bp, BNX2_MISC_ENABLE_CLR_BITS,
		       BNX2_MISC_ENABLE_CLR_BITS_TX_DMA_ENABLE |
		       BNX2_MISC_ENABLE_CLR_BITS_DMA_ENGINE_ENABLE |
		       BNX2_MISC_ENABLE_CLR_BITS_RX_DMA_ENABLE |
		       BNX2_MISC_ENABLE_CLR_BITS_HOST_COALESCE_ENABLE);
		val = REG_RD(bp, BNX2_MISC_ENABLE_CLR_BITS);
		udelay(5);
	} else {  /* 5709 */
		val = REG_RD(bp, BNX2_MISC_NEW_CORE_CTL);
		val &= ~BNX2_MISC_NEW_CORE_CTL_DMA_ENABLE;
		REG_WR(bp, BNX2_MISC_NEW_CORE_CTL, val);
		val = REG_RD(bp, BNX2_MISC_NEW_CORE_CTL);

		for (i = 0; i < 100; i++) {
			bnx2_msleep(1);
			val = REG_RD(bp, BNX2_PCICFG_DEVICE_CONTROL);
			if (!(val & BNX2_PCICFG_DEVICE_STATUS_NO_PEND))
				break;
		}
	}

	/* Wait for the firmware to tell us it is ok to issue a reset. */
	bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT0 | reset_code, 1, 1);

	/* Deposit a driver reset signature so the firmware knows that
	 * this is a soft reset. */
	bnx2_shmem_wr(bp, BNX2_DRV_RESET_SIGNATURE,
		      BNX2_DRV_RESET_SIGNATURE_MAGIC);

#if defined(__VMKLNX__)
#if (LINUX_VERSION_CODE >= 0x020611)
	pci_save_state(bp->pdev);
#endif
#endif /* defined(__VMKLNX__) */

	/* Do a dummy read to force the chip to complete all current transaction
	 * before we issue a reset. */
	val = REG_RD(bp, BNX2_MISC_ID);

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		REG_WR(bp, BNX2_MISC_COMMAND, BNX2_MISC_COMMAND_SW_RESET);
		REG_RD(bp, BNX2_MISC_COMMAND);
		udelay(5);

		val = BNX2_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
		      BNX2_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP;

		REG_WR(bp, BNX2_PCICFG_MISC_CONFIG, val);

	} else {
		val = BNX2_PCICFG_MISC_CONFIG_CORE_RST_REQ |
		      BNX2_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
		      BNX2_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP;

		/* Chip reset. */
		REG_WR(bp, BNX2_PCICFG_MISC_CONFIG, val);

		/* Reading back any register after chip reset will hang the
		 * bus on 5706 A0 and A1.  The msleep below provides plenty
		 * of margin for write posting.
		 */
		if ((CHIP_ID(bp) == CHIP_ID_5706_A0) ||
		    (CHIP_ID(bp) == CHIP_ID_5706_A1))
			bnx2_msleep(20);

		/* Reset takes approximate 30 usec */
		for (i = 0; i < 10; i++) {
			val = REG_RD(bp, BNX2_PCICFG_MISC_CONFIG);
			if ((val & (BNX2_PCICFG_MISC_CONFIG_CORE_RST_REQ |
				    BNX2_PCICFG_MISC_CONFIG_CORE_RST_BSY)) == 0)
				break;
			udelay(10);
		}

		if (val & (BNX2_PCICFG_MISC_CONFIG_CORE_RST_REQ |
			   BNX2_PCICFG_MISC_CONFIG_CORE_RST_BSY)) {
			pr_err("Chip reset did not complete\n");
			return -EBUSY;
		}
	}

#if defined(__VMKLNX__)
	if (bp->flags & BNX2_FLAG_USING_MSIX)
		bnx2_setup_msix_tbl_cfg(bp);

#if (LINUX_VERSION_CODE >= 0x020611)
	pci_restore_state(bp->pdev);
#endif
#endif /* defined(__VMKLNX__) */

	/* Make sure byte swapping is properly configured. */
	val = REG_RD(bp, BNX2_PCI_SWAP_DIAG0);
	if (val != 0x01020304) {
		pr_err("Chip not in correct endian mode\n");
		return -ENODEV;
	}

	/* Wait for the firmware to finish its initialization. */
	rc = bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT1 | reset_code, 1, 0);
	if (rc)
		return rc;

	spin_lock_bh(&bp->phy_lock);
	old_port = bp->phy_port;
	bnx2_init_fw_cap(bp);
	if ((bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP) &&
	    old_port != bp->phy_port)
		bnx2_set_default_remote_link(bp);
	spin_unlock_bh(&bp->phy_lock);

	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		/* Adjust the voltage regular to two steps lower.  The default
		 * of this register is 0x0000000e. */
		REG_WR(bp, BNX2_MISC_VREG_CONTROL, 0x000000fa);

		/* Remove bad rbuf memory from the free pool. */
		rc = bnx2_alloc_bad_rbuf(bp);
	}

	if (bp->flags & BNX2_FLAG_USING_MSIX) {
		bnx2_setup_msix_tbl(bp);
		/* Prevent MSIX table reads and write from timing out */
		REG_WR(bp, BNX2_MISC_ECO_HW_CTL,
			BNX2_MISC_ECO_HW_CTL_LARGE_GRC_TMOUT_EN);
	}

	return rc;
}

static int
bnx2_init_chip(struct bnx2 *bp)
{
	u32 val, mtu;
	int rc, i;

	/* Make sure the interrupt is not active. */
	REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD, BNX2_PCICFG_INT_ACK_CMD_MASK_INT);

	val = BNX2_DMA_CONFIG_DATA_BYTE_SWAP |
	      BNX2_DMA_CONFIG_DATA_WORD_SWAP |
#ifdef __BIG_ENDIAN
	      BNX2_DMA_CONFIG_CNTL_BYTE_SWAP |
#endif
	      BNX2_DMA_CONFIG_CNTL_WORD_SWAP |
	      DMA_READ_CHANS << 12 |
	      DMA_WRITE_CHANS << 16;

	val |= (0x2 << 20) | (1 << 11);

	if ((bp->flags & BNX2_FLAG_PCIX) && (bp->bus_speed_mhz == 133))
		val |= (1 << 23);

	if ((CHIP_NUM(bp) == CHIP_NUM_5706) &&
	    (CHIP_ID(bp) != CHIP_ID_5706_A0) && !(bp->flags & BNX2_FLAG_PCIX))
		val |= BNX2_DMA_CONFIG_CNTL_PING_PONG_DMA;

	REG_WR(bp, BNX2_DMA_CONFIG, val);

	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		val = REG_RD(bp, BNX2_TDMA_CONFIG);
		val |= BNX2_TDMA_CONFIG_ONE_DMA;
		REG_WR(bp, BNX2_TDMA_CONFIG, val);
	}

	if (bp->flags & BNX2_FLAG_PCIX) {
		u16 val16;

		pci_read_config_word(bp->pdev, bp->pcix_cap + PCI_X_CMD,
				     &val16);
		pci_write_config_word(bp->pdev, bp->pcix_cap + PCI_X_CMD,
				      val16 & ~PCI_X_CMD_ERO);
	}

	REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS,
	       BNX2_MISC_ENABLE_SET_BITS_HOST_COALESCE_ENABLE |
	       BNX2_MISC_ENABLE_STATUS_BITS_RX_V2P_ENABLE |
	       BNX2_MISC_ENABLE_STATUS_BITS_CONTEXT_ENABLE);

	/* Initialize context mapping and zero out the quick contexts.  The
	 * context block must have already been enabled. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		rc = bnx2_init_5709_context(bp);
		if (rc)
			return rc;
	} else
		bnx2_init_context(bp);

	if ((rc = bnx2_init_cpus(bp)) != 0)
		return rc;

	bnx2_init_nvram(bp);

	bnx2_set_mac_addr(bp, bp->dev->dev_addr, 0);

	val = REG_RD(bp, BNX2_MQ_CONFIG);
	val &= ~BNX2_MQ_CONFIG_KNL_BYP_BLK_SIZE;
	val |= BNX2_MQ_CONFIG_KNL_BYP_BLK_SIZE_256;
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		val |= BNX2_MQ_CONFIG_BIN_MQ_MODE;
		if (CHIP_REV(bp) == CHIP_REV_Ax)
			val |= BNX2_MQ_CONFIG_HALT_DIS;
	}

	REG_WR(bp, BNX2_MQ_CONFIG, val);

	val = 0x10000 + (MAX_CID_CNT * MB_KERNEL_CTX_SIZE);
	REG_WR(bp, BNX2_MQ_KNL_BYP_WIND_START, val);
	REG_WR(bp, BNX2_MQ_KNL_WIND_END, val);

	val = (BCM_PAGE_BITS - 8) << 24;
	REG_WR(bp, BNX2_RV2P_CONFIG, val);

	/* Configure page size. */
	val = REG_RD(bp, BNX2_TBDR_CONFIG);
	val &= ~BNX2_TBDR_CONFIG_PAGE_SIZE;
	val |= (BCM_PAGE_BITS - 8) << 24 | 0x40;
	REG_WR(bp, BNX2_TBDR_CONFIG, val);

	val = bp->mac_addr[0] +
	      (bp->mac_addr[1] << 8) +
	      (bp->mac_addr[2] << 16) +
	      bp->mac_addr[3] +
	      (bp->mac_addr[4] << 8) +
	      (bp->mac_addr[5] << 16);
	REG_WR(bp, BNX2_EMAC_BACKOFF_SEED, val);

	/* Program the MTU.  Also include 4 bytes for CRC32. */
	mtu = bp->dev->mtu;
	val = mtu + ETH_HLEN + ETH_FCS_LEN;
	if (val > (MAX_ETHERNET_PACKET_SIZE + 4))
		val |= BNX2_EMAC_RX_MTU_SIZE_JUMBO_ENA;
	REG_WR(bp, BNX2_EMAC_RX_MTU_SIZE, val);

	if (mtu < 1500)
		mtu = 1500;

	bnx2_reg_wr_ind(bp, BNX2_RBUF_CONFIG, BNX2_RBUF_CONFIG_VAL(mtu));
	bnx2_reg_wr_ind(bp, BNX2_RBUF_CONFIG2, BNX2_RBUF_CONFIG2_VAL(mtu));
	bnx2_reg_wr_ind(bp, BNX2_RBUF_CONFIG3, BNX2_RBUF_CONFIG3_VAL(mtu));

	memset(bp->bnx2_napi[0].status_blk.msi, 0, bp->status_stats_size);
	for (i = 0; i < BNX2_MAX_MSIX_VEC; i++)
		bp->bnx2_napi[i].last_status_idx = 0;

	bp->idle_chk_status_idx = 0xffff;

	bp->rx_mode = BNX2_EMAC_RX_MODE_SORT_MODE;

	/* Set up how to generate a link change interrupt. */
	REG_WR(bp, BNX2_EMAC_ATTENTION_ENA, BNX2_EMAC_ATTENTION_ENA_LINK);

	REG_WR(bp, BNX2_HC_STATUS_ADDR_L,
	       (u64) bp->status_blk_mapping & 0xffffffff);
	REG_WR(bp, BNX2_HC_STATUS_ADDR_H, (u64) bp->status_blk_mapping >> 32);

	REG_WR(bp, BNX2_HC_STATISTICS_ADDR_L,
	       (u64) bp->stats_blk_mapping & 0xffffffff);
	REG_WR(bp, BNX2_HC_STATISTICS_ADDR_H,
	       (u64) bp->stats_blk_mapping >> 32);

	REG_WR(bp, BNX2_HC_TX_QUICK_CONS_TRIP,
	       (bp->tx_quick_cons_trip_int << 16) | bp->tx_quick_cons_trip);

	REG_WR(bp, BNX2_HC_RX_QUICK_CONS_TRIP,
	       (bp->rx_quick_cons_trip_int << 16) | bp->rx_quick_cons_trip);

	REG_WR(bp, BNX2_HC_COMP_PROD_TRIP,
	       (bp->comp_prod_trip_int << 16) | bp->comp_prod_trip);

	REG_WR(bp, BNX2_HC_TX_TICKS, (bp->tx_ticks_int << 16) | bp->tx_ticks);

	REG_WR(bp, BNX2_HC_RX_TICKS, (bp->rx_ticks_int << 16) | bp->rx_ticks);

	REG_WR(bp, BNX2_HC_COM_TICKS,
	       (bp->com_ticks_int << 16) | bp->com_ticks);

	REG_WR(bp, BNX2_HC_CMD_TICKS,
	       (bp->cmd_ticks_int << 16) | bp->cmd_ticks);

	if (bp->flags & BNX2_FLAG_BROKEN_STATS)
		REG_WR(bp, BNX2_HC_STATS_TICKS, 0);
	else
		REG_WR(bp, BNX2_HC_STATS_TICKS, bp->stats_ticks);
	REG_WR(bp, BNX2_HC_STAT_COLLECT_TICKS, 0xbb8);  /* 3ms */

	if (CHIP_ID(bp) == CHIP_ID_5706_A1)
		val = BNX2_HC_CONFIG_COLLECT_STATS;
	else {
		val = BNX2_HC_CONFIG_RX_TMR_MODE | BNX2_HC_CONFIG_TX_TMR_MODE |
		      BNX2_HC_CONFIG_COLLECT_STATS;
	}

	if (bp->flags & BNX2_FLAG_USING_MSIX) {
		REG_WR(bp, BNX2_HC_MSIX_BIT_VECTOR,
		       BNX2_HC_MSIX_BIT_VECTOR_VAL);

		val |= BNX2_HC_CONFIG_SB_ADDR_INC_128B;
	}

	if (bp->flags & BNX2_FLAG_ONE_SHOT_MSI)
		val |= BNX2_HC_CONFIG_ONE_SHOT | BNX2_HC_CONFIG_USE_INT_PARAM;

	REG_WR(bp, BNX2_HC_CONFIG, val);

	if (bp->rx_ticks < 25)
		bnx2_reg_wr_ind(bp, BNX2_FW_RX_LOW_LATENCY, 1);
	else
		bnx2_reg_wr_ind(bp, BNX2_FW_RX_LOW_LATENCY, 0);

	for (i = 1; i < bp->irq_nvecs; i++) {
		u32 base = ((i - 1) * BNX2_HC_SB_CONFIG_SIZE) +
			   BNX2_HC_SB_CONFIG_1;

		REG_WR(bp, base,
			BNX2_HC_SB_CONFIG_1_TX_TMR_MODE |
			BNX2_HC_SB_CONFIG_1_RX_TMR_MODE |
			BNX2_HC_SB_CONFIG_1_ONE_SHOT);

		REG_WR(bp, base + BNX2_HC_TX_QUICK_CONS_TRIP_OFF,
			(bp->tx_quick_cons_trip_int << 16) |
			 bp->tx_quick_cons_trip);

		REG_WR(bp, base + BNX2_HC_TX_TICKS_OFF,
			(bp->tx_ticks_int << 16) | bp->tx_ticks);

		REG_WR(bp, base + BNX2_HC_RX_QUICK_CONS_TRIP_OFF,
		       (bp->rx_quick_cons_trip_int << 16) |
			bp->rx_quick_cons_trip);

		REG_WR(bp, base + BNX2_HC_RX_TICKS_OFF,
			(bp->rx_ticks_int << 16) | bp->rx_ticks);
	}

	/* Clear internal stats counters. */
	REG_WR(bp, BNX2_HC_COMMAND, BNX2_HC_COMMAND_CLR_STAT_NOW);

	REG_WR(bp, BNX2_HC_ATTN_BITS_ENABLE, STATUS_ATTN_EVENTS);

	/* Initialize the receive filter. */
	bnx2_set_rx_mode(bp->dev);

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		val = REG_RD(bp, BNX2_MISC_NEW_CORE_CTL);
		val |= BNX2_MISC_NEW_CORE_CTL_DMA_ENABLE;
		REG_WR(bp, BNX2_MISC_NEW_CORE_CTL, val);
	}
	rc = bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT2 | BNX2_DRV_MSG_CODE_RESET,
			  1, 0);

	REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS, BNX2_MISC_ENABLE_DEFAULT);
	REG_RD(bp, BNX2_MISC_ENABLE_SET_BITS);

	udelay(20);

	bp->hc_cmd = REG_RD(bp, BNX2_HC_COMMAND);

	return rc;
}

static void
bnx2_clear_ring_states(struct bnx2 *bp)
{
	struct bnx2_napi *bnapi;
	struct bnx2_tx_ring_info *txr;
	struct bnx2_rx_ring_info *rxr;
	int i;

	for (i = 0; i < BNX2_MAX_MSIX_VEC; i++) {
		bnapi = &bp->bnx2_napi[i];
		txr = &bnapi->tx_ring;
		rxr = &bnapi->rx_ring;

		txr->tx_cons = 0;
		txr->hw_tx_cons = 0;
		rxr->rx_prod_bseq = 0;
		rxr->rx_prod = 0;
		rxr->rx_cons = 0;
		rxr->rx_pg_prod = 0;
		rxr->rx_pg_cons = 0;
	}
}

static void
bnx2_init_tx_context(struct bnx2 *bp, u32 cid, struct bnx2_tx_ring_info *txr)
{
	u32 val, offset0, offset1, offset2, offset3;
	u32 cid_addr = GET_CID_ADDR(cid);

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		offset0 = BNX2_L2CTX_TYPE_XI;
		offset1 = BNX2_L2CTX_CMD_TYPE_XI;
		offset2 = BNX2_L2CTX_TBDR_BHADDR_HI_XI;
		offset3 = BNX2_L2CTX_TBDR_BHADDR_LO_XI;
	} else {
		offset0 = BNX2_L2CTX_TYPE;
		offset1 = BNX2_L2CTX_CMD_TYPE;
		offset2 = BNX2_L2CTX_TBDR_BHADDR_HI;
		offset3 = BNX2_L2CTX_TBDR_BHADDR_LO;
	}
	val = BNX2_L2CTX_TYPE_TYPE_L2 | BNX2_L2CTX_TYPE_SIZE_L2;
	bnx2_ctx_wr(bp, cid_addr, offset0, val);

	val = BNX2_L2CTX_CMD_TYPE_TYPE_L2 | (8 << 16);
	bnx2_ctx_wr(bp, cid_addr, offset1, val);

	val = (u64) txr->tx_desc_mapping >> 32;
	bnx2_ctx_wr(bp, cid_addr, offset2, val);

	val = (u64) txr->tx_desc_mapping & 0xffffffff;
	bnx2_ctx_wr(bp, cid_addr, offset3, val);
}

static void
bnx2_init_tx_ring(struct bnx2 *bp, int ring_num)
{
	struct tx_bd *txbd;
	u32 cid = TX_CID;
	struct bnx2_napi *bnapi;
	struct bnx2_tx_ring_info *txr;

	bnapi = &bp->bnx2_napi[ring_num];
	txr = &bnapi->tx_ring;

	if (ring_num == 0)
		cid = TX_CID;
	else
		cid = TX_TSS_CID + ring_num - 1;

	bp->tx_wake_thresh = bp->tx_ring_size / 2;

	txbd = &txr->tx_desc_ring[MAX_TX_DESC_CNT];

	txbd->tx_bd_haddr_hi = (u64) txr->tx_desc_mapping >> 32;
	txbd->tx_bd_haddr_lo = (u64) txr->tx_desc_mapping & 0xffffffff;

	txr->tx_prod = 0;
	txr->tx_prod_bseq = 0;

	txr->tx_bidx_addr = MB_GET_CID_ADDR(cid) + BNX2_L2CTX_TX_HOST_BIDX;
	txr->tx_bseq_addr = MB_GET_CID_ADDR(cid) + BNX2_L2CTX_TX_HOST_BSEQ;

	bnx2_init_tx_context(bp, cid, txr);
}

static void
bnx2_init_rxbd_rings(struct rx_bd *rx_ring[], dma_addr_t dma[], u32 buf_size,
		     int num_rings)
{
	int i;
	struct rx_bd *rxbd;

	for (i = 0; i < num_rings; i++) {
		int j;

		rxbd = &rx_ring[i][0];
		for (j = 0; j < MAX_RX_DESC_CNT; j++, rxbd++) {
			rxbd->rx_bd_len = buf_size;
			rxbd->rx_bd_flags = RX_BD_FLAGS_START | RX_BD_FLAGS_END;
		}
		if (i == (num_rings - 1))
			j = 0;
		else
			j = i + 1;
		rxbd->rx_bd_haddr_hi = (u64) dma[j] >> 32;
		rxbd->rx_bd_haddr_lo = (u64) dma[j] & 0xffffffff;
	}
}

static void
bnx2_init_rx_ring(struct bnx2 *bp, int ring_num)
{
	int i;
	u16 prod, ring_prod;
	u32 cid, rx_cid_addr, val;
	struct bnx2_napi *bnapi = &bp->bnx2_napi[ring_num];
	struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;

	if (ring_num == 0)
		cid = RX_CID;
	else
		cid = RX_RSS_CID + ring_num - 1;

	rx_cid_addr = GET_CID_ADDR(cid);

	bnx2_init_rxbd_rings(rxr->rx_desc_ring, rxr->rx_desc_mapping,
			     bp->rx_buf_use_size, bp->rx_max_ring);

	bnx2_init_rx_context(bp, cid);

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		val = REG_RD(bp, BNX2_MQ_MAP_L2_5);
		REG_WR(bp, BNX2_MQ_MAP_L2_5, val | BNX2_MQ_MAP_L2_5_ARM);

#if defined(BNX2_ENABLE_NETQUEUE)
		/*  Set in the RX context the proper CID location
		 *  for the completion
		 */
		if(BNX2_NETQUEUE_ENABLED(bp))
			bnx2_ctx_wr(bp, rx_cid_addr, 0x04, 1 << 16);
#endif
	}

	bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_PG_BUF_SIZE, 0);
	if (bp->rx_pg_ring_size) {
		bnx2_init_rxbd_rings(rxr->rx_pg_desc_ring,
				     rxr->rx_pg_desc_mapping,
				     PAGE_SIZE, bp->rx_max_pg_ring);
		val = (bp->rx_buf_use_size << 16) | PAGE_SIZE;
		bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_PG_BUF_SIZE, val);
		bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_RBDC_KEY,
		       BNX2_L2CTX_RBDC_JUMBO_KEY - ring_num);

		val = (u64) rxr->rx_pg_desc_mapping[0] >> 32;
		bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_NX_PG_BDHADDR_HI, val);

		val = (u64) rxr->rx_pg_desc_mapping[0] & 0xffffffff;
		bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_NX_PG_BDHADDR_LO, val);

		if (CHIP_NUM(bp) == CHIP_NUM_5709)
			REG_WR(bp, BNX2_MQ_MAP_L2_3, BNX2_MQ_MAP_L2_3_DEFAULT);
	}

	val = (u64) rxr->rx_desc_mapping[0] >> 32;
	bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_NX_BDHADDR_HI, val);

	val = (u64) rxr->rx_desc_mapping[0] & 0xffffffff;
	bnx2_ctx_wr(bp, rx_cid_addr, BNX2_L2CTX_NX_BDHADDR_LO, val);

	ring_prod = prod = rxr->rx_pg_prod;
	for (i = 0; i < bp->rx_pg_ring_size; i++) {
		if (bnx2_alloc_rx_page(bp, rxr, ring_prod, GFP_KERNEL) < 0) {
			netdev_warn(bp->dev, "init'ed rx page ring %d with %d/%d pages only\n",
				    ring_num, i, bp->rx_pg_ring_size);
			break;
		}
		prod = NEXT_RX_BD(prod);
		ring_prod = RX_PG_RING_IDX(prod);
	}
	rxr->rx_pg_prod = prod;

	ring_prod = prod = rxr->rx_prod;
	for (i = 0; i < bp->rx_ring_size; i++) {
		if (bnx2_alloc_rx_skb(bp, rxr, ring_prod, GFP_KERNEL) < 0) {
			netdev_warn(bp->dev, "init'ed rx ring %d with %d/%d skbs only\n",
				    ring_num, i, bp->rx_ring_size);
			break;
		}
		prod = NEXT_RX_BD(prod);
		ring_prod = RX_RING_IDX(prod);
	}
	rxr->rx_prod = prod;

	rxr->rx_bidx_addr = MB_GET_CID_ADDR(cid) + BNX2_L2CTX_HOST_BDIDX;
	rxr->rx_bseq_addr = MB_GET_CID_ADDR(cid) + BNX2_L2CTX_HOST_BSEQ;
	rxr->rx_pg_bidx_addr = MB_GET_CID_ADDR(cid) + BNX2_L2CTX_HOST_PG_BDIDX;

	REG_WR16(bp, rxr->rx_pg_bidx_addr, rxr->rx_pg_prod);
	REG_WR16(bp, rxr->rx_bidx_addr, prod);

	REG_WR(bp, rxr->rx_bseq_addr, rxr->rx_prod_bseq);
}

static void
bnx2_init_all_rings(struct bnx2 *bp)
{
	int i;
#if !defined(BNX2_ENABLE_NETQUEUE)
	u32 val;
#endif

	bnx2_clear_ring_states(bp);

	REG_WR(bp, BNX2_TSCH_TSS_CFG, 0);
	for (i = 0; i < bp->num_tx_rings; i++)
		bnx2_init_tx_ring(bp, i);

	if (bp->num_tx_rings > 1)
		REG_WR(bp, BNX2_TSCH_TSS_CFG, ((bp->num_tx_rings - 1) << 24) |
		       (TX_TSS_CID << 7));

	REG_WR(bp, BNX2_RLUP_RSS_CONFIG, 0);
	bnx2_reg_wr_ind(bp, BNX2_RXP_SCRATCH_RSS_TBL_SZ, 0);

	for (i = 0; i < bp->num_rx_rings; i++)
		bnx2_init_rx_ring(bp, i);

#if !defined(BNX2_ENABLE_NETQUEUE)
	if (bp->num_rx_rings > 1) {
		u32 tbl_32 = 0;

		for (i = 0; i < BNX2_RXP_SCRATCH_RSS_TBL_MAX_ENTRIES; i++) {
			int shift = (i % 8) << 2;

			tbl_32 |= (i % (bp->num_rx_rings - 1)) << shift;
			if ((i % 8) == 7) {
				REG_WR(bp, BNX2_RLUP_RSS_DATA, tbl_32);
				REG_WR(bp, BNX2_RLUP_RSS_COMMAND, (i >> 3) |
					BNX2_RLUP_RSS_COMMAND_RSS_WRITE_MASK |
					BNX2_RLUP_RSS_COMMAND_WRITE |
					BNX2_RLUP_RSS_COMMAND_HASH_MASK);
				tbl_32 = 0;
			}
		}

		val = BNX2_RLUP_RSS_CONFIG_IPV4_RSS_TYPE_ALL_XI |
		      BNX2_RLUP_RSS_CONFIG_IPV6_RSS_TYPE_ALL_XI;

		REG_WR(bp, BNX2_RLUP_RSS_CONFIG, val);

	}
#endif
}

static u32 bnx2_find_max_ring(u32 ring_size, u32 max_size)
{
	u32 max, num_rings = 1;

	while (ring_size > MAX_RX_DESC_CNT) {
		ring_size -= MAX_RX_DESC_CNT;
		num_rings++;
	}
	/* round to next power of 2 */
	max = max_size;
	while ((max & num_rings) == 0)
		max >>= 1;

	if (num_rings != max)
		max <<= 1;

	return max;
}

static void
bnx2_set_rx_ring_size(struct bnx2 *bp, u32 size)
{
	u32 rx_size, rx_space;

	/* 8 for CRC and VLAN */
	rx_size = bp->dev->mtu + ETH_HLEN + BNX2_RX_OFFSET + 8;

	rx_space = SKB_DATA_ALIGN(rx_size + BNX2_RX_ALIGN) + NET_SKB_PAD +
		sizeof(struct skb_shared_info);

	bp->rx_copy_thresh = BNX2_RX_COPY_THRESH;
	bp->rx_pg_ring_size = 0;
	bp->rx_max_pg_ring = 0;
	bp->rx_max_pg_ring_idx = 0;
#if !defined(__VMKLNX__)
	if ((rx_space > PAGE_SIZE) && !(bp->flags & BNX2_FLAG_JUMBO_BROKEN)) {
		int pages = PAGE_ALIGN(bp->dev->mtu - 40) >> PAGE_SHIFT;

		u32 jumbo_size = size * pages;
		if (jumbo_size > MAX_TOTAL_RX_PG_DESC_CNT)
			jumbo_size = MAX_TOTAL_RX_PG_DESC_CNT;

		bp->rx_pg_ring_size = jumbo_size;
		bp->rx_max_pg_ring = bnx2_find_max_ring(jumbo_size,
							MAX_RX_PG_RINGS);
		bp->rx_max_pg_ring_idx = (bp->rx_max_pg_ring * RX_DESC_CNT) - 1;
		rx_size = BNX2_RX_COPY_THRESH + BNX2_RX_OFFSET;
		bp->rx_copy_thresh = 0;
	}
#endif

	bp->rx_buf_use_size = rx_size;
	/* hw alignment */
	bp->rx_buf_size = bp->rx_buf_use_size + BNX2_RX_ALIGN;
	bp->rx_jumbo_thresh = rx_size - BNX2_RX_OFFSET;
	bp->rx_ring_size = size;
	bp->rx_max_ring = bnx2_find_max_ring(size, MAX_RX_RINGS);
	bp->rx_max_ring_idx = (bp->rx_max_ring * RX_DESC_CNT) - 1;
}

static void
bnx2_free_tx_skbs(struct bnx2 *bp)
{
	int i;

	for (i = 0; i < bp->num_tx_rings; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
		struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;
		int j;

		if (txr->tx_buf_ring == NULL)
			continue;

		for (j = 0; j < TX_DESC_CNT; ) {
			struct sw_tx_bd *tx_buf = &txr->tx_buf_ring[j];
			struct sk_buff *skb = tx_buf->skb;
			int k, last;

			if (skb == NULL) {
				j = NEXT_TX_BD(j);
				continue;
			}

#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_unmap_single(&bp->pdev->dev,
#else
			pci_unmap_single(bp->pdev,
#endif
					 dma_unmap_addr(tx_buf, mapping),
					 skb_headlen(skb),
					 PCI_DMA_TODEVICE);

			tx_buf->skb = NULL;

			last = tx_buf->nr_frags;
			j = NEXT_TX_BD(j);
			for (k = 0; k < last; k++, j = NEXT_TX_BD(j)) {
				tx_buf = &txr->tx_buf_ring[TX_RING_IDX(j)];
#if (LINUX_VERSION_CODE >= 0x02061b)
				dma_unmap_page(&bp->pdev->dev,
#else
				pci_unmap_page(bp->pdev,
#endif
					dma_unmap_addr(tx_buf, mapping),
					skb_frag_size(&skb_shinfo(skb)->frags[k]),
					PCI_DMA_TODEVICE);
			}
			dev_kfree_skb(skb);
		}
	}
}

static void
bnx2_free_rx_skbs(struct bnx2 *bp)
{
	int i;

	for (i = 0; i < bp->num_rx_rings; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
		struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;
		int j;

		if (rxr->rx_buf_ring == NULL)
			return;

		for (j = 0; j < bp->rx_max_ring_idx; j++) {
			struct sw_bd *rx_buf = &rxr->rx_buf_ring[j];
			struct sk_buff *skb = rx_buf->skb;

			if (skb == NULL)
				continue;

#if (LINUX_VERSION_CODE >= 0x02061b)
			dma_unmap_single(&bp->pdev->dev,
#else
			pci_unmap_single(bp->pdev,
#endif
					 dma_unmap_addr(rx_buf, mapping),
					 bp->rx_buf_use_size,
					 PCI_DMA_FROMDEVICE);

			rx_buf->skb = NULL;

			dev_kfree_skb(skb);
		}
		for (j = 0; j < bp->rx_max_pg_ring_idx; j++)
			bnx2_free_rx_page(bp, rxr, j);
	}
}

static void
bnx2_free_skbs(struct bnx2 *bp)
{
	bnx2_free_tx_skbs(bp);
	bnx2_free_rx_skbs(bp);
}

static int
bnx2_reset_nic(struct bnx2 *bp, u32 reset_code)
{
	int rc;

	rc = bnx2_reset_chip(bp, reset_code);
	bnx2_free_skbs(bp);
	if (rc)
		return rc;

	if ((rc = bnx2_init_chip(bp)) != 0)
		return rc;

	bnx2_init_all_rings(bp);
	return 0;
}

static int
bnx2_init_nic(struct bnx2 *bp, int reset_phy)
{
	int rc;

	if ((rc = bnx2_reset_nic(bp, BNX2_DRV_MSG_CODE_RESET)) != 0)
		return rc;

	spin_lock_bh(&bp->phy_lock);
	bnx2_init_phy(bp, reset_phy);
	bnx2_set_link(bp);
	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
		bnx2_remote_phy_event(bp);
	spin_unlock_bh(&bp->phy_lock);
	return 0;
}

static int
bnx2_shutdown_chip(struct bnx2 *bp)
{
	u32 reset_code;

	if (bp->flags & BNX2_FLAG_NO_WOL)
		reset_code = BNX2_DRV_MSG_CODE_UNLOAD_LNK_DN;
	else if (bp->wol)
		reset_code = BNX2_DRV_MSG_CODE_SUSPEND_WOL;
	else
		reset_code = BNX2_DRV_MSG_CODE_SUSPEND_NO_WOL;

	return bnx2_reset_chip(bp, reset_code);
}

static int
bnx2_test_registers(struct bnx2 *bp)
{
	int ret;
	int i, is_5709;
	static const struct {
		u16   offset;
		u16   flags;
#define BNX2_FL_NOT_5709	1
		u32   rw_mask;
		u32   ro_mask;
	} reg_tbl[] = {
		{ 0x006c, 0, 0x00000000, 0x0000003f },
		{ 0x0090, 0, 0xffffffff, 0x00000000 },
		{ 0x0094, 0, 0x00000000, 0x00000000 },

		{ 0x0404, BNX2_FL_NOT_5709, 0x00003f00, 0x00000000 },
		{ 0x0418, BNX2_FL_NOT_5709, 0x00000000, 0xffffffff },
		{ 0x041c, BNX2_FL_NOT_5709, 0x00000000, 0xffffffff },
		{ 0x0420, BNX2_FL_NOT_5709, 0x00000000, 0x80ffffff },
		{ 0x0424, BNX2_FL_NOT_5709, 0x00000000, 0x00000000 },
		{ 0x0428, BNX2_FL_NOT_5709, 0x00000000, 0x00000001 },
		{ 0x0450, BNX2_FL_NOT_5709, 0x00000000, 0x0000ffff },
		{ 0x0454, BNX2_FL_NOT_5709, 0x00000000, 0xffffffff },
		{ 0x0458, BNX2_FL_NOT_5709, 0x00000000, 0xffffffff },

		{ 0x0808, BNX2_FL_NOT_5709, 0x00000000, 0xffffffff },
		{ 0x0854, BNX2_FL_NOT_5709, 0x00000000, 0xffffffff },
		{ 0x0868, BNX2_FL_NOT_5709, 0x00000000, 0x77777777 },
		{ 0x086c, BNX2_FL_NOT_5709, 0x00000000, 0x77777777 },
		{ 0x0870, BNX2_FL_NOT_5709, 0x00000000, 0x77777777 },
		{ 0x0874, BNX2_FL_NOT_5709, 0x00000000, 0x77777777 },

		{ 0x0c00, BNX2_FL_NOT_5709, 0x00000000, 0x00000001 },
		{ 0x0c04, BNX2_FL_NOT_5709, 0x00000000, 0x03ff0001 },
		{ 0x0c08, BNX2_FL_NOT_5709,  0x0f0ff073, 0x00000000 },

		{ 0x1000, 0, 0x00000000, 0x00000001 },
		{ 0x1004, BNX2_FL_NOT_5709, 0x00000000, 0x000f0001 },

		{ 0x1408, 0, 0x01c00800, 0x00000000 },
		{ 0x149c, 0, 0x8000ffff, 0x00000000 },
		{ 0x14a8, 0, 0x00000000, 0x000001ff },
		{ 0x14ac, 0, 0x0fffffff, 0x10000000 },
		{ 0x14b0, 0, 0x00000002, 0x00000001 },
		{ 0x14b8, 0, 0x00000000, 0x00000000 },
		{ 0x14c0, 0, 0x00000000, 0x00000009 },
		{ 0x14c4, 0, 0x00003fff, 0x00000000 },
		{ 0x14cc, 0, 0x00000000, 0x00000001 },
		{ 0x14d0, 0, 0xffffffff, 0x00000000 },

		{ 0x1800, 0, 0x00000000, 0x00000001 },
		{ 0x1804, 0, 0x00000000, 0x00000003 },

		{ 0x2800, 0, 0x00000000, 0x00000001 },
		{ 0x2804, 0, 0x00000000, 0x00003f01 },
		{ 0x2808, 0, 0x0f3f3f03, 0x00000000 },
		{ 0x2810, 0, 0xffff0000, 0x00000000 },
		{ 0x2814, 0, 0xffff0000, 0x00000000 },
		{ 0x2818, 0, 0xffff0000, 0x00000000 },
		{ 0x281c, 0, 0xffff0000, 0x00000000 },
		{ 0x2834, 0, 0xffffffff, 0x00000000 },
		{ 0x2840, 0, 0x00000000, 0xffffffff },
		{ 0x2844, 0, 0x00000000, 0xffffffff },
		{ 0x2848, 0, 0xffffffff, 0x00000000 },
		{ 0x284c, 0, 0xf800f800, 0x07ff07ff },

		{ 0x2c00, 0, 0x00000000, 0x00000011 },
		{ 0x2c04, 0, 0x00000000, 0x00030007 },

		{ 0x3c00, 0, 0x00000000, 0x00000001 },
		{ 0x3c04, 0, 0x00000000, 0x00070000 },
		{ 0x3c08, 0, 0x00007f71, 0x07f00000 },
		{ 0x3c0c, 0, 0x1f3ffffc, 0x00000000 },
		{ 0x3c10, 0, 0xffffffff, 0x00000000 },
		{ 0x3c14, 0, 0x00000000, 0xffffffff },
		{ 0x3c18, 0, 0x00000000, 0xffffffff },
		{ 0x3c1c, 0, 0xfffff000, 0x00000000 },
		{ 0x3c20, 0, 0xffffff00, 0x00000000 },

		{ 0x5004, 0, 0x00000000, 0x0000007f },
		{ 0x5008, 0, 0x0f0007ff, 0x00000000 },

		{ 0x5c00, 0, 0x00000000, 0x00000001 },
		{ 0x5c04, 0, 0x00000000, 0x0003000f },
		{ 0x5c08, 0, 0x00000003, 0x00000000 },
		{ 0x5c0c, 0, 0x0000fff8, 0x00000000 },
		{ 0x5c10, 0, 0x00000000, 0xffffffff },
		{ 0x5c80, 0, 0x00000000, 0x0f7113f1 },
		{ 0x5c84, 0, 0x00000000, 0x0000f333 },
		{ 0x5c88, 0, 0x00000000, 0x00077373 },
		{ 0x5c8c, 0, 0x00000000, 0x0007f737 },

		{ 0x6808, 0, 0x0000ff7f, 0x00000000 },
		{ 0x680c, 0, 0xffffffff, 0x00000000 },
		{ 0x6810, 0, 0xffffffff, 0x00000000 },
		{ 0x6814, 0, 0xffffffff, 0x00000000 },
		{ 0x6818, 0, 0xffffffff, 0x00000000 },
		{ 0x681c, 0, 0xffffffff, 0x00000000 },
		{ 0x6820, 0, 0x00ff00ff, 0x00000000 },
		{ 0x6824, 0, 0x00ff00ff, 0x00000000 },
		{ 0x6828, 0, 0x00ff00ff, 0x00000000 },
		{ 0x682c, 0, 0x03ff03ff, 0x00000000 },
		{ 0x6830, 0, 0x03ff03ff, 0x00000000 },
		{ 0x6834, 0, 0x03ff03ff, 0x00000000 },
		{ 0x6838, 0, 0x03ff03ff, 0x00000000 },
		{ 0x683c, 0, 0x0000ffff, 0x00000000 },
		{ 0x6840, 0, 0x00000ff0, 0x00000000 },
		{ 0x6844, 0, 0x00ffff00, 0x00000000 },
		{ 0x684c, 0, 0xffffffff, 0x00000000 },
		{ 0x6850, 0, 0x7f7f7f7f, 0x00000000 },
		{ 0x6854, 0, 0x7f7f7f7f, 0x00000000 },
		{ 0x6858, 0, 0x7f7f7f7f, 0x00000000 },
		{ 0x685c, 0, 0x7f7f7f7f, 0x00000000 },
		{ 0x6908, 0, 0x00000000, 0x0001ff0f },
		{ 0x690c, 0, 0x00000000, 0x0ffe00f0 },

		{ 0xffff, 0, 0x00000000, 0x00000000 },
	};

	ret = 0;
	is_5709 = 0;
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		is_5709 = 1;

	for (i = 0; reg_tbl[i].offset != 0xffff; i++) {
		u32 offset, rw_mask, ro_mask, save_val, val;
		u16 flags = reg_tbl[i].flags;

		if (is_5709 && (flags & BNX2_FL_NOT_5709))
			continue;

		offset = (u32) reg_tbl[i].offset;
		rw_mask = reg_tbl[i].rw_mask;
		ro_mask = reg_tbl[i].ro_mask;

		save_val = readl(bp->regview + offset);

		writel(0, bp->regview + offset);

		val = readl(bp->regview + offset);
		if ((val & rw_mask) != 0) {
			goto reg_test_err;
		}

		if ((val & ro_mask) != (save_val & ro_mask)) {
			goto reg_test_err;
		}

		writel(0xffffffff, bp->regview + offset);

		val = readl(bp->regview + offset);
		if ((val & rw_mask) != rw_mask) {
			goto reg_test_err;
		}

		if ((val & ro_mask) != (save_val & ro_mask)) {
			goto reg_test_err;
		}

		writel(save_val, bp->regview + offset);
		continue;

reg_test_err:
		writel(save_val, bp->regview + offset);
		ret = -ENODEV;
		break;
	}
	return ret;
}

static int
bnx2_do_mem_test(struct bnx2 *bp, u32 start, u32 size)
{
	static const u32 test_pattern[] = { 0x00000000, 0xffffffff, 0x55555555,
		0xaaaaaaaa , 0xaa55aa55, 0x55aa55aa };
	int i;

	for (i = 0; i < sizeof(test_pattern) / 4; i++) {
		u32 offset;

		for (offset = 0; offset < size; offset += 4) {

			bnx2_reg_wr_ind(bp, start + offset, test_pattern[i]);

			if (bnx2_reg_rd_ind(bp, start + offset) !=
				test_pattern[i]) {
				return -ENODEV;
			}
		}
	}
	return 0;
}

static int
bnx2_test_memory(struct bnx2 *bp)
{
	int ret = 0;
	int i;
	static struct mem_entry {
		u32   offset;
		u32   len;
	} mem_tbl_5706[] = {
		{ 0x60000,  0x4000 },
		{ 0xa0000,  0x3000 },
		{ 0xe0000,  0x4000 },
		{ 0x120000, 0x4000 },
		{ 0x1a0000, 0x4000 },
		{ 0x160000, 0x4000 },
		{ 0xffffffff, 0    },
	},
	mem_tbl_5709[] = {
		{ 0x60000,  0x4000 },
		{ 0xa0000,  0x3000 },
		{ 0xe0000,  0x4000 },
		{ 0x120000, 0x4000 },
		{ 0x1a0000, 0x4000 },
		{ 0xffffffff, 0    },
	};
	struct mem_entry *mem_tbl;

	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		mem_tbl = mem_tbl_5709;
	else
		mem_tbl = mem_tbl_5706;

	for (i = 0; mem_tbl[i].offset != 0xffffffff; i++) {
		if ((ret = bnx2_do_mem_test(bp, mem_tbl[i].offset,
			mem_tbl[i].len)) != 0) {
			return ret;
		}
	}

	return ret;
}

#define BNX2_MAC_LOOPBACK	0
#define BNX2_PHY_LOOPBACK	1

static int
bnx2_run_loopback(struct bnx2 *bp, int loopback_mode)
{
	unsigned int pkt_size, num_pkts, i;
	struct sk_buff *skb, *rx_skb;
	unsigned char *packet;
	u16 rx_start_idx, rx_idx;
	dma_addr_t map;
	struct tx_bd *txbd;
	struct sw_bd *rx_buf;
	struct l2_fhdr *rx_hdr;
	int ret = -ENODEV;
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0], *tx_napi;
	struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;
	struct bnx2_rx_ring_info *rxr = &bnapi->rx_ring;

	tx_napi = bnapi;

	txr = &tx_napi->tx_ring;
	rxr = &bnapi->rx_ring;
	if (loopback_mode == BNX2_MAC_LOOPBACK) {
		bp->loopback = MAC_LOOPBACK;
		bnx2_set_mac_loopback(bp);
	}
	else if (loopback_mode == BNX2_PHY_LOOPBACK) {
		if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
			return 0;

		bp->loopback = PHY_LOOPBACK;
		bnx2_set_phy_loopback(bp);
	}
	else
		return -EINVAL;

	pkt_size = min(bp->dev->mtu + ETH_HLEN, bp->rx_jumbo_thresh - 4);
	skb = netdev_alloc_skb(bp->dev, pkt_size);
	if (!skb)
		return -ENOMEM;
	packet = skb_put(skb, pkt_size);
	memcpy(packet, bp->dev->dev_addr, 6);
	memset(packet + 6, 0x0, 8);
	for (i = 14; i < pkt_size; i++)
		packet[i] = (unsigned char) (i & 0xff);

#if (LINUX_VERSION_CODE >= 0x02061b)
	map = dma_map_single(&bp->pdev->dev, skb->data, pkt_size,
			     PCI_DMA_TODEVICE);
	if (dma_mapping_error(&bp->pdev->dev, map)) {
#else
	map = pci_map_single(bp->pdev, skb->data, pkt_size,
		PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(map)) {
#endif
		dev_kfree_skb(skb);
		return -EIO;
	}

	REG_WR(bp, BNX2_HC_COMMAND,
	       bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);

	REG_RD(bp, BNX2_HC_COMMAND);

	udelay(5);
	rx_start_idx = bnx2_get_hw_rx_cons(bnapi);

	num_pkts = 0;

	txbd = &txr->tx_desc_ring[TX_RING_IDX(txr->tx_prod)];

	txbd->tx_bd_haddr_hi = (u64) map >> 32;
	txbd->tx_bd_haddr_lo = (u64) map & 0xffffffff;
	txbd->tx_bd_mss_nbytes = pkt_size;
	txbd->tx_bd_vlan_tag_flags = TX_BD_FLAGS_START | TX_BD_FLAGS_END;

	num_pkts++;
	txr->tx_prod = NEXT_TX_BD(txr->tx_prod);
	txr->tx_prod_bseq += pkt_size;

	REG_WR16(bp, txr->tx_bidx_addr, txr->tx_prod);
	REG_WR(bp, txr->tx_bseq_addr, txr->tx_prod_bseq);

	udelay(100);

	REG_WR(bp, BNX2_HC_COMMAND,
	       bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);

	REG_RD(bp, BNX2_HC_COMMAND);

	udelay(5);

#if (LINUX_VERSION_CODE >= 0x02061b)
	dma_unmap_single(&bp->pdev->dev, map, pkt_size, PCI_DMA_TODEVICE);
#else
	pci_unmap_single(bp->pdev, map, pkt_size, PCI_DMA_TODEVICE);
#endif
	dev_kfree_skb(skb);

	if (bnx2_get_hw_tx_cons(tx_napi) != txr->tx_prod)
		goto loopback_test_done;

	rx_idx = bnx2_get_hw_rx_cons(bnapi);
	if (rx_idx != rx_start_idx + num_pkts) {
		goto loopback_test_done;
	}

	rx_buf = &rxr->rx_buf_ring[rx_start_idx];
	rx_skb = rx_buf->skb;

	rx_hdr = rx_buf->desc;
	skb_reserve(rx_skb, BNX2_RX_OFFSET);

#if (LINUX_VERSION_CODE >= 0x02061b)
	dma_sync_single_for_cpu(&bp->pdev->dev,
#else
	pci_dma_sync_single_for_cpu(bp->pdev,
#endif
		dma_unmap_addr(rx_buf, mapping),
		bp->rx_buf_size, PCI_DMA_FROMDEVICE);

	if (rx_hdr->l2_fhdr_status &
		(L2_FHDR_ERRORS_BAD_CRC |
		L2_FHDR_ERRORS_PHY_DECODE |
		L2_FHDR_ERRORS_ALIGNMENT |
		L2_FHDR_ERRORS_TOO_SHORT |
		L2_FHDR_ERRORS_GIANT_FRAME)) {

		goto loopback_test_done;
	}

	if ((rx_hdr->l2_fhdr_pkt_len - 4) != pkt_size) {
		goto loopback_test_done;
	}

	for (i = 14; i < pkt_size; i++) {
		if (*(rx_skb->data + i) != (unsigned char) (i & 0xff)) {
			goto loopback_test_done;
		}
	}

	ret = 0;

loopback_test_done:
	bp->loopback = 0;
	return ret;
}

#define BNX2_MAC_LOOPBACK_FAILED	1
#define BNX2_PHY_LOOPBACK_FAILED	2
#define BNX2_LOOPBACK_FAILED		(BNX2_MAC_LOOPBACK_FAILED |	\
					 BNX2_PHY_LOOPBACK_FAILED)

static int
bnx2_test_loopback(struct bnx2 *bp)
{
	int rc = 0;

	if (!netif_running(bp->dev))
		return BNX2_LOOPBACK_FAILED;

	bnx2_reset_nic(bp, BNX2_DRV_MSG_CODE_RESET);
	spin_lock_bh(&bp->phy_lock);
	bnx2_init_phy(bp, 1);
	spin_unlock_bh(&bp->phy_lock);
	if (bnx2_run_loopback(bp, BNX2_MAC_LOOPBACK))
		rc |= BNX2_MAC_LOOPBACK_FAILED;
	if (bnx2_run_loopback(bp, BNX2_PHY_LOOPBACK))
		rc |= BNX2_PHY_LOOPBACK_FAILED;
	return rc;
}

#define NVRAM_SIZE 0x200
#define CRC32_RESIDUAL 0xdebb20e3

static int
bnx2_test_nvram(struct bnx2 *bp)
{
	__be32 buf[NVRAM_SIZE / 4];
	u8 *data = (u8 *) buf;
	int rc = 0;
	u32 magic, csum;

	if ((rc = bnx2_nvram_read(bp, 0, data, 4)) != 0)
		goto test_nvram_done;

        magic = be32_to_cpu(buf[0]);
	if (magic != 0x669955aa) {
		rc = -ENODEV;
		goto test_nvram_done;
	}

	if ((rc = bnx2_nvram_read(bp, 0x100, data, NVRAM_SIZE)) != 0)
		goto test_nvram_done;

	csum = ether_crc_le(0x100, data);
	if (csum != CRC32_RESIDUAL) {
		rc = -ENODEV;
		goto test_nvram_done;
	}

	csum = ether_crc_le(0x100, data + 0x100);
	if (csum != CRC32_RESIDUAL) {
		rc = -ENODEV;
	}

test_nvram_done:
	return rc;
}

static int
bnx2_test_link(struct bnx2 *bp)
{
	u32 bmsr;

	if (!netif_running(bp->dev))
		return -ENODEV;

	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP) {
		int i;

		for (i = 0; i < 6 && !bp->link_up; i++) {
			if (bnx2_msleep_interruptible(500))
				break;
		}
		if (bp->link_up)
			return 0;
		return -ENODEV;
	}
	spin_lock_bh(&bp->phy_lock);
	bnx2_enable_bmsr1(bp);
	bnx2_read_phy(bp, bp->mii_bmsr1, &bmsr);
	bnx2_read_phy(bp, bp->mii_bmsr1, &bmsr);
	bnx2_disable_bmsr1(bp);
	spin_unlock_bh(&bp->phy_lock);

	if (bmsr & BMSR_LSTATUS) {
		return 0;
	}
	return -ENODEV;
}

static int
bnx2_test_intr(struct bnx2 *bp)
{
	int i;
	u16 status_idx;

	if (!netif_running(bp->dev))
		return -ENODEV;

	status_idx = REG_RD(bp, BNX2_PCICFG_INT_ACK_CMD) & 0xffff;

	/* This register is not touched during run-time. */
	REG_WR(bp, BNX2_HC_COMMAND, bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW);
	REG_RD(bp, BNX2_HC_COMMAND);

	for (i = 0; i < 10; i++) {
		if ((REG_RD(bp, BNX2_PCICFG_INT_ACK_CMD) & 0xffff) !=
			status_idx) {

			break;
		}

		bnx2_msleep_interruptible(10);
	}
	if (i < 10)
		return 0;

	return -ENODEV;
}

/* Determining link for parallel detection. */
static int
bnx2_5706_serdes_has_link(struct bnx2 *bp)
{
	u32 mode_ctl, an_dbg, exp;

	if (bp->phy_flags & BNX2_PHY_FLAG_NO_PARALLEL)
		return 0;

	bnx2_write_phy(bp, MII_BNX2_MISC_SHADOW, MISC_SHDW_MODE_CTL);
	bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &mode_ctl);

	if (!(mode_ctl & MISC_SHDW_MODE_CTL_SIG_DET))
		return 0;

	bnx2_write_phy(bp, MII_BNX2_MISC_SHADOW, MISC_SHDW_AN_DBG);
	bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &an_dbg);
	bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &an_dbg);

	if (an_dbg & (MISC_SHDW_AN_DBG_NOSYNC | MISC_SHDW_AN_DBG_RUDI_INVALID))
		return 0;

	bnx2_write_phy(bp, MII_BNX2_DSP_ADDRESS, MII_EXPAND_REG1);
	bnx2_read_phy(bp, MII_BNX2_DSP_RW_PORT, &exp);
	bnx2_read_phy(bp, MII_BNX2_DSP_RW_PORT, &exp);

	if (exp & MII_EXPAND_REG1_RUDI_C)	/* receiving CONFIG */
		return 0;

	return 1;
}

static void
bnx2_5706_serdes_timer(struct bnx2 *bp)
{
	int check_link = 1;

	spin_lock(&bp->phy_lock);
	if (bp->serdes_an_pending) {
		bp->serdes_an_pending--;
		check_link = 0;
	} else if ((bp->link_up == 0) && (bp->autoneg & AUTONEG_SPEED)) {
		u32 bmcr;

		bp->current_interval = BNX2_TIMER_INTERVAL;

		bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);

		if (bmcr & BMCR_ANENABLE) {
			if (bnx2_5706_serdes_has_link(bp)) {
				bmcr &= ~BMCR_ANENABLE;
				bmcr |= BMCR_SPEED1000 | BMCR_FULLDPLX;
				bnx2_write_phy(bp, bp->mii_bmcr, bmcr);
				bp->phy_flags |= BNX2_PHY_FLAG_PARALLEL_DETECT;
			}
		}
	}
	else if ((bp->link_up) && (bp->autoneg & AUTONEG_SPEED) &&
		 (bp->phy_flags & BNX2_PHY_FLAG_PARALLEL_DETECT)) {
		u32 phy2;

		bnx2_write_phy(bp, 0x17, 0x0f01);
		bnx2_read_phy(bp, 0x15, &phy2);
		if (phy2 & 0x20) {
			u32 bmcr;

			bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
			bmcr |= BMCR_ANENABLE;
			bnx2_write_phy(bp, bp->mii_bmcr, bmcr);

			bp->phy_flags &= ~BNX2_PHY_FLAG_PARALLEL_DETECT;
		}
	} else
		bp->current_interval = BNX2_TIMER_INTERVAL;

	if (check_link) {
		u32 val;

		bnx2_write_phy(bp, MII_BNX2_MISC_SHADOW, MISC_SHDW_AN_DBG);
		bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &val);
		bnx2_read_phy(bp, MII_BNX2_MISC_SHADOW, &val);

		if (bp->link_up && (val & MISC_SHDW_AN_DBG_NOSYNC)) {
			if (!(bp->phy_flags & BNX2_PHY_FLAG_FORCED_DOWN)) {
				bnx2_5706s_force_link_dn(bp, 1);
				bp->phy_flags |= BNX2_PHY_FLAG_FORCED_DOWN;
			} else
				bnx2_set_link(bp);
		} else if (!bp->link_up && !(val & MISC_SHDW_AN_DBG_NOSYNC))
			bnx2_set_link(bp);
	}
	spin_unlock(&bp->phy_lock);
}

static void
bnx2_5708_serdes_timer(struct bnx2 *bp)
{
	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
		return;

	if ((bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE) == 0) {
		bp->serdes_an_pending = 0;
		return;
	}

	spin_lock(&bp->phy_lock);
	if (bp->serdes_an_pending)
		bp->serdes_an_pending--;
	else if ((bp->link_up == 0) && (bp->autoneg & AUTONEG_SPEED)) {
		u32 bmcr;

		bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
		if (bmcr & BMCR_ANENABLE) {
			bnx2_enable_forced_2g5(bp);
			bp->current_interval = BNX2_SERDES_FORCED_TIMEOUT;
		} else {
			bnx2_disable_forced_2g5(bp);
			bp->serdes_an_pending = 2;
			bp->current_interval = BNX2_TIMER_INTERVAL;
		}

	} else
		bp->current_interval = BNX2_TIMER_INTERVAL;

	spin_unlock(&bp->phy_lock);
}

static void
bnx2_timer(unsigned long data)
{
	struct bnx2 *bp = (struct bnx2 *) data;

	if (!netif_running(bp->dev))
		return;

	if (atomic_read(&bp->intr_sem) != 0)
		goto bnx2_restart_timer;

#ifdef CONFIG_PCI_MSI
	if ((bp->flags & (BNX2_FLAG_USING_MSI | BNX2_FLAG_ONE_SHOT_MSI)) ==
	     BNX2_FLAG_USING_MSI)
		bnx2_chk_missed_msi(bp);
#endif

	bnx2_send_heart_beat(bp);

	bp->stats_blk->stat_FwRxDrop =
		bnx2_reg_rd_ind(bp, BNX2_FW_RX_DROP_COUNT);

	/* workaround occasional corrupted counters */
	if ((bp->flags & BNX2_FLAG_BROKEN_STATS) && bp->stats_ticks)
		REG_WR(bp, BNX2_HC_COMMAND, bp->hc_cmd |
					    BNX2_HC_COMMAND_STATS_NOW);

	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		if (CHIP_NUM(bp) == CHIP_NUM_5706)
			bnx2_5706_serdes_timer(bp);
		else
			bnx2_5708_serdes_timer(bp);
	}

bnx2_restart_timer:
	mod_timer(&bp->timer, jiffies + bp->current_interval);
}

static int
bnx2_request_irq(struct bnx2 *bp)
{
	unsigned long flags;
	struct bnx2_irq *irq;
	int rc = 0, i;

	if (bp->flags & BNX2_FLAG_USING_MSI_OR_MSIX)
		flags = 0;
	else
		flags = IRQF_SHARED;

#if defined(__VMKLNX__)
	/*
	 * In ESX, bnx2 will setup int mode during .probe time. However, the dev->name
	 * will be finalized only when pci_announce_device is done. So, we assign
	 * irq->name here instead of in bnx2_setup_int_mode.
	 */
	strcpy(bp->irq_tbl[0].name, bp->dev->name);
	if (bp->flags & BNX2_FLAG_USING_MSIX) {
		for (i = 0; i < BNX2_MAX_MSIX_VEC; i++) {
                   snprintf(bp->irq_tbl[i].name, sizeof(bp->irq_tbl[i].name),
				"%s-%d", bp->dev->name, i);
		}
        }
#endif

	for (i = 0; i < bp->irq_nvecs; i++) {
		irq = &bp->irq_tbl[i];
		rc = request_irq(irq->vector, irq->handler, flags, irq->name,
				 &bp->bnx2_napi[i]);
		if (rc)
			break;
		irq->requested = 1;
	}
	return rc;
}

#if defined(__VMKLNX__)
static void
bnx2_free_irq(struct bnx2 *bp)
{
	struct bnx2_irq *irq;
	int i;

	for (i = 0; i < bp->irq_nvecs; i++) {
		irq = &bp->irq_tbl[i];
		if (irq->requested)
			free_irq(irq->vector, &bp->bnx2_napi[i]);
		irq->requested = 0;
	}
}

/* disable MSI/MSIX */
static void
bnx2_disable_msi(struct bnx2 *bp)
{
#ifdef CONFIG_PCI_MSI
	if (bp->flags & BNX2_FLAG_USING_MSI)
		pci_disable_msi(bp->pdev);
	else if (bp->flags & BNX2_FLAG_USING_MSIX)
		pci_disable_msix(bp->pdev);

	bp->flags &= ~(BNX2_FLAG_USING_MSI_OR_MSIX | BNX2_FLAG_ONE_SHOT_MSI);
#endif
}

#else

static void
__bnx2_free_irq(struct bnx2 *bp)
{
	struct bnx2_irq *irq;
	int i;

	for (i = 0; i < bp->irq_nvecs; i++) {
		irq = &bp->irq_tbl[i];
		if (irq->requested)
			free_irq(irq->vector, &bp->bnx2_napi[i]);
		irq->requested = 0;
	}
}

static void
bnx2_free_irq(struct bnx2 *bp)
{

	__bnx2_free_irq(bp);
#ifdef CONFIG_PCI_MSI
	if (bp->flags & BNX2_FLAG_USING_MSI)
		pci_disable_msi(bp->pdev);
	else if (bp->flags & BNX2_FLAG_USING_MSIX)
		pci_disable_msix(bp->pdev);

	bp->flags &= ~(BNX2_FLAG_USING_MSI_OR_MSIX | BNX2_FLAG_ONE_SHOT_MSI);
#endif
}
#endif  /* defined(__VMKLNX__) */

#ifdef CONFIG_PCI_MSI
static void
bnx2_enable_msix(struct bnx2 *bp, int msix_vecs)
{
#ifdef BNX2_NEW_NAPI
	int i, total_vecs, rc;
	struct msix_entry msix_ent[BNX2_MAX_MSIX_VEC];
#if !defined(__VMKLNX__)
	struct net_device *dev = bp->dev;
	const int len = sizeof(bp->irq_tbl[0].name);
#endif

	bnx2_setup_msix_tbl(bp);
	REG_WR(bp, BNX2_PCI_MSIX_CONTROL, BNX2_MAX_MSIX_HW_VEC - 1);
	REG_WR(bp, BNX2_PCI_MSIX_TBL_OFF_BIR, BNX2_PCI_GRC_WINDOW2_BASE);
	REG_WR(bp, BNX2_PCI_MSIX_PBA_OFF_BIT, BNX2_PCI_GRC_WINDOW3_BASE);

	/*  Need to flush the previous three writes to ensure MSI-X
	 *  is setup properly */
	REG_RD(bp, BNX2_PCI_MSIX_CONTROL);

	for (i = 0; i < BNX2_MAX_MSIX_VEC; i++) {
		msix_ent[i].entry = i;
		msix_ent[i].vector = 0;
	}

	total_vecs = msix_vecs;
#ifdef BCM_CNIC
	total_vecs++;
#endif
	rc = -ENOSPC;
	while (total_vecs >= BNX2_MIN_MSIX_VEC) {
		rc = pci_enable_msix(bp->pdev, msix_ent, total_vecs);
		if (rc <= 0)
			break;
		if (rc > 0)
			total_vecs = rc;
	}

	if (rc != 0)
		return;

	msix_vecs = total_vecs;
#ifdef BCM_CNIC
	msix_vecs--;
#endif
	bp->irq_nvecs = msix_vecs;
	bp->flags |= BNX2_FLAG_USING_MSIX | BNX2_FLAG_ONE_SHOT_MSI;
#if defined(__VMKLNX__)
	if (disable_msi_1shot) 
		bp->flags &= ~BNX2_FLAG_ONE_SHOT_MSI; 
#endif
	for (i = 0; i < total_vecs; i++) {
		bp->irq_tbl[i].vector = msix_ent[i].vector;
#if !defined(__VMKLNX__)
		snprintf(bp->irq_tbl[i].name, len, "%s-%d", dev->name, i);
		bp->irq_tbl[i].handler = bnx2_msi_1shot;
#else
		if (disable_msi_1shot)
			bp->irq_tbl[i].handler = bnx2_msi;
		else
			bp->irq_tbl[i].handler = bnx2_msi_1shot;
#endif
	}
#endif
}
#endif

static int
bnx2_setup_int_mode(struct bnx2 *bp, int dis_msi)
{
#ifdef CONFIG_PCI_MSI
#if defined(BNX2_ENABLE_NETQUEUE)
	int cpus = num_online_cpus();
	int msix_vecs = min(cpus, 4);
	if (force_netq_param[bp->index] != BNX2_OPTION_UNSET)
		msix_vecs = min(force_netq_param[bp->index], RX_MAX_RSS_RINGS);

	/* Once is for the default queuue */
	msix_vecs += 1;
#else
#if defined(__VMKLNX__)
	/*  If NetQueue is not enable then force the number of queues to 1 */
	int msix_vecs = 1;
#else
	int cpus = num_online_cpus();
	int msix_vecs;
#endif /* defined(__VMKLNX__) */
#endif
#endif

#if !defined(__VMKLNX__)
	if (!bp->num_req_rx_rings)
		msix_vecs = max(cpus + 1, bp->num_req_tx_rings);
	else if (!bp->num_req_tx_rings)
		msix_vecs = max(cpus, bp->num_req_rx_rings);
	else
		msix_vecs = max(bp->num_req_rx_rings, bp->num_req_tx_rings);

	msix_vecs = min(msix_vecs, RX_MAX_RINGS);
#endif
	bp->irq_tbl[0].handler = bnx2_interrupt;
#if !defined(__VMKLNX__)
	strcpy(bp->irq_tbl[0].name, bp->dev->name);
#endif
	bp->irq_nvecs = 1;
	bp->irq_tbl[0].vector = bp->pdev->irq;

#ifdef CONFIG_PCI_MSI
	if ((bp->flags & BNX2_FLAG_MSIX_CAP) && !dis_msi)
		bnx2_enable_msix(bp, msix_vecs);

	if ((bp->flags & BNX2_FLAG_MSI_CAP) && !dis_msi &&
	    !(bp->flags & BNX2_FLAG_USING_MSIX)) {
		if (pci_enable_msi(bp->pdev) == 0) {
			bp->flags |= BNX2_FLAG_USING_MSI;
			if (CHIP_NUM(bp) == CHIP_NUM_5709) {
				bp->flags |= BNX2_FLAG_ONE_SHOT_MSI;
				bp->irq_tbl[0].handler = bnx2_msi_1shot;
#if defined(__VMKLNX__)
				if (disable_msi_1shot) {
					bp->flags &= ~BNX2_FLAG_ONE_SHOT_MSI;
					bp->irq_tbl[0].handler = bnx2_msi;
				}
#endif
			} else
				bp->irq_tbl[0].handler = bnx2_msi;

			bp->irq_tbl[0].vector = bp->pdev->irq;
		}
	}
#endif

#ifndef BCM_HAVE_MULTI_QUEUE
	bp->num_tx_rings = 1;
	bp->num_rx_rings = bp->irq_nvecs;
#else
#if defined(__VMKLNX__)
#if defined(BNX2_ENABLE_NETQUEUE)
	bp->num_tx_rings = bp->irq_nvecs;
	bp->dev->real_num_tx_queues = bp->num_tx_rings;
#else
	bp->num_tx_rings = 1;
#endif
	bp->num_rx_rings = bp->irq_nvecs;
#else
	if (!bp->num_req_tx_rings)
		bp->num_tx_rings = rounddown_pow_of_two(bp->irq_nvecs);
	else
		bp->num_tx_rings = min(bp->irq_nvecs, bp->num_req_tx_rings);

	if (!bp->num_req_rx_rings)
		bp->num_rx_rings = bp->irq_nvecs;
	else
		bp->num_rx_rings = min(bp->irq_nvecs, bp->num_req_rx_rings);
#endif
	netif_set_real_num_tx_queues(bp->dev, bp->num_tx_rings);
#endif
	return netif_set_real_num_rx_queues(bp->dev, bp->num_rx_rings);
}

/* Called with rtnl_lock */
static int
bnx2_open(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);
	int rc;

	netif_carrier_off(dev);

	bnx2_set_power_state(bp, PCI_D0);
	bnx2_disable_int(bp);

#if !(defined __VMKLNX__)
	rc = bnx2_setup_int_mode(bp, disable_msi);
	if (rc)
		goto open_err;
	bnx2_init_napi(bp);
#endif /* !(defined __VMKLNX__) */
#ifdef BNX2_NEW_NAPI
	bnx2_napi_enable(bp);
#endif
	rc = bnx2_alloc_mem(bp);
	if (rc)
		goto open_err;

	rc = bnx2_request_irq(bp);
	if (rc)
		goto open_err;

	rc = bnx2_init_nic(bp, 1);
	if (rc)
		goto open_err;

	mod_timer(&bp->timer, jiffies + bp->current_interval);

	atomic_set(&bp->intr_sem, 0);

	memset(bp->temp_stats_blk, 0, sizeof(struct statistics_block));

	bnx2_enable_int(bp);

#ifdef CONFIG_PCI_MSI
	if (bp->flags & BNX2_FLAG_USING_MSI) {
		/* Test MSI to make sure it is working
		 * If MSI test fails, go back to INTx mode
		 */
		if (bnx2_test_intr(bp) != 0) {
			netdev_warn(bp->dev, "No interrupt was generated using MSI, switching to INTx mode. Please report this failure to the PCI maintainer and include system chipset information.\n");

			bnx2_disable_int(bp);
			bnx2_free_irq(bp);
#if defined(__VMKLNX__)
			bnx2_disable_msi(bp);
#endif

			bnx2_setup_int_mode(bp, 1);

			rc = bnx2_init_nic(bp, 0);

			if (!rc)
				rc = bnx2_request_irq(bp);

			if (rc) {
				del_timer_sync(&bp->timer);
				goto open_err;
			}
			bnx2_enable_int(bp);
		}
	}
	if (bp->flags & BNX2_FLAG_USING_MSI)
		netdev_info(dev, "using MSI\n");
	else if (bp->flags & BNX2_FLAG_USING_MSIX)
		netdev_info(dev, "using MSIX\n");
#endif
#if defined(BNX2_ENABLE_NETQUEUE)
	if (bnx2_netqueue_is_avail(bp))
		bnx2_open_netqueue_hw(bp);
#endif

	netif_tx_start_all_queues(dev);

	return 0;

open_err:
#ifdef BNX2_NEW_NAPI
	bnx2_napi_disable(bp);
#endif
	bnx2_free_skbs(bp);
	bnx2_free_irq(bp);
	bnx2_free_mem(bp);
#if !defined(__VMKLNX__)
	bnx2_del_napi(bp);
#endif /* !(defined __VMKLNX__) */
	return rc;
}

static void
#if defined(INIT_DELAYED_WORK_DEFERRABLE) || defined(INIT_WORK_NAR)  || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
bnx2_reset_task(struct work_struct *work)
#else
bnx2_reset_task(void *data)
#endif
{
#if defined(INIT_DELAYED_WORK_DEFERRABLE) || defined(INIT_WORK_NAR)  || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
	struct bnx2 *bp = container_of(work, struct bnx2, reset_task);
#else
	struct bnx2 *bp = data;
#endif
	int rc;
	u16 pcicmd;

	rtnl_lock();
	if (!netif_running(bp->dev)) {
		rtnl_unlock();
		return;
	}

	bnx2_netif_stop(bp, true);

	pci_read_config_word(bp->pdev, PCI_COMMAND, &pcicmd);
	if (!(pcicmd & PCI_COMMAND_MEMORY)) {
		/* in case PCI block has reset */
		pci_restore_state(bp->pdev);
		pci_save_state(bp->pdev);
	}
	rc = bnx2_init_nic(bp, 1);
	if (rc) {
		netdev_err(bp->dev, "failed to reset NIC, closing\n");
		bnx2_napi_enable(bp);
		dev_close(bp->dev);
#if defined(__VMKLNX__)
#if (VMWARE_ESX_DDK_VERSION == 41000) || (VMWARE_ESX_DDK_VERSION == 50000)
		/* PR 533926
		 * This is a workaround to sync device status in dev->flags and
		 * dev->gflags. It is needed to avoid PSOD (due to double dev_close)
		 * on reboot. For post MN releases, we plan to move it to vmklinux.
		 */
		bp->dev->gflags &= ~IFF_DEV_IS_OPEN;
#endif
#endif
		rtnl_unlock();
		return;
	}
 
 	atomic_set(&bp->intr_sem, 1);
 	bnx2_netif_start(bp, true);

	rtnl_unlock();
}

#define BNX2_FTQ_ENTRY(ftq) { __stringify(ftq##FTQ_CTL), BNX2_##ftq##FTQ_CTL }
static const struct ftq_reg {
	char *name;
	u32 off;
} ftq_arr[] = {
	BNX2_FTQ_ENTRY(RV2P_P),
	BNX2_FTQ_ENTRY(RV2P_T),
	BNX2_FTQ_ENTRY(RV2P_M),
	BNX2_FTQ_ENTRY(TBDR_),
	BNX2_FTQ_ENTRY(TSCH_),
	BNX2_FTQ_ENTRY(TDMA_),
	BNX2_FTQ_ENTRY(TXP_),
	BNX2_FTQ_ENTRY(TPAT_),
	BNX2_FTQ_ENTRY(TAS_),
	BNX2_FTQ_ENTRY(RXP_C),
	BNX2_FTQ_ENTRY(RXP_),
	BNX2_FTQ_ENTRY(RLUP_),
	BNX2_FTQ_ENTRY(COM_COMXQ_),
	BNX2_FTQ_ENTRY(COM_COMTQ_),
	BNX2_FTQ_ENTRY(COM_COMQ_),
	BNX2_FTQ_ENTRY(CP_CPQ_),
	BNX2_FTQ_ENTRY(RDMA_),
	BNX2_FTQ_ENTRY(CSCH_CH_),
	BNX2_FTQ_ENTRY(MCP_MCPQ_),
};

static void
bnx2_dump_ftq(struct bnx2 *bp)
{
	int i;
	u32 reg, bdidx, cid, valid;
	struct net_device *dev = bp->dev;

	netdev_err(dev, "<--- start FTQ dump --->\n");
	for (i = 0; i < ARRAY_SIZE(ftq_arr); i++)
		netdev_err(dev, "%s %08x\n", ftq_arr[i].name,
			   bnx2_reg_rd_ind(bp, ftq_arr[i].off));

	netdev_err(dev, "CPU states:\n");
	for (reg = BNX2_TXP_CPU_MODE; reg <= BNX2_CP_CPU_MODE; reg += 0x40000)
		netdev_err(dev, "%06x mode %x state %x evt_mask %x pc %x pc %x instr %x\n",
			   reg, bnx2_reg_rd_ind(bp, reg),
			   bnx2_reg_rd_ind(bp, reg + 4),
			   bnx2_reg_rd_ind(bp, reg + 8),
			   bnx2_reg_rd_ind(bp, reg + 0x1c),
			   bnx2_reg_rd_ind(bp, reg + 0x1c),
			   bnx2_reg_rd_ind(bp, reg + 0x20));

	netdev_err(dev, "<--- end FTQ dump --->\n");
	netdev_err(dev, "<--- start TBDC dump --->\n");
	netdev_err(dev, "TBDC free cnt: %ld\n",
		   REG_RD(bp, BNX2_TBDC_STATUS) & BNX2_TBDC_STATUS_FREE_CNT);
	netdev_err(dev, "LINE     CID  BIDX   CMD  VALIDS\n");
	for (i = 0; i < 0x20; i++) {
		int j = 0;

		REG_WR(bp, BNX2_TBDC_BD_ADDR, i);
		REG_WR(bp, BNX2_TBDC_CAM_OPCODE,
		       BNX2_TBDC_CAM_OPCODE_OPCODE_CAM_READ);
		REG_WR(bp, BNX2_TBDC_COMMAND, BNX2_TBDC_COMMAND_CMD_REG_ARB);
		while ((REG_RD(bp, BNX2_TBDC_COMMAND) &
		       	BNX2_TBDC_COMMAND_CMD_REG_ARB) && j < 100)
			j++;

		cid = REG_RD(bp, BNX2_TBDC_CID);
		bdidx = REG_RD(bp, BNX2_TBDC_BIDX);
		valid = REG_RD(bp, BNX2_TBDC_CAM_OPCODE);
		netdev_err(dev, "%02x    %06x  %04lx   %02x    [%x]\n",
			   i, cid, bdidx & BNX2_TBDC_BDIDX_BDIDX,
			   bdidx >> 24, (valid >> 8) & 0x0ff);
	}
	netdev_err(dev, "<--- end TBDC dump --->\n");
}

static void
bnx2_dump_state(struct bnx2 *bp)
{
	struct net_device *dev = bp->dev;
	u32 val1, val2;

	pci_read_config_dword(bp->pdev, PCI_COMMAND, &val1);
	netdev_err(dev, "DEBUG: intr_sem[%x] PCI_CMD[%08x]\n",
		   atomic_read(&bp->intr_sem), val1);
	pci_read_config_dword(bp->pdev, bp->pm_cap + PCI_PM_CTRL, &val1);
	pci_read_config_dword(bp->pdev, BNX2_PCICFG_MISC_CONFIG, &val2);
	netdev_err(dev, "DEBUG: PCI_PM[%08x] PCI_MISC_CFG[%08x]\n", val1, val2);
	netdev_err(dev, "DEBUG: EMAC_TX_STATUS[%08x] EMAC_RX_STATUS[%08x]\n",
		   REG_RD(bp, BNX2_EMAC_TX_STATUS),
		   REG_RD(bp, BNX2_EMAC_RX_STATUS));
	netdev_err(dev, "DEBUG: RPM_MGMT_PKT_CTRL[%08x]\n",
		   REG_RD(bp, BNX2_RPM_MGMT_PKT_CTRL));
	netdev_err(dev, "DEBUG: HC_STATS_INTERRUPT_STATUS[%08x]\n",
		   REG_RD(bp, BNX2_HC_STATS_INTERRUPT_STATUS));
	if (bp->flags & BNX2_FLAG_USING_MSIX) {
		int i;

		netdev_err(dev, "DEBUG: PBA[%08x]\n",
			   REG_RD(bp, BNX2_PCI_GRC_WINDOW3_BASE));
		netdev_err(dev, "DEBUG: MSIX table:\n");
		val1 = BNX2_PCI_GRC_WINDOW2_BASE;
		for (i = 0; i < bp->irq_nvecs; i++) {
			netdev_err(dev, "DEBUG: [%d]: %08x %08x %08x %08x\n",
				   i, REG_RD(bp, val1), 
				   REG_RD(bp, val1 + 4), REG_RD(bp, val1 + 8),
				   REG_RD(bp, val1 + 12));
			val1 += 16;
		}
	}
}

static void
bnx2_tx_timeout(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);

	bnx2_dump_ftq(bp);
	bnx2_dump_state(bp);
	bnx2_dump_mcp_state(bp);

#if defined(__VMKLNX__)
	if (psod_on_tx_timeout) {
		msleep(100);
		BUG_ON(1);
		return;
	}
#endif
	if (stop_on_tx_timeout) {
		netdev_err(dev, "prevent chip reset during tx timeout\n");
		return;
	}

	/* This allows the netif to be shutdown gracefully before resetting */
#if (LINUX_VERSION_CODE >= 0x20600)
	schedule_work(&bp->reset_task);
#else
	schedule_task(&bp->reset_task);
#endif
}

#ifdef BCM_VLAN
/* Called with rtnl_lock */
static void
bnx2_vlan_rx_register(struct net_device *dev, struct vlan_group *vlgrp)
{
	struct bnx2 *bp = netdev_priv(dev);

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
	/* rtnl_lock() needed for ESX 4.0 and 4.1 only */
	rtnl_lock();
#endif
	if (netif_running(dev))
		bnx2_netif_stop(bp, false);

	bp->vlgrp = vlgrp;

	if (netif_running(dev)) {
		bnx2_set_rx_mode(dev);
		if (bp->flags & BNX2_FLAG_CAN_KEEP_VLAN)
			bnx2_fw_sync(bp, BNX2_DRV_MSG_CODE_KEEP_VLAN_UPDATE, 0,
				     1);
		bnx2_netif_start(bp, false);
	}
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
	rtnl_unlock();
#endif
}

#if (LINUX_VERSION_CODE < 0x20616)
/* Called with rtnl_lock */
static void
bnx2_vlan_rx_kill_vid(struct net_device *dev, uint16_t vid)
{
	struct bnx2 *bp = netdev_priv(dev);

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
	/* rtnl_lock() needed for ESX 4.0 and 4.1 only */
	rtnl_lock();
#endif
	if (netif_running(dev))
		bnx2_netif_stop(bp, false);

	vlan_group_set_device(bp->vlgrp, vid, NULL);

	if (!netif_running(dev)) {
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
		rtnl_unlock();
#endif
		return;
	}

	bnx2_set_rx_mode(dev);
	if (bp->flags & BNX2_FLAG_CAN_KEEP_VLAN)
		bnx2_fw_sync(bp, BNX2_DRV_MSG_CODE_KEEP_VLAN_UPDATE, 0, 1);

	bnx2_netif_start(bp, false);
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
	rtnl_unlock();
#endif
}
#endif
#endif

/* Called with netif_tx_lock.
 * bnx2_tx_int() runs without netif_tx_lock unless it needs to call
 * netif_wake_queue().
 */
static netdev_tx_t
bnx2_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);
	dma_addr_t mapping;
	struct tx_bd *txbd;
	struct sw_tx_bd *tx_buf;
	u32 len, vlan_tag_flags, last_frag, mss;
	u16 prod, ring_prod;
	int i;
#ifndef BCM_HAVE_MULTI_QUEUE
	struct bnx2_napi *bnapi = &bp->bnx2_napi[0];
	struct bnx2_tx_ring_info *txr = &bnapi->tx_ring;

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
	/*  Drop the packet if the queue has been stopped */
	if (unlikely(netif_queue_stopped(dev))) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
#endif
#else
	struct bnx2_napi *bnapi;
	struct bnx2_tx_ring_info *txr;
	struct netdev_queue *txq;

	/*  Determine which tx ring we will be placed on */
	i = skb_get_queue_mapping(skb);
	bnapi = &bp->bnx2_napi[i];
	txr = &bnapi->tx_ring;
	txq = netdev_get_tx_queue(dev, i);

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 50000)
	/*  Drop the packet if the queue has been stopped */
	if (unlikely(netif_tx_queue_stopped(txq))) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
#endif
#endif

	if (unlikely(bnx2_tx_avail(bp, txr) <
	    (skb_shinfo(skb)->nr_frags + 1))) {
#ifndef BCM_HAVE_MULTI_QUEUE
		netif_stop_queue(dev);
#else
		netif_tx_stop_queue(txq);
#endif
		netdev_err(dev, "BUG! Tx ring full when queue awake!\n");

		return NETDEV_TX_BUSY;
	}
	len = skb_headlen(skb);
	prod = txr->tx_prod;
	ring_prod = TX_RING_IDX(prod);

	vlan_tag_flags = 0;
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		vlan_tag_flags |= TX_BD_FLAGS_TCP_UDP_CKSUM;
	}

#ifdef BCM_VLAN
	if (bp->vlgrp && vlan_tx_tag_present(skb)) {
		vlan_tag_flags |=
			(TX_BD_FLAGS_VLAN_TAG | (vlan_tx_tag_get(skb) << 16));
	}
#endif
#ifdef BCM_TSO 
	if ((mss = skb_shinfo(skb)->gso_size)) {
		u32 tcp_opt_len;
		struct iphdr *iph;

		tcp_opt_len = tcp_optlen(skb);

		if (skb_transport_offset(skb) + tcp_opt_len +
		    sizeof(struct tcphdr) + mss >= skb->len)
			goto abort_tso;

		vlan_tag_flags |= TX_BD_FLAGS_SW_LSO;

#ifndef BCM_NO_TSO6
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6) {
			u32 tcp_off = skb_transport_offset(skb) -
				      sizeof(struct ipv6hdr) - ETH_HLEN;

			vlan_tag_flags |= ((tcp_opt_len >> 2) << 8) |
					  TX_BD_FLAGS_SW_FLAGS;
			if (likely(tcp_off == 0))
				vlan_tag_flags &= ~TX_BD_FLAGS_TCP6_OFF0_MSK;
			else {
				tcp_off >>= 3;
				vlan_tag_flags |= ((tcp_off & 0x3) <<
						   TX_BD_FLAGS_TCP6_OFF0_SHL) |
						  ((tcp_off & 0x10) <<
						   TX_BD_FLAGS_TCP6_OFF4_SHL);
				mss |= (tcp_off & 0xc) << TX_BD_TCP6_OFF2_SHL;
			}
		} else
#endif
		{
			iph = ip_hdr(skb);
			if (tcp_opt_len || (iph->ihl > 5)) {
				vlan_tag_flags |= ((iph->ihl - 5) +
						   (tcp_opt_len >> 2)) << 8;
			}
		}
	}
	else
abort_tso:
#endif
	{
		mss = 0;
	}

#if (LINUX_VERSION_CODE >= 0x02061b)
	mapping = dma_map_single(&bp->pdev->dev, skb->data, len, PCI_DMA_TODEVICE);
	if (dma_mapping_error(&bp->pdev->dev, mapping)) {
#else
	mapping = pci_map_single(bp->pdev, skb->data, len, PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(mapping)) {
#endif
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	tx_buf = &txr->tx_buf_ring[ring_prod];
	tx_buf->skb = skb;
	dma_unmap_addr_set(tx_buf, mapping, mapping);

	txbd = &txr->tx_desc_ring[ring_prod];

	txbd->tx_bd_haddr_hi = (u64) mapping >> 32;
	txbd->tx_bd_haddr_lo = (u64) mapping & 0xffffffff;
	txbd->tx_bd_mss_nbytes = len | (mss << 16);
	txbd->tx_bd_vlan_tag_flags = vlan_tag_flags | TX_BD_FLAGS_START;

	last_frag = skb_shinfo(skb)->nr_frags;
	tx_buf->nr_frags = last_frag;
	tx_buf->is_gso = skb_is_gso(skb);

	for (i = 0; i < last_frag; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		prod = NEXT_TX_BD(prod);
		ring_prod = TX_RING_IDX(prod);
		txbd = &txr->tx_desc_ring[ring_prod];

		len = skb_frag_size(frag);
#if (LINUX_VERSION_CODE >= 0x02061b)
		mapping = dma_map_page(&bp->pdev->dev, frag->page, frag->page_offset,
				       len, PCI_DMA_TODEVICE);
		if (dma_mapping_error(&bp->pdev->dev, mapping))
#else
		mapping = pci_map_page(bp->pdev, frag->page, frag->page_offset,
			len, PCI_DMA_TODEVICE);
		if (pci_dma_mapping_error(mapping))
#endif
			goto dma_error;
		dma_unmap_addr_set(&txr->tx_buf_ring[ring_prod], mapping,
				   mapping);

		txbd->tx_bd_haddr_hi = (u64) mapping >> 32;
		txbd->tx_bd_haddr_lo = (u64) mapping & 0xffffffff;
		txbd->tx_bd_mss_nbytes = len | (mss << 16);
		txbd->tx_bd_vlan_tag_flags = vlan_tag_flags;

	}
	txbd->tx_bd_vlan_tag_flags |= TX_BD_FLAGS_END;

	/* Sync BD data before updating TX mailbox */
	wmb();

	prod = NEXT_TX_BD(prod);
	txr->tx_prod_bseq += skb->len;

	REG_WR16(bp, txr->tx_bidx_addr, prod);
	REG_WR(bp, txr->tx_bseq_addr, txr->tx_prod_bseq);

	mmiowb();

	txr->tx_prod = prod;
#if (LINUX_VERSION_CODE <= 0x2061e) || defined(__VMKLNX__)
	dev->trans_start = jiffies;
#endif

#if defined(BNX2_ENABLE_NETQUEUE)
	bnapi->tx_packets_sent++;
	wmb();
#endif

	if (unlikely(bnx2_tx_avail(bp, txr) <= MAX_SKB_FRAGS)) {
#ifndef BCM_HAVE_MULTI_QUEUE
		netif_stop_queue(dev);
#else
		netif_tx_stop_queue(txq);
#endif
		/* netif_tx_stop_queue() must be done before checking
		 * tx index in bnx2_tx_avail() below, because in
		 * bnx2_tx_int(), we update tx index before checking for
		 * netif_tx_queue_stopped().
		 */
		smp_mb();
		if (bnx2_tx_avail(bp, txr) > bp->tx_wake_thresh)
#ifndef BCM_HAVE_MULTI_QUEUE
			netif_wake_queue(dev);
#else
			netif_tx_wake_queue(txq);
#endif
	}

	return NETDEV_TX_OK;
dma_error:
	/* save value of frag that failed */
	last_frag = i;

	/* start back at beginning and unmap skb */
	prod = txr->tx_prod;
	ring_prod = TX_RING_IDX(prod);
	tx_buf = &txr->tx_buf_ring[ring_prod];
	tx_buf->skb = NULL;
#if (LINUX_VERSION_CODE >= 0x02061b)
	dma_unmap_single(&bp->pdev->dev, dma_unmap_addr(tx_buf, mapping),
			 skb_headlen(skb), PCI_DMA_TODEVICE);
#else
	pci_unmap_single(bp->pdev, dma_unmap_addr(tx_buf, mapping),
			 skb_headlen(skb), PCI_DMA_TODEVICE);
#endif

	/* unmap remaining mapped pages */
	for (i = 0; i < last_frag; i++) {
		prod = NEXT_TX_BD(prod);
		ring_prod = TX_RING_IDX(prod);
		tx_buf = &txr->tx_buf_ring[ring_prod];
#if (LINUX_VERSION_CODE >= 0x02061b)
		dma_unmap_page(&bp->pdev->dev, dma_unmap_addr(tx_buf, mapping),
#else
		pci_unmap_page(bp->pdev, dma_unmap_addr(tx_buf, mapping),
#endif
			       skb_frag_size(&skb_shinfo(skb)->frags[i]),
			       PCI_DMA_TODEVICE);
	}

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/* Called with rtnl_lock */
static int
bnx2_close(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);

#if defined(__VMKLNX__)
	bnx2_cnic_stop(bp);
#endif /* defined(__VMKLNX__) */
	bnx2_disable_int_sync(bp);
#ifdef BNX2_NEW_NAPI
	bnx2_napi_disable(bp);
#endif
	netif_tx_disable(bp->dev);
#if defined(BNX2_ENABLE_NETQUEUE)
	if (bnx2_netqueue_is_avail(bp) &&
	    (bp->netq_state == BNX2_NETQ_HW_STARTED))
		bnx2_netqueue_flush_all(bp);

	if (bnx2_netqueue_open_started(bp))
		bnx2_netqueue_tx_flush(bp);

	if (bnx2_netqueue_is_avail(bp))
		bnx2_close_netqueue_hw(bp);

#endif	/* BNX2_ENABLE_NETQUEUE */

	del_timer_sync(&bp->timer);
#if defined(BNX2_ENABLE_NETQUEUE)
	if (bp->reset_failed == 0)
		bnx2_shutdown_chip(bp);
#else /* BNX2_ENABLE_NETQUEUE */
	bnx2_shutdown_chip(bp);
#endif /* BNX2_ENABLE_NETQUEUE */

	bnx2_free_irq(bp);
	bnx2_free_skbs(bp);
	bnx2_free_mem(bp);
#if !defined(__VMKLNX__)
	bnx2_del_napi(bp);
#endif
	bp->link_up = 0;
	netif_carrier_off(bp->dev);
	bnx2_set_power_state(bp, PCI_D3hot);
	return 0;
}

static void
bnx2_save_stats(struct bnx2 *bp)
{
	u32 *hw_stats = (u32 *) bp->stats_blk;
	u32 *temp_stats = (u32 *) bp->temp_stats_blk;
	int i;

	/* The 1st 10 counters are 64-bit counters */
	for (i = 0; i < 20; i += 2) {
		u32 hi;
		u64 lo;

		hi = temp_stats[i] + hw_stats[i];
		lo = (u64) temp_stats[i + 1] + (u64) hw_stats[i + 1];
		if (lo > 0xffffffff)
			hi++;
		temp_stats[i] = hi;
		temp_stats[i + 1] = lo & 0xffffffff;
	}

	for ( ; i < sizeof(struct statistics_block) / 4; i++)
		temp_stats[i] += hw_stats[i];
}

#define GET_64BIT_NET_STATS64(ctr)				\
	(unsigned long) ((unsigned long) (ctr##_hi) << 32) +	\
	(unsigned long) (ctr##_lo)

#define GET_64BIT_NET_STATS32(ctr)				\
	(ctr##_lo)

#if (BITS_PER_LONG == 64)
#define GET_64BIT_NET_STATS(ctr)				\
	GET_64BIT_NET_STATS64(bp->stats_blk->ctr) +		\
	GET_64BIT_NET_STATS64(bp->temp_stats_blk->ctr)
#else
#define GET_64BIT_NET_STATS(ctr)				\
	GET_64BIT_NET_STATS32(bp->stats_blk->ctr) +		\
	GET_64BIT_NET_STATS32(bp->temp_stats_blk->ctr)
#endif

#define GET_32BIT_NET_STATS(ctr)				\
	(unsigned long) (bp->stats_blk->ctr +			\
			 bp->temp_stats_blk->ctr)

static struct net_device_stats *
bnx2_get_stats(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);
	struct net_device_stats *net_stats = &bp->net_stats;

	if (bp->stats_blk == NULL)
		return net_stats;

	net_stats->rx_packets =
		GET_64BIT_NET_STATS(stat_IfHCInUcastPkts) +
		GET_64BIT_NET_STATS(stat_IfHCInMulticastPkts) +
		GET_64BIT_NET_STATS(stat_IfHCInBroadcastPkts);

	net_stats->tx_packets =
		GET_64BIT_NET_STATS(stat_IfHCOutUcastPkts) +
		GET_64BIT_NET_STATS(stat_IfHCOutMulticastPkts) +
		GET_64BIT_NET_STATS(stat_IfHCOutBroadcastPkts);

	net_stats->rx_bytes =
		GET_64BIT_NET_STATS(stat_IfHCInOctets);

	net_stats->tx_bytes =
		GET_64BIT_NET_STATS(stat_IfHCOutOctets);

	net_stats->multicast =
		GET_64BIT_NET_STATS(stat_IfHCInMulticastPkts);

	net_stats->collisions =
		GET_32BIT_NET_STATS(stat_EtherStatsCollisions);

	net_stats->rx_length_errors =
		GET_32BIT_NET_STATS(stat_EtherStatsUndersizePkts) +
		GET_32BIT_NET_STATS(stat_EtherStatsOverrsizePkts);

	net_stats->rx_over_errors =
		GET_32BIT_NET_STATS(stat_IfInFTQDiscards) +
		GET_32BIT_NET_STATS(stat_IfInMBUFDiscards);

	net_stats->rx_frame_errors =
		GET_32BIT_NET_STATS(stat_Dot3StatsAlignmentErrors);

	net_stats->rx_crc_errors =
		GET_32BIT_NET_STATS(stat_Dot3StatsFCSErrors);

	net_stats->rx_errors = net_stats->rx_length_errors +
		net_stats->rx_over_errors + net_stats->rx_frame_errors +
		net_stats->rx_crc_errors;

	net_stats->tx_aborted_errors =
		GET_32BIT_NET_STATS(stat_Dot3StatsExcessiveCollisions) +
		GET_32BIT_NET_STATS(stat_Dot3StatsLateCollisions);

	if ((CHIP_NUM(bp) == CHIP_NUM_5706) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_A0))
		net_stats->tx_carrier_errors = 0;
	else {
		net_stats->tx_carrier_errors =
			GET_32BIT_NET_STATS(stat_Dot3StatsCarrierSenseErrors);
	}

	net_stats->tx_errors =
		GET_32BIT_NET_STATS(stat_emac_tx_stat_dot3statsinternalmactransmiterrors) +
		net_stats->tx_aborted_errors +
		net_stats->tx_carrier_errors;

	net_stats->rx_missed_errors =
		GET_32BIT_NET_STATS(stat_IfInFTQDiscards) +
		GET_32BIT_NET_STATS(stat_IfInMBUFDiscards) +
		GET_32BIT_NET_STATS(stat_FwRxDrop);

	return net_stats;
}

/* All ethtool functions called with rtnl_lock */

static int
bnx2_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct bnx2 *bp = netdev_priv(dev);
	int support_serdes = 0, support_copper = 0;

	cmd->supported = SUPPORTED_Autoneg;
	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP) {
		support_serdes = 1;
		support_copper = 1;
	} else if (bp->phy_port == PORT_FIBRE)
		support_serdes = 1;
	else
		support_copper = 1;

	if (support_serdes) {
		cmd->supported |= SUPPORTED_1000baseT_Full |
			SUPPORTED_FIBRE;
		if (bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE)
			cmd->supported |= SUPPORTED_2500baseX_Full;

	}
	if (support_copper) {
		cmd->supported |= SUPPORTED_10baseT_Half |
			SUPPORTED_10baseT_Full |
			SUPPORTED_100baseT_Half |
			SUPPORTED_100baseT_Full |
			SUPPORTED_1000baseT_Full |
			SUPPORTED_TP;

	}

	spin_lock_bh(&bp->phy_lock);
	cmd->port = bp->phy_port;
	cmd->advertising = bp->advertising;

	if (bp->autoneg & AUTONEG_SPEED) {
		cmd->autoneg = AUTONEG_ENABLE;
	} else {
		cmd->autoneg = AUTONEG_DISABLE;
	}

	if (netif_carrier_ok(dev)) {
		ethtool_cmd_speed_set(cmd, bp->line_speed);
		cmd->duplex = bp->duplex;
	}
	else {
		ethtool_cmd_speed_set(cmd, -1);
		cmd->duplex = -1;
	}
	spin_unlock_bh(&bp->phy_lock);

	cmd->transceiver = XCVR_INTERNAL;
	cmd->phy_address = bp->phy_addr;

	return 0;
}

static int
bnx2_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct bnx2 *bp = netdev_priv(dev);
	u8 autoneg = bp->autoneg;
	u8 req_duplex = bp->req_duplex;
	u16 req_line_speed = bp->req_line_speed;
	u32 advertising = bp->advertising;
	int err = -EINVAL;

	spin_lock_bh(&bp->phy_lock);

	if (cmd->port != PORT_TP && cmd->port != PORT_FIBRE)
		goto err_out_unlock;

	if (cmd->port != bp->phy_port &&
	    !(bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP))
		goto err_out_unlock;

	/* If device is down, we can store the settings only if the user
	 * is setting the currently active port.
	 */
	if (!netif_running(dev) && cmd->port != bp->phy_port)
		goto err_out_unlock;

	if (cmd->autoneg == AUTONEG_ENABLE) {
		autoneg |= AUTONEG_SPEED;

		advertising = cmd->advertising;
		if (cmd->port == PORT_TP) {
			advertising &= ETHTOOL_ALL_COPPER_SPEED;
			if (!advertising)
				advertising = ETHTOOL_ALL_COPPER_SPEED;
		} else {
			advertising &= ETHTOOL_ALL_FIBRE_SPEED;
			if (!advertising)
				advertising = ETHTOOL_ALL_FIBRE_SPEED;
		}
		advertising |= ADVERTISED_Autoneg;
	}
	else {
		if (cmd->port == PORT_FIBRE) {
			if ((cmd->speed != SPEED_1000 &&
			     cmd->speed != SPEED_2500) ||
			    (cmd->duplex != DUPLEX_FULL))
				goto err_out_unlock;

			if (cmd->speed == SPEED_2500 &&
			    !(bp->phy_flags & BNX2_PHY_FLAG_2_5G_CAPABLE))
				goto err_out_unlock;
		}
		else if (cmd->speed == SPEED_1000 || cmd->speed == SPEED_2500)
			goto err_out_unlock;

		autoneg &= ~AUTONEG_SPEED;
		req_line_speed = cmd->speed;
		req_duplex = cmd->duplex;
		advertising = 0;
	}

	bp->autoneg = autoneg;
	bp->advertising = advertising;
	bp->req_line_speed = req_line_speed;
	bp->req_duplex = req_duplex;

	err = 0;
	/* If device is down, the new settings will be picked up when it is
	 * brought up.
	 */
	if (netif_running(dev))
		err = bnx2_setup_phy(bp, cmd->port);

err_out_unlock:
	spin_unlock_bh(&bp->phy_lock);

	return err;
}

static void
bnx2_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct bnx2 *bp = netdev_priv(dev);

	strcpy(info->driver, DRV_MODULE_NAME);
	strcpy(info->version, DRV_MODULE_VERSION);
	strcpy(info->bus_info, pci_name(bp->pdev));
	strcpy(info->fw_version, bp->fw_version);

#if defined(VMWARE_ESX_DDK_VERSION) && \
    (VMWARE_ESX_DDK_VERSION >= 35000) && (VMWARE_ESX_DDK_VERSION < 40000)
	info->eedump_len = bnx2_get_eeprom_len(dev);
#endif
}

#define BNX2_REGDUMP_LEN		(32 * 1024)

static int
bnx2_get_regs_len(struct net_device *dev)
{
	return BNX2_REGDUMP_LEN;
}

static void
bnx2_get_regs(struct net_device *dev, struct ethtool_regs *regs, void *_p)
{
	u32 *p = _p, i, offset;
	u8 *orig_p = _p;
	struct bnx2 *bp = netdev_priv(dev);
	static const u32 reg_boundaries[] = {
		0x0000, 0x0098, 0x0400, 0x045c,
		0x0800, 0x0880, 0x0c00, 0x0c10,
		0x0c30, 0x0d08, 0x1000, 0x101c,
		0x1040, 0x1048, 0x1080, 0x10a4,
		0x1400, 0x1490, 0x1498, 0x14f0,
		0x1500, 0x155c, 0x1580, 0x15dc,
		0x1600, 0x1658, 0x1680, 0x16d8,
		0x1800, 0x1820, 0x1840, 0x1854,
		0x1880, 0x1894, 0x1900, 0x1984,
		0x1c00, 0x1c0c, 0x1c40, 0x1c54,
		0x1c80, 0x1c94, 0x1d00, 0x1d84,
		0x2000, 0x2030, 0x23c0, 0x2400,
		0x2800, 0x2820, 0x2830, 0x2850,
		0x2b40, 0x2c10, 0x2fc0, 0x3058,
		0x3c00, 0x3c94, 0x4000, 0x4010,
		0x4080, 0x4090, 0x43c0, 0x4458,
		0x4c00, 0x4c18, 0x4c40, 0x4c54,
		0x4fc0, 0x5010, 0x53c0, 0x5444,
		0x5c00, 0x5c18, 0x5c80, 0x5c90,
		0x5fc0, 0x6000, 0x6400, 0x6428,
		0x6800, 0x6848, 0x684c, 0x6860,
		0x6888, 0x6910, 0x8000
	};

	regs->version = 0;

	memset(p, 0, BNX2_REGDUMP_LEN);

	if (!netif_running(bp->dev))
		return;

	i = 0;
	offset = reg_boundaries[0];
	p += offset;
	while (offset < BNX2_REGDUMP_LEN) {
		*p++ = REG_RD(bp, offset);
		offset += 4;
		if (offset == reg_boundaries[i + 1]) {
			offset = reg_boundaries[i + 2];
			p = (u32 *) (orig_p + offset);
			i += 2;
		}
	}
}

static void
bnx2_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct bnx2 *bp = netdev_priv(dev);

	if (bp->flags & BNX2_FLAG_NO_WOL) {
		wol->supported = 0;
		wol->wolopts = 0;
	}
	else {
		wol->supported = WAKE_MAGIC;
		if (bp->wol)
			wol->wolopts = WAKE_MAGIC;
		else
			wol->wolopts = 0;
	}
	memset(&wol->sopass, 0, sizeof(wol->sopass));
}

static int
bnx2_set_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct bnx2 *bp = netdev_priv(dev);

	if (wol->wolopts & ~WAKE_MAGIC)
		return -EINVAL;

	if (wol->wolopts & WAKE_MAGIC) {
		if (bp->flags & BNX2_FLAG_NO_WOL)
			return -EINVAL;

		bp->wol = 1;
	}
	else {
		bp->wol = 0;
	}
	return 0;
}

static int
bnx2_nway_reset(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);
	u32 bmcr;

	if (!netif_running(dev))
		return -EAGAIN;

	if (!(bp->autoneg & AUTONEG_SPEED)) {
		return -EINVAL;
	}

	spin_lock_bh(&bp->phy_lock);

	if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP) {
		int rc;

		rc = bnx2_setup_remote_phy(bp, bp->phy_port);
		spin_unlock_bh(&bp->phy_lock);
		return rc;
	}

	/* Force a link down visible on the other side */
	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		bnx2_write_phy(bp, bp->mii_bmcr, BMCR_LOOPBACK);
		spin_unlock_bh(&bp->phy_lock);

		bnx2_msleep(20);

		spin_lock_bh(&bp->phy_lock);

		bp->current_interval = BNX2_SERDES_AN_TIMEOUT;
		bp->serdes_an_pending = 1;
		mod_timer(&bp->timer, jiffies + bp->current_interval);
	}

	bnx2_read_phy(bp, bp->mii_bmcr, &bmcr);
	bmcr &= ~BMCR_LOOPBACK;
	bnx2_write_phy(bp, bp->mii_bmcr, bmcr | BMCR_ANRESTART | BMCR_ANENABLE);

	spin_unlock_bh(&bp->phy_lock);

	return 0;
}

static u32
bnx2_get_link(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);

	return bp->link_up;
}

#if (LINUX_VERSION_CODE >= 0x20418) || \
    (defined(VMWARE_ESX_DDK_VERSION) && \
    ((VMWARE_ESX_DDK_VERSION >= 35000) && (VMWARE_ESX_DDK_VERSION < 40000)))
static int
bnx2_get_eeprom_len(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);

	if (bp->flash_info == NULL)
		return 0;

	return (int) bp->flash_size;
}
#endif

#ifdef ETHTOOL_GEEPROM
static int
bnx2_get_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom,
		u8 *eebuf)
{
	struct bnx2 *bp = netdev_priv(dev);
	int rc;

	if (!netif_running(dev))
		return -EAGAIN;

	/* parameters already validated in ethtool_get_eeprom */

	rc = bnx2_nvram_read(bp, eeprom->offset, eebuf, eeprom->len);

	return rc;
}
#endif

#ifdef ETHTOOL_SEEPROM
static int
bnx2_set_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom,
		u8 *eebuf)
{
	struct bnx2 *bp = netdev_priv(dev);
	int rc;

	if (!netif_running(dev))
		return -EAGAIN;

	/* parameters already validated in ethtool_set_eeprom */

	rc = bnx2_nvram_write(bp, eeprom->offset, eebuf, eeprom->len);

	return rc;
}
#endif

static int
bnx2_get_coalesce(struct net_device *dev, struct ethtool_coalesce *coal)
{
	struct bnx2 *bp = netdev_priv(dev);

	memset(coal, 0, sizeof(struct ethtool_coalesce));

	coal->rx_coalesce_usecs = bp->rx_ticks;
	coal->rx_max_coalesced_frames = bp->rx_quick_cons_trip;
	coal->rx_coalesce_usecs_irq = bp->rx_ticks_int;
	coal->rx_max_coalesced_frames_irq = bp->rx_quick_cons_trip_int;

	coal->tx_coalesce_usecs = bp->tx_ticks;
	coal->tx_max_coalesced_frames = bp->tx_quick_cons_trip;
	coal->tx_coalesce_usecs_irq = bp->tx_ticks_int;
	coal->tx_max_coalesced_frames_irq = bp->tx_quick_cons_trip_int;

	coal->stats_block_coalesce_usecs = bp->stats_ticks;

	return 0;
}

static int
bnx2_set_coalesce(struct net_device *dev, struct ethtool_coalesce *coal)
{
	struct bnx2 *bp = netdev_priv(dev);

	bp->rx_ticks = (u16) coal->rx_coalesce_usecs;
	if (bp->rx_ticks > 0x3ff) bp->rx_ticks = 0x3ff;

	bp->rx_quick_cons_trip = (u16) coal->rx_max_coalesced_frames;
	if (bp->rx_quick_cons_trip > 0xff) bp->rx_quick_cons_trip = 0xff;

	bp->rx_ticks_int = (u16) coal->rx_coalesce_usecs_irq;
	if (bp->rx_ticks_int > 0x3ff) bp->rx_ticks_int = 0x3ff;

	bp->rx_quick_cons_trip_int = (u16) coal->rx_max_coalesced_frames_irq;
	if (bp->rx_quick_cons_trip_int > 0xff)
		bp->rx_quick_cons_trip_int = 0xff;

	bp->tx_ticks = (u16) coal->tx_coalesce_usecs;
	if (bp->tx_ticks > 0x3ff) bp->tx_ticks = 0x3ff;

	bp->tx_quick_cons_trip = (u16) coal->tx_max_coalesced_frames;
	if (bp->tx_quick_cons_trip > 0xff) bp->tx_quick_cons_trip = 0xff;

	bp->tx_ticks_int = (u16) coal->tx_coalesce_usecs_irq;
	if (bp->tx_ticks_int > 0x3ff) bp->tx_ticks_int = 0x3ff;

	bp->tx_quick_cons_trip_int = (u16) coal->tx_max_coalesced_frames_irq;
	if (bp->tx_quick_cons_trip_int > 0xff) bp->tx_quick_cons_trip_int =
		0xff;

	bp->stats_ticks = coal->stats_block_coalesce_usecs;
	if (bp->flags & BNX2_FLAG_BROKEN_STATS) {
		if (bp->stats_ticks != 0 && bp->stats_ticks != USEC_PER_SEC)
			bp->stats_ticks = USEC_PER_SEC;
	}
	if (bp->stats_ticks > BNX2_HC_STATS_TICKS_HC_STAT_TICKS)
		bp->stats_ticks = BNX2_HC_STATS_TICKS_HC_STAT_TICKS;
	bp->stats_ticks &= BNX2_HC_STATS_TICKS_HC_STAT_TICKS;

	if (netif_running(bp->dev)) {
		bnx2_netif_stop(bp, true);
		bnx2_init_nic(bp, 0);
		bnx2_netif_start(bp, true);
	}

	return 0;
}

static void
bnx2_get_ringparam(struct net_device *dev, struct ethtool_ringparam *ering)
{
	struct bnx2 *bp = netdev_priv(dev);

	ering->rx_max_pending = MAX_TOTAL_RX_DESC_CNT;
	ering->rx_jumbo_max_pending = MAX_TOTAL_RX_PG_DESC_CNT;

	ering->rx_pending = bp->rx_ring_size;
	ering->rx_jumbo_pending = bp->rx_pg_ring_size;

	ering->tx_max_pending = MAX_TX_DESC_CNT;
	ering->tx_pending = bp->tx_ring_size;
}

static int
bnx2_change_ring_size(struct bnx2 *bp, u32 rx, u32 tx, bool reset_irq)
{
	int rc = 0;

#if defined(__VMKLNX__)
	if(bp->reset_failed) {
		netdev_err(bp->dev, "Previous error detected preventing MTU "
				    "change\n");
		return -EIO;
	}
#endif /* defined(__VMKLNX__) */

	if (netif_running(bp->dev)) {
		/* Reset will erase chipset stats; save them */
		bnx2_save_stats(bp);

#if defined(__VMKLNX__) && defined(BNX2_ENABLE_NETQUEUE)
		netif_tx_disable(bp->dev);
		bp->dev->trans_start = jiffies; /* prevent tx timeout */

		if (bnx2_netqueue_is_avail(bp) &&
		    (bp->netq_state & BNX2_NETQ_HW_STARTED)) {
			bnx2_netqueue_flush_all(bp);
		}
		bnx2_stop_netqueue_hw(bp);
#endif /* defined(BNX2_ENABLE_NETQUEUE) && defined(__VMKLNX__) */

		bnx2_netif_stop(bp, true);

#if defined(__VMKLNX__)
#if defined(BNX2_ENABLE_NETQUEUE) && (VMWARE_ESX_DDK_VERSION >= 41000)
		vmknetddi_queueops_invalidate_state(bp->dev);
#endif /* defined(BNX2_ENABLE_NETQUEUE) && (VMWARE_ESX_DDK_VERSION >= 41000) */

		rc = bnx2_reset_chip(bp, BNX2_DRV_MSG_CODE_RESET);

		/*  Did the chip reset fail ? */
		if (rc != 0) {
			netdev_err(bp->dev, "chip reset failed during MTU "
					    "change\n");

			bp->reset_failed = 1;

			goto error;
		}
		bnx2_free_irq(bp);
#else  /* !defined(__VMKLNX__) */
		bnx2_reset_chip(bp, BNX2_DRV_MSG_CODE_RESET);
		if (reset_irq) {
			bnx2_free_irq(bp);
			bnx2_del_napi(bp);
		} else {
			__bnx2_free_irq(bp);
		}
#endif /* defined(__VMKLNX__) */
		bnx2_free_skbs(bp);
		bnx2_free_mem(bp);
	}

	bnx2_set_rx_ring_size(bp, rx);
	bp->tx_ring_size = tx;

	if (netif_running(bp->dev)) {
		if (reset_irq) {
			rc = bnx2_setup_int_mode(bp, disable_msi);
			bnx2_init_napi(bp);
		}

		if (!rc) 
			rc = bnx2_alloc_mem(bp);
#if defined(BNX2_ENABLE_NETQUEUE)
		if (rc) {
			netdev_err(bp->dev, "failed alloc mem during MTU "
					    "change\n");
			goto error;
		}

		rc = bnx2_request_irq(bp);
		if (rc) {
			netdev_err(bp->dev, "failed request irq during MTU "
					    "change %d\n", rc);
			goto error;
		}

		rc = bnx2_init_nic(bp, 0);
		if (rc) {
			netdev_err(bp->dev, "failed init nic during MTU "
					    "change\n");
			goto error;
		}

		bnx2_init_netqueue_hw(bp);
		bnx2_start_netqueue_hw(bp);
#else /* !defined(BNX2_ENABLE_NETQUEUE) */
		if (!rc)
			rc = bnx2_request_irq(bp);

		if (!rc)
			rc = bnx2_init_nic(bp, 0);

		if (rc) {

			bnx2_napi_enable(bp);
			dev_close(bp->dev);
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION == 41000)
			/* PR 533926
			 * This is a workaround to sync device status in dev->flags and
			 * dev->gflags. It is needed to avoid PSOD (due to double dev_close)
			 * on reboot. In ESX5.0, the return value of this function will be
			 * checked by NICSetMTU, where gflags will be updated appropriately.
			 */
			bp->dev->gflags &= ~IFF_DEV_IS_OPEN;
#endif
			return rc;
		}
#endif /* defined(BNX2_ENABLE_NETQUEUE) */
#ifdef BCM_CNIC
		mutex_lock(&bp->cnic_lock);
		/* Let cnic know about the new status block. */
		if (bp->cnic_eth_dev.drv_state & CNIC_DRV_STATE_REGD)
			bnx2_setup_cnic_irq_info(bp);
		mutex_unlock(&bp->cnic_lock);
#endif
		bnx2_netif_start(bp, true);
	}

	return 0;

#if defined(__VMKLNX__)
error:
	netif_carrier_off(bp->dev);

	return rc;
#endif /* defined(__VMKLNX__) */
}

static int
bnx2_set_ringparam(struct net_device *dev, struct ethtool_ringparam *ering)
{
	struct bnx2 *bp = netdev_priv(dev);
	int rc;

	if ((ering->rx_pending > MAX_TOTAL_RX_DESC_CNT) ||
		(ering->tx_pending > MAX_TX_DESC_CNT) ||
		(ering->tx_pending <= MAX_SKB_FRAGS)) {

		return -EINVAL;
	}
	rc = bnx2_change_ring_size(bp, ering->rx_pending, ering->tx_pending,
				   false);
	return rc;
}

static void
bnx2_get_pauseparam(struct net_device *dev, struct ethtool_pauseparam *epause)
{
	struct bnx2 *bp = netdev_priv(dev);

	epause->autoneg = ((bp->autoneg & AUTONEG_FLOW_CTRL) != 0);
	epause->rx_pause = ((bp->flow_ctrl & FLOW_CTRL_RX) != 0);
	epause->tx_pause = ((bp->flow_ctrl & FLOW_CTRL_TX) != 0);
}

static int
bnx2_set_pauseparam(struct net_device *dev, struct ethtool_pauseparam *epause)
{
	struct bnx2 *bp = netdev_priv(dev);

	bp->req_flow_ctrl = 0;
	if (epause->rx_pause)
		bp->req_flow_ctrl |= FLOW_CTRL_RX;
	if (epause->tx_pause)
		bp->req_flow_ctrl |= FLOW_CTRL_TX;

	if (epause->autoneg) {
		bp->autoneg |= AUTONEG_FLOW_CTRL;
	}
	else {
		bp->autoneg &= ~AUTONEG_FLOW_CTRL;
	}

	if (netif_running(dev)) {
		spin_lock_bh(&bp->phy_lock);
		bnx2_setup_phy(bp, bp->phy_port);
		spin_unlock_bh(&bp->phy_lock);
	}

	return 0;
}

static u32
bnx2_get_rx_csum(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);

	return bp->rx_csum;
}

static int
bnx2_set_rx_csum(struct net_device *dev, u32 data)
{
	struct bnx2 *bp = netdev_priv(dev);

	bp->rx_csum = data;
	return 0;
}

#ifdef BCM_TSO
static int
bnx2_set_tso(struct net_device *dev, u32 data)
{
	struct bnx2 *bp = netdev_priv(dev);

	if (data) {
		dev->features |= NETIF_F_TSO | NETIF_F_TSO_ECN;
		if (CHIP_NUM(bp) == CHIP_NUM_5709)
			dev->features |= NETIF_F_TSO6;
	} else
		dev->features &= ~(NETIF_F_TSO | NETIF_F_TSO6 |
				   NETIF_F_TSO_ECN);
	return 0;
}
#endif

static struct {
	char string[ETH_GSTRING_LEN];
} bnx2_stats_str_arr[] = {
	{ "rx_bytes" },
	{ "rx_error_bytes" },
	{ "tx_bytes" },
	{ "tx_error_bytes" },
	{ "rx_ucast_packets" },
	{ "rx_mcast_packets" },
	{ "rx_bcast_packets" },
	{ "tx_ucast_packets" },
	{ "tx_mcast_packets" },
	{ "tx_bcast_packets" },
	{ "tx_mac_errors" },
	{ "tx_carrier_errors" },
	{ "rx_crc_errors" },
	{ "rx_align_errors" },
	{ "tx_single_collisions" },
	{ "tx_multi_collisions" },
	{ "tx_deferred" },
	{ "tx_excess_collisions" },
	{ "tx_late_collisions" },
	{ "tx_total_collisions" },
	{ "rx_fragments" },
	{ "rx_jabbers" },
	{ "rx_undersize_packets" },
	{ "rx_oversize_packets" },
	{ "rx_64_byte_packets" },
	{ "rx_65_to_127_byte_packets" },
	{ "rx_128_to_255_byte_packets" },
	{ "rx_256_to_511_byte_packets" },
	{ "rx_512_to_1023_byte_packets" },
	{ "rx_1024_to_1522_byte_packets" },
	{ "rx_1523_to_9022_byte_packets" },
	{ "tx_64_byte_packets" },
	{ "tx_65_to_127_byte_packets" },
	{ "tx_128_to_255_byte_packets" },
	{ "tx_256_to_511_byte_packets" },
	{ "tx_512_to_1023_byte_packets" },
	{ "tx_1024_to_1522_byte_packets" },
	{ "tx_1523_to_9022_byte_packets" },
	{ "rx_xon_frames" },
	{ "rx_xoff_frames" },
	{ "tx_xon_frames" },
	{ "tx_xoff_frames" },
	{ "rx_mac_ctrl_frames" },
	{ "rx_filtered_packets" },
	{ "rx_ftq_discards" },
	{ "rx_discards" },
	{ "rx_fw_discards" },
#if defined(BNX2_ENABLE_NETQUEUE)
	{ "[0] rx_packets" },
	{ "[0] rx_bytes" },
	{ "[0] rx_errors" },
	{ "[0] tx_packets" },
	{ "[0] tx_bytes" },
	{ "[1] rx_packets" },
	{ "[1] rx_bytes" },
	{ "[1] rx_errors" },
	{ "[1] tx_packets" },
	{ "[1] tx_bytes" },
	{ "[2] rx_packets" },
	{ "[2] rx_bytes" },
	{ "[2] rx_errors" },
	{ "[2] tx_packets" },
	{ "[2] tx_bytes" },
	{ "[3] rx_packets" },
	{ "[3] rx_bytes" },
	{ "[3] rx_errors" },
	{ "[3] tx_packets" },
	{ "[3] tx_bytes" },
	{ "[4] rx_packets" },
	{ "[4] rx_bytes" },
	{ "[4] rx_errors" },
	{ "[4] tx_packets" },
	{ "[4] tx_bytes" },
	{ "[5] rx_packets" },
	{ "[5] rx_bytes" },
	{ "[5] rx_errors" },
	{ "[5] tx_packets" },
	{ "[5] tx_bytes" },
	{ "[6] rx_packets" },
	{ "[6] rx_bytes" },
	{ "[6] rx_errors" },
	{ "[6] tx_packets" },
	{ "[6] tx_bytes" },
	{ "[7] rx_packets" },
	{ "[7] rx_bytes" },
	{ "[7] rx_errors" },
	{ "[7] tx_packets" },
	{ "[7] tx_bytes" },
	{ "[8] rx_packets" },
	{ "[8] rx_bytes" },
	{ "[8] rx_errors" },
	{ "[8] tx_packets" },
	{ "[8] tx_bytes" },
#endif
};

#define BNX2_NUM_STATS ARRAY_SIZE(bnx2_stats_str_arr)

#if defined(BNX2_ENABLE_NETQUEUE)
#define BNX2_NUM_NETQ_STATS 45
#endif

#define STATS_OFFSET32(offset_name) (offsetof(struct statistics_block, offset_name) / 4)

static const unsigned long bnx2_stats_offset_arr[BNX2_NUM_STATS] = {
    STATS_OFFSET32(stat_IfHCInOctets_hi),
    STATS_OFFSET32(stat_IfHCInBadOctets_hi),
    STATS_OFFSET32(stat_IfHCOutOctets_hi),
    STATS_OFFSET32(stat_IfHCOutBadOctets_hi),
    STATS_OFFSET32(stat_IfHCInUcastPkts_hi),
    STATS_OFFSET32(stat_IfHCInMulticastPkts_hi),
    STATS_OFFSET32(stat_IfHCInBroadcastPkts_hi),
    STATS_OFFSET32(stat_IfHCOutUcastPkts_hi),
    STATS_OFFSET32(stat_IfHCOutMulticastPkts_hi),
    STATS_OFFSET32(stat_IfHCOutBroadcastPkts_hi),
    STATS_OFFSET32(stat_emac_tx_stat_dot3statsinternalmactransmiterrors),
    STATS_OFFSET32(stat_Dot3StatsCarrierSenseErrors),
    STATS_OFFSET32(stat_Dot3StatsFCSErrors),
    STATS_OFFSET32(stat_Dot3StatsAlignmentErrors),
    STATS_OFFSET32(stat_Dot3StatsSingleCollisionFrames),
    STATS_OFFSET32(stat_Dot3StatsMultipleCollisionFrames),
    STATS_OFFSET32(stat_Dot3StatsDeferredTransmissions),
    STATS_OFFSET32(stat_Dot3StatsExcessiveCollisions),
    STATS_OFFSET32(stat_Dot3StatsLateCollisions),
    STATS_OFFSET32(stat_EtherStatsCollisions),
    STATS_OFFSET32(stat_EtherStatsFragments),
    STATS_OFFSET32(stat_EtherStatsJabbers),
    STATS_OFFSET32(stat_EtherStatsUndersizePkts),
    STATS_OFFSET32(stat_EtherStatsOverrsizePkts),
    STATS_OFFSET32(stat_EtherStatsPktsRx64Octets),
    STATS_OFFSET32(stat_EtherStatsPktsRx65Octetsto127Octets),
    STATS_OFFSET32(stat_EtherStatsPktsRx128Octetsto255Octets),
    STATS_OFFSET32(stat_EtherStatsPktsRx256Octetsto511Octets),
    STATS_OFFSET32(stat_EtherStatsPktsRx512Octetsto1023Octets),
    STATS_OFFSET32(stat_EtherStatsPktsRx1024Octetsto1522Octets),
    STATS_OFFSET32(stat_EtherStatsPktsRx1523Octetsto9022Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx64Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx65Octetsto127Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx128Octetsto255Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx256Octetsto511Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx512Octetsto1023Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx1024Octetsto1522Octets),
    STATS_OFFSET32(stat_EtherStatsPktsTx1523Octetsto9022Octets),
    STATS_OFFSET32(stat_XonPauseFramesReceived),
    STATS_OFFSET32(stat_XoffPauseFramesReceived),
    STATS_OFFSET32(stat_OutXonSent),
    STATS_OFFSET32(stat_OutXoffSent),
    STATS_OFFSET32(stat_MacControlFramesReceived),
    STATS_OFFSET32(stat_IfInFramesL2FilterDiscards),
    STATS_OFFSET32(stat_IfInFTQDiscards),
    STATS_OFFSET32(stat_IfInMBUFDiscards),
    STATS_OFFSET32(stat_FwRxDrop),
};

/* stat_IfHCInBadOctets and stat_Dot3StatsCarrierSenseErrors are
 * skipped because of errata.
 */
static u8 bnx2_5706_stats_len_arr[BNX2_NUM_STATS] = {
	8,0,8,8,8,8,8,8,8,8,
	4,0,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,
};

static u8 bnx2_5708_stats_len_arr[BNX2_NUM_STATS] = {
	8,0,8,8,8,8,8,8,8,8,
	4,4,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,
};

#define BNX2_NUM_TESTS 6

static struct {
	char string[ETH_GSTRING_LEN];
} bnx2_tests_str_arr[BNX2_NUM_TESTS] = {
	{ "register_test (offline)" },
	{ "memory_test (offline)" },
	{ "loopback_test (offline)" },
	{ "nvram_test (online)" },
	{ "interrupt_test (online)" },
	{ "link_test (online)" },
};

#ifdef ETHTOOL_GFLAGS
static int
bnx2_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_TEST:
		return BNX2_NUM_TESTS;
	case ETH_SS_STATS:
		return BNX2_NUM_STATS;
	default:
		return -EOPNOTSUPP;
	}
}
#else
static int
bnx2_self_test_count(struct net_device *dev)
{
	return BNX2_NUM_TESTS;
}
#endif

static void
bnx2_self_test(struct net_device *dev, struct ethtool_test *etest, u64 *buf)
{
	struct bnx2 *bp = netdev_priv(dev);

	bnx2_set_power_state(bp, PCI_D0);

	memset(buf, 0, sizeof(u64) * BNX2_NUM_TESTS);
	if (etest->flags & ETH_TEST_FL_OFFLINE) {
		int i;

		bnx2_netif_stop(bp, true);
		bnx2_reset_chip(bp, BNX2_DRV_MSG_CODE_DIAG);
		bnx2_free_skbs(bp);

		if (bnx2_test_registers(bp) != 0) {
			buf[0] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
		if (bnx2_test_memory(bp) != 0) {
			buf[1] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
		if ((buf[2] = bnx2_test_loopback(bp)) != 0)
			etest->flags |= ETH_TEST_FL_FAILED;

		if (!netif_running(bp->dev))
			bnx2_shutdown_chip(bp);
		else {
			bnx2_init_nic(bp, 1);
			bnx2_netif_start(bp, true);
		}

		/* wait for link up */
		for (i = 0; i < 7; i++) {
			if (bp->link_up)
				break;
			bnx2_msleep_interruptible(1000);
		}
	}

	if (bnx2_test_nvram(bp) != 0) {
		buf[3] = 1;
		etest->flags |= ETH_TEST_FL_FAILED;
	}
	if (bnx2_test_intr(bp) != 0) {
		buf[4] = 1;
		etest->flags |= ETH_TEST_FL_FAILED;
	}

	if (bnx2_test_link(bp) != 0) {
		buf[5] = 1;
		etest->flags |= ETH_TEST_FL_FAILED;

	}
	if (!netif_running(bp->dev))
		bnx2_set_power_state(bp, PCI_D3hot);
}

static void
bnx2_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	switch (stringset) {
	case ETH_SS_STATS:
		memcpy(buf, bnx2_stats_str_arr,
			sizeof(bnx2_stats_str_arr));
		break;
	case ETH_SS_TEST:
		memcpy(buf, bnx2_tests_str_arr,
			sizeof(bnx2_tests_str_arr));
		break;
	}
}

#ifndef ETHTOOL_GFLAGS
static int
bnx2_get_stats_count(struct net_device *dev)
{
	return BNX2_NUM_STATS;
}
#endif

static void
bnx2_get_ethtool_stats(struct net_device *dev,
		struct ethtool_stats *stats, u64 *buf)
{
	struct bnx2 *bp = netdev_priv(dev);
	int i;
	u32 *hw_stats = (u32 *) bp->stats_blk;
	u32 *temp_stats = (u32 *) bp->temp_stats_blk;
	u8 *stats_len_arr = NULL;

	if (hw_stats == NULL) {
		memset(buf, 0, sizeof(u64) * BNX2_NUM_STATS);
		return;
	}

	if ((CHIP_ID(bp) == CHIP_ID_5706_A0) ||
	    (CHIP_ID(bp) == CHIP_ID_5706_A1) ||
	    (CHIP_ID(bp) == CHIP_ID_5706_A2) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_A0))
		stats_len_arr = bnx2_5706_stats_len_arr;
	else
		stats_len_arr = bnx2_5708_stats_len_arr;

#if defined(BNX2_ENABLE_NETQUEUE)
	for (i = 0; i < BNX2_NUM_STATS - BNX2_NUM_NETQ_STATS; i++) {
#else
	for (i = 0; i < BNX2_NUM_STATS; i++) {
#endif
		unsigned long offset;

		if (stats_len_arr[i] == 0) {
			/* skip this counter */
			buf[i] = 0;
			continue;
		}

		offset = bnx2_stats_offset_arr[i];
		if (stats_len_arr[i] == 4) {
			/* 4-byte counter */
			buf[i] = (u64) *(hw_stats + offset) +
				 *(temp_stats + offset);
			continue;
		}
		/* 8-byte counter */
		buf[i] = (((u64) *(hw_stats + offset)) << 32) +
			 *(hw_stats + offset + 1) +
			 (((u64) *(temp_stats + offset)) << 32) +
			 *(temp_stats + offset + 1);
	}

#if defined(BNX2_ENABLE_NETQUEUE)
	/*  Copy over the NetQ specific statistics */
	{
		int j;

		for (j = 0; j < BNX2_MAX_MSIX_VEC; j++) {
			struct bnx2_napi *bnapi = &bp->bnx2_napi[j];

			buf[i + (j*5) + 0] = (u64) (bnapi->stats.rx_packets);
			buf[i + (j*5) + 1] = (u64) (bnapi->stats.rx_bytes);
			buf[i + (j*5) + 2] = (u64) (bnapi->stats.rx_errors);
			buf[i + (j*5) + 3] = (u64) (bnapi->stats.tx_packets);
			buf[i + (j*5) + 4] = (u64) (bnapi->stats.tx_bytes);
		}
	}
#endif
}

#if (LINUX_VERSION_CODE < 0x30000)
static int
bnx2_phys_id(struct net_device *dev, u32 data)
{
	struct bnx2 *bp = netdev_priv(dev);
	int i;
	u32 save;

	bnx2_set_power_state(bp, PCI_D0);

	if (data == 0)
		data = 2;

	save = REG_RD(bp, BNX2_MISC_CFG);
	REG_WR(bp, BNX2_MISC_CFG, BNX2_MISC_CFG_LEDMODE_MAC);

	for (i = 0; i < (data * 2); i++) {
		if ((i % 2) == 0) {
			REG_WR(bp, BNX2_EMAC_LED, BNX2_EMAC_LED_OVERRIDE);
		}
		else {
			REG_WR(bp, BNX2_EMAC_LED, BNX2_EMAC_LED_OVERRIDE |
				BNX2_EMAC_LED_1000MB_OVERRIDE |
				BNX2_EMAC_LED_100MB_OVERRIDE |
				BNX2_EMAC_LED_10MB_OVERRIDE |
				BNX2_EMAC_LED_TRAFFIC_OVERRIDE |
				BNX2_EMAC_LED_TRAFFIC);
		}
		bnx2_msleep_interruptible(500);
		if (signal_pending(current))
			break;
	}
	REG_WR(bp, BNX2_EMAC_LED, 0);
	REG_WR(bp, BNX2_MISC_CFG, save);

	if (!netif_running(dev))
		bnx2_set_power_state(bp, PCI_D3hot);

	return 0;
}

#else

static int
bnx2_set_phys_id(struct net_device *dev, enum ethtool_phys_id_state state)
{
	struct bnx2 *bp = netdev_priv(dev);

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		bnx2_set_power_state(bp, PCI_D0);

		bp->leds_save = REG_RD(bp, BNX2_MISC_CFG);
		REG_WR(bp, BNX2_MISC_CFG, BNX2_MISC_CFG_LEDMODE_MAC);
		return 1;	/* cycle on/off once per second */

	case ETHTOOL_ID_ON:
		REG_WR(bp, BNX2_EMAC_LED, BNX2_EMAC_LED_OVERRIDE |
		       BNX2_EMAC_LED_1000MB_OVERRIDE |
		       BNX2_EMAC_LED_100MB_OVERRIDE |
		       BNX2_EMAC_LED_10MB_OVERRIDE |
		       BNX2_EMAC_LED_TRAFFIC_OVERRIDE |
		       BNX2_EMAC_LED_TRAFFIC);
		break;

	case ETHTOOL_ID_OFF:
		REG_WR(bp, BNX2_EMAC_LED, BNX2_EMAC_LED_OVERRIDE);
		break;

	case ETHTOOL_ID_INACTIVE:
		REG_WR(bp, BNX2_EMAC_LED, 0);
		REG_WR(bp, BNX2_MISC_CFG, bp->leds_save);

		if (!netif_running(dev))
			bnx2_set_power_state(bp, PCI_D3hot);
		break;
	}

	return 0;
}

#endif

#if (LINUX_VERSION_CODE >= 0x20418)
static int
bnx2_set_tx_csum(struct net_device *dev, u32 data)
{
	struct bnx2 *bp = netdev_priv(dev);

	if (CHIP_NUM(bp) == CHIP_NUM_5709)
#if (LINUX_VERSION_CODE < 0x2060c)
		return bnx2_set_tx_hw_csum(dev, data);
#elif (LINUX_VERSION_CODE >= 0x20617)
		return ethtool_op_set_tx_ipv6_csum(dev, data);
#else
		return ethtool_op_set_tx_hw_csum(dev, data);
#endif
	else
		return ethtool_op_set_tx_csum(dev, data);
}
#endif

#ifdef NETIF_F_RXHASH
#if (LINUX_VERSION_CODE >= 0x20624)
static int
bnx2_set_flags(struct net_device *dev, u32 data)
{
	return ethtool_op_set_flags(dev, data, ETH_FLAG_RXHASH);
}

#else
static int
bnx2_set_flags(struct net_device *dev, u32 data)
{
	if (data & (ETH_FLAG_LRO | ETH_FLAG_NTUPLE))
		return -EOPNOTSUPP;

	if (data & ETH_FLAG_RXHASH)
		dev->features |= NETIF_F_RXHASH;
	else
		dev->features &= ~NETIF_F_RXHASH;
	return 0;
}
#endif
#endif

#ifdef ETHTOOL_GCHANNELS
static void bnx2_get_channels(struct net_device *dev,
			      struct ethtool_channels *channels)
{
	struct bnx2 *bp = netdev_priv(dev);
	u32 max_rx_rings = 1;
	u32 max_tx_rings = 1;

	if ((bp->flags & BNX2_FLAG_MSIX_CAP) && !disable_msi) {
		max_rx_rings = RX_MAX_RINGS;
		max_tx_rings = TX_MAX_RINGS;
	}

	channels->max_rx = max_rx_rings;
	channels->max_tx = max_tx_rings;
	channels->max_other = 0;
	channels->max_combined = 0;
	channels->rx_count = bp->num_rx_rings;
	channels->tx_count = bp->num_tx_rings;
	channels->other_count = 0;
	channels->combined_count = 0;
}

static int bnx2_set_channels(struct net_device *dev,
			      struct ethtool_channels *channels)
{
	struct bnx2 *bp = netdev_priv(dev);
	u32 max_rx_rings = 1;
	u32 max_tx_rings = 1;
	int rc = 0;

	if ((bp->flags & BNX2_FLAG_MSIX_CAP) && !disable_msi) {
		max_rx_rings = RX_MAX_RINGS;
		max_tx_rings = TX_MAX_RINGS;
	}
	if (channels->rx_count > max_rx_rings ||
	    channels->tx_count > max_tx_rings)
		return -EINVAL;

	bp->num_req_rx_rings = channels->rx_count;
	bp->num_req_tx_rings = channels->tx_count;

	if (netif_running(dev))
		rc = bnx2_change_ring_size(bp, bp->rx_ring_size,
					   bp->tx_ring_size, true);

	return rc;
}

#endif

static struct ethtool_ops bnx2_ethtool_ops = {
	.get_settings		= bnx2_get_settings,
	.set_settings		= bnx2_set_settings,
	.get_drvinfo		= bnx2_get_drvinfo,
	.get_regs_len		= bnx2_get_regs_len,
	.get_regs		= bnx2_get_regs,
	.get_wol		= bnx2_get_wol,
	.set_wol		= bnx2_set_wol,
	.nway_reset		= bnx2_nway_reset,
	.get_link		= bnx2_get_link,
#if (LINUX_VERSION_CODE >= 0x20418)
	.get_eeprom_len		= bnx2_get_eeprom_len,
#endif
#ifdef ETHTOOL_GEEPROM
	.get_eeprom		= bnx2_get_eeprom,
#endif
#ifdef ETHTOOL_SEEPROM
	.set_eeprom		= bnx2_set_eeprom,
#endif
	.get_coalesce		= bnx2_get_coalesce,
	.set_coalesce		= bnx2_set_coalesce,
	.get_ringparam		= bnx2_get_ringparam,
	.set_ringparam		= bnx2_set_ringparam,
	.get_pauseparam		= bnx2_get_pauseparam,
	.set_pauseparam		= bnx2_set_pauseparam,
	.get_rx_csum		= bnx2_get_rx_csum,
	.set_rx_csum		= bnx2_set_rx_csum,
	.get_tx_csum		= ethtool_op_get_tx_csum,
#if (LINUX_VERSION_CODE >= 0x20418)
	.set_tx_csum		= bnx2_set_tx_csum,
#endif
	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,
#ifdef BCM_TSO
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= bnx2_set_tso,
#endif
#ifndef ETHTOOL_GFLAGS
	.self_test_count	= bnx2_self_test_count,
#endif
	.self_test		= bnx2_self_test,
	.get_strings		= bnx2_get_strings,
#if (LINUX_VERSION_CODE < 0x30000)
	.phys_id		= bnx2_phys_id,
#else
	.set_phys_id		= bnx2_set_phys_id,
#endif
#ifndef ETHTOOL_GFLAGS
	.get_stats_count	= bnx2_get_stats_count,
#endif
	.get_ethtool_stats	= bnx2_get_ethtool_stats,
#ifdef ETHTOOL_GPERMADDR
#if (LINUX_VERSION_CODE < 0x020617)
	.get_perm_addr		= ethtool_op_get_perm_addr,
#endif
#endif
#ifdef ETHTOOL_GFLAGS
	.get_sset_count		= bnx2_get_sset_count,
#endif
#ifdef NETIF_F_RXHASH
	.set_flags		= bnx2_set_flags,
	.get_flags		= ethtool_op_get_flags,
#endif
#ifdef ETHTOOL_GCHANNELS
	.get_channels		= bnx2_get_channels,
	.set_channels		= bnx2_set_channels,
#endif
};

#if defined(BNX2_VMWARE_BMAPILNX)
static int
bnx2_ioctl_cim(struct net_device *dev, struct ifreq *ifr)
{
	struct bnx2 *bp = netdev_priv(dev);
	void __user *useraddr = ifr->ifr_data;
	struct bnx2_ioctl_req req;
	int rc = 0;
	u32 val;

	if (copy_from_user(&req, useraddr, sizeof(req))) {
		netdev_err(bp->dev, "bnx2_ioctl() could not copy from user");
		return -EFAULT;
	}

	switch(req.cmd) {
	case BNX2_VMWARE_CIM_CMD_ENABLE_NIC:
		netdev_info(bp->dev, "bnx2_ioctl() enable NIC\n");

		rc = bnx2_open(bp->dev);
		break;
	case BNX2_VMWARE_CIM_CMD_DISABLE_NIC:
		netdev_info(bp->dev, " bnx2_ioctl() disable NIC\n");

		rc = bnx2_close(bp->dev);
		break;
	case BNX2_VMWARE_CIM_CMD_REG_READ: {
		u32 mem_len;

#if defined(__VMKLNX__) && defined(__VMKNETDDI_QUEUEOPS__)
		mem_len = MB_GET_CID_ADDR(NETQUEUE_KCQ_CID + 2);
#else
		mem_len = MB_GET_CID_ADDR(TX_TSS_CID + TX_MAX_TSS_RINGS + 1);
#endif
		if(mem_len < req.cmd_req.reg_read.reg_offset) {
			netdev_info(bp->dev, "bnx2_ioctl() reg read: "
					     "out of range: max reg: 0x%x "
					     "req reg: 0x%x\n",
				mem_len, req.cmd_req.reg_read.reg_offset);
			rc = -EINVAL;
			break;
		}

		val = REG_RD(bp, req.cmd_req.reg_read.reg_offset);

		netdev_err(bp->dev, "bnx2_ioctl() reg read: "
				     "reg: 0x%x value:0x%x",
				     req.cmd_req.reg_read.reg_offset,
				     req.cmd_req.reg_read.reg_value);
		req.cmd_req.reg_read.reg_value = val;

		break;
	} case BNX2_VMWARE_CIM_CMD_REG_WRITE: {
		u32 mem_len;

#if defined(__VMKLNX__) && defined(__VMKNETDDI_QUEUEOPS__)
		mem_len = MB_GET_CID_ADDR(NETQUEUE_KCQ_CID + 2);
#else
		mem_len = MB_GET_CID_ADDR(TX_TSS_CID + TX_MAX_TSS_RINGS + 1);
#endif
		if(mem_len < req.cmd_req.reg_write.reg_offset) {
			netdev_err(bp->dev, "bnx2_ioctl() reg write: "
					    "out of range: max reg: 0x%x "
					    "req reg: 0x%x\n",
				mem_len, req.cmd_req.reg_write.reg_offset);
			rc = -EINVAL;
			break;
		}

		netdev_info(bp->dev, "bnx2_ioctl() reg write: "
				     "reg: 0x%x value:0x%x",
				     req.cmd_req.reg_write.reg_offset,
				     req.cmd_req.reg_write.reg_value);

		REG_WR(bp, req.cmd_req.reg_write.reg_offset,
			   req.cmd_req.reg_write.reg_value);

		break;
	} case BNX2_VMWARE_CIM_CMD_GET_NIC_PARAM:
		netdev_info(bp->dev, "bnx2_ioctl() get NIC param\n");

		req.cmd_req.get_nic_param.mtu = dev->mtu;
		memcpy(req.cmd_req.get_nic_param.current_mac_addr,
		       dev->dev_addr,
		       sizeof(req.cmd_req.get_nic_param.current_mac_addr));
		break;
	case BNX2_VMWARE_CIM_CMD_GET_NIC_STATUS:
		netdev_info(bp->dev, "bnx2_ioctl() get NIC status\n");

		req.cmd_req.get_nic_status.nic_status = netif_running(dev);
		break;
	default:
		netdev_warn(bp->dev, "bnx2_ioctl() unknown req.cmd: 0x%x\n",
				     req.cmd);
		rc = -EINVAL;
	}

        if (rc == 0 &&
	    copy_to_user(useraddr, &req, sizeof(req))) {
		netdev_err(bp->dev, "bnx2_ioctl() couldn't copy to user "
				    "bnx2_ioctl_req\n");
                return -EFAULT;
	}

	return rc;
}
#endif  /* BNX2_VMWARE_BMAPILNX */

/* Called with rtnl_lock */
static int
bnx2_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
#if (LINUX_VERSION_CODE >= 0x020607)
	struct mii_ioctl_data *data = if_mii(ifr);
#else
	struct mii_ioctl_data *data = (struct mii_ioctl_data *) &ifr->ifr_ifru;
#endif
	struct bnx2 *bp = netdev_priv(dev);
	int err;

	switch(cmd) {
	case SIOCGMIIPHY:
		data->phy_id = bp->phy_addr;

		/* fallthru */
	case SIOCGMIIREG: {
		u32 mii_regval;

		if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
			return -EOPNOTSUPP;

		if (!netif_running(dev))
			return -EAGAIN;

		spin_lock_bh(&bp->phy_lock);
		err = bnx2_read_phy(bp, data->reg_num & 0x1f, &mii_regval);
		spin_unlock_bh(&bp->phy_lock);

		data->val_out = mii_regval;

		return err;
	}

	case SIOCSMIIREG:
#if defined(__VMKLNX__)
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
#endif

		if (bp->phy_flags & BNX2_PHY_FLAG_REMOTE_PHY_CAP)
			return -EOPNOTSUPP;

		if (!netif_running(dev))
			return -EAGAIN;

		spin_lock_bh(&bp->phy_lock);
		err = bnx2_write_phy(bp, data->reg_num & 0x1f, data->val_in);
		spin_unlock_bh(&bp->phy_lock);

		return err;

#if defined(BNX2_VMWARE_BMAPILNX)
#define SIOBNX2CIM	0x89F0
	case SIOBNX2CIM:
		return bnx2_ioctl_cim(dev, ifr);
#endif  /* BNX2_VMWARE_BMAPILNX */
	default:
		/* do nothing */
		break;
	}
	return -EOPNOTSUPP;
}

#if defined(__VMKLNX__)
static int
bnx2_vmk_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int rc;

#if (VMWARE_ESX_DDK_VERSION < 50000)
	/* rtnl_lock() needed for ESX 4.0 and 4.1 only */
	rtnl_lock();
#endif
	rc = bnx2_ioctl(dev, ifr, cmd);
#if (VMWARE_ESX_DDK_VERSION < 50000)
	rtnl_unlock();
#endif
	return rc;
}
#endif

/* Called with rtnl_lock */
static int
bnx2_change_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	struct bnx2 *bp = netdev_priv(dev);

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	if (netif_running(dev))
		bnx2_set_mac_addr(bp, bp->dev->dev_addr, 0);

	return 0;
}

/* Called with rtnl_lock */
static int
bnx2_change_mtu(struct net_device *dev, int new_mtu)
{
	struct bnx2 *bp = netdev_priv(dev);

	if (((new_mtu + ETH_HLEN) > MAX_ETHERNET_JUMBO_PACKET_SIZE) ||
		((new_mtu + ETH_HLEN) < MIN_ETHERNET_PACKET_SIZE))
		return -EINVAL;

	dev->mtu = new_mtu;
	return (bnx2_change_ring_size(bp, bp->rx_ring_size, bp->tx_ring_size,
				      false));
}

#if defined(__VMKLNX__)
static int
bnx2_vmk_change_mtu(struct net_device *dev, int new_mtu)
{
	int rc;

#if (VMWARE_ESX_DDK_VERSION < 50000)
	/* rtnl_lock() needed for ESX 4.0 and 4.1 only */
	rtnl_lock();
#endif
	rc = bnx2_change_mtu(dev, new_mtu);
#if (VMWARE_ESX_DDK_VERSION < 50000)
	rtnl_unlock();
#endif

	return rc;
}
#endif

#if defined(HAVE_POLL_CONTROLLER) || defined(CONFIG_NET_POLL_CONTROLLER)
static void
poll_bnx2(struct net_device *dev)
{
	struct bnx2 *bp = netdev_priv(dev);

#if defined(RED_HAT_LINUX_KERNEL) && (LINUX_VERSION_CODE < 0x020600)
	if (netdump_mode) {
		struct bnx2_irq *irq = &bp->irq_tbl[0];

		irq_handler(irq->vector, &bp->bnx2_napi[0], NULL);
		if (dev->poll_list.prev) {
			int budget = 64;

			bnx2_poll(dev, &budget);
		}
	}
	else
#endif
	{
		int i;

		for (i = 0; i < bp->irq_nvecs; i++) {
			struct bnx2_irq *irq = &bp->irq_tbl[i];

			disable_irq(irq->vector);
#if (LINUX_VERSION_CODE >= 0x20613) || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
			irq->handler(irq->vector, &bp->bnx2_napi[i]);
#else
			irq->handler(irq->vector, &bp->bnx2_napi[i], NULL);
#endif
			enable_irq(irq->vector);
		}
	}
}
#endif

static void __devinit
bnx2_get_5709_media(struct bnx2 *bp)
{
	u32 val = REG_RD(bp, BNX2_MISC_DUAL_MEDIA_CTRL);
	u32 bond_id = val & BNX2_MISC_DUAL_MEDIA_CTRL_BOND_ID;
	u32 strap;

	if (bond_id == BNX2_MISC_DUAL_MEDIA_CTRL_BOND_ID_C)
		return;
	else if (bond_id == BNX2_MISC_DUAL_MEDIA_CTRL_BOND_ID_S) {
		bp->phy_flags |= BNX2_PHY_FLAG_SERDES;
		return;
	}

	if (val & BNX2_MISC_DUAL_MEDIA_CTRL_STRAP_OVERRIDE)
		strap = (val & BNX2_MISC_DUAL_MEDIA_CTRL_PHY_CTRL) >> 21;
	else
		strap = (val & BNX2_MISC_DUAL_MEDIA_CTRL_PHY_CTRL_STRAP) >> 8;

	if (bp->func == 0) {
		switch (strap) {
		case 0x4:
		case 0x5:
		case 0x6:
			bp->phy_flags |= BNX2_PHY_FLAG_SERDES;
			return;
		}
	} else {
		switch (strap) {
		case 0x1:
		case 0x2:
		case 0x4:
			bp->phy_flags |= BNX2_PHY_FLAG_SERDES;
			return;
		}
	}
}

static void __devinit
bnx2_get_pci_speed(struct bnx2 *bp)
{
	u32 reg;

	reg = REG_RD(bp, BNX2_PCICFG_MISC_STATUS);
	if (reg & BNX2_PCICFG_MISC_STATUS_PCIX_DET) {
		u32 clkreg;

		bp->flags |= BNX2_FLAG_PCIX;

		clkreg = REG_RD(bp, BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS);

		clkreg &= BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET;
		switch (clkreg) {
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_133MHZ:
			bp->bus_speed_mhz = 133;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_95MHZ:
			bp->bus_speed_mhz = 100;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_66MHZ:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_80MHZ:
			bp->bus_speed_mhz = 66;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_48MHZ:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_55MHZ:
			bp->bus_speed_mhz = 50;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_LOW:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_32MHZ:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_38MHZ:
			bp->bus_speed_mhz = 33;
			break;
		}
	}
	else {
		if (reg & BNX2_PCICFG_MISC_STATUS_M66EN)
			bp->bus_speed_mhz = 66;
		else
			bp->bus_speed_mhz = 33;
	}

	if (reg & BNX2_PCICFG_MISC_STATUS_32BIT_DET)
		bp->flags |= BNX2_FLAG_PCI_32BIT;

}

static void __devinit
bnx2_read_vpd_fw_ver(struct bnx2 *bp)
{
	int rc, i, v0_len = 0;
	u8 *data;
	u8 *v0_str = NULL;
	bool mn_match = false;

#define BNX2_VPD_NVRAM_OFFSET	0x300
#define BNX2_VPD_LEN		128
#define BNX2_MAX_VER_SLEN	30

	data = kmalloc(256, GFP_KERNEL);
	if (!data)
		return;

	rc = bnx2_nvram_read(bp, BNX2_VPD_NVRAM_OFFSET, data + BNX2_VPD_LEN,
			     BNX2_VPD_LEN);
	if (rc)
		goto vpd_done;

	for (i = 0; i < BNX2_VPD_LEN; i += 4) {
		data[i] = data[i + BNX2_VPD_LEN + 3];
		data[i + 1] = data[i + BNX2_VPD_LEN + 2];
		data[i + 2] = data[i + BNX2_VPD_LEN + 1];
		data[i + 3] = data[i + BNX2_VPD_LEN];
	}

	for (i = 0; i <= BNX2_VPD_LEN - 3; ) {
		unsigned char val = data[i];
		unsigned int block_end;

		if (val == 0x82 || val == 0x91) {
			i = (i + 3 + (data[i + 1] + (data[i + 2] << 8)));
			continue;
		}

		if (val != 0x90)
			goto vpd_done;

		block_end = (i + 3 + (data[i + 1] + (data[i + 2] << 8)));
		i += 3;

		if (block_end > BNX2_VPD_LEN)
			goto vpd_done;

		while (i < (block_end - 2)) {
			int len = data[i + 2];

			if (i + 3 + len > block_end)
				goto vpd_done;

			if (data[i] == 'M' && data[i + 1] == 'N') {
				if (len != 4 ||
				    memcmp(&data[i + 3], "1028", 4))
					goto vpd_done;
				mn_match = true;

			} else if (data[i] == 'V' && data[i + 1] == '0') {
				if (len > BNX2_MAX_VER_SLEN)
					goto vpd_done;

				v0_len = len;
				v0_str = &data[i + 3];
			}
			i += 3 + len;

			if (mn_match && v0_str) {
				memcpy(bp->fw_version, v0_str, v0_len);
				bp->fw_version[v0_len] = ' ';
				goto vpd_done;
			}
		}
		goto vpd_done;
	}

vpd_done:
	kfree(data);
}

static int __devinit
bnx2_init_board(struct pci_dev *pdev, struct net_device *dev)
{
	struct bnx2 *bp;
	int rc, i, j;
	u32 reg;
	u64 dma_mask, persist_dma_mask;
	int err;

#if (LINUX_VERSION_CODE < 0x20610)
	SET_MODULE_OWNER(dev);
#endif
#if (LINUX_VERSION_CODE >= 0x20419)
	SET_NETDEV_DEV(dev, &pdev->dev);
#endif
	bp = netdev_priv(dev);

	bp->flags = 0;
	bp->phy_flags = 0;

	bp->temp_stats_blk =
		kmalloc(sizeof(struct statistics_block), GFP_KERNEL);

	if (bp->temp_stats_blk == NULL) {
		rc = -ENOMEM;
		goto err_out;
	}
	memset(bp->temp_stats_blk, 0, sizeof(struct statistics_block));

	/* enable device (incl. PCI PM wakeup), and bus-mastering */
	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_out;
	}

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev,
			"Cannot find PCI device base address, aborting\n");
		rc = -ENODEV;
		goto err_out_disable;
	}

	rc = pci_request_regions(pdev, DRV_MODULE_NAME);
	if (rc) {
		dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
		goto err_out_disable;
	}

	pci_set_master(pdev);

	bp->pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
	if (bp->pm_cap == 0) {
		dev_err(&pdev->dev,
			"Cannot find power management capability, aborting\n");
		rc = -EIO;
		goto err_out_release;
	}

	bp->dev = dev;
	bp->pdev = pdev;

	spin_lock_init(&bp->phy_lock);
	spin_lock_init(&bp->indirect_lock);
#if defined(BNX2_ENABLE_NETQUEUE)
	mutex_init(&bp->netq_lock);
#endif
#ifdef BCM_CNIC
	mutex_init(&bp->cnic_lock);
#endif
#if (LINUX_VERSION_CODE >= 0x20600)
#if defined(INIT_DELAYED_WORK_DEFERRABLE) || defined(INIT_WORK_NAR)  || (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 40000))
	INIT_WORK(&bp->reset_task, bnx2_reset_task);
#else
	INIT_WORK(&bp->reset_task, bnx2_reset_task, bp);
#endif
#else
	INIT_TQUEUE(&bp->reset_task, bnx2_reset_task, bp);
#endif

#if defined(BNX2_ENABLE_NETQUEUE)
	bp->regview = pci_iomap(pdev, 0, MB_GET_CID_ADDR(NETQUEUE_KCQ_CID + 2));
#else
	bp->regview = pci_iomap(pdev, 0, MB_GET_CID_ADDR(TX_TSS_CID +
							 TX_MAX_TSS_RINGS + 1));
#endif

	if (!bp->regview) {
		dev_err(&pdev->dev, "Cannot map register space, aborting\n");
		rc = -ENOMEM;
		goto err_out_release;
	}

	bnx2_set_power_state(bp, PCI_D0);

	/* Configure byte swap and enable write to the reg_window registers.
	 * Rely on CPU to do target byte swapping on big endian systems
	 * The chip's target access swapping will not swap all accesses
	 */
	REG_WR(bp, BNX2_PCICFG_MISC_CONFIG,
		   BNX2_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
		   BNX2_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP);

	bp->chip_id = REG_RD(bp, BNX2_MISC_ID);

	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		if (!pci_is_pcie(pdev)) {
			dev_err(&pdev->dev, "Not PCIE, aborting\n");
			rc = -EIO;
			goto err_out_unmap;
		}
		bp->flags |= BNX2_FLAG_PCIE;
		if (CHIP_REV(bp) == CHIP_REV_Ax)
			bp->flags |= BNX2_FLAG_JUMBO_BROKEN;

#if !defined(CONFIG_PPC64) && !defined(CONFIG_PPC32)
		/* AER (Advanced Error Reporting) hooks */
		err = pci_enable_pcie_error_reporting(pdev);
		if (!err)
			bp->flags |= BNX2_FLAG_AER_ENABLED;
#endif

	} else {
		bp->pcix_cap = pci_find_capability(pdev, PCI_CAP_ID_PCIX);
		if (bp->pcix_cap == 0) {
			dev_err(&pdev->dev,
				"Cannot find PCIX capability, aborting\n");
			rc = -EIO;
			goto err_out_unmap;
		}
		bp->flags |= BNX2_FLAG_BROKEN_STATS;
	}

#ifdef CONFIG_PCI_MSI
	if (CHIP_NUM(bp) == CHIP_NUM_5709 && CHIP_REV(bp) != CHIP_REV_Ax) {
		if (pci_find_capability(pdev, PCI_CAP_ID_MSIX))
			bp->flags |= BNX2_FLAG_MSIX_CAP;
	}
#endif

	if (CHIP_ID(bp) != CHIP_ID_5706_A0 && CHIP_ID(bp) != CHIP_ID_5706_A1) {
		if (pci_find_capability(pdev, PCI_CAP_ID_MSI))
			bp->flags |= BNX2_FLAG_MSI_CAP;
	}

	/* 5708 cannot support DMA addresses > 40-bit.  */
	if (CHIP_NUM(bp) == CHIP_NUM_5708)
		persist_dma_mask = dma_mask = DMA_BIT_MASK(40);
	else
		persist_dma_mask = dma_mask = DMA_BIT_MASK(64);

	/* Configure DMA attributes. */
	if (pci_set_dma_mask(pdev, dma_mask) == 0) {
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000)
                if (CHIP_NUM(bp) == CHIP_NUM_5708)
                        dev->features |= NETIF_F_DMA40;
                else
                        dev->features |= NETIF_F_HIGHDMA;
#else
		dev->features |= NETIF_F_HIGHDMA;
#endif
		rc = pci_set_consistent_dma_mask(pdev, persist_dma_mask);
		if (rc) {
			dev_err(&pdev->dev,
				"pci_set_consistent_dma_mask failed, aborting\n");
			goto err_out_unmap;
		}
	} else if ((rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) != 0) {
		dev_err(&pdev->dev, "System does not support DMA, aborting\n");
		goto err_out_unmap;
	}

	if (!(bp->flags & BNX2_FLAG_PCIE))
		bnx2_get_pci_speed(bp);

	/* 5706A0 may falsely detect SERR and PERR. */
	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		reg = REG_RD(bp, PCI_COMMAND);
		reg &= ~(PCI_COMMAND_SERR | PCI_COMMAND_PARITY);
		REG_WR(bp, PCI_COMMAND, reg);
	}
	else if ((CHIP_ID(bp) == CHIP_ID_5706_A1) &&
		!(bp->flags & BNX2_FLAG_PCIX)) {

		dev_err(&pdev->dev,
			"5706 A1 can only be used in a PCIX bus, aborting\n");
		goto err_out_unmap;
	}

	bnx2_init_nvram(bp);

	reg = bnx2_reg_rd_ind(bp, BNX2_SHM_HDR_SIGNATURE);

	if (bnx2_reg_rd_ind(bp, BNX2_MCP_TOE_ID) & BNX2_MCP_TOE_ID_FUNCTION_ID)
		bp->func = 1;

	if ((reg & BNX2_SHM_HDR_SIGNATURE_SIG_MASK) ==
	    BNX2_SHM_HDR_SIGNATURE_SIG) {
		u32 off = bp->func << 2;

		bp->shmem_base = bnx2_reg_rd_ind(bp, BNX2_SHM_HDR_ADDR_0 + off);
	} else
		bp->shmem_base = HOST_VIEW_SHMEM_BASE;

	/* Get the permanent MAC address.  First we need to make sure the
	 * firmware is actually running.
	 */
	reg = bnx2_shmem_rd(bp, BNX2_DEV_INFO_SIGNATURE);

	if ((reg & BNX2_DEV_INFO_SIGNATURE_MAGIC_MASK) !=
	    BNX2_DEV_INFO_SIGNATURE_MAGIC) {
		dev_err(&pdev->dev, "Firmware not running, aborting\n");
		rc = -ENODEV;
		goto err_out_unmap;
	}

	bnx2_read_vpd_fw_ver(bp);

	j = strlen(bp->fw_version);
	reg = bnx2_shmem_rd(bp, BNX2_DEV_INFO_BC_REV);
	for (i = 0; i < 3 && j < 24; i++) {
		u8 num, k, skip0;

		if (i == 0) {
			bp->fw_version[j++] = 'b';
			bp->fw_version[j++] = 'c';
			bp->fw_version[j++] = ' ';
		}
		num = (u8) (reg >> (24 - (i * 8)));
		for (k = 100, skip0 = 1; k >= 1; num %= k, k /= 10) {
			if (num >= k || !skip0 || k == 1) {
				bp->fw_version[j++] = (num / k) + '0';
				skip0 = 0;
			}
		}
		if (i != 2)
			bp->fw_version[j++] = '.';
	}
	reg = bnx2_shmem_rd(bp, BNX2_PORT_FEATURE);
	if (reg & BNX2_PORT_FEATURE_WOL_ENABLED)
		bp->wol = 1;

	if (reg & BNX2_PORT_FEATURE_ASF_ENABLED) {
		bp->flags |= BNX2_FLAG_ASF_ENABLE;

		for (i = 0; i < 30; i++) {
			reg = bnx2_shmem_rd(bp, BNX2_BC_STATE_CONDITION);
			if (reg & BNX2_CONDITION_MFW_RUN_MASK)
				break;
			bnx2_msleep(10);
		}
	}
	reg = bnx2_shmem_rd(bp, BNX2_BC_STATE_CONDITION);
	reg &= BNX2_CONDITION_MFW_RUN_MASK;
	if (reg != BNX2_CONDITION_MFW_RUN_UNKNOWN &&
	    reg != BNX2_CONDITION_MFW_RUN_NONE) {
		u32 addr = bnx2_shmem_rd(bp, BNX2_MFW_VER_PTR);

		if (j < 32)
			bp->fw_version[j++] = ' ';
		for (i = 0; i < 3 && j < 28; i++) {
			reg = bnx2_reg_rd_ind(bp, addr + i * 4);
			reg = be32_to_cpu(reg);
			memcpy(&bp->fw_version[j], &reg, 4);
			j += 4;
		}
	}

	reg = bnx2_shmem_rd(bp, BNX2_PORT_HW_CFG_MAC_UPPER);
	bp->mac_addr[0] = (u8) (reg >> 8);
	bp->mac_addr[1] = (u8) reg;

	reg = bnx2_shmem_rd(bp, BNX2_PORT_HW_CFG_MAC_LOWER);
	bp->mac_addr[2] = (u8) (reg >> 24);
	bp->mac_addr[3] = (u8) (reg >> 16);
	bp->mac_addr[4] = (u8) (reg >> 8);
	bp->mac_addr[5] = (u8) reg;

	bp->tx_ring_size = MAX_TX_DESC_CNT;
	bnx2_set_rx_ring_size(bp, 255);

	bp->rx_csum = 1;

	bp->tx_quick_cons_trip_int = 2;
	bp->tx_quick_cons_trip = 20;
	bp->tx_ticks_int = 18;
	bp->tx_ticks = 80;

	bp->rx_quick_cons_trip_int = 2;
	bp->rx_quick_cons_trip = 12;
	bp->rx_ticks_int = 18;
	bp->rx_ticks = 18;

	bp->stats_ticks = USEC_PER_SEC & BNX2_HC_STATS_TICKS_HC_STAT_TICKS;

	bp->current_interval = BNX2_TIMER_INTERVAL;

	bp->phy_addr = 1;

	/* Disable WOL support if we are running on a SERDES chip. */
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		bnx2_get_5709_media(bp);
	else if (CHIP_BOND_ID(bp) & CHIP_BOND_ID_SERDES_BIT)
		bp->phy_flags |= BNX2_PHY_FLAG_SERDES;

	bp->phy_port = PORT_TP;
	if (bp->phy_flags & BNX2_PHY_FLAG_SERDES) {
		bp->phy_port = PORT_FIBRE;
		reg = bnx2_shmem_rd(bp, BNX2_SHARED_HW_CFG_CONFIG);
		if (!(reg & BNX2_SHARED_HW_CFG_GIG_LINK_ON_VAUX)) {
			bp->flags |= BNX2_FLAG_NO_WOL;
			bp->wol = 0;
		}
		if (CHIP_NUM(bp) == CHIP_NUM_5706) {
			/* Don't do parallel detect on this board because of
			 * some board problems.  The link will not go down
			 * if we do parallel detect.
			 */
			if (pdev->subsystem_vendor == PCI_VENDOR_ID_HP &&
			    pdev->subsystem_device == 0x310c)
				bp->phy_flags |= BNX2_PHY_FLAG_NO_PARALLEL;
		} else {
			bp->phy_addr = 2;
			if (reg & BNX2_SHARED_HW_CFG_PHY_2_5G)
				bp->phy_flags |= BNX2_PHY_FLAG_2_5G_CAPABLE;
		}
	} else if (CHIP_NUM(bp) == CHIP_NUM_5706 ||
		   CHIP_NUM(bp) == CHIP_NUM_5708)
		bp->phy_flags |= BNX2_PHY_FLAG_CRC_FIX;
	else if (CHIP_NUM(bp) == CHIP_NUM_5709 &&
		 (CHIP_REV(bp) == CHIP_REV_Ax ||
		  CHIP_REV(bp) == CHIP_REV_Bx))
		bp->phy_flags |= BNX2_PHY_FLAG_DIS_EARLY_DAC;

	bnx2_init_fw_cap(bp);

	if ((CHIP_ID(bp) == CHIP_ID_5708_A0) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_B0) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_B1) ||
	    !(REG_RD(bp, BNX2_PCI_CONFIG_3) & BNX2_PCI_CONFIG_3_VAUX_PRESET)) {
		bp->flags |= BNX2_FLAG_NO_WOL;
		bp->wol = 0;
	}

	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		bp->tx_quick_cons_trip_int =
			bp->tx_quick_cons_trip;
		bp->tx_ticks_int = bp->tx_ticks;
		bp->rx_quick_cons_trip_int =
			bp->rx_quick_cons_trip;
		bp->rx_ticks_int = bp->rx_ticks;
		bp->comp_prod_trip_int = bp->comp_prod_trip;
		bp->com_ticks_int = bp->com_ticks;
		bp->cmd_ticks_int = bp->cmd_ticks;
	}

#ifdef CONFIG_PCI_MSI
#if defined(__VMKLNX__)
	/* PR496996: There is some additional setup needed for the P2P
	 *           ServerWorks bridge with VID/DID of 0x1666/0x0036 when
         *           5706 is plugged into an IBM system x3655 server and MSI
         *           is used.  Since that workaround cannot be done using
         *           vmklinux api, we are disabling MSI on 5706 to avoid PSOD.
         */
        if (CHIP_NUM(bp) == CHIP_NUM_5706)
                disable_msi = 1;
#else /* !defined(__VMKLNX__) */
	/* Disable MSI on 5706 if AMD 8132 bridge is found.
	 *
	 * MSI is defined to be 32-bit write.  The 5706 does 64-bit MSI writes
	 * with byte enables disabled on the unused 32-bit word.  This is legal
	 * but causes problems on the AMD 8132 which will eventually stop
	 * responding after a while.
	 *
	 * AMD believes this incompatibility is unique to the 5706, and
	 * prefers to locally disable MSI rather than globally disabling it.
	 */
	if (CHIP_NUM(bp) == CHIP_NUM_5706 && disable_msi == 0) {
		struct pci_dev *amd_8132 = NULL;

		while ((amd_8132 = pci_get_device(PCI_VENDOR_ID_AMD,
						  PCI_DEVICE_ID_AMD_8132_BRIDGE,
						  amd_8132))) {
			u8 rev;

			pci_read_config_byte(amd_8132, PCI_REVISION_ID, &rev);
			if (rev >= 0x10 && rev <= 0x13) {
				disable_msi = 1;
				pci_dev_put(amd_8132);
				break;
			}
		}
	}
#endif /* defined(__VMKLNX__) */
#endif
	bnx2_set_default_link(bp);
	bp->req_flow_ctrl = FLOW_CTRL_RX | FLOW_CTRL_TX;

	init_timer(&bp->timer);
	bp->timer.expires = RUN_AT(BNX2_TIMER_INTERVAL);
	bp->timer.data = (unsigned long) bp;
	bp->timer.function = bnx2_timer;

#ifdef BCM_CNIC
	if (bnx2_shmem_rd(bp, BNX2_ISCSI_INITIATOR) & BNX2_ISCSI_INITIATOR_EN)
		bp->cnic_eth_dev.max_iscsi_conn =
			(bnx2_shmem_rd(bp, BNX2_ISCSI_MAX_CONN) &
			 BNX2_ISCSI_MAX_CONN_MASK) >> BNX2_ISCSI_MAX_CONN_SHIFT;
#endif

#if (LINUX_VERSION_CODE >= 0x020611)
	pci_save_state(pdev);
#endif

	return 0;

err_out_unmap:
	if (bp->flags & BNX2_FLAG_AER_ENABLED) {
		pci_disable_pcie_error_reporting(pdev);
		bp->flags &= ~BNX2_FLAG_AER_ENABLED;
	}

	pci_iounmap(pdev, bp->regview);
	bp->regview = NULL;

err_out_release:
	pci_release_regions(pdev);

err_out_disable:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

err_out:
	return rc;
}

static char * __devinit
bnx2_bus_string(struct bnx2 *bp, char *str)
{
	char *s = str;

	if (bp->flags & BNX2_FLAG_PCIE) {
		s += sprintf(s, "PCI Express");
	} else {
		s += sprintf(s, "PCI");
		if (bp->flags & BNX2_FLAG_PCIX)
			s += sprintf(s, "-X");
		if (bp->flags & BNX2_FLAG_PCI_32BIT)
			s += sprintf(s, " 32-bit");
		else
			s += sprintf(s, " 64-bit");
		s += sprintf(s, " %dMHz", bp->bus_speed_mhz);
	}
	return str;
}

#if !defined(__VMKLNX__)
static void
bnx2_del_napi(struct bnx2 *bp)
#else
static void __devinit
bnx2_del_napi(struct bnx2 *bp)
#endif
{
#ifdef BNX2_NEW_NAPI
	int i;

	for (i = 0; i < bp->irq_nvecs; i++)
		netif_napi_del(&bp->bnx2_napi[i].napi);
#endif
}

#if !defined(__VMKLNX__)
static void
bnx2_init_napi(struct bnx2 *bp)
#else
static void __devinit
bnx2_init_napi(struct bnx2 *bp)
#endif
{
	int i;

	for (i = 0; i < bp->irq_nvecs; i++) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[i];
#ifdef BNX2_NEW_NAPI
		int (*poll)(struct napi_struct *, int);

		if (i == 0)
			poll = bnx2_poll;
		else
			poll = bnx2_poll_msix;

		netif_napi_add(bp->dev, &bp->bnx2_napi[i].napi, poll, 64);
#endif

		bnapi->bp = bp;
	}
#ifndef BNX2_NEW_NAPI
	bp->dev->poll = bnx2_poll;
	bp->dev->weight = 64;
#endif
}

#if defined(HAVE_NET_DEVICE_OPS) || (LINUX_VERSION_CODE >= 0x30000)
static const struct net_device_ops bnx2_netdev_ops = {
	.ndo_open		= bnx2_open,
	.ndo_start_xmit		= bnx2_start_xmit,
	.ndo_stop		= bnx2_close,
	.ndo_get_stats		= bnx2_get_stats,
	.ndo_set_rx_mode	= bnx2_set_rx_mode,
#if defined(__VMKLNX__)
	.ndo_do_ioctl		= bnx2_vmk_ioctl,
#else
	.ndo_do_ioctl		= bnx2_ioctl,
#endif
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= bnx2_change_mac_addr,
#if defined(__VMKLNX__)
	.ndo_change_mtu		= bnx2_vmk_change_mtu,
#else
	.ndo_change_mtu		= bnx2_change_mtu,
#endif
	.ndo_tx_timeout		= bnx2_tx_timeout,
#ifdef BCM_VLAN
	.ndo_vlan_rx_register	= bnx2_vlan_rx_register,
#endif
#if defined(HAVE_POLL_CONTROLLER) || defined(CONFIG_NET_POLL_CONTROLLER)
	.ndo_poll_controller	= poll_bnx2,
#endif
};
#endif

static inline void vlan_features_add(struct net_device *dev, unsigned long flags)
{
#if (LINUX_VERSION_CODE >= 0x2061a)
#ifdef BCM_VLAN
	dev->vlan_features |= flags;
#endif
#endif
}

static int __devinit
bnx2_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	static int version_printed = 0;
	struct net_device *dev;
	struct bnx2 *bp;
	int rc;
	char str[40];
	DECLARE_MAC_BUF(mac);
#if (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 60000)) || \
    (defined(BNX2_ENABLE_NETQUEUE))
	static int index = 0;
#endif

	if (version_printed++ == 0)
		pr_info("%s", version);

	/* dev zeroed in init_etherdev */
#if (LINUX_VERSION_CODE >= 0x20418)
#ifndef BCM_HAVE_MULTI_QUEUE
	dev = alloc_etherdev(sizeof(*bp));
#else
	dev = alloc_etherdev_mq(sizeof(*bp), TX_MAX_RINGS);
#endif
#else
	dev = init_etherdev(NULL, sizeof(*bp));
#endif

	if (!dev)
		return -ENOMEM;

	rc = bnx2_init_board(pdev, dev);
	if (rc < 0)
		goto err_free;

#ifndef HAVE_NET_DEVICE_OPS
	dev->open = bnx2_open;
	dev->hard_start_xmit = bnx2_start_xmit;
	dev->stop = bnx2_close;
	dev->get_stats = bnx2_get_stats;
#ifdef BCM_HAVE_SET_RX_MODE
	dev->set_rx_mode = bnx2_set_rx_mode;
#else
	dev->set_multicast_list = bnx2_set_rx_mode;
#endif
#if defined(__VMKLNX__)
	dev->do_ioctl = bnx2_vmk_ioctl;
#else
	dev->do_ioctl = bnx2_ioctl;
#endif
	dev->set_mac_address = bnx2_change_mac_addr;
#if defined(__VMKLNX__)
	dev->change_mtu = bnx2_vmk_change_mtu;
#else
	dev->change_mtu = bnx2_change_mtu;
#endif
	dev->tx_timeout = bnx2_tx_timeout;
#ifdef BCM_VLAN
	dev->vlan_rx_register = bnx2_vlan_rx_register;
#if (LINUX_VERSION_CODE < 0x20616)
	dev->vlan_rx_kill_vid = bnx2_vlan_rx_kill_vid;
#endif
#endif
#if defined(HAVE_POLL_CONTROLLER) || defined(CONFIG_NET_POLL_CONTROLLER)
	dev->poll_controller = poll_bnx2;
#endif
#else
	dev->netdev_ops = &bnx2_netdev_ops;
#endif
	dev->watchdog_timeo = TX_TIMEOUT;
	dev->ethtool_ops = &bnx2_ethtool_ops;

	bp = netdev_priv(dev);
	/*  NAPI add must be called in bnx2_init_one() on ESX so that the
	 *  proper affinity will be assigned */

#if defined(__VMKLNX__)
	bnx2_setup_int_mode(bp, disable_msi);
	bnx2_init_napi(bp);
#endif /* (__VMKLNX__)*/

	pci_set_drvdata(pdev, dev);

	memcpy(dev->dev_addr, bp->mac_addr, 6);
#ifdef ETHTOOL_GPERMADDR
	memcpy(dev->perm_addr, bp->mac_addr, 6);
#endif

#ifdef NETIF_F_IPV6_CSUM
	dev->features |= NETIF_F_IP_CSUM | NETIF_F_SG;
#if defined(NETIF_F_GRO) && defined(BNX2_NEW_NAPI)
	dev->features |= NETIF_F_GRO;
#endif
#ifdef NETIF_F_RXHASH
	dev->features |= NETIF_F_RXHASH;
#endif
	vlan_features_add(dev, NETIF_F_IP_CSUM | NETIF_F_SG);
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		dev->features |= NETIF_F_IPV6_CSUM;
		vlan_features_add(dev, NETIF_F_IPV6_CSUM);
	}
#else
	dev->features |= NETIF_F_SG;
	if (CHIP_NUM(bp) == CHIP_NUM_5709)
		dev->features |= NETIF_F_HW_CSUM;
	else
		dev->features |= NETIF_F_IP_CSUM;
#endif
#ifdef BCM_VLAN
	dev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
#endif
#ifdef BCM_TSO
	dev->features |= NETIF_F_TSO | NETIF_F_TSO_ECN;
	vlan_features_add(dev, NETIF_F_TSO | NETIF_F_TSO_ECN);
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		dev->features |= NETIF_F_TSO6;
		vlan_features_add(dev, NETIF_F_TSO6);
	}
#endif

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000)
        if (CHIP_NUM(bp) == CHIP_NUM_5706 ||
            CHIP_NUM(bp) == CHIP_NUM_5708) {
                dev->features |= NETIF_F_NO_SCHED;
        }
#endif

#if (defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 60000)) || \
    (defined(BNX2_ENABLE_NETQUEUE))
	bp->index = index;
	index++;
#endif
#if defined(BNX2_ENABLE_NETQUEUE)
	/*  If enabled register the NetQueue callbacks */
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		if (BNX2_NETQUEUE_ENABLED(bp))
			VMKNETDDI_REGISTER_QUEUEOPS(dev, bnx2_netqueue_ops);
	}
#endif
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 60000)
	fwdmp_bp_ptr[bp->index] = bp;
#endif

#if (LINUX_VERSION_CODE >= 0x20418)
	if ((rc = register_netdev(dev))) {
		dev_err(&pdev->dev, "Cannot register net device\n");
		goto error;
	}
#endif
	netdev_info(dev, "%s (%c%d) %s found at mem %lx, IRQ %d, "
		    "node addr %s\n", board_info[ent->driver_data].name,
		    ((CHIP_ID(bp) & 0xf000) >> 12) + 'A',
		    ((CHIP_ID(bp) & 0x0ff0) >> 4),
		    bnx2_bus_string(bp, str), (long)pci_resource_start(pdev, 0),
		    bp->pdev->irq, print_mac(mac, dev->dev_addr));

#if defined(BNX2_ENABLE_NETQUEUE)
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		if (BNX2_NETQUEUE_ENABLED(bp)) {
			netdev_info(bp->dev, "NetQueue Ops registered [%d]\n",
					     bp->index);
		} else
			netdev_info(bp->dev, "NetQueue Ops not registered "
					     "[%d]\n",
					     bp->index);
	}
#endif

	return 0;

error:
	pci_iounmap(pdev, bp->regview);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
err_free:
#if (LINUX_VERSION_CODE >= 0x20418)
	free_netdev(dev);
#else
	unregister_netdev(dev);
	kfree(dev);
#endif
	return rc;
}

static void __devexit
bnx2_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2 *bp = netdev_priv(dev);

#if defined(__VMKLNX__)
	bnx2_del_napi(bp);
	bnx2_disable_msi(bp);
#endif /* !(defined __VMKLNX__) */

	unregister_netdev(dev);

	del_timer_sync(&bp->timer);
#if (LINUX_VERSION_CODE >= 0x20616) || defined(__VMKLNX__)
	cancel_work_sync(&bp->reset_task);
#elif (LINUX_VERSION_CODE >= 0x20600)
	flush_scheduled_work();
#endif

	if (bp->regview)
		iounmap(bp->regview);

	kfree(bp->temp_stats_blk);

	if (bp->flags & BNX2_FLAG_AER_ENABLED) {
		pci_disable_pcie_error_reporting(pdev);
		bp->flags &= ~BNX2_FLAG_AER_ENABLED;
	}

#if (LINUX_VERSION_CODE >= 0x20418)
	free_netdev(dev);
#else
	kfree(dev);
#endif

	pci_disable_pcie_error_reporting(pdev);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int
bnx2_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2 *bp = netdev_priv(dev);

#if (LINUX_VERSION_CODE >= 0x2060b)
	/* PCI register 4 needs to be saved whether netif_running() or not.
	 * MSI address and data need to be saved if using MSI and
	 * netif_running().
	 */
	pci_save_state(pdev);
#endif
	if (!netif_running(dev))
		return 0;

#if (LINUX_VERSION_CODE >= 0x20616) || defined(__VMKLNX__)
	cancel_work_sync(&bp->reset_task);
#endif
	bnx2_netif_stop(bp, true);
	netif_device_detach(dev);
	del_timer_sync(&bp->timer);
	bnx2_shutdown_chip(bp);
	bnx2_free_skbs(bp);
#if (LINUX_VERSION_CODE < 0x2060b)
	bnx2_set_power_state(bp, state);
#else
	bnx2_set_power_state(bp, pci_choose_state(pdev, state));
#endif
	return 0;
}

static int
bnx2_resume(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2 *bp = netdev_priv(dev);

#if (LINUX_VERSION_CODE >= 0x2060b)
	pci_restore_state(pdev);
#endif
	if (!netif_running(dev))
		return 0;

	bnx2_set_power_state(bp, PCI_D0);
	netif_device_attach(dev);
	bnx2_init_nic(bp, 1);
	bnx2_netif_start(bp, true);
	return 0;
}

#if !defined(__VMKLNX__)
#if (LINUX_VERSION_CODE >= 0x020611)
/**
 * bnx2_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t bnx2_io_error_detected(struct pci_dev *pdev,
					       pci_channel_state_t state)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2 *bp = netdev_priv(dev);

	rtnl_lock();
	netif_device_detach(dev);

	if (state == pci_channel_io_perm_failure) {
		rtnl_unlock();
		return PCI_ERS_RESULT_DISCONNECT;
	}

	if (netif_running(dev)) {
		bnx2_netif_stop(bp, true);
		del_timer_sync(&bp->timer);
		bnx2_reset_nic(bp, BNX2_DRV_MSG_CODE_RESET);
	}

	pci_disable_device(pdev);
	rtnl_unlock();

	/* Request a slot slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * bnx2_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot.
 */
static pci_ers_result_t bnx2_io_slot_reset(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2 *bp = netdev_priv(dev);
	pci_ers_result_t result;
	int err;

	rtnl_lock();
	if (pci_enable_device(pdev)) {
		dev_err(&pdev->dev,
			"Cannot re-enable PCI device after reset\n");
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		pci_save_state(pdev);

		if (netif_running(dev)) {
			bnx2_set_power_state(bp, PCI_D0);
			bnx2_init_nic(bp, 1);
		}
		result = PCI_ERS_RESULT_RECOVERED;
	}
	rtnl_unlock();

	if (!(bp->flags & BNX2_FLAG_AER_ENABLED))
		return result;

	err = pci_cleanup_aer_uncorrect_error_status(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"pci_cleanup_aer_uncorrect_error_status failed 0x%0x\n",
			 err); /* non-fatal, continue */
	}

	return result;
}

/**
 * bnx2_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation.
 */
static void bnx2_io_resume(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2 *bp = netdev_priv(dev);

	rtnl_lock();
	if (netif_running(dev))
		bnx2_netif_start(bp, true);

	netif_device_attach(dev);
	rtnl_unlock();
}

static struct pci_error_handlers bnx2_err_handler = {
	.error_detected	= bnx2_io_error_detected,
	.slot_reset	= bnx2_io_slot_reset,
	.resume		= bnx2_io_resume,
};

#endif
#endif

static struct pci_driver bnx2_pci_driver = {
	.name		= DRV_MODULE_NAME,
	.id_table	= bnx2_pci_tbl,
	.probe		= bnx2_init_one,
	.remove		= __devexit_p(bnx2_remove_one),
	.suspend	= bnx2_suspend,
	.resume		= bnx2_resume,
#if !defined(__VMKLNX__)
#if (LINUX_VERSION_CODE >= 0x020611)
	.err_handler	= &bnx2_err_handler,
#endif
#endif
};

static int __init bnx2_init(void)
{
	int rc = 0;
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 60000)
	VMK_ReturnStatus status;
#endif
#if defined(BNX2_ENABLE_NETQUEUE)
	int i;

	/*  sanity check the force_netq parameter */
	for (i = 0; i < BNX2_MAX_NIC; i++) {
		if((force_netq_param[i] < BNX2_OPTION_UNSET) ||
		   (force_netq_param[i] > 7)) {
			pr_err("bnx2: please use a 'force_netq' "
			       "value between (-1 to 7), "
			       "0 to disable NetQueue, "
			       "-1 to use the default value "
			       "failure at index %d val: %d\n",
			       i, force_netq_param[i]);
			rc = -EINVAL;
		}
	}

	if(rc != 0)
		return rc;
#endif

#if (LINUX_VERSION_CODE < 0x020613)
	rc = pci_module_init(&bnx2_pci_driver);
#else
	rc = pci_register_driver(&bnx2_pci_driver);
#endif

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000)
#if defined(BNX2_INBOX)
	if (cnic_register_adapter("bnx2", bnx2_cnic_probe) < 0) {
#else /* !defined(BNX2_INBOX) */
	if (cnic_register_adapter("bnx2", bnx2_cnic_probe2) < 0) {
#endif /* defined(BNX2_INBOX) */
		pr_warn("bnx2: Unable to register with CNIC adapter\n");
		/*
		 *  We won't call pci_unregister_driver(&bnx2_pci_driver) here,
		 *  because we still want to retain L2 funtion
		 *  even if cnic_register_adapter failed
		 */
	} else {
		bnx2_registered_cnic_adapter = 1;
	}
#endif /* defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 50000) */

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 60000)
	if (!disable_fw_dmp) {
		fwdmp_va_ptr = kzalloc(BNX2_FWDMP_SIZE, GFP_KERNEL);
		if (!fwdmp_va_ptr)
			pr_warn("bnx2: Unable to allocate memory "
				"for firmware dump handler!\n");
		else {
			status = vmklnx_dump_add_callback(BNX2_DUMPNAME,
					bnx2_fwdmp_callback,
					NULL,
					BNX2_DUMPNAME,
					&bnx2_fwdmp_dh);
			if (status != VMK_OK)
				pr_warn("bnx2: Unable to register firmware "
					"dump handler (rc = 0x%x!)\n",
					status);
		}
	}
#endif
	return rc;
}

static void __exit bnx2_cleanup(void)
{
#if defined(__VMKLNX__)
#if (VMWARE_ESX_DDK_VERSION >= 60000)
	if (bnx2_fwdmp_dh) {
		VMK_ReturnStatus status;

		status = vmklnx_dump_delete_callback(bnx2_fwdmp_dh);
		if (status != VMK_OK) {
			VMK_ASSERT(0);
		} else {
			pr_info("bnx2: firmware dump handler (%p)"
				" unregistered!\n",
				bnx2_fwdmp_dh);
		}
	}
	kfree(fwdmp_va_ptr);
	fwdmp_va_ptr = NULL;
#endif
#if (VMWARE_ESX_DDK_VERSION >= 50000)
	if (bnx2_registered_cnic_adapter) {
	        cnic_register_cancel("bnx2");
		bnx2_registered_cnic_adapter = 0;
	}
#endif
#endif /* defined(__VMKLNX__) */
	pci_unregister_driver(&bnx2_pci_driver);
}

module_init(bnx2_init);
module_exit(bnx2_cleanup);


#if defined(BNX2_ENABLE_NETQUEUE)

#ifdef BNX2_DEBUG
static u32 bnx2_read_ctx(struct bnx2 *bp, u32 offset)
{
	int i;

	if (CHIP_NUM(bp) != CHIP_NUM_5709) {
		REG_WR(bp, BNX2_CTX_DATA_ADR, offset);
		return REG_RD(bp, BNX2_CTX_DATA);
	}

	REG_WR(bp, BNX2_CTX_CTX_CTRL, offset | BNX2_CTX_CTX_CTRL_READ_REQ);
	for (i = 0; i < 5; i++) {
		udelay(5);
		if (REG_RD(bp, BNX2_CTX_CTX_CTRL) & BNX2_CTX_CTX_CTRL_READ_REQ)
			continue;
		break;
	}

	return REG_RD(bp, BNX2_CTX_CTX_DATA);
}

static void dump_ctx(struct bnx2 *bp, u32 cid)
{
	u32 addr = cid * 128;
	int i;

	for (i = 0; i < 8; i++) {
		u32 val, val1, val2, val3;

		val  = bnx2_read_ctx(bp, addr);
		val1 = bnx2_read_ctx(bp, addr+4);
		val2 = bnx2_read_ctx(bp, addr+8);
		val3 = bnx2_read_ctx(bp, addr+0xc);
		netdev_err(bp->dev, "ctx  %08x: %08x %08x %08x %08x\n",
			addr, val, val1, val2, val3);
		addr += 0x10;
	}
}
#endif

#define BNX2_NETQ_WAIT_EVENT_TIMEOUT	msecs_to_jiffies(1000)

#define L2_KWQ_PAGE_CNT    1
#define L2_KCQ_PAGE_CNT    1

#define L2_KWQE_CNT (BCM_PAGE_SIZE / sizeof(struct l2_kwqe))
#define L2_KCQE_CNT (BCM_PAGE_SIZE / sizeof(struct l2_kcqe))
#define MAX_L2_KWQE_CNT (L2_KWQE_CNT - 1)
#define MAX_L2_KCQE_CNT (L2_KCQE_CNT - 1)

#define MAX_L2_KWQ_IDX     ((L2_KWQ_PAGE_CNT * L2_KWQE_CNT) - 1)
#define MAX_L2_KCQ_IDX     ((L2_KCQ_PAGE_CNT * L2_KCQE_CNT) - 1)

#define L2_KWQ_PG(x) (((x) & ~MAX_L2_KWQE_CNT) >> (BCM_PAGE_BITS - 5))
#define L2_KWQ_IDX(x) ((x) & MAX_L2_KWQE_CNT)

#define L2_KCQ_PG(x) (((x) & ~MAX_L2_KCQE_CNT) >> (BCM_PAGE_BITS - 5))
#define L2_KCQ_IDX(x) ((x) & MAX_L2_KCQE_CNT)

/*
 *      krnlq_context definition
 */
#define L2_KRNLQ_FLAGS  		0x00000000
#define L2_KRNLQ_SIZE   		0x00000000
#define L2_KRNLQ_TYPE   		0x00000000
#define KRNLQ_FLAGS_PG_SZ		(0xf<<0)
#define KRNLQ_FLAGS_PG_SZ_256		(0<<0)
#define KRNLQ_FLAGS_PG_SZ_512		(1<<0)
#define KRNLQ_FLAGS_PG_SZ_1K		(2<<0)
#define KRNLQ_FLAGS_PG_SZ_2K		(3<<0)
#define KRNLQ_FLAGS_PG_SZ_4K		(4<<0)
#define KRNLQ_FLAGS_PG_SZ_8K		(5<<0)
#define KRNLQ_FLAGS_PG_SZ_16K		(6<<0)
#define KRNLQ_FLAGS_PG_SZ_32K		(7<<0)
#define KRNLQ_FLAGS_PG_SZ_64K		(8<<0)
#define KRNLQ_FLAGS_PG_SZ_128K		(9<<0)
#define KRNLQ_FLAGS_PG_SZ_256K		(10<<0)
#define KRNLQ_FLAGS_PG_SZ_512K		(11<<0)
#define KRNLQ_FLAGS_PG_SZ_1M		(12<<0)
#define KRNLQ_FLAGS_PG_SZ_2M		(13<<0)
#define KRNLQ_FLAGS_QE_SELF_SEQ		(1<<15)
#define KRNLQ_SIZE_TYPE_SIZE    ((((0x28 + 0x1f) & ~0x1f) / 0x20) << 16)
#define KRNLQ_TYPE_TYPE			(0xf<<28)
#define KRNLQ_TYPE_TYPE_EMPTY		(0<<28)
#define KRNLQ_TYPE_TYPE_KRNLQ		(6<<28)

#define L2_KRNLQ_HOST_QIDX              0x00000004
#define L2_KRNLQ_HOST_FW_QIDX           0x00000008
#define L2_KRNLQ_NX_QE_SELF_SEQ         0x0000000c
#define L2_KRNLQ_QE_SELF_SEQ_MAX        0x0000000c
#define L2_KRNLQ_NX_QE_HADDR_HI         0x00000010
#define L2_KRNLQ_NX_QE_HADDR_LO         0x00000014
#define L2_KRNLQ_PGTBL_PGIDX            0x00000018
#define L2_KRNLQ_NX_PG_QIDX             0x00000018
#define L2_KRNLQ_PGTBL_NPAGES           0x0000001c
#define L2_KRNLQ_QIDX_INCR              0x0000001c
#define L2_KRNLQ_PGTBL_HADDR_HI         0x00000020
#define L2_KRNLQ_PGTBL_HADDR_LO         0x00000024

#define BNX2_PG_CTX_MAP                 0x1a0034

static int
bnx2_netq_free_rx_queue(struct net_device *netdev, int index);

static int
bnx2_netqueue_is_avail(struct bnx2 *bp)
{
	rmb();

	return ((BNX2_NETQUEUE_ENABLED(bp)) &&
		(bp->flags & BNX2_FLAG_USING_MSIX) &&
		(CHIP_NUM(bp) == CHIP_NUM_5709));
}

static inline u32
bnx2_netqueue_kwq_avail(struct bnx2 *bp)
{
	return MAX_L2_KWQ_IDX -
		((bp->netq_kwq_prod_idx - bp->netq_kwq_con_idx) &
		  MAX_L2_KWQ_IDX);
}

static int
bnx2_netqueue_submit_kwqes(struct bnx2 *bp, struct l2_kwqe *wqes)
{
	struct l2_kwqe *prod_qe;
	u16 prod, sw_prod;

	if (1 > bnx2_netqueue_kwq_avail(bp)) {
		netdev_warn(bp->dev, "No kwq's available\n");
		return -EAGAIN;
	}

	prod = bp->netq_kwq_prod_idx;
	sw_prod = prod & MAX_L2_KWQ_IDX;

	prod_qe = &bp->netq_kwq[L2_KWQ_PG(sw_prod)][L2_KWQ_IDX(sw_prod)];
	memcpy(prod_qe, wqes, sizeof(struct l2_kwqe));
	prod++;
	sw_prod = prod & MAX_L2_KWQ_IDX;

	bp->netq_kwq_prod_idx = prod;

	barrier();
	REG_WR16(bp, bp->netq_kwq_io_addr, bp->netq_kwq_prod_idx);
	wmb();
	mmiowb();

	return 0;
}

static void
bnx2_netqueue_free_dma(struct bnx2 *bp, struct netq_dma *dma)
{
	int i;

	if (dma->pg_arr) {
		for (i = 0; i < dma->num_pages; i++) {
			if (dma->pg_arr[i]) {
				pci_free_consistent(bp->pdev, BCM_PAGE_SIZE,
						    dma->pg_arr[i],
						    dma->pg_map_arr[i]);
				dma->pg_arr[i] = NULL;
			}
		}
	}
	if (dma->pgtbl) {
		pci_free_consistent(bp->pdev, dma->pgtbl_size,
				    dma->pgtbl, dma->pgtbl_map);
		dma->pgtbl = NULL;
	}
	kfree(dma->pg_arr);
	dma->pg_arr = NULL;
	dma->num_pages = 0;
}

static void
bnx2_netqueue_free_resc(struct bnx2 *bp)
{
	bnx2_netqueue_free_dma(bp, &bp->netq_kwq_info);
	bnx2_netqueue_free_dma(bp, &bp->netq_kcq_info);
}

static void
bnx2_netqueue_setup_page_tbl(struct bnx2 *bp,
			     struct netq_dma *dma)
{
	int i;
	u32 *page_table = dma->pgtbl;

	for (i = 0; i < dma->num_pages; i++) {
		/* Each entry needs to be in big endian format. */
		*page_table = (u32) ((u64) dma->pg_map_arr[i] >> 32);
		page_table++;
		*page_table = (u32) dma->pg_map_arr[i];
		page_table++;
	}
}

static int
bnx2_netqueue_alloc_dma(struct bnx2 *bp, struct netq_dma *dma,
			int pages)
{
	int i, size;

	size = pages * (sizeof(void *) + sizeof(dma_addr_t));
	dma->pg_arr = kzalloc(size, GFP_ATOMIC);
	if (dma->pg_arr == NULL) {
		netdev_err(bp->dev, "Couldn't alloc dma page array\n");
		return -ENOMEM;
	}

	dma->pg_map_arr = (dma_addr_t *) (dma->pg_arr + pages);
	dma->num_pages = pages;

	for (i = 0; i < pages; i++) {
		dma->pg_arr[i] = pci_alloc_consistent(bp->pdev,
						      BCM_PAGE_SIZE,
						      &dma->pg_map_arr[i]);
		if (dma->pg_arr[i] == NULL) {
			netdev_err(bp->dev, "Couldn't alloc dma page\n");

			goto error;
		}
	}

	dma->pgtbl_size = ((pages * 8) + BCM_PAGE_SIZE - 1) &
			  ~(BCM_PAGE_SIZE - 1);
	dma->pgtbl = pci_alloc_consistent(bp->pdev, dma->pgtbl_size,
					  &dma->pgtbl_map);
	if (dma->pgtbl == NULL)
		goto error;

	bnx2_netqueue_setup_page_tbl(bp, dma);

	return 0;

error:
	bnx2_netqueue_free_dma(bp, dma);
	return -ENOMEM;
}

static int
bnx2_netqueue_alloc_resc(struct bnx2 *bp)
{
	int ret;

	ret = bnx2_netqueue_alloc_dma(bp, &bp->netq_kwq_info,
				      L2_KWQ_PAGE_CNT);
	if (ret) {
		netdev_err(bp->dev, "Couldn't alloc space for kwq\n");
		goto error;
	}
	bp->netq_kwq = (struct l2_kwqe **) bp->netq_kwq_info.pg_arr;

	ret = bnx2_netqueue_alloc_dma(bp, &bp->netq_kcq_info,
				      L2_KCQ_PAGE_CNT);
	if (ret) {
		netdev_err(bp->dev, "Couldn't alloc space for kwq\n");
		goto error;
	}
	bp->netq_kcq = (struct l2_kcqe **) bp->netq_kcq_info.pg_arr;

	return 0;

error:
	bnx2_netqueue_free_resc(bp);
	bp->netq_kwq = NULL;
	bp->netq_kcq = NULL;

	return ret;
}

static void
bnx2_init_netqueue_context(struct bnx2 *bp, u32 cid)
{
	u32 cid_addr;
	int i;

	cid_addr = GET_CID_ADDR(cid);

	for (i = 0; i < CTX_SIZE; i += 4)
		bnx2_ctx_wr(bp, cid_addr, i, 0);
}

static int
bnx2_netqueue_get_kcqes(struct bnx2 *bp, u16 hw_prod, u16 *sw_prod)
{
	u16 i, ri, last;
	struct l2_kcqe *kcqe;
	int kcqe_cnt = 0, last_cnt = 0;

	i = ri = last = *sw_prod;
	ri &= MAX_L2_KCQ_IDX;

	while ((i != hw_prod) && (kcqe_cnt < BNX2_NETQ_MAX_COMPLETED_KCQE)) {
		kcqe = &bp->netq_kcq[L2_KCQ_PG(ri)][L2_KCQ_IDX(ri)];
		bp->netq_completed_kcq[kcqe_cnt++] = kcqe;
		i = (i + 1);
		ri = i & MAX_L2_KCQ_IDX;
		if (likely(!(kcqe->flags & L2_KCQE_FLAGS_NEXT))) {
			last_cnt = kcqe_cnt;
			last = i;
		}
	}

	*sw_prod = last;
	return last_cnt;
}


static void
bnx2_service_netq_kcqes(struct bnx2_napi *bnapi, int num_cqes)
{
	struct bnx2 *bp = bnapi->bp;
	int i, j;

	i = 0;
	j = 1;
	while (num_cqes) {
		u32 kcqe_op_flag = bp->netq_completed_kcq[i]->opcode;
		u32 kcqe_layer = bp->netq_completed_kcq[i]->flags &
				 L2_KCQE_FLAGS_LAYER_MASK;

		while (j < num_cqes) {
			u32 next_op = bp->netq_completed_kcq[i + j]->opcode;

			if ((next_op & L2_KCQE_FLAGS_LAYER_MASK) != kcqe_layer)
				break;
			j++;
		}

		if (kcqe_layer != L2_KCQE_FLAGS_LAYER_MASK_L2) {
			netdev_err(bp->dev, "Unknown type of KCQE(0x%x)\n",
					    kcqe_op_flag);
			goto end;
		}

		bp->netq_flags = kcqe_op_flag;
		wake_up(&bp->netq_wait);
		wmb();

end:
		num_cqes -= j;
		i += j;
		j = 1;
	}


	return;
}

static void
bnx2_netqueue_service_bnx2_msix(struct bnx2_napi *bnapi)
{
	struct bnx2 *bp = bnapi->bp;
	struct status_block *status_blk = bp->bnx2_napi[0].status_blk.msi;
	u32 status_idx = status_blk->status_idx;
	u16 hw_prod, sw_prod;
	int kcqe_cnt;

	bp->netq_kwq_con_idx = status_blk->status_cmd_consumer_index;

	hw_prod = status_blk->status_completion_producer_index;
	sw_prod = bp->netq_kcq_prod_idx;

	/*  Ensure that there is a NetQ kcq avaliable */
	if (sw_prod == hw_prod)
		return;

	while (sw_prod != hw_prod) {
		kcqe_cnt = bnx2_netqueue_get_kcqes(bp, hw_prod, &sw_prod);
		if (kcqe_cnt == 0)
			goto done;

		bnx2_service_netq_kcqes(bnapi, kcqe_cnt);

		/* Tell compiler that status_blk fields can change. */
		barrier();
		if (status_idx != status_blk->status_idx) {
			status_idx = status_blk->status_idx;
			bp->netq_kwq_con_idx = status_blk->status_cmd_consumer_index;
			hw_prod = status_blk->status_completion_producer_index;
		} else
			break;
	}

	barrier();
done:
	REG_WR16(bp, bp->netq_kcq_io_addr, sw_prod);

	bp->netq_kcq_prod_idx = sw_prod;
	bp->netq_last_status_idx = status_idx;
}

static int
bnx2_netqueue_open_started(struct bnx2 *bp)
{
	return (((bp->netq_state & BNX2_NETQ_HW_STARTED) ==
			 BNX2_NETQ_HW_STARTED)  &&
		((bp->netq_state & BNX2_NETQ_HW_OPENED) ==
			 BNX2_NETQ_HW_OPENED));
}

static void
bnx2_stop_netqueue_hw(struct bnx2 *bp)
{
	u32 val;

	/* Disable the CP and COM doorbells.  These two processors polls the
	 * doorbell for a non zero value before running.  This must be done
	 * after setting up the kernel queue contexts. This is for
	 * KQW/KCQ #1. */

	val = bnx2_reg_rd_ind(bp, BNX2_CP_SCRATCH + 0x20);
	val &= ~KWQ1_READY;
	bnx2_reg_wr_ind(bp, BNX2_CP_SCRATCH + 0x20, val);

	val = bnx2_reg_rd_ind(bp, BNX2_COM_SCRATCH + 0x20);
	val &= ~KCQ1_READY;
	bnx2_reg_wr_ind(bp, BNX2_COM_SCRATCH + 0x20, val);

	barrier();

	bp->netq_state &= ~BNX2_NETQ_HW_STARTED;
	wmb();
}

static void
bnx2_close_netqueue_hw(struct bnx2 *bp)
{
	bnx2_stop_netqueue_hw(bp);
	bnx2_netqueue_free_resc(bp);

	bp->netq_state &= ~BNX2_NETQ_HW_OPENED;
	wmb();
}

static void
bnx2_start_netqueue_hw(struct bnx2 *bp)
{

	/* Set the CP and COM doorbells.  These two processors polls the
	 * doorbell for a non zero value before running.  This must be done
	 * after setting up the kernel queue contexts. This is for
	 * KQW/KCQ 1. */
	bnx2_reg_wr_ind(bp, BNX2_CP_SCRATCH + 0x20, KWQ1_READY);
	bnx2_reg_wr_ind(bp, BNX2_COM_SCRATCH + 0x20, KCQ1_READY);

	bp->netq_state |= BNX2_NETQ_HW_STARTED;
	wmb();
}

static void
bnx2_init_netqueue_hw(struct bnx2 *bp)
{
	u32 val;

	/*  Initialize the bnx2 netqueue structures */
	init_waitqueue_head(&bp->netq_wait);

	val = REG_RD(bp, BNX2_MQ_CONFIG);
	val &= ~BNX2_MQ_CONFIG_KNL_BYP_BLK_SIZE;
	if (BCM_PAGE_BITS > 12)
		val |= (12 - 8)  << 4;
	else
		val |= (BCM_PAGE_BITS - 8)  << 4;

	REG_WR(bp, BNX2_MQ_CONFIG, val);

	REG_WR(bp, BNX2_HC_COMP_PROD_TRIP, (2 << 16) | 8);
	REG_WR(bp, BNX2_HC_COM_TICKS, (64 << 16) | 220);
	REG_WR(bp, BNX2_HC_CMD_TICKS, (64 << 16) | 220);

	bnx2_init_netqueue_context(bp, NETQUEUE_KWQ_CID);
	bnx2_init_netqueue_context(bp, NETQUEUE_KCQ_CID);

	bp->netq_kwq_cid_addr = GET_CID_ADDR(NETQUEUE_KWQ_CID);
	bp->netq_kwq_io_addr  = MB_GET_CID_ADDR(NETQUEUE_KWQ_CID) +
				L2_KRNLQ_HOST_QIDX;

	bp->netq_kwq_prod_idx = 0;
	bp->netq_kwq_con_idx = 0;

	/* Initialize the kernel work queue context. */
	val = KRNLQ_TYPE_TYPE_KRNLQ | KRNLQ_SIZE_TYPE_SIZE |
	      (BCM_PAGE_BITS - 8) | KRNLQ_FLAGS_QE_SELF_SEQ;
	bnx2_ctx_wr(bp, bp->netq_kwq_cid_addr, L2_KRNLQ_TYPE, val);

	val = (BCM_PAGE_SIZE / sizeof(struct l2_kwqe) - 1) << 16;
	bnx2_ctx_wr(bp, bp->netq_kwq_cid_addr, L2_KRNLQ_QE_SELF_SEQ_MAX, val);

	val = ((BCM_PAGE_SIZE / sizeof(struct l2_kwqe)) << 16) | L2_KWQ_PAGE_CNT;
	bnx2_ctx_wr(bp, bp->netq_kwq_cid_addr, L2_KRNLQ_PGTBL_NPAGES, val);

	val = (u32) ((u64) bp->netq_kwq_info.pgtbl_map >> 32);
	bnx2_ctx_wr(bp, bp->netq_kwq_cid_addr, L2_KRNLQ_PGTBL_HADDR_HI, val);

	val = (u32) bp->netq_kwq_info.pgtbl_map;
	bnx2_ctx_wr(bp, bp->netq_kwq_cid_addr, L2_KRNLQ_PGTBL_HADDR_LO, val);

	bp->netq_kcq_cid_addr = GET_CID_ADDR(NETQUEUE_KCQ_CID);
	bp->netq_kcq_io_addr = MB_GET_CID_ADDR(NETQUEUE_KCQ_CID) +
			       L2_KRNLQ_HOST_QIDX;
	bp->netq_kcq_prod_idx = 0;

	/* Initialize the kernel complete queue context. */
	val = KRNLQ_TYPE_TYPE_KRNLQ | KRNLQ_SIZE_TYPE_SIZE |
	      (BCM_PAGE_BITS - 8) | KRNLQ_FLAGS_QE_SELF_SEQ;
	bnx2_ctx_wr(bp, bp->netq_kcq_cid_addr, L2_KRNLQ_TYPE, val);

	val = (BCM_PAGE_SIZE / sizeof(struct l2_kcqe) - 1) << 16;
	bnx2_ctx_wr(bp, bp->netq_kcq_cid_addr, L2_KRNLQ_QE_SELF_SEQ_MAX, val);

	val = ((BCM_PAGE_SIZE / sizeof(struct l2_kcqe)) << 16)|L2_KCQ_PAGE_CNT;
	bnx2_ctx_wr(bp, bp->netq_kcq_cid_addr, L2_KRNLQ_PGTBL_NPAGES, val);

	val = (u32) ((u64) bp->netq_kcq_info.pgtbl_map >> 32);
	bnx2_ctx_wr(bp, bp->netq_kcq_cid_addr, L2_KRNLQ_PGTBL_HADDR_HI, val);

	val = (u32) bp->netq_kcq_info.pgtbl_map;
	bnx2_ctx_wr(bp, bp->netq_kcq_cid_addr, L2_KRNLQ_PGTBL_HADDR_LO, val);

	/* Enable Commnad Scheduler notification when we write to the
	 * host producer index of the kernel contexts. */
	REG_WR(bp, BNX2_MQ_KNL_CMD_MASK1, 2);

	/* Enable Command Scheduler notification when we write to either
	 * the Send Queue or Receive Queue producer indexes of the kernel
	 * bypass contexts. */
	REG_WR(bp, BNX2_MQ_KNL_BYP_CMD_MASK1, 7);
	REG_WR(bp, BNX2_MQ_KNL_BYP_WRITE_MASK1, 7);

	/* Notify COM when the driver post an application buffer. */
	REG_WR(bp, BNX2_MQ_KNL_RX_V2P_MASK2, 0x2000);

	barrier();
}

static int
bnx2_open_netqueue_hw(struct bnx2 *bp)
{
	int err;

	err = bnx2_netqueue_alloc_resc(bp);
	if (err != 0) {
		netdev_err(bp->dev, "Couldn't allocate netq resources\n");
		return err;
	}

	bnx2_init_netqueue_hw(bp);
	bnx2_start_netqueue_hw(bp);

	bp->netq_state |= BNX2_NETQ_HW_OPENED;
	wmb();

	netdev_info(bp->dev, "NetQueue hardware support is enabled\n");

	return 0;
}



static int
bnx2_netq_get_netqueue_features(vmknetddi_queueop_get_features_args_t *args)
{
	args->features = VMKNETDDI_QUEUEOPS_FEATURE_NONE;
	args->features |= VMKNETDDI_QUEUEOPS_FEATURE_RXQUEUES;
	args->features |= VMKNETDDI_QUEUEOPS_FEATURE_TXQUEUES;
	return VMKNETDDI_QUEUEOPS_OK;
}

static int
bnx2_netq_get_queue_count(vmknetddi_queueop_get_queue_count_args_t *args)
{
	struct bnx2 *bp = netdev_priv(args->netdev);

	/* workaround for packets duplicated */
	if (bp->num_tx_rings + bp->num_rx_rings > 1)
		bp->netq_enabled = 1;

	if (args->type == VMKNETDDI_QUEUEOPS_QUEUE_TYPE_RX) {
		args->count = max_t(u16, bp->num_rx_rings - 1, 0);

		netdev_info(args->netdev, "Using %d RX NetQ rings\n",
					  args->count);

		return VMKNETDDI_QUEUEOPS_OK;
	} else if (args->type == VMKNETDDI_QUEUEOPS_QUEUE_TYPE_TX) {
		args->count = max_t(u16, bp->num_tx_rings - 1, 0);

		netdev_info(args->netdev, "Using %d TX NetQ rings\n",
					  args->count);

		return VMKNETDDI_QUEUEOPS_OK;
	} else {
		netdev_err(args->netdev, "queue count: invalid queue type "
					 "0x%x\n", args->type);
		return VMKNETDDI_QUEUEOPS_ERR;
	}
}

static int
bnx2_netq_get_filter_count(vmknetddi_queueop_get_filter_count_args_t *args)
{
	/* Only support 1 Mac filter per queue */
	args->count = 1;
	return VMKNETDDI_QUEUEOPS_OK;
}

static int
bnx2_netq_alloc_rx_queue(struct bnx2 *bp,
			 struct bnx2_napi *bnapi,
			 int index)
{
	/* We need to count the default ring as part of the number of RX rings
	   avaliable */
	if (bp->n_rx_queues_allocated >= (bp->num_rx_rings - 1)) {
		netdev_warn(bp->dev, "Unable to allocate RX NetQueue n_rx_queues_allocated(%d) >= Num NetQ's(%d)\n",
			    bp->n_rx_queues_allocated, (bp->num_rx_rings - 1));
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if((bp->netq_state & BNX2_NETQ_HW_STARTED) != BNX2_NETQ_HW_STARTED) {
		netdev_warn(bp->dev, "NetQueue hardware not running\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnapi->rx_queue_allocated) {
		int rc;
		struct l2_kwqe_vm_alloc_rx_queue kwqe_alloc_rx;

		/*  Prepare the kwqe to be passed to the firmware */
		memset(&kwqe_alloc_rx, 0, sizeof(kwqe_alloc_rx));

		kwqe_alloc_rx.kwqe_flags  = L2_KWQE_FLAGS_LAYER_MASK_L2;
		kwqe_alloc_rx.kwqe_opcode = L2_KWQE_OPCODE_VALUE_VM_ALLOC_RX_QUEUE;
		kwqe_alloc_rx.queue_type  = L2_NET_QUEUE;
		kwqe_alloc_rx.qid         = BNX2_DRV_TO_FW_QUEUE_ID(index);

		rc = bnx2_netqueue_submit_kwqes(bp,
					(struct l2_kwqe *)&kwqe_alloc_rx);
		if (rc != 0) {
			netdev_err(bp->dev, "Couldn't submit alloc rx kwqe\n");
			return VMKNETDDI_QUEUEOPS_ERR;
		}

		bp->netq_flags = 0;
		wmb();
		rc = wait_event_timeout(bp->netq_wait,
					(bp->netq_flags &
					 L2_KCQE_OPCODE_VALUE_VM_ALLOC_RX_QUEUE),
					BNX2_NETQ_WAIT_EVENT_TIMEOUT);

		if (rc != 0) {
			bnapi->rx_queue_allocated = TRUE;

			netdev_info(bp->dev, "RX NetQ allocated on %d\n",
					     index);
			return VMKNETDDI_QUEUEOPS_OK;
		} else {
			netdev_info(bp->dev, "Timeout RX NetQ allocate on %d\n",
					     index);

			return VMKNETDDI_QUEUEOPS_ERR;
		}
	}

	netdev_info(bp->dev, "No RX NetQueues avaliable!\n");
	return VMKNETDDI_QUEUEOPS_ERR;
}

static int
bnx2_netq_alloc_rx_queue_vmk(struct net_device *netdev,
			     vmknetddi_queueops_queueid_t *p_qid,
			     struct napi_struct **napi_p)
{
	int index;
	struct bnx2 *bp = netdev_priv(netdev);

	/* We need to count the default ring as part of the number of RX rings
	   avaliable */
	if (bp->n_rx_queues_allocated >= (bp->num_rx_rings - 1)) {
		netdev_warn(bp->dev, "Unable to allocate RX NetQueue n_rx_queues_allocated(%d) >= Num NetQ's(%d)\n",
			    bp->n_rx_queues_allocated, (bp->num_rx_rings - 1));
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	for_each_nondefault_rx_queue(bp, index) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[index];
		if (!bnapi->rx_queue_allocated) {
			int rc;

			rc = bnx2_netq_alloc_rx_queue(bp, bnapi, index);

			if (rc == VMKNETDDI_QUEUEOPS_OK) {
				bp->n_rx_queues_allocated++;
				*p_qid = VMKNETDDI_QUEUEOPS_MK_RX_QUEUEID(index);
				*napi_p = &bnapi->napi;

				return VMKNETDDI_QUEUEOPS_OK;
			} else 
				return VMKNETDDI_QUEUEOPS_ERR;
		}
	}

	netdev_err(bp->dev, "No free RX NetQueues found!\n");
	return VMKNETDDI_QUEUEOPS_ERR;
}


static int
bnx2_netq_alloc_tx_queue(struct bnx2 *bp,
			 struct bnx2_napi *bnapi,
			 int index)
{
	if (bp->n_tx_queues_allocated >= (bp->num_tx_rings - 1))
		return VMKNETDDI_QUEUEOPS_ERR;

	if (!bnapi->tx_queue_allocated) {
		bnapi->tx_queue_allocated = TRUE;
		bp->n_tx_queues_allocated++;

		netdev_info(bp->dev, "TX NetQ allocated on %d\n", index);
		return VMKNETDDI_QUEUEOPS_OK;
	}
	netdev_err(bp->dev, "tx queue already allocated!\n");
	return VMKNETDDI_QUEUEOPS_ERR;
}

static int
bnx2_netq_alloc_tx_queue_vmk(struct net_device *netdev,
			     vmknetddi_queueops_queueid_t *p_qid,
			     u16 *queue_mapping)
{
	int index;
	struct bnx2 *bp = netdev_priv(netdev);

	if (bp->n_tx_queues_allocated >= (bp->num_tx_rings - 1))
		return VMKNETDDI_QUEUEOPS_ERR;

	for_each_nondefault_tx_queue(bp, index) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[index];
		if (!bnapi->tx_queue_allocated) {
			int rc = bnx2_netq_alloc_tx_queue(bp, bnapi, index);

			*p_qid = VMKNETDDI_QUEUEOPS_MK_TX_QUEUEID(index);
			*queue_mapping = index;

			return rc;
		}
	}

	netdev_err(bp->dev, "no free tx queues found!\n");
	return VMKNETDDI_QUEUEOPS_ERR;
}

static int
bnx2_netq_alloc_queue(vmknetddi_queueop_alloc_queue_args_t *args)
{
	struct net_device *netdev = args->netdev;
	struct bnx2 *bp = netdev_priv(netdev);

	if(bp->reset_failed == 1) {
		netdev_err(bp->dev, "Trying to alloc NetQueue on failed reset "
				    "device\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_warn(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (args->type == VMKNETDDI_QUEUEOPS_QUEUE_TYPE_TX) {
		return bnx2_netq_alloc_tx_queue_vmk(args->netdev,
						    &args->queueid,
						    &args->queue_mapping);
	} else if (args->type == VMKNETDDI_QUEUEOPS_QUEUE_TYPE_RX) {
		return bnx2_netq_alloc_rx_queue_vmk(args->netdev,
						    &args->queueid,
						    &args->napi);
	} else {
		netdev_err(bp->dev, "Trying to alloc invalid queue type: %x\n",
			   args->type);
		return VMKNETDDI_QUEUEOPS_ERR;
	}
}

static int
bnx2_netq_free_tx_queue(struct net_device *netdev,
		        vmknetddi_queueops_queueid_t qid)
{
	struct bnx2 *bp = netdev_priv(netdev);
	struct bnx2_napi *bnapi;

	u16 index = VMKNETDDI_QUEUEOPS_QUEUEID_VAL(qid);
	if (index > bp->num_tx_rings)
		return VMKNETDDI_QUEUEOPS_ERR;

	bnapi = &bp->bnx2_napi[index];
	if (bnapi->tx_queue_allocated != TRUE)
		return VMKNETDDI_QUEUEOPS_ERR;

	bnapi->tx_queue_allocated = FALSE;
	bp->n_tx_queues_allocated--;

	netdev_info(bp->dev, "Free NetQ TX Queue: 0x%x\n", index);

	return VMKNETDDI_QUEUEOPS_OK;
}

static int
bnx2_netq_free_rx_queue(struct net_device *netdev,
			int index)
{
	int rc;
	struct bnx2 *bp = netdev_priv(netdev);
	struct bnx2_napi *bnapi;
	struct l2_kwqe_vm_free_rx_queue kwqe_free_rx;

	if (index > bp->num_rx_rings) {
		netdev_err(bp->dev, "Error Free NetQ RX Queue: "
				    "index(%d) > bp->num_rx_rings(%d)\n",
			   index, bp->num_rx_rings);

		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_warn(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bnapi = &bp->bnx2_napi[index];
	if (bnapi->rx_queue_allocated != TRUE) {
		netdev_warn(bp->dev, "NetQ RX Queue %d already freed\n", index);

		return VMKNETDDI_QUEUEOPS_OK;
	}

	memset(&kwqe_free_rx, 0, sizeof(kwqe_free_rx));

	kwqe_free_rx.flags	= L2_KWQE_FLAGS_LAYER_MASK_L2;
	kwqe_free_rx.opcode	= L2_KWQE_OPCODE_VALUE_VM_FREE_RX_QUEUE;
	kwqe_free_rx.qid	= BNX2_DRV_TO_FW_QUEUE_ID(index);
	kwqe_free_rx.queue_type = L2_NET_QUEUE;

	rc = bnx2_netqueue_submit_kwqes(bp,
					(struct l2_kwqe *) &kwqe_free_rx);
	if (rc != 0) {
		netdev_err(bp->dev, "Couldn't submit free rx kwqe\n");

		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bp->netq_flags = 0;
	wmb();
	rc = wait_event_timeout(bp->netq_wait,
				(bp->netq_flags &
				L2_KCQE_OPCODE_VALUE_VM_FREE_RX_QUEUE),
				BNX2_NETQ_WAIT_EVENT_TIMEOUT);
	if (rc != 0) {
		bnapi->rx_queue_allocated = FALSE;
		bp->n_rx_queues_allocated--;

		netdev_info(bp->dev, "Free NetQ RX Queue %d\n", index);

		return VMKNETDDI_QUEUEOPS_OK;
	} else {
		netdev_err(bp->dev, "Timeout free NetQ RX Queue %d\n", index);

		return VMKNETDDI_QUEUEOPS_ERR;
	}
}

static int
bnx2_netq_free_queue(vmknetddi_queueop_free_queue_args_t *args)
{
	struct bnx2 *bp = netdev_priv(args->netdev);

	if(bp->reset_failed == 1) {
		netdev_err(bp->dev, "Trying to free NetQueue on failed reset "
				    "device\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_warn(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (VMKNETDDI_QUEUEOPS_IS_TX_QUEUEID(args->queueid)) {
		return bnx2_netq_free_tx_queue(args->netdev, args->queueid);
	} else if (VMKNETDDI_QUEUEOPS_IS_RX_QUEUEID(args->queueid)) {
		return bnx2_netq_free_rx_queue(args->netdev,
				VMKNETDDI_QUEUEOPS_QUEUEID_VAL(args->queueid));
	} else {
		netdev_err(bp->dev, "free netq: invalid queue type: 0x%x\n",
			   args->queueid);
		return VMKNETDDI_QUEUEOPS_ERR;
	}
}

static int
bnx2_netq_get_queue_vector(vmknetddi_queueop_get_queue_vector_args_t *args)
{
	int qid;
	struct bnx2 *bp = netdev_priv(args->netdev);
	qid = VMKNETDDI_QUEUEOPS_QUEUEID_VAL(args->queueid);
	if (qid > bp->num_rx_rings)
		return VMKNETDDI_QUEUEOPS_ERR;

#ifdef CONFIG_PCI_MSI
	args->vector = bp->bnx2_napi[qid].int_num;
#endif
	return VMKNETDDI_QUEUEOPS_OK;
}

static int
bnx2_netq_get_default_queue(vmknetddi_queueop_get_default_queue_args_t *args)
{
	struct bnx2 *bp = netdev_priv(args->netdev);

	if (args->type == VMKNETDDI_QUEUEOPS_QUEUE_TYPE_RX) {
		args->queueid = VMKNETDDI_QUEUEOPS_MK_RX_QUEUEID(0);
		args->napi = &bp->bnx2_napi[0].napi;
		return VMKNETDDI_QUEUEOPS_OK;
	} else if (args->type == VMKNETDDI_QUEUEOPS_QUEUE_TYPE_TX) {
		args->queueid = VMKNETDDI_QUEUEOPS_MK_TX_QUEUEID(0);
		args->queue_mapping = 0;
		return VMKNETDDI_QUEUEOPS_OK;
	} else
		return VMKNETDDI_QUEUEOPS_ERR;
}

static int
bnx2_netq_remove_rx_filter(struct bnx2 *bp, int index)
{
	u16 fw_qid = BNX2_DRV_TO_FW_QUEUE_ID(index);
	struct bnx2_napi *bnapi;
	struct l2_kwqe_vm_remove_rx_filter kwqe_remove_rx_filter;
	int rc;

	if(bp->reset_failed == 1) {
		netdev_err(bp->dev, "Trying to remove RX filter NetQueue on "
				    "failed reset device\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_err(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bnapi = &bp->bnx2_napi[index];

	if (fw_qid > bp->num_rx_rings) {
		netdev_info(bp->dev, "Free RX Filter NetQ: failed "
				     "qid(%d) > bp->num_rx_rings(%d)\n",
			    index, bp->num_rx_rings);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	memset(&kwqe_remove_rx_filter, 0, sizeof(kwqe_remove_rx_filter));

	kwqe_remove_rx_filter.flags		= L2_KWQE_FLAGS_LAYER_MASK_L2;
	kwqe_remove_rx_filter.opcode		= L2_KWQE_OPCODE_VALUE_VM_REMOVE_RX_FILTER;
	kwqe_remove_rx_filter.filter_type	= L2_VM_FILTER_MAC;
	kwqe_remove_rx_filter.qid		= fw_qid;
	kwqe_remove_rx_filter.filter_id		= fw_qid + BNX2_START_FILTER_ID;

	rc = bnx2_netqueue_submit_kwqes(bp,
					(struct l2_kwqe *) &kwqe_remove_rx_filter);
	if (rc != 0) {
		netdev_err(bp->dev, "Couldn't submit rx filter kwqe\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bp->netq_flags = 0;
	wmb();
	rc = wait_event_timeout(bp->netq_wait,
				(bp->netq_flags &
				 L2_KCQE_OPCODE_VALUE_VM_REMOVE_RX_FILTER),
				BNX2_NETQ_WAIT_EVENT_TIMEOUT);
	if (rc != 0) {
		bnapi->rx_queue_active = FALSE;
		bnapi->netq_state &= ~BNX2_NETQ_RX_FILTER_APPLIED;

		netdev_info(bp->dev, "NetQ remove RX filter: %d\n", index);

		return VMKNETDDI_QUEUEOPS_OK;
	} else {
		netdev_warn(bp->dev, "Timeout NetQ remove RX filter: %d\n",
			    index);

		return VMKNETDDI_QUEUEOPS_ERR;
	}
}

static int
bnx2_netq_remove_rx_filter_vmk(vmknetddi_queueop_remove_rx_filter_args_t *args)
{
	struct bnx2 *bp = netdev_priv(args->netdev);
	u16 index = VMKNETDDI_QUEUEOPS_QUEUEID_VAL(args->queueid);
	struct bnx2_napi *bnapi;

	if (bp->reset_failed == 1) {
		netdev_err(bp->dev, "Trying to remove RX filter NetQueue on "
				    "failed reset device\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_warn(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bnapi = &bp->bnx2_napi[index];

	if (!VMKNETDDI_QUEUEOPS_IS_RX_QUEUEID(args->queueid)) {
		netdev_err(bp->dev, "!VMKNETDDI_QUEUEOPS_IS_RX_QUEUEID: "
				    "qid: %d)\n", index);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (index > bp->num_rx_rings) {
		netdev_err(bp->dev, "qid(%d) > bp->num_rx_rings(%d)\n",
			   index, bp->num_rx_rings);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	/* Only support one Mac filter per queue */
	if (bnapi->rx_queue_active == 0) {
		netdev_info(bp->dev, "bnapi->rx_queue_active(%d) == 0\n",
			    bnapi->rx_queue_active);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	return bnx2_netq_remove_rx_filter(bp, index);
}


static int
bnx2_netq_apply_rx_filter(struct bnx2 *bp, struct bnx2_napi *bnapi,
			  int index)
{
	u16 fw_queueid = BNX2_DRV_TO_FW_QUEUE_ID(index);
	struct l2_kwqe_vm_set_rx_filter kwqe_set_rx_filter;
	int rc;
	DECLARE_MAC_BUF(mac);

	if (bp->reset_failed == 1) {
		netdev_err(bp->dev, "Trying to apply RX filter NetQueue on %d"
				    "failed reset device\n", index);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_warn(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (bnapi->rx_queue_active == TRUE || !bnapi->rx_queue_allocated) {
		netdev_err(bp->dev, "apply filter: RX NetQ %d already active"
				"bnapi->rx_queue_active(%d) || "
				"!bnapi->rx_queue_allocated(%d)\n",
			   index, bnapi->rx_queue_active,
			   bnapi->rx_queue_allocated);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bnx2_set_mac_addr(bp, bnapi->mac_filter_addr,
			  fw_queueid + QID_TO_PM_OFFSET);


	memset(&kwqe_set_rx_filter, 0, sizeof(kwqe_set_rx_filter));

	kwqe_set_rx_filter.flags	= L2_KWQE_FLAGS_LAYER_MASK_L2;
	kwqe_set_rx_filter.opcode	= L2_KWQE_OPCODE_VALUE_VM_SET_RX_FILTER;
	kwqe_set_rx_filter.filter_id	= fw_queueid + BNX2_START_FILTER_ID;

#if defined(__LITTLE_ENDIAN)
	memcpy(&kwqe_set_rx_filter.mac_addr_hi, bnapi->mac_filter_addr, 2);
	memcpy(&kwqe_set_rx_filter.mac_addr_lo, bnapi->mac_filter_addr + 2, 4);
#else
	memcpy(&kwqe_set_rx_filter.mac_addr, bnapi->mac_filter_addr, 6);
#endif

	if (bnapi->class == VMKNETDDI_QUEUEOPS_FILTER_MACADDR) {
		kwqe_set_rx_filter.filter_type	= L2_VM_FILTER_MAC;
	} else {
		kwqe_set_rx_filter.filter_type	= L2_VM_FILTER_MAC_VLAN;
		kwqe_set_rx_filter.vlan		= bnapi->vlan_id;
	}
	kwqe_set_rx_filter.qid		= fw_queueid;

	rc = bnx2_netqueue_submit_kwqes(bp,
					(struct l2_kwqe *) &kwqe_set_rx_filter);
	if (rc != 0) {
		netdev_err(bp->dev, "Couldn't submit rx filter kwqe\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bp->netq_flags = 0;
	wmb();
	rc = wait_event_timeout(bp->netq_wait,
				(bp->netq_flags &
				 L2_KCQE_OPCODE_VALUE_VM_SET_RX_FILTER),
				BNX2_NETQ_WAIT_EVENT_TIMEOUT);

	if (rc != 0) {
		bnapi->rx_queue_active = TRUE;
		bnapi->netq_state |= BNX2_NETQ_RX_FILTER_APPLIED;

		netdev_info(bp->dev,  "NetQ set RX Filter: %d [%s %d]\n",
			    index, print_mac(mac, bnapi->mac_filter_addr),
			    bnapi->vlan_id);

		return VMKNETDDI_QUEUEOPS_OK;
	} else {
		netdev_info(bp->dev, "Timeout submitting NetQ set RX Filter: "
				     "%d [%s]\n",
			    index, print_mac(mac, bnapi->mac_filter_addr));

		return VMKNETDDI_QUEUEOPS_ERR;
	}
}

static int
bnx2_netq_apply_rx_filter_vmk(vmknetddi_queueop_apply_rx_filter_args_t *args)
{
	u8 *macaddr;
	struct bnx2_napi *bnapi;
	struct bnx2 *bp = netdev_priv(args->netdev);
	u16 index = VMKNETDDI_QUEUEOPS_QUEUEID_VAL(args->queueid);
	vmknetddi_queueops_filter_class_t class;
	DECLARE_MAC_BUF(mac);

	if (bp->reset_failed == 1) {
		netdev_err(bp->dev, "Trying to apply RX filter NetQueue on %d"
				    "failed reset device\n", index);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!bnx2_netqueue_open_started(bp)) {
		netdev_warn(bp->dev, "NetQueue hardware not running yet\n");
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	if (!VMKNETDDI_QUEUEOPS_IS_RX_QUEUEID(args->queueid)) {
		netdev_err(bp->dev, "invalid NetQ RX ID: %x\n", args->queueid);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	class = vmknetddi_queueops_get_filter_class(&args->filter);
	if ((class != VMKNETDDI_QUEUEOPS_FILTER_MACADDR) &&
	    (class != VMKNETDDI_QUEUEOPS_FILTER_VLANMACADDR)) {
		netdev_err(bp->dev, "recieved invalid RX NetQ filter: %x\n",
			   class);
		return VMKNETDDI_QUEUEOPS_ERR;
	}
	if (index > bp->num_rx_rings) {
		netdev_err(bp->dev, "applying filter with invalid "
				    "RX NetQ %d ID\n", index);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	bnapi = &bp->bnx2_napi[index];

	if (bnapi->rx_queue_active || !bnapi->rx_queue_allocated) {
		netdev_err(bp->dev, "RX NetQ %d already active\n", index);
		return VMKNETDDI_QUEUEOPS_ERR;
	}

	macaddr = (void *)vmknetddi_queueops_get_filter_macaddr(&args->filter);
	memcpy(bnapi->mac_filter_addr, macaddr, ETH_ALEN);
	bnapi->vlan_id = vmknetddi_queueops_get_filter_vlanid(&args->filter);
	bnapi->class = class;

	/*  Apply RX filter code here */
	args->filterid = VMKNETDDI_QUEUEOPS_MK_FILTERID(index);

	return bnx2_netq_apply_rx_filter(bp, bnapi, index);
}

static int
bnx2_netq_get_queue_stats(vmknetddi_queueop_get_stats_args_t *args)
{
	u16 index = VMKNETDDI_QUEUEOPS_QUEUEID_VAL(args->queueid);
	struct bnx2_napi *bnapi;
	struct bnx2 *bp = netdev_priv(args->netdev);

	bnapi = &bp->bnx2_napi[index];

	args->stats = &bnapi->stats;

	return VMKNETDDI_QUEUEOPS_OK;
}

static int
bnx2_netq_get_netqueue_version(vmknetddi_queueop_get_version_args_t *args)
{
	return vmknetddi_queueops_version(args);
}

static void
bnx2_netqueue_flush_all(struct bnx2 *bp)
{
	int index;
	u16 num_tx = 0, num_rx = 0;

	netdev_info(bp->dev, "Flushing NetQueues\n");

	mutex_lock(&bp->netq_lock);

	for_each_nondefault_rx_queue(bp, index) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[index];

		if(bnapi->netq_state & BNX2_NETQ_RX_FILTER_APPLIED) {
			int rc = bnx2_netq_remove_rx_filter(bp, index);
			if (rc == VMKNETDDI_QUEUEOPS_ERR) {
				netdev_err(bp->dev, "could not remove RX "
						    "filter during flush\n");
			}

			if(bnapi->rx_queue_allocated == TRUE) {
				rc = bnx2_netq_free_rx_queue(bp->dev, index);
				if (rc == VMKNETDDI_QUEUEOPS_OK) {
					num_rx++;
				} else {
					netdev_err(bp->dev, "couldn't free RX "
							    "queue %d during "
							    "flush\n", index);
				}
			}
		}
	}

	for_each_nondefault_tx_queue(bp, index) {
		struct bnx2_napi *bnapi = &bp->bnx2_napi[index];

		if(bnapi->tx_queue_allocated == TRUE) {
			bnx2_netq_free_tx_queue(bp->dev, index);
		}

		num_tx++;
	}

	mutex_unlock(&bp->netq_lock);

	netdev_info(bp->dev, "Flushed NetQueues: rx: %d tx: %d\n",
		    num_rx, num_tx);
}


static int
bnx2_netqueue_ops(vmknetddi_queueops_op_t op, void *args)
{
	int rc;
	struct bnx2 *bp;

	if (op == VMKNETDDI_QUEUEOPS_OP_GET_VERSION)
		 return bnx2_netq_get_netqueue_version(
			(vmknetddi_queueop_get_version_args_t *)args);

	bp = netdev_priv(((vmknetddi_queueop_get_features_args_t *)args)->netdev);

	if (!bnx2_netqueue_is_avail(bp))
		return VMKNETDDI_QUEUEOPS_ERR;

	mutex_lock(&bp->netq_lock);

	switch (op) {
	case VMKNETDDI_QUEUEOPS_OP_GET_FEATURES:
		rc = bnx2_netq_get_netqueue_features(
			(vmknetddi_queueop_get_features_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_GET_QUEUE_COUNT:
		rc = bnx2_netq_get_queue_count(
			(vmknetddi_queueop_get_queue_count_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_GET_FILTER_COUNT:
		rc = bnx2_netq_get_filter_count(
			(vmknetddi_queueop_get_filter_count_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_ALLOC_QUEUE:
		rc = bnx2_netq_alloc_queue(
			(vmknetddi_queueop_alloc_queue_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_FREE_QUEUE:
		rc = bnx2_netq_free_queue(
			(vmknetddi_queueop_free_queue_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_GET_QUEUE_VECTOR:
		rc = bnx2_netq_get_queue_vector(
			(vmknetddi_queueop_get_queue_vector_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_GET_DEFAULT_QUEUE:
		rc = bnx2_netq_get_default_queue(
			(vmknetddi_queueop_get_default_queue_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_APPLY_RX_FILTER:
		rc = bnx2_netq_apply_rx_filter_vmk(
			(vmknetddi_queueop_apply_rx_filter_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_REMOVE_RX_FILTER:
		rc = bnx2_netq_remove_rx_filter_vmk(
			(vmknetddi_queueop_remove_rx_filter_args_t *)args);
		break;

	case VMKNETDDI_QUEUEOPS_OP_GET_STATS:
		rc = bnx2_netq_get_queue_stats(
			(vmknetddi_queueop_get_stats_args_t *)args);
		break;

	/*  Unsupported for now */
	case VMKNETDDI_QUEUEOPS_OP_SET_TX_PRIORITY:
		rc = VMKNETDDI_QUEUEOPS_ERR;
		break;

#if (VMWARE_ESX_DDK_VERSION >= 41000)
	case VMKNETDDI_QUEUEOPS_OP_ALLOC_QUEUE_WITH_ATTR:
		rc = VMKNETDDI_QUEUEOPS_ERR;
		break;

	case VMKNETDDI_QUEUEOPS_OP_GET_SUPPORTED_FEAT:
		rc = VMKNETDDI_QUEUEOPS_ERR;
		break;
#if (VMWARE_ESX_DDK_VERSION >= 50000)
	case VMKNETDDI_QUEUEOPS_OP_GET_SUPPORTED_FILTER_CLASS:
		rc = VMKNETDDI_QUEUEOPS_ERR;
		break;
#endif
#endif
	default:
		netdev_warn(bp->dev, "Unhandled NETQUEUE OP %d\n", op);
		rc = VMKNETDDI_QUEUEOPS_ERR;
	}

	mutex_unlock(&bp->netq_lock);

	return rc;
}
#endif /* defined(BNX2_ENABLE_NETQUEUE) */

#if defined(__VMKLNX__)
#if (VMWARE_ESX_DDK_VERSION >= 60000)
static void
bnx2_dump(struct bnx2 *bp, u32 reg_offset, u32 *dest_addr, u32 word_cnt)
{
	u32 *dst = dest_addr;
	u32 i;

	for (i = 0; i < word_cnt; i++) {
		*dst++ = REG_RD(bp, reg_offset);
		reg_offset += 4;
	}
}

static void
bnx2_dump_ind(struct bnx2 *bp, u32 reg_offset, u32 *dest_addr, u32 word_cnt)
{
	u32 *dst = dest_addr;
	u32 i;

	for (i = 0; i < word_cnt; i++) {
		*dst++ = bnx2_reg_rd_ind(bp, reg_offset);
		reg_offset += 4;
	}
}

#define BNX2_CPU_ENTRY(offset, size) { offset, size }
static const struct cpu_data_reg {
	u32 off;
	u32 size;
} cpu_arr[] = {
	BNX2_CPU_ENTRY(0, 3),
	BNX2_CPU_ENTRY(0x1c, 8),
	BNX2_CPU_ENTRY(0x48, 1),
	BNX2_CPU_ENTRY(0x200, 32),
};

static u32 *
dump_cpu_state(struct bnx2 *bp, u32 *dst, struct chip_core_dmp *dmp)
{
	u32 reg, i;
	u32 cpu_size = 0;

	if (dmp->fw_hdr.dmp_size >= BNX2_FWDMP_SIZE)
		return dst;
	for (reg = BNX2_TXP_CPU_MODE; reg <= BNX2_CP_CPU_MODE; reg += 0x40000) {
		/* make sure these are 64-bit align */
		for (i = 0; i < ARRAY_SIZE(cpu_arr); i++)
			cpu_size += cpu_arr[i].size * 4;
	}
	if ((dmp->fw_hdr.dmp_size + cpu_size + BNX2_FWDMP_MARKER_SZ) >
		BNX2_FWDMP_SIZE)
		return dst;
	*dst++ = BNX2_FWDMP_MARKER;
	*dst++ = 0;
	*dst++ = BNX2_FWDMP_CPU_DUMP;
	*dst++ = cpu_size;
	for (reg = BNX2_TXP_CPU_MODE; reg <= BNX2_CP_CPU_MODE; reg += 0x40000) {
		/* make sure these are 64-bit align */
		for (i = 0; i < ARRAY_SIZE(cpu_arr); i++) {
			bnx2_dump_ind(bp, reg + cpu_arr[i].off,
				      dst, cpu_arr[i].size);
			dst += cpu_arr[i].size;
		}
	}
	*dst++ = BNX2_FWDMP_MARKER_END;
	dmp->fw_hdr.dmp_size += cpu_size + BNX2_FWDMP_MARKER_SZ;

	return dst;
}

#define BNX2_FTQ_DATA_ENTRY(offset, cmdoff, size, dataoff) { BNX2_##offset, \
							     BNX2_##cmdoff, \
							     size, \
							     BNX2_##dataoff }
static const struct ftq_data_reg {
	u32 off;
	u32 cmdoff;
	u32 size;
	u32 dataoff;
} ftq_data_arr[] = {
	BNX2_FTQ_DATA_ENTRY(TSCH_FTQ_CMD,
			    TSCH_FTQ_CMD_RD_DATA,
			    2, TSCH_TSCHQ),
	BNX2_FTQ_DATA_ENTRY(TBDR_FTQ_CMD,
			    TBDR_FTQ_CMD_RD_DATA,
			    5, TBDR_TBDRQ),
	BNX2_FTQ_DATA_ENTRY(TXP_FTQ_CMD,
			    TXP_FTQ_CMD_RD_DATA,
			    5, TXP_TXPQ),
	BNX2_FTQ_DATA_ENTRY(TDMA_FTQ_CMD,
			    TDMA_FTQ_CMD_RD_DATA,
			    12, TDMA_TDMAQ),
	BNX2_FTQ_DATA_ENTRY(TPAT_FTQ_CMD,
			    TPAT_FTQ_CMD_RD_DATA,
			    5, TPAT_TPATQ),
	BNX2_FTQ_DATA_ENTRY(TAS_FTQ_CMD,
			    TAS_FTQ_CMD_RD_DATA,
			    4, TPAT_TPATQ),
	BNX2_FTQ_DATA_ENTRY(RLUP_FTQ_COMMAND,
			    RLUP_FTQ_CMD_RD_DATA,
			    30, RLUP_RLUPQ),
	BNX2_FTQ_DATA_ENTRY(RXP_FTQ_CMD,
			    RXP_FTQ_CMD_RD_DATA,
			    13, RXP_RXPQ),
	BNX2_FTQ_DATA_ENTRY(RXP_CFTQ_CMD,
			    RXP_CFTQ_CMD_RD_DATA,
			    4, RXP_RXPCQ),
	BNX2_FTQ_DATA_ENTRY(RV2P_MFTQ_CMD,
			    RV2P_MFTQ_CMD_RD_DATA,
			    1, RV2P_RV2PMQ),
	BNX2_FTQ_DATA_ENTRY(RV2P_TFTQ_CMD,
			    RV2P_TFTQ_CMD_RD_DATA,
			    1, RV2P_RV2PTQ),
	BNX2_FTQ_DATA_ENTRY(RV2P_PFTQ_CMD,
			    RV2P_PFTQ_CMD_RD_DATA,
			    13, RV2P_RV2PPQ),
	BNX2_FTQ_DATA_ENTRY(RDMA_FTQ_COMMAND,
			    RDMA_FTQ_CMD_RD_DATA,
			    13, RDMA_RDMAQ),
	BNX2_FTQ_DATA_ENTRY(COM_COMQ_FTQ_CMD,
			    COM_COMQ_FTQ_CMD_RD_DATA,
			    10, COM_COMQ),
	BNX2_FTQ_DATA_ENTRY(COM_COMTQ_FTQ_CMD,
			    COM_COMTQ_FTQ_CMD_RD_DATA,
			    3, COM_COMTQ),
	BNX2_FTQ_DATA_ENTRY(COM_COMXQ_FTQ_CMD,
			    COM_COMXQ_FTQ_CMD_RD_DATA,
			    4, COM_COMXQ),
	BNX2_FTQ_DATA_ENTRY(CP_CPQ_FTQ_CMD,
			    CP_CPQ_FTQ_CMD_RD_DATA,
			    1, CP_CPQ),
	BNX2_FTQ_DATA_ENTRY(CSCH_CH_FTQ_COMMAND,
			    CSCH_CH_FTQ_CMD_RD_DATA,
			    2, CSCH_CSQ),
	BNX2_FTQ_DATA_ENTRY(MCP_MCPQ_FTQ_CMD,
			    MCP_MCPQ_FTQ_CMD_RD_DATA,
			    5, MCP_MCPQ),
};

static u32 *
dump_ftq_ctrl_info(struct bnx2 *bp, u32 *dst, struct chip_core_dmp *dmp)
{
	int i;
	u32 ftq_size = 0;

	if (dmp->fw_hdr.dmp_size >= BNX2_FWDMP_SIZE)
		return dst;
	for (i = 0; i < ARRAY_SIZE(ftq_arr); i++)
		ftq_size += 4;
	for (i = 0; i < ARRAY_SIZE(ftq_data_arr); i++)
		ftq_size += ftq_data_arr[i].size * 4;
	if ((dmp->fw_hdr.dmp_size + ftq_size + BNX2_FWDMP_MARKER_SZ) >
		BNX2_FWDMP_SIZE)
		return dst;
	*dst++ = BNX2_FWDMP_MARKER;
	*dst++ = 0;
	*dst++ = BNX2_FWDMP_FTQ_DUMP;
	*dst++ = ftq_size;
	for (i = 0; i < ARRAY_SIZE(ftq_arr); i++)
		*dst++ = bnx2_reg_rd_ind(bp, ftq_arr[i].off);

	for (i = 0; i < ARRAY_SIZE(ftq_data_arr); i++) {
		bnx2_reg_wr_ind(bp, ftq_data_arr[i].off,
				ftq_data_arr[i].cmdoff);
		bnx2_dump_ind(bp, ftq_data_arr[i].dataoff,
			      dst, ftq_data_arr[i].size);
		dst += ftq_data_arr[i].size;
	}
	*dst++ = BNX2_FWDMP_MARKER_END;
	dmp->fw_hdr.dmp_size += ftq_size + BNX2_FWDMP_MARKER_SZ;
	return dst;
}

#define BNX2_GRCBLK_SIZE   0x400
#define BNX2_GRC_ENTRY(offset) { BNX2_##offset }
static const struct grc_reg {
	u32 off;
} grc_arr[] = {
	BNX2_GRC_ENTRY(PCICFG_START),
	BNX2_GRC_ENTRY(PCI_GRC_WINDOW_ADDR),
	BNX2_GRC_ENTRY(MISC_COMMAND),
	BNX2_GRC_ENTRY(DMA_COMMAND),
	BNX2_GRC_ENTRY(CTX_COMMAND),
	BNX2_GRC_ENTRY(EMAC_MODE),
	BNX2_GRC_ENTRY(RPM_COMMAND),
	BNX2_GRC_ENTRY(RCP_START),
	BNX2_GRC_ENTRY(RLUP_COMMAND),
	BNX2_GRC_ENTRY(CH_COMMAND),
	BNX2_GRC_ENTRY(RV2P_COMMAND),
	BNX2_GRC_ENTRY(RDMA_COMMAND),
	BNX2_GRC_ENTRY(RBDC_COMMAND),
	BNX2_GRC_ENTRY(MQ_COMMAND),
	BNX2_GRC_ENTRY(TIMER_COMMAND),
	BNX2_GRC_ENTRY(TSCH_COMMAND),
	BNX2_GRC_ENTRY(TBDR_COMMAND),
	BNX2_GRC_ENTRY(TBDC_COMMAND),
	BNX2_GRC_ENTRY(TDMA_COMMAND),
	BNX2_GRC_ENTRY(DBU_CMD),
	BNX2_GRC_ENTRY(NVM_COMMAND),
	BNX2_GRC_ENTRY(HC_COMMAND),
	BNX2_GRC_ENTRY(DEBUG_COMMAND),
};

static u32 *dump_grc(struct bnx2 *bp, u32 *dst, struct chip_core_dmp *dmp)
{
	u32 i;
	u32 grc_size = 0;

	if (dmp->fw_hdr.dmp_size >= BNX2_FWDMP_SIZE)
		return dst;
	for (i = 0; i < ARRAY_SIZE(grc_arr); i++)
		grc_size += BNX2_GRCBLK_SIZE;
	if ((dmp->fw_hdr.dmp_size + grc_size + BNX2_FWDMP_MARKER_SZ) >
		BNX2_FWDMP_SIZE)
		return dst;
	*dst++ = BNX2_FWDMP_MARKER;
	*dst++ = 0;
	*dst++ = BNX2_FWDMP_GRC_DUMP;
	*dst++ = grc_size;
	for (i = 0; i < ARRAY_SIZE(grc_arr); i++) {
		bnx2_dump(bp, grc_arr[i].off, dst, BNX2_GRCBLK_SIZE/4);
		dst += BNX2_GRCBLK_SIZE/4;
	}
	*dst++ = BNX2_FWDMP_MARKER_END;
	dmp->fw_hdr.dmp_size += grc_size + BNX2_FWDMP_MARKER_SZ;
	return dst;
}

#define BNX2_HSI_ENTRY(offset, size) { BNX2_##offset, BNX2_##size }
static const struct hsi_reg {
	u32 off;
	u32 size;
} hsi_arr[] = {
	BNX2_HSI_ENTRY(CP_HSI_START, CP_HSI_SIZE),
	BNX2_HSI_ENTRY(COM_HSI_START, COM_HSI_SIZE),
	BNX2_HSI_ENTRY(RXP_HSI_START, RXP_HSI_SIZE),
	BNX2_HSI_ENTRY(TXP_HSI_START, TXP_HSI_SIZE),
	BNX2_HSI_ENTRY(TPAT_HSI_START, TPAT_HSI_SIZE),
};

static u32 *dump_hsi(struct bnx2 *bp, u32 *dst, struct chip_core_dmp *dmp)
{
	u32 i;
	u32 hsi_size = 0;

	if (dmp->fw_hdr.dmp_size >= BNX2_FWDMP_SIZE)
		return dst;
	for (i = 0; i < ARRAY_SIZE(hsi_arr); i++)
		hsi_size += hsi_arr[i].size;
	if ((dmp->fw_hdr.dmp_size + hsi_size + BNX2_FWDMP_MARKER_SZ) >
		 BNX2_FWDMP_SIZE)
		return dst;
	*dst++ = BNX2_FWDMP_MARKER;
	*dst++ = 0;
	*dst++ = BNX2_FWDMP_HSI_DUMP;
	*dst++ = hsi_size;
	for (i = 0; i < ARRAY_SIZE(hsi_arr); i++) {
		bnx2_dump_ind(bp, hsi_arr[i].off, dst, hsi_arr[i].size/4);
		dst += hsi_arr[i].size/4;
	}
	*dst++ = BNX2_FWDMP_MARKER_END;
	dmp->fw_hdr.dmp_size += hsi_size + BNX2_FWDMP_MARKER_SZ;
	return dst;
}

static u32 *
dump_mcp_info(struct bnx2 *bp, u32 *dst, struct chip_core_dmp *dmp)
{
	u32 i;

	if (dmp->fw_hdr.dmp_size >= BNX2_FWDMP_SIZE)
		return dst;
	*dst++ = BNX2_FWDMP_MARKER;
	*dst++ = 0;
	*dst++ = BNX2_FWDMP_MCP_DUMP;
	*dst++ = BNX2_MCP_DUMP_SIZE;
	if (CHIP_NUM(bp) == CHIP_NUM_5709) {
		*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_STATE_P0);
		*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_STATE_P1);
	} else {
		*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_STATE_P0_5708);
		*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_STATE_P1_5708);
	}
	*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_MODE);
	*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_STATE);
	*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_EVENT_MASK);
	*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_PROGRAM_COUNTER);
	*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_PROGRAM_COUNTER);
	*dst++ = bnx2_reg_rd_ind(bp, BNX2_MCP_CPU_INSTRUCTION);
	*dst++ = bnx2_shmem_rd(bp, BNX2_DRV_MB);
	*dst++ = bnx2_shmem_rd(bp, BNX2_FW_MB);
	*dst++ = bnx2_shmem_rd(bp, BNX2_LINK_STATUS);
	*dst++ = bnx2_shmem_rd(bp, BNX2_DRV_PULSE_MB);
	*dst++ = bnx2_shmem_rd(bp, BNX2_DEV_INFO_SIGNATURE);
	*dst++ = bnx2_shmem_rd(bp, BNX2_BC_STATE_RESET_TYPE);
	*dst++ = bnx2_shmem_rd(bp, BNX2_BC_STATE_CONDITION);
	for (i = 0; i < 16;) {
		*dst++ = bnx2_shmem_rd(bp, BNX2_BC_STATE_RESET_TYPE);
		i += 4;
	}
	for (i = 0; i < 16;) {
		*dst++ = bnx2_shmem_rd(bp, 0x3cc);
		i += 4;
	}
	for (i = 0; i < 16;) {
		*dst++ = bnx2_shmem_rd(bp, 0x3dc);
		i += 4;
	}
	for (i = 0; i < 16;) {
		*dst++ = bnx2_shmem_rd(bp, 0x3ec);
		i += 4;
	}
	*dst++ = bnx2_shmem_rd(bp, 0x3fc);
	*dst++ = BNX2_FWDMP_MARKER_END;
	dmp->fw_hdr.dmp_size += BNX2_MCP_DUMP_SIZE + BNX2_FWDMP_MARKER_SZ;
	return dst;
}

static u32 *dump_tbdc(struct bnx2 *bp, u32 *dst, struct chip_core_dmp *dmp)
{
	u32 i;

	if (dmp->fw_hdr.dmp_size >= BNX2_FWDMP_SIZE)
		return dst;
	if ((dmp->fw_hdr.dmp_size + BNX2_TBDC_DUMP_SIZE +
		BNX2_FWDMP_MARKER_SZ) > BNX2_FWDMP_SIZE)
		return dst;
	*dst++ = BNX2_FWDMP_MARKER;
	*dst++ = 0;
	*dst++ = BNX2_FWDMP_TBDC_DUMP;
	*dst++ = BNX2_TBDC_DUMP_SIZE;
	for (i = 0; i < 0x20; i++) {
		int j = 0;

		REG_WR(bp, BNX2_TBDC_BD_ADDR, i);
		REG_WR(bp, BNX2_TBDC_CAM_OPCODE,
		       BNX2_TBDC_CAM_OPCODE_OPCODE_CAM_READ);
		REG_WR(bp, BNX2_TBDC_COMMAND, BNX2_TBDC_COMMAND_CMD_REG_ARB);
		while ((REG_RD(bp, BNX2_TBDC_COMMAND) &
			BNX2_TBDC_COMMAND_CMD_REG_ARB) && j < 100)
			j++;

		*dst++ = REG_RD(bp, BNX2_TBDC_CID);
		*dst++ = REG_RD(bp, BNX2_TBDC_BIDX);
		*dst++ = REG_RD(bp, BNX2_TBDC_CAM_OPCODE);
	}
	*dst++ = BNX2_FWDMP_MARKER_END;
	dmp->fw_hdr.dmp_size += BNX2_TBDC_DUMP_SIZE + BNX2_FWDMP_MARKER_SZ;
	return dst;
}

static VMK_ReturnStatus bnx2_fwdmp_callback(void *cookie, vmk_Bool liveDump)
{
	VMK_ReturnStatus status = VMK_OK;
	u32 idx;
	u32 *dst;
	struct chip_core_dmp *dmp;
	struct bnx2 *bp;

	for (idx = 0; idx < BNX2_MAX_NIC; idx++) {
		if (fwdmp_va_ptr && fwdmp_bp_ptr[idx]) {
			/* dump chip information to buffer */
			bp = fwdmp_bp_ptr[idx];
			dmp = (struct chip_core_dmp *)fwdmp_va_ptr;
			snprintf(dmp->fw_hdr.name, sizeof(dmp->fw_hdr.name),
				"%s", bp->dev->name);
			dmp->fw_hdr.bp = (void *)bp;
			dmp->fw_hdr.chip_id = bp->chip_id;
			dmp->fw_hdr.len = sizeof(struct fw_dmp_hdr);
			dmp->fw_hdr.ver = 0x000700006;
			dmp->fw_hdr.dmp_size = dmp->fw_hdr.len;
			/* 1. dump all CPUs states  */
			dst = dmp->fw_dmp_buf;
			dst = dump_cpu_state(bp, dst, dmp);
			/* 2. dump all ftqs control information */
			dst = dump_ftq_ctrl_info(bp, dst, dmp);
			/* 3. dump mcp info */
			dst = dump_mcp_info(bp, dst, dmp);
			/* 4. dump tbdc contents */
			dst = dump_tbdc(bp, dst, dmp);
			/* 5. dump hsi section for all processors */
			dst = dump_hsi(bp, dst, dmp);
			/* 6. dump 32k grc registers */
			dst = dump_grc(bp, dst, dmp);

			status = vmklnx_dump_range(bnx2_fwdmp_dh,
					fwdmp_va_ptr, dmp->fw_hdr.dmp_size);
			if (status != VMK_OK) {
				printk(KERN_ERR "####failed to dump firmware/chip data %x %d!\n",
						status, idx);
				break;
			}
		}
	}
	return status;
}
#endif

/* The following debug buffers and exported routines are used by GDB to access
   teton/xinan hardware registers when doing live debug over serial port. */

#define DBG_BUF_SZ  128

static u32 bnx2_dbg_buf[DBG_BUF_SZ];

static u32 bnx2_dbg_read32_ind_single(void __iomem *reg_view, u32 off)
{
	u32 val;
	writel(off, reg_view + BNX2_PCICFG_REG_WINDOW_ADDRESS);
	val = readl(reg_view + BNX2_PCICFG_REG_WINDOW);
	return val;
}

void bnx2_dbg_read32_ind(void __iomem *reg_view, u32 off, u32 len)
{
	u32 *buf = bnx2_dbg_buf;

	if (len & 0x3)
		len = (len + 3) & ~3;
	if (len > DBG_BUF_SZ)
		len = DBG_BUF_SZ;

	while (len > 0) {
		*buf = bnx2_dbg_read32_ind_single(reg_view, off);
		buf++;
		off += 4;
		len -= 4;
	}
}
EXPORT_SYMBOL(bnx2_dbg_read32_ind);

static u32 bnx2_dbg_read32_single(void __iomem *reg_view, u32 off)
{
	return readl(reg_view + off);
}

void bnx2_dbg_read32(void __iomem *reg_view, u32 off, u32 len)
{
	u32 *buf = bnx2_dbg_buf;

	if (len & 0x3)
		len = (len + 3) & ~3;
	if (len > DBG_BUF_SZ)
		len = DBG_BUF_SZ;

	while (len > 0) {
		*buf = bnx2_dbg_read32_single(reg_view, off);
		buf++;
		off += 4;
		len -= 4;
	}
}
EXPORT_SYMBOL(bnx2_dbg_read32);

void bnx2_dbg_write32(void __iomem *reg_view, u32 off, u32 val)
{
	writel(val, reg_view + off);
}
EXPORT_SYMBOL(bnx2_dbg_write32);

void bnx2_dbg_write32_ind(void __iomem *reg_view, u32 off, u32 val)
{
	writel(off, reg_view + BNX2_PCICFG_REG_WINDOW_ADDRESS);
	writel(val, reg_view + BNX2_PCICFG_REG_WINDOW);
}
EXPORT_SYMBOL(bnx2_dbg_write32_ind);

#endif /*__VMKLNX__ */
