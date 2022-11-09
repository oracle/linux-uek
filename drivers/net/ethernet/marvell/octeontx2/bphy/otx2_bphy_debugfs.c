// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>

#include "otx2_bphy_debugfs.h"
#include "otx2_bphy.h"
#include "otx2_rfoe.h"
#include "cnf10k_rfoe.h"
#include "otx2_bphy_hw.h"

#define OTX2_BPHY_DEBUGFS_MODE 0400
#define RPM_CSR_BASE_ADDR		0x87E0E0000000
#define RPM_CFG_BAR_RSRC_LEN		0x7FFFFF
#define RPMX_MTI_STAT_RX_STAT_PAGES_COUNTERX 0x12000
#define RPMX_MTI_STAT_TX_STAT_PAGES_COUNTERX 0x13000
#define RPMX_MTI_STAT_DATA_HI_CDC            0x10038
#define CGXX_CMRX_RX_STAT0		0x070
#define CGXX_CMRX_TX_STAT0		0x700
#define RPMX_EXT_MTI_GLOBAL_FEC_CONTROL			0x50008
#define RPMX_EXT_MTI_GLOBAL_FEC_CONTROL_KP_MODE_IN	GENMASK_ULL(27, 24)
#define RPMX_EXT_MTI_GLOBAL_FEC_CONTROL_FEC91_ENA	GENMASK_ULL(19, 16)
#define RPMX_EXT_MTI_GLOBAL_FEC_CONTROL_FEC_ENA		GENMASK_ULL(3, 0)
#define RPMX_EXT_MTI_PORTX_STATUS(a)			(0x51008 |\
							 ((a) * 0x100))
#define RPMX_EXT_MTI_PORTX_STATUS_MAC_RES_SPEED		GENMASK_ULL(12, 5)

/* FEC stats */
#define RPMX_MTI_STAT_STATN_CONTROL			0x10018
#define RPMX_MTI_STAT_DATA_HI_CDC			0x10038
#define RPMX_RSFEC_RX_CAPTURE				BIT_ULL(27)
#define RPMX_MTI_RSFEC_STAT_COUNTER_CAPTURE_2		0x40050
#define RPMX_MTI_RSFEC_STAT_COUNTER_CAPTURE_3		0x40058
#define RPMX_MTI_FCFECX_VL0_CCW_LO(a)			(0x38618 + ((a) * 0x40))
#define RPMX_MTI_FCFECX_VL0_NCCW_LO(a)			(0x38620 + ((a) * 0x40))
#define RPMX_MTI_FCFECX_VL1_CCW_LO(a)			(0x38628 + ((a) * 0x40))
#define RPMX_MTI_FCFECX_VL1_NCCW_LO(a)			(0x38630 + ((a) * 0x40))
#define RPMX_MTI_FCFECX_CW_HI(a)			(0x38638 + ((a) * 0x40))

enum fec_type {
	OTX2_FEC_NONE,
	OTX2_FEC_BASER,
	OTX2_FEC_RS,
};

enum LMAC_TYPE {
	LMAC_MODE_10M_R		= 1,
	LMAC_MODE_100M_R	= 2,
	LMAC_MODE_1G_2G_R	= 3,
	LMAC_MODE_10G_25G_R	= 6,
	LMAC_MODE_40G_R		= 7,
	LMAC_MODE_50G_R		= 8,
	LMAC_MODE_100G_R	= 9,
	LMAC_MODE_RESET		= 0xFF,
};

enum {
	CGX_STAT0,
	CGX_STAT1,
	CGX_STAT2,
	CGX_STAT3,
	CGX_STAT4,
	CGX_STAT5,
	CGX_STAT6,
	CGX_STAT7,
	CGX_STAT8,
	CGX_STAT9,
	CGX_STAT10,
	CGX_STAT11,
	CGX_STAT12,
	CGX_STAT13,
	CGX_STAT14,
	CGX_STAT15,
	CGX_STAT16,
	CGX_STAT17,
	CGX_STAT18,
};

static char *cgx_rx_stats_fields[] = {
	[CGX_STAT0]	= "Received packets",
	[CGX_STAT1]	= "Octets of received packets",
	[CGX_STAT2]	= "Received PAUSE packets",
	[CGX_STAT3]	= "Received PAUSE and control packets",
	[CGX_STAT4]	= "Filtered DMAC0 (NIX-bound) packets",
	[CGX_STAT5]	= "Filtered DMAC0 (NIX-bound) octets",
	[CGX_STAT6]	= "Packets dropped due to RX FIFO full",
	[CGX_STAT7]	= "Octets dropped due to RX FIFO full",
	[CGX_STAT8]	= "Error packets",
	[CGX_STAT9]	= "Filtered DMAC1 (NCSI-bound) packets",
	[CGX_STAT10]	= "Filtered DMAC1 (NCSI-bound) octets",
	[CGX_STAT11]	= "NCSI-bound packets dropped",
	[CGX_STAT12]	= "NCSI-bound octets dropped",
};

static char *cgx_tx_stats_fields[] = {
	[CGX_STAT0]	= "Packets dropped due to excessive collisions",
	[CGX_STAT1]	= "Packets dropped due to excessive deferral",
	[CGX_STAT2]	= "Multiple collisions before successful transmission",
	[CGX_STAT3]	= "Single collisions before successful transmission",
	[CGX_STAT4]	= "Total octets sent on the interface",
	[CGX_STAT5]	= "Total frames sent on the interface",
	[CGX_STAT6]	= "Packets sent with an octet count < 64",
	[CGX_STAT7]	= "Packets sent with an octet count == 64",
	[CGX_STAT8]	= "Packets sent with an octet count of 65-127",
	[CGX_STAT9]	= "Packets sent with an octet count of 128-255",
	[CGX_STAT10]	= "Packets sent with an octet count of 256-511",
	[CGX_STAT11]	= "Packets sent with an octet count of 512-1023",
	[CGX_STAT12]	= "Packets sent with an octet count of 1024-1518",
	[CGX_STAT13]	= "Packets sent with an octet count of > 1518",
	[CGX_STAT14]	= "Packets sent to a broadcast DMAC",
	[CGX_STAT15]	= "Packets sent to the multicast DMAC",
	[CGX_STAT16]	= "Transmit underflow and were truncated",
	[CGX_STAT17]	= "Control/PAUSE packets sent",
};

static char *rpm_rx_stats_fields[] = {
	"Octets of received packets",
	"Octets of received packets with out error",
	"Received packets with alignment errors",
	"Control/PAUSE packets received",
	"Packets received with Frame too long Errors",
	"Packets received with a1nrange length Errors",
	"Received packets",
	"Packets received with FrameCheckSequenceErrors",
	"Packets received with VLAN header",
	"Error packets",
	"Packets received with unicast DMAC",
	"Packets received with multicast DMAC",
	"Packets received with broadcast DMAC",
	"Dropped packets",
	"Total frames received on interface",
	"Packets received with an octet count < 64",
	"Packets received with an octet count == 64",
	"Packets received with an octet count of 65-127",
	"Packets received with an octet count of 128-255",
	"Packets received with an octet count of 256-511",
	"Packets received with an octet count of 512-1023",
	"Packets received with an octet count of 1024-1518",
	"Packets received with an octet count of > 1518",
	"Oversized Packets",
	"Jabber Packets",
	"Fragmented Packets",
	"CBFC(class based flow control) pause frames received for class 0",
	"CBFC pause frames received for class 1",
	"CBFC pause frames received for class 2",
	"CBFC pause frames received for class 3",
	"CBFC pause frames received for class 4",
	"CBFC pause frames received for class 5",
	"CBFC pause frames received for class 6",
	"CBFC pause frames received for class 7",
	"CBFC pause frames received for class 8",
	"CBFC pause frames received for class 9",
	"CBFC pause frames received for class 10",
	"CBFC pause frames received for class 11",
	"CBFC pause frames received for class 12",
	"CBFC pause frames received for class 13",
	"CBFC pause frames received for class 14",
	"CBFC pause frames received for class 15",
	"MAC control packets received",
};

static char *rpm_tx_stats_fields[] = {
	"Total octets sent on the interface",
	"Total octets transmitted OK",
	"Control/Pause frames sent",
	"Total frames transmitted OK",
	"Total frames sent with VLAN header",
	"Error Packets",
	"Packets sent to unicast DMAC",
	"Packets sent to the multicast DMAC",
	"Packets sent to a broadcast DMAC",
	"Packets sent with an octet count == 64",
	"Packets sent with an octet count of 65-127",
	"Packets sent with an octet count of 128-255",
	"Packets sent with an octet count of 256-511",
	"Packets sent with an octet count of 512-1023",
	"Packets sent with an octet count of 1024-1518",
	"Packets sent with an octet count of > 1518",
	"CBFC(class based flow control) pause frames transmitted for class 0",
	"CBFC pause frames transmitted for class 1",
	"CBFC pause frames transmitted for class 2",
	"CBFC pause frames transmitted for class 3",
	"CBFC pause frames transmitted for class 4",
	"CBFC pause frames transmitted for class 5",
	"CBFC pause frames transmitted for class 6",
	"CBFC pause frames transmitted for class 7",
	"CBFC pause frames transmitted for class 8",
	"CBFC pause frames transmitted for class 9",
	"CBFC pause frames transmitted for class 10",
	"CBFC pause frames transmitted for class 11",
	"CBFC pause frames transmitted for class 12",
	"CBFC pause frames transmitted for class 13",
	"CBFC pause frames transmitted for class 14",
	"CBFC pause frames transmitted for class 15",
	"MAC control packets sent",
	"Total frames sent on the interface"
};

struct otx2_bphy_debugfs_reader_info {
	atomic_t			refcnt;
	size_t				buffer_size;
	void				*priv;
	otx2_bphy_debugfs_reader	reader;
	struct dentry			*entry;
	char				buffer[1];
};

static struct dentry *otx2_bphy_debugfs;

static bool is_otx2;
static int otx2_bphy_debugfs_open(struct inode *inode, struct file *file);

static int otx2_bphy_debugfs_release(struct inode *inode, struct file *file);

static ssize_t otx2_bphy_debugfs_read(struct file *file, char __user *buffer,
				      size_t count, loff_t *offset);

static const struct file_operations otx2_bphy_debugfs_foper = {
	.owner		= THIS_MODULE,
	.open		= otx2_bphy_debugfs_open,
	.release	= otx2_bphy_debugfs_release,
	.read		= otx2_bphy_debugfs_read,
};

void __init otx2_bphy_debugfs_init(void)
{
	struct pci_dev *bphy_pdev;

	otx2_bphy_debugfs = debugfs_create_dir(DRV_NAME, NULL);
	if (!otx2_bphy_debugfs)
		pr_info("%s: debugfs is not enabled\n", DRV_NAME);

	bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
				   OTX2_BPHY_PCI_DEVICE_ID, NULL);

	if (!bphy_pdev)
		return;

	if (bphy_pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_A ||
	    bphy_pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B)
		is_otx2 = false;
	else
		is_otx2 = true;
}

static u64 rfoe_dbg_rpm_get_tx_stats(void __iomem *reg_base, int lmac_id, int idx,
				     u8 tx_stats_cnt)
{
	u64 val_lo, val_hi;

	if (!is_otx2) {
		/* Update idx to point per lmac Rx statistics page */
		idx += lmac_id * tx_stats_cnt;
		val_lo = ioread64(reg_base + RPMX_MTI_STAT_TX_STAT_PAGES_COUNTERX + (idx * 8));
		val_hi = ioread64(reg_base + RPMX_MTI_STAT_DATA_HI_CDC);
		return (val_hi << 32 | val_lo);
	} else {
		return ioread64(reg_base + (lmac_id << 18) + CGXX_CMRX_TX_STAT0 + (idx * 8));
	}
}

static u64 rfoe_dbg_rpm_get_rx_stats(void __iomem *reg_base, int lmac_id, int idx,
				     u8 rx_stats_cnt)
{
	u64 val_lo, val_hi;

	if (!is_otx2) {
		/* Update idx to point per lmac Rx statistics page */
		idx += lmac_id * rx_stats_cnt;
		val_lo = ioread64(reg_base + RPMX_MTI_STAT_RX_STAT_PAGES_COUNTERX + (idx * 8));
		val_hi = ioread64(reg_base + RPMX_MTI_STAT_DATA_HI_CDC);
		return (val_hi << 32 | val_lo);
	} else {
		return ioread64(reg_base + (lmac_id << 18) + CGXX_CMRX_RX_STAT0 + (idx * 8));
	}
}

static void rfoe_dbg_rpm_get_fec_stats(void __iomem *reg_base, int lmac_id,
				       u64 *fec_corr_blks, u64 *fec_uncorr_blks)
{
	u64 val_lo, val_hi, cfg;
	int fec_mode, lmac_mode;

	cfg = ioread64(reg_base + RPMX_EXT_MTI_GLOBAL_FEC_CONTROL);
	if (cfg & RPMX_EXT_MTI_GLOBAL_FEC_CONTROL_FEC91_ENA ||
	    cfg & RPMX_EXT_MTI_GLOBAL_FEC_CONTROL_KP_MODE_IN)
		fec_mode = OTX2_FEC_RS;
	else if (cfg & RPMX_EXT_MTI_GLOBAL_FEC_CONTROL_FEC_ENA)
		fec_mode = OTX2_FEC_BASER;
	else
		fec_mode = OTX2_FEC_NONE;

	cfg = ioread64(reg_base + RPMX_EXT_MTI_PORTX_STATUS(lmac_id));
	lmac_mode = ((cfg & RPMX_EXT_MTI_PORTX_STATUS_MAC_RES_SPEED) >> 5);

	if (fec_mode == OTX2_FEC_NONE) {
		*fec_corr_blks = 0;
		*fec_uncorr_blks = 0;
	} else if (fec_mode == OTX2_FEC_BASER) {
		val_lo = ioread64(reg_base + RPMX_MTI_FCFECX_VL0_CCW_LO(lmac_id));
		val_hi = ioread64(reg_base + RPMX_MTI_FCFECX_CW_HI(lmac_id));
		*fec_corr_blks = (val_hi << 16 | val_lo);

		val_lo = ioread64(reg_base + RPMX_MTI_FCFECX_VL0_NCCW_LO(lmac_id));
		val_hi = ioread64(reg_base + RPMX_MTI_FCFECX_CW_HI(lmac_id));
		*fec_uncorr_blks = (val_hi << 16 | val_lo);

		/* 50G uses 2 Physical serdes lines */
		if (lmac_mode == LMAC_MODE_50G_R) {
			val_lo = ioread64(reg_base + RPMX_MTI_FCFECX_VL1_CCW_LO(lmac_id));
			val_hi = ioread64(reg_base + RPMX_MTI_FCFECX_CW_HI(lmac_id));
			*fec_corr_blks += (val_hi << 16 | val_lo);

			val_lo = ioread64(reg_base + RPMX_MTI_FCFECX_VL1_NCCW_LO(lmac_id));
			val_hi = ioread64(reg_base + RPMX_MTI_FCFECX_CW_HI(lmac_id));
			*fec_uncorr_blks += (val_hi << 16 | val_lo);
		}
	} else {
		/* enable RS-FEC capture */
		cfg = ioread64(reg_base + RPMX_MTI_STAT_STATN_CONTROL);
		cfg |= RPMX_RSFEC_RX_CAPTURE | BIT(lmac_id);
		iowrite64(cfg, reg_base + RPMX_MTI_STAT_STATN_CONTROL);

		val_lo = ioread64(reg_base + RPMX_MTI_RSFEC_STAT_COUNTER_CAPTURE_2);
		val_hi = ioread64(reg_base + RPMX_MTI_STAT_DATA_HI_CDC);
		*fec_corr_blks = (val_hi << 32 | val_lo);

		val_lo = ioread64(reg_base + RPMX_MTI_RSFEC_STAT_COUNTER_CAPTURE_3);
		val_hi = ioread64(reg_base + RPMX_MTI_STAT_DATA_HI_CDC);
		*fec_uncorr_blks = (val_hi << 32 | val_lo);
	}
}

static int otx2_rfoe_dbg_read_rpm_stats(struct seq_file *filp, void *unused)
{
	int stat, rx_stats_cnt, tx_stats_cnt;
	u64 rpm_base_addr, rx_stat, tx_stat;
	u64 fec_corr_blks, fec_uncorr_blks;
	struct cnf10k_rfoe_ndev_priv *priv;
	struct cnf10k_rfoe_drv_ctx *ctx;
	void __iomem *rpm_reg_base;
	u8 rpm_id, lmac_id;

	ctx = filp->private;
	priv = netdev_priv(ctx->netdev);
	lmac_id = priv->lmac_id;

	if (is_otx2) {
		rx_stats_cnt = 9;
		tx_stats_cnt = 18;
		rpm_id = priv->rfoe_num + 1;
	} else {
		rx_stats_cnt = 43;
		tx_stats_cnt = 34;
		rpm_id = priv->rfoe_num + 2;
	}

	rpm_base_addr = (RPM_CSR_BASE_ADDR | (rpm_id << 24));
	rpm_reg_base = ioremap(rpm_base_addr, RPM_CFG_BAR_RSRC_LEN);

	/* Rx stats */
	stat = 0;
	seq_puts(filp, "\n======= RX_STATS======\n\n");
	while (stat < rx_stats_cnt) {
		rx_stat = rfoe_dbg_rpm_get_rx_stats(rpm_reg_base, lmac_id, stat, rx_stats_cnt);
		if (is_otx2)
			seq_printf(filp, "%s: %llu\n", cgx_rx_stats_fields[stat],
				   rx_stat);
		else
			seq_printf(filp, "%s: %llu\n", rpm_rx_stats_fields[stat],
				   rx_stat);
		stat++;
	}

	/* Tx stats */
	stat = 0;
	seq_puts(filp, "\n======= TX_STATS======\n\n");
	while (stat < tx_stats_cnt) {
		tx_stat = rfoe_dbg_rpm_get_tx_stats(rpm_reg_base, lmac_id, stat, tx_stats_cnt);

		if (is_otx2)
			seq_printf(filp, "%s: %llu\n", cgx_tx_stats_fields[stat],
				   tx_stat);
		else
			seq_printf(filp, "%s: %llu\n", rpm_tx_stats_fields[stat],
				   tx_stat);
		stat++;
	}

	if (!is_otx2) {
		rfoe_dbg_rpm_get_fec_stats(rpm_reg_base, lmac_id, &fec_corr_blks,
					   &fec_uncorr_blks);
		seq_printf(filp, "Fec Corrected Errors: %llu\n", fec_corr_blks);
		seq_printf(filp, "Fec Uncorrected Errors: %llu\n", fec_uncorr_blks);
	}

	iounmap(rpm_reg_base);

	return 0;
}

static int otx2_rfoe_dbg_open_rpm_stats(struct inode *inode, struct file *file)
{
	return single_open(file, otx2_rfoe_dbg_read_rpm_stats, inode->i_private);
}

static const struct file_operations otx2_rfoe_dbg_rpm_stats_fops = {
	.owner = THIS_MODULE,
	.open =	otx2_rfoe_dbg_open_rpm_stats,
	.read = seq_read,
};

void otx2_debugfs_add_rpm_stats_file(void *priv)
{
	struct cnf10k_rfoe_drv_ctx *cnf10k_ctx;
	struct otx2_rfoe_drv_ctx *ctx;
	struct dentry *root;
	char entry[10];

	if (is_otx2) {
		strcpy(entry, "cgx_stats");
		ctx = (struct otx2_rfoe_drv_ctx *)priv;
		root = ctx->root;
		debugfs_create_file(entry, 0444, root, ctx, &otx2_rfoe_dbg_rpm_stats_fops);
	} else {
		strcpy(entry, "rpm_stats");
		cnf10k_ctx = (struct cnf10k_rfoe_drv_ctx *)priv;
		root = cnf10k_ctx->root;
		debugfs_create_file(entry, 0444, root, cnf10k_ctx, &otx2_rfoe_dbg_rpm_stats_fops);
	}
}

static int otx2_rfoe_dbg_read_ptp_tstamp_ring(struct seq_file *filp, void *unused)
{
	struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
	struct cnf10k_rfoe_drv_ctx *cnf10k_ctx;
	struct otx2_rfoe_ndev_priv *otx2_priv;
	struct otx2_rfoe_drv_ctx *otx2_ctx;
	struct rfoe_tx_ptp_tstmp_s *tx_tstmp;
	void __iomem *ptp_ring_base;
	u64 tstmp_w1, tstmp_w0;
	u8 idx, ring_size;
	u64 *ptp_tstamp;

	seq_puts(filp, "Ring ID\t TSTAMP_W0\t\tTSTAMP_W1\n");
	if (is_otx2) {
		otx2_ctx = filp->private;
		otx2_priv = netdev_priv(otx2_ctx->netdev);
		idx = 0;
		tstmp_w1 = readq(otx2_priv->rfoe_reg_base +
				 RFOEX_TX_PTP_TSTMP_W1(otx2_priv->rfoe_num,
						       otx2_priv->lmac_id));
		tstmp_w0 = readq(otx2_priv->rfoe_reg_base +
				 RFOEX_TX_PTP_TSTMP_W0(otx2_priv->rfoe_num,
						       otx2_priv->lmac_id));
		seq_printf(filp, "%d\t0x%llx\t\t0x%llx\n", idx, tstmp_w0, tstmp_w1);
	} else {
		cnf10k_ctx = filp->private;
		cnf10k_priv = netdev_priv(cnf10k_ctx->netdev);
		ring_size = cnf10k_priv->ptp_ring_cfg.ptp_ring_size;
		ptp_ring_base = cnf10k_priv->ptp_ring_cfg.ptp_ring_base;
		for (idx = 0; idx < ring_size; idx++) {
			tx_tstmp = (struct rfoe_tx_ptp_tstmp_s *)
					((u8 *)ptp_ring_base +
					(16 * idx));
			ptp_tstamp = (u64 *)tx_tstmp;
			seq_printf(filp, "%d\t0x%llx\t\t0x%llx\n", idx, *ptp_tstamp,
				   *(ptp_tstamp + 1));
		}
	}

	return 0;
}

static int otx2_rfoe_dbg_open_ptp_tstamp_ring(struct inode *inode, struct file *file)
{
	return single_open(file, otx2_rfoe_dbg_read_ptp_tstamp_ring, inode->i_private);
}

static const struct file_operations otx2_rfoe_dbg_tstamp_ring_fops = {
	.owner = THIS_MODULE,
	.open =	otx2_rfoe_dbg_open_ptp_tstamp_ring,
	.read = seq_read,
};

void otx2_debugfs_add_tstamp_ring_file(void *priv)
{
	struct cnf10k_rfoe_drv_ctx *cnf10k_ctx;
	struct otx2_rfoe_drv_ctx *ctx;
	struct dentry *root;
	char entry[10];

	strcpy(entry, "ptp_ring");

	if (is_otx2) {
		ctx = (struct otx2_rfoe_drv_ctx *)priv;
		root = ctx->root;
		debugfs_create_file(entry, 0444, root, ctx, &otx2_rfoe_dbg_tstamp_ring_fops);
	} else {
		cnf10k_ctx = (struct cnf10k_rfoe_drv_ctx *)priv;
		root = cnf10k_ctx->root;
		debugfs_create_file(entry, 0444, root, cnf10k_ctx, &otx2_rfoe_dbg_tstamp_ring_fops);
	}
}

static void otx2_rfoe_dbg_dump_jdt_ring(struct seq_file *filp, struct tx_job_queue_cfg *job_cfg,
					void *priv)
{
	struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
	struct otx2_rfoe_ndev_priv *otx2_priv;
	struct tx_job_entry *job_entry;
	u64 jd_cfg_iova, iova;
	int idx;

	if (is_otx2)
		otx2_priv = (struct otx2_rfoe_ndev_priv *)priv;
	else
		cnf10k_priv = (struct cnf10k_rfoe_ndev_priv *)priv;

	for (idx = 0; idx < job_cfg->num_entries; idx++) {
		job_entry = &job_cfg->job_entries[idx];
		iova = job_entry->jd_iova_addr;

		if (is_otx2)
			job_entry->jd_ptr = otx2_iova_to_virt(otx2_priv->iommu_domain, iova);
		else
			job_entry->jd_ptr = otx2_iova_to_virt(cnf10k_priv->iommu_domain, iova);

		seq_printf(filp, "Ring idx:\t%d\n", idx);
		seq_printf(filp, "Contents of JD Header:\t0x%llx\n", *(u64 *)(job_entry->jd_ptr));
		jd_cfg_iova = *(u64 *)((u8 *)job_entry->jd_ptr + 8);

		if (is_otx2)
			job_entry->jd_cfg_ptr = otx2_iova_to_virt(otx2_priv->iommu_domain,
								  jd_cfg_iova);
		else
			job_entry->jd_cfg_ptr = otx2_iova_to_virt(cnf10k_priv->iommu_domain,
								  jd_cfg_iova);

		seq_puts(filp, "Contents of JD CFG pointer\n");
		seq_printf(filp, "AB_SLOT_CFG0:\t0x%llx\n", *(u64 *)((u8 *)job_entry->jd_cfg_ptr));
		seq_printf(filp, "AB_SLOT_CFG1:\t0x%llx\n",
			   *(u64 *)((u8 *)job_entry->jd_cfg_ptr + 8));
		seq_printf(filp, "AB_SLOT_CFG2:\t0x%llx\n",
			   *(u64 *)((u8 *)job_entry->jd_cfg_ptr + 16));
		seq_printf(filp, "AB_SLOT_CFG3:\t0x%llx\n",
			   *(u64 *)((u8 *)job_entry->jd_cfg_ptr + 24));
		seq_puts(filp, "Contents of RD DMA pointer\n");
		seq_printf(filp, "0x%llx\t0x%llx\n", *(u64 *)((u8 *)job_entry->rd_dma_ptr),
			   *(u64 *)(((u8 *)job_entry->rd_dma_ptr + 8)));
	}
}

static int otx2_rfoe_dbg_read_jdt_ring(struct seq_file *filp, void *unused)
{
	struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
	struct cnf10k_rfoe_drv_ctx *cnf10k_ctx;
	struct otx2_rfoe_ndev_priv *otx2_priv;
	struct otx2_rfoe_drv_ctx *otx2_ctx;
	struct tx_job_queue_cfg *job_cfg;

	seq_puts(filp, "============== PTP JD Ring=================\n");
	if (is_otx2) {
		otx2_ctx = filp->private;
		otx2_priv = netdev_priv(otx2_ctx->netdev);
		job_cfg = &otx2_priv->tx_ptp_job_cfg;
		otx2_rfoe_dbg_dump_jdt_ring(filp, job_cfg, otx2_priv);
	} else {
		cnf10k_ctx = filp->private;
		cnf10k_priv = netdev_priv(cnf10k_ctx->netdev);
		job_cfg = &cnf10k_priv->tx_ptp_job_cfg;
		otx2_rfoe_dbg_dump_jdt_ring(filp, job_cfg, cnf10k_priv);
	}

	seq_puts(filp, "============== OTH/ECPRI JD Ring =================\n");
	if (is_otx2) {
		job_cfg = &otx2_priv->rfoe_common->tx_oth_job_cfg;
		otx2_rfoe_dbg_dump_jdt_ring(filp, job_cfg, otx2_priv);
	} else {
		job_cfg = &cnf10k_priv->rfoe_common->tx_oth_job_cfg;
		otx2_rfoe_dbg_dump_jdt_ring(filp, job_cfg, cnf10k_priv);
	}

	return 0;
}

static int otx2_rfoe_dbg_open_jdt_ring(struct inode *inode, struct file *file)
{
	return single_open(file, otx2_rfoe_dbg_read_jdt_ring, inode->i_private);
}

static const struct file_operations otx2_rfoe_dbg_jdt_ring_fops = {
	.owner = THIS_MODULE,
	.open =	otx2_rfoe_dbg_open_jdt_ring,
	.read = seq_read,
};

void otx2_debugfs_add_jdt_ring_file(void *priv)
{
	struct cnf10k_rfoe_drv_ctx *cnf10k_ctx;
	struct otx2_rfoe_drv_ctx *ctx;
	struct dentry *root;
	char entry[10];

	strcpy(entry, "jdt_ring");
	if (is_otx2) {
		ctx = (struct otx2_rfoe_drv_ctx *)priv;
		root = ctx->root;
		debugfs_create_file(entry, 0444, root, ctx, &otx2_rfoe_dbg_jdt_ring_fops);
	} else {
		cnf10k_ctx = (struct cnf10k_rfoe_drv_ctx *)priv;
		root = cnf10k_ctx->root;
		debugfs_create_file(entry, 0444, root, cnf10k_ctx, &otx2_rfoe_dbg_jdt_ring_fops);
	}
}

void *otx2_bphy_debugfs_add_dir(const char *name)
{
	struct dentry *root = NULL;

	if (!otx2_bphy_debugfs) {
		pr_info("%s: debugfs not enabled, ignoring %s\n", DRV_NAME,
			name);
		goto out;
	}

	root = debugfs_create_dir(name, otx2_bphy_debugfs);
	if (!root)
		pr_info("%s: debugfs dir is not created %s\n", DRV_NAME, name);

out:
	return root;
}

void *otx2_bphy_debugfs_add_file(const char *name,
				 size_t buffer_size,
				 void *priv,
				 otx2_bphy_debugfs_reader reader)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;
	struct cnf10k_rfoe_drv_ctx *cnf10k_ctx;
	struct otx2_rfoe_drv_ctx *ctx;
	size_t total_size = 0;
	struct dentry *root;
	bool is_cpri;

	is_cpri = (strncmp(name, "cpri", 4) ? false : true);

	if (is_otx2) {
		ctx = (struct otx2_rfoe_drv_ctx *)priv;
		root = ctx->root;
	} else {
		cnf10k_ctx = (struct cnf10k_rfoe_drv_ctx *)priv;
		root = cnf10k_ctx->root;
	}

	if (!root && !is_cpri) {
		pr_info("%s: debugfs not enabled, ignoring %s\n", DRV_NAME,
			name);
		goto out;
	}

	total_size = buffer_size +
		offsetof(struct otx2_bphy_debugfs_reader_info,
			 buffer);

	info = kzalloc(total_size, GFP_KERNEL);

	if (!info)
		goto out;

	info->buffer_size = buffer_size;
	info->priv = priv;
	info->reader = reader;

	atomic_set(&info->refcnt, 0);

	if (is_cpri)
		info->entry = debugfs_create_file(name, OTX2_BPHY_DEBUGFS_MODE,
						  otx2_bphy_debugfs, info,
						  &otx2_bphy_debugfs_foper);
	else
		info->entry = debugfs_create_file(name, OTX2_BPHY_DEBUGFS_MODE,
						  root, info,
						  &otx2_bphy_debugfs_foper);

	if (!info->entry) {
		pr_err("%s: debugfs failed to add file %s\n", DRV_NAME, name);
		kfree(info);
		info = NULL;
		goto out;
	}

	pr_info("%s: debugfs created successfully for %s\n", DRV_NAME, name);

out:
	return info;
}

void otx2_bphy_debugfs_remove_file(void *entry)
{
	struct otx2_bphy_debugfs_reader_info *info = entry;

	debugfs_remove(info->entry);

	kfree(info);
}

void __exit otx2_bphy_debugfs_exit(void)
{
	debugfs_remove_recursive(otx2_bphy_debugfs);
}

static int otx2_bphy_debugfs_open(struct inode *inode, struct file *file)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;

	info = inode->i_private;

	if (!atomic_cmpxchg(&info->refcnt, 0, 1)) {
		file->private_data = info;
		return 0;
	}

	return -EBUSY;
}

static int otx2_bphy_debugfs_release(struct inode *inode, struct file *file)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;

	info = inode->i_private;

	atomic_cmpxchg(&info->refcnt, 1, 0);

	return 0;
}

static ssize_t otx2_bphy_debugfs_read(struct file *file, char __user *buffer,
				      size_t count, loff_t *offset)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;
	ssize_t retval = 0;

	info = file->private_data;

	if (!(*offset))
		info->reader(&info->buffer[0], info->buffer_size, info->priv);

	if (*offset >= info->buffer_size)
		goto out;

	if (*offset + count > info->buffer_size)
		count = info->buffer_size - *offset;

	if (copy_to_user((void __user *)buffer, info->buffer + *offset,
			 count)) {
		retval = -EFAULT;
		goto out;
	}

	*offset += count;
	retval = count;

out:
	return retval;
}
