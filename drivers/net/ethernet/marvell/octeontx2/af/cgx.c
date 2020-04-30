// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 CGX driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>

#include "cgx.h"
#include "rvu.h"

#define DRV_NAME	"octeontx2-cgx"
#define DRV_STRING      "Marvell OcteonTX2 CGX/MAC Driver"

#define CGX_RX_STAT_GLOBAL_INDEX	9

/**
 * struct lmac
 * @wq_cmd_cmplt:	waitq to keep the process blocked until cmd completion
 * @cmd_lock:		Lock to serialize the command interface
 * @resp:		command response
 * @link_info:		link related information
 * @mac_to_index_bmap:	Mac address to CGX table index mapping
 * @event_cb:		callback for linkchange events
 * @event_cb_lock:	lock for serializing callback with unregister
 * @cmd_pend:		flag set before new command is started
 *			flag cleared after command response is received
 * @cgx:		parent cgx port
 * @lmac_id:		lmac port id
 * @name:		lmac port name
 */
struct lmac {
	wait_queue_head_t wq_cmd_cmplt;
	struct mutex cmd_lock;
	u64 resp;
	struct cgx_link_user_info link_info;
	struct rsrc_bmap mac_to_index_bmap;
	struct cgx_event_cb event_cb;
	spinlock_t event_cb_lock;
	bool cmd_pend;
	struct cgx *cgx;
	u8 lmac_id;
	char *name;
};

struct cgx {
	void __iomem		*reg_base;
	struct pci_dev		*pdev;
	u8			cgx_id;
	u8			lmac_count;
	struct lmac		*lmac_idmap[MAX_LMAC_PER_CGX];
	struct			work_struct cgx_cmd_work;
	struct			workqueue_struct *cgx_cmd_workq;
	struct list_head	cgx_list;
};

static LIST_HEAD(cgx_list);

/* Convert firmware speed encoding to user format(Mbps) */
static u32 cgx_speed_mbps[CGX_LINK_SPEED_MAX];

/* Convert firmware lmac type encoding to string */
static char *cgx_lmactype_string[LMAC_MODE_MAX];

/* CGX PHY management internal APIs */
static int cgx_fwi_link_change(struct cgx *cgx, int lmac_id, bool en);

/* Supported devices */
static const struct pci_device_id cgx_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_CGX) },
	{ 0, }  /* end of table */
};

MODULE_DEVICE_TABLE(pci, cgx_id_table);

static void cgx_write(struct cgx *cgx, u64 lmac, u64 offset, u64 val)
{
	writeq(val, cgx->reg_base + (lmac << 18) + offset);
}

static u64 cgx_read(struct cgx *cgx, u64 lmac, u64 offset)
{
	return readq(cgx->reg_base + (lmac << 18) + offset);
}

static inline struct lmac *lmac_pdata(u8 lmac_id, struct cgx *cgx)
{
	if (!cgx || lmac_id >= MAX_LMAC_PER_CGX)
		return NULL;

	return cgx->lmac_idmap[lmac_id];
}

int cgx_get_cgxcnt_max(void)
{
	struct cgx *cgx_dev;
	int idmax = -ENODEV;

	list_for_each_entry(cgx_dev, &cgx_list, cgx_list)
		if (cgx_dev->cgx_id > idmax)
			idmax = cgx_dev->cgx_id;

	if (idmax < 0)
		return 0;

	return idmax + 1;
}
EXPORT_SYMBOL(cgx_get_cgxcnt_max);

int cgx_get_lmac_cnt(void *cgxd)
{
	struct cgx *cgx = cgxd;

	if (!cgx)
		return -ENODEV;

	return cgx->lmac_count;
}
EXPORT_SYMBOL(cgx_get_lmac_cnt);

void *cgx_get_pdata(int cgx_id)
{
	struct cgx *cgx_dev;

	list_for_each_entry(cgx_dev, &cgx_list, cgx_list) {
		if (cgx_dev->cgx_id == cgx_id)
			return cgx_dev;
	}
	return NULL;
}
EXPORT_SYMBOL(cgx_get_pdata);

int cgx_get_cgxid(void *cgxd)
{
	struct cgx *cgx = cgxd;

	if (!cgx)
		return -EINVAL;

	return cgx->cgx_id;
}

u8 cgx_lmac_get_p2x(int cgx_id, int lmac_id)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	u64 cfg;

	cfg = cgx_read(cgx_dev, lmac_id, CGXX_CMRX_CFG);

	return (cfg & CMR_P2X_SEL_MASK) >> CMR_P2X_SEL_SHIFT;
}

/* Ensure the required lock for event queue(where asynchronous events are
 * posted) is acquired before calling this API. Else an asynchronous event(with
 * latest link status) can reach the destination before this function returns
 * and could make the link status appear wrong.
 */
int cgx_get_link_info(void *cgxd, int lmac_id,
		      struct cgx_link_user_info *linfo)
{
	struct lmac *lmac = lmac_pdata(lmac_id, cgxd);

	if (!lmac)
		return -ENODEV;

	*linfo = lmac->link_info;
	return 0;
}
EXPORT_SYMBOL(cgx_get_link_info);

static u64 mac2u64 (u8 *mac_addr)
{
	u64 mac = 0;
	int index;

	for (index = ETH_ALEN - 1; index >= 0; index--)
		mac |= ((u64)*mac_addr++) << (8 * index);
	return mac;
}

int cgx_lmac_addr_set(u8 cgx_id, u8 lmac_id, u8 *mac_addr)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx_dev);
	int index;
	u64 cfg;

	/* copy 6bytes from macaddr */
	/* memcpy(&cfg, mac_addr, 6); */

	/* Calculate real index of CGX DMAC table */
	index = lmac_id * lmac->mac_to_index_bmap.max;

	cfg = mac2u64 (mac_addr);

	cgx_write(cgx_dev, 0, (CGXX_CMRX_RX_DMAC_CAM0 + (index * 0x8)),
		  cfg | CGX_DMAC_CAM_ADDR_ENABLE | ((u64)lmac_id << 49));

	cfg = cgx_read(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
	cfg |= (CGX_DMAC_CTL0_CAM_ENABLE | CGX_DMAC_BCAST_MODE |
		CGX_DMAC_MCAST_MODE);
	cgx_write(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_addr_set);

int cgx_lmac_addr_add(u8 cgx_id, u8 lmac_id, u8 *mac_addr)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx_dev);
	int index, idx;
	u64 cfg = 0;

	/* Get available index where entry is to be installed */
	idx = rvu_alloc_rsrc(&lmac->mac_to_index_bmap);
	if (idx < 0)
		return idx;

	/* Calculate real index of CGX DMAC table */
	index = lmac_id * lmac->mac_to_index_bmap.max + idx;

	cfg = mac2u64 (mac_addr);
	cfg |= CGX_DMAC_CAM_ADDR_ENABLE;
	cfg |= ((u64)lmac_id << 49);
	cgx_write(cgx_dev, 0, (CGXX_CMRX_RX_DMAC_CAM0 + (index * 0x8)), cfg);

	cfg = cgx_read(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
	cfg |= (CGX_DMAC_BCAST_MODE | CGX_DMAC_MCAST_MODE |
		CGX_DMAC_CAM_ACCEPT);
	cgx_write(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);

	return idx;
}
EXPORT_SYMBOL(cgx_lmac_addr_add);

int cgx_lmac_addr_reset(u8 cgx_id, u8 lmac_id)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx_dev);
	u8 index = 0;
	u64 cfg;

	/* Restore index 0 to its default init value as done during
	 * cgx_lmac_init
	 */
	set_bit(0, lmac->mac_to_index_bmap.bmap);

	index = lmac_id * lmac->mac_to_index_bmap.max + index;
	cgx_write(cgx_dev, 0, (CGXX_CMRX_RX_DMAC_CAM0 + (index * 0x8)), 0);

	/* Reset CGXX_CMRX_RX_DMAC_CTL0 register to default state */
	cfg = cgx_read(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
	cfg &= ~CGX_DMAC_CAM_ACCEPT;
	cfg |= (CGX_DMAC_BCAST_MODE | CGX_DMAC_MCAST_MODE);
	cgx_write(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_addr_reset);

int cgx_lmac_addr_del(u8 cgx_id, u8 lmac_id, u8 index)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx_dev);

	/* Validate the index */
	if (index >= lmac->mac_to_index_bmap.max)
		return -EINVAL;

	/* Skip deletion for reserved index i.e. index 0 */
	if (index == 0)
		return 0;

	rvu_free_rsrc(&lmac->mac_to_index_bmap, index);

	index = lmac_id * lmac->mac_to_index_bmap.max + index;
	cgx_write(cgx_dev, 0, (CGXX_CMRX_RX_DMAC_CAM0 + (index * 0x8)), 0);

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_addr_del);

int cgx_lmac_addr_max_entries_get(u8 cgx_id, u8 lmac_id)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx_dev);

	if (lmac)
		return lmac->mac_to_index_bmap.max;

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_addr_max_entries_get);

u64 cgx_lmac_addr_get(u8 cgx_id, u8 lmac_id)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx_dev);
	int index;
	u64 cfg;

	/* Calculate real index of CGX DMAC table */
	index = lmac_id * lmac->mac_to_index_bmap.max;
	cfg = cgx_read(cgx_dev, 0, CGXX_CMRX_RX_DMAC_CAM0 + index * 0x8);
	return cfg & CGX_RX_DMAC_ADR_MASK;
}
EXPORT_SYMBOL(cgx_lmac_addr_get);

int cgx_set_pkind(void *cgxd, u8 lmac_id, int pkind)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	cgx_write(cgx, lmac_id, CGXX_CMRX_RX_ID_MAP, (pkind & 0x3F));
	return 0;
}
EXPORT_SYMBOL(cgx_set_pkind);

int cgx_get_pkind(void *cgxd, u8 lmac_id, int *pkind)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	*pkind = cgx_read(cgx, lmac_id, CGXX_CMRX_RX_ID_MAP);
	*pkind = *pkind & 0x3F;
	return 0;
}

static inline u8 cgx_get_lmac_type(struct cgx *cgx, int lmac_id)
{
	u64 cfg;

	cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_CFG);
	return (cfg >> CGX_LMAC_TYPE_SHIFT) & CGX_LMAC_TYPE_MASK;
}

/* Configure CGX LMAC in internal loopback mode */
int cgx_lmac_internal_loopback(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u8 lmac_type;
	u64 cfg;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	lmac_type = cgx_get_lmac_type(cgx, lmac_id);
	if (lmac_type == LMAC_MODE_SGMII || lmac_type == LMAC_MODE_QSGMII) {
		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_PCS_MRX_CTL);
		if (enable)
			cfg |= CGXX_GMP_PCS_MRX_CTL_LBK;
		else
			cfg &= ~CGXX_GMP_PCS_MRX_CTL_LBK;
		cgx_write(cgx, lmac_id, CGXX_GMP_PCS_MRX_CTL, cfg);
	} else {
		cfg = cgx_read(cgx, lmac_id, CGXX_SPUX_CONTROL1);
		if (enable)
			cfg |= CGXX_SPUX_CONTROL1_LBK;
		else
			cfg &= ~CGXX_SPUX_CONTROL1_LBK;
		cgx_write(cgx, lmac_id, CGXX_SPUX_CONTROL1, cfg);
	}
	return 0;
}
EXPORT_SYMBOL(cgx_lmac_internal_loopback);

void cgx_lmac_promisc_config(int cgx_id, int lmac_id, bool enable)
{
	struct cgx *cgx = cgx_get_pdata(cgx_id);
	struct lmac *lmac = lmac_pdata(lmac_id, cgx);
	u16 max_dmac = lmac->mac_to_index_bmap.max;
	int index, i;
	u64 cfg = 0;

	if (!cgx)
		return;

	if (enable) {
		/* Enable promiscuous mode on LMAC */
		cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
		cfg &= ~CGX_DMAC_CAM_ACCEPT;
		cfg |= (CGX_DMAC_BCAST_MODE | CGX_DMAC_MCAST_MODE);
		cgx_write(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);

		for (i = 0; i < max_dmac; i++) {
			index = lmac_id * max_dmac + i;
			cfg = cgx_read(cgx, 0,
				       (CGXX_CMRX_RX_DMAC_CAM0 + index * 0x8));
			cfg &= ~CGX_DMAC_CAM_ADDR_ENABLE;
			cgx_write(cgx, 0,
				  (CGXX_CMRX_RX_DMAC_CAM0 + index * 0x8), cfg);
		}
	} else {
		/* Disable promiscuous mode */
		cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
		cfg |= CGX_DMAC_CAM_ACCEPT | CGX_DMAC_MCAST_MODE;
		cgx_write(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);
		for (i = 0; i < max_dmac; i++) {
			index = lmac_id * max_dmac + i;
			cfg = cgx_read(cgx, 0,
				       (CGXX_CMRX_RX_DMAC_CAM0 + index * 0x8));
			if ((cfg & CGX_RX_DMAC_ADR_MASK) != 0) {
				cfg |= CGX_DMAC_CAM_ADDR_ENABLE;
				cgx_write(cgx, 0,
					  (CGXX_CMRX_RX_DMAC_CAM0 + index * 0x8),
					  cfg);
			}
		}
	}
}
EXPORT_SYMBOL(cgx_lmac_promisc_config);

/* Enable or disable forwarding received pause frames to Tx block */
void cgx_lmac_enadis_rx_pause_fwding(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	if (!cgx)
		return;

	if (enable) {
		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL);
		cfg |= CGX_GMP_GMI_RXX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
		cfg |= CGX_SMUX_RX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id,	CGXX_SMUX_RX_FRM_CTL, cfg);
	} else {
		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL);
		cfg &= ~CGX_GMP_GMI_RXX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
		cfg &= ~CGX_SMUX_RX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id,	CGXX_SMUX_RX_FRM_CTL, cfg);
	}
}
EXPORT_SYMBOL(cgx_lmac_enadis_rx_pause_fwding);

void cgx_lmac_ptp_config(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	if (!cgx)
		return;

	if (enable) {
		/* Enable inbound PTP timestamping */
		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL);
		cfg |= CGX_GMP_GMI_RXX_FRM_CTL_PTP_MODE;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
		cfg |= CGX_SMUX_RX_FRM_CTL_PTP_MODE;
		cgx_write(cgx, lmac_id,	CGXX_SMUX_RX_FRM_CTL, cfg);
	} else {
		/* Disable inbound PTP stamping */
		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL);
		cfg &= ~CGX_GMP_GMI_RXX_FRM_CTL_PTP_MODE;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
		cfg &= ~CGX_SMUX_RX_FRM_CTL_PTP_MODE;
		cgx_write(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL, cfg);
	}
}
EXPORT_SYMBOL(cgx_lmac_ptp_config);

int cgx_get_rx_stats(void *cgxd, int lmac_id, int idx, u64 *rx_stat)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	/* pass lmac as 0 for CGX_CMR_RX_STAT9-12 */
	if (idx >= CGX_RX_STAT_GLOBAL_INDEX)
		lmac_id = 0;

	*rx_stat =  cgx_read(cgx, lmac_id, CGXX_CMRX_RX_STAT0 + (idx * 8));
	return 0;
}
EXPORT_SYMBOL(cgx_get_rx_stats);

int cgx_get_tx_stats(void *cgxd, int lmac_id, int idx, u64 *tx_stat)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;
	*tx_stat = cgx_read(cgx, lmac_id, CGXX_CMRX_TX_STAT0 + (idx * 8));
	return 0;
}
EXPORT_SYMBOL(cgx_get_tx_stats);

int cgx_stats_rst(void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;
	int stat_id;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	for (stat_id = 0 ; stat_id < CGX_RX_STATS_COUNT; stat_id++) {
		if (stat_id >= CGX_RX_STAT_GLOBAL_INDEX)
		/* pass lmac as 0 for CGX_CMR_RX_STAT9-12 */
			cgx_write(cgx, 0,
				  (CGXX_CMRX_RX_STAT0 + (stat_id * 8)), 0);
		else
			cgx_write(cgx, lmac_id,
				  (CGXX_CMRX_RX_STAT0 + (stat_id * 8)), 0);
	}

	for (stat_id = 0 ; stat_id < CGX_TX_STATS_COUNT; stat_id++)
		cgx_write(cgx, lmac_id, CGXX_CMRX_TX_STAT0 + (stat_id * 8), 0);

	return 0;
}

static int cgx_set_fec_stats_count(struct cgx_link_user_info *linfo)
{
	if (linfo->fec) {
		switch (linfo->lmac_type_id) {
		case LMAC_MODE_SGMII:
		case LMAC_MODE_XAUI:
		case LMAC_MODE_RXAUI:
		case LMAC_MODE_QSGMII:
			return 0;
		case LMAC_MODE_10G_R:
		case LMAC_MODE_25G_R:
		case LMAC_MODE_100G_R:
		case LMAC_MODE_USXGMII:
			return 1;
		case LMAC_MODE_40G_R:
			return 4;
		case LMAC_MODE_50G_R:
			if (linfo->fec == OTX2_FEC_BASER)
				return 2;
			else
				return 1;
		}
	}
	return 0;
}

int cgx_get_fec_stats(void *cgxd, int lmac_id, struct cgx_fec_stats_rsp *rsp)
{
	int stats, fec_stats_count = 0;
	int corr_reg, uncorr_reg;
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;
	fec_stats_count =
		cgx_set_fec_stats_count(&cgx->lmac_idmap[lmac_id]->link_info);
	if (cgx->lmac_idmap[lmac_id]->link_info.fec == OTX2_FEC_BASER) {
		corr_reg = CGXX_SPUX_LNX_FEC_CORR_BLOCKS;
		uncorr_reg = CGXX_SPUX_LNX_FEC_UNCORR_BLOCKS;
	} else {
		corr_reg = CGXX_SPUX_RSFEC_CORR;
		uncorr_reg = CGXX_SPUX_RSFEC_UNCORR;
	}
	for (stats = 0; stats < fec_stats_count; stats++) {
		rsp->fec_corr_blks +=
			cgx_read(cgx, lmac_id, corr_reg + (stats * 8));
		rsp->fec_uncorr_blks +=
			cgx_read(cgx, lmac_id, uncorr_reg + (stats * 8));
	}
	return 0;
}

u64 cgx_get_lmac_tx_fifo_status(void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return 0;
	return cgx_read(cgx, lmac_id, CGXX_CMRX_TX_FIFO_LEN);
}
EXPORT_SYMBOL(cgx_get_lmac_tx_fifo_status);

int cgx_lmac_rx_tx_enable(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_CFG);
	if (enable)
		cfg |= DATA_PKT_RX_EN | DATA_PKT_TX_EN;
	else
		cfg &= ~(DATA_PKT_RX_EN | DATA_PKT_TX_EN);
	cgx_write(cgx, lmac_id, CGXX_CMRX_CFG, cfg);
	return 0;
}
EXPORT_SYMBOL(cgx_lmac_rx_tx_enable);

int cgx_lmac_tx_enable(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u64 cfg, last;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_CFG);
	last = cfg;
	if (enable)
		cfg |= DATA_PKT_TX_EN;
	else
		cfg &= ~DATA_PKT_TX_EN;

	if (cfg != last)
		cgx_write(cgx, lmac_id, CGXX_CMRX_CFG, cfg);
	return !!(last & DATA_PKT_TX_EN);
}
EXPORT_SYMBOL(cgx_lmac_tx_enable);

static int  cgx_lmac_get_higig2_pause_frm_status(void *cgxd, int lmac_id,
						 u8 *tx_pause, u8 *rx_pause)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL);

	*rx_pause = !!(cfg & CGXX_SMUX_HG2_CONTROL_RX_ENABLE);
	*tx_pause = !!(cfg & CGXX_SMUX_HG2_CONTROL_TX_ENABLE);
	return 0;
}

int cgx_lmac_get_pause_frm_status(void *cgxd, int lmac_id,
				  u8 *tx_pause, u8 *rx_pause)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	if (is_higig2_enabled(cgxd, lmac_id))
		return cgx_lmac_get_higig2_pause_frm_status(cgxd, lmac_id,
							    tx_pause, rx_pause);

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
	*rx_pause = !!(cfg & CGX_SMUX_RX_FRM_CTL_CTL_BCK);

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_CTL);
	*tx_pause = !!(cfg & CGX_SMUX_TX_CTL_L2P_BP_CONV);
	return 0;
}
EXPORT_SYMBOL(cgx_lmac_get_pause_frm_status);

static int cgx_lmac_enadis_higig2_pause_frm(void *cgxd, int lmac_id,
					    u8 tx_pause, u8 rx_pause)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL);
	cfg &= ~CGXX_SMUX_HG2_CONTROL_RX_ENABLE;
	cfg |= rx_pause ? CGXX_SMUX_HG2_CONTROL_RX_ENABLE : 0x0;
	cgx_write(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL, cfg);

	/* Forward PAUSE information to TX block */
	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
	cfg &= ~CGX_SMUX_RX_FRM_CTL_CTL_BCK;
	cfg |= rx_pause ? CGX_SMUX_RX_FRM_CTL_CTL_BCK : 0x0;
	cgx_write(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL, cfg);

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL);
	cfg &= ~CGXX_SMUX_HG2_CONTROL_TX_ENABLE;
	cfg |= tx_pause ? CGXX_SMUX_HG2_CONTROL_TX_ENABLE : 0x0;
	cgx_write(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL, cfg);

	/* allow intra packet hg2 generation */
	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_INTERVAL);
	cfg &= ~CGXX_SMUX_TX_PAUSE_PKT_HG2_INTRA_EN;
	cfg |= tx_pause ? CGXX_SMUX_TX_PAUSE_PKT_HG2_INTRA_EN : 0x0;
	cgx_write(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_INTERVAL, cfg);

	cfg = cgx_read(cgx, 0, CGXX_CMR_RX_OVR_BP);
	if (tx_pause) {
		cfg &= ~CGX_CMR_RX_OVR_BP_EN(lmac_id);
	} else {
		cfg |= CGX_CMR_RX_OVR_BP_EN(lmac_id);
		cfg &= ~CGX_CMR_RX_OVR_BP_BP(lmac_id);
	}
	cgx_write(cgx, 0, CGXX_CMR_RX_OVR_BP, cfg);

	return 0;
}

static int cgx_lmac_enadis_8023_pause_frm(void *cgxd, int lmac_id,
					  u8 tx_pause, u8 rx_pause)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
	cfg &= ~CGX_SMUX_RX_FRM_CTL_CTL_BCK;
	cfg |= rx_pause ? CGX_SMUX_RX_FRM_CTL_CTL_BCK : 0x0;
	cgx_write(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL, cfg);

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_CTL);
	cfg &= ~CGX_SMUX_TX_CTL_L2P_BP_CONV;
	cfg |= tx_pause ? CGX_SMUX_TX_CTL_L2P_BP_CONV : 0x0;
	cgx_write(cgx, lmac_id, CGXX_SMUX_TX_CTL, cfg);

	cfg = cgx_read(cgx, 0, CGXX_CMR_RX_OVR_BP);
	if (tx_pause) {
		cfg &= ~CGX_CMR_RX_OVR_BP_EN(lmac_id);
	} else {
		cfg |= CGX_CMR_RX_OVR_BP_EN(lmac_id);
		cfg &= ~CGX_CMR_RX_OVR_BP_BP(lmac_id);
	}
	cgx_write(cgx, 0, CGXX_CMR_RX_OVR_BP, cfg);

	return 0;
}

int cgx_lmac_enadis_pause_frm(void *cgxd, int lmac_id,
			      u8 tx_pause, u8 rx_pause)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	if (is_higig2_enabled(cgxd, lmac_id))
		return	cgx_lmac_enadis_higig2_pause_frm(cgxd, lmac_id,
						   tx_pause, rx_pause);
	else
		return  cgx_lmac_enadis_8023_pause_frm(cgxd, lmac_id,
						   tx_pause, rx_pause);
	return 0;
}
EXPORT_SYMBOL(cgx_lmac_enadis_pause_frm);

static void cgx_lmac_pause_frm_config(struct cgx *cgx, int lmac_id, bool enable)
{
	u64 cfg;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return;
	if (enable) {
		/* Enable receive pause frames */
		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
		cfg |=  CGX_SMUX_RX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL);
		cfg |=  CGX_GMP_GMI_RXX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL, cfg);

		/* Enable pause frames transmission */
		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_CTL);
		cfg |= CGX_SMUX_TX_CTL_L2P_BP_CONV;
		cgx_write(cgx, lmac_id, CGXX_SMUX_TX_CTL, cfg);

		/* Set pause time and interval*/
		cgx_write(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_TIME,
			  DEFAULT_PAUSE_TIME);
		/* Set pause interval as the hardware default is too short */
		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_INTERVAL);
		cfg &= ~0xFFFFULL;
		cgx_write(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_INTERVAL,
			  cfg | (DEFAULT_PAUSE_TIME / 2));

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_INTERVAL);
		cfg = FIELD_SET(HG2_INTRA_INTERVAL, (DEFAULT_PAUSE_TIME / 2),
				cfg);
		cgx_write(cgx, lmac_id, CGXX_SMUX_TX_PAUSE_PKT_INTERVAL,
			  cfg);

		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_TX_PAUSE_PKT_TIME,
			  DEFAULT_PAUSE_TIME);

		cfg = cgx_read(cgx, lmac_id,
			       CGXX_GMP_GMI_TX_PAUSE_PKT_INTERVAL);
		cfg &= ~0xFFFFULL;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_TX_PAUSE_PKT_INTERVAL,
			  cfg | (DEFAULT_PAUSE_TIME / 2));
	} else {
		/* ALL pause frames received are completely ignored */
		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL);
		cfg &= ~CGX_SMUX_RX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id, CGXX_SMUX_RX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL);
		cfg &= ~CGX_GMP_GMI_RXX_FRM_CTL_CTL_BCK;
		cgx_write(cgx, lmac_id, CGXX_GMP_GMI_RXX_FRM_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL);
		cfg &= ~CGXX_SMUX_HG2_CONTROL_RX_ENABLE;
		cgx_write(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL, cfg);

		/* Disable pause frames transmission */
		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_CTL);
		cfg &= ~CGX_SMUX_TX_CTL_L2P_BP_CONV;
		cgx_write(cgx, lmac_id, CGXX_SMUX_TX_CTL, cfg);

		cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL);
		cfg &= ~CGXX_SMUX_HG2_CONTROL_TX_ENABLE;
		cgx_write(cgx, lmac_id, CGXX_SMUX_HG2_CONTROL, cfg);
	}
}

/* CGX Firmware interface low level support */
static int cgx_fwi_cmd_send(u64 req, u64 *resp, struct lmac *lmac)
{
	struct cgx *cgx = lmac->cgx;
	struct device *dev;
	int err = 0;
	u64 cmd;

	/* Ensure no other command is in progress */
	err = mutex_lock_interruptible(&lmac->cmd_lock);
	if (err)
		return err;

	/* Ensure command register is free */
	cmd = cgx_read(cgx, lmac->lmac_id,  CGX_COMMAND_REG);
	if (FIELD_GET(CMDREG_OWN, cmd) != CGX_CMD_OWN_NS) {
		err = -EBUSY;
		goto unlock;
	}

	/* Update ownership in command request */
	req = FIELD_SET(CMDREG_OWN, CGX_CMD_OWN_FIRMWARE, req);

	/* Mark this lmac as pending, before we start */
	lmac->cmd_pend = true;

	/* Start command in hardware */
	cgx_write(cgx, lmac->lmac_id, CGX_COMMAND_REG, req);

	/* Ensure command is completed without errors */
	if (!wait_event_timeout(lmac->wq_cmd_cmplt, !lmac->cmd_pend,
				msecs_to_jiffies(CGX_CMD_TIMEOUT))) {
		dev = &cgx->pdev->dev;
		dev_err(dev, "cgx port %d:%d cmd timeout\n",
			cgx->cgx_id, lmac->lmac_id);
		err = -EIO;
		goto unlock;
	}

	/* we have a valid command response */
	smp_rmb(); /* Ensure the latest updates are visible */
	*resp = lmac->resp;

unlock:
	mutex_unlock(&lmac->cmd_lock);

	return err;
}

static inline int cgx_fwi_cmd_generic(u64 req, u64 *resp,
				      struct cgx *cgx, int lmac_id)
{
	struct lmac *lmac;
	int err;

	lmac = lmac_pdata(lmac_id, cgx);
	if (!lmac)
		return -ENODEV;

	err = cgx_fwi_cmd_send(req, resp, lmac);

	/* Check for valid response */
	if (!err) {
		if (FIELD_GET(EVTREG_STAT, *resp) == CGX_STAT_FAIL)
			return -EIO;
		else
			return 0;
	}

	return err;
}

static inline void cgx_link_usertable_init(void)
{
	cgx_speed_mbps[CGX_LINK_NONE] = 0;
	cgx_speed_mbps[CGX_LINK_10M] = 10;
	cgx_speed_mbps[CGX_LINK_100M] = 100;
	cgx_speed_mbps[CGX_LINK_1G] = 1000;
	cgx_speed_mbps[CGX_LINK_2HG] = 2500;
	cgx_speed_mbps[CGX_LINK_5G] = 5000;
	cgx_speed_mbps[CGX_LINK_10G] = 10000;
	cgx_speed_mbps[CGX_LINK_20G] = 20000;
	cgx_speed_mbps[CGX_LINK_25G] = 25000;
	cgx_speed_mbps[CGX_LINK_40G] = 40000;
	cgx_speed_mbps[CGX_LINK_50G] = 50000;
	cgx_speed_mbps[CGX_LINK_80G] = 80000;
	cgx_speed_mbps[CGX_LINK_100G] = 100000;

	cgx_lmactype_string[LMAC_MODE_SGMII] = "SGMII";
	cgx_lmactype_string[LMAC_MODE_XAUI] = "XAUI";
	cgx_lmactype_string[LMAC_MODE_RXAUI] = "RXAUI";
	cgx_lmactype_string[LMAC_MODE_10G_R] = "10G_R";
	cgx_lmactype_string[LMAC_MODE_40G_R] = "40G_R";
	cgx_lmactype_string[LMAC_MODE_QSGMII] = "QSGMII";
	cgx_lmactype_string[LMAC_MODE_25G_R] = "25G_R";
	cgx_lmactype_string[LMAC_MODE_50G_R] = "50G_R";
	cgx_lmactype_string[LMAC_MODE_100G_R] = "100G_R";
	cgx_lmactype_string[LMAC_MODE_USXGMII] = "USXGMII";
}

static inline int cgx_link_usertable_index_map(int speed)
{
	switch (speed) {
	case SPEED_10:
		return CGX_LINK_10M;
	case SPEED_100:
		return CGX_LINK_100M;
	case SPEED_1000:
		return CGX_LINK_1G;
	case SPEED_2500:
		return CGX_LINK_2HG;
	case SPEED_5000:
		return CGX_LINK_5G;
	case SPEED_10000:
		return CGX_LINK_10G;
	case SPEED_20000:
		return CGX_LINK_20G;
	case SPEED_25000:
		return CGX_LINK_25G;
	case SPEED_40000:
		return CGX_LINK_40G;
	case SPEED_50000:
		return CGX_LINK_50G;
	case 80000:
		return CGX_LINK_80G;
	case SPEED_100000:
		return CGX_LINK_100G;
	case SPEED_UNKNOWN:
		return CGX_LINK_NONE;
	}
	return CGX_LINK_NONE;
}

static void set_mod_args(struct cgx_set_link_mode_args *args,
			 u32 speed, u8 duplex, u8 autoneg, u64 mode)
{
	/* firmware requires this value in the reverse format */
	args->duplex = duplex;
	args->speed = speed;
	args->mode = mode;
	args->an = autoneg;
	args->ports = 0;
}

static void otx2_map_ethtool_link_modes(u64 bitmask,
					struct cgx_set_link_mode_args *args)
{
	switch (bitmask) {
	case BIT_ULL(ETHTOOL_LINK_MODE_10baseT_Half_BIT):
		set_mod_args(args, 10, 1, 1, BIT_ULL(CGX_MODE_SGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10baseT_Full_BIT):
		set_mod_args(args, 10, 0, 1, BIT_ULL(CGX_MODE_SGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_100baseT_Half_BIT):
		set_mod_args(args, 100, 1, 1, BIT_ULL(CGX_MODE_SGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_100baseT_Full_BIT):
		set_mod_args(args, 100, 0, 1, BIT_ULL(CGX_MODE_SGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_1000baseT_Half_BIT):
		set_mod_args(args, 1000, 1, 1, BIT_ULL(CGX_MODE_SGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_1000baseT_Full_BIT):
		set_mod_args(args, 1000, 0, 1, BIT_ULL(CGX_MODE_SGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_1000baseX_Full_BIT):
		set_mod_args(args, 1000, 0, 0, BIT_ULL(CGX_MODE_1000_BASEX));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseT_Full_BIT):
		set_mod_args(args, 1000, 0, 1, BIT_ULL(CGX_MODE_QSGMII));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT):
		set_mod_args(args, 10000, 0, 0, BIT_ULL(CGX_MODE_10G_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseR_FEC_BIT):
		set_mod_args(args, 10000, 0, 0, BIT_ULL(CGX_MODE_10G_C2M));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT):
		set_mod_args(args, 10000, 0, 1, BIT_ULL(CGX_MODE_10G_KR));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT):
		set_mod_args(args, 20000, 0, 0, BIT_ULL(CGX_MODE_20G_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseCR_Full_BIT):
		set_mod_args(args, 25000, 0, 0, BIT_ULL(CGX_MODE_25G_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_25000baseSR_Full_BIT):
		set_mod_args(args, 25000, 0, 0, BIT_ULL(CGX_MODE_25G_C2M));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT):
		set_mod_args(args, 25000, 0, 0, BIT_ULL(CGX_MODE_25G_2_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT):
		set_mod_args(args, 25000, 0, 1, BIT_ULL(CGX_MODE_25G_CR));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_25000baseKR_Full_BIT):
		set_mod_args(args, 25000, 0, 1, BIT_ULL(CGX_MODE_25G_KR));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT):
		set_mod_args(args, 40000, 0, 0, BIT_ULL(CGX_MODE_40G_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT):
		set_mod_args(args, 40000, 0, 0, BIT_ULL(CGX_MODE_40G_C2M));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT):
		set_mod_args(args, 40000, 0, 1, BIT_ULL(CGX_MODE_40G_CR4));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT):
		set_mod_args(args, 40000, 0, 1, BIT_ULL(CGX_MODE_40G_KR4));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseSR_Full_BIT):
		set_mod_args(args, 40000, 0, 0, BIT_ULL(CGX_MODE_40GAUI_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT):
		set_mod_args(args, 50000, 0, 0, BIT_ULL(CGX_MODE_50G_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT):
		set_mod_args(args, 50000, 0, 0, BIT_ULL(CGX_MODE_50G_4_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseLR_Full_BIT):
		set_mod_args(args, 50000, 0, 0, BIT_ULL(CGX_MODE_50G_C2M));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT):
		set_mod_args(args, 50000, 0, 1, BIT_ULL(CGX_MODE_50G_CR));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT):
		set_mod_args(args, 50000, 0, 1, BIT_ULL(CGX_MODE_50G_KR));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT):
		set_mod_args(args, 80000, 0, 0, BIT_ULL(CGX_MODE_80GAUI_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT):
		set_mod_args(args, 100000, 0, 0, BIT_ULL(CGX_MODE_100G_C2C));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT):
		set_mod_args(args, 100000, 0, 0, BIT_ULL(CGX_MODE_100G_C2M));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT):
		set_mod_args(args, 100000, 0, 1, BIT_ULL(CGX_MODE_100G_CR4));
		break;
	case  BIT_ULL(ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT):
		set_mod_args(args, 100000, 0, 1, BIT_ULL(CGX_MODE_100G_KR4));
		break;
	default:
		set_mod_args(args, 0, 1, 0, BIT_ULL(CGX_MODE_MAX));
		break;
	}
}
static inline void link_status_user_format(u64 lstat,
					   struct cgx_link_user_info *linfo,
					   struct cgx *cgx, u8 lmac_id)
{
	char *lmac_string;

	linfo->link_up = FIELD_GET(RESP_LINKSTAT_UP, lstat);
	linfo->full_duplex = FIELD_GET(RESP_LINKSTAT_FDUPLEX, lstat);
	linfo->speed = cgx_speed_mbps[FIELD_GET(RESP_LINKSTAT_SPEED, lstat)];
	linfo->an = FIELD_GET(RESP_LINKSTAT_AN, lstat);
	linfo->fec = FIELD_GET(RESP_LINKSTAT_FEC, lstat);
	linfo->port = FIELD_GET(RESP_LINKSTAT_PORT, lstat);
	linfo->lmac_type_id = cgx_get_lmac_type(cgx, lmac_id);
	lmac_string = cgx_lmactype_string[linfo->lmac_type_id];
	strncpy(linfo->lmac_type, lmac_string, LMACTYPE_STR_LEN - 1);
}

/* Hardware event handlers */
static inline void cgx_link_change_handler(u64 lstat,
					   struct lmac *lmac)
{
	struct cgx_link_user_info *linfo;
	struct cgx *cgx = lmac->cgx;
	struct cgx_link_event event;
	struct device *dev;
	int err_type;

	dev = &cgx->pdev->dev;

	link_status_user_format(lstat, &event.link_uinfo, cgx, lmac->lmac_id);
	err_type = FIELD_GET(RESP_LINKSTAT_ERRTYPE, lstat);

	event.cgx_id = cgx->cgx_id;
	event.lmac_id = lmac->lmac_id;

	/* update the local copy of link status */
	lmac->link_info = event.link_uinfo;
	linfo = &lmac->link_info;

	if (err_type == CGX_ERR_SPEED_CHANGE_INVALID)
		return;
	/* Ensure callback doesn't get unregistered until we finish it */
	spin_lock(&lmac->event_cb_lock);

	if (!lmac->event_cb.notify_link_chg) {
		dev_dbg(dev, "cgx port %d:%d Link change handler null",
			cgx->cgx_id, lmac->lmac_id);
		if (err_type != CGX_ERR_NONE) {
			dev_err(dev, "cgx port %d:%d Link error %d\n",
				cgx->cgx_id, lmac->lmac_id, err_type);
		}
		dev_info(dev, "cgx port %d:%d Link is %s %d Mbps\n",
			 cgx->cgx_id, lmac->lmac_id,
			 linfo->link_up ? "UP" : "DOWN", linfo->speed);
		goto err;
	}

	if (lmac->event_cb.notify_link_chg(&event, lmac->event_cb.data))
		dev_err(dev, "event notification failure\n");
err:
	spin_unlock(&lmac->event_cb_lock);
}

static inline bool cgx_cmdresp_is_linkevent(u64 event)
{
	u8 id;

	id = FIELD_GET(EVTREG_ID, event);
	if (id == CGX_CMD_LINK_BRING_UP ||
	    id == CGX_CMD_LINK_BRING_DOWN ||
	    id == CGX_CMD_MODE_CHANGE)
		return true;
	else
		return false;
}

static inline bool cgx_event_is_linkevent(u64 event)
{
	if (FIELD_GET(EVTREG_ID, event) == CGX_EVT_LINK_CHANGE)
		return true;
	else
		return false;
}

static irqreturn_t cgx_fwi_event_handler(int irq, void *data)
{
	struct lmac *lmac = data;
	struct cgx *cgx;
	u64 event;

	cgx = lmac->cgx;

	event = cgx_read(cgx, lmac->lmac_id, CGX_EVENT_REG);

	if (!FIELD_GET(EVTREG_ACK, event))
		return IRQ_NONE;

	switch (FIELD_GET(EVTREG_EVT_TYPE, event)) {
	case CGX_EVT_CMD_RESP:
		/* Copy the response. Since only one command is active at a
		 * time, there is no way a response can get overwritten
		 */
		lmac->resp = event;
		/* Ensure response is updated before thread context starts */
		smp_wmb();

		/* There wont be separate events for link change initiated from
		 * software; Hence report the command responses as events
		 */
		if (cgx_cmdresp_is_linkevent(event))
			cgx_link_change_handler(event, lmac);

		/* Release thread waiting for completion  */
		lmac->cmd_pend = false;
		wake_up(&lmac->wq_cmd_cmplt);
		break;
	case CGX_EVT_ASYNC:
		if (cgx_event_is_linkevent(event))
			cgx_link_change_handler(event, lmac);
		break;
	}

	/* Any new event or command response will be posted by firmware
	 * only after the current status is acked.
	 * Ack the interrupt register as well.
	 */
	cgx_write(lmac->cgx, lmac->lmac_id, CGX_EVENT_REG, 0);
	cgx_write(lmac->cgx, lmac->lmac_id, CGXX_CMRX_INT, FW_CGX_INT);

	return IRQ_HANDLED;
}

/* APIs for PHY management using CGX firmware interface */

/* callback registration for hardware events like link change */
int cgx_lmac_evh_register(struct cgx_event_cb *cb, void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;
	struct lmac *lmac;

	lmac = lmac_pdata(lmac_id, cgx);
	if (!lmac)
		return -ENODEV;

	lmac->event_cb = *cb;

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_evh_register);

int cgx_lmac_evh_unregister(void *cgxd, int lmac_id)
{
	struct lmac *lmac;
	unsigned long flags;
	struct cgx *cgx = cgxd;

	lmac = lmac_pdata(lmac_id, cgx);
	if (!lmac)
		return -ENODEV;

	spin_lock_irqsave(&lmac->event_cb_lock, flags);
	lmac->event_cb.notify_link_chg = NULL;
	lmac->event_cb.data = NULL;
	spin_unlock_irqrestore(&lmac->event_cb_lock, flags);

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_evh_unregister);

int cgx_get_fwdata_base(u64 *base)
{
	u64 req = 0, resp;
	struct cgx *cgx;
	int err;

	cgx = list_first_entry_or_null(&cgx_list, struct cgx, cgx_list);
	if (!cgx)
		return -ENXIO;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_GET_FWD_BASE, req);
	err = cgx_fwi_cmd_generic(req, &resp, cgx, 0);
	if (!err)
		*base = FIELD_GET(RESP_FWD_BASE, resp);

	return err;
}

int cgx_set_fec(u64 fec, int cgx_id, int lmac_id)
{
	u64 req = 0, resp;
	struct cgx *cgx;
	int err = 0;

	cgx = cgx_get_pdata(cgx_id);
	if (!cgx)
		return -ENXIO;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_SET_FEC, req);
	req = FIELD_SET(CMDSETFEC, fec, req);
	err = cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);
	if (!err) {
		cgx->lmac_idmap[lmac_id]->link_info.fec =
			FIELD_GET(RESP_LINKSTAT_FEC, resp);
		return cgx->lmac_idmap[lmac_id]->link_info.fec;
	}
	return err;
}

int cgx_set_phy_mod_type(int mod, void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;
	u64 req = 0, resp;

	if (!cgx)
		return -ENODEV;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_SET_PHY_MOD_TYPE, req);
	req = FIELD_SET(CMDSETPHYMODTYPE, mod, req);
	return cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);
}

int cgx_get_phy_mod_type(void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;
	u64 req = 0, resp;
	int err;

	if (!cgx)
		return -ENODEV;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_GET_PHY_MOD_TYPE, req);
	err = cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);
	if (!err)
		return FIELD_GET(RESP_GETPHYMODTYPE, resp);
	return err;
}

int cgx_get_phy_fec_stats(void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;
	u64 req = 0, resp;

	if (!cgx)
		return -ENODEV;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_GET_PHY_FEC_STATS, req);
	return cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);
}

int cgx_set_link_mode(void *cgxd, struct cgx_set_link_mode_args args,
		      int cgx_id, int lmac_id)
{
	struct cgx *cgx = cgxd;
	u64 req = 0, resp;
	int err = 0;

	if (!cgx)
		return -ENODEV;

	if (args.mode)
		otx2_map_ethtool_link_modes(args.mode, &args);
	if (!args.speed && args.duplex && !args.an)
		return -EINVAL;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_MODE_CHANGE, req);
	req = FIELD_SET(CMDMODECHANGE_SPEED,
			cgx_link_usertable_index_map(args.speed), req);
	req = FIELD_SET(CMDMODECHANGE_DUPLEX, args.duplex, req);
	req = FIELD_SET(CMDMODECHANGE_AN, args.an, req);
	req = FIELD_SET(CMDMODECHANGE_PORT, args.ports, req);
	req = FIELD_SET(CMDMODECHANGE_FLAGS, args.mode, req);
	err = cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);
	return err;
}

static int cgx_fwi_link_change(struct cgx *cgx, int lmac_id, bool enable)
{
	u64 req = 0;
	u64 resp;

	if (enable)
		req = FIELD_SET(CMDREG_ID, CGX_CMD_LINK_BRING_UP, req);
	else
		req = FIELD_SET(CMDREG_ID, CGX_CMD_LINK_BRING_DOWN, req);

	return cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);
}

static inline int cgx_fwi_read_version(u64 *resp, struct cgx *cgx)
{
	u64 req = 0;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_GET_FW_VER, req);
	return cgx_fwi_cmd_generic(req, resp, cgx, 0);
}

static int cgx_lmac_verify_fwi_version(struct cgx *cgx)
{
	struct device *dev = &cgx->pdev->dev;
	int major_ver, minor_ver;
	u64 resp;
	int err;

	if (!cgx->lmac_count)
		return 0;

	err = cgx_fwi_read_version(&resp, cgx);
	if (err)
		return err;

	major_ver = FIELD_GET(RESP_MAJOR_VER, resp);
	minor_ver = FIELD_GET(RESP_MINOR_VER, resp);
	dev_dbg(dev, "Firmware command interface version = %d.%d\n",
		major_ver, minor_ver);
	if (major_ver != CGX_FIRMWARE_MAJOR_VER)
		return -EIO;
	else
		return 0;
}

static void cgx_lmac_linkup_work(struct work_struct *work)
{
	struct cgx *cgx = container_of(work, struct cgx, cgx_cmd_work);
	struct device *dev = &cgx->pdev->dev;
	int i, err;

	/* Do Link up for all the lmacs */
	for (i = 0; i < cgx->lmac_count; i++) {
		err = cgx_fwi_link_change(cgx, i, true);
		if (err)
			dev_info(dev, "cgx port %d:%d Link up command failed\n",
				 cgx->cgx_id, i);
	}
}

int cgx_set_link_state(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;

	if (!cgx)
		return -ENODEV;

	return cgx_fwi_link_change(cgx, lmac_id, enable);
}
EXPORT_SYMBOL(cgx_set_link_state);

int cgx_lmac_linkup_start(void *cgxd)
{
	struct cgx *cgx = cgxd;

	if (!cgx)
		return -ENODEV;

	queue_work(cgx->cgx_cmd_workq, &cgx->cgx_cmd_work);

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_linkup_start);

void cgx_lmac_enadis_higig2(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u64 req = 0, resp;

	/* disable 802.3 pause frames before enabling higig2 */
	if (enable) {
		cgx_lmac_enadis_8023_pause_frm(cgxd, lmac_id, false, false);
		cgx_lmac_enadis_higig2_pause_frm(cgxd, lmac_id, true, true);
	}

	req = FIELD_SET(CMDREG_ID, CGX_CMD_HIGIG, req);
	req = FIELD_SET(CMDREG_ENABLE, enable, req);
	cgx_fwi_cmd_generic(req, &resp, cgx, lmac_id);

	/* enable 802.3 pause frames as higig2 disabled */
	if (!enable) {
		cgx_lmac_enadis_higig2_pause_frm(cgxd, lmac_id, false, false);
		cgx_lmac_enadis_8023_pause_frm(cgxd, lmac_id, true, true);
	}
}

bool is_higig2_enabled(void *cgxd, int lmac_id)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	cfg = cgx_read(cgx, lmac_id, CGXX_SMUX_TX_CTL);
	return (cfg & CGXX_SMUX_TX_CTL_HIGIG_EN);
}

static int cgx_lmac_init(struct cgx *cgx)
{
	struct lmac *lmac;
	int i, err;

	cgx->lmac_count = cgx_read(cgx, 0, CGXX_CMRX_RX_LMACS) & 0x7;
	if (cgx->lmac_count > MAX_LMAC_PER_CGX)
		cgx->lmac_count = MAX_LMAC_PER_CGX;

	for (i = 0; i < cgx->lmac_count; i++) {
		lmac = kcalloc(1, sizeof(struct lmac), GFP_KERNEL);
		if (!lmac)
			return -ENOMEM;
		lmac->name = kcalloc(1, sizeof("cgx_fwi_xxx_yyy"), GFP_KERNEL);
		if (!lmac->name)
			return -ENOMEM;
		sprintf(lmac->name, "cgx_fwi_%d_%d", cgx->cgx_id, i);
		lmac->lmac_id = i;
		lmac->cgx = cgx;
		lmac->mac_to_index_bmap.max =
				MAX_DMAC_ENTRIES_PER_CGX / cgx->lmac_count;
		err = rvu_alloc_bitmap(&lmac->mac_to_index_bmap);
		if (err)
			return err;

		/* Reserve first entry for default MAC address */
		set_bit(0, lmac->mac_to_index_bmap.bmap);

		init_waitqueue_head(&lmac->wq_cmd_cmplt);
		mutex_init(&lmac->cmd_lock);
		spin_lock_init(&lmac->event_cb_lock);
		err = request_irq(pci_irq_vector(cgx->pdev,
						 CGX_LMAC_FWI + i * 9),
				   cgx_fwi_event_handler, 0, lmac->name, lmac);
		if (err)
			return err;

		/* Enable interrupt */
		cgx_write(cgx, lmac->lmac_id, CGXX_CMRX_INT_ENA_W1S,
			  FW_CGX_INT);

		/* Add reference */
		cgx->lmac_idmap[i] = lmac;
		cgx_lmac_pause_frm_config(cgx, i, true);
	}

	return cgx_lmac_verify_fwi_version(cgx);
}

static int cgx_lmac_exit(struct cgx *cgx)
{
	struct lmac *lmac;
	int i;

	if (cgx->cgx_cmd_workq) {
		flush_workqueue(cgx->cgx_cmd_workq);
		destroy_workqueue(cgx->cgx_cmd_workq);
		cgx->cgx_cmd_workq = NULL;
	}

	/* Free all lmac related resources */
	for (i = 0; i < cgx->lmac_count; i++) {
		cgx_lmac_pause_frm_config(cgx, i, false);
		lmac = cgx->lmac_idmap[i];
		if (!lmac)
			continue;
		free_irq(pci_irq_vector(cgx->pdev, CGX_LMAC_FWI + i * 9), lmac);
		kfree(lmac->mac_to_index_bmap.bmap);
		kfree(lmac->name);
		kfree(lmac);
	}

	return 0;
}

static int cgx_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct cgx *cgx;
	int err, nvec;

	cgx = devm_kzalloc(dev, sizeof(*cgx), GFP_KERNEL);
	if (!cgx)
		return -ENOMEM;
	cgx->pdev = pdev;

	pci_set_drvdata(pdev, cgx);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	/* MAP configuration registers */
	cgx->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!cgx->reg_base) {
		dev_err(dev, "CGX: Cannot map CSR memory space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

	nvec = CGX_NVEC;
	err = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSIX);
	if (err < 0 || err != nvec) {
		dev_err(dev, "Request for %d msix vectors failed, err %d\n",
			nvec, err);
		goto err_release_regions;
	}

	cgx->cgx_id = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 24)
		& CGX_ID_MASK;

	 /* Skip probe if CGX is not mapped to NIX */
	if (!is_cgx_mapped_to_nix(pdev->subsystem_device, cgx->cgx_id)) {
		dev_notice(dev, "skip cgx%d probe\n", cgx->cgx_id);
		err = -ENOMEM;
		goto err_release_regions;
	}

	/* init wq for processing linkup requests */
	INIT_WORK(&cgx->cgx_cmd_work, cgx_lmac_linkup_work);
	cgx->cgx_cmd_workq = alloc_workqueue("cgx_cmd_workq", 0, 0);
	if (!cgx->cgx_cmd_workq) {
		dev_err(dev, "alloc workqueue failed for cgx cmd");
		err = -ENOMEM;
		goto err_release_regions;
	}

	list_add(&cgx->cgx_list, &cgx_list);

	cgx_link_usertable_init();

	err = cgx_lmac_init(cgx);
	if (err)
		goto err_release_lmac;

	return 0;

err_release_lmac:
	cgx_lmac_exit(cgx);
	list_del(&cgx->cgx_list);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void cgx_remove(struct pci_dev *pdev)
{
	struct cgx *cgx = pci_get_drvdata(pdev);

	if (cgx) {
		cgx_lmac_exit(cgx);
		list_del(&cgx->cgx_list);
	}

	pci_free_irq_vectors(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

struct pci_driver cgx_driver = {
	.name = DRV_NAME,
	.id_table = cgx_id_table,
	.probe = cgx_probe,
	.remove = cgx_remove,
};
