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
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>

#include "cgx.h"

#define DRV_NAME	"OcteonTX2 CGX driver"
#define DRV_VERSION	"1.0"

/**
 * struct lmac
 * @wq_cmd_cmplt:	waitq to keep the process blocked until cmd completion
 * @cmd_lock:		Lock to serialize the command interface
 * @resp:		command response
 * @link_info:		link related information
 * @event_cb:		callback for linkchange events
 * @cmd_pend:		flag set before new command is started
 *			flag cleared after command response is received
 * @cgx:		parent cgx port
 * @lmac_id:		lmac port id
 * @name:		lmac port name
 */
struct lmac {
	wait_queue_head_t wq_cmd_cmplt;
	struct mutex cmd_lock;
	struct cgx_evt_sts resp;
	struct cgx_link_user_info link_info;
	struct cgx_event_cb event_cb;
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

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 CGX/MAC Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
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

int cgx_get_cgx_cnt(void)
{
	struct cgx *cgx_dev;
	int count = 0;

	list_for_each_entry(cgx_dev, &cgx_list, cgx_list)
		count++;

	return count;
}
EXPORT_SYMBOL(cgx_get_cgx_cnt);

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
	u64 cfg;

	/* copy 6bytes from macaddr */
	/* memcpy(&cfg, mac_addr, 6); */

	cfg = mac2u64 (mac_addr);

	cgx_write(cgx_dev, 0, (CGXX_CMRX_RX_DMAC_CAM0 + (lmac_id * 0x8)),
		  cfg | CGX_DMAC_CAM_ADDR_ENABLE | ((u64)lmac_id << 49));

	cfg = cgx_read(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
	cfg |= CGX_DMAC_CTL0_CAM_ENABLE;
	cgx_write(cgx_dev, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_addr_set);

u64 cgx_lmac_addr_get(u8 cgx_id, u8 lmac_id)
{
	struct cgx *cgx_dev = cgx_get_pdata(cgx_id);
	u64 cfg;

	cfg = cgx_read(cgx_dev, 0, CGXX_CMRX_RX_DMAC_CAM0 + lmac_id * 0x8);
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
	u64 cfg;
	u8 lmac_type;

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
	u64 cfg = 0;

	if (!cgx)
		return;

	if (enable) {
		/* Enable promiscuous mode on LMAC */
		cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
		cfg &= ~(CGX_DMAC_CAM_ACCEPT | CGX_DMAC_MCAST_MODE);
		cfg |= CGX_DMAC_BCAST_MODE;
		cgx_write(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);

		cfg = cgx_read(cgx, 0,
			       (CGXX_CMRX_RX_DMAC_CAM0 + lmac_id * 0x8));
		cfg &= ~CGX_DMAC_CAM_ADDR_ENABLE;
		cgx_write(cgx, 0,
			  (CGXX_CMRX_RX_DMAC_CAM0 + lmac_id * 0x8), cfg);
	} else {
		/* Disable promiscuous mode */
		cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0);
		cfg |= CGX_DMAC_CAM_ACCEPT | CGX_DMAC_MCAST_MODE;
		cgx_write(cgx, lmac_id, CGXX_CMRX_RX_DMAC_CTL0, cfg);
		cfg = cgx_read(cgx, 0,
			       (CGXX_CMRX_RX_DMAC_CAM0 + lmac_id * 0x8));
		cfg |= CGX_DMAC_CAM_ADDR_ENABLE;
		cgx_write(cgx, 0,
			  (CGXX_CMRX_RX_DMAC_CAM0 + lmac_id * 0x8), cfg);
	}
}
EXPORT_SYMBOL(cgx_lmac_promisc_config);

int cgx_get_rx_stats(void *cgxd, int lmac_id, int idx, u64 *rx_stat)
{
	struct cgx *cgx = cgxd;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;
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

int cgx_lmac_rx_tx_enable(void *cgxd, int lmac_id, bool enable)
{
	struct cgx *cgx = cgxd;
	u64 cfg;

	if (!cgx || lmac_id >= cgx->lmac_count)
		return -ENODEV;

	cfg = cgx_read(cgx, lmac_id, CGXX_CMRX_CFG);
	if (enable)
		cfg |= CMR_EN | DATA_PKT_RX_EN | DATA_PKT_TX_EN;
	else
		cfg &= ~(CMR_EN | DATA_PKT_RX_EN | DATA_PKT_TX_EN);
	cgx_write(cgx, lmac_id, CGXX_CMRX_CFG, cfg);
	return 0;
}
EXPORT_SYMBOL(cgx_lmac_rx_tx_enable);

/* CGX Firmware interface low level support */
static int cgx_fwi_cmd_send(struct cgx_cmd *cmd, struct cgx_evt_sts *rsp,
			    struct lmac *lmac)
{
	struct cgx *cgx = lmac->cgx;
	union cgx_cmdreg creg;
	union cgx_evtreg ereg;
	struct device *dev;
	int err = 0;

	/* Ensure no other command is in progress */
	err = mutex_lock_interruptible(&lmac->cmd_lock);
	if (err)
		return err;

	/* Ensure command register is free */
	creg.val = cgx_read(cgx, lmac->lmac_id,  CGX_COMMAND_REG);
	if (creg.cmd.own != CGX_CMD_OWN_NS) {
		err = -EBUSY;
		goto unlock;
	}

	/* Update ownership in command request */
	cmd->own = CGX_CMD_OWN_FIRMWARE;

	/* Mark this lmac as pending, before we start */
	lmac->cmd_pend = true;

	/* Start command in hardware */
	creg.cmd = *cmd;
	cgx_write(cgx, lmac->lmac_id, CGX_COMMAND_REG, creg.val);
	creg.val = cgx_read(cgx, lmac->lmac_id,  CGX_COMMAND_REG);

	/* Ensure command is completed without errors */
	if (!wait_event_timeout(lmac->wq_cmd_cmplt, !lmac->cmd_pend,
				msecs_to_jiffies(CGX_CMD_TIMEOUT))) {
		dev = &cgx->pdev->dev;
		ereg.val = cgx_read(cgx, lmac->lmac_id,  CGX_EVENT_REG);
		if (ereg.val) {
			dev_err(dev, "cgx port %d:%d: No event for response\n",
				cgx->cgx_id, lmac->lmac_id);
			/* copy event */
			lmac->resp = ereg.evt_sts;
		} else {
			dev_err(dev, "cgx port %d:%d cmd timeout\n",
				cgx->cgx_id, lmac->lmac_id);
			err = -EIO;
			goto unlock;
		}
	}

	/* we have a valid command response */
	smp_rmb(); /* Ensure the latest updates are visible */
	*rsp = lmac->resp;

unlock:
	mutex_unlock(&lmac->cmd_lock);

	return err;
}

static inline int cgx_fwi_cmd_generic(struct cgx_cmd *req,
				      struct cgx_evt_sts *rsp,
				      struct cgx *cgx, int lmac_id)
{
	struct lmac *lmac;
	int err;

	lmac = lmac_pdata(lmac_id, cgx);
	if (!lmac)
		return -ENODEV;

	err = cgx_fwi_cmd_send(req, rsp, lmac);

	/* Check for valid response */
	if (!err) {
		if (rsp->stat == CGX_STAT_FAIL)
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

static inline void link_status_user_format(struct cgx_lnk_sts *lstat,
					   struct cgx_link_user_info *linfo,
					   struct cgx *cgx, u8 lmac_id)
{
	char *lmac_string;

	linfo->link_up = lstat->link_up;
	linfo->full_duplex = lstat->full_duplex;
	linfo->lmac_type_id = cgx_get_lmac_type(cgx, lmac_id);
	linfo->speed = cgx_speed_mbps[lstat->speed];
	lmac_string = cgx_lmactype_string[linfo->lmac_type_id];
	strncpy(linfo->lmac_type, lmac_string, LMACTYPE_STR_LEN - 1);
}

/* Hardware event handlers */
static inline void cgx_link_change_handler(struct cgx_lnk_sts *lstat,
					   struct lmac *lmac)
{
	struct cgx_link_user_info *linfo;
	struct cgx *cgx = lmac->cgx;
	struct cgx_link_event event;
	struct device *dev;

	dev = &cgx->pdev->dev;

	link_status_user_format(lstat, &event.link_uinfo, cgx, lmac->lmac_id);
	event.cgx_id = cgx->cgx_id;
	event.lmac_id = lmac->lmac_id;

	/* update the local copy of link status */
	lmac->link_info = event.link_uinfo;
	linfo = &lmac->link_info;

	if (!lmac->event_cb.notify_link_chg) {
		dev_dbg(dev, "cgx port %d:%d Link change handler null",
			cgx->cgx_id, lmac->lmac_id);
		if (lstat->err_type != CGX_ERR_NONE) {
			dev_err(dev, "cgx port %d:%d Link error %d\n",
				cgx->cgx_id, lmac->lmac_id, lstat->err_type);
		}
		dev_info(dev, "cgx port %d:%d Link is %s %d Mbps\n",
			 cgx->cgx_id, lmac->lmac_id,
			 linfo->link_up ? "UP" : "DOWN", linfo->speed);
		return;
	}

	if (lmac->event_cb.notify_link_chg(&event, lmac->event_cb.data))
		dev_err(dev, "event notification failure\n");
}

static inline bool cgx_cmdresp_is_linkevent(struct cgx_evt_sts *rsp)
{
	if (rsp->id == CGX_CMD_LINK_BRING_UP ||
	    rsp->id == CGX_CMD_LINK_BRING_DOWN)
		return true;
	else
		return false;
}

static inline bool cgx_event_is_linkevent(struct cgx_evt_sts *evt)
{
	if (evt->id == CGX_EVT_LINK_CHANGE)
		return true;
	else
		return false;
}

static irqreturn_t cgx_fwi_event_handler(int irq, void *data)
{
	struct lmac *lmac = data;
	struct cgx *cgx = lmac->cgx;
	struct cgx_evt_sts event;
	union cgx_evtreg ereg;
	struct device *dev;

	ereg.val = cgx_read(cgx, lmac->lmac_id, CGX_EVENT_REG);
	if (!ereg.evt_sts.ack)
		return IRQ_NONE;

	dev = &cgx->pdev->dev;

	event = ereg.evt_sts;

	switch (event.evt_type) {
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
		if (cgx_cmdresp_is_linkevent(&event))
			cgx_link_change_handler(&ereg.link_sts, lmac);

		/* Release thread waiting for completion  */
		lmac->cmd_pend = false;
		wake_up_interruptible(&lmac->wq_cmd_cmplt);
		break;
	case CGX_EVT_ASYNC:
		if (cgx_event_is_linkevent(&event))
			cgx_link_change_handler(&ereg.link_sts, lmac);
		break;
	default:
		dev_err(dev, "cgx port %d:%d Unknown event received\n",
			cgx->cgx_id, lmac->lmac_id);
	}

	/*  Any new event or command response will be posted by firmware
	 *  only after the current status is acked.
	 */
	cgx_write(lmac->cgx, lmac->lmac_id, CGX_EVENT_REG, 0);

	return IRQ_HANDLED;
}

/* APIs for PHY management using CGX firmware interface */

/* callback registration for hardware events like link change */
int cgx_lmac_evh_register(struct cgx_event_cb *cb, void *cgxd, int lmac_id)
{
	struct lmac *lmac;
	struct cgx *cgx = cgxd;

	lmac = lmac_pdata(lmac_id, cgx);
	if (!lmac)
		return -ENODEV;

	lmac->event_cb = *cb;

	return 0;
}
EXPORT_SYMBOL(cgx_lmac_evh_register);

static int cgx_fwi_link_change(struct cgx *cgx, int lmac_id, bool enable)
{
	struct cgx_cmd req = { 0 };
	struct cgx_evt_sts rsp;

	if (enable)
		req.id = CGX_CMD_LINK_BRING_UP;
	else
		req.id = CGX_CMD_LINK_BRING_DOWN;

	return cgx_fwi_cmd_generic(&req, &rsp, cgx, lmac_id);
}
EXPORT_SYMBOL(cgx_fwi_link_change);

static inline int cgx_fwi_read_version(struct cgx_ver_s *ver, struct cgx *cgx)
{
	struct cgx_cmd req = { 0 };
	union cgx_evtreg event;
	int err;

	req.id = CGX_CMD_GET_FW_VER;

	err = cgx_fwi_cmd_generic(&req, &event.evt_sts, cgx, 0);
	if (!err)
		*ver = event.ver;

	return err;
}

static int cgx_lmac_verify_fwi_version(struct cgx *cgx)
{
	struct cgx_ver_s ver;
	struct device *dev = &cgx->pdev->dev;
	int err;

	err = cgx_fwi_read_version(&ver, cgx);
	dev_dbg(dev, "Firmware command interface version = %d.%d\n",
		ver.major_ver, ver.minor_ver);
	if (err || ver.major_ver != CGX_FIRMWARE_MAJOR_VER ||
	    ver.minor_ver != CGX_FIRMWARE_MINOR_VER)
		return -EIO;
	else
		return 0;
}

static void cgx_lmac_link_up(struct cgx *cgx)
{
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
		init_waitqueue_head(&lmac->wq_cmd_cmplt);
		mutex_init(&lmac->cmd_lock);
		err = request_irq(pci_irq_vector(cgx->pdev,
						 CGX_LMAC_FWI + i * 9),
				   cgx_fwi_event_handler, 0, lmac->name, lmac);
		if (err)
			return err;

		/* Add reference */
		cgx->lmac_idmap[i] = lmac;
	}

	return cgx_lmac_verify_fwi_version(cgx);
}

static int cgx_lmac_exit(struct cgx *cgx)
{
	struct lmac *lmac;
	int i;

	/* Free all lmac related resources */
	for (i = 0; i < cgx->lmac_count; i++) {
		lmac = cgx->lmac_idmap[i];
		if (!lmac)
			continue;
		free_irq(pci_irq_vector(cgx->pdev, CGX_LMAC_FWI + i * 9), lmac);
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

	list_add(&cgx->cgx_list, &cgx_list);
	cgx->cgx_id = cgx_get_cgx_cnt() - 1;

	cgx_link_usertable_init();

	err = cgx_lmac_init(cgx);
	if (err)
		goto err_release_lmac;

	cgx_lmac_link_up(cgx);

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

	cgx_lmac_exit(cgx);
	list_del(&cgx->cgx_list);
	pci_free_irq_vectors(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver cgx_driver = {
	.name = DRV_NAME,
	.id_table = cgx_id_table,
	.probe = cgx_probe,
	.remove = cgx_remove,
};

static int __init cgx_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&cgx_driver);
}

static void __exit cgx_cleanup_module(void)
{
	pci_unregister_driver(&cgx_driver);
}

module_init(cgx_init_module);
module_exit(cgx_cleanup_module);
