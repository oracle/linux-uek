// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/interrupt.h>

#include "otx2_bphy.h"
#include "otx2_rfoe.h"
#include "otx2_cpri.h"
#include "otx2_bphy_debugfs.h"
#include "cnf10k_rfoe.h"
#include "cnf10k_cpri.h"

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION(DRV_STRING);
MODULE_LICENSE("GPL v2");

/* max ptp tx requests */
int max_ptp_req = 16;
module_param(max_ptp_req, int, 0644);
MODULE_PARM_DESC(max_ptp_req, "Maximum PTP Tx requests");

/* cdev */
static struct class *otx2rfoe_class;

/* reg base address */
void __iomem *bphy_reg_base;
void __iomem *psm_reg_base;
void __iomem *rfoe_reg_base;
void __iomem *bcn_reg_base;
void __iomem *ptp_reg_base;
void __iomem *cpri_reg_base;

/* check if cpri block is available */
#define cpri_available()		((cpri_reg_base) ? 1 : 0)

/* GPINT(2) interrupt handler routine */
static irqreturn_t cnf10k_gpint2_intr_handler(int irq, void *dev_id)
{
	struct otx2_bphy_cdev_priv *cdev_priv;
	int rfoe_num, cpri_num;
	u32 status, intr_mask;

	cdev_priv = (struct otx2_bphy_cdev_priv *)dev_id;

	/* clear interrupt status */
	status = readq(bphy_reg_base + PSM_INT_GP_SUM_W1C(2)) & 0xFFFFFFFF;
	writeq(status, bphy_reg_base + PSM_INT_GP_SUM_W1C(2));

	pr_debug("gpint2 status = 0x%x\n", status);

	/* rx intr processing */
	for (rfoe_num = 0; rfoe_num < cdev_priv->num_rfoe_mhab; rfoe_num++) {
		intr_mask = CNF10K_RFOE_RX_INTR_MASK(rfoe_num);
		if (status & intr_mask)
			cnf10k_rfoe_rx_napi_schedule(rfoe_num, status);
	}

	/* cpri intr processing */
	for (cpri_num = 0; cpri_num < OTX2_BPHY_CPRI_MAX_MHAB; cpri_num++) {
		intr_mask = CNF10K_CPRI_RX_INTR_MASK(cpri_num);
		if (status & intr_mask) {
			/* clear UL ETH interrupt */
			writeq(0x1, cpri_reg_base + CPRIX_ETH_UL_INT(cpri_num));
			cnf10k_cpri_rx_napi_schedule(cpri_num, status);
		}
	}

	return IRQ_HANDLED;
}

/* GPINT(1) interrupt handler routine */
static irqreturn_t otx2_bphy_intr_handler(int irq, void *dev_id)
{
	struct otx2_bphy_cdev_priv *cdev_priv;
	struct otx2_rfoe_drv_ctx *drv_ctx;
	struct otx2_rfoe_ndev_priv *priv;
	struct net_device *netdev;
	int rfoe_num, cpri_num, i;
	u32 intr_mask, status;

	cdev_priv = (struct otx2_bphy_cdev_priv *)dev_id;

	/* clear interrupt status */
	status = readq(bphy_reg_base + PSM_INT_GP_SUM_W1C(1)) & 0xFFFFFFFF;
	writeq(status, bphy_reg_base + PSM_INT_GP_SUM_W1C(1));

	pr_debug("gpint status = 0x%x\n", status);

	/* CNF10K intr processing */
	if (CHIP_CNF10K(cdev_priv->hw_version)) {
		cnf10k_bphy_intr_handler(cdev_priv, status);
		return IRQ_HANDLED;
	}

	/* CNF95 intr processing */
	for (rfoe_num = 0; rfoe_num < MAX_RFOE_INTF; rfoe_num++) {
		intr_mask = RFOE_RX_INTR_MASK(rfoe_num);
		if (status & intr_mask)
			otx2_rfoe_rx_napi_schedule(rfoe_num, status);
	}

	for (cpri_num = 0; cpri_num < OTX2_BPHY_CPRI_MAX_MHAB; cpri_num++) {
		intr_mask = CPRI_RX_INTR_MASK(cpri_num);
		if (status & intr_mask) {
			/* clear UL ETH interrupt */
			writeq(0x1, cpri_reg_base + CPRIX_ETH_UL_INT(cpri_num));
			otx2_cpri_rx_napi_schedule(cpri_num, status);
		}
	}

	/* tx intr processing */
	for (i = 0; i < RFOE_MAX_INTF; i++) {
		drv_ctx = &rfoe_drv_ctx[i];
		if (drv_ctx->valid) {
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			intr_mask = RFOE_TX_PTP_INTR_MASK(priv->rfoe_num,
							  priv->lmac_id);
			if ((status & intr_mask) && priv->ptp_tx_skb)
				schedule_work(&priv->ptp_tx_work);
		}
	}

	return IRQ_HANDLED;
}

static inline void msix_enable_ctrl(struct pci_dev *dev)
{
	u16 control;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
	control |= PCI_MSIX_FLAGS_ENABLE;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, control);
}

static long otx2_bphy_cdev_ioctl(struct file *filp, unsigned int cmd,
				 unsigned long arg)
{
	struct otx2_bphy_cdev_priv *cdev = filp->private_data;
	int ret;

	if (!cdev) {
		pr_warn("ioctl: device not opened\n");
		return -EIO;
	}

	mutex_lock(&cdev->mutex_lock);

	switch (cmd) {
	case OTX2_RFOE_IOCTL_ODP_INTF_CFG:
	{
		struct bphy_netdev_comm_intf_cfg *intf_cfg;
		struct pci_dev *bphy_pdev;
		int idx;

		if (cdev->odp_intf_cfg) {
			dev_info(cdev->dev, "odp interface cfg already done\n");
			ret = -EBUSY;
			goto out;
		}

		intf_cfg = kzalloc(MAX_RFOE_INTF * sizeof(*intf_cfg),
				   GFP_KERNEL);
		if (!intf_cfg) {
			ret = -ENOMEM;
			goto out;
		}

		if (copy_from_user(intf_cfg, (void __user *)arg,
				   (MAX_RFOE_INTF *
				   sizeof(struct bphy_netdev_comm_intf_cfg)))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}

		for (idx = 0; idx < OTX2_BPHY_MHAB_INST; idx++)
			cdev->mhab_mode[idx] = intf_cfg[idx].if_type;

		ret = otx2_rfoe_parse_and_init_intf(cdev, intf_cfg);
		if (ret < 0) {
			dev_err(cdev->dev, "odp <-> netdev parse error\n");
			goto out;
		}

		if (cpri_available()) {
			ret = otx2_cpri_parse_and_init_intf(cdev, intf_cfg);
			if (ret < 0) {
				dev_err(cdev->dev, "odp <-> netdev parse error\n");
				goto out;
			}
		}

		/* The MSIXEN bit is getting cleared when ODP BPHY driver
		 * resets BPHY. So enabling it back in IOCTL.
		 */
		bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
					   OTX2_BPHY_PCI_DEVICE_ID, NULL);
		if (!bphy_pdev) {
			dev_err(cdev->dev, "Couldn't find BPHY PCI device %x\n",
				OTX2_BPHY_PCI_DEVICE_ID);
			ret = -ENODEV;
			goto out;
		}
		msix_enable_ctrl(bphy_pdev);

		/* Enable CPRI ETH UL INT */
		for (idx = 0; idx < OTX2_BPHY_CPRI_MAX_MHAB; idx++) {
			if (intf_cfg[idx].if_type == IF_TYPE_CPRI)
				writeq(0x1, cpri_reg_base +
				       CPRIX_ETH_UL_INT_ENA_W1S(idx));
		}

		/* Enable GPINT Rx and Tx interrupts */
		writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1S(1));

		cdev->odp_intf_cfg = 1;

		kfree(intf_cfg);

		ret = 0;
		goto out;
	}
	case OTX2_RFOE_IOCTL_ODP_DEINIT:
	{
		u32 status;

		/* Disable GPINT Rx and Tx interrupts */
		writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1C(1));

		/* clear interrupt status */
		status = readq(bphy_reg_base + PSM_INT_GP_SUM_W1C(1)) &
				0xFFFFFFFF;
		writeq(status, bphy_reg_base + PSM_INT_GP_SUM_W1C(1));

		if (CHIP_CNF10K(cdev->hw_version)) {
			if (cdev->gpint2_irq) {
				/* Disable GPINT Rx and Tx interrupts */
				writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1C(2));
				/* clear interrupt status */
				status = readq(bphy_reg_base + PSM_INT_GP_SUM_W1C(2)) &
						0xFFFFFFFF;
				writeq(status, bphy_reg_base + PSM_INT_GP_SUM_W1C(2));
			}
			cnf10k_bphy_rfoe_cleanup();
			if (cpri_available())
				cnf10k_bphy_cpri_cleanup();
		} else {
			otx2_bphy_rfoe_cleanup();
			if (cpri_available())
				otx2_bphy_cpri_cleanup();
		}

		cdev->odp_intf_cfg = 0;

		ret = 0;
		goto out;
	}
	case OTX2_RFOE_IOCTL_RX_IND_CFG:
	{
		struct otx2_rfoe_rx_ind_cfg cfg;
		unsigned long flags;

		if (copy_from_user(&cfg, (void __user *)arg,
				   sizeof(struct otx2_rfoe_rx_ind_cfg))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}

		spin_lock_irqsave(&cdev->mbt_lock, flags);
		writeq(cfg.rx_ind_idx, (rfoe_reg_base +
		       RFOEX_RX_INDIRECT_INDEX_OFFSET(cfg.rfoe_num)));
		if (cfg.dir == OTX2_RFOE_RX_IND_READ)
			cfg.regval = readq(rfoe_reg_base + cfg.regoff);
		else
			writeq(cfg.regval, rfoe_reg_base + cfg.regoff);
		spin_unlock_irqrestore(&cdev->mbt_lock, flags);
		if (copy_to_user((void __user *)(unsigned long)arg, &cfg,
				 sizeof(struct otx2_rfoe_rx_ind_cfg))) {
			dev_err(cdev->dev, "copy to user fault\n");
			ret = -EFAULT;
			goto out;
		}
		ret = 0;
		goto out;
	}
	case OTX2_RFOE_IOCTL_PTP_OFFSET:
	{
		u32 bcn_capture_off = 0, bcn_capture_n1_n2_off = 0, bcn_capture_ptp_off = 0;
		u64 bcn_n1, bcn_n2, bcn_n1_ns, bcn_n2_ps, ptp0_ns, regval;
		struct cnf10k_rfoe_drv_ctx *cnf10k_drv_ctx = NULL;
		struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
		struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
		struct otx2_rfoe_ndev_priv *priv;
		struct ptp_bcn_off_cfg *ptp_cfg;
		struct ptp_clk_cfg clk_cfg;
		struct net_device *netdev;
		struct ptp_bcn_ref ref;
		unsigned long expires;
		int idx;

		if (!cdev->odp_intf_cfg) {
			dev_info(cdev->dev, "odp interface cfg is not done\n");
			ret = -EBUSY;
			goto out;
		}
		if (copy_from_user(&clk_cfg, (void __user *)arg,
				   sizeof(struct ptp_clk_cfg))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}
		if (!(clk_cfg.clk_freq_ghz && clk_cfg.clk_freq_div)) {
			dev_err(cdev->dev, "Invalid ptp clk parameters\n");
			ret = -EINVAL;
			goto out;
		}
		if (CHIP_CNF10K(cdev->hw_version)) {
			for (idx = 0; idx < cdev->tot_rfoe_intf; idx++) {
				cnf10k_drv_ctx = &cnf10k_rfoe_drv_ctx[idx];
				if (cnf10k_drv_ctx->valid) {
					netdev = cnf10k_drv_ctx->netdev;
					cnf10k_priv = netdev_priv(netdev);
					ptp_cfg = cnf10k_priv->ptp_cfg;
					bcn_capture_off = CNF10K_BCN_CAPTURE_CFG;
					bcn_capture_n1_n2_off = CNF10K_BCN_CAPTURE_N1_N2;
					bcn_capture_ptp_off = CNF10K_BCN_CAPTURE_PTP;
					break;
				}
			}
			if (idx >= cdev->tot_rfoe_intf) {
				dev_err(cdev->dev, "drv ctx not found\n");
				ret = -EINVAL;
				goto out;
			}
		} else {
			for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
				drv_ctx = &rfoe_drv_ctx[idx];
				if (drv_ctx->valid) {
					netdev = drv_ctx->netdev;
					priv = netdev_priv(netdev);
					ptp_cfg = priv->ptp_cfg;
					bcn_capture_off = BCN_CAPTURE_CFG;
					bcn_capture_n1_n2_off = BCN_CAPTURE_N1_N2;
					bcn_capture_ptp_off = BCN_CAPTURE_PTP;
					break;
				}
			}
			if (idx >= RFOE_MAX_INTF) {
				dev_err(cdev->dev, "drv ctx not found\n");
				ret = -EINVAL;
				goto out;
			}
		}
		ptp_cfg->clk_cfg.clk_freq_ghz = clk_cfg.clk_freq_ghz;
		ptp_cfg->clk_cfg.clk_freq_div = clk_cfg.clk_freq_div;
		/* capture ptp and bcn timestamp using BCN_CAPTURE_CFG */
		writeq(CAPT_EN | CAPT_TRIG_SW, bcn_reg_base + bcn_capture_off);
		/* poll for capt_en to become 0 */
		while ((readq(bcn_reg_base + bcn_capture_off) & CAPT_EN))
			cpu_relax();
		ptp0_ns = readq(bcn_reg_base + bcn_capture_ptp_off);
		regval = readq(bcn_reg_base + bcn_capture_n1_n2_off);
		bcn_n1 = (regval >> 24) & 0xFFFFFFFFFF;
		bcn_n2 = regval & 0xFFFFFF;
		/* BCN N1 10 msec counter to nsec */
		bcn_n1_ns = bcn_n1 * 10 * NSEC_PER_MSEC;
		bcn_n1_ns += UTC_GPS_EPOCH_DIFF * NSEC_PER_SEC;
		/* BCN N2 clock period 0.813802083 nsec to pico secs */
		bcn_n2_ps = (bcn_n2 * 813802083UL) / 1000000;
		ref.ptp0_ns = ptp0_ns;
		ref.bcn0_n1_ns = bcn_n1_ns;
		ref.bcn0_n2_ps = bcn_n2_ps;
		memcpy(&ptp_cfg->old_ref, &ref, sizeof(struct ptp_bcn_ref));
		memcpy(&ptp_cfg->new_ref, &ref, sizeof(struct ptp_bcn_ref));
		ptp_cfg->use_ptp_alg = 1;
		expires = jiffies + PTP_OFF_RESAMPLE_THRESH * HZ;
		mod_timer(&ptp_cfg->ptp_timer, expires);
		ret = 0;
		goto out;
	}
	case OTX2_RFOE_IOCTL_SEC_BCN_OFFSET:
	{
		struct cnf10k_rfoe_drv_ctx *cnf10k_drv_ctx = NULL;
		struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
		struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
		struct otx2_rfoe_ndev_priv *priv;
		struct bcn_sec_offset_cfg cfg;
		struct net_device *netdev;
		int idx;

		if (!cdev->odp_intf_cfg) {
			dev_info(cdev->dev, "odp interface cfg is not done\n");
			ret = -EBUSY;
			goto out;
		}
		if (copy_from_user(&cfg, (void __user *)arg,
				   sizeof(struct bcn_sec_offset_cfg))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}
		if (CHIP_CNF10K(cdev->hw_version)) {
			for (idx = 0; idx < cdev->tot_rfoe_intf; idx++) {
				cnf10k_drv_ctx = &cnf10k_rfoe_drv_ctx[idx];
				if (cnf10k_drv_ctx->valid &&
				    cnf10k_drv_ctx->rfoe_num == cfg.rfoe_num &&
				    cnf10k_drv_ctx->lmac_id == cfg.lmac_id) {
					netdev = cnf10k_drv_ctx->netdev;
					cnf10k_priv = netdev_priv(netdev);
					cnf10k_priv->sec_bcn_offset = cfg.sec_bcn_offset;
					break;
				}
			}
			if (idx >= cdev->tot_rfoe_intf) {
				dev_err(cdev->dev, "drv ctx not found\n");
				ret = -EINVAL;
				goto out;
			}
		} else {
			for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
				drv_ctx = &rfoe_drv_ctx[idx];
				if (drv_ctx->valid &&
				    drv_ctx->rfoe_num == cfg.rfoe_num &&
				    drv_ctx->lmac_id == cfg.lmac_id) {
					netdev = drv_ctx->netdev;
					priv = netdev_priv(netdev);
					priv->sec_bcn_offset = cfg.sec_bcn_offset;
					break;
				}
			}
			if (idx >= RFOE_MAX_INTF) {
				dev_err(cdev->dev, "drv ctx not found\n");
				ret = -EINVAL;
				goto out;
			}
		}
		ret = 0;
		goto out;
	}
	case OTX2_RFOE_IOCTL_MODE_CPRI:
	{
		int id = 0;

		if (!cdev->odp_intf_cfg) {
			dev_info(cdev->dev, "odp interface cfg is not done\n");
			ret = -EBUSY;
			goto out;
		}

		if (copy_from_user(&id, (void __user *)arg, sizeof(int))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}

		if (cdev->mhab_mode[id] == IF_TYPE_ETHERNET) {
			otx2_rfoe_disable_intf(id);
			otx2_cpri_enable_intf(id);
			cdev->mhab_mode[id] = IF_TYPE_CPRI;
		}

		ret = 0;
		goto out;
	}
	case OTX2_RFOE_IOCTL_LINK_EVENT:
	{
		struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
		struct otx2_rfoe_link_event cfg;
		struct net_device *netdev;
		int idx;

		if (!cdev->odp_intf_cfg) {
			dev_info(cdev->dev, "odp interface cfg is not done\n");
			ret = -EBUSY;
			goto out;
		}
		if (copy_from_user(&cfg, (void __user *)arg,
				   sizeof(struct otx2_rfoe_link_event))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}
		for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
			drv_ctx = &rfoe_drv_ctx[idx];
			if (drv_ctx->valid &&
			    drv_ctx->rfoe_num == cfg.rfoe_num &&
			    drv_ctx->lmac_id == cfg.lmac_id)
				break;
		}
		if (idx >= RFOE_MAX_INTF) {
			dev_err(cdev->dev, "drv ctx not found\n");
			ret = -EINVAL;
			goto out;
		}
		netdev = drv_ctx->netdev;
		otx2_rfoe_set_link_state(netdev, cfg.link_state);
		ret = 0;
		goto out;
	}
	case OTX2_CPRI_IOCTL_LINK_EVENT:
	{
		struct otx2_cpri_drv_ctx *drv_ctx = NULL;
		struct otx2_cpri_link_event cfg;
		struct net_device *netdev;
		int idx;

		if (!cdev->odp_intf_cfg) {
			dev_info(cdev->dev, "odp interface cfg is not done\n");
			ret = -EBUSY;
			goto out;
		}
		if (copy_from_user(&cfg, (void __user *)arg,
				   sizeof(struct otx2_cpri_link_event))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}
		for (idx = 0; idx < OTX2_BPHY_CPRI_MAX_INTF; idx++) {
			drv_ctx = &cpri_drv_ctx[idx];
			if (drv_ctx->valid &&
			    drv_ctx->cpri_num == cfg.cpri_num &&
			    drv_ctx->lmac_id == cfg.lmac_id)
				break;
		}
		if (idx >= OTX2_BPHY_CPRI_MAX_INTF) {
			dev_err(cdev->dev, "drv ctx not found\n");
			ret = -EINVAL;
			goto out;
		}
		netdev = drv_ctx->netdev;
		otx2_cpri_set_link_state(netdev, cfg.link_state);
		ret = 0;
		goto out;
	}
	case OTX2_IOCTL_RFOE_10x_CFG:
	{
		struct cnf10k_rfoe_ndev_comm_intf_cfg *intf_cfg;
		struct pci_dev *bphy_pdev;
		int idx;

		if (cdev->odp_intf_cfg && (cdev->flags & ODP_INTF_CFG_RFOE)) {
			dev_info(cdev->dev, "odp rfoe interface cfg already done\n");
			ret = -EBUSY;
			goto out;
		}

		intf_cfg = kzalloc(BPHY_MAX_RFOE_MHAB * sizeof(*intf_cfg),
				   GFP_KERNEL);
		if (!intf_cfg) {
			ret = -ENOMEM;
			goto out;
		}

		if (copy_from_user(intf_cfg, (void __user *)arg,
				   (BPHY_MAX_RFOE_MHAB *
				    sizeof(*intf_cfg)))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}

		for (idx = 0; idx < BPHY_MAX_RFOE_MHAB; idx++)
			cdev->mhab_mode[idx] = IF_TYPE_ETHERNET;

		ret = cnf10k_rfoe_parse_and_init_intf(cdev, intf_cfg);
		if (ret < 0) {
			dev_err(cdev->dev, "odp <-> netdev parse error\n");
			goto out;
		}

		/* The MSIXEN bit is getting cleared when ODP BPHY driver
		 * resets BPHY. So enabling it back in IOCTL.
		 */
		bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
					   OTX2_BPHY_PCI_DEVICE_ID, NULL);
		if (!bphy_pdev) {
			dev_err(cdev->dev, "Couldn't find BPHY PCI device %x\n",
				OTX2_BPHY_PCI_DEVICE_ID);
			ret = -ENODEV;
			goto out;
		}
		msix_enable_ctrl(bphy_pdev);

		/* Enable GPINT Rx and Tx interrupts */
		writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
		if (cdev->gpint2_irq)
			writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1S(2));

		cdev->odp_intf_cfg = 1;
		cdev->flags |= ODP_INTF_CFG_RFOE;

		kfree(intf_cfg);

		ret = 0;
		goto out;
	}
	case OTX2_IOCTL_CPRI_INTF_CFG:
	{
		struct cnf10k_bphy_cpri_netdev_comm_intf_cfg  *intf_cfg;
		struct pci_dev *bphy_pdev;
		int idx;

		if (cdev->odp_intf_cfg && (cdev->flags & ODP_INTF_CFG_CPRI)) {
			dev_info(cdev->dev, "odp cpri interface cfg already done\n");
			ret = -EBUSY;
			goto out;
		}

		intf_cfg = kzalloc(sizeof(*intf_cfg), GFP_KERNEL);
		if (!intf_cfg) {
			ret = -ENOMEM;
			goto out;
		}

		if (copy_from_user(intf_cfg, (void __user *)arg,
				   sizeof(*intf_cfg))) {
			dev_err(cdev->dev, "copy from user fault\n");
			ret = -EFAULT;
			goto out;
		}

		if (cpri_available()) {
			ret = cnf10k_cpri_parse_and_init_intf(cdev, intf_cfg);
			if (ret < 0) {
				dev_err(cdev->dev, "odp <-> netdev parse error\n");
				goto out;
			}
		}

		/* The MSIXEN bit is getting cleared when ODP BPHY driver
		 * resets BPHY. So enabling it back in IOCTL.
		 */
		bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
					   OTX2_BPHY_PCI_DEVICE_ID, NULL);
		if (!bphy_pdev) {
			dev_err(cdev->dev, "Couldn't find BPHY PCI device %x\n",
				OTX2_BPHY_PCI_DEVICE_ID);
			ret = -ENODEV;
			goto out;
		}
		msix_enable_ctrl(bphy_pdev);

		/* Enable CPRI ETH UL INT */
		for (idx = 0; idx < CNF10K_BPHY_CPRI_MAX_MHAB; idx++)
			writeq(0x1, cpri_reg_base + CNF10K_CPRIX_ETH_UL_INT_ENA_W1S(idx));

		/* Enable GPINT Rx and Tx interrupts */
		writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1S(2));

		cdev->odp_intf_cfg = 1;
		cdev->flags |= ODP_INTF_CFG_CPRI;

		kfree(intf_cfg);

		ret = 0;
		goto out;
	}
	default:
	{
		dev_info(cdev->dev, "ioctl: no match\n");
		ret = -EINVAL;
	}
	}

out:
	mutex_unlock(&cdev->mutex_lock);
	return ret;
}

static int otx2_bphy_cdev_open(struct inode *inode, struct file *filp)
{
	struct otx2_bphy_cdev_priv *cdev;
	int status = 0;

	cdev = container_of(inode->i_cdev, struct otx2_bphy_cdev_priv, cdev);

	mutex_lock(&cdev->mutex_lock);

	if (cdev->is_open) {
		dev_err(cdev->dev, "failed to open the device\n");
		status = -EBUSY;
		goto error;
	}
	cdev->is_open = 1;
	filp->private_data = cdev;

error:
	mutex_unlock(&cdev->mutex_lock);

	return status;
}

static int otx2_bphy_cdev_release(struct inode *inode, struct file *filp)
{
	struct otx2_bphy_cdev_priv *cdev = filp->private_data;
	u32 status;

	mutex_lock(&cdev->mutex_lock);

	if (!cdev->odp_intf_cfg)
		goto cdev_release_exit;

	/* Disable GPINT Rx and Tx interrupts */
	writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1C(1));

	/* clear interrupt status */
	status = readq(bphy_reg_base + PSM_INT_GP_SUM_W1C(1)) & 0xFFFFFFFF;
	writeq(status, bphy_reg_base + PSM_INT_GP_SUM_W1C(1));

	if (CHIP_CNF10K(cdev->hw_version)) {
		if (cdev->gpint2_irq) {
			/* Disable GPINT Rx and Tx interrupts */
			writeq(0xFFFFFFFF, bphy_reg_base + PSM_INT_GP_ENA_W1C(2));
			/* clear interrupt status */
			status = readq(bphy_reg_base + PSM_INT_GP_SUM_W1C(2)) &
					0xFFFFFFFF;
			writeq(status, bphy_reg_base + PSM_INT_GP_SUM_W1C(2));
		}
		cnf10k_bphy_rfoe_cleanup();
		if (cpri_available())
			cnf10k_bphy_cpri_cleanup();
	} else {
		otx2_bphy_rfoe_cleanup();
		if (cpri_available())
			otx2_bphy_cpri_cleanup();
	}

	cdev->odp_intf_cfg = 0;

cdev_release_exit:
	cdev->is_open = 0;
	mutex_unlock(&cdev->mutex_lock);

	return 0;
}

static const struct file_operations otx2_bphy_cdev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= otx2_bphy_cdev_ioctl,
	.open		= otx2_bphy_cdev_open,
	.release	= otx2_bphy_cdev_release,
};

static int otx2_bphy_probe(struct platform_device *pdev)
{
	struct otx2_bphy_cdev_priv *cdev_priv;
	struct pci_dev *bphy_pdev;
	struct resource *res;
	int err = 0;
	dev_t devt;

	/* allocate priv structure */
	cdev_priv = kzalloc(sizeof(*cdev_priv), GFP_KERNEL);
	if (!cdev_priv) {
		err = -ENOMEM;
		goto out;
	}

	/* BPHY is a PCI device and the kernel resets the MSIXEN bit during
	 * enumeration. So enable it back for interrupts to be generated.
	 */
	bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
				   OTX2_BPHY_PCI_DEVICE_ID, NULL);
	if (!bphy_pdev) {
		dev_err(&pdev->dev, "Couldn't find BPHY PCI device %x\n",
			OTX2_BPHY_PCI_DEVICE_ID);
		err = -ENODEV;
		goto free_cdev_priv;
	}
	msix_enable_ctrl(bphy_pdev);

	/* bphy registers ioremap */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "failed to get bphy resource\n");
		err = -ENXIO;
		goto free_cdev_priv;
	}
	bphy_reg_base = ioremap_nocache(res->start, resource_size(res));
	if (IS_ERR(bphy_reg_base)) {
		dev_err(&pdev->dev, "failed to ioremap bphy registers\n");
		err = PTR_ERR(bphy_reg_base);
		goto free_cdev_priv;
	}
	/* psm registers ioremap */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "failed to get psm resource\n");
		err = -ENXIO;
		goto out_unmap_bphy_reg;
	}
	psm_reg_base = ioremap_nocache(res->start, resource_size(res));
	if (IS_ERR(psm_reg_base)) {
		dev_err(&pdev->dev, "failed to ioremap psm registers\n");
		err = PTR_ERR(psm_reg_base);
		goto out_unmap_bphy_reg;
	}
	/* rfoe registers ioremap */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!res) {
		dev_err(&pdev->dev, "failed to get rfoe resource\n");
		err = -ENXIO;
		goto out_unmap_psm_reg;
	}
	rfoe_reg_base = ioremap_nocache(res->start, resource_size(res));
	if (IS_ERR(rfoe_reg_base)) {
		dev_err(&pdev->dev, "failed to ioremap rfoe registers\n");
		err = PTR_ERR(rfoe_reg_base);
		goto out_unmap_psm_reg;
	}
	/* bcn register ioremap */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 3);
	if (!res) {
		dev_err(&pdev->dev, "failed to get bcn resource\n");
		err = -ENXIO;
		goto out_unmap_rfoe_reg;
	}
	bcn_reg_base = ioremap_nocache(res->start, resource_size(res));
	if (IS_ERR(bcn_reg_base)) {
		dev_err(&pdev->dev, "failed to ioremap bcn registers\n");
		err = PTR_ERR(bcn_reg_base);
		goto out_unmap_rfoe_reg;
	}
	/* ptp register ioremap */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 4);
	if (!res) {
		dev_err(&pdev->dev, "failed to get ptp resource\n");
		err = -ENXIO;
		goto out_unmap_bcn_reg;
	}
	ptp_reg_base = ioremap_nocache(res->start, resource_size(res));
	if (IS_ERR(ptp_reg_base)) {
		dev_err(&pdev->dev, "failed to ioremap ptp registers\n");
		err = PTR_ERR(ptp_reg_base);
		goto out_unmap_bcn_reg;
	}
	/* cpri registers ioremap */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 5);
	if (!res) {
		cpri_reg_base = NULL;
	} else {
		dev_info(&pdev->dev, "cpri mem resource found\n");
		cpri_reg_base = ioremap_nocache(res->start, resource_size(res));
		if (IS_ERR(cpri_reg_base)) {
			dev_err(&pdev->dev, "failed to ioremap cpri registers\n");
			err = PTR_ERR(cpri_reg_base);
			goto out_unmap_ptp_reg;
		}
	}
	/* get irq */
	cdev_priv->irq = platform_get_irq(pdev, 0);
	if (cdev_priv->irq <= 0) {
		dev_err(&pdev->dev, "irq resource not found\n");
		goto out_unmap_cpri_reg;
	}
	cdev_priv->gpint2_irq = platform_get_irq(pdev, 1);
	if (cdev_priv->gpint2_irq < 0)
		cdev_priv->gpint2_irq = 0;
	else
		dev_info(&pdev->dev, "gpint2 irq resource found\n");

	/* create a character device */
	err = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to alloc chrdev device region\n");
		goto out_unmap_cpri_reg;
	}

	otx2rfoe_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(otx2rfoe_class)) {
		dev_err(&pdev->dev, "couldn't create class %s\n", DEVICE_NAME);
		err = PTR_ERR(otx2rfoe_class);
		goto out_unregister_chrdev_region;
	}

	cdev_priv->devt = devt;
	cdev_priv->is_open = 0;
	spin_lock_init(&cdev_priv->lock);
	spin_lock_init(&cdev_priv->mbt_lock);
	mutex_init(&cdev_priv->mutex_lock);

	cdev_init(&cdev_priv->cdev, &otx2_bphy_cdev_fops);
	cdev_priv->cdev.owner = THIS_MODULE;

	err = cdev_add(&cdev_priv->cdev, devt, 1);
	if (err < 0) {
		dev_err(&pdev->dev, "cdev_add() failed\n");
		goto out_class_destroy;
	}

	cdev_priv->dev = device_create(otx2rfoe_class, &pdev->dev,
				       cdev_priv->cdev.dev, cdev_priv,
				       DEVICE_NAME);
	if (IS_ERR(cdev_priv->dev)) {
		dev_err(&pdev->dev, "device_create failed\n");
		err = PTR_ERR(cdev_priv->dev);
		goto out_cdev_del;
	}

	dev_info(&pdev->dev, "successfully registered char device, major=%d\n",
		 MAJOR(cdev_priv->cdev.dev));

	err = request_irq(cdev_priv->irq, otx2_bphy_intr_handler, 0,
			  "otx2_bphy_int", cdev_priv);
	if (err) {
		dev_err(&pdev->dev, "can't assign irq %d\n", cdev_priv->irq);
		goto out_device_destroy;
	}

	if (cdev_priv->gpint2_irq) {
		err = request_irq(cdev_priv->gpint2_irq,
				  cnf10k_gpint2_intr_handler, 0,
				  "cn10k_bphy_int", cdev_priv);
		if (err) {
			dev_err(&pdev->dev, "can't assign irq %d\n",
				cdev_priv->gpint2_irq);
			goto free_irq;
		}
	}

	err = 0;
	goto out;

free_irq:
	free_irq(cdev_priv->irq, cdev_priv);
out_device_destroy:
	device_destroy(otx2rfoe_class, cdev_priv->cdev.dev);
out_cdev_del:
	cdev_del(&cdev_priv->cdev);
out_class_destroy:
	class_destroy(otx2rfoe_class);
out_unregister_chrdev_region:
	unregister_chrdev_region(devt, 1);
out_unmap_cpri_reg:
	iounmap(cpri_reg_base);
out_unmap_ptp_reg:
	iounmap(ptp_reg_base);
out_unmap_bcn_reg:
	iounmap(bcn_reg_base);
out_unmap_rfoe_reg:
	iounmap(rfoe_reg_base);
out_unmap_psm_reg:
	iounmap(psm_reg_base);
out_unmap_bphy_reg:
	iounmap(bphy_reg_base);
free_cdev_priv:
	kfree(cdev_priv);
out:
	return err;
}

static int otx2_bphy_remove(struct platform_device *pdev)
{
	struct otx2_bphy_cdev_priv *cdev_priv = dev_get_drvdata(&pdev->dev);

	/* unmap register regions */
	iounmap(cpri_reg_base);
	iounmap(ptp_reg_base);
	iounmap(bcn_reg_base);
	iounmap(rfoe_reg_base);
	iounmap(psm_reg_base);
	iounmap(bphy_reg_base);

	/* free irq */
	free_irq(cdev_priv->irq, cdev_priv);

	/* char device cleanup */
	device_destroy(otx2rfoe_class, cdev_priv->cdev.dev);
	cdev_del(&cdev_priv->cdev);
	class_destroy(otx2rfoe_class);
	unregister_chrdev_region(cdev_priv->cdev.dev, 1);
	kfree(cdev_priv);

	return 0;
}

static const struct of_device_id otx2_bphy_of_match[] = {
	{ .compatible = "marvell,bphy-netdev" },
	{ }
};
MODULE_DEVICE_TABLE(of, otx2_bphy_of_match);

static struct platform_driver otx2_bphy_driver = {
	.probe	= otx2_bphy_probe,
	.remove	= otx2_bphy_remove,
	.driver	= {
		.name = DRV_NAME,
		.of_match_table = otx2_bphy_of_match,
	},
};

static int __init otx2_bphy_init(void)
{
	int ret;

	pr_info("%s: %s\n", DRV_NAME, DRV_STRING);

	ret = platform_driver_register(&otx2_bphy_driver);
	if (ret < 0)
		return ret;

	otx2_bphy_debugfs_init();

	return 0;
}

static void __exit otx2_bphy_exit(void)
{
	otx2_bphy_debugfs_exit();

	platform_driver_unregister(&otx2_bphy_driver);
}

module_init(otx2_bphy_init);
module_exit(otx2_bphy_exit);
