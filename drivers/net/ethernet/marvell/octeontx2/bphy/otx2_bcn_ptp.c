// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY BCN PTP clock synchronization support
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/io.h>

#include "otx2_bphy_hw.h"
#include "otx2_bphy.h"
#include "otx2_rfoe.h"
#include "cnf10k_rfoe.h"

#define BCN_DEVICE_NAME			"bcn_ptp_sync"
#define CLASS_NAME			"bcn_ptp_class"
#define BCN_PTP_IOCTL_BASE		0xCD	/* Temporary */
#define IOCTL_BCN_PTP_SYNC		_IOW(BCN_PTP_IOCTL_BASE, 0x01, \
					     struct bcn_ptp_cfg)
#define IOCTL_BCN_PTP_DELTA		_IOWR(BCN_PTP_IOCTL_BASE, 0x02, \
					      struct bcn_ptp_cfg)

static struct class *bcn_ptp_class;
static int major_no;

int otx2_bcn_poll_reg(void __iomem *bcn_reg_base, u64 offset, u64 mask, bool zero)
{
	unsigned long timeout = jiffies + usecs_to_jiffies(20000);
	bool twice = false;
	u64 reg_val;

again:
	reg_val = readq(bcn_reg_base + offset);
	if (zero && !(reg_val & mask))
		return 0;
	if (!zero && (reg_val & mask))
		return 0;
	if (time_before(jiffies, timeout)) {
		usleep_range(1, 5);
		goto again;
	}
	/* In scenarios where CPU is scheduled out before checking
	 * 'time_before' (above) and gets scheduled in such that
	 * jiffies are beyond timeout value, then check again if HW is
	 * done with the operation in the meantime.
	 */
	if (!twice) {
		twice = true;
		goto again;
	}
	return -EBUSY;
}

int bcn_ptp_sync(int ptp_phc_idx)
{
	u64 bcn_cfg2, bcn_capture_cfg, bcn_capture_n1_n2, bcn_capture_ptp, bcn_cfg_off;
	u64 bcn_n1_n2, bcn_cfg, ptp_clock, tsns, bcn_ns, bcn_delta_val, bcn_n2_len;
	struct cnf10k_rfoe_drv_ctx *cnf10k_drv_ctx = NULL;
	struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
	struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
	struct otx2_rfoe_ndev_priv *priv = NULL;
	struct timecounter *time_counter;
	void __iomem *bcn_reg_base;
	struct pci_dev *bphy_pdev;
	struct net_device *netdev;
	int idx, err, sign = 0;
	s32 sec_bcn_offset;
	u64 bcn_n1, bcn_n2;
	s64 ptp_bcn_delta;
	u64 bcn_cfg2_val;
	bool is_otx2;

	bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
				   OTX2_BPHY_PCI_DEVICE_ID, NULL);

	if (bphy_pdev->subsystem_device == PCI_SUBSYS_DEVID_OCTX2_95XXN)
		is_otx2 = true;
	else
		is_otx2 = false;

	if (!is_otx2) {
		for (idx = 0; idx < CNF10K_RFOE_MAX_INTF; idx++) {
			cnf10k_drv_ctx = &cnf10k_rfoe_drv_ctx[idx];
			if (cnf10k_drv_ctx->valid) {
				netdev = cnf10k_drv_ctx->netdev;
				cnf10k_priv = netdev_priv(netdev);
				if (ptp_clock_index(cnf10k_priv->ptp_clock) != ptp_phc_idx)
					continue;
				else
					break;
			}
		}
		if (idx >= CNF10K_RFOE_MAX_INTF) {
			pr_err("Invalid PTP PHC index\n");
			return -ENODEV;
		}

		bcn_reg_base = cnf10k_priv->bcn_reg_base;
		time_counter = &cnf10k_priv->time_counter;
		sec_bcn_offset = cnf10k_priv->sec_bcn_offset;
		bcn_cfg2 = CNF10K_BCN_CFG2;
		bcn_cfg_off = CNF10K_BCN_CFG;
		bcn_capture_cfg = CNF10K_BCN_CAPTURE_CFG;
		bcn_capture_n1_n2 = CNF10K_BCN_CAPTURE_N1_N2;
		bcn_capture_ptp = CNF10K_BCN_CAPTURE_PTP;
		bcn_delta_val = CNF10K_BCN_DELTA_VAL;
	} else {
		for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
			drv_ctx = &rfoe_drv_ctx[idx];
			if (drv_ctx->valid) {
				netdev = drv_ctx->netdev;
				priv = netdev_priv(netdev);
				if (ptp_clock_index(priv->ptp_clock) != ptp_phc_idx)
					continue;
				else
					break;
			}
		}

		if (idx == RFOE_MAX_INTF) {
			pr_err("Invalid PTP PHC index\n");
			return -ENODEV;
		}

		bcn_reg_base = priv->bcn_reg_base;
		time_counter = &priv->time_counter;
		sec_bcn_offset = priv->sec_bcn_offset;
		bcn_cfg2 = BCN_CFG2;
		bcn_cfg_off = BCN_CFG;
		bcn_capture_cfg = BCN_CAPTURE_CFG;
		bcn_capture_n1_n2 = BCN_CAPTURE_N1_N2;
		bcn_capture_ptp = BCN_CAPTURE_PTP;
		bcn_delta_val = BCN_DELTA_VAL;
	}
	bcn_cfg2_val = readq(bcn_reg_base + bcn_cfg2);
	bcn_cfg2_val |= BCN_DELTA_WRAP_MODE | BCN_DELTA_N1_FORMULA;
	writeq(bcn_cfg2_val, bcn_reg_base + bcn_cfg2);
	bcn_n2_len = bcn_cfg2_val & 0xFFFFFF;
	/* capture ptp and bcn timestamp using BCN_CAPTURE_CFG */
	writeq(CAPT_EN | CAPT_TRIG_SW, bcn_reg_base + bcn_capture_cfg);

	err = otx2_bcn_poll_reg(bcn_reg_base, bcn_capture_cfg, CAPT_EN, true);
	if (err) {
		pr_err("Timeout waiting for CAPT_EN to clear\n");
		return err;
	}

	bcn_n1_n2 = readq(bcn_reg_base + bcn_capture_n1_n2);
	ptp_clock = readq(bcn_reg_base + bcn_capture_ptp);
	if (!is_otx2)
		ptp_clock = cnf10k_ptp_convert_timestamp(ptp_clock);

	tsns = timecounter_cyc2time(time_counter, ptp_clock);

	/* Convert BCN timestamp to PTP timestamp in nanoseconds
	 * BCN clock has two counters.
	 * N1[63:24] is the frame counter, which increments every 10 ms.
	 * N2[23:0] is the universal time unit (UTU), which is 1.2288 GHz
	 * N2 ranges from 0 to 12288000(which corresponds to 10ms).
	 * The following calculation is used to convert BCN clock to
	 * nanoseconds.
	 * N1[63:24] * 10 * Nano seconds per millisecond +
	 * N2[23:0] * 10 * nanoseconds per millisecond / 12288000.
	 */

	bcn_ns = (bcn_n1_n2 >> 24) * 10 * NSEC_PER_MSEC;
	bcn_ns += (((bcn_n1_n2 & 0xFFFFFF) * 10 * NSEC_PER_MSEC) / bcn_n2_len);

	ptp_bcn_delta = tsns - (UTC_GPS_EPOCH_DIFF * NSEC_PER_SEC) - bcn_ns - sec_bcn_offset;
	if (ptp_bcn_delta < 0) {
		sign = 1;
		ptp_bcn_delta = -ptp_bcn_delta;
	}

	/* The reverse calculation needs to be followed to convert timestamp in
	 * nanoseconds to BCN Timestamp format
	 * N1[63:24] = delta / 10 msec.
	 * N2[23:0] = (delta % 10 msec) * 1.2288
	 */

	bcn_n1 = ptp_bcn_delta / (10 * NSEC_PER_MSEC);
	bcn_n2 = ((ptp_bcn_delta % (10 * NSEC_PER_MSEC)) * bcn_n2_len) / (10 * NSEC_PER_MSEC);

	if (sign) {
		bcn_n1 = 0xFFFFFFFFFF - bcn_n1;
		bcn_n2 = 0xFFFFFF - bcn_n2;
	}

	writeq(bcn_n1 << 24 | (bcn_n2 & 0xFFFFFF), bcn_reg_base + bcn_delta_val);

	bcn_cfg = readq(bcn_reg_base + bcn_cfg_off);
	bcn_cfg |= BCN_DELTA_EN;
	writeq(bcn_cfg, bcn_reg_base + bcn_cfg_off);

	err = otx2_bcn_poll_reg(bcn_reg_base, bcn_cfg_off, BCN_DELTA_EN, true);
	if (err) {
		pr_err("Timeout waiting for BCN_DELTA_EN to clear\n");
		return err;
	}

	return 0;
}

s64 bcn_ptp_delta(int ptp_phc_idx)
{
	u64 bcn_cfg2, bcn_capture_cfg, bcn_capture_n1_n2, bcn_capture_ptp_off;
	u64 bcn_capture_ptp, bcn_n1_n2, bcn_ns, tsns, bcn_n2_len;
	struct cnf10k_rfoe_drv_ctx *cnf10k_drv_ctx = NULL;
	struct cnf10k_rfoe_ndev_priv *cnf10k_priv;
	struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
	struct otx2_rfoe_ndev_priv *priv = NULL;
	struct timecounter *time_counter;
	void __iomem *bcn_reg_base;
	struct net_device *netdev;
	struct pci_dev *bphy_pdev;
	s32 sec_bcn_offset;
	int idx, err;
	bool is_otx2;
	s64 delta;

	bphy_pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
				   OTX2_BPHY_PCI_DEVICE_ID, NULL);

	if (bphy_pdev->subsystem_device == PCI_SUBSYS_DEVID_OCTX2_95XXN)
		is_otx2 = true;
	else
		is_otx2 = false;

	if (!is_otx2) {
		for (idx = 0; idx < CNF10K_RFOE_MAX_INTF; idx++) {
			cnf10k_drv_ctx = &cnf10k_rfoe_drv_ctx[idx];
			if (cnf10k_drv_ctx->valid) {
				netdev = cnf10k_drv_ctx->netdev;
				cnf10k_priv = netdev_priv(netdev);
				break;
			}
		}

		if (idx >= CNF10K_RFOE_MAX_INTF) {
			pr_err("Invalid PTP PHC index\n");
			return -ENODEV;
		}

		bcn_reg_base = cnf10k_priv->bcn_reg_base;
		time_counter = &cnf10k_priv->time_counter;
		sec_bcn_offset = cnf10k_priv->sec_bcn_offset;
		bcn_cfg2 = CNF10K_BCN_CFG2;
		bcn_capture_cfg = CNF10K_BCN_CAPTURE_CFG;
		bcn_capture_n1_n2 = CNF10K_BCN_CAPTURE_N1_N2;
		bcn_capture_ptp_off = CNF10K_BCN_CAPTURE_PTP;
	} else {
		for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
			drv_ctx = &rfoe_drv_ctx[idx];
			if (drv_ctx->valid) {
				netdev = drv_ctx->netdev;
				priv = netdev_priv(netdev);
				if (ptp_clock_index(priv->ptp_clock) != ptp_phc_idx)
					continue;
				else
					break;
			}
		}

		if (idx == RFOE_MAX_INTF) {
			pr_err("Invalid PTP PHC index\n");
			return -ENODEV;
		}

		bcn_reg_base = priv->bcn_reg_base;
		time_counter = &priv->time_counter;
		sec_bcn_offset = priv->sec_bcn_offset;
		bcn_cfg2 = BCN_CFG2;
		bcn_capture_cfg = BCN_CAPTURE_CFG;
		bcn_capture_n1_n2 = BCN_CAPTURE_N1_N2;
		bcn_capture_ptp_off = BCN_CAPTURE_PTP;
	}

	bcn_n2_len = readq(bcn_reg_base + bcn_cfg2) & 0xFFFFFF;
	/* capture ptp and bcn timestamp using BCN_CAPTURE_CFG */
	writeq(CAPT_EN | CAPT_TRIG_SW, bcn_reg_base + bcn_capture_cfg);

	err = otx2_bcn_poll_reg(bcn_reg_base, bcn_capture_cfg, CAPT_EN, true);
	if (err) {
		pr_err("Timeout waiting for CAPT_EN to clear\n");
		return err;
	}

	bcn_n1_n2 = readq(bcn_reg_base + bcn_capture_n1_n2);
	bcn_capture_ptp = readq(bcn_reg_base + bcn_capture_ptp_off);
	if (!is_otx2)
		bcn_capture_ptp = cnf10k_ptp_convert_timestamp(bcn_capture_ptp);

	tsns = timecounter_cyc2time(time_counter, bcn_capture_ptp);

	bcn_ns = (bcn_n1_n2 >> 24) * 10 * NSEC_PER_MSEC;
	bcn_ns += (((bcn_n1_n2 & 0xFFFFFF) * 10 * NSEC_PER_MSEC) / bcn_n2_len);

	delta = tsns + sec_bcn_offset - bcn_ns - (UTC_GPS_EPOCH_DIFF * NSEC_PER_SEC);

	return delta;
}

static long bcn_ptp_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	int ret;

	switch (cmd) {
	case IOCTL_BCN_PTP_SYNC:
	{
		struct bcn_ptp_cfg cfg;

		if (copy_from_user(&cfg, (void __user *)arg,
				   sizeof(struct bcn_ptp_cfg))) {
			pr_err("copy from user fault\n");
			ret = -EFAULT;
			break;
		}

		ret = bcn_ptp_sync(cfg.ptp_phc_idx);
		break;
	}
	case IOCTL_BCN_PTP_DELTA:
	{
		struct bcn_ptp_cfg cfg;

		if (copy_from_user(&cfg, (void __user *)arg,
				   sizeof(struct bcn_ptp_cfg))) {
			pr_err("copy from user fault\n");
			ret = -EFAULT;
			break;
		}

		cfg.delta = bcn_ptp_delta(cfg.ptp_phc_idx);

		if (copy_to_user((void __user *)(unsigned long)arg, &cfg,
				 sizeof(struct bcn_ptp_cfg))) {
			pr_err("copy to user fault\n");
			ret = -EFAULT;
			break;
		}
		ret = 0;
		break;
	}
	default:
	{
		pr_err("ioctl: no match\n");
		ret = -EINVAL;
	}
	}

	return ret;
}

static const struct file_operations bcn_ptp_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = bcn_ptp_ioctl,
};

int bcn_ptp_start(void)
{
	static struct device *bcn_ptp_device;
	int ret = 0;

	major_no = register_chrdev(0, BCN_DEVICE_NAME, &bcn_ptp_fops);
	if (major_no < 0) {
		pr_err("failed to register a major number for %s\n",
		       BCN_DEVICE_NAME);
		return major_no;
	}

	bcn_ptp_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(bcn_ptp_class)) {
		unregister_chrdev(major_no, BCN_DEVICE_NAME);
		return PTR_ERR(bcn_ptp_class);
	}

	bcn_ptp_device = device_create(bcn_ptp_class, NULL,
				       MKDEV(major_no, 0), NULL,
				       BCN_DEVICE_NAME);
	if (IS_ERR(bcn_ptp_device)) {
		class_destroy(bcn_ptp_class);
		unregister_chrdev(major_no, BCN_DEVICE_NAME);
		return PTR_ERR(bcn_ptp_device);
	}

	return ret;
}
