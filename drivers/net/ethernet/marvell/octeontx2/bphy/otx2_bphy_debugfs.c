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
