// SPDX-License-Identifier: GPL-2.0
/* Hardware device CSR Access driver
 * Copyright (C) 2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* This driver supports Read/Write of only OcteonTx2/OcteonTx3 HW device
 * config registers. Read/Write of System Registers are not supported.
 */

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/stddef.h>
#include <linux/debugfs.h>
#include <linux/arm-smccc.h>

#include "rvu_struct.h"
#include "rvu.h"
#include "mbox.h"

#define OCTEONTX_ACCESS_REG_SMCID 0xc2000fff

#define READ 0
#define WRITE 1

static bool size_32 = true;
static u64 reg_addr;
static int filevalue;
struct dentry *dirret;

#define DEVICE_NAME			"hw_access"
#define CLASS_NAME			"hw_access_class"

/* PCI device IDs */
#define	PCI_DEVID_OCTEONTX2_RVU_AF	0xA065

struct hw_reg_cfg {
	u64	regaddr; /* Register physical address within a hw device */
	u64	regval; /* Register value to be read or to write */
};

struct hw_ctx_cfg {
	u16	blkaddr;
	u16	pcifunc;
	union {
		u16	qidx;
		u16	aura;
	};
	u8	ctype;
	u8	op;
};

struct hw_cgx_info {
	u8	pf;
	u8	cgx_id;
	u8	lmac_id;
	u8	nix_idx;
};

struct hw_csr_mapping {
	void __iomem *reg_base;
	bool mapped;
};

struct hw_priv_data {
	struct hw_csr_mapping *map;
	u32 total_mappings;
	struct rvu *rvu;
	struct pci_dev *pdev;
};

struct hw_csr_lookup_tbl {
	u64 base;       /* Base BAR address for each HW */
	u64 size;	/* Size of mapping */
	u8 alpha;       /* Alpha component in CSRs */
	u8 alpha_shift; /* Alpha shift */
	u8 beta;	/* Beta component in CSRs */
	u8 beta_shift;  /* Beta shift */
	u64 mask;	/* Mask for extracting the CSR offsets */
};

const struct hw_csr_lookup_tbl lkp_tbl[] = {
	/* [BASE] [SIZE] [ALPHA] [ALPHA SHIFT] [BETA] [BETA SHIFT] [MASK] */
	/* RVU BAR0 */
	{ 0x840000000000, 0xa000000, 32, 28, 1,   0,  0xFFFFFFF },
	/* RVU BAR2 */
	{ 0x840200000000, 0x2000000, 32, 36, 129, 25, 0xFFFFFF },
	/* RST */
	{ 0x87E006000000, 0x10000,   1,  0,  1,   0,  0xFFFF },
	/* RPM */
	{ 0x87E0E0000000, 0x900000,  5,  24, 1,   0,  0xFFFFFF },
	/* NCB */
	{ 0x87E0F0000000, 0x100000,  3,  24, 1,   0,  0xFFFFF },
	/* LMC */
	{ 0x87E088000000, 0x10000,   6,  24, 1,   0,  0xFFFF },
};

#define HW_ACCESS_TYPE			120

#define HW_ACCESS_CSR_READ_IOCTL	_IO(HW_ACCESS_TYPE, 1)
#define HW_ACCESS_CSR_WRITE_IOCTL	_IO(HW_ACCESS_TYPE, 2)
#define HW_ACCESS_CTX_READ_IOCTL	_IO(HW_ACCESS_TYPE, 3)
#define HW_ACCESS_CGX_INFO_IOCTL	_IO(HW_ACCESS_TYPE, 4)

#define MAX_ALPHA	32
#define MAX_BETA	129

static struct class *hw_reg_class;
static int major_no;

/* Check if mapping already exists else create a new one */
static int
create_mapping(struct hw_priv_data *priv_data, void __iomem **reg_base,
	       int idx, u64 base, u64 size)
{
	struct hw_csr_mapping *map;

	map = (struct hw_csr_mapping *)(priv_data->map + idx);
	if (map->mapped != true) {
		map->reg_base = ioremap(base, size);
		if (!map->reg_base) {
			pr_err("Unable to map Physical Base Address\n");
			return -ENOMEM;
		}
		pr_debug("Mapping io addr %p at index %d\n", map->reg_base,
			 idx);

		priv_data->total_mappings++;
		map->mapped = true;
	}
	*reg_base = map->reg_base;

	return 0;
}

/* To access CSR space, mappings are setup in small chunks. Unique mapping is
 * identified based on HW (eg. RVU, RPM), alpha (PF in case of RVU, CGX in RPM),
 * beta (FUNC/VF in RVU) attributes. Since each HW may have different alpha/beta
 * components, sizes to map, masking the register offsets, a lookup table is
 * defined where each index represents different values for differetn HWs.
 */
static int
setup_csr_mapping(struct hw_priv_data *priv_data, u64 addr,
			void __iomem **reg_base, u64 *offset)
{
	int i, j, k, idx;
	u64 base = 0;

	for (i = 0; i < ARRAY_SIZE(lkp_tbl); i++) {
		for (j = 0; j < lkp_tbl[i].alpha; j++) {
			for (k = 0; k < lkp_tbl[i].beta; k++) {
				/* Base address is prepared based on different
				 * attr and then compared with user address if
				 * it falls in the range.
				 */
				base = lkp_tbl[i].base |
					((u64)j << lkp_tbl[i].alpha_shift) |
					((u64)k << lkp_tbl[i].beta_shift);

				if ((addr < base) || (addr > (u64)(u8 *)base +
						      lkp_tbl[i].size))
					continue;

				/* Found the base address range for user addr,
				 * create a new mapping at the specific index.
				 */
				idx = ((i * MAX_ALPHA * MAX_BETA) +
				       (j * MAX_BETA) + k);

				if (create_mapping(priv_data, reg_base, idx,
						   base, lkp_tbl[i].size))
					goto err;

				/* Extract the register offset from user addr. */
				*offset = addr & lkp_tbl[i].mask;
				return 0;
			}

		}
	}

err:
	/* User address not in any range of HW defined in lookup table */
	pr_err("Address [0x%llx] out of range\n", addr);
	return -1;
}


static void
destroy_mapping(struct hw_priv_data *priv_data, int idx)
{
	struct hw_csr_mapping *map;

	map = (struct hw_csr_mapping *)(priv_data->map + idx);
	if (map->mapped == true) {
		pr_debug("Unmapping io addr %p at index %d\n", map->reg_base,
			 idx);
		iounmap(map->reg_base);
		priv_data->total_mappings--;
		map->mapped = false;
	}
}

/* Releasing the mappings */
static void
release_csr_mapping(struct hw_priv_data *priv_data)
{
	int i, j, k, idx;

	for (i = 0 ; i < ARRAY_SIZE(lkp_tbl); i++) {
		for (j = 0; j < lkp_tbl[i].alpha; j++) {
			for (k = 0; k < lkp_tbl[i].beta; k++) {
				idx = ((i * MAX_ALPHA * MAX_BETA) +
				       (j * MAX_BETA) + k);
				destroy_mapping(priv_data, idx);
			}
		}
	}

	if (priv_data->total_mappings != 0)
		pr_err("All mappings not released, %d are remaining\n",
		       priv_data->total_mappings);
}

static int hw_access_open(struct inode *inode, struct file *filp)
{
	struct hw_priv_data *priv_data = NULL;

	priv_data = kzalloc(sizeof(*priv_data), GFP_KERNEL);
	if (!priv_data)
		return -ENOMEM;

	priv_data->map = kzalloc(ARRAY_SIZE(lkp_tbl) * MAX_ALPHA * MAX_BETA *
				 sizeof(struct hw_csr_mapping), GFP_KERNEL);
	if (!priv_data->map)
		return -ENOMEM;

	priv_data->pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
					 PCI_DEVID_OCTEONTX2_RVU_AF, NULL);
	priv_data->rvu = pci_get_drvdata(priv_data->pdev);

	filp->private_data = priv_data;

	return 0;
}

static int
hw_access_csr_read(struct hw_priv_data *priv_data, unsigned long arg)
{
	void __iomem *reg_base;
	struct hw_reg_cfg reg_cfg;
	u64 regoff;

	if (copy_from_user(&reg_cfg, (void __user *)arg,
			   sizeof(struct hw_reg_cfg))) {
		pr_err("Read Fault copy from user\n");

		return -EFAULT;
	}

	if (setup_csr_mapping(priv_data, reg_cfg.regaddr, &reg_base, &regoff))
		return -1;

	reg_cfg.regval = readq(reg_base + regoff);

	if (copy_to_user((void __user *)(unsigned long)arg,
			 &reg_cfg,
			 sizeof(struct hw_reg_cfg))) {
		pr_err("Fault in copy to user\n");

		return -EFAULT;
	}
	return 0;
}

static int
hw_access_csr_write(struct hw_priv_data *priv_data, unsigned long arg)
{
	struct hw_reg_cfg reg_cfg;
	void __iomem *reg_base;
	u64 regoff;

	if (copy_from_user(&reg_cfg, (void __user *)arg,
			   sizeof(struct hw_reg_cfg))) {
		pr_err("Write Fault in copy from user\n");

		return -EFAULT;
	}

	/* Only 64 bit reads/writes are allowed */
	if (setup_csr_mapping(priv_data, reg_cfg.regaddr, &reg_base, &regoff))
		return -1;

	writeq(reg_cfg.regval, reg_base + regoff);

	return 0;
}

static int
hw_access_nix_ctx_read(struct rvu *rvu, struct hw_ctx_cfg *ctx_cfg,
		       unsigned long arg)
{
	struct nix_aq_enq_req aq_req;
	struct nix_aq_enq_rsp rsp;

	memset(&aq_req, 0, sizeof(struct nix_aq_enq_req));
	aq_req.hdr.pcifunc = ctx_cfg->pcifunc;
	aq_req.ctype = ctx_cfg->ctype;
	aq_req.op = ctx_cfg->op;
	aq_req.qidx = ctx_cfg->qidx;

	if (rvu_mbox_handler_nix_aq_enq(rvu, &aq_req, &rsp)) {
		pr_err("Failed to read the context\n");
		return -EINVAL;
	}

	if (copy_to_user((struct nix_aq_enq_rsp *)arg,
			 &rsp, sizeof(struct nix_aq_enq_rsp))) {
		pr_err("Fault in copy to user\n");
		return -EFAULT;
	}

	return 0;
}

static int
hw_access_npa_ctx_read(struct rvu *rvu, struct hw_ctx_cfg *ctx_cfg,
		       unsigned long arg)
{
	struct npa_aq_enq_req aq_req;
	struct npa_aq_enq_rsp rsp;

	memset(&aq_req, 0, sizeof(struct npa_aq_enq_req));
	aq_req.hdr.pcifunc = ctx_cfg->pcifunc;
	aq_req.ctype = ctx_cfg->ctype;
	aq_req.op = ctx_cfg->op;
	aq_req.aura_id = ctx_cfg->aura;

	if (rvu_mbox_handler_npa_aq_enq(rvu, &aq_req, &rsp)) {
		pr_err("Failed to read the npa context\n");
		return -EINVAL;
	}

	if (copy_to_user((struct npa_aq_enq_rsp *)arg,
			 &rsp, sizeof(struct npa_aq_enq_rsp))) {
		pr_err("Fault in copy to user\n");
		return -EFAULT;
	}

	return 0;
}

static int
hw_access_ctx_read(struct rvu *rvu, unsigned long arg)
{
	struct hw_ctx_cfg ctx_cfg;
	int rc;

	if (copy_from_user(&ctx_cfg, (struct hw_ctx_cfg *)arg,
			   sizeof(struct hw_ctx_cfg))) {
		pr_err("Write Fault in copy from user\n");
		return -EFAULT;
	}

	switch (ctx_cfg.blkaddr) {
	case BLKADDR_NIX0:
	case BLKADDR_NIX1:
		rc = hw_access_nix_ctx_read(rvu, &ctx_cfg, arg);
		break;
	case BLKADDR_NPA:
		rc = hw_access_npa_ctx_read(rvu, &ctx_cfg, arg);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int
hw_access_cgx_info(struct rvu *rvu, unsigned long arg)
{
	struct hw_cgx_info cgx_info;
	struct rvu_pfvf *pfvf;
	u8 cgx_id, lmac_id, pf;
	u16 pcifunc;

	if (copy_from_user(&cgx_info, (void __user *)arg, sizeof(struct hw_cgx_info))) {
		pr_err("Reading PF value failed: copy from user\n");
		return -EFAULT;
	}

	pf = cgx_info.pf;
	if (!(pf >= PF_CGXMAP_BASE && pf <= rvu->cgx_mapped_pfs)) {
		pr_err("Invalid PF value %d\n", pf);
		return -EFAULT;
	}

	pcifunc = pf << 10;
	pfvf = &rvu->pf[pf];
	rvu_get_cgx_lmac_id(rvu->pf2cgxlmac_map[pf], &cgx_id,
			    &lmac_id);
	cgx_info.cgx_id = cgx_id;
	cgx_info.lmac_id = lmac_id;
	cgx_info.nix_idx = (pfvf->nix_blkaddr == BLKADDR_NIX0) ? 0 : 1;

	if (copy_to_user((void __user *)(unsigned long)arg,
			 &cgx_info,
			 sizeof(struct hw_cgx_info))) {
		pr_err("Fault in copy to user\n");

		return -EFAULT;
	}
	return 0;
}

static long hw_access_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	struct hw_priv_data *priv_data = filp->private_data;
	struct rvu *rvu = priv_data->rvu;

	switch (cmd) {
	case HW_ACCESS_CSR_READ_IOCTL:
		return hw_access_csr_read(priv_data, arg);

	case HW_ACCESS_CSR_WRITE_IOCTL:
		return hw_access_csr_write(priv_data, arg);

	case HW_ACCESS_CTX_READ_IOCTL:
		return hw_access_ctx_read(rvu, arg);

	case HW_ACCESS_CGX_INFO_IOCTL:
		return hw_access_cgx_info(rvu, arg);

	default:
		pr_info("Invalid IOCTL: %d\n", cmd);

		return -EINVAL;
	}
}

static int hw_access_release(struct inode *inode, struct file *filp)
{
	struct hw_priv_data *priv_data = filp->private_data;

	release_csr_mapping(priv_data);
	pci_dev_put(priv_data->pdev);
	filp->private_data = NULL;
	kfree(priv_data->map);
	priv_data->map = NULL;
	kfree(priv_data);
	priv_data = NULL;

	return 0;
}

static ssize_t reg_data_read(struct file *fp, char __user *user_buffer,
			     size_t count, loff_t *position)
{
	struct arm_smccc_res smc_resp;
	u8 buf[100];
	unsigned int len;

	if (!reg_addr) {
		pr_err("Secure Reg Read failure : Invalid Reg_Addr\n");
		return -EFAULT;
	}

	arm_smccc_smc(OCTEONTX_ACCESS_REG_SMCID, 0,
		      reg_addr, READ, size_32, 0, 0, 0, &smc_resp);
	if (smc_resp.a0 != SMCCC_RET_SUCCESS)
		pr_err("Secure Reg Read failure\n");

	if (size_32)
		len = scnprintf(buf, sizeof(buf), "0x%llx:0x%x\n", reg_addr,
				(u32)smc_resp.a1);
	else
		len = scnprintf(buf, sizeof(buf), "0x%llx:0x%llx\n", reg_addr,
				(u64)smc_resp.a1);

	return simple_read_from_buffer(user_buffer, count, position, buf, len);
}

static ssize_t reg_data_write(struct file *fp, const char __user *user_buffer,
			      size_t count, loff_t *position)
{
	int ret;
	struct arm_smccc_res smc_resp;
	u64 reg_data;

	if (!reg_addr) {
		pr_err("Secure Reg Write failure : Invalid Reg_Addr\n");
		return -EFAULT;
	}

	if (size_32) {
		ret = kstrtou32_from_user(user_buffer, count, 0,
					  (void *)&reg_data);
		if (ret)
			return ret;
	} else {
		ret = kstrtou64_from_user(user_buffer, count, 0,
					  &reg_data);
		if (ret)
			return ret;
	}
	arm_smccc_smc(OCTEONTX_ACCESS_REG_SMCID, reg_data,
		      reg_addr, WRITE, size_32, 0, 0, 0, &smc_resp);
	if (smc_resp.a0 != SMCCC_RET_SUCCESS)
		pr_err("Secure Reg Write failure\n");
	return count;
}

static const struct file_operations mmap_fops = {
	.open = hw_access_open,
	.unlocked_ioctl = hw_access_ioctl,
	.release = hw_access_release,
};

static const struct file_operations fops_reg_data = {
	.read = reg_data_read,
	.write = reg_data_write,
};

static int __init hw_access_module_init(void)
{
	static struct device *hw_reg_device;

	major_no = register_chrdev(0, DEVICE_NAME, &mmap_fops);
	if (major_no < 0) {
		pr_err("failed to register a major number for %s\n",
		       DEVICE_NAME);
		return major_no;
	}

	hw_reg_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(hw_reg_class)) {
		unregister_chrdev(major_no, DEVICE_NAME);
		return PTR_ERR(hw_reg_class);
	}

	hw_reg_device = device_create(hw_reg_class, NULL,
				      MKDEV(major_no, 0), NULL,
				      DEVICE_NAME);
	if (IS_ERR(hw_reg_device)) {
		class_destroy(hw_reg_class);
		unregister_chrdev(major_no, DEVICE_NAME);
		return PTR_ERR(hw_reg_device);
	}

	/* create a directory sec_access in debufs */
	dirret = debugfs_create_dir("sec_access", NULL);
	/* create file to read/write 32/64 bit data from/to reg_addr */
	debugfs_create_file("reg_data", 0644, dirret, &filevalue,
			    &fops_reg_data);
	/* create file for reg_addr from where 32/64 bit data is read/written */
	debugfs_create_x64("reg_addr", 0644, dirret, &reg_addr);
	/* create file for choosing between 32 & 64 bit data */
	debugfs_create_bool("size_32", 0644, dirret, &size_32);
	return 0;
}

static void __exit hw_access_module_exit(void)
{
	device_destroy(hw_reg_class, MKDEV(major_no, 0));
	class_destroy(hw_reg_class);
	unregister_chrdev(major_no, DEVICE_NAME);
	debugfs_remove_recursive(dirret);
}

module_init(hw_access_module_init);
module_exit(hw_access_module_exit);
MODULE_AUTHOR("Marvell International Ltd.");
MODULE_LICENSE("GPL v2");
