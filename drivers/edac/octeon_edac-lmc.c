/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2009-2017 Wind River Systems,
 *   written by Ralf Baechle <ralf@linux-mips.org>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/edac.h>
#include <linux/nodemask.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/stop_machine.h>
#include <linux/sizes.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/circ_buf.h>

#include <asm/page.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-lmcx-defs.h>
#include <asm/octeon/cvmx-atomic.h>


#include "edac_module.h"

#define OCTEON_MAX_MC			8
#define OCTEON_MAX_SOCKETS		2	/* Nodes */
#define MAX_CHANNELS_PER_BRANCH		2
#define MAX_SLOTS			4

#define _Db(x) (x)		/** Data Bit */
#define _Ec(x) (0x100+x)	/** ECC Bit */
#define _Ad(x) (0x200+x)	/** Address Bit */
#define _Bu(x) (0x400+x)	/** Burst */
#define _Un()  (-1)		/** Unused */

/** Use ECC Code as index to lookup corrected bit */
static const short lmc_syndrome_bits[256] = {
	/* 00: */ _Un(),   _Ec(0),  _Ec(1),  _Un(),
	/* 04: */ _Ec(2),  _Un(),   _Un(),   _Un(),
	/* 08: */ _Ec(3),  _Un(),   _Un(),   _Db(17),
	/* 0C: */ _Un(),   _Un(),   _Db(16), _Un(),
	/* 10: */ _Ec(4),  _Un(),   _Un(),   _Db(18),
	/* 14: */ _Un(),   _Db(19), _Db(20), _Un(),
	/* 18: */ _Un(),   _Db(21), _Db(22), _Un(),
	/* 1C: */ _Db(23), _Un(),   _Un(),   _Un(),
	/* 20: */ _Ec(5),  _Un(),   _Un(),   _Db(8),
	/* 24: */ _Un(),   _Db(9),  _Db(10), _Un(),
	/* 28: */ _Un(),   _Db(11), _Db(12), _Un(),
	/* 2C: */ _Db(13), _Un(),   _Un(),   _Un(),
	/* 30: */ _Un(),   _Db(14), _Un(),   _Un(),
	/* 34: */ _Db(15), _Un(),   _Un(),   _Un(),
	/* 38: */ _Un(),   _Un(),   _Un(),   _Un(),
	/* 3C: */ _Un(),   _Un(),   _Ad(34), _Un(),
	/* 40: */ _Ec(6),  _Un(),   _Un(),   _Un(),
	/* 44: */ _Un(),   _Ad(7),  _Ad(8),  _Un(),
	/* 48: */ _Un(),   _Ad(9),  _Db(33), _Un(),
	/* 4C: */ _Ad(10), _Un(),   _Un(),   _Db(32),
	/* 50: */ _Un(),   _Ad(11), _Db(34), _Un(),
	/* 54: */ _Db(35), _Un(),   _Un(),   _Db(36),
	/* 58: */ _Db(37), _Un(),   _Un(),   _Db(38),
	/* 5C: */ _Un(),   _Db(39), _Ad(12), _Un(),
	/* 60: */ _Un(),   _Ad(13), _Db(56), _Un(),
	/* 64: */ _Db(57), _Un(),   _Un(),   _Db(58),
	/* 68: */ _Db(59), _Un(),   _Un(),   _Db(60),
	/* 6C: */ _Un(),   _Db(61), _Ad(14), _Un(),
	/* 70: */ _Db(62), _Un(),   _Un(),   _Ad(15),
	/* 74: */ _Un(),   _Db(63), _Ad(16), _Un(),
	/* 78: */ _Un(),   _Ad(17), _Ad(18), _Un(),
	/* 7C: */ _Ad(19), _Un(),   _Ad(20), _Un(),
	/* 80: */ _Ec(7),  _Un(),   _Un(),   _Ad(21),
	/* 84: */ _Un(),   _Ad(22), _Ad(23), _Un(),
	/* 88: */ _Un(),   _Ad(24), _Db(49), _Un(),
	/* 8C: */ _Ad(25), _Un(),   _Un(),   _Db(48),
	/* 90: */ _Un(),   _Ad(26), _Db(50), _Un(),
	/* 94: */ _Db(51), _Un(),   _Un(),   _Db(52),
	/* 98: */ _Db(53), _Un(),   _Un(),   _Db(54),
	/* 9C: */ _Un(),   _Db(55), _Ad(27), _Un(),
	/* A0: */ _Un(),   _Ad(28), _Db(40), _Un(),
	/* A4: */ _Db(41), _Un(),   _Un(),   _Db(42),
	/* A8: */ _Db(43), _Un(),   _Un(),   _Db(44),
	/* 8C: */ _Un(),   _Db(45), _Ad(29), _Un(),
	/* B0: */ _Db(46), _Un(),   _Un(),   _Ad(30),
	/* B4: */ _Un(),   _Db(47), _Ad(31), _Un(),
	/* B8: */ _Un(),   _Ad(32), _Ad(33), _Un(),
	/* BC: */ _Un(),   _Un(),   _Un(),   _Un(),
	/* C0: */ _Un(),   _Un(),   _Un(),   _Un(),
	/* C4: */ _Un(),   _Un(),   _Un(),   _Un(),
	/* C8: */ _Un(),   _Un(),   _Un(),   _Db(1),
	/* CC: */ _Un(),   _Un(),   _Db(0),  _Un(),
	/* D0: */ _Un(),   _Un(),   _Un(),   _Db(2),
	/* D4: */ _Un(),   _Db(3),  _Db(4),  _Un(),
	/* D8: */ _Un(),   _Db(5),  _Db(6),  _Un(),
	/* DC: */ _Db(7),  _Un(),   _Un(),   _Un(),
	/* E0: */ _Un(),   _Un(),   _Un(),   _Db(24),
	/* E4: */ _Un(),   _Db(25), _Db(26), _Un(),
	/* E8: */ _Un(),   _Db(27), _Db(28), _Un(),
	/* EC: */ _Db(29), _Un(),   _Un(),   _Un(),
	/* F0: */ _Un(),   _Db(30), _Un(),   _Un(),
	/* F4: */ _Db(31), _Un(),   _Un(),   _Un(),
	/* F8: */ _Un(),   _Un(),   _Un(),   _Un(),
	/* FC: */ _Un(),   _Un(),   _Un(),   _Un()
};

#define RING_ENTRIES			8
#define	MAX_SYNDROME_REGS		4

struct debugfs_entry {
	const char *name;
	umode_t mode;
	const struct file_operations fops;
};

struct lmc_err_ctx {
	u64 reg_int;
	u64 reg_fadr;
	u64 reg_nxm_fadr;
	u64 reg_scram_fadr;
	u64 reg_ecc_synd;
};

struct octeon_lmc {
	int lmc;			/** LMC number */

	atomic_t ecc_int;
	u64 mask0;
	u64 mask2;
	u64 parity_test;
	u64 node;
	int xbits;
	int bank_width;
	int pbank_lsb;
	int dimm_lsb;
	int rank_lsb;
	int row_lsb;
	int col_hi_lsb;
	int xor_bank;
	int l2c_alias;

	struct page *mem;
	struct lmc_err_ctx err_ctx[RING_ENTRIES];
	unsigned long ring_head;
	unsigned long ring_tail;
};

/* NOTE: remove this after upgrading to a newer kernel */
#ifndef VERIFY_OCTAL_PERMISSIONS
/* Permissions on a sysfs file: you didn't miss the 0 prefix did you? */
#define VERIFY_OCTAL_PERMISSIONS(perms)                                       \
	(BUILD_BUG_ON_ZERO((perms) < 0) +                                     \
	 BUILD_BUG_ON_ZERO((perms) > 0777) +                                  \
	 /* USER_READABLE >= GROUP_READABLE >= OTHER_READABLE */              \
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 4) < (((perms) >> 3) & 4)) +     \
	 BUILD_BUG_ON_ZERO((((perms) >> 3) & 4) < ((perms) & 4)) +            \
	 /* USER_WRITABLE >= GROUP_WRITABLE */                                \
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 2) < (((perms) >> 3) & 2)) +     \
	 /* OTHER_WRITABLE?  Generally considered a bad idea. */              \
	 BUILD_BUG_ON_ZERO((perms) & 2) +                                     \
	 (perms))
#endif

#define ring_pos(pos, size) ((pos) & (size - 1))

#define DEBUGFS_STRUCT(_name, _mode, _write, _read)			    \
static struct debugfs_entry debugfs_##_name = {				    \
	.name = __stringify(_name),					    \
	.mode = VERIFY_OCTAL_PERMISSIONS(_mode),			    \
	.fops = {							    \
		.open = simple_open,					    \
		.write = _write,					    \
		.read  = _read,						    \
		.llseek = generic_file_llseek,				    \
	},								    \
}

#define DEBUGFS_FIELD_ATTR(_type, _field)				    \
static ssize_t octeon_##_type##_##_field##_read(struct file *file,	    \
					     char __user *data,		    \
					     size_t count, loff_t *ppos)    \
{									    \
	struct octeon_##_type *pdata = file->private_data;		    \
	char buf[20];							    \
									    \
	snprintf(buf, count, "0x%016llx", pdata->_field);		    \
	return simple_read_from_buffer(data, count, ppos,		    \
				       buf, sizeof(buf));		    \
}									    \
									    \
static ssize_t octeon_##_type##_##_field##_write(struct file *file,	    \
					     const char __user *data,	    \
					     size_t count, loff_t *ppos)    \
{									    \
	struct octeon_##_type *pdata = file->private_data;		    \
	int res;							    \
									    \
	res = kstrtoull_from_user(data, count, 0, &pdata->_field);	    \
									    \
	return res ? res : count;					    \
}									    \
									    \
DEBUGFS_STRUCT(_field, 0600,						    \
	       octeon_##_type##_##_field##_write,			    \
	       octeon_##_type##_##_field##_read)			    \

#define DEBUGFS_REG_ATTR(_type, _name, _reg)				    \
static ssize_t octeon_##_type##_##_name##_read(struct file *file,	    \
					    char __user *data,		    \
					    size_t count, loff_t *ppos)	    \
{									    \
	struct octeon_##_type *pdata = file->private_data;		    \
	char buf[20];							    \
									    \
	sprintf(buf, "0x%016llx", readq(pdata->regs + _reg));		    \
	return simple_read_from_buffer(data, count, ppos,		    \
				       buf, sizeof(buf));		    \
}									    \
									    \
static ssize_t octeon_##_type##_##_name##_write(struct file *file,	    \
					    const char __user *data,	    \
					    size_t count, loff_t *ppos)     \
{									    \
	struct octeon_##_type *pdata = file->private_data;		    \
	u64 val;							    \
	int res;							    \
									    \
	res = kstrtoull_from_user(data, count, 0, &val);		    \
									    \
	if (!res) {							    \
		writeq(val, pdata->regs + _reg);			    \
		res = count;						    \
	}								    \
									    \
	return res;							    \
}									    \
									    \
DEBUGFS_STRUCT(_name, 0600,						    \
	       octeon_##_type##_##_name##_write,			    \
	       octeon_##_type##_##_name##_read)

#define LMC_DEBUGFS_ENT(_field)	DEBUGFS_FIELD_ATTR(lmc, _field)

static inline unsigned long get_bits(unsigned long data, int pos, int width)
{
	return (data >> pos) & ((1 << width) - 1);
}

#define TEST_PATTERN	0xa5

static int inject_lmc_ecc_fn(void *arg)
{
	struct octeon_lmc *lmc = arg;
	uintptr_t addr, phys;
	unsigned int cline_size = cache_line_size();
	const unsigned int lines = PAGE_SIZE / cline_size;
	unsigned int i, cl_idx;

	addr = (uintptr_t)page_address(lmc->mem);
	phys = (uintptr_t)page_to_phys(lmc->mem);

	cl_idx = (phys & 0x7f) >> 4;
	lmc->parity_test &= ~(7ULL << 8);
	lmc->parity_test |= (cl_idx << 8);

	barrier();
	CVMX_SYNCW;

	cvmx_write_csr_node(lmc->node, CVMX_LMCX_CHAR_MASK0(lmc->lmc),
			    lmc->mask0);
	cvmx_write_csr_node(lmc->node, CVMX_LMCX_CHAR_MASK2(lmc->lmc),
			    lmc->mask2);
	cvmx_write_csr_node(lmc->node, CVMX_LMCX_ECC_PARITY_TEST(lmc->lmc),
			    lmc->parity_test);
	CVMX_SYNCW;

	for (i = 0; i < lines; i++) {
		memset((void *)addr, TEST_PATTERN, cline_size);
		CVMX_SYNCW;
		CVMX_CACHE_L2HWB(addr, 0);
		barrier();
	}
	cvmx_write_csr_node(lmc->node, CVMX_LMCX_CHAR_MASK0(lmc->lmc), 0);
	cvmx_write_csr_node(lmc->node, CVMX_LMCX_CHAR_MASK2(lmc->lmc), 0);
	cvmx_write_csr_node(lmc->node, CVMX_LMCX_ECC_PARITY_TEST(lmc->lmc), 0);
	CVMX_SYNCW;
	return 0;
}

static ssize_t octeon_lmc_inject_ecc_write(struct file *file,
					   const char __user *data,
					   size_t count, loff_t *ppos)
{
	struct octeon_lmc *lmc = file->private_data;

	unsigned int cline_size = cache_line_size();
	u8 tmp[cline_size];
	void __iomem *addr;
	unsigned int offs, timeout = 100000;

	atomic_set(&lmc->ecc_int, 0);

	lmc->mem = alloc_pages_node(lmc->node, GFP_KERNEL, 0);

	if (!lmc->mem)
		return -ENOMEM;

	addr = page_address(lmc->mem);

	while (!atomic_read(&lmc->ecc_int) && timeout--) {
		stop_machine(*inject_lmc_ecc_fn, lmc, NULL);

		for (offs = 0; offs < PAGE_SIZE; offs += sizeof(tmp)) {
			/* Do a load from the previously rigged location.
			 * This should generate an error interrupt.
			 */
			memcpy(tmp, addr + offs, cline_size);
			CVMX_SYNC;
		}
	}

	__free_pages(lmc->mem, 0);

	return count;
}

LMC_DEBUGFS_ENT(mask0);
LMC_DEBUGFS_ENT(mask2);
LMC_DEBUGFS_ENT(parity_test);

DEBUGFS_STRUCT(inject_ecc, 0200, octeon_lmc_inject_ecc_write, NULL);

struct debugfs_entry *lmc_dfs_ents[] = {
	&debugfs_mask0,
	&debugfs_mask2,
	&debugfs_parity_test,
	&debugfs_inject_ecc,
};

#ifdef CONFIG_EDAC_DEBUG
static int octeon_create_debugfs_nodes(struct dentry *parent,
				       struct debugfs_entry *attrs[],
				       void *data, size_t num)
{
	int i;
	struct dentry *ent;

	if (!IS_ENABLED(CONFIG_EDAC_DEBUG))
		return 0;
	if (!parent)
		return -ENOENT;

	for (i = 0; i < num; i++) {
		ent = debugfs_create_file(attrs[i]->name, attrs[i]->mode,
					  parent, data, &attrs[i]->fops);
		if (!ent)
			break;
	}

	return i;
}
#endif

static void octeon_lmc_edac_poll(struct mem_ctl_info *mci)
{
	union cvmx_lmcx_mem_cfg0 cfg0;
	bool do_clear = false;
	char msg[64];

	cfg0.u64 = cvmx_read_csr(CVMX_LMCX_MEM_CFG0(mci->mc_idx));
	if (cfg0.s.sec_err || cfg0.s.ded_err) {
		union cvmx_lmcx_fadr fadr;
		fadr.u64 = cvmx_read_csr(CVMX_LMCX_FADR(mci->mc_idx));
		snprintf(msg, sizeof(msg),
			 "DIMM %d rank %d bank %d row %d col %d",
			 fadr.cn30xx.fdimm, fadr.cn30xx.fbunk,
			 fadr.cn30xx.fbank, fadr.cn30xx.frow, fadr.cn30xx.fcol);
	}

	if (cfg0.s.sec_err) {
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");
		cfg0.s.sec_err = -1;	/* Done, re-arm */
		do_clear = true;
	}

	if (cfg0.s.ded_err) {
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");
		cfg0.s.ded_err = -1;	/* Done, re-arm */
		do_clear = true;
	}
	if (do_clear)
		cvmx_write_csr(CVMX_LMCX_MEM_CFG0(mci->mc_idx), cfg0.u64);
}

static void octeon_lmc_edac_poll_o3(struct mem_ctl_info *mci)
{
	struct device *dev = &mci->dev;
	struct octeon_edac_lmc_data *lmc_data;
	union cvmx_lmcx_config lmc_config;
	union cvmx_lmcx_int lmc_int;
	union cvmx_lmcx_fadr fadr;
	union cvmx_lmcx_ecc_synd ecc_synd;
	union cvmx_l2c_ctl l2c_ctl;
	union cvmx_lmcx_ddr_pll_ctl lmc_ddr_pll_ctl;
	u64 fadr_physical;
	u64 fadr_c;
	u64 fadr_xkphys;
	int interface_bits = 0;
	int row_bits;
	int col_bits;
	int rank_bits;
	int bank_bits;
	int rmask;
	int cmask;
	int int_mask;
	int pbank_lsb;
	int row_lsb;
	int lmc = mci->mc_idx;
	int sec_err;
	int ded_err;
	int syndrome = -1;
	int phase;
	int i;
	int bit;
	int node = 0;
	char msg[128];
	bool do_clear = false;

	lmc_data = dev_get_platdata(mci->pdev);
	if (!lmc_data) {
		dev_err(dev, "Error: platform data is NULL\n");
		return;
	}
	lmc = lmc_data->lmc;
	node = lmc_data->node;

	lmc_int.u64 = cvmx_read_csr_node(node, CVMX_LMCX_INT(lmc));
	fadr.u64 = cvmx_read_csr_node(node, CVMX_LMCX_FADR(lmc));
	ecc_synd.u64 = cvmx_read_csr_node(node, CVMX_LMCX_ECC_SYND(lmc));
	lmc_config.u64 = cvmx_read_csr_node(node, CVMX_LMCX_CONFIG(lmc));
	lmc_ddr_pll_ctl.u64 = cvmx_read_csr_node(node,
						 CVMX_LMCX_DDR_PLL_CTL(lmc));
	l2c_ctl.u64 = cvmx_read_csr_node(node, CVMX_L2C_CTL);

	sec_err = lmc_int.s.sec_err;
	ded_err = lmc_int.s.ded_err;
	/* Double bit errors take precedence */
	phase = ded_err ? ded_err : sec_err;

	if (lmc_ddr_pll_ctl.s.ddr4_mode && lmc_config.s.bg2_enable)
		bank_bits = 4;
	else
		bank_bits = 3;

	/* The err mask should contain multiple failures.  Detect the first
	 * failing 64b chunk to convert the mask into the phase that
	 * corresponds to the information in FADR.
	 */
	for (i = 0; i < 4; i++) {
		if ((phase >> i) & 1)
			break;
	}
	phase = i;
	switch (phase) {
	case 0:
		syndrome = ecc_synd.s.mrdsyn0;
		break;
	case 1:
		syndrome = ecc_synd.s.mrdsyn1;
		break;
	case 2:
		syndrome = ecc_synd.s.mrdsyn2;
		break;
	case 3:
		syndrome = ecc_synd.s.mrdsyn3;
		break;
	}

	if (OCTEON_IS_MODEL(OCTEON_CN78XX) || OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		/* Detect four-lmc mode */
		union cvmx_lmcx_dll_ctl2 ctl2;

		ctl2.u64 = cvmx_read_csr_node(node, CVMX_LMCX_DLL_CTL2(3));
		interface_bits = 1 + (ctl2.cn78xx.quad_dll_ena | ctl2.cn78xx.intf_en);
	} else if (OCTEON_IS_MODEL(OCTEON_CN73XX) || OCTEON_IS_MODEL(OCTEON_CNF75XX)) {
		/* Detect two-lmc mode */
		union cvmx_lmcx_dll_ctl2 ctl2;

		ctl2.u64 = cvmx_read_csr(CVMX_LMCX_DLL_CTL2(1));
		interface_bits = (ctl2.cn73xx.intf_en | ctl2.cn73xx.quad_dll_ena);
	}
		

	rank_bits = lmc_config.s.rank_ena;
	pbank_lsb = lmc_config.s.pbank_lsb + 28 - rank_bits;

	row_lsb = lmc_config.s.row_lsb + 14;
	row_bits = pbank_lsb - row_lsb;
	col_bits = row_lsb - bank_bits - 3;

	cmask = (1 << col_bits) - 1;
	rmask = (1 << row_bits) - 1;
	int_mask = (1 << interface_bits) - 1;

	if (OCTEON_IS_OCTEON3()) {
		fadr_physical = (u64) fadr.cn73xx.fdimm <<
				(rank_bits + pbank_lsb + interface_bits);
		fadr_physical |= (u64) fadr.cn73xx.fbunk << (pbank_lsb + interface_bits);
		fadr_physical |= (u64) (fadr.cn73xx.frow & rmask) << (row_lsb + interface_bits);
		fadr_physical |= (u64) (fadr.cn73xx.fcol & 0xf) << 3;
		fadr_physical |= (u64) fadr.cn73xx.fbank << (7 + interface_bits);
		fadr_physical |= (u64) ((fadr.cn73xx.fcol & cmask) >> 4) <<
				(7 + bank_bits + interface_bits);
		if (!l2c_ctl.s.disidxalias) {
			fadr_c = (lmc ^ (fadr_physical >> 12) ^
				(fadr_physical >> 20)) & int_mask;
			fadr_physical |= fadr_c << 7;
		}
	} else {
		union cvmx_lmcx_control lmc_control;
		lmc_control.u64 = cvmx_read_csr_node(node, CVMX_LMCX_CONTROL(lmc));
		fadr_physical = (u64) lmc << 7;
		fadr_physical |= (u64) fadr.cn63xx.fdimm << (pbank_lsb + interface_bits);
		fadr_physical |= (u64) fadr.cn63xx.fbunk << (pbank_lsb + interface_bits - 1);
		fadr_physical |= (u64) (fadr.cn63xx.frow & rmask) << (row_lsb + interface_bits);
		fadr_physical |= (u64) (fadr.cn63xx.fcol & 0xf) << 3;
		fadr_physical |= (u64) ((fadr.cn63xx.fcol & cmask) >> 4) << (10 + interface_bits);
		if (lmc_control.s.xor_bank)
			fadr_physical |= (u64) (fadr.cn63xx.fbank ^
				 ((fadr_physical >> (12 + interface_bits)) & 7)) << (7 + interface_bits);
		else
			fadr_physical |= (u64) fadr.cn63xx.fbank << (7 + interface_bits);
		fadr_physical |= (u64) (phase & 1) << 3;
	}

	/* Account for 256MB hole */
	fadr_physical += (fadr_physical < (u64) 0x10000000) ?
		0 : (u64) 0x10000000;

	bit = lmc_syndrome_bits[syndrome];
	if (phase & 1)
		bit += 64;

	if (OCTEON_IS_OCTEON3()) {
		snprintf(msg, sizeof(msg), "DIMM %d rank %d bank %d row %d col %d bit %d address 0x%llx syndrome 0x%x",
		 	fadr.cn73xx.fdimm, fadr.cn73xx.fbunk, fadr.cn73xx.fbank,
		 	fadr.cn73xx.frow & rmask, fadr.cn73xx.fcol & cmask, bit,
		 	(unsigned long long)fadr_physical, syndrome);
	} else {
		snprintf(msg, sizeof(msg), "DIMM %d rank %d bank %d row %d col %d bit %d address 0x%llx syndrome 0x%x",
		 	fadr.cn63xx.fdimm, fadr.cn63xx.fbunk, fadr.cn63xx.fbank,
		 	fadr.cn63xx.frow & rmask, fadr.cn63xx.fcol & cmask, bit,
		 	(unsigned long long)fadr_physical, syndrome);
	}

	/* Re-write the data using atomic add with the value 0 */
	if (lmc_int.s.sec_err) {
		fadr_xkphys = fadr_physical | (1ull << 63) | ((phase & 1) << 3);
		CVMX_SYNC;
		cvmx_atomic_add64_nosync((s64 *)fadr_xkphys, 0);
		/* L2 cache hit writeback (no invalidate) */
		CVMX_SYNC;
		CVMX_CACHE_L2HWB(fadr_xkphys & ~0x7f, 0);

		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");
		lmc_int.s.sec_err = -1;	/* Done, re-arm */
		do_clear = true;
	}

	if (lmc_int.s.ded_err) {
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");
		lmc_int.s.ded_err = -1;	/* Done, re-arm */
		do_clear = true;
	}
	if (lmc_int.s.nxm_wr_err) {
		snprintf(msg, sizeof(msg), "NXM_WR_ERR: Write to non-existent memory");
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");
		lmc_int.s.nxm_wr_err = -1;	/* Done, re-arm */
		do_clear = true;
	}

	if (do_clear)
		cvmx_write_csr_node(node, CVMX_LMCX_INT(mci->mc_idx), lmc_int.u64);
}

static int octeon_lmc_edac_probe(struct platform_device *pdev)
{
	struct mem_ctl_info *mci;
	struct edac_mc_layer layers[2];
	int mc = pdev->id;

	layers[0].type = EDAC_MC_LAYER_CHANNEL;
	layers[0].size = 1;
	layers[0].is_virt_csrow = false;
	layers[1].type = EDAC_MC_LAYER_SLOT;
	layers[1].size = MAX_SLOTS;
	layers[1].is_virt_csrow = false;

	edac_op_state = EDAC_OPSTATE_POLL;

	if (OCTEON_IS_OCTEON1PLUS()) {
		union cvmx_lmcx_mem_cfg0 cfg0;
		cvmx_l2c_cfg_t l2c_cfg;
		int present = 0;

		l2c_cfg.u64 = cvmx_read_csr(CVMX_L2C_CFG);

		if (mc == 0)
			present = l2c_cfg.s.dpres0;
		else
			present = l2c_cfg.s.dpres1;

		if (!present)
			return -ENXIO;

		cfg0.u64 = cvmx_read_csr(CVMX_LMCX_MEM_CFG0(mc));
		if (!cfg0.s.ecc_ena) {
			dev_info(&pdev->dev, "Disabled (ECC not enabled)\n");
			return 0;
		}

		mci = edac_mc_alloc(mc, ARRAY_SIZE(layers), layers, 0);
		if (!mci)
			return -ENXIO;

		mci->pdev = &pdev->dev;
		mci->dev_name = dev_name(&pdev->dev);

		mci->mod_name = "octeon-lmc";
		mci->ctl_name = "octeon-lmc-err";
		mci->edac_check = octeon_lmc_edac_poll;

		if (edac_mc_add_mc(mci)) {
			dev_err(&pdev->dev, "edac_mc_add_mc() failed\n");
			edac_mc_free(mci);
			return -ENXIO;
		}

		cfg0.u64 = cvmx_read_csr(CVMX_LMCX_MEM_CFG0(mc));
		cfg0.s.intr_ded_ena = 0;	/* We poll */
		cfg0.s.intr_sec_ena = 0;
		cvmx_write_csr(CVMX_LMCX_MEM_CFG0(mc), cfg0.u64);
	} else {
		/* OCTEON II and OCTEON III */
		union cvmx_lmcx_int_en en;
		union cvmx_lmcx_config config;
		union cvmx_lmcx_dll_ctl2 ctl2;
		int node = 0;
		int intf = mc;
		struct octeon_lmc *lmc;

		if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
			if (mc >= 4) {
				intf -= 4;
				node = 1;
			}
		}

		ctl2.u64 = cvmx_read_csr_node(node, CVMX_LMCX_DLL_CTL2(intf));
		if (OCTEON_IS_OCTEON3()) {
			dev_info(&pdev->dev, "node: %d, intf: %d, intf_en: %d, quad_dll_en: %d\n",
				node, intf, ctl2.cn78xx.intf_en, ctl2.cn78xx.quad_dll_ena);
			if (!ctl2.cn78xx.quad_dll_ena) {
				dev_info(&pdev->dev, "Disabled (LMC not present)\n");
				return 0;
			}
		} else {
			dev_info(&pdev->dev, "intf: %d, quad_dll_en: %d\n",
				intf, ctl2.cn63xx.quad_dll_ena);
			if (!ctl2.cn63xx.quad_dll_ena) {
				dev_info(&pdev->dev, "Disabled (LMC not present)\n");
				return 0;
			}
		}

		config.u64 = cvmx_read_csr_node(node, CVMX_LMCX_CONFIG(intf));
		if (!config.s.ecc_ena) {
			dev_info(&pdev->dev, "Disabled (ECC not enabled)\n");
			return 0;
		}

		mci = edac_mc_alloc(mc, ARRAY_SIZE(layers), layers,
				    sizeof(struct octeon_lmc));
		if (!mci)
			return -ENXIO;

		mci->pdev = &pdev->dev;
		mci->dev_name = dev_name(&pdev->dev);
		mci->mod_name = "octeon-lmc";
		mci->ctl_name = "co_lmc_err";
		mci->edac_check = octeon_lmc_edac_poll_o3;
		mci->scrub_mode = SCRUB_NONE;
		lmc = mci->pvt_info;

		if (edac_mc_add_mc(mci)) {
			dev_err(&pdev->dev, "edac_mc_add_mc() failed\n");
			edac_mc_free(mci);
			return -ENXIO;
		}

		en.u64 = cvmx_read_csr_node(node, CVMX_LMCX_INT_EN(intf));
		en.s.intr_ded_ena = 0;	/* We poll */
		en.s.intr_sec_ena = 0;
		cvmx_write_csr_node(node, CVMX_LMCX_INT_EN(intf), en.u64);
#ifdef CONFIG_EDAC_DEBUG
		if (IS_ENABLED(CONFIG_EDAC_DEBUG)) {
			int ret = octeon_create_debugfs_nodes(mci->debugfs,
							  lmc_dfs_ents, lmc,
							  ARRAY_SIZE(lmc_dfs_ents));
			if (ret != ARRAY_SIZE(lmc_dfs_ents)) {
				dev_warn(&pdev->dev, "Error creating debugfs entries: %d%s\n",
					 ret, ret >= 0 ? " created" : "");
			}
		}
#endif
	}
	platform_set_drvdata(pdev, mci);

	return 0;
}

static int octeon_lmc_edac_remove(struct platform_device *pdev)
{
	struct mem_ctl_info *mci = platform_get_drvdata(pdev);

	edac_mc_del_mc(&pdev->dev);
	edac_mc_free(mci);
	return 0;
}

static struct platform_driver octeon_lmc_edac_driver = {
	.probe = octeon_lmc_edac_probe,
	.remove = octeon_lmc_edac_remove,
	.driver = {
		   .name = "octeon_lmc_edac",
	}
};
module_platform_driver(octeon_lmc_edac_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ralf Baechle <ralf@linux-mips.org>");
