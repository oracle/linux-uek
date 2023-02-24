// SPDX-License-Identifier: GPL-2.0
/* PCIe PTM (Precision Time Management) EP driver
 *
 * Copyright (c) 2023 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/io.h>
#include <asm/sysreg.h>

#include "ptm_ep.h"

#define PTM_DEBUG	0

/*
 * PTM/PTP time values reported through the sysfs files.  The register
 * values are not used directly as we use the value 0 to indicate that the
 * times aren't valid.
 */
static u64 ptm_time;
static u64 ptp_time;

/*
 * This driver supports cn9xxx and cn10k parts.  This value will be true
 * for cn10k, false for cn9xxx, driver will fail to load on anything else.
 */
static int cn10k;

/* sysfs functions/variables */
struct kobject *ptm_dir;
static ssize_t ptm_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t ptp_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t capture_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count);
static struct kobj_attribute ptm_attribute = __ATTR(ptm, 0660, ptm_show,  NULL);
static struct kobj_attribute ptp_attribute = __ATTR(ptp, 0660, ptp_show,  NULL);
static struct kobj_attribute capture_attribute = __ATTR(capture, 0660, NULL,  capture_store);


/*
 * Report the PTM time captured, or 0 if the PTM context is not valid
 */
static ssize_t ptm_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%llx\n", (unsigned long long)ptm_time);
}

/*
 * Report the PTP time captured, or 0 if the PTM context is not valid
 */
static ssize_t ptp_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%llx\n", (unsigned long long)ptp_time);
}

static u64 read_req_t4(void)
{
	u32 t4m, t4l, t4m_2;

	/*
	 * Make sure we read a consistent snapshot of both high and low
	 * parts of time.
	 */
	do {
		t4m = read_pcie_config32(0, PCIEEPX_PTM_REQ_T4M);
		t4l = read_pcie_config32(0, PCIEEPX_PTM_REQ_T4L);
		t4m_2 = read_pcie_config32(0, PCIEEPX_PTM_REQ_T4M);
	} while (t4m != t4m_2);

	return(((u64)t4m << 32) | t4l);
}

/*
 * Writes (of anything) to this file capture hardware to perform a
 * simultaneous capture of the PTM time and the PTP time.  The validity
 * of the PTM context is checked, as well as checking to make sure that
 * a PTM dialog happened very recently, as should be the case with
 * hardware triggering a new dialog every 10ms.
 * If the PTM context is invalid, or if there hasn't been a recent PTM
 * dialog then 0's will be returned for the two times when read from their
 * respective files, otherwise the times captured by hardware are
 * reported.
 * The update of both time variables that are used by the ptm/ptp
 * reporting files are both updated during the store function, so no
 * locking is used.  (spinlocks cannot be used in this function.)
 * The expected use case of these files is for the captureing and reading
 * of time values to be done by the same software thread, which ensures
 * that the updates are complete before values are read.  Locking also
 * will not help the multithreaded case where updates are being captureed
 * and values are being read at the same time, as inconsistent values can
 * be read in this case even with locking.
 */
static ssize_t capture_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	u32 val32;
	u64 val64;
	u64 ptm_dialog_time;
	u64 time_diff;


	u64 check64;

	/* Check for valid PTM context */
	val32 = read_pcie_config32(0, PCIEEPX_PTM_REQ_STAT);
	if (!(val32 & 0x1)) {
		pr_err("PTM_EP: ERROR: PTM context not valid: 0x%x\n", val32);
		ptm_time = 0;
		ptp_time = 0;
		return count;
	}

	/* Save time of most recent PTM dialog */
	ptm_dialog_time = read_req_t4();

	// Save LCL time value to check if trigger updated it
	check64 = npu_csr_read(PEMX_PTM_LCL_TIME);

	/* Trigger PTM/PTP capture */
	val64 = npu_csr_read(PEMX_PTM_CTL);
	val64 |= PEMX_PTM_CTL_CAP;
	npu_csr_write(PEMX_PTM_CTL, val64);
	udelay(1);  /* Delay here after readback */

	/*
	 * Make sure that PTM dialogs are still happening.  These should
	 * happen every 10ms, so if more than 50ms have passed between then
	 * don't consider times valid.
	 */
	val64 = npu_csr_read(PEMX_PTM_LCL_TIME);
	if (check64 == val64) {
		/*
		 * Check to see if we have a stale PEMX_PTM_LCL_TIME that
		 * wasn't updated by triggering a capture.
		 */
		pr_err("ERROR: stale local time read after trigger, 0x%llx",
		       (unsigned long long)val64);
		udelay(1);
#if PTM_DEBUG
		val64 = npu_csr_read(PEMX_PTM_LCL_TIME);
		if (check64 == val64)
			pr_err("ERROR: Double stale local time read after trigger, re-reading");
#endif
	} else {
		pr_notice("Local time changed after trigger, diff: %lld",
			  val64 - check64);
	}

	time_diff = val64 - ptm_dialog_time;
	if (time_diff > 50*1000*1000) {
#if PTM_DEBUG
		pr_err("PTM_EP: ERROR: PTM dialog out of date\n");
		pr_err("PTM_EP: dialog time: 0x%llx\n",
		       (unsigned long long)ptm_dialog_time);
		pr_err("PTM_EP: LCL    time: 0x%llx\n",
		       (unsigned long long)val64);
		pr_err("PTM_EP: diff   time: %lld\n",
		       (long long)time_diff);
#endif
		ptm_time = 0;
		ptp_time = 0;
		return count;
	}
#if PTM_DEBUG
	pr_info("PTM_EP: diff   time: %lld\n",
	       (long long)time_diff);
#endif

	/* Save PTM/PTP values to variables for reporting */
	ptp_time = npu_csr_read(PEMX_PTM_MAS_TIME);
	ptm_time = npu_csr_read(PEMX_PTM_LCL_TIME);

	return count;
}


static uint64_t npu_csr_read(u64 csr_addr)
{
	u64 val;
	u64 *addr;

	addr = ioremap(csr_addr, 8);
	if (addr == NULL) {
		pr_err("PTM_EP: Failed to ioremap CSR space\n");
		return -1UL;
	}
	val = READ_ONCE(*addr);
	iounmap(addr);
	return val;
}

static void npu_csr_write(u64 csr_addr, uint64_t val)
{
	u64 *addr;

	addr = ioremap(csr_addr, 8);
	if (addr == NULL) {
		pr_err("PTM_EP: Failed to ioremap CSR space\n");
		return;
	}
	WRITE_ONCE(*addr, val);
	iounmap(addr);
}

static u32 read_pcie_config32(int ep_pem, int cfg_addr)
{
	void __iomem *addr;
	u64 val;

	if (cn10k) {
		/* CN10K method */
		addr  = ioremap(PEMX_PFX_CSX_PFCFGX(ep_pem, 0, cfg_addr), 8);
		if (addr == NULL) {
			pr_err("PTM_EP: Failed to ioremap Octeon CSR space\n");
			return -1U;
		}
		/* 8 byte mapping needed, both 32 bit addresses used */
		val = readl(addr);
		iounmap(addr);
	} else {
		/* CN9XXX method */
		addr  = ioremap(PEMX_CFG_RD(ep_pem), 8);
		if (addr == NULL) {
			pr_err("PTM_EP: Failed to ioremap Octeon CSR space\n");
			return -1U;
		}
		val = ((1 << 15) | (cfg_addr & 0xfff));
		writeq(val, addr);
		val = readq(addr) >> 32;
		iounmap(addr);
	}
	return (val & 0xffffffff);

}

static int __init ptm_ep_init(void)
{
	int error;
	u64 midr_el1;

	midr_el1 = read_sysreg(midr_el1);

	if ((midr_el1 & 0xff00fff0) == 0x4100d490)
		cn10k = 1;
	else if (((midr_el1 >> 24) == 0x43) &&
		 (((midr_el1 >> 4) & 0xFF) == 0xB1 ||
		  ((midr_el1 >> 4) & 0xFF) == 0xB2 ||
		  ((midr_el1 >> 4) & 0xFF) == 0xB3 ||
		  ((midr_el1 >> 4) & 0xFF) == 0xB4 ||
		  ((midr_el1 >> 4) & 0xFF) == 0xB5))
		cn10k = 0;
	else {
		pr_err("PTM_EP: Error - unsupported processor\n");
		return -1;
	}

	/* Create ptm sysfs directory   */
	ptm_dir = kobject_create_and_add("ptm", kernel_kobj);
	if (!ptm_dir)
		goto error1;

	error = sysfs_create_file(ptm_dir, &ptm_attribute.attr);
	if (error)
		goto error;
	error = sysfs_create_file(ptm_dir, &ptp_attribute.attr);
	if (error)
		goto error;
	error = sysfs_create_file(ptm_dir, &capture_attribute.attr);
	if (error)
		goto error;

	return 0;
error:
	kobject_put(ptm_dir);
error1:
	pr_err("PTM_EP: Error creating sysfs files.\n");
	return -1;
}

static void __exit ptm_ep_exit(void)
{
	kobject_put(ptm_dir);
}

module_init(ptm_ep_init);
module_exit(ptm_ep_exit);
MODULE_AUTHOR("Marvell Inc.");
MODULE_DESCRIPTION("OTX PTM EP driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");
