// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 CCU controller driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

#define CCU_BASE	0x87E050000000
#define CCS_BASE	0x87E087100000

/* m - bit mask
 * y - value to be written in the bitrange
 * x - input value whose bitrange to be modified
 */
#define FIELD_SET(m, y, x)		\
	(((x) & ~(m)) |			\
	FIELD_PREP((m), (y)))

#define CCS_MPARX_MASK(pid)	\
	(0x1000		|	\
	((pid) & 0xff) << 3)

#define MPARX_MASK_LTG		GENMASK_ULL(13, 0)
#define MPARX_MASK_DTG		GENMASK_ULL(33, 14)

#define CCUX_TADX_MPARX_ACNT(ccu, tad, pid)	\
	(0x401000		|		\
	((ccu) & 0x3) << 24	|		\
	((tad) & 0x1) << 21	|		\
	((pid) & 0xff) << 4)

#define CCUX_TADX_MPARX_HCNT(ccu, tad, pid)	\
	(0x401008		|		\
	(((ccu) & 0x3) << 24)	|		\
	(((tad) & 0x1) << 21)	|		\
	(((pid) & 0xff) << 4))

#define MPARID_MAX	256

/* Global variables */
void __iomem *ccu_base;
void __iomem *ccs_base;
static u8 mparid;
static u64 waymask;
static u32 cpid_mask;
struct dentry *ccu_dent;
struct cpumask cpid_cpumask;
static u8 mparid_configured[MPARID_MAX];

#define COUNTER_BUF_SIZE	65536
#define	CONFIG_BUF_SIZE		4096
char *counter_buf;
char *config_buf;

/* Low level accessor functions */
static inline void apsys_cpidel2_read_remote(void *data)
{
	u64 val;

	asm volatile ("mrs %0, s3_4_c11_c6_4" : "=r" (val) : );
	*(u64 *)data = val;
}

static inline void apsys_cpidel2_write_remote(void *data)
{
	u64 val;

	val = *(u64 *)data;
	asm volatile ("msr s3_4_c11_c6_4, %0" : : "r" (val));
}

static inline u64 ccsreg_read(u64 offset)
{
	return readq(ccs_base + offset);
}

static inline void ccsreg_write(u64 offset, u64 val)
{
	writeq(val, ccs_base + offset);
}

static inline u64 ccureg_read(u64 offset)
{
	return readq(ccu_base + offset);
}

static inline void ccureg_write(u64 offset, u64 val)
{
	writeq(val, ccu_base + offset);
}

/* Mask LLC ways for a partition id */
static inline void ccsreg_mparmask_set(int mparid, u32 waymask)
{
	u64 val;

	val = ccsreg_read(CCS_MPARX_MASK(mparid));
	val = FIELD_SET(MPARX_MASK_LTG, waymask, val);
	val = FIELD_SET(MPARX_MASK_DTG, waymask, val);
	ccsreg_write(CCS_MPARX_MASK(mparid), val);
}

static ssize_t otx2_ccu_config_write(struct file *file, const char *buf,
				     size_t count, loff_t *position)
{
	int cpu;

	pr_info("ccu: configuring mparid:%d waymask:0x%llx cpumask:0x%x\n",
		mparid, waymask, cpid_mask);

	/* Configure the LLC ways */
	ccsreg_mparmask_set(mparid, waymask);

	/* Create a bitmap */
	cpumask_clear(&cpid_cpumask);
	for_each_set_bit(cpu, (unsigned long *)&cpid_mask, num_present_cpus())
		cpumask_set_cpu(cpu, &cpid_cpumask);

	/* Configure mparid for all cpus in the bitmap */
	for_each_cpu(cpu, &cpid_cpumask) {
		smp_call_function_single(cpu, apsys_cpidel2_write_remote,
					 &mparid, true);
	}

	/* Some book keeping */
	mparid_configured[mparid] = 1;

	return count;
}

static ssize_t otx2_ccu_config_read(struct file *file, char __user *buf,
				    size_t count, loff_t *position)
{
	u64 val, waymask;
	u32 cpu, sz = 0;
	u8 mparid;

	memset(config_buf, 0, CONFIG_BUF_SIZE);

	/* Read the mparid configured for each cpu and then read
	 * the associated waymask for that mparid.
	 */
	for_each_cpu(cpu, cpu_present_mask) {
		smp_call_function_single(cpu, apsys_cpidel2_read_remote,
					 &val, true);
		mparid = (u8)val;
		waymask = ccsreg_read(CCS_MPARX_MASK(mparid));
		sz += snprintf(config_buf + sz, CONFIG_BUF_SIZE - sz,
			       "core:%d mparid:%d waymask:0x%llx\n",
			       cpu, mparid, waymask);
	}

	/* Copy to the user buffer */
	return simple_read_from_buffer(buf, count, position, config_buf, sz);
}

static const struct file_operations otx2_ccu_config_fops = {
	.read = otx2_ccu_config_read,
	.write = otx2_ccu_config_write,
};

static ssize_t otx2_ccu_counter_read(struct file *file, char __user *buf,
				 size_t count, loff_t *position)
{
	int ccu, tad, pid;
	u64 acnt, hcnt;
	u32 sz = 0;

	memset(counter_buf, 0, COUNTER_BUF_SIZE);

	/* Read the Allocate and Hit counter values only for MPARIDs
	 * that were configured.
	 */
	for (pid = 0; pid < MPARID_MAX; pid++) {
		if (!mparid_configured[pid])
			continue;

		for (ccu = 0; ccu < 4; ccu++) {
			for (tad = 0; tad < 2; tad++) {
				acnt = ccureg_read(CCUX_TADX_MPARX_ACNT(ccu, tad, pid));
				hcnt = ccureg_read(CCUX_TADX_MPARX_HCNT(ccu, tad, pid));
				sz += snprintf(counter_buf + sz, COUNTER_BUF_SIZE - sz,
					      "CCU:%d TAD:%d MPARID:%d ALLOC:0x%llx HIT:0x%llx\n",
					      ccu, tad, pid, acnt, hcnt);
			}
		}
	}

	/* Copy to the user buffer */
	return simple_read_from_buffer(buf, count, position, counter_buf, sz);
}

static const struct file_operations otx2_ccu_counter_fops = {
	.read = otx2_ccu_counter_read,
};

static int __init otx2_ccu_init(void)
{
	u32 cpuid = read_cpuid_id();

	cpuid &= (MIDR_IMPLEMENTOR_MASK | (0xff0 << MIDR_PARTNUM_SHIFT));

	/* Valid only for OcteonTX2 Family */
	if (((ARM_CPU_IMP_CAVIUM << MIDR_IMPLEMENTOR_SHIFT) |
	    (0xB0 << MIDR_PARTNUM_SHIFT)) != cpuid)
		return -ENODEV;

	/* CCU Base address */
	ccu_base = ioremap(CCU_BASE, 0x4000000);
	if (IS_ERR(ccu_base)) {
		pr_err("%s: CCU ioremap failed\n", __func__);
		return PTR_ERR(ccu_base);
	}

	/* CCS Base address */
	ccs_base = ioremap(CCS_BASE, 0x1000);
	if (IS_ERR(ccs_base)) {
		pr_err("%s: CCS ioremap failed\n", __func__);
		return PTR_ERR(ccs_base);
	}

	/* Add debufs hooks */
	ccu_dent = debugfs_create_dir("ccu", NULL);

	debugfs_create_u8("mparid", 0644, ccu_dent, &mparid);

	debugfs_create_u64("waymask", 0644, ccu_dent, &waymask);

	debugfs_create_u32("cpumask", 0644, ccu_dent, &cpid_mask);

	debugfs_create_file("config", 0644, ccu_dent, NULL, &otx2_ccu_config_fops);

	debugfs_create_file("counter", 0644, ccu_dent, NULL, &otx2_ccu_counter_fops);

	counter_buf = kzalloc(COUNTER_BUF_SIZE, GFP_KERNEL);
	if (IS_ERR(counter_buf)) {
		pr_err("Failed to allocate memory for counter buffer\n");
		return PTR_ERR(counter_buf);
	}

	config_buf = kzalloc(CONFIG_BUF_SIZE, GFP_KERNEL);
	if (IS_ERR(config_buf)) {
		pr_err("Failed to allocate memory for config buffer\n");
		kfree(counter_buf);
		return PTR_ERR(config_buf);
	}

	/* Zero MPARID is the default configuration for all CPUs at bootup */
	mparid_configured[0] = 1;
	return 0;
}

static void __exit otx2_ccu_exit(void)
{
	kfree(config_buf);
	kfree(counter_buf);
	debugfs_remove_recursive(ccu_dent);
}

module_init(otx2_ccu_init);
module_exit(otx2_ccu_exit);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 CCU controller Driver");
MODULE_LICENSE("GPL v2");
