// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/soc/marvell/llc.h>

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Last Level Cache Manager for OcteonTX2");
MODULE_LICENSE("GPL v2");

/* SYS instruction opcode for LLC Hit Writeback Invalidate */
#define CVMCACHEWBIL3		"#0,c11,c1,#2"
/* SYS instruction opcode for LLC Fetch and Lock */
#define CVMCACHELCKL3		"#0,c11,c1,#4"
/* LLC cache line granule size on OcteonTx2 */
#define CVMCACHELCKL3_LINESIZE	BIT_ULL(7)

static spinlock_t llc_lock;

static bool is_octeontx2(void)
{
	u32 model;

	model = read_cpuid_id();
	model &= MIDR_IMPLEMENTOR_MASK | MIDR_ARCHITECTURE_MASK |
		MIDR_PARTNUM_MASK;

	return (model == MIDR_MRVL_OCTEONTX2_98XX ||
		model == MIDR_MRVL_OCTEONTX2_96XX ||
		model == MIDR_MRVL_OCTEONTX2_95XX ||
		model == MIDR_MRVL_OCTEONTX2_LOKI ||
		model == MIDR_MRVL_OCTEONTX2_95MM);
}

int octeontx2_llc_unlock(phys_addr_t addr, int size)
{
	bool cacheline_unaligned = 0;

	/* Unlock not supported on other silicon */
	if (!is_octeontx2())
		return 0;

	if (!addr || size < 0)
		return -EINVAL;

	if ((addr & (CVMCACHELCKL3_LINESIZE-1)) && size) {
		cacheline_unaligned = 1;
		addr -= (addr & (CVMCACHELCKL3_LINESIZE-1));
	}

	spin_lock(&llc_lock);

	while (size > 0) {
		/* write cache line into memory,invalidate and unlock in LLC */
		asm volatile ("sys " CVMCACHEWBIL3 ", %0" : : "r" (addr));
		addr += CVMCACHELCKL3_LINESIZE;
		size -= CVMCACHELCKL3_LINESIZE;
	}

	if (cacheline_unaligned)
		asm volatile ("sys " CVMCACHEWBIL3 ", %0" : : "r" (addr));

	isb();
	spin_unlock(&llc_lock);

	return 0;
}
EXPORT_SYMBOL(octeontx2_llc_unlock);

int octeontx2_llc_lock(phys_addr_t addr, int size)
{
	bool cacheline_unaligned = 0;

	/* Lock not supported on other silicon */
	if (!is_octeontx2())
		return 0;

	if (!addr || size < 0)
		return -EINVAL;

	if ((addr & (CVMCACHELCKL3_LINESIZE-1)) && size) {
		cacheline_unaligned = 1;
		addr -= (addr & (CVMCACHELCKL3_LINESIZE-1));
	}

	spin_lock(&llc_lock);

	while (size > 0) {
		/* Fill a block of memory into LLC and lock the cache line */
		asm volatile ("sys " CVMCACHELCKL3 ", %0" : : "r" (addr));
		addr += CVMCACHELCKL3_LINESIZE;
		size -= CVMCACHELCKL3_LINESIZE;
	}

	if (cacheline_unaligned)
		asm volatile ("sys " CVMCACHELCKL3 ", %0" : : "r" (addr));

	isb();
	spin_unlock(&llc_lock);

	return 0;
}
EXPORT_SYMBOL(octeontx2_llc_lock);

static int __init octx2_llc_init(void)
{
	spin_lock_init(&llc_lock);
	return 0;
}
arch_initcall(octx2_llc_init);
