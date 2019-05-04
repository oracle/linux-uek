/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Cavium, Inc.
 *
 * clocksource provider driven by node-0 FPA_CLK_COUNT.  This will
 * give consistent time across multi-node NUMA systems.
 */
#include <linux/clocksource.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-fpa-defs.h>
#include <asm/octeon/cvmx-rst-defs.h>

static u64 csrc_fpa_clk_read(struct clocksource *cs)
{
	return cvmx_read_csr(CVMX_FPA_CLK_COUNT);
}

static struct clocksource csrc_fpa_clk = {
	.name		= "OCTEON_FPA_CLK_COUNT",
	.read		= csrc_fpa_clk_read,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

void __init csrc_fpa_clk_init(void)
{
	union cvmx_rst_boot rst_boot;
	u64 f;

	rst_boot.u64 = cvmx_read_csr(CVMX_RST_BOOT);

	f = 50000000ull * rst_boot.s.pnr_mul;

	csrc_fpa_clk.rating = 300;
	clocksource_register_hz(&csrc_fpa_clk, f);
}

unsigned long long notrace csrc_fpa_clk_sched_clock(void)
{
	/* 64-bit arithmatic can overflow, so use 128-bit.  */
	u64 t1, t2, t3;
	unsigned long long rv;
	u64 mult = csrc_fpa_clk.mult;
	u64 shift = csrc_fpa_clk.shift;
	u64 cnt = cvmx_read_csr(CVMX_FPA_CLK_COUNT);

	asm (
		"dmultu\t%[cnt],%[mult]\n\t"
		"nor\t%[t1],$0,%[shift]\n\t"
		"mfhi\t%[t2]\n\t"
		"mflo\t%[t3]\n\t"
		"dsll\t%[t2],%[t2],1\n\t"
		"dsrlv\t%[rv],%[t3],%[shift]\n\t"
		"dsllv\t%[t1],%[t2],%[t1]\n\t"
		"or\t%[rv],%[t1],%[rv]\n\t"
		: [rv] "=&r" (rv), [t1] "=&r" (t1), [t2] "=&r" (t2), [t3] "=&r" (t3)
		: [cnt] "r" (cnt), [mult] "r" (mult), [shift] "r" (shift)
		: "hi", "lo");
	return rv;
}
