// SPDX-License-Identifier: GPL-2.0-only
/*
 * Spin Table SMP initialisation
 *
 * Copyright (C) 2013 ARM Ltd.
 */

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/mm.h>

#include <asm/cacheflush.h>
#include <asm/daifflags.h>
#include <asm/cpu_ops.h>
#include <asm/cputype.h>
#include <asm/io.h>
#include <asm/smp_plat.h>
#include <asm/mmu_context.h>
#include <asm/kexec.h>

#include "cpu-reset.h"
extern void secondary_holding_pen(void);
volatile unsigned long __section(.mmuoff.data.read)
secondary_holding_pen_release = INVALID_HWID;

static phys_addr_t cpu_release_addr[NR_CPUS];
static unsigned int spin_table_loop[4] = {
	0xd503205f,        /* wfe */
	0x58000060,        /* ldr  x0, spin_table_cpu_release_addr */
	0xb4ffffc0,        /* cbnz x0, 0b */
	0xd61f0000         /* br   x0 */
};
/*
 * Write secondary_holding_pen_release in a way that is guaranteed to be
 * visible to all observers, irrespective of whether they're taking part
 * in coherency or not.  This is necessary for the hotplug code to work
 * reliably.
 */
static void write_pen_release(u64 val)
{
	void *start = (void *)&secondary_holding_pen_release;
	unsigned long size = sizeof(secondary_holding_pen_release);

	secondary_holding_pen_release = val;
	__flush_dcache_area(start, size);
}


static int smp_spin_table_cpu_init(unsigned int cpu)
{
	struct device_node *dn;
	int ret;

	dn = of_get_cpu_node(cpu, NULL);
	if (!dn)
		return -ENODEV;

	/*
	 * Determine the address from which the CPU is polling.
	 */
	ret = of_property_read_u64(dn, "cpu-release-addr",
				   &cpu_release_addr[cpu]);
	if (ret)
		pr_err("CPU %d: missing or invalid cpu-release-addr property\n",
		       cpu);

	of_node_put(dn);

#ifdef CONFIG_FAST_KEXEC
	fast_kexec = 1;
#endif

	return ret;
}

static int smp_spin_table_cpu_prepare(unsigned int cpu)
{
	__le64 __iomem *release_addr;

	if (!cpu_release_addr[cpu])
		return -ENODEV;

	/*
	 * The cpu-release-addr may or may not be inside the linear mapping.
	 * As ioremap_cache will either give us a new mapping or reuse the
	 * existing linear mapping, we can use it to cover both cases. In
	 * either case the memory will be MT_NORMAL.
	 */
	release_addr = ioremap_cache(cpu_release_addr[cpu],
				     sizeof(*release_addr));
	if (!release_addr)
		return -ENOMEM;

	/*
	 * We write the release address as LE regardless of the native
	 * endianess of the kernel. Therefore, any boot-loaders that
	 * read this address need to convert this address to the
	 * boot-loader's endianess before jumping. This is mandated by
	 * the boot protocol.
	 */
	writeq_relaxed(__pa_symbol(secondary_holding_pen), release_addr);
	__flush_dcache_area((__force void *)release_addr,
			    sizeof(*release_addr));

	/*
	 * Send an event to wake up the secondary CPU.
	 */
	sev();

	iounmap(release_addr);

	return 0;
}

static int smp_spin_table_cpu_boot(unsigned int cpu)
{
	/*
	 * Update the pen release flag.
	 */
	write_pen_release(cpu_logical_map(cpu));

	/*
	 * Send an event, causing the secondaries to read pen_release.
	 */
	sev();

	return 0;
}



/*
 * There is a four instruction loop set aside in protected
 * memory by u-boot where secondary CPUs wait for the kernel to
 * start.
 *
 * 0:       wfe
 *          ldr    x0, spin_table_cpu_release_addr
 *          cbz    x0, 0b
 *          br     x0
 * spin_table_cpu_release_addr:
 *          .quad  0
 *
 * The address of spin_table_cpu_release_addr is passed in the
 * "release-address" property in the device table.
 * smp_spin_table_cpu_prepare() stores the real address of
 * secondary_holding_pen() where the secondary CPUs loop
 * until they are released one at a time by smp_spin_table_cpu_boot().
 * We reuse the spin-table loop by clearing spin_table_cpu_release_addr,
 * and branching to the beginning of the loop via cpu_soft_restart(),
 * which turns off the MMU and caching.
 */
static void smp_spin_table_cpu_die(unsigned int cpu)
{
	__le64 __iomem *release_addr;
	unsigned int *spin_table_inst;
	unsigned long spin_table_start;
#if defined(CONFIG_PENSANDO_SOC_PCIE)
	unsigned long entry, kpcimgr_get_entry(unsigned long, unsigned int);
#endif

	if (!cpu_release_addr[cpu])
		goto spin;

	spin_table_start = (cpu_release_addr[cpu] - sizeof(spin_table_loop));

	/*
	 * The cpu-release-addr may or may not be inside the linear mapping.
	 * As ioremap_cache will either give us a new mapping or reuse the
	 * existing linear mapping, we can use it to cover both cases. In
	 * either case the memory will be MT_NORMAL.
	 */
	release_addr = ioremap_cache(spin_table_start,
				sizeof(*release_addr) +
				sizeof(spin_table_loop));

	if (!release_addr)
		goto spin;

	spin_table_inst = (unsigned int *)release_addr;
	if (spin_table_inst[0] != spin_table_loop[0] ||
		spin_table_inst[1] != spin_table_loop[1] ||
		spin_table_inst[2] != spin_table_loop[2] ||
		spin_table_inst[3] != spin_table_loop[3])
		goto spin;

	/*
	 * Clear the release address, so that we can use it again
	 */
	writeq_relaxed(0, release_addr + 2);
	__flush_dcache_area((__force void *)(release_addr + 2),
			    sizeof(*release_addr));

	iounmap(release_addr);

	local_daif_mask();
#if defined(CONFIG_PENSANDO_SOC_PCIE)
	/*
	 * Ask kpcimgr if it would like to hijack a cpu.
	 * It will return its polling function
	 * address for the cpu it's borrowing, and for
	 * all the others, it will return spin_table_start.
	 */
	entry = kpcimgr_get_entry(spin_table_start, cpu);
	cpu_soft_restart(entry, spin_table_start, 0, cpu);
#else
	cpu_soft_restart(spin_table_start, 0, 0, cpu);
#endif

	BUG();

spin:
	cpu_park_loop();

}

static int smp_spin_table_cpu_kill(unsigned int cpu)
{
	unsigned long start, end;

	start = jiffies;
	end = start + msecs_to_jiffies(100);

	do {
		if (!cpu_online(cpu)) {
			pr_info("CPU%d killed\n", cpu);
			return 0;
		}
	} while (time_before(jiffies, end));
	pr_warn("CPU%d may not have shut down cleanly\n", cpu);
	return -ETIMEDOUT;

}

/* Nothing to do here */
static int smp_spin_table_cpu_disable(unsigned int cpu)
{
	return 0;
}

const struct cpu_operations smp_spin_table_ops = {
	.name		= "spin-table",
	.cpu_init	= smp_spin_table_cpu_init,
	.cpu_prepare	= smp_spin_table_cpu_prepare,
	.cpu_boot	= smp_spin_table_cpu_boot,
	.cpu_die	= smp_spin_table_cpu_die,
	.cpu_kill	= smp_spin_table_cpu_kill,
	.cpu_disable	= smp_spin_table_cpu_disable,
};
