// SPDX-License-Identifier: GPL-2.0-only
/*
 * MIPS support for CONFIG_OF device tree support
 *
 * Copyright (C) 2010 Cisco Systems Inc. <dediao@cisco.com>
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/debugfs.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_platform.h>

#include <asm/bootinfo.h>
#include <asm/page.h>
#include <asm/prom.h>

static char mips_machine_name[64] = "Unknown";

__init void mips_set_machine_name(const char *name)
{
	if (name == NULL)
		return;

	strlcpy(mips_machine_name, name, sizeof(mips_machine_name));
	pr_info("MIPS: machine is %s\n", mips_get_machine_name());
}

char *mips_get_machine_name(void)
{
	return mips_machine_name;
}

#ifdef CONFIG_USE_OF
void __init early_init_dt_add_memory_arch(u64 base, u64 size)
{
#ifdef CONFIG_CAVIUM_OCTEON_SOC
	/*
	 * This gets called from early_init_dt_scan_memory()
	 * using the fdt as a reference for available memory.
	 * On the Octeon MIPS platform this is the physical
	 * memory on the system and does not reflect memory
	 * used by u-boot and the other firmware.
	 *
	 * This gets called very early from relocate_kernel()
	 * when CONFIG_RELOCATABLE is set. This will inhibit
	 * later memory setup and the system will hang early
	 * in the boot process. When CONFIG_RELOCATABLE is not
	 * set, early_init_dt_scan() is called later, and it
	 * may appear that everything is okay, but other users
	 * of memblock may have problems and the kernel may
	 * panic.
	 *
	 * Do nothing on Octeon. arch_mem_init() will initialize
	 * memory correctly using the freelist pointer passed by
	 * u-boot.
	 */
	return;
#else
	if (base >= PHYS_ADDR_MAX) {
		pr_warn("Trying to add an invalid memory region, skipped\n");
		return;
	}

	/* Truncate the passed memory region instead of type casting */
	if (base + size - 1 >= PHYS_ADDR_MAX || base + size < base) {
		pr_warn("Truncate memory region %llx @ %llx to size %llx\n",
			size, base, PHYS_ADDR_MAX - base);
		size = PHYS_ADDR_MAX - base;
	}

	add_memory_region(base, size, BOOT_MEM_RAM);
#endif
}

int __init early_init_dt_reserve_memory_arch(phys_addr_t base,
					phys_addr_t size, bool nomap)
{
	add_memory_region(base, size,
			  nomap ? BOOT_MEM_NOMAP : BOOT_MEM_RESERVED);

	return 0;
}

void __init __dt_setup_arch(void *bph)
{
	if (!early_init_dt_scan(bph))
		return;

	mips_set_machine_name(of_flat_dt_get_machine_name());
}

int __init __dt_register_buses(const char *bus0, const char *bus1)
{
	static struct of_device_id of_ids[3];

	if (!of_have_populated_dt())
		panic("device tree not present");

	strlcpy(of_ids[0].compatible, bus0, sizeof(of_ids[0].compatible));
	if (bus1) {
		strlcpy(of_ids[1].compatible, bus1,
			sizeof(of_ids[1].compatible));
	}

	if (of_platform_populate(NULL, of_ids, NULL, NULL))
		panic("failed to populate DT");

	return 0;
}

#endif
