/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Cavium, Inc.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/percpu.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-boot-vector.h>
#include <asm/octeon/octeon-boot-info.h>
#include <asm/octeon/cvmx-app-hotplug.h>
#include <asm/octeon/cvmx-spinlock.h>
#include <asm/octeon/cvmx-coremask.h>

static struct cvmx_boot_vector_element *octeon_bootvector;
static void *octeon_replug_ll_raw;
asmlinkage void octeon_replug_ll(void);

static struct cvmx_app_hotplug_global *hgp;
static const cvmx_bootmem_named_block_desc_t *ccbi_desc;

DECLARE_PER_CPU(struct cpu, cpu_devices);

/* Need __ref to be able to call register_cpu().  This is OK as this
 * file is only compiled for HOTPLUG_CPU so the resulting call to a
 * __cpuinit function will always be valid.
 */
static ssize_t __ref plug_cpu_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	int cpu, r, coreid, node;
	unsigned long flags;
	bool made_present = false;
	bool is_available = false;

	r = sscanf(buf, "%d", &cpu);

	if (r != 1 || cpu < 0 || cpu >= NR_CPUS)
		return -EINVAL;


	cpu_maps_update_begin();

	if (!cpu_present(cpu) && cpu_possible(cpu)) {
		coreid = cpu_logical_map(cpu);

		local_irq_save(flags);
		cvmx_spinlock_lock(&hgp->hotplug_global_lock);
		if (cvmx_coremask_is_core_set(&hgp->avail_coremask, coreid)) {
			is_available = true;
			cvmx_coremask_clear_core(&hgp->avail_coremask, coreid);
		}
		cvmx_spinlock_unlock(&hgp->hotplug_global_lock);
		local_irq_restore(flags);
		if (!is_available) {
			pr_notice("CPU %d is not available for plugging\n", cpu);
			goto not_available_out;
		}

		octeon_bootvector[coreid].target_ptr = (uint64_t)octeon_replug_ll_raw;
		mb();
		node = cvmx_coremask_core_to_node(coreid);
		coreid = cvmx_coremask_core_on_node(coreid);
		if (octeon_has_feature(OCTEON_FEATURE_CIU3))
			cvmx_write_csr_node(node, CVMX_CIU3_NMI, (1ull << coreid));
		else
			cvmx_write_csr(CVMX_CIU_NMI, (1 << coreid));

		set_cpu_present(cpu, true);
		made_present = true;
		pr_info("CPU %d now present\n", cpu);
	}
not_available_out:
	cpu_maps_update_done();

	if (made_present) {
		struct cpu *c = &per_cpu(cpu_devices, cpu);
		memset(c, 0, sizeof(struct cpu));
		c->hotpluggable = 1;
		r = register_cpu(c, cpu);
		if (r)
			pr_warn("unplug_cpu: register_cpu %d failed (%d)\n.", cpu, r);
	}

	return count;
}

static ssize_t unplug_cpu_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int cpu, r;
	bool made_not_present = false;
	unsigned long flags;

	r = sscanf(buf, "%d", &cpu);

	if (r != 1 || cpu < 0 || cpu >= NR_CPUS)
		return -EINVAL;

	cpu_maps_update_begin();

	if (!cpu_online(cpu) && cpu_present(cpu)) {
		pr_info("CPU %d now not present\n", cpu);
		set_cpu_present(cpu, false);
		made_not_present = true;
	}

	cpu_maps_update_done();

	if (made_not_present) {
		int coreid = cpu_logical_map(cpu);
		struct cpu *c = &per_cpu(cpu_devices, cpu);
		unregister_cpu(c);

		local_irq_save(flags);
		cvmx_spinlock_lock(&hgp->hotplug_global_lock);
		cvmx_coremask_set_core(&hgp->avail_coremask, coreid);
		cvmx_spinlock_unlock(&hgp->hotplug_global_lock);
		local_irq_restore(flags);
	}

	return count;
}

static ssize_t unplug_cpu_print(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "hello\n");
}

DEVICE_ATTR(octeon_plug, 0644, unplug_cpu_print, plug_cpu_store);
DEVICE_ATTR(octeon_unplug, 0644, unplug_cpu_print, unplug_cpu_store);

/* the following function will work ONLY with size%8 = 0 */
static
int __cvmx_copy_from_bootmem(int64_t bootmem_src_addr, void *dst_ptr, int size)
{
	int i;
	int64_t base_addr = (1ull << 63) | bootmem_src_addr;
	int64_t *ptr64 = dst_ptr;

	for (i = 0; i < size/8; i++) {
		ptr64[i] = cvmx_read64_int64(base_addr);
		base_addr += 8;
	}
	return 0;
}

static void __init octeon_hotplug_global_init(void *arg)
{
	struct linux_app_boot_info *labi;
	cvmx_app_hotplug_global_t *hgp = arg;
	cvmx_cores_common_bootinfo_t ccbi;

	memset(hgp, 0, CVMX_APP_HOTPLUG_INFO_REGION_SIZE);

	hgp->magic_version = CVMX_HOTPLUG_MAGIC_VERSION;

	cvmx_spinlock_init(&hgp->hotplug_global_lock);

	/* Get legacy LABI data structure for initial parameters */
	labi = phys_to_virt(LABI_ADDR_IN_BOOTLOADER);

	/* Initialize available cores from LABI is limited to 32 cores
	 * - try to do not use it - instead do ... */
	if (ccbi_desc) { /* 'common bootinfo' named block is found - use it*/
		__cvmx_copy_from_bootmem(ccbi_desc->base_addr, &ccbi,
					sizeof(cvmx_cores_common_bootinfo_t));
		/* Validate signature */
		if (ccbi.magic != CVMX_COMMON_BOOTINFO_MAGIC)
			return; /* if 'magic' does not match - exit */
		/* the members from the initial(1) version are always valid */
		/* only hgp->avail_coremask is need - fill it in */
		cvmx_coremask_copy(&hgp->avail_coremask, &ccbi.avail_coremask);
		/* the extra (version) members (if any) are valid when
		 * (2 <= ccbi.version <= CVMX_COMMON_BOOTINFO_VERSION)
		 * if (ccbi.version >= 2) { xxx = ccbi.ver2_member; }
		 */
	} else { /* the older bootloaders provide only labi->avail_coremask */
		/* Validate signature */
		if (labi->labi_signature != LABI_SIGNATURE)
			return;
		cvmx_coremask_set64(&hgp->avail_coremask,
					(uint64_t) labi->avail_coremask);
	}
}

static int __init unplug_cpu_init(void)
{
	unsigned long t;

	octeon_bootvector = cvmx_boot_vector_get();
	if (!octeon_bootvector) {
		pr_err("Error: Cannot allocate boot vector.\n");
		return -ENOMEM;
	}
	t = __pa_symbol(octeon_replug_ll);
	octeon_replug_ll_raw = phys_to_virt(t);

	/* the 'common bootinfo' named block should be found/copied before
	 * creating hotplug named block,
	 * because avail_coremask is copied from it
	 */
	ccbi_desc =
		cvmx_bootmem_find_named_block(CVMX_APP_COMMON_BOOTINFO_NAME);
	if (!ccbi_desc)
		pr_info("Info: cvmx_bootmem_find_named_block(%s) not found.\n",
						CVMX_APP_COMMON_BOOTINFO_NAME);

	hgp = cvmx_bootmem_alloc_named_range_once(
		CVMX_APP_HOTPLUG_INFO_REGION_SIZE,
		0x0, 1ull << 29, 0,
		CVMX_APP_HOTPLUG_INFO_REGION_NAME,
		octeon_hotplug_global_init);

	if (!hgp) {
		pr_err("Error: cvmx_bootmem_alloc_named_range_once(%s)\n",
		       CVMX_APP_HOTPLUG_INFO_REGION_NAME);
		return -ENOMEM;
	}
	return 0;
}
module_init(unplug_cpu_init);
