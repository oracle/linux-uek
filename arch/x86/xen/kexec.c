/*
 * Copyright (c) 2011 Daniel Kiper
 * Copyright (c) 2012 Daniel Kiper, Oracle Corporation
 *
 * kexec/kdump implementation for Xen was written by Daniel Kiper.
 * Initial work on it was sponsored by Google under Google Summer
 * of Code 2011 program and Citrix. Konrad Rzeszutek Wilk from Oracle
 * was the mentor for this project.
 *
 * Some ideas are taken from:
 *   - native kexec/kdump implementation,
 *   - kexec/kdump implementation for Xen Linux Kernel Ver. 2.6.18,
 *   - PV-GRUB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <xen/interface/platform.h>
#include <xen/interface/xen.h>
#include <xen/xen.h>

#include <asm/xen/hypercall.h>

unsigned long xen_vmcoreinfo_maddr = 0;
unsigned long xen_vmcoreinfo_max_size = 0;

static int __init xen_init_kexec_resources(void)
{
	int rc;
	static struct resource xen_hypervisor_res = {
		.name = "Hypervisor code and data",
		.flags = IORESOURCE_BUSY | IORESOURCE_MEM
	};
	struct resource *cpu_res;
	struct xen_kexec_range xkr;
	struct xen_platform_op cpuinfo_op;
	uint32_t cpus, i;

	if (!xen_initial_domain())
		return 0;

	if (strstr(boot_command_line, "crashkernel="))
		pr_warn("kexec: Ignoring crashkernel option. "
			"It should be passed to Xen hypervisor.\n");

	/* Register Crash kernel resource. */
	xkr.range = KEXEC_RANGE_MA_CRASH;
	rc = HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &xkr);

	if (rc) {
		pr_warn("kexec: %s: HYPERVISOR_kexec_op(KEXEC_RANGE_MA_CRASH)"
			": %i\n", __func__, rc);
		return rc;
	}

	if (!xkr.size)
		return 0;

	crashk_res.start = xkr.start;
	crashk_res.end = xkr.start + xkr.size - 1;
	insert_resource(&iomem_resource, &crashk_res);

	/* Register Hypervisor code and data resource. */
	xkr.range = KEXEC_RANGE_MA_XEN;
	rc = HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &xkr);

	if (rc) {
		pr_warn("kexec: %s: HYPERVISOR_kexec_op(KEXEC_RANGE_MA_XEN)"
			": %i\n", __func__, rc);
		return rc;
	}

	xen_hypervisor_res.start = xkr.start;
	xen_hypervisor_res.end = xkr.start + xkr.size - 1;
	insert_resource(&iomem_resource, &xen_hypervisor_res);

	/* Determine maximum number of physical CPUs. */
	cpuinfo_op.cmd = XENPF_get_cpuinfo;
	cpuinfo_op.u.pcpu_info.xen_cpuid = 0;
	rc = HYPERVISOR_dom0_op(&cpuinfo_op);

	if (rc) {
		pr_warn("kexec: %s: HYPERVISOR_dom0_op(): %i\n", __func__, rc);
		return rc;
	}

	cpus = cpuinfo_op.u.pcpu_info.max_present + 1;

	/* Register CPUs Crash note resources. */
	cpu_res = kcalloc(cpus, sizeof(struct resource), GFP_KERNEL);

	if (!cpu_res) {
		pr_warn("kexec: %s: kcalloc(): %i\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	for (i = 0; i < cpus; ++i) {
		xkr.range = KEXEC_RANGE_MA_CPU;
		xkr.nr = i;
		rc = HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &xkr);

		if (rc) {
			pr_warn("kexec: %s: cpu: %u: HYPERVISOR_kexec_op"
				"(KEXEC_RANGE_MA_XEN): %i\n", __func__, i, rc);
			continue;
		}

		cpu_res->name = "Crash note";
		cpu_res->start = xkr.start;
		cpu_res->end = xkr.start + xkr.size - 1;
		cpu_res->flags = IORESOURCE_BUSY | IORESOURCE_MEM;
		insert_resource(&iomem_resource, cpu_res++);
	}

	/* Get vmcoreinfo address and maximum allowed size. */
	xkr.range = KEXEC_RANGE_MA_VMCOREINFO;
	rc = HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &xkr);

	if (rc) {
		pr_warn("kexec: %s: HYPERVISOR_kexec_op(KEXEC_RANGE_MA_VMCOREINFO)"
			": %i\n", __func__, rc);
		return rc;
	}

	xen_vmcoreinfo_maddr = xkr.start;
	xen_vmcoreinfo_max_size = xkr.size;

	return 0;
}

core_initcall(xen_init_kexec_resources);
