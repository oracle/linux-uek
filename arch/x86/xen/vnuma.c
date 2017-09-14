/*
 * vNUMA support for Dom0 Linux
 *
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
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
 */

#include <linux/err.h>
#include <linux/memblock.h>
#include <xen/interface/xen.h>
#include <xen/interface/memory.h>
#include <asm/xen/interface.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/vnuma.h>

/*
 * Called from numa_init if numa_off = 0;
 */
int __init xen_numa_init(void)
{
	unsigned int i, j;
	unsigned int nr_nodes, nr_cpus, nr_ranges;
	unsigned int *vdistance, *cpu_to_node;
	unsigned long mem_size, dist_size, cpu_to_node_size;
	struct xen_vmemrange *vmem;
	u64 physm, physd, physc;
	int rc;
	struct xen_vnuma_topology_info numa_topo = {
		.domid = DOMID_SELF,
		.pad = 0
	};

	physm = physd = physc = 0;

	/* For now only Dom0 is supported trough this mechanism. */
	if (!xen_initial_domain())
		return -EINVAL;

	/*
	 * Set the numa parameters to zero and hypercall should return -ENOBUFS
	 * and hypervisor will copy number of cpus, nodes and memory ranges.
	 */
	numa_topo.nr_vnodes = numa_topo.nr_vcpus = numa_topo.nr_vmemranges = 0;
	rc = HYPERVISOR_memory_op(XENMEM_get_vnumainfo, &numa_topo);
	if (rc != -ENOBUFS)
		return rc ? rc : -EINVAL;

	/* support for nodes with at least one cpu */
	nr_nodes = numa_topo.nr_vnodes;
	nr_ranges = numa_topo.nr_vmemranges;
	nr_cpus = numa_topo.nr_vcpus;

	/*
	 * Allocate arrays for nr_cpus/nr_nodes sizes and do second hypercall.
	 * If second time it fails, we dont try anymore and fail.
	 */
	mem_size =  nr_ranges * sizeof(struct xen_vmemrange);
	dist_size = nr_nodes * nr_nodes * sizeof(*numa_topo.vdistance.h);
	cpu_to_node_size = nr_cpus * sizeof(*numa_topo.vcpu_to_vnode.h);

	physm = memblock_alloc(mem_size, PAGE_SIZE);
	physd = memblock_alloc(dist_size, PAGE_SIZE);
	physc = memblock_alloc(cpu_to_node_size, PAGE_SIZE);

	if (!physm || !physd || !physc)
		goto out;

	vmem = __va(physm);
	vdistance  = __va(physd);
	cpu_to_node  = __va(physc);

	set_xen_guest_handle(numa_topo.vmemrange.h, vmem);
	set_xen_guest_handle(numa_topo.vdistance.h, vdistance);
	set_xen_guest_handle(numa_topo.vcpu_to_vnode.h, cpu_to_node);

	rc = HYPERVISOR_memory_op(XENMEM_get_vnumainfo, &numa_topo);
	if (rc < 0)
		goto out;

	/*
	 * NUMA nodes memory ranges are in pfns, constructed and
	 * aligned based on e820 ram domain map.
	 */
	for (i = 0; i < nr_ranges; i++) {
		rc = numa_add_memblk(vmem[i].nid, vmem[i].start, vmem[i].end);
		if (rc < 0)
			goto out;
	}

	for (i = 0; i < nr_cpus; i++)
		numa_set_node(i, cpu_to_node[i]);

	for (i = 0; i < nr_nodes; i++)
		for (j = 0; j < nr_nodes; j++)
			numa_set_distance(i, j, *(vdistance + ((i * nr_nodes) + j)));

	rc = 0;
out:
	if (physm)
		memblock_free(physm, mem_size);
	if (physd)
		memblock_free(physd, dist_size);
	if (physc)
		memblock_free(physc, cpu_to_node_size);

	return rc;
}
