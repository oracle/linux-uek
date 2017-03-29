/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "dax_impl.h"
#include <asm/pcr.h>

/*
 * Performance Counter Code
 *
 * Author: Dave Aldridge (david.j.aldridge@oracle.com)
 *
 */

/**
 * write_pcr_reg() - Write to a performance counter register
 * @register:	The register to write to
 * @value:	The value to write
 *
 * Return:	0 - success
 *		non 0 - failure
 */
static void write_pcr_reg(unsigned long reg, u64 value)
{
	dax_perf_dbg("initial pcr%lu[%016llx]", reg, pcr_ops->read_pcr(reg));

	pcr_ops->write_pcr(reg, value);
	dax_perf_dbg("updated pcr%lu[%016llx]", reg, pcr_ops->read_pcr(reg));
}


/**
 * dax_setup_counters() - Setup the DAX performance counters
 * @node:	The node
 * @dax:	The dax instance
 * @setup:	The config value to write
 *
 * Return:	0 - success
 *		non 0 - failure
 */
static void dax_setup_counters(unsigned int node, unsigned int dax, u64 setup)
{
	write_pcr_reg(DAX_PERF_CTR_CTL_OFFSET(node, dax), setup);
}

/**
 * @dax_get_counters() - Read the DAX performance counters
 * @node:	The node
 * @dax:	The dax instance
 * @counts:	Somewhere to write the count values
 *
 * Return:	0 - success
 *		non 0 - failure
 */
static void dax_get_counters(unsigned int node, unsigned int dax,
		unsigned long (*counts)[DAX_PER_NODE][COUNTERS_PER_DAX])
{
	int i;
	u64 pcr;
	unsigned long reg;

	for (i = 0; i < COUNTERS_PER_DAX; i++) {
		reg = DAX_PERF_CTR_OFFSET(i, node, dax);
		pcr = pcr_ops->read_pcr(reg);
		dax_perf_dbg("pcr%lu[%016llx]", reg, pcr);
		counts[node][dax][i] = pcr;
	}
}

/**
 * @dax_clear_counters() - Clear the DAX performance counters
 * @node:	The node
 * @dax:	The dax instance
 *
 * Return	0 - success
 *		non 0 - failure
 */
static void dax_clear_counters(unsigned int node, unsigned int dax)
{
	int i;

	for (i = 0; i < COUNTERS_PER_DAX; i++)
		write_pcr_reg(DAX_PERF_CTR_OFFSET(i, node, dax), 0);
}


long dax_perfcount_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	unsigned int node, dax;
	unsigned int max_nodes = num_online_nodes();
	unsigned long dax_config;
	/* DAX performance counters are 48 bits wide */
	unsigned long dax_count_bytes =
		max_nodes * DAX_PER_NODE * COUNTERS_PER_DAX * sizeof(u64);

	/* Somewhere to store away the dax performance counter 48 bit values */
	unsigned long (*dax_counts)[DAX_PER_NODE][COUNTERS_PER_DAX];

	switch (cmd) {
	case DAXIOC_PERF_GET_NODE_COUNT:

		dax_perf_dbg("DAXIOC_PERF_GET_NODE_COUNT: nodes = %u",
			     max_nodes);

		if (copy_to_user((void __user *)(void *)arg, &max_nodes,
				 sizeof(max_nodes)))
			return -EFAULT;

		return 0;

	case DAXIOC_PERF_SET_COUNTERS:

		dax_perf_dbg("DAXIOC_PERF_SET_COUNTERS");

		/* Get the performance counter setup from user land */
		if (copy_from_user(&dax_config, (void __user *)arg,
				   sizeof(unsigned long)))
			return -EFAULT;

		/* Setup the dax performance counter configuration registers */
		dax_perf_dbg("DAXIOC_PERF_SET_COUNTERS: dax_config = 0x%lx",
			dax_config);

		for (node = 0; node < max_nodes; node++)
			for (dax = 0; dax < DAX_PER_NODE; dax++)
				dax_setup_counters(node, dax, dax_config);

		return 0;

	case DAXIOC_PERF_GET_COUNTERS:

		dax_perf_dbg("DAXIOC_PERF_GET_COUNTERS");

		/* Somewhere to store the count data */
		dax_counts = kmalloc(dax_count_bytes, GFP_KERNEL);
		if (!dax_counts)
			return -ENOMEM;

		/* Read the counters */
		for (node = 0; node < max_nodes; node++)
			for (dax = 0; dax < DAX_PER_NODE; dax++)
				dax_get_counters(node, dax, dax_counts);

		dax_perf_dbg("DAXIOC_PERF_GET_COUNTERS: copying %lu bytes of perf counter data",
			dax_count_bytes);

		if (copy_to_user((void __user *)(void *)arg, dax_counts,
				 dax_count_bytes))
			ret = -EFAULT;

		kfree(dax_counts);
		return ret;

	case DAXIOC_PERF_CLEAR_COUNTERS:

		dax_perf_dbg("DAXIOC_PERF_CLEAR_COUNTERS");

		/* Clear the counters */
		for (node = 0; node < max_nodes; node++)
			for (dax = 0; dax < DAX_PER_NODE; dax++)
				dax_clear_counters(node, dax);

		return 0;

	default:
		dax_dbg("Invalid command: 0x%x", cmd);
		return -ENOTTY;
	}
}
