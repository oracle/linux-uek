/******************************************************************************
 * mcelog.c
 * Driver for receiving and transferring machine check error infomation
 *
 * Copyright (c) 2012 Intel Corporation
 * Author: Liu, Jinsong <jinsong.liu@intel.com>
 * Author: Jiang, Yunhong <yunhong.jiang@intel.com>
 * Author: Ke, Liping <liping.ke@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/mce.h>

#include <xen/interface/xen.h>
#include <xen/events.h>
#include <xen/interface/vcpu.h>
#include <xen/xen.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

#define XEN_MCELOG "xen_mcelog: "

static struct mc_info g_mi;
static struct mcinfo_logical_cpu *g_physinfo;
static uint32_t ncpus;

static DEFINE_SPINLOCK(mcelog_lock);

static int convert_log(struct mc_info *mi)
{
	struct mcinfo_common *mic;
	struct mcinfo_global *mc_global;
	struct mcinfo_bank *mc_bank;
	struct mce m;
	uint32_t i;

	mic = NULL;
	x86_mcinfo_lookup(&mic, mi, MC_TYPE_GLOBAL);
	if (unlikely(!mic)) {
		pr_warning(XEN_MCELOG "Failed to find global error info\n");
		return -ENODEV;
	}

	mce_setup(&m);
	mc_global = (struct mcinfo_global *)mic;
	m.mcgstatus = mc_global->mc_gstatus;
	m.apicid = mc_global->mc_apicid;

	for (i = 0; i < ncpus; i++)
		if (g_physinfo[i].mc_apicid == m.apicid)
			break;
	if (unlikely(i == ncpus)) {
		pr_warning(XEN_MCELOG "Failed to match cpu with apicid %d\n",
			   m.apicid);
		return -ENODEV;
	}

	m.socketid = g_physinfo[i].mc_chipid;
	m.cpu = m.extcpu = g_physinfo[i].mc_cpunr;
	m.cpuvendor = (__u8)g_physinfo[i].mc_vendor;
	m.mcgcap = g_physinfo[i].mc_msrvalues[__MC_MSR_MCGCAP].value;

	mic = NULL;
	x86_mcinfo_lookup(&mic, mi, MC_TYPE_BANK);
	if (unlikely(!mic)) {
		pr_warning(XEN_MCELOG "Fail to find bank error info\n");
		return -ENODEV;
	}

	do {
		if ((!mic) || (mic->size == 0) ||
		    (mic->type != MC_TYPE_GLOBAL   &&
		     mic->type != MC_TYPE_BANK     &&
		     mic->type != MC_TYPE_EXTENDED &&
		     mic->type != MC_TYPE_RECOVERY))
			break;

		if (mic->type == MC_TYPE_BANK) {
			mc_bank = (struct mcinfo_bank *)mic;
			m.misc = mc_bank->mc_misc;
			m.status = mc_bank->mc_status;
			m.addr = mc_bank->mc_addr;
			m.tsc = mc_bank->mc_tsc;
			m.bank = mc_bank->mc_bank;
			m.finished = 1;
			/*log this record*/
			mce_log(&m);
		}
		mic = x86_mcinfo_next(mic);
	} while (1);

	return 0;
}

static int mc_queue_handle(uint32_t flags)
{
	struct xen_mc mc_op;
	int ret = 0;
	unsigned long tmp;

	spin_lock_irqsave(&mcelog_lock, tmp);

	mc_op.cmd = XEN_MC_fetch;
	mc_op.interface_version = XEN_MCA_INTERFACE_VERSION;
	set_xen_guest_handle(mc_op.u.mc_fetch.data, &g_mi);
	do {
		mc_op.u.mc_fetch.flags = flags;
		ret = HYPERVISOR_mca(&mc_op);
		if (ret) {
			pr_err(XEN_MCELOG "Failed to fetch %s error log\n",
			       (flags == XEN_MC_URGENT) ?
			       "urgnet" : "nonurgent");
			break;
		}

		if (mc_op.u.mc_fetch.flags & XEN_MC_NODATA ||
		    mc_op.u.mc_fetch.flags & XEN_MC_FETCHFAILED)
			break;
		else {
			ret = convert_log(&g_mi);
			if (ret)
				pr_warning(XEN_MCELOG
					   "Failed to convert this error log, "
					   "continue acking it anyway\n");

			mc_op.u.mc_fetch.flags = flags | XEN_MC_ACK;
			ret = HYPERVISOR_mca(&mc_op);
			if (ret) {
				pr_err(XEN_MCELOG
				       "Failed to ack previous error log\n");
				break;
			}
		}
	} while (1);

	spin_unlock_irqrestore(&mcelog_lock, tmp);

	return ret;
}

/* virq handler for machine check error info*/
static irqreturn_t xen_mce_interrupt(int irq, void *dev_id)
{
	int err;

	/* urgent mc_info */
	err = mc_queue_handle(XEN_MC_URGENT);
	if (err)
		pr_err(XEN_MCELOG
		       "Failed to handle urgent mc_info queue, "
		       "continue handling nonurgent mc_info queue anyway.\n");

	/* nonurgent mc_info */
	err = mc_queue_handle(XEN_MC_NONURGENT);
	if (err)
		pr_err(XEN_MCELOG
		       "Failed to handle nonurgent mc_info queue.\n");

	return IRQ_HANDLED;
}

static int bind_virq_for_mce(void)
{
	int ret;
	struct xen_mc mc_op;

	memset(&mc_op, 0, sizeof(struct xen_mc));

	/* Fetch physical CPU Numbers */
	mc_op.cmd = XEN_MC_physcpuinfo;
	mc_op.interface_version = XEN_MCA_INTERFACE_VERSION;
	set_xen_guest_handle(mc_op.u.mc_physcpuinfo.info, g_physinfo);
	ret = HYPERVISOR_mca(&mc_op);
	if (ret) {
		pr_err(XEN_MCELOG "Failed to get CPU numbers\n");
		return ret;
	}

	/* Fetch each CPU Physical Info for later reference*/
	ncpus = mc_op.u.mc_physcpuinfo.ncpus;
	g_physinfo = kcalloc(ncpus, sizeof(struct mcinfo_logical_cpu),
			     GFP_KERNEL);
	if (!g_physinfo)
		return -ENOMEM;
	set_xen_guest_handle(mc_op.u.mc_physcpuinfo.info, g_physinfo);
	ret = HYPERVISOR_mca(&mc_op);
	if (ret) {
		pr_err(XEN_MCELOG "Failed to get CPU info\n");
		kfree(g_physinfo);
		return ret;
	}

	ret  = bind_virq_to_irqhandler(VIRQ_MCA, 0,
				       xen_mce_interrupt, 0, "mce", NULL);
	if (ret < 0) {
		pr_err(XEN_MCELOG "Failed to bind virq\n");
		kfree(g_physinfo);
		return ret;
	}

	return 0;
}

static int __init mcelog_init(void)
{
	/* Only DOM0 is responsible for MCE logging */
	if (xen_initial_domain())
		return bind_virq_for_mce();

	return -ENODEV;
}
late_initcall(mcelog_init);
