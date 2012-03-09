/******************************************************************************
 * mcelog.c
 * Add Machine Check event Logging support in DOM0
 *
 * Driver for receiving and logging machine check event
 *
 * Copyright (c) 2008, 2009 Intel Corporation
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
#include <xen/interface/xen.h>
#include <asm/xen/hypervisor.h>
#include <xen/events.h>
#include <xen/interface/vcpu.h>
#include <asm/xen/hypercall.h>
#include <asm/mce.h>
#include <xen/xen.h>

static mc_info_t *g_mi;
static mcinfo_logical_cpu_t *g_physinfo;
static uint32_t ncpus;

static int convert_log(struct mc_info *mi)
{
	struct mcinfo_common *mic = NULL;
	struct mcinfo_global *mc_global;
	struct mcinfo_bank *mc_bank;
	struct mce m;
	int i, found = 0;

	x86_mcinfo_lookup(&mic, mi, MC_TYPE_GLOBAL);
	WARN_ON(!mic);

	mce_setup(&m);
	mc_global = (struct mcinfo_global *)mic;
	m.mcgstatus = mc_global->mc_gstatus;
	m.apicid = mc_global->mc_apicid;
	for (i = 0; i < ncpus; i++) {
		if (g_physinfo[i].mc_apicid == m.apicid) {
			found = 1;
			break;
		}
	}
	WARN_ON(!found);

	m.socketid = g_physinfo[i].mc_chipid;
	m.cpu = m.extcpu = g_physinfo[i].mc_cpunr;
	m.cpuvendor = (__u8)g_physinfo[i].mc_vendor;
	m.mcgcap = g_physinfo[i].mc_msrvalues[0].value;
	x86_mcinfo_lookup(&mic, mi, MC_TYPE_BANK);
	do {
		if (mic == NULL || mic->size == 0)
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

/*pv_ops domain mce virq handler, logging physical mce error info*/
static irqreturn_t mce_dom_interrupt(int irq, void *dev_id)
{
	xen_mc_t mc_op;
	int result = 0;

	mc_op.cmd = XEN_MC_fetch;
	mc_op.interface_version = XEN_MCA_INTERFACE_VERSION;
	set_xen_guest_handle(mc_op.u.mc_fetch.data, g_mi);
urgent:
	mc_op.u.mc_fetch.flags = XEN_MC_URGENT;
	result = HYPERVISOR_mca(&mc_op);
	if (result || mc_op.u.mc_fetch.flags & XEN_MC_NODATA ||
			mc_op.u.mc_fetch.flags & XEN_MC_FETCHFAILED)
		goto nonurgent;
	else {
		result = convert_log(g_mi);
		if (result)
			goto end;
		/* After fetching the error event log entry from DOM0,
		 * we need to dec the refcnt and release the entry.
		 * The entry is reserved and inc refcnt when filling
		 * the error log entry.
		 */
		mc_op.u.mc_fetch.flags = XEN_MC_URGENT | XEN_MC_ACK;
		result = HYPERVISOR_mca(&mc_op);
		goto urgent;
	}
nonurgent:
	mc_op.u.mc_fetch.flags = XEN_MC_NONURGENT;
	result = HYPERVISOR_mca(&mc_op);
	if (result || mc_op.u.mc_fetch.flags & XEN_MC_NODATA ||
			mc_op.u.mc_fetch.flags & XEN_MC_FETCHFAILED)
		goto end;
	else {
		result = convert_log(g_mi);
		if (result)
			goto end;
		/* After fetching the error event log entry from DOM0,
		 * we need to dec the refcnt and release the entry. The
		 * entry is reserved and inc refcnt when filling the
		 * error log entry.
		 */
		mc_op.u.mc_fetch.flags = XEN_MC_NONURGENT | XEN_MC_ACK;
		result = HYPERVISOR_mca(&mc_op);
		goto nonurgent;
	}
end:
	return IRQ_HANDLED;
}

static int bind_virq_for_mce(void)
{
	int ret;
	xen_mc_t mc_op;

	g_mi = kmalloc(sizeof(struct mc_info), GFP_KERNEL);

	if (!g_mi)
		return -ENOMEM;

	/* Fetch physical CPU Numbers */
	mc_op.cmd = XEN_MC_physcpuinfo;
	mc_op.interface_version = XEN_MCA_INTERFACE_VERSION;
	set_xen_guest_handle(mc_op.u.mc_physcpuinfo.info, g_physinfo);
	ret = HYPERVISOR_mca(&mc_op);
	if (ret) {
		printk(KERN_ERR "MCE_DOM0_LOG: Fail to get physical CPU numbers\n");
		kfree(g_mi);
		return ret;
	}

	/* Fetch each CPU Physical Info for later reference*/
	ncpus = mc_op.u.mc_physcpuinfo.ncpus;
	g_physinfo = kmalloc(sizeof(struct mcinfo_logical_cpu)*ncpus,
					GFP_KERNEL);
	if (!g_physinfo) {
		kfree(g_mi);
		return -ENOMEM;
	}
	set_xen_guest_handle(mc_op.u.mc_physcpuinfo.info, g_physinfo);
	ret = HYPERVISOR_mca(&mc_op);
	if (ret) {
		printk(KERN_ERR "MCE_DOM0_LOG: Fail to get physical CPUs info\n");
		kfree(g_mi);
		kfree(g_physinfo);
		return ret;
	}

	ret  = bind_virq_to_irqhandler(VIRQ_MCA, 0,
		mce_dom_interrupt, 0, "mce", NULL);

	if (ret < 0) {
		printk(KERN_ERR "MCE_DOM0_LOG: bind_virq for DOM0 failed\n");
		return ret;
	}

	return 0;
}

static int __init mcelog_init(void)
{
	/* Only DOM0 is responsible for MCE logging */
	if (xen_initial_domain())
		return bind_virq_for_mce();

	return 0;
}


static void __exit mcelog_cleanup(void)
{
	kfree(g_mi);
	kfree(g_physinfo);
}
module_init(mcelog_init);
module_exit(mcelog_cleanup);

MODULE_LICENSE("GPL");
