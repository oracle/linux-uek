// SPDX-License-Identifier: GPL-2.0
/* Marvell GTI Watchdog driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/arm-smccc.h>
#include <linux/cpu.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/pci.h>

#include "gti.h"

#define DRV_NAME        "gti-watchdog"
#define DRV_VERSION     "1.0"

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell GTI Watchdog Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);

#define GTI_WDOG_MAGIC			'G'
#define SET_WATCHDOG			0x01
#define CLEAR_WATCHDOG			0x02
#define GTI_SET_WATCHDOG		_IOW(GTI_WDOG_MAGIC,	\
						SET_WATCHDOG, void *)
#define GTI_CLEAR_WATCHDOG		_IOW(GTI_WDOG_MAGIC,	\
						CLEAR_WATCHDOG, void *)

struct set_watchdog_args {
	uint64_t	watchdog_timeout_ms;
	uint64_t	core_mask;
};

static unsigned long g_mmio_base;
void __iomem *g_gti_devmem;

static void cleanup_gti_watchdog(void)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_REMOVE_WDOG, 0, 0, 0, 0, 0, 0, 0, &res);

	if (!res.a0)
		pr_warn("Failed to remove/clear watchdog handler: %ld\n",
			 res.a0);
}

static int gti_wdog_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int gti_wdog_close(struct inode *inode, struct file *file)
{
	cleanup_gti_watchdog();
	return 0;
}

void install_gti_cwd_wdog_secondary_cores(void *arg)
{
	struct set_watchdog_args *watchdog_args =
		(struct set_watchdog_args *)arg;
	struct arm_smccc_res res;

	pr_info("Installing GTI CWD on CPU %d\n", raw_smp_processor_id());

	arm_smccc_smc(OCTEONTX_INSTALL_WDOG, (uintptr_t)&el1_nmi_callback,
		smp_processor_id(), watchdog_args->watchdog_timeout_ms,
		watchdog_args->core_mask, 0, 0, 0, &res);

	if (!res.a0)
		pr_warn("Failed to install watchdog handler on core %d : %ld\n",
				raw_smp_processor_id(), res.a0);
}

void install_gti_cwd_wdog_all_cores(struct set_watchdog_args *watchdog_args)
{
	struct arm_smccc_res res;
	int cpu;

	for_each_online_cpu(cpu) {

		if (!(watchdog_args->core_mask & (1 << cpu)))
			continue;

		smp_call_function_single(cpu,
				install_gti_cwd_wdog_secondary_cores,
				(void *)watchdog_args, 1);
	}

	/*
	 * The last call actually sets up the wdog timers and
	 * enables the interrupts.
	 */

	pr_info("Setting and enable wdog timer on core %d\n", nr_cpu_ids);

	arm_smccc_smc(OCTEONTX_INSTALL_WDOG, (uintptr_t)&el1_nmi_callback,
		nr_cpu_ids, watchdog_args->watchdog_timeout_ms,
		watchdog_args->core_mask, 0, 0, 0, &res);

	if (!res.a0)
		pr_warn("Failed to install watchdog handler on core %d : %ld\n",
				nr_cpu_ids, res.a0);
}

static long gti_wdog_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	struct set_watchdog_args watchdog_args;

	if (cmd == GTI_SET_WATCHDOG) {
		pr_info("OCTEONTX_INSTALL_WDOG\n");

		if (copy_from_user(&watchdog_args, (char *)arg,
			sizeof(struct set_watchdog_args)))
			return -EFAULT;

		pr_info("timeout = %lld, core_mask = 0x%llx\n",
			watchdog_args.watchdog_timeout_ms,
			watchdog_args.core_mask);

		install_gti_cwd_wdog_all_cores(&watchdog_args);

	} else if (cmd == GTI_CLEAR_WATCHDOG) {
		pr_info("OCTEONTX_CLEAR_WDOG\n");

		cleanup_gti_watchdog();
	} else {
		return -ENOTTY;
	}
	return 0;
}

static int gti_wdog_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	int ret;

	pr_info("%s invoked, size = %ld\n", __func__, size);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	ret = io_remap_pfn_range(vma, vma->vm_start,
				g_mmio_base >> PAGE_SHIFT,
				size, vma->vm_page_prot);
	if (ret) {
		pr_info("%s failed, ret = %d\n", __func__, ret);
		return -EAGAIN;
	}

	return 0;
}

static const struct file_operations gti_wdog_fops = {
	.owner = THIS_MODULE,
	.open = gti_wdog_open,
	.release = gti_wdog_close,
	.unlocked_ioctl = gti_wdog_ioctl,
	.mmap  = gti_wdog_mmap,
};

static struct miscdevice gti_wdog_miscdevice = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "gti_watchdog",
	.fops = &gti_wdog_fops,
};

static int gti_wdog_probe(struct platform_device *pdev)
{
	struct resource *r;
	int ret_val;

	pr_info("gti wdog platform driver init\n");

	/* get our first memory resource from the device tree */
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		pr_err("IORESOURCE_MEM, 0 does not exist\n");
		return -EINVAL;
	}
	pr_info("r->start = 0x%08lx\n", (unsigned long int)r->start);
	pr_info("r->end = 0x%08lx\n", (unsigned long int)r->end);
	g_mmio_base = r->start;

	g_gti_devmem = devm_ioremap_resource(&pdev->dev, r);
	if (IS_ERR(g_gti_devmem))
		pr_warn("Could not ioremap gti device memory\n");

	ret_val = misc_register(&gti_wdog_miscdevice);
	if (ret_val != 0) {
		if (g_gti_devmem)
			devm_iounmap(&pdev->dev, g_gti_devmem);
		pr_warn("Could not register gti wdog misc device\n");
	}

	return 0;
}

static int gti_wdog_remove(struct platform_device *pdev)
{
	pr_info("gti wdog platform driver exit\n");
	if (g_gti_devmem)
		devm_iounmap(&pdev->dev, g_gti_devmem);
	misc_deregister(&gti_wdog_miscdevice);
	return 0;
}

static const struct of_device_id gti_wdog_of_ids[] = {
	{ .compatible = "marvell,octeontx2-timer"},
	{},
};

static struct platform_driver gti_wdog_driver = {
	.probe = gti_wdog_probe,
	.remove = gti_wdog_remove,
	.driver = {
		.name = "gti_watchdog",
		.of_match_table = gti_wdog_of_ids,
		.owner = THIS_MODULE,
	},
};

module_platform_driver(gti_wdog_driver);
