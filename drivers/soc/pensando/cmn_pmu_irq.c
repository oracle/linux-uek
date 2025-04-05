// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AMD Pensando Salina SoC CMN PMU Interrupt Handler
 *
 * Copyright 2024 Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

/*
 * The cmn_pmu_int reg base/size region is a small mapping that includes the
 * Salina CMN PMU CSR interrupt and AXI interrupt registers to initialize and
 * service the CMN PMU interrupt.  Below are offsets to iomem base.
 */
#define SAL_CMN_PMU_CSR_CSR_INT         0x00
#define SAL_CMN_PMU_CSR_NXCW_INTREG     0x20
#define SAL_CMN_PMU_CSR_NXCW_INT_TEST   0x24
#define SAL_CMN_PMU_CSR_NXCW_INT_ENABLE 0x28
#define SAL_CMN_PMU_CSR_NXCW_INT_CLEAR  0x2c

static irqreturn_t cmn_pmu_irq_handler(int irq, void *regs)
{
	writel(BIT(0), regs + SAL_CMN_PMU_CSR_NXCW_INTREG);
	return IRQ_HANDLED;
}

static int salina_cmn_pmu_irq_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct resource res;
	void __iomem *regs;
	size_t res_size;
	int irq, ret;

	ret = of_address_to_resource(node, 0, &res);
	if (ret) {
		pr_err("Failed to get memory resource\n");
		return ret;
	}
	res_size = resource_size(&res);

	if (!request_mem_region(res.start, res_size, "cmn_pmu_int")) {
		pr_err("Failed to request memory region\n");
		return -EBUSY;
	}

	regs = ioremap(res.start, res_size);
	if (!regs) {
		pr_err("Failed to remap memory region\n");
		ret = -ENOMEM;
		goto release_resource;
	}

	writel(GENMASK(13, 0), regs + SAL_CMN_PMU_CSR_NXCW_INT_CLEAR); /* Disable interrupts */
	writel(GENMASK(13, 0), regs + SAL_CMN_PMU_CSR_NXCW_INTREG);    /* Ack interrupts */
	writel(BIT(1), regs + SAL_CMN_PMU_CSR_CSR_INT);                /* Enable downstream int */
	writel(BIT(0), regs + SAL_CMN_PMU_CSR_NXCW_INT_ENABLE);        /* Enable eMMC int */

	irq = irq_of_parse_and_map(node, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev, "Failed to map interrupt\n");
		ret = -ENXIO;
		goto unmap_regs;
	}

	ret = request_irq(irq, cmn_pmu_irq_handler, IRQF_NOBALANCING | IRQF_NO_THREAD | IRQF_SHARED, "cmn_pmu_int", regs);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request IRQ\n");
		goto unmap_regs;
	}
	return 0;

unmap_regs:
	iounmap(regs);
release_resource:
	release_mem_region(res.start, res_size);
	return ret;
}

static const struct of_device_id salina_cmn_pmu_irq_of_match[] = {
	{ .compatible = "pensando,salina-cmn-pmu-interrupt" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, salina_cmn_pmu_irq_of_match);

static struct platform_driver salina_cmn_pmu_irq = {
	.probe = salina_cmn_pmu_irq_probe,
	.driver = {
		.name = "cmn_pmu_int",
		.of_match_table = salina_cmn_pmu_irq_of_match,
		.owner = THIS_MODULE,
	},
};

module_platform_driver(salina_cmn_pmu_irq);

MODULE_AUTHOR("Darshan Prajapati <darshan.prajapati@amd.com>");
MODULE_DESCRIPTION("AMD Pensando Salina SoC CMN PMU IRQ Handler");
MODULE_LICENSE("GPL");
