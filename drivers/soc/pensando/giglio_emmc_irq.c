// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AMD Pensando Giglio SoC eMMC Interrupt Handler
 *
 * Copyright 2023 Advanced Micro Devices, Inc.
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
 * The emmc_int reg base/size region is a small mapping that includes the
 * Giglio EM CSR interrupt and AXI interrupt registers to initialize and
 * service the eMMC interrupt.  Below are offsets to iomem base.
 */
#define GIG_EM_CSR_CSR_INT        0xc   /* gig_em_csr.csr_intr */
#define GIG_EM_CSR_AXI_INTREG     0x20  /* gig_em_csr.axi.intreg */
#define GIG_EM_CSR_AXI_INT_TEST   0x24  /* gig_em_csr.axi.int_test_set */
#define GIG_EM_CSR_AXI_INT_ENABLE 0x28  /* gig_em_csr.axi.int_enable_set */
#define GIG_EM_CSR_AXI_INT_CLEAR  0x2c  /* gig_em_csr.axi.int_enable_clear */

static irqreturn_t emmc_irq_handler(int irq, void *regs)
{
	writel(BIT(1), regs + GIG_EM_CSR_AXI_INTREG);
	return IRQ_HANDLED;
}

static int giglio_emmc_irq_probe(struct platform_device *pdev)
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

	if (!request_mem_region(res.start, res_size, "emmc_int")) {
		pr_err("Failed to request memory region\n");
		return -EBUSY;
	}

	regs = ioremap(res.start, res_size);
	if (!regs) {
		pr_err("Failed to remap memory region\n");
		ret = -ENOMEM;
		goto release_resource;
	}

	writel(GENMASK(11, 0), regs + GIG_EM_CSR_AXI_INT_CLEAR); /* Disable interrupts */
	writel(GENMASK(11, 0), regs + GIG_EM_CSR_AXI_INTREG);    /* Ack interrupts */
	writel(BIT(1), regs + GIG_EM_CSR_CSR_INT);               /* Enable downstream int */
	writel(BIT(1), regs + GIG_EM_CSR_AXI_INT_ENABLE);        /* Enable eMMC int */

	irq = irq_of_parse_and_map(node, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev, "Failed to map interrupt\n");
		ret = -ENXIO;
		goto unmap_regs;
	}

	ret = request_irq(irq, emmc_irq_handler, IRQF_SHARED, "emmc_int", regs);
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

static const struct of_device_id giglio_emmc_irq_of_match[] = {
	{ .compatible = "pensando,giglio-emmc-interrupt" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, giglio_emmc_irq_of_match);

static struct platform_driver giglio_emmc_irq = {
	.probe = giglio_emmc_irq_probe,
	.driver = {
		.name = "emmc_int",
		.of_match_table = giglio_emmc_irq_of_match,
		.owner = THIS_MODULE,
	},
};

module_platform_driver(giglio_emmc_irq);

MODULE_AUTHOR("Brad Larson <blarson@amd.com>");
MODULE_DESCRIPTION("AMD Pensando Giglio SoC eMMC IRQ Handler");
MODULE_LICENSE("GPL");
