// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 PEM EP driver
 *
 * Copyright (C) 2022 Marvell.
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/dma-mapping.h>

#define PEM_EP_DRV_NAME		"octeontx2-pem-ep"

#define PEM_DIS_PORT		0x50ull
#define PEM_BAR4_INDEX(x)	(0x700ull | (x << 3))

/* Address valid bit */
#define PEM_BAR4_INDEX_ADDR_V		BIT_ULL(0)
/* Access Cached bit */
#define PEM_BAR4_INDEX_CA		BIT_ULL(3)
#define PEM_BAR4_INDEX_ADDR_IDX(x)	((x) << 4)

#define PEM_BAR4_INDEX_START	8
#define PEM_BAR4_INDEX_END	16
#define PEM_BAR4_INDEX_SIZE	(4 * 1024 * 1024)
#define PEM_BAR4_INDEX_MEM	(64 * 1024 * 1024)


struct mv_pem_ep {
	struct device	*dev;
	void __iomem	*base;
	dma_addr_t	dh;
	void		*va;
};

static void pem_ep_reg_write(struct mv_pem_ep *pem_ep, u64 offset, u64 val)
{
	writeq(val, pem_ep->base + offset);
}

static int pem_ep_bar_setup(struct mv_pem_ep *pem_ep)
{
	int idx;

	pem_ep->va = dma_alloc_coherent(pem_ep->dev, PEM_BAR4_INDEX_MEM, &pem_ep->dh, GFP_KERNEL);
	if (!pem_ep->va)
		return -ENOMEM;

	for (idx = PEM_BAR4_INDEX_START; idx < PEM_BAR4_INDEX_END; idx++) {
		uint64_t val, addr;
		int i;

		/* Each index in BAR4 points to a 4MB region */
		i = idx - PEM_BAR4_INDEX_START;
		addr = pem_ep->dh + (i * PEM_BAR4_INDEX_SIZE);

		/* IOVA 52:22 is used by hardware */
		val = PEM_BAR4_INDEX_ADDR_IDX(addr >> 22);
		val |= PEM_BAR4_INDEX_ADDR_V;
		pem_ep_reg_write(pem_ep, PEM_BAR4_INDEX(idx), val);
	}

	/* Clear the PEMX_DIS_PORT[DIS_PORT] */
	pem_ep_reg_write(pem_ep, PEM_DIS_PORT, 1);

	return 0;
}

static int pem_ep_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mv_pem_ep *pem_ep;
	struct resource *res;
	int ret = 0;

	pem_ep = devm_kzalloc(dev, sizeof(*pem_ep), GFP_KERNEL);
	if (!pem_ep)
		return -ENOMEM;

	pem_ep->dev = dev;
	platform_set_drvdata(pdev, pem_ep);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pem_ep->base = ioremap(res->start, resource_size(res));
	if (IS_ERR(pem_ep->base)) {
		dev_err(dev, "error in mapping PEM EP base\n");
		return PTR_ERR(pem_ep->base);
	}

	ret = pem_ep_bar_setup(pem_ep);
	if (ret < 0) {
		dev_err(dev, "Error setting up EP BAR\n");
		goto err_exit;
	}

	return 0;

err_exit:
	dma_free_coherent(pem_ep->dev, PEM_BAR4_INDEX_MEM, pem_ep->va, pem_ep->dh);
	devm_kfree(dev, pem_ep);
	return ret;
}

static int pem_ep_remove(struct platform_device *pdev)
{
	struct mv_pem_ep *pem_ep = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	pr_info("Removing %s driver\n", PEM_EP_DRV_NAME);

	dma_free_coherent(pem_ep->dev, PEM_BAR4_INDEX_MEM, pem_ep->va, pem_ep->dh);
	devm_kfree(dev, pem_ep);

	return 0;
}

static const struct of_device_id pem_ep_of_match[] = {
	{ .compatible = "marvell,octeontx2-pem-ep", },
	{ .compatible = "marvell,cn10k-pem-ep", },
	{ },
};
MODULE_DEVICE_TABLE(of, pem_ep_of_match);

static const struct platform_device_id pem_ep_pdev_match[] = {
	{ .name = PEM_EP_DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, pem_ep_pdev_match);

static struct platform_driver pem_ep_driver = {
	.driver = {
		.name = PEM_EP_DRV_NAME,
		.of_match_table = pem_ep_of_match,
	},
	.probe = pem_ep_probe,
	.remove = pem_ep_remove,
	.id_table = pem_ep_pdev_match,
};

module_platform_driver(pem_ep_driver);

MODULE_DESCRIPTION("OcteonTX2 PEM EP Driver");
MODULE_AUTHOR("Marvell International Ltd.");
MODULE_LICENSE("GPL v2");

