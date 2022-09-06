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
#include <linux/uio_driver.h>

#define PEM_EP_DRV_NAME		"octeontx2-pem-ep"

#define PEM_DIS_PORT		0x50ull
#define PEM_CFG                 0x00D8ull
#define PEM_RST_INT             0x0300ull
#define PEM_RST_INT_ENA_W1C     0x0310ull
#define PEM_RST_INT_ENA_W1S     0x0318ull
#define PEM_BAR4_INDEX(x)	(0x700ull | (x << 3))

#define PEM_RST_INT_B_L2        BIT_ULL(2)
#define PEM_RST_INT_B_LINKDOWN  BIT_ULL(1)
#define PEM_RST_INT_B_PERST     BIT_ULL(0)

/* Address valid bit */
#define PEM_BAR4_INDEX_ADDR_V		BIT_ULL(0)
/* Access Cached bit */
#define PEM_BAR4_INDEX_CA		BIT_ULL(3)
#define PEM_BAR4_INDEX_ADDR_IDX(x)	((x) << 4)

#define PEM_BAR4_INDEX_START	8
#define PEM_BAR4_INDEX_END	16
#define PEM_BAR4_INDEX_SIZE	(4 * 1024 * 1024)
#define PEM_BAR4_INDEX_MEM	(64 * 1024 * 1024)

/* Some indexes have specific non-memory uses */
#define PEM_BAR4_INDEX_PTP	14
#define MIO_PTP_BASE_ADDR	0x807000000f00

#define	UIO_PERST_VERSION	"0.1"

struct mv_pem_ep {
	struct device	*dev;
	void __iomem	*base;
	void		*va;
	struct uio_info	uio_rst_int_perst;
};

static u64 pem_ep_reg_read(struct mv_pem_ep *pem_ep, u64 offset)
{
	return readq(pem_ep->base + offset);
}

static void pem_ep_reg_write(struct mv_pem_ep *pem_ep, u64 offset, u64 val)
{
	writeq(val, pem_ep->base + offset);
}

static irqreturn_t pem_rst_perst_handler(int irq, struct uio_info *uio_info)
{
	struct mv_pem_ep *pem_ep;
	u64 regval;

	pem_ep = container_of(uio_info, struct mv_pem_ep, uio_rst_int_perst);

	regval = pem_ep_reg_read(pem_ep, PEM_RST_INT);
	if (regval & PEM_RST_INT_B_PERST)
		pem_ep_reg_write(pem_ep, PEM_RST_INT, PEM_RST_INT_B_PERST);
	else
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static int register_perst_uio_dev(struct platform_device *pdev, struct mv_pem_ep *pem_ep)
{
	struct device_node *of_node;
	struct uio_info *uio_info;
	struct device *dev;
	int irq, ret;
	u64 regval;

	dev = &pdev->dev;
	of_node = dev->of_node;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	uio_info = &pem_ep->uio_rst_int_perst;
	uio_info->name = "PEM_RST_INT:PERST";
	uio_info->version = UIO_PERST_VERSION;
	uio_info->irq = irq;
	uio_info->irq_flags = IRQF_SHARED;
	uio_info->handler = pem_rst_perst_handler;

	ret = uio_register_device(dev, uio_info);
	if (ret != 0) {
		dev_err(dev, "Error %d registering PERST UIO device\n", ret);
		ret = -ENODEV;
		goto err_exit;
	}

	/* clear all RST interrupt enables */
	pem_ep_reg_write(pem_ep, PEM_RST_INT_ENA_W1C,
			 PEM_RST_INT_B_L2 | PEM_RST_INT_B_LINKDOWN | PEM_RST_INT_B_PERST);

	/* clear RST interrupt status */
	regval = pem_ep_reg_read(pem_ep, PEM_RST_INT);
	dev_info(dev, "PEM_RST_INT: 0x%llx\n", regval);
	pem_ep_reg_write(pem_ep, PEM_RST_INT, regval);

	/* set RST PERST & LINKDOWN interrupt enables */
	pem_ep_reg_write(pem_ep, PEM_RST_INT_ENA_W1S,
			 PEM_RST_INT_B_PERST | PEM_RST_INT_B_LINKDOWN);

	return 0;

err_exit:
	return ret;
}

static int pem_ep_bar_setup(struct mv_pem_ep *pem_ep)
{
	phys_addr_t pa;
	int idx;
	uint64_t val;

	pem_ep->va = devm_kzalloc(pem_ep->dev, PEM_BAR4_INDEX_MEM, GFP_KERNEL);
	if (!pem_ep->va)
		return -ENOMEM;

	pa = virt_to_phys(pem_ep->va);
	for (idx = PEM_BAR4_INDEX_START; idx < PEM_BAR4_INDEX_END; idx++) {
		phys_addr_t addr;
		int i;

		/* Each index in BAR4 points to a 4MB region */
		i = idx - PEM_BAR4_INDEX_START;
		addr = pa + (i * PEM_BAR4_INDEX_SIZE);

		/* IOVA 52:22 is used by hardware */
		val = PEM_BAR4_INDEX_ADDR_IDX(addr >> 22);
		val |= PEM_BAR4_INDEX_ADDR_V;
		pem_ep_reg_write(pem_ep, PEM_BAR4_INDEX(idx), val);
	}
	/* Set up mapping used by host PHC driver, which needs access to
	 * PTP registers on Octeon.  This overrides the generic memory
	 * mapping for this index done above.
	 */
	val = PEM_BAR4_INDEX_ADDR_IDX(MIO_PTP_BASE_ADDR >> 22);
	val |= PEM_BAR4_INDEX_ADDR_V;
	pem_ep_reg_write(pem_ep, PEM_BAR4_INDEX(PEM_BAR4_INDEX_PTP), val);

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

	/* register the PERST interrupt UIO device */
	ret = register_perst_uio_dev(pdev, pem_ep);
	if (ret < 0) {
		dev_err(dev, "Error registering UIO PERST device\n");
		goto err_exit;
	}

	return 0;

err_exit:
	devm_kfree(pem_ep->dev, pem_ep->va);
	devm_kfree(dev, pem_ep);
	return ret;
}

static int pem_ep_remove(struct platform_device *pdev)
{
	struct mv_pem_ep *pem_ep = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	pr_info("Removing %s driver\n", PEM_EP_DRV_NAME);

	devm_kfree(pem_ep->dev, pem_ep->va);
	uio_unregister_device(&pem_ep->uio_rst_int_perst);
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

