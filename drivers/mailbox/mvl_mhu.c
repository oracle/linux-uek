// SPDX-License-Identifier: GPL-2.0
/*
 * Marvell Message Handling Unit driver
 *
 * Copyright (C) 2019-2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt)	"mvl-mhu: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/acpi.h>
#include <linux/mailbox_controller.h>
#include <linux/spinlock.h>

#define MHU_PCHANS_NUM 1

#define BAR0 0
#define SCP_INDEX    0x0
#define DEV_AP0      0x2
#define SCP_TO_AP_INTERRUPT 2
#define DRV_NAME "mbox-thunderx"

#define XCPX_DEVY_XCP_MBOX_LINT_OFFSET 0x000E1C00
#define XCP_TO_DEV_XCP_MBOX_LINT(xcp_core, device_id)  \
	(XCPX_DEVY_XCP_MBOX_LINT_OFFSET | \
	((uint64_t)(xcp_core) << 36) | \
	((uint64_t)(device_id) << 4))

#define AP0_TO_SCP_MBOX_LINT    XCP_TO_DEV_XCP_MBOX_LINT(SCP_INDEX, DEV_AP0)

/*
 * Doorbell-Register: XCP(0..1)_DEV(0..7)_XCP_MBOX
 * Communication data from devices to XCP. When written, sets
 * XCP(0..1)_DEV(0..7)_XCP_MBOX.
 * PS: it doesn't matter what is written into this register,
 * Attempting to writing 'anything' would cause an interrupt
 * to the target!
 */

#define DONT_CARE_DATA               0xFF
#define XCPX_DEVY_XCP_MBOX_OFFSET    0x000E1000
#define XCP_TO_DEV_XCP_MBOX(xcp_core, device_id) \
	(XCPX_DEVY_XCP_MBOX_OFFSET | \
	((uint64_t)(xcp_core) << 36) | \
	((uint64_t)(device_id) << 4))

/* AP0-to-SCP doorbell */
#define AP0_TO_SCP_MBOX         XCP_TO_DEV_XCP_MBOX(SCP_INDEX, DEV_AP0)

/*  Register offset: Enable interrupt from SCP to AP */
#define XCP0_XCP_DEV0_MBOX_RINT_ENA_W1S 0x000D1C40
#define XCP0_XCP_DEV1_MBOX_RINT_ENA_W1S 0x000D1C50
#define XCP0_XCP_DEV2_MBOX_RINT_ENA_W1S 0x000D1C60
#define XCP0_XCP_DEV3_MBOX_RINT_ENA_W1S 0x000D1C70

/* Rx interrupt from SCP to Non-secure AP (linux kernel) */
#define XCPX_XCP_DEVY_MBOX_RINT_OFFSET 0x000D1C00
#define XCPX_XCP_DEVY_MBOX_RINT(xcp_core, device_id) \
	(XCPX_XCP_DEVY_MBOX_RINT_OFFSET | \
	((uint64_t)(xcp_core) << 36) | \
	((uint64_t)(device_id) << 4))

/* The interrupt status register */
#define SCP_TO_AP0_MBOX_RINT  XCPX_XCP_DEVY_MBOX_RINT(SCP_INDEX, DEV_AP0)

#define XCPX_XCP_DEVY_MBOX_RINT_OFFSET 0x000D1C00
#define XCPX_XCP_DEVY_MBOX_RINT(xcp_core, device_id) \
	(XCPX_XCP_DEVY_MBOX_RINT_OFFSET | \
	((uint64_t)(xcp_core) << 36) | \
	((uint64_t)(device_id) << 4))

#define SCP_TO_AP0_MBOX_RINT  XCPX_XCP_DEVY_MBOX_RINT(SCP_INDEX, DEV_AP0)
#define SCP_TO_DEV0 XCPX_XCP_DEVY_MBOX_RINT(0, 0)
#define SCP_TO_DEV1 XCPX_XCP_DEVY_MBOX_RINT(0, 1)
#define SCP_TO_DEV2 XCPX_XCP_DEVY_MBOX_RINT(0, 2)
#define SCP_TO_DEV3 XCPX_XCP_DEVY_MBOX_RINT(0, 3)

struct mhu {
	struct device *dev;

	/* SCP link information */
	void __iomem *base; /* tx_reg, rx_reg */
	void __iomem *payload; /* Shared mem */
	struct mbox_chan *chan;
};

#define MHU_CHANNEL_INDEX(mhu, chan) (chan - &mhu->chan[0])

/* Sources of interrupt */
enum {
	INDEX_INT_SRC_SCMI_TX,
	INDEX_INT_SRC_AVS_STS,
	INDEX_INT_SRC_NONE,
};

/* information of interrupts from SCP */
struct int_src_data_s {
	uint64_t int_src_cnt;
	uint64_t int_src_data;
};

/* Secures static data processed in the handler */
DEFINE_SPINLOCK(mhu_irq_spinlock);

/* bottom half of rx interrupt */
static irqreturn_t mhu_rx_interrupt_thread(int irq, void *p)
{
	struct mhu *mhu = (struct mhu *)p;
	struct int_src_data_s *data = (struct int_src_data_s *)mhu->payload;
	u64 val, scmi_tx_cnt, avs_failure_cnt;

	/*
	 * Local copy of event counters. A mismatch of received
	 * count value and the local copy means additional events
	 * are being flagged that needs to be attended by AP
	 */
	static u64 event_counter[INDEX_INT_SRC_NONE] = {0};

	spin_lock_irq(&mhu_irq_spinlock);
	/* scmi interrupt */
	scmi_tx_cnt = readq(&data[INDEX_INT_SRC_SCMI_TX].int_src_cnt);
	if (event_counter[INDEX_INT_SRC_SCMI_TX] != scmi_tx_cnt) {
		mbox_chan_received_data(mhu->chan, (void *)&val);
		/* Update the memory to prepare for next */
		event_counter[INDEX_INT_SRC_SCMI_TX] = scmi_tx_cnt;
	}

	/* AVS failures */
	avs_failure_cnt = readq(&data[INDEX_INT_SRC_AVS_STS].int_src_cnt);
	if (event_counter[INDEX_INT_SRC_AVS_STS] != avs_failure_cnt) {
		pr_err("!!! FATAL ERROR IN AVS BUS !!! FATAL ERROR IN AVS BUS !!!\n");
		/* Update the memory to prepare for next */
		event_counter[INDEX_INT_SRC_AVS_STS] = avs_failure_cnt;
	}
	spin_unlock_irq(&mhu_irq_spinlock);

	return IRQ_HANDLED;
}

static irqreturn_t mhu_rx_interrupt(int irq, void *p)
{
	struct mhu *mhu = (struct mhu *)p;
	u64 val;

	/* Read interrupt status register */
	val = readq_relaxed(mhu->base + SCP_TO_AP0_MBOX_RINT);
	if (val) {
		/* Clear the interrupt : Write on clear */
		writeq_relaxed(1ul, mhu->base + SCP_TO_AP0_MBOX_RINT);
	} else {
		return IRQ_NONE;
	}

	return IRQ_WAKE_THREAD;
}

static int mhu_send_data(struct mbox_chan *chan, void *data)
{
	struct mhu *mhu = chan->con_priv;

	iowrite64(DONT_CARE_DATA, mhu->base + AP0_TO_SCP_MBOX);

	return 0;
}

static bool mhu_last_tx_done(struct mbox_chan *chan)
{
	struct mhu *mhu = chan->con_priv;
	u64 status;

	status = ioread64(mhu->base + XCPX_XCP_DEVY_MBOX_RINT(0, 2));
	pr_debug("last_tx_done status: %#llx\n", status);

	return status != 0;
}

static const struct mbox_chan_ops mhu_chan_ops = {
	.send_data = mhu_send_data,
	.last_tx_done = mhu_last_tx_done,
};

static struct mbox_chan mhu_chan = {};

static struct mbox_controller mhu_mbox_ctrl = {
	.chans = &mhu_chan,
	.num_chans = MHU_PCHANS_NUM,
	.txdone_irq = false,
	.txdone_poll = true,
	.txpoll_period = 100,
	.ops = &mhu_chan_ops,
};

static int mhu_plat_setup_mbox(struct device *dev)
{
	struct mhu *mhu;
	struct device_node *shmem, *np;
	struct resource res;
	struct mbox_chan *chan;
	int ret;

	mhu = dev_get_drvdata(dev);
	np = dev->of_node;

	shmem = of_parse_phandle(np, "shmem", 0);
	if (!shmem)
		return -EINVAL;

	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret)
		return ret;

	mhu->payload = devm_ioremap_resource(dev, &res);
	if (!mhu->payload)
		return -ENOMEM;

	chan = &mhu_mbox_ctrl.chans[0];
	chan->con_priv = mhu;
	mhu->chan = chan;
	mhu_mbox_ctrl.dev = dev;

	return mbox_controller_register(&mhu_mbox_ctrl);
}

/* Platform device interface for SPI based configurations */
static int mhu_plat_setup_irq(struct platform_device *pdev)
{
	struct device *dev;
	struct mhu *mhu;
	struct device_node *np;
	int irq, ret;

	mhu = platform_get_drvdata(pdev);
	dev = &pdev->dev;
	np = dev->of_node;

	irq = of_irq_get(np, 0);
	if (irq < 0)
		return irq;

	ret = devm_request_threaded_irq(dev, irq, mhu_rx_interrupt,
					mhu_rx_interrupt_thread, 0,
					"mvl-mhu", mhu);
	if (ret)
		return ret;

	writeq_relaxed(1ul, mhu->base + XCP0_XCP_DEV2_MBOX_RINT_ENA_W1S);

	return 0;
}

static int mhu_plat_probe(struct platform_device *pdev)
{
	struct mhu *mhu;
	struct resource *res;
	struct device *dev;
	int ret;

	dev = &pdev->dev;
	mhu = devm_kzalloc(dev, sizeof(*mhu), GFP_KERNEL);
	if (!mhu)
		return -ENOMEM;
	platform_set_drvdata(pdev, mhu);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pr_debug("base: %llx, len: %llx\n", res->start, resource_size(res));

	mhu->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(mhu->base))
		return PTR_ERR(mhu->base);

	ret = mhu_plat_setup_irq(pdev);
	if (ret)
		return ret;

	return mhu_plat_setup_mbox(dev);
}

static int mhu_plat_remove(struct platform_device *pdev)
{
	mbox_controller_unregister(&mhu_mbox_ctrl);

	return 0;
}

static const struct of_device_id mhu_of_match[] = {
	{
		.compatible = "marvell,mbox",
	},
	{},
};
MODULE_DEVICE_TABLE(of, mhu_of_match);

static struct platform_driver mhu_plat_driver = {
	.driver = {
		.name = "mvl-mhu",
		.of_match_table = mhu_of_match,
	},
	.probe = mhu_plat_probe,
	.remove = mhu_plat_remove,

};

/* PCI interface in case of LPI based configuration */
static int mhu_pci_setup_irq(struct pci_dev *pdev)
{
	struct device *dev;
	struct mhu *mhu;
	struct device_node *np;
	int irq, ret, nvec;

	mhu = pci_get_drvdata(pdev);
	dev = &pdev->dev;
	np = dev->of_node;

	nvec = pci_alloc_irq_vectors(pdev, 0, 3, PCI_IRQ_MSIX);
	if (nvec < 0)
		return nvec;

	irq = pci_irq_vector(pdev, SCP_TO_AP_INTERRUPT);
	if (irq < 0) {
		ret = irq;
		goto irq_err;
	}

	ret = devm_request_threaded_irq(dev, irq, mhu_rx_interrupt,
					mhu_rx_interrupt_thread, 0,
					"mvl-mhu", mhu);
	if (ret)
		goto irq_err;

	writeq_relaxed(1ul, mhu->base + XCP0_XCP_DEV2_MBOX_RINT_ENA_W1S);

	return 0;

irq_err:
	/* In case of error, release the resources */
	pci_free_irq_vectors(pdev);

	return ret;
}

static int mhu_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mhu *mhu;
	struct device *dev;
	int ret;

	dev = &pdev->dev;
	if (!dev->of_node) /* This case rejects not configured CPC instances */
		return -ENODEV;

	mhu = devm_kzalloc(dev, sizeof(*mhu), GFP_KERNEL);
	if (!mhu)
		return -ENOMEM;
	pci_set_drvdata(pdev, mhu);

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	ret = pci_request_region(pdev, BAR0, "mvl-mhu");
	if (ret)
		return ret;

	mhu->base = pcim_iomap(pdev, BAR0, pci_resource_len(pdev, BAR0));
	if (!mhu->base)
		return -EINVAL;

	pr_debug("base: %llx, len: %llx\n", pci_resource_start(pdev, BAR0),
		 pci_resource_len(pdev, BAR0));

	ret = mhu_pci_setup_irq(pdev);
	if (ret)
		goto irq_err;

	ret = mhu_plat_setup_mbox(dev);
	if (!ret) /* Success */
		return 0;

	/* In case of error, release the resources */
	pci_free_irq_vectors(pdev);
irq_err:
	pci_release_region(pdev, BAR0);

	return ret;
}

static void mhu_pci_remove(struct pci_dev *pdev)
{
	struct mhu *mhu;

	mhu = pci_get_drvdata(pdev);
	mbox_controller_unregister(&mhu_mbox_ctrl);

	pci_free_irq_vectors(pdev);
	pcim_iounmap(pdev, mhu->base);
	pci_release_region(pdev, BAR0);
}

static const struct pci_device_id mhu_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xA067) },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, mhu_pci_ids);

static struct pci_driver mhu_pci_driver = {
	.name = "mvl-mhu",
	.id_table = mhu_pci_ids,
	.probe = mhu_pci_probe,
	.remove = mhu_pci_remove,
};

static int __init mvl_mhu_init(void)
{
	/* The driver has two ways it can interface the hardware.
	 * In case of SPI interrupt, the driver uses platform driver model.
	 * For LPI interrupts the driver uses basic PCI driver model.
	 */
	int ret;

	/* This driver should not be used for ACPI based platforms */
	if (!acpi_disabled)
		return -ENODEV;

	ret = platform_driver_register(&mhu_plat_driver);
	if (ret) {
		pr_err("Platform driver can't be registered. (%d)\n", ret);
		return ret;
	}

	ret = pci_register_driver(&mhu_pci_driver);
	if (!ret) /* Success */
		return 0;

	pr_err("PCI driver can't be registered. (%d)\n", ret);
	/* Handle errors */
	platform_driver_unregister(&mhu_plat_driver);
	return ret;
}
module_init(mvl_mhu_init);

static void __exit mvl_mhu_exit(void)
{
	pci_unregister_driver(&mhu_pci_driver);
	platform_driver_unregister(&mhu_plat_driver);
}
module_exit(mvl_mhu_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Marvell MHU Driver");
MODULE_AUTHOR("Sujeet Baranwal <sbaranwal@marvell.com>");
