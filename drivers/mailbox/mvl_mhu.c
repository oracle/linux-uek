// SPDX-License-Identifier: GPL-2.0
/*
 * Marvell Message Handling Unit driver
 *
 * Copyright (C) 2019-2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */


#include <linux/pci.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mailbox_controller.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

#define MHU_NUM_PCHANS 2

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
#define XCP0_XCP_DEV2_MBOX_RINT_ENA_W1S 0x000D1C60

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

/**
 * MHU link is a structure that describes SCMI memory and irq for the mailbox
 *
 */
struct mvl_mhu_link {
	struct device *dev;
	bool initialized;
	unsigned int irq;
	void __iomem *tx_reg;
	void __iomem *rx_reg;
	void __iomem *shared_mem;
};

struct mvl_mhu {
	struct pci_dev *pdev;
	struct device *dev;
	void __iomem *base;
	struct mvl_mhu_link mlink;
	struct mbox_chan chan[MHU_NUM_PCHANS];
	struct mbox_controller mbox;
	void __iomem *payload;
	const char *name;
};

/**
 * MVL MHU Mailbox platform specific configuration
 *
 * @num_pchans: Maximum number of physical channels
 * @num_doorbells: Maximum number of doorbells per physical channel
 */
struct mvl_mhu_mbox_pdata {
	unsigned int num_pchans;
	unsigned int num_doorbells;
	bool support_doorbells;
};

/**
 * MVL MHU Mailbox allocated channel information
 *
 * @mhu: Pointer to parent mailbox device
 * @pchan: Physical channel within which this doorbell resides in
 * @doorbell: doorbell number pertaining to this channel
 */
struct mvl_mhu_channel {
	struct mvl_mhu *mhu;
	unsigned int pchan;
	unsigned int doorbell;
};

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

/* bottom half of rx interrupt */
static irqreturn_t mvl_mhu_rx_interrupt_thread(int irq, void *p)
{
	struct mbox_chan *chan = p;
	u64 val, scmi_tx_cnt, avs_failure_cnt;
	struct mvl_mhu_link *mlink = chan->con_priv;
	struct int_src_data_s *data =
		(struct int_src_data_s *)mlink->shared_mem;

	/*
	 * Local copy of event counters. A mismatch of received
	 * count value and the local copy means additional events
	 * are being flagged that needs to be attended by AP
	 */
	static u64 event_counter[INDEX_INT_SRC_NONE] = {0};

	/* scmi interrupt */
	scmi_tx_cnt = readq(&data[INDEX_INT_SRC_SCMI_TX].int_src_cnt);
	if (event_counter[INDEX_INT_SRC_SCMI_TX] != scmi_tx_cnt) {
		mbox_chan_received_data(chan, (void *)&val);
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

	return IRQ_HANDLED;
}

static irqreturn_t mvl_mhu_rx_interrupt(int irq, void *p)
{
	struct mbox_chan *chan = p;
	struct mvl_mhu_link *mlink = chan->con_priv;
	void __iomem *base = mlink->tx_reg;
	u64 val;

	/* Read interrupt status register */
	val = readq_relaxed(base + SCP_TO_AP0_MBOX_RINT);
	if (val) {
		/* Clear the interrupt : Write on clear */
		writeq_relaxed(0x1, base + SCP_TO_AP0_MBOX_RINT);
	} else {
		return IRQ_NONE;
	}

	return IRQ_WAKE_THREAD;
}

static bool mvl_mhu_last_tx_done(struct mbox_chan *chan)
{
	struct mvl_mhu_link *mlink = chan->con_priv;
	void __iomem *base = mlink->tx_reg;
	u64 val;

	val = readq_relaxed(base + SCP_TO_AP0_MBOX_RINT);

	return (val == 0);
}

static int mvl_mhu_send_data(struct mbox_chan *chan, void *data)
{
	struct mvl_mhu_link *mlink = chan->con_priv;
	void __iomem *base = mlink->tx_reg;

	writeq_relaxed(DONT_CARE_DATA, base + AP0_TO_SCP_MBOX);

	return 0;
}

/* Channels initialization might be called multiple times at once */
static DEFINE_MUTEX(mhu_startup_mutex);

static int mvl_mhu_startup(struct mbox_chan *chan)
{
	int ret = 0;
	struct mvl_mhu_link *mlink = chan->con_priv;

	mutex_lock(&mhu_startup_mutex);
	if (likely(!mlink->initialized)) {
		ret =  request_threaded_irq(mlink->irq, mvl_mhu_rx_interrupt,
					    mvl_mhu_rx_interrupt_thread, 0,
					    DRV_NAME, chan);
		if (!ret) {
			/* Enable interrupt from SCP to NS_AP */
			writeq_relaxed(0x1, mlink->tx_reg + XCP0_XCP_DEV2_MBOX_RINT_ENA_W1S);
			mlink->initialized = true;
		}
	}
	mutex_unlock(&mhu_startup_mutex);

	if (ret)
		dev_err(mlink->dev, "request_irq failed:%d\n", ret);

	return ret;
}

static const struct mbox_chan_ops mvl_mhu_ops = {
	.send_data = mvl_mhu_send_data,
	.startup = mvl_mhu_startup,
	.last_tx_done = mvl_mhu_last_tx_done,
};

static const struct mvl_mhu_mbox_pdata mvl_mhu_pdata = {
	.num_pchans = MHU_NUM_PCHANS,
	.num_doorbells = 1,
	.support_doorbells = false,
};

static int mvl_mhu_mlink_init(struct mvl_mhu *mhu)
{
	int ret;

	ret = pci_irq_vector(mhu->pdev, SCP_TO_AP_INTERRUPT);
	if (ret < 0)
		return ret;

	mhu->mlink.dev = mhu->dev;
	mhu->mlink.irq = ret;
	mhu->mlink.initialized = false;
	mhu->mlink.tx_reg = mhu->base;
	mhu->mlink.rx_reg = mhu->base;
	mhu->mlink.shared_mem = mhu->payload;

	return 0;
}

static int mvl_mhu_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mvl_mhu *mhu;
	int i, ret, nvec;
	struct resource res;
	resource_size_t size;
	struct device_node *shmem, *np;

	if (!pdev || !pdev->dev.of_node)
		return -ENODEV;

	np = pdev->dev.of_node;
	mhu = devm_kzalloc(&pdev->dev, sizeof(*mhu), GFP_KERNEL);
	if (!mhu)
		return -ENOMEM;

	mhu->pdev = pdev;
	mhu->dev = &pdev->dev;
	pci_set_drvdata(pdev, mhu);

	if (mvl_mhu_pdata.num_pchans > MHU_NUM_PCHANS) {
		dev_err(mhu->dev, "Number of physical channel can't exceed %d\n",
			MHU_NUM_PCHANS);
		return -EINVAL;
	}
	mhu->dev->platform_data = (void *)&mvl_mhu_pdata;

	ret = pcim_enable_device(mhu->pdev);
	if (ret) {
		dev_err(mhu->dev, "Failed to enable PCI device: err %d\n", ret);
		return ret;
	}

	ret = pci_request_region(mhu->pdev, BAR0, DRV_NAME);
	if (ret) {
		dev_err(mhu->dev, "Failed requested region PCI dev err:%d\n",
			ret);
		return ret;
	}

	mhu->base = pcim_iomap(pdev, BAR0, pci_resource_len(mhu->pdev, BAR0));
	if (!mhu->base) {
		dev_err(mhu->dev, "Failed to iomap PCI device: err %d\n", ret);
		return -EINVAL;
	}

	nvec = pci_alloc_irq_vectors(pdev, 0, 3, PCI_IRQ_MSIX);
	if (nvec < 0) {
		dev_err(mhu->dev, "irq vectors allocation failed:%d\n", nvec);
		return nvec;
	}

	ret = of_property_read_string(np, "mbox-name", &mhu->name);
	if (ret)
		mhu->name = np->full_name;

	/* get shared memory details between NS AP & SCP */
	shmem = of_parse_phandle(np, "shmem", 0);
	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(mhu->dev, "failed to get CPC COMMON payload mem resource\n");
		return ret;
	}
	size = resource_size(&res);

	mhu->payload = devm_ioremap(mhu->dev, res.start, size);
	if (!mhu->payload) {
		dev_err(mhu->dev, "failed to ioremap CPC COMMON payload\n");
		return -EADDRNOTAVAIL;
	}

	ret = mvl_mhu_mlink_init(mhu);
	if (ret) {
		dev_err(mhu->dev, "failed to initialize mlink (%d)\n", ret);
		return ret;
	}

	mhu->mbox.dev = mhu->dev;
	mhu->mbox.chans = &mhu->chan[0];
	mhu->mbox.num_chans = MHU_NUM_PCHANS;
	mhu->mbox.txdone_irq = false;
	mhu->mbox.txdone_poll = true;
	mhu->mbox.txpoll_period = 1;
	mhu->mbox.ops = &mvl_mhu_ops;

	for (i = 0; i < mvl_mhu_pdata.num_pchans; i++)
		mhu->chan[i].con_priv = &mhu->mlink;

	ret = mbox_controller_register(&mhu->mbox);
	if (ret) {
		dev_err(mhu->dev, "Failed to register mailboxes %d\n", ret);
		return ret;
	}

	return 0;
}

static void mvl_mhu_remove(struct pci_dev *pdev)
{
	struct mvl_mhu *mhu = pci_get_drvdata(pdev);

	pci_free_irq_vectors(pdev);
	mbox_controller_unregister(&mhu->mbox);
	pcim_iounmap(pdev, mhu->base);
	pci_release_region(pdev, BAR0);
}

static const struct pci_device_id mvl_mhu_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xA067) },
	{ 0, }	/* end of table */
};

static struct pci_driver mvl_mhu_driver = {
	.name		= "mvl_mhu",
	.id_table	= mvl_mhu_ids,
	.probe		= mvl_mhu_probe,
	.remove		= mvl_mhu_remove,
};
module_pci_driver(mvl_mhu_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Marvell MHU Driver");
MODULE_AUTHOR("Sujeet Baranwal <sbaranwal@marvell.com>");
