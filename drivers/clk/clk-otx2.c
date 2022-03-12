// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt)	"clk-otx2: " fmt

#include <linux/types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/processor.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/completion.h>
#include <linux/clk-provider.h>
#include <linux/acpi.h>
#include <linux/mailbox_controller.h>
#include <linux/mailbox_client.h>
#include <acpi/pcc.h>

/*
 * The driver creates a fixed rate clock presented to Common CLK framework.
 * The clock frequency is read from coprocessor clock PLL (sclk).
 * Later, the frequency value could be used by other drivers for OcteonTX2
 * to perform frequency based operations. The interface matches the one used
 * by device tree.
 *
 * The driver uses PCC mailbox to SCP to send valid SCMI message
 * with get rate query for SCLK.
 */

/* Tag used to be passed through mailbox API, could be anything */
#define PCC_OTX2_CLK_TAG	((void *)0xcafebabe)

#define PCC_CMD_DONE_MASK BIT(0)

#define PCC_PROT_ID        0x14
#define PCC_PROT_GET_RATE  0x6
#define PCC_PROT_TYPE	   0x0
#define OTX2_CLK_ID        0x0

/* Shared memory layout, matches SCMI v3.0 shared memory layout */
struct clk_otx2_shmem {
	__le32 rsvd0;
	__le32 channel_status;
	__le32 rsvd1[2];
	__le32 flags;
	__le32 length;
	__le32 msg_header;
	u8 msg_payload[];
};

/* The header for the message, matches SCMI v3.0 */
struct clk_otx2_msg_hdr {
	u8 id;
	u8 protocol_id;
	u8 type;
	u16 seq;
	u32 status;
};

#define MSG_HDR_ID_MASK      GENMASK(7, 0)
#define MSG_HDR_TYPE_MASK    GENMASK(9, 8)
#define MSG_HDR_PROT_ID_MASK GENMASK(17, 10)
#define MSG_HDR_SEQ_MASK     GENMASK(27, 18)

/* The single message will be sent, no need to make it variable */
static const struct clk_otx2_msg_hdr get_sclk_rate __initconst = {
	.id = PCC_PROT_GET_RATE,
	.protocol_id = PCC_PROT_ID,
	.type = PCC_PROT_TYPE,
	.seq = 0x20,
	.status = 0,
};

/* Ensures the subspace index is always defined */
#ifndef CONFIG_COMMON_CLK_MARVELL_OTX2_SUBSPACE
#define OTX2_CLK_DEFAULT_SUBSPACE 0
#else
#define OTX2_CLK_DEFAULT_SUBSPACE CONFIG_COMMON_CLK_MARVELL_OTX2_SUBSPACE
#endif

/* This variables will be alive to the module removal */
static struct clk *clk_otx2_sclk_clk;

/* Helper structure to gather all object involved into SCP communication */
struct clk_otx2_scp_comm {
	struct mbox_chan *pcc_chan;
	struct mbox_client cl;
	unsigned int pcc_timeout;
	void __iomem *shmem;
	struct completion scp_msg_done;
	unsigned long sclk_freq;
};

#define TO_SCP_COMM(p)  container_of(p, struct clk_otx2_scp_comm, cl)

static inline u32 pack_msg_hdr(const struct clk_otx2_msg_hdr *hdr)
{
	return FIELD_PREP(MSG_HDR_ID_MASK, hdr->id) |
		FIELD_PREP(MSG_HDR_PROT_ID_MASK, hdr->protocol_id) |
		FIELD_PREP(MSG_HDR_TYPE_MASK, hdr->type) |
		FIELD_PREP(MSG_HDR_SEQ_MASK, hdr->seq);
}

/* The message will be prepared by mbox_send_message() */
static void __init clk_otx2_tx_prep(struct mbox_client *cl, void *m)
{
	struct clk_otx2_scp_comm *comm = TO_SCP_COMM(cl);
	struct clk_otx2_shmem __iomem *mem = comm->shmem;

	spin_until_cond(ioread32(&mem->channel_status) & PCC_CMD_DONE_MASK);
	/* Mark PCC channel busy */
	iowrite32(0, &mem->channel_status);
	iowrite32(0, &mem->flags);
	/* Single datum is send clk_id (u32/__le32) */
	iowrite32(cpu_to_le32(sizeof(mem->msg_header) + sizeof(__le32)),
		  &mem->length);
	iowrite32(cpu_to_le32(pack_msg_hdr(&get_sclk_rate)), &mem->msg_header);
	/* Send command */
	iowrite32(cpu_to_le32(OTX2_CLK_ID), &mem->msg_payload[0]);
}

static void __init clk_otx2_rx(struct mbox_client *cl, void *m)
{
	struct clk_otx2_scp_comm *comm = TO_SCP_COMM(cl);

	/* Notify main thread that channel has data */
	complete_all(&comm->scp_msg_done);
}

/* Initialize the PCC channel */
static int __init clk_otx2_sclk_get_channel(struct clk_otx2_scp_comm *comm)
{
	struct acpi_pcct_hw_reduced *scp_ss;
	struct mbox_client *cl;
	int ret = 0;

	/* Setup mbox client */
	cl = &comm->cl;
	cl->tx_prepare = clk_otx2_tx_prep;
	cl->rx_callback = clk_otx2_rx;
	cl->knows_txdone = true;

	/* Request  PCC channel */
	comm->pcc_chan = pcc_mbox_request_channel(cl,
						  OTX2_CLK_DEFAULT_SUBSPACE);
	if (IS_ERR_OR_NULL(comm->pcc_chan)) {
		if (IS_ERR(comm->pcc_chan))
			ret = PTR_ERR(comm->pcc_chan);
		else
			ret = -ENODEV;
		return ret;
	}

	scp_ss = comm->pcc_chan->con_priv;
	if (!scp_ss) {
		ret = -ENODEV;
		goto err_no_ss;
	}

	/* Map channel resources (shared memory) */
	comm->shmem = ioremap_nocache(scp_ss->base_address, scp_ss->length);
	if (!comm->shmem) {
		ret = -ENOMEM;
		goto err_no_ss;
	}
	/* Get expected message latency */
	comm->pcc_timeout = scp_ss->latency;
	init_completion(&comm->scp_msg_done);

	return 0;

err_no_ss:  /* No subspace found */
	pcc_mbox_free_channel(comm->pcc_chan);

	return ret;
}

static void __init clk_otx2_rx_read(struct clk_otx2_scp_comm *comm)
{
	struct clk_otx2_shmem __iomem *mem = comm->shmem;
	u32 status;
	u32 freq_hi, freq_lo;
	u64 val;

	status = ioread32(&mem->msg_payload[0]);
	freq_lo = ioread32(&mem->msg_payload[sizeof(freq_lo)]);
	freq_hi = ioread32(&mem->msg_payload[2 * sizeof(freq_lo)]);

	/* Convert value to single u64 in the correct endianness */
	val = (((u64)freq_hi) << 32) + freq_lo;
	comm->sclk_freq = __le64_to_cpu(val);
}

static int __init clk_otx2_sclk_get_sclk_freq(struct clk_otx2_scp_comm *comm)
{
	struct clk_otx2_shmem __iomem *mem = comm->shmem;
	int ret;
	unsigned long timeout;
	u32 stat;

	ret = mbox_send_message(comm->pcc_chan, PCC_OTX2_CLK_TAG);
	if (ret < 0) {
		return ret;
	}

	/* Wait for answer from SCP */
	/* Check if the controller has irq enabled */
	if (comm->pcc_chan->mbox->txdone_irq) {
		timeout = msecs_to_jiffies(comm->pcc_timeout);
		if (!wait_for_completion_timeout(&comm->scp_msg_done, timeout))
			return -ETIMEDOUT;
	} else { /* Use polling to complete the request. Poll every 100us */
		timeout = comm->pcc_timeout * 1000;
		ret = readl_relaxed_poll_timeout(&mem->channel_status,
						 stat,
						 (stat & PCC_CMD_DONE_MASK),
						 10, timeout);
		if (ret)
			return ret;
	}

	/* Read sclk_freq from SCP answer */
	clk_otx2_rx_read(comm);

	return 0;
}

static void __init clk_otx2_put_channel(struct clk_otx2_scp_comm *comm)
{
	iounmap(comm->shmem);
	pcc_mbox_free_channel(comm->pcc_chan);
}

static int __init clk_otx2_init(void)
{
	struct clk_otx2_scp_comm comm;
	int ret = 0;

	/* This driver supports only ACPI based platforms */
	if (acpi_disabled) {
		pr_debug("This is not ACPI based platform\n");
		return 0;
	}

	/* Set initial frequency to max of the type */
	comm.sclk_freq = ULONG_MAX;

	/* Get SCLK value using SCP and PCC */
	ret = clk_otx2_sclk_get_channel(&comm);
	if (ret) {
		pr_err("Failed to initialize PCC channel. (%d)\n", ret);
		return ret;
	}

	ret = clk_otx2_sclk_get_sclk_freq(&comm);
	clk_otx2_put_channel(&comm);
	if (ret) {
		pr_err("Can't retrieve sclk frequency. (%d)\n", ret);
		return ret;
	}

	clk_otx2_sclk_clk = clk_register_fixed_rate(NULL, "sclk", NULL, 0,
						    comm.sclk_freq);
	if (IS_ERR_OR_NULL(clk_otx2_sclk_clk)) {
		if (IS_ERR(clk_otx2_sclk_clk))
			ret = PTR_ERR(clk_otx2_sclk_clk);
		else
			ret = -ENOMEM;
		pr_err("Can't register OcteonTX2 sclk! %d\n", ret);
		return ret;
	}

	return 0;
}
module_init(clk_otx2_init);

static void __exit clk_otx2_exit(void)
{
	if (acpi_disabled)
		return; /* In case of DT based system there are no resources */

	clk_unregister_fixed_rate(clk_otx2_sclk_clk);
}
module_exit(clk_otx2_exit);

MODULE_DESCRIPTION("Basic clock provider for OTX2 platforms with ACPI");
MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
MODULE_LICENSE("GPL");
