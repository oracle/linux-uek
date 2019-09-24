/*
 *  MMC Oops/Panic logger
 *
 *  Copyright (C) 2010-2015 Samsung Electronics
 *  Jaehoon Chung <jh80.chung@samsung.com>
 *  Kyungmin Park <kyungmin.park@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmsg_dump.h>
#include <linux/slab.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/scatterlist.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include "bus.h"
#include "card.h"
#include "core.h"

/* TODO Unify the oops header, mmtoops, ramoops, mmcoops */
#define MMCOOPS_KERNMSG_HDR	"===="
#define MMCOOPS_HEADER_SIZE	(5 + sizeof(struct timeval))

#define RECORD_SIZE		10240UL

#define PART_TYPE		0

static int dump_oops = 1;
module_param(dump_oops, int, 0600);
MODULE_PARM_DESC(dump_oops,
		"set to 1 to dump oopses, 0 to only dump panics (default 1)");

#define dev_to_mmc_card(d)	container_of(d, struct mmc_card, dev)

static struct mmcoops_context {
	struct kmsg_dumper	dump;
	struct mmc_request	*mrq;
	struct mmc_card		*card;
	unsigned long		start;
	unsigned long		size;
	struct device		*dev;
	struct platform_device	*pdev;
	int			count;
	int			max_count;
	void			*virt_addr;
} oops_cxt;

static void mmc_panic_write(struct mmcoops_context *cxt,
	char *buf, unsigned long start, unsigned int size)
{
	struct mmc_card *card = cxt->card;
	struct mmc_host *host = card->host;
	struct mmc_request *mrq = cxt->mrq;
	struct scatterlist sg;

	sg_init_one(&sg, buf, (size << 9));

	if (size > 1)
		mrq->cmd->opcode = MMC_WRITE_MULTIPLE_BLOCK;
	else
		mrq->cmd->opcode = MMC_WRITE_BLOCK;
	mrq->cmd->arg = start;
	mrq->cmd->flags = MMC_RSP_R1 | MMC_CMD_ADTC;

	if (size == 1)
		mrq->stop = NULL;
	else {
		mrq->stop->opcode = MMC_STOP_TRANSMISSION;
		mrq->stop->arg = 0;
		mrq->stop->flags = MMC_RSP_R1B | MMC_CMD_AC;
	}

	mrq->data->blksz = 512;
	mrq->data->blocks = size;
	mrq->data->flags = MMC_DATA_WRITE;
	mrq->data->sg = &sg;
	mrq->data->sg_len = 1;

	mmc_set_data_timeout(mrq->data, card);
	mmc_wait_for_oops_req(host, mrq);

	if (mrq->cmd->error)
		pr_info("%s: cmd error %d\n", __func__, mrq->cmd->error);
	if (mrq->data->error)
		pr_info("%s: data error %d\n", __func__, mrq->data->error);
	/* wait busy */

	cxt->count = (cxt->count + 1) % cxt->max_count;
}

static void mmcoops_part_switch(struct mmcoops_context *cxt)
{
	struct mmc_card *card = cxt->card;
	struct mmc_command cmd = {};
	struct mmc_host *host = card->host;
	bool use_r1b_resp = true;
	unsigned int timeout_ms = card->ext_csd.part_time;
	struct mmc_request mrq = {};

	if (timeout_ms && host->max_busy_timeout &&
		(timeout_ms > host->max_busy_timeout))
		use_r1b_resp = false;

	cmd.opcode = MMC_SWITCH;

	cmd.arg = (MMC_SWITCH_MODE_WRITE_BYTE << 24) |
		  (EXT_CSD_PART_CONFIG << 16) |
		  (PART_TYPE << 8) |
		  EXT_CSD_CMD_SET_NORMAL;

	cmd.flags = MMC_CMD_AC;
	if (use_r1b_resp) {
		cmd.flags |= MMC_RSP_SPI_R1B | MMC_RSP_R1B;
		/*
		 * A busy_timeout of zero means the host can decide to use
		 * whatever value it finds suitable.
		 */
		cmd.busy_timeout = timeout_ms;
	} else {
		cmd.flags |= MMC_RSP_SPI_R1 | MMC_RSP_R1;
	}

	memset(cmd.resp, 0, sizeof(cmd.resp));
	cmd.retries = MMC_CMD_RETRIES;

	mrq.cmd = &cmd;
	cmd.data = NULL;

	mmc_wait_for_oops_req(host, &mrq);
	mdelay(card->ext_csd.part_time);

	if (cmd.error)
		pr_err("%s: cmd error %d\n", __func__, cmd.error);
}

static void mmcoops_do_dump(struct kmsg_dumper *dumper,
		enum kmsg_dump_reason reason)
{
	struct mmcoops_context *cxt = container_of(dumper,
			struct mmcoops_context, dump);
	struct mmc_card *card = cxt->card;
	unsigned int count = 0;
	char *buf;

	if (!card)
		return;

	mmc_claim_host(card->host);

	if (mmc_card_mmc(card))
		mmcoops_part_switch(cxt);

	/* Only dump oopses if dump_oops is set */
	if (reason == KMSG_DUMP_OOPS && !dump_oops)
		return;

	buf = (char *)(cxt->virt_addr + (cxt->count * RECORD_SIZE));
	memset(buf, '\0', RECORD_SIZE);
	count = sprintf(buf + count, "%s", MMCOOPS_KERNMSG_HDR);

	kmsg_dump_get_buffer(dumper, true, buf + MMCOOPS_HEADER_SIZE,
			RECORD_SIZE - MMCOOPS_HEADER_SIZE, NULL);

	mmc_panic_write(cxt, buf, cxt->start + (cxt->count * 8), cxt->size);
}

int  mmc_oops_card_set(struct mmc_card *card)
{
	struct mmcoops_context *cxt = &oops_cxt;

	if (!mmc_card_mmc(card) && !mmc_card_sd(card))
		return -ENODEV;

	cxt->card = card;
	pr_info("%s: %s\n", mmc_hostname(card->host), __func__);

	return 0;
}
EXPORT_SYMBOL(mmc_oops_card_set);

static int mmc_oops_probe(struct mmc_card *card)
{
	int ret = 0;

	ret = mmc_oops_card_set(card);
	if (ret)
		return ret;

	mmc_claim_host(card->host);

	return 0;
}

static void mmc_oops_remove(struct mmc_card *card)
{
	mmc_release_host(card->host);
}

/*
 * You can always switch between mmc_test and mmc_block by
 * unbinding / binding e.g.
 *
 *
 * # ls -al /sys/bus/mmc/drivers/mmcblk
 * drwxr-xr-x    2 root     0               0 Jan  1 00:00 .
 * drwxr-xr-x    4 root     0               0 Jan  1 00:00 ..
 * --w-------    1 root     0            4096 Jan  1 00:01 bind
 *  lrwxrwxrwx    1 root     0               0 Jan  1 00:01
 *			mmc0:0001 -> ../../../../class/mmc_host/mmc0/mmc0:0001
 *  --w-------    1 root     0            4096 Jan  1 00:01 uevent
 *  --w-------    1 root     0            4096 Jan  1 00:01 unbind
 *
 *  # echo mmc0:0001 > /sys/bus/mmc/drivers/mmcblk/unbind
 *
 *  # echo mmc0:0001 > /sys/bus/mmc/drivers/mmc_oops/bind
 *  [   48.490814] mmc0: mmc_oops_card_set
 */
static struct mmc_driver mmc_driver = {
	.drv		= {
		.name	= "mmc_oops",
	},
	.probe		= mmc_oops_probe,
	.remove		= mmc_oops_remove,
};

/* Parsing dt node */
static int mmcoops_parse_dt(struct mmcoops_context *cxt)
{
	struct device_node *np = cxt->dev->of_node;
	u32 start_offset = 0;
	u32 size = 0;
	int ret = 0;

	ret = of_property_read_u32(np, "start-offset", &start_offset);
	if (ret) {
		pr_err("%s: Start offset can't set..\n", __func__);
		return ret;
	}

	ret = of_property_read_u32(np, "size", &size);
	if (ret) {
		pr_err("%s: Size can't set..\n", __func__);
		return ret;
	}

	cxt->start = start_offset;
	cxt->size = size;

	return 0;
}

static int mmc_alloc_req_resources(struct platform_device *pdev,
				   struct mmcoops_context *cxt)
{
	struct mmc_request *mrq;
	struct mmc_command *cmd, *stop;
	struct mmc_data *data;

	mrq = devm_kzalloc(&pdev->dev, sizeof(struct mmc_request), GFP_KERNEL);
	if (!mrq)
		return -ENOMEM;

	cmd = devm_kzalloc(&pdev->dev, sizeof(struct mmc_command), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	stop = devm_kzalloc(&pdev->dev, sizeof(struct mmc_command), GFP_KERNEL);
	if (!stop)
		return -ENOMEM;

	data = devm_kzalloc(&pdev->dev, sizeof(struct mmc_data), GFP_KERNEL);
	if (!mrq)
		return -ENOMEM;

	mrq->cmd = cmd;
	mrq->data = data;
	mrq->stop = stop;

	cxt->mrq = mrq;

	return 0;
}

static int __init mmcoops_probe(struct platform_device *pdev)
{
	struct mmcoops_context *cxt = &oops_cxt;
	int err = -EINVAL;

	err = mmc_register_driver(&mmc_driver);
	if (err)
		return err;

	cxt->card = NULL;
	cxt->count = 0;
	cxt->dev = &pdev->dev;

	err = mmcoops_parse_dt(cxt);
	if (err) {
		pr_err("mmcoops: parsing mmcoops property failed");
		return err;
	}

	cxt->max_count = (cxt->size << 9) / RECORD_SIZE;

	cxt->virt_addr = kmalloc((cxt->size << 9), GFP_KERNEL);
	if (!cxt->virt_addr)
		goto kmalloc_failed;

	err = mmc_alloc_req_resources(pdev, cxt);
	if (err) {
		pr_err("%s: failed to allocate req resources\n", __func__);
		return err;
	}

	cxt->dump.dump = mmcoops_do_dump;

	err = kmsg_dump_register(&cxt->dump);
	if (err) {
		pr_err("mmcoops: registering kmsg dumper failed");
		goto kmsg_dump_register_failed;
	}

	pr_info("mmcoops is probed\n");
	return err;

kmsg_dump_register_failed:
	kfree(cxt->virt_addr);
kmalloc_failed:
	mmc_unregister_driver(&mmc_driver);

	return err;
}

static int mmcoops_remove(struct platform_device *pdev)
{
	struct mmcoops_context *cxt = &oops_cxt;

	if (kmsg_dump_unregister(&cxt->dump) < 0)
		pr_warn("mmcoops: colud not unregister kmsg dumper");
	kfree(cxt->virt_addr);
	mmc_unregister_driver(&mmc_driver);

	return 0;
}

static const struct of_device_id mmcoops_match[] = {
	{ .compatible = "mmcoops", },
};

static struct platform_driver mmcoops_driver = {
	.remove			= mmcoops_remove,
	.driver			= {
		.name		= "mmcoops",
		.of_match_table	= mmcoops_match,
	},
};

static int __init mmcoops_init(void)
{
	return platform_driver_probe(&mmcoops_driver, mmcoops_probe);
}

static void __exit mmcoops_exit(void)
{
	platform_driver_unregister(&mmcoops_driver);
}

module_init(mmcoops_init);
module_exit(mmcoops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaehoon Chung <jh80.chung@samsung.com>");
MODULE_DESCRIPTION("MMC Oops/Panic Looger");
