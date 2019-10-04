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
#define DEFAULT_RECORD_SIZE	20 /* default 20KB: 20 * 512B */
#define DEFAULT_START_OFFSET	14680064 /* default 7GB: 14680064 * 512B */
#define MAX_RECORD_SIZE		128 /* 64KB: 128 * 512  */

#define PART_TYPE		0

static unsigned long start_offset = DEFAULT_START_OFFSET;
module_param(start_offset, ulong, 0400);
MODULE_PARM_DESC(start_offset,
		"block-start_offset for start (default: DEFAULT_START_OFFSET)");

static unsigned long record_size = DEFAULT_RECORD_SIZE;
module_param(record_size, ulong, 0400);
MODULE_PARM_DESC(record_size,
		"the number of block to write oopses and panics (default: DEFAULT_RECORD_SIZE");

static char mmcdev[80];
module_param_string(mmcdev, mmcdev, 80, 0400);
MODULE_PARM_DESC(mmcdev,
		"name of the MMC device to use");

static int dump_oops = 1;
module_param(dump_oops, int, 0600);
MODULE_PARM_DESC(dump_oops,
		"set to 1 to dump oopses, 0 to only dump panics (default 1)");

static struct mmcoops_context {
	struct kmsg_dumper	dump;
	struct mmc_request	*mrq;
	struct mmc_card		*card;
	struct platform_device	*pdev;
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
	static int runonce;
	char *buf;

	if (!card || runonce++)
		return;

	mmc_claim_host(card->host);

	if (mmc_card_mmc(card))
		mmcoops_part_switch(cxt);

	/* Only dump oopses if dump_oops is set */
	if (reason == KMSG_DUMP_OOPS && !dump_oops)
		return;

	buf = (char *)(cxt->virt_addr);
	memset(buf, '\0', record_size);
	sprintf(buf, "%s", MMCOOPS_KERNMSG_HDR);

	kmsg_dump_get_buffer(dumper, true, buf + MMCOOPS_HEADER_SIZE,
			(record_size << 9) - MMCOOPS_HEADER_SIZE, NULL);

	mmc_panic_write(cxt, buf, start_offset, record_size);
}

int  mmc_oops_card_set(struct mmc_card *card)
{
	struct mmcoops_context *cxt = &oops_cxt;

	if (strcmp(mmc_hostname(card->host), mmcdev))
		return 0;

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

static int __init mmcoops_init(void)
{
	struct mmcoops_context *cxt = &oops_cxt;
	struct mmc_request *mrq;
	struct mmc_command *cmd, *stop;
	struct mmc_data *data;
	int err = -EINVAL;

	/* If no mmcdev specify exit silently */
	if (strlen(mmcdev) == 0)
		return -ENODEV;

	err = mmc_register_driver(&mmc_driver);
	if (err)
		return err;

	cxt->card = NULL;

	if (record_size > MAX_RECORD_SIZE || record_size <= 0) {
		pr_warn("%s: wrong record size - forcing max record size %d\n",
			__func__, MAX_RECORD_SIZE);
		record_size = MAX_RECORD_SIZE;
	}

	cxt->virt_addr = kmalloc((record_size << 9), GFP_KERNEL);
	if (!cxt->virt_addr)
		goto kmalloc_failed;

	/* alloc resources needed for mmc request */
	mrq = kzalloc(sizeof(struct mmc_request), GFP_KERNEL);
	if (!mrq)
		goto kmalloc_mrq_failed;

	cmd = kzalloc(sizeof(struct mmc_command), GFP_KERNEL);
	if (!cmd)
		goto kmalloc_cmd_failed;

	stop = kzalloc(sizeof(struct mmc_command), GFP_KERNEL);
	if (!stop)
		goto kmalloc_stop_failed;

	data = kzalloc(sizeof(struct mmc_data), GFP_KERNEL);
	if (!data)
		goto kmalloc_data;

	mrq->cmd = cmd;
	mrq->data = data;
	mrq->stop = stop;

	cxt->mrq = mrq;

	cxt->dump.dump = mmcoops_do_dump;

	err = kmsg_dump_register(&cxt->dump);
	if (err) {
		pr_err("mmcoops: registering kmsg dumper failed");
		goto kmsg_dump_register_failed;
	}

	pr_info("mmcoops is probed\n");
	return err;

kmsg_dump_register_failed:
	kfree(data);
kmalloc_data:
	kfree(stop);
kmalloc_stop_failed:
	kfree(cmd);
kmalloc_cmd_failed:
	kfree(mrq);
kmalloc_mrq_failed:
	kfree(cxt->virt_addr);
kmalloc_failed:
	mmc_unregister_driver(&mmc_driver);

	return err;
}

static void __exit mmcoops_exit(void)
{
	struct mmcoops_context *cxt = &oops_cxt;

	if (kmsg_dump_unregister(&cxt->dump) < 0)
		pr_warn("mmcoops: colud not unregister kmsg dumper");

	kfree(cxt->virt_addr);
	kfree(cxt->mrq->data);
	kfree(cxt->mrq->stop);
	kfree(cxt->mrq->cmd);
	kfree(cxt->mrq);

	mmc_unregister_driver(&mmc_driver);
}

module_init(mmcoops_init);
module_exit(mmcoops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jaehoon Chung <jh80.chung@samsung.com>");
MODULE_DESCRIPTION("MMC Oops/Panic Looger");
