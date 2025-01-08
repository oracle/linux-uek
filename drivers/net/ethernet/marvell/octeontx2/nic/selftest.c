// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Physical Function ethernet driver test module
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>

#include "otx2_common.h"

#define FW_AF_SIG 0x5b /* an arbitrary non zero value */

static int otx2_mbox_route_to_fw(struct mbox *mbox)
{
	struct otx2_mbox *otx2_mbox = &mbox->mbox;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *tx_hdr;
	void *hw_mbase;

	mdev = &otx2_mbox->dev[0];
	hw_mbase = mdev->hwbase;

	if (!otx2_mbox_nonempty(&mbox->mbox, 0))
		return -EINVAL;

	tx_hdr = hw_mbase + otx2_mbox->tx_start;
	tx_hdr->sig = FW_AF_SIG;
	tx_hdr->num_msgs = 1; /* Set number of messages */
	return 0;
}

static int mbox_test_firmware(struct mbox *mbox, struct device *dev)
{
	struct msg_req *req;
	int err;

	req = otx2_mbox_alloc_msg_ready(mbox);
	if (!req)
		return -ENOMEM;

	err = otx2_mbox_route_to_fw(mbox);
	if (err) {
		dev_dbg(dev, "mbox empty\n");
		return -ENOMEM;
	}
	err = otx2_sync_mbox_msg(mbox);
	if (err) {
		dev_dbg(dev, "Firmware not responding\n");
		return -ENXIO;
	}
	return 0;
}

static int mbox_test_kernel(struct mbox *mbox, struct device *dev)
{
	struct msg_req *req;
	int err;

	req = otx2_mbox_alloc_msg_free_rsrc_cnt(mbox);
	if (!req)
		return -ENOMEM;

	err = otx2_sync_mbox_msg(mbox);
	if (err) {
		dev_dbg(dev, "Kernel AF not responding\n");
		return -ENXIO;
	}

	return 0;
}

int otx2_selftest_mbox(struct otx2_nic *pf)
{
	int err;

	dev_dbg(pf->dev, "Sending mbox message 1 to kernel\n");

	/* Check mailbox communication with kernel AF */
	err = mbox_test_kernel(&pf->mbox, pf->dev);
	if (err)
		return err;

	dev_dbg(pf->dev, "Sending mbox message 2 to firmware\n");
	/* Check mailbox communication with FW AF */
	err = mbox_test_firmware(&pf->mbox, pf->dev);
	if (err)
		return err;

	dev_dbg(pf->dev, "Sending mbox message 3 to kernel\n");
	/* Check mailbox communication with kernel AF again */
	err = mbox_test_kernel(&pf->mbox, pf->dev);
	if (err)
		return err;

	dev_dbg(pf->dev, "End of back to back mbox test\n");
	return 0;
}
