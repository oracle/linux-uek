/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_COMMON_H
#define OTX2_COMMON_H

#include <mbox.h>

#include "otx2_reg.h"

/* PCI device IDs */
#define PCI_DEVID_OCTEONTX2_RVU_PF              0xA063

/* PCI BAR nos */
#define PCI_CFG_REG_BAR_NUM                     2
#define PCI_MBOX_BAR_NUM                        4

#define NAME_SIZE                               32

struct  mbox {
	struct otx2_mbox	mbox;
	struct work_struct	mbox_wrk;
	struct otx2_mbox	mbox_up;
	struct work_struct	mbox_up_wrk;
	struct otx2_nic		*pfvf;
	void *bbuf_base; /* Bounce buffer for mbox memory */
};

struct otx2_hw {
	struct pci_dev		*pdev;
	u16                     rx_queues;
	u16                     tx_queues;
	u16			max_queues;

	/* MSI-X*/
	u16			npa_msixoff; /* Offset of NPA vectors */
	u16			nix_msixoff; /* Offset of NIX vectors */
	char			*irq_name;
	cpumask_var_t           *affinity_mask;
};

struct otx2_nic {
	void __iomem		*reg_base;
	struct pci_dev		*pdev;
	struct device		*dev;
	struct net_device	*netdev;

	struct otx2_hw		hw;
	struct mbox		mbox;
	struct workqueue_struct *mbox_wq;
	u16			pcifunc;
};

/* Register read/write APIs */
static inline void otx2_write64(struct otx2_nic *nic, u64 offset, u64 val)
{
	writeq(val, nic->reg_base + offset);
}

static inline u64 otx2_read64(struct otx2_nic *nic, u64 offset)
{
	return readq(nic->reg_base + offset);
}

/* Mbox bounce buffer APIs */
static inline int otx2_mbox_bbuf_init(struct mbox *mbox, struct pci_dev *pdev)
{
	struct otx2_mbox_dev *mdev;
	struct otx2_mbox *otx2_mbox;

	mbox->bbuf_base = devm_kmalloc(&pdev->dev, MBOX_SIZE, GFP_KERNEL);
	if (!mbox->bbuf_base)
		return -ENOMEM;

	/* Overwrite mbox mbase to point to bounce buffer, so that PF/VF
	 * prepare all mbox messages in bounce buffer instead of directly
	 * in hw mbox memory.
	 */
	otx2_mbox = &mbox->mbox;
	mdev = &otx2_mbox->dev[0];
	mdev->mbase = mbox->bbuf_base;

	return 0;
}

static inline void otx2_sync_mbox_bbuf(struct otx2_mbox *mbox, int devid)
{
	u16 msgs_offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);
	void *hw_mbase = mbox->hwbase + (devid * MBOX_SIZE);
	struct otx2_mbox_dev *mdev = &mbox->dev[devid];
	struct mbox_hdr *hdr;
	u64 msg_size;

	if (mdev->mbase == hw_mbase)
		return;

	hdr = hw_mbase + mbox->rx_start;
	msg_size = hdr->msg_size;

	if (msg_size > mbox->rx_size - msgs_offset)
		msg_size = mbox->rx_size - msgs_offset;

	/* Copy mbox messages from mbox memory to bounce buffer */
	memcpy(mdev->mbase + mbox->rx_start,
	       hw_mbase + mbox->rx_start, msg_size + msgs_offset);
}

/* Mbox APIs */
static inline int otx2_sync_mbox_msg(struct mbox *mbox)
{
	int err;

	if (!otx2_mbox_nonempty(&mbox->mbox, 0))
		return 0;
	otx2_mbox_msg_send(&mbox->mbox, 0);
	err = otx2_mbox_wait_for_rsp(&mbox->mbox, 0);
	if (err)
		return err;

	return otx2_mbox_check_rsp_msgs(&mbox->mbox, 0);
}

/* Use this API to send mbox msgs in atomic context
 * where sleeping is not allowed
 */
static inline int otx2_sync_mbox_msg_busy_poll(struct mbox *mbox)
{
	int err;

	if (!otx2_mbox_nonempty(&mbox->mbox, 0))
		return 0;
	otx2_mbox_msg_send(&mbox->mbox, 0);
	err = otx2_mbox_busy_poll_for_rsp(&mbox->mbox, 0);
	if (err)
		return err;

	return otx2_mbox_check_rsp_msgs(&mbox->mbox, 0);
}

#define M(_name, _id, _fn_name, _req_type, _rsp_type)                   \
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct mbox *mbox)                    \
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&mbox->mbox, 0, sizeof(struct _req_type),		\
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	return req;							\
}

MBOX_MESSAGES
#undef M

/* RVU block related APIs */
int otx2_attach_npa_nix(struct otx2_nic *pfvf);
int otx2_detach_resources(struct mbox *mbox);

/* Mbox handlers */
void mbox_handler_msix_offset(struct otx2_nic *pf, struct msix_offset_rsp *rsp);

#endif /* OTX2_COMMON_H */
