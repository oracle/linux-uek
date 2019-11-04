// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Virtual Function ethernet driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>

#include "otx2_common.h"
#include "otx2_reg.h"
#include "otx2_struct.h"
#include "rvu_fixes.h"

/* serialize device removal and xmit */
DEFINE_MUTEX(remove_lock);

static char pkt_data[64] = { 0x00, 0x0f, 0xb7, 0x11, 0xa6, 0x87, 0x02, 0xe0,
			     0x28, 0xa5, 0xf6, 0x00, 0x08, 0x00, 0x45, 0x00,
			     0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x04, 0x11,
			     0xee, 0x53, 0x50, 0x50, 0x50, 0x02, 0x14, 0x14,
			     0x14, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x1e,
			     0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			     0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
			     0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76 };

static struct sk_buff *the_skb;
static struct otx2_nic *the_smqvf;
static u16 drop_entry = 0xFFFF;

static bool is_otx2_smqvf(struct otx2_nic *vf)
{
	if (vf->pcifunc == RVU_SMQVF_PCIFUNC &&
	    (is_96xx_A0(vf->pdev) || is_95xx_A0(vf->pdev)))
		return true;

	return false;
}

static void otx2_sqe_flush(struct otx2_snd_queue *sq, int size)
{
	u64 status;

	/* Packet data stores should finish before SQE is flushed to HW */
	dma_wmb();

	do {
		memcpy(sq->lmt_addr, sq->sqe_base, size);
		status = otx2_lmt_flush(sq->io_addr);
	} while (status == 0);

	sq->head++;
	sq->head &= (sq->sqe_cnt - 1);
}

static int otx2_ctx_update(struct otx2_nic *vf, u16 qidx)
{
	struct nix_aq_enq_req *sq_aq, *rq_aq, *cq_aq;

	/* Do not link CQ for SQ and disable RQ, CQ */
	sq_aq = otx2_mbox_alloc_msg_nix_aq_enq(&vf->mbox);
	if (!sq_aq)
		return -ENOMEM;

	sq_aq->sq.cq_ena = 0;
	sq_aq->sq_mask.cq_ena = 1;
	sq_aq->qidx = qidx;
	sq_aq->ctype = NIX_AQ_CTYPE_SQ;
	sq_aq->op = NIX_AQ_INSTOP_WRITE;

	rq_aq = otx2_mbox_alloc_msg_nix_aq_enq(&vf->mbox);
	if (!rq_aq)
		return -ENOMEM;

	rq_aq->rq.ena = 0;
	rq_aq->rq_mask.ena = 1;
	rq_aq->qidx = qidx;
	rq_aq->ctype = NIX_AQ_CTYPE_RQ;
	rq_aq->op = NIX_AQ_INSTOP_WRITE;

	cq_aq = otx2_mbox_alloc_msg_nix_aq_enq(&vf->mbox);
	if (!cq_aq)
		return -ENOMEM;

	cq_aq->cq.ena = 0;
	cq_aq->cq_mask.ena = 1;
	cq_aq->qidx = qidx;
	cq_aq->ctype = NIX_AQ_CTYPE_CQ;
	cq_aq->op = NIX_AQ_INSTOP_WRITE;

	return otx2_sync_mbox_msg(&vf->mbox);
}

void otx2smqvf_xmit(void)
{
	struct otx2_snd_queue *sq;
	int i, size;

	mutex_lock(&remove_lock);

	if (!the_smqvf) {
		mutex_unlock(&remove_lock);
		return;
	}

	sq = &the_smqvf->qset.sq[0];
	/* Min. set of send descriptors required to send packets */
	size = sizeof(struct nix_sqe_hdr_s) + sizeof(struct nix_sqe_sg_s) +
	       sizeof(struct nix_sqe_ext_s) + sizeof(u64);

	for (i = 0; i < 256; i++)
		otx2_sqe_flush(sq, size);

	mutex_unlock(&remove_lock);
}
EXPORT_SYMBOL(otx2smqvf_xmit);

static int otx2smqvf_install_flow(struct otx2_nic *vf)
{
	struct npc_mcam_alloc_entry_req *alloc_req;
	struct npc_mcam_free_entry_req *free_req;
	struct npc_install_flow_req *install_req;
	struct npc_mcam_alloc_entry_rsp *rsp;
	struct msg_req *msg;
	int err, qid;
	size_t size;
	void *data;

	size = SKB_DATA_ALIGN(64 + OTX2_ALIGN) + NET_SKB_PAD +
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	err = -ENOMEM;

	data = kzalloc(size, GFP_KERNEL);
	if (!data)
		return err;

	memcpy(data, &pkt_data, 64);

	the_skb = build_skb(data, 0);
	the_skb->len = 64;

	for (qid = 0; qid < vf->hw.tx_queues; qid++) {
		err = otx2_ctx_update(vf, qid);
		/* If something wrong with Q0 then treat as error */
		if (err && !qid)
			goto err_free_mem;
	}

	otx2_mbox_lock(&vf->mbox);

	alloc_req = otx2_mbox_alloc_msg_npc_mcam_alloc_entry(&vf->mbox);
	if (!alloc_req) {
		otx2_mbox_unlock(&vf->mbox);
		goto err_free_mem;
	}
	alloc_req->count = 1;
	alloc_req->contig = true;

	/* Send message to AF */
	if (otx2_sync_mbox_msg(&vf->mbox)) {
		err = -EINVAL;
		otx2_mbox_unlock(&vf->mbox);
		goto err_free_mem;
	}
	otx2_mbox_unlock(&vf->mbox);

	rsp = (struct npc_mcam_alloc_entry_rsp *)otx2_mbox_get_rsp
	       (&vf->mbox.mbox, 0, &alloc_req->hdr);
	drop_entry = rsp->entry;

	otx2_mbox_lock(&vf->mbox);

	/* Send messages to drop Tx packets at NPC and stop Rx traffic */
	install_req = otx2_mbox_alloc_msg_npc_install_flow(&vf->mbox);
	if (!install_req) {
		err = -ENOMEM;
		otx2_mbox_unlock(&vf->mbox);
		goto err_free_entry;
	}

	u64_to_ether_addr(0x0ull, install_req->mask.dmac);
	install_req->entry = drop_entry;
	install_req->features = BIT_ULL(NPC_DMAC);
	install_req->intf = NIX_INTF_TX;
	install_req->op = NIX_TX_ACTIONOP_DROP;
	install_req->set_cntr = 1;

	msg = otx2_mbox_alloc_msg_nix_lf_stop_rx(&vf->mbox);
	if (!msg) {
		otx2_mbox_unlock(&vf->mbox);
		goto err_free_entry;
	}

	/* Send message to AF */
	if (otx2_sync_mbox_msg(&vf->mbox)) {
		err = -EINVAL;
		otx2_mbox_unlock(&vf->mbox);
		goto err_free_entry;
	}
	otx2_mbox_unlock(&vf->mbox);

	otx2_sq_append_skb(vf->netdev, &vf->qset.sq[0], the_skb, 0);

	return 0;

err_free_entry:
	otx2_mbox_lock(&vf->mbox);
	free_req = otx2_mbox_alloc_msg_npc_mcam_free_entry(&vf->mbox);
	if (!free_req) {
		dev_err(vf->dev, "Could not allocate msg for freeing entry\n");
	} else {
		free_req->entry = drop_entry;
		WARN_ON(otx2_sync_mbox_msg(&vf->mbox));
	}
	otx2_mbox_unlock(&vf->mbox);
err_free_mem:
	kfree_skb(the_skb);
	drop_entry = 0xFFFF;
	return err;
}

int otx2smqvf_probe(struct otx2_nic *vf)
{
	int err;

	if (!is_otx2_smqvf(vf))
		return -EPERM;

	err = otx2_open(vf->netdev);
	if (err)
		return -EINVAL;

	/* Disable QINT interrupts because we do not use a CQ for SQ and
	 * drop TX packets intentionally
	 */
	otx2_write64(vf, NIX_LF_QINTX_ENA_W1C(0), BIT_ULL(0));

	err = otx2smqvf_install_flow(vf);
	if (err) {
		otx2_stop(vf->netdev);
		return -EINVAL;
	}

	the_smqvf = vf;

	return 0;
}

int otx2smqvf_remove(struct otx2_nic *vf)
{
	struct npc_mcam_free_entry_req *free_req;
	struct npc_delete_flow_req *del_req;

	if (!is_otx2_smqvf(vf))
		return -EPERM;

	mutex_lock(&remove_lock);
	kfree_skb(the_skb);
	the_smqvf = NULL;
	the_skb = NULL;
	mutex_unlock(&remove_lock);

	otx2_mbox_lock(&vf->mbox);
	del_req = otx2_mbox_alloc_msg_npc_delete_flow(&vf->mbox);
	free_req = otx2_mbox_alloc_msg_npc_mcam_free_entry(&vf->mbox);
	if (!del_req || !free_req) {
		dev_err(vf->dev, "Could not allocate msg for freeing entry\n");
	} else {
		del_req->entry = drop_entry;
		free_req->entry = drop_entry;
		WARN_ON(otx2_sync_mbox_msg(&vf->mbox));
	}
	otx2_mbox_unlock(&vf->mbox);

	otx2_stop(vf->netdev);
	drop_entry = 0xFFFF;

	return 0;
}
