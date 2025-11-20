// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include "rvu.h"
#include "rvu_eblock.h"
#include "rvu_eb_sdp.h"

struct sdp_drvdata sdp_data; /*global struct to hold mbox_wqs */
struct sdp_irq_data epf_cookie[SDP_MAX_EPF];

/* SDP Mbox handler */
static int sdp_process_mbox_msg(struct otx2_mbox *mbox, int devid,
				struct mbox_msghdr *req)
{
	struct rvu *rvu = pci_get_drvdata(mbox->pdev);
	int _id = req->id;

	switch (_id) {
	#define M(_name, _id, _fn_name, _req_type, _rsp_type)		\
	{								\
	case _id: {							\
		struct _rsp_type *rsp;					\
		int err;						\
									\
		rsp = (struct _rsp_type *)otx2_mbox_alloc_msg(		\
			mbox, devid,					\
			sizeof(struct _rsp_type));			\
		if (rsp) {						\
			rsp->hdr.id = _id;				\
			rsp->hdr.sig = OTX2_MBOX_RSP_SIG;		\
			rsp->hdr.pcifunc = req->pcifunc;		\
			rsp->hdr.rc = 0;				\
		}							\
									\
		err = rvu_mbox_handler_ ## _fn_name(rvu,		\
						    (struct _req_type *)req, \
						    rsp);		\
		if (rsp && err)						\
			rsp->hdr.rc = err;				\
									\
		trace_otx2_msg_process(mbox->pdev, _id, err, req->pcifunc); \
		return rsp ? err : -ENOMEM;				\
	}								\
	}
		MBOX_EBLOCK_SDP_MESSAGES

	default :
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}
}

/*Duplicate mbox APIs */
static void __sdp_mbox_up_handler(struct rvu_work *mwork, int type)
{
	struct rvu *rvu = mwork->rvu;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	struct mbox_wq_info *mw;
	struct otx2_mbox *mbox;
	int offset, id, devid;

	switch (type) {
	case TYPE_AFEPF:
		mw = &sdp_data.afepf_wq_info;
		break;
	default:
		return;
	}

	devid = mwork - mw->mbox_wrk_up;
	mbox = &mw->mbox_up;
	mdev = &mbox->dev[devid];

	rsp_hdr = mdev->mbase + mbox->rx_start;
	if (mw->mbox_wrk_up[devid].up_num_msgs == 0) {
		dev_warn(rvu->dev, "mbox up handler: num_msgs = 0\n");
		return;
	}

	offset = mbox->rx_start + ALIGN(sizeof(*rsp_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < mw->mbox_wrk_up[devid].up_num_msgs; id++) {
		msg = mdev->mbase + offset;

		if (msg->id >= MBOX_MSG_MAX) {
			dev_err(rvu->dev,
				"Mbox msg with unknown ID 0x%x\n", msg->id);
			goto end;
		}

		if (msg->sig != OTX2_MBOX_RSP_SIG) {
			dev_err(rvu->dev,
				"Mbox msg with wrong signature %x, ID 0x%x\n",
				msg->sig, msg->id);
			goto end;
		}

		switch (msg->id) {
		case MBOX_MSG_CGX_LINK_EVENT:
			break;
		default:
			if (msg->rc)
				dev_err(rvu->dev,
					"Mbox msg response has err %d, ID 0x%x\n",
					msg->rc, msg->id);
			break;
		}
end:
		offset = mbox->rx_start + msg->next_msgoff;
		mdev->msgs_acked++;
	}
	mw->mbox_wrk_up[devid].up_num_msgs = 0;

	otx2_mbox_reset(mbox, devid);
}

static void __sdp_mbox_handler(struct rvu_work *mwork, int type, bool poll)
{
	struct rvu *rvu = mwork->rvu;
	int offset, err, id, devid;
	struct otx2_mbox_dev *mdev;
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	struct mbox_wq_info *mw;
	struct otx2_mbox *mbox;

	switch (type) {
	case TYPE_AFEPF:
		mw = &sdp_data.afepf_wq_info;
		break;
	default:
		return;
	}

	devid = mwork - mw->mbox_wrk;
	mbox = &mw->mbox;
	mdev = &mbox->dev[devid];

	/* Process received mbox messages */
	req_hdr = mdev->mbase + mbox->rx_start;
	if (mw->mbox_wrk[devid].num_msgs == 0)
		return;

	offset = mbox->rx_start + ALIGN(sizeof(*req_hdr), MBOX_MSG_ALIGN);

	for (id = 0; id < mw->mbox_wrk[devid].num_msgs; id++) {
		msg = mdev->mbase + offset;

		/* Set which PF/VF sent this message based on mbox IRQ */
		switch (type) {
		case TYPE_AFEPF:
			msg->pcifunc &=
				~(RVU_PFVF_PF_MASK << RVU_PFVF_PF_SHIFT);
			msg->pcifunc |= (devid << RVU_PFVF_PF_SHIFT);
			break;
		}

		err = sdp_process_mbox_msg(mbox, devid, msg);
		if (!err) {
			offset = mbox->rx_start + msg->next_msgoff;
			continue;
		}

		if (msg->pcifunc & RVU_PFVF_FUNC_MASK)
			dev_warn(rvu->dev, "Error %d when processing message %s (0x%x) from EPF%d:VF%d\n",
				 err, otx2_mbox_id2name(msg->id),
				 msg->id, rvu_get_pf(msg->pcifunc),
				 (msg->pcifunc & RVU_PFVF_FUNC_MASK) - 1);
		else
			dev_warn(rvu->dev, "Error %d when processing message %s (0x%x) from EPF%d\n",
				 err, otx2_mbox_id2name(msg->id),
				 msg->id, devid);
	}

	mw->mbox_wrk[devid].num_msgs = 0;

	if (!is_cn20k(mbox->pdev) && poll)
		otx2_mbox_wait_for_zero(mbox, devid);

	/* Send mbox responses to VF/PF */
	otx2_mbox_msg_send(mbox, devid);
}

/* Each PEM supports upto 8 EPFs
 * SCRATCH(0) contains start address of mbox region of PEM0
 */
static int sdp_get_mbox_regions(struct rvu *rvu, void **mbox_addr,
				int num, int type, unsigned long *pf_bmap,
				int blkaddr)
{
	int region;
	u64 bar;

	bar = rvu_read64(rvu, blkaddr, SDP_AF_EPFX_SCRATCH(0));
	if (type == TYPE_AFEPF) {
		for (region = 0; region < num; region++) {
			if (!test_bit(region, pf_bmap))
				continue;

			bar += region * MBOX_SIZE;
			mbox_addr[region] = (void *)ioremap_wc(bar, MBOX_SIZE);

			if (!mbox_addr[region])
				goto error;
		}
	}
	return 0;

error:
	return -ENOMEM;
}

static int sdp_mbox_init(struct rvu *rvu, struct mbox_wq_info *mw,
			 int type, int num, int blkaddr,
			 void (mbox_handler)(struct work_struct *),
			 void (mbox_up_handler)(struct work_struct *))
{
	int err = -EINVAL, i, dir, dir_up;
	void __iomem *reg_base;
	struct rvu_work *mwork;
	unsigned long *pf_bmap;
	void **mbox_regions;
	const char *name;

	pf_bmap = bitmap_zalloc(num, GFP_KERNEL);
	if (!pf_bmap)
		return -ENOMEM;

	if (type == TYPE_AFEPF)
		*pf_bmap = GENMASK(num - 1, 0);

	mutex_init(&rvu->mbox_lock);

	mbox_regions = kcalloc(num, sizeof(void *), GFP_KERNEL);
	if (!mbox_regions) {
		err = -ENOMEM;
		goto free_bitmap;
	}

	switch (type) {
	case TYPE_AFEPF:
		name = "rvu_afepf_mailbox";
		dir = MBOX_DIR_AFEPF;
		dir_up = MBOX_DIR_AFEPF_UP;
		reg_base = rvu->afreg_base;
		err = sdp_get_mbox_regions(rvu, mbox_regions, num, TYPE_AFEPF,
					   pf_bmap, blkaddr);
		if (err)
			goto free_regions;
		break;
	default:
		goto free_regions;
	}

	mw->mbox_wq = alloc_workqueue(name,
				      WQ_HIGHPRI | WQ_MEM_RECLAIM,
				      num);
	if (!mw->mbox_wq) {
		err = -ENOMEM;
		goto unmap_regions;
	}

	mw->mbox_wrk = devm_kcalloc(rvu->dev, num,
				    sizeof(struct rvu_work), GFP_KERNEL);
	if (!mw->mbox_wrk) {
		err = -ENOMEM;
		goto exit;
	}

	mw->mbox_wrk_up = devm_kcalloc(rvu->dev, num,
				       sizeof(struct rvu_work), GFP_KERNEL);
	if (!mw->mbox_wrk_up) {
		err = -ENOMEM;
		goto exit;
	}

	err = otx2_mbox_regions_init(&mw->mbox, mbox_regions, rvu->pdev,
				     reg_base, dir, num, pf_bmap);
	if (err)
		goto exit;

	err = otx2_mbox_regions_init(&mw->mbox_up, mbox_regions, rvu->pdev,
				     reg_base, dir_up, num, pf_bmap);
	if (err)
		goto exit;

	for (i = 0; i < num; i++) {
		if (!test_bit(i, pf_bmap))
			continue;

		mwork = &mw->mbox_wrk[i];
		mwork->rvu = rvu;
		INIT_WORK(&mwork->work, mbox_handler);

		mwork = &mw->mbox_wrk_up[i];
		mwork->rvu = rvu;
		INIT_WORK(&mwork->work, mbox_up_handler);
	}
	return 0;

exit:
	destroy_workqueue(mw->mbox_wq);
unmap_regions:
	while (num--)
		iounmap((void __iomem *)mbox_regions[num]);
free_regions:
	kfree(mbox_regions);
free_bitmap:
	bitmap_free(pf_bmap);
	return err;
}

static irqreturn_t rvu_mbox_epf_intr_handler(int irq, void *cookie)
{
	struct sdp_irq_data *epf_cookie = cookie;
	struct rvu *rvu = epf_cookie->block->rvu;
	int epf_id = epf_cookie->pf_data;
	u64 epf_intr;

	epf_intr = rvu_read64(rvu, BLKADDR_SDP, SDP_AF_AP_EPFX_MBOX_LINT(epf_id));
	/* Clear interrupts */
	rvu_write64(rvu, BLKADDR_SDP, SDP_AF_AP_EPFX_MBOX_LINT(epf_id), epf_intr);
	if (epf_intr)
		trace_otx2_msg_interrupt(rvu->pdev, "EPF(s) to AF", epf_intr);

	/* Sync with mbox memory region */
	rmb();

	rvu_queue_work(&sdp_data.afepf_wq_info, 0, SDP_MAX_EPF, BIT(epf_id));
	return IRQ_HANDLED;
}

static void rvu_sdp_unregister_interrupts_block(struct rvu_block *block,
						void *data)
{
	int i, offs, blkaddr;
	struct rvu *rvu = block->rvu;

	blkaddr = block->addr;

	offs = rvu_read64(rvu, blkaddr, SDP_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get SDP_AF_INT vector offsets");
		return;
	}

	for (i = 0; i < SDP_MBOX_VEC_CNT; i++) {
		rvu_write64(rvu, blkaddr, SDP_AF_AP_EPFX_MBOX_LINT_ENA_W1S(i), 0x1);
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), block);
			rvu->irq_allocated[offs + i] = false;
		}
	}
}

static int rvu_sdp_af_request_irq(struct sdp_irq_data *epf_cookie,
				  int offset, irq_handler_t handler,
				  const char *name)
{
	struct rvu *rvu = epf_cookie->block->rvu;
	int ret = 0;

	WARN_ON(rvu->irq_allocated[offset]);
	rvu->irq_allocated[offset] = false;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "%s", name);
	ret = request_irq(pci_irq_vector(rvu->pdev, offset), handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], epf_cookie);
	if (ret)
		dev_warn(rvu->dev, "Failed to register %s irq\n", name);
	else
		rvu->irq_allocated[offset] = true;

	return rvu->irq_allocated[offset];
}

static int rvu_sdp_register_interrupts_block(struct rvu_block *block,
					     void *data)
{
	int offs, blkaddr, ret = 0, epf;
	struct rvu *rvu = block->rvu;

	blkaddr = block->addr;

	/* Read interrupt vector */
	offs = rvu_read64(rvu, blkaddr, SDP_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get SDP_AF_INT vector offsets");
		return 0;
	}
	/* Register and enable mbox interrupt */
	for (epf = 0; epf < SDP_MBOX_VEC_CNT; epf++) {
		epf_cookie[epf].block = block;
		epf_cookie[epf].pf_data = epf;
		sprintf(epf_cookie[epf].irq_name, "epf%d_intr_handler", epf);
		ret = rvu_sdp_af_request_irq(&epf_cookie[epf], offs + SDP_MBOX_LINT_EPF_0 + epf,
					     rvu_mbox_epf_intr_handler, epf_cookie[epf].irq_name);
		if (!ret)
			goto err;

		rvu_write64(rvu, block->addr, SDP_AF_AP_EPFX_MBOX_LINT_ENA_W1S(epf), ~0ULL);
	}

	return 0;
err:
	rvu_sdp_unregister_interrupts_block(block, data);
	return ret;
}

static inline void rvu_afepf_mbox_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);
	struct rvu *rvu = mwork->rvu;

	mutex_lock(&rvu->mbox_lock);
	__sdp_mbox_handler(mwork, TYPE_AFEPF, true);
	mutex_unlock(&rvu->mbox_lock);
}

static inline void rvu_afepf_mbox_up_handler(struct work_struct *work)
{
	struct rvu_work *mwork = container_of(work, struct rvu_work, work);

	__sdp_mbox_up_handler(mwork, TYPE_AFEPF);
}

int rvu_mbox_handler_sdp_read_const(struct rvu *rvu,
				    struct msg_req *req,
				    struct sdp_rsp_const *rsp)
{
	u64 sdp_const;
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_SDP, req->hdr.pcifunc);
	if (blkaddr < 0)
		return -ENODEV;

	sdp_const = rvu_read64(rvu, blkaddr, SDP_AF_CONST);
	rsp->fifo_sz = sdp_const & 0xffff;
	rsp->rings  = FIELD_GET(SDP_NUMBER_OF_RINGS_IMPL, sdp_const);
	return 0;
}

static int rvu_sdp_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	int  num_chan;
	int blkaddr;
	u64 regval;

	/* Channel Configuration */
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	num_chan = rvu_read64(rvu, blkaddr, NIX_AF_CONST1) & 0XFFFUL;
	regval = rvu->hw->sdp_chan_base;
	regval |= ilog2(num_chan) << 16;
	rvu_write64(rvu, block->addr, SDP_AF_LINK_CFG, regval);

	/* BPFLR_D disable clearing BP in FLR */
	regval = rvu_read64(rvu, block->addr, SDP_AF_GBL_CONTROL);
	regval |= (1 << 2);
	rvu_write64(rvu, block->addr, SDP_AF_GBL_CONTROL, regval);

	sdp_mbox_init(rvu, &sdp_data.afepf_wq_info, TYPE_AFEPF,
		      SDP_MAX_EPF, block->addr, rvu_afepf_mbox_handler,
		      rvu_afepf_mbox_up_handler);

	/* Now that mbox frame work setup, allow access from EPF */
	rvu_write64(rvu, block->addr, SDP_AF_ACCESS_CTL, 0xDF);

	return 0;
}

static int rvu_setup_sdp_hw_resource(struct rvu_block *block, void *data)
{
	block->type = BLKTYPE_SDP;
	block->addr = BLKADDR_SDP;
	sprintf(block->name, "SDP");
	return 0;
}

static void *rvu_sdp_probe(struct rvu *rvu, int blkaddr)
{
	struct sdp_drvdata *data;

	switch (blkaddr) {
	case BLKADDR_SDP:
		data = devm_kzalloc(rvu->dev, sizeof(struct sdp_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_sdp_remove(struct rvu_block *hwblock, void *data)
{
	devm_kfree(hwblock->rvu->dev, data);
}

static void rvu_sdp_free(struct rvu_block *block, void *data)
{
	//nothing
}

static struct rvu_eblock_driver_ops sdp_ops = {
	.probe	= rvu_sdp_probe,
	.remove	= rvu_sdp_remove,
	.init	= rvu_sdp_init_block,
	.setup	= rvu_setup_sdp_hw_resource,
	.register_interrupt = rvu_sdp_register_interrupts_block,
	.unregister_interrupt = rvu_sdp_unregister_interrupts_block,
	.free    = rvu_sdp_free,
};

void sdp_eb_module_init(void)
{
	rvu_eblock_register_driver(&sdp_ops);
}

void sdp_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&sdp_ops);
}
