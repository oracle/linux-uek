// SPDX-License-Identifier: GPL-2.0
/* Marvell MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include "mcs.h"
#include "mcs_fips_reg.h"

#define MCS_AES_GCM_256_KEYLEN	32

enum mcs_fips_af_status {
	MCS_AF_ERR_TIMEOUT	= -1203,
};

static int mcs_fips_reset(struct mcs *mcs, struct mcs_fips_req *req)
{
	unsigned long timeout = jiffies + usecs_to_jiffies(2000);
	int ret = 0;
	u64 reg;

	if (req->dir == MCS_RX)
		reg = MCSX_GAE_RX_SLAVE_FIPS_RESET;
	else
		reg = MCSX_GAE_TX_SLAVE_FIPS_RESET;

	mcs_reg_write(mcs, reg, BIT_ULL(0));

	while (mcs_reg_read(mcs, reg) & BIT_ULL(0)) {
		if (time_after(jiffies, timeout)) {
			dev_err(mcs->dev, "MCS fips reset failed\n");
			ret = MCS_AF_ERR_TIMEOUT;
			break;
		}
	}

	return ret;
}

static int mcs_fips_start(struct mcs *mcs, struct mcs_fips_req *req)
{
	unsigned long timeout = jiffies + usecs_to_jiffies(2000);
	int ret = 0;
	u64 reg;

	if (req->dir == MCS_RX)
		reg = MCSX_GAE_RX_SLAVE_FIPS_START;
	else
		reg = MCSX_GAE_TX_SLAVE_FIPS_START;

	mcs_reg_write(mcs, reg, BIT_ULL(0));

	while (mcs_reg_read(mcs, reg) & BIT_ULL(0)) {
		if (time_after(jiffies, timeout)) {
			dev_err(mcs->dev, "MCS fips start failed\n");
			ret = MCS_AF_ERR_TIMEOUT;
			break;
		}
	}

	return ret;
}

int rvu_mbox_handler_mcs_fips_reset(struct rvu *rvu,
				    struct mcs_fips_req *req,
				    struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	return mcs_fips_reset(mcs, req);
}

int rvu_mbox_handler_mcs_fips_mode_set(struct rvu *rvu,
				       struct mcs_fips_mode_req *req,
				       struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX)
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_MODE, req->mode);
	else
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_MODE, req->mode);

	return 0;
}

int rvu_mbox_handler_mcs_fips_ctl_set(struct rvu *rvu,
				      struct mcs_fips_ctl_req *req,
				      struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX)
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_CTL, req->ctl);
	else
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_CTL, req->ctl);

	return 0;
}

int rvu_mbox_handler_mcs_fips_iv_set(struct rvu *rvu, struct mcs_fips_iv_req *req,
				     struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX) {
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_IV_BITS95_64, req->iv_bits95_64);
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_IV_BITS63_0, req->iv_bits63_0);
	} else {
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_IV_BITS95_64, req->iv_bits95_64);
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_IV_BITS63_0, req->iv_bits63_0);
	}

	return 0;
}

int rvu_mbox_handler_mcs_fips_ctr_set(struct rvu *rvu, struct mcs_fips_ctr_req *req,
				      struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX)
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_CTR, req->fips_ctr);
	else
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_CTR, req->fips_ctr);

	return 0;
}

int rvu_mbox_handler_mcs_fips_key_set(struct rvu *rvu, struct mcs_fips_key_req *req,
				      struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX) {
		if (req->sak_len == MCS_AES_GCM_256_KEYLEN) {
			mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS255_192,
				      req->sak_bits255_192);
			mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS191_128,
				      req->sak_bits191_128);
		}
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS127_64,
			      req->sak_bits127_64);
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS63_0, req->sak_bits63_0);
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_HASHKEY_BITS127_64,
			      req->hashkey_bits127_64);
		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_HASHKEY_BITS63_0,
			      req->hashkey_bits63_0);
	} else {
		if (req->sak_len == MCS_AES_GCM_256_KEYLEN) {
			mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS255_192,
				      req->sak_bits255_192);
			mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS191_128,
				      req->sak_bits191_128);
		}
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS127_64,
			      req->sak_bits127_64);
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS63_0, req->sak_bits63_0);
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_HASHKEY_BITS127_64,
			      req->hashkey_bits127_64);
		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_HASHKEY_BITS63_0,
			      req->hashkey_bits63_0);
	}

	return 0;
}

int rvu_mbox_handler_mcs_fips_block_set(struct rvu *rvu, struct mcs_fips_block_req *req,
					struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX) {
		if (mcs->hw->mcs_blks > 1)
			mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_BLOCK_BITS127_64,
				      req->blk_bits127_64);

		mcs_reg_write(mcs, MCSX_GAE_RX_SLAVE_FIPS_BLOCK_BITS63_0, req->blk_bits63_0);
	} else {
		if (mcs->hw->mcs_blks > 1)
			mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_BLOCK_BITS127_64,
				      req->blk_bits127_64);

		mcs_reg_write(mcs, MCSX_GAE_TX_SLAVE_FIPS_BLOCK_BITS63_0, req->blk_bits63_0);
	}

	return 0;
}

int rvu_mbox_handler_mcs_fips_start(struct rvu *rvu, struct mcs_fips_req *req,
				    struct msg_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	return mcs_fips_start(mcs, req);
}

int rvu_mbox_handler_mcs_fips_result_get(struct rvu *rvu, struct mcs_fips_req *req,
					 struct mcs_fips_result_rsp *rsp)
{
	struct mcs *mcs;

	if (req->mcs_id >= rvu->mcs_blk_cnt)
		return MCS_AF_ERR_INVALID_MCSID;

	mcs = mcs_get_pdata(req->mcs_id);

	if (req->dir == MCS_RX) {
		if (mcs->hw->mcs_blks > 1)
			rsp->blk_bits127_64 =
				mcs_reg_read(mcs, MCSX_GAE_RX_SLAVE_FIPS_RESULT_BLOCK_BITS127_64);

		rsp->blk_bits63_0 = mcs_reg_read(mcs, MCSX_GAE_RX_SLAVE_FIPS_RESULT_BLOCK_BITS63_0);
		rsp->icv_bits63_0 = mcs_reg_read(mcs, MCSX_GAE_RX_SLAVE_FIPS_RESULT_ICV_BITS63_0);
		rsp->icv_bits127_64 = mcs_reg_read(mcs,
						   MCSX_GAE_RX_SLAVE_FIPS_RESULT_ICV_BITS127_64);
		rsp->result_pass = mcs_reg_read(mcs, MCSX_GAE_RX_SLAVE_FIPS_RESULT_PASS);
	} else {
		if (mcs->hw->mcs_blks > 1)
			rsp->blk_bits127_64 =
				mcs_reg_read(mcs, MCSX_GAE_TX_SLAVE_FIPS_RESULT_BLOCK_BITS127_64);

		rsp->blk_bits63_0 = mcs_reg_read(mcs, MCSX_GAE_TX_SLAVE_FIPS_RESULT_BLOCK_BITS63_0);
		rsp->icv_bits63_0 = mcs_reg_read(mcs, MCSX_GAE_TX_SLAVE_FIPS_RESULT_ICV_BITS63_0);
		rsp->icv_bits127_64 = mcs_reg_read(mcs,
						   MCSX_GAE_TX_SLAVE_FIPS_RESULT_ICV_BITS127_64);
	}

	return 0;
}
