/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CN10K MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include "mbox.h"

#define MBOX_MCS_FIPS_MESSAGES							\
M(MCS_FIPS_RESET,	0xa040, mcs_fips_reset, mcs_fips_req, msg_rsp)		\
M(MCS_FIPS_MODE_SET,	0xa041, mcs_fips_mode_set, mcs_fips_mode_req, msg_rsp)	\
M(MCS_FIPS_CTL_SET,	0xa042, mcs_fips_ctl_set, mcs_fips_ctl_req, msg_rsp)	\
M(MCS_FIPS_IV_SET,	0xa043, mcs_fips_iv_set, mcs_fips_iv_req, msg_rsp)	\
M(MCS_FIPS_CTR_SET,	0xa044, mcs_fips_ctr_set, mcs_fips_ctr_req, msg_rsp)	\
M(MCS_FIPS_KEY_SET,	0xa045, mcs_fips_key_set, mcs_fips_key_req, msg_rsp)	\
M(MCS_FIPS_BLOCK_SET,	0xa046, mcs_fips_block_set, mcs_fips_block_req,		\
				msg_rsp)					\
M(MCS_FIPS_START,	0xa047, mcs_fips_start, mcs_fips_req, msg_rsp)		\
M(MCS_FIPS_RESULT_GET,	0xa048, mcs_fips_result_get, mcs_fips_req,		\
				mcs_fips_result_rsp)				\

struct mcs_fips_req {
	struct mbox_msghdr hdr;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_mode_req {
	struct mbox_msghdr hdr;
	u64 mode;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_ctl_req {
	struct mbox_msghdr hdr;
	u64 ctl;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_iv_req {
	struct mbox_msghdr hdr;
	u32 iv_bits95_64;
	u64 iv_bits63_0;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_ctr_req {
	struct mbox_msghdr hdr;
	u32 fips_ctr;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_key_req {
	struct mbox_msghdr hdr;
	u64 sak_bits255_192;
	u64 sak_bits191_128;
	u64 sak_bits127_64;
	u64 sak_bits63_0;
	u64 hashkey_bits127_64;
	u64 hashkey_bits63_0;
	u8 sak_len;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_block_req {
	struct mbox_msghdr hdr;
	u64 blk_bits127_64;
	u64 blk_bits63_0;
	u8 mcs_id;
	u8 dir;
};

struct mcs_fips_result_rsp {
	struct mbox_msghdr hdr;
	u64 blk_bits127_64;
	u64 blk_bits63_0;
	u64 icv_bits127_64;
	u64 icv_bits63_0;
	u8 result_pass;
};
