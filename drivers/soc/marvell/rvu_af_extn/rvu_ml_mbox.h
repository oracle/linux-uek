/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF ML extension
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef __RVU_ML_MBOX_H__
#define __RVU_ML_MBOX_H__

#include "mbox.h"
#include "rvu.h"

#define MBOX_EBLOCK_ML_MESSAGES                                                \
	M(ML_RD_WR_REGISTER, 0xB000, ml_rd_wr_register, ml_rd_wr_reg_msg,      \
	  ml_rd_wr_reg_msg)                                                    \
	M(ML_CAPS_GET, 0xB001, ml_caps_get, msg_req, ml_caps_rsp_msg)          \
	M(ML_FREE_RSRC_CNT, 0xB002, ml_free_rsrc_cnt, msg_req,                 \
	  ml_free_rsrcs_rsp)                                                   \
	M(ML_ATTACH_RESOURCES, 0xB003, ml_attach_resources, ml_rsrc_attach,    \
	  msg_rsp)                                                             \
	M(ML_DETACH_RESOURCES, 0xB004, ml_detach_resources, msg_req, msg_rsp)  \
	M(ML_MSIX_OFFSET, 0xB005, ml_msix_offset, msg_req, ml_msix_offset_rsp) \
	M(ML_LF_ALLOC, 0xB006, ml_lf_alloc, ml_lf_alloc_req, msg_rsp)          \
	M(ML_LF_FREE, 0xB007, ml_lf_free, msg_req, msg_rsp)                    \
	M(ML_PID_LF_MAP, 0xB008, ml_pid_lf_map, ml_pid_lf_map_req, msg_rsp)

/* ML mailbox error codes
 * Range 1301 - 1400.
 */
enum ml_af_status {
	ML_AF_ERR_BLOCK_NOT_IMPLEMENTED = -1301,
	ML_AF_ERR_REG_INVALID = -1302,
	ML_AF_ERR_ACCESS_DENIED = -1303,
	ML_AF_ERR_LF_INVALID = -1304,
	ML_AF_ERR_SSO_PF_FUNC_INVALID = -1305,
};

/* ML mbox message formats */

struct ml_rd_wr_reg_msg {
	struct mbox_msghdr hdr;
	u64 reg_offset;
	u64 *ret_val;
	u64 val;
	u8 is_write;
};

struct ml_caps_rsp_msg {
	struct mbox_msghdr hdr;
	u64 ml_af_const;
};

struct ml_free_rsrcs_rsp {
	struct mbox_msghdr hdr;
	u8 ml;
};

struct ml_rsrc_attach {
	struct mbox_msghdr hdr;
	u8 modify : 1;
	u16 mllfs;
};

struct ml_msix_offset_rsp {
	struct mbox_msghdr hdr;
	u16 mllfs;
	u16 mllf_msixoff[MAX_RVU_BLKLF_CNT];
};

struct ml_lf_alloc_req {
	struct mbox_msghdr hdr;
	u16 sso_pf_func;
};

struct ml_pid_lf_map_req {
	struct mbox_msghdr hdr;
	u8 enable;
	u8 pid;
	u16 lf_id;
};

#define M(_name, _id, fn_name, req, rsp)                           \
	int rvu_mbox_handler_##fn_name(struct rvu *, struct req *, \
				       struct rsp *);
MBOX_EBLOCK_ML_MESSAGES
#undef M

enum {
#define M(_name, _id, _1, _2, _3) MBOX_MSG_##_name = _id,
	MBOX_EBLOCK_ML_MESSAGES
#undef M
};

#endif /* __RVU_ML_MBOX_H__ */
