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

#define MBOX_EBLOCK_ML_MESSAGES                                           \
	M(ML_RD_WR_REGISTER, 0xB000, ml_rd_wr_register, ml_rd_wr_reg_msg, \
	  ml_rd_wr_reg_msg)

/* ML mailbox error codes
 * Range 1301 - 1400.
 */
enum ml_af_status {
	ML_AF_ERR_BLOCK_NOT_IMPLEMENTED = -1301,
	ML_AF_ERR_REG_INVALID = -1302,
	ML_AF_ERR_ACCESS_DENIED = -1303,
};

/* ML mbox message formats */

struct ml_rd_wr_reg_msg {
	struct mbox_msghdr hdr;
	u64 reg_offset;
	u64 *ret_val;
	u64 val;
	u8 is_write;
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
