/* SPDX-License-Identifier: GPL-2.0
 * Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef __RVU_EB_SDP_H__
#define __RVU_EB_SDP_H__

#include "rvu_trace.h"

/* SDP CSR */
#define SDP_AF_GBL_CONTROL		           (0x4090000)
#define SDP_AF_LINK_CFG		                   (0x4090100)
#define SDP_AF_CONST				   (0x4090038)
#define SDP_AF_ACCESS_CTL			   (0x4090018)
#define SDP_NUMBER_OF_RINGS_IMPL		   GENMASK_ULL(31, 16)
#define SDP_AF_EPFX_SCRATCH(a)			   (0x4018000 + 0x400000 * ((a) & 0xf))
#define SDP_MAX_EPF				   0x10
#define SDP_PRIV_AF_INT_CFG			   0xc000000
#define SDP_AF_AP_EPFX_MBOX_LINT(a)		   (0x40c0040 + 0x400000 * ((a) & 0xf))
#define SDP_AF_AP_EPFX_MBOX_LINT_ENA_W1S(a)        (0x40c0058 + 0x400000 * ((a) & 0xf))

/* SDP IRQ */
#define SDP_MBOX_VEC_CNT			   0x10
#define SDP_MBOX_LINT_EPF_0			   0x20

#define PEMX_EPF_IDX				   8

/* SDP mbox handlers */
#define MBOX_EBLOCK_SDP_MESSAGES		   \
M(SDP_READ_CONST,    0x1, sdp_read_const, msg_req, \
			  sdp_rsp_const)

/* SDP mailbox error codes
 * Range 2001 - 2100.
 */
enum sdp_af_status {
	SDP_AF_CONFIG_PERM_DENIED		= -2001,
};

/* SDP mbox message formats */
struct sdp_rsp_const {
	struct mbox_msghdr hdr;
	u64 fifo_sz;
	u64 rings;
};

struct sdp_drvdata {
	struct mbox_wq_info	afepf_wq_info;
};

struct sdp_irq_data {
	struct rvu_block *block;
	char irq_name[NAME_SIZE];
	int pf_data;
};

#define M(_name, _id, fn_name, req, rsp)\
int rvu_mbox_handler_ ## fn_name(struct rvu *, struct req *, struct rsp *);
MBOX_EBLOCK_SDP_MESSAGES
#undef M

#endif /* __RVU_EB_SDP_H__ */
