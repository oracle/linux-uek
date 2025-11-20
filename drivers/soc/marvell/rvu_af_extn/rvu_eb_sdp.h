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
#define MBOX_EBLOCK_SDP_MESSAGES				\
M(SDP_READ_CONST,    0x1001, sdp_read_const, msg_req,		\
				sdp_rsp_const)			\
M(SDP_RINGS_ALLOC, 0x1002, sdp_rings_alloc, sdp_rings_alloc_req, sdp_rings_alloc_rsp) \
M(SDP_RINGS_FREE, 0x1003, sdp_rings_free, sdp_rings_free_req, msg_rsp) \
M(SDP_RINGS_DEFAULT, 0x1004, sdp_rings_default, msg_req, sdp_rings_default_rsp)

#define MBOX_EBLOCK_UP_SDP_MESSAGES					\
M(SDP_RINGS_UPDATE,	0xE40, sdp_rings_update, sdp_rings_cfg, msg_rsp) \
M(SDP_CREATE_VFS,	0xE41, sdp_create_vfs, sdp_create_vfs_req, msg_rsp)

enum {
#define M(_name, _id, _1, _2, _3) MBOX_MSG_ ## _name = _id,
MBOX_EBLOCK_SDP_MESSAGES
MBOX_EBLOCK_UP_SDP_MESSAGES
#undef M
};

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

struct sdp_rings_alloc_req {
	struct mbox_msghdr hdr;
	u16 nr_rings;
	u16 rsvd[16];	/* Reserved */
};

struct sdp_rings_alloc_rsp {
	struct mbox_msghdr hdr;
	u16 count; /* Number of rings allocated */
	u16 rsvd[16];	/* Reserved */
};

struct sdp_rings_free_req {
	struct mbox_msghdr hdr;
	u8 all;
};

struct sdp_rings_cfg {
	struct mbox_msghdr hdr;
	unsigned long vf_bmap1;
	unsigned long vf_bmap2;
#define SDP_RING_F_ALLOC	0x1ULL
#define SDP_RING_F_FREE		0x2ULL
	u64 flags;
#define SDP_MAX_RINGS_PER_VF	128
	u16 sq2chan_map[SDP_MAX_RINGS_PER_VF];
	u16 nr_rings;
};

struct sdp_rings_default_rsp {
	struct mbox_msghdr hdr;
	u16 default_nr_rings;
};

struct sdp_create_vfs_req {
	struct mbox_msghdr hdr;
	unsigned long vf_bmap1;
	unsigned long vf_bmap2;
};

#define M(_name, _id, fn_name, req, rsp)\
int rvu_mbox_handler_ ## fn_name(struct rvu *, struct req *, struct rsp *);
MBOX_EBLOCK_SDP_MESSAGES
MBOX_EBLOCK_UP_SDP_MESSAGES
#undef M

#endif /* __RVU_EB_SDP_H__ */
