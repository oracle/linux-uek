/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF PSW extension
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#ifndef __RVU_PSW_MBOX_H__
#define __RVU_PSW_MBOX_H__

#include "mbox.h"
#include "rvu.h"

#define MBOX_EBLOCK_PSW_MESSAGES					\
M(PSW_ATTACH_RESOURCES, 0x1200, psw_attach_resources,			\
				psw_rsrc_attach_req, msg_rsp)		\
M(PSW_DETACH_RESOURCES, 0x1201, psw_detach_resources,			\
				psw_rsrc_detach_req, msg_rsp)		\
M(PSW_FREE_RSRC_CNT,	0x1202, psw_free_rsrc_cnt, msg_req,             \
				psw_free_rsrcs_rsp)                     \
M(PSW_MSIX_OFFSET,	0x1203, psw_msix_offset, msg_req,               \
				psw_msix_offset_rsp)                    \
M(PSW_CAPS_GET,      0x1204, psw_caps_get, msg_req, psw_caps_get_rsp)	\

/* PSW mailbox error codes
 * Range 1301 - 1400.
 */
enum psw_af_status {
	PSW_AF_ERR_PARAM		= -1301,
	PSW_AF_ERR_LF_INVALID           = -1302,
};

struct psw_rsrc_attach_req {
	struct mbox_msghdr hdr;
	u8 modify:1;
	u16 pswlfs;
};

struct psw_rsrc_detach_req {
	struct mbox_msghdr hdr;
	u8 partial:1;
	u8 pswlfs:1;
};

struct psw_free_rsrcs_rsp {
	struct mbox_msghdr hdr;
	u8 psw;
};

struct psw_msix_offset_rsp {
	struct mbox_msghdr hdr;
	u16 pswlfs;
	u16 pswlf_msixoff[MAX_RVU_BLKLF_CNT];
};

struct psw_caps_get_rsp {
	struct mbox_msghdr hdr;
	/* Host pf func ID of requested RVU pcifunc */
	u8 epf;
	u8 rsvd[7];
	/* PSW_AF_CONST0 includes, mevf, mdbl, mmsix and nepf */
	u64 const0;
	/* PSW_AF_CONST1 includes, mqueues, fidentrynum, gidbucketnum
	 * and gidentrynum
	 */
	u64 const1;
	/* PSW_AF_CONST2 includes, shared_size, TPT entries, PST and TST
	 * entries and number of LFs.
	 */
	u64 const2;
#define PSW_TYPE_COUNT 9
	/* PSW_AF_FID_TYPE(0..8)_CONST, includes pfoffset and vfoffset
	 * for each psw type
	 */
	u64 fid_type_const[PSW_TYPE_COUNT];
	u64 rsvd1[7];
};

#define M(_name, _id, _fn, _req_t, _rsp_t)                              \
	int rvu_mbox_handler_##_fn(struct rvu *, struct _req_t *,       \
				   struct _rsp_t *);
MBOX_EBLOCK_PSW_MESSAGES
#undef M

enum {
#define M(_name, _id, _1, _2, _3) MBOX_MSG_ ## _name = _id,
	MBOX_EBLOCK_PSW_MESSAGES
#undef M
};

#endif /* __RVU_PSW_MBOX_H__ */
