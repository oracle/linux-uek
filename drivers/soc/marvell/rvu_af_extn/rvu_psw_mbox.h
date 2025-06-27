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
M(PSW_GID_ALLOC,     0x1205, psw_gid_alloc, psw_gid_alloc_req, msg_rsp)	\
M(PSW_GID_FREE,      0x1206, psw_gid_free, psw_gid_free_req, msg_rsp)	\
M(PSW_FID_ALLOC_ENTRY,  0x1207, psw_fid_alloc_entry, psw_fid_alloc_entry_req,\
				psw_fid_alloc_entry_rsp)		\
M(PSW_FID_FREE_ENTRY,   0x1208, psw_fid_free_entry, psw_fid_free_entry_req,\
				msg_rsp)				\
M(PSW_EPF_DBL_CFG,      0x1209, psw_epf_dbl_cfg, psw_epf_dbl_cfg_req, msg_rsp) \
M(PSW_EPFVF_MAP_CFG,    0x120A, psw_epfvf_map_cfg, psw_epfvf_map_cfg_req, \
				msg_rsp)				\
M(PSW_EPFVF_PCIE_CFG,   0x120B, psw_epfvf_pcie_cfg, psw_epfvf_pcie_cfg_req, \
				msg_rsp)				\
M(PSW_TPT_CFG,          0x120C, psw_tpt_cfg, psw_tpt_cfg_req, psw_tpt_cfg_rsp)	\
M(PSW_TST_ADD_ENTRY,    0x120D, psw_tst_add_entry, psw_tst_add_entry_req, \
				psw_tst_add_entry_rsp)			\
M(PSW_TST_MODIFY_ENTRY, 0x120E, psw_tst_modify_entry, psw_tst_modify_entry_req, \
				msg_rsp)				\

/* PSW mailbox error codes
 * Range 1301 - 1400.
 */
enum psw_af_status {
	PSW_AF_ERR_PARAM		= -1301,
	PSW_AF_ERR_LF_INVALID           = -1302,
	PSW_AF_ERR_NOSPC                = -1303,
	PSW_AF_ERR_GID_MLL              = -1304,
	PSW_AF_ERR_GID_EXIST            = -1305,
	PSW_AF_ERR_GID_NOENT            = -1306,
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

/* Setups GID table and provides resources for the requested number of
 * queues.
 *
 * GID_ENTRY[X]: PF_FUNC = EPF_FUNC, RID = rid_base, QID = A1;
 * GID_ENTRY[X+1]: PF_FUNC = EPF_FUNC, RID = rid_base + 1, QID = A2;
 * GID_ENTRY[X+2]: PF_FUNC = EPF_FUNC, RID = rid_base + 2, QID = A3;
 * ...
 * ...
 * GID_ENTRY[X + nb_inb_qs - 1]: PF_FUNC = EPF_FUNC, RID = nb_inb_qs - 1,
 * QID = AN;
 */
struct psw_gid_alloc_req {
	struct mbox_msghdr hdr;
	u16 evf_id;  /* Host VF ID */
	u16 nb_inb_qs; /* Number of inbound queues */
	u16 nb_outb_qs; /* Number of outbound queues */
	u16 nb_mid; /* Number of MSIX ID's */
	u16 rid_base; /* Base RID */
	u16 rsvd1[3];
	u64 rsvd2;
};

/* Frees up GID table all entries for requested epf_func.
 * and releases the associated HIB, SHIB, HOB, SHOB.
 */
struct psw_gid_free_req {
	struct mbox_msghdr hdr;
	u16 evf_id; /* Host VF ID */
	u16 nb_rids;
	u16 rid_base;
	u16 rsvd1;
	u64 rsvd2;
};

/* Allocates a FID entry for the requested epf_func
 * and populates PSW_AF_FID_INDX, PSW_AF_FID_BASEX, PSW_AF_FID_ATTRX
 * and returns the index.
 */
struct psw_fid_alloc_entry_req {
	struct mbox_msghdr hdr;
	u16 evf_id; /* Host VF ID */
	u16 evfm1_mask; /* EVF minus 1 MASK */
	u16 bar; /* BAR number */
	u16 isepf;
	u32 base_addr; /* Base address */
	u32 base_mask; /* Mask for base address */
	u8 read_en; /* 0-write, 1-read */
	u8 read_mask;
	/* Indirection */
	u8 log2size; /* Log2 of size of address area */
	u8 log2stride; /* Log2 of stride */
	u32 offset;
	u8 psw_type; /* PSW type */
	u8 rsvd1[3];
	u32 rsvd2;
};

struct psw_fid_alloc_entry_rsp {
	struct mbox_msghdr hdr;
	u16 fid_idx;
	u16 rsvd[3];
};

/* Frees up FID table entry */
struct psw_fid_free_entry_req {
	struct mbox_msghdr hdr;
	u16 fid_idx;
	u16 rsvd1[3];
	u64 rsvd2;
};

struct psw_epf_dbl_cfg {
	u16 mask; /* mask on 8 bytes doorbell value */
	u8 les; /* Little endian swap */
	u8 tglen; /* toggle enable */
	u8 rotate; /* Bit rotate right */
	u8 rsvd[3];
};

struct psw_epf_dbl_cfg_req {
	struct mbox_msghdr hdr;
	struct psw_epf_dbl_cfg pi;
	struct psw_epf_dbl_cfg ci;
	u64 rsvd;
};

/* Configures PSW_AF_EPF(0..15)_EVF(0..127)_MAP and PSW_AF_EPF(0..15)_MAP */
struct psw_epfvf_map_cfg_req {
	struct mbox_msghdr hdr;
	u16 evf_id;/* Host VF ID */
	u16 lf_id; /* PSW LF slot id */
	u8 enable; /* Enable or disable EPF/EVF mapping */
	u8 rsvd1[3];
	u64 rsvd2;
};

/* Configures PSW_AF_EPF(0..15)_EVF(0..127)_PCIE_CFG and
 * PSW_AF_EPF(0..15)_PCIE_CFG
 */
struct psw_epfvf_pcie_cfg_req {
	struct mbox_msghdr hdr;
	u16 evf_id; /* Host VF ID */
	u8 msix_enable; /* Enable or disable MSIX */
	u8 master_enable; /* Enable or disable master */
	u32 rsvd1;
	u64 rsvd2;
};

/* Adds, modifies or removes a entry in timer profile table. */
struct psw_tpt_cfg_req {
	struct mbox_msghdr hdr;
#define PSW_TPT_ENTRY_ADD 0x1
#define PSW_TPT_ENTRY_MODIFY 0x2
#define PSW_TPT_ENTRY_REMOVE 0x3
	/* Operation to be performed on tpt entry */
	u8 op;
	/* Timer profile table(TPT) entry ID incase of MODIFY and REMOVE */
	u8 tpt_id;
	/* Number of timer ticks between polling structure transfers */
	u16 target;
	/* Profile start delay */
	u8 start_dly;
	u8 rsvd1[3];
	u64 rsvd2;
};

struct psw_tpt_cfg_rsp {
	struct mbox_msghdr hdr;
	/* Allocated Timer profile table entry ID incase of op:ADD */
	u16 tpt_id;
	u16 rsvd[3];
};

struct psw_timed_polling_s {
	u64 w0;
	u64 w1;
	u64 w2;
	u64 w3;
};

/* Adds a entry in timer select table. */
struct psw_tst_add_entry_req {
	struct mbox_msghdr hdr;
	/* Timer profile table(TPT) entry ID to be used for a tst */
	u8 tpt_id;
	u8 rsvd1[7];
	struct psw_timed_polling_s entry;
	u64 rsvd2;
};

struct psw_tst_add_entry_rsp {
	struct mbox_msghdr hdr;
	/* Allocated Timer select table entry ID incase of op:ADD */
	u16 tst_id;
	u16 rsvd[3];
};

/* Modifies or removes a entry in timer select table. */
struct psw_tst_modify_entry_req {
	struct mbox_msghdr hdr;
	u8 enable;
	/* Timer profile table(TPT) entry ID to be used for a tst */
	u8 tpt_id;
	/* Timer select table entry ID incase of MODIFY and REMOVE */
	u16 tst_id;
	u32 rsvd1;
	u64 rsvd2;
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
