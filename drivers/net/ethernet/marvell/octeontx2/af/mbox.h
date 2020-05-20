/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef MBOX_H
#define MBOX_H

#include <linux/etherdevice.h>
#include <linux/sizes.h>

#include "rvu_struct.h"
#include "common.h"

#define MBOX_SIZE		SZ_64K

/* AF/PF: PF initiated, PF/VF VF initiated */
#define MBOX_DOWN_RX_START	0
#define MBOX_DOWN_RX_SIZE	(46 * SZ_1K)
#define MBOX_DOWN_TX_START	(MBOX_DOWN_RX_START + MBOX_DOWN_RX_SIZE)
#define MBOX_DOWN_TX_SIZE	(16 * SZ_1K)
/* AF/PF: AF initiated, PF/VF PF initiated */
#define MBOX_UP_RX_START	(MBOX_DOWN_TX_START + MBOX_DOWN_TX_SIZE)
#define MBOX_UP_RX_SIZE		SZ_1K
#define MBOX_UP_TX_START	(MBOX_UP_RX_START + MBOX_UP_RX_SIZE)
#define MBOX_UP_TX_SIZE		SZ_1K

#if MBOX_UP_TX_SIZE + MBOX_UP_TX_START != MBOX_SIZE
# error "incorrect mailbox area sizes"
#endif

#define INTR_MASK(pfvfs) ((pfvfs < 64) ? (BIT_ULL(pfvfs) - 1) : (~0ull))

#define MBOX_RSP_TIMEOUT	3000 /* Time(ms) to wait for mbox response */

#define MBOX_MSG_ALIGN		16  /* Align mbox msg start to 16bytes */

/* Mailbox directions */
#define MBOX_DIR_AFPF		0  /* AF replies to PF */
#define MBOX_DIR_PFAF		1  /* PF sends messages to AF */
#define MBOX_DIR_PFVF		2  /* PF replies to VF */
#define MBOX_DIR_VFPF		3  /* VF sends messages to PF */
#define MBOX_DIR_AFPF_UP	4  /* AF sends messages to PF */
#define MBOX_DIR_PFAF_UP	5  /* PF replies to AF */
#define MBOX_DIR_PFVF_UP	6  /* PF sends messages to VF */
#define MBOX_DIR_VFPF_UP	7  /* VF replies to PF */

struct otx2_mbox_dev {
	void	    *mbase;   /* This dev's mbox region */
	spinlock_t  mbox_lock;
	u16         msg_size; /* Total msg size to be sent */
	u16         rsp_size; /* Total rsp size to be sure the reply is ok */
	u16         num_msgs; /* No of msgs sent or waiting for response */
	u16         msgs_acked; /* No of msgs for which response is received */
};

struct otx2_mbox {
	struct pci_dev *pdev;
	void   *hwbase;  /* Mbox region advertised by HW */
	void   *reg_base;/* CSR base for this dev */
	u64    trigger;  /* Trigger mbox notification */
	u16    tr_shift; /* Mbox trigger shift */
	u64    rx_start; /* Offset of Rx region in mbox memory */
	u64    tx_start; /* Offset of Tx region in mbox memory */
	u16    rx_size;  /* Size of Rx region */
	u16    tx_size;  /* Size of Tx region */
	u16    ndevs;    /* The number of peers */
	struct otx2_mbox_dev *dev;
};

/* Header which preceeds all mbox messages */
struct mbox_hdr {
	u64 msg_size;	/* Total msgs size embedded */
	u16  num_msgs;   /* No of msgs embedded */
};

/* Header which preceeds every msg and is also part of it */
struct mbox_msghdr {
	u16 pcifunc;     /* Who's sending this msg */
	u16 id;          /* Mbox message ID */
#define OTX2_MBOX_REQ_SIG (0xdead)
#define OTX2_MBOX_RSP_SIG (0xbeef)
	u16 sig;         /* Signature, for validating corrupted msgs */
#define OTX2_MBOX_VERSION (0x0007)
	u16 ver;         /* Version of msg's structure for this ID */
	u16 next_msgoff; /* Offset of next msg within mailbox region */
	int rc;          /* Msg process'ed response code */
};

void otx2_mbox_reset(struct otx2_mbox *mbox, int devid);
void otx2_mbox_destroy(struct otx2_mbox *mbox);
int otx2_mbox_init(struct otx2_mbox *mbox, void __force *hwbase,
		   struct pci_dev *pdev, void __force *reg_base,
		   int direction, int ndevs);
void otx2_mbox_msg_send(struct otx2_mbox *mbox, int devid);
int otx2_mbox_wait_for_rsp(struct otx2_mbox *mbox, int devid);
int otx2_mbox_busy_poll_for_rsp(struct otx2_mbox *mbox, int devid);
struct mbox_msghdr *otx2_mbox_alloc_msg_rsp(struct otx2_mbox *mbox, int devid,
					    int size, int size_rsp);
struct mbox_msghdr *otx2_mbox_get_rsp(struct otx2_mbox *mbox, int devid,
				      struct mbox_msghdr *msg);
int otx2_mbox_check_rsp_msgs(struct otx2_mbox *mbox, int devid);
int otx2_reply_invalid_msg(struct otx2_mbox *mbox, int devid,
			   u16 pcifunc, u16 id);
bool otx2_mbox_nonempty(struct otx2_mbox *mbox, int devid);
const char *otx2_mbox_id2name(u16 id);
static inline struct mbox_msghdr *otx2_mbox_alloc_msg(struct otx2_mbox *mbox,
						      int devid, int size)
{
	return otx2_mbox_alloc_msg_rsp(mbox, devid, size, 0);
}

/* Mailbox message types */
#define MBOX_MSG_MASK				0xFFFF
#define MBOX_MSG_INVALID			0xFFFE
#define MBOX_MSG_MAX				0xFFFF

#define MBOX_MESSAGES							\
/* Generic mbox IDs (range 0x000 - 0x1FF) */				\
M(READY,		0x001, ready, msg_req, ready_msg_rsp)		\
M(ATTACH_RESOURCES,	0x002, attach_resources, rsrc_attach, msg_rsp)	\
M(DETACH_RESOURCES,	0x003, detach_resources, rsrc_detach, msg_rsp)	\
M(FREE_RSRC_CNT,	0x004, free_rsrc_cnt, msg_req, free_rsrcs_rsp)	\
M(MSIX_OFFSET,		0x005, msix_offset, msg_req, msix_offset_rsp)	\
M(VF_FLR,		0x006, vf_flr, msg_req, msg_rsp)		\
M(PTP_OP,		0x007, ptp_op, ptp_req, ptp_rsp)		\
M(GET_HW_CAP,		0x008, get_hw_cap, msg_req, get_hw_cap_rsp)	\
M(NDC_SYNC_OP,		0x009, ndc_sync_op, ndc_sync_op, msg_rsp)	\
/* CGX mbox IDs (range 0x200 - 0x3FF) */				\
M(CGX_START_RXTX,	0x200, cgx_start_rxtx, msg_req, msg_rsp)	\
M(CGX_STOP_RXTX,	0x201, cgx_stop_rxtx, msg_req, msg_rsp)		\
M(CGX_STATS,		0x202, cgx_stats, msg_req, cgx_stats_rsp)	\
M(CGX_MAC_ADDR_SET,	0x203, cgx_mac_addr_set, cgx_mac_addr_set_or_get,    \
				cgx_mac_addr_set_or_get)		\
M(CGX_MAC_ADDR_GET,	0x204, cgx_mac_addr_get, cgx_mac_addr_set_or_get,    \
				cgx_mac_addr_set_or_get)		\
M(CGX_PROMISC_ENABLE,	0x205, cgx_promisc_enable, msg_req, msg_rsp)	\
M(CGX_PROMISC_DISABLE,	0x206, cgx_promisc_disable, msg_req, msg_rsp)	\
M(CGX_START_LINKEVENTS, 0x207, cgx_start_linkevents, msg_req, msg_rsp)	\
M(CGX_STOP_LINKEVENTS,	0x208, cgx_stop_linkevents, msg_req, msg_rsp)	\
M(CGX_GET_LINKINFO,	0x209, cgx_get_linkinfo, msg_req, cgx_link_info_msg) \
M(CGX_INTLBK_ENABLE,	0x20A, cgx_intlbk_enable, msg_req, msg_rsp)	\
M(CGX_INTLBK_DISABLE,	0x20B, cgx_intlbk_disable, msg_req, msg_rsp)	\
M(CGX_PTP_RX_ENABLE,	0x20C, cgx_ptp_rx_enable, msg_req, msg_rsp)	\
M(CGX_PTP_RX_DISABLE,	0x20D, cgx_ptp_rx_disable, msg_req, msg_rsp)	\
M(CGX_CFG_PAUSE_FRM,	0x20E, cgx_cfg_pause_frm, cgx_pause_frm_cfg,\
			       cgx_pause_frm_cfg)			\
M(CGX_FW_DATA_GET,	0x20F, cgx_get_aux_link_info, msg_req, cgx_fw_data) \
M(CGX_FEC_SET,		0x210, cgx_set_fec_param, fec_mode, fec_mode) \
M(CGX_MAC_ADDR_ADD,	0x211, cgx_mac_addr_add, cgx_mac_addr_add_req,    \
				cgx_mac_addr_add_rsp)		\
M(CGX_MAC_ADDR_DEL,	0x212, cgx_mac_addr_del, cgx_mac_addr_del_req,    \
				msg_rsp)		\
M(CGX_MAC_MAX_ENTRIES_GET, 0x213, cgx_mac_max_entries_get, msg_req,    \
				cgx_max_dmac_entries_get_rsp)		\
M(CGX_SET_LINK_STATE,	0x214, cgx_set_link_state,    \
				cgx_set_link_state_msg, msg_rsp)	\
M(CGX_GET_PHY_MOD_TYPE, 0x215, cgx_get_phy_mod_type, msg_req, \
				cgx_phy_mod_type) \
M(CGX_SET_PHY_MOD_TYPE, 0x216, cgx_set_phy_mod_type, cgx_phy_mod_type,	\
				msg_rsp) \
M(CGX_FEC_STATS,	0x217, cgx_fec_stats, msg_req, cgx_fec_stats_rsp) \
M(CGX_SET_LINK_MODE,	0x218, cgx_set_link_mode, cgx_set_link_mode_req,\
			       cgx_set_link_mode_rsp)	\
M(CGX_GET_PHY_FEC_STATS, 0x219, cgx_get_phy_fec_stats, msg_req, msg_rsp) \
M(CGX_STATS_RST,	0x21A, cgx_stats_rst, msg_req, msg_rsp)		\
/* NPA mbox IDs (range 0x400 - 0x5FF) */				\
M(NPA_LF_ALLOC,		0x400, npa_lf_alloc,				\
				npa_lf_alloc_req, npa_lf_alloc_rsp)	\
M(NPA_LF_FREE,		0x401, npa_lf_free, msg_req, msg_rsp)		\
M(NPA_AQ_ENQ,		0x402, npa_aq_enq, npa_aq_enq_req, npa_aq_enq_rsp)   \
M(NPA_HWCTX_DISABLE,	0x403, npa_hwctx_disable, hwctx_disable_req, msg_rsp)\
/* SSO/SSOW mbox IDs (range 0x600 - 0x7FF) */				\
M(SSO_LF_ALLOC,		0x600, sso_lf_alloc,				\
				sso_lf_alloc_req, sso_lf_alloc_rsp)	\
M(SSO_LF_FREE,		0x601, sso_lf_free, sso_lf_free_req, msg_rsp)	\
M(SSOW_LF_ALLOC,	0x602, ssow_lf_alloc, ssow_lf_alloc_req, msg_rsp)\
M(SSOW_LF_FREE,		0x603, ssow_lf_free, ssow_lf_free_req, msg_rsp)	\
M(SSO_HW_SETCONFIG,	0x604, sso_hw_setconfig, sso_hw_setconfig, msg_rsp)\
M(SSO_GRP_SET_PRIORITY,	0x605, sso_grp_set_priority,			\
				sso_grp_priority, msg_rsp)		\
M(SSO_GRP_GET_PRIORITY,	0x606, sso_grp_get_priority,			\
				sso_info_req, sso_grp_priority)		\
M(SSO_WS_CACHE_INV,	0x607, sso_ws_cache_inv, msg_req, msg_rsp)	\
M(SSO_GRP_QOS_CONFIG,	0x608, sso_grp_qos_config, sso_grp_qos_cfg, msg_rsp)\
M(SSO_GRP_GET_STATS,	0x609, sso_grp_get_stats, sso_info_req, sso_grp_stats)\
M(SSO_HWS_GET_STATS,	0x610, sso_hws_get_stats, sso_info_req, sso_hws_stats)\
/* TIM mbox IDs (range 0x800 - 0x9FF) */				\
M(TIM_LF_ALLOC,		0x800, tim_lf_alloc,				\
				tim_lf_alloc_req, tim_lf_alloc_rsp)	\
M(TIM_LF_FREE,		0x801, tim_lf_free, tim_ring_req, msg_rsp)	\
M(TIM_CONFIG_RING,	0x802, tim_config_ring, tim_config_req, msg_rsp)\
M(TIM_ENABLE_RING,	0x803, tim_enable_ring, tim_ring_req, tim_enable_rsp)\
M(TIM_DISABLE_RING,	0x804, tim_disable_ring, tim_ring_req, msg_rsp)	\
/* CPT mbox IDs (range 0xA00 - 0xBFF) */				\
M(CPT_LF_ALLOC,		0xA00, cpt_lf_alloc, cpt_lf_alloc_req_msg,	\
			       msg_rsp)			\
M(CPT_LF_FREE,		0xA01, cpt_lf_free, msg_req, msg_rsp)		\
M(CPT_RD_WR_REGISTER,	0xA02, cpt_rd_wr_register,  cpt_rd_wr_reg_msg,	\
			       cpt_rd_wr_reg_msg)			\
M(CPT_INLINE_IPSEC_CFG,	0xA04, cpt_inline_ipsec_cfg,			\
			       cpt_inline_ipsec_cfg_msg, msg_rsp)	\
/* REE mbox IDs (range 0xE00 - 0xFFF) */				\
M(REE_CONFIG_LF,	0xE01, ree_config_lf, ree_lf_req_msg,		\
				msg_rsp)				\
M(REE_RD_WR_REGISTER,	0xE02, ree_rd_wr_register, ree_rd_wr_reg_msg,	\
				ree_rd_wr_reg_msg)			\
M(REE_RULE_DB_PROG,	0xE03, ree_rule_db_prog,			\
				ree_rule_db_prog_req_msg,		\
				msg_rsp)				\
M(REE_RULE_DB_LEN_GET,	0xE04, ree_rule_db_len_get, ree_req_msg,	\
				ree_rule_db_len_rsp_msg)		\
M(REE_RULE_DB_GET,	0xE05, ree_rule_db_get,				\
				ree_rule_db_get_req_msg,		\
				ree_rule_db_get_rsp_msg)		\
/* NPC mbox IDs (range 0x6000 - 0x7FFF) */				\
M(NPC_MCAM_ALLOC_ENTRY,	0x6000, npc_mcam_alloc_entry, npc_mcam_alloc_entry_req,\
				npc_mcam_alloc_entry_rsp)		\
M(NPC_MCAM_FREE_ENTRY,	0x6001, npc_mcam_free_entry,			\
				 npc_mcam_free_entry_req, msg_rsp)	\
M(NPC_MCAM_WRITE_ENTRY,	0x6002, npc_mcam_write_entry,			\
				 npc_mcam_write_entry_req, msg_rsp)	\
M(NPC_MCAM_ENA_ENTRY,   0x6003, npc_mcam_ena_entry,			\
				 npc_mcam_ena_dis_entry_req, msg_rsp)	\
M(NPC_MCAM_DIS_ENTRY,   0x6004, npc_mcam_dis_entry,			\
				 npc_mcam_ena_dis_entry_req, msg_rsp)	\
M(NPC_MCAM_SHIFT_ENTRY, 0x6005, npc_mcam_shift_entry, npc_mcam_shift_entry_req,\
				npc_mcam_shift_entry_rsp)		\
M(NPC_MCAM_ALLOC_COUNTER, 0x6006, npc_mcam_alloc_counter,		\
					npc_mcam_alloc_counter_req,	\
					npc_mcam_alloc_counter_rsp)	\
M(NPC_MCAM_FREE_COUNTER,  0x6007, npc_mcam_free_counter,		\
				    npc_mcam_oper_counter_req, msg_rsp)	\
M(NPC_MCAM_UNMAP_COUNTER, 0x6008, npc_mcam_unmap_counter,		\
				   npc_mcam_unmap_counter_req, msg_rsp)	\
M(NPC_MCAM_CLEAR_COUNTER, 0x6009, npc_mcam_clear_counter,		\
				   npc_mcam_oper_counter_req, msg_rsp)	\
M(NPC_MCAM_COUNTER_STATS, 0x600a, npc_mcam_counter_stats,		\
				   npc_mcam_oper_counter_req,		\
				   npc_mcam_oper_counter_rsp)		\
M(NPC_MCAM_ALLOC_AND_WRITE_ENTRY, 0x600b, npc_mcam_alloc_and_write_entry,      \
					  npc_mcam_alloc_and_write_entry_req,  \
					  npc_mcam_alloc_and_write_entry_rsp)  \
M(NPC_GET_KEX_CFG,	  0x600c, npc_get_kex_cfg,			\
				   msg_req, npc_get_kex_cfg_rsp)	\
M(NPC_INSTALL_FLOW,	  0x600d, npc_install_flow,			       \
				  npc_install_flow_req, npc_install_flow_rsp)  \
M(NPC_DELETE_FLOW,	  0x600e, npc_delete_flow,			\
				  npc_delete_flow_req, msg_rsp)		\
M(NPC_MCAM_READ_ENTRY,	  0x600f, npc_mcam_read_entry,			\
				  npc_mcam_read_entry_req,		\
				  npc_mcam_read_entry_rsp)		\
M(NPC_SET_PKIND,        0x6010,   npc_set_pkind,                        \
				  npc_set_pkind, msg_rsp)               \
/* NIX mbox IDs (range 0x8000 - 0xFFFF) */				\
M(NIX_LF_ALLOC,		0x8000, nix_lf_alloc,				\
				 nix_lf_alloc_req, nix_lf_alloc_rsp)	\
M(NIX_LF_FREE,		0x8001, nix_lf_free, nix_lf_free_req, msg_rsp)	\
M(NIX_AQ_ENQ,		0x8002, nix_aq_enq, nix_aq_enq_req, nix_aq_enq_rsp)  \
M(NIX_HWCTX_DISABLE,	0x8003, nix_hwctx_disable,			\
				 hwctx_disable_req, msg_rsp)		\
M(NIX_TXSCH_ALLOC,	0x8004, nix_txsch_alloc,			\
				 nix_txsch_alloc_req, nix_txsch_alloc_rsp)   \
M(NIX_TXSCH_FREE,	0x8005, nix_txsch_free, nix_txsch_free_req, msg_rsp) \
M(NIX_TXSCHQ_CFG,	0x8006, nix_txschq_cfg, nix_txschq_config,	\
				nix_txschq_config)			\
M(NIX_STATS_RST,	0x8007, nix_stats_rst, msg_req, msg_rsp)	\
M(NIX_VTAG_CFG,		0x8008, nix_vtag_cfg, nix_vtag_config,		\
				 nix_vtag_config_rsp)			\
M(NIX_RSS_FLOWKEY_CFG,  0x8009, nix_rss_flowkey_cfg,			\
				 nix_rss_flowkey_cfg,			\
				 nix_rss_flowkey_cfg_rsp)		\
M(NIX_SET_MAC_ADDR,	0x800a, nix_set_mac_addr, nix_set_mac_addr, msg_rsp) \
M(NIX_SET_RX_MODE,	0x800b, nix_set_rx_mode, nix_rx_mode, msg_rsp)	\
M(NIX_SET_HW_FRS,	0x800c, nix_set_hw_frs, nix_frs_cfg, msg_rsp)	\
M(NIX_LF_START_RX,	0x800d, nix_lf_start_rx, msg_req, msg_rsp)	\
M(NIX_LF_STOP_RX,	0x800e, nix_lf_stop_rx, msg_req, msg_rsp)	\
M(NIX_MARK_FORMAT_CFG,	0x800f, nix_mark_format_cfg,			\
				 nix_mark_format_cfg,			\
				 nix_mark_format_cfg_rsp)		\
M(NIX_SET_RX_CFG,	0x8010, nix_set_rx_cfg, nix_rx_cfg, msg_rsp)	\
M(NIX_LSO_FORMAT_CFG,	0x8011, nix_lso_format_cfg,			\
				 nix_lso_format_cfg,			\
				 nix_lso_format_cfg_rsp)		\
M(NIX_LF_PTP_TX_ENABLE, 0x8013, nix_lf_ptp_tx_enable, msg_req, msg_rsp)	\
M(NIX_LF_PTP_TX_DISABLE, 0x8014, nix_lf_ptp_tx_disable, msg_req, msg_rsp) \
M(NIX_SET_VLAN_TPID,	0x8015, nix_set_vlan_tpid, nix_set_vlan_tpid, msg_rsp) \
M(NIX_BP_ENABLE,	0x8016, nix_bp_enable, nix_bp_cfg_req,	\
				nix_bp_cfg_rsp)	\
M(NIX_BP_DISABLE,	0x8017, nix_bp_disable, nix_bp_cfg_req, msg_rsp) \
M(NIX_GET_MAC_ADDR, 0x8018, nix_get_mac_addr, msg_req, nix_get_mac_addr_rsp) \
M(NIX_INLINE_IPSEC_CFG, 0x8019, nix_inline_ipsec_cfg,			\
				nix_inline_ipsec_cfg, msg_rsp)		\
M(NIX_INLINE_IPSEC_LF_CFG, 0x801a, nix_inline_ipsec_lf_cfg,		\
				nix_inline_ipsec_lf_cfg, msg_rsp)

/* Messages initiated by AF (range 0xC00 - 0xDFF) */
#define MBOX_UP_CGX_MESSAGES						\
M(CGX_LINK_EVENT,	0xC00, cgx_link_event, cgx_link_info_msg, msg_rsp) \
M(CGX_PTP_RX_INFO,	0xC01, cgx_ptp_rx_info,	cgx_ptp_rx_info_msg, msg_rsp)

enum {
#define M(_name, _id, _1, _2, _3) MBOX_MSG_ ## _name = _id,
MBOX_MESSAGES
MBOX_UP_CGX_MESSAGES
#undef M
};

/* Mailbox message formats */

#define RVU_DEFAULT_PF_FUNC     0xFFFF

/* Generic request msg used for those mbox messages which
 * don't send any data in the request.
 */
struct msg_req {
	struct mbox_msghdr hdr;
};

/* Generic rsponse msg used a ack or response for those mbox
 * messages which doesn't have a specific rsp msg format.
 */
struct msg_rsp {
	struct mbox_msghdr hdr;
};

/* RVU mailbox error codes
 * Range 256 - 300.
 */
enum rvu_af_status {
	RVU_INVALID_VF_ID           = -256,
};

struct ready_msg_rsp {
	struct mbox_msghdr hdr;
	u16    sclk_freq;	/* SCLK frequency (in MHz) */
	u16    rclk_freq;	/* RCLK frequency (in MHz) */
};

/* Structure for requesting resource provisioning.
 * 'modify' flag to be used when either requesting more
 * or to detach partial of a cetain resource type.
 * Rest of the fields specify how many of what type to
 * be attached.
 * To request LFs from two blocks of same type this mailbox
 * can be sent twice as below:
 *      struct rsrc_attach *attach;
 *       .. Allocate memory for message ..
 *       attach->cptlfs = 3; <3 LFs from CPT0>
 *       .. Send message ..
 *       .. Allocate memory for message ..
 *       attach->modify = 1;
 *       attach->cpt_blkaddr = BLKADDR_CPT1;
 *       attach->cptlfs = 2; <2 LFs from CPT1>
 *       .. Send message ..
 */
struct rsrc_attach {
	struct mbox_msghdr hdr;
	u8   modify:1;
	u8   npalf:1;
	u8   nixlf:1;
	u16  sso;
	u16  ssow;
	u16  timlfs;
	u16  cptlfs;
	u16  reelfs;
	int  cpt_blkaddr; /* BLKADDR_CPT0/BLKADDR_CPT1 or 0 for BLKADDR_CPT0 */
	int  ree_blkaddr; /* BLKADDR_REE0/BLKADDR_REE1 or 0 for BLKADDR_REE0 */
};

/* Structure for relinquishing resources.
 * 'partial' flag to be used when relinquishing all resources
 * but only of a certain type. If not set, all resources of all
 * types provisioned to the RVU function will be detached.
 */
struct rsrc_detach {
	struct mbox_msghdr hdr;
	u8 partial:1;
	u8 npalf:1;
	u8 nixlf:1;
	u8 sso:1;
	u8 ssow:1;
	u8 timlfs:1;
	u8 cptlfs:1;
	u8 reelfs:1;
};

/*
 * Number of resources available to the caller.
 * In reply to MBOX_MSG_FREE_RSRC_CNT.
 */
struct free_rsrcs_rsp {
	struct mbox_msghdr hdr;
	u16 schq[NIX_TXSCH_LVL_CNT];
	u16  sso;
	u16  tim;
	u16  ssow;
	u16  cpt;
	u8   npa;
	u8   nix;
	u16  schq_nix1[NIX_TXSCH_LVL_CNT];
	u8   nix1;
	u8   cpt1;
	u8   ree0;
	u8   ree1;
};

#define MSIX_VECTOR_INVALID	0xFFFF
#define MAX_RVU_BLKLF_CNT	256

struct msix_offset_rsp {
	struct mbox_msghdr hdr;
	u16  npa_msixoff;
	u16  nix_msixoff;
	u8   sso;
	u8   ssow;
	u8   timlfs;
	u8   cptlfs;
	u16  sso_msixoff[MAX_RVU_BLKLF_CNT];
	u16  ssow_msixoff[MAX_RVU_BLKLF_CNT];
	u16  timlf_msixoff[MAX_RVU_BLKLF_CNT];
	u16  cptlf_msixoff[MAX_RVU_BLKLF_CNT];
	u8   cpt1_lfs;
	u8   ree0_lfs;
	u8   ree1_lfs;
	u16  cpt1_lf_msixoff[MAX_RVU_BLKLF_CNT];
	u16  ree0_lf_msixoff[MAX_RVU_BLKLF_CNT];
	u16  ree1_lf_msixoff[MAX_RVU_BLKLF_CNT];
};

/* CGX mbox message formats */

struct cgx_stats_rsp {
	struct mbox_msghdr hdr;
#define CGX_RX_STATS_COUNT	13
#define CGX_TX_STATS_COUNT	18
	u64 rx_stats[CGX_RX_STATS_COUNT];
	u64 tx_stats[CGX_TX_STATS_COUNT];
};

struct cgx_fec_stats_rsp {
	struct mbox_msghdr hdr;
	u64 fec_corr_blks;
	u64 fec_uncorr_blks;
};
/* Structure for requesting the operation for
 * setting/getting mac address in the CGX interface
 */
struct cgx_mac_addr_set_or_get {
	struct mbox_msghdr hdr;
	u8 mac_addr[ETH_ALEN];
};

/* Structure for requesting the operation to
 * add DMAC filter entry into CGX interface
 */
struct cgx_mac_addr_add_req {
	struct mbox_msghdr hdr;
	u8 mac_addr[ETH_ALEN];
};

/* Structure for response against the operation to
 * add DMAC filter entry into CGX interface
 */
struct cgx_mac_addr_add_rsp {
	struct mbox_msghdr hdr;
	u8 index;
};

/* Structure for requesting the operation to
 * delete DMAC filter entry from CGX interface
 */
struct cgx_mac_addr_del_req {
	struct mbox_msghdr hdr;
	u8 index;
};

/* Structure for response against the operation to
 * get maximum supported DMAC filter entries
 */
struct cgx_max_dmac_entries_get_rsp {
	struct mbox_msghdr hdr;
	u8 max_dmac_filters;
};

struct cgx_link_user_info {
	uint64_t link_up:1;
	uint64_t full_duplex:1;
	uint64_t lmac_type_id:4;
	uint64_t speed:20; /* speed in Mbps */
	uint64_t an:1;	  /* AN supported or not */
	uint64_t fec:2;	 /* FEC type if enabled else 0 */
	uint64_t port:8;
#define LMACTYPE_STR_LEN 16
	char lmac_type[LMACTYPE_STR_LEN];
};

struct cgx_link_info_msg {
	struct mbox_msghdr hdr;
	struct cgx_link_user_info link_info;
};

struct cgx_ptp_rx_info_msg {
	struct mbox_msghdr hdr;
	u8 ptp_en;
};

struct cgx_pause_frm_cfg {
	struct mbox_msghdr hdr;
	u8 set;
	/* set = 1 if the request is to config pause frames */
	/* set = 0 if the request is to fetch pause frames config */
	u8 rx_pause;
	u8 tx_pause;
};

struct sfp_eeprom_s {
#define SFP_EEPROM_SIZE 256
	u16 sff_id;
	u8 buf[SFP_EEPROM_SIZE];
	u64 reserved;
};

enum fec_type {
	OTX2_FEC_NONE,
	OTX2_FEC_BASER,
	OTX2_FEC_RS,
};

struct phy_s {
	struct {
		u64 can_change_mod_type : 1;
		u64 mod_type            : 1;
		u64 has_fec_stats       : 1;
	} misc;
	struct fec_stats_s {
		u32 rsfec_corr_cws;
		u32 rsfec_uncorr_cws;
		u32 brfec_corr_blks;
		u32 brfec_uncorr_blks;
	} fec_stats;
};

struct cgx_lmac_fwdata_s {
	u16 rw_valid;
	u64 supported_fec;
	u64 supported_an;
	u64 supported_link_modes;
	/* only applicable if AN is supported */
	u64 advertised_fec;
	u64 advertised_link_modes;
	/* Only applicable if SFP/QSFP slot is present */
	struct sfp_eeprom_s sfp_eeprom;
	struct phy_s phy;
#define LMAC_FWDATA_RESERVED_MEM 1021
	u64 reserved[LMAC_FWDATA_RESERVED_MEM];
};

struct cgx_fw_data {
	struct mbox_msghdr hdr;
	struct cgx_lmac_fwdata_s fwdata;
};

struct fec_mode {
	struct mbox_msghdr hdr;
	int fec;
};

struct cgx_set_link_state_msg {
	struct mbox_msghdr hdr;
	u8 enable; /* '1' for link up, '0' for link down */
};

struct cgx_phy_mod_type {
	struct mbox_msghdr hdr;
	int mod;
};

struct npc_set_pkind {
	struct mbox_msghdr hdr;
#define OTX2_PRIV_FLAGS_DEFAULT  BIT_ULL(0)
#define OTX2_PRIV_FLAGS_EDSA     BIT_ULL(1)
#define OTX2_PRIV_FLAGS_HIGIG    BIT_ULL(2)
#define OTX2_PRIV_FLAGS_FDSA     BIT_ULL(3)
#define OTX2_PRIV_FLAGS_CUSTOM   BIT_ULL(63)
	u64 mode;
#define PKIND_TX		BIT_ULL(0)
#define PKIND_RX		BIT_ULL(1)
	u8 dir;
	u8 pkind; /* valid only in case custom flag */
};
struct cgx_set_link_mode_args {
	u32 speed;
	u8 duplex;
	u8 an;
	u8 ports;
	u64 mode;
};

struct cgx_set_link_mode_req {
	struct mbox_msghdr hdr;
	struct cgx_set_link_mode_args args;
};

struct cgx_set_link_mode_rsp {
	struct mbox_msghdr hdr;
	int status;
};
/* NPA mbox message formats */

/* NPA mailbox error codes
 * Range 301 - 400.
 */
enum npa_af_status {
	NPA_AF_ERR_PARAM            = -301,
	NPA_AF_ERR_AQ_FULL          = -302,
	NPA_AF_ERR_AQ_ENQUEUE       = -303,
	NPA_AF_ERR_AF_LF_INVALID    = -304,
	NPA_AF_ERR_AF_LF_ALLOC      = -305,
	NPA_AF_ERR_LF_RESET         = -306,
};

/* For NPA LF context alloc and init */
struct npa_lf_alloc_req {
	struct mbox_msghdr hdr;
	int node;
	int aura_sz;  /* No of auras */
	u32 nr_pools; /* No of pools */
	u64 way_mask;
};

struct npa_lf_alloc_rsp {
	struct mbox_msghdr hdr;
	u32 stack_pg_ptrs;  /* No of ptrs per stack page */
	u32 stack_pg_bytes; /* Size of stack page */
	u16 qints; /* NPA_AF_CONST::QINTS */
};

/* NPA AQ enqueue msg */
struct npa_aq_enq_req {
	struct mbox_msghdr hdr;
	u32 aura_id;
	u8 ctype;
	u8 op;
	union {
		/* Valid when op == WRITE/INIT and ctype == AURA.
		 * LF fills the pool_id in aura.pool_addr. AF will translate
		 * the pool_id to pool context pointer.
		 */
		struct npa_aura_s aura;
		/* Valid when op == WRITE/INIT and ctype == POOL */
		struct npa_pool_s pool;
	};
	/* Mask data when op == WRITE (1=write, 0=don't write) */
	union {
		/* Valid when op == WRITE and ctype == AURA */
		struct npa_aura_s aura_mask;
		/* Valid when op == WRITE and ctype == POOL */
		struct npa_pool_s pool_mask;
	};
};

struct npa_aq_enq_rsp {
	struct mbox_msghdr hdr;
	union {
		/* Valid when op == READ and ctype == AURA */
		struct npa_aura_s aura;
		/* Valid when op == READ and ctype == POOL */
		struct npa_pool_s pool;
	};
};

/* Disable all contexts of type 'ctype' */
struct hwctx_disable_req {
	struct mbox_msghdr hdr;
	u8 ctype;
};

/* NIX mbox message formats */

/* NIX mailbox error codes
 * Range 401 - 500.
 */
enum nix_af_status {
	NIX_AF_ERR_PARAM            = -401,
	NIX_AF_ERR_AQ_FULL          = -402,
	NIX_AF_ERR_AQ_ENQUEUE       = -403,
	NIX_AF_ERR_AF_LF_INVALID    = -404,
	NIX_AF_ERR_AF_LF_ALLOC      = -405,
	NIX_AF_ERR_TLX_ALLOC_FAIL   = -406,
	NIX_AF_ERR_TLX_INVALID      = -407,
	NIX_AF_ERR_RSS_SIZE_INVALID = -408,
	NIX_AF_ERR_RSS_GRPS_INVALID = -409,
	NIX_AF_ERR_FRS_INVALID      = -410,
	NIX_AF_ERR_RX_LINK_INVALID  = -411,
	NIX_AF_INVAL_TXSCHQ_CFG     = -412,
	NIX_AF_SMQ_FLUSH_FAILED     = -413,
	NIX_AF_ERR_LF_RESET         = -414,
	NIX_AF_ERR_RSS_NOSPC_FIELD  = -415,
	NIX_AF_ERR_RSS_NOSPC_ALGO   = -416,
	NIX_AF_ERR_MARK_CFG_FAIL    = -417,
	NIX_AF_ERR_LSO_CFG_FAIL     = -418,
	NIX_AF_INVAL_NPA_PF_FUNC    = -419,
	NIX_AF_INVAL_SSO_PF_FUNC    = -420,
	NIX_AF_ERR_TX_VTAG_NOSPC    = -421,
	NIX_AF_ERR_RX_VTAG_INUSE    = -422,
	NIX_AF_ERR_PTP_CONFIG_FAIL  = -423,
};

/* For NIX RX vtag action  */
enum nix_rx_vtag0_type {
	NIX_AF_LFX_RX_VTAG_TYPE0, /* reserved for rx vlan offload */
	NIX_AF_LFX_RX_VTAG_TYPE1,
	NIX_AF_LFX_RX_VTAG_TYPE2,
	NIX_AF_LFX_RX_VTAG_TYPE3,
	NIX_AF_LFX_RX_VTAG_TYPE4,
	NIX_AF_LFX_RX_VTAG_TYPE5,
	NIX_AF_LFX_RX_VTAG_TYPE6,
	NIX_AF_LFX_RX_VTAG_TYPE7,
};

/* For NIX LF context alloc and init */
struct nix_lf_alloc_req {
	struct mbox_msghdr hdr;
	int node;
	u32 rq_cnt;   /* No of receive queues */
	u32 sq_cnt;   /* No of send queues */
	u32 cq_cnt;   /* No of completion queues */
	u8  xqe_sz;
	u16 rss_sz;
	u8  rss_grps;
	u16 npa_func;
	u16 sso_func;
	u64 rx_cfg;   /* See NIX_AF_LF(0..127)_RX_CFG */
	u64 way_mask;
#define NIX_LF_RSS_TAG_LSB_AS_ADDER BIT_ULL(0)
	u64 flags;
};

struct nix_lf_alloc_rsp {
	struct mbox_msghdr hdr;
	u16	sqb_size;
	u16	rx_chan_base;
	u16	tx_chan_base;
	u8      rx_chan_cnt; /* total number of RX channels */
	u8      tx_chan_cnt; /* total number of TX channels */
	u8	lso_tsov4_idx;
	u8	lso_tsov6_idx;
	u8      mac_addr[ETH_ALEN];
	u8	lf_rx_stats; /* NIX_AF_CONST1::LF_RX_STATS */
	u8	lf_tx_stats; /* NIX_AF_CONST1::LF_TX_STATS */
	u16	cints; /* NIX_AF_CONST2::CINTS */
	u16	qints; /* NIX_AF_CONST2::QINTS */
	u8	hw_rx_tstamp_en;
	u8	cgx_links;  /* No. of CGX links present in HW */
	u8	lbk_links;  /* No. of LBK links present in HW */
	u8	sdp_links;  /* No. of SDP links present in HW */
};

struct nix_lf_free_req {
	struct mbox_msghdr hdr;
#define NIX_LF_DISABLE_FLOWS		BIT_ULL(0)
#define NIX_LF_DONT_FREE_TX_VTAG	BIT_ULL(1)
	u64 flags;
};

/* NIX AQ enqueue msg */
struct nix_aq_enq_req {
	struct mbox_msghdr hdr;
	u32  qidx;
	u8 ctype;
	u8 op;
	union {
		struct nix_rq_ctx_s rq;
		struct nix_sq_ctx_s sq;
		struct nix_cq_ctx_s cq;
		struct nix_rsse_s   rss;
		struct nix_rx_mce_s mce;
	};
	union {
		struct nix_rq_ctx_s rq_mask;
		struct nix_sq_ctx_s sq_mask;
		struct nix_cq_ctx_s cq_mask;
		struct nix_rsse_s   rss_mask;
		struct nix_rx_mce_s mce_mask;
	};
};

struct nix_aq_enq_rsp {
	struct mbox_msghdr hdr;
	union {
		struct nix_rq_ctx_s rq;
		struct nix_sq_ctx_s sq;
		struct nix_cq_ctx_s cq;
		struct nix_rsse_s   rss;
		struct nix_rx_mce_s mce;
	};
};

/* Tx scheduler/shaper mailbox messages */

#define MAX_TXSCHQ_PER_FUNC		128

struct nix_txsch_alloc_req {
	struct mbox_msghdr hdr;
	/* Scheduler queue count request at each level */
	u16 schq_contig[NIX_TXSCH_LVL_CNT]; /* No of contiguous queues */
	u16 schq[NIX_TXSCH_LVL_CNT]; /* No of non-contiguous queues */
};

struct nix_txsch_alloc_rsp {
	struct mbox_msghdr hdr;
	/* Scheduler queue count allocated at each level */
	u16 schq_contig[NIX_TXSCH_LVL_CNT];
	u16 schq[NIX_TXSCH_LVL_CNT];
	/* Scheduler queue list allocated at each level */
	u16 schq_contig_list[NIX_TXSCH_LVL_CNT][MAX_TXSCHQ_PER_FUNC];
	u16 schq_list[NIX_TXSCH_LVL_CNT][MAX_TXSCHQ_PER_FUNC];
	u8  aggr_level; /* Traffic aggregation scheduler level */
	u8  aggr_lvl_rr_prio; /* Aggregation lvl's RR_PRIO config */
	u8  link_cfg_lvl; /* LINKX_CFG CSRs mapped to TL3 or TL2's index ? */
};

struct nix_txsch_free_req {
	struct mbox_msghdr hdr;
#define TXSCHQ_FREE_ALL BIT_ULL(0)
	u16 flags;
	/* Scheduler queue level to be freed */
	u16 schq_lvl;
	/* List of scheduler queues to be freed */
	u16 schq;
};

struct nix_txschq_config {
	struct mbox_msghdr hdr;
	u8 lvl;	/* SMQ/MDQ/TL4/TL3/TL2/TL1 */
	u8 read;
#define TXSCHQ_IDX_SHIFT	16
#define TXSCHQ_IDX_MASK		(BIT_ULL(10) - 1)
#define TXSCHQ_IDX(reg, shift)	(((reg) >> (shift)) & TXSCHQ_IDX_MASK)
	u8 num_regs;
#define MAX_REGS_PER_MBOX_MSG	20
	u64 reg[MAX_REGS_PER_MBOX_MSG];
	u64 regval[MAX_REGS_PER_MBOX_MSG];
	/* All 0's => overwrite with new value */
	u64 regval_mask[MAX_REGS_PER_MBOX_MSG];
};

struct nix_vtag_config {
	struct mbox_msghdr hdr;
	/* '0' for 4 octet VTAG, '1' for 8 octet VTAG */
	u8 vtag_size;
	/* cfg_type is '0' for tx vlan cfg
	 * cfg_type is '1' for rx vlan cfg
	 */
	u8 cfg_type;
	union {
		/* valid when cfg_type is '0' */
		struct {
			u64 vtag0;
			u64 vtag1;

			/* cfg_vtag0 & cfg_vtag1 fields are valid
			 * when free_vtag0 & free_vtag1 are '0's.
			 */
			/* cfg_vtag0 = 1 to configure vtag0 */
			u8 cfg_vtag0 :1;
			/* cfg_vtag1 = 1 to configure vtag1 */
			u8 cfg_vtag1 :1;

			/* vtag0_idx & vtag1_idx are only valid when
			 * both cfg_vtag0 & cfg_vtag1 are '0's,
			 * these fields are used along with free_vtag0
			 * & free_vtag1 to free the nix lf's tx_vlan
			 * configuration.
			 *
			 * Denotes the indices of tx_vtag def registers
			 * that needs to be cleared and freed.
			 */
			int vtag0_idx;
			int vtag1_idx;

			/* free_vtag0 & free_vtag1 fields are valid
			 * when cfg_vtag0 & cfg_vtag1 are '0's.
			 */
			/* free_vtag0 = 1 clears vtag0 configuration
			 * vtag0_idx denotes the index to be cleared.
			 */
			u8 free_vtag0 :1;
			/* free_vtag1 = 1 clears vtag1 configuration
			 * vtag1_idx denotes the index to be cleared.
			 */
			u8 free_vtag1 :1;
		} tx;

		/* valid when cfg_type is '1' */
		struct {
			/* rx vtag type index, valid values are in 0..7 range */
			u8 vtag_type;
			/* rx vtag strip */
			u8 strip_vtag :1;
			/* rx vtag capture */
			u8 capture_vtag :1;
		} rx;
	};
};

struct nix_vtag_config_rsp {
	struct mbox_msghdr hdr;
	int vtag0_idx;
	int vtag1_idx;
	/* Indices of tx_vtag def registers used to configure
	 * tx vtag0 & vtag1 headers, these indices are valid
	 * when nix_vtag_config mbox requested for vtag0 and/
	 * or vtag1 configuration.
	 */
};

#define NIX_FLOW_KEY_TYPE_L3_L4_MASK (~(0xf << 28))

struct nix_rss_flowkey_cfg {
	struct mbox_msghdr hdr;
	int	mcam_index;  /* MCAM entry index to modify */
#define NIX_FLOW_KEY_TYPE_PORT	BIT(0)
#define NIX_FLOW_KEY_TYPE_IPV4	BIT(1)
#define NIX_FLOW_KEY_TYPE_IPV6	BIT(2)
#define NIX_FLOW_KEY_TYPE_TCP	BIT(3)
#define NIX_FLOW_KEY_TYPE_UDP	BIT(4)
#define NIX_FLOW_KEY_TYPE_SCTP	BIT(5)
#define NIX_FLOW_KEY_TYPE_NVGRE    BIT(6)
#define NIX_FLOW_KEY_TYPE_VXLAN    BIT(7)
#define NIX_FLOW_KEY_TYPE_GENEVE   BIT(8)
#define NIX_FLOW_KEY_TYPE_ETH_DMAC BIT(9)
#define NIX_FLOW_KEY_TYPE_IPV6_EXT BIT(10)
#define NIX_FLOW_KEY_TYPE_GTPU       BIT(11)
#define NIX_FLOW_KEY_TYPE_INNR_IPV4     BIT(12)
#define NIX_FLOW_KEY_TYPE_INNR_IPV6     BIT(13)
#define NIX_FLOW_KEY_TYPE_INNR_TCP      BIT(14)
#define NIX_FLOW_KEY_TYPE_INNR_UDP      BIT(15)
#define NIX_FLOW_KEY_TYPE_INNR_SCTP     BIT(16)
#define NIX_FLOW_KEY_TYPE_INNR_ETH_DMAC BIT(17)
#define NIX_FLOW_KEY_TYPE_CH_LEN_90B    BIT(18)
#define NIX_FLOW_KEY_TYPE_CUSTOM0	BIT(19)
#define NIX_FLOW_KEY_TYPE_L4_DST_ONLY BIT(28)
#define NIX_FLOW_KEY_TYPE_L4_SRC_ONLY BIT(29)
#define NIX_FLOW_KEY_TYPE_L3_DST_ONLY BIT(30)
#define NIX_FLOW_KEY_TYPE_L3_SRC_ONLY BIT(31)
	u32	flowkey_cfg; /* Flowkey types selected */
	u8	group;       /* RSS context or group */
};

struct nix_rss_flowkey_cfg_rsp {
	struct mbox_msghdr hdr;
	u8	alg_idx; /* Selected algo index */
};

struct nix_set_mac_addr {
	struct mbox_msghdr hdr;
	u8 mac_addr[ETH_ALEN]; /* MAC address to be set for this pcifunc */
};

struct nix_get_mac_addr_rsp {
	struct mbox_msghdr hdr;
	u8 mac_addr[ETH_ALEN];
};

struct nix_mark_format_cfg {
	struct mbox_msghdr hdr;
	u8 offset;
	u8 y_mask;
	u8 y_val;
	u8 r_mask;
	u8 r_val;
};

struct nix_mark_format_cfg_rsp {
	struct mbox_msghdr hdr;
	u8 mark_format_idx;
};

struct nix_rx_mode {
	struct mbox_msghdr hdr;
#define NIX_RX_MODE_UCAST	BIT(0)
#define NIX_RX_MODE_PROMISC	BIT(1)
#define NIX_RX_MODE_ALLMULTI	BIT(2)
	u16	mode;
};

struct nix_rx_cfg {
	struct mbox_msghdr hdr;
#define NIX_RX_OL3_VERIFY   BIT(0)
#define NIX_RX_OL4_VERIFY   BIT(1)
	u8 len_verify; /* Outer L3/L4 len check */
#define NIX_RX_CSUM_OL4_VERIFY  BIT(0)
	u8 csum_verify; /* Outer L4 checksum verification */
};

struct nix_frs_cfg {
	struct mbox_msghdr hdr;
	u8	update_smq;    /* Update SMQ's min/max lens */
	u8	update_minlen; /* Set minlen also */
	u8	sdp_link;      /* Set SDP RX link */
	u16	maxlen;
	u16	minlen;
};

struct nix_lso_format_cfg {
	struct mbox_msghdr hdr;
	u64 field_mask;
#define NIX_LSO_FIELD_MAX	8
	u64 fields[NIX_LSO_FIELD_MAX];
};

struct nix_lso_format_cfg_rsp {
	struct mbox_msghdr hdr;
	u8 lso_format_idx;
};

struct nix_set_vlan_tpid {
	struct mbox_msghdr hdr;
#define NIX_VLAN_TYPE_INNER 0
#define NIX_VLAN_TYPE_OUTER 1
	u8  vlan_type;
	u16 tpid;
};

struct nix_bp_cfg_req {
	struct mbox_msghdr hdr;
	u16	chan_base; /* Starting channel number */
	u8	chan_cnt; /* Number of channels */
	u8	bpid_per_chan;
	/* bpid_per_chan = 0  assigns single bp id for range of channels */
	/* bpid_per_chan = 1 assigns separate bp id for each channel */
};

/* PF can be mapped to either CGX or LBK interface,
 * so maximum 64 channels are possible.
 */
#define NIX_MAX_BPID_CHAN	64
struct nix_bp_cfg_rsp {
	struct mbox_msghdr hdr;
	u16	chan_bpid[NIX_MAX_BPID_CHAN]; /* Channel and bpid mapping */
	u8	chan_cnt; /* Number of channel for which bpids are assigned */
};

/* Global NIX inline IPSec configuration */
struct nix_inline_ipsec_cfg {
	struct mbox_msghdr hdr;
	u32 cpt_credit;
	struct {
		u8 egrp;
		u8 opcode;
	} gen_cfg;
	struct {
		u16 cpt_pf_func;
		u8 cpt_slot;
	} inst_qsel;
	u8 enable;
};

/* Per NIX LF inline IPSec configuration */
struct nix_inline_ipsec_lf_cfg {
	struct mbox_msghdr hdr;
	u64 sa_base_addr;
	struct {
		u32 tag_const;
		u16 lenm1_max;
		u8 sa_pow2_size;
		u8 tt;
	} ipsec_cfg0;
	struct {
		u32 sa_idx_max;
		u8 sa_idx_w;
	} ipsec_cfg1;
	u8 enable;
};

/* SSO mailbox error codes
 * Range 501 - 600.
 */
enum sso_af_status {
	SSO_AF_ERR_PARAM	= -501,
	SSO_AF_ERR_LF_INVALID	= -502,
	SSO_AF_ERR_AF_LF_ALLOC	= -503,
	SSO_AF_ERR_GRP_EBUSY	= -504,
	SSO_AF_INVAL_NPA_PF_FUNC = -505,
};

struct sso_lf_alloc_req {
	struct mbox_msghdr hdr;
	int node;
	u16 hwgrps;
};

struct sso_lf_alloc_rsp {
	struct mbox_msghdr hdr;
	u32	xaq_buf_size;
	u32	xaq_wq_entries;
	u32	in_unit_entries;
	u16	hwgrps;
};

struct sso_lf_free_req {
	struct mbox_msghdr hdr;
	int node;
	u16 hwgrps;
};

/* SSOW mailbox error codes
 * Range 601 - 700.
 */
enum ssow_af_status {
	SSOW_AF_ERR_PARAM	= -601,
	SSOW_AF_ERR_LF_INVALID	= -602,
	SSOW_AF_ERR_AF_LF_ALLOC	= -603,
};

struct ssow_lf_alloc_req {
	struct mbox_msghdr hdr;
	int node;
	u16 hws;
};

struct ssow_lf_free_req {
	struct mbox_msghdr hdr;
	int node;
	u16 hws;
};

struct sso_hw_setconfig {
	struct mbox_msghdr hdr;
	u32	npa_aura_id;
	u16	npa_pf_func;
	u16	hwgrps;
};

struct sso_info_req {
	struct mbox_msghdr hdr;
	union {
		u16 grp;
		u16 hws;
	};
};

struct sso_grp_priority {
	struct mbox_msghdr hdr;
	u16 grp;
	u8 priority;
	u8 affinity;
	u8 weight;
};

struct sso_grp_qos_cfg {
	struct mbox_msghdr hdr;
	u16 grp;
	u32 xaq_limit;
	u16 taq_thr;
	u16 iaq_thr;
};

struct sso_grp_stats {
	struct mbox_msghdr hdr;
	u16 grp;
	u64 ws_pc;
	u64 ext_pc;
	u64 wa_pc;
	u64 ts_pc;
	u64 ds_pc;
	u64 dq_pc;
	u64 aw_status;
	u64 page_cnt;
};

struct sso_hws_stats {
	struct mbox_msghdr hdr;
	u16 hws;
	u64 arbitration;
};

/* NPC mbox message structs */

#define NPC_MCAM_ENTRY_INVALID	0xFFFF
#define NPC_MCAM_INVALID_MAP	0xFFFF

/* NPC mailbox error codes
 * Range 701 - 800.
 */
enum npc_af_status {
	NPC_MCAM_INVALID_REQ	= -701,
	NPC_MCAM_ALLOC_DENIED	= -702,
	NPC_MCAM_ALLOC_FAILED	= -703,
	NPC_MCAM_PERM_DENIED	= -704,
	NPC_AF_ERR_HIGIG_CONFIG_FAIL	= -705,
};

struct npc_mcam_alloc_entry_req {
	struct mbox_msghdr hdr;
#define NPC_MAX_NONCONTIG_ENTRIES	256
	u8  contig;   /* Contiguous entries ? */
#define NPC_MCAM_ANY_PRIO		0
#define NPC_MCAM_LOWER_PRIO		1
#define NPC_MCAM_HIGHER_PRIO		2
	u8  priority; /* Lower or higher w.r.t ref_entry */
	u16 ref_entry;
	u16 count;    /* Number of entries requested */
};

struct npc_mcam_alloc_entry_rsp {
	struct mbox_msghdr hdr;
	u16 entry; /* Entry allocated or start index if contiguous.
		    * Invalid incase of non-contiguous.
		    */
	u16 count; /* Number of entries allocated */
	u16 free_count; /* Number of entries available */
	u16 entry_list[NPC_MAX_NONCONTIG_ENTRIES];
};

struct npc_mcam_free_entry_req {
	struct mbox_msghdr hdr;
	u16 entry; /* Entry index to be freed */
	u8  all;   /* If all entries allocated to this PFVF to be freed */
};

struct mcam_entry {
#define NPC_MAX_KWS_IN_KEY	7 /* Number of keywords in max keywidth */
	u64	kw[NPC_MAX_KWS_IN_KEY];
	u64	kw_mask[NPC_MAX_KWS_IN_KEY];
	u64	action;
	u64	vtag_action;
};

struct npc_mcam_write_entry_req {
	struct mbox_msghdr hdr;
	struct mcam_entry entry_data;
	u16 entry;	 /* MCAM entry to write this match key */
	u16 cntr;	 /* Counter for this MCAM entry */
	u8  intf;	 /* Rx or Tx interface */
	u8  enable_entry;/* Enable this MCAM entry ? */
	u8  set_cntr;    /* Set counter for this entry ? */
};

/* Enable/Disable a given entry */
struct npc_mcam_ena_dis_entry_req {
	struct mbox_msghdr hdr;
	u16 entry;
};

struct npc_mcam_shift_entry_req {
	struct mbox_msghdr hdr;
#define NPC_MCAM_MAX_SHIFTS	64
	u16 curr_entry[NPC_MCAM_MAX_SHIFTS];
	u16 new_entry[NPC_MCAM_MAX_SHIFTS];
	u16 shift_count; /* Number of entries to shift */
};

struct npc_mcam_shift_entry_rsp {
	struct mbox_msghdr hdr;
	u16 failed_entry_idx; /* Index in 'curr_entry', not entry itself */
};

struct npc_mcam_alloc_counter_req {
	struct mbox_msghdr hdr;
	u8  contig;	/* Contiguous counters ? */
#define NPC_MAX_NONCONTIG_COUNTERS       64
	u16 count;	/* Number of counters requested */
};

struct npc_mcam_alloc_counter_rsp {
	struct mbox_msghdr hdr;
	u16 cntr;   /* Counter allocated or start index if contiguous.
		     * Invalid incase of non-contiguous.
		     */
	u16 count;  /* Number of counters allocated */
	u16 cntr_list[NPC_MAX_NONCONTIG_COUNTERS];
};

struct npc_mcam_oper_counter_req {
	struct mbox_msghdr hdr;
	u16 cntr;   /* Free a counter or clear/fetch it's stats */
};

struct npc_mcam_oper_counter_rsp {
	struct mbox_msghdr hdr;
	u64 stat;  /* valid only while fetching counter's stats */
};

struct npc_mcam_unmap_counter_req {
	struct mbox_msghdr hdr;
	u16 cntr;
	u16 entry; /* Entry and counter to be unmapped */
	u8  all;   /* Unmap all entries using this counter ? */
};

struct npc_mcam_alloc_and_write_entry_req {
	struct mbox_msghdr hdr;
	struct mcam_entry entry_data;
	u16 ref_entry;
	u8  priority;    /* Lower or higher w.r.t ref_entry */
	u8  intf;	 /* Rx or Tx interface */
	u8  enable_entry;/* Enable this MCAM entry ? */
	u8  alloc_cntr;  /* Allocate counter and map ? */
};

struct npc_mcam_alloc_and_write_entry_rsp {
	struct mbox_msghdr hdr;
	u16 entry;
	u16 cntr;
};

struct npc_get_kex_cfg_rsp {
	struct mbox_msghdr hdr;
	u64 rx_keyx_cfg;   /* NPC_AF_INTF(0)_KEX_CFG */
	u64 tx_keyx_cfg;   /* NPC_AF_INTF(1)_KEX_CFG */
#define NPC_MAX_INTF	2
#define NPC_MAX_LID	8
#define NPC_MAX_LT	16
#define NPC_MAX_LD	2
#define NPC_MAX_LFL	16
	/* NPC_AF_KEX_LDATA(0..1)_FLAGS_CFG */
	u64 kex_ld_flags[NPC_MAX_LD];
	/* NPC_AF_INTF(0..1)_LID(0..7)_LT(0..15)_LD(0..1)_CFG */
	u64 intf_lid_lt_ld[NPC_MAX_INTF][NPC_MAX_LID][NPC_MAX_LT][NPC_MAX_LD];
	/* NPC_AF_INTF(0..1)_LDATA(0..1)_FLAGS(0..15)_CFG */
	u64 intf_ld_flags[NPC_MAX_INTF][NPC_MAX_LD][NPC_MAX_LFL];
#define MKEX_NAME_LEN 128
	u8 mkex_pfl_name[MKEX_NAME_LEN];
};

enum header_fields {
	NPC_DMAC,
	NPC_SMAC,
	NPC_ETYPE,
	NPC_OUTER_VID,
	NPC_TOS,
	NPC_SIP_IPV4,
	NPC_DIP_IPV4,
	NPC_SIP_IPV6,
	NPC_DIP_IPV6,
	NPC_SPORT_TCP,
	NPC_DPORT_TCP,
	NPC_SPORT_UDP,
	NPC_DPORT_UDP,
	NPC_FDSA_VAL,
	NPC_HEADER_FIELDS_MAX,
};

struct flow_msg {
	unsigned char dmac[6];
	unsigned char smac[6];
	__be16 etype;
	__be16 vlan_etype;
	__be16 vlan_tci;
	union {
		__be32 ip4src;
		__be32 ip6src[4];
	};
	union {
		__be32 ip4dst;
		__be32 ip6dst[4];
	};
	u8 tos;
	u8 ip_ver;
	u8 ip_proto;
	u8 tc;
	__be16 sport;
	__be16 dport;
};

struct npc_install_flow_req {
	struct mbox_msghdr hdr;
	struct flow_msg packet;
	struct flow_msg mask;
	u64 features;
	u16 entry;
	u16 channel;
	u8 intf;
	u8 set_cntr; /* If counter is available set counter for this entry ? */
	u8 default_rule;
	u8 append; /* overwrite(0) or append(1) flow to default rule? */
	u16 vf;
	/* action */
	u32 index;
	u16 match_id;
	u8 flow_key_alg;
	u8 op;
	/* vtag rx action */
	u8 vtag0_type;
	u8 vtag0_valid;
	u8 vtag1_type;
	u8 vtag1_valid;
	/* vtag tx action */
	u16 vtag0_def;
	u8  vtag0_op;
	u16 vtag1_def;
	u8  vtag1_op;
};

struct npc_install_flow_rsp {
	struct mbox_msghdr hdr;
	int counter; /* negative if no counter else counter number */
};

struct npc_delete_flow_req {
	struct mbox_msghdr hdr;
	u16 entry;
	u16 start;/*Disable range of entries */
	u16 end;
	u8 all; /* PF + VFs */
};

struct npc_mcam_read_entry_req {
	struct mbox_msghdr hdr;
	u16 entry;	 /* MCAM entry to read */
};

struct npc_mcam_read_entry_rsp {
	struct mbox_msghdr hdr;
	struct mcam_entry entry_data;
	u8 intf;
	u8 enable;
};

/* TIM mailbox error codes
 * Range 801 - 900.
 */
enum tim_af_status {
	TIM_AF_NO_RINGS_LEFT			= -801,
	TIM_AF_INVAL_NPA_PF_FUNC		= -802,
	TIM_AF_INVAL_SSO_PF_FUNC		= -803,
	TIM_AF_RING_STILL_RUNNING		= -804,
	TIM_AF_LF_INVALID			= -805,
	TIM_AF_CSIZE_NOT_ALIGNED		= -806,
	TIM_AF_CSIZE_TOO_SMALL			= -807,
	TIM_AF_CSIZE_TOO_BIG			= -808,
	TIM_AF_INTERVAL_TOO_SMALL		= -809,
	TIM_AF_INVALID_BIG_ENDIAN_VALUE		= -810,
	TIM_AF_INVALID_CLOCK_SOURCE		= -811,
	TIM_AF_GPIO_CLK_SRC_NOT_ENABLED		= -812,
	TIM_AF_INVALID_BSIZE			= -813,
	TIM_AF_INVALID_ENABLE_PERIODIC		= -814,
	TIM_AF_INVALID_ENABLE_DONTFREE		= -815,
	TIM_AF_ENA_DONTFRE_NSET_PERIODIC	= -816,
	TIM_AF_RING_ALREADY_DISABLED		= -817,
};

enum tim_clk_srcs {
	TIM_CLK_SRCS_TENNS	= 0,
	TIM_CLK_SRCS_GPIO	= 1,
	TIM_CLK_SRCS_GTI	= 2,
	TIM_CLK_SRCS_PTP	= 3,
	TIM_CLK_SRSC_INVALID,
};

enum tim_gpio_edge {
	TIM_GPIO_NO_EDGE		= 0,
	TIM_GPIO_LTOH_TRANS		= 1,
	TIM_GPIO_HTOL_TRANS		= 2,
	TIM_GPIO_BOTH_TRANS		= 3,
	TIM_GPIO_INVALID,
};

struct tim_lf_alloc_req {
	struct mbox_msghdr hdr;
	u16	ring;
	u16	npa_pf_func;
	u16	sso_pf_func;
};

struct tim_ring_req {
	struct mbox_msghdr hdr;
	u16	ring;
};

struct tim_config_req {
	struct mbox_msghdr hdr;
	u16	ring;
	u8	bigendian;
	u8	clocksource;
	u8	enableperiodic;
	u8	enabledontfreebuffer;
	u32	bucketsize;
	u32	chunksize;
	u32	interval;
	u8	gpioedge;
};

struct tim_lf_alloc_rsp {
	struct mbox_msghdr hdr;
	u64 tenns_clk;
};

struct tim_enable_rsp {
	struct mbox_msghdr hdr;
	u64	timestarted;
	u32	currentbucket;
};

enum ptp_op {
	PTP_OP_ADJFINE = 0, /* adjfine(req.scaled_ppm); */
	PTP_OP_GET_CLOCK = 1, /* rsp.clk = get_clock() */
};

struct ptp_req {
	struct mbox_msghdr hdr;
	u8 op;
	s64 scaled_ppm;
	u8 is_pmu;
};

struct ptp_rsp {
	struct mbox_msghdr hdr;
	u64 clk;
	u64 tsc;
};

struct get_hw_cap_rsp {
	struct mbox_msghdr hdr;
	u8 nix_fixed_txschq_mapping; /* Schq mapping fixed or flexible */
	u8 nix_shaping;		     /* Is shaping and coloring supported */
};

struct ndc_sync_op {
	struct mbox_msghdr hdr;
	u8 nix_lf_tx_sync;
	u8 nix_lf_rx_sync;
	u8 npa_lf_sync;
};

/* CPT mailbox error codes
 * Range 901 - 1000.
 */
enum cpt_af_status {
	CPT_AF_ERR_PARAM		= -901,
	CPT_AF_ERR_GRP_INVALID		= -902,
	CPT_AF_ERR_LF_INVALID		= -903,
	CPT_AF_ERR_ACCESS_DENIED	= -904,
	CPT_AF_ERR_SSO_PF_FUNC_INVALID	= -905,
	CPT_AF_ERR_NIX_PF_FUNC_INVALID	= -906,
	CPT_AF_ERR_INLINE_IPSEC_INB_ENA	= -907,
	CPT_AF_ERR_INLINE_IPSEC_OUT_ENA	= -908
};

/* CPT mbox message formats */

struct cpt_rd_wr_reg_msg {
	struct mbox_msghdr hdr;
	u64 reg_offset;
	u64 *ret_val;
	u64 val;
	u8 is_write;
	u8 blkaddr; /* BLKADDR_CPT0/BLKADDR_CPT1 or 0 for BLKADDR_CPT0 */
};

struct cpt_lf_alloc_req_msg {
	struct mbox_msghdr hdr;
	u16 nix_pf_func;
	u16 sso_pf_func;
	u16 eng_grpmsk;
	u8 blkaddr; /* BLKADDR_CPT0/BLKADDR_CPT1 or 0 for BLKADDR_CPT0 */
};

#define CPT_INLINE_INBOUND      0
#define CPT_INLINE_OUTBOUND     1
struct cpt_inline_ipsec_cfg_msg {
	struct mbox_msghdr hdr;
	u8 enable;
	u8 slot;
	u8 dir;
	u8 sso_pf_func_ovrd;
	u16 sso_pf_func; /* inbound path SSO_PF_FUNC */
	u16 nix_pf_func; /* outbound path NIX_PF_FUNC */
};

/* REE mailbox error codes
 * Range 1001 - 1100.
 */
enum ree_af_status {
	REE_AF_ERR_RULE_UNKNOWN_VALUE		= -1001,
	REE_AF_ERR_LF_NO_MORE_RESOURCES		= -1002,
	REE_AF_ERR_LF_INVALID			= -1003,
	REE_AF_ERR_ACCESS_DENIED		= -1004,
	REE_AF_ERR_RULE_DB_PARTIAL		= -1005,
	REE_AF_ERR_RULE_DB_EQ_BAD_VALUE		= -1006,
	REE_AF_ERR_RULE_DB_BLOCK_ALLOC_FAILED	= -1007,
	REE_AF_ERR_BLOCK_NOT_IMPLEMENTED	= -1008,
	REE_AF_ERR_RULE_DB_INC_OFFSET_TOO_BIG	= -1009,
	REE_AF_ERR_RULE_DB_OFFSET_TOO_BIG	= -1010,
	REE_AF_ERR_Q_IS_GRACEFUL_DIS		= -1011,
	REE_AF_ERR_Q_NOT_GRACEFUL_DIS		= -1012,
	REE_AF_ERR_RULE_DB_ALLOC_FAILED		= -1013,
	REE_AF_ERR_RULE_DB_TOO_BIG		= -1014,
	REE_AF_ERR_RULE_DB_GEQ_BAD_VALUE	= -1015,
	REE_AF_ERR_RULE_DB_LEQ_BAD_VALUE	= -1016,
	REE_AF_ERR_RULE_DB_WRONG_LENGTH		= -1017,
	REE_AF_ERR_RULE_DB_WRONG_OFFSET		= -1018,
	REE_AF_ERR_RULE_DB_BLOCK_TOO_BIG	= -1019,
	REE_AF_ERR_RULE_DB_SHOULD_FILL_REQUEST	= -1020,
	REE_AF_ERR_RULE_DBI_ALLOC_FAILED	= -1021,
	REE_AF_ERR_LF_WRONG_PRIORITY		= -1022,
	REE_AF_ERR_LF_SIZE_TOO_BIG		= -1023,
};

/* REE mbox message formats */

struct ree_req_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
};

struct ree_lf_req_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
	u32 size;
	u8 lf;
	u8 pri;
};

struct ree_rule_db_prog_req_msg {
	struct mbox_msghdr	hdr;
/* Rule DB passed in MBOX and is copied to internal REE DB
 * This size should be power of 2 to fit into rule DB internal blocks
 */
#define REE_RULE_DB_REQ_BLOCK_SIZE (MBOX_SIZE >> 1)
	u8 rule_db[REE_RULE_DB_REQ_BLOCK_SIZE];
	u32 blkaddr;		/* REE0 or REE1 */
	u32 total_len;		/* Total len of rule db */
	u32 offset;		/* Offset of current rule db block */
	u16 len;		/* Length of rule db block */
	u8 is_last;		/* Is this the last block */
	u8 is_incremental;	/* Is incremental flow */
	u8 is_dbi;		/* Is rule db incremental */
};

struct ree_rule_db_get_req_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
	u32 offset;	/* Retrieve db from this offset */
	u8 is_dbi;	/* Is request for rule db incremental */
};

struct ree_rd_wr_reg_msg {
	struct mbox_msghdr hdr;
	u64 reg_offset;
	u64 *ret_val;
	u64 val;
	u32 blkaddr;
	u8 is_write;
};

struct ree_rule_db_len_rsp_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
	u32 len;
	u32 inc_len;
};

struct ree_rule_db_get_rsp_msg {
	struct mbox_msghdr hdr;
#define REE_RULE_DB_RSP_BLOCK_SIZE (MBOX_DOWN_TX_SIZE - SZ_1K)
	u8 rule_db[REE_RULE_DB_RSP_BLOCK_SIZE];
	u32 total_len;		/* Total len of rule db */
	u32 offset;		/* Offset of current rule db block */
	u16 len;		/* Length of rule db block */
	u8 is_last;		/* Is this the last block */
};

#endif /* MBOX_H */
