/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF CPLT RPM extension
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef __RVU_CPLT_MBOX_H__
#define __RVU_CPLT_MBOX_H__

#include "rvu.h"
#include "mbox.h"

/* CPLT mailbox error codes
 * Range 1301 - 1400.
 */
enum cplt_af_status {
	CPLT_AF_ERR_PARAM			= -1301,
	CPLT_AF_ERR_ACCESS_DENIED		= -1302,
};

/* CPLT MBOX IDs (range 0xD000 to 0xDFFF) */
#define MBOX_EBLOCK_CPLT_MESSAGES					\
M(CPLT_RPM_PORT_READY,		0xd000, cplt_rpm_port_ready,		\
					cplt_rpm_port_ready_req,	\
					msg_rsp)			\
M(CPLT_RPM_LINK_EVENT,		0xd001, cplt_rpm_link_event,		\
					cplt_rpm_link_event_req,	\
					msg_rsp)			\
M(CPLT_RPM_PTP_RX_INFO,		0xd002, cplt_rpm_ptp_rx_info,		\
					cplt_rpm_ptp_rx_info_req,	\
					msg_rsp)			\
M(CPLT_RPM_PTP_RX_EN,		0xd003, cplt_ptp_rx_enable,		\
					msg_req, msg_rsp)		\
M(CPLT_RPM_GET_CHAN_INFO,	0xd004, cplt_rpm_get_chan_info,		\
					cplt_rpm_get_chan_info_req,	\
					cplt_rpm_get_chan_info_rsp)	\
M(CPLT_RPM_EB_READY,		0xd005, cplt_rpm_eb_ready,		\
					cplt_rpm_eb_ready_req, msg_rsp)	\

#define MBOX_EBLOCK_UP_CPLT_MESSAGES					\
M(CPLT_RPM_PTP_EN,		0x0EF8, cplt_rpm_ptp_en,		\
					cplt_rpm_ptp_en_req, msg_rsp)

struct cplt_rpm_port_ready_req {
	struct mbox_msghdr hdr;
	u8 num_bphy_chiplets;
	u32 valid_interface_bitmap;
};

enum port_link_state {
	LINK_STATE_DOWN = 0,
	LINK_STATE_UP,
};

struct cplt_link_user_info {
	uint64_t link_up:1;
	uint64_t full_duplex:1;
	uint64_t lmac_type_id:4;
	uint64_t speed:20; /* speed in Mbps */
	uint64_t an:1;	   /* AN supported or not */
	uint64_t fec:2;    /* FEC type if enabled else 0 */
#define LMACTYPE_STR_LEN 16
	char lmac_type[LMACTYPE_STR_LEN];
};

struct cplt_link_event {
	struct cplt_link_user_info link_uinfo;
	u8 chiplet_id;
	u8 rpm_id;
	u8 lmac_id;
};

struct cplt_evq_entry {
	struct list_head evq_node;
	struct cplt_link_event link_event;
};

struct cplt_rpm_link_event_req {
	struct mbox_msghdr hdr;
	u8 chiplet_id;
	u8 rpm_id;
	u8 lmac_id;
	struct cplt_link_user_info link_info;
};

struct cplt_rpm_ptp_rx_info_req {
	struct mbox_msghdr hdr;
	u8 chiplet_id;
	u8 rpm_id;
	u8 lmac_id;
	u8 ptp_en;
};

struct cplt_rpm_ptp_en_req {
	struct mbox_msghdr hdr;
	u8 chiplet_id;
	u8 rpm_id;
	u8 lmac_id;
	u8 ptp_en;
};

struct cplt_rpm_get_chan_info_req {
	struct mbox_msghdr hdr;
	u8 chiplet_id;
	u8 rpm_id;
	u8 lmac_id;
};

struct cplt_rpm_get_chan_info_rsp {
	struct mbox_msghdr hdr;
	u8 chiplet_id;
	u8 rpm_id;
	u8 lmac_id;
	u16 chan_base;
	u16 pkind;
};

struct cplt_rpm_eb_ready_req {
	struct mbox_msghdr hdr;
};

enum {
#define M(_name, _id, _1, _2, _3) MBOX_MSG_ ## _name = _id,
	MBOX_EBLOCK_CPLT_MESSAGES
#undef M
};

#define M(_name, _id, fn_name, req, rsp)				\
int rvu_mbox_handler_ ## fn_name(struct rvu *, struct req *, struct rsp *);
MBOX_EBLOCK_CPLT_MESSAGES
#undef M

#endif /* __RVU_CPLT_MBOX_H__ */
