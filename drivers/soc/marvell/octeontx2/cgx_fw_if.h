// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 CGX driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CGX_FW_INTF_H__
#define __CGX_FW_INTF_H__

#define CGX_FIRMWARE_MAJOR_VER		1
#define CGX_FIRMWARE_MINOR_VER		0

#define CGX_EVENT_ACK                   1UL

/* CGX error types. set for cmd response status as CGX_STAT_FAIL */
enum cgx_error_type {
	CGX_ERR_NONE,
	CGX_ERR_LMAC_NOT_ENABLED,
	CGX_ERR_LMAC_MODE_INVALID,
	CGX_ERR_REQUEST_ID_INVALID,
	CGX_ERR_PREV_ACK_NOT_CLEAR,
	CGX_ERR_PHY_LINK_DOWN,
	CGX_ERR_PCS_RESET_FAIL,
	CGX_ERR_AN_CPT_FAIL,
	CGX_ERR_TX_NOT_IDLE,
	CGX_ERR_RX_NOT_IDLE,
	CGX_ERR_SPUX_BR_BLKLOCK_FAIL,
	CGX_ERR_SPUX_RX_ALIGN_FAIL,
	CGX_ERR_SPUX_TX_FAULT,
	CGX_ERR_SPUX_RX_FAULT,
	CGX_ERR_SPUX_RESET_FAIL,
	CGX_ERR_SMUX_RX_LINK_NOT_OK,
	CGX_ERR_PCS_RECV_LINK_FAIL,
	CGX_ERR_TRAINING_FAIL,
	CGX_ERR_RX_EQU_FAIL,		/* = 18 */
	/* FIXME : add more error types when adding support for new modes */
};

/* LINK speed types */
enum cgx_link_speed {
	CGX_LINK_NONE,
	CGX_LINK_10M,
	CGX_LINK_100M,
	CGX_LINK_1G,
	CGX_LINK_10G,
	CGX_LINK_25G,
	CGX_LINK_40G,
	CGX_LINK_50G,
	CGX_LINK_100G,
	CGX_LINK_SPEED_MAX,
};

/* REQUEST ID types. Input to firmware */
enum cgx_cmd_id {
	CGX_CMD_NONE,
	CGX_CMD_GET_FW_VER,
	CGX_CMD_GET_MAC_ADDR,
	CGX_CMD_SET_MTU,
	CGX_CMD_GET_LINK_STS,		/* optional to user */
	CGX_CMD_LINK_BRING_UP,
	CGX_CMD_LINK_BRING_DOWN,
	CGX_CMD_INTERNAL_LBK,
	CGX_CMD_EXTERNAL_LBK,
	CGX_CMD_HIGIG,
	CGX_CMD_LINK_STATE_CHANGE,
	CGX_CMD_MODE_CHANGE,		/* hot plug support */
	CGX_CMD_INTF_SHUTDOWN,
	CGX_CMD_IRQ_ENABLE,
	CGX_CMD_IRQ_DISABLE,
};

/* async event ids */
enum cgx_evt_id {
	CGX_EVT_NONE,
	CGX_EVT_LINK_CHANGE,
};

/* event types - cause of interrupt */
enum cgx_evt_type {
	CGX_EVT_ASYNC,
	CGX_EVT_CMD_RESP
};

enum cgx_stat {
	CGX_STAT_SUCCESS,
	CGX_STAT_FAIL
};

enum cgx_cmd_own {
	/* set by kernel/uefi/u-boot after posting a new request to ATF */
	/* set by firmware */
	CGX_CMD_OWN_NS,
	CGX_CMD_OWN_FIRMWARE,
};

/* scratchx(0) CSR used for ATF->non-secure SW communication.
 * This acts as the status register
 * Provides details on command ack/status, link status, error details
 */

/* CAUTION : below structures are placed in order based on the bit positions
 * For any updates/new bitfields, corresponding structures needs to be updated
 */
struct cgx_evt_sts {			/* start from bit 0 */
	uint64_t ack:1;
	uint64_t evt_type:1;		/* cgx_evt_type */
	uint64_t stat:1;		/* cgx_stat */
	uint64_t id:6;			/* cgx_evt_id/cgx_cmd_id */
	uint64_t reserved:55;
};

/* all the below structures are in the same memory location of SCRATCHX(0)
 * value can be read/written based on command ID
 */

/* Resp to command IDs with command status as CGX_STAT_FAIL
 *
 * Not applicable for commands :
 * CGX_CMD_LINK_BRING_UP/DOWN/CGX_EVT_LINK_CHANGE
 * check struct cgx_lnk_sts comments
 */
struct cgx_err_sts_s {			/* start from bit 9 */
	uint64_t reserved1:9;
	uint64_t type:10;		/* cgx_error_type */
	uint64_t reserved2:35;
};

/* Resp to cmd ID as CGX_CMD_GET_FW_VER with cmd status as CGX_STAT_SUCCESS */
struct cgx_ver_s {			/* start from bit 9 */
	uint64_t reserved1:9;
	uint64_t major_ver:4;
	uint64_t minor_ver:4;
	uint64_t reserved2:47;
};

/* Resp to cmd ID as CGX_CMD_GET_MAC_ADDR with cmd status as CGX_STAT_SUCCESS */
struct cgx_mac_addr_s {			/* start from bit 9 */
	uint64_t reserved1:9;
	uint64_t local_mac_addr:48;
	uint64_t reserved2:7;
};

/* Resp to cmd ID - CGX_CMD_LINK_BRING_UP/DOWN, event ID CGX_EVT_LINK_CHANGE
 * status can be either CGX_STAT_FAIL or CGX_STAT_SUCCESS
 * In case of CGX_STAT_FAIL, it indicates CGX configuration failed
 * when processing link up/down/change command.
 * Both err_type and current link status will be updated
 * In case of CGX_STAT_SUCCESS, err_type will be CGX_ERR_NONE and current
 * link status will be updated
 */
struct cgx_lnk_sts {
	uint64_t reserved1:9;
	uint64_t link_up:1;
	uint64_t full_duplex:1;
	uint64_t speed:4;		/* cgx_link_speed */
	uint64_t err_type:10;
	uint64_t reserved2:39;
};

union cgx_evtreg {
	u64 val;
	struct cgx_evt_sts evt_sts; /* common for all commands/events */
	struct cgx_lnk_sts link_sts; /* response to LINK_BRINGUP/DOWN/CHANGE */
	struct cgx_ver_s ver;		/* response to CGX_CMD_GET_FW_VER */
	struct cgx_mac_addr_s mac_addr;	/* response to CGX_CMD_GET_MAC_ADDR */
	struct cgx_err_sts_s err;	/* response if evt_status = CMD_FAIL */
};

/* scratchx(1) CSR used for non-secure SW->ATF communication
 * This CSR acts as a command register
 */
struct cgx_cmd {			/* start from bit 2 */
	uint64_t own:2;			/* cgx_csr_own */
	uint64_t id:6;			/* cgx_request_id */
	uint64_t reserved2:56;
};

/* all the below structures are in the same memory location of SCRATCHX(1)
 * corresponding arguments for command Id needs to be updated
 */

/* Any command using enable/disable as an argument need
 * to pass the option via this structure.
 * Ex: Loopback, HiGig...
 */
struct cgx_ctl_args {			/* start from bit 8 */
	uint64_t reserved1:8;
	uint64_t enable:1;
	uint64_t reserved2:55;
};

/* command argument to be passed for cmd ID - CGX_CMD_SET_MTU */
struct cgx_mtu_args {
	uint64_t reserved1:8;
	uint64_t size:16;
	uint64_t reserved2:40;
};

/* command argument to be passed for cmd ID - CGX_CMD_LINK_CHANGE */
struct cgx_link_change_args {		/* start from bit 8 */
	uint64_t reserved1:8;
	uint64_t link_up:1;
	uint64_t full_duplex:1;
	uint64_t speed:4;		/* cgx_link_speed */
	uint64_t reserved2:50;
};

struct cgx_irq_cfg {
	uint64_t reserved1:8;
	uint64_t irq_phys:32;
	uint64_t reserved2:24;
};

union cgx_cmdreg {
	u64 val;
	struct cgx_cmd cmd;
	struct cgx_ctl_args cmd_args;
	struct cgx_mtu_args mtu_size;
	struct cgx_irq_cfg irq_cfg; /* Input to CGX_CMD_IRQ_ENABLE */
	struct cgx_link_change_args lnk_args;/* Input to CGX_CMD_LINK_CHANGE */
	/* any other arg for command id * like : mtu, dmac filtering control */
};

#endif /* __CGX_FW_INTF_H__ */
