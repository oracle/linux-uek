/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_HW_DATA_H
#define	_PSIF_HW_DATA_H


#include "psif_api.h"

#define psif_port_flags psif_event
#define string_enum_psif_port_flags(data) string_enum_psif_event((enum psif_event)data)
#include "psif_endian.h"

/* Extent of all psif enums */
enum psif_enum_extent {
	PSIF_MMU_TRANSLATION_EXTENT	 = 0x8u,
	PSIF_PAGE_SIZE_EXTENT	 = 0xfu,
	PSIF_WR_TYPE_EXTENT	 = 0x8fu,
	PSIF_PORT_EXTENT	 = 0x2u,
	PSIF_USE_AH_EXTENT	 = 0x2u,
	PSIF_TSU_QOS_EXTENT	 = 0x2u,
	PSIF_WC_OPCODE_EXTENT	 = 0x83u,
	PSIF_WC_STATUS_EXTENT	 = 0x16u,
	PSIF_TSL_QP_WR_EXTENT	 = 0x10u,
	PSIF_TABLE_LEVEL_EXTENT	 = 0x6u,
	PSIF_RB_TYPE_EXTENT	 = 0x7u,
	PSIF_EPS_A_CORE_EXTENT	 = 0x4u,
	PSIF_QP_STATE_EXTENT	 = 0x8u,
	PSIF_CMPL_OUTSTANDING_ERROR_EXTENT	 = 0xau,
	PSIF_EXPECTED_OP_EXTENT	 = 0x4u,
	PSIF_MIGRATION_EXTENT	 = 0x4u,
	PSIF_QP_TRANS_EXTENT	 = 0x8u,
	PSIF_BOOL_EXTENT	 = 0x2u,
	PSIF_EOIB_TYPE_EXTENT	 = 0x4u,
	PSIF_COMM_LIVE_EXTENT	 = 0x2u,
	PSIF_PATH_MTU_EXTENT	 = 0x8u,
	PSIF_USE_GRH_EXTENT	 = 0x2u,
	PSIF_LOOPBACK_EXTENT	 = 0x2u,
	PSIF_QP_COMMAND_EXTENT	 = 0x4u,
	PSIF_SIBS_MBOX_TYPE_EXTENT	 = 0x2u,
	PSIF_MBOX_TYPE_EXTENT	 = 0x6u,
	PSIF_DMA_VT_KEY_STATES_EXTENT	 = 0x4u,
	PSIF_EVENT_EXTENT	 = 0x13u,
	PSIF_TSU_ERROR_TYPES_EXTENT	 = 0x8cu,
	PSIF_EPS_CORE_ID_EXTENT	 = 0x5u,
	PSIF_EPSC_QUERY_PERSISTENT_EXTENT	 = 0x3u,
	PSIF_PORT_SPEED_EXTENT	 = 0x21u,
	PSIF_EPSC_PORT_STATE_EXTENT	 = 0x6u,
	PSIF_EPSC_PATH_MTU_EXTENT	 = 0x8u,
	PSIF_EPSC_LOG_MODE_EXTENT	 = 0x11u,
	PSIF_EPSC_LOG_LEVEL_EXTENT	 = 0x8u,
	PSIF_EPSC_DEGRADE_CAUSE_EXTENT	 = 0x7u,
	PSIF_EPSC_ATOMIC_CAP_EXTENT	 = 0x3u,
	PSIF_EPSC_CSR_STATUS_EXTENT	 = 0x100u,
	PSIF_EPSC_CSR_OPCODE_EXTENT	 = 0x50u,
	PSIF_EPSC_CSR_FLAGS_EXTENT	 = 0x5u,
	PSIF_VLINK_STATE_EXTENT	 = 0x11u,
	PSIF_EPSC_CSR_MODIFY_DEVICE_FLAGS_EXTENT	 = 0x3u,
	PSIF_EPSC_CSR_MODIFY_PORT_FLAGS_EXTENT	 = 0x11u,
	PSIF_EPSC_CSR_EPSA_COMMAND_EXTENT	 = 0x4u,
	PSIF_EPSA_COMMAND_EXTENT	 = 0xcu,
	PSIF_EPSC_QUERY_OP_EXTENT	 = 0x56u,
	PSIF_EPSC_CSR_UPDATE_OPCODE_EXTENT	 = 0x8u,
	PSIF_EPSC_FLASH_SLOT_EXTENT	 = 0x6u,
	PSIF_EPSC_UPDATE_SET_EXTENT	 = 0x5u,
	PSIF_EPSC_CSR_UF_CTRL_OPCODE_EXTENT	 = 0xbu,
	PSIF_EPSC_VIMMA_CTRL_OPCODE_EXTENT	 = 0x8u,
	PSIF_EPSC_VIMMA_ADMMODE_EXTENT	 = 0x2u,
	PSIF_EPSC_CSR_PMA_COUNTERS_ENUM_EXTENT	 = 0x17u,
	PSIF_EPSC_CSR_ATOMIC_OP_EXTENT	 = 0x4u,
	PSIF_CQ_STATE_EXTENT	 = 0x4u,
	PSIF_RSS_HASH_SOURCE_EXTENT	 = 0x2u
}; /* enum psif_enum_extent [16 bits] */

/* MMU operation modes. */
enum psif_mmu_translation {
	MMU_PASS_THROUGH0	 = 0u,
	MMU_PASS_THROUGH_PAD,
	MMU_GVA2GPA_MODE,
	MMU_GVA2GPA_MODE_PAD,
	MMU_PRETRANSLATED,
	MMU_PRETRANSLATED_PAD,
	MMU_EPSA_MODE,
	MMU_EPSC_MODE
}; /* enum psif_mmu_translation [ 3 bits] */

/*
 * Enumeration for the different supported page sizes. XXX: Define the page
 * sizes
 */
enum psif_page_size {
	PAGE_SIZE_IA32E_4KB	 = 0u,
	PAGE_SIZE_IA32E_2MB	 = 0x1u,
	PAGE_SIZE_IA32E_1GB	 = 0x2u,
	PAGE_SIZE_S64_8KB	 = 0x8u,
	PAGE_SIZE_S64_64KB	 = 0x9u,
	PAGE_SIZE_S64_512KB	 = 0xau,
	PAGE_SIZE_S64_4MB	 = 0xbu,
	PAGE_SIZE_S64_32MB	 = 0xcu,
	PAGE_SIZE_S64_2GB	 = 0xdu,
	PAGE_SIZE_S64_16GB	 = 0xeu
}; /* enum psif_page_size [ 4 bits] */

/*
 * These are the different work request opcodes supported by PSIF.
 * PSIF_WR_ENTER_SQ_MODE and PSIF_WR_CANCEL_CMD are special opcodes only used
 * when writing to a special offset of the VCBs. RQS must check that the
 * PSIF_WR_SEND_EPS and PSIF_WR_SEND_EPS_DR really comes from the EPS. CBU
 * must report the source of a WR to RQS.
 */
enum psif_wr_type {
	PSIF_WR_SEND	 = 0u,
	PSIF_WR_SEND_IMM,
	PSIF_WR_SPECIAL_QP_SEND,
	PSIF_WR_QP0_SEND_DR_XMIT,
	PSIF_WR_QP0_SEND_DR_LOOPBACK,
	PSIF_WR_EPS_SPECIAL_QP_SEND,
	PSIF_WR_EPS_QP0_SEND_DR_XMIT,
	PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK,
	PSIF_WR_RDMA_WR,
	PSIF_WR_RDMA_WR_IMM,
	PSIF_WR_RDMA_RD,
	PSIF_WR_CMP_SWAP,
	PSIF_WR_FETCH_ADD,
	PSIF_WR_MASK_CMP_SWAP,
	PSIF_WR_MASK_FETCH_ADD,
	PSIF_WR_LSO,
	PSIF_WR_INVALIDATE_RKEY	 = 0x80u,
	PSIF_WR_INVALIDATE_LKEY,
	PSIF_WR_INVALIDATE_BOTH_KEYS,
	PSIF_WR_INVALIDATE_TLB,
	PSIF_WR_RESIZE_CQ,
	PSIF_WR_SET_SRQ_LIM,
	PSIF_WR_SET_XRCSRQ_LIM,
	PSIF_WR_REQ_CMPL_NOTIFY,
	PSIF_WR_CMPL_NOTIFY_RCVD,
	PSIF_WR_REARM_CMPL_EVENT,
	PSIF_WR_GENERATE_COMPLETION,
	PSIF_WR_INVALIDATE_RQ,
	PSIF_WR_INVALIDATE_CQ,
	PSIF_WR_INVALIDATE_XRCSRQ,
	PSIF_WR_INVALIDATE_SGL_CACHE
}; /* enum psif_wr_type [ 8 bits] */

/* Port number the IB packet is transimitted on. */
enum psif_port {
	PORT_1	 = 0u,
	PORT_2	 = 0x1u
}; /* enum psif_port [ 1 bits] */

/*
 * Enumeration for using AHA or not. When set, AHA should be used instead of
 * information from the QP state in appropriate places.
 */
enum psif_use_ah {
	NO_AHA	 = 0u,
	USE_AHA	 = 0x1u
}; /* enum psif_use_ah [ 1 bits] */

/*
 * Indicating if this QP is configured as a high bandwidth or a low latency
 * QP.
 */
enum psif_tsu_qos {
	QOSL_HIGH_BANDWIDTH	 = 0u,
	QOSL_LOW_LATENCY	 = 0x1u
}; /* enum psif_tsu_qos [ 1 bits] */

/*
 * Completion entry opcode indicating what type of request this completion
 * entry is completed.
 */
enum psif_wc_opcode {
	PSIF_WC_OPCODE_SEND	 = 0u,
	PSIF_WC_OPCODE_RDMA_WR	 = 0x1u,
	PSIF_WC_OPCODE_RDMA_READ	 = 0x2u,
	PSIF_WC_OPCODE_CMP_SWAP	 = 0x3u,
	PSIF_WC_OPCODE_FETCH_ADD	 = 0x4u,
	PSIF_WC_OPCODE_LSO	 = 0x6u,
	PSIF_WC_OPCODE_MASKED_CMP_SWAP	 = 0x9u,
	PSIF_WC_OPCODE_MASKED_FETCH_ADD,
	PSIF_WC_OPCODE_INVALIDATE_RKEY	 = 0x40u,
	PSIF_WC_OPCODE_INVALIDATE_LKEY,
	PSIF_WC_OPCODE_INVALIDATE_BOTH_KEYS,
	PSIF_WC_OPCODE_INVALIDATE_TLB,
	PSIF_WC_OPCODE_RESIZE_CQ,
	PSIF_WC_OPCODE_SET_SRQ_LIM,
	PSIF_WC_OPCODE_SET_XRCSRQ_LIM,
	PSIF_WC_OPCODE_REQ_CMPL_NOTIFY,
	PSIF_WC_OPCODE_CMPL_NOTIFY_RCVD,
	PSIF_WC_OPCODE_REARM_CMPL_EVENT,
	PSIF_WC_OPCODE_GENERATE_COMPLETION,
	PSIF_WC_OPCODE_INVALIDATE_RQ,
	PSIF_WC_OPCODE_INVALIDATE_CQ,
	PSIF_WC_OPCODE_INVALIDATE_RB,
	PSIF_WC_OPCODE_INVALIDATE_XRCSRQ,
	PSIF_WC_OPCODE_INVALIDATE_SGL_CACHE,
	PSIF_WC_OPCODE_RECEIVE_SEND	 = 0x80u,
	PSIF_WC_OPCODE_RECEIVE_RDMA_WR_IMM,
	PSIF_WC_OPCODE_RECEIVE_CONDITIONAL_WR_IMM
}; /* enum psif_wc_opcode [ 8 bits] */

/* Completion status for this completion. */
enum psif_wc_status {
	PSIF_WC_STATUS_SUCCESS	 = 0u,
	PSIF_WC_STATUS_LOC_LEN_ERR,
	PSIF_WC_STATUS_LOC_QP_OP_ERR,
	PSIF_WC_STATUS_LOC_EEC_OP_ERR,
	PSIF_WC_STATUS_LOC_PROT_ERR,
	PSIF_WC_STATUS_WR_FLUSH_ERR,
	PSIF_WC_STATUS_MW_BIND_ERR,
	PSIF_WC_STATUS_BAD_RESP_ERR,
	PSIF_WC_STATUS_LOC_ACCESS_ERR,
	PSIF_WC_STATUS_REM_INV_REQ_ERR,
	PSIF_WC_STATUS_REM_ACCESS_ERR,
	PSIF_WC_STATUS_REM_OP_ERR,
	PSIF_WC_STATUS_RETRY_EXC_ERR,
	PSIF_WC_STATUS_RNR_RETRY_EXC_ERR,
	PSIF_WC_STATUS_LOC_RDD_VIOL_ERR,
	PSIF_WC_STATUS_REM_INV_RD_REQ_ERR,
	PSIF_WC_STATUS_REM_ABORT_ERR,
	PSIF_WC_STATUS_INV_EECN_ERR,
	PSIF_WC_STATUS_INV_EEC_STATE_ERR,
	PSIF_WC_STATUS_FATAL_ERR,
	PSIF_WC_STATUS_RESP_TIMEOUT_ERR,
	PSIF_WC_STATUS_GENERAL_ERR,
	/* Padding out to required bits allocated */
	PSIF_WC_STATUS_FIELD_MAX	 = 0xffu
}; /* enum psif_wc_status [ 8 bits] */

/* TSU Service level required in the QP and WR */
enum psif_tsl_qp_wr {
	/* Dataplane traffic separated in 4 TSLs */
	TSL_DATA	 = 0u,
	TSL_DATA_1,
	TSL_DATA_2,
	TSL_DATA_3,
	/* TSL for privelidge QP */
	TSL_PRIV	 = 0xeu,
	/* Strapped down TSL for testing */
	TSL_JUNK	 = 0xfu
}; /* enum psif_tsl_qp_wr [ 4 bits] */

/* MMU table level definition
 *  If page level is not applicable it should be set to  PAGE_LEVEL0
 *  Values beyond PAGE_LEVEL4 (5-7) are reserved by HW
 */
enum psif_table_level {
	/* */
	PAGE_LEVEL0	 = 0u,
	PAGE_LEVEL1,
	PAGE_LEVEL2,
	PAGE_LEVEL3,
	/* PAGE_LEVEL4 is SPARC only ? */
	PAGE_LEVEL4,
	PAGE_LEVEL_RESERVED
}; /* enum psif_table_level [ 3 bits] */

/*
 * This is a ring buffer type defining the type of transaction this
 * represents.
 */
enum psif_rb_type {
	PSIF_RB_TYPE_INVALID	 = 0u,
	PSIF_RB_TYPE_DM_PUT,
	PSIF_RB_TYPE_DM_GET_RESP,
	PSIF_RB_TYPE_RCV_PROXY_COMPLETION,
	PSIF_RB_TYPE_RCV_PROXY_COMPLETION_AND_DATA,
	PSIF_RB_TYPE_SEND_PROXY_COMPLETION,
	PSIF_RB_TYPE_SEND_COMPLETION
}; /* enum psif_rb_type [ 3 bits] */

/*
 * Core number for EPS-A.1 PSIF_EPS_A_1 PSIF_EPS_A_2 PSIF_EPS_A_3
 * PSIF_EPS_A_4
 */
enum psif_eps_a_core {
	PSIF_EPS_A_1	 = 0u,
	PSIF_EPS_A_2,
	PSIF_EPS_A_3,
	PSIF_EPS_A_4
}; /* enum psif_eps_a_core [ 2 bits] */

/* This is the state this QP is in. */
enum psif_qp_state {
	PSIF_QP_STATE_RESET	 = 0u,
	PSIF_QP_STATE_INIT	 = 0x1u,
	PSIF_QP_STATE_RTR	 = 0x2u,
	PSIF_QP_STATE_RTS	 = 0x3u,
	PSIF_QP_STATE_SQERR	 = 0x5u,
	PSIF_QP_STATE_ERROR	 = 0x6u,
	PSIF_QP_STATE_INVALID	 = 0x7u
}; /* enum psif_qp_state [ 3 bits] */

/*
 * CMPL_NO_ERROR CMPL_RQS_INVALID_REQUEST_ERR CMPL_RQS_QP_IN_WRONG_STATE_ERR
 * CMPL_RQS_MAX_OUTSTANDING_REACHED_ERR CMPL_RQS_REQUEST_FENCED_ERR
 * CMPL_RQS_CMD_FROM_EPS_ERR CMPL_DMA_SGL_RD_ERR CMPL_DMA_PYLD_RD_ERR
 * CMPL_DMA_SGL_LENGTH_ERR CMPL_DMA_LKEY_ERR
 */
enum psif_cmpl_outstanding_error {
	CMPL_NO_ERROR,
	CMPL_RQS_INVALID_REQUEST_ERR,
	CMPL_RQS_QP_IN_WRONG_STATE_ERR,
	CMPL_RQS_MAX_OUTSTANDING_REACHED_ERR,
	CMPL_RQS_REQUEST_FENCED_ERR,
	CMPL_RQS_CMD_FROM_EPS_ERR,
	CMPL_DMA_SGL_RD_ERR,
	CMPL_DMA_PYLD_RD_ERR,
	CMPL_DMA_SGL_LENGTH_ERR,
	CMPL_DMA_LKEY_ERR
}; /* enum psif_cmpl_outstanding_error [ 4 bits] */

/*
 * 2 bits (next_opcode) 0x0: No operation in progress 0x1: Expect SEND middle
 * or last 0x2: Expect RDMA_WR middle or last 0x3: Expect DM_PUT middle or
 * last
 */
enum psif_expected_op {
	NO_OPERATION_IN_PROGRESS	 = 0u,
	EXPECT_SEND_MIDDLE_LAST	 = 0x1u,
	EXPECT_RDMA_WR_MIDDLE_LAST	 = 0x2u,
	EXPECT_DM_PUT_MIDDLE_LAST	 = 0x3u
}; /* enum psif_expected_op [ 2 bits] */

/*
 * Migration state (migrated, re-arm and armed). XXX: Assign values to the
 * states.
 */
enum psif_migration {
	APM_OFF	 = 0u,
	APM_MIGRATED,
	APM_REARM,
	APM_ARMED
}; /* enum psif_migration [ 2 bits] */

/*
 * 3 bits (transport) 0x0: RC - Reliable connection. 0x1: UC - Unreliable
 * connection. 0x2: RD - Reliable datagram - not supported. 0x3: UD -
 * Unreliable datagram. 0x4: RSVD1 0x5: XRC - Extended reliable connection.
 * 0x6: MANSP1 - manufacturer specific opcodes. 0x7: MANSP2 - manufacturer
 * specific opcodes.
 */
enum psif_qp_trans {
	PSIF_QP_TRANSPORT_RC	 = 0u,
	PSIF_QP_TRANSPORT_UC	 = 0x1u,
	PSIF_QP_TRANSPORT_RD	 = 0x2u,
	PSIF_QP_TRANSPORT_UD	 = 0x3u,
	PSIF_QP_TRANSPORT_RSVD1	 = 0x4u,
	PSIF_QP_TRANSPORT_XRC	 = 0x5u,
	PSIF_QP_TRANSPORT_MANSP1	 = 0x6u,
	PSIF_QP_TRANSPORT_MANSP2	 = 0x7u
}; /* enum psif_qp_trans [ 3 bits] */


enum psif_bool {
	FALSE	 = 0u,
	TRUE	 = 0x1u
}; /* enum psif_bool [ 1 bits] */

/*
 * EoIB types enumerated type having these enumerations: EOIB_FULL,
 * EOIB_PARTIAL, EOIB_QKEY_ONLY, EOIB_NONE.
 */
enum psif_eoib_type {
	EOIB_FULL	 = 0u,
	EOIB_PARTIAL,
	EOIB_QKEY_ONLY,
	EOIB_NONE
}; /* enum psif_eoib_type [ 2 bits] */

/*
 * Communication established state. This gets set when a packet is received
 * error free when in RTR state.
 */
enum psif_comm_live {
	NO_COMM_ESTABLISHED	 = 0u,
	COMM_ESTABLISHED	 = 0x1u
}; /* enum psif_comm_live [ 1 bits] */

/* Definitions for the different supported MTU sizes. */
enum psif_path_mtu {
	MTU_INVALID	 = 0u,
	MTU_256B	 = 0x1u,
	MTU_512B	 = 0x2u,
	MTU_1024B	 = 0x3u,
	MTU_2048B	 = 0x4u,
	MTU_4096B	 = 0x5u,
	MTU_10240B	 = 0x6u,
	MTU_XXX	 = 0x7u
}; /* enum psif_path_mtu [ 3 bits] */

/* Enumeration for using GRH or not. When set GRH should be used. */
enum psif_use_grh {
	NO_GRH	 = 0u,
	USE_GRH	 = 0x1u
}; /* enum psif_use_grh [ 1 bits] */

/* Enumeration for loopback indication NO_LOOPBACK = 0 LOOPBACK = 1. */
enum psif_loopback {
	NO_LOOPBACK	 = 0u,
	LOOPBACK	 = 0x1u
}; /* enum psif_loopback [ 1 bits] */

/* Commands used for modify/query QP. */
enum psif_qp_command {
	QP_CMD_INVALID	 = 0u,
	QP_CMD_MODIFY	 = 0x1u,
	QP_CMD_QUERY	 = 0x2u,
	QP_CMD_CHECK_TIMEOUT	 = 0x3u
}; /* enum psif_qp_command [ 2 bits] */


enum psif_sibs_mbox_type {
	SIBS_MBOX_EPSC,
	SIBS_MBOX_EPS_MAX,
	/* Padding out to required bits allocated */
	PSIF_SIBS_MBOX_TYPE_FIELD_MAX	 = 0xffu
}; /* enum psif_sibs_mbox_type [ 8 bits] */


enum psif_mbox_type {
	MBOX_EPSA0,
	MBOX_EPSA1,
	MBOX_EPSA2,
	MBOX_EPSA3,
	MBOX_EPSC,
	MBOX_EPS_MAX,
	/* Padding out to required bits allocated */
	PSIF_MBOX_TYPE_FIELD_MAX	 = 0xffu
}; /* enum psif_mbox_type [ 8 bits] */

/*
 * DMA Validation Key states. The valid states are: PSIF_DMA_KEY_INVALID=0
 * PSIF_DMA_KEY_FREE = 1 PSIF_DMA_KEY_VALID = 2 PSIF_DMA_KEY_MMU_VALID
 */
enum psif_dma_vt_key_states {
	PSIF_DMA_KEY_INVALID	 = 0u,
	PSIF_DMA_KEY_FREE	 = 0x1u,
	PSIF_DMA_KEY_VALID	 = 0x2u,
	PSIF_DMA_KEY_MMU_VALID	 = 0x3u
}; /* enum psif_dma_vt_key_states [ 2 bits] */

/** \brief SW EQ event type
 *  \details
 *  Software events use `eq_entry::port_flags` for the event type. As this is
 *  limited to 4 bits the special value `PSIF_EVENT_EXTENSION` is used to
 *  indicate that the actual event type is to be found in
 *  `eq_entry::extension_type`. This is done for all enum values larger than
 *  4 bits.
 *
 * \par Width
 *      32 bit
 * \par Used in
 *      struct psif_eq_entry
 * \par Restrictions
 *      none (all UF)
 * \par Classification
 *      driver
 */
enum psif_event {
	/** Event without a reason... */
	PSIF_EVENT_NO_CHANGE	 = 0u,
	/** GID table have been updated */
	PSIF_EVENT_SGID_TABLE_CHANGED,
	/** PKEY table have been updated by the SM */
	PSIF_EVENT_PKEY_TABLE_CHANGED,
	/** SM lid have been updated by master SM */
	PSIF_EVENT_MASTER_SM_LID_CHANGED,
	/** The SMs SL have changed */
	PSIF_EVENT_MASTER_SM_SL_CHANGED,
	/** */
	PSIF_EVENT_SUBNET_TIMEOUT_CHANGED,
	/** */
	PSIF_EVENT_IS_SM_DISABLED_CHANGED,
	/** New master SM - client must reregister */
	PSIF_EVENT_CLIENT_REREGISTER,
	/** vHCA have been assigned a new LID */
	PSIF_EVENT_LID_TABLE_CHANGED,
	/** */
	PSIF_EVENT_EPSC_COMPLETION,
	/** Mailbox request handled (only if EPSC_FL_NOTIFY was set in the request) */
	PSIF_EVENT_MAILBOX,
	/** The real event type value is found in `eq_entry::extension_type` */
	PSIF_EVENT_EXTENSION,
	/** Host should retrieve the EPS log for persistent storage */
	PSIF_EVENT_LOG,
	/** */
	PSIF_EVENT_PORT_ACTIVE,
	/** */
	PSIF_EVENT_PORT_ERR,
	/** Event queue full (replaces the actual event) */
	PSIF_EVENT_QUEUE_FULL,
	/** FW entered degraded mode */
	PSIF_EVENT_DEGRADED_MODE,
	/** Request a keep-alive message */
	PSIF_EVENT_EPSC_KEEP_ALIVE,
	/** FW finished flushing MMU */
	PSIF_EVENT_EPSC_MMU_FLUSH_DONE,
	/* Padding out to required bits allocated */
	PSIF_EVENT_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_event [32 bits] */

/*
 * Enumerations of error types. The following error types are defined for the
 * TSU: TSU_NO_ERROR = 8'h0 TSU_IBPR_ICRC_ERR TSU_IBPR_INVALID_PKEY_ERR
 * TSU_IBPR_INVALID_QP_ERR TSU_IBPR_VSWITCH_UF_ERR
 * TSU_IBPR_UNDEFINED_OPCODE_ERR TSU_IBPR_MCAST_NO_GRH_ERR
 * TSU_IBPR_MCAST_NO_TARGET_ERR TSU_IBPR_INVALID_DGID_ERR TSU_IBPR_BADPKT_ERR
 * TSU_RCV_QP_INVALID_ERR TSU_RCV_HDR_BTH_TVER_ERR TSU_RCV_HDR_BTH_QP_ERR
 * TSU_RCV_HDR_GRH_ERR TSU_RCV_HDR_PKEY_ERR TSU_RCV_HDR_QKEY_ERR
 * TSU_RCV_HDR_LID_ERR TSU_RCV_HDR_MAD_ERR TSU_RCV_EOIB_MCAST_ERR
 * TSU_RCV_EOIB_BCAST_ERR TSU_RCV_EOIB_UCAST_ERR TSU_RCV_EOIB_FRAGMENT_ERR
 * TSU_RCV_EOIB_RUNTS_ERR TSU_RCV_EOIB_OUTER_VLAN_ERR
 * TSU_RCV_EOIB_VLAN_TAG_ERR TSU_RCV_EOIB_VID_ERR TSU_RCV_MCAST_DUP_ERR
 * TSU_RCV_ECC_ERR TSU_DSCR_RESPONDER_RC_PSN_ERR
 * TSU_DSCR_RESPONDER_RC_DUPLICATE TSU_DSCR_RESPONDER_RC_OPCODE_SEQ_ERR
 * TSU_DSCR_RESPONDER_RC_OPCODE_VAL_ERR TSU_DSCR_RESPONDER_RC_OPCODE_LEN_ERR
 * TSU_DSCR_RESPONDER_RC_DMALEN_ERR TSU_DSCR_RESPONDER_XRC_PSN_ERR
 * TSU_DSCR_RESPONDER_XRC_DUPLICATE TSU_DSCR_RESPONDER_XRC_OPCODE_SEQ_ERR
 * TSU_DSCR_RESPONDER_XRC_OPCODE_VAL_ERR
 * TSU_DSCR_RESPONDER_XRC_OPCODE_LEN_ERR TSU_DSCR_RESPONDER_XRC_DMALEN_ERR
 * TSU_DSCR_RESPONDER_UC_PSN_ERR TSU_DSCR_RESPONDER_UC_OPCODE_SEQ_ERR
 * TSU_DSCR_RESPONDER_UC_OPCODE_VAL_ERR TSU_DSCR_RESPONDER_UC_OPCODE_LEN_ERR
 * TSU_DSCR_RESPONDER_UC_DMALEN_ERR TSU_DSCR_RESPONDER_UD_OPCODE_LEN_ERR
 * TSU_DSCR_RESPONDER_DUPLICATE_WITH_ERR
 * TSU_DSCR_QP_CAP_MASKED_ATOMIC_ENABLE_ERR
 * TSU_DSCR_QP_CAP_RDMA_RD_ENABLE_ERR TSU_DSCR_QP_CAP_RDMA_WR_ENABLE_ERR
 * TSU_DSCR_QP_CAP_ATOMIC_ENABLE_ERR TSU_DSCR_XRC_DOMAIN_VIOLATION_ERR
 * TSU_DSCR_XRCETH_ERR TSU_DSCR_RQ_INVALID_ERR TSU_DSCR_RQ_PD_CHECK_ERR
 * TSU_DSCR_RQ_EMPTY_ERR TSU_DSCR_RQ_IN_ERROR_ERR
 * TSU_DSCR_TRANSLATION_TYPE_ERR TSU_DSCR_RQ_DESCRIPTOR_INCONSISTENT_ERR
 * TSU_DSCR_PCIE_ERR TSU_DSCR_ECC_ERR TSU_RQH_PCIE_ERR TSU_RQH_SGL_LKEY_ERR
 * TSU_RQH_NOT_ENOUGH_RQ_SPACE_ERR TSU_RQH_ECC_ERR TSU_VAL_DUPLICATE_WITH_ERR
 * TSU_VAL_RKEY_VLD_ERR TSU_VAL_RKEY_ADDR_RANGE_ERR TSU_VAL_RKEY_ACCESS_ERR
 * TSU_VAL_RKEY_PD_ERR TSU_VAL_RKEY_RANGE_ERR TSU_VAL_LKEY_VLD_ERR
 * TSU_VAL_LKEY_ADDR_RANGE_ERR TSU_VAL_LKEY_ACCESS_ERR TSU_VAL_LKEY_PD_ERR
 * TSU_VAL_LKEY_RANGE_ERR TSU_VAL_TRANSLATION_TYPE_ERR TSU_VAL_PCIE_ERR
 * TSU_VAL_ECC_ERR TSU_MMU_DUPLICATE_WITH_ERR TSU_MMU_PTW_ERR TSU_MMU_UF_ERR
 * TSU_MMU_AC_ERR TSU_MMU_ECC_ERR TSU_CBLD_CQ_INVALID_ERR
 * TSU_CBLD_CQ_FULL_ERR TSU_CBLD_CQ_IS_PROXY_ERR
 * TSU_CBLD_TRANSLATION_TYPE_ERR TSU_CBLD_CQ_DESCRIPTOR_INCONSISTENT_ERR
 * TSU_CBLD_ECC_ERR TSU_CBLD_QP_ERR TSU_RQS_CHECKSUM_ERR TSU_RQS_SEQNUM_ERR
 * TSU_RQS_INVALID_REQUEST_ERR TSU_RQS_QP_IN_WRONG_STATE_ERR
 * TSU_RQS_STOP_TIMER_ERR TSU_RQS_CMD_FROM_EPS_ERR TSU_RQS_SQ_FLUSH_ERR
 * TSU_RQS_SMP_NOT_AUTH_ERR TSU_RQS_REQUEST_FENCED_ERR
 * TSU_RQS_MAX_OUTSTANDING_REACHED_ERR TSU_RQS_ECC_ERR
 * TSU_RQS_EOIB_QKEY_VIOLATION TSU_RQS_IPOIB_QKEY_VIOLATION
 * TSU_RQS_EOIB_MODE_VIOLATION TSU_RQS_MISCONFIGURED_QP
 * TSU_RQS_PORT_AUTH_VIOLATION TSU_DMA_SGL_RD_ERR TSU_DMA_PYLD_RD_ERR
 * TSU_DMA_SGL_LENGTH_ERR TSU_DMA_LKEY_ERR TSU_DMA_RKEY_ERR
 * TSU_DMA_LSO_PKTLEN_ERR TSU_DMA_LSO_ILLEGAL_CLASSIFICATION_ERR
 * TSU_DMA_PCIE_ERR TSU_DMA_ECC_ERR TSU_CMPL_PCIE_ERR TSU_CMPL_ECC_ERR
 * TSU_CMPL_REQUESTER_PSN_ERR TSU_CMPL_REQUESTER_SYNDROME_ERR
 * TSU_CMPL_REQUESTER_OUTSTANDING_MATCH_ERR TSU_CMPL_REQUESTER_LEN_ERR
 * TSU_CMPL_REQUESTER_UNEXP_OPCODE_ERR TSU_CMPL_REQUESTER_DUPLICATE
 * TSU_CMPL_RC_IN_ERROR_ERR TSU_CMPL_NAK_RNR_ERR TSU_CMPL_NAK_SEQUENCE_ERR
 * TSU_CMPL_NAK_INVALID_REQUEST_ERR TSU_CMPL_NAK_REMOTE_ACCESS_ERR
 * TSU_CMPL_NAK_REMOTE_OPS_ERR TSU_CMPL_NAK_INVALID_RD_REQUEST_ERR
 * TSU_CMPL_TIMEOUT_ERR TSU_CMPL_IMPLIED_NAK TSU_CMPL_GHOST_RESP_ERR
 */
enum psif_tsu_error_types {
	TSU_NO_ERROR	 = 0u,
	TSU_IBPR_ICRC_ERR,
	TSU_IBPR_INVALID_PKEY_ERR,
	TSU_IBPR_INVALID_QP_ERR,
	TSU_IBPR_VSWITCH_UF_ERR,
	TSU_IBPR_PKTLEN_ERR,
	TSU_IBPR_UNDEFINED_OPCODE_ERR,
	TSU_IBPR_MCAST_NO_GRH_ERR,
	TSU_IBPR_MCAST_NO_TARGET_ERR,
	TSU_IBPR_INVALID_DGID_ERR,
	TSU_IBPR_BADPKT_ERR,
	TSU_RCV_QP_INVALID_ERR,
	TSU_RCV_HDR_BTH_TVER_ERR,
	TSU_RCV_HDR_BTH_QP_ERR,
	TSU_RCV_HDR_GRH_ERR,
	TSU_RCV_HDR_PKEY_ERR,
	TSU_RCV_HDR_QKEY_ERR,
	TSU_RCV_HDR_LID_ERR,
	TSU_RCV_HDR_MAD_ERR,
	TSU_RCV_EOIB_MCAST_ERR,
	TSU_RCV_EOIB_BCAST_ERR,
	TSU_RCV_EOIB_UCAST_ERR,
	TSU_RCV_EOIB_TCP_PORT_VIOLATION_ERR,
	TSU_RCV_EOIB_RUNTS_ERR,
	TSU_RCV_EOIB_OUTER_VLAN_ERR,
	TSU_RCV_EOIB_VLAN_TAG_ERR,
	TSU_RCV_EOIB_VID_ERR,
	TSU_RCV_IPOIB_TCP_PORT_VIOLATION_ERR,
	TSU_RCV_MCAST_DUP_ERR,
	TSU_RCV_ECC_ERR,
	TSU_DSCR_RESPONDER_RC_PSN_ERR,
	TSU_DSCR_RESPONDER_RC_DUPLICATE,
	TSU_DSCR_RESPONDER_RC_OPCODE_SEQ_ERR,
	TSU_DSCR_RESPONDER_RC_OPCODE_VAL_ERR,
	TSU_DSCR_RESPONDER_RC_OPCODE_LEN_ERR,
	TSU_DSCR_RESPONDER_RC_DMALEN_ERR,
	TSU_DSCR_RESPONDER_XRC_PSN_ERR,
	TSU_DSCR_RESPONDER_XRC_DUPLICATE,
	TSU_DSCR_RESPONDER_XRC_OPCODE_SEQ_ERR,
	TSU_DSCR_RESPONDER_XRC_OPCODE_VAL_ERR,
	TSU_DSCR_RESPONDER_XRC_OPCODE_LEN_ERR,
	TSU_DSCR_RESPONDER_XRC_DMALEN_ERR,
	TSU_DSCR_RESPONDER_UC_PSN_ERR,
	TSU_DSCR_RESPONDER_UC_OPCODE_SEQ_ERR,
	TSU_DSCR_RESPONDER_UC_OPCODE_VAL_ERR,
	TSU_DSCR_RESPONDER_UC_OPCODE_LEN_ERR,
	TSU_DSCR_RESPONDER_UC_DMALEN_ERR,
	TSU_DSCR_RESPONDER_UD_OPCODE_LEN_ERR,
	TSU_DSCR_RESPONDER_DUPLICATE_WITH_ERR,
	TSU_DSCR_QP_CAP_MASKED_ATOMIC_ENABLE_ERR,
	TSU_DSCR_QP_CAP_RDMA_RD_ENABLE_ERR,
	TSU_DSCR_QP_CAP_RDMA_WR_ENABLE_ERR,
	TSU_DSCR_QP_CAP_ATOMIC_ENABLE_ERR,
	TSU_DSCR_XRC_DOMAIN_VIOLATION_ERR,
	TSU_DSCR_XRCETH_ERR,
	TSU_DSCR_RQ_INVALID_ERR,
	TSU_DSCR_RQ_PD_CHECK_ERR,
	TSU_DSCR_RQ_EMPTY_ERR,
	TSU_DSCR_RQ_IN_ERROR_ERR,
	TSU_DSCR_TRANSLATION_TYPE_ERR,
	TSU_DSCR_RQ_DESCRIPTOR_INCONSISTENT_ERR,
	TSU_DSCR_MISALIGNED_ATOMIC_ERR,
	TSU_DSCR_PCIE_ERR,
	TSU_DSCR_ECC_ERR,
	TSU_RQH_PCIE_ERR,
	TSU_RQH_SGL_LKEY_ERR,
	TSU_RQH_NOT_ENOUGH_RQ_SPACE_ERR,
	TSU_RQH_ECC_ERR,
	TSU_VAL_DUPLICATE_WITH_ERR,
	TSU_VAL_RKEY_VLD_ERR,
	TSU_VAL_RKEY_ADDR_RANGE_ERR,
	TSU_VAL_RKEY_ACCESS_ERR,
	TSU_VAL_RKEY_PD_ERR,
	TSU_VAL_RKEY_RANGE_ERR,
	TSU_VAL_LKEY_VLD_ERR,
	TSU_VAL_LKEY_ADDR_RANGE_ERR,
	TSU_VAL_LKEY_ACCESS_ERR,
	TSU_VAL_LKEY_PD_ERR,
	TSU_VAL_LKEY_RANGE_ERR,
	TSU_VAL_TRANSLATION_TYPE_ERR,
	TSU_VAL_PCIE_ERR,
	TSU_VAL_ECC_ERR,
	TSU_MMU_DUPLICATE_WITH_ERR,
	TSU_MMU_PTW_ERR,
	TSU_MMU_UF_ERR,
	TSU_MMU_AC_ERR,
	TSU_MMU_ECC_ERR,
	TSU_CBLD_CQ_INVALID_ERR,
	TSU_CBLD_CQ_FULL_ERR,
	TSU_CBLD_CQ_ALREADY_IN_ERR,
	TSU_CBLD_CQ_IS_PROXY_ERR,
	TSU_CBLD_TRANSLATION_TYPE_ERR,
	TSU_CBLD_CQ_DESCRIPTOR_INCONSISTENT_ERR,
	TSU_CBLD_ECC_ERR,
	TSU_CBLD_PCIE_ERR,
	TSU_CBLD_QP_ERR,
	TSU_RQS_CHECKSUM_ERR,
	TSU_RQS_SEQNUM_ERR,
	TSU_RQS_INVALID_REQUEST_ERR,
	TSU_RQS_QP_IN_WRONG_STATE_ERR,
	TSU_RQS_STOP_TIMER_ERR,
	TSU_RQS_CMD_FROM_EPS_ERR,
	TSU_RQS_SQ_FLUSH_ERR,
	TSU_RQS_SMP_NOT_AUTH_ERR,
	TSU_RQS_REQUEST_FENCED_ERR,
	TSU_RQS_MAX_OUTSTANDING_REACHED_ERR,
	TSU_RQS_ECC_ERR,
	TSU_RQS_EOIB_QKEY_VIOLATION,
	TSU_RQS_IPOIB_QKEY_VIOLATION,
	TSU_RQS_EOIB_MODE_VIOLATION,
	TSU_RQS_MISCONFIGURED_QP,
	TSU_RQS_PORT_AUTH_VIOLATION,
	TSU_DMA_SGL_RD_ERR,
	TSU_DMA_REQ_PYLD_RD_ERR,
	TSU_DMA_RESP_PYLD_RD_ERR,
	TSU_DMA_SGL_LENGTH_ERR,
	TSU_DMA_LKEY_ERR,
	TSU_DMA_RKEY_ERR,
	TSU_DMA_LSO_PKTLEN_ERR,
	TSU_DMA_LSO_ILLEGAL_CLASSIFICATION_ERR,
	TSU_DMA_PCIE_ERR,
	TSU_DMA_ECC_ERR,
	TSU_CMPL_PCIE_ERR,
	TSU_CMPL_ECC_ERR,
	TSU_CMPL_REQUESTER_PSN_ERR,
	TSU_CMPL_REQUESTER_SYNDROME_ERR,
	TSU_CMPL_REQUESTER_OUTSTANDING_MATCH_ERR,
	TSU_CMPL_REQUESTER_LEN_ERR,
	TSU_CMPL_REQUESTER_UNEXP_OPCODE_ERR,
	TSU_CMPL_REQUESTER_DUPLICATE,
	TSU_CMPL_RC_IN_ERROR_ERR,
	TSU_CMPL_NAK_RNR_ERR,
	TSU_CMPL_NAK_SEQUENCE_ERR,
	TSU_CMPL_NAK_INVALID_REQUEST_ERR,
	TSU_CMPL_NAK_REMOTE_ACCESS_ERR,
	TSU_CMPL_NAK_REMOTE_OPS_ERR,
	TSU_CMPL_NAK_INVALID_RD_REQUEST_ERR,
	TSU_CMPL_TIMEOUT_ERR,
	TSU_CMPL_IMPLIED_NAK,
	TSU_CMPL_GHOST_RESP_ERR
}; /* enum psif_tsu_error_types [ 8 bits] */

/*
 * Here are the different EPS core IDs: PSIF_EVENT_EPS_A_1 PSIF_EVENT_EPS_A_2
 * PSIF_EVENT_EPS_A_3 PSIF_EVENT_EPS_A_4 PSIF_EVENT_EPS_C
 */
enum psif_eps_core_id {
	PSIF_EVENT_CORE_EPS_A_1	 = 0u,
	PSIF_EVENT_CORE_EPS_A_2,
	PSIF_EVENT_CORE_EPS_A_3,
	PSIF_EVENT_CORE_EPS_A_4,
	PSIF_EVENT_CORE_EPS_C,
	/* Padding out to required bits allocated */
	PSIF_EPS_CORE_ID_FIELD_MAX	 = 0xfu
}; /* enum psif_eps_core_id [ 4 bits] */

/**
 * \brief Discriminator for PSIF_QUERY of persistent values
 * \details
 * \par Width
 *      32 bit
 * \par Used in
 * the parameter for the PSIF_QUERY sub-operation EPSC_QUERY_NUM_VFS and EPS_QUERY_JUMBO - set in the index field
 * \par Classification
 *      driver
 */
enum psif_epsc_query_persistent {
	EPSC_QUERY_PERSISTENT_STORED,
	EPSC_QUERY_PERSISTENT_ACTIVE,
	EPSC_QUERY_PERSISTENT_HW_CAP,
	/* Padding out to required bits allocated */
	PSIF_EPSC_QUERY_PERSISTENT_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_query_persistent [32 bits] */

/*
 * Should match definitions in ib_verbs.h
 */
enum psif_port_speed {
	PSIF_SPEED_SDR	 = 0x1u,
	PSIF_SPEED_DDR	 = 0x2u,
	PSIF_SPEED_QDR	 = 0x4u,
	PSIF_SPEED_FDR10	 = 0x8u,
	PSIF_SPEED_FDR	 = 0x10u,
	PSIF_SPEED_EDR	 = 0x20u,
	/* Padding out to required bits allocated */
	PSIF_PORT_SPEED_FIELD_MAX	 = 0xffu
}; /* enum psif_port_speed [ 8 bits] */

/**
 * \brief Port state
 * \details
 * This enum specifies the state of a UF port's port state machine. It
 * is used to either force a new state or to report the current state
 * (via \ref EPSC_QUERY_PORT_1 and \ref EPSC_QUERY_PORT_2).
 *
 * \par Width
 *      32 bit
 * \par Used in
 *      psif_epsc_port_attr_t
 * \par Classification
 *      driver, internal
 *
 * \todo
 * The externally provided version of the documentation should probably
 * not contain the information about forcing the state as this is only
 * for FW.
 */
enum psif_epsc_port_state {
	/** No change */
	EPSC_PORT_NOP	 = 0u,
	/** The port is down. */
	EPSC_PORT_DOWN	 = 0x1u,
	/** The port is in init state. */
	EPSC_PORT_INIT	 = 0x2u,
	/** The port state is armed. */
	EPSC_PORT_ARMED	 = 0x3u,
	/** The port is active. */
	EPSC_PORT_ACTIVE	 = 0x4u,
	/** The port is in deferred active state. */
	EPSC_PORT_ACTIVE_DEFER	 = 0x5u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_PORT_STATE_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_port_state [32 bits] */

/**
 * \brief Version fixed copy of psif_path_mtu
 * \details
 * This enum specifies the path MTU values and is the same as `psif_path_mtu`
 * found in `psif_verbs.h`. The difference is the data type. The version in
 * `psif_verbs.h` is smaller!
 *
 * \todo
 * Change version in `psif_verbs.h` to 32b and then drop this one here?
 *
 * \par Width
 *      32 bit
 * \par Used in
 *      psif_epsc_port_attr_t
 * \par Classification
 *      driver
 */
enum psif_epsc_path_mtu {
	/** Not a valid MTU. */
	EPSC_MTU_INVALID	 = 0u,
	/** The MTU is 256 bytes. */
	EPSC_MTU_256B	 = 0x1u,
	/** The MTU is 512 bytes. */
	EPSC_MTU_512B	 = 0x2u,
	/** The MTU is 1024 bytes. */
	EPSC_MTU_1024B	 = 0x3u,
	/** The MTU is 2048 bytes. */
	EPSC_MTU_2048B	 = 0x4u,
	/** The MTU is 4069 bytes. */
	EPSC_MTU_4096B	 = 0x5u,
	/** The MTU is 10240 bytes. */
	EPSC_MTU_10240B	 = 0x6u,
	/** Not a specific MTU. */
	EPSC_MTU_XXX	 = 0x7u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_PATH_MTU_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_path_mtu [32 bits] */


enum psif_epsc_log_mode {
/* Logging completely disabled */

	EPSC_LOG_MODE_OFF	 = 0u,
/* See epsfw/src/include/logging.h */

	EPSC_LOG_MODE_SCAT	 = 0x1u,
	EPSC_LOG_MODE_MALLOC	 = 0x2u,
	EPSC_LOG_MODE_LOCAL	 = 0x3u,
/* Redirect logging to host (dma) */

	EPSC_LOG_MODE_HOST	 = 0x4u,
/* Save the set log mode in the flash */

	EPSC_LOG_MODE_SAVE	 = 0x10u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_LOG_MODE_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_log_mode [32 bits] */

/**
 * EPSC_LOG_CTRL
 */
enum psif_epsc_log_level {
	EPS_LOG_OFF	 = 0u,
	EPS_LOG_FATAL	 = 0x1u,
	EPS_LOG_ERROR	 = 0x2u,
	EPS_LOG_WARN	 = 0x3u,
	EPS_LOG_INFO	 = 0x4u,
	EPS_LOG_DEBUG	 = 0x5u,
	EPS_LOG_TRACE	 = 0x6u,
	EPS_LOG_ALL	 = 0x7u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_LOG_LEVEL_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_log_level [32 bits] */

/** Bits describing the cause(s) for EPSC to have entered degraded mode
 * \par Used in
 *      response to `EPSC_QUERY_DEGRADED_MODE` and `psif_eq_entry::event_data`
 * \par Classification
 *      driver
 */
enum psif_epsc_degrade_cause {
/**< degrade cause: no GUID programmed or not readable */

	DEGRADE_CAUSE_FLAG_MISSING_GUID,
/**< degrade cause: invalid function name in VPD */

	DEGRADE_CAUSE_FLAG_VPD_INVALID_NAME,
/**< degrade cause: HW not supported by FW */

	DEGRADE_CAUSE_FLAG_HW_UNSUPPORTED,
/**< degrade cause: failed MDIO access */

	DEGRADE_CAUSE_FLAG_HW_MDIO_ERROR,
/**< degrade cause: modify QP timeout */

	DEGRADE_CAUSE_FLAG_MODIFY_QP_TIMEOUT,
/**< degrade cause: Virtualization mode reconfigured, reset needed */

	DEGRADE_CAUSE_FLAG_VIRTMODE_RECONF,
/**< degrade cause: no credits for sending multicast packets */

	DEGRADE_CAUSE_FLAG_MCAST_LACK_OF_CREDIT,
	/* Padding out to required bits allocated */
	PSIF_EPSC_DEGRADE_CAUSE_FIELD_MAX	 = 0x1fu
}; /* enum psif_epsc_degrade_cause [ 5 bits] */

/**
 * \brief Query HCA verb response member `atomicity guarantee` values
 * \details
 * This enum specifies values possible for the (masked) atomicity guarantee
 * capability reported in the Query HCA verb (via \ref EPSC_QUERY_DEVICE).
 *
 * \par Width
 *      32 bit
 * \par Used in
 *      psif_epsc_device_attr_t
 * \par Classification
 *      driver
 */
enum psif_epsc_atomic_cap {
	/** no atomicity guarantee */
	EPSC_ATOMIC_NONE,
	/** HCA atomicity guarantee */
	EPSC_ATOMIC_HCA,
	/** global atomicity guarantee */
	EPSC_ATOMIC_GLOB,
	/* Padding out to required bits allocated */
	PSIF_EPSC_ATOMIC_CAP_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_atomic_cap [32 bits] */

/**
 * \brief The EPS-C FW status return codes
 * \details These error codes are retured from the EPS-C.
 * \par Width
 *      8 bit
 * \par Used in
 *      psif_epsc_csr_rsp member `status`
 * \par Classification
 *      external, driver
 */
enum psif_epsc_csr_status {
	/** Successful exit status. */
	EPSC_SUCCESS	 = 0u,
	/** Key was rejected by service. */
	EPSC_EKEYREJECTED	 = 0x1u,
	/** Cannot assign requested address. */
	EPSC_EADDRNOTAVAIL	 = 0x2u,
	/** Operation not supported on transport endpoint. */
	EPSC_EOPNOTSUPP	 = 0x3u,
	/** Out of memory. */
	EPSC_ENOMEM	 = 0x4u,
	/** No data available. */
	EPSC_ENODATA	 = 0x5u,
	/** Try again. */
	EPSC_EAGAIN	 = 0x6u,
	/** Operation canceled. */
	EPSC_ECANCELED	 = 0x7u,
	/** Connection reset by peer. */
	EPSC_ECONNRESET	 = 0x8u,
	/** CSR operation failed. */
	EPSC_ECSR	 = 0x9u,
	/** Modify queue pair error: QP index out of range. */
	EPSC_MODIFY_QP_OUT_OF_RANGE	 = 0xau,
	/** Modify queue pair error: QP is invalid. */
	EPSC_MODIFY_QP_INVALID	 = 0xbu,
	/** Modify queue pair error: failed to change QP attribute. */
	EPSC_MODIFY_CANNOT_CHANGE_QP_ATTR	 = 0xcu,
	/** Modify queue pair error: failed to change QP due to invalid or not matching state. */
	EPSC_MODIFY_INVALID_QP_STATE	 = 0xdu,
	/** Modify queue pair error: failed to change QP due to invalid or not matching migration state. */
	EPSC_MODIFY_INVALID_MIG_STATE	 = 0xeu,
	/** Modify queue pair error: the operation timed out. */
	EPSC_MODIFY_TIMEOUT	 = 0xfu,
	/** DMA test failure in HEAD. */
	EPSC_ETEST_HEAD	 = 0x10u,
	/** DMA test failure in TAIL. */
	EPSC_ETEST_TAIL	 = 0x11u,
	/** DMA test failure in PATTERN. */
	EPSC_ETEST_PATTERN	 = 0x12u,
	/** Multicast address already exist. */
	EPSC_EADDRINUSE	 = 0x13u,
	/** vHCA out of range */
	EPSC_EINVALID_VHCA	 = 0x14u,
	/** Port out of range */
	EPSC_EINVALID_PORT	 = 0x15u,
	/** Address out of range */
	EPSC_EINVALID_ADDRESS	 = 0x16u,
	/** Parameter out of range */
	EPSC_EINVALID_PARAMETER	 = 0x17u,
	/** General failure. */
	EPSC_FAIL	 = 0xffu
}; /* enum psif_epsc_csr_status [ 8 bits] */

/**
 * \brief Host to EPS operation codes
 * \details
 * These operation codes are sent in the \ref psif_epsc_csr_req::opcode member
 * from the host or a particular core (EPS-Ax/EPS-C) to the mailbox thread in
 * EPS-C or EPS-Ax in order to specify the request. In addition the operation
 * codes are used as a selector for the \ref psif_epsc_csr_req::u member of
 * type \ref psif_epsc_csr_details_t in order to specify the particular
 * structure if the request requires specific arguments. In some cases the
 * selected structure defines an own set of sub-operation codes like for
 * \ref EPSC_QUERY with \ref psif_epsc_query_req_t::op of type
 * \ref psif_epsc_query_op_t.
 * \par
 * Responses are always of type \ref psif_epsc_csr_rsp_t but the meaning of the
 * members of that structure depend on the operation code. The response state
 * is \ref EPSC_EADDRNOTAVAIL for all not supported operation codes.
 *
 * \par Width
 *      8 bit
 * \par Used in
 *      psif_epsc_csr_req_t
 * \par Classification
 *      see each of the operation codes
 *
 * \note
 * - All codes must be unique and fit into a 8 bit number.
 * - In order to provide backward compatibility new codes must start from the
 *   current value of \ref EPSC_LAST_OP and the value of \ref EPSC_LAST_OP
 *   must be incremented by the number of newly inserted codes.
 */
enum psif_epsc_csr_opcode {
	/** Not a valid operation code. */
	EPSC_NOOP	 = 0u,
	/** EPS-C ping over mailbox. */
	EPSC_MAILBOX_PING	 = 0x4cu,
	/** Host patting of EPS-C SW watch-dog. */
	EPSC_KEEP_ALIVE	 = 0x4du,
	/** Initial configuration request per UF.
	 * This request is transferred from the host to the epsc at driver
	 * attach using an encoding of the physical mailbox register. It
	 * is not a legal request on an operational mailbox communication
	 *
	 * \par Request
	 *      Structure details:
	 *      Member | Content
	 *      -------|-------------------
	 *      u      | \ref psif_epsc_csr_config_t
	 * \par Response
	 *      Structure contents:
	 *      Member | Content
	 *      -------|-------------------
	 *      addr   | number of event queues (EQ) per UF
	 *      data   | PSIF/EPS-C version
	 * \par
	 *      The version is encoded this way:
	 *      Bits  | Version Specifier
	 *      ------|---------
	 *      63-48 | PSIF_MAJOR_VERSION
	 *      47-32 | PSIF_MINOR_VERSION
	 *      31-16 | EPSC_MAJOR_VERSION
	 *      15-0  | EPSC_MINOR_VERSION
	 *
	 * \par Return Codes
	 *      \ref EPSC_SUCCESS
	 * \par Restrictions
	 *      none (all UF)
	 * \par Classification
	 *      driver
	 */
	EPSC_SETUP	 = 0x1u,
	/** Final de-configuration request.
	 * This request is sent from the host driver to indicate that it has
	 * cleaned up all queues and flushed caches associated with the current
	 * UF. It is the last command for that UF and the firmware will take down
	 * the associated virtual links and mailbox settings. For further
	 * communication with that UF the mailbox needs to be set up again via
	 * \ref EPSC_SETUP .
	 *
	 * \par Request
	 *      N/A
	 * \par Return Codes
	 *      \ref EPSC_SUCCESS
	 * \par Restrictions
	 *      none (all UF)
	 * \par Classification
	 *      driver
	 */
	EPSC_TEARDOWN	 = 0x36u,
	/** Operation code for a general set request.
	 * The request usees the same parameter structure as the \ref EPSC_QUERY
	 * request. Upon recieve the mailbox thread first processes the set request
	 * in \ref psif_epsc_csr_query_t::info and then the request in
	 * \ref psif_epsc_csr_query_t::data. Both members are of type
	 * \ref psif_epsc_query_req_t and have their own sub-operation codes in
	 * \ref psif_epsc_query_req_t::op (of type \ref psif_epsc_query_op_t).
	 * Therefore requests instantiating only one set attribute
	 * (i.e. \ref psif_epsc_csr_query_t::info or \ref psif_epsc_csr_query_t::data)
	 * have to set the sub-operation code of the other member to
	 * \ref EPSC_QUERY_BLANK.
	 *
	 * \par Request
	 *      Structure details:
	 *      Member | Content
	 *      -------|-------------------
	 *      u      | \ref psif_epsc_csr_query_t
	 * \par Return Codes
	 *      \ref EPSC_SUCCESS, \ref EPSC_EOPNOTSUPP, \ref EPSC_FAIL
	 * \par Restrictions
	 *      none (all UF)
	 * \par Classification
	 *      external
	 */
	EPSC_SET	 = 0x46u,
	/** Operation code for a single CSR write request.
	 * \note
	 * The request is deprecated and will be removed as soon as all
	 * references to this opcode have been cleaned up.
	 * \par Return Codes
	 *      \ref EPSC_EADDRNOTAVAIL
	 */
	EPSC_SET_SINGLE	 = 0x2u,
	/** Operation code for setting an arbitrary CSR.
	 * \note
	 * The request is used mainly for debugging tools and will be either removed
	 * completely or limited to certain register addresses.
	 *
	 * \par Request
	 *      Structure details:
	 *      Member | Content
	 *      -------|-------------------
	 *      addr   | CSR address
	 *      u      | `data[0]` value to write to CSR
	 * \par Response
	 *      Structure contents:
	 *      Member | Content
	 *      -------|----------------------------------------
	 *      addr   | the value `addr` from the request
	 *      data   | the value `data[0]` from the request
	 *
	 * \par Return Codes
	 *      \ref EPSC_SUCCESS, \ref EPSC_FAIL
	 * \par Restrictions
	 *      valid register addresses depend on UF
	 * \par Classification
	 *      driver, development
	 */
	EPSC_SET_ONE_CSR	 = 0x3u,
	/** Old operation code to set up a descriptor base address.
	 * \note
	 * The request is deprecated and will be removed as soon as all
	 * references to this opcode have been cleaned up.
	 *
	 * \par Return Codes
	 *      \ref EPSC_EADDRNOTAVAIL
	 * \par Classification
	 *      driver
	 */
	EPSC_SETUP_BASEADDR	 = 0x4u,
	/** Operation code to set up a descriptor base address.
	 * With this request the driver configures the descriptor base addresses
	 * of queues, queue pairs and address handles.
	 *
	 * \par Request
	 *      Structure details:
	 *      Member | Content
	 *      -------|-------------------------------------------
	 *      addr   | Descriptor base address setup CSR address
	 *      u      | \ref psif_epsc_csr_base_addr_t
	 *
	 * \par Return Codes
	 *      \ref EPSC_SUCCESS, \ref EPSC_FAIL
	 * \par Restrictions
	 *      none (all UF)
	 * \par Classification
	 *      driver, development
	 */
	EPSC_SET_BASEADDR	 = 0x5u,
	/** Operation code to set up an event queue (EQ).
	 * With this request the driver configures an EQ descriptor base address
	 * as well as the associated interrupt.
	 *
	 * \par Request
	 *      Structure details:
	 *      Member | Content
	 *      -------|-------------------------------------------
	 *      addr   | event queue number
	 *      u      | \ref psif_epsc_csr_base_addr_t
	 *
	 * \par Return Codes
	 *      \ref EPSC_SUCCESS, \ref EPSC_FAIL
	 * \par Restrictions
	 *      none (all UF)
	 * \par Classification
	 *      driver
	 */
	EPSC_SET_BASEADDR_EQ	 = 0x6u,
	/* Set Local ID for UF (backdoor) */
	EPSC_SET_LID	 = 0x7u,
	OBSOLETE_1	 = 0x8u,
	OBSOLETE_2	 = 0x9u,
	/* Set Global ID for UF (backdoor) */
	EPSC_SET_GID	 = 0xau,
	/* Set EoIB MAC address (backdoor) */
	EPSC_SET_EOIB_MAC	 = 0x40u,
	/* Set Vlink state */
	EPSC_SET_VLINK_STATE	 = 0xbu,
	/* Get Vlink state */
	EPSC_QUERY_VLINK_STATE	 = 0xcu,
	/* Reset UF at startup */
	EPSC_UF_RESET	 = 0xdu,
	/* Modify QP complete w/kick */
	EPSC_MODIFY_QP	 = 0xeu,
	/* Get single 64bit register - deprecated */
	EPSC_GET_SINGLE	 = 0xfu,
	/* Get one 64bit register using CSR addr */
	EPSC_GET_ONE_CSR	 = 0x10u,
	/* Query QP sub-entry */
	EPSC_QUERY_QP	 = 0x11u,
	/** Query HW receive queue. */
	EPSC_QUERY_HW_RQ	 = 0x42u,
	/** Query HW SQ. */
	EPSC_QUERY_HW_SQ	 = 0x43u,
	/* Non-MAD query device */
	EPSC_QUERY_DEVICE	 = 0x12u,
	/* Non-MAD query port */
	EPSC_QUERY_PORT_1	 = 0x13u,
	EPSC_QUERY_PORT_2	 = 0x14u,
	/* Non-MAD SMA attribute query */
	EPSC_QUERY_PKEY	 = 0x15u,
	EPSC_QUERY_GID	 = 0x16u,
	/* Non-MAD SMA attribute setting */
	EPSC_MODIFY_DEVICE	 = 0x17u,
	EPSC_MODIFY_PORT_1	 = 0x18u,
	EPSC_MODIFY_PORT_2	 = 0x19u,
	/* Local MC subscription handling */
	EPSC_MC_ATTACH	 = 0x1au,
	EPSC_MC_DETACH	 = 0x1bu,
	EPSC_MC_QUERY	 = 0x1cu,
	/* Handle asynchronous events */
	EPSC_EVENT_ACK	 = 0x1du,
	EPSC_EVENT_INDEX	 = 0x1eu,
	/* Program flash content */
	EPSC_FLASH_START	 = 0x1fu,
	EPSC_FLASH_INFO	 = 0x20u,
	EPSC_FLASH_ERASE_SECTOR	 = 0x21u,
	EPSC_FLASH_RD	 = 0x22u,
	EPSC_FLASH_WR	 = 0x23u,
	EPSC_FLASH_CHECK	 = 0x24u,
	EPSC_FLASH_SCAN	 = 0x25u,
	EPSC_FLASH_STOP	 = 0x26u,
	/* new update handling */
	EPSC_UPDATE	 = 0x47u,
	/* IB packet tracer */
	EPSC_TRACE_STATUS	 = 0x27u,
	EPSC_TRACE_SETUP	 = 0x28u,
	EPSC_TRACE_START	 = 0x29u,
	EPSC_TRACE_STOP	 = 0x2au,
	EPSC_TRACE_ACQUIRE	 = 0x2bu,
	/* Test operations */
	EPSC_TEST_HOST_RD	 = 0x2cu,
	EPSC_TEST_HOST_WR	 = 0x2du,
	/* Get EPS-C version details */
	EPSC_FW_VERSION	 = 0x2eu,
	/* Redirection/configuration of EPSC's internal log subsystem */
	EPSC_LOG_CTRL	 = 0x2fu,
	EPSC_LOG_REQ_NOTIFY	 = 0x30u,
	/* Force & read back link speed */
	EPSC_LINK_CNTRL	 = 0x31u,
	/* EPS-A control & communication (to EPS-C) */
	EPSC_A_CONTROL	 = 0x33u,
	/* EPS-A targeted commands (to EPS-A) */
	EPSC_A_COMMAND	 = 0x35u,
	/* Exercise mmu with access from epsc */
	EPSC_EXERCISE_MMU	 = 0x34u,
	/* Access to EPS-C CLI */
	EPSC_CLI_ACCESS	 = 0x37u,
	/* IB packet proxy to/from host */
	EPSC_MAD_PROCESS	 = 0x38u,
	EPSC_MAD_SEND_WR	 = 0x39u,
	/** Generic query epsc interface. */
	EPSC_QUERY	 = 0x41u,
	/* Setup interrupt coalescing etc. */
	EPSC_HOST_INT_COMMON_CTRL	 = 0x44u,
	EPSC_HOST_INT_CHANNEL_CTRL	 = 0x45u,
	/** UF control depends on \ref psif_epsc_csr_uf_ctrl_t::opcode. */
	EPSC_UF_CTRL	 = 0x48u,
	/* Flush MMU and-or PTW Caches */
	EPSC_FLUSH_CACHES	 = 0x49u,
	/* Query PMA counters - alternative path to sending MAD's */
	EPSC_PMA_COUNTERS	 = 0x4au,
	/** VIMMA operations depends on \ref psif_epsc_csr_vimma_ctrl_t::opcode. */
	EPSC_VIMMA_CTRL	 = 0x4bu,
	/* EPSC BER (Bit Error Report) Data */
	EPSC_BER_DATA	 = 0x4eu,
	/** EOF marker - must be last and highest in this enum type. */
	EPSC_LAST_OP	 = 0x4fu,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_OPCODE_FIELD_MAX	 = 0xffu
}; /* enum psif_epsc_csr_opcode [ 8 bits] */

/**
 * The eps-c fw csr flags
 */
enum psif_epsc_csr_flags {
	EPSC_FL_NONE	 = 0u,
	/* Request notification (interrupt) when completion is ready */
	EPSC_FL_NOTIFY	 = 0x1u,
	/* Privileged QP indicator only valid for query and modify QP */
	EPSC_FL_PQP	 = 0x2u,
	/* Allways report opertion success */
	EPSC_FL_IGNORE_ERROR	 = 0x4u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_FLAGS_FIELD_MAX	 = 0xffu
}; /* enum psif_epsc_csr_flags [ 8 bits] */

/*
 * Link states for the virtual HCA and switch. The following onehot encoded
 * states exist: PSIF_LINK_DISABLED = 1 PSIF_LINK_DOWN = 2 PSIF_LINK_INIT = 4
 * PSIF_LINK_ARM = 8 PSIF_LINK_ACTIVE = 16
 */
enum psif_vlink_state {
	PSIF_LINK_DISABLED	 = 0x1u,
	PSIF_LINK_DOWN	 = 0x2u,
	PSIF_LINK_INIT	 = 0x4u,
	PSIF_LINK_ARM	 = 0x8u,
	PSIF_LINK_ACTIVE	 = 0x10u
}; /* enum psif_vlink_state [ 5 bits] */

/**
 * EPSC_MODIFY_DEVICE operations
 */
enum psif_epsc_csr_modify_device_flags {
	PSIF_DEVICE_MODIFY_SYS_IMAGE_GUID	 = 0x1u,
	PSIF_DEVICE_MODIFY_NODE_DESC	 = 0x2u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_MODIFY_DEVICE_FLAGS_FIELD_MAX	 = 0xffffu
}; /* enum psif_epsc_csr_modify_device_flags [16 bits] */

/**
 * EPSC_MODIFY_PORT_{1,2} operations
 */
enum psif_epsc_csr_modify_port_flags {
	PSIF_PORT_SHUTDOWN	 = 0x1u,
	PSIF_PORT_INIT_TYPE	 = 0x4u,
	PSIF_PORT_RESET_QKEY_CNTR	 = 0x8u,
	PSIF_PORT_RESET_PKEY_CNTR	 = 0x10u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_MODIFY_PORT_FLAGS_FIELD_MAX	 = 0xffffu
}; /* enum psif_epsc_csr_modify_port_flags [16 bits] */


enum psif_epsc_csr_epsa_command {
	EPSC_A_LOAD,
	EPSC_A_START,
	EPSC_A_STOP,
	EPSC_A_STATUS,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_EPSA_COMMAND_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_csr_epsa_command [32 bits] */

/*
 */
enum psif_epsa_command {
	EPSA_DYNAMIC_LOAD,
	EPSA_TEST_FABOUT,
	EPSA_TEST_FABIN,
	EPSA_TEST_FABIN_FABOUT,
	EPSA_TEST_SKJM_MEMREAD,
	EPSA_TEST_SKJM_MEMWRITE,
	EPSA_TEST_SKJM_MEMLOCK,
	EPSA_SKJM_LOAD,
	EPSA_SKJM_ACC,
	EPSA_SKJM_MEMACC,
	EPSA_GET_PROXY_QP_SQ_KEY,
	EPSA_GENERIC_CMD,
	/* Padding out to required bits allocated */
	PSIF_EPSA_COMMAND_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsa_command [32 bits] */

/**
 * \brief Sub-operation codes as used by EPSC_QUERY and EPSC_SET requests.
 * \details
 * \par Width
 *      32 bit
 * \par Used in
 *      psif_epsc_query_req member `op`
 * \par Classification
 *      internal, development
 */
enum psif_epsc_query_op {
	/** If initiated from a EPSC_QUERY this operation code will always return zero
	 *  and report success. In case of a intended set request (EPSC_SET) this
	 *  operation code ignore the request and return success.
	 */
	EPSC_QUERY_BLANK	 = 0u,
	/* Obsolete - use EPSC_QUERY_CAP_VCB_{LO HI} */
	EPSC_QUERY_CAP_VCB	 = 0x1u,
	/* Obsolete - use EPSC_QUERY_CAP_PCB_{LO HI} */
	EPSC_QUERY_CAP_PCB	 = 0x2u,
	EPSC_QUERY_NUM_UF	 = 0x3u,
	EPSC_QUERY_GID_HI	 = 0x4u,
	EPSC_QUERY_GID_LO	 = 0x5u,
	EPSC_QUERY_P_KEY	 = 0x6u,
	EPSC_QUERY_Q_KEY	 = 0x7u,
	EPSC_QUERY_UF	 = 0x8u,
	EPSC_QUERY_LINK_STATE	 = 0x9u,
	EPSC_QUERY_VHCA_STATE	 = 0xau,
	/* Corresponds to register TSU_HOST_INT_CTRL_ADDR */
	EPSC_QUERY_INT_COMMON	 = 0xbu,
	/* Corresponds to register TSU_HOST_INT_CHAN_CTRL_0 */
	EPSC_QUERY_INT_CHAN_RATE	 = 0xcu,
	/* Corresponds to register TSU_HOST_INT_CHAN_CTRL_1 */
	EPSC_QUERY_INT_CHAN_AUSEC	 = 0xdu,
	/* Corresponds to register TSU_HOST_INT_CHAN_CTRL_2 */
	EPSC_QUERY_INT_CHAN_PUSEC	 = 0xeu,
	/* Number of VCBs in PCI lo BAR */
	EPSC_QUERY_CAP_VCB_LO	 = 0xfu,
	/* Number of VCBs in PCI hi BAR */
	EPSC_QUERY_CAP_VCB_HI	 = 0x10u,
	/* Number of PCBs mapped to lo BAR VCBs */
	EPSC_QUERY_CAP_PCB_LO	 = 0x11u,
	/* Number of PCBs mapped to hi BAR VCBs */
	EPSC_QUERY_CAP_PCB_HI	 = 0x12u,
	/*
	 * QP number for EPS-C to forward PMA responces to host
	 * psif_epsc_query_req.index = IB port number [1,2]
	 */
	EPSC_QUERY_PMA_REDIRECT_QP	 = 0x13u,
	/* uptime in seconds */
	EPSC_QUERY_FW_UPTIME	 = 0x14u,
	/* date the firmware was programmed in epoch time */
	EPSC_QUERY_FW_PROG_DATE	 = 0x15u,
	/* date the firmware was built in epoch time */
	EPSC_QUERY_FW_BUILD_DATE	 = 0x16u,
	/* current firmware image number (flash slot) */
	EPSC_QUERY_FW_CURR_IMG	 = 0x17u,
	/* oneshot firmware image number (flash slot) */
	EPSC_QUERY_FW_ONESHOT_IMG	 = 0x18u,
	/* autostart firmware image number (flash slot) */
	EPSC_QUERY_FW_AUTOSTART_IMG	 = 0x19u,
	/* bit field encoding why the FW image was booted */
	EPSC_QUERY_FW_START_CAUSE	 = 0x1au,
	/* firmware version */
	EPSC_QUERY_FW_VERSION	 = 0x1bu,
	/* Requester - number of bad response errors. */
	EPSC_QUERY_SQ_NUM_BRE	 = 0x1cu,
	/* Requester - number of bad response errors. */
	EPSC_QUERY_NUM_CQOVF	 = 0x1du,
	/* Requester - number of CQEs with status flushed in error. */
	EPSC_QUERY_SQ_NUM_WRFE	 = 0x1eu,
	/* Responder - number of CQEs with status flushed in error. */
	EPSC_QUERY_RQ_NUM_WRFE	 = 0x1fu,
	/* Responder - number of local access errors. */
	EPSC_QUERY_RQ_NUM_LAE	 = 0x20u,
	/* Responder - number of local protection errors. */
	EPSC_QUERY_RQ_NUM_LPE	 = 0x21u,
	/* Requester - number of local length errors. */
	EPSC_QUERY_SQ_NUM_LLE	 = 0x22u,
	/* Responder - number of local length errors. */
	EPSC_QUERY_RQ_NUM_LLE	 = 0x23u,
	/* Requester - number local QP operation error. */
	EPSC_QUERY_SQ_NUM_LQPOE	 = 0x24u,
	/* Responder - number local QP operation error. */
	EPSC_QUERY_RQ_NUM_LQPOE	 = 0x25u,
	/* Requester - number of NAK-Sequence Error received. */
	EPSC_QUERY_SQ_NUM_OOS	 = 0x26u,
	/* Responder - number of NAK-Sequence Error sent. */
	EPSC_QUERY_RQ_NUM_OOS	 = 0x27u,
	/* Requester - number of RNR nak retries exceeded errors. */
	EPSC_QUERY_SQ_NUM_RREE	 = 0x28u,
	/* Requester - number of transport retries exceeded errors. */
	EPSC_QUERY_SQ_NUM_TREE	 = 0x29u,
	/* Requester - number of NAK-Remote Access Error received. */
	EPSC_QUERY_SQ_NUM_ROE	 = 0x2au,
	/*
	 * Responder - number of NAK-Remote Access Error sent. NAK-Remote Operation
	 * Error on: 1. Malformed WQE: Responder detected a malformed Receive Queue
	 * WQE while processing the packet. 2. Remote Operation Error: Responder
	 * encountered an error, (local to the responder), which prevented it from
	 * completing the request.
	 */
	EPSC_QUERY_RQ_NUM_ROE	 = 0x2bu,
	/*
	 * Requester - number of NAK-Remote Access Error received. R_Key Violation:
	 * Responder detected an invalid R_Key while executing an RDMA Request.
	 */
	EPSC_QUERY_SQ_NUM_RAE	 = 0x2cu,
	/*
	 * Responder - number of NAK-Remote Access Error sent. R_Key Violation
	 * Responder detected an R_Key violation while executing an RDMA request.
	 */
	EPSC_QUERY_RQ_NUM_RAE	 = 0x2du,
	/*
	 * The number of UD packets silently discarded on the receive queue due to
	 * lack of receive descriptor.
	 */
	EPSC_QUERY_RQ_NUM_UDSDPRD	 = 0x2eu,
	/*
	 * The number of UC packets silently discarded on the receive queue due to
	 * lack of receive descriptor.
	 */
	EPSC_QUERY_RQ_NUM_UCSDPRD	 = 0x2fu,
	/*
	 * Requester - number of remote invalid request errors NAK-Invalid Request
	 * on: 1. Unsupported OpCode: Responder detected an unsupported OpCode. 2.
	 * Unexpected OpCode: Responder detected an error in the sequence of OpCodes,
	 * such as a missing Last packet.
	 */
	EPSC_QUERY_SQ_NUM_RIRE	 = 0x30u,
	/*
	 * Responder - number of remote invalid request errors. NAK may or may not be
	 * sent. 1. QP Async Affiliated Error: Unsupported or Reserved OpCode (RC,RD
	 * only): Inbound request OpCode was either reserved, or was for a function
	 * not supported by thisQP. (E.g. RDMA or ATOMIC on QP not set up for this).
	 * 2. Misaligned ATOMIC: VA does not point to an aligned address on an atomic
	 * operation. 3. Too many RDMA READ or ATOMIC Requests: There were more
	 * requests received and not ACKed than allowed for the connection. 4. Out of
	 * Sequence OpCode, current packet is First or Only: The Responder detected
	 * an error in the sequence of OpCodes; a missing Last packet. 5. Out of
	 * Sequence OpCode, current packet is not First or Only: The Responder
	 * detected an error in the sequence of OpCodes; a missing First packet. 6.
	 * Local Length Error: Inbound Send request message exceeded the responder's
	 * available buffer space. 7. Length error: RDMA WRITE request message
	 * contained too much or too little pay-load data compared to the DMA length
	 * advertised in the first or only packet. 8. Length error: Payload length
	 * was not consistent with the opcode: a: only is between 0 and PMTU bytes b:
	 * (first or middle) equals PMTU bytes c: last is between 1 byte and PMTU
	 * bytes 9. Length error: Inbound message exceeded the size supported by the
	 * CA port.
	 */
	EPSC_QUERY_RQ_NUM_RIRE	 = 0x31u,
	/* Requester - the number of RNR Naks received. */
	EPSC_QUERY_SQ_NUM_RNR	 = 0x32u,
	/* Responder - the number of RNR Naks sent. */
	EPSC_QUERY_RQ_NUM_RNR	 = 0x33u,
	/* twoshot firmware image number (flash slot) */
	EPSC_QUERY_FW_TWOSHOT_IMG	 = 0x34u,
	/* firmware type */
	EPSC_QUERY_FW_TYPE	 = 0x35u,
	/* firmware size */
	EPSC_QUERY_FW_SIZE	 = 0x36u,
	/* firmware slot size (available space for an image) */
	EPSC_QUERY_FW_SLOT_SIZE	 = 0x37u,
	/* version of boot loader that has started the application */
	EPSC_QUERY_BL_VERSION	 = 0x38u,
	/* boot loader build date in epoch time format */
	EPSC_QUERY_BL_BUILD_DATE	 = 0x39u,
	/* only used by EPSC_SET mark a PQP CQ ID as clean (WA bug 3769) */
	EPSC_QUERY_CLEAN_CQ_ID	 = 0x3au,
	/* Number of TSL supported by FW */
	EPSC_QUERY_CAP_TSL_TX	 = 0x3bu,
	EPSC_QUERY_CAP_TSL_RX	 = 0x3cu,
	/* Reset CBLD Diag counters. Only used by EPSC_SET */
	EPSC_QUERY_RESET_CBLD_DIAG_COUNTERS	 = 0x3du,
	/* Max QP index used since power-on or host reset - to optimize WA for HW bug 3251 */
	EPSC_QUERY_MAX_QP_USED	 = 0x3eu,
	/** the UF and QP where modify QP timed out ((uf << 32) | (qp)) */
	EPSC_QUERY_MODQP_TO_SOURCE	 = 0x3fu,
	/** the debug register when modify QP timed out */
	EPSC_QUERY_MODQP_TO_DEBUG	 = 0x40u,
	/** the bit vector containing the reasons for entering degraded mode */
	EPSC_QUERY_DEGRADED_CAUSE	 = 0x41u,
	/** CMPL spin set mode (safe = 1 fast = 0) */
	EPSC_QUERY_SPIN_SET_CONTROL	 = 0x42u,
	/** VPD MAC address */
	EPSC_QUERY_VPD_MAC	 = 0x43u,
	/** VPD part number */
	EPSC_QUERY_VPD_PART_NUMBER	 = 0x44u,
	/** VPD revision */
	EPSC_QUERY_VPD_REVISION	 = 0x45u,
	/** VPD serial number (big endian sub-string) - 8 byte offset in query index */
	EPSC_QUERY_VPD_SERIAL_NUMBER	 = 0x46u,
	/** VPD manufacturer = = Oracle Corporation - 8 byte offset in query index */
	EPSC_QUERY_VPD_MANUFACTURER	 = 0x47u,
	/** VPD product name (big endian sub-string) - 8 byte offset in query index */
	EPSC_QUERY_VPD_PRODUCT_NAME	 = 0x4bu,
	/** VPD Base GUID */
	EPSC_QUERY_VPD_BASE_GUID	 = 0x4eu,
	/** PSIF TSU SL and QoS mapping for for QP 0 - port number in query index */
	EPSC_QUERY_MAP_QP0_TO_TSL	 = 0x52u,
	/** PSIF TSU SL and QoS mapping for priv QP - port number in query index */
	EPSC_QUERY_MAP_PQP_TO_TSL	 = 0x48u,
	/** PSIF TSU SL and QoS mapping for IB SL 0-7 - port number in query index */
	EPSC_QUERY_MAP_SL_TO_TSL_LO	 = 0x49u,
	/** PSIF TSU SL and QoS mapping for IB SL 8-15 - port number in query index */
	EPSC_QUERY_MAP_SL_TO_TSL_HI	 = 0x4au,
	/** MMU static configuration of TA_UPPER_TWELVE bits (SPARC only) */
	EPSC_QUERY_TA_UPPER_TWELVE	 = 0x4cu,
	/** MMU static configuration of PA_UPPER_TWELVE bits (SPARC only) */
	EPSC_QUERY_PA_UPPER_TWELVE	 = 0x4du,
	/** Number of VFs configured - valid values limited to power-of-two.
	 * For BARE_METAL mode, number of VFs is -1 i.e. not applicable.
	 * PSIF_QUERY index as defined in psif_epsc_query_num_vfs_mode
	 * PSIF_SET   index = #VFs for next restart
	 */
	EPSC_QUERY_NUM_VFS	 = 0x4fu,
	/** Development debug only operation: SET and QUERY the TSU credit
	 * mode setup as defined by epsc_cli: cfg tsu_credit
	 */
	EPSC_QUERY_CREDIT_MODE	 = 0x50u,
	/** Query version on onboard CPLD (Titan only Other platforms will return EPSC_ENODATA) */
	EPSC_QUERY_CPLD_VERSION	 = 0x51u,
	/** Query portinfo on exernal port (defined in psif_epsc_query_external_port_info_t) */
	EPSC_QUERY_EXTERNAL_PORT_INFO	 = 0x53u,
	/* Query the HW revision of the board */
	EPSC_QUERY_HW_REVISION	 = 0x54u,
	/* EOF marker - must be last and highest in this enum type. */
	EPSC_QUERY_LAST	 = 0x55u,
	/* Padding out to required bits allocated */
	PSIF_EPSC_QUERY_OP_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_query_op [32 bits] */

/**
 * Valid values for struct psif_epsc_csr_update::opcode
 */
enum psif_epsc_csr_update_opcode {
	EPSC_UPDATE_OP_POLL	 = 0u,
	EPSC_UPDATE_OP_START,
	EPSC_UPDATE_OP_ERASE,
	EPSC_UPDATE_OP_WRITE,
	EPSC_UPDATE_OP_READ,
	EPSC_UPDATE_OP_STOP,
	EPSC_UPDATE_OP_SET,
	EPSC_UPDATE_OP_MAX,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_UPDATE_OPCODE_FIELD_MAX	 = 0xffffu
}; /* enum psif_epsc_csr_update_opcode [16 bits] */

/**
 * Flash slot numbers used by e.g. EPSC_QUERY::EPSC_QUERY_FW_CURR_IMG
 */
enum psif_epsc_flash_slot {
	EPSC_FLASH_SLOT_INVALID,
	EPSC_FLASH_SLOT_EPS_C_IMG_1,
	EPSC_FLASH_SLOT_EPS_C_IMG_2,
	EPSC_FLASH_SLOT_EPS_A_IMG,
	EPSC_FLASH_SLOT_BOOT_IMG,
	/* always last */
	EPSC_FLASH_SLOT_COUNT,
	/* Padding out to required bits allocated */
	PSIF_EPSC_FLASH_SLOT_FIELD_MAX	 = 0xffffu
}; /* enum psif_epsc_flash_slot [16 bits] */

/**
 * Valid values for struct psif_epsc_csr_update::u::set
 */
enum psif_epsc_update_set {
	EPSC_UPDATE_SET_INVALID,
	EPSC_UPDATE_SET_AUTOSTART_IMG,
	EPSC_UPDATE_SET_ONESHOT_IMG,
	EPSC_UPDATE_SET_TWOSHOT_IMG,
	EPSC_UPDATE_SET_IMG_VALID,
	/* Padding out to required bits allocated */
	PSIF_EPSC_UPDATE_SET_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_update_set [32 bits] */

/**
 * Opcodes for psif_epsc_csr_uf_ctrl_t::opcode
 */
enum psif_epsc_csr_uf_ctrl_opcode {
	EPSC_UF_CTRL_MMU_FLUSH,
	EPSC_UF_CTRL_GET_UF_USED_QP,
	EPSC_UF_CTRL_CLEAR_UF_USED_QP,
	/** For SMP {en dis}able is the flag param a bitvector for which ports
	 *  to update, 0x6 hence indicate P1 and P2.
	 */
	EPSC_UF_CTRL_SMP_ENABLE,
	EPSC_UF_CTRL_SMP_DISABLE,
	/** For Vlink {dis }connect is the flag param a bitvector for which ports
	 * to update, 0x6 hence indicate P1 and P2.
	 */
	EPSC_UF_CTRL_VLINK_CONNECT,
	EPSC_UF_CTRL_VLINK_DISCONNECT,
	/** Retrieve the highest QP number used by the given UF */
	EPSC_UF_CTRL_GET_HIGHEST_QP_IDX,
	/** Reset the highest QP number cache for the given UF */
	EPSC_UF_CTRL_RESET_HIGHEST_QP_IDX,
	/** Retrieve the current UF settings for SMP enable */
	EPSC_UF_CTRL_GET_SMP_ENABLE,
	/** Retrieve the current UF settings for vlink connect */
	EPSC_UF_CTRL_GET_VLINK_CONNECT,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_UF_CTRL_OPCODE_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_csr_uf_ctrl_opcode [32 bits] */

/**
 * \brief Host to VIMMA operation codes
 * \details
 * These operation codes are sent in the
 * \ref psif_epsc_csr_vimma_ctrl_t::opcode member
 * from the host to the mailbox thread in EPS-C in order to specify the
 * VIMMA request. In addition the operation
 * codes are used as a selector for the
 * \ref psif_epsc_csr_vimma_ctrl_t::u member of
 * psif_epsc_csr_vimma_ctrl_t in order to specify a particular
 * set of arguments if the request requires specific arguments.
 * \par
 * User of the VIMMA operation codes is the "PSIF SRIOV control API" library
 * running in Dom0 in user space. This library uses libsif to access the
 * mailbox. Requests are formed by using the VIMMA operation codes. Response
 * status is always delivered "inline" as return codes when the libsif API
 * returns from the mailbox operations.
 * Additional information retrieval can either be delivered "inline" as long
 * as space permits inside the mailbox response, OR responses
 * can also be extended by DMA-ing back response structures to pinned memory
 * in the library.
 * The DMA memory is prepared by the library before executing an opcode
 * that requires DMA for requested data.
 * \par
 * INLINE responses: Response data from VIMMA operation codes are delivered
 * via libsif to the "PSIF SRIOV control API" as two u64
 * parameters: "data" and "info".
 * These are carried by \ref psif_epsc_csr_rsp_t as part of mailbox response.
 * The encoding of the "data" and "info" responses depend on the VIMMA operation
 * code. For code using libsif library, the two u64 response codes "data"
 * and "info" is overlayed with the union
 * \ref psif_epsc_csr_vimma_ctrl_resp_inline_u,
 * and by using the opcode as a selector for the union members, the correct info
 * from the operation will be found.
 * \par
 * DMA responses: The requested data using DMA is delivered back to caller in
 * pinned memory of appropriate size. A pinned memory block of the maximum sized
 * response structure will do, and this can be obtained as
 * sizeof(psif_epsc_csr_vimma_ctrl_resp_dma_u) + appropriate extension for
 * for some variable arrays if those extend outside of
 * psif_epsc_csr_vimma_ctrl_resp_dma_uend of some union members.
 * The opcode just executed will be the selector for the union members.
 *
 * \par Width
 *      32 bit
 * \par Used in
 *      psif_epsc_csr_vimma_ctrl_t
 * \par Classification
 *      external
 *
 * \note
 * - In order to provide backward compatibility new codes must be added
 *   at the end of the enum. Deprecated codes can not be removed, but will instead
 *   be responded to with error codes if not supported anymore.
 */
enum psif_epsc_vimma_ctrl_opcode {
	/* no DMA.*/
	EPSC_VIMMA_CTRL_GET_VER_AND_COMPAT,
	/* DMA for resp. */
	EPSC_VIMMA_CTRL_GET_MISC_INFO,
	/* DMA for resp. */
	EPSC_VIMMA_CTRL_GET_GUIDS,
	/* DMA for resp. */
	EPSC_VIMMA_CTRL_GET_REG_INFO,
	/* DMA for resp. */
	EPSC_VIMMA_CTRL_GET_VHCA_STATS,
	/* no DMA. */
	EPSC_VIMMA_CTRL_SET_VFP_VHCA_REGISTER,
	/* no DMA. */
	EPSC_VIMMA_CTRL_SET_VFP_VHCA_DEREGISTER,
	/* no DMA or DMA if multiple UFs */
	EPSC_VIMMA_CTRL_SET_ADMIN_MODE,
	/* Padding out to required bits allocated */
	PSIF_EPSC_VIMMA_CTRL_OPCODE_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_vimma_ctrl_opcode [32 bits] */

/** \brief IB admin modes supported by VIMMA
 * \details
 * VIMMA IB admin mode defines the way the VF will be configured
 * by the fabric, either by SM alone, or by SM/VIMM combo.
 * \par Classification
 *     external
 */
enum psif_epsc_vimma_admmode {
	/** SM only mode is default and behaves according to IBTA standard */
	EPSC_VIMMA_CTRL_IB_ADM_MODE_SM_STANDARD,
	/** VFP mode requires support of a VIMM service in the fabric.
	 * VFP = VM Fabric Profile
	 */
	EPSC_VIMMA_CTRL_IB_ADM_MODE_VM_FABRIC_PROFILE,
	/* Padding out to required bits allocated */
	PSIF_EPSC_VIMMA_ADMMODE_FIELD_MAX	 = 0xffffu
}; /* enum psif_epsc_vimma_admmode [16 bits] */

/**
 * For response structure to EPSC_PMA_COUNTERS Op.
 * Common PMA counters for TSU and IBU layers.
 */
enum psif_epsc_csr_pma_counters_enum {
	/** Regular counters - IB Spec chapter 16.1.3.5 */
	EPSC_PMA_SYMBOL_ERR_CNTR	 = 0u,
	EPSC_PMA_LINK_ERR_RECOVERY_CNTR,
	EPSC_PMA_LINK_DOWNED_CNTR,
	EPSC_PMA_PORT_RCV_ERR,
	EPSC_PMA_PORT_RCV_REMOTE_PHYSICAL_ERR,
	EPSC_PMA_PORT_RCV_SWITCH_RELAY_ERR,
	EPSC_PMA_PORT_XMIT_DISCARD,
	EPSC_PMA_PORT_XMIT_CONSTRAINT_ERR,
	EPSC_PMA_PORT_RCV_CONSTRAINT_ERR,
	EPSC_PMA_LOCAL_LINK_INTEGRITY_ERR,
	EPSC_PMA_EXCESS_BUFF_OVERRUN_ERR,
	EPSC_PMA_VL15_DROPPED,
	/** Extended counters if Extended Width supported Regular otherwise */
	EPSC_PMA_PORT_XMIT_DATA,
	EPSC_PMA_PORT_RCV_DATA,
	EPSC_PMA_PORT_XMIT_PKTS,
	EPSC_PMA_PORT_RCV_PKTS,
	/**
	 * If ClassPortInfo:CapabilityMask.PortCountersXmitWaitSupported
	 * set to 1. IB Spec chapter 16.1.3.5
	 */
	EPSC_PMA_PORT_XMIT_WAIT,
	/** Strictly Extended counters - IB Spec Chapter 16.1.4.11 */
	EPSC_PMA_PORT_UNICAST_XMIT_PKTS,
	EPSC_PMA_PORT_UNICAST_RCV_PKTS,
	EPSC_PMA_PORT_MULTICAST_XMIT_PKTS,
	EPSC_PMA_PORT_MULTICAST_RCV_PKTS,
	/* IB Spec Chapter 16.1.4.1 */
	EPSC_PMA_PORT_LOCAL_PHYSICAL_ERR,
	/* Keep this in End */
	EPSC_PMA_COUNTERS_TOTAL,
	/* Padding out to required bits allocated */
	PSIF_EPSC_CSR_PMA_COUNTERS_ENUM_FIELD_MAX	 = 0x7fffffffu
}; /* enum psif_epsc_csr_pma_counters_enum [32 bits] */

/**
 * \brief PSIF atomic op requester config values.
 * \details
 * \par Width
 *      2 bit
 * \par Used in
 *      psif_epsc_csr_config member `atomic_support`
 * \par Classification
 *      driver
 */
enum psif_epsc_csr_atomic_op {
	/** PSIF requests atomic operations for IB and SQS. */
	PSIF_PCIE_ATOMIC_OP_BOTH	 = 0u,
	/** PSIF requests atomic operations for IB. */
	PSIF_PCIE_ATOMIC_OP_IB,
	/** PSIF requests atomic operations for SQS. */
	PSIF_PCIE_ATOMIC_OP_SQS,
	/** PSIF doesn't request atomic operations. */
	PSIF_PCIE_ATOMIC_OP_NONE
}; /* enum psif_epsc_csr_atomic_op [ 2 bits] */

/*
 * Completion notification states. Could take any of these values:
 * PSIF_CQ_UNARMED PSIF_CQ_ARMED_SE PSIF_CQ_ARMED_ALL PSIF_CQ_TRIGGERED
 */
enum psif_cq_state {
	PSIF_CQ_UNARMED	 = 0u,
	PSIF_CQ_ARMED_SE,
	PSIF_CQ_ARMED_ALL,
	PSIF_CQ_TRIGGERED
}; /* enum psif_cq_state [ 2 bits] */

/*
 * This is an indication if the RSS hash was generated with port inputs or
 * not.
 */
enum psif_rss_hash_source {
	RSS_WITHOUT_PORT	 = 0u,
	RSS_WITH_PORT
}; /* enum psif_rss_hash_source [ 1 bits] */

#if defined(HOST_LITTLE_ENDIAN)
#include "psif_hw_data_le.h"
#elif defined(HOST_BIG_ENDIAN)
#include "psif_hw_data_be.h"
#else
#error "Could not determine byte order in psif_hw_data.h !?"
#endif




#endif	/* _PSIF_HW_DATA_H */
