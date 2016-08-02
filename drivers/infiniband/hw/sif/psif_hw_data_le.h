/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_HW_DATA_H_LE
#define	_PSIF_HW_DATA_H_LE

/*
 * Context used by tsu_mmu when performing address translation. The structure
 * is follows: [63:56] st [55:55] no_snoop [54:53] tph [52:52] ro [51:12]
 * table_ptr [11:11] th [10:8] translation_type [7:4] page_size [3:3]
 * wr_access [2:0] table_level
 */
struct psif_mmu_cntx {
	/*
	 * XXX: Should this be enumerated? XXX: Make sure description is added when
	 * encoding is decided...
	 */
	u64	table_level:3;
	/* Set for write access. */
	u64	wr_access:1;
	/* Different supported page sizes. */
	enum psif_page_size	page_size:4;

	/*
	 * Translation types supported by the PSIF MMU. The modes are:
	 * MMU_PASS_THROUGH MMU_GVA2GPA_MODE, MMU_EPSA_MODE, MMU_EPSC_MODE
	 */
	enum psif_mmu_translation	translation_type:3;

	/* Indicates that the TPH field is valid for the PCIe request. */
	u64	th:1;
	/*
	 * This is bit [51:12] of the table pointer. The lower twelve bits are always
	 * set to zero. The pointer is pointing to a certain level in the page table
	 * structure. Only applicable if translation_type is set.
	 */
	u64	table_ptr:40;
	/* PCIe relaxed ordering. */
	u64	ro:1;
	/* PCIe TLP hints. */
	u64	tph:2;
	/* PCIe no snoop. */
	u64	ns:1;
	/* PCIe steering tag. */
	u64	st:8;
} PSIF_PACKED_ALIGNED; /* struct psif_mmu_cntx [ 8 byte] */

/* Descriptor for hardware updated portion of XRC receive queue. */
struct psif_xrq_hw { /* Subjected to copy and convert */
	/*
	 * If set to something greater than zero, event notification is armed. An
	 * Affiliated Synchronous Event will be sent when number of WQE are less than
	 * srq_lim.
	 */
	u32	srq_lim:14;
	/*
	 * Hardware modified index pointing to the head of the receive queue. TSU is
	 * using this to find the address of the receive queue entry.
	 */
	u32	head_indx:14;
	/* This is the shift value to use to find start of the receive queue element. */
	u32	extent_log2:4;
	/* pd(24[0] bits)Protection domain. */
	u32	pd:24;
	/* This is indicating how many scatter entries are valid. */
	u32	scatter:4;
	/* Reserved */
	u32	noname:1;
	/* The shared receive queue is in error. */
	u32	srq_err:1;
	/* This is a shared receive queue. This is always set for XRCSRQs. */
	u32	srq:1;
	/*
	 * Do not evict this entry if this bit is set. There can only be a fixed
	 * number of descriptors with this bit set. XXX: Should this be used as a
	 * hint, or should it be fixed?
	 */
	u32	sticky:1;
	/* Inlined rq : struct psif_rq_no_pad (256 bits) */
	/* Base address for the receive queue in host memory. */
	u64	base_addr;
	struct psif_mmu_cntx	mmu_cntx;
	/* Completion queue to use for the incoming packet. */
	u64	cqd_id:24;
	/*
	 * XRC domain used to check if this descriptor can be used for the incoming
	 * packet.
	 */
	u64	xrc_domain:24;
	/* Reserved */
	u64	noname1:7;
	/* The desciptor is valid. */
	u64	valid:1;
	/*
	 * Pre-fetch threshold (clog2) indicating when to read the software portion
	 * of the descriptor. If there are less entries than indicated by this
	 * threshold, the software portion of the descriptor must be read.
	 */
	u64	prefetch_threshold_log2:4;
	/*
	 * Log2 size of the receive queue. Maximum number of entries in the receive
	 * queue. This is used for calculating when to wrap the head and tail
	 * indexes.
	 */
	u64	size_log2:4;
} PSIF_PACKED_ALIGNED; /* struct psif_xrq_hw [32 byte] */

/* Temp.definition of Shared receive queue content */
struct psif_xrq { /* Subjected to copy and convert */
	/* Content pt. not defined in ASIC XML */
	u64	something_tbd;
} PSIF_PACKED_ALIGNED; /* struct psif_xrq [ 8 byte] */

struct psif_vlan_union_struct {
	/* Reserved */
	u32	noname:20;
	/* VLAN priority. */
	u32	vlan_pri:4;
} PSIF_PACKED; /* struct psif_vlan_union_struct [ 3 byte] */

/*
 * Union between the CQ descriptor ID and VLAN pri. The CQ desc id is only
 * used for privileged requests, and the vlan_pri is only used for EoIB
 * offloading.
 */
union psif_cq_desc_vlan_pri {
	/*
	 * This is only used for privileged requests. Completion queue descriptor
	 * index where completions for privileged requests end up. This index points
	 * to the completion queue to be used with this work request.
	 */
	u32	cqd_id:24;
	/* VLAN priority. */
	struct psif_vlan_union_struct	vlan_pri;
} PSIF_PACKED; /* union psif_cq_desc_vlan_pri [ 3 byte] */

/*
 * Generic header for work requests to PSIF. This is present for all packet
 * types.
 */
struct psif_wr_common {
	/*
	 * Send queue sequence number. Used to map request to a particular work
	 * request in the send queue.
	 */
	u16	sq_seq;
	/* Length (number of bytes of valid data in the collect payload buffer). */
	u16	collect_length:9;
	/*
	 * High Bandwidth/Low Latency BAR. The QoSL must be matched against the QoSL
	 * in the QP State. If it is unequal, the QP should be in error.
	 */
	enum psif_tsu_qos	tsu_qosl:1;

	/* Only applicable to UD. This is an indication that AHA should be used. */
	enum psif_use_ah	ud_pkt:1;

	/* Port number to use for QP0/1 packets. This field is ignored if not QP0/1. */
	enum psif_port	port:1;

	/*
	 * The TSL (Tsu SL) must be matched against the TSL in the QP State (XXX: or
	 * in the AHA?). If it is unequal, the QP should be put in error.
	 */
	u16	tsu_sl:4;
	/*
	 * QP sending this request. XXX: Should name be own_qp_num as defined in QP
	 * state?
	 */
	u32	local_qp:24;
	/* Indicates shat type of request this is. */
	enum psif_wr_type	op:8;

	/* Union between VLAN priority and CQ descriptor ID. */
	union psif_cq_desc_vlan_pri	cq_desc_vlan_pri_union;
	/* UF used for all EPS-C QP0/1 packets. This field is ignored otherwise. */
	u64	srcuf:6;
	/* Fence indicator. */
	u64	fence:1;
	/* Completion notification identifier. */
	u64	completion:1;
	/*
	 * EPS tag - used by EPS to associate process and work request. This field is
	 * not used by non-EPS work requests.
	 */
	u64	eps_tag:16;
	/* Reserved */
	u64	noname:2;
	/* UF used for DR loopback packets. This field is ignored otherwise. */
	u64	destuf:6;
	/* Number of SGL entries are valid for this request. */
	u64	num_sgl:4;
	/* L4 checksum enabled when set. This is used for EoIB and IPoIB packets. */
	u64	l4_checksum_en:1;
	/* L3 checksum enabled when set. This is used for EoIB and IPoIB packets. */
	u64	l3_checksum_en:1;
	/* Dynamic MTU is enabled for this work request. */
	u64	dynamic_mtu_enable:1;
	/* Solicited event bit to be set in IB packet. */
	u64	se:1;
	/* Info: Edge padding added (for endian convert) */
	u32	space1;
	/*
	 * Checksum used for data protection and consistency between work request and
	 * QP state.
	 */
	u32	checksum;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_common [24 byte] */

struct psif_wr_qp {
	/* Q-Key for the remote node. */
	u32	qkey;
	/* QP number for the remote node. */
	u32	remote_qp:24;
	/* Reserved */
	u32	noname:8;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_qp [ 8 byte] */

/* Local address structure. */
struct psif_wr_local {
	/* Host address. */
	u64	addr;
	/* This is the total length of the message. */
	u32	length;
	/* Local key used to validate the memory region this address is pointing to. */
	u32	lkey;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_local [16 byte] */

struct psif_wr_addr {
	/* Index into the Address Handle Array. */
	u32	ah_indx:24;
	/* Reserved */
	u32	noname:8;
} PSIF_PACKED; /* struct psif_wr_addr [ 4 byte] */

/*
 * This header is used for IB send operations. The header is a union and
 * consists of either a connected mode header or a datagram mode header. The
 * following opcodes are using this header: PSIF_WR_SEND PSIF_WR_SEND_IMM
 * PSIF_WR_SPECIAL_QP_SEND PSIF_WR_QP0_SEND_DR_XMIT
 * PSIF_WR_QP0_SEND_DR_LOOPBACK PSIF_WR_EPS_SPECIAL_QP_SEND
 * PSIF_WR_EPS_QP0_SEND_DR_XMIT PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK PSIF_WR_LSO
 */
struct psif_wr_send_header_ud {
	struct psif_wr_qp	qp;
	/* Header used for IB send commands using UD mode. */
	/* Inlined ud : struct psif_wr_ud_send (224 bits) */
	struct psif_wr_local	local_addr;
	/*
	 * Max segment size used for PSIF_WR_LSO. This field is not used for other
	 * operations.
	 */
	u32	mss:14;
	/* Reserved */
	u32	noname:18;
	struct psif_wr_addr	remote_addr;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_send_header_ud [32 byte] */

/*
 * This header is used for IB send operations. The header is a union and
 * consists of either a connected mode header or a datagram mode header. The
 * following opcodes are using this header: PSIF_WR_SEND PSIF_WR_SEND_IMM
 * PSIF_WR_SPECIAL_QP_SEND PSIF_WR_QP0_SEND_DR_XMIT
 * PSIF_WR_QP0_SEND_DR_LOOPBACK PSIF_WR_EPS_SPECIAL_QP_SEND
 * PSIF_WR_EPS_QP0_SEND_DR_XMIT PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK PSIF_WR_LSO
 */
struct psif_wr_send_header_uc_rc_xrc {
	struct psif_wr_local	local_addr;
	/* Header used with IB send commands using connected mode. */
	/* Inlined uc_rc_xrc : struct psif_wr_cm (224 bits) */
	/*
	 * Reserved. XXX: FIX ME - calculation of this field based on constant, not
	 * psif_wr_local_address_header as it should.
	 */
	u32	reserved10[3];
	/*
	 * Max segment size used for PSIF_WR_LSO. This field is not used for other
	 * operations.
	 */
	u32	mss:14;
	/* Reserved */
	u32	noname:18;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_send_header_uc_rc_xrc [32 byte] */

/*
 * This header is used for IB send operations. The header is a union and
 * consists of either a connected mode header or a datagram mode header. The
 * following opcodes are using this header: PSIF_WR_SEND PSIF_WR_SEND_IMM
 * PSIF_WR_SPECIAL_QP_SEND PSIF_WR_QP0_SEND_DR_XMIT
 * PSIF_WR_QP0_SEND_DR_LOOPBACK PSIF_WR_EPS_SPECIAL_QP_SEND
 * PSIF_WR_EPS_QP0_SEND_DR_XMIT PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK PSIF_WR_LSO
 */
union psif_wr_send_header {
	/* Header used for IB send commands using UD mode. */
	struct psif_wr_send_header_ud	ud;
	/* Header used with IB send commands using connected mode. */
	struct psif_wr_send_header_uc_rc_xrc	uc_rc_xrc;
} PSIF_PACKED; /* union psif_wr_send_header [32 byte] */

/* Remote address structure. */
struct psif_wr_remote {
	/* Address to the remote side. */
	u64	addr;
	/* For RDMA and DM this is the length to add to dmalen in RETH of IB packet. */
	u32	length;
	/*
	 * Remote key used to validate the memory region the associated address is
	 * pointing to.
	 */
	u32	rkey;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_remote [16 byte] */

/*
 * This header is used for RDMA type operations. The following opcodes are
 * using this header: PSIF_WR_RDMA_WR PSIF_WR_RDMA_WR_IMM PSIF_WR_RDMA_RD
 * PSIF_WR_CMP_SWAP PSIF_WR_FETCH_ADD PSIF_WR_MASK_CMP_SWAP
 * PSIF_WR_MASK_FETCH_ADD
 */
struct psif_wr_rdma {
	struct psif_wr_local	local_addr;
	struct psif_wr_remote	remote_addr;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_rdma [32 byte] */

/* Send completion ID. */
struct psif_send_completion_id {
	/*
	 * This field is only valid for ring buffer send completions (proxy type send
	 * requests). In all other cases this field is ignored.
	 */
	u16	eps_tag;
	/*
	 * Send queue sequence number. This is used to map the completion back to a
	 * request in the send queue.
	 */
	u16	sq_seq_num;
	/*
	 * Completion queue sequence number for the completion queue being re-armed.
	 * This is going into the completion for the privileged request.
	 */
	u32	sequence_number;
} PSIF_PACKED_ALIGNED; /* struct psif_send_completion_id [ 8 byte] */

/* Event completion ID. */
struct psif_event_completion_id {
	/* Completion queue descriptor ID which is the source of the event. */
	u64	cq_id:24;
	/* Reserved */
	u64	noname:40;
} PSIF_PACKED_ALIGNED; /* struct psif_event_completion_id [ 8 byte] */

/* Union containing a send or receive completion ID. */
union psif_completion_wc_id {
	/*
	 * Receive Queue completion ID. This is the receive queue entry ID found as
	 * part of receive queue entry.
	 */
	u64	rq_id;
	/*
	 * Send Queue completion ID. This contain the send queue sequence number. In
	 * ring buffer send completions this field also conatain a valid EPS tag.
	 */
	struct psif_send_completion_id	sq_id;
	/* Completion queue descriptor ID which is the source of the event. */
	struct psif_event_completion_id	ecq_id;
} PSIF_PACKED; /* union psif_completion_wc_id [ 8 byte] */

/*
 * Union used for descriptor types used when operations on the descriptors
 * themselves are done, like invalidation, resizing etc. It can the take the
 * follwing types: rq_id xrq_id cq_id target_qp
 */
union psif_descriptor_union {
	/*
	 * Receive queue descriptor used for the following request:
	 * PSIF_WR_SET_SRQ_LIM: this is the receive queue to set the new limit for.
	 * PSIF_WR_INVALIDATE_RQ: this is the receive queue to invalidate/flush from
	 * the descriptor cache.
	 */
	u32	rq_id:24;
	/*
	 * XRCSRQ descriptor used for the following request: PSIF_WR_SET_XRCSRQ_LIM:
	 * this is the XRCSRQ to set the new limit for. PSIF_WR_INVALIDATE_XRCSRQ:
	 * this is the XRCSRQ to invalidate/flush from the descriptor cache.
	 */
	u32	xrq_id:24;
	/*
	 * Completion queue descriptor ID used when operations are done on the CQ
	 * descriptor, no completion is sent to this CQ. This field is valid for
	 * PSIF_WR_INVALIDATE_CQ, PSIF_WR_RESIZE_CQ, PSIF_WR_REQ_CMPL_NOTIFY,
	 * PSIF_WR_CMPL_NOTIFY_RCVD, PSIF_WR_REARM_CMPL_EVENT.
	 */
	u32	cq_id:24;
	/*
	 * Target QP for PSIF_WR_INVALIDATE_SGL_CACHE command. This field is also
	 * valid for PSIF_WR_GENERATE_COMPLETION, then this is the QP number put in
	 * the completion.
	 */
	u32	target_qp:24;
} PSIF_PACKED; /* union psif_descriptor_union [ 3 byte] */

/*
 * This header is used for privileged operations. The following opcodes are
 * using this header: PSIF_WR_INVALIDATE_LKEY PSIF_WR_INVALIDATE_RKEY
 * PSIF_WR_INVALIDATE_BOTH_KEYS PSIF_WR_INVALIDATE_TLB PSIF_WR_RESIZE_CQ
 * PSIF_WR_SET_SRQ_LIM PSIF_WR_SET_XRCSRQ_LIM PSIF_WR_REQ_CMPL_NOTIFY
 * PSIF_WR_CMPL_NOTIFY_RCVD PSIF_WR_REARM_CMPL_EVENT
 * PSIF_WR_GENERATE_COMPLETION PSIF_WR_INVALIDATE_RQ PSIF_WR_INVALIDATE_CQ
 * PSIF_WR_INVALIDATE_XRCSRQ PSIF_WR_INVALIDATE_SGL_CACHE
 */
struct psif_wr_su {
	/* PSIF_WR_GENERATE_COMPLETION: This is the WC ID to put in the completion. */
	union psif_completion_wc_id	wc_id;
	/*
	 * PSIF_WR_INVALIDATE_TLB: this is the address vector to invalidate in the
	 * TLB. PSIF_WR_RESIZE_CQ: this is the new address of the CQ.
	 */
	u64	addr;
	/*
	 * PSIF_WR_INVALIDATE_TLB: this is the length for invalidate in the TLB. Only
	 * the lower 16 bits are valid for specifying length of TLB invalidation.
	 * PSIF_WR_RESIZE_CQ: this is the new length of the CQ.
	 */
	u32	length;
	/*
	 * PSIF_WR_INVALIDATE_LKEY: key to invalidate/flush from the DMA VT cache.
	 * PSIF_WR_INVALIDATE_RKEY: key to invalidate/flush from the DMA VT cache.
	 * PSIF_WR_INVALIDATE_BOTH_KEYS: key to invalidate/flush from the DMA VT
	 * cache. PSIF_WR_INVALIDATE_TLB: this is the address vector to invalidate in
	 * the TLB.
	 */
	u32	key;
	union psif_descriptor_union	u2;
	/*
	 * This field is valid for PSIF_WR_GENERATE_COMPLETION. This is the
	 * completion status to put in the completion.
	 */
	enum psif_wc_status	completion_status:8;

	/*
	 * This field is valid for PSIF_WR_GENERATE_COMPLETION. This is the opcode
	 * going into the completion.
	 */
	enum psif_wc_opcode	completion_opcode:8;

	/* Reserved */
	u64	noname:10;
	/* This is used by the PSIF_WR_SET_SRQ_LIM request. */
	u64	srq_lim:14;
} PSIF_PACKED_ALIGNED; /* struct psif_wr_su [32 byte] */

/* SEND RDMA DM ATOMIC or PRIVILEGED data - depending on opcode. */
union psif_wr_details {
	union psif_wr_send_header	send;
	struct psif_wr_rdma	rdma;
	struct psif_wr_rdma	atomic;
	struct psif_wr_su	su;
} PSIF_PACKED; /* union psif_wr_details [32 byte] */

struct psif_wr_xrc {
	/* Descriptor index for XRC SRQ. */
	u32	xrqd_id:24;
	/* Reserved */
	u32	noname:8;
} PSIF_PACKED; /* struct psif_wr_xrc [ 4 byte] */

/* PSIF work request. */
struct psif_wr { /* Subjected to copy and convert */
	/*
	 * Send queue sequence number. Used to map request to a particular work
	 * request in the send queue.
	 */
	u16	sq_seq;
	/* Length (number of bytes of valid data in the collect payload buffer). */
	u16	collect_length:9;
	/*
	 * High Bandwidth/Low Latency BAR. The QoSL must be matched against the QoSL
	 * in the QP State. If it is unequal, the QP should be in error.
	 */
	enum psif_tsu_qos	tsu_qosl:1;

	/* Only applicable to UD. This is an indication that AHA should be used. */
	enum psif_use_ah	ud_pkt:1;

	/* Port number to use for QP0/1 packets. This field is ignored if not QP0/1. */
	enum psif_port	port:1;

	/*
	 * The TSL (Tsu SL) must be matched against the TSL in the QP State (XXX: or
	 * in the AHA?). If it is unequal, the QP should be put in error.
	 */
	u16	tsu_sl:4;
	/*
	 * QP sending this request. XXX: Should name be own_qp_num as defined in QP
	 * state?
	 */
	u32	local_qp:24;
	/* Indicates shat type of request this is. */
	enum psif_wr_type	op:8;

	/* Inlined common : struct psif_wr_common (192 bits) */
	/* Union between VLAN priority and CQ descriptor ID. */
	union psif_cq_desc_vlan_pri	cq_desc_vlan_pri_union;
	/* UF used for all EPS-C QP0/1 packets. This field is ignored otherwise. */
	u64	srcuf:6;
	/* Fence indicator. */
	u64	fence:1;
	/* Completion notification identifier. */
	u64	completion:1;
	/*
	 * EPS tag - used by EPS to associate process and work request. This field is
	 * not used by non-EPS work requests.
	 */
	u64	eps_tag:16;
	/* Reserved */
	u64	noname:2;
	/* UF used for DR loopback packets. This field is ignored otherwise. */
	u64	destuf:6;
	/* Number of SGL entries are valid for this request. */
	u64	num_sgl:4;
	/* L4 checksum enabled when set. This is used for EoIB and IPoIB packets. */
	u64	l4_checksum_en:1;
	/* L3 checksum enabled when set. This is used for EoIB and IPoIB packets. */
	u64	l3_checksum_en:1;
	/* Dynamic MTU is enabled for this work request. */
	u64	dynamic_mtu_enable:1;
	/* Solicited event bit to be set in IB packet. */
	u64	se:1;
	/* Immediate data is only valid when indicated by the opcode. */
	u64	imm:32;
	/*
	 * Checksum used for data protection and consistency between work request and
	 * QP state.
	 */
	u32	checksum;
	union psif_wr_details	details;
	/* Manually added spacing to pad out wr */
	u32	space2;
	struct psif_wr_xrc	xrc_hdr;
} PSIF_PACKED_ALIGNED; /* struct psif_wr [64 byte] */

/** \brief Table of TSU SL and QoS mappings
 *  \details
 *  Driver queries EPS-C for mapping of privileged QP and Infinband SL to
 *  TSU SL and QoS. These values then need to be applied in QP and WR
 *  as well as selecting hi or low PCIe BAR VCB (tqos) to obtain PSIF TSU
 *  internal traffic separation.
 */
struct psif_tsl_map {
	u16	noname:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m0_tqos:1;

	u16	noname1:2;
	/* PSIF TSU SL assignmnet */
	u16	m0_tsl:4;
	/* Inlined m0 : struct psif_tsl_map_entry (8 bits) */
	u16	noname2:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m1_tqos:1;

	u16	noname3:2;
	/* PSIF TSU SL assignmnet */
	u16	m1_tsl:4;
	/* Inlined m1 : struct psif_tsl_map_entry (8 bits) */
	u16	noname4:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m2_tqos:1;

	u16	noname5:2;
	/* PSIF TSU SL assignmnet */
	u16	m2_tsl:4;
	/* Inlined m2 : struct psif_tsl_map_entry (8 bits) */
	u16	noname6:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m3_tqos:1;

	u16	noname7:2;
	/* PSIF TSU SL assignmnet */
	u16	m3_tsl:4;
	/* Inlined m3 : struct psif_tsl_map_entry (8 bits) */
	u16	noname8:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m4_tqos:1;

	u16	noname9:2;
	/* PSIF TSU SL assignmnet */
	u16	m4_tsl:4;
	/* Inlined m4 : struct psif_tsl_map_entry (8 bits) */
	u16	noname10:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m5_tqos:1;

	u16	noname11:2;
	/* PSIF TSU SL assignmnet */
	u16	m5_tsl:4;
	/* Inlined m5 : struct psif_tsl_map_entry (8 bits) */
	u16	noname12:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m6_tqos:1;

	u16	noname13:2;
	/* PSIF TSU SL assignmnet */
	u16	m6_tsl:4;
	/* Inlined m6 : struct psif_tsl_map_entry (8 bits) */
	u16	noname14:1;
	/* PSIF TSU QoS selection */
	enum psif_tsu_qos	m7_tqos:1;

	u16	noname15:2;
	/* PSIF TSU SL assignmnet */
	u16	m7_tsl:4;
	/* Inlined m7 : struct psif_tsl_map_entry (8 bits) */
} PSIF_PACKED_ALIGNED; /* struct psif_tsl_map [ 8 byte] */

/* Temp.definition of content */
struct psif_sq_tvl {
	/* Content pt. not defined in ASIC XML */
	u64	something_tbd[2];
} PSIF_PACKED_ALIGNED; /* struct psif_sq_tvl [16 byte] */

/* This is the portion of the descriptor which is updated by software. */
struct psif_sq_sw { /* Subjected to copy and convert */
	/* Info: Edge padding added (for endian convert) */
	u32	space3;
	/*
	 * Index to where elements are added to the send queue by SW. SW is
	 * responsibel for keeping track of how many entries there are in the send
	 * queue. I.e. SW needs to keep track of the head_index so it doesn't
	 * overwrite entries in the send queue which is not yet completed.
	 */
	u16	tail_indx;
	/* Reserved */
	u16	noname:16;
} PSIF_PACKED_ALIGNED; /* struct psif_sq_sw [ 8 byte] */

/* Temp.definition of content */
struct psif_sq_rspq {
	/* Content pt. not defined in ASIC XML */
	u64	something_tbd[52];
} PSIF_PACKED_ALIGNED; /* struct psif_sq_rspq [416 byte] */

/* Hardware structure indicating what is the next QP. */
struct psif_next {
	/*
	 * If all high, the next pointer is null. If next_null == 1, it is transport
	 * timer on evicted QP
	 */
	u32	next_null:8;
	/* QP number for the next QP to be processed. */
	u32	next_qp_num:24;
} PSIF_PACKED; /* struct psif_next [ 4 byte] */

/* Descriptor used by the send queue scheduler to operate on the send queue. */
struct psif_sq_hw { /* Subjected to copy and convert */
	u16	u_1;
	/*
	 * Send queue sequence number used by the SQS to maintain ordering and keep
	 * track of where which send queue elements to fetch. This field is not in
	 * sync with the field in qp_t. This number is typically a little bit before
	 * the number in the qp_t as SQS has to fetch the elements from host memory.
	 * This is also used as tail_index when checking if there are more elements
	 * in the send queue.
	 */
	u16	last_seq;
	/* QP and UF to be processed next. */
	struct psif_next	sq_next;
	/* Maximum inline data length supported by this send queue. */
	u32	sq_max_inline:9;
	/* Maximum number of SGEs supported by this send queue. */
	u32	size_log2:4;
	/* Maximum number of SGEs supported by this send queue. */
	u32	sq_max_sge:5;
	/*
	 * The size between each work queue element in the send queue. This is the
	 * shift value to use in order to find the start of a work queue element.
	 */
	u32	extent_log2:5;
	/*
	 * Indication if this QP is configured as a low latency or high throughput
	 * quality of service level.
	 */
	u32	qos:1;
	/*
	 * Timestamp qualifier. This bit is set when retry is entered to the queue
	 * and clear when the timestamp has expired.
	 */
	u32	sq_timestamp_valid:1;
	/*
	 * Done[0] is set when the last SQ WR is processed (sq_sequence_number ==
	 * tail_indx). When done[0] is set, SQS only process the SQ WR when
	 * sq_sequence_number != tail_index. Done[1] is set when done[0] is set and
	 * sq_sequence_number == tail_index.
	 */
	u32	sq_done:2;
	/*
	 * This bit is set through the doorbell. SW should check this bit plus
	 * psif_next = null to ensure SW can own the SQ descriptor.
	 */
	u32	destroyed:1;
	/* Reserved */
	u32	noname:4;
	u32	u_2;
	/* The base address to the send queue. */
	u64	base_addr;
	/* The MMU context used to get the send queue. */
	struct psif_mmu_cntx	mmu_cntx;
} PSIF_PACKED_ALIGNED; /* struct psif_sq_hw [32 byte] */

/* Temp.definition of Send queue content */
struct psif_sq_entry { /* Subjected to copy and convert */
	/* Content pt. not defined in ASIC XML */
	struct psif_wr	wr;
	u64	payload[32];
} PSIF_PACKED_ALIGNED; /* struct psif_sq_entry [320 byte] */

/**
 * SQS ring buffer entry
 */
struct psif_sq_ring {
	u64	something;
} PSIF_PACKED_ALIGNED; /* struct psif_sq_ring [ 8 byte] */

/* Temp. definition of the send queue entry cache for the completion block.
 * The only info used by the driver is the size of this struct,
 * when allocating space for the cache in memory:
 */
struct psif_sq_cmpl {
	/* Content pt. not defined in ASIC XML */
	u64	payload[8];
} PSIF_PACKED_ALIGNED; /* struct psif_sq_cmpl [64 byte] */

/* Recveive queue scatter entry. */
struct psif_rq_scatter {
	/* Base address for this scatter element. */
	u64	base_addr;
	/* L-Key to be used for this scatter element. */
	u32	lkey;
	/* Length of scatter element. */
	u32	length;
} PSIF_PACKED_ALIGNED; /* struct psif_rq_scatter [16 byte] */

/* Data type for TSU_RQH_QP_BASE_ADDR - rq scratch pad
 * Layout as defined by struct psif_rq_entry
 */
struct psif_rqsp {
	/*
	 * Receive queue entry ID. This is added to the receive completion using this
	 * receive queue entry.
	 */
	u64	rqe_id;
	/* Scatter entries for this receive queue element. */
	struct psif_rq_scatter	scatter[16];
} PSIF_PACKED_ALIGNED; /* struct psif_rqsp [264 byte] */

/* This is the part of the descriptor which is updated by SW (user space). */
struct psif_rq_sw { /* Subjected to copy and convert */
	/* Info: Edge padding added (for endian convert) */
	u32	space4;
	/* Software modified index pointing to the tail reecive entry in host memory. */
	u32	tail_indx:14;
	/* Reserved */
	u32	noname:18;
} PSIF_PACKED_ALIGNED; /* struct psif_rq_sw [ 8 byte] */

struct psif_rq_hw { /* Subjected to copy and convert */
	/*
	 * If set to something greater than zero, event notification is armed. An
	 * Affiliated Synchronous Event will be sent when number of WQE are less than
	 * srq_lim.
	 */
	u32	srq_lim:14;
	/*
	 * Hardware modified index pointing to the head of the receive queue. TSU is
	 * using this to find the address of the receive queue entry.
	 */
	u32	head_indx:14;
	/* This is the shift value to use to find start of the receive queue element. */
	u32	extent_log2:4;
	/* pd(24[0] bits)Protection domain. */
	u32	pd:24;
	/* This is indicating how many scatter entries are valid. */
	u32	scatter:4;
	/* Reserved */
	u32	noname:1;
	/* The shared receive queue is in error. */
	u32	srq_err:1;
	/* This is a shared receive queue. This is always set for XRCSRQs. */
	u32	srq:1;
	/*
	 * Do not evict this entry if this bit is set. There can only be a fixed
	 * number of descriptors with this bit set. XXX: Should this be used as a
	 * hint, or should it be fixed?
	 */
	u32	sticky:1;
	/* Hardware updated portion of descriptor. */
	/* Inlined hw_no_pad : struct psif_rq_no_pad (256 bits) */
	/* Base address for the receive queue in host memory. */
	u64	base_addr;
	struct psif_mmu_cntx	mmu_cntx;
	/* Reserved */
	u64	noname1:55;
	/* The desciptor is valid. */
	u64	valid:1;
	/*
	 * Pre-fetch threshold (clog2) indicating when to read the software portion
	 * of the descriptor. If there are less entries than indicated by this
	 * threshold, the software portion of the descriptor must be read.
	 */
	u64	prefetch_threshold_log2:4;
	/*
	 * Log2 size of the receive queue. Maximum number of entries in the receive
	 * queue. This is used for calculating when to wrap the head and tail
	 * indexes.
	 */
	u64	size_log2:4;
} PSIF_PACKED_ALIGNED; /* struct psif_rq_hw [32 byte] */

/* A receive queue entry structure contianing scatter entries. */
struct psif_rq_entry { /* Subjected to copy and convert */
	/*
	 * Receive queue entry ID. This is added to the receive completion using this
	 * receive queue entry.
	 */
	u64	rqe_id;
	/* Scatter entries for this receive queue element. */
	struct psif_rq_scatter	scatter[16];
} PSIF_PACKED_ALIGNED; /* struct psif_rq_entry [264 byte] */

/* This is the portion of the descriptor which is updated by software. */
struct psif_rb_sw { /* Subjected to copy and convert */
	/* Info: Edge padding added (for endian convert) */
	u32	space5;
	/* Index to ring buffer elements added by SW. */
	u32	head_indx;
} PSIF_PACKED_ALIGNED; /* struct psif_rb_sw [ 8 byte] */

/*
 * Descriptor entry for a ring buffer. This entry is used to address into the
 * ring buffer and write the correct entries. This structure is the hardware
 * updateable part of the RB descriptor.
 */
struct psif_rb_hw { /* Subjected to copy and convert */
	/* Index to ring buffer elements to be consumed by HW. */
	u32	tail_indx;
	/*
	 * Log2 size of the ring buffer. The entries are specified as 64B entities.
	 * The number indicates when the tail_index should wrap. If one message is
	 * running over the edge, the message is stored in consecutive entries
	 * outside the ring buffer. max_message_size additional space is added to the
	 * edge of the buffer.
	 */
	u32	size_log2:5;
	/*
	 * Interrupt channel associated with the event queue. In the PSIF design the
	 * event queues are one to one with interrupt channel.
	 */
	u32	int_channel:7;
	/* Reserved */
	u32	noname:11;
	/* rb_size_log2(5[0] bits)Log2 size of the ring buffer. */
	u32	max_size_log2:5;
	/* The descriptor is valid. */
	u32	valid:1;
	/*
	 * When this bit is set, the solicited bit is used in order to send events to
	 * event queues.
	 */
	u32	armed:1;
	/*
	 * This functionality is not valid unless armed is set. If set and incoming
	 * message has SE bit set, an event should be generated to the event queue
	 * indicated by eventq_dscr_id. If not set, an event is sent reqardless of
	 * the value of the SE bit in the incoming message.
	 */
	u32	filter_se:1;
	/* Do not evict this entry if this bit is set. */
	u32	sticky:1;
	struct psif_mmu_cntx	mmu_cntx;
	/*
	 * VA or PA of the base of the completion queue. If PA the MMU context above
	 * will be a bypass context. Updated by software. The head and tail pointers
	 * can be calculated by the following calculations: Address = base_ptr +
	 * (head * 64B ) Head Pointer and Tail Pointer will use the same MMU context
	 * as the base, and all need to be VA from one address space, or all need to
	 * be PA. In typical use, to allow direct user access to the head and tail
	 * pointer VAs are used.
	 */
	u64	base_addr;
	/* XXX: should this be defined as rb_sequence_number_t? */
	u32	sequence_number;
	/* pd(24[0] bits)Protection domain. */
	u32	pd:24;
	/*
	 * Pre-fetch threshold (clog2) indicating when to read the software portion
	 * of the descriptor. If there are less entries than indicated by this
	 * threshold, the software portion of the descriptor must be read.
	 */
	u32	prefetch_threshold_log2:5;
	/* Reserved */
	u32	noname1:3;
} PSIF_PACKED_ALIGNED; /* struct psif_rb_hw [32 byte] */

/*
 * Ring buffer header. A ring buffer header is preceding payload data when
 * written to host memory. The full message with RB header and payload data
 * is padded out to become a multiple of 64 bytes. The last 4 bytes of every
 * 64B data written, will contain the ring buffer sequence number.
 */
struct psif_rb_entry { /* Subjected to copy and convert */
	/* Length of data associated with this ring buffer header. */
	u32	byte_len;
	/* ib_bth_qp_number(24[0] bits)Queue Pair */
	u32	qp_num:24;
	/* Applicable only if this is for EPS-A. */
	enum psif_eps_a_core	eps_a_core:2;

	/* Reserved */
	u32	noname:3;
	/*
	 * Defining the packet type the headers valid for this ring buffer.
	 * PSIF_RB_TYPE_INVALID PSIF_RB_TYPE_DM_PUT PSIF_RB_TYPE_DM_GET_RESP
	 * PSIF_RB_TYPE_RCV_PROXY_COMPLETION
	 * PSIF_RB_TYPE_RCV_PROXY_COMPLETION_AND_DATA
	 * PSIF_RB_TYPE_SEND_PROXY_COMPLETION PSIF_RB_TYPE_SEND_COMPLETION
	 */
	enum psif_rb_type	pkt_type:3;

	/* Payload bulk */
	u64	payload[6];
	/* sequence number for sanity checking */
	u32	seq_num;
	/* Payload last */
	u32	payload_tail;
} PSIF_PACKED_ALIGNED; /* struct psif_rb_entry [64 byte] */

/*
 * QP state information as laid out in system memory. This structure should
 * be used to cast the state information stored to a register.
 */
struct psif_qp_core { /* Subjected to copy and convert */
	/*
	 * This retry tag is the one used by tsu_rqs and added to the packets sent to
	 * tsu_dma. It is the responsibility of tsu_rqs to update this retry tag
	 * whenever the sq_sequence_number in QP state is equal to the one in the
	 * request.
	 */
	u32	retry_tag_committed:3;
	/*
	 * This retry tag is updated by the error block when an error occur. If
	 * tsu_rqs reads this retry tag and it is different than the
	 * retry_tag_comitted, tsu_rqs must update retry_tag_comitted to the value of
	 * retry_tag_err when the sq_sequence_number indicates this is the valid
	 * request. The sq_sequence_number has been updated by tsu_err at the same
	 * time the retry_tag_err is updated.
	 */
	u32	retry_tag_err:3;
	/*
	 * If the DMA is getting an L-Key violation or an error from PCIe when
	 * fetching data for requests, it has to set this bit. When set, all requests
	 * behind must be marked in error and not transmitted on IB. Responses are
	 * sent as normal.
	 */
	u32	req_access_error:1;
	/*
	 * If the DMA is getting an R-Key violation or an error from PCIe when
	 * fetching data for RDMA read responses, it has to set this bit. When set,
	 * all packets sitting behind the RDMA read on this QP (requests and
	 * responses), must be marked bad so they are not transmitted on IB.
	 */
	u32	resp_access_error:1;
	/*
	 * The XRC domain is used to check against the XRC domain in the XRCSRQ
	 * descriptor indexed by the request. If the XRC domain matches, the
	 * protection domain in the XRCSRQ descriptor is used instead of the
	 * protection domain associated with the QP.
	 */
	u32	xrc_domain:24;
	/*
	 * Error retry counter initial value. Read by tsu_dma and used by tsu_cmpl to
	 * calculate exp_backoff etc..
	 */
	u32	error_retry_init:3;
	/*
	 * Retry counter associated with retries to received NAK or implied NAK. If
	 * it expires, a path migration will be attempted if it is armed, or the QP
	 * will go to error state. Read by tsu_dma and used by tsu_cmpl.
	 */
	u32	error_retry_count:3;
	/*
	 * When 1, indicates that the receive queue of this QP is a shared receive
	 * queue. This bit is used by tsu_err to classify errors.
	 */
	u32	cq_in_err:1;
	/* A hit in the set locally spun out of tsu_cmpl is found. */
	u32	spin_hit:1;
	/* Send queue extent - the clog2 size between the work requests. */
	u32	sq_clog2_extent:5;
	/* The size (log2 number of entries) of the send queue. */
	u32	sq_clog2_size:4;
	/*
	 * Current number of outstanding read or atomic requests. Intialize to zero.
	 * It is updated by tsu_rqs every time a new read or atomic requests is
	 * transmitted.
	 */
	u32	current_outstanding:5;
	/*
	 * Current number of retired read or atomic requests. Initialze to zero.
	 * Updated by tsu_cmpl every time a read or atomic request is completed.
	 */
	u32	current_retired:5;
	/*
	 * This is a multicast QP, and is creating UC multicasts. The is_multicast
	 * bit is based on the destination QP being the multicast QP number
	 * (0xffffff). When the QP is not a UD QP, this bit is forwarded to DMA as
	 * the is_multicast bit.
	 */
	u32	is_multicast:1;
	/*
	 * Indication that a receive queue access is in progress. The bit is set on a
	 * Send First packet and cleared on a Send Last packet. It is used to
	 * indicate if there exists an RQ which can be re-used in the case of UC
	 * transport packet drop.
	 */
	u32	dscr_rq_in_progress:1;
	/* Bit used internally in tsu_cmpl. */
	u32	first_at_floor_seen:1;
	/*
	 * When 1, indicates that the receive queue of this QP is a shared receive
	 * queue. This bit is used by tsu_err to classify errors.
	 */
	u32	rq_is_srq:1;
	/*
	 * If set, this QP will not be evicted unless QP state is filled up by QPs
	 * with this bit set.
	 */
	u32	do_not_evict:1;
	/*
	 * Minium RNR NAK timeout. This is added to RNR NAK packets and the requester
	 * receiving the RNR NAK must wait until the timer has expired before the
	 * retry is sent.
	 */
	u32	min_rnr_nak_time:5;
	/* QP State for this QP. */
	enum psif_qp_state	state:3;

	/* QP number for the remote node. */
	u32	remote_qp:24;
	/* R-Key of received multipacket message. */
	u32	rcv_rkey;
	/*
	 * Number of bytes received for in progress RDMA RD Responses. This is
	 * maintained by tsu_cmpl.
	 */
	u32	rcv_bytes;
	/* sq_seq(16[0] bits) * Send queue sequence number. This sequence number is used to make sure
 * order is maintained for requests sent from the process/host.
 */
	u16	retry_sq_seq;
	/* sq_seq(16[0] bits) * Send queue sequence number. This sequence number is used to make sure
 * order is maintained for requests sent from the process/host.
 */
	u16	sq_seq;
	/*
	 * Magic number used to verify use of QP state. This is done by calculating a
	 * checksum of the work request incorporating the magic number. This checksum
	 * is checked against the checksum in the work request.
	 */
	u32	magic;
	/*
	 * Completion queue sequence number. This is used for privileged requests,
	 * where sequence number for one CQ is added to a different completion.
	 */
	u32	cq_seq;
	/*
	 * Q-Key received in incoming IB packet is checked towards this Q-Key. Q-Key
	 * used on transmit if top bit of Q-Key in WR is set.
	 */
	u32	qkey;
	/* When 1 indicates that we have an IB retry outstanding. */
	u32	ib_retry_outstanding:1;
	/* When 1 indicates that we have a fence retry outstanding. */
	u32	fence_retry_outstanding:1;
	/*
	 * When 1, indicates that we have started a flush retry. SQ or QP in error.
	 * Must be cleared on modify QP - SQErr to RTS.
	 */
	u32	flush_started:1;
	/*
	 * Bit used for internal use when QP is moved to error and error completions
	 * etc should be sent. Should alway be initialized to zero by SW.
	 */
	u32	request_handled:1;
	/*
	 * This is set by CMPL when there are outstanding requests and a TX error is
	 * received from DMA. It is cleared when the error is sent on.
	 */
	enum psif_cmpl_outstanding_error	outstanding_error:4;

	/*
	 * Sequence number of the last ACK received. Read and written by tsu_cmpl.
	 * Used to verify that the received response packet is a valid response.
	 */
	u32	last_acked_psn:24;
	/* Offset within scatter element of in progress SEND. */
	u32	scatter_offs;
	/* Index to scatter element of in progress SEND. */
	u32	scatter_indx:5;
	/*
	 * 2 bits (next_opcode) 0x0: No operation in progress 0x1: Expect SEND middle
	 * or last 0x2: Expect RDMA_WR middle or last
	 */
	enum psif_expected_op	expected_opcode:2;

	/*
	 * When 1, indicates that a psn_nak has been sent. Need a valid request in
	 * order to clear the bit.
	 */
	u32	psn_nak:1;
	/*
	 * Expected packet sequence number: Sequence number on next expected packet.
	 */
	u32	expected_psn:24;
	/*
	 * Timeout timestamp - if the timer is running and the timestamp indicates a
	 * timeout, a retry iss issued.
	 */
	u64	timeout_time:48;
	/*
	 * When 1, indicates that a NAK has been for committed_psn+1. Need a valid
	 * request in order to clear the bit. This means receiving a good first/only
	 * packet for the committed_psn+1.
	 */
	u64	nak_sent:1;
	/*
	 * TSU quality of service level. Can take values indicating low latency and
	 * high throughput. This is equivalent to high/low BAR when writing doorbells
	 * to PSIF. The qosl bit in the doorbell request must match this bit in the
	 * QP state, otherwise the QP must be put in error. This check only applies
	 * to tsu_rqs.
	 */
	enum psif_tsu_qos	qosl:1;

	/*
	 * Migration state (migrated, re-arm and armed). Since path migration is
	 * handled by tsu_qps, this is controlled by tsu_qps. XXX: Should error
	 * handler also be able to change the path?
	 */
	enum psif_migration	mstate:2;

	/* This is an Ethernet over IB QP. */
	u64	eoib_enable:1;
	/* This is an IB over IB QP. */
	u64	ipoib_enable:1;
	/*
	 * Enable header/data split for offloading. Header and data should end up in
	 * separate scatter elements.
	 */
	u64	hdr_split_enable:1;
	/*
	 * Dynamic MTU is enabled - i.e. incoming requests can have 256B payload
	 * instead of MTU size specified in QP state.
	 */
	u64	rcv_dynamic_mtu_enable:1;
	/*
	 * This is a proxy QP. Packets less than a particular size are forwarded to
	 * EPS-A core indicated in the CQ descriptor.
	 */
	u64	proxy_qp_enable:1;
	/* Enable capability for RSS. */
	u64	rss_enable:1;
	/* Reserved */
	u64	noname:2;
	/* PSIF specific capability enable for receiving Masked Atomic operations. */
	u64	masked_atomic_enable:1;
	/* IB defined capability enable for receiving Atomic operations. */
	u64	atomic_enable:1;
	/* IB defined capability enable for receiving RDMA WR. */
	u64	rdma_wr_enable:1;
	/* IB defined capability enable for receiving RDMA RD. */
	u64	rdma_rd_enable:1;
	/* Receive capabilities enabled for this QP. */
	/* Inlined rcv_cap : struct psif_qp_rcv_cap (64 bits) */
	/*
	 * Transmit packet sequence number. Read and updated by tsu_dma before
	 * sending packets to tsu_ibpb and tsu_cmpl.
	 */
	u64	xmit_psn:24;
	/*
	 * Retry transmit packet sequence number. This is the xmit_psn which should
	 * be used on the first packet of a retry. This is set by tsu_err. When
	 * tsu_dma see that a packet is the first of a retry, it must use this psn as
	 * the xmit_psn and write back xmit_psn as this psn+1.
	 */
	u64	retry_xmit_psn:24;
	/*
	 * Index to scatter element of in progress RDMA RD response. This field does
	 * not need to be written to host memory.
	 */
	u64	resp_scatter_indx:5;
	/*
	 * An error is found by tsu_cmpl. All packets on this QP is forwarded to
	 * tsu_err until this bit is cleared. The bit is cleared either from QP
	 * cleanup or when tsu_cmpl is receiving is_retry.
	 */
	u64	rc_in_error:1;
	/* The timestamp is valid and will indicate when to time out the request.. */
	u64	timer_running:1;
	/*
	 * TSU Service Level used to decide the TSU VL for requests associated with
	 * this QP.
	 */
	u64	tsl:4;
	/*
	 * Maximum number of outstanding read or atomic requests allowed by the
	 * remote HCA. Initialized by software.
	 */
	u64	max_outstanding:5;
	/*
	 * DMA length found in first packet of inbound request. When last packet is
	 * received, it must be made sure the dmalen and received_bytes are equal.
	 */
	u32	dmalen;
	/* Send Queue RNR retry count initialization value. */
	u32	rnr_retry_init:3;
	/*
	 * Retry counter associated with RNR NAK retries. If it expires, a path
	 * migration will be attempted if it is armed, or the QP will go to error
	 * state.
	 */
	u32	rnr_retry_count:3;
	/*
	 * When this bit is set, ordering from the send queue is ignored. The
	 * sq_sequence_number check in the RQS is ignored. When the bit is not set,
	 * sq_sequence_number check is done. This bit must be set for QP0 and QP1.
	 */
	u32	no_ordering:1;
	/*
	 * When set, RQS should only check that the orig_checksum is equal to magic
	 * number. When not set, RQS should perform the checksum check towards the
	 * checksum in the psif_wr.
	 */
	u32	no_checksum:1;
	/*
	 * This is an index to a receive queue descriptor. The descriptor points to
	 * the next receive queue element to be used. Receive queues are used for IB
	 * Send and RDMA Writes with Immediate data.
	 */
	u32	rq_indx:24;
	/*
	 * Transport type of the QP (RC, UC, UD, XRC, MANSP1). MANSP1 is set for
	 * privileged QPs.
	 */
	enum psif_qp_trans	transport_type:3;

	/* Reserved */
	u32	noname1:5;
	/*
	 * This is an index to completion queue descriptor. The descriptor points to
	 * a receive completion queue, which may or may not be the same as the send
	 * completion queue. For XRC QPs, this field is written by the CQ descriptor
	 * received by the XRCSRQ on the first packet. This way we don't need to look
	 * up the XRCSRQ for every packet. of the message.
	 */
	u32	rcv_cq_indx:24;
	/*
	 * Number of bytes received of in progress RDMA Write or SEND. The data
	 * received for SENDs and RDMA WR w/Imm are needed for completions. This
	 * should be added to the msg_length.
	 */
	u32	bytes_received;
	/*
	 * Offloading type for EoIB. Indicating how the Enforcement of EoIB is done
	 * by PSIF.
	 */
	enum psif_eoib_type	eoib_type:2;

	/* PSIF specific exponential backoff enable. */
	u32	exp_backoff_enable:1;
	/*
	 * The privileged QP is not so privileged, which means that it is not allowed
	 * to perform all privileged requests.
	 */
	u32	not_so_privileged:1;
	/*
	 * Dynamic MTU is enabled - i.e. requests can use 256B payload instead of
	 * what is specified in QP state.
	 */
	u32	send_dynamic_mtu_enable:1;
	/* This QP is running IP over IB. */
	u32	ipoib:1;
	/* This QP is running Ethernet over IB. */
	u32	eoib:1;
	/* Send capabilities enabled for this QP. */
	/* Inlined send_cap : struct psif_qp_snd_cap (64 bits) */
	/* Used for retry handling. */
	u32	wait_for_psn:1;
	/*
	 * The counter is taken from the response packet and stored. tsu_host is
	 * using this value to decide if we go into or out of response scheduling
	 * mode.
	 */
	u32	resp_sched_count_done:24;
	/*
	 * The counter is compared towards the resp_sched_count_done and incremented
	 * every time a packet is sent to the SQS.
	 */
	u32	resp_sched_count_sched:24;
	/*
	 * Write pointer for the scheduling of responses. Host is updating and
	 * forwarding this to tsu_sqs.
	 */
	u32	resp_sched_sched_ptr:5;
	/*
	 * Set when entering response scheduling mode and cleared when going out of
	 * the mode. We exit this mode when resp_sched_count_sched ==
	 * resp_sched_count_done.
	 */
	u32	resp_sched_mode:1;
	/*
	 * Flag indicating if the swap in the last atomic swap operation was
	 * performed or not. If swapped, the next RDMA WR should be performed towards
	 * host memory. If not swapped, the next RDMA WR should not be performed
	 * towards host memory, but should be ACK'ed at the IB level as normal.
	 */
	enum psif_bool	swapped:1;

	/*
	 * This bit is set by RQS when a TSU_RQS_MAX_OUTSTANDING_REACHED_ERR or
	 * TSU_RQS_REQUEST_FENCED_ERR error is seen and cleared when the first packet
	 * of a retry is seen. While this bit is set, all packets towards DMA shall
	 * have the TSU_RQS_SEQNUM_ERR set.
	 */
	u32	retry_needed:1;
	/*
	 * Combined 'Last Received MSN' and 'Last Outstanding MSN', used to maintain
	 * 'spin set floor' and indicate 'all retries completed', respectively.
	 */
	u16	last_received_outstanding_msn;
	/* Reserved */
	u64	noname2:41;
	/*
	 * This bit is set when a HOST initiated NAK is sent due to errors when
	 * handling an atomic. When this bit is set, no data is forwarded to EPS or
	 * XIU, and no responses or ACK/NAKs should be forwarded to RQS.
	 */
	u64	host_sent_nak:1;
	/*
	 * This bit indicates that the QP is now handling responses in a safe manner
	 * with respect to MSN values in the incoming IB packets.
	 */
	u64	in_safe_mode:1;
	/*
	 * This is set when the field operation_successful == 0 from HOST. It is used
	 * to make sure that no good completion is to be sent after an atomic error
	 * has occurred. When set, the QP state is moved to error when seen on the
	 * exec side.
	 */
	u64	atomic_error:1;
	/*
	 * When this bit is not equal to apm_failed_event_needed, CBLD should send an
	 * event and set this bit equal to apm_failed_event_needed. When the QP is
	 * initialized, this value should be set equal to apm_failed_event_needed.
	 */
	u64	apm_failed_event_sent:1;
	/*
	 * When this bit is not equal to apm_success_event_needed, CBLD should send
	 * an event and set this bit equal to apm_success_event_needed. When the QP
	 * is initialized, this value should be set equal to
	 * apm_success_event_needed.
	 */
	u64	apm_success_event_sent:1;
	/* This is inverted by the APM module when an event should be sent. */
	u64	apm_failed_event_needed:1;
	/* This is inverted by the APM module when an event should be sent. */
	u64	apm_success_event_needed:1;
	/*
	 * Request address. In the case of RDMA WR, this is the current write
	 * pointer. In the case of a SEND, this is the address to the receive queue
	 * element.
	 */
	u64	req_addr;
	/*
	 * Write pointer to atomic data stored in QP. Every time an atomic operation
	 * is performed, the original atomic data is stored in order be to returned
	 * in the event of duplicate atomic.
	 */
	u32	orig_atomic_wr_ptr:4;
	enum psif_path_mtu	path_mtu:3;

	/*
	 * Communication established bit. When a packet is received when in RTR
	 * state, this bit should be set, and an asynchronous event should be sent.
	 */
	enum psif_comm_live	comm_established:1;

	/* This PSN is committed - ACKs sent will contain this PSN. */
	u32	committed_received_psn:24;
	/*
	 * Offset within scatter element of in progress RDMA RD response. This field
	 * does not need to be written to host memory.
	 */
	u32	resp_scatter_offs;
	/*
	 * Message sequence number used in AETH when sending ACKs. The number is
	 * incremented every time a new inbound message is processed.
	 */
	u64	msn:24;
	/*
	 * This is an index to send completion queue descriptor. The descriptor
	 * points to a send completion queue, which may or may not be the same as the
	 * send completion queue.
	 */
	u64	send_cq_indx:24;
	/*
	 * Committed MSN - the MSN of the newest committed request for this QP. Only
	 * the bottom 16 bits of the MSN is used.
	 */
	u64	last_committed_msn:16;
	/* pd(24[0] bits)Protection domain. */
	u64	srq_pd:24;
	/* pd(24[0] bits)Protection domain. */
	u64	pd:24;
	/*
	 * This is the eps_tag to be used in the case there is an outstanding error
	 * detected in CMPL. The field is owned CMPL and is used for internal
	 * handling.
	 */
	u64	eps_tag:16;
} PSIF_PACKED_ALIGNED; /* struct psif_qp_core [128 byte] */

/*
 * Path specific information. This is information which can be different for
 * primary and alternate path.
 */
struct psif_qp_path { /* Subjected to copy and convert */
	u64	remote_gid_0;
	/* Inlined grh : struct psif_grh (192 bits) */
	u64	remote_gid_1;
	/* ib_lrh_lid(16[0] bits)Local ID */
	u16	remote_lid;
	/* gid_indx(1[0] bits)GID index indicating which of the UFs two GIDs are used. */
	u64	gid_indx:1;
	enum psif_port	port:1;

	enum psif_loopback	loopback:1;

	enum psif_use_grh	use_grh:1;

	/* ib_lrh_sl(4[0] bits)Service Level */
	u64	sl:4;
	/* Reserved */
	u64	noname:4;
	/* ib_grh_hoplmt(8[0] bits)Hop Limit */
	u64	hoplmt:8;
	/* ib_grh_tclass(8[0] bits)Traffic Class */
	u64	tclass:8;
	/* ib_grh_flowl(20[0] bits)Flow Label */
	u64	flowlabel:20;
	/* Reserved */
	u64	noname1:26;
	/* Reserved field - used by hardware for error handling on PCIe errors. */
	u64	path_invalid:1;
	/* timeout(5[0] bits) * Local ACK timeout. This is the exponent used to calculate the delay before
 * an ACK is declared 'lost'
 */
	u64	local_ack_timeout:5;
	/* ipd(8[0] bits)Inter packet delay. Encoded as specified in IB spec. */
	u64	ipd:8;
	/* Reserved */
	u64	noname2:8;
	/*
	 * This is the LID path bits. This is used by tsu_ibpb when generating the
	 * SLID in the packet, and it is used by tsu_rcv when checking the DLID.
	 */
	u64	local_lid_path:7;
	/* pkey_indx(9[0] bits)Index into the P-Key table. */
	u64	pkey_indx:9;
} PSIF_PACKED_ALIGNED; /* struct psif_qp_path [32 byte] */

/* Query QP structure. */
struct psif_query_qp {
	/* QP state information from query. */
	struct psif_qp_core	qp;
	/* Primary path information. */
	struct psif_qp_path	primary_path;
	/* Alternate path information. */
	struct psif_qp_path	alternate_path;
} PSIF_PACKED_ALIGNED; /* struct psif_query_qp [192 byte] */

/* XXX: This is how the QP state in host memory is organized. */
struct psif_qp { /* Subjected to copy and convert */
	struct psif_qp_core	state;
	/*
	 * Path information for path A specific for this QP connection. This field
	 * only makes sense for QPs using connected mode. For datagram mode, this
	 * information comes from the AHA.
	 */
	struct psif_qp_path	path_a;
	/*
	 * Path information for path B specific for this QP connection. This field
	 * only makes sense for QPs using connected mode. For datagram mode, this
	 * information comes from the AHA.
	 */
	struct psif_qp_path	path_b;
} PSIF_PACKED_ALIGNED; /* struct psif_qp [192 byte] */

struct psif_mbox {
	/* Host posting to EPS-x */

	u64	in;
	/* EPS-x posting to Host */

	u64	out;
} PSIF_PACKED_ALIGNED; /* struct psif_mbox [16 byte] */

struct psif_pcie_mbox {
	/* MBOX_EPS_MAX mbox'es for all the EPS's */

	struct psif_mbox	eps[5];
	/* (Reset all mailboxes) */

	u64	eps_reset;
} PSIF_PACKED_ALIGNED; /* struct psif_pcie_mbox [88 byte] */

/* Modify QP structure. */
struct psif_modify_qp {
	/*
	 * Current number of retired read or atomic requests. Initialze to zero.
	 * Updated by tsu_cmpl every time a read or atomic request is completed.
	 */
	u16	max_outstanding:5;
	/* QP State for this QP. */
	enum psif_qp_state	state:3;

	/*
	 * Minium RNR NAK timeout. This is added to RNR NAK packets and the requester
	 * receiving the RNR NAK must wait until the timer has expired before the
	 * retry is sent.
	 */
	u16	min_rnr_nak_time:5;
	/*
	 * Error retry counter initial value. Read by tsu_dma and used by tsu_cmpl to
	 * calculate exp_backoff etc..
	 */
	u16	error_retry_count:3;
	/* This is an Ethernet over IB QP. */
	u16	eoib_enable:1;
	/* This is an IB over IB QP. */
	u16	ipoib_enable:1;
	/*
	 * Enable header/data split for offloading. Header and data should end up in
	 * separate scatter elements.
	 */
	u16	hdr_split_enable:1;
	/*
	 * Dynamic MTU is enabled - i.e. incoming requests can have 256B payload
	 * instead of MTU size specified in QP state.
	 */
	u16	rcv_dynamic_mtu_enable:1;
	/*
	 * This is a proxy QP. Packets less than a particular size are forwarded to
	 * EPS-A core indicated in the CQ descriptor.
	 */
	u16	proxy_qp_enable:1;
	/* Enable capability for RSS. */
	u16	rss_enable:1;
	/* Reserved */
	u16	noname:2;
	/* PSIF specific capability enable for receiving Masked Atomic operations. */
	u16	masked_atomic_enable:1;
	/* IB defined capability enable for receiving Atomic operations. */
	u16	atomic_enable:1;
	/* IB defined capability enable for receiving RDMA WR. */
	u16	rdma_wr_enable:1;
	/* IB defined capability enable for receiving RDMA RD. */
	u16	rdma_rd_enable:1;
	/* Receive capabilities enabled for this QP. */
	/* Inlined rcv_cap : struct psif_qp_rcv_cap (64 bits) */
	/*
	 * Retry counter associated with RNR NAK retries. If it expires, a path
	 * migration will be attempted if it is armed, or the QP will go to error
	 * state.
	 */
	u16	rnr_retry_count:3;
	/*
	 * If the DMA is getting an L-Key violation or an error from PCIe when
	 * fetching data for requests, it has to set this bit. When set, all requests
	 * behind must be marked in error and not transmitted on IB. Responses are
	 * sent as normal.
	 */
	u16	req_access_error:1;
	/* Q-Key received in incoming IB packet is checked towards this Q-Key. */
	u32	rx_qkey;
	/*
	 * Transmit packet sequence number. Read and updated by tsu_dma before
	 * sending packets to tsu_ibpb and tsu_cmpl.
	 */
	u32	xmit_psn:24;
	/* Reserved */
	u32	noname1:8;
	/*
	 * Migration state (migrated, re-arm and armed). Since path migration is
	 * handled by tsu_qps, this is controlled by tsu_qps. XXX: Should error
	 * handler also be able to change the path?
	 */
	enum psif_migration	mstate:2;

	/* Reserved */
	u32	noname2:3;
	/* Path MTU. */
	enum psif_path_mtu	path_mtu:3;

	/*
	 * Receive packet sequence number. Read and updated by tsu_dscr before
	 * passing packets to tsu_rqh.
	 */
	u32	expected_psn:24;
	/* Primary path information. */
	struct psif_qp_path	primary_path;
	/* Alternate path information. */
	struct psif_qp_path	alternate_path;
} PSIF_PACKED_ALIGNED; /* struct psif_modify_qp [80 byte] */

/* QP number UF and command for either modify or query QP. */
struct psif_modify_command {
	/* Manually added spacing to pad out psif_modify_command */
	u32	pad01:3;
	/*
	 * This will arm interrupt to be sent when the refcount for the QP index used
	 * have reached zero. It should be used when modify to Reset - when interrupt
	 * is seen, there are no outstanding transactions towards RQs or CQs for the
	 * QP, and it should be safe to take these queues down.
	 */
	u32	notify_when_zero:1;
	/* QP number for this operation. */
	u32	qp_num:24;
	/* Current state the QP must be in to do the modification. */
	enum psif_qp_state	current_state:3;

	/*
	 * Port number used for accesses to QP0/1. This field is don't care for all
	 * other QPs.
	 */
	enum psif_port	port_num:1;

	/* UF this QP belongs to. */
	u8	uf:6;
	/* Command indicating operation - query or modify. */
	enum psif_qp_command	cmd:2;

} PSIF_PACKED; /* struct psif_modify_command [ 5 byte] */

/*
 * Structure defining DMA Key Validation entries. This structure is specific
 * to IB and has information about R/L-Key states. One entry kan represent an
 * R-Key, an L-Key or both at the same time. This is is decided bythe key
 * states.
 */
struct psif_key {
	/* Reserved */
	u32	noname:24;
	/*
	 * If this bit is set, the va in the key is used as an offset to the base
	 * address given in this descriptor.
	 */
	u32	zero_based_addr_en:1;
	/*
	 * If this bit is set, it means that this memory region is enabled for
	 * conditional RDMA write. The bit must be added to the header at tsu_val and
	 * follow the request towards tsu_host. When tsu_host receives this bit, it
	 * is checking the 'swapped' bit in the QP state in order to decide if the
	 * payload is written to host memory or not.
	 */
	u32	conditional_wr:1;
	/* Atomic access enabled. */
	u32	local_access_atomic:1;
	/* Write access enabled. */
	u32	local_access_wr:1;
	/* Read access enabled. */
	u32	local_access_rd:1;
	/*
	 * Local access rights. Used for L-Key accesses when this is a valid L-Key.
	 * Must be set correctly by SW so that RD access is always set.
	 */
	/* Inlined local_access : struct psif_dma_vt_mem_access (64 bits) */
	/* Atomic access enabled. */
	u32	remote_access_atomic:1;
	/* Write access enabled. */
	u32	remote_access_wr:1;
	/* Read access enabled. */
	u32	remote_access_rd:1;
	/* Remote access rights. Used for R-Key accesses when this is a valid R-Key. */
	/* Inlined remote_access : struct psif_dma_vt_mem_access (64 bits) */
	/* pd(24[0] bits)Protection domain. */
	u32	pd:24;
	/* Reserved */
	u32	noname1:4;
	/* L-key state for this DMA validation entry */
	enum psif_dma_vt_key_states	lkey_state:2;

	/* R-key state for this DMA validation entry */
	enum psif_dma_vt_key_states	rkey_state:2;

	/* Length of memory region this validation entry is associated with. */
	u64	length;
	struct psif_mmu_cntx	mmu_context;
	/* host_address(64[0] bits)Host address used for accesses to/from TSU HOST. */
	u64	base_addr;
} PSIF_PACKED_ALIGNED; /* struct psif_key [32 byte] */

/* This is the portion of the descriptor which is updated by software. */
struct psif_eq_sw {
	/* Index to event elements consumed by SW. */
	u32	head_indx;
} PSIF_PACKED; /* struct psif_eq_sw [ 4 byte] */

/*
 * Descriptor entry for an event queue. This entry is used to address into
 * the event queue and write the correct entries. This structure is the
 * hardware updateable part of the EQ descriptor.
 */
struct psif_eq_hw {
	/*
	 * Event queue sequence number. This is the sequence number to be used for
	 * this event. When used by a client, it is incremented and written back to
	 * this descriptor.
	 */
	u32	sequence_number;
	/*
	 * The size (log2 number of entries) of the event queue. This is used for
	 * calculating when to wrap the head and tail indexes.
	 */
	u32	size_log2:5;
	/*
	 * The size between event queue entries. This is the shift value to find the
	 * start of the next entry.
	 */
	u32	extent_log2:5;
	/* The descriptor is valid. */
	u32	valid:1;
	/* Inlined ctrl : struct psif_eq_ctrl (64 bits) */
	/* Reserved */
	u32	noname:21;
	struct psif_mmu_cntx	mmu_cntx;
	/*
	 * VA or PA of the base of the queue. If PA the MMU context above will be a
	 * bypass context. Updated by software. The head and tail pointers can be
	 * calculated by the following calculations: Address = base_ptr + (head *
	 * ($bits(event_entry_t)/8 ) Head Pointer and Tail Pointer will use the same
	 * MMU context as the base, and all need to be VA from one address space, or
	 * all need to be PA. In typical use, to allow direct user access to the head
	 * and tail pointer VAs are used.
	 */
	u64	base_addr;
	/* Info: Edge padding added (for endian convert) */
	u32	space6;
	/* Index to event queue elements added by HW. */
	u32	tail_indx;
} PSIF_PACKED_ALIGNED; /* struct psif_eq_hw [32 byte] */

/* Event queue entry. */
struct psif_eq_entry {
	enum psif_eps_core_id	eps_core_id:4;

	/* vendor_fields(3[0] bits)Should this be an enum? */
	u32	vendor_fields:3;
	/* IB port number */
	enum psif_port	port:1;

	/* Completion queue descriptor ID. */
	u32	cqd_id:24;
	/* Error field indicating vendor error when this is an error event. */
	enum psif_tsu_error_types	vendor_error:8;

	/*
	 * The port_flags are only applicable for port type events. These are not set
	 * from the TSU, but implemented from EPS.
	 */
	u16	port_flags:4;
	/* PSIF_EVENT_EPS_A. */
	u16	event_status_eps_a:1;
	/* PSIF_EVENT_EPS_C. */
	u16	event_status_eps_c:1;
	/* PSIF_EVENT_CMPL_NOTIFY. */
	u16	event_status_cmpl_notify:1;
	/* PSIF_EVENT_PORT_ERROR. */
	u16	event_status_port_error:1;
	/* PSIF_EVENT_LOCAL_CATASTROPHIC_ERROR. */
	u16	event_status_local_catastrophic_error:1;
	/* PSIF_EVENT_PORT_CHANGED. */
	u16	event_status_port_changed:1;
	/* PSIF_EVENT_CLIENT_REGISTRATION. */
	u16	event_status_client_registration:1;
	/* PSIF_EVENT_PORT_ACTIVE. */
	u16	event_status_port_active:1;
	/* PSIF_EVENT_LOCAL_WORK_QUEUE_CATASTROPHIC_ERROR. */
	u16	event_status_local_work_queue_catastrophic_error:1;
	/* PSIF_EVENT_SRQ_CATASTROPHIC_ERROR. */
	u16	event_status_srq_catastrophic_error:1;
	/* PSIF_EVENT_INVALID_XRCETH. */
	u16	event_status_invalid_xrceth:1;
	/* PSIF_EVENT_XRC_DOMAIN_VIOLATION. */
	u16	event_status_xrc_domain_violation:1;
	/* PSIF_EVENT_PATH_MIGRATION_REQUEST_ERROR. */
	u16	event_status_path_migration_request_error:1;
	/* PSIF_EVENT_LOCAL_ACCESS_VIOLATION_WQ_ERROR. */
	u16	event_status_local_access_violation_wq_error:1;
	/* PSIF_EVENT_INVALID_REQUEST_LOCAL_WQ_ERROR. */
	u16	event_status_invalid_request_local_wq_error:1;
	/* PSIF_EVENT_CQ_ERROR. */
	u16	event_status_cq_error:1;
	/* PSIF_EVENT_LAST_WQE_REACHED. */
	u16	event_status_last_wqe_reached:1;
	/* PSIF_EVENT_SRQ_LIMIT_REACHED. */
	u16	event_status_srq_limit_reached:1;
	/* PSIF_EVENT_COMMUNICATION_ESTABLISHED. */
	u16	event_status_communication_established:1;
	/* PSIF_EVENT_PATH_MIGRATED. */
	u16	event_status_path_migrated:1;
	/* Inlined event_status : struct psif_event_status (64 bits) */
	/* LID. */
	u16	lid;
	/* QP number. */
	u64	qp:24;
	/* Receive queue descriptor ID. */
	u64	rqd_id:24;
	/* Event type if port_flags is PSIF_EVENT_EXTENSION */
	enum psif_event	extension_type:32;

	/* Completion queue sequence number causing the event to be sent. */
	u32	cq_sequence_number;
	/* More info on event */
	u64	event_info;
	/* Additional data on event */
	u64	event_data;
	/* Padding out struct bulk */
	u64	reserved[2];
	/* sequence number for sanity checking */
	u32	seq_num;
	/* Padding out struct last */
	u32	noname:32;
} PSIF_PACKED_ALIGNED32; /* struct psif_eq_entry [64 byte] */

/**
 * \brief Definition of struct returned by EPSC_QUERY_EXTERNAL_PORT_INFO
 * \details
 * This struct is returning several attributes of the external IB port. The vHCA IB portnumber
 * is set in the index field. Values returned maches description in PortInfo (See IB specification
 * 1.3 vol1 chapter 14.2.5.6), except for active speed which will return values as defined in
 * enum psif_port_speed.
 * \par Width
 *      64 bit
 * \par Used in
 * the parameter for the PSIF_QUERY sub-operation EPSC_QUERY_PORT_INFO - vHCA IB portnumber set in index field
 * \par Classification
 *      internal, development
 */

struct psif_epsc_query_external_port_info {
	/**< Reserved */

	u16	noname:8;
	/**< Number of operational Data VLs */

	u16	operational_vls:4;
	/**< Active MTU of external port (values will match psif_epsc_path_mtu_t */

	u16	active_mtu:4;
	/**< IB LinkWidthActive of external port */

	u16	active_width:8;
	/**< IB LinkSpeedActive of external port */

	enum psif_port_speed	active_speed:8;

	/**< Physical port state of IB port */

	u16	port_physical_state:4;
	/**< IB port state of external port values will match psif_epsc_port_state_t */

	u16	port_state:4;
	/**< IB port number of external port (on the IB device above) */

	u16	portnumber:8;
	/**< LID of the IB device connected to the external port */

	u16	lid;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_query_external_port_info [ 8 byte] */

/**
 * CSR Query port structure
 */
struct psif_epsc_port_attr {
	/** port state */
	enum psif_epsc_port_state	state:32;

	/** port number */
	u32	portNumber;
	/** currently configured path MTU */
	enum psif_epsc_path_mtu	active_mtu:32;

	/** maximum supported path MTU */
	enum psif_epsc_path_mtu	max_mtu:32;

	u32	port_cap_flags;
	u32	gid_tbl_len;
	u32	bad_pkey_cntr;
	u32	max_msg_sz;
	u16	lid;
	u16	pkey_tbl_len;
	u32	qkey_viol_cntr;
	u16	active_width:8;
	u16	init_type_reply:8;
	u16	subnet_timeout:8;
	u16	sm_sl:8;
	u16	max_vl_num:8;
	u16	lmc:8;
	u16	sm_lid;
	u64	noname:48;
	u64	phys_state:8;
	enum psif_port_speed	active_speed:8;

	u64	pad;
} PSIF_PACKED_ALIGNED32; /* struct psif_epsc_port_attr [64 byte] */

struct psif_epsc_log_stat {
	/* Owned by epsc runs all the way to 64 bit */
	u64	produce_offset;
	/* Owned by host */
	u64	consume_offset;
	/* Owned by host real offset modulo sz */
	u64	size;
	/* Allign to 32 byte */
	u64	pad;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_log_stat [32 byte] */

/**
 * Query GID response in host memory
 */
struct psif_epsc_gid_attr {
	u64	gid_0;
	u64	gid_1;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_gid_attr [16 byte] */

/**
 * Populate MMU table
 */
struct psif_epsc_exercise_mmu {
	/* Start adress */
	u64	host_addr;
	/* MMU context supplied by driver */
	struct psif_mmu_cntx	mmu_cntx;
	/* Buffer length in bytes */
	u64	length;
	/* Stride in bytes */
	u64	stride;
	u64	reserved[7];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_exercise_mmu [88 byte] */

/**
 * CSR Query device structure
 */
struct psif_epsc_device_attr {
	u64	fw_ver;
	u64	sys_image_guid;
	u64	node_guid;
	u64	max_mr_size;
	u64	page_size_cap;
	u32	vendor_part_id;
	u32	vendor_id;
	u32	max_qp;
	u32	hw_ver;
	u32	device_cap_flags;
	u32	max_qp_wr;
	u32	max_sge_rd;
	u32	max_sge;
	u32	max_cqe;
	u32	max_cq;
	u32	max_pd;
	u32	max_mr;
	u32	max_ee_rd_atom;
	u32	max_qp_rd_atom;
	u32	max_qp_init_rd_atom;
	u32	max_res_rd_atom;
	enum psif_epsc_atomic_cap	atomic_cap:32;

	u32	max_ee_init_rd_atom;
	u32	max_ee;
	enum psif_epsc_atomic_cap	masked_atomic_cap:32;

	u32	max_mw;
	u32	max_rdd;
	u32	max_raw_ethy_qp;
	u32	max_raw_ipv6_qp;
	u32	max_mcast_qp_attach;
	u32	max_mcast_grp;
	u32	max_ah;
	u32	max_total_mcast_qp_attach;
	u32	max_map_per_fmr;
	u32	max_fmr;
	u32	max_srq_wr;
	u32	max_srq;
	u32	max_fast_reg_page_list_len;
	u32	max_srq_sge;
	u64	noname:8;
	u64	phys_port_cnt:32;
	u64	local_ca_ack_delay:8;
	u64	max_pkeys:16;
	u64	pad;
} PSIF_PACKED_ALIGNED32; /* struct psif_epsc_device_attr [192 byte] */

/**
 * The eps-c fw csr to host sw completion
 * Response to a CSR request
 */
struct psif_epsc_csr_rsp {
	/* Address from request */
	u32	addr;
	/* Data integrity */
	u16	crc;
	/* enum psif_epsc_csr_opcode from request */
	enum psif_epsc_csr_opcode	opcode:8;

	/* return status of operation */
	enum psif_epsc_csr_status	status:8;

	/* Data from operation */
	u64	data;
	/* Info from operation */
	u64	info;
	/* Sequence number from request */
	u64	seq_num;
} PSIF_PACKED_ALIGNED32; /* struct psif_epsc_csr_rsp [32 byte] */

struct psif_epsc_csr_opaque {
	u64	data[11];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_opaque [88 byte] */

struct psif_epsc_csr_single {
	u64	data;
	u64	reserved[10];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_single [88 byte] */

/**
 * \brief Padded base address structure
 * \details
 * With this structure the driver provides the information needed be the
 * firmware to set up queue, queue pair and address handle descriptor base
 * addresses before they can be used.
 * \par Used in
 *      psif_epsc_csr_details for \ref EPSC_SET_BASEADDR and
 *      \ref EPSC_SET_BASEADDR_EQ mailbox requests
 * \par Classification
 *      driver
 */
struct psif_epsc_csr_base_addr {
	/** base address in host memory to be used for the descriptor */
	u64	address;
	/** MMU context for `address` */
	struct psif_mmu_cntx	mmu_context;
	/**
	 * Size of an entry as log2 value. The address to an entry is calculated
	 * as host_addr + entry_num*(1 << extent_log2).
	 */
	u32	extent_log2:5;
	/** unused (padding) */
	u32	noname:27;
	/** number of entries in the table */
	u32	num_entries;
	/** unused (padding) */
	u32	noname1:32;
	/** MSI-X interrupt index only valid for EQ setup */
	u32	msix_index;
	/** unused (padding) */
	u64	padding[7];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_base_addr [88 byte] */

/* CSR automated type for TSU_QPS_MODIFY_QP_CTRL */
/*
 * Per UF modify/query QP command/attribute register. Only one register is
 * implemented in hardware - one at a time. EPS implements one register per
 * UF. When one is written, the modify data is written to modify_qp_data
 * register before this register is written. The Modify or Query QP command
 * is autmatically kicked when this register is written. Is one outstanding
 * modify/query QP per UF ok, or do we need more?
 */
struct psif_csr_modify_qp_ctrl {
	/* Do not modify unless current state is as indicated in command. */
	u16	use_current_state:1;
	/* Change max outstanding RD/ATOMIC towards destination. */
	u16	max_outstanding:1;
	/* Change the xmit psn (SQ PSN) when set. */
	u16	xmit_psn:1;
	/* Change the RNR retry count when set. */
	u16	rnr_retry_count:1;
	/* Change the retry count when set. */
	u16	error_retry_count:1;
	/* Change the RNR minimum timer value when set. */
	u16	min_rnr_nak_time:1;
	/* Change the local ack timeout when set. */
	u16	local_ack_timeout:1;
	/* Change P-Key index if set. */
	u16	pkey_index:1;
	/* Change the Q-Key when set. */
	u16	qkey:1;
	/* Change the receive capabilities when set. */
	u16	qp_rcv_cap:1;
	/* Change the state of the QP when set. */
	u16	qp_state:1;
	/* Change alternate path if set. */
	u16	alt_path:1;
	/*
	 * Change migration state if set. In some cases this might lead to a path
	 * migration.
	 */
	u16	mig_state:1;
	/* Change primary path if set. */
	u16	prim_path:1;
	/* Change expected PSN (RQ PSN) if set. */
	u16	expected_psn:1;
	/* Change path MTU if set. */
	u16	path_mtu:1;
	/* Change path req_access error if set. */
	u64	req_access_error:1;
	/* Manually added spacing to pad outpsif_qp_attributes */
	u64	pad02:7;
	/* Inlined cmd_attributes : struct psif_qp_attributes (24 bits) */
	/* Manually added spacing to pad out psif_modify_command */
	u64	pad03:3;
	/*
	 * This will arm interrupt to be sent when the refcount for the QP index used
	 * have reached zero. It should be used when modify to Reset - when interrupt
	 * is seen, there are no outstanding transactions towards RQs or CQs for the
	 * QP, and it should be safe to take these queues down.
	 */
	u64	notify_when_zero:1;
	/* QP number for this operation. */
	u64	qp_num:24;
	/* Current state the QP must be in to do the modification. */
	enum psif_qp_state	current_state:3;

	/*
	 * Port number used for accesses to QP0/1. This field is don't care for all
	 * other QPs.
	 */
	enum psif_port	port_num:1;

	/* UF this QP belongs to. */
	u64	uf:6;
	/* Command indicating operation - query or modify. */
	enum psif_qp_command	cmd:2;

	/* Inlined cmd : struct psif_modify_command (40 bits) */
} PSIF_PACKED_ALIGNED; /* struct psif_csr_modify_qp_ctrl [ 8 byte] */

/**
 * Modify QP CSR structure
 */
struct psif_epsc_csr_modify_qp {
	struct psif_csr_modify_qp_ctrl	ctrl;
	struct psif_modify_qp	data;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_modify_qp [88 byte] */

/**
 * Query QP
 *
 * int ibv_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, enum
 * ibv_qp_attr_mask attr_mask, struct ibv_qp_init_attr *init_attr)
 *
 * Input Parameters:
 *  qp struct ibv_qp from ibv_create_qp
 *  attr_mask bitmask of items to query (see ibv_modify_qp)
 * Output Parameters:
 *  attr struct ibv_qp_attr to be filled in with requested attributes
 *  init_attr struct ibv_qp_init_attr to be filled in with initial
 *  attributes
 * Return Value:
 *  0 on success, errno on failure.
 */
struct psif_epsc_csr_query_qp {
	/* host_address(64[0] bits)Host address used for accesses to/from TSU HOST. */
	u64	address;
	struct psif_csr_modify_qp_ctrl	ctrl;
	/* MMU context supplied by driver */
	struct psif_mmu_cntx	mmu_cntx;
	u64	padding[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_query_qp [88 byte] */

/* CSR automated type for TSU_RQS_P{1,2}_OWN_LID_BASE */
/*
 * Own LIDs base and LMC. Potentially all own LID bits come from the QP state
 * entry. The number of bits to use is based on the LMC. Per UF register.
 */
struct psif_csr_own_lid_base {
	u64	gid_flag:1;
	/* lmc(3[0] bits)LID Mask Control data type. */
	u64	lmc:3;
	/* ib_lrh_lid(16[0] bits)Local ID */
	u64	lid_base:16;
	u64	noname:44;
} PSIF_PACKED_ALIGNED; /* struct psif_csr_own_lid_base [ 8 byte] */

/* CSR automated type for TSU_IBPB_P{1,2}_OWN_LID_BASE */
/*
 * Own LIDs base and LMC. Potentially all own LID bits come from the QP state
 * entry. The number of bits to use is based on the LMC. Per UF register.
 */
struct psif_csr_snd_lid {
	/* lmc(3[0] bits)LID Mask Control data type. */
	u64	lmc:3;
	/* ib_lrh_lid(16[0] bits)Local ID */
	u64	lid_base:16;
	u64	noname:45;
} PSIF_PACKED_ALIGNED; /* struct psif_csr_snd_lid [ 8 byte] */

/* CSR automated type for TSU_IBPR_P{1,2}_OWN_LID_BASE */
/*
 * Own LIDs base and LMC. Potentially all own LID bits come from the QP state
 * entry. The number of bits to use is based on the LMC. Per UF register.
 */
struct psif_csr_rcv_lid {
	/* If set GID routing must be used. */
	u64	gid_flag:1;
	/* LID mask control. */
	u64	lmc:3;
	/* LID base. */
	u64	lid_base:16;
	/* Inlined data : struct psif_lid_base (64 bits) */
	u64	noname:44;
} PSIF_PACKED_ALIGNED; /* struct psif_csr_rcv_lid [ 8 byte] */

/**
 * EPSC_SET_LID
 */
struct psif_epsc_csr_set_lid {
	struct psif_csr_own_lid_base	lid_rqs;
	struct psif_csr_snd_lid	lid_snd;
	struct psif_csr_rcv_lid	lid_rcv;
	u64	noname:48;
	/* Index pt. not used (PSIF.ARCH.03.12 and later) */
	u64	index:8;
	u64	port:8;
	u64	padding[7];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_set_lid [88 byte] */

/**
 * EPSC_SET_GID{,_P1,_P2}
 */
struct psif_epsc_csr_set_gid {
	u64	gid_0;
	u64	gid_1;
	u64	noname:48;
	u64	index:8;
	u64	port:8;
	u64	padding[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_set_gid [88 byte] */

/**
 * EPSC_SET_EOIB_MAC
 */
struct psif_epsc_csr_set_eoib_mac {
	u64	mac;
	u64	noname:48;
	u64	index:8;
	u64	port:8;
	u64	padding[9];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_set_eoib_mac [88 byte] */

/**
 * Set EPSC_SET_VLINK_STATE
 */
struct psif_epsc_csr_vlink_state {
	u64	noname:52;
	enum psif_vlink_state	vlink_state:5;

	enum psif_port	port:1;

	/* universal_function(6[0] bits)UF */
	u64	uf:6;
	u64	padding[10];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_vlink_state [88 byte] */

/**
 * EPSC_QUERY_DEVICE, EPSC_QUERY_PORT, EPSC_QUERY_INFO,
 */
struct psif_epsc_csr_query_hw {
	/* host_address(64[0] bits)Host address used for accesses to/from TSU HOST. */
	u64	address;
	/* MMU context supplied by driver */
	struct psif_mmu_cntx	mmu_cntx;
	u64	padding[9];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_query_hw [88 byte] */

/**
 * EPSC_QUERY_PKEY, EPSC_QUERY_GID,
 */
struct psif_epsc_csr_query_table {
	u64	noname:40;
	u64	index:16;
	u64	port:8;
	u64	padding[10];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_query_table [88 byte] */

/**
 * EPSC_MC_ATTACH, EPSC_MC_DETACH, EPSC_QUERY_MC
 */
struct psif_epsc_csr_mc {
	u32	noname:32;
	u32	qp:24;
	u32	port:8;
	u64	mgid_0;
	u64	mgid_1;
	u64	padding[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_mc [88 byte] */

/**
 * EPSC_EVENT_ACK
 */
struct psif_epsc_csr_event {
	u32	eq_index;
	u16	noname:16;
	u16	eq_num:8;
	u16	port:8;
	/* Will become : psif_eq_event event */
	u64	event[8];
	u64	padding[2];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_event [88 byte] */

/**
 * EPSC_MODIFY_DEVICE
 */
struct psif_epsc_csr_modify_device {
	u64	noname:48;
	enum psif_epsc_csr_modify_device_flags	modify_mask:16;

	u64	sys_image_guid;
	u8	node_desc[64];
	u64	padding;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_modify_device [88 byte] */

/**
 * EPSC_MODIFY_PORT_{1,2}
 */
struct psif_epsc_csr_modify_port {
	u32	noname:32;
	u16	init_type:8;
	u16	port:8;
	enum psif_epsc_csr_modify_port_flags	modify_mask:16;

	u32	clr_port_cap_mask;
	u32	set_port_cap_mask;
	u64	reserved[9];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_modify_port [88 byte] */

/**
 * Test operations : EPSC_TEST_HOST_RD & EPSC_TEST_HOST_WR
 */
struct psif_epsc_csr_test_host_wrd {
	u64	host_addr;
	u32	epsc_offs;
	u32	key;
	/* pattern number 0..xxx */
	u32	pattern;
	u32	length;
	u64	reserved_1[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_test_host_wrd [88 byte] */

/**
 * Flash programming: EPSC_FLASH_START, EPSC_FLASH_RD,
 *                    EPSC_FLASH_WR & EPSC_FLASH_STOP
 */
struct psif_epsc_csr_flash_access {
	u32	length;
	u32	offset;
	struct psif_mmu_cntx	mmu_cntx;
	u64	host_addr;
	u64	crc;
	u64	reserved[7];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_flash_access [88 byte] */

/**
 * IB packet trace acquire : EPSC_TRACE_ACQUIRE
 */
struct psif_epsc_csr_trace_acquire {
	/* Pointer to trace buffer */
	u64	host_addr;
	/* Buffer length in bytes */
	u32	maxtrace;
	/* Buffer offset in bytes */
	u32	offset;
	/* MMU context supplied by driver */
	struct psif_mmu_cntx	mmu_cntx;
	u64	padding[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_trace_acquire [88 byte] */

/**
 * EPSC_FW_VERSION
 */
struct psif_epsc_csr_fw_version {
	struct psif_mmu_cntx	mmu_cntx;
	u64	host_addr;
	u64	data;
	u64	reserved[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_fw_version [88 byte] */

struct psif_epsc_csr_log_ctrl {
	struct psif_mmu_cntx	mmu_cntx;
	/* Log mode to use */
	enum psif_epsc_log_mode	mode:32;

	/* Log level to use */
	enum psif_epsc_log_level	level:32;

	/*
	 * Fields only used by log mode EPSC_LOG_MODE_HOST:
	 * Start address of the data area to write to.
	 */
	u64	base;
	/* pointer to a log_stat data area */
	u64	stat_base;
	/* Length in bytes of the buffer */
	u64	length;
	u64	reserved_2[6];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_log_ctrl [88 byte] */

/**
 * EPS-A to EPS-C
 */
struct psif_epsc_csr_epsa_cntrl {
	u32	noname:30;
	/* Which EPS-A core */
	enum psif_eps_a_core	epsa:2;

	/* Operation */
	enum psif_epsc_csr_epsa_command	command:32;

	/* Offset within flash */
	u64	flash_addr;
	/* Address in EPS-A memory */
	u64	epsa_addr;
	u64	reserved[8];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_epsa_cntrl [88 byte] */

/**
 * host to EPS-A
 */
struct psif_epsc_csr_epsa_cmd {
	u32	length;
	enum psif_epsa_command	cmd:32;

	/* Buffer adress in host memory */
	u64	host_addr;
	u8	entry_point[16];
	u32	qpnum;
	u32	key;
	u64	reserved[6];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_epsa_cmd [88 byte] */

/**
 * EPSC_CLI_ACCESS - buffer size is presumed to be 2K
 */
struct psif_epsc_csr_cli_access {
	u64	host_addr;
	struct psif_mmu_cntx	mmu_cntx;
	u8	command[72];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_cli_access [88 byte] */

/**
 * EPSC_MAD_PROCESS:
 */
struct psif_epsc_csr_mad_process {
	u64	host_addr;
	struct psif_mmu_cntx	mmu_cntx;
	/* ib_bth_qp_number(24[0] bits)Queue Pair */
	u32	qp:24;
	enum psif_wc_opcode	opcode:8;

	/* ib_reth_dmalen(32[0] bits)Direct Memory Access Length */
	u32	byte_len;
	/*
	 * SLID taken from the received packet. This is only valid for UD QPs. Only
	 * valid if not privileged.
	 */
	u16	slid;
	/* IB portnumber this packet was received on. Only valid if not privileged. */
	enum psif_port	port:1;

	/* Only valid for UD QPs. */
	u16	sl:4;
	/* P-Key index from UD packet. */
	u16	pkey_indx:9;
	u16	wc_flags_with_imm:1;
	u16	wc_flags_grh:1;
	/* Flags indicating GRH and immediate presence.Only valid if not privileged. */
	/* Inlined wc_flags : struct psif_wc_flags (64 bits) */
	/* Only valid for UD QPs. */
	u32	src_qp:24;
	enum psif_wc_status	status:8;

	u64	noname:57;
	/*
	 * Path bits (lower 7 bits) taken from the DLID in the received packet. This
	 * is only valid for UD QPs. Only valid if not privileged.
	 */
	u64	dlid_path_bits:7;
	u64	reserved_2[6];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_mad_process [88 byte] */

/**
 * EPSC_MAD_SEND_WR:
 */
struct psif_epsc_csr_mad_send_wr {
	u64	host_addr;
	struct psif_mmu_cntx	mmu_cntx;
	u64	reserved[9];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_mad_send_wr [88 byte] */

struct psif_epsc_query_req {
	u32	index;
	enum psif_epsc_query_op	op:32;

	/* Value for EPSC_SET operation */
	u64	value;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_query_req [16 byte] */

/**
 * Structure for EPSC_QUERY
 *
 */
struct psif_epsc_csr_query {
	/* Future */
	u32	noname:32;
	/* UF number */
	u32	uf;
	/* Query destin for the response data field */
	struct psif_epsc_query_req	data;
	/* Query destin for the response info field */
	struct psif_epsc_query_req	info;
	u64	reserved[6];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_query [88 byte] */

/**
 * Structure for EPSC_SET
 */
struct psif_epsc_csr_set {
	/* Future */
	u32	noname:32;
	/* UF number */
	u32	uf;
	/* Set destin for the response data field */
	struct psif_epsc_query_req	data;
	/* Set destin for the response info field */
	struct psif_epsc_query_req	info;
	u64	reserved[6];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_set [88 byte] */

/**
 *  EPSC_HOST_INT_COMMON_CTRL - PF only
 */
struct psif_epsc_csr_interrupt_common {
	u64	noname:48;
	/* Moderate total interrupt generation. How many usecs to delay. */
	u64	total_usec:16;
	u64	reserved_2[10];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_interrupt_common [88 byte] */

/**
 * EPSC_HOST_INT_CHANNEL_CTRL - PF + VF
 */
struct psif_interrupt_attributes {
	u64	noname:54;
	u64	channel_pusec_high:1;
	u64	channel_pusec_low:1;
	u64	channel_pusec:1;
	u64	channel_ausec_high:1;
	u64	channel_ausec_low:1;
	u64	channel_ausec:1;
	u64	channel_rate_high:1;
	u64	channel_rate_low:1;
	u64	channel_rx_scale:1;
	u64	enable_adaptive:1;
} PSIF_PACKED_ALIGNED; /* struct psif_interrupt_attributes [ 8 byte] */

struct psif_epsc_csr_interrupt_channel {
	/* Mask of attributes to set */
	struct psif_interrupt_attributes	attributes;
	/* rx-to-tx timer scaling factor 2-exponent value */
	u16	channel_rx_scale;
	/* Future */
	u64	noname:31;
	/* Set to 1 for adaptive coalescing */
	u64	enable_adaptive:1;
	/* EQ number */
	u64	int_channel:16;
	/* Message rate in messages per second. High rate threshold. */
	u64	channel_rate_high:32;
	/* Message rate in messages per second. Low rate threshold. */
	u32	channel_rate_low;
	/* How many usecs to delay after packet. */
	u16	channel_pusec;
	/* How many usecs to delay after first packet. High rate value. */
	u16	channel_ausec_high;
	/* How many usecs to delay after first packet. Low rate value. */
	u16	channel_ausec_low;
	/* How many usecs to delay after first packet. */
	u16	channel_ausec;
	/* Align to 64 bit */
	u32	noname1:32;
	/* How many usecs to delay after packet. High rate value. */
	u16	channel_pusec_high;
	/* How many usecs to delay after packet. Low rate value. */
	u16	channel_pusec_low;
	u64	reserved_2[6];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_interrupt_channel [88 byte] */

union psif_epsc_update_set_or_offset {
	u32	offset;
	enum psif_epsc_update_set	set:32;

} PSIF_PACKED; /* union psif_epsc_update_set_or_offset [ 4 byte] */

/**
 * Flash update: EPSC_UPDATE
 */
struct psif_epsc_csr_update {
	union psif_epsc_update_set_or_offset	u;
	enum psif_epsc_flash_slot	slot:16;

	enum psif_epsc_csr_update_opcode	opcode:16;

	u32	id;
	u32	length;
	struct psif_mmu_cntx	mmu_cntx;
	u64	host_addr;
	u64	reserved[7];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_update [88 byte] */

/**
 * UF maintenance: EPSC_UF_CTRL
 */
struct psif_epsc_csr_uf_ctrl {
	u32	flags;
	enum psif_epsc_csr_uf_ctrl_opcode	opcode:32;

	u64	uf_vector;
	u64	reserved[9];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_uf_ctrl [88 byte] */

/* CSR automated type for TSU_MMU_FLUSH_CACHES */
/* Flush MMU and-or PTW Caches. */
struct psif_csr_mmu_flush_caches {
	u64	flush_mmu_cache:1;
	u64	flush_ptw_cache:1;
	u64	mmu_cache_flushed:1;
	u64	ptw_cache_flushed:1;
	u64	noname:60;
} PSIF_PACKED_ALIGNED; /* struct psif_csr_mmu_flush_caches [ 8 byte] */

/**
 * Flush MMU and-or PTW Caches: EPSC_FLUSH_CACHES
 */
struct psif_epsc_flush_caches {
	struct psif_csr_mmu_flush_caches	flush_mmu_caches;
	u64	reserved[10];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_flush_caches [88 byte] */

/**
 * Structure for EPSC_PMA_COUNTERS
 * Common structure for virtual port per UF and
 * external (physical) port per vSwitch.
 */
struct psif_epsc_csr_pma_counters {
	/**
	 * If MSB is set then it's a physical port number.
	 * Otherwise it's a virtual port number.
	 */
	u32	port;
	/* UF number */
	u32	uf;
	/* Base address in host memory */
	u64	host_addr;
	struct psif_mmu_cntx	mmu_cntx;
	/**
	 * Bitmask to indicate which counters to clear. Bit
	 * positions are based on the response structure's enum.
	 */
	u64	clear_mask;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_pma_counters [32 byte] */

/** \brief Command params for opcode EPSC_VIMMA_CTRL_SET_VFP_VHCA_DEREGISTER
 *  \note This struct belongs to capability: EPSC_VIMMA_CTRL_CAP_PSIF_VFP_CAPS
 *  \par Classification
 *       external
 */
struct psif_epsc_vimma_dereg {
	/* highest uf index set in array below */
	u16	high_uf;
	/* lowest uf index set in array below */
	u16	low_uf;
	/* size 5*u64 */
	u32	noname:32;
	/* allows multi UF setting. bit0 = UF0 bit1 = UF1 etc. */
	u64	uf_vector[4];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_vimma_dereg [40 byte] */

/** \brief Struct defintion for vHCA registration details
 * \note This struct belongs to capability: EPSC_VIMMA_CTRL_CAP_PSIF_VFP_CAPS
 * \par Classification
 *      external
 */
struct psif_epsc_vimma_vfp_reg {
	u32	vm_context;
	u16	noname:16;
	/* size 5*u64 */
	u16	uf;
	u8	vm_id[16];
	u16	noname1:16;
	u16	vhca_instance;
	u32	vm_incarnation;
	u64	noname2:64;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_vimma_vfp_reg [40 byte] */

/** \brief Command params for opcode EPSC_VIMMA_CTRL_SET_ADMIN_MODE
 *  \note This struct belongs to capability: EPSC_VIMMA_CTRL_CAP_PSIF_VFP_CAPS
 *  \par Classification
 *       external
 */
struct psif_epsc_vimma_set_admmode {
	/* highest uf index set in array below */
	u16	high_uf;
	/* lowest uf index set in array below */
	u16	low_uf;
	u16	noname:16;
	/* size 5*u64 */
	enum psif_epsc_vimma_admmode	mode:16;

	/* allows multi UF setting. bit0 = UF0 bit1 = UF1 etc. */
	u64	uf_vector[4];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_vimma_set_admmode [40 byte] */

/** \brief Command params for opcode EPSC_VIMMA_CTRL_SET_VFP_VHCA_REGISTER
 *  \note This struct belongs to capability: EPSC_VIMMA_CTRL_CAP_PSIF_VFP_CAPS
 *  \par Classification
 *       external
 */
struct psif_epsc_vimma_reg_info {
	/* highest uf index set in array below */
	u16	high_uf;
	/* lowest uf index set in array below */
	u16	low_uf;
	u32	noname:32;
	/* allows multi UF setting. bit0 = UF0 bit1 = UF1 etc. */
	u64	uf_vector[4];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_vimma_reg_info [40 byte] */

/** \brief Defining params for VIMMA opcodes
 *  \par Classification
 *       external
 */
union psif_epsc_vimma_ctrl_cmd {
	/* all union elements are size 5*u64 */
	struct psif_epsc_vimma_dereg	dereg;
	struct psif_epsc_vimma_vfp_reg	vfp_reg;
	struct psif_epsc_vimma_set_admmode	adm_mode;
	struct psif_epsc_vimma_reg_info	reg_info;
} PSIF_PACKED; /* union psif_epsc_vimma_ctrl_cmd [40 byte] */

/** \brief Defines the complete command params for VIMMA opcodes
 *  \note This struct belongs to capability: EPSC_VIMMA_CTRL_CAP_PSIF_BASIC_CAPS
 *   and should never change in an incompatible way.
 *  \par Classification
 *       external
 */
struct psif_epsc_csr_vimma_ctrl {
	/* length of DMA response buffer pinned in host memory */
	u32	length;
	/** VIMMA sub-opcodes triggered by EPSC_VIMMA_CTRL */
	enum psif_epsc_vimma_ctrl_opcode	opcode:32;

	/** Size 5*64 bits: union of the params for the various opcodes */
	union psif_epsc_vimma_ctrl_cmd	u;
	/** Size 64 bits */
	struct psif_mmu_cntx	mmu_cntx;
	/** Place to DMA back longer responses during retrieval */
	u64	host_addr;
	/* Summing up to 11 * u64 which is total and max */
	u64	reserved[3];
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_vimma_ctrl [88 byte] */

/**
 * Structure for EPSC_BER_DATA
 */
struct psif_epsc_csr_ber_data {
	/* Buffer address in host memory */
	u64	host_addr;
	/* MMU supplied by the driver */
	struct psif_mmu_cntx	mmu_cntx;
	/* Buffer length in bytes */
	u32	len;
	/* IBU port number */
	u32	port;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_ber_data [24 byte] */

/* Public API for mailbox requests details */
union psif_epsc_csr_details {
	/* Anonymous data */
	struct psif_epsc_csr_opaque	opaque;
	/* Single data to write */
	struct psif_epsc_csr_single	single;
	/* Descriptor base address */
	struct psif_epsc_csr_base_addr	base_addr;
	/* Modify QP request */
	struct psif_epsc_csr_modify_qp	modify_qp;
	/* Query QP */
	struct psif_epsc_csr_query_qp	query_qp;
	/* Set LID entry (backdoor setup) */
	struct psif_epsc_csr_set_lid	set_lid;
	/* Set GID entry (backdoor setup) */
	struct psif_epsc_csr_set_gid	set_gid;
	/* Set EoIB MAC address (backdoor setup) */
	struct psif_epsc_csr_set_eoib_mac	set_eoib_mac;
	/* Set vlink state */
	struct psif_epsc_csr_vlink_state	set_vlink;
	/* Query HW state of device port or other */
	struct psif_epsc_csr_query_hw	query_hw;
	/* Query table info pkey or gid */
	struct psif_epsc_csr_query_table	query_table;
	/* MC subscription */
	struct psif_epsc_csr_mc	mc;
	/* Asynchronous event */
	struct psif_epsc_csr_event	event;
	/* EPSC_MODIFY_DEVICE */
	struct psif_epsc_csr_modify_device	device;
	/* EPSC_MODIFY_PORT_{1 2} */
	struct psif_epsc_csr_modify_port	port;
	/* EPSC_TEST_HOST_RD & EPSC_TEST_HOST_WR */
	struct psif_epsc_csr_test_host_wrd	host_wrd;
	/* EPSC_FLASH_START EPSC_FLASH_RD EPSC_FLASH_WR & EPSC_FLASH_STOP */
	struct psif_epsc_csr_flash_access	flash;
	/* EPSC_TRACE_ACQUIRE */
	struct psif_epsc_csr_trace_acquire	trace_acquire;
	/* EPSC_FW_VERSION */
	struct psif_epsc_csr_fw_version	fw_version;
	/* EPSC_LOG_CTRL */
	struct psif_epsc_csr_log_ctrl	log_ctrl;
	/* Control epsa */
	struct psif_epsc_csr_epsa_cntrl	epsa_cntrl;
	struct psif_epsc_csr_epsa_cmd	epsa_cmd;
	/* Issue commands to serial console */
	struct psif_epsc_csr_cli_access	cli;
	/* Process incomming (QP 1) packet from host */
	struct psif_epsc_csr_mad_process	mad_process;
	/* Send MAD formated WR to host for sending */
	struct psif_epsc_csr_mad_send_wr	mad_send_wr;
	/* Single value query */
	struct psif_epsc_csr_query	query;
	/* Single value set */
	struct psif_epsc_csr_set	set;
	/* Setup interrupt control */
	struct psif_epsc_csr_interrupt_common	int_common;
	struct psif_epsc_csr_interrupt_channel	int_channel;
	/* EPSC_UPDATE (update firmware) */
	struct psif_epsc_csr_update	update;
	/* EPSC_UF_CTRL: UF maintenance functions */
	struct psif_epsc_csr_uf_ctrl	uf_ctrl;
	/* EPSC_FLUSH_CACHES: Flush MMU and-or PTW Caches */
	struct psif_epsc_flush_caches	flush_caches;
	/* PMA counters query */
	struct psif_epsc_csr_pma_counters	pma_counters;
	/* EPSC_VIMMA_CTRL: VIMMA functions */
	struct psif_epsc_csr_vimma_ctrl	vimma_ctrl;
	/* BER data query */
	struct psif_epsc_csr_ber_data	ber;
} PSIF_PACKED; /* union psif_epsc_csr_details [88 byte] */

/**
 * The host sw to eps-c fw csr workrequest
 *
 * The EPSC will post the completion responses for request `#seq_num`
 * into the completion queue at :
 *    `index = #seq_num % epsc_cq.base_addr.num_entries`
 * as provided by the initial EPSC_SETUP work request:
 */
struct psif_epsc_csr_req {
	/* Data integrity */
	u16	crc;
	/* UF - only valid for UF 0 - must be 0 otherwise */
	u16	uf;
	/* Sequence number - included in response */
	u16	seq_num;
	enum psif_epsc_csr_flags	flags:8;

	enum psif_epsc_csr_opcode	opcode:8;

	/* Register offset or port number */
	u64	addr;
	/* Operation specific data */
	union psif_epsc_csr_details	u;
	u64	reserved[3];
} PSIF_PACKED_ALIGNED32; /* struct psif_epsc_csr_req [128 byte] */

/** Doorbel/mail-box register layout */
struct psif_epsc_csr_doorbell {
	/** Identical to head to assure 8 byte atomic write */
	u16	tail;
	/** Payload or info */
	u64	data:32;
	/** Transfer index */
	u64	head:16;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_doorbell [ 8 byte] */

/**
 * Basic configuration data for each UF
 */
struct psif_epsc_csr_config {
	/** Minor HW API version identifier. */
	u16	hwapi_minor_ver;
	/** Major HW API version identifier. */
	u16	hwapi_major_ver;
	/** Minor EPS API version identifier. */
	u16	epsapi_minor_ver;
	/** Major EPS API version identifier. */
	u16	epsapi_major_ver;
	/** Request base address. */
	u64	request;
	/** Respose base address. */
	u64	response;
	/** Size of response entry. */
	u16	extent_rsp;
	/** Size of request entry. */
	u16	extent_req;
	/** Number of entries in table. */
	u32	entries;
	/** MMU context for mailbox. */
	struct psif_mmu_cntx	mmu_cntx;
	/** Padded field. */
	u64	noname:55;
	/** Setup CMPL spin set mode to be fast - default is safe (PF only). */
	u64	fast_spin:1;
	/** Connect all vlinks to external port (PF only). */
	u64	vlink_connect:1;
	/** Enable all VFs to receive SMPs at startup (PF only). */
	u64	enable_vf_smp:1;
	/** VCB access: Exact length for scoreboard data copy (PF only). */
	u64	vcb_exact:1;
	/** PCI access: Select host endian memory layout (PF only). */
	u64	big_endian:1;
	/** Flush SIF pipeline similar to FLR (PF and VF). */
	u64	clean_state:1;
	/** PCI access: enable atomic support from SIF (PF only). */
	enum psif_epsc_csr_atomic_op	atomic_support:2;

	/** PCI access: setup for sparc memory layout (PF only). */
	u64	sparc_pages:1;
} PSIF_PACKED_ALIGNED; /* struct psif_epsc_csr_config [48 byte] */

/* This is the portion of the descriptor which is updated by software. */
struct psif_cq_sw { /* Subjected to copy and convert */
	/* Info: Edge padding added (for endian convert) */
	u32	space7;
	/* Index to completion elements added by SW. */
	u32	head_indx;
} PSIF_PACKED_ALIGNED; /* struct psif_cq_sw [ 8 byte] */

/*
 * Descriptor entry for a completion queue. This entry is used to address
 * into the completion queue and write the correct entries. This structure is
 * the hardware updateable part of the CQ descriptor.
 */
struct psif_cq_hw { /* Subjected to copy and convert */
	/* cq_max_msg(32[0] bits)Maximum message size in bytes. */
	u32	max_size;
	/*
	 * Interrupt channel associated with the event queue. In the PSIF design the
	 * event queues are one to one with interrupt channel.
	 */
	u32	int_channel:7;
	/*
	 * Set by DSCR when CQ overrun async event is sent for this CQ. Not cleared
	 * before CQ is destroyed.
	 */
	u32	cq_overrun_event_sent:1;
	/* Reserved */
	u32	noname:7;
	/*
	 * Pre-fetch threshold (clog2) indicating when to read the software portion
	 * of the descriptor. If there are less entries than indicated by this
	 * threshold, the software portion of the descriptor must be read.
	 */
	u32	prefetch_threshold_log2:5;
	/*
	 * EPS-A core number completions are forwarded to if the proxy_enabled bit is
	 * set.
	 */
	enum psif_eps_a_core	eps_core:2;

	/*
	 * If set, this completion queue is proxy enabled and should send completions
	 * to EPS core indicated by the eps_core field.
	 */
	u32	proxy_en:1;
	/*
	 * Log2 size of the completion queue. Maximum number of entries in the
	 * completion queue. This is used for calculating when to wrap the head and
	 * tail indexes.
	 */
	u32	size_log2:5;
	/* The descriptor is valid. */
	u32	valid:1;
	/*
	 * CQ notification states. The use of these are as defined in the description
	 * of the PSIF interrupt coalsecing scheme.
	 */
	enum psif_cq_state	cq_not_state:2;

	/* Do not evict this entry if this bit is set. */
	u32	sticky:1;
	struct psif_mmu_cntx	mmu_cntx;
	/*
	 * VA or PA of the base of the completion queue. If PA the MMU context above
	 * will be a bypass context. Updated by software. The head and tail pointers
	 * can be calculated by the following calculations: Address = base_ptr +
	 * (head * ($bits(completion_entry_t)/8 ) Head Pointer and Tail Pointer will
	 * use the same MMU context as the base, and all need to be VA from one
	 * address space, or all need to be PA. In typical use, to allow direct user
	 * access to the head and tail pointer VAs are used.
	 */
	u64	base_addr;
	/*
	 * Completion queue sequence number. This is the sequence number to be used
	 * for this completion. When used by a client, it is incremented and written
	 * back to this descriptor.
	 */
	u32	sequence_number;
	/* Index to completion elements to be consumed by HW. */
	u32	tail_indx;
} PSIF_PACKED_ALIGNED; /* struct psif_cq_hw [32 byte] */

/*
 * Union between CQ sequence number and immediate date. CQ sequence number is
 * only valid for privileged QP requests.
 */
union psif_seq_num_immdt {
	/*
	 * Completion queue sequence number for arming of completion queues. This is
	 * the CQ sequence number for the completion queue which was armed.
	 */
	u32	cq_sequence_number;
	/* ib_immediate(32[0] bits)Immediate Data */
	u32	imm;
} PSIF_PACKED; /* union psif_seq_num_immdt [ 4 byte] */

struct psif_offload_info {
	/* Reserved */
	u32	noname:1;
	/*
	 * This bit is set if the incoming request is a conditional RDMA WR w/Imm
	 * which is not written to memory.
	 */
	u32	not_written:1;
	/*
	 * Receive Tossed Packet. PSIF thought there was something wrong with this
	 * offloaded packet so it should be tossed.
	 */
	u32	rtp:1;
	/*
	 * Header length used for header/data split offloading. The length of this
	 * header is added to one scatter element.
	 */
	u32	hdr_split_hdr_length:9;
	/* The header length is valid for header/data split offloading. */
	u32	hdr_split_valid:1;
	/*
	 * When valid, header/data split is performed and the header length is given
	 * in hdr_length.
	 */
	/* Inlined hdr_split : struct psif_hdr_split_offload (64 bits) */
	/* This is set if the packet was a DR packet. Only valid if not privileged. */
	u32	is_dr:1;
	/*
	 * Original UF for QP0/1 packets going to the EPS-C. Only valid if not
	 * privileged.
	 */
	u32	orig_uf:6;
	/*
	 * L4 checksum calculated ok. This is either correct TCP/UDP checksum or UDP
	 * checksum not generated by the transmitter. Only valid if not privileged.
	 */
	u32	l4_checksum_ok:1;
	/*
	 * L3 checksum calculated ok. This is either an IPv6 packet or a correctly
	 * checksummed IPv4 header. Only valid if not privileged.
	 */
	u32	l3_checksum_ok:1;
	/* L4 is UDP. */
	u32	packet_classification_udp:1;
	/* L4 is TCP. */
	u32	packet_classification_tcp:1;
	/* Unsupported IPv6 extension headers detected. */
	u32	packet_classification_ip6_unsupported_exthdr:1;
	/* Packet is ARP reply */
	u32	packet_classification_arp_reply:1;
	/* Packet is ARP */
	u32	packet_classification_arp:1;
	/* IPv4 options or IPv6 extension headers present. */
	u32	packet_classification_ip_options:1;
	/* IP fragment. */
	u32	packet_classification_ip_frag:1;
	/* This is set for IPv6 packets only. */
	u32	packet_classification_ipv6:1;
	/* This is set for IPv4 packets only. */
	u32	packet_classification_ipv4:1;
	/* L3/L4 packet classification. */
	/* Inlined packet_classification_ip_class : struct psif_ip_class (64 bits) */
	/*
	 * 0: means LLC_SNAP, 1: means Ethernet type 2. (L2 packet classification.)
	 * This field is applicable for EoIB only.
	 */
	u32	packet_classification_eth2:1;
	/*
	 * Packet classification structure for offloading packets. Only valid if not
	 * privileged.
	 */
	/* Inlined packet_classification : struct psif_packet_classification (64 bits) */
	/* RSS hash. Only valid if not privileged. */
	u32	rss_hash;
} PSIF_PACKED_ALIGNED; /* struct psif_offload_info [ 8 byte] */

/*
 * Union - offload is valid for normal QPs. For privileged QPs, it is the WC
 * ID needed to completed if outstanding is set.
 */
union psif_offload_wc_id {
	/*
	 * This is used if this is a privileged commend INVALIDATE_SGL_CACHE.
	 * Software must figure out if this WC_ID is valid or not.
	 */
	union psif_completion_wc_id	wc_id;
	/* This countain offload or PSIF specific infornation. */
	struct psif_offload_info	offload;
} PSIF_PACKED; /* union psif_offload_wc_id [ 8 byte] */

/*
 * Completion entry. A completion entry written to host memory, will be
 * padded out to 64 bytes. The last 4 bytes will contain a completion queue
 * sequence number.
 */
struct psif_cq_entry { /* Subjected to copy and convert */
	/*
	 * Work queue completion ID. For receive completions this is the entry number
	 * in the receive queue and the receive queue descriptor index. For send
	 * completions this is the sq_sequence number.
	 */
	union psif_completion_wc_id	wc_id;
	/* ib_bth_qp_number(24[0] bits)Queue Pair */
	u32	qp:24;
	enum psif_wc_opcode	opcode:8;

	/* Length of message. Only valid if not privileged. */
	u32	byte_len;
	/* Only valid for UD QPs. */
	u32	src_qp:24;
	enum psif_wc_status	status:8;

	union psif_seq_num_immdt	seq_num_imm;
	/* RSS source. Only valid if not privileged. */
	enum psif_rss_hash_source	rss_hash_src:1;

	enum psif_tsu_error_types	vendor_err:8;

	/*
	 * Checksum with error. This is not inverted for UDP if zero result from
	 * check. It can be either a full or partial checksum. Only valid if not
	 * privileged.
	 */
	u32	error_checksum:16;
	/*
	 * Path bits (lower 7 bits) taken from the DLID in the received packet. This
	 * is only valid for UD QPs. Only valid if not privileged.
	 */
	u32	dlid_path_bits:7;
	/*
	 * SLID taken from the received packet. This is only valid for UD QPs. Only
	 * valid if not privileged.
	 */
	u16	slid;
	/* IB portnumber this packet was received on. Only valid if not privileged. */
	enum psif_port	port:1;

	/* Only valid for UD QPs. */
	u16	sl:4;
	/* P-Key index from UD packet. */
	u16	pkey_indx:9;
	u16	with_imm:1;
	u16	grh:1;
	/* Flags indicating GRH and immediate presence.Only valid if not privileged. */
	/* Inlined wc_flags : struct psif_wc_flags (64 bits) */
	/*
	 * For normal QPs, this is offload information. For privileged QPs, this is
	 * WC ID for in progress RQE.
	 */
	union psif_offload_wc_id	offload_wc_id;
	/* Padding out struct bulk */
	u64	reserved[2];
	/* sequence number for sanity checking */
	u32	seq_num;
	/* Padding out struct last */
	u32	noname:32;
} PSIF_PACKED_ALIGNED; /* struct psif_cq_entry [64 byte] */

/* Temp.definition of collect buffers */
struct psif_cb { /* Subjected to copy and convert */
	/* Content pt. not defined in ASIC XML */
	struct psif_wr	wr;
	u64	payload[32];
} PSIF_PACKED_ALIGNED; /* struct psif_cb [320 byte] */

/* Compact Base Address Register format. Not for use in register definitions. */
struct psif_base_addr { /* Subjected to copy and convert */
	/* host_address(64[0] bits)Host address used for accesses to/from TSU HOST. */
	u64	address;
	struct psif_mmu_cntx	mmu_context;
	/*
	 * clog2_extent used for entry alignment. This field used to calculate
	 * address for a particular entry. Address to an entry is calculated as
	 * follows: host_addr + entry_num*(1 (leftshift) clog2_extent)
	 */
	u32	extent_log2:5;
	/* Manually added spacing to pad out base addr */
	u32	pad04:27;
	/* Number of entries in table. */
	u32	num_entries;
} PSIF_PACKED_ALIGNED; /* struct psif_base_addr [24 byte] */

/* Retry data for one atomic request. Layout per BugZilla 3710 */
struct psif_atomic_retry_element {
	/* [255:192] response atomic data */
	u64	orig_data;
	/* [157:0] Padding. Always set to zero. */
	u32	padding:30;
	/* [158] This atomic response was in error. */
	u32	response_error:1;
	/*
	 * [159] When set to one, entry has been used. When set to zero,
	 * no duplicate has been written in this entry.
	 */
	u32	used:1;
	/* [183:160] psn */
	u32	psn:24;
	/* [191:184] padding. always zero */
	u32	zero:8;
	u64	reserved[2];
} PSIF_PACKED_ALIGNED; /* struct psif_atomic_retry_element [32 byte] */

/*
 * Data type for TSU_HOST_QP_BASE_ADDR - atomic replay scratch pad
 *  Layout as of 16 deep atomic queue - elements padded to 32 byte
 */
struct psif_atsp {
	struct psif_atomic_retry_element	retry[16];
} PSIF_PACKED_ALIGNED; /* struct psif_atsp [512 byte] */

/*
 * Address handle array entry used for sending UD packets. The structure
 * contains information about the destination for a request.
 */
struct psif_ah { /* Subjected to copy and convert */
	u64	grh_remote_gid_0;
	/* Inlined grh : struct psif_grh (192 bits) */
	u64	grh_remote_gid_1;
	/* ib_lrh_lid(16[0] bits)Local ID */
	u16	remote_lid;
	/* gid_indx(1[0] bits)GID index indicating which of the UFs two GIDs are used. */
	u64	gid_indx:1;
	enum psif_port	port:1;

	enum psif_loopback	loopback:1;

	enum psif_use_grh	use_grh:1;

	/* ib_lrh_sl(4[0] bits)Service Level */
	u64	sl:4;
	/* Reserved */
	u64	noname:4;
	/* ib_grh_hoplmt(8[0] bits)Hop Limit */
	u64	grh_hoplmt:8;
	/* ib_grh_tclass(8[0] bits)Traffic Class */
	u64	grh_tclass:8;
	/* ib_grh_flowl(20[0] bits)Flow Label */
	u64	grh_flowlabel:20;
	/* Reserved */
	u64	noname1:8;
	/*
	 * The protection domain is checked against the protection domain in the QP
	 * state. As long as they are equal, the QP is allowed to use this AHA entry.
	 */
	u64	pd:24;
	/* ipd(8[0] bits)Inter packet delay. Encoded as specified in IB spec. */
	u64	ipd:8;
	/* Reserved */
	u64	noname2:8;
	/* ib_lrh_lid_path_bits(7[0] bits)Path bits for the LID. Used as the least signficant bits in a LID */
	u64	local_lid_path:7;
	/* Reserved */
	u64	noname3:9;
} PSIF_PACKED_ALIGNED; /* struct psif_ah [32 byte] */



#endif	/* _PSIF_HW_DATA_H_LE */
