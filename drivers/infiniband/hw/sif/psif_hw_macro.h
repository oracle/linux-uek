/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_HW_MACRO_H
#define	_PSIF_HW_MACRO_H


#include "psif_api.h"

#include "psif_endian.h"


/*
 * PSIF_WR_INVALIDATE_LKEY: key to invalidate/flush from the DMA VT cache.
 * PSIF_WR_INVALIDATE_RKEY: key to invalidate/flush from the DMA VT cache.
 * PSIF_WR_INVALIDATE_BOTH_KEYS: key to invalidate/flush from the DMA VT
 * cache. PSIF_WR_INVALIDATE_TLB: this is the address vector to invalidate in
 * the TLB.
 */
#define PSIF_WR_SU_KEY_OFFSET	2
#define PSIF_WR_SU_2_KEY_SHIFT	32
#define PSIF_WR_SU_2_KEY_BITS	32
#define PSIF_WR_SU_2_KEY_MASK	0xffffffff00000000ull

/*
 * Send queue sequence number. Used to map request to a particular work
 * request in the send queue.
 */
#define PSIF_WR_SQ_SEQ_OFFSET	0
#define PSIF_WR_SQ_SEQ_SHIFT	0
#define PSIF_WR_SQ_SEQ_BITS	16
#define PSIF_WR_SQ_SEQ_MASK	0x000000000000ffffull

/*
 * QP sending this request. XXX: Should name be own_qp_num as defined in QP
 * state?
 */
#define PSIF_WR_LOCAL_QP_OFFSET	0
#define PSIF_WR_LOCAL_QP_SHIFT	32
#define PSIF_WR_LOCAL_QP_BITS	24
#define PSIF_WR_LOCAL_QP_MASK	0x00ffffff00000000ull

/* Completion notification identifier. */
#define PSIF_WR_COMPLETION_OFFSET	1
#define PSIF_WR_1_COMPLETION_BIT_POSITION		31
#define PSIF_WR_1_COMPLETION_BIT	0x0000000080000000ull

/*
 * Checksum used for data protection and consistency between work request and
 * QP state.
 */
#define PSIF_WR_CHECKSUM_OFFSET	2
#define PSIF_WR_2_CHECKSUM_SHIFT	32
#define PSIF_WR_2_CHECKSUM_BITS	32
#define PSIF_WR_2_CHECKSUM_MASK	0xffffffff00000000ull

/*
 * Index to where elements are added to the send queue by SW. SW is
 * responsibel for keeping track of how many entries there are in the send
 * queue. I.e. SW needs to keep track of the head_index so it doesn't
 * overwrite entries in the send queue which is not yet completed.
 */
#define PSIF_SQ_SW_TAIL_INDX_OFFSET	0
#define PSIF_SQ_SW_TAIL_INDX_SHIFT	32
#define PSIF_SQ_SW_TAIL_INDX_BITS	16
#define PSIF_SQ_SW_TAIL_INDX_MASK	0x0000ffff00000000ull

/*
 * Send queue sequence number used by the SQS to maintain ordering and keep
 * track of where which send queue elements to fetch. This field is not in
 * sync with the field in qp_t. This number is typically a little bit before
 * the number in the qp_t as SQS has to fetch the elements from host memory.
 * This is also used as tail_index when checking if there are more elements
 * in the send queue.
 */
#define PSIF_SQ_HW_LAST_SEQ_OFFSET	0
#define PSIF_SQ_HW_LAST_SEQ_SHIFT	16
#define PSIF_SQ_HW_LAST_SEQ_BITS	16
#define PSIF_SQ_HW_LAST_SEQ_MASK	0x00000000ffff0000ull

/* QP and UF to be processed next. */
#define PSIF_SQ_HW_SQ_NEXT_OFFSET	0
#define PSIF_SQ_HW_SQ_NEXT_SHIFT	32
#define PSIF_SQ_HW_SQ_NEXT_BITS	32
#define PSIF_SQ_HW_SQ_NEXT_MASK	0xffffffff00000000ull

/*
 * This bit is set through the doorbell. SW should check this bit plus
 * psif_next = null to ensure SW can own the SQ descriptor.
 */
#define PSIF_SQ_HW_DESTROYED_OFFSET	1
#define PSIF_SQ_HW_1_DESTROYED_BIT_POSITION		27
#define PSIF_SQ_HW_1_DESTROYED_BIT	0x0000000008000000ull

/* Software modified index pointing to the tail reecive entry in host memory. */
#define PSIF_RQ_SW_TAIL_INDX_OFFSET	0
#define PSIF_RQ_SW_TAIL_INDX_SHIFT	32
#define PSIF_RQ_SW_TAIL_INDX_BITS	14
#define PSIF_RQ_SW_TAIL_INDX_MASK	0x00003fff00000000ull

/*
 * Hardware modified index pointing to the head of the receive queue. TSU is
 * using this to find the address of the receive queue entry.
 */
#define PSIF_RQ_HW_HEAD_INDX_OFFSET	0
#define PSIF_RQ_HW_HEAD_INDX_SHIFT	14
#define PSIF_RQ_HW_HEAD_INDX_BITS	14
#define PSIF_RQ_HW_HEAD_INDX_MASK	0x000000000fffc000ull

/* The desciptor is valid. */
#define PSIF_RQ_HW_VALID_OFFSET	3
#define PSIF_RQ_HW_3_VALID_BIT_POSITION		55
#define PSIF_RQ_HW_3_VALID_BIT	0x0080000000000000ull

/*
 * Receive queue entry ID. This is added to the receive completion using this
 * receive queue entry.
 */
#define PSIF_RQ_ENTRY_RQE_ID_OFFSET	0
#define PSIF_RQ_ENTRY_RQE_ID_SHIFT	0
#define PSIF_RQ_ENTRY_RQE_ID_BITS	64
#define PSIF_RQ_ENTRY_RQE_ID_MASK	0xffffffffffffffffull

/*
 * This retry tag is the one used by tsu_rqs and added to the packets sent to
 * tsu_dma. It is the responsibility of tsu_rqs to update this retry tag
 * whenever the sq_sequence_number in QP state is equal to the one in the
 * request.
 */
#define PSIF_QP_CORE_RETRY_TAG_COMMITTED_OFFSET	0
#define PSIF_QP_CORE_RETRY_TAG_COMMITTED_SHIFT	0
#define PSIF_QP_CORE_RETRY_TAG_COMMITTED_BITS	3
#define PSIF_QP_CORE_RETRY_TAG_COMMITTED_MASK	0x0000000000000007ull

/*
 * This retry tag is updated by the error block when an error occur. If
 * tsu_rqs reads this retry tag and it is different than the
 * retry_tag_comitted, tsu_rqs must update retry_tag_comitted to the value of
 * retry_tag_err when the sq_sequence_number indicates this is the valid
 * request. The sq_sequence_number has been updated by tsu_err at the same
 * time the retry_tag_err is updated.
 */
#define PSIF_QP_CORE_RETRY_TAG_ERR_OFFSET	0
#define PSIF_QP_CORE_RETRY_TAG_ERR_SHIFT	3
#define PSIF_QP_CORE_RETRY_TAG_ERR_BITS	3
#define PSIF_QP_CORE_RETRY_TAG_ERR_MASK	0x0000000000000038ull

/*
 * Error retry counter initial value. Read by tsu_dma and used by tsu_cmpl to
 * calculate exp_backoff etc..
 */
#define PSIF_QP_CORE_ERROR_RETRY_INIT_OFFSET	0
#define PSIF_QP_CORE_ERROR_RETRY_INIT_SHIFT	32
#define PSIF_QP_CORE_ERROR_RETRY_INIT_BITS	3
#define PSIF_QP_CORE_ERROR_RETRY_INIT_MASK	0x0000000700000000ull

/*
 * Retry counter associated with retries to received NAK or implied NAK. If
 * it expires, a path migration will be attempted if it is armed, or the QP
 * will go to error state. Read by tsu_dma and used by tsu_cmpl.
 */
#define PSIF_QP_CORE_ERROR_RETRY_COUNT_OFFSET	0
#define PSIF_QP_CORE_ERROR_RETRY_COUNT_SHIFT	35
#define PSIF_QP_CORE_ERROR_RETRY_COUNT_BITS	3
#define PSIF_QP_CORE_ERROR_RETRY_COUNT_MASK	0x0000003800000000ull

/* A hit in the set locally spun out of tsu_cmpl is found. */
#define PSIF_QP_CORE_SPIN_HIT_OFFSET	0
#define PSIF_QP_CORE_SPIN_HIT_BIT_POSITION		39
#define PSIF_QP_CORE_SPIN_HIT_BIT	0x0000008000000000ull

/*
 * Minium RNR NAK timeout. This is added to RNR NAK packets and the requester
 * receiving the RNR NAK must wait until the timer has expired before the
 * retry is sent.
 */
#define PSIF_QP_CORE_MIN_RNR_NAK_TIME_OFFSET	1
#define PSIF_QP_CORE_1_MIN_RNR_NAK_TIME_SHIFT	0
#define PSIF_QP_CORE_1_MIN_RNR_NAK_TIME_BITS	5
#define PSIF_QP_CORE_1_MIN_RNR_NAK_TIME_MASK	0x000000000000001full

/* QP State for this QP. */
#define PSIF_QP_CORE_STATE_OFFSET	1
#define PSIF_QP_CORE_1_STATE_SHIFT	5
#define PSIF_QP_CORE_1_STATE_BITS	3
#define PSIF_QP_CORE_1_STATE_MASK	0x00000000000000e0ull

/* QP number for the remote node. */
#define PSIF_QP_CORE_REMOTE_QP_OFFSET	1
#define PSIF_QP_CORE_1_REMOTE_QP_SHIFT	8
#define PSIF_QP_CORE_1_REMOTE_QP_BITS	24
#define PSIF_QP_CORE_1_REMOTE_QP_MASK	0x00000000ffffff00ull

#define PSIF_QP_CORE_RETRY_SQ_SEQ_OFFSET	2
#define PSIF_QP_CORE_2_RETRY_SQ_SEQ_SHIFT	32
#define PSIF_QP_CORE_2_RETRY_SQ_SEQ_BITS	16
#define PSIF_QP_CORE_2_RETRY_SQ_SEQ_MASK	0x0000ffff00000000ull

#define PSIF_QP_CORE_SQ_SEQ_OFFSET	2
#define PSIF_QP_CORE_2_SQ_SEQ_SHIFT	48
#define PSIF_QP_CORE_2_SQ_SEQ_BITS	16
#define PSIF_QP_CORE_2_SQ_SEQ_MASK	0xffff000000000000ull

/*
 * Magic number used to verify use of QP state. This is done by calculating a
 * checksum of the work request incorporating the magic number. This checksum
 * is checked against the checksum in the work request.
 */
#define PSIF_QP_CORE_MAGIC_OFFSET	3
#define PSIF_QP_CORE_3_MAGIC_SHIFT	0
#define PSIF_QP_CORE_3_MAGIC_BITS	32
#define PSIF_QP_CORE_3_MAGIC_MASK	0x00000000ffffffffull

/*
 * Q-Key received in incoming IB packet is checked towards this Q-Key. Q-Key
 * used on transmit if top bit of Q-Key in WR is set.
 */
#define PSIF_QP_CORE_QKEY_OFFSET	4
#define PSIF_QP_CORE_4_QKEY_SHIFT	0
#define PSIF_QP_CORE_4_QKEY_BITS	32
#define PSIF_QP_CORE_4_QKEY_MASK	0x00000000ffffffffull

/*
 * Sequence number of the last ACK received. Read and written by tsu_cmpl.
 * Used to verify that the received response packet is a valid response.
 */
#define PSIF_QP_CORE_LAST_ACKED_PSN_OFFSET	4
#define PSIF_QP_CORE_4_LAST_ACKED_PSN_SHIFT	40
#define PSIF_QP_CORE_4_LAST_ACKED_PSN_BITS	24
#define PSIF_QP_CORE_4_LAST_ACKED_PSN_MASK	0xffffff0000000000ull

/* Index to scatter element of in progress SEND. */
#define PSIF_QP_CORE_SCATTER_INDX_OFFSET	5
#define PSIF_QP_CORE_5_SCATTER_INDX_SHIFT	32
#define PSIF_QP_CORE_5_SCATTER_INDX_BITS	5
#define PSIF_QP_CORE_5_SCATTER_INDX_MASK	0x0000001f00000000ull

/*
 * Expected packet sequence number: Sequence number on next expected packet.
 */
#define PSIF_QP_CORE_EXPECTED_PSN_OFFSET	5
#define PSIF_QP_CORE_5_EXPECTED_PSN_SHIFT	40
#define PSIF_QP_CORE_5_EXPECTED_PSN_BITS	24
#define PSIF_QP_CORE_5_EXPECTED_PSN_MASK	0xffffff0000000000ull

/*
 * TSU quality of service level. Can take values indicating low latency and
 * high throughput. This is equivalent to high/low BAR when writing doorbells
 * to PSIF. The qosl bit in the doorbell request must match this bit in the
 * QP state, otherwise the QP must be put in error. This check only applies
 * to tsu_rqs.
 */
#define PSIF_QP_CORE_QOSL_OFFSET	6
#define PSIF_QP_CORE_6_QOSL_BIT_POSITION		49
#define PSIF_QP_CORE_6_QOSL_BIT	0x0002000000000000ull

/*
 * Migration state (migrated, re-arm and armed). Since path migration is
 * handled by tsu_qps, this is controlled by tsu_qps. XXX: Should error
 * handler also be able to change the path?
 */
#define PSIF_QP_CORE_MSTATE_OFFSET	6
#define PSIF_QP_CORE_6_MSTATE_SHIFT	50
#define PSIF_QP_CORE_6_MSTATE_BITS	2
#define PSIF_QP_CORE_6_MSTATE_MASK	0x000c000000000000ull

/* This is an IB over IB QP. */
#define PSIF_QP_CORE_IPOIB_ENABLE_OFFSET	6
#define PSIF_QP_CORE_6_IPOIB_ENABLE_BIT_POSITION		53
#define PSIF_QP_CORE_6_IPOIB_ENABLE_BIT	0x0020000000000000ull

/* IB defined capability enable for receiving Atomic operations. */
#define PSIF_QP_CORE_ATOMIC_ENABLE_OFFSET	6
#define PSIF_QP_CORE_6_ATOMIC_ENABLE_BIT_POSITION		61
#define PSIF_QP_CORE_6_ATOMIC_ENABLE_BIT	0x2000000000000000ull

/* IB defined capability enable for receiving RDMA WR. */
#define PSIF_QP_CORE_RDMA_WR_ENABLE_OFFSET	6
#define PSIF_QP_CORE_6_RDMA_WR_ENABLE_BIT_POSITION		62
#define PSIF_QP_CORE_6_RDMA_WR_ENABLE_BIT	0x4000000000000000ull

/* IB defined capability enable for receiving RDMA RD. */
#define PSIF_QP_CORE_RDMA_RD_ENABLE_OFFSET	6
#define PSIF_QP_CORE_6_RDMA_RD_ENABLE_BIT_POSITION		63
#define PSIF_QP_CORE_6_RDMA_RD_ENABLE_BIT	0x8000000000000000ull

/*
 * Transmit packet sequence number. Read and updated by tsu_dma before
 * sending packets to tsu_ibpb and tsu_cmpl.
 */
#define PSIF_QP_CORE_XMIT_PSN_OFFSET	7
#define PSIF_QP_CORE_7_XMIT_PSN_SHIFT	0
#define PSIF_QP_CORE_7_XMIT_PSN_BITS	24
#define PSIF_QP_CORE_7_XMIT_PSN_MASK	0x0000000000ffffffull

/*
 * TSU Service Level used to decide the TSU VL for requests associated with
 * this QP.
 */
#define PSIF_QP_CORE_TSL_OFFSET	7
#define PSIF_QP_CORE_7_TSL_SHIFT	55
#define PSIF_QP_CORE_7_TSL_BITS	4
#define PSIF_QP_CORE_7_TSL_MASK	0x0780000000000000ull

/*
 * Maximum number of outstanding read or atomic requests allowed by the
 * remote HCA. Initialized by software.
 */
#define PSIF_QP_CORE_MAX_OUTSTANDING_OFFSET	7
#define PSIF_QP_CORE_7_MAX_OUTSTANDING_SHIFT	59
#define PSIF_QP_CORE_7_MAX_OUTSTANDING_BITS	5
#define PSIF_QP_CORE_7_MAX_OUTSTANDING_MASK	0xf800000000000000ull

/* Send Queue RNR retry count initialization value. */
#define PSIF_QP_CORE_RNR_RETRY_INIT_OFFSET	8
#define PSIF_QP_CORE_8_RNR_RETRY_INIT_SHIFT	32
#define PSIF_QP_CORE_8_RNR_RETRY_INIT_BITS	3
#define PSIF_QP_CORE_8_RNR_RETRY_INIT_MASK	0x0000000700000000ull

/*
 * Retry counter associated with RNR NAK retries. If it expires, a path
 * migration will be attempted if it is armed, or the QP will go to error
 * state.
 */
#define PSIF_QP_CORE_RNR_RETRY_COUNT_OFFSET	8
#define PSIF_QP_CORE_8_RNR_RETRY_COUNT_SHIFT	35
#define PSIF_QP_CORE_8_RNR_RETRY_COUNT_BITS	3
#define PSIF_QP_CORE_8_RNR_RETRY_COUNT_MASK	0x0000003800000000ull

/*
 * When set, RQS should only check that the orig_checksum is equal to magic
 * number. When not set, RQS should perform the checksum check towards the
 * checksum in the psif_wr.
 */
#define PSIF_QP_CORE_NO_CHECKSUM_OFFSET	8
#define PSIF_QP_CORE_8_NO_CHECKSUM_BIT_POSITION		39
#define PSIF_QP_CORE_8_NO_CHECKSUM_BIT	0x0000008000000000ull

/*
 * Transport type of the QP (RC, UC, UD, XRC, MANSP1). MANSP1 is set for
 * privileged QPs.
 */
#define PSIF_QP_CORE_TRANSPORT_TYPE_OFFSET	9
#define PSIF_QP_CORE_9_TRANSPORT_TYPE_SHIFT	0
#define PSIF_QP_CORE_9_TRANSPORT_TYPE_BITS	3
#define PSIF_QP_CORE_9_TRANSPORT_TYPE_MASK	0x0000000000000007ull

/*
 * This is an index to completion queue descriptor. The descriptor points to
 * a receive completion queue, which may or may not be the same as the send
 * completion queue. For XRC QPs, this field is written by the CQ descriptor
 * received by the XRCSRQ on the first packet. This way we don't need to look
 * up the XRCSRQ for every packet. of the message.
 */
#define PSIF_QP_CORE_RCV_CQ_INDX_OFFSET	9
#define PSIF_QP_CORE_9_RCV_CQ_INDX_SHIFT	8
#define PSIF_QP_CORE_9_RCV_CQ_INDX_BITS	24
#define PSIF_QP_CORE_9_RCV_CQ_INDX_MASK	0x00000000ffffff00ull

/*
 * Number of bytes received of in progress RDMA Write or SEND. The data
 * received for SENDs and RDMA WR w/Imm are needed for completions. This
 * should be added to the msg_length.
 */
#define PSIF_QP_CORE_BYTES_RECEIVED_OFFSET	9
#define PSIF_QP_CORE_9_BYTES_RECEIVED_SHIFT	32
#define PSIF_QP_CORE_9_BYTES_RECEIVED_BITS	32
#define PSIF_QP_CORE_9_BYTES_RECEIVED_MASK	0xffffffff00000000ull

/* This QP is running IP over IB. */
#define PSIF_QP_CORE_IPOIB_OFFSET	10
#define PSIF_QP_CORE_10_IPOIB_BIT_POSITION		5
#define PSIF_QP_CORE_10_IPOIB_BIT	0x0000000000000020ull

/*
 * Combined 'Last Received MSN' and 'Last Outstanding MSN', used to maintain
 * 'spin set floor' and indicate 'all retries completed', respectively.
 */
#define PSIF_QP_CORE_LAST_RECEIVED_OUTSTANDING_MSN_OFFSET	11
#define PSIF_QP_CORE_11_LAST_RECEIVED_OUTSTANDING_MSN_SHIFT	0
#define PSIF_QP_CORE_11_LAST_RECEIVED_OUTSTANDING_MSN_BITS	16
#define PSIF_QP_CORE_11_LAST_RECEIVED_OUTSTANDING_MSN_MASK	0x000000000000ffffull

#define PSIF_QP_CORE_PATH_MTU_OFFSET	13
#define PSIF_QP_CORE_13_PATH_MTU_SHIFT	4
#define PSIF_QP_CORE_13_PATH_MTU_BITS	3
#define PSIF_QP_CORE_13_PATH_MTU_MASK	0x0000000000000070ull

/* This PSN is committed - ACKs sent will contain this PSN. */
#define PSIF_QP_CORE_COMMITTED_RECEIVED_PSN_OFFSET	13
#define PSIF_QP_CORE_13_COMMITTED_RECEIVED_PSN_SHIFT	8
#define PSIF_QP_CORE_13_COMMITTED_RECEIVED_PSN_BITS	24
#define PSIF_QP_CORE_13_COMMITTED_RECEIVED_PSN_MASK	0x00000000ffffff00ull

/*
 * Message sequence number used in AETH when sending ACKs. The number is
 * incremented every time a new inbound message is processed.
 */
#define PSIF_QP_CORE_MSN_OFFSET	14
#define PSIF_QP_CORE_14_MSN_SHIFT	0
#define PSIF_QP_CORE_14_MSN_BITS	24
#define PSIF_QP_CORE_14_MSN_MASK	0x0000000000ffffffull

/*
 * This is an index to send completion queue descriptor. The descriptor
 * points to a send completion queue, which may or may not be the same as the
 * send completion queue.
 */
#define PSIF_QP_CORE_SEND_CQ_INDX_OFFSET	14
#define PSIF_QP_CORE_14_SEND_CQ_INDX_SHIFT	24
#define PSIF_QP_CORE_14_SEND_CQ_INDX_BITS	24
#define PSIF_QP_CORE_14_SEND_CQ_INDX_MASK	0x0000ffffff000000ull

/*
 * Committed MSN - the MSN of the newest committed request for this QP. Only
 * the bottom 16 bits of the MSN is used.
 */
#define PSIF_QP_CORE_LAST_COMMITTED_MSN_OFFSET	14
#define PSIF_QP_CORE_14_LAST_COMMITTED_MSN_SHIFT	48
#define PSIF_QP_CORE_14_LAST_COMMITTED_MSN_BITS	16
#define PSIF_QP_CORE_14_LAST_COMMITTED_MSN_MASK	0xffff000000000000ull

#define PSIF_QP_CORE_SRQ_PD_OFFSET	15
#define PSIF_QP_CORE_15_SRQ_PD_SHIFT	0
#define PSIF_QP_CORE_15_SRQ_PD_BITS	24
#define PSIF_QP_CORE_15_SRQ_PD_MASK	0x0000000000ffffffull

#define PSIF_QP_PATH_REMOTE_GID_0_OFFSET	0
#define PSIF_QP_PATH_REMOTE_GID_0_SHIFT	0
#define PSIF_QP_PATH_REMOTE_GID_0_BITS	64
#define PSIF_QP_PATH_REMOTE_GID_0_MASK	0xffffffffffffffffull

#define PSIF_QP_PATH_REMOTE_GID_1_OFFSET	1
#define PSIF_QP_PATH_1_REMOTE_GID_1_SHIFT	0
#define PSIF_QP_PATH_1_REMOTE_GID_1_BITS	64
#define PSIF_QP_PATH_1_REMOTE_GID_1_MASK	0xffffffffffffffffull

#define PSIF_QP_PATH_REMOTE_LID_OFFSET	2
#define PSIF_QP_PATH_2_REMOTE_LID_SHIFT	0
#define PSIF_QP_PATH_2_REMOTE_LID_BITS	16
#define PSIF_QP_PATH_2_REMOTE_LID_MASK	0x000000000000ffffull

#define PSIF_QP_PATH_PORT_OFFSET	2
#define PSIF_QP_PATH_2_PORT_BIT_POSITION		17
#define PSIF_QP_PATH_2_PORT_BIT	0x0000000000020000ull

#define PSIF_QP_PATH_LOOPBACK_OFFSET	2
#define PSIF_QP_PATH_2_LOOPBACK_BIT_POSITION		18
#define PSIF_QP_PATH_2_LOOPBACK_BIT	0x0000000000040000ull

#define PSIF_QP_PATH_USE_GRH_OFFSET	2
#define PSIF_QP_PATH_2_USE_GRH_BIT_POSITION		19
#define PSIF_QP_PATH_2_USE_GRH_BIT	0x0000000000080000ull

#define PSIF_QP_PATH_SL_OFFSET	2
#define PSIF_QP_PATH_2_SL_SHIFT	20
#define PSIF_QP_PATH_2_SL_BITS	4
#define PSIF_QP_PATH_2_SL_MASK	0x0000000000f00000ull

#define PSIF_QP_PATH_HOPLMT_OFFSET	2
#define PSIF_QP_PATH_2_HOPLMT_SHIFT	28
#define PSIF_QP_PATH_2_HOPLMT_BITS	8
#define PSIF_QP_PATH_2_HOPLMT_MASK	0x0000000ff0000000ull

#define PSIF_QP_PATH_FLOWLABEL_OFFSET	2
#define PSIF_QP_PATH_2_FLOWLABEL_SHIFT	44
#define PSIF_QP_PATH_2_FLOWLABEL_BITS	20
#define PSIF_QP_PATH_2_FLOWLABEL_MASK	0xfffff00000000000ull

#define PSIF_QP_PATH_LOCAL_ACK_TIMEOUT_OFFSET	3
#define PSIF_QP_PATH_3_LOCAL_ACK_TIMEOUT_SHIFT	27
#define PSIF_QP_PATH_3_LOCAL_ACK_TIMEOUT_BITS	5
#define PSIF_QP_PATH_3_LOCAL_ACK_TIMEOUT_MASK	0x00000000f8000000ull

#define PSIF_QP_PATH_IPD_OFFSET	3
#define PSIF_QP_PATH_3_IPD_SHIFT	32
#define PSIF_QP_PATH_3_IPD_BITS	8
#define PSIF_QP_PATH_3_IPD_MASK	0x000000ff00000000ull

/*
 * This is the LID path bits. This is used by tsu_ibpb when generating the
 * SLID in the packet, and it is used by tsu_rcv when checking the DLID.
 */
#define PSIF_QP_PATH_LOCAL_LID_PATH_OFFSET	3
#define PSIF_QP_PATH_3_LOCAL_LID_PATH_SHIFT	48
#define PSIF_QP_PATH_3_LOCAL_LID_PATH_BITS	7
#define PSIF_QP_PATH_3_LOCAL_LID_PATH_MASK	0x007f000000000000ull

#define PSIF_QP_PATH_PKEY_INDX_OFFSET	3
#define PSIF_QP_PATH_3_PKEY_INDX_SHIFT	55
#define PSIF_QP_PATH_3_PKEY_INDX_BITS	9
#define PSIF_QP_PATH_3_PKEY_INDX_MASK	0xff80000000000000ull

/* L-key state for this DMA validation entry */
#define PSIF_KEY_LKEY_STATE_OFFSET	0
#define PSIF_KEY_LKEY_STATE_SHIFT	60
#define PSIF_KEY_LKEY_STATE_BITS	2
#define PSIF_KEY_LKEY_STATE_MASK	0x3000000000000000ull

/* R-key state for this DMA validation entry */
#define PSIF_KEY_RKEY_STATE_OFFSET	0
#define PSIF_KEY_RKEY_STATE_SHIFT	62
#define PSIF_KEY_RKEY_STATE_BITS	2
#define PSIF_KEY_RKEY_STATE_MASK	0xc000000000000000ull

/* Length of memory region this validation entry is associated with. */
#define PSIF_KEY_LENGTH_OFFSET	1
#define PSIF_KEY_1_LENGTH_SHIFT	0
#define PSIF_KEY_1_LENGTH_BITS	64
#define PSIF_KEY_1_LENGTH_MASK	0xffffffffffffffffull

#define PSIF_KEY_MMU_CONTEXT_OFFSET	2
#define PSIF_KEY_2_MMU_CONTEXT_SHIFT	0
#define PSIF_KEY_2_MMU_CONTEXT_BITS	64
#define PSIF_KEY_2_MMU_CONTEXT_MASK	0xffffffffffffffffull

#define PSIF_KEY_BASE_ADDR_OFFSET	3
#define PSIF_KEY_3_BASE_ADDR_SHIFT	0
#define PSIF_KEY_3_BASE_ADDR_BITS	64
#define PSIF_KEY_3_BASE_ADDR_MASK	0xffffffffffffffffull

/* sequence number for sanity checking */
#define PSIF_EQ_ENTRY_SEQ_NUM_OFFSET	7
#define PSIF_EQ_ENTRY_7_SEQ_NUM_SHIFT	0
#define PSIF_EQ_ENTRY_7_SEQ_NUM_BITS	32
#define PSIF_EQ_ENTRY_7_SEQ_NUM_MASK	0x00000000ffffffffull

/* enum psif_epsc_csr_opcode from request */
#define PSIF_EPSC_CSR_RSP_OPCODE_OFFSET	0
#define PSIF_EPSC_CSR_RSP_OPCODE_SHIFT	48
#define PSIF_EPSC_CSR_RSP_OPCODE_BITS	8
#define PSIF_EPSC_CSR_RSP_OPCODE_MASK	0x00ff000000000000ull

/* Sequence number from request */
#define PSIF_EPSC_CSR_RSP_SEQ_NUM_OFFSET	3
#define PSIF_EPSC_CSR_RSP_3_SEQ_NUM_SHIFT	0
#define PSIF_EPSC_CSR_RSP_3_SEQ_NUM_BITS	64
#define PSIF_EPSC_CSR_RSP_3_SEQ_NUM_MASK	0xffffffffffffffffull

/* Sequence number - included in response */
#define PSIF_EPSC_CSR_REQ_SEQ_NUM_OFFSET	0
#define PSIF_EPSC_CSR_REQ_SEQ_NUM_SHIFT	32
#define PSIF_EPSC_CSR_REQ_SEQ_NUM_BITS	16
#define PSIF_EPSC_CSR_REQ_SEQ_NUM_MASK	0x0000ffff00000000ull

#define PSIF_EPSC_CSR_REQ_OPCODE_OFFSET	0
#define PSIF_EPSC_CSR_REQ_OPCODE_SHIFT	56
#define PSIF_EPSC_CSR_REQ_OPCODE_BITS	8
#define PSIF_EPSC_CSR_REQ_OPCODE_MASK	0xff00000000000000ull

/* Index to completion elements added by SW. */
#define PSIF_CQ_SW_HEAD_INDX_OFFSET	0
#define PSIF_CQ_SW_HEAD_INDX_SHIFT	32
#define PSIF_CQ_SW_HEAD_INDX_BITS	32
#define PSIF_CQ_SW_HEAD_INDX_MASK	0xffffffff00000000ull

/*
 * EPS-A core number completions are forwarded to if the proxy_enabled bit is
 * set.
 */
#define PSIF_CQ_HW_EPS_CORE_OFFSET	0
#define PSIF_CQ_HW_EPS_CORE_SHIFT	52
#define PSIF_CQ_HW_EPS_CORE_BITS	2
#define PSIF_CQ_HW_EPS_CORE_MASK	0x0030000000000000ull

/*
 * If set, this completion queue is proxy enabled and should send completions
 * to EPS core indicated by the eps_core field.
 */
#define PSIF_CQ_HW_PROXY_EN_OFFSET	0
#define PSIF_CQ_HW_PROXY_EN_BIT_POSITION		54
#define PSIF_CQ_HW_PROXY_EN_BIT	0x0040000000000000ull

/* The descriptor is valid. */
#define PSIF_CQ_HW_VALID_OFFSET	0
#define PSIF_CQ_HW_VALID_BIT_POSITION		60
#define PSIF_CQ_HW_VALID_BIT	0x1000000000000000ull

/*
 * VA or PA of the base of the completion queue. If PA the MMU context above
 * will be a bypass context. Updated by software. The head and tail pointers
 * can be calculated by the following calculations: Address = base_ptr +
 * (head * ($bits(completion_entry_t)/8 ) Head Pointer and Tail Pointer will
 * use the same MMU context as the base, and all need to be VA from one
 * address space, or all need to be PA. In typical use, to allow direct user
 * access to the head and tail pointer VAs are used.
 */
#define PSIF_CQ_HW_BASE_ADDR_OFFSET	2
#define PSIF_CQ_HW_2_BASE_ADDR_SHIFT	0
#define PSIF_CQ_HW_2_BASE_ADDR_BITS	64
#define PSIF_CQ_HW_2_BASE_ADDR_MASK	0xffffffffffffffffull

/* Index to completion elements to be consumed by HW. */
#define PSIF_CQ_HW_TAIL_INDX_OFFSET	3
#define PSIF_CQ_HW_3_TAIL_INDX_SHIFT	32
#define PSIF_CQ_HW_3_TAIL_INDX_BITS	32
#define PSIF_CQ_HW_3_TAIL_INDX_MASK	0xffffffff00000000ull

/*
 * Work queue completion ID. For receive completions this is the entry number
 * in the receive queue and the receive queue descriptor index. For send
 * completions this is the sq_sequence number.
 */
#define PSIF_CQ_ENTRY_WC_ID_OFFSET	0
#define PSIF_CQ_ENTRY_WC_ID_SHIFT	0
#define PSIF_CQ_ENTRY_WC_ID_BITS	64
#define PSIF_CQ_ENTRY_WC_ID_MASK	0xffffffffffffffffull

#define PSIF_CQ_ENTRY_QP_OFFSET	1
#define PSIF_CQ_ENTRY_1_QP_SHIFT	0
#define PSIF_CQ_ENTRY_1_QP_BITS	24
#define PSIF_CQ_ENTRY_1_QP_MASK	0x0000000000ffffffull

#define PSIF_CQ_ENTRY_OPCODE_OFFSET	1
#define PSIF_CQ_ENTRY_1_OPCODE_SHIFT	24
#define PSIF_CQ_ENTRY_1_OPCODE_BITS	8
#define PSIF_CQ_ENTRY_1_OPCODE_MASK	0x00000000ff000000ull

#define PSIF_CQ_ENTRY_STATUS_OFFSET	2
#define PSIF_CQ_ENTRY_2_STATUS_SHIFT	24
#define PSIF_CQ_ENTRY_2_STATUS_BITS	8
#define PSIF_CQ_ENTRY_2_STATUS_MASK	0x00000000ff000000ull

/* sequence number for sanity checking */
#define PSIF_CQ_ENTRY_SEQ_NUM_OFFSET	7
#define PSIF_CQ_ENTRY_7_SEQ_NUM_SHIFT	0
#define PSIF_CQ_ENTRY_7_SEQ_NUM_BITS	32
#define PSIF_CQ_ENTRY_7_SEQ_NUM_MASK	0x00000000ffffffffull

#define PSIF_AH_REMOTE_LID_OFFSET	2
#define PSIF_AH_2_REMOTE_LID_SHIFT	0
#define PSIF_AH_2_REMOTE_LID_BITS	16
#define PSIF_AH_2_REMOTE_LID_MASK	0x000000000000ffffull
#if defined(HOST_LITTLE_ENDIAN)
#include "psif_hw_macro_le.h"
#elif defined(HOST_BIG_ENDIAN)
#include "psif_hw_macro_be.h"
#else
#error "Could not determine byte order in psif_hw_macro.h !?"
#endif




#endif	/* _PSIF_HW_MACRO_H */
