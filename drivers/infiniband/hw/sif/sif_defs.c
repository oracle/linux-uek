/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_defs.c: IB-to-SIF Mapper.
 */
#include <linux/version.h>
#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_defs.h"
#include "psif_hw_setget.h"
#include "sif_qp.h"

/* This is where we build and define kernel utilities for logging psif structures: */
#define copy_convert	   copy_conv_to_sw
#define copy_convert_to_sw copy_conv_to_sw
#define copy_convert_to_hw copy_conv_to_hw
#define assert(x) BUG_ON(!(x))
#include "psif_hw_print.c"

enum psif_wr_type sif_invalidate_opcode(enum sif_tab_type type)
{
	switch (type) {
	case rq_sw:
	case rq_hw:
		return PSIF_WR_INVALIDATE_RQ;
	case cq_sw:
	case cq_hw:
		return PSIF_WR_INVALIDATE_CQ;
	case key:
		return PSIF_WR_INVALIDATE_BOTH_KEYS;
	case qp:
		return PSIF_WR_INVALIDATE_SGL_CACHE;
	default:
		/* This function is used to figure out if an invalidate
		 * request is needed so ending here is a normal case
		 */
		break;
	}
	return (enum psif_wr_type)-1;
}


enum psif_wr_type ib2sif_wr_op(enum ib_wr_opcode op, bool is_dr)
{
	switch (op) {
	case IB_WR_RDMA_WRITE:
		return PSIF_WR_RDMA_WR;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return PSIF_WR_RDMA_WR_IMM;
	case IB_WR_SEND:
		return !is_dr ? PSIF_WR_SEND : PSIF_WR_QP0_SEND_DR_LOOPBACK;
	case IB_WR_SEND_WITH_IMM:
		return PSIF_WR_SEND_IMM;
	case IB_WR_RDMA_READ:
		return PSIF_WR_RDMA_RD;
	case IB_WR_ATOMIC_CMP_AND_SWP:
		return PSIF_WR_CMP_SWAP;
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		return PSIF_WR_FETCH_ADD;
	case IB_WR_MASKED_ATOMIC_CMP_AND_SWP:
		return PSIF_WR_MASK_CMP_SWAP;
	case IB_WR_MASKED_ATOMIC_FETCH_AND_ADD:
		return PSIF_WR_MASK_FETCH_ADD;
	case IB_WR_LSO:
		return PSIF_WR_LSO;
	case IB_WR_SEND_WITH_INV:
	case IB_WR_RDMA_READ_WITH_INV:
	case IB_WR_LOCAL_INV:
	default:
		break;
	}
	sif_log0(SIF_INFO, "Unsupported opcode %d", op);
	return (enum psif_wr_type)-1;
}

enum ib_wr_opcode sif2ib_wr_op(enum psif_wr_type op)
{
	switch (op) {
	case PSIF_WR_SEND:
		return IB_WR_SEND;
	case PSIF_WR_SEND_IMM:
		return IB_WR_SEND_WITH_IMM;
	case PSIF_WR_RDMA_WR:
		return IB_WR_RDMA_WRITE;
	case PSIF_WR_RDMA_WR_IMM:
		return IB_WR_RDMA_WRITE_WITH_IMM;
	case PSIF_WR_RDMA_RD:
		return IB_WR_RDMA_READ;
	case PSIF_WR_CMP_SWAP:
		return IB_WR_ATOMIC_CMP_AND_SWP;
	case PSIF_WR_FETCH_ADD:
		return IB_WR_ATOMIC_FETCH_AND_ADD;
	case PSIF_WR_MASK_CMP_SWAP:
		return IB_WR_MASKED_ATOMIC_CMP_AND_SWP;
	case PSIF_WR_MASK_FETCH_ADD:
		return IB_WR_MASKED_ATOMIC_FETCH_AND_ADD;
	case PSIF_WR_LSO:
		return IB_WR_LSO;
	case PSIF_WR_INVALIDATE_RKEY:
	case PSIF_WR_INVALIDATE_LKEY:
	case PSIF_WR_INVALIDATE_BOTH_KEYS:
	case PSIF_WR_INVALIDATE_TLB:
	case PSIF_WR_RESIZE_CQ:
	case PSIF_WR_SET_SRQ_LIM:
	case PSIF_WR_SET_XRCSRQ_LIM:
	case PSIF_WR_INVALIDATE_RQ:
	case PSIF_WR_INVALIDATE_CQ:
	case PSIF_WR_INVALIDATE_XRCSRQ:
	default:
		break;
	}
	sif_log0(SIF_INFO, "Unable to convert opcode %d", op);
	return (enum ib_wr_opcode)-1;
}

/* TBD: These should map directly - must add test first */
enum ib_wc_opcode sif2ib_wc_opcode(enum psif_wc_opcode opcode)
{
	switch (opcode) {
	case PSIF_WC_OPCODE_SEND:
		return IB_WC_SEND;
	case PSIF_WC_OPCODE_RDMA_WR:
		return IB_WC_RDMA_WRITE;
	case PSIF_WC_OPCODE_RDMA_READ:
		return IB_WC_RDMA_READ;
	case PSIF_WC_OPCODE_CMP_SWAP:
		return IB_WC_COMP_SWAP;
	case PSIF_WC_OPCODE_FETCH_ADD:
		return IB_WC_FETCH_ADD;
	case PSIF_WC_OPCODE_LSO:
		return IB_WC_LSO;
	case PSIF_WC_OPCODE_MASKED_CMP_SWAP:
		return IB_WC_MASKED_COMP_SWAP;
	case PSIF_WC_OPCODE_MASKED_FETCH_ADD:
		return IB_WC_MASKED_FETCH_ADD;
	case PSIF_WC_OPCODE_RECEIVE_SEND:
		return IB_WC_RECV;
	case PSIF_WC_OPCODE_RECEIVE_RDMA_WR_IMM:
		return IB_WC_RECV_RDMA_WITH_IMM;
	case PSIF_WC_OPCODE_INVALIDATE_SGL_CACHE:
		return PSIF_WR_INVALIDATE_SGL_CACHE;
	case PSIF_WC_OPCODE_INVALIDATE_RKEY:
	case PSIF_WC_OPCODE_INVALIDATE_LKEY:
	case PSIF_WC_OPCODE_INVALIDATE_BOTH_KEYS:
	case PSIF_WC_OPCODE_INVALIDATE_TLB:
	case PSIF_WC_OPCODE_RESIZE_CQ:
	case PSIF_WC_OPCODE_SET_SRQ_LIM:
	case PSIF_WC_OPCODE_REQ_CMPL_NOTIFY:
	case PSIF_WC_OPCODE_CMPL_NOTIFY_RCVD:
	case PSIF_WC_OPCODE_REARM_CMPL_EVENT:
	case PSIF_WC_OPCODE_SET_XRCSRQ_LIM:
	case PSIF_WC_OPCODE_INVALIDATE_RQ:
	case PSIF_WC_OPCODE_INVALIDATE_CQ:
	case PSIF_WC_OPCODE_INVALIDATE_RB:
	case PSIF_WC_OPCODE_INVALIDATE_XRCSRQ:
	case PSIF_WC_OPCODE_GENERATE_COMPLETION:
	case PSIF_WC_OPCODE_RECEIVE_CONDITIONAL_WR_IMM:
		break;
	}
	return -1;
}

enum psif_wc_opcode ib2sif_wc_opcode(enum ib_wc_opcode opcode)
{
	switch (opcode) {
	case IB_WC_SEND:
		return PSIF_WC_OPCODE_SEND;
	case IB_WC_RDMA_WRITE:
		return PSIF_WC_OPCODE_RDMA_WR;
	case IB_WC_RDMA_READ:
		return PSIF_WC_OPCODE_RDMA_READ;
	case IB_WC_COMP_SWAP:
		return PSIF_WC_OPCODE_CMP_SWAP;
	case IB_WC_FETCH_ADD:
		return PSIF_WC_OPCODE_FETCH_ADD;
	case IB_WC_LSO:
		return PSIF_WC_OPCODE_LSO;
	case IB_WC_MASKED_COMP_SWAP:
		return PSIF_WC_OPCODE_MASKED_CMP_SWAP;
	case IB_WC_MASKED_FETCH_ADD:
		return PSIF_WC_OPCODE_MASKED_FETCH_ADD;
	case IB_WC_RECV:
		return PSIF_WC_OPCODE_RECEIVE_SEND;
	case IB_WC_RECV_RDMA_WITH_IMM:
		return PSIF_WC_OPCODE_RECEIVE_RDMA_WR_IMM;
	case IB_WC_LOCAL_INV:
	case IB_WC_BIND_MW:
	case IB_WC_FAST_REG_MR:
		break;
	}
	sif_log0(SIF_INFO, "IB opcode %d not implemented", opcode);
	return -1;
}

enum ib_wc_status sif2ib_wc_status(enum psif_wc_status status)
{
	switch (status) {
	case PSIF_WC_STATUS_SUCCESS:
		return IB_WC_SUCCESS;
	case PSIF_WC_STATUS_LOC_LEN_ERR:
		return IB_WC_LOC_LEN_ERR;
	case PSIF_WC_STATUS_LOC_QP_OP_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case PSIF_WC_STATUS_LOC_EEC_OP_ERR:
		return IB_WC_LOC_EEC_OP_ERR;
	case PSIF_WC_STATUS_LOC_PROT_ERR:
		return IB_WC_LOC_PROT_ERR;
	case PSIF_WC_STATUS_WR_FLUSH_ERR:
		return IB_WC_WR_FLUSH_ERR;
	case PSIF_WC_STATUS_MW_BIND_ERR:
		return IB_WC_MW_BIND_ERR;
	case PSIF_WC_STATUS_BAD_RESP_ERR:
		return IB_WC_BAD_RESP_ERR;
	case PSIF_WC_STATUS_LOC_ACCESS_ERR:
		return IB_WC_LOC_ACCESS_ERR;
	case PSIF_WC_STATUS_REM_INV_REQ_ERR:
		return IB_WC_REM_INV_REQ_ERR;
	case PSIF_WC_STATUS_REM_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case PSIF_WC_STATUS_REM_OP_ERR:
		return IB_WC_REM_OP_ERR;
	case PSIF_WC_STATUS_RETRY_EXC_ERR:
		return IB_WC_RETRY_EXC_ERR;
	case PSIF_WC_STATUS_RNR_RETRY_EXC_ERR:
		return IB_WC_RNR_RETRY_EXC_ERR;
	case PSIF_WC_STATUS_LOC_RDD_VIOL_ERR:
		return IB_WC_LOC_RDD_VIOL_ERR;
	case PSIF_WC_STATUS_REM_INV_RD_REQ_ERR:
		return IB_WC_REM_INV_RD_REQ_ERR;
	case PSIF_WC_STATUS_REM_ABORT_ERR:
		return IB_WC_REM_ABORT_ERR;
	case PSIF_WC_STATUS_INV_EECN_ERR:
		return IB_WC_INV_EECN_ERR;
	case PSIF_WC_STATUS_INV_EEC_STATE_ERR:
		return IB_WC_INV_EEC_STATE_ERR;
	case PSIF_WC_STATUS_FATAL_ERR:
		return IB_WC_FATAL_ERR;
	case PSIF_WC_STATUS_RESP_TIMEOUT_ERR:
		return IB_WC_RESP_TIMEOUT_ERR;
	case PSIF_WC_STATUS_GENERAL_ERR:
		return IB_WC_GENERAL_ERR;
	case PSIF_WC_STATUS_FIELD_MAX:
		return -1;
	}
	return -1;
}

enum psif_wc_status ib2sif_wc_status(enum ib_wc_status status)
{
	switch (status) {
	case IB_WC_SUCCESS:
		return PSIF_WC_STATUS_LOC_LEN_ERR;
	case IB_WC_LOC_LEN_ERR:
		return PSIF_WC_STATUS_LOC_LEN_ERR;
	case IB_WC_LOC_QP_OP_ERR:
		return PSIF_WC_STATUS_LOC_QP_OP_ERR;
	case IB_WC_LOC_EEC_OP_ERR:
		return PSIF_WC_STATUS_LOC_EEC_OP_ERR;
	case IB_WC_LOC_PROT_ERR:
		return PSIF_WC_STATUS_LOC_PROT_ERR;
	case IB_WC_WR_FLUSH_ERR:
		return PSIF_WC_STATUS_WR_FLUSH_ERR;
	case IB_WC_MW_BIND_ERR:
		return PSIF_WC_STATUS_MW_BIND_ERR;
	case IB_WC_BAD_RESP_ERR:
		return PSIF_WC_STATUS_BAD_RESP_ERR;
	case IB_WC_LOC_ACCESS_ERR:
		return PSIF_WC_STATUS_LOC_ACCESS_ERR;
	case IB_WC_REM_INV_REQ_ERR:
		return PSIF_WC_STATUS_REM_INV_REQ_ERR;
	case IB_WC_REM_ACCESS_ERR:
		return PSIF_WC_STATUS_REM_ACCESS_ERR;
	case IB_WC_REM_OP_ERR:
		return PSIF_WC_STATUS_REM_OP_ERR;
	case IB_WC_RETRY_EXC_ERR:
		return PSIF_WC_STATUS_RETRY_EXC_ERR;
	case IB_WC_RNR_RETRY_EXC_ERR:
		return PSIF_WC_STATUS_RNR_RETRY_EXC_ERR;
	case IB_WC_LOC_RDD_VIOL_ERR:
		return PSIF_WC_STATUS_LOC_RDD_VIOL_ERR;
	case IB_WC_REM_INV_RD_REQ_ERR:
		return PSIF_WC_STATUS_REM_INV_RD_REQ_ERR;
	case IB_WC_REM_ABORT_ERR:
		return PSIF_WC_STATUS_REM_ABORT_ERR;
	case IB_WC_INV_EECN_ERR:
		return PSIF_WC_STATUS_INV_EECN_ERR;
	case IB_WC_INV_EEC_STATE_ERR:
		return PSIF_WC_STATUS_INV_EEC_STATE_ERR;
	case IB_WC_FATAL_ERR:
		return PSIF_WC_STATUS_FATAL_ERR;
	case IB_WC_RESP_TIMEOUT_ERR:
		return PSIF_WC_STATUS_RESP_TIMEOUT_ERR;
	case IB_WC_GENERAL_ERR:
		return PSIF_WC_STATUS_GENERAL_ERR;
	}
	return -1;
}


enum psif_qp_trans ib2sif_qp_type(enum ib_qp_type type)
{
	switch (type) {
	case IB_QPT_RC:
		return PSIF_QP_TRANSPORT_RC;
	case IB_QPT_UC:
		return PSIF_QP_TRANSPORT_UC;
	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_UD:
		return PSIF_QP_TRANSPORT_UD;
	case IB_QPT_RAW_IPV6:
	case IB_QPT_RAW_ETHERTYPE:
		break;
	case IB_QPT_XRC_INI:
	case IB_QPT_XRC_TGT:
		return PSIF_QP_TRANSPORT_XRC;
	case IB_QPT_MAX:
	case IB_QPT_RAW_PACKET:
	/* IB_QPT_EPSA_TUNNELING = IB_QPT_RESERVED1; */
		break;
	case IB_QPT_EPSA_TUNNELING:
		return PSIF_QP_TRANSPORT_UD;

	case IB_QPT_RESERVED2:
	case IB_QPT_RESERVED3:
	case IB_QPT_RESERVED4:
	case IB_QPT_RESERVED5:
	case IB_QPT_RESERVED6:
	case IB_QPT_RESERVED7:
	case IB_QPT_RESERVED8:
	case IB_QPT_RESERVED9:
	case IB_QPT_RESERVED10:
		break;
	}
	/* map to a value we don't support as the
	 * error status value for now..
	 */
	return (enum psif_qp_trans)(-1);
}


enum psif_qp_state ib2sif_qp_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:
		return PSIF_QP_STATE_RESET;
	case IB_QPS_INIT:
		return PSIF_QP_STATE_INIT;
	case IB_QPS_RTR:
		return PSIF_QP_STATE_RTR;
	case IB_QPS_RTS:
		return PSIF_QP_STATE_RTS;
	case IB_QPS_ERR:
		return PSIF_QP_STATE_ERROR;
	case IB_QPS_SQE:
		return PSIF_QP_STATE_SQERR;
	case IB_QPS_SQD: /* TBD: Is this right? */
		break;
	}
	return PSIF_QP_STATE_INVALID;
}


enum ib_qp_state sif2ib_qp_state(enum psif_qp_state state)
{
	switch (state) {
	case PSIF_QP_STATE_RESET:
		return IB_QPS_RESET;
	case PSIF_QP_STATE_INIT:
		return IB_QPS_INIT;
	case PSIF_QP_STATE_RTR:
		return IB_QPS_RTR;
	case PSIF_QP_STATE_RTS:
		return IB_QPS_RTS;
	case PSIF_QP_STATE_ERROR:
		return IB_QPS_ERR;
	case PSIF_QP_STATE_SQERR:
		return IB_QPS_SQE;
	case PSIF_QP_STATE_INVALID:
		break;
	}
	return IB_QPS_ERR;
}

enum psif_migration ib2sif_mig_state(enum ib_mig_state mstate)
{
	switch (mstate) {
	case IB_MIG_MIGRATED:
		return APM_MIGRATED;
	case IB_MIG_REARM:
		return APM_REARM;
	case IB_MIG_ARMED:
		return APM_ARMED;
	}
	return APM_OFF;
}

enum ib_mig_state sif2ib_mig_state(enum psif_migration mstate)
{
	switch (mstate) {
	case APM_MIGRATED:
		return IB_MIG_MIGRATED;
	case APM_REARM:
		return IB_MIG_REARM;
	case APM_ARMED:
		return IB_MIG_ARMED;
	default:
		return (enum ib_mig_state)-1;
	}
}

enum psif_path_mtu ib2sif_path_mtu(enum ib_mtu mtu)
{
	switch (mtu) {
	case IB_MTU_256:
		return MTU_256B;
	case IB_MTU_512:
		return MTU_512B;
	case IB_MTU_1024:
		return MTU_1024B;
	case IB_MTU_2048:
		return MTU_2048B;
	case IB_MTU_4096:
		return MTU_4096B;
	}
	return MTU_INVALID;
}

enum ib_mtu sif2ib_path_mtu(enum psif_path_mtu mtu)
{
	switch (mtu) {
	case MTU_256B:
		return IB_MTU_256;
	case MTU_512B:
		return IB_MTU_512;
	case MTU_1024B:
		return IB_MTU_1024;
	case MTU_2048B:
		return IB_MTU_2048;
	case MTU_4096B:
		return IB_MTU_4096;
	default:
		return (enum ib_mtu)0;
	}
}


/* TBD: IB datastructure dump functions - remove/replace? */

const char *ib_event2str(enum ib_event_type e)
{
	switch (e) {
	case IB_EVENT_CQ_ERR:
		return "IB_EVENT_CQ_ERR";
	case IB_EVENT_QP_FATAL:
		return "IB_EVENT_QP_FATAL";
	case IB_EVENT_QP_REQ_ERR:
		return "IB_EVENT_QP_REQ_ERR";
	case IB_EVENT_QP_ACCESS_ERR:
		return "IB_EVENT_QP_ACCESS_ERR";
	case IB_EVENT_COMM_EST:
		return "IB_EVENT_COMM_EST";
	case IB_EVENT_SQ_DRAINED:
		return "IB_EVENT_SQ_DRAINED";
	case IB_EVENT_PATH_MIG:
		return "IB_EVENT_PATH_MIG";
	case IB_EVENT_PATH_MIG_ERR:
		return "IB_EVENT_PATH_MIG_ERR";
	case IB_EVENT_DEVICE_FATAL:
		return "IB_EVENT_DEVICE_FATAL";
	case IB_EVENT_PORT_ACTIVE:
		return "IB_EVENT_PORT_ACTIVE";
	case IB_EVENT_PORT_ERR:
		return "IB_EVENT_PORT_ERR";
	case IB_EVENT_LID_CHANGE:
		return "IB_EVENT_LID_CHANGE";
	case IB_EVENT_PKEY_CHANGE:
		return "IB_EVENT_PKEY_CHANGE";
	case IB_EVENT_SM_CHANGE:
		return "IB_EVENT_SM_CHANGE";
	case IB_EVENT_SRQ_ERR:
		return "IB_EVENT_SRQ_ERR";
	case IB_EVENT_SRQ_LIMIT_REACHED:
		return "IB_EVENT_SRQ_LIMIT_REACHED";
	case IB_EVENT_QP_LAST_WQE_REACHED:
		return "IB_EVENT_QP_LAST_WQE_REACHED";
	case IB_EVENT_CLIENT_REREGISTER:
		return "IB_EVENT_CLIENT_REREGISTER";
	case IB_EVENT_GID_CHANGE:
		return "IB_EVENT_GID_CHANGE";
	default:
		return "(Undefined event type)";
	}
}

static inline enum kernel_ulp_type find_ulp_type_from_address(void *ptr)
{
	if (ptr) {
#if defined(__x86_64__) || defined(__sparc__) || defined(__aarch64__)
		char symbol_name[100];

		snprintf(symbol_name, sizeof(symbol_name), "%ps", ptr);
		if (strstr(symbol_name, "rds_"))
			return RDS_ULP;
		else if (strstr(symbol_name, "ipoib_cm_"))
			return IPOIB_CM_ULP;
		else if (strstr(symbol_name, "ipoib_"))
			return IPOIB_ULP;
#endif
	}
	return OTHER_ULP;
}

static inline enum kernel_ulp_type find_ulp_type_via_stack_unwind(const int level)
{
/* __builtin_return_address argument must be a constant */
#define STACK_UNWIND_CASE_LEVEL(n) \
	case (n):  { \
		enum kernel_ulp_type type = OTHER_ULP;	\
		void *ptr = __builtin_return_address(n);\
		type = find_ulp_type_from_address(ptr);	\
		if (type != OTHER_ULP)	\
			return type;	\
	}

	switch (level) {
	default:
		STACK_UNWIND_CASE_LEVEL(7);
		STACK_UNWIND_CASE_LEVEL(6);
		STACK_UNWIND_CASE_LEVEL(5);
		STACK_UNWIND_CASE_LEVEL(4);
		STACK_UNWIND_CASE_LEVEL(3);
		STACK_UNWIND_CASE_LEVEL(2);
		STACK_UNWIND_CASE_LEVEL(1);
		STACK_UNWIND_CASE_LEVEL(0);
	}
#undef STACK_UNWIND_CASE_LEVEL
	return OTHER_ULP;
}

enum kernel_ulp_type sif_find_kernel_ulp_caller(void)
{
	enum kernel_ulp_type type = OTHER_ULP;

	if (!(__builtin_return_address(0))) {
		/* if current function returns NULL,
		 * there is no reason to check further.
		 */
		goto error;
	}
	type = find_ulp_type_via_stack_unwind(STACK_UNWIND_LEVEL);
error:
	return type;
}
