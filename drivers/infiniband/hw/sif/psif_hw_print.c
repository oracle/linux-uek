/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_HW_PRINT_C
#define	_PSIF_HW_PRINT_C

#if defined(__arm__)

#include <stdio.h>
#include <stdint.h>
#include "psif_endian.h"
typedef uint64_t __be64;

#else /* virtualized  */

#endif /* __arm__ */

#include "psif_api.h"
#include "psif_hw_data.h"
#include "psif_hw_macro.h"
#include "psif_hw_setget.h"
#include "psif_hw_print.h"
#include "psif_api.h"

#if !defined(xprintf)
#define xprintf fprintf
#endif
#if !defined(OS_PRIx64)
#define OS_PRIx64 "llx"
#endif

/* Write fixed size bit field represented as unsigned int types */
void write_bits_u8(XFILE *fd, int extent, u8 data)
{
	xprintf(fd, "%#04x", data);
} /* end write_bits_u8(u8 data) */

/* Write fixed size bit field represented as unsigned int types */
void write_bits_u16(XFILE *fd, int extent, u16 data)
{
	xprintf(fd, "%#06x", data);
} /* end write_bits_u16(u16 data) */

/* Write fixed size bit field represented as unsigned int types */
void write_bits_u32(XFILE *fd, int extent, u32 data)
{
	xprintf(fd, "%#010x", data);
} /* end write_bits_u32(u32 data) */

/* Write fixed size bit field represented as unsigned int types */
void write_bits_u64(XFILE *fd, int extent, u64 data)
{
	xprintf(fd, "%#018" OS_PRIx64 "", data);
} /* end write_bits_u64(u64 data) */


/* Convert enum psif_mmu_translation to string */
const char *string_enum_psif_mmu_translation(enum psif_mmu_translation val)
{
	switch (val) {
	case MMU_PASS_THROUGH0:
		return "MMU_PASS_THROUGH0";
	case MMU_PASS_THROUGH_PAD:
		return "MMU_PASS_THROUGH_PAD";
	case MMU_GVA2GPA_MODE:
		return "MMU_GVA2GPA_MODE";
	case MMU_GVA2GPA_MODE_PAD:
		return "MMU_GVA2GPA_MODE_PAD";
	case MMU_PRETRANSLATED:
		return "MMU_PRETRANSLATED";
	case MMU_PRETRANSLATED_PAD:
		return "MMU_PRETRANSLATED_PAD";
	case MMU_EPSA_MODE:
		return "MMU_EPSA_MODE";
	case MMU_EPSC_MODE:
		return "MMU_EPSC_MODE";
	default:
		return "UNKNOWN_psif_mmu_translation";
	}
}

void write_enum_psif_mmu_translation(XFILE *fd,
	enum psif_mmu_translation data)
{
	xprintf(fd, "%s", string_enum_psif_mmu_translation(data));
} /* end write_..._psif_mmu_translation(psif_mmu_translation data) */

/* Convert enum psif_page_size to string */
const char *string_enum_psif_page_size(enum psif_page_size val)
{
	switch (val) {
	case PAGE_SIZE_IA32E_4KB:
		return "PAGE_SIZE_IA32E_4KB";
	case PAGE_SIZE_IA32E_2MB:
		return "PAGE_SIZE_IA32E_2MB";
	case PAGE_SIZE_IA32E_1GB:
		return "PAGE_SIZE_IA32E_1GB";
	case PAGE_SIZE_S64_8KB:
		return "PAGE_SIZE_S64_8KB";
	case PAGE_SIZE_S64_64KB:
		return "PAGE_SIZE_S64_64KB";
	case PAGE_SIZE_S64_512KB:
		return "PAGE_SIZE_S64_512KB";
	case PAGE_SIZE_S64_4MB:
		return "PAGE_SIZE_S64_4MB";
	case PAGE_SIZE_S64_32MB:
		return "PAGE_SIZE_S64_32MB";
	case PAGE_SIZE_S64_2GB:
		return "PAGE_SIZE_S64_2GB";
	case PAGE_SIZE_S64_16GB:
		return "PAGE_SIZE_S64_16GB";
	default:
		return "UNKNOWN_psif_page_size";
	}
}

void write_enum_psif_page_size(XFILE *fd,
	enum psif_page_size data)
{
	xprintf(fd, "%s", string_enum_psif_page_size(data));
} /* end write_..._psif_page_size(psif_page_size data) */

/* Convert enum psif_wr_type to string */
const char *string_enum_psif_wr_type(enum psif_wr_type val)
{
	switch (val) {
	case PSIF_WR_SEND:
		return "PSIF_WR_SEND";
	case PSIF_WR_SEND_IMM:
		return "PSIF_WR_SEND_IMM";
	case PSIF_WR_SPECIAL_QP_SEND:
		return "PSIF_WR_SPECIAL_QP_SEND";
	case PSIF_WR_QP0_SEND_DR_XMIT:
		return "PSIF_WR_QP0_SEND_DR_XMIT";
	case PSIF_WR_QP0_SEND_DR_LOOPBACK:
		return "PSIF_WR_QP0_SEND_DR_LOOPBACK";
	case PSIF_WR_EPS_SPECIAL_QP_SEND:
		return "PSIF_WR_EPS_SPECIAL_QP_SEND";
	case PSIF_WR_EPS_QP0_SEND_DR_XMIT:
		return "PSIF_WR_EPS_QP0_SEND_DR_XMIT";
	case PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK:
		return "PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK";
	case PSIF_WR_RDMA_WR:
		return "PSIF_WR_RDMA_WR";
	case PSIF_WR_RDMA_WR_IMM:
		return "PSIF_WR_RDMA_WR_IMM";
	case PSIF_WR_RDMA_RD:
		return "PSIF_WR_RDMA_RD";
	case PSIF_WR_CMP_SWAP:
		return "PSIF_WR_CMP_SWAP";
	case PSIF_WR_FETCH_ADD:
		return "PSIF_WR_FETCH_ADD";
	case PSIF_WR_MASK_CMP_SWAP:
		return "PSIF_WR_MASK_CMP_SWAP";
	case PSIF_WR_MASK_FETCH_ADD:
		return "PSIF_WR_MASK_FETCH_ADD";
	case PSIF_WR_LSO:
		return "PSIF_WR_LSO";
	case PSIF_WR_INVALIDATE_RKEY:
		return "PSIF_WR_INVALIDATE_RKEY";
	case PSIF_WR_INVALIDATE_LKEY:
		return "PSIF_WR_INVALIDATE_LKEY";
	case PSIF_WR_INVALIDATE_BOTH_KEYS:
		return "PSIF_WR_INVALIDATE_BOTH_KEYS";
	case PSIF_WR_INVALIDATE_TLB:
		return "PSIF_WR_INVALIDATE_TLB";
	case PSIF_WR_RESIZE_CQ:
		return "PSIF_WR_RESIZE_CQ";
	case PSIF_WR_SET_SRQ_LIM:
		return "PSIF_WR_SET_SRQ_LIM";
	case PSIF_WR_SET_XRCSRQ_LIM:
		return "PSIF_WR_SET_XRCSRQ_LIM";
	case PSIF_WR_REQ_CMPL_NOTIFY:
		return "PSIF_WR_REQ_CMPL_NOTIFY";
	case PSIF_WR_CMPL_NOTIFY_RCVD:
		return "PSIF_WR_CMPL_NOTIFY_RCVD";
	case PSIF_WR_REARM_CMPL_EVENT:
		return "PSIF_WR_REARM_CMPL_EVENT";
	case PSIF_WR_GENERATE_COMPLETION:
		return "PSIF_WR_GENERATE_COMPLETION";
	case PSIF_WR_INVALIDATE_RQ:
		return "PSIF_WR_INVALIDATE_RQ";
	case PSIF_WR_INVALIDATE_CQ:
		return "PSIF_WR_INVALIDATE_CQ";
	case PSIF_WR_INVALIDATE_XRCSRQ:
		return "PSIF_WR_INVALIDATE_XRCSRQ";
	case PSIF_WR_INVALIDATE_SGL_CACHE:
		return "PSIF_WR_INVALIDATE_SGL_CACHE";
	default:
		return "UNKNOWN_psif_wr_type";
	}
}

void write_enum_psif_wr_type(XFILE *fd,
	enum psif_wr_type data)
{
	xprintf(fd, "%s", string_enum_psif_wr_type(data));
} /* end write_..._psif_wr_type(psif_wr_type data) */

/* Convert enum psif_port to string */
const char *string_enum_psif_port(enum psif_port val)
{
	switch (val) {
	case PORT_1:
		return "PORT_1";
	case PORT_2:
		return "PORT_2";
	default:
		return "UNKNOWN_psif_port";
	}
}

void write_enum_psif_port(XFILE *fd,
	enum psif_port data)
{
	xprintf(fd, "%s", string_enum_psif_port(data));
} /* end write_..._psif_port(psif_port data) */

/* Convert enum psif_use_ah to string */
const char *string_enum_psif_use_ah(enum psif_use_ah val)
{
	switch (val) {
	case NO_AHA:
		return "NO_AHA";
	case USE_AHA:
		return "USE_AHA";
	default:
		return "UNKNOWN_psif_use_ah";
	}
}

void write_enum_psif_use_ah(XFILE *fd,
	enum psif_use_ah data)
{
	xprintf(fd, "%s", string_enum_psif_use_ah(data));
} /* end write_..._psif_use_ah(psif_use_ah data) */

/* Convert enum psif_tsu_qos to string */
const char *string_enum_psif_tsu_qos(enum psif_tsu_qos val)
{
	switch (val) {
	case QOSL_HIGH_BANDWIDTH:
		return "QOSL_HIGH_BANDWIDTH";
	case QOSL_LOW_LATENCY:
		return "QOSL_LOW_LATENCY";
	default:
		return "UNKNOWN_psif_tsu_qos";
	}
}

void write_enum_psif_tsu_qos(XFILE *fd,
	enum psif_tsu_qos data)
{
	xprintf(fd, "%s", string_enum_psif_tsu_qos(data));
} /* end write_..._psif_tsu_qos(psif_tsu_qos data) */

/* Convert enum psif_wc_opcode to string */
const char *string_enum_psif_wc_opcode(enum psif_wc_opcode val)
{
	switch (val) {
	case PSIF_WC_OPCODE_SEND:
		return "PSIF_WC_OPCODE_SEND";
	case PSIF_WC_OPCODE_RDMA_WR:
		return "PSIF_WC_OPCODE_RDMA_WR";
	case PSIF_WC_OPCODE_RDMA_READ:
		return "PSIF_WC_OPCODE_RDMA_READ";
	case PSIF_WC_OPCODE_CMP_SWAP:
		return "PSIF_WC_OPCODE_CMP_SWAP";
	case PSIF_WC_OPCODE_FETCH_ADD:
		return "PSIF_WC_OPCODE_FETCH_ADD";
	case PSIF_WC_OPCODE_LSO:
		return "PSIF_WC_OPCODE_LSO";
	case PSIF_WC_OPCODE_MASKED_CMP_SWAP:
		return "PSIF_WC_OPCODE_MASKED_CMP_SWAP";
	case PSIF_WC_OPCODE_MASKED_FETCH_ADD:
		return "PSIF_WC_OPCODE_MASKED_FETCH_ADD";
	case PSIF_WC_OPCODE_INVALIDATE_RKEY:
		return "PSIF_WC_OPCODE_INVALIDATE_RKEY";
	case PSIF_WC_OPCODE_INVALIDATE_LKEY:
		return "PSIF_WC_OPCODE_INVALIDATE_LKEY";
	case PSIF_WC_OPCODE_INVALIDATE_BOTH_KEYS:
		return "PSIF_WC_OPCODE_INVALIDATE_BOTH_KEYS";
	case PSIF_WC_OPCODE_INVALIDATE_TLB:
		return "PSIF_WC_OPCODE_INVALIDATE_TLB";
	case PSIF_WC_OPCODE_RESIZE_CQ:
		return "PSIF_WC_OPCODE_RESIZE_CQ";
	case PSIF_WC_OPCODE_SET_SRQ_LIM:
		return "PSIF_WC_OPCODE_SET_SRQ_LIM";
	case PSIF_WC_OPCODE_SET_XRCSRQ_LIM:
		return "PSIF_WC_OPCODE_SET_XRCSRQ_LIM";
	case PSIF_WC_OPCODE_REQ_CMPL_NOTIFY:
		return "PSIF_WC_OPCODE_REQ_CMPL_NOTIFY";
	case PSIF_WC_OPCODE_CMPL_NOTIFY_RCVD:
		return "PSIF_WC_OPCODE_CMPL_NOTIFY_RCVD";
	case PSIF_WC_OPCODE_REARM_CMPL_EVENT:
		return "PSIF_WC_OPCODE_REARM_CMPL_EVENT";
	case PSIF_WC_OPCODE_GENERATE_COMPLETION:
		return "PSIF_WC_OPCODE_GENERATE_COMPLETION";
	case PSIF_WC_OPCODE_INVALIDATE_RQ:
		return "PSIF_WC_OPCODE_INVALIDATE_RQ";
	case PSIF_WC_OPCODE_INVALIDATE_CQ:
		return "PSIF_WC_OPCODE_INVALIDATE_CQ";
	case PSIF_WC_OPCODE_INVALIDATE_RB:
		return "PSIF_WC_OPCODE_INVALIDATE_RB";
	case PSIF_WC_OPCODE_INVALIDATE_XRCSRQ:
		return "PSIF_WC_OPCODE_INVALIDATE_XRCSRQ";
	case PSIF_WC_OPCODE_INVALIDATE_SGL_CACHE:
		return "PSIF_WC_OPCODE_INVALIDATE_SGL_CACHE";
	case PSIF_WC_OPCODE_RECEIVE_SEND:
		return "PSIF_WC_OPCODE_RECEIVE_SEND";
	case PSIF_WC_OPCODE_RECEIVE_RDMA_WR_IMM:
		return "PSIF_WC_OPCODE_RECEIVE_RDMA_WR_IMM";
	case PSIF_WC_OPCODE_RECEIVE_CONDITIONAL_WR_IMM:
		return "PSIF_WC_OPCODE_RECEIVE_CONDITIONAL_WR_IMM";
	default:
		return "UNKNOWN_psif_wc_opcode";
	}
}

void write_enum_psif_wc_opcode(XFILE *fd,
	enum psif_wc_opcode data)
{
	xprintf(fd, "%s", string_enum_psif_wc_opcode(data));
} /* end write_..._psif_wc_opcode(psif_wc_opcode data) */

/* Convert enum psif_wc_status to string */
const char *string_enum_psif_wc_status(enum psif_wc_status val)
{
	switch (val) {
	case PSIF_WC_STATUS_SUCCESS:
		return "PSIF_WC_STATUS_SUCCESS";
	case PSIF_WC_STATUS_LOC_LEN_ERR:
		return "PSIF_WC_STATUS_LOC_LEN_ERR";
	case PSIF_WC_STATUS_LOC_QP_OP_ERR:
		return "PSIF_WC_STATUS_LOC_QP_OP_ERR";
	case PSIF_WC_STATUS_LOC_EEC_OP_ERR:
		return "PSIF_WC_STATUS_LOC_EEC_OP_ERR";
	case PSIF_WC_STATUS_LOC_PROT_ERR:
		return "PSIF_WC_STATUS_LOC_PROT_ERR";
	case PSIF_WC_STATUS_WR_FLUSH_ERR:
		return "PSIF_WC_STATUS_WR_FLUSH_ERR";
	case PSIF_WC_STATUS_MW_BIND_ERR:
		return "PSIF_WC_STATUS_MW_BIND_ERR";
	case PSIF_WC_STATUS_BAD_RESP_ERR:
		return "PSIF_WC_STATUS_BAD_RESP_ERR";
	case PSIF_WC_STATUS_LOC_ACCESS_ERR:
		return "PSIF_WC_STATUS_LOC_ACCESS_ERR";
	case PSIF_WC_STATUS_REM_INV_REQ_ERR:
		return "PSIF_WC_STATUS_REM_INV_REQ_ERR";
	case PSIF_WC_STATUS_REM_ACCESS_ERR:
		return "PSIF_WC_STATUS_REM_ACCESS_ERR";
	case PSIF_WC_STATUS_REM_OP_ERR:
		return "PSIF_WC_STATUS_REM_OP_ERR";
	case PSIF_WC_STATUS_RETRY_EXC_ERR:
		return "PSIF_WC_STATUS_RETRY_EXC_ERR";
	case PSIF_WC_STATUS_RNR_RETRY_EXC_ERR:
		return "PSIF_WC_STATUS_RNR_RETRY_EXC_ERR";
	case PSIF_WC_STATUS_LOC_RDD_VIOL_ERR:
		return "PSIF_WC_STATUS_LOC_RDD_VIOL_ERR";
	case PSIF_WC_STATUS_REM_INV_RD_REQ_ERR:
		return "PSIF_WC_STATUS_REM_INV_RD_REQ_ERR";
	case PSIF_WC_STATUS_REM_ABORT_ERR:
		return "PSIF_WC_STATUS_REM_ABORT_ERR";
	case PSIF_WC_STATUS_INV_EECN_ERR:
		return "PSIF_WC_STATUS_INV_EECN_ERR";
	case PSIF_WC_STATUS_INV_EEC_STATE_ERR:
		return "PSIF_WC_STATUS_INV_EEC_STATE_ERR";
	case PSIF_WC_STATUS_FATAL_ERR:
		return "PSIF_WC_STATUS_FATAL_ERR";
	case PSIF_WC_STATUS_RESP_TIMEOUT_ERR:
		return "PSIF_WC_STATUS_RESP_TIMEOUT_ERR";
	case PSIF_WC_STATUS_GENERAL_ERR:
		return "PSIF_WC_STATUS_GENERAL_ERR";
	case PSIF_WC_STATUS_FIELD_MAX:
		return "PSIF_WC_STATUS_FIELD_MAX";
	default:
		return "UNKNOWN_psif_wc_status";
	}
}

void write_enum_psif_wc_status(XFILE *fd,
	enum psif_wc_status data)
{
	xprintf(fd, "%s", string_enum_psif_wc_status(data));
} /* end write_..._psif_wc_status(psif_wc_status data) */

/* Convert enum psif_eps_a_core to string */
const char *string_enum_psif_eps_a_core(enum psif_eps_a_core val)
{
	switch (val) {
	case PSIF_EPS_A_1:
		return "PSIF_EPS_A_1";
	case PSIF_EPS_A_2:
		return "PSIF_EPS_A_2";
	case PSIF_EPS_A_3:
		return "PSIF_EPS_A_3";
	case PSIF_EPS_A_4:
		return "PSIF_EPS_A_4";
	default:
		return "UNKNOWN_psif_eps_a_core";
	}
}

void write_enum_psif_eps_a_core(XFILE *fd,
	enum psif_eps_a_core data)
{
	xprintf(fd, "%s", string_enum_psif_eps_a_core(data));
} /* end write_..._psif_eps_a_core(psif_eps_a_core data) */

/* Convert enum psif_qp_state to string */
const char *string_enum_psif_qp_state(enum psif_qp_state val)
{
	switch (val) {
	case PSIF_QP_STATE_RESET:
		return "PSIF_QP_STATE_RESET";
	case PSIF_QP_STATE_INIT:
		return "PSIF_QP_STATE_INIT";
	case PSIF_QP_STATE_RTR:
		return "PSIF_QP_STATE_RTR";
	case PSIF_QP_STATE_RTS:
		return "PSIF_QP_STATE_RTS";
	case PSIF_QP_STATE_SQERR:
		return "PSIF_QP_STATE_SQERR";
	case PSIF_QP_STATE_ERROR:
		return "PSIF_QP_STATE_ERROR";
	case PSIF_QP_STATE_INVALID:
		return "PSIF_QP_STATE_INVALID";
	default:
		return "UNKNOWN_psif_qp_state";
	}
}

void write_enum_psif_qp_state(XFILE *fd,
	enum psif_qp_state data)
{
	xprintf(fd, "%s", string_enum_psif_qp_state(data));
} /* end write_..._psif_qp_state(psif_qp_state data) */

/* Convert enum psif_cmpl_outstanding_error to string */
const char *string_enum_psif_cmpl_outstanding_error(enum psif_cmpl_outstanding_error val)
{
	switch (val) {
	case CMPL_NO_ERROR:
		return "CMPL_NO_ERROR";
	case CMPL_RQS_INVALID_REQUEST_ERR:
		return "CMPL_RQS_INVALID_REQUEST_ERR";
	case CMPL_RQS_QP_IN_WRONG_STATE_ERR:
		return "CMPL_RQS_QP_IN_WRONG_STATE_ERR";
	case CMPL_RQS_MAX_OUTSTANDING_REACHED_ERR:
		return "CMPL_RQS_MAX_OUTSTANDING_REACHED_ERR";
	case CMPL_RQS_REQUEST_FENCED_ERR:
		return "CMPL_RQS_REQUEST_FENCED_ERR";
	case CMPL_RQS_CMD_FROM_EPS_ERR:
		return "CMPL_RQS_CMD_FROM_EPS_ERR";
	case CMPL_DMA_SGL_RD_ERR:
		return "CMPL_DMA_SGL_RD_ERR";
	case CMPL_DMA_PYLD_RD_ERR:
		return "CMPL_DMA_PYLD_RD_ERR";
	case CMPL_DMA_SGL_LENGTH_ERR:
		return "CMPL_DMA_SGL_LENGTH_ERR";
	case CMPL_DMA_LKEY_ERR:
		return "CMPL_DMA_LKEY_ERR";
	default:
		return "UNKNOWN_psif_cmpl_outstanding_error";
	}
}

void write_enum_psif_cmpl_outstanding_error(XFILE *fd,
	enum psif_cmpl_outstanding_error data)
{
	xprintf(fd, "%s", string_enum_psif_cmpl_outstanding_error(data));
} /* end write_..._psif_cmpl_outstanding_error(psif_cmpl_outstanding_error data) */

/* Convert enum psif_expected_op to string */
const char *string_enum_psif_expected_op(enum psif_expected_op val)
{
	switch (val) {
	case NO_OPERATION_IN_PROGRESS:
		return "NO_OPERATION_IN_PROGRESS";
	case EXPECT_SEND_MIDDLE_LAST:
		return "EXPECT_SEND_MIDDLE_LAST";
	case EXPECT_RDMA_WR_MIDDLE_LAST:
		return "EXPECT_RDMA_WR_MIDDLE_LAST";
	case EXPECT_DM_PUT_MIDDLE_LAST:
		return "EXPECT_DM_PUT_MIDDLE_LAST";
	default:
		return "UNKNOWN_psif_expected_op";
	}
}

void write_enum_psif_expected_op(XFILE *fd,
	enum psif_expected_op data)
{
	xprintf(fd, "%s", string_enum_psif_expected_op(data));
} /* end write_..._psif_expected_op(psif_expected_op data) */

/* Convert enum psif_migration to string */
const char *string_enum_psif_migration(enum psif_migration val)
{
	switch (val) {
	case APM_OFF:
		return "APM_OFF";
	case APM_MIGRATED:
		return "APM_MIGRATED";
	case APM_REARM:
		return "APM_REARM";
	case APM_ARMED:
		return "APM_ARMED";
	default:
		return "UNKNOWN_psif_migration";
	}
}

void write_enum_psif_migration(XFILE *fd,
	enum psif_migration data)
{
	xprintf(fd, "%s", string_enum_psif_migration(data));
} /* end write_..._psif_migration(psif_migration data) */

/* Convert enum psif_qp_trans to string */
const char *string_enum_psif_qp_trans(enum psif_qp_trans val)
{
	switch (val) {
	case PSIF_QP_TRANSPORT_RC:
		return "PSIF_QP_TRANSPORT_RC";
	case PSIF_QP_TRANSPORT_UC:
		return "PSIF_QP_TRANSPORT_UC";
	case PSIF_QP_TRANSPORT_RD:
		return "PSIF_QP_TRANSPORT_RD";
	case PSIF_QP_TRANSPORT_UD:
		return "PSIF_QP_TRANSPORT_UD";
	case PSIF_QP_TRANSPORT_RSVD1:
		return "PSIF_QP_TRANSPORT_RSVD1";
	case PSIF_QP_TRANSPORT_XRC:
		return "PSIF_QP_TRANSPORT_XRC";
	case PSIF_QP_TRANSPORT_MANSP1:
		return "PSIF_QP_TRANSPORT_MANSP1";
	case PSIF_QP_TRANSPORT_MANSP2:
		return "PSIF_QP_TRANSPORT_MANSP2";
	default:
		return "UNKNOWN_psif_qp_trans";
	}
}

void write_enum_psif_qp_trans(XFILE *fd,
	enum psif_qp_trans data)
{
	xprintf(fd, "%s", string_enum_psif_qp_trans(data));
} /* end write_..._psif_qp_trans(psif_qp_trans data) */

/* Convert enum psif_bool to string */
const char *string_enum_psif_bool(enum psif_bool val)
{
	switch (val) {
	case FALSE:
		return "FALSE";
	case TRUE:
		return "TRUE";
	default:
		return "UNKNOWN_psif_bool";
	}
}

void write_enum_psif_bool(XFILE *fd,
	enum psif_bool data)
{
	xprintf(fd, "%s", string_enum_psif_bool(data));
} /* end write_..._psif_bool(psif_bool data) */

/* Convert enum psif_eoib_type to string */
const char *string_enum_psif_eoib_type(enum psif_eoib_type val)
{
	switch (val) {
	case EOIB_FULL:
		return "EOIB_FULL";
	case EOIB_PARTIAL:
		return "EOIB_PARTIAL";
	case EOIB_QKEY_ONLY:
		return "EOIB_QKEY_ONLY";
	case EOIB_NONE:
		return "EOIB_NONE";
	default:
		return "UNKNOWN_psif_eoib_type";
	}
}

void write_enum_psif_eoib_type(XFILE *fd,
	enum psif_eoib_type data)
{
	xprintf(fd, "%s", string_enum_psif_eoib_type(data));
} /* end write_..._psif_eoib_type(psif_eoib_type data) */

/* Convert enum psif_comm_live to string */
const char *string_enum_psif_comm_live(enum psif_comm_live val)
{
	switch (val) {
	case NO_COMM_ESTABLISHED:
		return "NO_COMM_ESTABLISHED";
	case COMM_ESTABLISHED:
		return "COMM_ESTABLISHED";
	default:
		return "UNKNOWN_psif_comm_live";
	}
}

void write_enum_psif_comm_live(XFILE *fd,
	enum psif_comm_live data)
{
	xprintf(fd, "%s", string_enum_psif_comm_live(data));
} /* end write_..._psif_comm_live(psif_comm_live data) */

/* Convert enum psif_path_mtu to string */
const char *string_enum_psif_path_mtu(enum psif_path_mtu val)
{
	switch (val) {
	case MTU_INVALID:
		return "MTU_INVALID";
	case MTU_256B:
		return "MTU_256B";
	case MTU_512B:
		return "MTU_512B";
	case MTU_1024B:
		return "MTU_1024B";
	case MTU_2048B:
		return "MTU_2048B";
	case MTU_4096B:
		return "MTU_4096B";
	case MTU_10240B:
		return "MTU_10240B";
	case MTU_XXX:
		return "MTU_XXX";
	default:
		return "UNKNOWN_psif_path_mtu";
	}
}

void write_enum_psif_path_mtu(XFILE *fd,
	enum psif_path_mtu data)
{
	xprintf(fd, "%s", string_enum_psif_path_mtu(data));
} /* end write_..._psif_path_mtu(psif_path_mtu data) */

/* Convert enum psif_use_grh to string */
const char *string_enum_psif_use_grh(enum psif_use_grh val)
{
	switch (val) {
	case NO_GRH:
		return "NO_GRH";
	case USE_GRH:
		return "USE_GRH";
	default:
		return "UNKNOWN_psif_use_grh";
	}
}

void write_enum_psif_use_grh(XFILE *fd,
	enum psif_use_grh data)
{
	xprintf(fd, "%s", string_enum_psif_use_grh(data));
} /* end write_..._psif_use_grh(psif_use_grh data) */

/* Convert enum psif_loopback to string */
const char *string_enum_psif_loopback(enum psif_loopback val)
{
	switch (val) {
	case NO_LOOPBACK:
		return "NO_LOOPBACK";
	case LOOPBACK:
		return "LOOPBACK";
	default:
		return "UNKNOWN_psif_loopback";
	}
}

void write_enum_psif_loopback(XFILE *fd,
	enum psif_loopback data)
{
	xprintf(fd, "%s", string_enum_psif_loopback(data));
} /* end write_..._psif_loopback(psif_loopback data) */

/* Convert enum psif_qp_command to string */
const char *string_enum_psif_qp_command(enum psif_qp_command val)
{
	switch (val) {
	case QP_CMD_INVALID:
		return "QP_CMD_INVALID";
	case QP_CMD_MODIFY:
		return "QP_CMD_MODIFY";
	case QP_CMD_QUERY:
		return "QP_CMD_QUERY";
	case QP_CMD_CHECK_TIMEOUT:
		return "QP_CMD_CHECK_TIMEOUT";
	default:
		return "UNKNOWN_psif_qp_command";
	}
}

void write_enum_psif_qp_command(XFILE *fd,
	enum psif_qp_command data)
{
	xprintf(fd, "%s", string_enum_psif_qp_command(data));
} /* end write_..._psif_qp_command(psif_qp_command data) */

/* Convert enum psif_mbox_type to string */
const char *string_enum_psif_mbox_type(enum psif_mbox_type val)
{
	switch (val) {
	case MBOX_EPSA0:
		return "MBOX_EPSA0";
	case MBOX_EPSA1:
		return "MBOX_EPSA1";
	case MBOX_EPSA2:
		return "MBOX_EPSA2";
	case MBOX_EPSA3:
		return "MBOX_EPSA3";
	case MBOX_EPSC:
		return "MBOX_EPSC";
	case MBOX_EPS_MAX:
		return "MBOX_EPS_MAX";
	case PSIF_MBOX_TYPE_FIELD_MAX:
		return "PSIF_MBOX_TYPE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_mbox_type";
	}
}

void write_enum_psif_mbox_type(XFILE *fd,
	enum psif_mbox_type data)
{
	xprintf(fd, "%s", string_enum_psif_mbox_type(data));
} /* end write_..._psif_mbox_type(psif_mbox_type data) */

/* Convert enum psif_dma_vt_key_states to string */
const char *string_enum_psif_dma_vt_key_states(enum psif_dma_vt_key_states val)
{
	switch (val) {
	case PSIF_DMA_KEY_INVALID:
		return "PSIF_DMA_KEY_INVALID";
	case PSIF_DMA_KEY_FREE:
		return "PSIF_DMA_KEY_FREE";
	case PSIF_DMA_KEY_VALID:
		return "PSIF_DMA_KEY_VALID";
	case PSIF_DMA_KEY_MMU_VALID:
		return "PSIF_DMA_KEY_MMU_VALID";
	default:
		return "UNKNOWN_psif_dma_vt_key_states";
	}
}

void write_enum_psif_dma_vt_key_states(XFILE *fd,
	enum psif_dma_vt_key_states data)
{
	xprintf(fd, "%s", string_enum_psif_dma_vt_key_states(data));
} /* end write_..._psif_dma_vt_key_states(psif_dma_vt_key_states data) */

/* Convert enum psif_event to string */
const char *string_enum_psif_event(enum psif_event val)
{
	switch (val) {
	case PSIF_EVENT_NO_CHANGE:
		return "PSIF_EVENT_NO_CHANGE";
	case PSIF_EVENT_SGID_TABLE_CHANGED:
		return "PSIF_EVENT_SGID_TABLE_CHANGED";
	case PSIF_EVENT_PKEY_TABLE_CHANGED:
		return "PSIF_EVENT_PKEY_TABLE_CHANGED";
	case PSIF_EVENT_MASTER_SM_LID_CHANGED:
		return "PSIF_EVENT_MASTER_SM_LID_CHANGED";
	case PSIF_EVENT_MASTER_SM_SL_CHANGED:
		return "PSIF_EVENT_MASTER_SM_SL_CHANGED";
	case PSIF_EVENT_SUBNET_TIMEOUT_CHANGED:
		return "PSIF_EVENT_SUBNET_TIMEOUT_CHANGED";
	case PSIF_EVENT_IS_SM_DISABLED_CHANGED:
		return "PSIF_EVENT_IS_SM_DISABLED_CHANGED";
	case PSIF_EVENT_CLIENT_REREGISTER:
		return "PSIF_EVENT_CLIENT_REREGISTER";
	case PSIF_EVENT_LID_TABLE_CHANGED:
		return "PSIF_EVENT_LID_TABLE_CHANGED";
	case PSIF_EVENT_EPSC_COMPLETION:
		return "PSIF_EVENT_EPSC_COMPLETION";
	case PSIF_EVENT_MAILBOX:
		return "PSIF_EVENT_MAILBOX";
	case PSIF_EVENT_EXTENSION:
		return "PSIF_EVENT_EXTENSION";
	case PSIF_EVENT_LOG:
		return "PSIF_EVENT_LOG";
	case PSIF_EVENT_PORT_ACTIVE:
		return "PSIF_EVENT_PORT_ACTIVE";
	case PSIF_EVENT_PORT_ERR:
		return "PSIF_EVENT_PORT_ERR";
	case PSIF_EVENT_QUEUE_FULL:
		return "PSIF_EVENT_QUEUE_FULL";
	case PSIF_EVENT_DEGRADED_MODE:
		return "PSIF_EVENT_DEGRADED_MODE";
	case PSIF_EVENT_EPSC_KEEP_ALIVE:
		return "PSIF_EVENT_EPSC_KEEP_ALIVE";
	case PSIF_EVENT_EPSC_MMU_FLUSH_DONE:
		return "PSIF_EVENT_EPSC_MMU_FLUSH_DONE";
	case PSIF_EVENT_FIELD_MAX:
		return "PSIF_EVENT_FIELD_MAX";
	default:
		return "UNKNOWN_psif_event";
	}
}

void write_enum_psif_event(XFILE *fd,
	enum psif_event data)
{
	xprintf(fd, "%s", string_enum_psif_event(data));
} /* end write_..._psif_event(psif_event data) */

/* Convert enum psif_tsu_error_types to string */
const char *string_enum_psif_tsu_error_types(enum psif_tsu_error_types val)
{
	switch (val) {
	case TSU_NO_ERROR:
		return "TSU_NO_ERROR";
	case TSU_IBPR_ICRC_ERR:
		return "TSU_IBPR_ICRC_ERR";
	case TSU_IBPR_INVALID_PKEY_ERR:
		return "TSU_IBPR_INVALID_PKEY_ERR";
	case TSU_IBPR_INVALID_QP_ERR:
		return "TSU_IBPR_INVALID_QP_ERR";
	case TSU_IBPR_VSWITCH_UF_ERR:
		return "TSU_IBPR_VSWITCH_UF_ERR";
	case TSU_IBPR_PKTLEN_ERR:
		return "TSU_IBPR_PKTLEN_ERR";
	case TSU_IBPR_UNDEFINED_OPCODE_ERR:
		return "TSU_IBPR_UNDEFINED_OPCODE_ERR";
	case TSU_IBPR_MCAST_NO_GRH_ERR:
		return "TSU_IBPR_MCAST_NO_GRH_ERR";
	case TSU_IBPR_MCAST_NO_TARGET_ERR:
		return "TSU_IBPR_MCAST_NO_TARGET_ERR";
	case TSU_IBPR_INVALID_DGID_ERR:
		return "TSU_IBPR_INVALID_DGID_ERR";
	case TSU_IBPR_BADPKT_ERR:
		return "TSU_IBPR_BADPKT_ERR";
	case TSU_RCV_QP_INVALID_ERR:
		return "TSU_RCV_QP_INVALID_ERR";
	case TSU_RCV_HDR_BTH_TVER_ERR:
		return "TSU_RCV_HDR_BTH_TVER_ERR";
	case TSU_RCV_HDR_BTH_QP_ERR:
		return "TSU_RCV_HDR_BTH_QP_ERR";
	case TSU_RCV_HDR_GRH_ERR:
		return "TSU_RCV_HDR_GRH_ERR";
	case TSU_RCV_HDR_PKEY_ERR:
		return "TSU_RCV_HDR_PKEY_ERR";
	case TSU_RCV_HDR_QKEY_ERR:
		return "TSU_RCV_HDR_QKEY_ERR";
	case TSU_RCV_HDR_LID_ERR:
		return "TSU_RCV_HDR_LID_ERR";
	case TSU_RCV_HDR_MAD_ERR:
		return "TSU_RCV_HDR_MAD_ERR";
	case TSU_RCV_EOIB_MCAST_ERR:
		return "TSU_RCV_EOIB_MCAST_ERR";
	case TSU_RCV_EOIB_BCAST_ERR:
		return "TSU_RCV_EOIB_BCAST_ERR";
	case TSU_RCV_EOIB_UCAST_ERR:
		return "TSU_RCV_EOIB_UCAST_ERR";
	case TSU_RCV_EOIB_TCP_PORT_VIOLATION_ERR:
		return "TSU_RCV_EOIB_TCP_PORT_VIOLATION_ERR";
	case TSU_RCV_EOIB_RUNTS_ERR:
		return "TSU_RCV_EOIB_RUNTS_ERR";
	case TSU_RCV_EOIB_OUTER_VLAN_ERR:
		return "TSU_RCV_EOIB_OUTER_VLAN_ERR";
	case TSU_RCV_EOIB_VLAN_TAG_ERR:
		return "TSU_RCV_EOIB_VLAN_TAG_ERR";
	case TSU_RCV_EOIB_VID_ERR:
		return "TSU_RCV_EOIB_VID_ERR";
	case TSU_RCV_IPOIB_TCP_PORT_VIOLATION_ERR:
		return "TSU_RCV_IPOIB_TCP_PORT_VIOLATION_ERR";
	case TSU_RCV_MCAST_DUP_ERR:
		return "TSU_RCV_MCAST_DUP_ERR";
	case TSU_RCV_ECC_ERR:
		return "TSU_RCV_ECC_ERR";
	case TSU_DSCR_RESPONDER_RC_PSN_ERR:
		return "TSU_DSCR_RESPONDER_RC_PSN_ERR";
	case TSU_DSCR_RESPONDER_RC_DUPLICATE:
		return "TSU_DSCR_RESPONDER_RC_DUPLICATE";
	case TSU_DSCR_RESPONDER_RC_OPCODE_SEQ_ERR:
		return "TSU_DSCR_RESPONDER_RC_OPCODE_SEQ_ERR";
	case TSU_DSCR_RESPONDER_RC_OPCODE_VAL_ERR:
		return "TSU_DSCR_RESPONDER_RC_OPCODE_VAL_ERR";
	case TSU_DSCR_RESPONDER_RC_OPCODE_LEN_ERR:
		return "TSU_DSCR_RESPONDER_RC_OPCODE_LEN_ERR";
	case TSU_DSCR_RESPONDER_RC_DMALEN_ERR:
		return "TSU_DSCR_RESPONDER_RC_DMALEN_ERR";
	case TSU_DSCR_RESPONDER_XRC_PSN_ERR:
		return "TSU_DSCR_RESPONDER_XRC_PSN_ERR";
	case TSU_DSCR_RESPONDER_XRC_DUPLICATE:
		return "TSU_DSCR_RESPONDER_XRC_DUPLICATE";
	case TSU_DSCR_RESPONDER_XRC_OPCODE_SEQ_ERR:
		return "TSU_DSCR_RESPONDER_XRC_OPCODE_SEQ_ERR";
	case TSU_DSCR_RESPONDER_XRC_OPCODE_VAL_ERR:
		return "TSU_DSCR_RESPONDER_XRC_OPCODE_VAL_ERR";
	case TSU_DSCR_RESPONDER_XRC_OPCODE_LEN_ERR:
		return "TSU_DSCR_RESPONDER_XRC_OPCODE_LEN_ERR";
	case TSU_DSCR_RESPONDER_XRC_DMALEN_ERR:
		return "TSU_DSCR_RESPONDER_XRC_DMALEN_ERR";
	case TSU_DSCR_RESPONDER_UC_PSN_ERR:
		return "TSU_DSCR_RESPONDER_UC_PSN_ERR";
	case TSU_DSCR_RESPONDER_UC_OPCODE_SEQ_ERR:
		return "TSU_DSCR_RESPONDER_UC_OPCODE_SEQ_ERR";
	case TSU_DSCR_RESPONDER_UC_OPCODE_VAL_ERR:
		return "TSU_DSCR_RESPONDER_UC_OPCODE_VAL_ERR";
	case TSU_DSCR_RESPONDER_UC_OPCODE_LEN_ERR:
		return "TSU_DSCR_RESPONDER_UC_OPCODE_LEN_ERR";
	case TSU_DSCR_RESPONDER_UC_DMALEN_ERR:
		return "TSU_DSCR_RESPONDER_UC_DMALEN_ERR";
	case TSU_DSCR_RESPONDER_UD_OPCODE_LEN_ERR:
		return "TSU_DSCR_RESPONDER_UD_OPCODE_LEN_ERR";
	case TSU_DSCR_RESPONDER_DUPLICATE_WITH_ERR:
		return "TSU_DSCR_RESPONDER_DUPLICATE_WITH_ERR";
	case TSU_DSCR_QP_CAP_MASKED_ATOMIC_ENABLE_ERR:
		return "TSU_DSCR_QP_CAP_MASKED_ATOMIC_ENABLE_ERR";
	case TSU_DSCR_QP_CAP_RDMA_RD_ENABLE_ERR:
		return "TSU_DSCR_QP_CAP_RDMA_RD_ENABLE_ERR";
	case TSU_DSCR_QP_CAP_RDMA_WR_ENABLE_ERR:
		return "TSU_DSCR_QP_CAP_RDMA_WR_ENABLE_ERR";
	case TSU_DSCR_QP_CAP_ATOMIC_ENABLE_ERR:
		return "TSU_DSCR_QP_CAP_ATOMIC_ENABLE_ERR";
	case TSU_DSCR_XRC_DOMAIN_VIOLATION_ERR:
		return "TSU_DSCR_XRC_DOMAIN_VIOLATION_ERR";
	case TSU_DSCR_XRCETH_ERR:
		return "TSU_DSCR_XRCETH_ERR";
	case TSU_DSCR_RQ_INVALID_ERR:
		return "TSU_DSCR_RQ_INVALID_ERR";
	case TSU_DSCR_RQ_PD_CHECK_ERR:
		return "TSU_DSCR_RQ_PD_CHECK_ERR";
	case TSU_DSCR_RQ_EMPTY_ERR:
		return "TSU_DSCR_RQ_EMPTY_ERR";
	case TSU_DSCR_RQ_IN_ERROR_ERR:
		return "TSU_DSCR_RQ_IN_ERROR_ERR";
	case TSU_DSCR_TRANSLATION_TYPE_ERR:
		return "TSU_DSCR_TRANSLATION_TYPE_ERR";
	case TSU_DSCR_RQ_DESCRIPTOR_INCONSISTENT_ERR:
		return "TSU_DSCR_RQ_DESCRIPTOR_INCONSISTENT_ERR";
	case TSU_DSCR_MISALIGNED_ATOMIC_ERR:
		return "TSU_DSCR_MISALIGNED_ATOMIC_ERR";
	case TSU_DSCR_PCIE_ERR:
		return "TSU_DSCR_PCIE_ERR";
	case TSU_DSCR_ECC_ERR:
		return "TSU_DSCR_ECC_ERR";
	case TSU_RQH_PCIE_ERR:
		return "TSU_RQH_PCIE_ERR";
	case TSU_RQH_SGL_LKEY_ERR:
		return "TSU_RQH_SGL_LKEY_ERR";
	case TSU_RQH_NOT_ENOUGH_RQ_SPACE_ERR:
		return "TSU_RQH_NOT_ENOUGH_RQ_SPACE_ERR";
	case TSU_RQH_ECC_ERR:
		return "TSU_RQH_ECC_ERR";
	case TSU_VAL_DUPLICATE_WITH_ERR:
		return "TSU_VAL_DUPLICATE_WITH_ERR";
	case TSU_VAL_RKEY_VLD_ERR:
		return "TSU_VAL_RKEY_VLD_ERR";
	case TSU_VAL_RKEY_ADDR_RANGE_ERR:
		return "TSU_VAL_RKEY_ADDR_RANGE_ERR";
	case TSU_VAL_RKEY_ACCESS_ERR:
		return "TSU_VAL_RKEY_ACCESS_ERR";
	case TSU_VAL_RKEY_PD_ERR:
		return "TSU_VAL_RKEY_PD_ERR";
	case TSU_VAL_RKEY_RANGE_ERR:
		return "TSU_VAL_RKEY_RANGE_ERR";
	case TSU_VAL_LKEY_VLD_ERR:
		return "TSU_VAL_LKEY_VLD_ERR";
	case TSU_VAL_LKEY_ADDR_RANGE_ERR:
		return "TSU_VAL_LKEY_ADDR_RANGE_ERR";
	case TSU_VAL_LKEY_ACCESS_ERR:
		return "TSU_VAL_LKEY_ACCESS_ERR";
	case TSU_VAL_LKEY_PD_ERR:
		return "TSU_VAL_LKEY_PD_ERR";
	case TSU_VAL_LKEY_RANGE_ERR:
		return "TSU_VAL_LKEY_RANGE_ERR";
	case TSU_VAL_TRANSLATION_TYPE_ERR:
		return "TSU_VAL_TRANSLATION_TYPE_ERR";
	case TSU_VAL_PCIE_ERR:
		return "TSU_VAL_PCIE_ERR";
	case TSU_VAL_ECC_ERR:
		return "TSU_VAL_ECC_ERR";
	case TSU_MMU_DUPLICATE_WITH_ERR:
		return "TSU_MMU_DUPLICATE_WITH_ERR";
	case TSU_MMU_PTW_ERR:
		return "TSU_MMU_PTW_ERR";
	case TSU_MMU_UF_ERR:
		return "TSU_MMU_UF_ERR";
	case TSU_MMU_AC_ERR:
		return "TSU_MMU_AC_ERR";
	case TSU_MMU_ECC_ERR:
		return "TSU_MMU_ECC_ERR";
	case TSU_CBLD_CQ_INVALID_ERR:
		return "TSU_CBLD_CQ_INVALID_ERR";
	case TSU_CBLD_CQ_FULL_ERR:
		return "TSU_CBLD_CQ_FULL_ERR";
	case TSU_CBLD_CQ_ALREADY_IN_ERR:
		return "TSU_CBLD_CQ_ALREADY_IN_ERR";
	case TSU_CBLD_CQ_IS_PROXY_ERR:
		return "TSU_CBLD_CQ_IS_PROXY_ERR";
	case TSU_CBLD_TRANSLATION_TYPE_ERR:
		return "TSU_CBLD_TRANSLATION_TYPE_ERR";
	case TSU_CBLD_CQ_DESCRIPTOR_INCONSISTENT_ERR:
		return "TSU_CBLD_CQ_DESCRIPTOR_INCONSISTENT_ERR";
	case TSU_CBLD_ECC_ERR:
		return "TSU_CBLD_ECC_ERR";
	case TSU_CBLD_PCIE_ERR:
		return "TSU_CBLD_PCIE_ERR";
	case TSU_CBLD_QP_ERR:
		return "TSU_CBLD_QP_ERR";
	case TSU_RQS_CHECKSUM_ERR:
		return "TSU_RQS_CHECKSUM_ERR";
	case TSU_RQS_SEQNUM_ERR:
		return "TSU_RQS_SEQNUM_ERR";
	case TSU_RQS_INVALID_REQUEST_ERR:
		return "TSU_RQS_INVALID_REQUEST_ERR";
	case TSU_RQS_QP_IN_WRONG_STATE_ERR:
		return "TSU_RQS_QP_IN_WRONG_STATE_ERR";
	case TSU_RQS_STOP_TIMER_ERR:
		return "TSU_RQS_STOP_TIMER_ERR";
	case TSU_RQS_CMD_FROM_EPS_ERR:
		return "TSU_RQS_CMD_FROM_EPS_ERR";
	case TSU_RQS_SQ_FLUSH_ERR:
		return "TSU_RQS_SQ_FLUSH_ERR";
	case TSU_RQS_SMP_NOT_AUTH_ERR:
		return "TSU_RQS_SMP_NOT_AUTH_ERR";
	case TSU_RQS_REQUEST_FENCED_ERR:
		return "TSU_RQS_REQUEST_FENCED_ERR";
	case TSU_RQS_MAX_OUTSTANDING_REACHED_ERR:
		return "TSU_RQS_MAX_OUTSTANDING_REACHED_ERR";
	case TSU_RQS_ECC_ERR:
		return "TSU_RQS_ECC_ERR";
	case TSU_RQS_EOIB_QKEY_VIOLATION:
		return "TSU_RQS_EOIB_QKEY_VIOLATION";
	case TSU_RQS_IPOIB_QKEY_VIOLATION:
		return "TSU_RQS_IPOIB_QKEY_VIOLATION";
	case TSU_RQS_EOIB_MODE_VIOLATION:
		return "TSU_RQS_EOIB_MODE_VIOLATION";
	case TSU_RQS_MISCONFIGURED_QP:
		return "TSU_RQS_MISCONFIGURED_QP";
	case TSU_RQS_PORT_AUTH_VIOLATION:
		return "TSU_RQS_PORT_AUTH_VIOLATION";
	case TSU_DMA_SGL_RD_ERR:
		return "TSU_DMA_SGL_RD_ERR";
	case TSU_DMA_REQ_PYLD_RD_ERR:
		return "TSU_DMA_REQ_PYLD_RD_ERR";
	case TSU_DMA_RESP_PYLD_RD_ERR:
		return "TSU_DMA_RESP_PYLD_RD_ERR";
	case TSU_DMA_SGL_LENGTH_ERR:
		return "TSU_DMA_SGL_LENGTH_ERR";
	case TSU_DMA_LKEY_ERR:
		return "TSU_DMA_LKEY_ERR";
	case TSU_DMA_RKEY_ERR:
		return "TSU_DMA_RKEY_ERR";
	case TSU_DMA_LSO_PKTLEN_ERR:
		return "TSU_DMA_LSO_PKTLEN_ERR";
	case TSU_DMA_LSO_ILLEGAL_CLASSIFICATION_ERR:
		return "TSU_DMA_LSO_ILLEGAL_CLASSIFICATION_ERR";
	case TSU_DMA_PCIE_ERR:
		return "TSU_DMA_PCIE_ERR";
	case TSU_DMA_ECC_ERR:
		return "TSU_DMA_ECC_ERR";
	case TSU_CMPL_PCIE_ERR:
		return "TSU_CMPL_PCIE_ERR";
	case TSU_CMPL_ECC_ERR:
		return "TSU_CMPL_ECC_ERR";
	case TSU_CMPL_REQUESTER_PSN_ERR:
		return "TSU_CMPL_REQUESTER_PSN_ERR";
	case TSU_CMPL_REQUESTER_SYNDROME_ERR:
		return "TSU_CMPL_REQUESTER_SYNDROME_ERR";
	case TSU_CMPL_REQUESTER_OUTSTANDING_MATCH_ERR:
		return "TSU_CMPL_REQUESTER_OUTSTANDING_MATCH_ERR";
	case TSU_CMPL_REQUESTER_LEN_ERR:
		return "TSU_CMPL_REQUESTER_LEN_ERR";
	case TSU_CMPL_REQUESTER_UNEXP_OPCODE_ERR:
		return "TSU_CMPL_REQUESTER_UNEXP_OPCODE_ERR";
	case TSU_CMPL_REQUESTER_DUPLICATE:
		return "TSU_CMPL_REQUESTER_DUPLICATE";
	case TSU_CMPL_RC_IN_ERROR_ERR:
		return "TSU_CMPL_RC_IN_ERROR_ERR";
	case TSU_CMPL_NAK_RNR_ERR:
		return "TSU_CMPL_NAK_RNR_ERR";
	case TSU_CMPL_NAK_SEQUENCE_ERR:
		return "TSU_CMPL_NAK_SEQUENCE_ERR";
	case TSU_CMPL_NAK_INVALID_REQUEST_ERR:
		return "TSU_CMPL_NAK_INVALID_REQUEST_ERR";
	case TSU_CMPL_NAK_REMOTE_ACCESS_ERR:
		return "TSU_CMPL_NAK_REMOTE_ACCESS_ERR";
	case TSU_CMPL_NAK_REMOTE_OPS_ERR:
		return "TSU_CMPL_NAK_REMOTE_OPS_ERR";
	case TSU_CMPL_NAK_INVALID_RD_REQUEST_ERR:
		return "TSU_CMPL_NAK_INVALID_RD_REQUEST_ERR";
	case TSU_CMPL_TIMEOUT_ERR:
		return "TSU_CMPL_TIMEOUT_ERR";
	case TSU_CMPL_IMPLIED_NAK:
		return "TSU_CMPL_IMPLIED_NAK";
	case TSU_CMPL_GHOST_RESP_ERR:
		return "TSU_CMPL_GHOST_RESP_ERR";
	default:
		return "UNKNOWN_psif_tsu_error_types";
	}
}

void write_enum_psif_tsu_error_types(XFILE *fd,
	enum psif_tsu_error_types data)
{
	xprintf(fd, "%s", string_enum_psif_tsu_error_types(data));
} /* end write_..._psif_tsu_error_types(psif_tsu_error_types data) */

/* Convert enum psif_eps_core_id to string */
const char *string_enum_psif_eps_core_id(enum psif_eps_core_id val)
{
	switch (val) {
	case PSIF_EVENT_CORE_EPS_A_1:
		return "PSIF_EVENT_CORE_EPS_A_1";
	case PSIF_EVENT_CORE_EPS_A_2:
		return "PSIF_EVENT_CORE_EPS_A_2";
	case PSIF_EVENT_CORE_EPS_A_3:
		return "PSIF_EVENT_CORE_EPS_A_3";
	case PSIF_EVENT_CORE_EPS_A_4:
		return "PSIF_EVENT_CORE_EPS_A_4";
	case PSIF_EVENT_CORE_EPS_C:
		return "PSIF_EVENT_CORE_EPS_C";
	case PSIF_EPS_CORE_ID_FIELD_MAX:
		return "PSIF_EPS_CORE_ID_FIELD_MAX";
	default:
		return "UNKNOWN_psif_eps_core_id";
	}
}

void write_enum_psif_eps_core_id(XFILE *fd,
	enum psif_eps_core_id data)
{
	xprintf(fd, "%s", string_enum_psif_eps_core_id(data));
} /* end write_..._psif_eps_core_id(psif_eps_core_id data) */

/* Convert enum psif_epsc_log_mode to string */
const char *string_enum_psif_epsc_log_mode(enum psif_epsc_log_mode val)
{
	switch (val) {
	case EPSC_LOG_MODE_OFF:
		return "EPSC_LOG_MODE_OFF";
	case EPSC_LOG_MODE_SCAT:
		return "EPSC_LOG_MODE_SCAT";
	case EPSC_LOG_MODE_MALLOC:
		return "EPSC_LOG_MODE_MALLOC";
	case EPSC_LOG_MODE_LOCAL:
		return "EPSC_LOG_MODE_LOCAL";
	case EPSC_LOG_MODE_HOST:
		return "EPSC_LOG_MODE_HOST";
	case EPSC_LOG_MODE_SAVE:
		return "EPSC_LOG_MODE_SAVE";
	case PSIF_EPSC_LOG_MODE_FIELD_MAX:
		return "PSIF_EPSC_LOG_MODE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_log_mode";
	}
}

void write_enum_psif_epsc_log_mode(XFILE *fd,
	enum psif_epsc_log_mode data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_log_mode(data));
} /* end write_..._psif_epsc_log_mode(psif_epsc_log_mode data) */

/* Convert enum psif_epsc_log_level to string */
const char *string_enum_psif_epsc_log_level(enum psif_epsc_log_level val)
{
	switch (val) {
	case EPS_LOG_OFF:
		return "EPS_LOG_OFF";
	case EPS_LOG_FATAL:
		return "EPS_LOG_FATAL";
	case EPS_LOG_ERROR:
		return "EPS_LOG_ERROR";
	case EPS_LOG_WARN:
		return "EPS_LOG_WARN";
	case EPS_LOG_INFO:
		return "EPS_LOG_INFO";
	case EPS_LOG_DEBUG:
		return "EPS_LOG_DEBUG";
	case EPS_LOG_TRACE:
		return "EPS_LOG_TRACE";
	case EPS_LOG_ALL:
		return "EPS_LOG_ALL";
	case PSIF_EPSC_LOG_LEVEL_FIELD_MAX:
		return "PSIF_EPSC_LOG_LEVEL_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_log_level";
	}
}

void write_enum_psif_epsc_log_level(XFILE *fd,
	enum psif_epsc_log_level data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_log_level(data));
} /* end write_..._psif_epsc_log_level(psif_epsc_log_level data) */

/* Convert enum psif_epsc_degrade_cause to string */
const char *string_enum_psif_epsc_degrade_cause(enum psif_epsc_degrade_cause val)
{
	switch (val) {
	case DEGRADE_CAUSE_FLAG_MISSING_GUID:
		return "DEGRADE_CAUSE_FLAG_MISSING_GUID";
	case DEGRADE_CAUSE_FLAG_VPD_INVALID_NAME:
		return "DEGRADE_CAUSE_FLAG_VPD_INVALID_NAME";
	case DEGRADE_CAUSE_FLAG_HW_UNSUPPORTED:
		return "DEGRADE_CAUSE_FLAG_HW_UNSUPPORTED";
	case DEGRADE_CAUSE_FLAG_HW_MDIO_ERROR:
		return "DEGRADE_CAUSE_FLAG_HW_MDIO_ERROR";
	case DEGRADE_CAUSE_FLAG_MODIFY_QP_TIMEOUT:
		return "DEGRADE_CAUSE_FLAG_MODIFY_QP_TIMEOUT";
	case DEGRADE_CAUSE_FLAG_VIRTMODE_RECONF:
		return "DEGRADE_CAUSE_FLAG_VIRTMODE_RECONF";
	case DEGRADE_CAUSE_FLAG_MCAST_LACK_OF_CREDIT:
		return "DEGRADE_CAUSE_FLAG_MCAST_LACK_OF_CREDIT";
	case PSIF_EPSC_DEGRADE_CAUSE_FIELD_MAX:
		return "PSIF_EPSC_DEGRADE_CAUSE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_degrade_cause";
	}
}

void write_enum_psif_epsc_degrade_cause(XFILE *fd,
	enum psif_epsc_degrade_cause data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_degrade_cause(data));
} /* end write_..._psif_epsc_degrade_cause(psif_epsc_degrade_cause data) */

/* Convert enum psif_epsc_csr_status to string */
const char *string_enum_psif_epsc_csr_status(enum psif_epsc_csr_status val)
{
	switch (val) {
	case EPSC_SUCCESS:
		return "EPSC_SUCCESS";
	case EPSC_EKEYREJECTED:
		return "EPSC_EKEYREJECTED";
	case EPSC_EADDRNOTAVAIL:
		return "EPSC_EADDRNOTAVAIL";
	case EPSC_EOPNOTSUPP:
		return "EPSC_EOPNOTSUPP";
	case EPSC_ENOMEM:
		return "EPSC_ENOMEM";
	case EPSC_ENODATA:
		return "EPSC_ENODATA";
	case EPSC_EAGAIN:
		return "EPSC_EAGAIN";
	case EPSC_ECANCELED:
		return "EPSC_ECANCELED";
	case EPSC_ECONNRESET:
		return "EPSC_ECONNRESET";
	case EPSC_ECSR:
		return "EPSC_ECSR";
	case EPSC_MODIFY_QP_OUT_OF_RANGE:
		return "EPSC_MODIFY_QP_OUT_OF_RANGE";
	case EPSC_MODIFY_QP_INVALID:
		return "EPSC_MODIFY_QP_INVALID";
	case EPSC_MODIFY_CANNOT_CHANGE_QP_ATTR:
		return "EPSC_MODIFY_CANNOT_CHANGE_QP_ATTR";
	case EPSC_MODIFY_INVALID_QP_STATE:
		return "EPSC_MODIFY_INVALID_QP_STATE";
	case EPSC_MODIFY_INVALID_MIG_STATE:
		return "EPSC_MODIFY_INVALID_MIG_STATE";
	case EPSC_MODIFY_TIMEOUT:
		return "EPSC_MODIFY_TIMEOUT";
	case EPSC_ETEST_HEAD:
		return "EPSC_ETEST_HEAD";
	case EPSC_ETEST_TAIL:
		return "EPSC_ETEST_TAIL";
	case EPSC_ETEST_PATTERN:
		return "EPSC_ETEST_PATTERN";
	case EPSC_EADDRINUSE:
		return "EPSC_EADDRINUSE";
	case EPSC_EINVALID_VHCA:
		return "EPSC_EINVALID_VHCA";
	case EPSC_EINVALID_PORT:
		return "EPSC_EINVALID_PORT";
	case EPSC_EINVALID_ADDRESS:
		return "EPSC_EINVALID_ADDRESS";
	case EPSC_EINVALID_PARAMETER:
		return "EPSC_EINVALID_PARAMETER";
	case EPSC_FAIL:
		return "EPSC_FAIL";
	default:
		return "UNKNOWN_psif_epsc_csr_status";
	}
}

void write_enum_psif_epsc_csr_status(XFILE *fd,
	enum psif_epsc_csr_status data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_status(data));
} /* end write_..._psif_epsc_csr_status(psif_epsc_csr_status data) */

/* Convert enum psif_epsc_csr_opcode to string */
const char *string_enum_psif_epsc_csr_opcode(enum psif_epsc_csr_opcode val)
{
	switch (val) {
	case EPSC_NOOP:
		return "EPSC_NOOP";
	case EPSC_MAILBOX_PING:
		return "EPSC_MAILBOX_PING";
	case EPSC_KEEP_ALIVE:
		return "EPSC_KEEP_ALIVE";
	case EPSC_SETUP:
		return "EPSC_SETUP";
	case EPSC_TEARDOWN:
		return "EPSC_TEARDOWN";
	case EPSC_SET:
		return "EPSC_SET";
	case EPSC_SET_SINGLE:
		return "EPSC_SET_SINGLE";
	case EPSC_SET_ONE_CSR:
		return "EPSC_SET_ONE_CSR";
	case EPSC_SETUP_BASEADDR:
		return "EPSC_SETUP_BASEADDR";
	case EPSC_SET_BASEADDR:
		return "EPSC_SET_BASEADDR";
	case EPSC_SET_BASEADDR_EQ:
		return "EPSC_SET_BASEADDR_EQ";
	case EPSC_SET_LID:
		return "EPSC_SET_LID";
	case OBSOLETE_1:
		return "OBSOLETE_1";
	case OBSOLETE_2:
		return "OBSOLETE_2";
	case EPSC_SET_GID:
		return "EPSC_SET_GID";
	case EPSC_SET_EOIB_MAC:
		return "EPSC_SET_EOIB_MAC";
	case EPSC_SET_VLINK_STATE:
		return "EPSC_SET_VLINK_STATE";
	case EPSC_QUERY_VLINK_STATE:
		return "EPSC_QUERY_VLINK_STATE";
	case EPSC_UF_RESET:
		return "EPSC_UF_RESET";
	case EPSC_MODIFY_QP:
		return "EPSC_MODIFY_QP";
	case EPSC_GET_SINGLE:
		return "EPSC_GET_SINGLE";
	case EPSC_GET_ONE_CSR:
		return "EPSC_GET_ONE_CSR";
	case EPSC_QUERY_QP:
		return "EPSC_QUERY_QP";
	case EPSC_QUERY_HW_RQ:
		return "EPSC_QUERY_HW_RQ";
	case EPSC_QUERY_HW_SQ:
		return "EPSC_QUERY_HW_SQ";
	case EPSC_QUERY_DEVICE:
		return "EPSC_QUERY_DEVICE";
	case EPSC_QUERY_PORT_1:
		return "EPSC_QUERY_PORT_1";
	case EPSC_QUERY_PORT_2:
		return "EPSC_QUERY_PORT_2";
	case EPSC_QUERY_PKEY:
		return "EPSC_QUERY_PKEY";
	case EPSC_QUERY_GID:
		return "EPSC_QUERY_GID";
	case EPSC_MODIFY_DEVICE:
		return "EPSC_MODIFY_DEVICE";
	case EPSC_MODIFY_PORT_1:
		return "EPSC_MODIFY_PORT_1";
	case EPSC_MODIFY_PORT_2:
		return "EPSC_MODIFY_PORT_2";
	case EPSC_MC_ATTACH:
		return "EPSC_MC_ATTACH";
	case EPSC_MC_DETACH:
		return "EPSC_MC_DETACH";
	case EPSC_MC_QUERY:
		return "EPSC_MC_QUERY";
	case EPSC_EVENT_ACK:
		return "EPSC_EVENT_ACK";
	case EPSC_EVENT_INDEX:
		return "EPSC_EVENT_INDEX";
	case EPSC_FLASH_START:
		return "EPSC_FLASH_START";
	case EPSC_FLASH_INFO:
		return "EPSC_FLASH_INFO";
	case EPSC_FLASH_ERASE_SECTOR:
		return "EPSC_FLASH_ERASE_SECTOR";
	case EPSC_FLASH_RD:
		return "EPSC_FLASH_RD";
	case EPSC_FLASH_WR:
		return "EPSC_FLASH_WR";
	case EPSC_FLASH_CHECK:
		return "EPSC_FLASH_CHECK";
	case EPSC_FLASH_SCAN:
		return "EPSC_FLASH_SCAN";
	case EPSC_FLASH_STOP:
		return "EPSC_FLASH_STOP";
	case EPSC_UPDATE:
		return "EPSC_UPDATE";
	case EPSC_TRACE_STATUS:
		return "EPSC_TRACE_STATUS";
	case EPSC_TRACE_SETUP:
		return "EPSC_TRACE_SETUP";
	case EPSC_TRACE_START:
		return "EPSC_TRACE_START";
	case EPSC_TRACE_STOP:
		return "EPSC_TRACE_STOP";
	case EPSC_TRACE_ACQUIRE:
		return "EPSC_TRACE_ACQUIRE";
	case EPSC_TEST_HOST_RD:
		return "EPSC_TEST_HOST_RD";
	case EPSC_TEST_HOST_WR:
		return "EPSC_TEST_HOST_WR";
	case EPSC_FW_VERSION:
		return "EPSC_FW_VERSION";
	case EPSC_LOG_CTRL:
		return "EPSC_LOG_CTRL";
	case EPSC_LOG_REQ_NOTIFY:
		return "EPSC_LOG_REQ_NOTIFY";
	case EPSC_LINK_CNTRL:
		return "EPSC_LINK_CNTRL";
	case EPSC_A_CONTROL:
		return "EPSC_A_CONTROL";
	case EPSC_A_COMMAND:
		return "EPSC_A_COMMAND";
	case EPSC_EXERCISE_MMU:
		return "EPSC_EXERCISE_MMU";
	case EPSC_CLI_ACCESS:
		return "EPSC_CLI_ACCESS";
	case EPSC_MAD_PROCESS:
		return "EPSC_MAD_PROCESS";
	case EPSC_MAD_SEND_WR:
		return "EPSC_MAD_SEND_WR";
	case EPSC_QUERY:
		return "EPSC_QUERY";
	case EPSC_HOST_INT_COMMON_CTRL:
		return "EPSC_HOST_INT_COMMON_CTRL";
	case EPSC_HOST_INT_CHANNEL_CTRL:
		return "EPSC_HOST_INT_CHANNEL_CTRL";
	case EPSC_UF_CTRL:
		return "EPSC_UF_CTRL";
	case EPSC_FLUSH_CACHES:
		return "EPSC_FLUSH_CACHES";
	case EPSC_PMA_COUNTERS:
		return "EPSC_PMA_COUNTERS";
	case EPSC_VIMMA_CTRL:
		return "EPSC_VIMMA_CTRL";
	case EPSC_BER_DATA:
		return "EPSC_BER_DATA";
	case EPSC_LAST_OP:
		return "EPSC_LAST_OP";
	case PSIF_EPSC_CSR_OPCODE_FIELD_MAX:
		return "PSIF_EPSC_CSR_OPCODE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_opcode";
	}
}

void write_enum_psif_epsc_csr_opcode(XFILE *fd,
	enum psif_epsc_csr_opcode data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_opcode(data));
} /* end write_..._psif_epsc_csr_opcode(psif_epsc_csr_opcode data) */

/* Convert enum psif_epsc_csr_flags to string */
const char *string_enum_psif_epsc_csr_flags(enum psif_epsc_csr_flags val)
{
	switch (val) {
	case EPSC_FL_NONE:
		return "EPSC_FL_NONE";
	case EPSC_FL_NOTIFY:
		return "EPSC_FL_NOTIFY";
	case EPSC_FL_PQP:
		return "EPSC_FL_PQP";
	case EPSC_FL_IGNORE_ERROR:
		return "EPSC_FL_IGNORE_ERROR";
	case PSIF_EPSC_CSR_FLAGS_FIELD_MAX:
		return "PSIF_EPSC_CSR_FLAGS_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_flags";
	}
}

void write_enum_psif_epsc_csr_flags(XFILE *fd,
	enum psif_epsc_csr_flags data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_flags(data));
} /* end write_..._psif_epsc_csr_flags(psif_epsc_csr_flags data) */

/* Convert enum psif_vlink_state to string */
const char *string_enum_psif_vlink_state(enum psif_vlink_state val)
{
	switch (val) {
	case PSIF_LINK_DISABLED:
		return "PSIF_LINK_DISABLED";
	case PSIF_LINK_DOWN:
		return "PSIF_LINK_DOWN";
	case PSIF_LINK_INIT:
		return "PSIF_LINK_INIT";
	case PSIF_LINK_ARM:
		return "PSIF_LINK_ARM";
	case PSIF_LINK_ACTIVE:
		return "PSIF_LINK_ACTIVE";
	default:
		return "UNKNOWN_psif_vlink_state";
	}
}

void write_enum_psif_vlink_state(XFILE *fd,
	enum psif_vlink_state data)
{
	xprintf(fd, "%s", string_enum_psif_vlink_state(data));
} /* end write_..._psif_vlink_state(psif_vlink_state data) */

/* Convert enum psif_epsc_csr_modify_device_flags to string */
const char *string_enum_psif_epsc_csr_modify_device_flags(enum psif_epsc_csr_modify_device_flags val)
{
	switch (val) {
	case PSIF_DEVICE_MODIFY_SYS_IMAGE_GUID:
		return "PSIF_DEVICE_MODIFY_SYS_IMAGE_GUID";
	case PSIF_DEVICE_MODIFY_NODE_DESC:
		return "PSIF_DEVICE_MODIFY_NODE_DESC";
	case PSIF_EPSC_CSR_MODIFY_DEVICE_FLAGS_FIELD_MAX:
		return "PSIF_EPSC_CSR_MODIFY_DEVICE_FLAGS_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_modify_device_flags";
	}
}

void write_enum_psif_epsc_csr_modify_device_flags(XFILE *fd,
	enum psif_epsc_csr_modify_device_flags data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_modify_device_flags(data));
} /* end write_..._psif_epsc_csr_modify_device_flags(psif_epsc_csr_modify_device_flags data) */

/* Convert enum psif_epsc_csr_modify_port_flags to string */
const char *string_enum_psif_epsc_csr_modify_port_flags(enum psif_epsc_csr_modify_port_flags val)
{
	switch (val) {
	case PSIF_PORT_SHUTDOWN:
		return "PSIF_PORT_SHUTDOWN";
	case PSIF_PORT_INIT_TYPE:
		return "PSIF_PORT_INIT_TYPE";
	case PSIF_PORT_RESET_QKEY_CNTR:
		return "PSIF_PORT_RESET_QKEY_CNTR";
	case PSIF_PORT_RESET_PKEY_CNTR:
		return "PSIF_PORT_RESET_PKEY_CNTR";
	case PSIF_EPSC_CSR_MODIFY_PORT_FLAGS_FIELD_MAX:
		return "PSIF_EPSC_CSR_MODIFY_PORT_FLAGS_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_modify_port_flags";
	}
}

void write_enum_psif_epsc_csr_modify_port_flags(XFILE *fd,
	enum psif_epsc_csr_modify_port_flags data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_modify_port_flags(data));
} /* end write_..._psif_epsc_csr_modify_port_flags(psif_epsc_csr_modify_port_flags data) */

/* Convert enum psif_epsc_csr_epsa_command to string */
const char *string_enum_psif_epsc_csr_epsa_command(enum psif_epsc_csr_epsa_command val)
{
	switch (val) {
	case EPSC_A_LOAD:
		return "EPSC_A_LOAD";
	case EPSC_A_START:
		return "EPSC_A_START";
	case EPSC_A_STOP:
		return "EPSC_A_STOP";
	case EPSC_A_STATUS:
		return "EPSC_A_STATUS";
	case PSIF_EPSC_CSR_EPSA_COMMAND_FIELD_MAX:
		return "PSIF_EPSC_CSR_EPSA_COMMAND_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_epsa_command";
	}
}

void write_enum_psif_epsc_csr_epsa_command(XFILE *fd,
	enum psif_epsc_csr_epsa_command data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_epsa_command(data));
} /* end write_..._psif_epsc_csr_epsa_command(psif_epsc_csr_epsa_command data) */

/* Convert enum psif_epsa_command to string */
const char *string_enum_psif_epsa_command(enum psif_epsa_command val)
{
	switch (val) {
	case EPSA_DYNAMIC_LOAD:
		return "EPSA_DYNAMIC_LOAD";
	case EPSA_TEST_FABOUT:
		return "EPSA_TEST_FABOUT";
	case EPSA_TEST_FABIN:
		return "EPSA_TEST_FABIN";
	case EPSA_TEST_FABIN_FABOUT:
		return "EPSA_TEST_FABIN_FABOUT";
	case EPSA_TEST_SKJM_MEMREAD:
		return "EPSA_TEST_SKJM_MEMREAD";
	case EPSA_TEST_SKJM_MEMWRITE:
		return "EPSA_TEST_SKJM_MEMWRITE";
	case EPSA_TEST_SKJM_MEMLOCK:
		return "EPSA_TEST_SKJM_MEMLOCK";
	case EPSA_SKJM_LOAD:
		return "EPSA_SKJM_LOAD";
	case EPSA_SKJM_ACC:
		return "EPSA_SKJM_ACC";
	case EPSA_SKJM_MEMACC:
		return "EPSA_SKJM_MEMACC";
	case EPSA_GET_PROXY_QP_SQ_KEY:
		return "EPSA_GET_PROXY_QP_SQ_KEY";
	case EPSA_GENERIC_CMD:
		return "EPSA_GENERIC_CMD";
	case EPSA_GET_EXPORTED_SYMBOL_MAP:
		return "EPSA_GET_EXPORTED_SYMBOL_MAP";
	case PSIF_EPSA_COMMAND_FIELD_MAX:
		return "PSIF_EPSA_COMMAND_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsa_command";
	}
}

void write_enum_psif_epsa_command(XFILE *fd,
	enum psif_epsa_command data)
{
	xprintf(fd, "%s", string_enum_psif_epsa_command(data));
} /* end write_..._psif_epsa_command(psif_epsa_command data) */

/* Convert enum psif_epsc_query_op to string */
const char *string_enum_psif_epsc_query_op(enum psif_epsc_query_op val)
{
	switch (val) {
	case EPSC_QUERY_BLANK:
		return "EPSC_QUERY_BLANK";
	case EPSC_QUERY_CAP_VCB:
		return "EPSC_QUERY_CAP_VCB";
	case EPSC_QUERY_CAP_PCB:
		return "EPSC_QUERY_CAP_PCB";
	case EPSC_QUERY_NUM_UF:
		return "EPSC_QUERY_NUM_UF";
	case EPSC_QUERY_GID_HI:
		return "EPSC_QUERY_GID_HI";
	case EPSC_QUERY_GID_LO:
		return "EPSC_QUERY_GID_LO";
	case EPSC_QUERY_P_KEY:
		return "EPSC_QUERY_P_KEY";
	case EPSC_QUERY_Q_KEY:
		return "EPSC_QUERY_Q_KEY";
	case EPSC_QUERY_UF:
		return "EPSC_QUERY_UF";
	case EPSC_QUERY_LINK_STATE:
		return "EPSC_QUERY_LINK_STATE";
	case EPSC_QUERY_VHCA_STATE:
		return "EPSC_QUERY_VHCA_STATE";
	case EPSC_QUERY_INT_COMMON:
		return "EPSC_QUERY_INT_COMMON";
	case EPSC_QUERY_INT_CHAN_RATE:
		return "EPSC_QUERY_INT_CHAN_RATE";
	case EPSC_QUERY_INT_CHAN_AUSEC:
		return "EPSC_QUERY_INT_CHAN_AUSEC";
	case EPSC_QUERY_INT_CHAN_PUSEC:
		return "EPSC_QUERY_INT_CHAN_PUSEC";
	case EPSC_QUERY_CAP_VCB_LO:
		return "EPSC_QUERY_CAP_VCB_LO";
	case EPSC_QUERY_CAP_VCB_HI:
		return "EPSC_QUERY_CAP_VCB_HI";
	case EPSC_QUERY_CAP_PCB_LO:
		return "EPSC_QUERY_CAP_PCB_LO";
	case EPSC_QUERY_CAP_PCB_HI:
		return "EPSC_QUERY_CAP_PCB_HI";
	case EPSC_QUERY_PMA_REDIRECT_QP:
		return "EPSC_QUERY_PMA_REDIRECT_QP";
	case EPSC_QUERY_FW_UPTIME:
		return "EPSC_QUERY_FW_UPTIME";
	case EPSC_QUERY_FW_PROG_DATE:
		return "EPSC_QUERY_FW_PROG_DATE";
	case EPSC_QUERY_FW_BUILD_DATE:
		return "EPSC_QUERY_FW_BUILD_DATE";
	case EPSC_QUERY_FW_CURR_IMG:
		return "EPSC_QUERY_FW_CURR_IMG";
	case EPSC_QUERY_FW_ONESHOT_IMG:
		return "EPSC_QUERY_FW_ONESHOT_IMG";
	case EPSC_QUERY_FW_AUTOSTART_IMG:
		return "EPSC_QUERY_FW_AUTOSTART_IMG";
	case EPSC_QUERY_FW_START_CAUSE:
		return "EPSC_QUERY_FW_START_CAUSE";
	case EPSC_QUERY_FW_VERSION:
		return "EPSC_QUERY_FW_VERSION";
	case EPSC_QUERY_SQ_NUM_BRE:
		return "EPSC_QUERY_SQ_NUM_BRE";
	case EPSC_QUERY_NUM_CQOVF:
		return "EPSC_QUERY_NUM_CQOVF";
	case EPSC_QUERY_SQ_NUM_WRFE:
		return "EPSC_QUERY_SQ_NUM_WRFE";
	case EPSC_QUERY_RQ_NUM_WRFE:
		return "EPSC_QUERY_RQ_NUM_WRFE";
	case EPSC_QUERY_RQ_NUM_LAE:
		return "EPSC_QUERY_RQ_NUM_LAE";
	case EPSC_QUERY_RQ_NUM_LPE:
		return "EPSC_QUERY_RQ_NUM_LPE";
	case EPSC_QUERY_SQ_NUM_LLE:
		return "EPSC_QUERY_SQ_NUM_LLE";
	case EPSC_QUERY_RQ_NUM_LLE:
		return "EPSC_QUERY_RQ_NUM_LLE";
	case EPSC_QUERY_SQ_NUM_LQPOE:
		return "EPSC_QUERY_SQ_NUM_LQPOE";
	case EPSC_QUERY_RQ_NUM_LQPOE:
		return "EPSC_QUERY_RQ_NUM_LQPOE";
	case EPSC_QUERY_SQ_NUM_OOS:
		return "EPSC_QUERY_SQ_NUM_OOS";
	case EPSC_QUERY_RQ_NUM_OOS:
		return "EPSC_QUERY_RQ_NUM_OOS";
	case EPSC_QUERY_SQ_NUM_RREE:
		return "EPSC_QUERY_SQ_NUM_RREE";
	case EPSC_QUERY_SQ_NUM_TREE:
		return "EPSC_QUERY_SQ_NUM_TREE";
	case EPSC_QUERY_SQ_NUM_ROE:
		return "EPSC_QUERY_SQ_NUM_ROE";
	case EPSC_QUERY_RQ_NUM_ROE:
		return "EPSC_QUERY_RQ_NUM_ROE";
	case EPSC_QUERY_SQ_NUM_RAE:
		return "EPSC_QUERY_SQ_NUM_RAE";
	case EPSC_QUERY_RQ_NUM_RAE:
		return "EPSC_QUERY_RQ_NUM_RAE";
	case EPSC_QUERY_RQ_NUM_UDSDPRD:
		return "EPSC_QUERY_RQ_NUM_UDSDPRD";
	case EPSC_QUERY_RQ_NUM_UCSDPRD:
		return "EPSC_QUERY_RQ_NUM_UCSDPRD";
	case EPSC_QUERY_SQ_NUM_RIRE:
		return "EPSC_QUERY_SQ_NUM_RIRE";
	case EPSC_QUERY_RQ_NUM_RIRE:
		return "EPSC_QUERY_RQ_NUM_RIRE";
	case EPSC_QUERY_SQ_NUM_RNR:
		return "EPSC_QUERY_SQ_NUM_RNR";
	case EPSC_QUERY_RQ_NUM_RNR:
		return "EPSC_QUERY_RQ_NUM_RNR";
	case EPSC_QUERY_FW_TWOSHOT_IMG:
		return "EPSC_QUERY_FW_TWOSHOT_IMG";
	case EPSC_QUERY_FW_TYPE:
		return "EPSC_QUERY_FW_TYPE";
	case EPSC_QUERY_FW_SIZE:
		return "EPSC_QUERY_FW_SIZE";
	case EPSC_QUERY_FW_SLOT_SIZE:
		return "EPSC_QUERY_FW_SLOT_SIZE";
	case EPSC_QUERY_BL_VERSION:
		return "EPSC_QUERY_BL_VERSION";
	case EPSC_QUERY_BL_BUILD_DATE:
		return "EPSC_QUERY_BL_BUILD_DATE";
	case EPSC_QUERY_CLEAN_CQ_ID:
		return "EPSC_QUERY_CLEAN_CQ_ID";
	case EPSC_QUERY_CAP_TSL_TX:
		return "EPSC_QUERY_CAP_TSL_TX";
	case EPSC_QUERY_CAP_TSL_RX:
		return "EPSC_QUERY_CAP_TSL_RX";
	case EPSC_QUERY_RESET_CBLD_DIAG_COUNTERS:
		return "EPSC_QUERY_RESET_CBLD_DIAG_COUNTERS";
	case EPSC_QUERY_MAX_QP_USED:
		return "EPSC_QUERY_MAX_QP_USED";
	case EPSC_QUERY_MODQP_TO_SOURCE:
		return "EPSC_QUERY_MODQP_TO_SOURCE";
	case EPSC_QUERY_MODQP_TO_DEBUG:
		return "EPSC_QUERY_MODQP_TO_DEBUG";
	case EPSC_QUERY_DEGRADED_CAUSE:
		return "EPSC_QUERY_DEGRADED_CAUSE";
	case EPSC_QUERY_SPIN_SET_CONTROL:
		return "EPSC_QUERY_SPIN_SET_CONTROL";
	case EPSC_QUERY_VPD_MAC:
		return "EPSC_QUERY_VPD_MAC";
	case EPSC_QUERY_VPD_PART_NUMBER:
		return "EPSC_QUERY_VPD_PART_NUMBER";
	case EPSC_QUERY_VPD_REVISION:
		return "EPSC_QUERY_VPD_REVISION";
	case EPSC_QUERY_VPD_SERIAL_NUMBER:
		return "EPSC_QUERY_VPD_SERIAL_NUMBER";
	case EPSC_QUERY_VPD_MANUFACTURER:
		return "EPSC_QUERY_VPD_MANUFACTURER";
	case EPSC_QUERY_VPD_PRODUCT_NAME:
		return "EPSC_QUERY_VPD_PRODUCT_NAME";
	case EPSC_QUERY_VPD_BASE_GUID:
		return "EPSC_QUERY_VPD_BASE_GUID";
	case EPSC_QUERY_MAP_QP0_TO_TSL:
		return "EPSC_QUERY_MAP_QP0_TO_TSL";
	case EPSC_QUERY_MAP_PQP_TO_TSL:
		return "EPSC_QUERY_MAP_PQP_TO_TSL";
	case EPSC_QUERY_MAP_SL_TO_TSL_LO:
		return "EPSC_QUERY_MAP_SL_TO_TSL_LO";
	case EPSC_QUERY_MAP_SL_TO_TSL_HI:
		return "EPSC_QUERY_MAP_SL_TO_TSL_HI";
	case EPSC_QUERY_TA_UPPER_TWELVE:
		return "EPSC_QUERY_TA_UPPER_TWELVE";
	case EPSC_QUERY_PA_UPPER_TWELVE:
		return "EPSC_QUERY_PA_UPPER_TWELVE";
	case EPSC_QUERY_NUM_VFS:
		return "EPSC_QUERY_NUM_VFS";
	case EPSC_QUERY_CREDIT_MODE:
		return "EPSC_QUERY_CREDIT_MODE";
	case EPSC_QUERY_CPLD_VERSION:
		return "EPSC_QUERY_CPLD_VERSION";
	case EPSC_QUERY_EXTERNAL_PORT_INFO:
		return "EPSC_QUERY_EXTERNAL_PORT_INFO";
	case EPSC_QUERY_HW_REVISION:
		return "EPSC_QUERY_HW_REVISION";
	case EPSC_QUERY_ON_CHIP_TEMP:
		return "EPSC_QUERY_ON_CHIP_TEMP";
	case EPSC_QUERY_LAST:
		return "EPSC_QUERY_LAST";
	case PSIF_EPSC_QUERY_OP_FIELD_MAX:
		return "PSIF_EPSC_QUERY_OP_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_query_op";
	}
}

void write_enum_psif_epsc_query_op(XFILE *fd,
	enum psif_epsc_query_op data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_query_op(data));
} /* end write_..._psif_epsc_query_op(psif_epsc_query_op data) */

/* Convert enum psif_epsc_csr_update_opcode to string */
const char *string_enum_psif_epsc_csr_update_opcode(enum psif_epsc_csr_update_opcode val)
{
	switch (val) {
	case EPSC_UPDATE_OP_POLL:
		return "EPSC_UPDATE_OP_POLL";
	case EPSC_UPDATE_OP_START:
		return "EPSC_UPDATE_OP_START";
	case EPSC_UPDATE_OP_ERASE:
		return "EPSC_UPDATE_OP_ERASE";
	case EPSC_UPDATE_OP_WRITE:
		return "EPSC_UPDATE_OP_WRITE";
	case EPSC_UPDATE_OP_READ:
		return "EPSC_UPDATE_OP_READ";
	case EPSC_UPDATE_OP_STOP:
		return "EPSC_UPDATE_OP_STOP";
	case EPSC_UPDATE_OP_SET:
		return "EPSC_UPDATE_OP_SET";
	case EPSC_UPDATE_OP_MAX:
		return "EPSC_UPDATE_OP_MAX";
	case PSIF_EPSC_CSR_UPDATE_OPCODE_FIELD_MAX:
		return "PSIF_EPSC_CSR_UPDATE_OPCODE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_update_opcode";
	}
}

void write_enum_psif_epsc_csr_update_opcode(XFILE *fd,
	enum psif_epsc_csr_update_opcode data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_update_opcode(data));
} /* end write_..._psif_epsc_csr_update_opcode(psif_epsc_csr_update_opcode data) */

/* Convert enum psif_epsc_flash_slot to string */
const char *string_enum_psif_epsc_flash_slot(enum psif_epsc_flash_slot val)
{
	switch (val) {
	case EPSC_FLASH_SLOT_INVALID:
		return "EPSC_FLASH_SLOT_INVALID";
	case EPSC_FLASH_SLOT_EPS_C_IMG_1:
		return "EPSC_FLASH_SLOT_EPS_C_IMG_1";
	case EPSC_FLASH_SLOT_EPS_C_IMG_2:
		return "EPSC_FLASH_SLOT_EPS_C_IMG_2";
	case EPSC_FLASH_SLOT_EPS_A_IMG:
		return "EPSC_FLASH_SLOT_EPS_A_IMG";
	case EPSC_FLASH_SLOT_BOOT_IMG:
		return "EPSC_FLASH_SLOT_BOOT_IMG";
	case EPSC_FLASH_SLOT_COUNT:
		return "EPSC_FLASH_SLOT_COUNT";
	case PSIF_EPSC_FLASH_SLOT_FIELD_MAX:
		return "PSIF_EPSC_FLASH_SLOT_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_flash_slot";
	}
}

void write_enum_psif_epsc_flash_slot(XFILE *fd,
	enum psif_epsc_flash_slot data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_flash_slot(data));
} /* end write_..._psif_epsc_flash_slot(psif_epsc_flash_slot data) */

/* Convert enum psif_epsc_update_set to string */
const char *string_enum_psif_epsc_update_set(enum psif_epsc_update_set val)
{
	switch (val) {
	case EPSC_UPDATE_SET_INVALID:
		return "EPSC_UPDATE_SET_INVALID";
	case EPSC_UPDATE_SET_AUTOSTART_IMG:
		return "EPSC_UPDATE_SET_AUTOSTART_IMG";
	case EPSC_UPDATE_SET_ONESHOT_IMG:
		return "EPSC_UPDATE_SET_ONESHOT_IMG";
	case EPSC_UPDATE_SET_TWOSHOT_IMG:
		return "EPSC_UPDATE_SET_TWOSHOT_IMG";
	case EPSC_UPDATE_SET_IMG_VALID:
		return "EPSC_UPDATE_SET_IMG_VALID";
	case PSIF_EPSC_UPDATE_SET_FIELD_MAX:
		return "PSIF_EPSC_UPDATE_SET_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_update_set";
	}
}

void write_enum_psif_epsc_update_set(XFILE *fd,
	enum psif_epsc_update_set data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_update_set(data));
} /* end write_..._psif_epsc_update_set(psif_epsc_update_set data) */

/* Convert enum psif_epsc_csr_uf_ctrl_opcode to string */
const char *string_enum_psif_epsc_csr_uf_ctrl_opcode(enum psif_epsc_csr_uf_ctrl_opcode val)
{
	switch (val) {
	case EPSC_UF_CTRL_MMU_FLUSH:
		return "EPSC_UF_CTRL_MMU_FLUSH";
	case EPSC_UF_CTRL_GET_UF_USED_QP:
		return "EPSC_UF_CTRL_GET_UF_USED_QP";
	case EPSC_UF_CTRL_CLEAR_UF_USED_QP:
		return "EPSC_UF_CTRL_CLEAR_UF_USED_QP";
	case EPSC_UF_CTRL_SMP_ENABLE:
		return "EPSC_UF_CTRL_SMP_ENABLE";
	case EPSC_UF_CTRL_SMP_DISABLE:
		return "EPSC_UF_CTRL_SMP_DISABLE";
	case EPSC_UF_CTRL_VLINK_CONNECT:
		return "EPSC_UF_CTRL_VLINK_CONNECT";
	case EPSC_UF_CTRL_VLINK_DISCONNECT:
		return "EPSC_UF_CTRL_VLINK_DISCONNECT";
	case EPSC_UF_CTRL_GET_HIGHEST_QP_IDX:
		return "EPSC_UF_CTRL_GET_HIGHEST_QP_IDX";
	case EPSC_UF_CTRL_RESET_HIGHEST_QP_IDX:
		return "EPSC_UF_CTRL_RESET_HIGHEST_QP_IDX";
	case EPSC_UF_CTRL_GET_SMP_ENABLE:
		return "EPSC_UF_CTRL_GET_SMP_ENABLE";
	case EPSC_UF_CTRL_GET_VLINK_CONNECT:
		return "EPSC_UF_CTRL_GET_VLINK_CONNECT";
	case PSIF_EPSC_CSR_UF_CTRL_OPCODE_FIELD_MAX:
		return "PSIF_EPSC_CSR_UF_CTRL_OPCODE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_csr_uf_ctrl_opcode";
	}
}

void write_enum_psif_epsc_csr_uf_ctrl_opcode(XFILE *fd,
	enum psif_epsc_csr_uf_ctrl_opcode data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_csr_uf_ctrl_opcode(data));
} /* end write_..._psif_epsc_csr_uf_ctrl_opcode(psif_epsc_csr_uf_ctrl_opcode data) */

/* Convert enum psif_epsc_vimma_ctrl_opcode to string */
const char *string_enum_psif_epsc_vimma_ctrl_opcode(enum psif_epsc_vimma_ctrl_opcode val)
{
	switch (val) {
	case EPSC_VIMMA_CTRL_GET_VER_AND_COMPAT:
		return "EPSC_VIMMA_CTRL_GET_VER_AND_COMPAT";
	case EPSC_VIMMA_CTRL_GET_MISC_INFO:
		return "EPSC_VIMMA_CTRL_GET_MISC_INFO";
	case EPSC_VIMMA_CTRL_GET_GUIDS:
		return "EPSC_VIMMA_CTRL_GET_GUIDS";
	case EPSC_VIMMA_CTRL_GET_REG_INFO:
		return "EPSC_VIMMA_CTRL_GET_REG_INFO";
	case EPSC_VIMMA_CTRL_GET_VHCA_STATS:
		return "EPSC_VIMMA_CTRL_GET_VHCA_STATS";
	case EPSC_VIMMA_CTRL_SET_VFP_VHCA_REGISTER:
		return "EPSC_VIMMA_CTRL_SET_VFP_VHCA_REGISTER";
	case EPSC_VIMMA_CTRL_SET_VFP_VHCA_DEREGISTER:
		return "EPSC_VIMMA_CTRL_SET_VFP_VHCA_DEREGISTER";
	case EPSC_VIMMA_CTRL_SET_ADMIN_MODE:
		return "EPSC_VIMMA_CTRL_SET_ADMIN_MODE";
	case EPSC_VIMMA_CTRL_RESET:
		return "EPSC_VIMMA_CTRL_RESET";
	case PSIF_EPSC_VIMMA_CTRL_OPCODE_FIELD_MAX:
		return "PSIF_EPSC_VIMMA_CTRL_OPCODE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_vimma_ctrl_opcode";
	}
}

void write_enum_psif_epsc_vimma_ctrl_opcode(XFILE *fd,
	enum psif_epsc_vimma_ctrl_opcode data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_vimma_ctrl_opcode(data));
} /* end write_..._psif_epsc_vimma_ctrl_opcode(psif_epsc_vimma_ctrl_opcode data) */

/* Convert enum psif_epsc_vimma_admmode to string */
const char *string_enum_psif_epsc_vimma_admmode(enum psif_epsc_vimma_admmode val)
{
	switch (val) {
	case EPSC_VIMMA_CTRL_IB_ADM_MODE_SM_STANDARD:
		return "EPSC_VIMMA_CTRL_IB_ADM_MODE_SM_STANDARD";
	case EPSC_VIMMA_CTRL_IB_ADM_MODE_VM_FABRIC_PROFILE:
		return "EPSC_VIMMA_CTRL_IB_ADM_MODE_VM_FABRIC_PROFILE";
	case PSIF_EPSC_VIMMA_ADMMODE_FIELD_MAX:
		return "PSIF_EPSC_VIMMA_ADMMODE_FIELD_MAX";
	default:
		return "UNKNOWN_psif_epsc_vimma_admmode";
	}
}

void write_enum_psif_epsc_vimma_admmode(XFILE *fd,
	enum psif_epsc_vimma_admmode data)
{
	xprintf(fd, "%s", string_enum_psif_epsc_vimma_admmode(data));
} /* end write_..._psif_epsc_vimma_admmode(psif_epsc_vimma_admmode data) */

/* Convert enum psif_cq_state to string */
const char *string_enum_psif_cq_state(enum psif_cq_state val)
{
	switch (val) {
	case PSIF_CQ_UNARMED:
		return "PSIF_CQ_UNARMED";
	case PSIF_CQ_ARMED_SE:
		return "PSIF_CQ_ARMED_SE";
	case PSIF_CQ_ARMED_ALL:
		return "PSIF_CQ_ARMED_ALL";
	case PSIF_CQ_TRIGGERED:
		return "PSIF_CQ_TRIGGERED";
	default:
		return "UNKNOWN_psif_cq_state";
	}
}

void write_enum_psif_cq_state(XFILE *fd,
	enum psif_cq_state data)
{
	xprintf(fd, "%s", string_enum_psif_cq_state(data));
} /* end write_..._psif_cq_state(psif_cq_state data) */

/* Convert enum psif_rss_hash_source to string */
const char *string_enum_psif_rss_hash_source(enum psif_rss_hash_source val)
{
	switch (val) {
	case RSS_WITHOUT_PORT:
		return "RSS_WITHOUT_PORT";
	case RSS_WITH_PORT:
		return "RSS_WITH_PORT";
	default:
		return "UNKNOWN_psif_rss_hash_source";
	}
}

void write_enum_psif_rss_hash_source(XFILE *fd,
	enum psif_rss_hash_source data)
{
	xprintf(fd, "%s", string_enum_psif_rss_hash_source(data));
} /* end write_..._psif_rss_hash_source(psif_rss_hash_source data) */

#if !defined(PSIF_EXCLUDE_WRITE_STRUCTS)


void write_struct_psif_mmu_cntx(XFILE *fd,
	int network_order,
	const struct psif_mmu_cntx *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_mmu_cntx *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .table_level = ");
	write_bits_u8(fd, 3, data->table_level);
	xprintf(fd, ", .wr_access = ");
	write_bits_u8(fd, 1, data->wr_access);
	xprintf(fd, ", .page_size = ");
	write_enum_psif_page_size(fd, data->page_size);
	xprintf(fd, ", .translation_type = ");
	write_enum_psif_mmu_translation(fd, data->translation_type);
	xprintf(fd, ", .th = ");
	write_bits_u8(fd, 1, data->th);
	xprintf(fd, ", .table_ptr = ");
	write_bits_u64(fd, 40, data->table_ptr);
	xprintf(fd, ", .ro = ");
	write_bits_u8(fd, 1, data->ro);
	xprintf(fd, ", .tph = ");
	write_bits_u8(fd, 2, data->tph);
	xprintf(fd, ", .ns = ");
	write_bits_u8(fd, 1, data->ns);
	xprintf(fd, ", .st = ");
	write_bits_u8(fd, 8, data->st);
	xprintf(fd, "}");
} /* end write_..._psif_mmu_cntx(psif_mmu_cntx data) */

void write_struct_psif_vlan_union_struct(XFILE *fd,
	int network_order,
	const struct psif_vlan_union_struct *data)
{
	xprintf(fd, "{");
	xprintf(fd, ", .vlan_pri = ");
	write_bits_u8(fd, 4, data->vlan_pri);
	xprintf(fd, "}");
} /* end write_..._psif_vlan_union_struct(psif_vlan_union_struct data) */

void write_union_psif_cq_desc_vlan_pri(XFILE *fd,
	int network_order,
	const union psif_cq_desc_vlan_pri *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .cqd_id = ");
	write_bits_u32(fd, 24, data->cqd_id);
	xprintf(fd, ", .vlan_pri = ");
	write_struct_psif_vlan_union_struct(fd, 0, &(data->vlan_pri));
	xprintf(fd, "}");
} /* end write_..._psif_cq_desc_vlan_pri(psif_cq_desc_vlan_pri data) */

void write_struct_psif_wr_common(XFILE *fd,
	int network_order,
	const struct psif_wr_common *data)
{
	u64 swap[3];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 24);
		data = (struct psif_wr_common *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .sq_seq = ");
	write_bits_u16(fd, 16, data->sq_seq);
	xprintf(fd, ", .collect_length = ");
	write_bits_u16(fd, 9, data->collect_length);
	xprintf(fd, ", .tsu_qosl = ");
	write_enum_psif_tsu_qos(fd, data->tsu_qosl);
	xprintf(fd, ", .ud_pkt = ");
	write_enum_psif_use_ah(fd, data->ud_pkt);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .tsu_sl = ");
	write_bits_u8(fd, 4, data->tsu_sl);
	xprintf(fd, ", .local_qp = ");
	write_bits_u32(fd, 24, data->local_qp);
	xprintf(fd, ", .op = ");
	write_enum_psif_wr_type(fd, data->op);
	xprintf(fd, ", .cq_desc_vlan_pri_union = ");
	write_union_psif_cq_desc_vlan_pri(fd, 0, &(data->cq_desc_vlan_pri_union));
	xprintf(fd, ", .srcuf = ");
	write_bits_u8(fd, 6, data->srcuf);
	xprintf(fd, ", .fence = ");
	write_bits_u8(fd, 1, data->fence);
	xprintf(fd, ", .completion = ");
	write_bits_u8(fd, 1, data->completion);
	xprintf(fd, ", .eps_tag = ");
	write_bits_u16(fd, 16, data->eps_tag);
	xprintf(fd, ", .destuf = ");
	write_bits_u8(fd, 6, data->destuf);
	xprintf(fd, ", .num_sgl = ");
	write_bits_u8(fd, 4, data->num_sgl);
	xprintf(fd, ", .l4_checksum_en = ");
	write_bits_u8(fd, 1, data->l4_checksum_en);
	xprintf(fd, ", .l3_checksum_en = ");
	write_bits_u8(fd, 1, data->l3_checksum_en);
	xprintf(fd, ", .dynamic_mtu_enable = ");
	write_bits_u8(fd, 1, data->dynamic_mtu_enable);
	xprintf(fd, ", .se = ");
	write_bits_u8(fd, 1, data->se);
	xprintf(fd, ", .checksum = ");
	write_bits_u32(fd, 32, data->checksum);
	xprintf(fd, "}");
} /* end write_..._psif_wr_common(psif_wr_common data) */

void write_struct_psif_wr_qp(XFILE *fd,
	int network_order,
	const struct psif_wr_qp *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_wr_qp *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .qkey = ");
	write_bits_u32(fd, 32, data->qkey);
	xprintf(fd, ", .remote_qp = ");
	write_bits_u32(fd, 24, data->remote_qp);
	xprintf(fd, "}");
} /* end write_..._psif_wr_qp(psif_wr_qp data) */

void write_struct_psif_wr_local(XFILE *fd,
	int network_order,
	const struct psif_wr_local *data)
{
	u64 swap[2];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 16);
		data = (struct psif_wr_local *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .addr = ");
	write_bits_u64(fd, 64, data->addr);
	xprintf(fd, ", .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .lkey = ");
	write_bits_u32(fd, 32, data->lkey);
	xprintf(fd, "}");
} /* end write_..._psif_wr_local(psif_wr_local data) */

void write_struct_psif_wr_addr(XFILE *fd,
	int network_order,
	const struct psif_wr_addr *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .ah_indx = ");
	write_bits_u32(fd, 24, data->ah_indx);
	xprintf(fd, "}");
} /* end write_..._psif_wr_addr(psif_wr_addr data) */

void write_struct_psif_wr_send_header_ud(XFILE *fd,
	int network_order,
	const struct psif_wr_send_header_ud *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_wr_send_header_ud *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .qp = ");
	write_struct_psif_wr_qp(fd, 0, &(data->qp));
	xprintf(fd, ", .local_addr = ");
	write_struct_psif_wr_local(fd, 0, &(data->local_addr));
	xprintf(fd, ", .mss = ");
	write_bits_u16(fd, 14, data->mss);
	xprintf(fd, ", .remote_addr = ");
	write_struct_psif_wr_addr(fd, 0, &(data->remote_addr));
	xprintf(fd, "}");
} /* end write_..._psif_wr_send_header_ud(psif_wr_send_header_ud data) */

void write_struct_psif_wr_send_header_uc_rc_xrc(XFILE *fd,
	int network_order,
	const struct psif_wr_send_header_uc_rc_xrc *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_wr_send_header_uc_rc_xrc *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .local_addr = ");
	write_struct_psif_wr_local(fd, 0, &(data->local_addr));
	xprintf(fd, ", .mss = ");
	write_bits_u16(fd, 14, data->mss);
	xprintf(fd, "}");
} /* end write_..._psif_wr_send_header_uc_rc_xrc(psif_wr_send_header_uc_rc_xrc data) */

void write_union_psif_wr_send_header(XFILE *fd,
	int network_order,
	const union psif_wr_send_header *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (union psif_wr_send_header *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .ud = ");
	write_struct_psif_wr_send_header_ud(fd, 0, &(data->ud));
	xprintf(fd, ", .uc_rc_xrc = ");
	write_struct_psif_wr_send_header_uc_rc_xrc(fd, 0, &(data->uc_rc_xrc));
	xprintf(fd, "}");
} /* end write_..._psif_wr_send_header(psif_wr_send_header data) */

void write_struct_psif_wr_remote(XFILE *fd,
	int network_order,
	const struct psif_wr_remote *data)
{
	u64 swap[2];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 16);
		data = (struct psif_wr_remote *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .addr = ");
	write_bits_u64(fd, 64, data->addr);
	xprintf(fd, ", .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .rkey = ");
	write_bits_u32(fd, 32, data->rkey);
	xprintf(fd, "}");
} /* end write_..._psif_wr_remote(psif_wr_remote data) */

void write_struct_psif_wr_rdma(XFILE *fd,
	int network_order,
	const struct psif_wr_rdma *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_wr_rdma *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .local_addr = ");
	write_struct_psif_wr_local(fd, 0, &(data->local_addr));
	xprintf(fd, ", .remote_addr = ");
	write_struct_psif_wr_remote(fd, 0, &(data->remote_addr));
	xprintf(fd, "}");
} /* end write_..._psif_wr_rdma(psif_wr_rdma data) */

void write_struct_psif_send_completion_id(XFILE *fd,
	int network_order,
	const struct psif_send_completion_id *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_send_completion_id *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .eps_tag = ");
	write_bits_u16(fd, 16, data->eps_tag);
	xprintf(fd, ", .sq_seq_num = ");
	write_bits_u16(fd, 16, data->sq_seq_num);
	xprintf(fd, ", .sequence_number = ");
	write_bits_u32(fd, 32, data->sequence_number);
	xprintf(fd, "}");
} /* end write_..._psif_send_completion_id(psif_send_completion_id data) */

void write_struct_psif_event_completion_id(XFILE *fd,
	int network_order,
	const struct psif_event_completion_id *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_event_completion_id *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .cq_id = ");
	write_bits_u32(fd, 24, data->cq_id);
	xprintf(fd, "}");
} /* end write_..._psif_event_completion_id(psif_event_completion_id data) */

void write_union_psif_completion_wc_id(XFILE *fd,
	int network_order,
	const union psif_completion_wc_id *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (union psif_completion_wc_id *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .rq_id = ");
	write_bits_u64(fd, 64, data->rq_id);
	xprintf(fd, ", .sq_id = ");
	write_struct_psif_send_completion_id(fd, 0, &(data->sq_id));
	xprintf(fd, ", .ecq_id = ");
	write_struct_psif_event_completion_id(fd, 0, &(data->ecq_id));
	xprintf(fd, "}");
} /* end write_..._psif_completion_wc_id(psif_completion_wc_id data) */

void write_union_psif_descriptor_union(XFILE *fd,
	int network_order,
	const union psif_descriptor_union *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .rq_id = ");
	write_bits_u32(fd, 24, data->rq_id);
	xprintf(fd, ", .xrq_id = ");
	write_bits_u32(fd, 24, data->xrq_id);
	xprintf(fd, ", .cq_id = ");
	write_bits_u32(fd, 24, data->cq_id);
	xprintf(fd, ", .target_qp = ");
	write_bits_u32(fd, 24, data->target_qp);
	xprintf(fd, "}");
} /* end write_..._psif_descriptor_union(psif_descriptor_union data) */

void write_struct_psif_wr_su(XFILE *fd,
	int network_order,
	const struct psif_wr_su *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_wr_su *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .wc_id = ");
	write_union_psif_completion_wc_id(fd, 0, &(data->wc_id));
	xprintf(fd, ", .addr = ");
	write_bits_u64(fd, 64, data->addr);
	xprintf(fd, ", .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .key = ");
	write_bits_u32(fd, 32, data->key);
	xprintf(fd, ", .u2 = ");
	write_union_psif_descriptor_union(fd, 0, &(data->u2));
	xprintf(fd, ", .completion_status = ");
	write_enum_psif_wc_status(fd, data->completion_status);
	xprintf(fd, ", .completion_opcode = ");
	write_enum_psif_wc_opcode(fd, data->completion_opcode);
	xprintf(fd, ", .srq_lim = ");
	write_bits_u16(fd, 14, data->srq_lim);
	xprintf(fd, "}");
} /* end write_..._psif_wr_su(psif_wr_su data) */

void write_union_psif_wr_details(XFILE *fd,
	int network_order,
	const union psif_wr_details *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (union psif_wr_details *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .send = ");
	write_union_psif_wr_send_header(fd, 0, &(data->send));
	xprintf(fd, ", .rdma = ");
	write_struct_psif_wr_rdma(fd, 0, &(data->rdma));
	xprintf(fd, ", .atomic = ");
	write_struct_psif_wr_rdma(fd, 0, &(data->atomic));
	xprintf(fd, ", .su = ");
	write_struct_psif_wr_su(fd, 0, &(data->su));
	xprintf(fd, "}");
} /* end write_..._psif_wr_details(psif_wr_details data) */

void write_struct_psif_wr_xrc(XFILE *fd,
	int network_order,
	const struct psif_wr_xrc *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .xrqd_id = ");
	write_bits_u32(fd, 24, data->xrqd_id);
	xprintf(fd, "}");
} /* end write_..._psif_wr_xrc(psif_wr_xrc data) */

void write_struct_psif_wr(XFILE *fd,
	int network_order,
	const struct psif_wr *data)
{
	enum psif_wr_type op;
	enum psif_use_ah  ud;
	struct psif_wr    swap;

	if (network_order) {
		copy_convert_to_sw(&swap, (volatile void *)data, 64);
		data = &swap;
	}

	op = data->op;
	ud = data->ud_pkt;

	/* assertion: offsetof(struct psif_wr, imm) == sizeof(struct psif_wr_common) */
	xprintf(fd, "{");
	write_struct_psif_wr_common(fd, 0, (struct psif_wr_common *)data);
	if ((op == PSIF_WR_SEND_IMM) || (op == PSIF_WR_RDMA_WR_IMM)) {
		xprintf(fd, "  .imm = ");
		write_bits_u32(fd, 32, data->imm);
	}

	xprintf(fd, "  .details = ");
	/*   write_union_psif_wr_details(fd, 0, &(data->details)); */
	xprintf(fd, "{");
	/* write_union_psif_wr_send_header(fd, 0, &(data->send)); */

	switch (op) {
	case PSIF_WR_SEND:
	case PSIF_WR_SEND_IMM:
	case PSIF_WR_SPECIAL_QP_SEND:
	case PSIF_WR_QP0_SEND_DR_XMIT:
	case PSIF_WR_QP0_SEND_DR_LOOPBACK:
	case PSIF_WR_EPS_SPECIAL_QP_SEND:
	case PSIF_WR_EPS_QP0_SEND_DR_XMIT:
	case PSIF_WR_EPS_QP0_SEND_DR_LOOPBACK:
		xprintf(fd, " send = ");
		xprintf(fd, "{");
		if (ud) {
		xprintf(fd, " .ud = ");
		write_struct_psif_wr_send_header_ud(fd, 0, &(data->details.send.ud));
		} else {
		xprintf(fd, "  .uc_rc_xrc = ");
		write_struct_psif_wr_send_header_uc_rc_xrc(fd, 0, &(data->details.send.uc_rc_xrc));
		}
		xprintf(fd, "}");
		break;

	case PSIF_WR_RDMA_WR:
	case PSIF_WR_RDMA_WR_IMM:
	case PSIF_WR_RDMA_RD:
		xprintf(fd, "  .rdma = ");
		write_struct_psif_wr_rdma(fd, 0, &(data->details.rdma));
		break;

	case PSIF_WR_CMP_SWAP:
	case PSIF_WR_FETCH_ADD:
	case PSIF_WR_MASK_CMP_SWAP:
	case PSIF_WR_MASK_FETCH_ADD:
		xprintf(fd, "  .atomic = ");
		write_struct_psif_wr_rdma(fd, 0, &(data->details.atomic));
		break;

	case PSIF_WR_INVALIDATE_RKEY:
	case PSIF_WR_INVALIDATE_LKEY:
	case PSIF_WR_INVALIDATE_BOTH_KEYS:
	case PSIF_WR_INVALIDATE_TLB:
	case PSIF_WR_RESIZE_CQ:
	case PSIF_WR_SET_SRQ_LIM:
	case PSIF_WR_SET_XRCSRQ_LIM:
	case PSIF_WR_REQ_CMPL_NOTIFY:
	case PSIF_WR_CMPL_NOTIFY_RCVD:
	case PSIF_WR_REARM_CMPL_EVENT:
	case PSIF_WR_INVALIDATE_RQ:
	case PSIF_WR_INVALIDATE_CQ:
	case PSIF_WR_INVALIDATE_XRCSRQ:
	case PSIF_WR_INVALIDATE_SGL_CACHE:
	case PSIF_WR_GENERATE_COMPLETION:
		xprintf(fd, "  .su = ");
		write_struct_psif_wr_su(fd, 0, &(data->details.su));
		break;

	case PSIF_WR_LSO:
		break;
	}
	xprintf(fd, "}");

	xprintf(fd, "  .xrc_hdr = ");
	write_struct_psif_wr_xrc(fd, 0, &(data->xrc_hdr));
	xprintf(fd, "}");
		}

void write_struct_psif_wr_expand(XFILE *fd,
	int network_order,
	const struct psif_wr *data)
{
	u64 swap[8];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 64);
		data = (struct psif_wr *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .sq_seq = ");
	write_bits_u16(fd, 16, data->sq_seq);
	xprintf(fd, ", .collect_length = ");
	write_bits_u16(fd, 9, data->collect_length);
	xprintf(fd, ", .tsu_qosl = ");
	write_enum_psif_tsu_qos(fd, data->tsu_qosl);
	xprintf(fd, ", .ud_pkt = ");
	write_enum_psif_use_ah(fd, data->ud_pkt);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .tsu_sl = ");
	write_bits_u8(fd, 4, data->tsu_sl);
	xprintf(fd, ", .local_qp = ");
	write_bits_u32(fd, 24, data->local_qp);
	xprintf(fd, ", .op = ");
	write_enum_psif_wr_type(fd, data->op);
	xprintf(fd, ", .cq_desc_vlan_pri_union = ");
	write_union_psif_cq_desc_vlan_pri(fd, 0, &(data->cq_desc_vlan_pri_union));
	xprintf(fd, ", .srcuf = ");
	write_bits_u8(fd, 6, data->srcuf);
	xprintf(fd, ", .fence = ");
	write_bits_u8(fd, 1, data->fence);
	xprintf(fd, ", .completion = ");
	write_bits_u8(fd, 1, data->completion);
	xprintf(fd, ", .eps_tag = ");
	write_bits_u16(fd, 16, data->eps_tag);
	xprintf(fd, ", .destuf = ");
	write_bits_u8(fd, 6, data->destuf);
	xprintf(fd, ", .num_sgl = ");
	write_bits_u8(fd, 4, data->num_sgl);
	xprintf(fd, ", .l4_checksum_en = ");
	write_bits_u8(fd, 1, data->l4_checksum_en);
	xprintf(fd, ", .l3_checksum_en = ");
	write_bits_u8(fd, 1, data->l3_checksum_en);
	xprintf(fd, ", .dynamic_mtu_enable = ");
	write_bits_u8(fd, 1, data->dynamic_mtu_enable);
	xprintf(fd, ", .se = ");
	write_bits_u8(fd, 1, data->se);
	xprintf(fd, ", .imm = ");
	write_bits_u32(fd, 32, data->imm);
	xprintf(fd, ", .checksum = ");
	write_bits_u32(fd, 32, data->checksum);
	xprintf(fd, ", .details = ");
	write_union_psif_wr_details(fd, 0, &(data->details));
	xprintf(fd, ", .xrc_hdr = ");
	write_struct_psif_wr_xrc(fd, 0, &(data->xrc_hdr));
	xprintf(fd, "}");
} /* end write_..._psif_wr(psif_wr data) */

void write_struct_psif_sq_sw(XFILE *fd,
	int network_order,
	const struct psif_sq_sw *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_sq_sw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .tail_indx = ");
	write_bits_u16(fd, 16, data->tail_indx);
	xprintf(fd, "}");
} /* end write_..._psif_sq_sw(psif_sq_sw data) */

void write_struct_psif_next(XFILE *fd,
	int network_order,
	const struct psif_next *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .next_null = ");
	write_bits_u8(fd, 8, data->next_null);
	xprintf(fd, ", .next_qp_num = ");
	write_bits_u32(fd, 24, data->next_qp_num);
	xprintf(fd, "}");
} /* end write_..._psif_next(psif_next data) */

void write_struct_psif_sq_hw(XFILE *fd,
	int network_order,
	const struct psif_sq_hw *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_sq_hw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .u_1 = ");
	write_bits_u16(fd, 16, data->u_1);
	xprintf(fd, ", .last_seq = ");
	write_bits_u16(fd, 16, data->last_seq);
	xprintf(fd, ", .sq_next = ");
	write_struct_psif_next(fd, 0, &(data->sq_next));
	xprintf(fd, ", .sq_max_inline = ");
	write_bits_u16(fd, 9, data->sq_max_inline);
	xprintf(fd, ", .size_log2 = ");
	write_bits_u8(fd, 4, data->size_log2);
	xprintf(fd, ", .sq_max_sge = ");
	write_bits_u8(fd, 5, data->sq_max_sge);
	xprintf(fd, ", .extent_log2 = ");
	write_bits_u8(fd, 5, data->extent_log2);
	xprintf(fd, ", .qos = ");
	write_bits_u8(fd, 1, data->qos);
	xprintf(fd, ", .sq_timestamp_valid = ");
	write_bits_u8(fd, 1, data->sq_timestamp_valid);
	xprintf(fd, ", .sq_done = ");
	write_bits_u8(fd, 2, data->sq_done);
	xprintf(fd, ", .destroyed = ");
	write_bits_u8(fd, 1, data->destroyed);
	xprintf(fd, ", .u_2 = ");
	write_bits_u32(fd, 32, data->u_2);
	xprintf(fd, ", .base_addr = ");
	write_bits_u64(fd, 64, data->base_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, "}");
} /* end write_..._psif_sq_hw(psif_sq_hw data) */

void write_struct_psif_sq_entry(XFILE *fd,
	int network_order,
	const struct psif_sq_entry *data)
{
	u64 swap[40];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 320);
		data = (struct psif_sq_entry *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .wr = ");
	write_struct_psif_wr(fd, 0, &(data->wr));
	xprintf(fd, ", .payload = ");
	{ unsigned int i; for (i = 0; i < 32; i++) {
		write_bits_u64(fd, 64, data->payload[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_sq_entry(psif_sq_entry data) */

void write_struct_psif_rq_scatter(XFILE *fd,
	int network_order,
	const struct psif_rq_scatter *data)
{
	u64 swap[2];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 16);
		data = (struct psif_rq_scatter *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .base_addr = ");
	write_bits_u64(fd, 64, data->base_addr);
	xprintf(fd, ", .lkey = ");
	write_bits_u32(fd, 32, data->lkey);
	xprintf(fd, ", .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, "}");
} /* end write_..._psif_rq_scatter(psif_rq_scatter data) */

void write_struct_psif_rq_sw(XFILE *fd,
	int network_order,
	const struct psif_rq_sw *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_rq_sw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .tail_indx = ");
	write_bits_u16(fd, 14, data->tail_indx);
	xprintf(fd, "}");
} /* end write_..._psif_rq_sw(psif_rq_sw data) */

void write_struct_psif_rq_hw(XFILE *fd,
	int network_order,
	const struct psif_rq_hw *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_rq_hw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .srq_lim = ");
	write_bits_u16(fd, 14, data->srq_lim);
	xprintf(fd, ", .head_indx = ");
	write_bits_u16(fd, 14, data->head_indx);
	xprintf(fd, ", .extent_log2 = ");
	write_bits_u8(fd, 4, data->extent_log2);
	xprintf(fd, ", .pd = ");
	write_bits_u32(fd, 24, data->pd);
	xprintf(fd, ", .scatter = ");
	write_bits_u8(fd, 4, data->scatter);
	xprintf(fd, ", .srq_err = ");
	write_bits_u8(fd, 1, data->srq_err);
	xprintf(fd, ", .srq = ");
	write_bits_u8(fd, 1, data->srq);
	xprintf(fd, ", .sticky = ");
	write_bits_u8(fd, 1, data->sticky);
	xprintf(fd, ", .base_addr = ");
	write_bits_u64(fd, 64, data->base_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .valid = ");
	write_bits_u8(fd, 1, data->valid);
	xprintf(fd, ", .prefetch_threshold_log2 = ");
	write_bits_u8(fd, 4, data->prefetch_threshold_log2);
	xprintf(fd, ", .size_log2 = ");
	write_bits_u8(fd, 4, data->size_log2);
	xprintf(fd, "}");
} /* end write_..._psif_rq_hw(psif_rq_hw data) */

void write_struct_psif_rq_entry(XFILE *fd,
	int network_order,
	const struct psif_rq_entry *data)
{
	u64 swap[33];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 264);
		data = (struct psif_rq_entry *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .rqe_id = ");
	write_bits_u64(fd, 64, data->rqe_id);
	xprintf(fd, ", .scatter = ");
	{ unsigned int i; for (i = 0; i < 16; i++) {
		write_struct_psif_rq_scatter(fd, 0, &(data->scatter[i]));
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_rq_entry(psif_rq_entry data) */

void write_struct_psif_qp_core(XFILE *fd,
	int network_order,
	const struct psif_qp_core *data)
{
	u64 swap[16];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 128);
		data = (struct psif_qp_core *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .retry_tag_committed = ");
	write_bits_u8(fd, 3, data->retry_tag_committed);
	xprintf(fd, ", .retry_tag_err = ");
	write_bits_u8(fd, 3, data->retry_tag_err);
	xprintf(fd, ", .req_access_error = ");
	write_bits_u8(fd, 1, data->req_access_error);
	xprintf(fd, ", .resp_access_error = ");
	write_bits_u8(fd, 1, data->resp_access_error);
	xprintf(fd, ", .xrc_domain = ");
	write_bits_u32(fd, 24, data->xrc_domain);
	xprintf(fd, ", .error_retry_init = ");
	write_bits_u8(fd, 3, data->error_retry_init);
	xprintf(fd, ", .error_retry_count = ");
	write_bits_u8(fd, 3, data->error_retry_count);
	xprintf(fd, ", .cq_in_err = ");
	write_bits_u8(fd, 1, data->cq_in_err);
	xprintf(fd, ", .spin_hit = ");
	write_bits_u8(fd, 1, data->spin_hit);
	xprintf(fd, ", .sq_clog2_extent = ");
	write_bits_u8(fd, 5, data->sq_clog2_extent);
	xprintf(fd, ", .sq_clog2_size = ");
	write_bits_u8(fd, 4, data->sq_clog2_size);
	xprintf(fd, ", .current_outstanding = ");
	write_bits_u8(fd, 5, data->current_outstanding);
	xprintf(fd, ", .current_retired = ");
	write_bits_u8(fd, 5, data->current_retired);
	xprintf(fd, ", .is_multicast = ");
	write_bits_u8(fd, 1, data->is_multicast);
	xprintf(fd, ", .dscr_rq_in_progress = ");
	write_bits_u8(fd, 1, data->dscr_rq_in_progress);
	xprintf(fd, ", .first_at_floor_seen = ");
	write_bits_u8(fd, 1, data->first_at_floor_seen);
	xprintf(fd, ", .rq_is_srq = ");
	write_bits_u8(fd, 1, data->rq_is_srq);
	xprintf(fd, ", .do_not_evict = ");
	write_bits_u8(fd, 1, data->do_not_evict);
	xprintf(fd, ", .min_rnr_nak_time = ");
	write_bits_u8(fd, 5, data->min_rnr_nak_time);
	xprintf(fd, ", .state = ");
	write_enum_psif_qp_state(fd, data->state);
	xprintf(fd, ", .remote_qp = ");
	write_bits_u32(fd, 24, data->remote_qp);
	xprintf(fd, ", .rcv_rkey = ");
	write_bits_u32(fd, 32, data->rcv_rkey);
	xprintf(fd, ", .rcv_bytes = ");
	write_bits_u32(fd, 32, data->rcv_bytes);
	xprintf(fd, ", .retry_sq_seq = ");
	write_bits_u16(fd, 16, data->retry_sq_seq);
	xprintf(fd, ", .sq_seq = ");
	write_bits_u16(fd, 16, data->sq_seq);
	xprintf(fd, ", .magic = ");
	write_bits_u32(fd, 32, data->magic);
	xprintf(fd, ", .cq_seq = ");
	write_bits_u32(fd, 32, data->cq_seq);
	xprintf(fd, ", .qkey = ");
	write_bits_u32(fd, 32, data->qkey);
	xprintf(fd, ", .ib_retry_outstanding = ");
	write_bits_u8(fd, 1, data->ib_retry_outstanding);
	xprintf(fd, ", .fence_retry_outstanding = ");
	write_bits_u8(fd, 1, data->fence_retry_outstanding);
	xprintf(fd, ", .flush_started = ");
	write_bits_u8(fd, 1, data->flush_started);
	xprintf(fd, ", .request_handled = ");
	write_bits_u8(fd, 1, data->request_handled);
	xprintf(fd, ", .outstanding_error = ");
	write_enum_psif_cmpl_outstanding_error(fd, data->outstanding_error);
	xprintf(fd, ", .last_acked_psn = ");
	write_bits_u32(fd, 24, data->last_acked_psn);
	xprintf(fd, ", .scatter_offs = ");
	write_bits_u32(fd, 32, data->scatter_offs);
	xprintf(fd, ", .scatter_indx = ");
	write_bits_u8(fd, 5, data->scatter_indx);
	xprintf(fd, ", .expected_opcode = ");
	write_enum_psif_expected_op(fd, data->expected_opcode);
	xprintf(fd, ", .psn_nak = ");
	write_bits_u8(fd, 1, data->psn_nak);
	xprintf(fd, ", .expected_psn = ");
	write_bits_u32(fd, 24, data->expected_psn);
	xprintf(fd, ", .timeout_time = ");
	write_bits_u64(fd, 48, data->timeout_time);
	xprintf(fd, ", .nak_sent = ");
	write_bits_u8(fd, 1, data->nak_sent);
	xprintf(fd, ", .qosl = ");
	write_enum_psif_tsu_qos(fd, data->qosl);
	xprintf(fd, ", .mstate = ");
	write_enum_psif_migration(fd, data->mstate);
	xprintf(fd, ", .eoib_enable = ");
	write_bits_u8(fd, 1, data->eoib_enable);
	xprintf(fd, ", .ipoib_enable = ");
	write_bits_u8(fd, 1, data->ipoib_enable);
	xprintf(fd, ", .hdr_split_enable = ");
	write_bits_u8(fd, 1, data->hdr_split_enable);
	xprintf(fd, ", .rcv_dynamic_mtu_enable = ");
	write_bits_u8(fd, 1, data->rcv_dynamic_mtu_enable);
	xprintf(fd, ", .proxy_qp_enable = ");
	write_bits_u8(fd, 1, data->proxy_qp_enable);
	xprintf(fd, ", .rss_enable = ");
	write_bits_u8(fd, 1, data->rss_enable);
	xprintf(fd, ", .masked_atomic_enable = ");
	write_bits_u8(fd, 1, data->masked_atomic_enable);
	xprintf(fd, ", .atomic_enable = ");
	write_bits_u8(fd, 1, data->atomic_enable);
	xprintf(fd, ", .rdma_wr_enable = ");
	write_bits_u8(fd, 1, data->rdma_wr_enable);
	xprintf(fd, ", .rdma_rd_enable = ");
	write_bits_u8(fd, 1, data->rdma_rd_enable);
	xprintf(fd, ", .xmit_psn = ");
	write_bits_u32(fd, 24, data->xmit_psn);
	xprintf(fd, ", .retry_xmit_psn = ");
	write_bits_u32(fd, 24, data->retry_xmit_psn);
	xprintf(fd, ", .resp_scatter_indx = ");
	write_bits_u8(fd, 5, data->resp_scatter_indx);
	xprintf(fd, ", .rc_in_error = ");
	write_bits_u8(fd, 1, data->rc_in_error);
	xprintf(fd, ", .timer_running = ");
	write_bits_u8(fd, 1, data->timer_running);
	xprintf(fd, ", .tsl = ");
	write_bits_u8(fd, 4, data->tsl);
	xprintf(fd, ", .max_outstanding = ");
	write_bits_u8(fd, 5, data->max_outstanding);
	xprintf(fd, ", .dmalen = ");
	write_bits_u32(fd, 32, data->dmalen);
	xprintf(fd, ", .rnr_retry_init = ");
	write_bits_u8(fd, 3, data->rnr_retry_init);
	xprintf(fd, ", .rnr_retry_count = ");
	write_bits_u8(fd, 3, data->rnr_retry_count);
	xprintf(fd, ", .no_ordering = ");
	write_bits_u8(fd, 1, data->no_ordering);
	xprintf(fd, ", .no_checksum = ");
	write_bits_u8(fd, 1, data->no_checksum);
	xprintf(fd, ", .rq_indx = ");
	write_bits_u32(fd, 24, data->rq_indx);
	xprintf(fd, ", .transport_type = ");
	write_enum_psif_qp_trans(fd, data->transport_type);
	xprintf(fd, ", .rcv_cq_indx = ");
	write_bits_u32(fd, 24, data->rcv_cq_indx);
	xprintf(fd, ", .bytes_received = ");
	write_bits_u32(fd, 32, data->bytes_received);
	xprintf(fd, ", .eoib_type = ");
	write_enum_psif_eoib_type(fd, data->eoib_type);
	xprintf(fd, ", .exp_backoff_enable = ");
	write_bits_u8(fd, 1, data->exp_backoff_enable);
	xprintf(fd, ", .not_so_privileged = ");
	write_bits_u8(fd, 1, data->not_so_privileged);
	xprintf(fd, ", .send_dynamic_mtu_enable = ");
	write_bits_u8(fd, 1, data->send_dynamic_mtu_enable);
	xprintf(fd, ", .ipoib = ");
	write_bits_u8(fd, 1, data->ipoib);
	xprintf(fd, ", .eoib = ");
	write_bits_u8(fd, 1, data->eoib);
	xprintf(fd, ", .wait_for_psn = ");
	write_bits_u8(fd, 1, data->wait_for_psn);
	xprintf(fd, ", .resp_sched_count_done = ");
	write_bits_u32(fd, 24, data->resp_sched_count_done);
	xprintf(fd, ", .resp_sched_count_sched = ");
	write_bits_u32(fd, 24, data->resp_sched_count_sched);
	xprintf(fd, ", .resp_sched_sched_ptr = ");
	write_bits_u8(fd, 5, data->resp_sched_sched_ptr);
	xprintf(fd, ", .resp_sched_mode = ");
	write_bits_u8(fd, 1, data->resp_sched_mode);
	xprintf(fd, ", .swapped = ");
	write_enum_psif_bool(fd, data->swapped);
	xprintf(fd, ", .retry_needed = ");
	write_bits_u8(fd, 1, data->retry_needed);
	xprintf(fd, ", .last_received_outstanding_msn = ");
	write_bits_u16(fd, 16, data->last_received_outstanding_msn);
	xprintf(fd, ", .host_sent_nak = ");
	write_bits_u8(fd, 1, data->host_sent_nak);
	xprintf(fd, ", .in_safe_mode = ");
	write_bits_u8(fd, 1, data->in_safe_mode);
	xprintf(fd, ", .atomic_error = ");
	write_bits_u8(fd, 1, data->atomic_error);
	xprintf(fd, ", .apm_failed_event_sent = ");
	write_bits_u8(fd, 1, data->apm_failed_event_sent);
	xprintf(fd, ", .apm_success_event_sent = ");
	write_bits_u8(fd, 1, data->apm_success_event_sent);
	xprintf(fd, ", .apm_failed_event_needed = ");
	write_bits_u8(fd, 1, data->apm_failed_event_needed);
	xprintf(fd, ", .apm_success_event_needed = ");
	write_bits_u8(fd, 1, data->apm_success_event_needed);
	xprintf(fd, ", .req_addr = ");
	write_bits_u64(fd, 64, data->req_addr);
	xprintf(fd, ", .orig_atomic_wr_ptr = ");
	write_bits_u8(fd, 4, data->orig_atomic_wr_ptr);
	xprintf(fd, ", .path_mtu = ");
	write_enum_psif_path_mtu(fd, data->path_mtu);
	xprintf(fd, ", .comm_established = ");
	write_enum_psif_comm_live(fd, data->comm_established);
	xprintf(fd, ", .committed_received_psn = ");
	write_bits_u32(fd, 24, data->committed_received_psn);
	xprintf(fd, ", .resp_scatter_offs = ");
	write_bits_u32(fd, 32, data->resp_scatter_offs);
	xprintf(fd, ", .msn = ");
	write_bits_u32(fd, 24, data->msn);
	xprintf(fd, ", .send_cq_indx = ");
	write_bits_u32(fd, 24, data->send_cq_indx);
	xprintf(fd, ", .last_committed_msn = ");
	write_bits_u16(fd, 16, data->last_committed_msn);
	xprintf(fd, ", .srq_pd = ");
	write_bits_u32(fd, 24, data->srq_pd);
	xprintf(fd, ", .pd = ");
	write_bits_u32(fd, 24, data->pd);
	xprintf(fd, ", .eps_tag = ");
	write_bits_u16(fd, 16, data->eps_tag);
	xprintf(fd, "}");
} /* end write_..._psif_qp_core(psif_qp_core data) */

void write_struct_psif_qp_path(XFILE *fd,
	int network_order,
	const struct psif_qp_path *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_qp_path *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .remote_gid_0 = ");
	write_bits_u64(fd, 64, data->remote_gid_0);
	xprintf(fd, ", .remote_gid_1 = ");
	write_bits_u64(fd, 64, data->remote_gid_1);
	xprintf(fd, ", .remote_lid = ");
	write_bits_u16(fd, 16, data->remote_lid);
	xprintf(fd, ", .gid_indx = ");
	write_bits_u8(fd, 1, data->gid_indx);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .loopback = ");
	write_enum_psif_loopback(fd, data->loopback);
	xprintf(fd, ", .use_grh = ");
	write_enum_psif_use_grh(fd, data->use_grh);
	xprintf(fd, ", .sl = ");
	write_bits_u8(fd, 4, data->sl);
	xprintf(fd, ", .hoplmt = ");
	write_bits_u8(fd, 8, data->hoplmt);
	xprintf(fd, ", .tclass = ");
	write_bits_u8(fd, 8, data->tclass);
	xprintf(fd, ", .flowlabel = ");
	write_bits_u32(fd, 20, data->flowlabel);
	xprintf(fd, ", .path_invalid = ");
	write_bits_u8(fd, 1, data->path_invalid);
	xprintf(fd, ", .local_ack_timeout = ");
	write_bits_u8(fd, 5, data->local_ack_timeout);
	xprintf(fd, ", .ipd = ");
	write_bits_u8(fd, 8, data->ipd);
	xprintf(fd, ", .local_lid_path = ");
	write_bits_u8(fd, 7, data->local_lid_path);
	xprintf(fd, ", .pkey_indx = ");
	write_bits_u16(fd, 9, data->pkey_indx);
	xprintf(fd, "}");
} /* end write_..._psif_qp_path(psif_qp_path data) */

void write_struct_psif_query_qp(XFILE *fd,
	int network_order,
	const struct psif_query_qp *data)
{
	u64 swap[24];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 192);
		data = (struct psif_query_qp *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .qp = ");
	write_struct_psif_qp_core(fd, 0, &(data->qp));
	xprintf(fd, ", .primary_path = ");
	write_struct_psif_qp_path(fd, 0, &(data->primary_path));
	xprintf(fd, ", .alternate_path = ");
	write_struct_psif_qp_path(fd, 0, &(data->alternate_path));
	xprintf(fd, "}");
} /* end write_..._psif_query_qp(psif_query_qp data) */

void write_struct_psif_qp(XFILE *fd,
	int network_order,
	const struct psif_qp *data)
{
	u64 swap[24];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 192);
		data = (struct psif_qp *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .state = ");
	write_struct_psif_qp_core(fd, 0, &(data->state));
	xprintf(fd, ", .path_a = ");
	write_struct_psif_qp_path(fd, 0, &(data->path_a));
	xprintf(fd, ", .path_b = ");
	write_struct_psif_qp_path(fd, 0, &(data->path_b));
	xprintf(fd, "}");
} /* end write_..._psif_qp(psif_qp data) */

void write_struct_psif_modify_qp(XFILE *fd,
	int network_order,
	const struct psif_modify_qp *data)
{
	u64 swap[10];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 80);
		data = (struct psif_modify_qp *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .max_outstanding = ");
	write_bits_u8(fd, 5, data->max_outstanding);
	xprintf(fd, ", .state = ");
	write_enum_psif_qp_state(fd, data->state);
	xprintf(fd, ", .min_rnr_nak_time = ");
	write_bits_u8(fd, 5, data->min_rnr_nak_time);
	xprintf(fd, ", .error_retry_count = ");
	write_bits_u8(fd, 3, data->error_retry_count);
	xprintf(fd, ", .eoib_enable = ");
	write_bits_u8(fd, 1, data->eoib_enable);
	xprintf(fd, ", .ipoib_enable = ");
	write_bits_u8(fd, 1, data->ipoib_enable);
	xprintf(fd, ", .hdr_split_enable = ");
	write_bits_u8(fd, 1, data->hdr_split_enable);
	xprintf(fd, ", .rcv_dynamic_mtu_enable = ");
	write_bits_u8(fd, 1, data->rcv_dynamic_mtu_enable);
	xprintf(fd, ", .proxy_qp_enable = ");
	write_bits_u8(fd, 1, data->proxy_qp_enable);
	xprintf(fd, ", .rss_enable = ");
	write_bits_u8(fd, 1, data->rss_enable);
	xprintf(fd, ", .masked_atomic_enable = ");
	write_bits_u8(fd, 1, data->masked_atomic_enable);
	xprintf(fd, ", .atomic_enable = ");
	write_bits_u8(fd, 1, data->atomic_enable);
	xprintf(fd, ", .rdma_wr_enable = ");
	write_bits_u8(fd, 1, data->rdma_wr_enable);
	xprintf(fd, ", .rdma_rd_enable = ");
	write_bits_u8(fd, 1, data->rdma_rd_enable);
	xprintf(fd, ", .rnr_retry_count = ");
	write_bits_u8(fd, 3, data->rnr_retry_count);
	xprintf(fd, ", .req_access_error = ");
	write_bits_u8(fd, 1, data->req_access_error);
	xprintf(fd, ", .rx_qkey = ");
	write_bits_u32(fd, 32, data->rx_qkey);
	xprintf(fd, ", .xmit_psn = ");
	write_bits_u32(fd, 24, data->xmit_psn);
	xprintf(fd, ", .mstate = ");
	write_enum_psif_migration(fd, data->mstate);
	xprintf(fd, ", .path_mtu = ");
	write_enum_psif_path_mtu(fd, data->path_mtu);
	xprintf(fd, ", .expected_psn = ");
	write_bits_u32(fd, 24, data->expected_psn);
	xprintf(fd, ", .primary_path = ");
	write_struct_psif_qp_path(fd, 0, &(data->primary_path));
	xprintf(fd, ", .alternate_path = ");
	write_struct_psif_qp_path(fd, 0, &(data->alternate_path));
	xprintf(fd, "}");
} /* end write_..._psif_modify_qp(psif_modify_qp data) */

void write_struct_psif_key(XFILE *fd,
	int network_order,
	const struct psif_key *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_key *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .zero_based_addr_en = ");
	write_bits_u8(fd, 1, data->zero_based_addr_en);
	xprintf(fd, ", .conditional_wr = ");
	write_bits_u8(fd, 1, data->conditional_wr);
	xprintf(fd, ", .local_access_atomic = ");
	write_bits_u8(fd, 1, data->local_access_atomic);
	xprintf(fd, ", .local_access_wr = ");
	write_bits_u8(fd, 1, data->local_access_wr);
	xprintf(fd, ", .local_access_rd = ");
	write_bits_u8(fd, 1, data->local_access_rd);
	xprintf(fd, ", .remote_access_atomic = ");
	write_bits_u8(fd, 1, data->remote_access_atomic);
	xprintf(fd, ", .remote_access_wr = ");
	write_bits_u8(fd, 1, data->remote_access_wr);
	xprintf(fd, ", .remote_access_rd = ");
	write_bits_u8(fd, 1, data->remote_access_rd);
	xprintf(fd, ", .pd = ");
	write_bits_u32(fd, 24, data->pd);
	xprintf(fd, ", .lkey_state = ");
	write_enum_psif_dma_vt_key_states(fd, data->lkey_state);
	xprintf(fd, ", .rkey_state = ");
	write_enum_psif_dma_vt_key_states(fd, data->rkey_state);
	xprintf(fd, ", .length = ");
	write_bits_u64(fd, 64, data->length);
	xprintf(fd, ", .mmu_context = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_context));
	xprintf(fd, ", .base_addr = ");
	write_bits_u64(fd, 64, data->base_addr);
	xprintf(fd, "}");
} /* end write_..._psif_key(psif_key data) */

void write_struct_psif_eq_entry(XFILE *fd,
	int network_order,
	const struct psif_eq_entry *data)
{
	u64 swap[8];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 64);
		data = (struct psif_eq_entry *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .eps_core_id = ");
	write_enum_psif_eps_core_id(fd, data->eps_core_id);
	xprintf(fd, ", .vendor_fields = ");
	write_bits_u8(fd, 3, data->vendor_fields);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .cqd_id = ");
	write_bits_u32(fd, 24, data->cqd_id);
	xprintf(fd, ", .vendor_error = ");
	write_enum_psif_tsu_error_types(fd, data->vendor_error);
	xprintf(fd, ", .port_flags = ");
	write_bits_u8(fd, 4, data->port_flags);
	xprintf(fd, ", .event_status_eps_a = ");
	write_bits_u8(fd, 1, data->event_status_eps_a);
	xprintf(fd, ", .event_status_eps_c = ");
	write_bits_u8(fd, 1, data->event_status_eps_c);
	xprintf(fd, ", .event_status_cmpl_notify = ");
	write_bits_u8(fd, 1, data->event_status_cmpl_notify);
	xprintf(fd, ", .event_status_port_error = ");
	write_bits_u8(fd, 1, data->event_status_port_error);
	xprintf(fd, ", .event_status_local_catastrophic_error = ");
	write_bits_u8(fd, 1, data->event_status_local_catastrophic_error);
	xprintf(fd, ", .event_status_port_changed = ");
	write_bits_u8(fd, 1, data->event_status_port_changed);
	xprintf(fd, ", .event_status_client_registration = ");
	write_bits_u8(fd, 1, data->event_status_client_registration);
	xprintf(fd, ", .event_status_port_active = ");
	write_bits_u8(fd, 1, data->event_status_port_active);
	xprintf(fd, ", .event_status_local_work_queue_catastrophic_error = ");
	write_bits_u8(fd, 1, data->event_status_local_work_queue_catastrophic_error);
	xprintf(fd, ", .event_status_srq_catastrophic_error = ");
	write_bits_u8(fd, 1, data->event_status_srq_catastrophic_error);
	xprintf(fd, ", .event_status_invalid_xrceth = ");
	write_bits_u8(fd, 1, data->event_status_invalid_xrceth);
	xprintf(fd, ", .event_status_xrc_domain_violation = ");
	write_bits_u8(fd, 1, data->event_status_xrc_domain_violation);
	xprintf(fd, ", .event_status_path_migration_request_error = ");
	write_bits_u8(fd, 1, data->event_status_path_migration_request_error);
	xprintf(fd, ", .event_status_local_access_violation_wq_error = ");
	write_bits_u8(fd, 1, data->event_status_local_access_violation_wq_error);
	xprintf(fd, ", .event_status_invalid_request_local_wq_error = ");
	write_bits_u8(fd, 1, data->event_status_invalid_request_local_wq_error);
	xprintf(fd, ", .event_status_cq_error = ");
	write_bits_u8(fd, 1, data->event_status_cq_error);
	xprintf(fd, ", .event_status_last_wqe_reached = ");
	write_bits_u8(fd, 1, data->event_status_last_wqe_reached);
	xprintf(fd, ", .event_status_srq_limit_reached = ");
	write_bits_u8(fd, 1, data->event_status_srq_limit_reached);
	xprintf(fd, ", .event_status_communication_established = ");
	write_bits_u8(fd, 1, data->event_status_communication_established);
	xprintf(fd, ", .event_status_path_migrated = ");
	write_bits_u8(fd, 1, data->event_status_path_migrated);
	xprintf(fd, ", .lid = ");
	write_bits_u16(fd, 16, data->lid);
	xprintf(fd, ", .qp = ");
	write_bits_u32(fd, 24, data->qp);
	xprintf(fd, ", .rqd_id = ");
	write_bits_u32(fd, 24, data->rqd_id);
	xprintf(fd, ", .extension_type = ");
	write_enum_psif_event(fd, data->extension_type);
	xprintf(fd, ", .cq_sequence_number = ");
	write_bits_u32(fd, 32, data->cq_sequence_number);
	xprintf(fd, ", .event_info = ");
	write_bits_u64(fd, 64, data->event_info);
	xprintf(fd, ", .event_data = ");
	write_bits_u64(fd, 64, data->event_data);
	xprintf(fd, ", .seq_num = ");
	write_bits_u32(fd, 32, data->seq_num);
	xprintf(fd, "}");
} /* end write_..._psif_eq_entry(psif_eq_entry data) */

void write_struct_psif_epsc_csr_opaque(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_opaque *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_opaque *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .data = ");
	{ unsigned int i; for (i = 0; i < 11; i++) {
		write_bits_u64(fd, 64, data->data[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_opaque(psif_epsc_csr_opaque data) */

void write_struct_psif_epsc_csr_single(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_single *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_single *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .data = ");
	write_bits_u64(fd, 64, data->data);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_single(psif_epsc_csr_single data) */

void write_struct_psif_epsc_csr_base_addr(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_base_addr *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_base_addr *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .address = ");
	write_bits_u64(fd, 64, data->address);
	xprintf(fd, ", .mmu_context = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_context));
	xprintf(fd, ", .extent_log2 = ");
	write_bits_u8(fd, 5, data->extent_log2);
	xprintf(fd, ", .num_entries = ");
	write_bits_u32(fd, 32, data->num_entries);
	xprintf(fd, ", .msix_index = ");
	write_bits_u32(fd, 32, data->msix_index);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 7; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_base_addr(psif_epsc_csr_base_addr data) */

void write_struct_psif_csr_modify_qp_ctrl(XFILE *fd,
	int network_order,
	const struct psif_csr_modify_qp_ctrl *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_csr_modify_qp_ctrl *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .use_current_state = ");
	write_bits_u8(fd, 1, data->use_current_state);
	xprintf(fd, ", .max_outstanding = ");
	write_bits_u8(fd, 1, data->max_outstanding);
	xprintf(fd, ", .xmit_psn = ");
	write_bits_u8(fd, 1, data->xmit_psn);
	xprintf(fd, ", .rnr_retry_count = ");
	write_bits_u8(fd, 1, data->rnr_retry_count);
	xprintf(fd, ", .error_retry_count = ");
	write_bits_u8(fd, 1, data->error_retry_count);
	xprintf(fd, ", .min_rnr_nak_time = ");
	write_bits_u8(fd, 1, data->min_rnr_nak_time);
	xprintf(fd, ", .local_ack_timeout = ");
	write_bits_u8(fd, 1, data->local_ack_timeout);
	xprintf(fd, ", .pkey_index = ");
	write_bits_u8(fd, 1, data->pkey_index);
	xprintf(fd, ", .qkey = ");
	write_bits_u8(fd, 1, data->qkey);
	xprintf(fd, ", .qp_rcv_cap = ");
	write_bits_u8(fd, 1, data->qp_rcv_cap);
	xprintf(fd, ", .qp_state = ");
	write_bits_u8(fd, 1, data->qp_state);
	xprintf(fd, ", .alt_path = ");
	write_bits_u8(fd, 1, data->alt_path);
	xprintf(fd, ", .mig_state = ");
	write_bits_u8(fd, 1, data->mig_state);
	xprintf(fd, ", .prim_path = ");
	write_bits_u8(fd, 1, data->prim_path);
	xprintf(fd, ", .expected_psn = ");
	write_bits_u8(fd, 1, data->expected_psn);
	xprintf(fd, ", .path_mtu = ");
	write_bits_u8(fd, 1, data->path_mtu);
	xprintf(fd, ", .req_access_error = ");
	write_bits_u8(fd, 1, data->req_access_error);
	xprintf(fd, ", .notify_when_zero = ");
	write_bits_u8(fd, 1, data->notify_when_zero);
	xprintf(fd, ", .qp_num = ");
	write_bits_u32(fd, 24, data->qp_num);
	xprintf(fd, ", .current_state = ");
	write_enum_psif_qp_state(fd, data->current_state);
	xprintf(fd, ", .port_num = ");
	write_enum_psif_port(fd, data->port_num);
	xprintf(fd, ", .uf = ");
	write_bits_u8(fd, 6, data->uf);
	xprintf(fd, ", .cmd = ");
	write_enum_psif_qp_command(fd, data->cmd);
	xprintf(fd, "}");
} /* end write_..._psif_csr_modify_qp_ctrl(psif_csr_modify_qp_ctrl data) */

void write_struct_psif_epsc_csr_modify_qp(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_modify_qp *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_modify_qp *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .ctrl = ");
	write_struct_psif_csr_modify_qp_ctrl(fd, 0, &(data->ctrl));
	xprintf(fd, ", .data = ");
	write_struct_psif_modify_qp(fd, 0, &(data->data));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_modify_qp(psif_epsc_csr_modify_qp data) */

void write_struct_psif_epsc_csr_query_qp(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query_qp *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_query_qp *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .address = ");
	write_bits_u64(fd, 64, data->address);
	xprintf(fd, ", .ctrl = ");
	write_struct_psif_csr_modify_qp_ctrl(fd, 0, &(data->ctrl));
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 8; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_query_qp(psif_epsc_csr_query_qp data) */

void write_struct_psif_csr_own_lid_base(XFILE *fd,
	int network_order,
	const struct psif_csr_own_lid_base *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_csr_own_lid_base *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .gid_flag = ");
	write_bits_u8(fd, 1, data->gid_flag);
	xprintf(fd, ", .lmc = ");
	write_bits_u8(fd, 3, data->lmc);
	xprintf(fd, ", .lid_base = ");
	write_bits_u16(fd, 16, data->lid_base);
	xprintf(fd, "}");
} /* end write_..._psif_csr_own_lid_base(psif_csr_own_lid_base data) */

void write_struct_psif_csr_snd_lid(XFILE *fd,
	int network_order,
	const struct psif_csr_snd_lid *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_csr_snd_lid *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .lmc = ");
	write_bits_u8(fd, 3, data->lmc);
	xprintf(fd, ", .lid_base = ");
	write_bits_u16(fd, 16, data->lid_base);
	xprintf(fd, "}");
} /* end write_..._psif_csr_snd_lid(psif_csr_snd_lid data) */

void write_struct_psif_csr_rcv_lid(XFILE *fd,
	int network_order,
	const struct psif_csr_rcv_lid *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_csr_rcv_lid *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .gid_flag = ");
	write_bits_u8(fd, 1, data->gid_flag);
	xprintf(fd, ", .lmc = ");
	write_bits_u8(fd, 3, data->lmc);
	xprintf(fd, ", .lid_base = ");
	write_bits_u16(fd, 16, data->lid_base);
	xprintf(fd, "}");
} /* end write_..._psif_csr_rcv_lid(psif_csr_rcv_lid data) */

void write_struct_psif_epsc_csr_set_lid(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set_lid *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_set_lid *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .lid_rqs = ");
	write_struct_psif_csr_own_lid_base(fd, 0, &(data->lid_rqs));
	xprintf(fd, ", .lid_snd = ");
	write_struct_psif_csr_snd_lid(fd, 0, &(data->lid_snd));
	xprintf(fd, ", .lid_rcv = ");
	write_struct_psif_csr_rcv_lid(fd, 0, &(data->lid_rcv));
	xprintf(fd, ", .index = ");
	write_bits_u8(fd, 8, data->index);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 7; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_set_lid(psif_epsc_csr_set_lid data) */

void write_struct_psif_epsc_csr_set_gid(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set_gid *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_set_gid *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .gid_0 = ");
	write_bits_u64(fd, 64, data->gid_0);
	xprintf(fd, ", .gid_1 = ");
	write_bits_u64(fd, 64, data->gid_1);
	xprintf(fd, ", .index = ");
	write_bits_u8(fd, 8, data->index);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 8; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_set_gid(psif_epsc_csr_set_gid data) */

void write_struct_psif_epsc_csr_set_eoib_mac(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set_eoib_mac *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_set_eoib_mac *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .mac = ");
	write_bits_u64(fd, 64, data->mac);
	xprintf(fd, ", .index = ");
	write_bits_u8(fd, 8, data->index);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 9; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_set_eoib_mac(psif_epsc_csr_set_eoib_mac data) */

void write_struct_psif_epsc_csr_vlink_state(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_vlink_state *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_vlink_state *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .vlink_state = ");
	write_enum_psif_vlink_state(fd, data->vlink_state);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .uf = ");
	write_bits_u8(fd, 6, data->uf);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 10; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_vlink_state(psif_epsc_csr_vlink_state data) */

void write_struct_psif_epsc_csr_query_hw(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query_hw *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_query_hw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .address = ");
	write_bits_u64(fd, 64, data->address);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 9; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_query_hw(psif_epsc_csr_query_hw data) */

void write_struct_psif_epsc_csr_query_table(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query_table *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_query_table *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .index = ");
	write_bits_u16(fd, 16, data->index);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 10; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_query_table(psif_epsc_csr_query_table data) */

void write_struct_psif_epsc_csr_mc(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_mc *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_mc *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .qp = ");
	write_bits_u32(fd, 24, data->qp);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .mgid_0 = ");
	write_bits_u64(fd, 64, data->mgid_0);
	xprintf(fd, ", .mgid_1 = ");
	write_bits_u64(fd, 64, data->mgid_1);
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 8; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_mc(psif_epsc_csr_mc data) */

void write_struct_psif_epsc_csr_event(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_event *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_event *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .eq_index = ");
	write_bits_u32(fd, 32, data->eq_index);
	xprintf(fd, ", .eq_num = ");
	write_bits_u8(fd, 8, data->eq_num);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .event = ");
	{ unsigned int i; for (i = 0; i < 8; i++) {
		write_bits_u64(fd, 64, data->event[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 2; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_event(psif_epsc_csr_event data) */

void write_struct_psif_epsc_csr_modify_device(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_modify_device *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_modify_device *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .modify_mask = ");
	write_enum_psif_epsc_csr_modify_device_flags(fd, data->modify_mask);
	xprintf(fd, ", .sys_image_guid = ");
	write_bits_u64(fd, 64, data->sys_image_guid);
	xprintf(fd, ", .node_desc = ");
	{ unsigned int i; for (i = 0; i < 64; i++) {
		write_bits_u8(fd, 8, data->node_desc[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, ", .padding = ");
	write_bits_u64(fd, 64, data->padding);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_modify_device(psif_epsc_csr_modify_device data) */

void write_struct_psif_epsc_csr_modify_port(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_modify_port *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_modify_port *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .init_type = ");
	write_bits_u8(fd, 8, data->init_type);
	xprintf(fd, ", .port = ");
	write_bits_u8(fd, 8, data->port);
	xprintf(fd, ", .modify_mask = ");
	write_enum_psif_epsc_csr_modify_port_flags(fd, data->modify_mask);
	xprintf(fd, ", .clr_port_cap_mask = ");
	write_bits_u32(fd, 32, data->clr_port_cap_mask);
	xprintf(fd, ", .set_port_cap_mask = ");
	write_bits_u32(fd, 32, data->set_port_cap_mask);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_modify_port(psif_epsc_csr_modify_port data) */

void write_struct_psif_epsc_csr_test_host_wrd(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_test_host_wrd *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_test_host_wrd *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .epsc_offs = ");
	write_bits_u32(fd, 32, data->epsc_offs);
	xprintf(fd, ", .key = ");
	write_bits_u32(fd, 32, data->key);
	xprintf(fd, ", .pattern = ");
	write_bits_u32(fd, 32, data->pattern);
	xprintf(fd, ", .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_test_host_wrd(psif_epsc_csr_test_host_wrd data) */

void write_struct_psif_epsc_csr_flash_access(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_flash_access *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_flash_access *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .offset = ");
	write_bits_u32(fd, 32, data->offset);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .crc = ");
	write_bits_u64(fd, 64, data->crc);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_flash_access(psif_epsc_csr_flash_access data) */

void write_struct_psif_epsc_csr_trace_acquire(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_trace_acquire *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_trace_acquire *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .maxtrace = ");
	write_bits_u32(fd, 32, data->maxtrace);
	xprintf(fd, ", .offset = ");
	write_bits_u32(fd, 32, data->offset);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .padding = ");
	{ unsigned int i; for (i = 0; i < 8; i++) {
		write_bits_u64(fd, 64, data->padding[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_trace_acquire(psif_epsc_csr_trace_acquire data) */

void write_struct_psif_epsc_csr_fw_version(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_fw_version *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_fw_version *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .data = ");
	write_bits_u64(fd, 64, data->data);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_fw_version(psif_epsc_csr_fw_version data) */

void write_struct_psif_epsc_csr_log_ctrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_log_ctrl *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_log_ctrl *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .mode = ");
	write_enum_psif_epsc_log_mode(fd, data->mode);
	xprintf(fd, ", .level = ");
	write_enum_psif_epsc_log_level(fd, data->level);
	xprintf(fd, ", .base = ");
	write_bits_u64(fd, 64, data->base);
	xprintf(fd, ", .stat_base = ");
	write_bits_u64(fd, 64, data->stat_base);
	xprintf(fd, ", .length = ");
	write_bits_u64(fd, 64, data->length);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_log_ctrl(psif_epsc_csr_log_ctrl data) */

void write_struct_psif_epsc_csr_epsa_cntrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_epsa_cntrl *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_epsa_cntrl *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .epsa = ");
	write_enum_psif_eps_a_core(fd, data->epsa);
	xprintf(fd, ", .command = ");
	write_enum_psif_epsc_csr_epsa_command(fd, data->command);
	xprintf(fd, ", .flash_addr = ");
	write_bits_u64(fd, 64, data->flash_addr);
	xprintf(fd, ", .epsa_addr = ");
	write_bits_u64(fd, 64, data->epsa_addr);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_epsa_cntrl(psif_epsc_csr_epsa_cntrl data) */

void write_struct_psif_epsc_csr_epsa_cmd(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_epsa_cmd *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_epsa_cmd *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .cmd = ");
	write_enum_psif_epsa_command(fd, data->cmd);
	xprintf(fd, ", .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .entry_point = ");
	{ unsigned int i; for (i = 0; i < 16; i++) {
		write_bits_u8(fd, 8, data->entry_point[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, ", .qpnum = ");
	write_bits_u32(fd, 32, data->qpnum);
	xprintf(fd, ", .key = ");
	write_bits_u32(fd, 32, data->key);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_epsa_cmd(psif_epsc_csr_epsa_cmd data) */

void write_struct_psif_epsc_csr_cli_access(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_cli_access *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_cli_access *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .command = ");
	{ unsigned int i; for (i = 0; i < 72; i++) {
		write_bits_u8(fd, 8, data->command[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_cli_access(psif_epsc_csr_cli_access data) */

void write_struct_psif_epsc_csr_mad_process(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_mad_process *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_mad_process *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .qp = ");
	write_bits_u32(fd, 24, data->qp);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_wc_opcode(fd, data->opcode);
	xprintf(fd, ", .byte_len = ");
	write_bits_u32(fd, 32, data->byte_len);
	xprintf(fd, ", .slid = ");
	write_bits_u16(fd, 16, data->slid);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .sl = ");
	write_bits_u8(fd, 4, data->sl);
	xprintf(fd, ", .pkey_indx = ");
	write_bits_u16(fd, 9, data->pkey_indx);
	xprintf(fd, ", .wc_flags_with_imm = ");
	write_bits_u8(fd, 1, data->wc_flags_with_imm);
	xprintf(fd, ", .wc_flags_grh = ");
	write_bits_u8(fd, 1, data->wc_flags_grh);
	xprintf(fd, ", .src_qp = ");
	write_bits_u32(fd, 24, data->src_qp);
	xprintf(fd, ", .status = ");
	write_enum_psif_wc_status(fd, data->status);
	xprintf(fd, ", .dlid_path_bits = ");
	write_bits_u8(fd, 7, data->dlid_path_bits);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_mad_process(psif_epsc_csr_mad_process data) */

void write_struct_psif_epsc_csr_mad_send_wr(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_mad_send_wr *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_mad_send_wr *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_mad_send_wr(psif_epsc_csr_mad_send_wr data) */

void write_struct_psif_epsc_query_req(XFILE *fd,
	int network_order,
	const struct psif_epsc_query_req *data)
{
	u64 swap[2];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 16);
		data = (struct psif_epsc_query_req *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .index = ");
	write_bits_u32(fd, 32, data->index);
	xprintf(fd, ", .op = ");
	write_enum_psif_epsc_query_op(fd, data->op);
	xprintf(fd, ", .value = ");
	write_bits_u64(fd, 64, data->value);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_query_req(psif_epsc_query_req data) */

void write_struct_psif_epsc_csr_query(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_query *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .uf = ");
	write_bits_u32(fd, 32, data->uf);
	xprintf(fd, ", .data = ");
	write_struct_psif_epsc_query_req(fd, 0, &(data->data));
	xprintf(fd, ", .info = ");
	write_struct_psif_epsc_query_req(fd, 0, &(data->info));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_query(psif_epsc_csr_query data) */

void write_struct_psif_epsc_csr_set(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_set *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .uf = ");
	write_bits_u32(fd, 32, data->uf);
	xprintf(fd, ", .data = ");
	write_struct_psif_epsc_query_req(fd, 0, &(data->data));
	xprintf(fd, ", .info = ");
	write_struct_psif_epsc_query_req(fd, 0, &(data->info));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_set(psif_epsc_csr_set data) */

void write_struct_psif_epsc_csr_interrupt_common(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_interrupt_common *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_interrupt_common *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .total_usec = ");
	write_bits_u16(fd, 16, data->total_usec);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_interrupt_common(psif_epsc_csr_interrupt_common data) */

void write_struct_psif_interrupt_attributes(XFILE *fd,
	int network_order,
	const struct psif_interrupt_attributes *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_interrupt_attributes *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .channel_pusec_high = ");
	write_bits_u8(fd, 1, data->channel_pusec_high);
	xprintf(fd, ", .channel_pusec_low = ");
	write_bits_u8(fd, 1, data->channel_pusec_low);
	xprintf(fd, ", .channel_pusec = ");
	write_bits_u8(fd, 1, data->channel_pusec);
	xprintf(fd, ", .channel_ausec_high = ");
	write_bits_u8(fd, 1, data->channel_ausec_high);
	xprintf(fd, ", .channel_ausec_low = ");
	write_bits_u8(fd, 1, data->channel_ausec_low);
	xprintf(fd, ", .channel_ausec = ");
	write_bits_u8(fd, 1, data->channel_ausec);
	xprintf(fd, ", .channel_rate_high = ");
	write_bits_u8(fd, 1, data->channel_rate_high);
	xprintf(fd, ", .channel_rate_low = ");
	write_bits_u8(fd, 1, data->channel_rate_low);
	xprintf(fd, ", .channel_rx_scale = ");
	write_bits_u8(fd, 1, data->channel_rx_scale);
	xprintf(fd, ", .enable_adaptive = ");
	write_bits_u8(fd, 1, data->enable_adaptive);
	xprintf(fd, "}");
} /* end write_..._psif_interrupt_attributes(psif_interrupt_attributes data) */

void write_struct_psif_epsc_csr_interrupt_channel(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_interrupt_channel *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_interrupt_channel *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .attributes = ");
	write_struct_psif_interrupt_attributes(fd, 0, &(data->attributes));
	xprintf(fd, ", .channel_rx_scale = ");
	write_bits_u16(fd, 16, data->channel_rx_scale);
	xprintf(fd, ", .enable_adaptive = ");
	write_bits_u8(fd, 1, data->enable_adaptive);
	xprintf(fd, ", .int_channel = ");
	write_bits_u16(fd, 16, data->int_channel);
	xprintf(fd, ", .channel_rate_high = ");
	write_bits_u32(fd, 32, data->channel_rate_high);
	xprintf(fd, ", .channel_rate_low = ");
	write_bits_u32(fd, 32, data->channel_rate_low);
	xprintf(fd, ", .channel_pusec = ");
	write_bits_u16(fd, 16, data->channel_pusec);
	xprintf(fd, ", .channel_ausec_high = ");
	write_bits_u16(fd, 16, data->channel_ausec_high);
	xprintf(fd, ", .channel_ausec_low = ");
	write_bits_u16(fd, 16, data->channel_ausec_low);
	xprintf(fd, ", .channel_ausec = ");
	write_bits_u16(fd, 16, data->channel_ausec);
	xprintf(fd, ", .channel_pusec_high = ");
	write_bits_u16(fd, 16, data->channel_pusec_high);
	xprintf(fd, ", .channel_pusec_low = ");
	write_bits_u16(fd, 16, data->channel_pusec_low);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_interrupt_channel(psif_epsc_csr_interrupt_channel data) */

void write_union_psif_epsc_update_set_or_offset(XFILE *fd,
	int network_order,
	const union psif_epsc_update_set_or_offset *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .offset = ");
	write_bits_u32(fd, 32, data->offset);
	xprintf(fd, ", .set = ");
	write_enum_psif_epsc_update_set(fd, data->set);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_update_set_or_offset(psif_epsc_update_set_or_offset data) */

void write_struct_psif_epsc_csr_update(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_update *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_update *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .u = ");
	write_union_psif_epsc_update_set_or_offset(fd, 0, &(data->u));
	xprintf(fd, ", .slot = ");
	write_enum_psif_epsc_flash_slot(fd, data->slot);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_epsc_csr_update_opcode(fd, data->opcode);
	xprintf(fd, ", .id = ");
	write_bits_u32(fd, 32, data->id);
	xprintf(fd, ", .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_update(psif_epsc_csr_update data) */

void write_struct_psif_epsc_csr_uf_ctrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_uf_ctrl *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_uf_ctrl *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .flags = ");
	write_bits_u32(fd, 32, data->flags);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_epsc_csr_uf_ctrl_opcode(fd, data->opcode);
	xprintf(fd, ", .uf_vector = ");
	write_bits_u64(fd, 64, data->uf_vector);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_uf_ctrl(psif_epsc_csr_uf_ctrl data) */

void write_struct_psif_csr_mmu_flush_caches(XFILE *fd,
	int network_order,
	const struct psif_csr_mmu_flush_caches *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_csr_mmu_flush_caches *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .flush_mmu_cache = ");
	write_bits_u8(fd, 1, data->flush_mmu_cache);
	xprintf(fd, ", .flush_ptw_cache = ");
	write_bits_u8(fd, 1, data->flush_ptw_cache);
	xprintf(fd, ", .mmu_cache_flushed = ");
	write_bits_u8(fd, 1, data->mmu_cache_flushed);
	xprintf(fd, ", .ptw_cache_flushed = ");
	write_bits_u8(fd, 1, data->ptw_cache_flushed);
	xprintf(fd, "}");
} /* end write_..._psif_csr_mmu_flush_caches(psif_csr_mmu_flush_caches data) */

void write_struct_psif_epsc_flush_caches(XFILE *fd,
	int network_order,
	const struct psif_epsc_flush_caches *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_flush_caches *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .flush_mmu_caches = ");
	write_struct_psif_csr_mmu_flush_caches(fd, 0, &(data->flush_mmu_caches));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_flush_caches(psif_epsc_flush_caches data) */

void write_struct_psif_epsc_csr_pma_counters(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_pma_counters *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_epsc_csr_pma_counters *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .port = ");
	write_bits_u32(fd, 32, data->port);
	xprintf(fd, ", .uf = ");
	write_bits_u32(fd, 32, data->uf);
	xprintf(fd, ", .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .clear_mask = ");
	write_bits_u64(fd, 64, data->clear_mask);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_pma_counters(psif_epsc_csr_pma_counters data) */

void write_struct_psif_epsc_vimma_dereg(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_dereg *data)
{
	u64 swap[5];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 40);
		data = (struct psif_epsc_vimma_dereg *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .high_uf = ");
	write_bits_u16(fd, 16, data->high_uf);
	xprintf(fd, ", .low_uf = ");
	write_bits_u16(fd, 16, data->low_uf);
	xprintf(fd, ", .uf_vector = ");
	{ unsigned int i; for (i = 0; i < 4; i++) {
		write_bits_u64(fd, 64, data->uf_vector[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_vimma_dereg(psif_epsc_vimma_dereg data) */

void write_struct_psif_epsc_vimma_vfp_reg(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_vfp_reg *data)
{
	u64 swap[5];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 40);
		data = (struct psif_epsc_vimma_vfp_reg *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .vm_context = ");
	write_bits_u32(fd, 32, data->vm_context);
	xprintf(fd, ", .uf = ");
	write_bits_u16(fd, 16, data->uf);
	xprintf(fd, ", .vm_id = ");
	{ unsigned int i; for (i = 0; i < 16; i++) {
		write_bits_u8(fd, 8, data->vm_id[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, ", .vhca_instance = ");
	write_bits_u16(fd, 16, data->vhca_instance);
	xprintf(fd, ", .vm_incarnation = ");
	write_bits_u32(fd, 32, data->vm_incarnation);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_vimma_vfp_reg(psif_epsc_vimma_vfp_reg data) */

void write_struct_psif_epsc_vimma_set_admmode(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_set_admmode *data)
{
	u64 swap[5];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 40);
		data = (struct psif_epsc_vimma_set_admmode *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .high_uf = ");
	write_bits_u16(fd, 16, data->high_uf);
	xprintf(fd, ", .low_uf = ");
	write_bits_u16(fd, 16, data->low_uf);
	xprintf(fd, ", .mode = ");
	write_enum_psif_epsc_vimma_admmode(fd, data->mode);
	xprintf(fd, ", .uf_vector = ");
	{ unsigned int i; for (i = 0; i < 4; i++) {
		write_bits_u64(fd, 64, data->uf_vector[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_vimma_set_admmode(psif_epsc_vimma_set_admmode data) */

void write_struct_psif_epsc_vimma_reg_info(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_reg_info *data)
{
	u64 swap[5];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 40);
		data = (struct psif_epsc_vimma_reg_info *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .high_uf = ");
	write_bits_u16(fd, 16, data->high_uf);
	xprintf(fd, ", .low_uf = ");
	write_bits_u16(fd, 16, data->low_uf);
	xprintf(fd, ", .uf_vector = ");
	{ unsigned int i; for (i = 0; i < 4; i++) {
		write_bits_u64(fd, 64, data->uf_vector[i]);
		xprintf(fd, ",");
	}
}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_vimma_reg_info(psif_epsc_vimma_reg_info data) */

void write_union_psif_epsc_vimma_ctrl_cmd(XFILE *fd,
	int network_order,
	const union psif_epsc_vimma_ctrl_cmd *data)
{
	u64 swap[5];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 40);
		data = (union psif_epsc_vimma_ctrl_cmd *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .dereg = ");
	write_struct_psif_epsc_vimma_dereg(fd, 0, &(data->dereg));
	xprintf(fd, ", .vfp_reg = ");
	write_struct_psif_epsc_vimma_vfp_reg(fd, 0, &(data->vfp_reg));
	xprintf(fd, ", .adm_mode = ");
	write_struct_psif_epsc_vimma_set_admmode(fd, 0, &(data->adm_mode));
	xprintf(fd, ", .reg_info = ");
	write_struct_psif_epsc_vimma_reg_info(fd, 0, &(data->reg_info));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_vimma_ctrl_cmd(psif_epsc_vimma_ctrl_cmd data) */

void write_struct_psif_epsc_csr_vimma_ctrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_vimma_ctrl *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (struct psif_epsc_csr_vimma_ctrl *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .length = ");
	write_bits_u32(fd, 32, data->length);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_epsc_vimma_ctrl_opcode(fd, data->opcode);
	xprintf(fd, ", .u = ");
	write_union_psif_epsc_vimma_ctrl_cmd(fd, 0, &(data->u));
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_vimma_ctrl(psif_epsc_csr_vimma_ctrl data) */

void write_struct_psif_epsc_csr_ber_data(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_ber_data *data)
{
	u64 swap[3];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 24);
		data = (struct psif_epsc_csr_ber_data *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .host_addr = ");
	write_bits_u64(fd, 64, data->host_addr);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .len = ");
	write_bits_u32(fd, 32, data->len);
	xprintf(fd, ", .port = ");
	write_bits_u32(fd, 32, data->port);
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_ber_data(psif_epsc_csr_ber_data data) */

void write_union_psif_epsc_csr_details(XFILE *fd,
	int network_order,
	const union psif_epsc_csr_details *data)
{
	u64 swap[11];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 88);
		data = (union psif_epsc_csr_details *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .opaque = ");
	write_struct_psif_epsc_csr_opaque(fd, 0, &(data->opaque));
	xprintf(fd, ", .single = ");
	write_struct_psif_epsc_csr_single(fd, 0, &(data->single));
	xprintf(fd, ", .base_addr = ");
	write_struct_psif_epsc_csr_base_addr(fd, 0, &(data->base_addr));
	xprintf(fd, ", .modify_qp = ");
	write_struct_psif_epsc_csr_modify_qp(fd, 0, &(data->modify_qp));
	xprintf(fd, ", .query_qp = ");
	write_struct_psif_epsc_csr_query_qp(fd, 0, &(data->query_qp));
	xprintf(fd, ", .set_lid = ");
	write_struct_psif_epsc_csr_set_lid(fd, 0, &(data->set_lid));
	xprintf(fd, ", .set_gid = ");
	write_struct_psif_epsc_csr_set_gid(fd, 0, &(data->set_gid));
	xprintf(fd, ", .set_eoib_mac = ");
	write_struct_psif_epsc_csr_set_eoib_mac(fd, 0, &(data->set_eoib_mac));
	xprintf(fd, ", .set_vlink = ");
	write_struct_psif_epsc_csr_vlink_state(fd, 0, &(data->set_vlink));
	xprintf(fd, ", .query_hw = ");
	write_struct_psif_epsc_csr_query_hw(fd, 0, &(data->query_hw));
	xprintf(fd, ", .query_table = ");
	write_struct_psif_epsc_csr_query_table(fd, 0, &(data->query_table));
	xprintf(fd, ", .mc = ");
	write_struct_psif_epsc_csr_mc(fd, 0, &(data->mc));
	xprintf(fd, ", .event = ");
	write_struct_psif_epsc_csr_event(fd, 0, &(data->event));
	xprintf(fd, ", .device = ");
	write_struct_psif_epsc_csr_modify_device(fd, 0, &(data->device));
	xprintf(fd, ", .port = ");
	write_struct_psif_epsc_csr_modify_port(fd, 0, &(data->port));
	xprintf(fd, ", .host_wrd = ");
	write_struct_psif_epsc_csr_test_host_wrd(fd, 0, &(data->host_wrd));
	xprintf(fd, ", .flash = ");
	write_struct_psif_epsc_csr_flash_access(fd, 0, &(data->flash));
	xprintf(fd, ", .trace_acquire = ");
	write_struct_psif_epsc_csr_trace_acquire(fd, 0, &(data->trace_acquire));
	xprintf(fd, ", .fw_version = ");
	write_struct_psif_epsc_csr_fw_version(fd, 0, &(data->fw_version));
	xprintf(fd, ", .log_ctrl = ");
	write_struct_psif_epsc_csr_log_ctrl(fd, 0, &(data->log_ctrl));
	xprintf(fd, ", .epsa_cntrl = ");
	write_struct_psif_epsc_csr_epsa_cntrl(fd, 0, &(data->epsa_cntrl));
	xprintf(fd, ", .epsa_cmd = ");
	write_struct_psif_epsc_csr_epsa_cmd(fd, 0, &(data->epsa_cmd));
	xprintf(fd, ", .cli = ");
	write_struct_psif_epsc_csr_cli_access(fd, 0, &(data->cli));
	xprintf(fd, ", .mad_process = ");
	write_struct_psif_epsc_csr_mad_process(fd, 0, &(data->mad_process));
	xprintf(fd, ", .mad_send_wr = ");
	write_struct_psif_epsc_csr_mad_send_wr(fd, 0, &(data->mad_send_wr));
	xprintf(fd, ", .query = ");
	write_struct_psif_epsc_csr_query(fd, 0, &(data->query));
	xprintf(fd, ", .set = ");
	write_struct_psif_epsc_csr_set(fd, 0, &(data->set));
	xprintf(fd, ", .int_common = ");
	write_struct_psif_epsc_csr_interrupt_common(fd, 0, &(data->int_common));
	xprintf(fd, ", .int_channel = ");
	write_struct_psif_epsc_csr_interrupt_channel(fd, 0, &(data->int_channel));
	xprintf(fd, ", .update = ");
	write_struct_psif_epsc_csr_update(fd, 0, &(data->update));
	xprintf(fd, ", .uf_ctrl = ");
	write_struct_psif_epsc_csr_uf_ctrl(fd, 0, &(data->uf_ctrl));
	xprintf(fd, ", .flush_caches = ");
	write_struct_psif_epsc_flush_caches(fd, 0, &(data->flush_caches));
	xprintf(fd, ", .pma_counters = ");
	write_struct_psif_epsc_csr_pma_counters(fd, 0, &(data->pma_counters));
	xprintf(fd, ", .vimma_ctrl = ");
	write_struct_psif_epsc_csr_vimma_ctrl(fd, 0, &(data->vimma_ctrl));
	xprintf(fd, ", .ber = ");
	write_struct_psif_epsc_csr_ber_data(fd, 0, &(data->ber));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_details(psif_epsc_csr_details data) */

void write_struct_psif_epsc_csr_req(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_req *data)
{
	u64 swap[16];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 128);
		data = (struct psif_epsc_csr_req *)swap;
		network_order = 0;
	}
	xprintf(fd, "{");
	xprintf(fd, " .crc = ");
	write_bits_u16(fd, 16, data->crc);
	xprintf(fd, ", .uf = ");
	write_bits_u16(fd, 16, data->uf);
	xprintf(fd, ", .seq_num = ");
	write_bits_u16(fd, 16, data->seq_num);
	xprintf(fd, ", .flags = ");
	write_enum_psif_epsc_csr_flags(fd, data->flags);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_epsc_csr_opcode(fd, data->opcode);
	xprintf(fd, ", .addr = ");
	write_bits_u64(fd, 64, data->addr);
	xprintf(fd, ", .u.");
	switch (data->opcode) {
	case EPSC_SETUP_BASEADDR:
	case EPSC_SET_BASEADDR:
	case EPSC_SET_BASEADDR_EQ:
		xprintf(fd, "base_addr = ");
		write_struct_psif_epsc_csr_base_addr(fd, network_order, &(data->u.base_addr));
		break;
	case EPSC_MODIFY_QP:
		xprintf(fd, "modify_qp = ");
		write_struct_psif_epsc_csr_modify_qp(fd, network_order, &(data->u.modify_qp));
		break;
	case EPSC_QUERY_QP:
		xprintf(fd, "query_qp = ");
		write_struct_psif_epsc_csr_query_qp(fd, network_order, &(data->u.query_qp));
		break;
	case EPSC_SET_LID:
		xprintf(fd, "set_lid = ");
		write_struct_psif_epsc_csr_set_lid(fd, network_order, &(data->u.set_lid));
		break;
	case EPSC_SET_GID:
		xprintf(fd, "set_gid = ");
		write_struct_psif_epsc_csr_set_gid(fd, network_order, &(data->u.set_gid));
		break;
	case EPSC_SET_EOIB_MAC:
		xprintf(fd, "set_eoib_mac = ");
		write_struct_psif_epsc_csr_set_eoib_mac(fd, network_order, &(data->u.set_eoib_mac));
		break;
	case EPSC_SET_VLINK_STATE:
	case EPSC_QUERY_VLINK_STATE:
		xprintf(fd, "set_vlink = ");
		write_struct_psif_epsc_csr_vlink_state(fd, network_order, &(data->u.set_vlink));
		break;
	case EPSC_QUERY_DEVICE:
	case EPSC_QUERY_PORT_1:
	case EPSC_QUERY_PORT_2:
	case EPSC_QUERY_HW_RQ:
	case EPSC_QUERY_HW_SQ:
		xprintf(fd, "query_hw = ");
		write_struct_psif_epsc_csr_query_hw(fd, network_order, &(data->u.query_hw));
		break;
	case EPSC_QUERY_PKEY:
	case EPSC_QUERY_GID:
		xprintf(fd, "query_table = ");
		write_struct_psif_epsc_csr_query_table(fd, network_order, &(data->u.query_table));
		break;
	case EPSC_MC_ATTACH:
	case EPSC_MC_DETACH:
	case EPSC_MC_QUERY:
		xprintf(fd, "mc = ");
		write_struct_psif_epsc_csr_mc(fd, network_order, &(data->u.mc));
		break;
	case EPSC_EVENT_ACK:
		xprintf(fd, "event = ");
		write_struct_psif_epsc_csr_event(fd, network_order, &(data->u.event));
		break;
	case EPSC_MODIFY_DEVICE:
		xprintf(fd, "device = ");
		write_struct_psif_epsc_csr_modify_device(fd, network_order, &(data->u.device));
		break;
	case EPSC_MODIFY_PORT_1:
	case EPSC_MODIFY_PORT_2:
		xprintf(fd, "port = ");
		write_struct_psif_epsc_csr_modify_port(fd, network_order, &(data->u.port));
		break;
	case EPSC_FW_VERSION:
		xprintf(fd, "fw_version = ");
		write_struct_psif_epsc_csr_fw_version(fd, network_order, &(data->u.fw_version));
		break;
	case EPSC_LOG_CTRL:
		xprintf(fd, "log_ctrl = ");
		write_struct_psif_epsc_csr_log_ctrl(fd, network_order, &(data->u.log_ctrl));
		break;
	case EPSC_A_CONTROL:
		xprintf(fd, "epsa_cntrl = ");
		write_struct_psif_epsc_csr_epsa_cntrl(fd, network_order, &(data->u.epsa_cntrl));
		break;
	case EPSC_A_COMMAND:
		xprintf(fd, "epsa_cmd = ");
		write_struct_psif_epsc_csr_epsa_cmd(fd, network_order, &(data->u.epsa_cmd));
		break;
	case EPSC_CLI_ACCESS:
		xprintf(fd, "cli = ");
		write_struct_psif_epsc_csr_cli_access(fd, network_order, &(data->u.cli));
		break;
	case EPSC_MAD_PROCESS:
		xprintf(fd, "mad_process = ");
		write_struct_psif_epsc_csr_mad_process(fd, network_order, &(data->u.mad_process));
		break;
	case EPSC_MAD_SEND_WR:
		xprintf(fd, "mad_send_wr = ");
		write_struct_psif_epsc_csr_mad_send_wr(fd, network_order, &(data->u.mad_send_wr));
		break;
	case EPSC_QUERY:
		xprintf(fd, "query = ");
		write_struct_psif_epsc_csr_query(fd, network_order, &(data->u.query));
		break;
	case EPSC_SET:
		xprintf(fd, "set = ");
		write_struct_psif_epsc_csr_set(fd, network_order, &(data->u.set));
		break;
	case EPSC_HOST_INT_COMMON_CTRL:
		xprintf(fd, "int_common = ");
		write_struct_psif_epsc_csr_interrupt_common(fd, network_order, &(data->u.int_common));
		break;
	case EPSC_HOST_INT_CHANNEL_CTRL:
		xprintf(fd, "int_channel = ");
		write_struct_psif_epsc_csr_interrupt_channel(fd, network_order, &(data->u.int_channel));
		break;
	case EPSC_UF_CTRL:
		xprintf(fd, "uf_ctrl = ");
		write_struct_psif_epsc_csr_uf_ctrl(fd, network_order, &(data->u.uf_ctrl));
		break;
	case EPSC_FLUSH_CACHES:
		xprintf(fd, "flush_caches = ");
		write_struct_psif_epsc_flush_caches(fd, network_order, &(data->u.flush_caches));
		break;
	case EPSC_PMA_COUNTERS:
		xprintf(fd, "pma_counters = ");
		write_struct_psif_epsc_csr_pma_counters(fd, network_order, &(data->u.pma_counters));
		break;
	case EPSC_NOOP:
	case EPSC_TEARDOWN:
	case EPSC_TRACE_STATUS:
	case EPSC_TRACE_START:
	case EPSC_TRACE_STOP:
	case EPSC_FLASH_START:
	case EPSC_FLASH_INFO:
	case EPSC_FLASH_STOP:
	case EPSC_GET_SINGLE:
	case EPSC_GET_ONE_CSR:
	case EPSC_LOG_REQ_NOTIFY:
		xprintf(fd, "nodata");
		break;
	case EPSC_SET_SINGLE:
	case EPSC_SET_ONE_CSR:
	case EPSC_UF_RESET:
	case EPSC_EVENT_INDEX:
	case EPSC_LINK_CNTRL:
		xprintf(fd, "single = ");
		write_struct_psif_epsc_csr_single(fd, network_order, &(data->u.single));
		break;
	default:
		xprintf(fd, "opaque = ");
		write_struct_psif_epsc_csr_opaque(fd, network_order, &(data->u.opaque));
		break;
	}
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_req(psif_epsc_csr_req data) */

void write_struct_psif_epsc_csr_req_expand(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_req *data)
{
	u64 swap[16];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 128);
		data = (struct psif_epsc_csr_req *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .crc = ");
	write_bits_u16(fd, 16, data->crc);
	xprintf(fd, ", .uf = ");
	write_bits_u16(fd, 16, data->uf);
	xprintf(fd, ", .seq_num = ");
	write_bits_u16(fd, 16, data->seq_num);
	xprintf(fd, ", .flags = ");
	write_enum_psif_epsc_csr_flags(fd, data->flags);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_epsc_csr_opcode(fd, data->opcode);
	xprintf(fd, ", .addr = ");
	write_bits_u64(fd, 64, data->addr);
	xprintf(fd, ", .u = ");
	write_union_psif_epsc_csr_details(fd, 0, &(data->u));
	xprintf(fd, "}");
} /* end write_..._psif_epsc_csr_req(psif_epsc_csr_req data) */

void write_struct_psif_cq_sw(XFILE *fd,
	int network_order,
	const struct psif_cq_sw *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_cq_sw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .head_indx = ");
	write_bits_u32(fd, 32, data->head_indx);
	xprintf(fd, "}");
} /* end write_..._psif_cq_sw(psif_cq_sw data) */

void write_struct_psif_cq_hw(XFILE *fd,
	int network_order,
	const struct psif_cq_hw *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_cq_hw *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .max_size = ");
	write_bits_u32(fd, 32, data->max_size);
	xprintf(fd, ", .int_channel = ");
	write_bits_u8(fd, 7, data->int_channel);
	xprintf(fd, ", .cq_overrun_event_sent = ");
	write_bits_u8(fd, 1, data->cq_overrun_event_sent);
	xprintf(fd, ", .prefetch_threshold_log2 = ");
	write_bits_u8(fd, 5, data->prefetch_threshold_log2);
	xprintf(fd, ", .eps_core = ");
	write_enum_psif_eps_a_core(fd, data->eps_core);
	xprintf(fd, ", .proxy_en = ");
	write_bits_u8(fd, 1, data->proxy_en);
	xprintf(fd, ", .size_log2 = ");
	write_bits_u8(fd, 5, data->size_log2);
	xprintf(fd, ", .valid = ");
	write_bits_u8(fd, 1, data->valid);
	xprintf(fd, ", .cq_not_state = ");
	write_enum_psif_cq_state(fd, data->cq_not_state);
	xprintf(fd, ", .sticky = ");
	write_bits_u8(fd, 1, data->sticky);
	xprintf(fd, ", .mmu_cntx = ");
	write_struct_psif_mmu_cntx(fd, 0, &(data->mmu_cntx));
	xprintf(fd, ", .base_addr = ");
	write_bits_u64(fd, 64, data->base_addr);
	xprintf(fd, ", .sequence_number = ");
	write_bits_u32(fd, 32, data->sequence_number);
	xprintf(fd, ", .tail_indx = ");
	write_bits_u32(fd, 32, data->tail_indx);
	xprintf(fd, "}");
} /* end write_..._psif_cq_hw(psif_cq_hw data) */

void write_union_psif_seq_num_immdt(XFILE *fd,
	int network_order,
	const union psif_seq_num_immdt *data)
{
	xprintf(fd, "{");
	xprintf(fd, " .cq_sequence_number = ");
	write_bits_u32(fd, 32, data->cq_sequence_number);
	xprintf(fd, ", .imm = ");
	write_bits_u32(fd, 32, data->imm);
	xprintf(fd, "}");
} /* end write_..._psif_seq_num_immdt(psif_seq_num_immdt data) */

void write_struct_psif_offload_info(XFILE *fd,
	int network_order,
	const struct psif_offload_info *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (struct psif_offload_info *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, ", .not_written = ");
	write_bits_u8(fd, 1, data->not_written);
	xprintf(fd, ", .rtp = ");
	write_bits_u8(fd, 1, data->rtp);
	xprintf(fd, ", .hdr_split_hdr_length = ");
	write_bits_u16(fd, 9, data->hdr_split_hdr_length);
	xprintf(fd, ", .hdr_split_valid = ");
	write_bits_u8(fd, 1, data->hdr_split_valid);
	xprintf(fd, ", .is_dr = ");
	write_bits_u8(fd, 1, data->is_dr);
	xprintf(fd, ", .orig_uf = ");
	write_bits_u8(fd, 6, data->orig_uf);
	xprintf(fd, ", .l4_checksum_ok = ");
	write_bits_u8(fd, 1, data->l4_checksum_ok);
	xprintf(fd, ", .l3_checksum_ok = ");
	write_bits_u8(fd, 1, data->l3_checksum_ok);
	xprintf(fd, ", .packet_classification_udp = ");
	write_bits_u8(fd, 1, data->packet_classification_udp);
	xprintf(fd, ", .packet_classification_tcp = ");
	write_bits_u8(fd, 1, data->packet_classification_tcp);
	xprintf(fd, ", .packet_classification_ip6_unsupported_exthdr = ");
	write_bits_u8(fd, 1, data->packet_classification_ip6_unsupported_exthdr);
	xprintf(fd, ", .packet_classification_arp_reply = ");
	write_bits_u8(fd, 1, data->packet_classification_arp_reply);
	xprintf(fd, ", .packet_classification_arp = ");
	write_bits_u8(fd, 1, data->packet_classification_arp);
	xprintf(fd, ", .packet_classification_ip_options = ");
	write_bits_u8(fd, 1, data->packet_classification_ip_options);
	xprintf(fd, ", .packet_classification_ip_frag = ");
	write_bits_u8(fd, 1, data->packet_classification_ip_frag);
	xprintf(fd, ", .packet_classification_ipv6 = ");
	write_bits_u8(fd, 1, data->packet_classification_ipv6);
	xprintf(fd, ", .packet_classification_ipv4 = ");
	write_bits_u8(fd, 1, data->packet_classification_ipv4);
	xprintf(fd, ", .packet_classification_eth2 = ");
	write_bits_u8(fd, 1, data->packet_classification_eth2);
	xprintf(fd, ", .rss_hash = ");
	write_bits_u32(fd, 32, data->rss_hash);
	xprintf(fd, "}");
} /* end write_..._psif_offload_info(psif_offload_info data) */

void write_union_psif_offload_wc_id(XFILE *fd,
	int network_order,
	const union psif_offload_wc_id *data)
{
	u64 swap[1];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 8);
		data = (union psif_offload_wc_id *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .wc_id = ");
	write_union_psif_completion_wc_id(fd, 0, &(data->wc_id));
	xprintf(fd, ", .offload = ");
	write_struct_psif_offload_info(fd, 0, &(data->offload));
	xprintf(fd, "}");
} /* end write_..._psif_offload_wc_id(psif_offload_wc_id data) */

void write_struct_psif_cq_entry(XFILE *fd,
	int network_order,
	const struct psif_cq_entry *data)
{
	u64 swap[8];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 64);
		data = (struct psif_cq_entry *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .wc_id = ");
	write_union_psif_completion_wc_id(fd, 0, &(data->wc_id));
	xprintf(fd, ", .qp = ");
	write_bits_u32(fd, 24, data->qp);
	xprintf(fd, ", .opcode = ");
	write_enum_psif_wc_opcode(fd, data->opcode);
	xprintf(fd, ", .byte_len = ");
	write_bits_u32(fd, 32, data->byte_len);
	xprintf(fd, ", .src_qp = ");
	write_bits_u32(fd, 24, data->src_qp);
	xprintf(fd, ", .status = ");
	write_enum_psif_wc_status(fd, data->status);
	xprintf(fd, ", .seq_num_imm = ");
	write_union_psif_seq_num_immdt(fd, 0, &(data->seq_num_imm));
	xprintf(fd, ", .rss_hash_src = ");
	write_enum_psif_rss_hash_source(fd, data->rss_hash_src);
	xprintf(fd, ", .vendor_err = ");
	write_enum_psif_tsu_error_types(fd, data->vendor_err);
	xprintf(fd, ", .error_checksum = ");
	write_bits_u16(fd, 16, data->error_checksum);
	xprintf(fd, ", .dlid_path_bits = ");
	write_bits_u8(fd, 7, data->dlid_path_bits);
	xprintf(fd, ", .slid = ");
	write_bits_u16(fd, 16, data->slid);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .sl = ");
	write_bits_u8(fd, 4, data->sl);
	xprintf(fd, ", .pkey_indx = ");
	write_bits_u16(fd, 9, data->pkey_indx);
	xprintf(fd, ", .with_imm = ");
	write_bits_u8(fd, 1, data->with_imm);
	xprintf(fd, ", .grh = ");
	write_bits_u8(fd, 1, data->grh);
	xprintf(fd, ", .offload_wc_id = ");
	write_union_psif_offload_wc_id(fd, 0, &(data->offload_wc_id));
	xprintf(fd, ", .seq_num = ");
	write_bits_u32(fd, 32, data->seq_num);
	xprintf(fd, "}");
} /* end write_..._psif_cq_entry(psif_cq_entry data) */

void write_struct_psif_ah(XFILE *fd,
	int network_order,
	const struct psif_ah *data)
{
	u64 swap[4];

	if (network_order) {
		copy_convert_to_sw(swap, (volatile void *)data, 32);
		data = (struct psif_ah *)swap;
	}
	xprintf(fd, "{");
	xprintf(fd, " .grh_remote_gid_0 = ");
	write_bits_u64(fd, 64, data->grh_remote_gid_0);
	xprintf(fd, ", .grh_remote_gid_1 = ");
	write_bits_u64(fd, 64, data->grh_remote_gid_1);
	xprintf(fd, ", .remote_lid = ");
	write_bits_u16(fd, 16, data->remote_lid);
	xprintf(fd, ", .gid_indx = ");
	write_bits_u8(fd, 1, data->gid_indx);
	xprintf(fd, ", .port = ");
	write_enum_psif_port(fd, data->port);
	xprintf(fd, ", .loopback = ");
	write_enum_psif_loopback(fd, data->loopback);
	xprintf(fd, ", .use_grh = ");
	write_enum_psif_use_grh(fd, data->use_grh);
	xprintf(fd, ", .sl = ");
	write_bits_u8(fd, 4, data->sl);
	xprintf(fd, ", .grh_hoplmt = ");
	write_bits_u8(fd, 8, data->grh_hoplmt);
	xprintf(fd, ", .grh_tclass = ");
	write_bits_u8(fd, 8, data->grh_tclass);
	xprintf(fd, ", .grh_flowlabel = ");
	write_bits_u32(fd, 20, data->grh_flowlabel);
	xprintf(fd, ", .pd = ");
	write_bits_u32(fd, 24, data->pd);
	xprintf(fd, ", .ipd = ");
	write_bits_u8(fd, 8, data->ipd);
	xprintf(fd, ", .local_lid_path = ");
	write_bits_u8(fd, 7, data->local_lid_path);
	xprintf(fd, "}");
} /* end write_..._psif_ah(psif_ah data) */

#endif /* !defined(PSIF_EXCLUDE_WRITE_STRUCTS) */


#endif	/* _PSIF_HW_PRINT_C */
