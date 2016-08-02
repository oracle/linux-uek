/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_HW_SETGET_H
#define	_PSIF_HW_SETGET_H


#include "psif_api.h"

#if defined(__arm__)
#include "epsfw_misc.h"
#  define htobe64(x) eps_htobe64(x)
#  define be64toh(x) eps_be64toh(x)
#  define htobe32(x) eps_htobe32(x)
#  define be32toh(x) eps_be32toh(x)
#  define htobe16(x) eps_htobe16(x)
#  define be16toh(x) eps_be16toh(x)
#  define cpu_to_be64(x) htobe64(x)
#  define be64_to_cpu(x) be64toh(x)
#  define cpu_to_be32(x) htobe32(x)
#  define be32_to_cpu(x) be32toh(x)
#  define cpu_to_be16(x) htobe16(x)
#  define be16_to_cpu(x) be16toh(x)
#endif /* __arm__ */
#include "psif_endian.h"


/*
 * PSIF_WR_INVALIDATE_LKEY: key to invalidate/flush from the DMA VT cache.
 * PSIF_WR_INVALIDATE_RKEY: key to invalidate/flush from the DMA VT cache.
 * PSIF_WR_INVALIDATE_BOTH_KEYS: key to invalidate/flush from the DMA VT
 * cache. PSIF_WR_INVALIDATE_TLB: this is the address vector to invalidate in
 * the TLB.
 */
static inline void set_psif_wr_su__key(
	volatile struct psif_wr_su *ptr,
	u32 data)
{
	/* group=2 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 2) + 0);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_wr_su__key(volatile struct psif_wr_su *ptr)
{
	/* group=2 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 2) + 0);
	return((u32)be32_to_cpu(*pte));
}

/*
 * Send queue sequence number. Used to map request to a particular work
 * request in the send queue.
 */
static inline void set_psif_wr__sq_seq(
	volatile struct psif_wr *ptr,
	u16 data)
{
	/* group=0 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 6);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_wr__sq_seq(volatile struct psif_wr *ptr)
{
	/* group=0 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 6);
	return((u16)be16_to_cpu(*pte));
}

/*
 * QP sending this request. XXX: Should name be own_qp_num as defined in QP
 * state?
 */
static inline void set_psif_wr__local_qp(
	volatile struct psif_wr *ptr,
	u32 data)
{
	/* group=0 shift=32 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xff000000ffffffffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 32));
}
static inline u32 get_psif_wr__local_qp(volatile struct psif_wr *ptr)
{
	/* group=0 shift=32 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[0]) >> 32) & 0x0000000000ffffffull));
}

/* Completion notification identifier. */
static inline void set_psif_wr__completion(
	volatile struct psif_wr *ptr,
	u8 data)
{
	/* group=1 shift=31 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[1] = cpu_to_be64((be64_to_cpu(pte[1]) & 0xffffffff7fffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 31));
}
static inline u8 get_psif_wr__completion(volatile struct psif_wr *ptr)
{
	/* group=1 shift=31 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[1]) >> 31) & 0x0000000000000001ull));
}

/*
 * Checksum used for data protection and consistency between work request and
 * QP state.
 */
static inline void set_psif_wr__checksum(
	volatile struct psif_wr *ptr,
	u32 data)
{
	/* group=2 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 2) + 0);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_wr__checksum(volatile struct psif_wr *ptr)
{
	/* group=2 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 2) + 0);
	return((u32)be32_to_cpu(*pte));
}

/*
 * Index to where elements are added to the send queue by SW. SW is
 * responsibel for keeping track of how many entries there are in the send
 * queue. I.e. SW needs to keep track of the head_index so it doesn't
 * overwrite entries in the send queue which is not yet completed.
 */
static inline void set_psif_sq_sw__tail_indx(
	volatile struct psif_sq_sw *ptr,
	u16 data)
{
	/* group=0 shift=32 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 2);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_sq_sw__tail_indx(volatile struct psif_sq_sw *ptr)
{
	/* group=0 shift=32 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 2);
	return((u16)be16_to_cpu(*pte));
}

/*
 * Send queue sequence number used by the SQS to maintain ordering and keep
 * track of where which send queue elements to fetch. This field is not in
 * sync with the field in qp_t. This number is typically a little bit before
 * the number in the qp_t as SQS has to fetch the elements from host memory.
 * This is also used as tail_index when checking if there are more elements
 * in the send queue.
 */
static inline void set_psif_sq_hw__last_seq(
	volatile struct psif_sq_hw *ptr,
	u16 data)
{
	/* group=0 shift=16 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 4);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_sq_hw__last_seq(volatile struct psif_sq_hw *ptr)
{
	/* group=0 shift=16 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 4);
	return((u16)be16_to_cpu(*pte));
}

/* QP and UF to be processed next. */
static inline void set_psif_sq_hw__sq_next(
	volatile struct psif_sq_hw *ptr,
	u32 data)
{
	/* group=0 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 0) + 0);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_sq_hw__sq_next(volatile struct psif_sq_hw *ptr)
{
	/* group=0 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 0) + 0);
	return((u32)be32_to_cpu(*pte));
}

/*
 * This bit is set through the doorbell. SW should check this bit plus
 * psif_next = null to ensure SW can own the SQ descriptor.
 */
static inline void set_psif_sq_hw__destroyed(
	volatile struct psif_sq_hw *ptr,
	u8 data)
{
	/* group=1 shift=27 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[1] = cpu_to_be64((be64_to_cpu(pte[1]) & 0xfffffffff7ffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 27));
}
static inline u8 get_psif_sq_hw__destroyed(volatile struct psif_sq_hw *ptr)
{
	/* group=1 shift=27 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[1]) >> 27) & 0x0000000000000001ull));
}

/* Software modified index pointing to the tail reecive entry in host memory. */
static inline void set_psif_rq_sw__tail_indx(
	volatile struct psif_rq_sw *ptr,
	u16 data)
{
	/* group=0 shift=32 bits=14 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xffffc000ffffffffull) |
		((((u64)(data)) & 0x0000000000003fffull) << 32));
}
static inline u16 get_psif_rq_sw__tail_indx(volatile struct psif_rq_sw *ptr)
{
	/* group=0 shift=32 bits=14 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u16)((be64_to_cpu(pte[0]) >> 32) & 0x0000000000003fffull));
}

/*
 * Hardware modified index pointing to the head of the receive queue. TSU is
 * using this to find the address of the receive queue entry.
 */
static inline void set_psif_rq_hw__head_indx(
	volatile struct psif_rq_hw *ptr,
	u16 data)
{
	/* group=0 shift=14 bits=14 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xfffffffff0003fffull) |
		((((u64)(data)) & 0x0000000000003fffull) << 14));
}
static inline u16 get_psif_rq_hw__head_indx(volatile struct psif_rq_hw *ptr)
{
	/* group=0 shift=14 bits=14 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u16)((be64_to_cpu(pte[0]) >> 14) & 0x0000000000003fffull));
}

/* The desciptor is valid. */
static inline void set_psif_rq_hw__valid(
	volatile struct psif_rq_hw *ptr,
	u8 data)
{
	/* group=3 shift=55 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[3] = cpu_to_be64((be64_to_cpu(pte[3]) & 0xff7fffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 55));
}
static inline u8 get_psif_rq_hw__valid(volatile struct psif_rq_hw *ptr)
{
	/* group=3 shift=55 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[3]) >> 55) & 0x0000000000000001ull));
}

/*
 * Receive queue entry ID. This is added to the receive completion using this
 * receive queue entry.
 */
static inline void set_psif_rq_entry__rqe_id(
	volatile struct psif_rq_entry *ptr,
	u64 data)
{
	/* group=0 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 0) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_rq_entry__rqe_id(volatile struct psif_rq_entry *ptr)
{
	/* group=0 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 0) + 0);
	return((u64)be64_to_cpu(*pte));
}

/*
 * This retry tag is the one used by tsu_rqs and added to the packets sent to
 * tsu_dma. It is the responsibility of tsu_rqs to update this retry tag
 * whenever the sq_sequence_number in QP state is equal to the one in the
 * request.
 */
static inline void set_psif_qp_core__retry_tag_committed(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=0 shift=0 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xfffffffffffffff8ull) |
		((((u64)(data)) & 0x0000000000000007ull) << 0));
}
static inline u8 get_psif_qp_core__retry_tag_committed(volatile struct psif_qp_core *ptr)
{
	/* group=0 shift=0 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 0) & 0x0000000000000007ull));
}

/*
 * This retry tag is updated by the error block when an error occur. If
 * tsu_rqs reads this retry tag and it is different than the
 * retry_tag_comitted, tsu_rqs must update retry_tag_comitted to the value of
 * retry_tag_err when the sq_sequence_number indicates this is the valid
 * request. The sq_sequence_number has been updated by tsu_err at the same
 * time the retry_tag_err is updated.
 */
static inline void set_psif_qp_core__retry_tag_err(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=0 shift=3 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xffffffffffffffc7ull) |
		((((u64)(data)) & 0x0000000000000007ull) << 3));
}
static inline u8 get_psif_qp_core__retry_tag_err(volatile struct psif_qp_core *ptr)
{
	/* group=0 shift=3 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 3) & 0x0000000000000007ull));
}

/*
 * Error retry counter initial value. Read by tsu_dma and used by tsu_cmpl to
 * calculate exp_backoff etc..
 */
static inline void set_psif_qp_core__error_retry_init(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=0 shift=32 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xfffffff8ffffffffull) |
		((((u64)(data)) & 0x0000000000000007ull) << 32));
}
static inline u8 get_psif_qp_core__error_retry_init(volatile struct psif_qp_core *ptr)
{
	/* group=0 shift=32 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 32) & 0x0000000000000007ull));
}

/*
 * Retry counter associated with retries to received NAK or implied NAK. If
 * it expires, a path migration will be attempted if it is armed, or the QP
 * will go to error state. Read by tsu_dma and used by tsu_cmpl.
 */
static inline void set_psif_qp_core__error_retry_count(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=0 shift=35 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xffffffc7ffffffffull) |
		((((u64)(data)) & 0x0000000000000007ull) << 35));
}
static inline u8 get_psif_qp_core__error_retry_count(volatile struct psif_qp_core *ptr)
{
	/* group=0 shift=35 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 35) & 0x0000000000000007ull));
}

/* A hit in the set locally spun out of tsu_cmpl is found. */
static inline void set_psif_qp_core__spin_hit(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=0 shift=39 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xffffff7fffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 39));
}
static inline u8 get_psif_qp_core__spin_hit(volatile struct psif_qp_core *ptr)
{
	/* group=0 shift=39 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 39) & 0x0000000000000001ull));
}

/*
 * Minium RNR NAK timeout. This is added to RNR NAK packets and the requester
 * receiving the RNR NAK must wait until the timer has expired before the
 * retry is sent.
 */
static inline void set_psif_qp_core__min_rnr_nak_time(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=1 shift=0 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[1] = cpu_to_be64((be64_to_cpu(pte[1]) & 0xffffffffffffffe0ull) |
		((((u64)(data)) & 0x000000000000001full) << 0));
}
static inline u8 get_psif_qp_core__min_rnr_nak_time(volatile struct psif_qp_core *ptr)
{
	/* group=1 shift=0 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[1]) >> 0) & 0x000000000000001full));
}

/* QP State for this QP. */
static inline void set_psif_qp_core__state(
	volatile struct psif_qp_core *ptr,
	enum psif_qp_state data)
{
	/* group=1 shift=5 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[1] = cpu_to_be64((be64_to_cpu(pte[1]) & 0xffffffffffffff1full) |
		((((u64)(data)) & 0x0000000000000007ull) << 5));
}
static inline enum psif_qp_state get_psif_qp_core__state(volatile struct psif_qp_core *ptr)
{
	/* group=1 shift=5 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_qp_state)((be64_to_cpu(pte[1]) >> 5) & 0x0000000000000007ull));
}

/* QP number for the remote node. */
static inline void set_psif_qp_core__remote_qp(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=1 shift=8 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[1] = cpu_to_be64((be64_to_cpu(pte[1]) & 0xffffffff000000ffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 8));
}
static inline u32 get_psif_qp_core__remote_qp(volatile struct psif_qp_core *ptr)
{
	/* group=1 shift=8 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[1]) >> 8) & 0x0000000000ffffffull));
}

static inline void set_psif_qp_core__retry_sq_seq(
	volatile struct psif_qp_core *ptr,
	u16 data)
{
	/* group=2 shift=32 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 2);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_qp_core__retry_sq_seq(volatile struct psif_qp_core *ptr)
{
	/* group=2 shift=32 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 2);
	return((u16)be16_to_cpu(*pte));
}

static inline void set_psif_qp_core__sq_seq(
	volatile struct psif_qp_core *ptr,
	u16 data)
{
	/* group=2 shift=48 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 0);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_qp_core__sq_seq(volatile struct psif_qp_core *ptr)
{
	/* group=2 shift=48 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 0);
	return((u16)be16_to_cpu(*pte));
}

/*
 * Magic number used to verify use of QP state. This is done by calculating a
 * checksum of the work request incorporating the magic number. This checksum
 * is checked against the checksum in the work request.
 */
static inline void set_psif_qp_core__magic(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=3 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 3) + 4);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_qp_core__magic(volatile struct psif_qp_core *ptr)
{
	/* group=3 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 3) + 4);
	return((u32)be32_to_cpu(*pte));
}

/*
 * Q-Key received in incoming IB packet is checked towards this Q-Key. Q-Key
 * used on transmit if top bit of Q-Key in WR is set.
 */
static inline void set_psif_qp_core__qkey(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=4 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 4) + 4);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_qp_core__qkey(volatile struct psif_qp_core *ptr)
{
	/* group=4 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 4) + 4);
	return((u32)be32_to_cpu(*pte));
}

/*
 * Sequence number of the last ACK received. Read and written by tsu_cmpl.
 * Used to verify that the received response packet is a valid response.
 */
static inline void set_psif_qp_core__last_acked_psn(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=4 shift=40 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[4] = cpu_to_be64((be64_to_cpu(pte[4]) & 0x000000ffffffffffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 40));
}
static inline u32 get_psif_qp_core__last_acked_psn(volatile struct psif_qp_core *ptr)
{
	/* group=4 shift=40 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[4]) >> 40) & 0x0000000000ffffffull));
}

/* Index to scatter element of in progress SEND. */
static inline void set_psif_qp_core__scatter_indx(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=5 shift=32 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[5] = cpu_to_be64((be64_to_cpu(pte[5]) & 0xffffffe0ffffffffull) |
		((((u64)(data)) & 0x000000000000001full) << 32));
}
static inline u8 get_psif_qp_core__scatter_indx(volatile struct psif_qp_core *ptr)
{
	/* group=5 shift=32 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[5]) >> 32) & 0x000000000000001full));
}

/*
 * Expected packet sequence number: Sequence number on next expected packet.
 */
static inline void set_psif_qp_core__expected_psn(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=5 shift=40 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[5] = cpu_to_be64((be64_to_cpu(pte[5]) & 0x000000ffffffffffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 40));
}
static inline u32 get_psif_qp_core__expected_psn(volatile struct psif_qp_core *ptr)
{
	/* group=5 shift=40 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[5]) >> 40) & 0x0000000000ffffffull));
}

/*
 * TSU quality of service level. Can take values indicating low latency and
 * high throughput. This is equivalent to high/low BAR when writing doorbells
 * to PSIF. The qosl bit in the doorbell request must match this bit in the
 * QP state, otherwise the QP must be put in error. This check only applies
 * to tsu_rqs.
 */
static inline void set_psif_qp_core__qosl(
	volatile struct psif_qp_core *ptr,
	enum psif_tsu_qos data)
{
	/* group=6 shift=49 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[6] = cpu_to_be64((be64_to_cpu(pte[6]) & 0xfffdffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 49));
}
static inline enum psif_tsu_qos get_psif_qp_core__qosl(volatile struct psif_qp_core *ptr)
{
	/* group=6 shift=49 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_tsu_qos)((be64_to_cpu(pte[6]) >> 49) & 0x0000000000000001ull));
}

/*
 * Migration state (migrated, re-arm and armed). Since path migration is
 * handled by tsu_qps, this is controlled by tsu_qps. XXX: Should error
 * handler also be able to change the path?
 */
static inline void set_psif_qp_core__mstate(
	volatile struct psif_qp_core *ptr,
	enum psif_migration data)
{
	/* group=6 shift=50 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[6] = cpu_to_be64((be64_to_cpu(pte[6]) & 0xfff3ffffffffffffull) |
		((((u64)(data)) & 0x0000000000000003ull) << 50));
}
static inline enum psif_migration get_psif_qp_core__mstate(volatile struct psif_qp_core *ptr)
{
	/* group=6 shift=50 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_migration)((be64_to_cpu(pte[6]) >> 50) & 0x0000000000000003ull));
}

/* This is an IB over IB QP. */
static inline void set_psif_qp_core__ipoib_enable(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=6 shift=53 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[6] = cpu_to_be64((be64_to_cpu(pte[6]) & 0xffdfffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 53));
}
static inline u8 get_psif_qp_core__ipoib_enable(volatile struct psif_qp_core *ptr)
{
	/* group=6 shift=53 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[6]) >> 53) & 0x0000000000000001ull));
}

/* IB defined capability enable for receiving Atomic operations. */
static inline void set_psif_qp_core__atomic_enable(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=6 shift=61 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[6] = cpu_to_be64((be64_to_cpu(pte[6]) & 0xdfffffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 61));
}
static inline u8 get_psif_qp_core__atomic_enable(volatile struct psif_qp_core *ptr)
{
	/* group=6 shift=61 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[6]) >> 61) & 0x0000000000000001ull));
}

/* IB defined capability enable for receiving RDMA WR. */
static inline void set_psif_qp_core__rdma_wr_enable(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=6 shift=62 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[6] = cpu_to_be64((be64_to_cpu(pte[6]) & 0xbfffffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 62));
}
static inline u8 get_psif_qp_core__rdma_wr_enable(volatile struct psif_qp_core *ptr)
{
	/* group=6 shift=62 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[6]) >> 62) & 0x0000000000000001ull));
}

/* IB defined capability enable for receiving RDMA RD. */
static inline void set_psif_qp_core__rdma_rd_enable(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=6 shift=63 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[6] = cpu_to_be64((be64_to_cpu(pte[6]) & 0x7fffffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 63));
}
static inline u8 get_psif_qp_core__rdma_rd_enable(volatile struct psif_qp_core *ptr)
{
	/* group=6 shift=63 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[6]) >> 63) & 0x0000000000000001ull));
}

/*
 * Transmit packet sequence number. Read and updated by tsu_dma before
 * sending packets to tsu_ibpb and tsu_cmpl.
 */
static inline void set_psif_qp_core__xmit_psn(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=7 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[7] = cpu_to_be64((be64_to_cpu(pte[7]) & 0xffffffffff000000ull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 0));
}
static inline u32 get_psif_qp_core__xmit_psn(volatile struct psif_qp_core *ptr)
{
	/* group=7 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[7]) >> 0) & 0x0000000000ffffffull));
}

/*
 * TSU Service Level used to decide the TSU VL for requests associated with
 * this QP.
 */
static inline void set_psif_qp_core__tsl(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=7 shift=55 bits=4 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[7] = cpu_to_be64((be64_to_cpu(pte[7]) & 0xf87fffffffffffffull) |
		((((u64)(data)) & 0x000000000000000full) << 55));
}
static inline u8 get_psif_qp_core__tsl(volatile struct psif_qp_core *ptr)
{
	/* group=7 shift=55 bits=4 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[7]) >> 55) & 0x000000000000000full));
}

/*
 * Maximum number of outstanding read or atomic requests allowed by the
 * remote HCA. Initialized by software.
 */
static inline void set_psif_qp_core__max_outstanding(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=7 shift=59 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[7] = cpu_to_be64((be64_to_cpu(pte[7]) & 0x07ffffffffffffffull) |
		((((u64)(data)) & 0x000000000000001full) << 59));
}
static inline u8 get_psif_qp_core__max_outstanding(volatile struct psif_qp_core *ptr)
{
	/* group=7 shift=59 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[7]) >> 59) & 0x000000000000001full));
}

/* Send Queue RNR retry count initialization value. */
static inline void set_psif_qp_core__rnr_retry_init(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=8 shift=32 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[8] = cpu_to_be64((be64_to_cpu(pte[8]) & 0xfffffff8ffffffffull) |
		((((u64)(data)) & 0x0000000000000007ull) << 32));
}
static inline u8 get_psif_qp_core__rnr_retry_init(volatile struct psif_qp_core *ptr)
{
	/* group=8 shift=32 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[8]) >> 32) & 0x0000000000000007ull));
}

/*
 * Retry counter associated with RNR NAK retries. If it expires, a path
 * migration will be attempted if it is armed, or the QP will go to error
 * state.
 */
static inline void set_psif_qp_core__rnr_retry_count(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=8 shift=35 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[8] = cpu_to_be64((be64_to_cpu(pte[8]) & 0xffffffc7ffffffffull) |
		((((u64)(data)) & 0x0000000000000007ull) << 35));
}
static inline u8 get_psif_qp_core__rnr_retry_count(volatile struct psif_qp_core *ptr)
{
	/* group=8 shift=35 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[8]) >> 35) & 0x0000000000000007ull));
}

/*
 * When set, RQS should only check that the orig_checksum is equal to magic
 * number. When not set, RQS should perform the checksum check towards the
 * checksum in the psif_wr.
 */
static inline void set_psif_qp_core__no_checksum(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=8 shift=39 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[8] = cpu_to_be64((be64_to_cpu(pte[8]) & 0xffffff7fffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 39));
}
static inline u8 get_psif_qp_core__no_checksum(volatile struct psif_qp_core *ptr)
{
	/* group=8 shift=39 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[8]) >> 39) & 0x0000000000000001ull));
}

/*
 * Transport type of the QP (RC, UC, UD, XRC, MANSP1). MANSP1 is set for
 * privileged QPs.
 */
static inline void set_psif_qp_core__transport_type(
	volatile struct psif_qp_core *ptr,
	enum psif_qp_trans data)
{
	/* group=9 shift=0 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[9] = cpu_to_be64((be64_to_cpu(pte[9]) & 0xfffffffffffffff8ull) |
		((((u64)(data)) & 0x0000000000000007ull) << 0));
}
static inline enum psif_qp_trans get_psif_qp_core__transport_type(volatile struct psif_qp_core *ptr)
{
	/* group=9 shift=0 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_qp_trans)((be64_to_cpu(pte[9]) >> 0) & 0x0000000000000007ull));
}

/*
 * This is an index to completion queue descriptor. The descriptor points to
 * a receive completion queue, which may or may not be the same as the send
 * completion queue. For XRC QPs, this field is written by the CQ descriptor
 * received by the XRCSRQ on the first packet. This way we don't need to look
 * up the XRCSRQ for every packet. of the message.
 */
static inline void set_psif_qp_core__rcv_cq_indx(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=9 shift=8 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[9] = cpu_to_be64((be64_to_cpu(pte[9]) & 0xffffffff000000ffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 8));
}
static inline u32 get_psif_qp_core__rcv_cq_indx(volatile struct psif_qp_core *ptr)
{
	/* group=9 shift=8 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[9]) >> 8) & 0x0000000000ffffffull));
}

/*
 * Number of bytes received of in progress RDMA Write or SEND. The data
 * received for SENDs and RDMA WR w/Imm are needed for completions. This
 * should be added to the msg_length.
 */
static inline void set_psif_qp_core__bytes_received(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=9 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 9) + 0);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_qp_core__bytes_received(volatile struct psif_qp_core *ptr)
{
	/* group=9 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 9) + 0);
	return((u32)be32_to_cpu(*pte));
}

/* This QP is running IP over IB. */
static inline void set_psif_qp_core__ipoib(
	volatile struct psif_qp_core *ptr,
	u8 data)
{
	/* group=10 shift=5 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[10] = cpu_to_be64((be64_to_cpu(pte[10]) & 0xffffffffffffffdfull) |
		((((u64)(data)) & 0x0000000000000001ull) << 5));
}
static inline u8 get_psif_qp_core__ipoib(volatile struct psif_qp_core *ptr)
{
	/* group=10 shift=5 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[10]) >> 5) & 0x0000000000000001ull));
}

/*
 * Combined 'Last Received MSN' and 'Last Outstanding MSN', used to maintain
 * 'spin set floor' and indicate 'all retries completed', respectively.
 */
static inline void set_psif_qp_core__last_received_outstanding_msn(
	volatile struct psif_qp_core *ptr,
	u16 data)
{
	/* group=11 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 11) + 6);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_qp_core__last_received_outstanding_msn(volatile struct psif_qp_core *ptr)
{
	/* group=11 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 11) + 6);
	return((u16)be16_to_cpu(*pte));
}

static inline void set_psif_qp_core__path_mtu(
	volatile struct psif_qp_core *ptr,
	enum psif_path_mtu data)
{
	/* group=13 shift=4 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[13] = cpu_to_be64((be64_to_cpu(pte[13]) & 0xffffffffffffff8full) |
		((((u64)(data)) & 0x0000000000000007ull) << 4));
}
static inline enum psif_path_mtu get_psif_qp_core__path_mtu(volatile struct psif_qp_core *ptr)
{
	/* group=13 shift=4 bits=3 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_path_mtu)((be64_to_cpu(pte[13]) >> 4) & 0x0000000000000007ull));
}

/* This PSN is committed - ACKs sent will contain this PSN. */
static inline void set_psif_qp_core__committed_received_psn(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=13 shift=8 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[13] = cpu_to_be64((be64_to_cpu(pte[13]) & 0xffffffff000000ffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 8));
}
static inline u32 get_psif_qp_core__committed_received_psn(volatile struct psif_qp_core *ptr)
{
	/* group=13 shift=8 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[13]) >> 8) & 0x0000000000ffffffull));
}

/*
 * Message sequence number used in AETH when sending ACKs. The number is
 * incremented every time a new inbound message is processed.
 */
static inline void set_psif_qp_core__msn(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=14 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[14] = cpu_to_be64((be64_to_cpu(pte[14]) & 0xffffffffff000000ull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 0));
}
static inline u32 get_psif_qp_core__msn(volatile struct psif_qp_core *ptr)
{
	/* group=14 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[14]) >> 0) & 0x0000000000ffffffull));
}

/*
 * This is an index to send completion queue descriptor. The descriptor
 * points to a send completion queue, which may or may not be the same as the
 * send completion queue.
 */
static inline void set_psif_qp_core__send_cq_indx(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=14 shift=24 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[14] = cpu_to_be64((be64_to_cpu(pte[14]) & 0xffff000000ffffffull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 24));
}
static inline u32 get_psif_qp_core__send_cq_indx(volatile struct psif_qp_core *ptr)
{
	/* group=14 shift=24 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[14]) >> 24) & 0x0000000000ffffffull));
}

/*
 * Committed MSN - the MSN of the newest committed request for this QP. Only
 * the bottom 16 bits of the MSN is used.
 */
static inline void set_psif_qp_core__last_committed_msn(
	volatile struct psif_qp_core *ptr,
	u16 data)
{
	/* group=14 shift=48 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 14) + 0);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_qp_core__last_committed_msn(volatile struct psif_qp_core *ptr)
{
	/* group=14 shift=48 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 14) + 0);
	return((u16)be16_to_cpu(*pte));
}

static inline void set_psif_qp_core__srq_pd(
	volatile struct psif_qp_core *ptr,
	u32 data)
{
	/* group=15 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[15] = cpu_to_be64((be64_to_cpu(pte[15]) & 0xffffffffff000000ull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 0));
}
static inline u32 get_psif_qp_core__srq_pd(volatile struct psif_qp_core *ptr)
{
	/* group=15 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[15]) >> 0) & 0x0000000000ffffffull));
}

static inline void set_psif_qp_path__remote_gid_0(
	volatile struct psif_qp_path *ptr,
	u64 data)
{
	/* group=0 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 0) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_qp_path__remote_gid_0(volatile struct psif_qp_path *ptr)
{
	/* group=0 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 0) + 0);
	return((u64)be64_to_cpu(*pte));
}

static inline void set_psif_qp_path__remote_gid_1(
	volatile struct psif_qp_path *ptr,
	u64 data)
{
	/* group=1 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 1) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_qp_path__remote_gid_1(volatile struct psif_qp_path *ptr)
{
	/* group=1 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 1) + 0);
	return((u64)be64_to_cpu(*pte));
}

static inline void set_psif_qp_path__remote_lid(
	volatile struct psif_qp_path *ptr,
	u16 data)
{
	/* group=2 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 6);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_qp_path__remote_lid(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 6);
	return((u16)be16_to_cpu(*pte));
}

static inline void set_psif_qp_path__port(
	volatile struct psif_qp_path *ptr,
	enum psif_port data)
{
	/* group=2 shift=17 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[2] = cpu_to_be64((be64_to_cpu(pte[2]) & 0xfffffffffffdffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 17));
}
static inline enum psif_port get_psif_qp_path__port(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=17 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_port)((be64_to_cpu(pte[2]) >> 17) & 0x0000000000000001ull));
}

static inline void set_psif_qp_path__loopback(
	volatile struct psif_qp_path *ptr,
	enum psif_loopback data)
{
	/* group=2 shift=18 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[2] = cpu_to_be64((be64_to_cpu(pte[2]) & 0xfffffffffffbffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 18));
}
static inline enum psif_loopback get_psif_qp_path__loopback(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=18 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_loopback)((be64_to_cpu(pte[2]) >> 18) & 0x0000000000000001ull));
}

static inline void set_psif_qp_path__use_grh(
	volatile struct psif_qp_path *ptr,
	enum psif_use_grh data)
{
	/* group=2 shift=19 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[2] = cpu_to_be64((be64_to_cpu(pte[2]) & 0xfffffffffff7ffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 19));
}
static inline enum psif_use_grh get_psif_qp_path__use_grh(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=19 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_use_grh)((be64_to_cpu(pte[2]) >> 19) & 0x0000000000000001ull));
}

static inline void set_psif_qp_path__sl(
	volatile struct psif_qp_path *ptr,
	u8 data)
{
	/* group=2 shift=20 bits=4 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[2] = cpu_to_be64((be64_to_cpu(pte[2]) & 0xffffffffff0fffffull) |
		((((u64)(data)) & 0x000000000000000full) << 20));
}
static inline u8 get_psif_qp_path__sl(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=20 bits=4 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[2]) >> 20) & 0x000000000000000full));
}

static inline void set_psif_qp_path__hoplmt(
	volatile struct psif_qp_path *ptr,
	u8 data)
{
	/* group=2 shift=28 bits=8 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[2] = cpu_to_be64((be64_to_cpu(pte[2]) & 0xfffffff00fffffffull) |
		((((u64)(data)) & 0x00000000000000ffull) << 28));
}
static inline u8 get_psif_qp_path__hoplmt(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=28 bits=8 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[2]) >> 28) & 0x00000000000000ffull));
}

static inline void set_psif_qp_path__flowlabel(
	volatile struct psif_qp_path *ptr,
	u32 data)
{
	/* group=2 shift=44 bits=20 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[2] = cpu_to_be64((be64_to_cpu(pte[2]) & 0x00000fffffffffffull) |
		((((u64)(data)) & 0x00000000000fffffull) << 44));
}
static inline u32 get_psif_qp_path__flowlabel(volatile struct psif_qp_path *ptr)
{
	/* group=2 shift=44 bits=20 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[2]) >> 44) & 0x00000000000fffffull));
}

static inline void set_psif_qp_path__local_ack_timeout(
	volatile struct psif_qp_path *ptr,
	u8 data)
{
	/* group=3 shift=27 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[3] = cpu_to_be64((be64_to_cpu(pte[3]) & 0xffffffff07ffffffull) |
		((((u64)(data)) & 0x000000000000001full) << 27));
}
static inline u8 get_psif_qp_path__local_ack_timeout(volatile struct psif_qp_path *ptr)
{
	/* group=3 shift=27 bits=5 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[3]) >> 27) & 0x000000000000001full));
}

static inline void set_psif_qp_path__ipd(
	volatile struct psif_qp_path *ptr,
	u8 data)
{
	/* group=3 shift=32 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 3) + 3);
	*pte = (data);
}
static inline u8 get_psif_qp_path__ipd(volatile struct psif_qp_path *ptr)
{
	/* group=3 shift=32 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 3) + 3);
	return((u8)(*pte));
}

/*
 * This is the LID path bits. This is used by tsu_ibpb when generating the
 * SLID in the packet, and it is used by tsu_rcv when checking the DLID.
 */
static inline void set_psif_qp_path__local_lid_path(
	volatile struct psif_qp_path *ptr,
	u8 data)
{
	/* group=3 shift=48 bits=7 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[3] = cpu_to_be64((be64_to_cpu(pte[3]) & 0xff80ffffffffffffull) |
		((((u64)(data)) & 0x000000000000007full) << 48));
}
static inline u8 get_psif_qp_path__local_lid_path(volatile struct psif_qp_path *ptr)
{
	/* group=3 shift=48 bits=7 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[3]) >> 48) & 0x000000000000007full));
}

static inline void set_psif_qp_path__pkey_indx(
	volatile struct psif_qp_path *ptr,
	u16 data)
{
	/* group=3 shift=55 bits=9 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[3] = cpu_to_be64((be64_to_cpu(pte[3]) & 0x007fffffffffffffull) |
		((((u64)(data)) & 0x00000000000001ffull) << 55));
}
static inline u16 get_psif_qp_path__pkey_indx(volatile struct psif_qp_path *ptr)
{
	/* group=3 shift=55 bits=9 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u16)((be64_to_cpu(pte[3]) >> 55) & 0x00000000000001ffull));
}

/* L-key state for this DMA validation entry */
static inline void set_psif_key__lkey_state(
	volatile struct psif_key *ptr,
	enum psif_dma_vt_key_states data)
{
	/* group=0 shift=60 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xcfffffffffffffffull) |
		((((u64)(data)) & 0x0000000000000003ull) << 60));
}
static inline enum psif_dma_vt_key_states get_psif_key__lkey_state(volatile struct psif_key *ptr)
{
	/* group=0 shift=60 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_dma_vt_key_states)((be64_to_cpu(pte[0]) >> 60) & 0x0000000000000003ull));
}

/* R-key state for this DMA validation entry */
static inline void set_psif_key__rkey_state(
	volatile struct psif_key *ptr,
	enum psif_dma_vt_key_states data)
{
	/* group=0 shift=62 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0x3fffffffffffffffull) |
		((((u64)(data)) & 0x0000000000000003ull) << 62));
}
static inline enum psif_dma_vt_key_states get_psif_key__rkey_state(volatile struct psif_key *ptr)
{
	/* group=0 shift=62 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_dma_vt_key_states)((be64_to_cpu(pte[0]) >> 62) & 0x0000000000000003ull));
}

/* Length of memory region this validation entry is associated with. */
static inline void set_psif_key__length(
	volatile struct psif_key *ptr,
	u64 data)
{
	/* group=1 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 1) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_key__length(volatile struct psif_key *ptr)
{
	/* group=1 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 1) + 0);
	return((u64)be64_to_cpu(*pte));
}

static inline void set_psif_key__mmu_context(
	volatile struct psif_key *ptr,
	u64 data)
{
	/* group=2 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 2) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_key__mmu_context(volatile struct psif_key *ptr)
{
	/* group=2 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 2) + 0);
	return((u64)be64_to_cpu(*pte));
}

static inline void set_psif_key__base_addr(
	volatile struct psif_key *ptr,
	u64 data)
{
	/* group=3 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 3) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_key__base_addr(volatile struct psif_key *ptr)
{
	/* group=3 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 3) + 0);
	return((u64)be64_to_cpu(*pte));
}

/* sequence number for sanity checking */
static inline void set_psif_eq_entry__seq_num(
	volatile struct psif_eq_entry *ptr,
	u32 data)
{
	/* group=7 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 7) + 4);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_eq_entry__seq_num(volatile struct psif_eq_entry *ptr)
{
	/* group=7 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 7) + 4);
	return((u32)be32_to_cpu(*pte));
}

/* enum psif_epsc_csr_opcode from request */
static inline void set_psif_epsc_csr_rsp__opcode(
	volatile struct psif_epsc_csr_rsp *ptr,
	enum psif_epsc_csr_opcode data)
{
	/* group=0 shift=48 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 0) + 1);
	*pte = (data);
}
static inline enum psif_epsc_csr_opcode get_psif_epsc_csr_rsp__opcode(volatile struct psif_epsc_csr_rsp *ptr)
{
	/* group=0 shift=48 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 0) + 1);
	return((enum psif_epsc_csr_opcode)(*pte));
}

/* Sequence number from request */
static inline void set_psif_epsc_csr_rsp__seq_num(
	volatile struct psif_epsc_csr_rsp *ptr,
	u64 data)
{
	/* group=3 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 3) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_epsc_csr_rsp__seq_num(volatile struct psif_epsc_csr_rsp *ptr)
{
	/* group=3 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 3) + 0);
	return((u64)be64_to_cpu(*pte));
}

/* Sequence number - included in response */
static inline void set_psif_epsc_csr_req__seq_num(
	volatile struct psif_epsc_csr_req *ptr,
	u16 data)
{
	/* group=0 shift=32 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 2);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_epsc_csr_req__seq_num(volatile struct psif_epsc_csr_req *ptr)
{
	/* group=0 shift=32 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 0) + 2);
	return((u16)be16_to_cpu(*pte));
}

static inline void set_psif_epsc_csr_req__opcode(
	volatile struct psif_epsc_csr_req *ptr,
	enum psif_epsc_csr_opcode data)
{
	/* group=0 shift=56 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 0) + 0);
	*pte = (data);
}
static inline enum psif_epsc_csr_opcode get_psif_epsc_csr_req__opcode(volatile struct psif_epsc_csr_req *ptr)
{
	/* group=0 shift=56 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 0) + 0);
	return((enum psif_epsc_csr_opcode)(*pte));
}

/* Index to completion elements added by SW. */
static inline void set_psif_cq_sw__head_indx(
	volatile struct psif_cq_sw *ptr,
	u32 data)
{
	/* group=0 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 0) + 0);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_cq_sw__head_indx(volatile struct psif_cq_sw *ptr)
{
	/* group=0 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 0) + 0);
	return((u32)be32_to_cpu(*pte));
}

/*
 * EPS-A core number completions are forwarded to if the proxy_enabled bit is
 * set.
 */
static inline void set_psif_cq_hw__eps_core(
	volatile struct psif_cq_hw *ptr,
	enum psif_eps_a_core data)
{
	/* group=0 shift=52 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xffcfffffffffffffull) |
		((((u64)(data)) & 0x0000000000000003ull) << 52));
}
static inline enum psif_eps_a_core get_psif_cq_hw__eps_core(volatile struct psif_cq_hw *ptr)
{
	/* group=0 shift=52 bits=2 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((enum psif_eps_a_core)((be64_to_cpu(pte[0]) >> 52) & 0x0000000000000003ull));
}

/*
 * If set, this completion queue is proxy enabled and should send completions
 * to EPS core indicated by the eps_core field.
 */
static inline void set_psif_cq_hw__proxy_en(
	volatile struct psif_cq_hw *ptr,
	u8 data)
{
	/* group=0 shift=54 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xffbfffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 54));
}
static inline u8 get_psif_cq_hw__proxy_en(volatile struct psif_cq_hw *ptr)
{
	/* group=0 shift=54 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 54) & 0x0000000000000001ull));
}

/* The descriptor is valid. */
static inline void set_psif_cq_hw__valid(
	volatile struct psif_cq_hw *ptr,
	u8 data)
{
	/* group=0 shift=60 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[0] = cpu_to_be64((be64_to_cpu(pte[0]) & 0xefffffffffffffffull) |
		((((u64)(data)) & 0x0000000000000001ull) << 60));
}
static inline u8 get_psif_cq_hw__valid(volatile struct psif_cq_hw *ptr)
{
	/* group=0 shift=60 bits=1 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u8)((be64_to_cpu(pte[0]) >> 60) & 0x0000000000000001ull));
}

/*
 * VA or PA of the base of the completion queue. If PA the MMU context above
 * will be a bypass context. Updated by software. The head and tail pointers
 * can be calculated by the following calculations: Address = base_ptr +
 * (head * ($bits(completion_entry_t)/8 ) Head Pointer and Tail Pointer will
 * use the same MMU context as the base, and all need to be VA from one
 * address space, or all need to be PA. In typical use, to allow direct user
 * access to the head and tail pointer VAs are used.
 */
static inline void set_psif_cq_hw__base_addr(
	volatile struct psif_cq_hw *ptr,
	u64 data)
{
	/* group=2 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 2) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_cq_hw__base_addr(volatile struct psif_cq_hw *ptr)
{
	/* group=2 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 2) + 0);
	return((u64)be64_to_cpu(*pte));
}

/* Index to completion elements to be consumed by HW. */
static inline void set_psif_cq_hw__tail_indx(
	volatile struct psif_cq_hw *ptr,
	u32 data)
{
	/* group=3 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 3) + 0);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_cq_hw__tail_indx(volatile struct psif_cq_hw *ptr)
{
	/* group=3 shift=32 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 3) + 0);
	return((u32)be32_to_cpu(*pte));
}

/*
 * Work queue completion ID. For receive completions this is the entry number
 * in the receive queue and the receive queue descriptor index. For send
 * completions this is the sq_sequence number.
 */
static inline void set_psif_cq_entry__wc_id(
	volatile struct psif_cq_entry *ptr,
	u64 data)
{
	/* group=0 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 0) + 0);
	*pte = cpu_to_be64(data);
}
static inline u64 get_psif_cq_entry__wc_id(volatile struct psif_cq_entry *ptr)
{
	/* group=0 shift=0 bits=64 */
	volatile u64 * const pte = (u64 *)((u8 *)((__be64 *)ptr + 0) + 0);
	return((u64)be64_to_cpu(*pte));
}

static inline void set_psif_cq_entry__qp(
	volatile struct psif_cq_entry *ptr,
	u32 data)
{
	/* group=1 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	pte[1] = cpu_to_be64((be64_to_cpu(pte[1]) & 0xffffffffff000000ull) |
		((((u64)(data)) & 0x0000000000ffffffull) << 0));
}
static inline u32 get_psif_cq_entry__qp(volatile struct psif_cq_entry *ptr)
{
	/* group=1 shift=0 bits=24 */
	volatile __be64 *const pte = (__be64 *)ptr;
	return((u32)((be64_to_cpu(pte[1]) >> 0) & 0x0000000000ffffffull));
}

static inline void set_psif_cq_entry__opcode(
	volatile struct psif_cq_entry *ptr,
	enum psif_wc_opcode data)
{
	/* group=1 shift=24 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 1) + 4);
	*pte = (data);
}
static inline enum psif_wc_opcode get_psif_cq_entry__opcode(volatile struct psif_cq_entry *ptr)
{
	/* group=1 shift=24 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 1) + 4);
	return((enum psif_wc_opcode)(*pte));
}

static inline void set_psif_cq_entry__status(
	volatile struct psif_cq_entry *ptr,
	enum psif_wc_status data)
{
	/* group=2 shift=24 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 2) + 4);
	*pte = (data);
}
static inline enum psif_wc_status get_psif_cq_entry__status(volatile struct psif_cq_entry *ptr)
{
	/* group=2 shift=24 bits=8 */
	volatile u8 * const pte = (u8 *)((u8 *)((__be64 *)ptr + 2) + 4);
	return((enum psif_wc_status)(*pte));
}

/* sequence number for sanity checking */
static inline void set_psif_cq_entry__seq_num(
	volatile struct psif_cq_entry *ptr,
	u32 data)
{
	/* group=7 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 7) + 4);
	*pte = cpu_to_be32(data);
}
static inline u32 get_psif_cq_entry__seq_num(volatile struct psif_cq_entry *ptr)
{
	/* group=7 shift=0 bits=32 */
	volatile u32 * const pte = (u32 *)((u8 *)((__be64 *)ptr + 7) + 4);
	return((u32)be32_to_cpu(*pte));
}

static inline void set_psif_ah__remote_lid(
	volatile struct psif_ah *ptr,
	u16 data)
{
	/* group=2 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 6);
	*pte = cpu_to_be16(data);
}
static inline u16 get_psif_ah__remote_lid(volatile struct psif_ah *ptr)
{
	/* group=2 shift=0 bits=16 */
	volatile u16 * const pte = (u16 *)((u8 *)((__be64 *)ptr + 2) + 6);
	return((u16)be16_to_cpu(*pte));
}
#if defined(HOST_LITTLE_ENDIAN)
#include "psif_hw_setget_le.h"
#elif defined(HOST_BIG_ENDIAN)
#include "psif_hw_setget_be.h"
#else
#error "Could not determine byte order in psif_hw_setget.h !?"
#endif




#endif	/* _PSIF_HW_SETGET_H */
