/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*		Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2015 Cavium, Inc.
*
* This file is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License, Version 2, as
* published by the Free Software Foundation.
*
* This file is distributed in the hope that it will be useful, but
* AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
* of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
* NONINFRINGEMENT.	See the GNU General Public License for more
* details.
*
* This file may also be available under a different license from Cavium.
* Contact Cavium, Inc. for more information
**********************************************************************/

#ifndef __CAVIUM_PTP_REGS_H__
#define __CAVIUM_PTP_REGS_H__

#define PTP_CLOCK_CFG			(0xF00ULL)
#define PTP_CLOCK_LO			(0xF08ULL)
#define PTP_CLOCK_HI			(0xF10ULL)
#define PTP_CLOCK_COMP			(0xF18ULL)
#define PTP_TIMESTAMP			(0xF20ULL)
#define PTP_EVT_CNT			(0xF28ULL)
#define PTP_CKOUT_THRESH_LO		(0xF30ULL)
#define PTP_CKOUT_THRESH_HI		(0xF38ULL)
#define PTP_CKOUT_HI_INCR		(0xF40ULL)
#define PTP_CKOUT_LO_INCR		(0xF48ULL)
#define PTP_PPS_THRESH_LO		(0xF50ULL)
#define PTP_PPS_THRESH_HI		(0xF58ULL)
#define PTP_PPS_HI_INCR			(0xF60ULL)
#define PTP_PPS_LO_INCR			(0xF68ULL)
#define PTP_INT				(0xF70ULL)
#define PTP_INT_W1S			(0xF78ULL)
#define PTP_DPLL_INCR			(0xF80ULL)
#define PTP_DPLL_ERR_THRESH		(0xF88ULL)
#define PTP_DPLL_ERR_INT		(0xF90ULL)
#define PTP_INT_ENA_W1C			(0xFA0ULL)
#define PTP_INT_ENA_W1S			(0xFA8ULL)

/* ***********************************************************************
 * REGISTERS */

union ptp_clock_cfg {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	ptp_en		: 1;
		uint64_t	ext_clk_en	: 1;
		uint64_t	ext_clk_in	: 6;
		uint64_t	tstmp_en	: 1;
		uint64_t	tstmp_edge	: 1;
		uint64_t	tstmp_in	: 6;
		uint64_t	evcnt_en	: 1;
		uint64_t	evcnt_edge	: 1;
		uint64_t	evcnt_in	: 6;
		uint64_t	ckout_en	: 1;
		uint64_t	ckout_inv	: 1;
		uint64_t	rsvd2		: 4;
		uint64_t	pps_en		: 1;
		uint64_t	pps_inv		: 1;
		uint64_t	rsvd1		: 6;
		uint64_t	ext_clk_edge	: 2;
		uint64_t	ckout		: 1;
		uint64_t	pps		: 1;
		uint64_t	rsvd0		: 22;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 22;
		uint64_t	pps		: 1;
		uint64_t	ckout		: 1;
		uint64_t	ext_clk_edge	: 2;
		uint64_t	rsvd1		: 6;
		uint64_t	pps_inv		: 1;
		uint64_t	pps_en		: 1;
		uint64_t	rsvd2		: 4;
		uint64_t	ckout_inv	: 1;
		uint64_t	ckout_en	: 1;
		uint64_t	evcnt_in	: 6;
		uint64_t	evcnt_edge	: 1;
		uint64_t	evcnt_en	: 1;
		uint64_t	tstmp_in	: 6;
		uint64_t	tstmp_edge	: 1;
		uint64_t	tstmp_en	: 1;
		uint64_t	ext_clk_in	: 6;
		uint64_t	ext_clk_en	: 1;
		uint64_t	ptp_en		: 1;
#endif
	} __packed s;
};

union ptp_clock_lo {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	rsvd0		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_clock_hi {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#endif
	} __packed s;
};

union ptp_clock_comp {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	nanosec		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_timestamp {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#endif
	} __packed s;
};

union ptp_evt_cnt {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	cntr		: 64;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	cntr		: 64;
#endif
	} __packed s;
};

union ptp_ckout_thresh_lo {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	rsvd0		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_ckout_thresh_hi {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#endif
	} __packed s;
};

union ptp_ckout_hi_incr {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	nanosec		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_ckout_lo_incr {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	nanosec		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_pps_thresh_lo {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	rsvd0		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_pps_thresh_hi {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 64;
#endif
	} __packed s;
};

union ptp_pps_hi_incr {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	nanosec		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_pps_lo_incr {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	nanosec		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_int {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	evt_int		: 1;
		uint64_t	dpll_int	: 1;
		uint64_t	rsvd0		: 62;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 62;
		uint64_t	dpll_int	: 1;
		uint64_t	evt_int		: 1;
#endif
	} __packed s;
};

union ptp_int_w1s {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	evt_int		: 1;
		uint64_t	dpll_int	: 1;
		uint64_t	rsvd0		: 62;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 62;
		uint64_t	dpll_int	: 1;
		uint64_t	evt_int		: 1;
#endif
	} __packed s;
};

union ptp_dpll_incr {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	frnanosec	: 32;
		uint64_t	nanosec		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	nanosec		: 32;
		uint64_t	frnanosec	: 32;
#endif
	} __packed s;
};

union ptp_dpll_err_thresh {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	min		: 32;
		uint64_t	max		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	max		: 32;
		uint64_t	min		: 32;
#endif
	} __packed s;
};

union ptp_dpll_err_int {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 32;
		uint64_t	n_sclk		: 32;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	n_sclk		: 32;
		uint64_t	rsvd0		: 32;
#endif
	} __packed s;
};

union ptp_int_ena_w1c {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	evt_int		: 1;
		uint64_t	dpll_int	: 1;
		uint64_t	rsvd0		: 62;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 62;
		uint64_t	dpll_int	: 1;
		uint64_t	evt_int		: 1;
#endif
	} __packed s;
};

union ptp_int_ena_w1s {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	evt_int		: 1;
		uint64_t	dpll_int	: 1;
		uint64_t	rsvd0		: 62;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 62;
		uint64_t	dpll_int	: 1;
		uint64_t	evt_int		: 1;
#endif
	} __packed s;
};

union ptp_msix_vecx_addr {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	secvec		: 1;
		uint64_t	rsvd1		: 1;
		uint64_t	addr		: 47;
		uint64_t	rsvd0		: 15;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 15;
		uint64_t	addr		: 47;
		uint64_t	rsvd1		: 1;
		uint64_t	secvec		: 1;
#endif
	} __packed s;
};

union ptp_msix_vecx_ctl {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	data		: 20;
		uint64_t	rsvd1		: 12;
		uint64_t	mask		: 1;
		uint64_t	rsvd0		: 31;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	rsvd0		: 31;
		uint64_t	mask		: 1;
		uint64_t	rsvd1		: 12;
		uint64_t	data		: 20;
#endif
	} __packed s;
};

union ptp_msix_pbax {
	uint64_t u64;
	uint32_t u32[2];
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint64_t	pend		: 64;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint64_t	pend		: 64;
#endif
	} __packed s;
};

#endif /* __CAVIUM_PTP_REGS_H__ */
