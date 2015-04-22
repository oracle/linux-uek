/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#ifndef _HPI_H
#define	_HPI_H

#include "../hxge_defs.h"

typedef	uint32_t hpi_status_t;
typedef void * hpi_handle_t;

/* Common Block ID */
#define	VMAC_BLK_ID			0x1
#define	TXDMA_BLK_ID			0x2
#define	RXDMA_BLK_ID			0x3
#define	PFC_BLK_ID			0x4
#define	VIR_BLK_ID			0x5
#define	PEU_BLK_ID			0x6

/* Common HW error code */
/* HW unable to exit from reset state. */
#define	RESET_FAILED			0x81

/* Write operation failed on indirect write. */
#define	WRITE_FAILED			0x82
/* Read operation failed on indirect read.	 */
#define	READ_FAILED			0x83

/* Error code boundary */

#define	COMMON_SW_ERR_START		0x40
#define	COMMON_SW_ERR_END		0x4f
#define	BLK_SPEC_SW_ERR_START		0x50
#define	BLK_SPEC_SW_ERR_END		0x7f
#define	COMMON_HW_ERR_START		0x80
#define	COMMON_HW_ERR_END		0x8f
#define	BLK_SPEC_HW_ERR_START		0x90
#define	BLK_SPEC_HW_ERR_END		0xbf

#define	IS_PORT				0x00100000
#define	IS_CHAN				0x00200000

/* Common SW errors code */

#define	PORT_INVALID			0x41	/* Invalid port number */
#define	CHANNEL_INVALID			0x42	/* Invalid dma channel number */
#define	OPCODE_INVALID			0x43	/* Invalid opcode */
#define	REGISTER_INVALID		0x44	/* Invalid register number */
#define	COUNTER_INVALID			0x45	/* Invalid counter number */
#define	CONFIG_INVALID			0x46	/* Invalid config input */
#define	LOGICAL_PAGE_INVALID		0x47	/* Invalid logical page # */
#define	VLAN_INVALID			0x48	/* Invalid Vlan ID */
#define	RDC_TAB_INVALID			0x49	/* Invalid RDC Group Number */
#define	LOCATION_INVALID		0x4a	/* Invalid Entry Location */

#define	HPI_SUCCESS			0		/* Operation succeed */
#define	HPI_FAILURE			0x80000000	/* Operation failed */

#define	HPI_CNT_CLR_VAL			0

/*
 * Block identifier starts at bit 8.
 */
#define	HPI_BLOCK_ID_SHIFT		8

/*
 * Port, channel and misc. information starts at bit 12.
 */
#define	HPI_PORT_CHAN_SHIFT			12

/*
 * Software Block specific error codes start at 0x50.
 */
#define	HPI_BK_ERROR_START		0x50

/*
 * Hardware block specific error codes start at 0x90.
 */
#define	HPI_BK_HW_ER_START		0x90

/* Structures for register tracing */

typedef struct _rt_buf {
	uint32_t	ctl_addr;
	uint32_t	val_l32;
	uint32_t	val_h32;
} rt_buf_t;

/*
 * Control Address field format
 *
 * Bit 0 - 23: Address
 * Bit 24 - 25: Function Number
 * Bit 26 - 29: Instance Number
 * Bit 30: Read/Write Direction bit
 * Bit 31: Invalid bit
 */

#define	MAX_RTRACE_ENTRIES	1024
#define	MAX_RTRACE_IOC_ENTRIES	64
#define	TRACE_ADDR_MASK		0x00FFFFFF
#define	TRACE_FUNC_MASK		0x03000000
#define	TRACE_INST_MASK		0x3C000000
#define	TRACE_CTL_WR		0x40000000
#define	TRACE_CTL_INVALID	0x80000000
#define	TRACE_FUNC_SHIFT	24
#define	TRACE_INST_SHIFT	26
#define	MSG_BUF_SIZE		1024


typedef struct _rtrace {
	uint16_t	next_idx;
	uint16_t	last_idx;
	boolean_t	wrapped;
	rt_buf_t	buf[MAX_RTRACE_ENTRIES];
} rtrace_t;

typedef struct _err_inject {
	uint8_t		blk_id;
	uint8_t		chan;
	uint32_t	err_id;
	uint32_t	control;
} err_inject_t;

/* Configuration options */
typedef enum config_op {
	DISABLE = 0,
	ENABLE,
	INIT
} config_op_t;

/* I/O options */
typedef enum io_op {
	OP_SET = 0,
	OP_GET,
	OP_UPDATE,
	OP_CLEAR
} io_op_t;

/* Counter options */
typedef enum counter_op {
	SNAP_STICKY = 0,
	SNAP_ACCUMULATE,
	CLEAR
} counter_op_t;

/* HPI attribute */
typedef struct _hpi_attr_t {
	uint32_t type;
	uint32_t idata[16];
	uint32_t odata[16];
} hpi_attr_t;

/* HPI Counter */
typedef struct _hpi_counter_t {
	uint32_t id;
	char *name;
	uint32_t val;
} hpi_counter_t;

/*
 * Commmon definitions for HPI RXDMA and TXDMA functions.
 */
typedef struct _dma_log_page {
	uint8_t			page_num;
	boolean_t		valid;
	uint8_t			func_num;
	uint64_t		mask;
	uint64_t		value;
	uint64_t		reloc;
} dma_log_page_t, *p_dma_log_page_t;

extern	rtrace_t hpi_rtracebuf;
void hpi_rtrace_buf_init(rtrace_t *rt);
void hpi_rtrace_update(boolean_t wr, rtrace_t *rt,
			uint32_t addr, uint64_t val);
void hpi_rtrace_buf_init(rtrace_t *rt);

void hpi_debug_msg(uint64_t level, char *fmt, ...);

#ifdef DBG	
#define	HPI_DEBUG_MSG(params) hpi_debug_msg params
#else
#define	HPI_DEBUG_MSG(params)
#endif

#define	HPI_ERROR_MSG(params) hpi_debug_msg params
#define	HPI_REG_DUMP_MSG(params) hpi_debug_msg params

#ifdef DBG
#define HPI_DEBUG(args...) printk(KERN_DEBUG "hpi: " __FUNCTION__ , ##args)
#else
#define HPI_DEBUG(args...)
#endif

#define HPI_ERR(args...) printk(KERN_ERR "hpi: " __FUNCTION__ , ##args)

#endif	/* _HPI_H */
