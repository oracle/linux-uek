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

#ifndef _HPI_RXDMA_H
#define	_HPI_RXDMA_H

#include "hpi.h"
#include "../hxge_defs.h"
#include "../hxge_rdc_hw.h"

#define	RXDMA_CFIG2_MBADDR_L_SHIFT	6	/* bit 31:6 */
#define	RXDMA_CFIG2_MBADDR_L_MASK	0x00000000ffffffc0ULL

#define	RBR_CFIG_A_STDADDR_MASK		0x000000000003ffc0ULL
#define	RBR_CFIG_A_STDADDR_BASE_MASK    0x00000ffffffc0000ULL

#define	RCRCFIG_A_STADDR_SHIFT		6	/* bit 18:6 */
#define	RCRCFIG_A_STADDR_MASK		0x000000000007FFC0ULL
#define	RCRCFIG_A_STADDR_BASE_SHIF	19	/* bit 43:19 */
#define	RCRCFIG_A_STADDR_BASE_MASK	0x00000FFFFFF80000ULL
#define	RCRCFIG_A_LEN_SHIF		48	/* bit 63:48 */
#define	RCRCFIG_A_LEN_MASK		0xFFFF000000000000ULL

#define	RCR_FLSH_SHIFT			0	/* RW, bit 0:0 */
#define	RCR_FLSH_SET			0x0000000000000001ULL
#define	RCR_FLSH_MASK			0x0000000000000001ULL

#define	RBR_CFIG_A_LEN_SHIFT		48	/* bits 63:48 */
#define	RBR_CFIG_A_LEN_MASK		0xFFFF000000000000ULL

#define  RXDMA_RESET_TRY_COUNT  5
#define  RXDMA_RESET_DELAY      5

#define  RXDMA_OP_DISABLE       0
#define  RXDMA_OP_ENABLE        1
#define  RXDMA_OP_RESET         2

#define  RCR_TIMEOUT_ENABLE     1
#define  RCR_TIMEOUT_DISABLE    2
#define  RCR_THRESHOLD          4


/*
 * Buffer block descriptor
 */
typedef struct _rx_desc_t {
	uint32_t	block_addr;
} rx_desc_t, *p_rx_desc_t;

/*
 * RXDMA HPI defined control types.
 */
typedef	enum _rxdma_cs_cntl_e {
	RXDMA_CS_CLEAR_ALL		= 0x1,
	RXDMA_MEX_SET			= 0x2,
	RXDMA_RCRTO_CLEAR		= 0x4,
	RXDMA_RCR_SFULL_CLEAR		= 0x8,
	RXDMA_RCR_FULL_CLEAR		= 0x10,
	RXDMA_RBR_PRE_EMPTY_CLEAR	= 0x20,
	RXDMA_RBR_EMPTY_CLEAR		= 0x40
} rxdma_cs_cntl_t;

typedef union _rcr_addr44 {
	uint64_t	addr;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t rsrvd:20;
		uint32_t hdw:25;
		uint32_t ldw:19;
#else
		uint32_t ldw:19;
		uint32_t hdw:25;
		uint32_t rsrvd:20;
#endif
	} bits;
} rcr_addr44_t;

typedef union _rbr_addr44 {
	uint64_t	addr;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t rsrvd:20;
		uint32_t hdw:26;
		uint32_t ldw:18;
#else
		uint32_t ldw:18;
		uint32_t hdw:26;
		uint32_t rsrvd:20;
#endif
	} bits;
} rbr_addr44_t;

typedef enum _bsize {
	SIZE_0B = 0x0,
	SIZE_64B = 64,
	SIZE_128B = 128,
	SIZE_192B = 192,
	SIZE_256B = 256,
	SIZE_512B = 512,
	SIZE_1KB = 1024,
	SIZE_2KB = 2048,
	SIZE_4KB = 4096,
	SIZE_8KB = 8192,
	SIZE_16KB = 16384,
	SIZE_32KB = 32668
} bsize_t;

typedef struct _rdc_desc_cfg_t {
	uint8_t mbox_enable;		/* Enable full (18b) header */
	uint8_t full_hdr;		/* Enable full (18b) header */
	uint8_t offset;			/* 64 byte offsets */
	uint8_t valid2;			/* size 2 is valid */
	bsize_t size2;			/* Size 2 length */
	uint8_t valid1;			/* size 1 is valid */
	bsize_t size1;			/* Size 1 length */
	uint8_t valid0;			/* size 0 is valid */
	bsize_t size0;			/* Size 1 length */
	bsize_t page_size;		/* Page or buffer Size */
	uint8_t	rcr_timeout_enable;
	uint8_t	rcr_timeout;
	uint16_t rcr_threshold;
	uint16_t rcr_len;		/* RBR Descriptor size (entries) */
	uint16_t rbr_len;		/* RBR Descriptor size (entries) */
	uint64_t mbox_addr;		/* Mailbox Address */
	uint64_t rcr_addr;		/* RCR Address */
	uint64_t rbr_addr;		/* RBB Address */
} rdc_desc_cfg_t;


/*
 * Register offset (0x800 bytes for each channel) for receive ring registers.
 */
#define	HXGE_RXDMA_OFFSET(x, v, channel) (x + \
		(!v ? DMC_OFFSET(channel) : \
		    RDMC_PIOVADDR_OFFSET(channel)))

#define	RXDMA_REG_READ64(handle, reg, channel, data_p) \
do {\
	HXGE_REG_RD64(handle, (HXGE_RXDMA_OFFSET(reg, 0,\
		channel)), (data_p));\
} while(0)

#define	RXDMA_REG_READ32(handle, reg, channel, data_p) \
	HXGE_REG_RD32(handle, (HXGE_RXDMA_OFFSET(reg, 0,\
		channel)), (data_p))

#define	RXDMA_REG_WRITE64(handle, reg, channel, data)\
do {\
	HXGE_REG_WR64(handle, (HXGE_RXDMA_OFFSET(reg, 0,\
		channel)), (data));\
} while(0)

/*
 * RX HPI error codes
 */
#define	RXDMA_ER_ST			(RXDMA_BLK_ID << HPI_BLOCK_ID_SHIFT)
#define	RXDMA_ID_SHIFT(n)		(n << HPI_PORT_CHAN_SHIFT)

#define	HPI_RXDMA_ERROR			RXDMA_ER_ST

#define	HPI_RXDMA_SW_PARAM_ERROR	(HPI_RXDMA_ERROR | 0x40)
#define	HPI_RXDMA_HW_ERROR		(HPI_RXDMA_ERROR | 0x80)

#define	HPI_RXDMA_RDC_INVALID		(HPI_RXDMA_ERROR | CHANNEL_INVALID)
#define	HPI_RXDMA_PAGE_INVALID		(HPI_RXDMA_ERROR | LOGICAL_PAGE_INVALID)
#define	HPI_RXDMA_RESET_ERR		(HPI_RXDMA_HW_ERROR | RESET_FAILED)
#define	HPI_RXDMA_DISABLE_ERR		(HPI_RXDMA_HW_ERROR | 0x0000a)
#define	HPI_RXDMA_ENABLE_ERR		(HPI_RXDMA_HW_ERROR | 0x0000b)
#define	HPI_RXDMA_FUNC_INVALID		(HPI_RXDMA_SW_PARAM_ERROR | 0x0000a)
#define	HPI_RXDMA_BUFSZIE_INVALID	(HPI_RXDMA_SW_PARAM_ERROR | 0x0000b)
#define	HPI_RXDMA_RBRSZIE_INVALID	(HPI_RXDMA_SW_PARAM_ERROR | 0x0000c)
#define	HPI_RXDMA_RCRSZIE_INVALID	(HPI_RXDMA_SW_PARAM_ERROR | 0x0000d)
#define	HPI_RXDMA_PORT_INVALID		(HPI_RXDMA_ERROR | PORT_INVALID)
#define	HPI_RXDMA_TABLE_INVALID		(HPI_RXDMA_ERROR | RDC_TAB_INVALID)

#define	HPI_RXDMA_CHANNEL_INVALID(n)	(RXDMA_ID_SHIFT(n) |	\
					HPI_RXDMA_ERROR | CHANNEL_INVALID)
#define	HPI_RXDMA_OPCODE_INVALID(n)	(RXDMA_ID_SHIFT(n) |	\
					HPI_RXDMA_ERROR | OPCODE_INVALID)

#define	HPI_RXDMA_ERROR_ENCODE(err, rdc)	\
	(RXDMA_ID_SHIFT(rdc) | RXDMA_ER_ST | err)

#define	RXDMA_CHANNEL_VALID(rdc) \
	((rdc < HXGE_MAX_RDCS))

#define	RXDMA_PAGE_VALID(page) \
	((page == 0) || (page == 1))

#define	RXDMA_BUFF_OFFSET_VALID(offset) \
	((offset == SW_OFFSET_NO_OFFSET) || \
	    (offset == SW_OFFSET_64) || \
	    (offset == SW_OFFSET_128))

#define	RXDMA_RCR_TO_VALID(tov) ((tov) && (tov < 64))
#define	RXDMA_RCR_THRESH_VALID(thresh) ((thresh < 65536))

#define	hpi_rxdma_rdc_rbr_kick(handle, rdc, num_buffers) \
	RXDMA_REG_WRITE64(handle, RDC_RBR_KICK, rdc, num_buffers)

hpi_status_t hpi_rxdma_cfg_rdc_ring(hpi_handle_t handle, uint8_t rdc,
    rdc_desc_cfg_t *rdc_desc_params);
hpi_status_t hpi_rxdma_cfg_clock_div_set(hpi_handle_t handle, uint16_t count);
hpi_status_t hpi_rxdma_cfg_logical_page_handle(hpi_handle_t handle, uint8_t rdc,
    uint64_t pg_handle);

hpi_status_t hpi_rxdma_rdc_rcr_read_update(hpi_handle_t handle, uint8_t channel,
    uint16_t num_pkts, uint16_t bufs_read);
hpi_status_t hpi_rxdma_rdc_rbr_qlen_get(hpi_handle_t handle, uint8_t rdc,
    rdc_rbr_qlen_t *rbr_stat);
hpi_status_t hpi_rxdma_cfg_rdc_reset(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_enable(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_disable(hpi_handle_t handle, uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_rcr_timeout(hpi_handle_t handle, uint8_t rdc,
    uint16_t rcr_timeout);

hpi_status_t hpi_rxdma_cfg_rdc_rcr_threshold(hpi_handle_t handle, uint8_t rdc,
    uint16_t rcr_threshold);
hpi_status_t hpi_rxdma_cfg_rdc_rcr_timeout_disable(hpi_handle_t handle,
    uint8_t rdc);
hpi_status_t hpi_rxdma_cfg_rdc_rcr_ctl(hpi_handle_t handle, uint8_t rdc,
                        uint8_t op, uint16_t rcr_timeout);
hpi_status_t hpi_rxdma_rdc_rcr_qlen_get(hpi_handle_t handle,
    uint8_t rdc,  uint16_t *qlen);
hpi_status_t hpi_rxdma_channel_mex_set(hpi_handle_t handle, uint8_t channel);
hpi_status_t hpi_rxdma_channel_control(hpi_handle_t handle,
    rxdma_cs_cntl_t control, uint8_t channel);
hpi_status_t hpi_rxdma_control_status(hpi_handle_t handle, io_op_t op_mode,
    uint8_t channel, rdc_stat_t *cs_p);
hpi_status_t hpi_rxdma_event_mask(hpi_handle_t handle, io_op_t op_mode,
    uint8_t channel, rdc_int_mask_t *mask_p);
hpi_status_t hpi_rxdma_channel_cs_clear_all(hpi_handle_t handle, 
	uint8_t channel);
hpi_status_t hpi_rx_fifo_status(hpi_handle_t handle, io_op_t op_mode,
	rdc_fifo_err_stat_t *stat);
hpi_status_t hpi_rx_fifo_mask(hpi_handle_t handle, io_op_t op_mode,
	rdc_fifo_err_mask_t *stat);
hpi_status_t hpi_rxdma_rdc_rcr_tail_get(hpi_handle_t handle, uint8_t channel, 
	uint32_t *rcr_tail);
hpi_status_t hpi_rxdma_cfg_rdc_wait_for_qst(hpi_handle_t handle, uint8_t rdc,
                       rdc_rx_cfg1_t *cfg, int state);


#endif	/* _HPI_RXDMA_H */
