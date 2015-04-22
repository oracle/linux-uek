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

#include	"hpi_txdma.h"

#define	TXDMA_WAIT_LOOP		10000
#define	TXDMA_WAIT_USEC		5

uint64_t tdc_dmc_offset[] = {
	TDC_PAGE_HANDLE,
	TDC_TDR_CFG,
	TDC_TDR_HEAD,
	TDC_TDR_PRE_HEAD,
	TDC_TDR_KICK,
	TDC_INT_MASK,
	TDC_STAT,
	TDC_MBH,
	TDC_MBL,
	TDC_BYTE_CNT,
	TDC_TDR_QLEN,
	TDC_DROP_CNT,
	TDC_PREF_PAR_LOG,
	TDC_STAT_INT_DBG,
	TDC_PKT_REQ_TID_TAG,
	TDC_SOP_PREF_DESC_LOG,
	TDC_PREF_DESC_LOG,
};

const char *tdc_dmc_name[] = {
	"TDC_PAGE_HANDLE",
	"TDC_TDR_CFG",
	"TDC_TDR_HEAD",
	"TDC_TDR_PRE_HEAD",
	"TDC_TDR_KICK",
	"TDC_INT_MASK",
	"TDC_STAT",
	"TDC_MBH",
	"TDC_MBL",
	"TDC_BYTE_CNT",
	"TDC_TDR_QLEN",
	"TDC_DROP_CNT",
	"TDC_PREF_PAR_LOG",
	"TDC_STAT_INT_DBG",
	"TDC_PKT_REQ_TID_TAG",
	"TDC_SOP_PREF_DESC_LOG",
	"TDC_PREF_DESC_LOG",
};

uint64_t tdc_reg_offset[] = {
	TDC_RTAB_PTR,
	TDC_LAST_PKT_RBUF_PTRS,
	TDC_PREF_CMD,
	TDC_PREF_DATA,
	TDC_PREF_PAR_DATA,
	TDC_REORD_BUF_CMD,
	TDC_REORD_BUF_DATA,
	TDC_REORD_BUF_ECC_DATA,
	TDC_REORD_TBL_CMD,
	TDC_REORD_TBL_DATA_LO,
	TDC_REORD_TBL_DATA_HI,
	TDC_REORD_BUF_ECC_LOG,
	TDC_REORD_TBL_PAR_LOG,
	TDC_FIFO_ERR_MASK,
	TDC_FIFO_ERR_STAT,
	TDC_FIFO_ERR_INT_DBG,
	TDC_PEU_TXN_LOG,
	TDC_DBG_TRAINING_VEC,
	TDC_DBG_GRP_SEL,
};

const char *tdc_reg_name[] = {
	"TDC_RTAB_PTR",
	"TDC_LAST_PKT_RBUF_PTRS",
	"TDC_PREF_CMD",
	"TDC_PREF_DATA",
	"TDC_PREF_PAR_DATA",
	"TDC_REORD_BUF_CMD",
	"TDC_REORD_BUF_DATA",
	"TDC_REORD_BUF_ECC_DATA",
	"TDC_REORD_TBL_CMD",
	"TDC_REORD_TBL_DATA_LO",
	"TDC_REORD_TBL_DATA_HI",
	"TDC_REORD_BUF_ECC_LOG",
	"TDC_REORD_TBL_PAR_LOG",
	"TDC_FIFO_ERR_MASK",
	"TDC_FIFO_ERR_STAT",
	"TDC_FIFO_ERR_INT_DBG",
	"TDC_PEU_TXN_LOG",
	"TDC_DBG_TRAINING_VEC",
	"TDC_DBG_GRP_SEL",
};

hpi_status_t
hpi_txdma_dump_tdc_regs(hpi_handle_t handle, uint8_t tdc)
{
	uint64_t value, offset;
	int num_regs, i;

	if (!TXDMA_CHANNEL_VALID(tdc)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    "hpi_txdma_dump_tdc_regs Invalid TDC number %d \n", tdc));

		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(tdc));
	}

	HPI_REG_DUMP_MSG(( HPI_REG_CTL,
	    "\nTXDMA Register Dump for Channel %d\n", tdc));

	num_regs = sizeof (tdc_dmc_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		TXDMA_REG_READ64(handle, tdc_dmc_offset[i], tdc, &value);
		offset = HXGE_TXDMA_OFFSET(tdc_dmc_offset[i], 0,
		    tdc);
		HPI_REG_DUMP_MSG(( HPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%016llx \n", offset, tdc_dmc_name[i], value));
	}

	HPI_REG_DUMP_MSG(( HPI_REG_CTL,
	    "\nTXDMA Register Dump for Channel %d done\n", tdc));

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_txdma_dump_tdc_common_regs(hpi_handle_t handle)
{
	uint64_t value, offset;
	int num_regs, i;

	HPI_REG_DUMP_MSG(( HPI_REG_CTL,
	    "\nTXDMA Common Register Dump\n"));

	num_regs = sizeof (tdc_reg_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		offset = tdc_reg_offset[i];
		HXGE_REG_RD64(handle, offset, &value);
		HPI_REG_DUMP_MSG(( HPI_REG_CTL, "0x%08llx "
		    "%s\t %016llx \n", offset, tdc_reg_name[i], value));
	}

	HPI_REG_DUMP_MSG(( HPI_REG_CTL,
	    "\nTXDMA Common Register Dump done\n"));

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_txdma_log_page_handle_set(hpi_handle_t handle, uint8_t channel,
	tdc_page_handle_t *hdl_p)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_log_page_handle_set"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_WRITE64(handle, TDC_PAGE_HANDLE, channel, hdl_p->value);

	return (status);
}

hpi_status_t
hpi_txdma_channel_reset(hpi_handle_t handle, uint8_t channel)
{
	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    " hpi_txdma_channel_reset" " RESETTING", channel));
	return (hpi_txdma_channel_control(handle, TXDMA_RESET, channel));
}

hpi_status_t
hpi_txdma_channel_init_enable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_INIT_START, channel));
}

hpi_status_t
hpi_txdma_channel_enable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_START, channel));
}

hpi_status_t
hpi_txdma_channel_disable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_STOP, channel));
}

hpi_status_t
hpi_txdma_channel_mbox_enable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_MBOX_ENABLE, channel));
}

hpi_status_t
hpi_txdma_channel_control(hpi_handle_t handle, txdma_cs_cntl_t control,
	uint8_t channel)
{
	hpi_status_t status = HPI_SUCCESS;
	tdc_stat_t cs;
	tdc_tdr_cfg_t cfg;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_channel_control"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (control) {
	case TXDMA_INIT_RESET:
		cfg.value = 0;
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.reset = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		return (hpi_txdma_control_reset_wait(handle, channel));

	case TXDMA_INIT_START:
		cfg.value = 0;
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.enable = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		break;

	case TXDMA_RESET:
		/*
		 * Sets reset bit only (Hardware will reset all the RW bits but
		 * leave the RO bits alone.
		 */
		cfg.value = 0;
		cfg.bits.reset = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		return (hpi_txdma_control_reset_wait(handle, channel));

	case TXDMA_START:
		/* Enable the DMA channel */
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.enable = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		break;

	case TXDMA_STOP:
		/* Disable the DMA channel */
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.enable = 0;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		status = hpi_txdma_control_stop_wait(handle, channel);
		if (status) {
			HPI_ERROR_MSG(( HPI_ERR_CTL,
			    "Cannot stop channel %d (TXC hung!)", channel));
		}
		break;

	case TXDMA_MBOX_ENABLE:
		/*
		 * Write 1 to MB bit to enable mailbox update (cleared to 0 by
		 * hardware after update).
		 */
		TXDMA_REG_READ64(handle, TDC_STAT, channel, &cs.value);
		cs.bits.mb = 1;
		TXDMA_REG_WRITE64(handle, TDC_STAT, channel, cs.value);
		break;

	default:
		status = (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_channel_control"
		    " Invalid Input: control <0x%x>", control));
	}

	return (status);
}

hpi_status_t
hpi_txdma_control_status(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
	tdc_stat_t *cs_p)
{
	int status = HPI_SUCCESS;
	tdc_stat_t txcs;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_control_status"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_STAT, channel, &cs_p->value);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TDC_STAT, channel, cs_p->value);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TDC_STAT, channel, &txcs.value);
		TXDMA_REG_WRITE64(handle, TDC_STAT, channel,
		    cs_p->value | txcs.value);
		break;

	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_control_status"
		    " Invalid Input: control <0x%x>", op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

hpi_status_t
hpi_txdma_event_mask(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
	tdc_int_mask_t *mask_p)
{
	int status = HPI_SUCCESS;
	tdc_int_mask_t mask;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_event_mask Invalid Input: channel <0x%x>",
		    channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_INT_MASK, channel, &mask_p->value);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TDC_INT_MASK, channel, mask_p->value);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TDC_INT_MASK, channel, &mask.value);
		TXDMA_REG_WRITE64(handle, TDC_INT_MASK, channel,
		    mask_p->value | mask.value);
		break;

	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_event_mask Invalid Input: eventmask <0x%x>",
		    op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

hpi_status_t
hpi_tx_fifo_status(hpi_handle_t handle, io_op_t op_mode,
		      tdc_fifo_err_stat_t *cs_p)
{
	int status = HPI_SUCCESS;

	switch (op_mode) {
	case OP_GET:
		HXGE_REG_RD64(handle, TDC_FIFO_ERR_STAT, &cs_p->value);
		break;

	case OP_SET:
		HXGE_REG_WR64(handle, TDC_FIFO_ERR_STAT, cs_p->value);
		break;

	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_tx_fifo_status:"
		    " Invalid Input: control <0x%x>", op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(0));
	}

	return (status);
}

hpi_status_t
hpi_tx_fifo_mask(hpi_handle_t handle, io_op_t op_mode, 
		    tdc_fifo_err_mask_t *mask_p)
{
	int status = HPI_SUCCESS;

	switch (op_mode) {
	case OP_GET:
		HXGE_REG_RD64(handle, TDC_FIFO_ERR_MASK, &mask_p->value);
		break;

	case OP_SET:
		HXGE_REG_WR64(handle, TDC_FIFO_ERR_MASK, mask_p->value);
		break;

	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_tx_fifo_mask: Invalid Input: eventmask <0x%x>",
		    op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(0));
	}

	return (status);
}

/*
 * This function is called to mask out the packet transmit marked event.
 */
hpi_status_t
hpi_txdma_event_mask_mk_out(hpi_handle_t handle, uint8_t channel)
{
	tdc_int_mask_t event_mask;
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_event_mask_mk_out"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	TXDMA_REG_READ64(handle, TDC_INT_MASK, channel, &event_mask.value);
	TXDMA_REG_WRITE64(handle, TDC_INT_MASK, channel,
	    (event_mask.value & ~TDC_INT_MASK_MK_MASK));

	return (status);
}

/*
 * This function is called to set the mask for the the packet marked event.
 */
hpi_status_t
hpi_txdma_event_mask_mk_in(hpi_handle_t handle, uint8_t channel)
{
	tdc_int_mask_t event_mask;
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_event_mask_mk_in"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	TXDMA_REG_READ64(handle, TDC_INT_MASK, channel, &event_mask.value);
	TXDMA_REG_WRITE64(handle, TDC_INT_MASK, channel,
	    (event_mask.value | TDC_INT_MASK_MK_MASK));

	return (status);
}

/*
 * This function is called to configure the transmit descriptor
 * ring address and its size.
 */
hpi_status_t
hpi_txdma_ring_addr_set(hpi_handle_t handle, uint8_t channel,
	uint64_t start_addr, uint32_t len)
{
	int status = HPI_SUCCESS;
	tdc_tdr_cfg_t cfg;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_ring_addr_set"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	cfg.value = ((start_addr & TDC_TDR_CFG_ADDR_MASK) |
	    (((uint64_t)len) << TDC_TDR_CFG_LEN_SHIFT));
	TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);

	return (status);
}

hpi_status_t
hpi_txdma_ring_config(hpi_handle_t handle, io_op_t op_mode,
	uint8_t channel, uint64_t *reg_data)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_ring_config"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, reg_data);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, *reg_data);
		break;

	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_ring_config"
		    " Invalid Input: ring_config <0x%x>", op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

hpi_status_t
hpi_txdma_mbox_config(hpi_handle_t handle, io_op_t op_mode,
	uint8_t channel, uint64_t *mbox_addr)
{
	int status = HPI_SUCCESS;
	tdc_mbh_t mh;
	tdc_mbl_t ml;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_mbox_config Invalid Input: channel <0x%x>",
		    channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}

	mh.value = ml.value = 0;

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_MBH, channel, &mh.value);
		TXDMA_REG_READ64(handle, TDC_MBL, channel, &ml.value);
		*mbox_addr = ml.value;
		*mbox_addr |= (mh.value << TDC_MBH_ADDR_SHIFT);

		break;

	case OP_SET:
		ml.bits.mbaddr = ((*mbox_addr & TDC_MBL_MASK) >> TDC_MBL_SHIFT);
		TXDMA_REG_WRITE64(handle, TDC_MBL, channel, ml.value);
		mh.bits.mbaddr = ((*mbox_addr >> TDC_MBH_ADDR_SHIFT) &
		    TDC_MBH_MASK);
		TXDMA_REG_WRITE64(handle, TDC_MBH, channel, mh.value);
		break;

	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_mbox_config Invalid Input: mbox <0x%x>",
		    op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * This function is called to set up a transmit descriptor entry.
 */
hpi_status_t
hpi_txdma_desc_gather_set(hpi_handle_t handle, p_tx_desc_t desc_p,
	uint8_t gather_index, boolean_t mark, uint8_t ngathers,
	uint64_t dma_ioaddr, uint32_t transfer_len)
{
	hpi_status_t status;

	status = HPI_TXDMA_GATHER_INDEX(gather_index);
	if (status) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_desc_gather_set"
		    " Invalid Input: gather_index <0x%x>", gather_index));
		return (status);
	}
	if (transfer_len > TX_MAX_TRANSFER_LENGTH) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_desc_gather_set"
		    " Invalid Input: tr_len <0x%x>", transfer_len));
		return (HPI_FAILURE | HPI_TXDMA_XFER_LEN_INVALID);
	}
	if (gather_index == 0) {
		desc_p->bits.sop = 1;
		desc_p->bits.mark = mark;
		desc_p->bits.num_ptr = ngathers;
		HPI_DEBUG_MSG(( HPI_TDC_CTL,
		    "hpi_txdma_gather_set: SOP len %d (%d)",
		    desc_p->bits.tr_len, transfer_len));
	}
	desc_p->bits.tr_len = transfer_len;
	desc_p->bits.sad = dma_ioaddr;

	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "hpi_txdma_gather_set: xfer len %d to set (%d)",
	    desc_p->bits.tr_len, transfer_len));

	HXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

/*
 * This function is called to set up the first gather entry.
 */
hpi_status_t
hpi_txdma_desc_gather_sop_set(hpi_handle_t handle, p_tx_desc_t desc_p,
	boolean_t mark_mode, uint8_t ngathers)
{
	hpi_status_t status = HPI_SUCCESS;

	desc_p->bits.sop = 1;
	desc_p->bits.mark = mark_mode;
	desc_p->bits.num_ptr = ngathers;

	HXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

hpi_status_t
hpi_txdma_desc_gather_sop_set_1(hpi_handle_t handle, p_tx_desc_t desc_p,
	boolean_t mark_mode, uint8_t ngathers, uint32_t extra)
{
	int status = HPI_SUCCESS;

	desc_p->bits.sop = 1;
	desc_p->bits.mark = mark_mode;
	desc_p->bits.num_ptr = ngathers;
	desc_p->bits.tr_len += extra;

	HXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

hpi_status_t
hpi_txdma_desc_set_xfer_len(hpi_handle_t handle, p_tx_desc_t desc_p,
	uint32_t transfer_len)
{
	int status = HPI_SUCCESS;

	desc_p->bits.tr_len = transfer_len;

	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "hpi_set_xfer_len: len %d (%d)",
	    desc_p->bits.tr_len, transfer_len));

	HXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

hpi_status_t
hpi_txdma_desc_set_zero(hpi_handle_t handle, uint16_t entries)
{
	uint32_t offset;
	int i;

	/*
	 * Assume no wrapped around.
	 */
	offset = 0;
	for (i = 0; i < entries; i++) {
		HXGE_REG_WR64(handle, offset, 0);
		offset += (i * (sizeof (tx_desc_t)));
	}

	return (HPI_SUCCESS);
}


hpi_status_t
hpi_txdma_desc_mem_get(hpi_handle_t handle, uint16_t index,
	p_tx_desc_t desc_p)
{
	int status = HPI_SUCCESS;

	hpi_txdma_dump_desc_one(handle, desc_p, index);

	return (status);
}

/*
 * This function is called to kick the transmit  to start transmission.
 */
hpi_status_t
hpi_txdma_desc_kick_reg_set(hpi_handle_t handle, uint8_t channel,
	uint16_t tail_index, boolean_t wrap)
{
	int status = HPI_SUCCESS;
	tdc_tdr_kick_t kick;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_desc_kick_reg_set"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    " hpi_txdma_desc_kick_reg_set: KICKING channel %d", channel));

	/* Toggle the wrap around bit */
	kick.value = 0;
	kick.bits.wrap = wrap;
	kick.bits.tail = tail_index;

	/* Kick start the Transmit kick register */
	TXDMA_REG_WRITE64(handle, TDC_TDR_KICK, channel, kick.value);

	return (status);
}

/*
 * This function is called to kick the transmit  to start transmission.
 */
hpi_status_t
hpi_txdma_desc_kick_reg_get(hpi_handle_t handle, uint8_t channel,
	tdc_tdr_kick_t *kick_p)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_desc_kick_reg_get"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	TXDMA_REG_READ64(handle, TDC_TDR_KICK, channel, &kick_p->value);

	return (status);
}

/*
 * This function is called to get the transmit ring head index.
 */
hpi_status_t
hpi_txdma_ring_head_get(hpi_handle_t handle, uint8_t channel,
	tdc_tdr_head_t *hdl_p)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_ring_head_get"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	TXDMA_REG_READ64(handle, TDC_TDR_HEAD, channel, &hdl_p->value);

	return (status);
}

/*ARGSUSED*/
hpi_status_t
hpi_txdma_channel_mbox_get(hpi_handle_t handle, uint8_t channel,
	p_txdma_mailbox_t mbox_p)
{
	int status = HPI_SUCCESS;

	return (status);
}

hpi_status_t
hpi_txdma_channel_pre_state_get(hpi_handle_t handle, uint8_t channel,
	tdc_tdr_pre_head_t *prep)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_txdma_channel_pre_state_get"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	TXDMA_REG_READ64(handle, TDC_TDR_PRE_HEAD, channel, &prep->value);

	return (status);
}

/*
 * Dumps the contents of transmit descriptors.
 */
/*ARGSUSED*/
void
hpi_txdma_dump_desc_one(hpi_handle_t handle, p_tx_desc_t desc_p, int desc_index)
{
	tx_desc_t desc, *desp;

#ifdef HXGE_DEBUG
	uint64_t sad;
	int xfer_len;
#endif

	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "\n==> hpi_txdma_dump_desc_one: dump "
	    " desc_p $%p descriptor entry %d\n", desc_p, desc_index));
	desc.value = 0;
	desp = ((desc_p != NULL) ? desc_p : (p_tx_desc_t)&desc);
	desp->value = HXGE_MEM_PIO_READ64(handle);
#ifdef HXGE_DEBUG
	sad = desp->bits.sad;
	xfer_len = desp->bits.tr_len;
#endif
	HPI_DEBUG_MSG(( HPI_TDC_CTL, "\n\t: value 0x%llx\n"
	    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\tmark %d sop %d\n",
	    desp->value, sad, desp->bits.hdw.tr_len, xfer_len,
	    desp->bits.hdw.num_ptr, desp->bits.hdw.mark, desp->bits.hdw.sop));

	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "\n<== hpi_txdma_dump_desc_one: Done \n"));
}

/*ARGSUSED*/
void
hpi_txdma_dump_hdr(hpi_handle_t handle, p_tx_pkt_header_t hdrp)
{
	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "\n==> hpi_txdma_dump_hdr: dump\n"));
	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "\n\t: value 0x%llx\n"
	    "\t\tpkttype 0x%x\tip_ver %d\tllc %d\tvlan %d \tihl %d\n"
	    "\t\tl3start %d\tl4start %d\tl4stuff %d\n"
	    "\t\txferlen %d\tpad %d\n",
	    hdrp->value,
	    hdrp->bits.hdw.cksum_en_pkt_type,
	    hdrp->bits.hdw.ip_ver,
	    hdrp->bits.hdw.llc,
	    hdrp->bits.hdw.vlan,
	    hdrp->bits.hdw.ihl,
	    hdrp->bits.hdw.l3start,
	    hdrp->bits.hdw.l4start,
	    hdrp->bits.hdw.l4stuff,
	    hdrp->bits.ldw.tot_xfer_len,
	    hdrp->bits.ldw.pad));

	HPI_DEBUG_MSG(( HPI_TDC_CTL,
	    "\n<== hpi_txdma_dump_hdr: Done \n"));
}

/*
 * Static functions start here.
 */
hpi_status_t
hpi_txdma_control_reset_wait(hpi_handle_t handle, uint8_t channel)
{
	tdc_tdr_cfg_t txcs;
	int loop = 0;

	txcs.value = 0;
	do {
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &txcs.value);

		/*
		 * Reset completes when this bit is set to 1 by hw
		 */
		if (txcs.bits.qst) {
			return (HPI_SUCCESS);
		}
		HXGE_DELAY(TXDMA_WAIT_USEC);
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    "hpi_txdma_control_reset_wait: RST bit not "
		    "cleared to 0 txcs.bits 0x%llx", txcs.value));
		return (HPI_FAILURE | HPI_TXDMA_RESET_FAILED);
	}
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_txdma_control_stop_wait(hpi_handle_t handle, uint8_t channel)
{
	tdc_tdr_cfg_t txcs;
	int loop = 0;

	do {
		txcs.value = 0;
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &txcs.value);
		if (txcs.bits.qst) {
			return (HPI_SUCCESS);
		}
		HXGE_DELAY(TXDMA_WAIT_USEC);
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    "hpi_txdma_control_stop_wait: SNG_STATE not "
		    "set to 1 txcs.bits 0x%llx", txcs.value));
		return (HPI_FAILURE | HPI_TXDMA_STOP_FAILED);
	}
	return (HPI_SUCCESS);
}
