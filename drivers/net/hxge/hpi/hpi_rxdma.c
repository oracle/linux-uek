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

#include "hpi_rxdma.h"

/* The state bit indicates the value that you want the qst bit to be */
hpi_status_t
hpi_rxdma_cfg_rdc_wait_for_qst(hpi_handle_t handle, uint8_t rdc,
			rdc_rx_cfg1_t *cfg, int state )
{
	uint32_t count = RXDMA_RESET_TRY_COUNT;
	uint32_t delay_time = RXDMA_RESET_DELAY;

	RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg->value);
	while ((count--) && (cfg->bits.qst == (1-state)))
	{
		HXGE_DELAY(delay_time);
		RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg->value);
	}

	if (!count) {
		printk(KERN_DEBUG "hpi_rxdma_cfg_rdc_wait_for_qst not set to %d\n",state);
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    " hpi_rxdma_cfg_rdc_ctl"
		    " RXDMA_OP_DISABLE Failed for RDC %d \n",
		    rdc));
		return (HPI_RXDMA_ERROR_ENCODE(HPI_RXDMA_RESET_ERR, rdc));
	}

	return (HPI_SUCCESS);
}

/* RX DMA functions */
hpi_status_t 
hpi_rxdma_cfg_rdc_ctl(hpi_handle_t handle, uint8_t rdc, uint8_t op)
{
	rdc_rx_cfg1_t cfg;
	uint32_t err = HPI_SUCCESS;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_cfg_rdc_ctl Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	switch (op) {
		case RXDMA_OP_ENABLE:
			RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
			cfg.bits.enable = 1;
			RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg.value);
			err = hpi_rxdma_cfg_rdc_wait_for_qst(handle, rdc, &cfg, 0);
			break;

		case RXDMA_OP_DISABLE:
			RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
			cfg.bits.enable = 0;
			RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg.value);
			err = hpi_rxdma_cfg_rdc_wait_for_qst(handle, rdc, &cfg, 1);
			break;

		case RXDMA_OP_RESET:
			cfg.value = 0;
			cfg.bits.reset = 1;
			RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg.value);
			err = hpi_rxdma_cfg_rdc_wait_for_qst(handle, rdc, &cfg,1);
			break;

		default:
			err = HPI_RXDMA_SW_PARAM_ERROR;
			break;
	}

	if (err !=  HPI_SUCCESS)
		HPI_ERROR_MSG((HPI_ERR_CTL,
			    " hpi_rxdma_cfg_rdc_ctl"
			    " Reset Failed for RDC %d \n", rdc));
	return (err);


}

hpi_status_t
hpi_rxdma_cfg_rdc_rcr_ctl(hpi_handle_t handle, uint8_t rdc, uint8_t op, 
                          uint16_t param)
{
	rdc_rcr_cfg_b_t rcr_cfgb;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "rxdma_cfg_rdc_rcr_ctl Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RDC_RCR_CFG_B, rdc, &rcr_cfgb.value);

	switch (op) {
		case RCR_TIMEOUT_ENABLE:
			rcr_cfgb.bits.timeout = (uint8_t)param;
			rcr_cfgb.bits.entout = 1;
			break;

		case RCR_THRESHOLD:
			rcr_cfgb.bits.pthres = param;
			break;

		case RCR_TIMEOUT_DISABLE:
			rcr_cfgb.bits.entout = 0;
			break;

		default:
			HPI_ERROR_MSG((HPI_ERR_CTL,
			    "rxdma_cfg_rdc_rcr_ctl Illegal opcode %x \n", op));
		return (HPI_RXDMA_OPCODE_INVALID(rdc));
	}

	RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_B, rdc, rcr_cfgb.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rxdma_cfg_rdc_rcr_timeout_disable(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_rcr_ctl(handle, rdc, RCR_TIMEOUT_DISABLE, 0));
}


hpi_status_t
hpi_rxdma_cfg_rdc_enable(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_ENABLE));
}

hpi_status_t
hpi_rxdma_cfg_rdc_disable(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_DISABLE));
}

hpi_status_t
hpi_rxdma_cfg_rdc_reset(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_RESET));
}


hpi_status_t
hpi_rxdma_cfg_rdc_rcr_timeout(hpi_handle_t handle, uint8_t rdc,
    uint16_t rcr_timeout)
{
	return (hpi_rxdma_cfg_rdc_rcr_ctl(handle, rdc,
	    RCR_TIMEOUT_ENABLE, rcr_timeout));
}

/*
 * hpi_rxdma_cfg_rdc_ring()
 * Configure The RDC channel Rcv Buffer Ring
 *
 * Inputs:
 *	rdc:		RX DMA Channel number
 *	rdc_params:	RDC confiuration parameters
 *
 * Return:
 * HPI_SUCCESS
 * HPI_FAILURE
 * HPI_SW_ERR
 * HPI_HW_ERR
 *
 */
hpi_status_t
hpi_rxdma_cfg_rdc_ring(hpi_handle_t handle, uint8_t rdc,
    rdc_desc_cfg_t *rdc_desc_cfg)
{
	rdc_rbr_cfg_a_t cfga;
	rdc_rbr_cfg_b_t cfgb;
	rdc_rx_cfg1_t cfg1;
	rdc_rx_cfg2_t cfg2;
	rdc_rcr_cfg_a_t rcr_cfga;
	rdc_rcr_cfg_b_t rcr_cfgb;
	rdc_page_handle_t page_handle;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "rxdma_cfg_rdc_ring Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	cfga.value = 0;
	cfgb.value = 0;
	cfg1.value = 0;
	cfg2.value = 0;
	page_handle.value = 0;

	if (rdc_desc_cfg->mbox_enable == 1) {
		cfg1.bits.mbaddr_h = (rdc_desc_cfg->mbox_addr >> 32) & 0xfff;
		cfg2.bits.mbaddr_l = ((rdc_desc_cfg->mbox_addr &
		    RXDMA_CFIG2_MBADDR_L_MASK) >> RXDMA_CFIG2_MBADDR_L_SHIFT);

		/*
		 * Only after all the configurations are set, then
		 * enable the RDC or else configuration fatal error
		 * will be returned (especially if the Hypervisor
		 * set up the logical pages with non-zero values.
		 * This HPI function only sets up the configuration.
		 * Call the enable function to enable the RDMC!
		 */
	}

	if (rdc_desc_cfg->full_hdr == 1)
		cfg2.bits.full_hdr = 1;

	if (RXDMA_BUFF_OFFSET_VALID(rdc_desc_cfg->offset)) {
		cfg2.bits.offset = rdc_desc_cfg->offset;
	} else {
		cfg2.bits.offset = SW_OFFSET_NO_OFFSET;
	}

	/* rbr config */
	cfga.value = (rdc_desc_cfg->rbr_addr &
	    (RBR_CFIG_A_STDADDR_MASK | RBR_CFIG_A_STDADDR_BASE_MASK));

	/* The remaining 20 bits in the DMA address form the handle */
	page_handle.bits.handle = (rdc_desc_cfg->rbr_addr >> 44) && 0xfffff;

	/*
	 * Hydra:
	 * The RBR ring size must be multiple of 64.
	 */
	if ((rdc_desc_cfg->rbr_len < RBR_DEFAULT_MIN_LEN) ||
	    (rdc_desc_cfg->rbr_len > RBR_DEFAULT_MAX_LEN) ||
	    (rdc_desc_cfg->rbr_len % 64)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_cfg_rdc_ring Illegal RBR Queue Length %d \n",
		    rdc_desc_cfg->rbr_len));
		return (HPI_RXDMA_ERROR_ENCODE(HPI_RXDMA_RBRSZIE_INVALID, rdc));
	}

	/*
	 * Hydra:
	 * The lower 6 bits are hardcoded to 0 and the higher 10 bits are
	 * stored in len.
	 */
	cfga.bits.len = rdc_desc_cfg->rbr_len >> 6;
	HPI_DEBUG_MSG((HPI_RDC_CTL,
	    "hpi_rxdma_cfg_rdc_ring CFGA 0x%llx len %d (RBR LEN %d)\n",
	    cfga.value, cfga.bits.len, rdc_desc_cfg->rbr_len));

	/*
	 * Hydra: bksize is 1 bit, Neptune: bksize is 2 bits
	 * Buffer Block Size. b0 - 4K; b1 - 8K.
	 */
	if (rdc_desc_cfg->page_size == SIZE_4KB)
		cfgb.bits.bksize = RBR_BKSIZE_4K;
	else if (rdc_desc_cfg->page_size == SIZE_8KB)
		cfgb.bits.bksize = RBR_BKSIZE_8K;
	else {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "rxdma_cfg_rdc_ring blksize: Illegal buffer size %d \n",
		    rdc_desc_cfg->page_size));
		return (HPI_RXDMA_BUFSZIE_INVALID);
	}

	/*
	 * Hydra:
	 * Size 0 of packet buffer. b00 - 256; b01 - 512; b10 - 1K; b11 - resvd.
	 */
	if (rdc_desc_cfg->valid0) {
		if (rdc_desc_cfg->size0 == SIZE_256B)
			cfgb.bits.bufsz0 = RBR_BUFSZ0_256B;
		else if (rdc_desc_cfg->size0 == SIZE_512B)
			cfgb.bits.bufsz0 = RBR_BUFSZ0_512B;
		else if (rdc_desc_cfg->size0 == SIZE_1KB)
			cfgb.bits.bufsz0 = RBR_BUFSZ0_1K;
		else {
			HPI_ERROR_MSG((HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize0: Illegal buffer size %x \n",
			    rdc_desc_cfg->size0));
			return (HPI_RXDMA_BUFSZIE_INVALID);
		}
		cfgb.bits.vld0 = 1;
	} else {
		cfgb.bits.vld0 = 0;
	}

	/*
	 * Hydra:
	 * Size 1 of packet buffer. b0 - 1K; b1 - 2K.
	 */
	if (rdc_desc_cfg->valid1) {
		if (rdc_desc_cfg->size1 == SIZE_1KB)
			cfgb.bits.bufsz1 = RBR_BUFSZ1_1K;
		else if (rdc_desc_cfg->size1 == SIZE_2KB)
			cfgb.bits.bufsz1 = RBR_BUFSZ1_2K;
		else {
			HPI_ERROR_MSG((HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize1: Illegal buffer size %x \n",
			    rdc_desc_cfg->size1));
			return (HPI_RXDMA_BUFSZIE_INVALID);
		}
		cfgb.bits.vld1 = 1;
	} else {
		cfgb.bits.vld1 = 0;
	}

	/*
	 * Hydra:
	 * Size 2 of packet buffer. b0 - 2K; b1 - 4K.
	 */
	if (rdc_desc_cfg->valid2) {
		if (rdc_desc_cfg->size2 == SIZE_2KB)
			cfgb.bits.bufsz2 = RBR_BUFSZ2_2K;
		else if (rdc_desc_cfg->size2 == SIZE_4KB)
			cfgb.bits.bufsz2 = RBR_BUFSZ2_4K;
		else {
			HPI_ERROR_MSG((HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize2: Illegal buffer size %x \n",
			    rdc_desc_cfg->size2));
			return (HPI_RXDMA_BUFSZIE_INVALID);
		}
		cfgb.bits.vld2 = 1;
	} else {
		cfgb.bits.vld2 = 0;
	}

	rcr_cfga.value = (rdc_desc_cfg->rcr_addr &
	    (RCRCFIG_A_STADDR_MASK | RCRCFIG_A_STADDR_BASE_MASK));

	/*
	 * Hydra:
	 * The rcr len must be multiple of 32.
	 */
	if ((rdc_desc_cfg->rcr_len < RCR_DEFAULT_MIN_LEN) ||
	    (rdc_desc_cfg->rcr_len > HXGE_RCR_MAX) ||
	    (rdc_desc_cfg->rcr_len % 32)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    " rxdma_cfg_rdc_ring Illegal RCR Queue Length %d \n",
		    rdc_desc_cfg->rcr_len));
		return (HPI_RXDMA_ERROR_ENCODE(HPI_RXDMA_RCRSZIE_INVALID, rdc));
	}

	/*
	 * Hydra:
	 * Bits 15:5 of the maximum number of 8B entries in RCR.  Bits 4:0 are
	 * hard-coded to zero.  The maximum size is 2^16 - 32.
	 */
	rcr_cfga.bits.len = rdc_desc_cfg->rcr_len >> 5;

	rcr_cfgb.value = 0;
	if (rdc_desc_cfg->rcr_timeout_enable == 1) {
		/* check if the rcr timeout value is valid */

		if (RXDMA_RCR_TO_VALID(rdc_desc_cfg->rcr_timeout)) {
			rcr_cfgb.bits.timeout = rdc_desc_cfg->rcr_timeout;
			rcr_cfgb.bits.entout = 1;
		} else {
			HPI_ERROR_MSG((HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " Illegal RCR Timeout value %d \n",
			    rdc_desc_cfg->rcr_timeout));
			rcr_cfgb.bits.entout = 0;
		}
	} else {
		rcr_cfgb.bits.entout = 0;
	}

	rcr_cfgb.bits.pthres = rdc_desc_cfg->rcr_threshold;

	/* now do the actual HW configuration */
	RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg1.value);
	RXDMA_REG_WRITE64(handle, RDC_RX_CFG2, rdc, cfg2.value);

	RXDMA_REG_WRITE64(handle, RDC_RBR_CFG_A, rdc, cfga.value);
	RXDMA_REG_WRITE64(handle, RDC_RBR_CFG_B, rdc, cfgb.value);

	RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_A, rdc, rcr_cfga.value);
	RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_B, rdc, rcr_cfgb.value);

	RXDMA_REG_WRITE64(handle, RDC_PAGE_HANDLE, rdc, page_handle.value);

	return (HPI_SUCCESS);
}

/* system wide conf functions */

hpi_status_t
hpi_rxdma_cfg_clock_div_set(hpi_handle_t handle, uint16_t count)
{
	uint64_t offset;
	rdc_clock_div_t clk_div;

	offset = RDC_CLOCK_DIV;

	clk_div.value = 0;
	clk_div.bits.count = count;
	HPI_DEBUG_MSG((HPI_RDC_CTL,
	    " hpi_rxdma_cfg_clock_div_set: value 0x%llx",
	    clk_div.value));

	HXGE_REG_WR64(handle, offset, clk_div.value);

	return (HPI_SUCCESS);
}


hpi_status_t
hpi_rxdma_rdc_rbr_qlen_get(hpi_handle_t handle, uint8_t rdc,
    rdc_rbr_qlen_t *rbr_qlen)
{
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    " rxdma_rdc_rbr_qlen_get Illegal RDC Number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RDC_RBR_QLEN, rdc, &rbr_qlen->value);
	return (HPI_SUCCESS);
}


hpi_status_t
hpi_rxdma_rdc_rcr_qlen_get(hpi_handle_t handle, uint8_t rdc,
    uint16_t *rcr_qlen)
{
	rdc_rcr_qlen_t stats;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    " rxdma_rdc_rcr_qlen_get Illegal RDC Number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RDC_RCR_QLEN, rdc, &stats.value);
	*rcr_qlen =  stats.bits.qlen;
	HPI_DEBUG_MSG((HPI_RDC_CTL,
	    " rxdma_rdc_rcr_qlen_get RDC %d qlen %x qlen %x\n",
	    rdc, *rcr_qlen, stats.bits.qlen));
	return (HPI_SUCCESS);
}


hpi_status_t
hpi_rxdma_rdc_rcr_tail_get(hpi_handle_t handle, uint8_t rdc,
	uint32_t *rcr_tail)
{
	rdc_rcr_tail_t tail;

        if (!RXDMA_CHANNEL_VALID(rdc)) {
                HPI_ERROR_MSG((HPI_ERR_CTL,
                    " rxdma_rdc_rcr_tail_get Illegal RDC Number %d \n", rdc));
                return (HPI_RXDMA_RDC_INVALID);
        }
 
        RXDMA_REG_READ64(handle, RDC_RCR_TAIL, rdc, &tail.value);
        *rcr_tail =  tail.bits.tail;
        HPI_DEBUG_MSG((HPI_RDC_CTL,
            " rxdma_rdc_rcr_qlen_get RDC %d qlen %x \n",
            rdc, *rcr_tail));
        return (HPI_SUCCESS);
}



hpi_status_t
hpi_rxdma_rdc_rcr_read_update(hpi_handle_t handle, uint8_t channel,
	uint16_t pkts_read, uint16_t bufs_read)
{
	rdc_stat_t	cs;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    " hpi_rxdma_rdc_rcr_read_update ", " channel %d", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	HPI_DEBUG_MSG((HPI_RDC_CTL,
	    " hpi_rxdma_rdc_rcr_read_update bufs read %d pkt read %d",
	    bufs_read, pkts_read));

	cs.value = 0; /* do not modify any other bits */
	cs.bits.pktread = pkts_read;
	cs.bits.ptrread = bufs_read;

	RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);

	return (HPI_SUCCESS);
}

/*
 * hpi_rxdma_channel_mex_set():
 *	This function is called to arm the DMA channel with
 *	mailbox updating capability. Software needs to rearm
 *	for each update by writing to the control and status register.
 *
 * Parameters:
 *	handle		- HPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *
 * Return:
 *	HPI_SUCCESS		- If enable channel with mailbox update
 *				  is complete successfully.
 *
 *	Error:
 *	HPI_FAILURE	-
 *		HPI_RXDMA_CHANNEL_INVALID -
 */
hpi_status_t
hpi_rxdma_channel_mex_set(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_rxdma_channel_control(handle, RXDMA_MEX_SET, channel));
}

hpi_status_t
hpi_rxdma_channel_cs_clear_all(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_rxdma_channel_control(handle, RXDMA_CS_CLEAR_ALL, channel));
}

/*
 * hpi_rxdma_channel_control():
 *	This function is called to control a receive DMA channel
 *	for arming the channel with mailbox updates, resetting
 *	various event status bits (control and status register).
 *
 * Parameters:
 *	handle		- HPI handle (virtualization flag must be defined).
 *	control		- HPI defined control type supported:
 *				- RXDMA_MEX_SET
 * 				- RXDMA_RCRTO_CLEAR
 *				- RXDMA_RCR_SFULL_CLEAR
 *				- RXDMA_RCR_FULL_CLEAR
 *				- RXDMA_RBR_PRE_EMPTY_CLEAR
 *				- RXDMA_RBR_EMPTY_CLEAR
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware.
 * Return:
 *	HPI_SUCCESS
 *
 *	Error:
 *	HPI_FAILURE		-
 *		HPI_TXDMA_OPCODE_INVALID	-
 *		HPI_TXDMA_CHANNEL_INVALID	-
 */
hpi_status_t
hpi_rxdma_channel_control(hpi_handle_t handle, rxdma_cs_cntl_t control,
	uint8_t channel)
{
	rdc_stat_t	cs;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    " hpi_rxdma_channel_control", " channel", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	cs.value = 0; // do not modify other bits
	switch (control) {
	case RXDMA_MEX_SET:
		cs.bits.mex = 1;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	case RXDMA_RCRTO_CLEAR:
		cs.bits.rcr_to = 1;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	case RXDMA_RCR_SFULL_CLEAR:
		cs.bits.rcr_shadow_full = 1;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	case RXDMA_RCR_FULL_CLEAR:
		cs.bits.rcr_full = 1;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	case RXDMA_RBR_PRE_EMPTY_CLEAR:
		cs.bits.rbr_pre_empty = 1;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	case RXDMA_RBR_EMPTY_CLEAR:
		cs.bits.rbr_empty = 1;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	case RXDMA_CS_CLEAR_ALL:
		cs.value = ~0ULL;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		break;

	default:
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_channel_control", "control", control));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (HPI_SUCCESS);
}

/*
 * hpi_rxdma_control_status():
 *	This function is called to operate on the control
 *	and status register.
 *
 * Parameters:
 *	handle		- HPI handle
 *	op_mode		- OP_GET: get hardware control and status
 *			  OP_SET: set hardware control and status
 *			  OP_UPDATE: update hardware control and status.
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	cs_p		- pointer to hardware defined control and status
 *			  structure.
 * Return:
 *	HPI_SUCCESS
 *
 *	Error:
 *	HPI_FAILURE		-
 *		HPI_RXDMA_OPCODE_INVALID	-
 *		HPI_RXDMA_CHANNEL_INVALID	-
 */
hpi_status_t
hpi_rxdma_control_status(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
    rdc_stat_t *cs_p)
{
	int		status = HPI_SUCCESS;
	rdc_stat_t	cs;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_control_status", "channel", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RDC_STAT, channel, &cs_p->value);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs_p->value);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RDC_STAT, channel, &cs.value);
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel,
		    cs_p->value | cs.value);
		break;

	default:
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_control_status", "control", op_mode));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * hpi_rxdma_event_mask():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts.
 *
 * Parameters:
 *	handle		- HPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	mask_p		- pointer to hardware defined event mask
 *			  structure.
 * Return:
 *	HPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	HPI_FAILURE		-
 *		HPI_RXDMA_OPCODE_INVALID	-
 *		HPI_RXDMA_CHANNEL_INVALID	-
 */


hpi_status_t
hpi_rxdma_event_mask(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
    rdc_int_mask_t *mask_p)
{
	int		status = HPI_SUCCESS;
	rdc_int_mask_t	mask;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_event_mask", "channel", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RDC_INT_MASK, channel, &mask_p->value);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RDC_INT_MASK, channel, mask_p->value);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RDC_INT_MASK, channel, &mask.value);
		RXDMA_REG_WRITE64(handle, RDC_INT_MASK, channel,
		    mask_p->value | mask.value);
		break;

	default:
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rxdma_event_mask", "eventmask", op_mode));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * hpi_rx_fifo_status():
 *	This function is called to operate on the RX Fifo Error Status
 *	register.
 *
 * Parameters:
 *	handle		- HPI handle
 *	op_mode		- OP_GET: get hardware control and status
 *			  OP_SET: set hardware control and status
 *	cs_p		- pointer to hardware defined fifo status structure.
 *
 * Return:
 *	HPI_SUCCESS
 *
 *	Error:
 *	HPI_FAILURE		-
 *		HPI_RXDMA_OPCODE_INVALID	-
 *		HPI_RXDMA_CHANNEL_INVALID	-
 */
hpi_status_t
hpi_rx_fifo_status(hpi_handle_t handle, io_op_t op_mode,
		   rdc_fifo_err_stat_t *cs_p)
{
	int		status = HPI_SUCCESS;

	switch (op_mode) {
	case OP_GET:
		HXGE_REG_RD64(handle, RDC_FIFO_ERR_STAT, &cs_p->value);
		break;

	case OP_SET:
		HXGE_REG_WR64(handle, RDC_FIFO_ERR_STAT, cs_p->value);
		break;

	default:
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rx_fifo_status", "control", op_mode));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(0));
	}

	return (status);
}

/*
 * hpi_rx_fifo_mask():
 *	This function is called to operate on the fifo error mask
 *	register which is used for generating interrupts.
 *
 * Parameters:
 *	handle		- HPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *	mask_p		- pointer to hardware defined event mask
 *			  structure.
 * Return:
 *	HPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	HPI_FAILURE		-
 *		HPI_RXDMA_OPCODE_INVALID	-
 *		HPI_RXDMA_CHANNEL_INVALID	-
 */


hpi_status_t
hpi_rx_fifo_mask(hpi_handle_t handle, io_op_t op_mode,
		 rdc_fifo_err_mask_t *mask_p)
{
	int		status = HPI_SUCCESS;

	switch (op_mode) {
	case OP_GET:
		HXGE_REG_RD64(handle, RDC_FIFO_ERR_MASK, &mask_p->value);
		break;

	case OP_SET:
		HXGE_REG_WR64(handle, RDC_FIFO_ERR_MASK, mask_p->value);
		break;

	default:
		HPI_ERROR_MSG((HPI_ERR_CTL,
		    "hpi_rx_fifo_mask", "interrupt-mask", op_mode));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(0));
	}

	return (status);
}
