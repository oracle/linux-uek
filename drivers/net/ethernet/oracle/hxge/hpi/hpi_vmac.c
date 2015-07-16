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

#include "hpi_vmac.h"

uint64_t vmac_offset[] = {
	VMAC_RST,
	VMAC_TX_CFG,
	VMAC_RX_CFG,
	VMAC_TX_STAT,
	VMAC_TX_MSK,
	VMAC_RX_STAT,
	VMAC_RX_MSK,
	VMAC_TX_STAT_MIRROR,
	VMAC_RX_STAT_MIRROR,
	VMAC_TX_FRAME_CNT,
	VMAC_TX_BYTE_CNT,
	VMAC_RX_FRAME_CNT,
	VMAC_RX_BYTE_CNT,
	VMAC_RX_DROP_FR_CNT,
	VMAC_RX_DROP_BYTE_CNT,
	VMAC_RX_CRC_CNT,
	VMAC_RX_PAUSE_CNT,
	VMAC_RX_BCAST_FR_CNT,
	VMAC_RX_MCAST_FR_CNT
};

const char *vmac_name[] = {
	"VMAC_RST",
	"VMAC_TX_CFG",
	"VMAC_RX_CFG",
	"VMAC_TX_STAT",
	"VMAC_TX_MSK",
	"VMAC_RX_STAT",
	"VMAC_RX_MSK",
	"VMAC_TX_STAT_MIRROR",
	"VMAC_RX_STAT_MIRROR",
	"VMAC_TX_FRAME_CNT",
	"VMAC_TX_BYTE_CNT",
	"VMAC_RX_FRAME_CNT",
	"VMAC_RX_BYTE_CNT",
	"VMAC_RX_DROP_FR_CNT",
	"VMAC_RX_DROP_BYTE_CNT",
	"VMAC_RX_CRC_CNT",
	"VMAC_RX_PAUSE_CNT",
	"VMAC_RX_BCAST_FR_CNT",
	"VMAC_RX_MCAST_FR_CNT"
};


hpi_status_t
hpi_vmac_dump_regs(hpi_handle_t handle)
{
	uint64_t value;
	int num_regs, i;

	num_regs = sizeof (vmac_offset) / sizeof (uint64_t);
	HPI_REG_DUMP_MSG(( HPI_REG_CTL,
	    "\nVMAC Register Dump\n"));

	for (i = 0; i < num_regs; i++) {
		HXGE_REG_RD64(handle, vmac_offset[i], &value);
		HPI_REG_DUMP_MSG(( HPI_REG_CTL,
			"%08llx %s\t %016llx \n",
			vmac_offset[i], vmac_name[i], value));
	}

	HPI_REG_DUMP_MSG(( HPI_REG_CTL,
	    "\n VMAC Register Dump done\n"));

	return (HPI_SUCCESS);
}


hpi_status_t
hpi_tx_vmac_reset(hpi_handle_t handle)
{
	vmac_rst_t	reset;

	HXGE_REG_RD64(handle, VMAC_RST, &(reset.value));

	reset.bits.tx_reset = 1;

	HXGE_REG_WR64(handle, VMAC_RST, reset.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_tx_ints(hpi_handle_t handle, int enable)
{
	uint64_t mask = 0;
	if (!enable)
		mask = ~0ULL;
        HXGE_REG_WR64(handle, VMAC_TX_MSK, mask);
	return (HPI_SUCCESS);
}


hpi_status_t
hpi_tx_vmac_clear_regs(hpi_handle_t handle)
{
	uint64_t val;

	HXGE_REG_WR64(handle, VMAC_TX_STAT, ~0ULL); /* RW1C */
	HXGE_REG_WR64(handle, VMAC_TX_MSK, ~0ULL); /* disable everything */
	HXGE_REG_RD64(handle, VMAC_TX_FRAME_CNT, &val);
	HXGE_REG_RD64(handle, VMAC_TX_BYTE_CNT, &val);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_rx_ints(hpi_handle_t handle, int enable)
{
	uint64_t mask = 0;
	if (!enable)
		mask = ~0ULL;
	HXGE_REG_WR64(handle, VMAC_RX_MSK, mask);
	return (HPI_SUCCESS);
}



hpi_status_t
hpi_rx_vmac_reset(hpi_handle_t handle)
{
	vmac_rst_t	reset;

	HXGE_REG_RD64(handle, VMAC_RST, &(reset.value));

	reset.bits.rx_reset = 1;

	HXGE_REG_WR64(handle, VMAC_RST, reset.value);
	
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rx_vmac_clear_regs(hpi_handle_t handle)
{
	uint64_t val;

	/* Clear off the Rx registers */
	HXGE_REG_WR64(handle, VMAC_RX_STAT, ~0ULL); /* RW1C */
	HXGE_REG_WR64(handle, VMAC_RX_MSK, ~0ULL); /* disable everything */
	HXGE_REG_WR64(handle, VMAC_RX_STAT_MIRROR, 0);
	HXGE_REG_RD64(handle, VMAC_RX_FRAME_CNT, &val); /* RORC */
	HXGE_REG_RD64(handle, VMAC_RX_BYTE_CNT, &val); /* RORC */
	HXGE_REG_RD64(handle, VMAC_RX_DROP_FR_CNT, &val); /* RORC */
	HXGE_REG_RD64(handle, VMAC_RX_DROP_BYTE_CNT, &val); /* RORC */
	HXGE_REG_RD64(handle, VMAC_RX_CRC_CNT, &val); /* RORC */
	HXGE_REG_RD64(handle, VMAC_RX_PAUSE_CNT, &val); /* RORC */
	HXGE_REG_RD64(handle, VMAC_RX_BCAST_FR_CNT, &val);/*  RORC */
	HXGE_REG_RD64(handle, VMAC_RX_MCAST_FR_CNT, &val); /* RORC */

	return (HPI_SUCCESS);

}


hpi_status_t
hpi_vmac_tx_config(hpi_handle_t handle, config_op_t op, uint64_t config,
    uint16_t max_frame_length)
{
	vmac_tx_cfg_t	cfg;
	hpi_status_t err = HPI_SUCCESS;

	if (config == 0) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_vmac_tx_config Invalid Input: config <0x%x>",
		    config));
		return (HPI_FAILURE);
	}

	HXGE_REG_RD64(handle, VMAC_TX_CFG, &cfg.value);

	switch (op) {
	case ENABLE:
		if (config & CFG_VMAC_TX_EN)
			cfg.bits.tx_en = 1;
		if (config & CFG_VMAC_TX_CRC_INSERT)
			cfg.bits.crc_insert = 1;
		if (config & CFG_VMAC_TX_PAD)
			cfg.bits.tx_pad = 1;

		/* If a bad MTU was passed, then leave the old value as is
		 * and return a failure so that "ifconfig mtu" can fail 
		 */
	        if (max_frame_length  > MAX_JUMBO_FRAME_SIZE) {
       	         HPI_ERROR_MSG(( HPI_ERR_CTL,
                 " hpi_vmac_tx_config Invalid Input: max_frame_length <0x%x>",
                    max_frame_length));
		    err = HPI_FAILURE;
        	}
		else if (max_frame_length)
			cfg.bits.tx_max_frame_length = max_frame_length;
		break;
	case DISABLE:
		if (config & CFG_VMAC_TX_EN)
			cfg.bits.tx_en = 0;
		if (config & CFG_VMAC_TX_CRC_INSERT)
			cfg.bits.crc_insert = 0;
		if (config & CFG_VMAC_TX_PAD)
			cfg.bits.tx_pad = 0;
		break;
	case INIT:
		if (config & CFG_VMAC_TX_EN)
			cfg.bits.tx_en = 1;
		else
			cfg.bits.tx_en = 0;

		if (config & CFG_VMAC_TX_CRC_INSERT)
			cfg.bits.crc_insert = 1;
		else
			cfg.bits.crc_insert = 0;

		if (config & CFG_VMAC_TX_PAD)
			cfg.bits.tx_pad = 1;
		else
			cfg.bits.tx_pad = 0;

	        if (max_frame_length  > MAX_JUMBO_FRAME_SIZE) {
       	         HPI_ERROR_MSG(( HPI_ERR_CTL,
                 " hpi_vmac_tx_config Invalid Input: max_frame_length <0x%x>",
                    max_frame_length));
		 err = HPI_FAILURE;
        	}
		else if (max_frame_length)
			cfg.bits.tx_max_frame_length = max_frame_length;

		break;
	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_vmac_tx_config Invalid Input: op <0x%x>", op));
		return (HPI_FAILURE);
	}

	HXGE_REG_WR64(handle, VMAC_TX_CFG, cfg.value);

	return (err);
}

hpi_status_t
hpi_vmac_rx_config(hpi_handle_t handle, config_op_t op, uint64_t config,
	uint16_t max_frame_length)
{
	vmac_rx_cfg_t cfg;

	if (!config && (op != INIT)) {
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_vmac_rx_config Invalid Input: config <0x%x>",
		    config));
		return (HPI_FAILURE);
	}

	HXGE_REG_RD64(handle, VMAC_RX_CFG, &cfg.value);

	switch (op) {
	case ENABLE:
		if (config & CFG_VMAC_RX_EN)
			cfg.bits.rx_en = 1;
		if (config & CFG_VMAC_RX_CRC_CHECK_DISABLE)
			cfg.bits.crc_check_disable = 1;
		if (config & CFG_VMAC_RX_STRIP_CRC)
			cfg.bits.strip_crc = 1;
		if (config & CFG_VMAC_RX_PASS_FLOW_CTRL_FR)
			cfg.bits.pass_flow_ctrl_fr = 1;
		if (config & CFG_VMAC_RX_PROMISCUOUS_GROUP)
			cfg.bits.promiscuous_group = 1;
		if (config & CFG_VMAC_RX_PROMISCUOUS_MODE)
			cfg.bits.promiscuous_mode = 1;
		if (config & CFG_VMAC_RX_LOOP_BACK)
			cfg.bits.loopback = 1;
		break;
	case DISABLE:
		if (config & CFG_VMAC_RX_EN)
			cfg.bits.rx_en = 0;
		if (config & CFG_VMAC_RX_CRC_CHECK_DISABLE)
			cfg.bits.crc_check_disable = 0;
		if (config & CFG_VMAC_RX_STRIP_CRC)
			cfg.bits.strip_crc = 0;
		if (config & CFG_VMAC_RX_PASS_FLOW_CTRL_FR)
			cfg.bits.pass_flow_ctrl_fr = 0;
		if (config & CFG_VMAC_RX_PROMISCUOUS_GROUP)
			cfg.bits.promiscuous_group = 0;
		if (config & CFG_VMAC_RX_PROMISCUOUS_MODE)
			cfg.bits.promiscuous_mode = 0;
		if (config & CFG_VMAC_RX_LOOP_BACK)
			cfg.bits.loopback = 0;
		break;
	case INIT:
		if (config & CFG_VMAC_RX_EN)
			cfg.bits.rx_en = 1;
		else
			cfg.bits.rx_en = 0;
		if (config & CFG_VMAC_RX_CRC_CHECK_DISABLE)
			cfg.bits.crc_check_disable = 1;
		else
			cfg.bits.crc_check_disable = 0;
		if (config & CFG_VMAC_RX_STRIP_CRC)
			cfg.bits.strip_crc = 1;
		else
			cfg.bits.strip_crc = 0;
		if (config & CFG_VMAC_RX_PASS_FLOW_CTRL_FR)
			cfg.bits.pass_flow_ctrl_fr = 1;
		else
			cfg.bits.pass_flow_ctrl_fr = 0;
		if (config & CFG_VMAC_RX_PROMISCUOUS_GROUP)
			cfg.bits.promiscuous_group = 1;
		else
			cfg.bits.promiscuous_group = 0;
		if (config & CFG_VMAC_RX_PROMISCUOUS_MODE)
			cfg.bits.promiscuous_mode = 1;
		else
			cfg.bits.promiscuous_mode = 0;
		if (config & CFG_VMAC_RX_LOOP_BACK)
			cfg.bits.loopback = 1;
		else
			cfg.bits.loopback = 0;

		break;
	default:
		HPI_ERROR_MSG(( HPI_ERR_CTL,
		    " hpi_vmac_rx_config Invalid Input: op <0x%x>", op));
		return (HPI_FAILURE);
	}
 
	if (max_frame_length  > MAX_JUMBO_FRAME_SIZE) {
                HPI_ERROR_MSG(( HPI_ERR_CTL,
                    " hpi_vmac_rx_config Invalid Input: max_frame_length <0x%x>",
                    max_frame_length));
                return (HPI_FAILURE);
	}
		
	if (max_frame_length > 0)
		cfg.bits.rx_max_frame_length = max_frame_length;

	HXGE_REG_WR64(handle, VMAC_RX_CFG, cfg.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_rx_set_framesize(hpi_handle_t handle, uint16_t max_frame_length)
{
	return(hpi_vmac_rx_config(handle, ENABLE, 0, max_frame_length));
}
