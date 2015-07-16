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

#ifndef _HPI_MAC_H
#define	_HPI_MAC_H

#include "hpi.h"
#include "../hxge_vmac_hw.h"

hpi_status_t hpi_tx_vmac_reset(hpi_handle_t handle);
hpi_status_t hpi_rx_vmac_reset(hpi_handle_t handle);
hpi_status_t hpi_vmac_rx_ints(hpi_handle_t handle, int enable);
hpi_status_t hpi_vmac_tx_ints(hpi_handle_t handle, int enable);
hpi_status_t hpi_tx_vmac_clear_regs(hpi_handle_t handle);
hpi_status_t hpi_rx_vmac_clear_regs(hpi_handle_t handle);
hpi_status_t hpi_vmac_dump_regs(hpi_handle_t handle);
hpi_status_t hpi_vmac_tx_config(hpi_handle_t handle, config_op_t op,
	uint64_t config, uint16_t max_frame_length);
hpi_status_t hpi_vmac_rx_config(hpi_handle_t handle, config_op_t op,
	uint64_t config, uint16_t max_frame_length);
hpi_status_t hpi_vmac_rx_set_framesize(hpi_handle_t handle, 
	uint16_t max_frame_length);


#define	CFG_VMAC_TX_EN			0x00000001
#define	CFG_VMAC_TX_CRC_INSERT		0x00000002
#define	CFG_VMAC_TX_PAD			0x00000004

#define	CFG_VMAC_RX_EN			0x00000001
#define	CFG_VMAC_RX_CRC_CHECK_DISABLE	0x00000002
#define	CFG_VMAC_RX_STRIP_CRC		0x00000004
#define	CFG_VMAC_RX_PASS_FLOW_CTRL_FR	0x00000008
#define	CFG_VMAC_RX_PROMISCUOUS_GROUP	0x00000010
#define	CFG_VMAC_RX_PROMISCUOUS_MODE	0x00000020
#define	CFG_VMAC_RX_LOOP_BACK		0x00000040

#endif	/* _HPI_MAC_H */
