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

#ifndef _HPI_PFC_H
#define	_HPI_PFC_H

#include "hpi.h"
#include "../hxge_pfc_hw.h"
#include "../hxge_pfc.h"

typedef enum _tcam_op {
	TCAM_RWC_STAT	= 0x1,
	TCAM_RWC_MATCH	= 0x2
} tcam_op_t;

#define	HPI_TCAM_COMP_NO_MATCH	0x8000000000000ULL

/*
 * HPI PFC ERROR Codes
 */
#define	HPI_PFC_BLK_CODE	PFC_BLK_ID << 8
#define	HPI_PFC_ERROR		(HPI_FAILURE | HPI_PFC_BLK_CODE)
#define	HPI_TCAM_ERROR		0x10
#define	HPI_FCRAM_ERROR		0x20
#define	HPI_GEN_PFC		0x30
#define	HPI_PFC_SW_PARAM_ERROR	0x40
#define	HPI_PFC_HW_ERROR	0x80

#define	HPI_PFC_RESET_ERROR	(HPI_PFC_ERROR | HPI_GEN_PFC | RESET_FAILED)
#define	HPI_PFC_RDC_TABLE_INVALID	(HPI_PFC_ERROR | RDC_TAB_INVALID)
#define	HPI_PFC_VLAN_INVALID		(HPI_PFC_ERROR | VLAN_INVALID)
#define	HPI_PFC_PORT_INVALID		(HPI_PFC_ERROR | PORT_INVALID)
#define	HPI_PFC_TCAM_RD_ERROR		\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | READ_FAILED)
#define	HPI_PFC_TCAM_WR_ERROR		\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | WRITE_FAILED)
#define	HPI_PFC_TCAM_LOC_INVALID	\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | LOCATION_INVALID)
#define	HPI_PFC_ASC_RAM_RD_ERROR	\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | READ_FAILED)
#define	HPI_PFC_ASC_RAM_WR_ERROR	\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | WRITE_FAILED)
#define	HPI_PFC_FCRAM_READ_ERROR	\
	(HPI_PFC_ERROR | HPI_FCRAM_ERROR | READ_FAILED)
#define	HPI_PFC_FCRAM_WR_ERROR		\
	(HPI_PFC_ERROR | HPI_FCRAM_ERROR | WRITE_FAILED)
#define	HPI_PFC_FCRAM_PART_INVALID	\
	(HPI_PFC_ERROR | HPI_FCRAM_ERROR | RDC_TAB_INVALID)
#define	HPI_PFC_FCRAM_LOC_INVALID	\
	(HPI_PFC_ERROR | HPI_FCRAM_ERROR | LOCATION_INVALID)

#define	TCAM_CLASS_INVALID		\
	(HPI_PFC_SW_PARAM_ERROR | 0xb)
/* have only 0xc, 0xd, 0xe and 0xf left for sw error codes */
#define	HPI_PFC_TCAM_CLASS_INVALID	\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | TCAM_CLASS_INVALID)
#define	HPI_PFC_TCAM_HW_ERROR		\
	(HPI_PFC_ERROR | HPI_PFC_HW_ERROR | HPI_TCAM_ERROR)
#define	HPI_PFC_FCRAM_HW_ERROR		\
	(HPI_PFC_ERROR | HPI_PFC_HW_ERROR | HPI_FCRAM_ERROR)

#define	PFC_N_VLAN_REGISTERS		0x80
#define	PFC_N_VLAN_MEMBERS		0x20

#define	PFC_N_MAC_ADDRESSES		16
#define	PFC_MAX_DMA_CHANNELS		4
#define	PFC_MAC_ADDR_STEP		8

#define	PFC_HASH_TABLE_SIZE		16
#define	PFC_HASH_STEP			0x08

#define	PFC_L2_CLASS_CONFIG_STEP	0x08

#define	PFC_L3_CLASS_SLOTS		0x08
#define	PFC_L3_CLASS_CONFIG_STEP	0x08

#define	PFC_N_TCAM_ENTRIES		42

#define	PFC_VLAN_REG_OFFSET(vlan_id) \
	((((vlan_id_t)(vlan_id / PFC_N_VLAN_MEMBERS)) * 8) + PFC_VLAN_TABLE)
#define	PFC_VLAN_BIT_OFFSET(vlan_id) \
	(vlan_id % PFC_N_VLAN_MEMBERS)
#define	PFC_MAC_ADDRESS(slot) \
	((slot * PFC_MAC_ADDR_STEP) + PFC_MAC_ADDR)
#define	PFC_MAC_ADDRESS_MASK(slot) \
	((slot * PFC_MAC_ADDR_STEP) + PFC_MAC_ADDR_MASK)
#define	PFC_HASH_ADDR(slot) \
	((slot * PFC_HASH_STEP) + PFC_HASH_TABLE)

#define	PFC_L2_CONFIG(slot) \
	((slot * PFC_L2_CLASS_CONFIG_STEP) + PFC_L2_CLASS_CONFIG)
#define	PFC_L3_CONFIG(slot) \
	(((slot - TCAM_CLASS_TCP_IPV4) * PFC_L3_CLASS_CONFIG_STEP) + \
	PFC_L3_CLASS_CONFIG)

typedef uint16_t vlan_id_t;

hpi_status_t hpi_pfc_dump_regs(hpi_handle_t handle);

/*
 * PFC Control Register Functions
 */
hpi_status_t hpi_pfc_set_tcam_enable(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_l2_hash(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_cksum(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_default_dma(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_mac_addr_enable(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_mac_addr_disable(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_set_force_csum(hpi_handle_t, boolean_t);

/*
 * PFC vlan Functions
 */
hpi_status_t hpi_pfc_cfg_vlan_table_dump(hpi_handle_t handle);
hpi_status_t hpi_pfc_cfg_vlan_table_clear(hpi_handle_t);
hpi_status_t hpi_pfc_cfg_vlan_table_entry_clear(hpi_handle_t, vlan_id_t);
hpi_status_t hpi_pfc_cfg_vlan_table_entry_set(hpi_handle_t, vlan_id_t);
hpi_status_t hpi_pfc_cfg_vlan_control_set(hpi_handle_t, boolean_t,
	boolean_t, vlan_id_t);
hpi_status_t	hpi_pfc_get_vlan_parity_log(hpi_handle_t,
	pfc_vlan_par_err_log_t *);

/*
 * PFC Mac Address Functions
 */
hpi_status_t hpi_pfc_set_mac_address(hpi_handle_t, uint32_t, uint64_t);
hpi_status_t hpi_pfc_clear_mac_address(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_clear_multicast_hash_table(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_set_multicast_hash_table(hpi_handle_t, uint32_t,
	uint64_t);

/*
 * PFC L2 and L3 Config Functions.
 */
hpi_status_t hpi_pfc_set_l2_class_slot(hpi_handle_t, uint16_t, boolean_t,
    int);
hpi_status_t hpi_pfc_get_l3_class_config(hpi_handle_t handle, tcam_class_t slot,
    tcam_key_cfg_t *cfg);
hpi_status_t hpi_pfc_set_l3_class_config(hpi_handle_t handle, tcam_class_t slot,
    tcam_key_cfg_t cfg);

/*
 * PFC TCAM Functions
 */
hpi_status_t	hpi_pfc_tcam_invalidate_all(hpi_handle_t);
hpi_status_t	hpi_pfc_tcam_entry_invalidate(hpi_handle_t, uint32_t);
hpi_status_t	hpi_pfc_tcam_entry_write(hpi_handle_t, uint32_t,
	hxge_tcam_entry_t *);
hpi_status_t	hpi_pfc_tcam_entry_read(hpi_handle_t, uint32_t,
	hxge_tcam_entry_t *);
hpi_status_t hpi_pfc_tcam_asc_ram_entry_read(hpi_handle_t handle,
	uint32_t location, uint64_t *ram_data);
hpi_status_t hpi_pfc_tcam_asc_ram_entry_write(hpi_handle_t handle,
	uint32_t location, uint64_t ram_data);
hpi_status_t	hpi_pfc_get_tcam_parity_log(hpi_handle_t,
	pfc_tcam_par_err_log_t *);
hpi_status_t	hpi_pfc_get_tcam_auto_init(hpi_handle_t,
	pfc_auto_init_t *);

/*
 * PFC Hash Seed Value
 */
hpi_status_t	hpi_pfc_set_hash_seed_value(hpi_handle_t, uint32_t);

/*
 * PFC Interrupt Management Functions
 */
hpi_status_t	hpi_pfc_get_interrupt_status(hpi_handle_t, pfc_int_status_t *);
hpi_status_t	hpi_pfc_clear_interrupt_status(hpi_handle_t);
hpi_status_t	hpi_pfc_set_interrupt_mask(hpi_handle_t, boolean_t,
	boolean_t, boolean_t);

/*
 * PFC Packet Logs
 */
hpi_status_t	hpi_pfc_get_drop_log(hpi_handle_t, pfc_drop_log_t *);
hpi_status_t	hpi_pfc_set_drop_log_mask(hpi_handle_t, boolean_t,
	boolean_t, boolean_t, boolean_t, boolean_t);
hpi_status_t	hpi_pfc_get_bad_csum_counter(hpi_handle_t, uint64_t *);
hpi_status_t	hpi_pfc_get_drop_counter(hpi_handle_t, uint64_t *);

hpi_status_t hpi_pfc_get_mac_address(hpi_handle_t handle, int i, uint8_t *data);
hpi_status_t hpi_hcr_mac_addr_get(hpi_handle_t handle, int i, uint8_t *data);
hpi_status_t hpi_pfc_num_macs_get(hpi_handle_t handle, uint8_t *data);

#endif /* !_HPI_PFC_H */
