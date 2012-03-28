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

#ifndef _HPI_VIR_H
#define	_HPI_VIR_H

#include "hpi.h"
#include "../hxge_peu_hw.h"

/*
 * Virtualization and Logical devices HPI error codes
 */
#define	VIR_ERR_ST		(VIR_BLK_ID << HPI_BLOCK_ID_SHIFT)
#define	VIR_ID_SHIFT(n)		(n << HPI_PORT_CHAN_SHIFT)

#define	VIR_LD_INVALID		(HPI_BK_ERROR_START | 0x30)
#define	VIR_LDG_INVALID		(HPI_BK_ERROR_START | 0x31)
#define	VIR_LDSV_INVALID	(HPI_BK_ERROR_START | 0x32)

#define	VIR_INTM_TM_INVALID	(HPI_BK_ERROR_START | 0x33)
#define	VIR_TM_RES_INVALID	(HPI_BK_ERROR_START | 0x34)
#define	VIR_SID_VEC_INVALID	(HPI_BK_ERROR_START | 0x35)

/*
 * Error codes of logical devices and groups functions.
 */
#define	HPI_VIR_LD_INVALID(n) 	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_LD_INVALID)
#define	HPI_VIR_LDG_INVALID(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_LDG_INVALID)
#define	HPI_VIR_LDSV_INVALID(n) (VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_LDSV_INVALID)
#define	HPI_VIR_INTM_TM_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_INTM_TM_INVALID)
#define	HPI_VIR_TM_RES_INVALID		(VIR_ERR_ST | VIR_TM_RES_INVALID)
#define	HPI_VIR_SID_VEC_INVALID(n)	(VIR_ID_SHIFT(n) | \
						VIR_ERR_ST | VIR_TM_RES_INVALID)

/*
 * Logical device definitions.
 */
#define	LDG_NUM_STEP		4
#define	LD_NUM_OFFSET(ld)	(ld * LDG_NUM_STEP)

#define	LDSV_STEP		8192
#define	LDSVG_OFFSET(ldg)	(ldg * LDSV_STEP)
#define	LDSV_OFFSET(ldv)	(ldv * LDSV_STEP)
#define	LDSV_OFFSET_MASK(ld)	(LD_INTR_MASK + LDSV_OFFSET(ld))

#define	LDG_SID_STEP		8192
#define	LDG_SID_OFFSET(ldg)	(ldg * LDG_SID_STEP)

typedef enum {
	VECTOR0,
	VECTOR1,
} ldsv_type_t;

/*
 * Definitions for the system interrupt data.
 */
typedef struct _fzc_sid {
	uint8_t		ldg;
	uint8_t		vector;
} fzc_sid_t, *p_fzc_sid_t;

/*
 * Virtualization and Interrupt Prototypes.
 */
hpi_status_t hpi_fzc_ldg_num_set(hpi_handle_t handle, uint8_t ld, uint8_t ldg);
hpi_status_t hpi_fzc_ldg_num_get(hpi_handle_t handle, uint8_t ld,
	uint8_t *ldg_p);
hpi_status_t hpi_ldsv_ldfs_get(hpi_handle_t handle, uint8_t ldg,
	uint32_t *vector0_p, uint32_t *vecto1_p);
hpi_status_t hpi_ldsv_get(hpi_handle_t handle, uint8_t ldg, ldsv_type_t vector,
	uint32_t *ldf_p);
hpi_status_t hpi_intr_mask_set(hpi_handle_t handle, uint8_t ld,
	uint8_t ldf_mask);
hpi_status_t hpi_intr_mask_get(hpi_handle_t handle, uint8_t ld,
	uint8_t *ldf_mask_p);
hpi_status_t hpi_intr_ldg_mgmt_set(hpi_handle_t handle, uint8_t ldg,
	boolean_t arm, uint8_t timer);
hpi_status_t hpi_intr_ldg_mgmt_timer_get(hpi_handle_t handle, uint8_t ldg,
	uint8_t *timer_p);
hpi_status_t hpi_intr_ldg_mgmt_arm(hpi_handle_t handle, uint8_t ldg);
hpi_status_t hpi_fzc_ldg_timer_res_set(hpi_handle_t handle, uint32_t res);
hpi_status_t hpi_fzc_ldg_timer_res_get(hpi_handle_t handle, uint8_t *res_p);
hpi_status_t hpi_fzc_sid_set(hpi_handle_t handle, fzc_sid_t sid);
hpi_status_t hpi_fzc_sid_get(hpi_handle_t handle, p_fzc_sid_t sid_p);
hpi_status_t hpi_fzc_sys_err_mask_set(hpi_handle_t handle, uint32_t mask);
hpi_status_t hpi_fzc_sys_err_stat_get(hpi_handle_t handle,
						dev_err_stat_t *statp);
hpi_status_t hpi_vir_dump_pio_fzc_regs_one(hpi_handle_t handle);
hpi_status_t hpi_vir_dump_ldgnum(hpi_handle_t handle);
hpi_status_t hpi_vir_dump_ldsv(hpi_handle_t handle);
hpi_status_t hpi_vir_dump_imask0(hpi_handle_t handle);
hpi_status_t hpi_vir_dump_sid(hpi_handle_t handle);

#endif	/* _HPI_VIR_H */
