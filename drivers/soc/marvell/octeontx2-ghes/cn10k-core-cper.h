/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Supports Marvell CN10K processor CPER Generic Hardware Error Source[s] (GHES).
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef __CN10K_CORE_CPER_H__
#define __CN10K_CORE_CPER_H__

#define CN10K_ERR_REC_FRU_TEXT_LEN 32

struct processor_error {
	uint32_t                 severity;
	char                     fru_text[CN10K_ERR_REC_FRU_TEXT_LEN];
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
	struct cper_arm_ctx_info ctx;
	uint64_t                 reg_type5[17];
};

struct processor_error_ring {
	uint32_t               head;
	uint32_t               tail;
	uint32_t               records;
	struct processor_error error[0];
};

struct mrvl_core_error_raport {
	struct acpi_hest_generic_status estatus;
	struct acpi_hest_generic_data   gdata;
	struct cper_sec_proc_arm        desc;
	struct cper_arm_err_info        info;
	struct cper_arm_ctx_info        ctx;
	uint64_t                        reg[0];
};

#endif // __CN10K_CORE_CPER_H__
