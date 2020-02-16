/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Supports OcteonTX2 Generic Hardware Error Source[s] (GHES).
 *
 */

#ifndef __OTX2_SDEI_GHES_H__
#define __OTX2_SDEI_GHES_H__

#define SDEI_GHES_EVENT_NAME_MAX_CHARS 16
/*
 * @estatus_pa:         physical address of error status information block
 * @estatus_address:    mapped pointer to error_status_address
 * @estatus:            mapped pointer to error status block
 */
struct otx2_ghes_event {
	char                            name[SDEI_GHES_EVENT_NAME_MAX_CHARS];
	u32                             id;
	phys_addr_t                     estatus_pa;
	phys_addr_t                     *estatus_address;
	struct acpi_hest_generic_status *estatus;
	struct otx2_ghes_err_ring       *ring;
};

/**
 * struct otx2_sdei_ghes_drv: driver state
 *
 * @of_node:                  associated device tree node
 * @event_list:               list of [GHES] events
 * @event_count:              count of [GHES] events (size of @event_list)
 */
struct otx2_sdei_ghes_drv {
	struct device_node                   *of_node;
	struct otx2_ghes_event               *event_list;
	size_t                               event_count;
	struct delayed_work                  dwork;
};

#define OTX2_GHES_ERR_REC_FRU_TEXT_LEN 32
/* This is shared with ATF */
struct otx2_ghes_err_record {
	union {
		struct cper_sec_mem_err_old  mcc;
		struct cper_sec_mem_err_old  mdc;
		struct cper_sec_mem_err_old  lmc;
		struct cper_arm_err_info     ap; /* application processor */
	} u;
	uint32_t                             severity; /* CPER_SEV_xxx */
	char fru_text[OTX2_GHES_ERR_REC_FRU_TEXT_LEN];
};

/* This is shared with ATF */
struct otx2_ghes_err_ring {
	/* The head resides in DRAM & can be updated by ATF (i.e. firmware).
	 * See Documentation/process/volatile-considered-harmful.rst, line 92.
	 */
	uint32_t volatile head;
	uint32_t          tail;
	uint32_t          size;       /* ring size */
	/* ring of records */
	struct otx2_ghes_err_record records[1] __aligned(8);
};

#endif // __OTX2_SDEI_GHES_H__
