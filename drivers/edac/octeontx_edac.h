/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2022 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OCTEONTX_EDAC_H__
#define __OCTEONTX_EDAC_H__

#define OCTEONTX_SDEI_RAS_MDC_EVENT		0x40000000
#define OCTEONTX_SDEI_RAS_MCC_EVENT		0x40000001
#define OCTEONTX_SDEI_RAS_LMC_EVENT		0x40000002
#define OCTEONTX_SDEI_RAS_AP0_EVENT		0x40000003
#define OCTEONTX_SDEI_RAS_DSS_EVENT		OCTEONTX_SDEI_RAS_MCC_EVENT
#define OCTEONTX_SDEI_RAS_TAD_EVENT		OCTEONTX_SDEI_RAS_LMC_EVENT

#define SDEI_GHES_EVENT_NAME_MAX_CHARS 16

#define OTX2_GHES_ERR_REC_FRU_TEXT_LEN 32

struct mrvl_core_error_raport {
	struct acpi_hest_generic_status estatus;
	struct acpi_hest_generic_data   gdata;
	struct cper_sec_proc_arm        desc;
	struct cper_arm_err_info        info;
//	struct cper_arm_ctx_info        ctx;
//	uint64_t                        reg[0];
};

struct mrvl_mem_error_raport {
	struct acpi_hest_generic_status estatus;
	struct acpi_hest_generic_data   gdata;
	struct cper_sec_mem_err_old     cper;
	char fru_text[OTX2_GHES_ERR_REC_FRU_TEXT_LEN];
};


/*
 * Describes an error source per ACPI 18.3.2.6 (Generic Hardware Error Source).
 * This produces GHES-compliant error records from data forwarded by the [ATF]
 * firmware.
 * There exists one of these for each error source.
 *
 * @name:               event source name mdc/mcc/lmc
 * @id:                 event id
 * @esa_pa              physical address of Error Status Address register/iomem
 * @esa_va:             mapped pointer to Error Status Address point on Error Status Block
 * @esb_pa:             phys address of Error Status Block follow Error Status Data
 * @esb_va:             mapped pointer to Error Status Block
 * @ring_pa:            physical address of Ring of Error Status Blocks
 * @ring:               mapped pointer to Ring of Error Status Blocks
 * @ring_sz:            ring buffer size
 */
struct mrvl_ghes_source {
	char                            name[SDEI_GHES_EVENT_NAME_MAX_CHARS];
	phys_addr_t                     esa_pa;
	phys_addr_t                     esb_pa;
	phys_addr_t                     ring_pa;
	phys_addr_t                     *esa_va;
	union {
		struct acpi_hest_generic_status *esb_va;
		struct mrvl_core_error_raport   *esb_core_va;
	};
	struct otx2_ghes_err_ring       *ring;
	size_t                          ring_sz;
	size_t                          esb_sz;
	u32                             id;
	struct device                   dev;
	struct mem_ctl_info             *mci;
};

/**
 * struct mrvl_sdei_ghes_drv: driver state
 *
 * @source_list:              list of [SDEI] producers
 *                            (1 for each error source)
 * @source_count:             count of [SDEI] producers
 *                            (size of @source_list)
 */
struct mrvl_sdei_ghes_drv {
	struct device           *dev;
	struct mrvl_ghes_source *source_list;
	size_t                  source_count;
};

#define OTX2_GHES_ERR_RING_SIG ((int)'M' << 24 | 'R' << 16 | 'V' << 8 | 'L')

struct processor_error {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
};

struct otx2_ghes_err_record {
	union {
		struct processor_error       core;
		struct cper_sec_mem_err_old  mcc;
		struct cper_sec_mem_err_old  mdc;
		struct cper_sec_mem_err_old  lmc;
	} u;
	uint32_t severity; /* CPER_SEV_xxx */
	char fru_text[OTX2_GHES_ERR_REC_FRU_TEXT_LEN];
};

/* This is shared with Linux sdei-ghes driver */
struct otx2_ghes_err_ring {
	uint32_t head;
	uint32_t tail;
	uint32_t size;       /* ring size */
	uint32_t sig;        /* set to OTX2_GHES_ERR_RING_SIG if initialized */
	uint32_t reg;
	/* ring of records */
	struct otx2_ghes_err_record records[1] __aligned(8);
};

struct octeontx_edac_pvt {
	unsigned long inject;
	unsigned long error_type;
	unsigned long address;
};

#endif // __OCTEONTX_EDAC_H__
