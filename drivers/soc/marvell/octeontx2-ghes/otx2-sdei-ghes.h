/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Supports OcteonTX2 Generic Hardware Error Source[s] (GHES).
 * GHES ACPI HEST & DT
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef __OTX2_SDEI_GHES_H__
#define __OTX2_SDEI_GHES_H__

#define SDEI_GHES_EVENT_NAME_MAX_CHARS 16
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
	union {
		struct mrvl_ghes_err_ring   *ring;
		struct processor_error_ring *ring_core;
	};
	size_t                          ring_sz;
	size_t                          esb_sz;
	u32                             id;
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

#define MRVL_GHES_ERR_REC_FRU_TEXT_LEN 32
/* This is shared with ATF */
struct mrvl_ghes_err_record {
	union {
		struct cper_sec_mem_err_old mcc;
		struct cper_sec_mem_err_old mdc;
		struct cper_sec_mem_err_old lmc;
	} u;
	uint32_t severity; /* CPER_SEV_xxx */
	char fru_text[MRVL_GHES_ERR_REC_FRU_TEXT_LEN];
};

/* This is shared with ATF */
struct mrvl_ghes_err_ring {
	/* The head resides in DRAM & can be updated by ATF (i.e. firmware).
	 * See Documentation/process/volatile-considered-harmful.rst, line 92.
	 */
	uint32_t volatile head;
	uint32_t          tail;
	uint32_t          size;  /* ring size */
	uint32_t          sig;   /* set to OTX2_GHES_ERR_RING_SIG if initialized */
	/* ring of records */
	struct mrvl_ghes_err_record records[1] __aligned(8);
};

#endif // __OTX2_SDEI_GHES_H__
