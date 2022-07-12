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

#define CN10K_CPU_MODEL			(0xd49)
#define PCI_DEVICE_ID_OCTEONTX2_LMC	(0xa022)
#define PCI_DEVICE_ID_OCTEONTX2_MCC	(0xa070)
#define PCI_DEVICE_ID_OCTEONTX2_MDC	(0xa073)

#define OCTEONTX_RAS_MDC_SDEI_EVENT	(0x40000000)
#define OCTEONTX_RAS_MCC_SDEI_EVENT	(0x40000001)
#define OCTEONTX_RAS_LMC_SDEI_EVENT	(0x40000002)
#define OCTEONTX_RAS_DSS_SDEI_EVENT	(0x40000001)
#define OCTEONTX_RAS_TAD_SDEI_EVENT	(0x40000002)

#define OCTEONTX_LMC	"lmc"
#define OCTEONTX_MCC	"mcc"
#define OCTEONTX_MDC	"mdc"
#define OCTEONTX_DSS	"dss"
#define OCTEONTX_TAD	"tad"

#define OCTEONTX2_EDAC_INJECT		(0xc2000c0b)
#define OCTEON10_EDAC_INJECT		(0xc2000b10)

#define OCTEONTX_EDAC_F_BITMASK		0x007 /* single bit to corrupt */
#define OCTEONTX_EDAC_F_MULTI		0x008 /* corrupt multiple bits */
#define OCTEONTX_EDAC_F_CLEVEL		0x070 /* cache level to corrupt (L0 == DRAM) */
#define OCTEONTX_EDAC_F_ICACHE		0x080 /* Icache, not Dcache */
#define OCTEONTX_EDAC_F_REREAD		0x100 /* read-back in EL3 */
#define OCTEONTX_EDAC_F_PHYS		0x200 /* target is EL3-physical, not EL012 */

#define OCTEONTX_GHES_NAME_MAX_LEN 16
#define OCTEONTX_GHES_FRU_TEXT_LEN 32

#define OCTEONTX_GHES_ERR_RING_SIG ((int)'M' << 24 | 'R' << 16 | 'V' << 8 | 'L')

#define IS_NOT_MC_SDEI_EVENT(id) ((id != OCTEONTX_RAS_MDC_SDEI_EVENT) && \
	(id != OCTEONTX_RAS_MCC_SDEI_EVENT) && \
	(id != OCTEONTX_RAS_LMC_SDEI_EVENT))

struct processor_error {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
};

union octeontx_edac_cper {
	struct cper_sec_mem_err mem;
	struct processor_error  core;
};

struct octeontx_edac_mc_record {
	struct acpi_hest_generic_status estatus;
	struct acpi_hest_generic_data   gdata;
	union octeontx_edac_cper        cper;
};

/*
 * Describes an error source per ACPI (Generic Hardware Error Source).
 * This produces GHES-compliant error records from data forwarded by the [ATF]
 * firmware.
 * There exists one of these for each error source.
 *
 * @name:               ghes source name
 * @id:                 sdei event id
 * @esa_pa              physical address of Error Status Address register/iomem
 * @esb_pa:             phys address of Error Status Block follow Error Status Data
 * @ring_pa:            physical address of Ring of Error Status Blocks
 * @esa_va:             mapped to Error Status Address point on Error Status Block
 * @esb_va:             mapped to Error Status Block
 * @ring:               mapped to Ring of Error Status Blocks
 * @ring_sz:            ring size
 * @esb_sz:             esb size
 * @dev:                memory controller owner device
 * @mci                 corresponding memory controller
 * @mc_work             worker for sdei callback
 */
struct octeontx_edac_ghes {
	phys_addr_t                     esa_pa;
	phys_addr_t                     esb_pa;
	phys_addr_t                     ring_pa;
	phys_addr_t                     *esa_va;
	struct octeontx_edac_mc_record  *esb_va;
	struct octeontx_edac_ghes_ring  *ring;
	size_t                          ring_sz;
	size_t                          esb_sz;
	struct device                   dev;
	struct mem_ctl_info             *mci;
	struct work_struct              mc_work;
	u32                             id;
	char                            name[OCTEONTX_GHES_NAME_MAX_LEN];
};

struct octeontx_edac_driver {
	struct device             *dev;
	struct octeontx_edac_ghes *source_list;
	size_t                    source_count;
};

struct octeontx_edac_ghes_ring_record {
	union {
		struct cper_sec_mem_err mcc;
		struct cper_sec_mem_err mdc;
		struct cper_sec_mem_err lmc;
		struct cper_sec_mem_err tad;
		struct cper_sec_mem_err dss;
	} u;
	uint32_t error_severity;
	char fru_text[OCTEONTX_GHES_FRU_TEXT_LEN];
};

struct octeontx_edac_ghes_ring {
	uint32_t head;
	uint32_t tail;
	uint32_t size;
	uint32_t sig;
	uint32_t reg;
	struct octeontx_edac_ghes_ring_record records[0] __aligned(8);
};

struct octeontx_edac_pvt {
	unsigned long inject;
	unsigned long error_type;
	unsigned long address;
};

#endif // __OCTEONTX_EDAC_H__
