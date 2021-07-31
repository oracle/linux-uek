/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Supports OcteonTX2 Generic Hardware Error Source (BED)
 * Boot Error Data (BED) from BERT table DT and ACPI
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef __OTX2_GHES_BERT_H__
#define __OTX2_GHES_BERT_H__

/*
 * Boot Error Data Source
 */
struct mrvl_bed_source {
	phys_addr_t          block_pa;
	u64                  block_sz;
	void __iomem         *block_va;
	phys_addr_t          bert_pa;
	u64                  bert_sz;
	void                 *bert_va;
	u32                  error_cnt;
};

struct bed_bert_mem_entry {
	union {
		/* These are identical; both are listed here for clarity */
		struct acpi_hest_generic_status hest;
		struct acpi_bert_region         bert;
	} estatus;
	struct acpi_hest_generic_data   gen_data;
	struct cper_sec_mem_err_old     mem_err;
} __packed;

#endif //__OTX2_GHES_BERT_H__
