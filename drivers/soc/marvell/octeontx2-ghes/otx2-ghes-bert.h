/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Supports OcteonTX2 Generic Hardware Error Source
 * Boot Error Data (BED)
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef __OTX2_GHES_BERT_H__
#define __OTX2_GHES_BERT_H__

/*
 * Boot Error Data Source
 */
struct mrvl_bed_source {
	phys_addr_t          estatus_pa;
	u64                  estatus_sz;
	void __iomem         *estatus_va;

	phys_addr_t          ring_pa;
	u64                  ring_sz;
	void __iomem         *ring_va;
};

struct bed_bert_mem_entry {
	struct acpi_bert_region       bert;
	struct acpi_hest_generic_data gen_data;
	struct cper_sec_mem_err       mem_err;
};

struct otx2_ghes_err_ring {
	uint32_t head;
	uint32_t tail;
	uint32_t size;
	uint32_t sig;
	uint32_t res;
	struct bed_bert_mem_entry records[0] __aligned(8);
};

#endif //__OTX2_GHES_BERT_H__
