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
	void __iomem         *bert_va;
	u32                  error_cnt;
};

struct bed_bert_mem_entry {
	struct acpi_bert_region         bert;
	struct acpi_hest_generic_data   gen_data;
	struct cper_sec_mem_err         mem_err;
} __packed;

#define SDEI_GHES_EVENT_NAME_MAX_CHARS 16

#define OTX2_GHES_ERR_RING_SIG ((int)'M' << 24 | 'R' << 16 | 'V' << 8 | 'L')

#define OTX2_GHES_ERR_REC_FRU_TEXT_LEN 32
#define OTX2_GHES_ERR_RECS 4

struct processor_error {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
};

struct otx2_ghes_err_record {
	union {
		struct processor_error  core;
		struct cper_sec_mem_err cper;
	};
	uint32_t severity;
	char fru_text[OTX2_GHES_ERR_REC_FRU_TEXT_LEN];
};

struct otx2_ghes_err_ring {
	uint32_t head;
	uint32_t tail;
	uint32_t size;
	uint32_t sig;
	uint32_t reg;
	struct otx2_ghes_err_record records[0] __aligned(8);
};

#endif //__OTX2_GHES_BERT_H__
