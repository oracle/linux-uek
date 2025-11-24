/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell OcteonTx2, CN10K EDAC Firmware First RAS driver
 *
 * Copyright (C) 2024 Marvell.
 */

#ifndef __OCTEONTX_EDAC_H__
#define __OCTEONTX_EDAC_H__

#define OCTEONTX2_RING_SIG ((int)'M' << 24 | 'R' << 16 | 'V' << 8 | 'L')

#define PCI_DEVICE_ID_OCTEONTX2_LMC	(0xa022)
#define PCI_DEVICE_ID_OCTEONTX2_MCC	(0xa070)
#define PCI_DEVICE_ID_OCTEONTX2_MDC	(0xa073)

#define OCTEONTX2_EDAC_INJECT	(0xc2000c0b)
#define OCTEONTX2_MDC_EINJ_CAP	(0x10000000)
#define OCTEONTX2_MCC_EINJ_CAP	(0x40000000)

#define CN10K_EDAC_INJECT	(0xc2000b10)
#define CN10K_DSS_EINJ_CAP	(0x20000000)	// ECC
#define CN10K_DSS_EINJ_CRC	(0x40000000)	// CRC

#define IS_BITMASK_SET(variable, bitmask) (((variable) & (bitmask)) == (bitmask))

#define SIZE	CPER_REC_LEN
#define NAME_SZ	8
#define OCTEONTX_GHES_REC_OLD_VER 0
#define OCTEONTX_GHES_REC_NEW_VER 1

extern u32 octeontx_ghes_record_ver;
struct cper_sec_plat_gic {
	uint8_t validation_bits;
	uint8_t error_type;
	uint8_t error_sev;
	uint8_t reserved0;
	uint32_t error_code;
	uint64_t misc0;
	uint64_t misc1;
	uint64_t erraddr;
};

struct cper_sec_platform_err {
	struct cper_sec_fw_err_rec_ref fwrec;
	uint32_t module_id;
	uint32_t reserved0;
	union {
		struct cper_sec_plat_gic gic;
	} perr;
};

struct apa_wdog_info {
	uint64_t core_id;
	uint64_t apa_wdog_int_w1c;
	uint64_t apa_wdog_core_diag;
	uint64_t apa_wdog_struct_crd_diag;
	uint64_t apa_wdog_struct_txnid_diag;
	uint64_t apa_wdog_struct_rqb_diag;
	uint64_t apa_wdog_struct_dat_diag;
};

struct vendor_info {
	struct apa_wdog_info apa_wdog_data;
};

struct processor_error {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
};

struct processor_error_new {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
	struct cper_arm_ctx_info ctx;
	uint64_t regs[32];
	struct cper_arm_ctx_info el1ctx;
	uint64_t elr_el1;
	uint64_t esr_el1;
	uint64_t far_el1;
	uint64_t isr_el1;
	uint64_t mair_el1;
	uint64_t midr_el1;
	uint64_t mpidr_el1;
	uint64_t sctlr_el1;
	uint64_t sp_el0;
	uint64_t sp_el1;
	uint64_t spsr_el1;
	uint64_t tcr_el1;
	uint64_t tpidr_el0;
	uint64_t tpidr_el1;
	uint64_t tpidrro_el0;
	uint64_t ttbr0_el1;
	uint64_t ttbr1_el1;
	struct cper_arm_ctx_info el2ctx;
	uint64_t elr_el2;
	uint64_t esr_el2;
	uint64_t far_el2;
	uint64_t hacr_el2;
	uint64_t hcr_el2;
	uint64_t hpfar_el2;
	uint64_t mair_el2;
	uint64_t sctlr_el2;
	uint64_t sp_el2;
	uint64_t spsr_el2;
	uint64_t tcr_el2;
	uint64_t tpidr_el2;
	uint64_t ttbr0_el2;
	uint64_t vtcr_el2;
	uint64_t vttbr_el2;

	struct cper_arm_ctx_info el3ctx;
	uint64_t elr_el3;
	uint64_t esr_el3;
	uint64_t far_el3;
	uint64_t mair_el3;
	uint64_t sctlr_el3;
	uint64_t sp_el3;
	uint64_t spsr_el3;
	uint64_t tcr_el3;
	uint64_t tpidr_el3;
	uint64_t ttbr0_el3;
	struct vendor_info vendor_data;
};

struct octeontx_ghes_record {
	union {
		struct processor_error  core;
		struct cper_sec_mem_err mem;
		struct cper_sec_platform_err gic;
	};
	u32 error_severity;
	char msg[32];
	u64 syndrome;
	struct processor_error_new  core_new;
};

struct octeontx_ghes_ring {
	u32 head;
	u32 tail;
	u32 size;
	u32 sig;
	u32 res;
	struct octeontx_ghes_record records[0] __aligned(8);
};

struct octeontx_edac {
	union {
		struct mem_ctl_info *mci;
		struct edac_device_ctl_info *edac_dev;
	};
	phys_addr_t ring_pa;
	struct octeontx_ghes_ring __iomem *ring;
	size_t ring_sz;
	u32 sdei_num;
	u32 ecc_cap;
	struct mutex lock;
	char name[NAME_SZ];
	struct delayed_work work;
};

struct octeontx_ghes_list {
	struct octeontx_edac *ghes;
	u32 count;
};

struct octeontx_edac_pvt {
	unsigned long inject;
	unsigned long error_type;
	unsigned long address;
	struct octeontx_edac *ghes;
};

#endif // __OCTEONTX_EDAC_H__
