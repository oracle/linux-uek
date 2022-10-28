/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell OcteonTx2, CN10K EDAC Firmware First RAS driver
 *
 * Copyright (C) 2022 Marvell.
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
#define CN10K_DSS_EINJ_CAP	(0x20000000)

#define SIZE	256
#define NAME_SZ	8

struct processor_error {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
};

struct octeontx_ghes_record {
	union {
		struct processor_error  core;
		struct cper_sec_mem_err mem;
	};
	u32 error_severity;
	char msg[32];
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
