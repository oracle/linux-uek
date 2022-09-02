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

#define OCTEONTX_GHES_ERR_RING_SIG ((int)'M' << 24 | 'R' << 16 | 'V' << 8 | 'L')

#define CN10K_CPU_MODEL			(0xd49)

#define PCI_DEVICE_ID_OCTEONTX2_LMC	(0xa022)
#define PCI_DEVICE_ID_OCTEONTX2_MCC	(0xa070)
#define PCI_DEVICE_ID_OCTEONTX2_MDC	(0xa073)

#define OCTEONTX2_EDAC_INJECT		(0xc2000c0b)
#define CN10K_EDAC_INJECT		(0xc2000b10)

#define OCTEONTX_MDC_EINJ_CAP	(0x10000000)
#define OCTEONTX_MCC_EINJ_CAP	(0x40000000)

#define CN10KA_DSS_EINJ_CAP	(0x20000000)

#define OCTEONTX_EDAC_F_BITMASK		0x007 /* single bit to corrupt */
#define OCTEONTX_EDAC_F_MULTI		0x008 /* corrupt multiple bits */
#define OCTEONTX_EDAC_F_CLEVEL		0x070 /* cache level to corrupt (L0 == DRAM) */
#define OCTEONTX_EDAC_F_ICACHE		0x080 /* Icache, not Dcache */
#define OCTEONTX_EDAC_F_REREAD		0x100 /* read-back in EL3 */
#define OCTEONTX_EDAC_F_PHYS		0x200 /* target is EL3-physical, not EL012 */

#define SIZE	256
#define EDAC_FW_REC_SIZE	32
#define NAME_SZ	8
#define CANARY	0xa5a5a5a5a5a5a5a5

struct processor_error {
	struct cper_sec_proc_arm desc;
	struct cper_arm_err_info info;
};

union octeontx_ghes_cper {
	struct cper_sec_mem_err mem;
	struct processor_error core;
};

struct octeontx_ghes_ring_record {
	union octeontx_ghes_cper cper;
	uint32_t severity;
	char msg[EDAC_FW_REC_SIZE];
};

struct octeontx_ghes_ring {
	uint32_t head;
	uint32_t tail;
	uint32_t size;
	uint32_t sig;
	uint32_t reg;
	struct octeontx_ghes_ring_record records[0] __aligned(8);
};

struct octeontx_ghes {
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
	struct octeontx_ghes *ghes;
	size_t count;
};

struct octeontx_edac_pvt {
	unsigned long inject;
	unsigned long error_type;
	unsigned long address;
	struct octeontx_ghes *ghes;
};

#endif // __OCTEONTX_EDAC_H__
