/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX and OcteonTX2 ZIP Physical Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ZIP_PF_H__
#define __ZIP_PF_H__

#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/pci.h>

#define DRV_NAME "octeontx-zip"
#define DRV_VERSION "1.0"

/* PCI device IDs */
#define PCI_DEVICE_ID_OCTEONTX_ZIP_PF 0xA01A
#define PCI_DEVICE_ID_OCTEONTX2_ZIP_PF 0xA082

/*
 * ZIP Command buffer size
 * Each ZIP instruction has 16 words of 8 byte each.
 * 8064/128 = 63, It can store upto 63 instructions in command buffer.
 * 8 bytes is used to store the address of the command buffer.
 */
#define ZIP_CMD_QBUF_SIZE (8064 + 8)

/* Maximum number of VFs supported */
#define ZIP_MAX_VFS 8

/* MSIX count for OcteonTX */
#define ZIP_PF_OCTEONTX_MSIX_COUNT 3

/* MSIX count for OcteonTX2 */
#define ZIP_PF_OCTEONTX2_MSIX_COUNT 1

struct zip_pf_device {
	struct pci_dev *pdev;
	struct msix_entry *msix_entries;
	int dev_id;
	int total_vf;
	u8 num_vf;
	void __iomem *reg_base;
};

/* ZIP PF Register Offsets */
#define ZIP_PF_CMD_CTL          0x0
#define ZIP_PF_QUEX_GMCTL(x)    (0x800  | ((x) << 20))
#define ZIP_PF_QUEX_SBUF_CTL(x) (0x1200 | ((x) << 3))
#define ZIP_PF_QUEX_MAP(x)      (0x1400 | ((x) << 3))
#define ZIP_PF_FIFE_INT         0x78
#define ZIP_PF_FIFE_INT_W1S     0x80
#define ZIP_PF_FIFE_ENA_W1S     0x88
#define ZIP_PF_FIFE_ENA_W1C     0x90
#define ZIP_PF_ECCE_INT         0x580
#define ZIP_PF_ECCE_INT_W1S     0x588
#define ZIP_PF_ECCE_ENA_W1S     0x590
#define ZIP_PF_ECCE_ENA_W1C     0x598
#define ZIP_PF_MBOX_INT         0x900
#define ZIP_PF_MBOX_INT_W1S     0x920
#define ZIP_PF_MBOX_ENA_W1C     0x940
#define ZIP_PF_MBOX_ENA_W1S     0x960
#define ZIP_PF_VFX_MBOXX(x, y)  (0x2000 | ((x) << 4) | ((y) << 3))

/**
 * Register (NCB) zip_que#_map
 *
 * ZIP Queue Mapping Registers
 * These registers control how each instruction queue maps to ZIP cores.
 */
union zip_quex_map {
	u64 u;
	struct zip_quex_map_s {
	/* Word 0 - Little Endian */
		u64 zce                   : 6;
		u64 reserved_6_63         : 58;
	} s;
};

/**
 * Register (NCB) zip_que#_sbuf_ctl
 *
 * ZIP Queue Buffer Parameter Registers
 * These registers set the buffer parameters for the instruction queues.
 * When quiescent (i.e. outstanding doorbell count is 0), it is safe to
 * rewrite this register to effectively reset the command buffer state
 * machine. These registers must be programmed before software programs
 * the corresponding ZIP_QUE(0..7)_SBUF_ADDR.
 */
union zip_quex_sbuf_ctl {
	u64 u;
	struct zip_quex_sbuf_ctl_s {
	/* Word 0 - Little Endian */
		u64 aura                  : 12;
		u64 reserved_12_15        : 4;
		u64 stream_id             : 8;
		u64 reserved_24_29        : 6;
		u64 inst_free             : 1;
		u64 inst_be               : 1;
		u64 size                  : 13;
		u64 reserved_45_63        : 19;
	} s;
};

/**
 * Register (NCB) zip_cmd_ctl
 *
 * ZIP Clock/Reset Control Register
 * This register controls clock and reset.
 */
union zip_cmd_ctl {
	u64 u;
	struct zip_cmd_ctl_s {
	/* Word 0 - Little Endian */
		u64 reset                 : 1;
		u64 forceclk              : 1;
		u64 reserved_2_63         : 62;
	} s;
};

/* ZIP register write API */
static inline void zip_pf_reg_write(struct zip_pf_device *pf, u64 offset,
				    u64 val)
{
	writeq(val, pf->reg_base + offset);
}

/* ZIP register read API */
static inline u64 zip_pf_reg_read(struct zip_pf_device *pf, u64 offset)
{
	return readq(pf->reg_base + offset);
}

#endif /* __ZIP_PF_H__ */
