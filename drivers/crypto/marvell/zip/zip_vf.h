/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ZIP_VF_H__
#define __ZIP_VF_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>

#include "zip_octeontx.h"

#define DRV_NAME "octeontx-zipvf"
#define DRV_VERSION "1.0"

/* OcteonTX-ZIP device Major number */
#define DEVICE_MAJOR 126

/* PCI device ID */
#define PCI_DEVICE_ID_OCTEONTX_ZIPVF 0xA037
#define PCI_DEVICE_ID_OCTEONTX2_ZIPVF 0xA083

/*
 * ZIP Command buffer size
 * Each ZIP instruction has 16 words of 8 byte each.
 * 8064/128 = 63, It can store upto 63 instructions in command buffer.
 * 8 bytes is used to store the address of the command buffer.
 */
#define ZIP_CMD_QBUF_SIZE (8064 + 8)

/* ZIP VF Register Offsets */
#define ZIP_VF_VQX_DOORBELL       0x1000
#define ZIP_VF_VQX_ENA            0x0010
#define ZIP_VF_VQX_SBUF_ADDR      0x0020
#define ZIP_VF_VQX_DONE           0x0100

struct zip_vf_device *zip_vf_get_device_by_id(int id);

/* ZIP Compression statistics */
struct zip_vf_stats {
	atomic64_t comp_req_submit; /* Compression requests submitted */
	atomic64_t comp_req_complete; /* Compression requests completed */
	atomic64_t pending_req; /* Pending requests */
	atomic64_t comp_in_bytes; /* Compression input bytes */
	atomic64_t comp_out_bytes; /* Compression output bytes */
};

/* ZIP VF Instruction Queue */
struct zip_vf_iq {
	spinlock_t lock; /* Spin lock variable */
	u64 *sw_head; /* Software head pointer to buffer */
};

/* ZIP VF buffer address structure */
struct zip_vf_buf_addr {
	dma_addr_t dma_addr; /* DMA handle */
	u64 *virt_addr; /* Virtual Address */
};

/* ZIP VF Device structure */
struct zip_vf_device {
	struct pci_dev *pdev;  /* Pointer to PCI device structure */
	struct zip_vf_iq iq; /* ZIP VF Instruction queue */
	struct zip_vf_stats stats; /* ZIP VF stats structure variable */
	struct zip_vf_buf_addr sbuf; /* ZIP VF starting buffer address */
	u32 index; /* Index for ZIP VF devices */
	void __iomem *reg_base; /* Register start address */
};

/* ZIP Generic pointer structure */
union zip_zptr_ctl_s {
	u64 u;
	struct {
		u64 data_be               : 1;  /* Reserved */
		u64 nc                    : 1;  /* No cache allocation */
		u64 fw                    : 1;  /* Full-block write */
		u64 reserved_67_95        : 29; /* Reserved */
		/**
		 * Number of gather/ scatter list pointer entries pointed
		 * by addr.
		 */
		u64 length                : 16;
		u64 reserved_112_127      : 16; /* Reserved */
	} s;
};

/* ZIP Generic address pointer */
union zip_zptr_addr_s {
	u64 u;
	struct {
		u64 addr : 64; /* Address */
	} s;
};

/**
 * ZIP Instruction Structure
 * Each ZIP instruction has 16 words (they are called IWORD0 to IWORD15
 * within the structure).
 */
union zip_inst_s {
	u64 u[16];
	struct zip_inst_s_cn83xx {
		/* Word 0 */
		u64 hg                    : 1;  /* History gather */
		u64 dg                    : 1;  /* Data gather */
		u64 ds                    : 1;  /* Data scatter */
		/* Compression/Decompression operation */
		u64 op                    : 2;
		u64 bf                    : 1;  /* Beginning of file */
		u64 ef                    : 1;  /* End of input data */
		u64 cc                    : 2;  /* Compression coding */
		/* Compression speed/storage */
		u64 ss                    : 2;
		u64 sf                    : 1;  /* Sync flush */
		/* Hash algorithm and enable */
		u64 halg                  : 3;
		u64 hmif                  : 1;  /* Hash more-in-file */
		/* Previously-generated compressed bits */
		u64 exbits                : 7;
		/* Initial values for hashing */
		u64 iv                    : 1;
		/**
		 * Number of bits produced beyond the last output byte
		 * written
		 */
		u64 exn                   : 3;
		u64 reserved_27_31        : 5;  /* Reserved */
		/* Indicates the maximum number of output-stream bytes */
		u64 totaloutputlength     : 24;
		u64 reserved_56_62        : 7;  /* Reserved */
		u64 doneint               : 1;  /* Done interrupt */
		/* Word 1: Current state of the ADLER32 or CRC32 */
		u64 adlercrc32            : 32;
		u64 reserved_96_111       : 16; /* Reserved */
		u64 historylength         : 16; /* Number of history bytes */
		/* Word 2: Decompression context pointer address */
		union zip_zptr_addr_s  ctx_ptr_addr;
		/* Word 3: Decompression context pointer control */
		union zip_zptr_ctl_s   ctx_ptr_ctl;
		/* Word 4: Decompression history pointer address */
		union zip_zptr_addr_s  his_ptr_addr;
		/* Word 5: Decompression history pointer control */
		union zip_zptr_ctl_s   his_ptr_ctl;
		/* Word 6: Input and compression history pointer address */
		union zip_zptr_addr_s  inp_ptr_addr;
		/* Word 7: Input and compression history pointer control */
		union zip_zptr_ctl_s   inp_ptr_ctl;
		/* Word 8: Output pointer address */
		union zip_zptr_addr_s  out_ptr_addr;
		/* Word 9: Output pointer control */
		union zip_zptr_ctl_s   out_ptr_ctl;
		/* Word 10: Result pointer address */
		union zip_zptr_addr_s  res_ptr_addr;
		/* Word 11: Result pointer control */
		union zip_zptr_ctl_s   res_ptr_ctl;
		/* Word 12 */
		u64 tag                   : 32;       /* SSO Tag */
		u64 tt                    : 2;        /* SSO Tag type */
		u64 ggrp                  : 10;       /* SSO guest group */
		u64 reserved_812_831      : 20;       /* Reserved */
		/* Word 13: Pointer to a work-queue entry */
		u64 wq_ptr                : 64;
		/* Word 14 */
		u64 reserved_896_959      : 64;  /* Reserved */
		/* Word 15 */
		u64 hash_ptr              : 64;  /* Hash structure pointer */
	} s;
};

/**
 * ZIP Instruction Next-Chunk-Buffer Pointer (NPTR) Structure
 * This structure is used to chain all the ZIP instruction buffers
 * together. ZIP instruction buffers are managed (allocated and released)
 * by software.
 */
union zip_nptr_s {
	u64 u;
	struct zip_nptr_s_s {
		u64 addr                  : 64;
	} s;
};

/**
 * ZIP Generic Pointer Structure
 * This structure is the generic format of pointers in ZIP_INST_S.
 */
union zip_zptr_s {
	u64 u[2];
	struct zip_zptr_s_s {
		u64 addr                  : 64; /* Address */
		u64 data_be               : 1;  /* Reserved */
		u64 nc                    : 1;  /* No cache allocation */
		u64 fw                    : 1;  /* Full-block write */
		u64 reserved_67_95        : 29; /* Reserved */
		/**
		 * Number of gather/ scatter list pointer entries pointed
		 * at by addr.
		 */
		u64 length                : 16;
		u64 reserved_112_127      : 16; /* Reserved */
	} s;
};

/**
 * ZIP Result Structure
 * The ZIP coprocessor writes the result structure after it completes the
 * invocation. The result structure is exactly 24 bytes, and each
 * invocation of the ZIP coprocessor produces exactly one result structure.
 */
union zip_zres_s {
	u64 u[8];
	struct zip_zres_s_s {
		/**
		 * Corresponding to the bytes processed in the uncompressed
		 * stream
		 */
		u64 adler32               : 32;
		/**
		 * Corresponding to the bytes processed in the uncompressed
		 * stream
		 */
		u64 crc32                 : 32;
		/* The total number of bytes produced in the input stream */
		u64 totalbytesread        : 32;
		/* The total number of bytes produced in the output stream */
		u64 totalbyteswritten     : 32;
		/* Indicates completion/error status of the ZIP coprocessor */
		u64 compcode              : 8;
		u64 ef                    : 1;    /* End of file */
		u64 reserved_137_143      : 7;    /* Reserved */
		/* Previously-generated compressed bits */
		u64 exbits                : 7;
		u64 reserved_151          : 1;    /* Reserved */
		/**
		 * Number of bits produced beyond the last output byte
		 * written
		 */
		u64 exn                   : 3;
		u64 reserved_155_158      : 4;    /* Reserved */
		u64 doneint               : 1;    /* Done interrupt */
		/**
		 * Number of compressed input bits consumed to decompress
		 * all blocks
		 */
		u64 totalbitsprocessed    : 32;
		/** Total hash length in bytes */
		u64 hshlen                : 61;
		u64 reserved_253_255      : 3;    /* Reserved */
		u64 hash0;             /* Double-word 0 of computed hash */
		u64 hash1;             /* Double-word 1 of computed hash */
		u64 hash2;             /* Double-word 2 of computed hash */
		u64 hash3;             /* Double-word 3 of computed hash */
	} s;
};

/**
 * Register (NCB) zip_vq#_doorbell
 *
 * ZIP VF Queue Doorbell Registers
 * Doorbells for the ZIP instruction queues.
 */
union zip_vqx_doorbell {
	u64 u;
	struct zip_vqx_doorbell_s {
		u64 dbell_cnt             : 20;
		u64 reserved_20_63        : 44;
	} s;
};

/**
 * Register (NCB) zip_vq#_ena
 *
 * ZIP VF Queue Enable Register
 * If a queue is disabled, ZIP CTL stops fetching instructions from the
 * queue.
 */
union zip_vqx_ena {
	u64 u;
	struct zip_vqx_ena_s {
		u64 ena                   : 1;
		u64 reserved_1_63         : 63;
	} s;
};

/**
 * Register (NCB) zip_vq#_sbuf_addr
 *
 * ZIP VF Queue Starting Buffer Address Registers
 * These registers set the buffer parameters for the instruction queues.
 * When quiescent (i.e. outstanding doorbell count is 0), it is safe to
 * rewrite this register to effectively reset the command buffer state
 * machine. These registers must be programmed after software programs
 * the corresponding ZIP_QUE()_SBUF_CTL.
 */
union zip_vqx_sbuf_addr {
	u64 u;
	struct zip_vqx_sbuf_addr_s {
		u64 off                   : 7;
		u64 ptr                   : 42;
		u64 reserved_49_63        : 15;
	} s;
};

/* ZIP register write API */
static inline void zip_vf_reg_write(struct zip_vf_device *vf, u64 offset,
					u64 val)
{
	writeq(val, vf->reg_base + offset);
}

/* ZIP register read API */
static inline u64 zip_vf_reg_read(struct zip_vf_device *vf, u64 offset)
{
	return readq(vf->reg_base + offset);
}

void zip_vf_load_instr(struct zip_vf_device *vf, union zip_inst_s *instr);

#endif /* __ZIP_VF_H__ */
