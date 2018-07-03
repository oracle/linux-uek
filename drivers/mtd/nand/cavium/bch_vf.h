/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __BCH_VF_H
#define __BCH_VF_H

#include "bch_common.h"

struct bch_vf {
	u16 flags; /* Flags to hold device status bits */
	u8 vfid; /* which VF (0.. _MAX - 1) */
	u8 node; /* Operating node: Bits (46:44) in BAR0 address */
	u8 priority; /* VF priority ring: 1-High proirity round
		      * robin ring;0-Low priority round robin ring;
		      * not for BCH
		      */
	struct pci_dev *pdev; /* pci device handle */
	void __iomem *reg_base; /* Register start address */
};

struct buf_ptr {
	u8 *vptr;
	dma_addr_t dma_addr;
	u16 size;
};

extern void *cavm_bch_getp(void);
extern void cavm_bch_putp(void *pf);
extern void *cavm_bch_getv(void);
extern void cavm_bch_putv(void *vf);

extern int cavm_bch_encode(struct bch_vf *vf,
		dma_addr_t block, uint16_t block_size,
		uint8_t ecc_level, dma_addr_t ecc,
		dma_addr_t resp);
extern int cavm_bch_decode(struct bch_vf *vf,
		dma_addr_t block_ecc_in, uint16_t block_size,
		uint8_t ecc_level, dma_addr_t block_out,
		dma_addr_t resp);


extern int cavm_bch_wait(struct bch_vf *vf, union bch_resp *resp,
				dma_addr_t bch_rhandle);

/**
 * Ring the BCH doorbell telling it that new commands are
 * available.
 *
 * @param num_commands	Number of new commands
 * @param vf		virtual function handle
 */
static inline void cavm_bch_write_doorbell(uint64_t num_commands,
						struct bch_vf *vf)
{
	uint64_t num_words =
		num_commands * sizeof(union bch_cmd) / sizeof(uint64_t);
	writeq(num_words, vf->reg_base + BCH_VQX_DOORBELL(0));
}

#endif /* __BCH_VF_H */
