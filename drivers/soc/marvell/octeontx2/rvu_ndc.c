// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/pci.h>

#include "rvu.h"
#include "rvu_reg.h"

static int ndc_errata_35094_preop(struct rvu *rvu, int blkaddr)
{
	u64 port_rc[6], port_wc[6];
	int port, retry_count;
	bool retry;
	u64 val;

	/* Enable full backpressure to stall all NDC requests */
	val = rvu_read64(rvu, blkaddr, NDC_AF_BP_TEST(0));
	val |= BIT_ULL(61);
	val &= ~GENMASK_ULL(23, 16);
	rvu_write64(rvu, blkaddr, NDC_AF_BP_TEST(0), val);

	val = rvu_read64(rvu, blkaddr, NDC_AF_BP_TEST_ENABLE);
	val |= GENMASK_ULL(43, 40);
	rvu_write64(rvu, blkaddr, NDC_AF_BP_TEST_ENABLE, val);

	/* Wait for OUTSTD_PC read and write count to be contstant
	 * over a period of 5 us
	 */
	retry_count = 0;
	do {
		retry = false;

		/* Take snapshot */
		for (port = 0; port < 6; port++) {
			port_rc[port] =  rvu_read64(rvu, blkaddr,
						 NDC_AF_PORTX_RTX_RWX_OSTDN_PC
						 (port, CACHING,
						  NDC_READ_TRANS));

			port_wc[port] =  rvu_read64(rvu, blkaddr,
						 NDC_AF_PORTX_RTX_RWX_OSTDN_PC
						 (port, CACHING,
						  NDC_WRITE_TRANS));
		}

		udelay(5);

		/* Verify for any change after the wait period */
		for (port = 0; port < 6; port++) {
			val =  rvu_read64(rvu, blkaddr,
						NDC_AF_PORTX_RTX_RWX_OSTDN_PC
						 (port, CACHING,
						  NDC_READ_TRANS));
			if (val ^ port_rc[port]) {
				retry = true;
				break;
			}

			val =  rvu_read64(rvu, blkaddr,
						 NDC_AF_PORTX_RTX_RWX_OSTDN_PC
						 (port, CACHING,
						  NDC_WRITE_TRANS));
			if (val ^ port_wc[port]) {
				retry = true;
				break;
			}
		}

		retry_count++;
		if (retry_count > 200) /* time out of ~1ms */
			return -EIO;

	} while (retry);

	return 0;
}

static int ndc_errata_35094_preop_blk(struct rvu *rvu, int blktype)
{
	int err = 0;

	if (blktype == BLKTYPE_NIX) {
		err = ndc_errata_35094_preop(rvu, BLKADDR_NDC_NIX0_RX);
		if (err)
			return err;
		return ndc_errata_35094_preop(rvu, BLKADDR_NDC_NIX0_TX);
	} else if (blktype == BLKTYPE_NPA) {
		return ndc_errata_35094_preop(rvu, BLKADDR_NDC_NPA0);
	}

	return 0;
}

static void ndc_errata_35094_postop1(struct rvu *rvu, int blkaddr)
{
	u64 val;

	val = rvu_read64(rvu, blkaddr, NDC_AF_BP_TEST_ENABLE);
	val &= ~GENMASK_ULL(43, 40);
	rvu_write64(rvu, blkaddr, NDC_AF_BP_TEST_ENABLE, val);
}

static void ndc_errata_35094_postop1_blk(struct rvu *rvu, int blktype)
{
	if (blktype == BLKTYPE_NIX) {
		ndc_errata_35094_postop1(rvu, BLKADDR_NDC_NIX0_RX);
		ndc_errata_35094_postop1(rvu, BLKADDR_NDC_NIX0_TX);
	} else if (blktype == BLKTYPE_NPA) {
		ndc_errata_35094_postop1(rvu, BLKADDR_NDC_NPA0);
	}
}

static void ndc_errata_35094_postop2(void)
{
	udelay(50);
}

int rvu_ndc_sync_errata_workaround(struct rvu *rvu, int lfblkaddr, int lfidx,
				   u64 lfoffset, int ndcblkaddr)
{
	int err;

	err = ndc_errata_35094_preop(rvu, ndcblkaddr);
	if (err)
		return err;

	/* Sync cached info for this LF in NDC to LLC/DRAM */
	rvu_write64(rvu, lfblkaddr, lfoffset, BIT_ULL(12) | lfidx);

	ndc_errata_35094_postop1(rvu, ndcblkaddr);

	err = rvu_poll_reg(rvu, lfblkaddr, lfoffset, BIT_ULL(12), true);

	ndc_errata_35094_postop2();

	return err;
}

int rvu_lf_reset_ndc_errata_workaround(struct rvu *rvu, struct rvu_block *block,
				   int lf)
{
	int err;

	err = ndc_errata_35094_preop_blk(rvu, block->type);
	if (err)
		return err;

	/* Do LF reset operation */
	rvu_write64(rvu, block->addr, block->lfreset_reg, lf | BIT_ULL(12));

	ndc_errata_35094_postop1_blk(rvu, block->type);

	err = rvu_poll_reg(rvu, block->addr, block->lfreset_reg, BIT_ULL(12),
			   true);

	ndc_errata_35094_postop2();

	return err;
}

int rvu_ndc_sync(struct rvu *rvu, int lfblkaddr, int lfidx,
		 u64 lfoffset, int ndcblkaddr)
{
	int err;

	if (is_rvu_9xxx_A0(rvu))
		return rvu_ndc_sync_errata_workaround(rvu, lfblkaddr, lfidx,
						      lfoffset, ndcblkaddr);

	/* Sync cached info for this LF in NDC to LLC/DRAM */
	rvu_write64(rvu, lfblkaddr, lfoffset, BIT_ULL(12) | lfidx);

	err = rvu_poll_reg(rvu, lfblkaddr, lfoffset, BIT_ULL(12), true);

	return err;
}
