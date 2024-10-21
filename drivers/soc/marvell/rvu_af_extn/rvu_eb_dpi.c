// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/pci.h>
#include "mbox.h"
#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eblock.h"
#include "rvu_trace.h"
#include "rvu_dpi_mbox.h"

/* Maximum number of DPI blocks */
#define MAX_DPI_BLKS		2

/* DPI_ENGX_BUF 8 KB FIFO for 0,1,2,3 engines, 16KB for 4,5
 * need to check for 6,7!!
 */
static unsigned long eng_fifo_buf = 0x101008080808;

#define DPI_MAX_ENGINES	6

#define DPI_ENG_BUF_BLKS(x)			((x) & 0x1fULL)
#define DPI_ENG_BUF_GET_BLKS(x)			((x) & 0x1fULL)
#define DPI_DMA_CONTROL_DMA_ENB(x)              (((x) & 0x3fULL) << 48)
#define DPI_CTL_EN                              (0x1ULL)

#define DPI_EBUS_MRRS_MIN			128
#define DPI_EBUS_MRRS_MAX			1024
#define DPI_EBUS_MPS_MIN			128
#define DPI_EBUS_MPS_MAX			1024
#define DPI_EBUS_MAX_PORTS			2
#define DPI_EBUS_PORTX_CFG_MRRS(x)		(((x) & 0x7) << 0)
#define DPI_EBUS_PORTX_CFG_MPS(x)		(((x) & 0x7) << 4)

#define RL_PERIOD 8
#define RL_BURST_TH 64
#define RL_TOKEN 8
#define SDP_RL_PERIOD 8
#define SDP_RL_BURST_TH 64
#define SDP_RL_TOKEN 8
#define BPHY_RL_PERIOD 8
#define BPHY_RL_BURST_TH 64
#define BPHY_RL_TOKEN 8
#define PSW_RL_PERIOD 8
#define PSW_RL_BURST_TH 64
#define PSW_RL_TOKEN 8

#define DPI_DMA_CONTROL_O_MODE			(0x1ULL << 14)
#define DPI_DMA_CONTROL_O_NS			(0x1ULL << 17)
#define DPI_DMA_CONTROL_O_RO			(0x1ULL << 18)
#define DPI_DMA_CONTROL_LDWB			(0x1ULL << 32)
#define DPI_DMA_CONTROL_WQECSMODE1		(0x1ULL << 37)
#define DPI_DMA_CONTROL_ZBWCSEN			(0x1ULL << 39)
#define DPI_DMA_CONTROL_WQECSOFF(offset)	(((u64)offset) << 40)
#define DPI_DMA_CONTROL_WQECSDIS		(0x1ULL << 47)
#define DPI_DMA_CONTROL_UIO_DIS			(0x1ULL << 55)
#define DPI_DMA_CONTROL_PKT_EN			(0x1ULL << 56)
#define DPI_DMA_CONTROL_PORT1_EN		(0x1ULL << 57)
#define DPI_DMA_CONTROL_FFP_DIS			(0x1ULL << 59)

#define DPI_WPORT				(0x1ULL << 4)
#define DPI_RPORT				(0x1ULL << 0)

struct dpi_drvdata {
	int res_idx;
};

static int dpi_dma_engine_get_num(void)
{
	return DPI_MAX_ENGINES;
}

static void rvu_dpi_unregister_interrupts_block(struct rvu_block *block,
						void *data)
{
	(void)block;
	(void)data;
}

static int rvu_dpi_register_interrupts_block(struct rvu_block *block,
					     void *data)
{
	(void)block;
	(void)data;

	return 0;
}

static int dpi_exit(struct rvu *rvu)
{
	int engine = 0, port, blkaddr;
	u64 val = 0ULL;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_DPI, 0);

		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_BUF(engine), val);
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_CFG(engine), 0x0ULL);
	}

	rvu_write64(rvu, blkaddr, DPI_AF_DMA_CONTROL, val);
	rvu_write64(rvu, blkaddr, DPI_AF_CTL, ~DPI_CTL_EN);

	for (port = 0; port < DPI_EBUS_MAX_PORTS; port++) {
		val = rvu_read64(rvu, blkaddr,
				 DPI_AF_EBUS_PORTX_CFG(port));
		val &= ~DPI_EBUS_PORTX_CFG_MRRS(0x7);
		val &= ~DPI_EBUS_PORTX_CFG_MPS(0x7);
		rvu_write64(rvu, blkaddr,
			    DPI_AF_EBUS_PORTX_CFG(port), val);
	}
	return 0;
}

static int rvu_dpi_init_block(struct rvu_block *block, void *data)
{
	int engine, blkaddr, port = 0, mrrs, mps, blkid;
	u8 *eng_buf = (u8 *)&eng_fifo_buf;
	struct dpi_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	u8 mrrs_val, mps_val;
	u64 val;

	if (!data)
		return -EINVAL;

	blkid = drvdata->res_idx;
	blkaddr = blkid ? BLKADDR_DPI1 : BLKADDR_DPI0;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		val = DPI_ENG_BUF_BLKS(eng_buf[engine & 0x7]);
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_BUF(engine), val);

		/* Here qmap for the engines are set to 0.
		 * No dpi queues are mapped to engines.
		 * When a VF is initialised corresponding bit
		 * in the qmap will be set for all engines.
		 */
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_CFG(engine), 0x0ULL);
	}

	/* Channel Table Cache Hash type.
	 * 0x0 - RND - Random spreading (Preferred)
	 * 0x1 - REM - Simple Remainder
	 * 0x2 - XOR1 - channel ^ channel_table
	 * 0x3 - XOR2 - More complex xor
	 */
	rvu_write64(rvu, blkaddr, DPI_AF_CHAN_HSEL, 0ULL);

	val = 0ULL;
	val =  (DPI_DMA_CONTROL_ZBWCSEN | DPI_DMA_CONTROL_PKT_EN |
		DPI_DMA_CONTROL_LDWB | DPI_DMA_CONTROL_O_MODE);

	val |= DPI_DMA_CONTROL_DMA_ENB(0x3fULL);

	rvu_write64(rvu, blkaddr, DPI_AF_DMA_CONTROL, val);
	rvu_write64(rvu, blkaddr, DPI_AF_CTL, DPI_CTL_EN);

	/* Set max outstanding read and load requests */
	val = (DPI_RD_FIFO_MAX_TH << 16) | DPI_NCB_MAX_MOLR;
	rvu_write64(rvu, blkaddr, DPI_AF_NCB_CFG, val);

	/* Configure MPS and MRRS for DPI */
	mrrs = DPI_EBUS_MRRS_MIN;
	mrrs_val = fls(mrrs) - 8;

	mps = DPI_EBUS_MPS_MIN;
	mps_val = fls(mps) - 8;

	for (port = 0; port < DPI_EBUS_MAX_PORTS; port++) {
		val = rvu_read64(rvu, blkaddr,
				 DPI_AF_EBUS_PORTX_CFG(port));
		val &= ~(DPI_EBUS_PORTX_CFG_MRRS(0x7) |
			 DPI_EBUS_PORTX_CFG_MPS(0x7));
		val |= (DPI_EBUS_PORTX_CFG_MPS(mps_val) |
			DPI_EBUS_PORTX_CFG_MRRS(mrrs_val));
		/* EXACT_RD_DIS, MOLR, MPS_LIM, MRRS */
		val |= (DPI_EBUS_MAX_MOLR << 8) | BIT_ULL(7) | BIT_ULL(20);
		rvu_write64(rvu, blkaddr,
			    DPI_AF_EBUS_PORTX_CFG(port), val);
	}

	/* Need to re-config DPI_AF_ENG_BUF_TH_LIMIT if required, reset values
	 * [LIMIT], [HITH_LIMIT], [HITH], [MEDTH_LIMIT],
	 * [MEDTH], [LOTH_LIMIT], and [LOTH] being used
	 */

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		val = BIT_ULL(63) | (RL_PERIOD < 32) | (RL_BURST_TH << 16) |
			RL_TOKEN;
		/* Disable rate limit initially */
		val = 0;
		rvu_write64(rvu, blkaddr, DPI_AF_ENGX_RATE_CTRL(engine), val);
	}

	val = BIT_ULL(63) | (SDP_RL_PERIOD < 32) | (SDP_RL_BURST_TH << 16) |
		SDP_RL_TOKEN;
	/* Disable rate limit initially */
	val = 0;
	rvu_write64(rvu, blkaddr, DPI_AF_SDP_OPKT_RATE_CTRL, val);
	rvu_write64(rvu, blkaddr, DPI_AF_SDP_OPKT_RATE_CTRL, val);

	val = BIT_ULL(63) | (BPHY_RL_PERIOD < 32) | (BPHY_RL_BURST_TH << 16) |
		BPHY_RL_TOKEN;
	/* Disable rate limit initially */
	val = 0;
	rvu_write64(rvu, blkaddr, DPI_AF_BPHYX_OPKT_RATE_CTRL(0), val);
	rvu_write64(rvu, blkaddr, DPI_AF_BPHYX_OPKT_RATE_CTRL(1), val);

	val = BIT_ULL(63) | (PSW_RL_PERIOD < 32) | (PSW_RL_BURST_TH << 16) |
		PSW_RL_TOKEN;
	/* Disable rate limit initially */
	val = 0;
	rvu_write64(rvu, blkaddr, DPI_AF_PSWX_OPKT_RATE_CTRL(0), val);
	rvu_write64(rvu, blkaddr, DPI_AF_PSWX_OPKT_RATE_CTRL(1), val);

	mutex_init(&rvu->dpi_rsrc_lock);

	return 0;
}

static void rvu_dpi_freemem_block(struct rvu_block *block, void *data)
{
	(void)block;
	(void)data;

	/* Free up resources related to DPI channel tables etc.. */
}

static int rvu_setup_dpi_hw_resource(struct rvu_block *block, void *data)
{
	struct dpi_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	struct rvu_hwinfo *hw = rvu->hw;
	int blkid, err, blkaddr;
	u64 cfg;

	blkid = drvdata->res_idx;
	blkaddr = blkid ? BLKADDR_DPI1 : BLKADDR_DPI0;
	block = &hw->block[blkaddr];

	/* Init DPI LF's bitmap */
	if (!block->implemented)
		return 0;
	cfg = rvu_read64(rvu, blkaddr, DPI_AF_CONST);
	block->lf.max = cfg & 0xFFF;
	block->addr = blkaddr;
	block->type = BLKTYPE_DPI;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = DPI_AF_RVU_LF_CFG_DEBUG;
	block->pf_lfcnt_reg = DPI_AF_CONST;
	block->vf_lfcnt_reg = DPI_AF_CONST;
	block->lfcfg_reg = DPI_PRIV_LFX_CFG;
	block->msixcfg_reg = DPI_PRIV_LFX_INT_CFG(0);
	block->lfreset_reg = DPI_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "DPI%d", blkid);
	err = rvu_alloc_bitmap(&block->lf);
	if (err)
		return err;

	/* Allocate memory for block LF/slot to pcifunc mapping info */
	block->fn_map =
		devm_kcalloc(rvu->dev, block->lf.max, sizeof(u16), GFP_KERNEL);
	if (!block->fn_map) {
		err = -ENOMEM;
		goto free_bmap;
	}

	rvu_reset_blk_lfcfg(rvu, block);

	rvu_scan_block(rvu, block);

	return 0;

free_bmap:
	rvu_free_bitmap(&block->lf);

	return err;
}

static int rvu_dpi_mbox_handler(struct otx2_mbox *mbox, int devid,
				struct mbox_msghdr *req)
{
	(void)mbox;
	(void)devid;
	(void)req;

	return 0;
}

static void *rvu_dpi_probe(struct rvu *rvu, int blkaddr)
{
	struct dpi_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_DPI0:
	case BLKADDR_DPI1:
		data = devm_kzalloc(rvu->dev, sizeof(struct dpi_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		data->res_idx = res_idx++;
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_dpi_remove(struct rvu_block *hwblock, void *data)
{
	dpi_exit(hwblock->rvu);
	devm_kfree(hwblock->rvu->dev, data);
}

struct mbox_op dpi_mbox_op = {
	.start = 0xC000,
	.end = 0xCFFF,
	.handler = rvu_dpi_mbox_handler,
};

static struct rvu_eblock_driver_ops dpi_ops = {
	.probe	= rvu_dpi_probe,
	.remove	= rvu_dpi_remove,
	.init	= rvu_dpi_init_block,
	.setup	= rvu_setup_dpi_hw_resource,
	.free	= rvu_dpi_freemem_block,
	.register_interrupt = rvu_dpi_register_interrupts_block,
	.unregister_interrupt = rvu_dpi_unregister_interrupts_block,
	.mbox_op = &dpi_mbox_op,
};

void dpi_eb_module_init(void)
{
	rvu_eblock_register_driver(&dpi_ops);
}

void dpi_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&dpi_ops);
}
