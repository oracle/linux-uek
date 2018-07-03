/*
 * Cavium cn8xxx NAND flash controller (NDF) driver.
 *
 * Copyright (C) 2018 Cavium Inc.
 * Authors: Jan Glauber <jglauber@cavium.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/iopoll.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/rawnand.h>
#include <linux/mtd/nand_bch.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "bch_vf.h"

/*
 * The NDF_CMD queue takes commands between 16 - 128 bit.
 * All commands must be 16 bit aligned and are little endian.
 * WAIT_STATUS commands must be 64 bit aligned.
 * Commands are selected by the 4 bit opcode.
 *
 * Available Commands:
 *
 * 16 Bit:
 *   NOP
 *   WAIT
 *   BUS_ACQ, BUS_REL
 *   CHIP_EN, CHIP_DIS
 *
 * 32 Bit:
 *   CLE_CMD
 *   RD_CMD, RD_EDO_CMD
 *   WR_CMD
 *
 * 64 Bit:
 *   SET_TM_PAR
 *
 * 96 Bit:
 *   ALE_CMD
 *
 * 128 Bit:
 *   WAIT_STATUS, WAIT_STATUS_ALE
 */

/* NDF Register offsets */
#define NDF_CMD			0x0
#define NDF_MISC		0x8
#define NDF_ECC_CNT		0x10
#define NDF_DRBELL		0x30
#define NDF_ST_REG		0x38	/* status */
#define NDF_INT			0x40
#define NDF_INT_W1S		0x48
#define NDF_DMA_CFG		0x50
#define NDF_DMA_ADR		0x58
#define NDF_INT_ENA_W1C		0x60
#define NDF_INT_ENA_W1S		0x68

/* NDF command opcodes */
#define NDF_OP_NOP		0x0
#define NDF_OP_SET_TM_PAR	0x1
#define NDF_OP_WAIT		0x2
#define NDF_OP_CHIP_EN_DIS	0x3
#define NDF_OP_CLE_CMD		0x4
#define NDF_OP_ALE_CMD		0x5
#define NDF_OP_WR_CMD		0x8
#define NDF_OP_RD_CMD		0x9
#define NDF_OP_RD_EDO_CMD	0xa
#define NDF_OP_WAIT_STATUS	0xb	/* same opcode for WAIT_STATUS_ALE */
#define NDF_OP_BUS_ACQ_REL	0xf

#define NDF_BUS_ACQUIRE		1
#define NDF_BUS_RELEASE		0

struct ndf_nop_cmd {
	u16 opcode	: 4;
	u16 nop		: 12;
};

struct ndf_wait_cmd {
	u16 opcode	: 4;
	u16 r_b		: 1;	/* wait for one cycle or PBUS_WAIT deassert */
	u16		: 3;
	u16 wlen	: 3;	/* timing parameter select */
	u16		: 5;
};

struct ndf_bus_cmd {
	u16 opcode	: 4;
	u16 direction	: 4;	/* 1 = acquire, 0 = release */
	u16		: 8;
};

struct ndf_chip_cmd {
	u16 opcode	: 4;
	u16 chip	: 3;	/* select chip, 0 = disable */
	u16 enable	: 1;	/* 1 = enable, 0 = disable */
	u16 bus_width	: 2;	/* 10 = 16 bit, 01 = 8 bit */
	u16		: 6;
};

struct ndf_cle_cmd {
	u32 opcode	: 4;
	u32		: 4;
	u32 cmd_data	: 8;	/* command sent to the PBUS AD pins */
	u32 clen1	: 3;	/* time between PBUS CLE and WE asserts */
	u32 clen2	: 3;	/* time WE remains asserted */
	u32 clen3	: 3;	/* time between WE deassert and CLE */
	u32		: 7;
};

/* RD_EDO_CMD uses the same layout as RD_CMD */
struct ndf_rd_cmd {
	u32 opcode	: 4;
	u32 data	: 16;	/* data bytes */
	u32 rlen1	: 3;
	u32 rlen2	: 3;
	u32 rlen3	: 3;
	u32 rlen4	: 3;
};

struct ndf_wr_cmd {
	u32 opcode	: 4;
	u32 data	: 16;	/* data bytes */
	u32		: 4;
	u32 wlen1	: 3;
	u32 wlen2	: 3;
	u32		: 3;
};

struct ndf_set_tm_par_cmd {
	u64 opcode	: 4;
	u64 tim_mult	: 4;	/* multiplier for the seven paramters */
	u64 tm_par1	: 8;	/* --> Following are the 7 timing parameters that */
	u64 tm_par2	: 8;	/*     specify the number of coprocessor cycles.  */
	u64 tm_par3	: 8;	/*     A value of zero means one cycle.		  */
	u64 tm_par4	: 8;	/*     All values are scaled by tim_mult	  */
	u64 tm_par5	: 8;	/*     using tim_par * (2 ^ tim_mult).		  */
	u64 tm_par6	: 8;
	u64 tm_par7	: 8;
};

struct ndf_ale_cmd {
	u32 opcode	: 4;
	u32		: 4;
	u32 adr_byte_num: 4;	/* number of address bytes to be sent */
	u32		: 4;
	u32 alen1	: 3;
	u32 alen2	: 3;
	u32 alen3	: 3;
	u32 alen4	: 3;
	u32		: 4;
	u8 adr_byt1;
	u8 adr_byt2;
	u8 adr_byt3;
	u8 adr_byt4;
	u8 adr_byt5;
	u8 adr_byt6;
	u8 adr_byt7;
	u8 adr_byt8;
};

struct ndf_wait_status_cmd {
	u32 opcode	: 4;
	u32		: 4;
	u32 data	: 8;	/* data */
	u32 clen1	: 3;
	u32 clen2	: 3;
	u32 clen3	: 3;
	u32		: 8;
	u32 ale_ind	: 8;	/* set to 5 to select WAIT_STATUS_ALE command */
	u32 adr_byte_num: 4;	/* ALE only: number of address bytes to be sent */
	u32		: 4;
	u32 alen1	: 3;	/* ALE only */
	u32 alen2	: 3;	/* ALE only */
	u32 alen3	: 3;	/* ALE only */
	u32 alen4	: 3;	/* ALE only */
	u32		: 4;
	u8 adr_byt[4];		/* ALE only */
	u32 nine	: 4;	/* set to 9 */
	u32 and_mask	: 8;
	u32 comp_byte	: 8;
	u32 rlen1	: 3;
	u32 rlen2	: 3;
	u32 rlen3	: 3;
	u32 rlen4	: 3;
};

union ndf_cmd {
	u64 val[2];
	union {
		struct ndf_nop_cmd		nop;
		struct ndf_wait_cmd		wait;
		struct ndf_bus_cmd		bus_acq_rel;
		struct ndf_chip_cmd		chip_en_dis;
		struct ndf_cle_cmd		cle_cmd;
		struct ndf_rd_cmd		rd_cmd;
		struct ndf_wr_cmd		wr_cmd;
		struct ndf_set_tm_par_cmd	set_tm_par;
		struct ndf_ale_cmd		ale_cmd;
		struct ndf_wait_status_cmd	wait_status;
	} u;
};

#define NDF_MISC_MB_DIS		BIT_ULL(27)	/* Disable multi-bit error hangs */
#define NDF_MISC_NBR_HWM	GENMASK_ULL(26, 24) /* High watermark for NBR FIFO or load/store operations */
#define NDF_MISC_WAIT_CNT	GENMASK_ULL(23, 18) /* Wait input filter count */
#define NDF_MISC_FR_BYTE	GENMASK_ULL(17, 7) /* Unfilled NFD_CMD queue bytes */
#define NDF_MISC_RD_DONE	BIT_ULL(6)	/* Set by HW when it reads the last 8 bytes of NDF_CMD */
#define NDF_MISC_RD_VAL		BIT_ULL(5)	/* Set by HW when it reads. SW read of NDF_CMD clears it */
#define NDF_MISC_RD_CMD		BIT_ULL(4)	/* Let HW read NDF_CMD queue. Cleared on SW NDF_CMD write */
#define NDF_MISC_BT_DIS		BIT_ULL(2)	/* Boot disable */
#define NDF_MISC_EX_DIS		BIT_ULL(1)	/* Stop comand execution after completing command queue */
#define NDF_MISC_RST_FF		BIT_ULL(0)	/* Reset fifo */

#define NDF_INT_DMA_DONE	BIT_ULL(7)	/* DMA request complete */
#define NDF_INT_OVFR		BIT_ULL(6)	/* NDF_CMD write when queue is full */
#define NDF_INT_ECC_MULT	BIT_ULL(5)	/* Multi-bit ECC error detected */
#define NDF_INT_ECC_1BIT	BIT_ULL(4)	/* Single-bit ECC error detected and fixed */
#define NDF_INT_SM_BAD		BIT_ULL(3)	/* State machine is in bad state */
#define NDF_INT_WDOG		BIT_ULL(2)	/* Watchdog timer expired during command execution */
#define NDF_INT_FULL		BIT_ULL(1)	/* NDF_CMD queue is full */
#define NDF_INT_EMPTY		BIT_ULL(0)	/* NDF_CMD queue is empty */

#define NDF_DMA_CFG_EN		BIT_ULL(63)	/* DMA engine enable */
#define NDF_DMA_CFG_RW		BIT_ULL(62)	/* Read or write */
#define NDF_DMA_CFG_CLR		BIT_ULL(61)	/* Terminates DMA and clears enable bit */
#define NDF_DMA_CFG_SWAP32	BIT_ULL(59)	/* 32-bit swap enable */
#define NDF_DMA_CFG_SWAP16	BIT_ULL(58)	/* 16-bit swap enable */
#define NDF_DMA_CFG_SWAP8	BIT_ULL(57)	/* 8-bit swap enable */
#define NDF_DMA_CFG_CMD_BE	BIT_ULL(56)	/* Endian mode */
#define NDF_DMA_CFG_SIZE	GENMASK_ULL(55, 36) /* Number of 64 bit transfers */

#define NDF_ST_REG_EXE_IDLE	BIT_ULL(15)	/* Command execution status idle */
#define NDF_ST_REG_EXE_SM	GENMASK_ULL(14, 11) /* Command execution SM states */
#define NDF_ST_REG_BT_SM	GENMASK_ULL(10, 7) /* DMA and load SM states */
#define NDF_ST_REG_RD_FF_BAD	BIT_ULL(6)	/* Queue read-back SM bad state */
#define NDF_ST_REG_RD_FF	GENMASK_ULL(5, 4) /* Queue read-back SM states */
#define NDF_ST_REG_MAIN_BAD	BIT_ULL(3)	/* Main SM is in a bad state */
#define NDF_ST_REG_MAIN_SM	GENMASK_ULL(2, 0) /* Main SM states */

#define MAX_NAND_NAME_LEN	64
#define NAND_MAX_PAGESIZE	4096
#define NAND_MAX_OOBSIZE	256

/* NAND chip related information */
struct cvm_nand_chip {
	struct list_head node;
	struct nand_chip nand;
	int cs;					/* chip select 0..7 */
	struct ndf_set_tm_par_cmd timings;	/* timing parameters */
	int selected_page;
	bool oob_only;
	bool iface_set;
	int iface_mode;
	int row_bytes;
	int col_bytes;
};

struct cvm_nand_buf {
	int dmabuflen;
	u8 *dmabuf;
	dma_addr_t dmaaddr;

	int data_len;           /* Number of bytes in the data buffer */
	int data_index;         /* Current read index */
};

/* NAND flash controller (NDF) related information */
struct cvm_nfc {
	struct nand_hw_control controller;
	struct device *dev;
	void __iomem *base;
	struct list_head chips;
	int selected_chip;      /* Currently selected NAND chip number */
	struct clk *clk;	/* System clock */

	/*
	 * Status is separate from cvm_nand_buf because
	 * it can be used in parallel and during init.
	 */
	u8 *stat;
	dma_addr_t stat_addr;
	bool use_status;

	struct cvm_nand_buf buf;
	union bch_resp *bch_resp;
	dma_addr_t bch_rhandle;

	/* BCH of all-0xff, so erased pages read as error-free */
	unsigned char *eccmask;
};

/* settable timings - 0..7 select timing of alen1..4/clen1..3/etc */
enum tm_idx {
	t0, /* fixed at 4<<mult cycles */
	t1, t2, t3, t4, t5, t6, t7, /* settable per ONFI-timing mode */
};

static struct bch_vf *bch_vf;
static inline struct cvm_nand_chip *to_cvm_nand(struct nand_chip *nand)
{
	return container_of(nand, struct cvm_nand_chip, nand);
}

static inline struct cvm_nfc *to_cvm_nfc(struct nand_hw_control *ctrl)
{
	return container_of(ctrl, struct cvm_nfc, controller);
}

/* default parameters used for probing chips */
#define MAX_ONFI_MODE	5
static int default_onfi_timing;
static int slew_ns = 2; /* default timing padding */
module_param(slew_ns, int, 0644);
static int def_ecc_size = 1024; /* 1024 best for sw_bch, <= 4095 for hw_bch */
module_param(def_ecc_size, int, 0644);

static int default_width = 1; /* 8 bit */
static int default_page_size = 2048;
static struct ndf_set_tm_par_cmd default_timing_parms;

static irqreturn_t cvm_nfc_isr(int irq, void *dev_id)
{
	struct cvm_nfc *tn = dev_id;

	wake_up(&tn->controller.wq);
	return IRQ_HANDLED;
}

/*
 * Read a single byte from the temporary buffer. Used after READID
 * to get the NAND information and for STATUS.
 */
static u8 cvm_nand_read_byte(struct mtd_info *mtd)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);

	if (tn->use_status) {
		tn->use_status = false;
		return *tn->stat;
	}

	if (tn->buf.data_index < tn->buf.data_len)
		return tn->buf.dmabuf[tn->buf.data_index++];
	else
		dev_err(tn->dev, "No data to read\n");

	return 0xff;
}

/*
 * Read a number of pending bytes from the temporary buffer. Used
 * to get page and OOB data.
 */
static void cvm_nand_read_buf(struct mtd_info *mtd, u8 *buf, int len)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);

	if (len > tn->buf.data_len - tn->buf.data_index) {
		dev_err(tn->dev, "Not enough data for read of %d bytes\n", len);
		return;
	}

	memcpy(buf, tn->buf.dmabuf + tn->buf.data_index, len);
	tn->buf.data_index += len;
}

static void cvm_nand_write_buf(struct mtd_info *mtd, const u8 *buf, int len)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);

	memcpy(tn->buf.dmabuf + tn->buf.data_len, buf, len);
	tn->buf.data_len += len;
}

/* Overwrite default function to avoid sync abort on chip = -1. */
static void cvm_nand_select_chip(struct mtd_info *mtd, int chip)
{
	return;
}

static inline int timing_to_cycle(u32 psec, unsigned long clock)
{
	unsigned int ns;
	int ticks;

	ns = DIV_ROUND_UP(psec, 1000);
	ns += slew_ns;

	clock /= 1000000; /* no rounding needed since clock is multiple of 1MHz */
	ns *= clock;

	ticks = DIV_ROUND_UP(ns, 1000);

	/* actual delay is (tm_parX+1)<<tim_mult */
	if (ticks)
		ticks--;

	return ticks;
}

static void set_timings(struct cvm_nand_chip *chip,
			struct ndf_set_tm_par_cmd *tp,
			const struct nand_sdr_timings *timings,
			unsigned long sclk)
{
	/* scaled coprocessor-cycle values */
	u32 sWH, sCLS, sCLH, sALS, sALH, sRP, sREH, sWB, sWC;

	tp->tim_mult = 0;
	sWH = timing_to_cycle(timings->tWH_min, sclk);
	sCLS = timing_to_cycle(timings->tCLS_min, sclk);
	sCLH = timing_to_cycle(timings->tCLH_min, sclk);
	sALS = timing_to_cycle(timings->tALS_min, sclk);
	sALH = timing_to_cycle(timings->tALH_min, sclk);
	sRP = timing_to_cycle(timings->tRP_min, sclk);
	sREH = timing_to_cycle(timings->tREH_min, sclk);
	sWB = timing_to_cycle(timings->tWB_max, sclk);
	sWC = timing_to_cycle(timings->tWC_min, sclk);

	tp->tm_par1 = sWH;
	tp->tm_par2 = sCLH;
	tp->tm_par3 = sRP + 1;
	tp->tm_par4 = sCLS - sWH;
	tp->tm_par5 = sWC - sWH + 1;
	tp->tm_par6 = sWB;
	tp->tm_par7 = 0;
	tp->tim_mult++; /* overcompensate for bad math */

	/* TODO: comment parameter re-use */

	pr_debug("%s: tim_par: mult: %d  p1: %d  p2: %d  p3: %d\n",
		__func__, tp->tim_mult, tp->tm_par1, tp->tm_par2, tp->tm_par3);
	pr_debug("                 p4: %d  p5: %d  p6: %d  p7: %d\n",
		tp->tm_par4, tp->tm_par5, tp->tm_par6, tp->tm_par7);

}

static int set_default_timings(struct cvm_nfc *tn,
			       const struct nand_sdr_timings *timings)
{
	unsigned long sclk = clk_get_rate(tn->clk);

	set_timings(NULL, &default_timing_parms, timings, sclk);
	return 0;
}

static int cvm_nfc_chip_set_timings(struct cvm_nand_chip *chip,
		 const struct nand_sdr_timings *timings)
{
	struct cvm_nfc *tn = to_cvm_nfc(chip->nand.controller);
	unsigned long sclk = clk_get_rate(tn->clk);

	set_timings(chip, &chip->timings, timings, sclk);
	return 0;
}

/* How many bytes are free in the NFD_CMD queue? */
static int ndf_cmd_queue_free(struct cvm_nfc *tn)
{
	u64 ndf_misc;

	ndf_misc = readq(tn->base + NDF_MISC);
	return FIELD_GET(NDF_MISC_FR_BYTE, ndf_misc);
}

/* Submit a command to the NAND command queue. */
static int ndf_submit(struct cvm_nfc *tn, union ndf_cmd *cmd)
{
	int opcode = cmd->val[0] & 0xf;

	switch (opcode) {
	/* All these commands fit in one 64bit word */
	case NDF_OP_NOP:
	case NDF_OP_SET_TM_PAR:
	case NDF_OP_WAIT:
	case NDF_OP_CHIP_EN_DIS:
	case NDF_OP_CLE_CMD:
	case NDF_OP_WR_CMD:
	case NDF_OP_RD_CMD:
	case NDF_OP_RD_EDO_CMD:
	case NDF_OP_BUS_ACQ_REL:
		if (ndf_cmd_queue_free(tn) < 8)
			goto full;
		writeq(cmd->val[0], tn->base + NDF_CMD);
		break;
	case NDF_OP_ALE_CMD: /* ALE commands take either one or two 64bit words */
		if (cmd->u.ale_cmd.adr_byte_num < 5) {
			if (ndf_cmd_queue_free(tn) < 8)
				goto full;
			writeq(cmd->val[0], tn->base + NDF_CMD);
		} else {
			if (ndf_cmd_queue_free(tn) < 16)
				goto full;
			writeq(cmd->val[0], tn->base + NDF_CMD);
			writeq(cmd->val[1], tn->base + NDF_CMD);
		}
		break;
	case NDF_OP_WAIT_STATUS: /* Wait status commands take two 64bit words */
		if (ndf_cmd_queue_free(tn) < 16)
			goto full;
		writeq(cmd->val[0], tn->base + NDF_CMD);
		writeq(cmd->val[1], tn->base + NDF_CMD);
		break;
	default:
		dev_err(tn->dev, "ndf_submit: unknown command: %u\n", opcode);
		return -EINVAL;
	}
	return 0;
full:
	dev_err(tn->dev, "ndf_submit: no space left in command queue\n");
	return -ENOMEM;
}

/*
 * Wait for the ready/busy signal. First wait for busy to be valid,
 * then wait for busy to de-assert.
 */
static int ndf_build_wait_busy(struct cvm_nfc *tn)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wait.opcode = NDF_OP_WAIT;
	cmd.u.wait.r_b = 1;
	cmd.u.wait.wlen = t6;

	if (ndf_submit(tn, &cmd))
		return -ENOMEM;
	return 0;
}

static bool ndf_dma_done(struct cvm_nfc *tn)
{
	u64 dma_cfg, ndf_int;

	/* Enable bit should be clear after a transfer */
	dma_cfg = readq(tn->base + NDF_DMA_CFG);
	if (!(dma_cfg & NDF_DMA_CFG_EN))
		return true;

	/* Check DMA done bit */
	ndf_int = readq(tn->base + NDF_INT);
	if (!(ndf_int & NDF_INT_DMA_DONE))
		return false;

	return true;
}

static int ndf_wait(struct cvm_nfc *tn)
{
	long time_left = HZ;

	/* enable all IRQ types */
	writeq(0xff, tn->base + NDF_INT_ENA_W1S);
	time_left = wait_event_timeout(tn->controller.wq,
				       ndf_dma_done(tn), time_left);
	writeq(0xff, tn->base + NDF_INT_ENA_W1C);

	if (!time_left) {
		dev_err(tn->dev, "ndf_wait: timeout error\n");
		return -ETIMEDOUT;
	}
	return 0;
}

static int ndf_wait_idle(struct cvm_nfc *tn)
{
	u64 val;
	u64 dval = 0;
	int rc;
	int pause = 100;
	u64 tot_us = USEC_PER_SEC / 10;

	rc = readq_poll_timeout(tn->base + NDF_ST_REG,
			val, val & NDF_ST_REG_EXE_IDLE, pause, tot_us);
	if (!rc)
		rc = readq_poll_timeout(tn->base + NDF_DMA_CFG,
			dval, !(dval & NDF_DMA_CFG_EN), pause, tot_us);

	return rc;
}

/* Issue set timing parameters */
static int ndf_queue_cmd_timing(struct cvm_nfc *tn,
				struct ndf_set_tm_par_cmd *timings)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.set_tm_par.opcode = NDF_OP_SET_TM_PAR;
	cmd.u.set_tm_par.tim_mult = timings->tim_mult;
	cmd.u.set_tm_par.tm_par1 = timings->tm_par1;
	cmd.u.set_tm_par.tm_par2 = timings->tm_par2;
	cmd.u.set_tm_par.tm_par3 = timings->tm_par3;
	cmd.u.set_tm_par.tm_par4 = timings->tm_par4;
	cmd.u.set_tm_par.tm_par5 = timings->tm_par5;
	cmd.u.set_tm_par.tm_par6 = timings->tm_par6;
	cmd.u.set_tm_par.tm_par7 = timings->tm_par7;
	return ndf_submit(tn, &cmd);
}

/* Issue bus acquire or release */
static int ndf_queue_cmd_bus(struct cvm_nfc *tn, int direction)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.bus_acq_rel.opcode = NDF_OP_BUS_ACQ_REL;
	cmd.u.bus_acq_rel.direction = direction;
	return ndf_submit(tn, &cmd);
}

/* Issue chip select or deselect */
static int ndf_queue_cmd_chip(struct cvm_nfc *tn, int enable, int chip,
			      int width)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.chip_en_dis.opcode = NDF_OP_CHIP_EN_DIS;
	cmd.u.chip_en_dis.chip = chip;
	cmd.u.chip_en_dis.enable = enable;
	cmd.u.chip_en_dis.bus_width = width;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_wait(struct cvm_nfc *tn, int t_delay)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wait.opcode = NDF_OP_WAIT;
	cmd.u.wait.wlen = t_delay;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_cle(struct cvm_nfc *tn, int command)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.cle_cmd.opcode = NDF_OP_CLE_CMD;
	cmd.u.cle_cmd.cmd_data = command;
	cmd.u.cle_cmd.clen1 = t4;
	cmd.u.cle_cmd.clen2 = t1;
	cmd.u.cle_cmd.clen3 = t2;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_ale(struct cvm_nfc *tn, int addr_bytes,
			     struct nand_chip *nand, u64 page,
			     u32 col, int page_size)
{
	struct cvm_nand_chip *cvm_nand = (nand) ? to_cvm_nand(nand) : NULL;
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.ale_cmd.opcode = NDF_OP_ALE_CMD;
	cmd.u.ale_cmd.adr_byte_num = addr_bytes;

	/* set column bit for OOB area, assume OOB follows page */
	if (cvm_nand && cvm_nand->oob_only)
		col += page_size;

	/* page is u64 for this generality, even if cmdfunc() passes int */
	switch (addr_bytes) {
	/* 4-8 bytes: page, then 2-byte col */
	case 8:
		cmd.u.ale_cmd.adr_byt8 = (page >> 40) & 0xff;
		/* fall thru */
	case 7:
		cmd.u.ale_cmd.adr_byt7 = (page >> 32) & 0xff;
		/* fall thru */
	case 6:
		cmd.u.ale_cmd.adr_byt6 = (page >> 24) & 0xff;
		/* fall thru */
	case 5:
		cmd.u.ale_cmd.adr_byt5 = (page >> 16) & 0xff;
		/* fall thru */
	case 4:
		cmd.u.ale_cmd.adr_byt4 = (page >> 8) & 0xff;
		cmd.u.ale_cmd.adr_byt3 = page & 0xff;
		cmd.u.ale_cmd.adr_byt2 = (col >> 8) & 0xff;
		cmd.u.ale_cmd.adr_byt1 =  col & 0xff;
		break;
	/* 1-3 bytes: just the page address */
	case 3:
		cmd.u.ale_cmd.adr_byt3 = (page >> 16) & 0xff;
		/* fall thru */
	case 2:
		cmd.u.ale_cmd.adr_byt2 = (page >> 8) & 0xff;
		/* fall thru */
	case 1:
		cmd.u.ale_cmd.adr_byt1 = page & 0xff;
		break;
	default:
		break;
	}

	cmd.u.ale_cmd.alen1 = t3;
	cmd.u.ale_cmd.alen2 = t1;
	cmd.u.ale_cmd.alen3 = t5;
	cmd.u.ale_cmd.alen4 = t2;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_write(struct cvm_nfc *tn, int len)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wr_cmd.opcode = NDF_OP_WR_CMD;
	cmd.u.wr_cmd.data = len;
	cmd.u.wr_cmd.wlen1 = t3;
	cmd.u.wr_cmd.wlen2 = t1;
	return ndf_submit(tn, &cmd);
}

static int ndf_build_pre_cmd(struct cvm_nfc *tn, int cmd1,
		 int addr_bytes, u64 page, u32 col, int cmd2)
{
	struct nand_chip *nand = tn->controller.active;
	struct cvm_nand_chip *cvm_nand;
	struct ndf_set_tm_par_cmd *timings;
	int width, page_size, rc;

	/* Also called before chip probing is finished */
	if (!nand) {
		timings = &default_timing_parms;
		page_size = default_page_size;
		width = default_width;
	} else {
		cvm_nand = to_cvm_nand(nand);
		timings = &cvm_nand->timings;
		page_size = nand->mtd.writesize;
		if (nand->options & NAND_BUSWIDTH_16)
			width = 2;
		else
			width = 1;
	}

	rc = ndf_queue_cmd_timing(tn, timings);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_bus(tn, NDF_BUS_ACQUIRE);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_chip(tn, 1, tn->selected_chip, width);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_wait(tn, t1);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_cle(tn, cmd1);
	if (rc)
		return rc;

	if (addr_bytes) {
		rc = ndf_build_wait_busy(tn);
		if (rc)
			return rc;

		rc = ndf_queue_cmd_ale(tn, addr_bytes, nand,
					page, col, page_size);
		if (rc)
			return rc;
	}

	/* CLE 2 */
	if (cmd2) {
		rc = ndf_build_wait_busy(tn);
		if (rc)
			return rc;

		rc = ndf_queue_cmd_cle(tn, cmd2);
		if (rc)
			return rc;
	}
	return 0;
}

static int ndf_build_post_cmd(struct cvm_nfc *tn, int hold_time)
{
	int rc;

	/* Deselect chip */
	rc = ndf_queue_cmd_chip(tn, 0, 0, 0);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_wait(tn, t2);
	if (rc)
		return rc;

	/* Release bus */
	rc = ndf_queue_cmd_bus(tn, 0);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_wait(tn, hold_time);
	if (rc)
		return rc;

	/* Write 1 to clear all interrupt bits before starting DMA */
	writeq(0xff, tn->base + NDF_INT);

	/* and enable, before doorbell starts actiion */
	writeq(0xff, tn->base + NDF_INT_ENA_W1S);

	/*
	 * Last action is ringing the doorbell with number of bus
	 * acquire-releases cycles (currently 1).
	 */
	writeq(1, tn->base + NDF_DRBELL);
	return 0;
}

/* Setup the NAND DMA engine for a transfer. */
static void ndf_setup_dma(struct cvm_nfc *tn, int is_write,
			  dma_addr_t bus_addr, int len)
{
	u64 dma_cfg;

	dma_cfg = FIELD_PREP(NDF_DMA_CFG_RW, is_write) |
		  FIELD_PREP(NDF_DMA_CFG_SIZE, (len >> 3) - 1);
	dma_cfg |= NDF_DMA_CFG_EN;
	writeq(bus_addr, tn->base + NDF_DMA_ADR);
	writeq(dma_cfg, tn->base + NDF_DMA_CFG);
}

static int cvm_nand_reset(struct cvm_nfc *tn)
{
	int rc;

	rc = ndf_build_pre_cmd(tn, NAND_CMD_RESET, 0, 0, 0, 0);
	if (rc)
		return rc;

	rc = ndf_build_wait_busy(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn, t2);
	if (rc)
		return rc;

	return 0;
}

static int ndf_read(struct cvm_nfc *tn, int cmd1, int addr_bytes,
		    u64 page, u32 col, int cmd2, int len)
{
	dma_addr_t bus_addr = tn->use_status ? tn->stat_addr : tn->buf.dmaaddr;
	struct nand_chip *nand = tn->controller.active;
	int timing_mode, bytes, rc;
	union ndf_cmd cmd;
	u64 start, end;

	if (!nand)
		timing_mode = default_onfi_timing;
	else
		timing_mode = nand->onfi_timing_mode_default;

	/* Build the command and address cycles */
	rc = ndf_build_pre_cmd(tn, cmd1, addr_bytes, page, col, cmd2);
	if (rc)
		return rc;

	/* This waits for some time, then waits for busy to be de-asserted. */
	rc = ndf_build_wait_busy(tn);
	if (rc)
		return rc;

	memset(&cmd, 0, sizeof(cmd));

	if (timing_mode < 4)
		cmd.u.rd_cmd.opcode = NDF_OP_RD_CMD;
	else
		cmd.u.rd_cmd.opcode = NDF_OP_RD_EDO_CMD;

	cmd.u.rd_cmd.data = len;
	cmd.u.rd_cmd.rlen1 = t7;
	cmd.u.rd_cmd.rlen2 = t3;
	cmd.u.rd_cmd.rlen3 = t1;
	cmd.u.rd_cmd.rlen4 = t7;
	rc = ndf_submit(tn, &cmd);
	if (rc)
		return rc;

	start = (u64) bus_addr;
	ndf_setup_dma(tn, 0, bus_addr, len);

	rc = ndf_build_post_cmd(tn, t2);
	if (rc)
		return rc;

	/* Wait for the DMA to complete */
	rc = ndf_wait(tn);
	if (rc)
		return rc;

	end = readq(tn->base + NDF_DMA_ADR);
	bytes = end - start;

	/* Make sure NDF is really done */
	rc = ndf_wait_idle(tn);
	if (rc) {
		dev_err(tn->dev, "poll idle failed\n");
		return rc;
	}

	return bytes;
}

static int cvm_nand_get_features(struct mtd_info *mtd,
				      struct nand_chip *chip, int feature_addr,
				      u8 *subfeature_para)
{
	struct nand_chip *nand = chip;
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int len = 8;
	int rc;

	memset(tn->buf.dmabuf, 0xff, len);
	tn->buf.data_index = 0;
	tn->buf.data_len = 0;
	rc = ndf_read(tn, NAND_CMD_GET_FEATURES, 1, feature_addr, 0, 0, len);
	if (rc)
		return rc;

	memcpy(subfeature_para, tn->buf.dmabuf, ONFI_SUBFEATURE_PARAM_LEN);

	return 0;
}

static int cvm_nand_set_features(struct mtd_info *mtd,
				      struct nand_chip *chip, int feature_addr,
				      u8 *subfeature_para)
{
	struct nand_chip *nand = chip;
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	const int len = ONFI_SUBFEATURE_PARAM_LEN;
	int rc;

	rc = ndf_build_pre_cmd(tn, NAND_CMD_SET_FEATURES,
				1, feature_addr, 0, 0);
	if (rc)
		return rc;

	memcpy(tn->buf.dmabuf, subfeature_para, len);
	memset(tn->buf.dmabuf + len, 0, 8 - len);

	ndf_setup_dma(tn, 1, tn->buf.dmaaddr, 8);

	rc = ndf_queue_cmd_write(tn, 8);
	if (rc)
		return rc;

	rc = ndf_build_wait_busy(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn, t2);
	if (rc)
		return rc;

	return 0;
}

/*
 * Read a page from NAND. If the buffer has room, the out of band
 * data will be included.
 */
static int ndf_page_read(struct cvm_nfc *tn, u64 page, int col, int len)
{
	struct nand_chip *nand = tn->controller.active;
	struct cvm_nand_chip *chip = to_cvm_nand(nand);
	int addr_bytes = chip->row_bytes + chip->col_bytes;

	memset(tn->buf.dmabuf, 0xff, len);
	return ndf_read(tn, NAND_CMD_READ0, addr_bytes,
		    page, col, NAND_CMD_READSTART, len);
}

/* Erase a NAND block */
static int ndf_block_erase(struct cvm_nfc *tn, u64 page_addr)
{
	struct nand_chip *nand = tn->controller.active;
	struct cvm_nand_chip *chip = to_cvm_nand(nand);
	int addr_bytes = chip->row_bytes;
	int rc;

	rc = ndf_build_pre_cmd(tn, NAND_CMD_ERASE1, addr_bytes,
		page_addr, 0, NAND_CMD_ERASE2);
	if (rc)
		return rc;

	/* Wait for R_B to signal erase is complete  */
	rc = ndf_build_wait_busy(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn, t2);
	if (rc)
		return rc;

	/* Wait until the command queue is idle */
	return ndf_wait_idle(tn);
}

/*
 * Write a page (or less) to NAND.
 */
static int ndf_page_write(struct cvm_nfc *tn, int page)
{
	int len, rc;
	struct nand_chip *nand = tn->controller.active;
	struct cvm_nand_chip *chip = to_cvm_nand(nand);
	int addr_bytes = chip->row_bytes + chip->col_bytes;

	len = tn->buf.data_len - tn->buf.data_index;
	chip->oob_only = (tn->buf.data_index >= nand->mtd.writesize);
	WARN_ON_ONCE(len & 0x7);

	ndf_setup_dma(tn, 1, tn->buf.dmaaddr + tn->buf.data_index, len);
	rc = ndf_build_pre_cmd(tn, NAND_CMD_SEQIN, addr_bytes, page, 0, 0);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_write(tn, len);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_cle(tn, NAND_CMD_PAGEPROG);
	if (rc)
		return rc;

	/* Wait for R_B to signal program is complete  */
	rc = ndf_build_wait_busy(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn, t2);
	if (rc)
		return rc;

	/* Wait for the DMA to complete */
	rc = ndf_wait(tn);
	if (rc)
		return rc;

	/* Data transfer is done but NDF is not, it is waiting for R/B# */
	return ndf_wait_idle(tn);
}

static void cvm_nand_cmdfunc(struct mtd_info *mtd, unsigned int command,
				  int column, int page_addr)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nand_chip *cvm_nand = to_cvm_nand(nand);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int rc;

	tn->selected_chip = cvm_nand->cs;
	if (tn->selected_chip < 0 || tn->selected_chip >= NAND_MAX_CHIPS) {
		dev_err(tn->dev, "invalid chip select\n");
		return;
	}

	tn->use_status = false;

	switch (command) {
	case NAND_CMD_READID:
		tn->buf.data_index = 0;
		cvm_nand->oob_only = false;
		rc = ndf_read(tn, command, 1, column, 0, 0, 8);
		if (rc < 0)
			dev_err(tn->dev, "READID failed with %d\n", rc);
		else
			tn->buf.data_len = rc;
		break;

	case NAND_CMD_READOOB:
		cvm_nand->oob_only = true;
		tn->buf.data_index = 0;
		tn->buf.data_len = 0;
		rc = ndf_page_read(tn, page_addr, column, mtd->oobsize);
		if (rc < mtd->oobsize)
			dev_err(tn->dev, "READOOB failed with %d\n",
				tn->buf.data_len);
		else
			tn->buf.data_len = rc;
		break;

	case NAND_CMD_READ0:
		cvm_nand->oob_only = false;
		tn->buf.data_index = 0;
		tn->buf.data_len = 0;
		rc = ndf_page_read(tn,
				page_addr, column,
				mtd->writesize + mtd->oobsize);

		if (rc < mtd->writesize + mtd->oobsize)
			dev_err(tn->dev, "READ0 failed with %d\n", rc);
		else
			tn->buf.data_len = rc;
		break;

	case NAND_CMD_STATUS:
		/* used in oob/not states */
		tn->use_status = true;
		rc = ndf_read(tn, command, 0, 0, 0, 0, 8);
		if (rc < 0)
			dev_err(tn->dev, "STATUS failed with %d\n", rc);
		break;

	case NAND_CMD_RESET:
		/* used in oob/not states */
		rc = cvm_nand_reset(tn);
		if (rc < 0)
			dev_err(tn->dev, "RESET failed with %d\n", rc);
		break;

	case NAND_CMD_PARAM:
		cvm_nand->oob_only = false;
		tn->buf.data_index = 0;
		rc = ndf_read(tn, command, 1, 0, 0, 0,
			min(tn->buf.dmabuflen, 3 * 512));
		if (rc < 0)
			dev_err(tn->dev, "PARAM failed with %d\n", rc);
		else
			tn->buf.data_len = rc;
		break;

	case NAND_CMD_RNDOUT:
		tn->buf.data_index = column;
		break;

	case NAND_CMD_ERASE1:
		if (ndf_block_erase(tn, page_addr))
			dev_err(tn->dev, "ERASE1 failed\n");
		break;

	case NAND_CMD_ERASE2:
		/* We do all erase processing in the first command, so ignore
		 * this one.
		 */
		break;

	case NAND_CMD_SEQIN:
		cvm_nand->oob_only = (column >= mtd->writesize);
		tn->buf.data_index = column;
		tn->buf.data_len = column;

		cvm_nand->selected_page = page_addr;
		break;

	case NAND_CMD_PAGEPROG:
		rc = ndf_page_write(tn, cvm_nand->selected_page);
		if (rc)
			dev_err(tn->dev, "PAGEPROG failed with %d\n", rc);
		break;

	case NAND_CMD_SET_FEATURES:
		cvm_nand->oob_only = false;
		/* assume tn->buf.data_len == 4 of data has been set there */
		rc = cvm_nand_set_features(mtd, nand,
					page_addr, tn->buf.dmabuf);
		if (rc)
			dev_err(tn->dev, "SET_FEATURES failed with %d\n", rc);
		break;

	case NAND_CMD_GET_FEATURES:
		cvm_nand->oob_only = false;
		rc = cvm_nand_get_features(mtd, nand,
					page_addr, tn->buf.dmabuf);
		if (!rc) {
			tn->buf.data_index = 0;
			tn->buf.data_len = 4;
		} else {
			dev_err(tn->dev, "GET_FEATURES failed with %d\n", rc);
		}
		break;

	default:
		WARN_ON_ONCE(1);
		dev_err(tn->dev, "unhandled nand cmd: %x\n", command);
	}
}

static int cvm_nand_waitfunc(struct mtd_info *mtd, struct nand_chip *chip)
{
	struct cvm_nfc *tn = to_cvm_nfc(chip->controller);
	int ret;

	ret = ndf_wait_idle(tn);
	return (ret < 0) ? -EIO : 0;
}

/* check compatibility with ONFI timing mode#N, and optionally apply */
static int cvm_nand_setup_data_interface(struct mtd_info *mtd, int chipnr,
	const struct nand_data_interface *conf)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nand_chip *chip = to_cvm_nand(nand);
	int rc;
	static u64 tWC_N[MAX_ONFI_MODE+2]; /* cache a mode signature */
	int mode; /* deduced mode number, for reporting and restricting */

	nand->select_chip(mtd, chipnr);

	/*
	 * Cache timing modes for reporting, and reducing needless change.
	 *
	 * Challenge: caller does not pass ONFI mode#, but reporting the mode
	 * and restricting to a maximum, or a list, are useful for diagnosing
	 * new hardware.  So use tWC_min, distinct and monotonic across modes,
	 * to discover the requested/accepted mode number
	 */
	for (mode = MAX_ONFI_MODE; mode >= 0 && !tWC_N[0]; mode--) {
		const struct nand_sdr_timings *t;

		t = onfi_async_timing_mode_to_sdr_timings(mode);
		if (!t)
			continue;
		tWC_N[mode] = t->tWC_min;
	}

	if (!conf) {
		rc = -EINVAL;
	} else if (nand->data_interface &&
			chip->iface_set && chip->iface_mode == mode) {
		/*
		 * Cases:
		 * - called from nand_reset, which clears DDR timing
		 *   mode back to SDR.  BUT if we're already in SDR,
		 *   timing mode persists over resets.
		 *   While mtd/nand layer only supports SDR,
		 *   this is always safe. And this driver only supports SDR.
		 *
		 * - called from post-power-event nand_reset (maybe
		 *   NFC+flash power down, or system hibernate.
		 *   Address this when CONFIG_PM support added
		 */
		rc = 0;
	} else {
		rc = cvm_nfc_chip_set_timings(chip, &conf->timings.sdr);
		if (!rc) {
			chip->iface_mode = mode;
			chip->iface_set = true;
		}
	}
	return rc;
}

#ifdef DEBUG
# define DEBUG_INIT	1
# define DEBUG_READ	2
# define DEBUG_WRITE	4
# define DEBUG_ALL	7
static int trace = DEBUG_INIT;
module_param(trace, int, 0644);
# define DEV_DBG(D, d, f, ...) do { \
		if ((D) & trace) \
			dev_dbg(d, f, ##__VA_ARGS__); \
	} while (0)
#else
# define DEV_DBG(D, d, f, ...) (void)0
#endif

#if IS_ENABLED(CONFIG_CAVIUM_BCH)
static void cavm_bch_reset(void)
{
	cavm_bch_putv(bch_vf);
	bch_vf = cavm_bch_getv();
}

/*
 * Given a page, calculate the ECC code
 *
 * chip:	Pointer to NAND chip data structure
 * buf:		Buffer to calculate ECC on
 * code:	Buffer to hold ECC data
 *
 * Return 0 on success or -1 on failure
 */
static int octeon_nand_bch_calculate_ecc_internal(struct mtd_info *mtd,
	      dma_addr_t ihandle, uint8_t *code)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int rc;
	int i;
	static uint8_t *ecc_buffer;
	static int ecc_size;
	static dma_addr_t ecc_handle;
	union bch_resp *r = tn->bch_resp;

	if (!ecc_buffer || ecc_size < nand->ecc.size) {
		ecc_size = nand->ecc.size;
		ecc_buffer = dma_alloc_coherent(tn->dev, ecc_size,
					&ecc_handle, GFP_KERNEL);
	}

	memset(ecc_buffer, 0, nand->ecc.bytes);

	r->u16 = 0;
	wmb(); /* flush done=0 before making request */

	rc = cavm_bch_encode(bch_vf, ihandle, nand->ecc.size,
			     nand->ecc.strength,
			     ecc_handle, tn->bch_rhandle);

	if (!rc) {
		cavm_bch_wait(bch_vf, r, tn->bch_rhandle);
	} else {

		dev_err(tn->dev, "octeon_bch_encode failed\n");
		return -1;
	}

	if (!r->s.done || r->s.uncorrectable) {
		dev_err(tn->dev,
			"%s timeout, done:%d uncorr:%d corr:%d erased:%d\n",
			__func__, r->s.done, r->s.uncorrectable,
			r->s.num_errors, r->s.erased);
		cavm_bch_reset();
		return -1;
	}

	memcpy(code, ecc_buffer, nand->ecc.bytes);

	for (i = 0; i < nand->ecc.bytes; i++)
		code[i] ^= tn->eccmask[i];

	return tn->bch_resp->s.num_errors;
}

/*
 * Given a page, calculate the ECC code
 *
 * mtd:        MTD block structure
 * dat:        raw data (unused)
 * ecc_code:   buffer for ECC
 */
static int octeon_nand_bch_calculate(struct mtd_info *mtd,
		const uint8_t *dat, uint8_t *ecc_code)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	dma_addr_t handle = dma_map_single(tn->dev, (u8 *)dat,
				nand->ecc.size, DMA_TO_DEVICE);
	int ret;

	ret = octeon_nand_bch_calculate_ecc_internal(
			mtd, handle, (void *)ecc_code);

	dma_unmap_single(tn->dev, handle,
				nand->ecc.size, DMA_TO_DEVICE);
	return ret;
}
/*
 * Detect and correct multi-bit ECC for a page
 *
 * mtd:        MTD block structure
 * dat:        raw data read from the chip
 * read_ecc:   ECC from the chip (unused)
 * isnull:     unused
 *
 * Returns number of bits corrected or -1 if unrecoverable
 */
static int octeon_nand_bch_correct(struct mtd_info *mtd, u_char *dat,
		u_char *read_ecc, u_char *isnull)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int i = nand->ecc.size + nand->ecc.bytes;
	static uint8_t *data_buffer;
	static dma_addr_t ihandle;
	static int buffer_size;
	dma_addr_t ohandle;
	union bch_resp *r = tn->bch_resp;
	int rc;

	if (i > buffer_size) {
		if (buffer_size)
			dma_free_coherent(tn->dev, buffer_size,
					data_buffer, ihandle);
		data_buffer = dma_alloc_coherent(tn->dev, i,
						&ihandle, GFP_KERNEL);
		if (!data_buffer) {
			dev_err(tn->dev,
				"%s: Could not allocate %d bytes for buffer\n",
				__func__, i);
			goto error;
		}
		buffer_size = i;
	}

	memcpy(data_buffer, dat, nand->ecc.size);
	memcpy(data_buffer + nand->ecc.size,
			read_ecc, nand->ecc.bytes);

	for (i = 0; i < nand->ecc.bytes; i++)
		data_buffer[nand->ecc.size + i] ^= tn->eccmask[i];

	r->u16 = 0;
	wmb(); /* flush done=0 before making request */

	ohandle = dma_map_single(tn->dev, dat, nand->ecc.size, DMA_FROM_DEVICE);
	rc = cavm_bch_decode(bch_vf, ihandle, nand->ecc.size,
			     nand->ecc.strength, ohandle, tn->bch_rhandle);

	if (!rc)
		cavm_bch_wait(bch_vf, r, tn->bch_rhandle);

	dma_unmap_single(tn->dev, ohandle, nand->ecc.size, DMA_FROM_DEVICE);

	if (rc) {
		dev_err(tn->dev, "cavm_bch_decode failed\n");
		goto error;
	}

	if (!r->s.done) {
		dev_err(tn->dev, "Error: BCH engine timeout\n");
		cavm_bch_reset();
		goto error;
	}

	if (r->s.erased) {
		DEV_DBG(DEBUG_ALL, tn->dev, "Info: BCH block is erased\n");
		return 0;
	}

	if (r->s.uncorrectable) {
		DEV_DBG(DEBUG_ALL, tn->dev,
			"Cannot correct NAND block, response: 0x%x\n",
			r->u16);
		goto error;
	}

	return r->s.num_errors;

error:
	DEV_DBG(DEBUG_ALL, tn->dev, "Error performing bch correction\n");
	return -1;
}

void octeon_nand_bch_hwctl(struct mtd_info *mtd, int mode)
{
	/* Do nothing. */
}

static int octeon_nand_hw_bch_read_page(struct mtd_info *mtd,
					struct nand_chip *chip, uint8_t *buf,
					int oob_required, int page)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int i, eccsize = chip->ecc.size, ret;
	int eccbytes = chip->ecc.bytes;
	int eccsteps = chip->ecc.steps;
	uint8_t *p;
	uint8_t *ecc_code = chip->buffers->ecccode;
	unsigned int max_bitflips = 0;

	/* chip->read_buf() insists on sequential order, we do OOB first */
	memcpy(chip->oob_poi, tn->buf.dmabuf + mtd->writesize, mtd->oobsize);

	/* Use private buffer as input for ECC correction */
	p = tn->buf.dmabuf;

	ret = mtd_ooblayout_get_eccbytes(mtd, ecc_code, chip->oob_poi, 0,
					 chip->ecc.total);
	if (ret)
		return ret;

	for (i = 0; eccsteps; eccsteps--, i += eccbytes, p += eccsize) {
		int stat;

		DEV_DBG(DEBUG_READ, tn->dev,
			"Correcting block offset %lx, ecc offset %x\n",
			p - buf, i);
		stat = chip->ecc.correct(mtd, p, &ecc_code[i], NULL);

		if (stat < 0) {
			mtd->ecc_stats.failed++;
			DEV_DBG(DEBUG_ALL, tn->dev,
				"Cannot correct NAND page %d\n", page);
		} else {
			mtd->ecc_stats.corrected += stat;
			max_bitflips = max_t(unsigned int, max_bitflips, stat);
		}
	}

	/* Copy corrected data to caller's buffer now */
	memcpy(buf, tn->buf.dmabuf, mtd->writesize);

	return max_bitflips;
}

static int octeon_nand_hw_bch_write_page(struct mtd_info *mtd,
					 struct nand_chip *chip,
					 const uint8_t *buf, int oob_required,
					 int page)
{
	struct cvm_nfc *tn = to_cvm_nfc(chip->controller);
	int i, eccsize = chip->ecc.size, ret;
	int eccbytes = chip->ecc.bytes;
	int eccsteps = chip->ecc.steps;
	const uint8_t *p;
	uint8_t *ecc_calc = chip->buffers->ecccalc;

	DEV_DBG(DEBUG_WRITE, tn->dev, "%s(buf?%p, oob%d p%x)\n",
		__func__, buf, oob_required, page);
	for (i = 0; i < chip->ecc.total; i++)
		ecc_calc[i] = 0xFF;

	/* Copy the page data from caller's buffers to private buffer */
	chip->write_buf(mtd, buf, mtd->writesize);
	/* Use private date as source for ECC calculation */
	p = tn->buf.dmabuf;

	/* Hardware ECC calculation */
	for (i = 0; eccsteps; eccsteps--, i += eccbytes, p += eccsize) {
		int ret;

		ret = chip->ecc.calculate(mtd, p, &ecc_calc[i]);

		if (ret < 0)
			DEV_DBG(DEBUG_WRITE, tn->dev,
				"calculate(mtd, p?%p, &ecc_calc[%d]?%p) returned %d\n",
				p, i, &ecc_calc[i], ret);

		DEV_DBG(DEBUG_WRITE, tn->dev,
			"block offset %lx, ecc offset %x\n", p - buf, i);
	}

	ret = mtd_ooblayout_set_eccbytes(mtd, ecc_calc, chip->oob_poi, 0,
					 chip->ecc.total);
	if (ret)
		return ret;

	/* Store resulting OOB into private buffer, will be sent to HW */
	chip->write_buf(mtd, chip->oob_poi, mtd->oobsize);

	return 0;
}

/**
 * nand_write_page_raw - [INTERN] raw page write function
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @buf: data buffer
 * @oob_required: must write chip->oob_poi to OOB
 * @page: page number to write
 *
 * Not for syndrome calculating ECC controllers, which use a special oob layout.
 */
static int octeon_nand_write_page_raw(struct mtd_info *mtd,
				      struct nand_chip *chip,
				      const uint8_t *buf, int oob_required,
				      int page)
{
	chip->write_buf(mtd, buf, mtd->writesize);
	if (oob_required)
		chip->write_buf(mtd, chip->oob_poi, mtd->oobsize);

	return 0;
}

/**
 * octeon_nand_write_oob_std - [REPLACEABLE] the most common OOB data write
 *                             function
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @page: page number to write
 */
static int octeon_nand_write_oob_std(struct mtd_info *mtd,
				     struct nand_chip *chip,
				     int page)
{
	int status = 0;
	const uint8_t *buf = chip->oob_poi;
	int length = mtd->oobsize;

	chip->cmdfunc(mtd, NAND_CMD_SEQIN, mtd->writesize, page);
	chip->write_buf(mtd, buf, length);
	/* Send command to program the OOB data */
	chip->cmdfunc(mtd, NAND_CMD_PAGEPROG, -1, -1);

	status = chip->waitfunc(mtd, chip);

	return status & NAND_STATUS_FAIL ? -EIO : 0;
}

/**
 * octeon_nand_read_page_raw - [INTERN] read raw page data without ecc
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @buf: buffer to store read data
 * @oob_required: caller requires OOB data read to chip->oob_poi
 * @page: page number to read
 *
 * Not for syndrome calculating ECC controllers, which use a special oob layout.
 */
static int octeon_nand_read_page_raw(struct mtd_info *mtd,
				     struct nand_chip *chip,
				     uint8_t *buf, int oob_required, int page)
{
	chip->read_buf(mtd, buf, mtd->writesize);
	if (oob_required)
		chip->read_buf(mtd, chip->oob_poi, mtd->oobsize);
	return 0;
}

static int octeon_nand_read_oob_std(struct mtd_info *mtd,
				    struct nand_chip *chip,
				    int page)

{
	chip->cmdfunc(mtd, NAND_CMD_READOOB, 0, page);
	chip->read_buf(mtd, chip->oob_poi, mtd->oobsize);
	return 0;
}

static int octeon_nand_calc_bch_ecc_strength(struct nand_chip *nand)
{
	struct mtd_info *mtd = nand_to_mtd(nand);
	struct nand_ecc_ctrl *ecc = &nand->ecc;
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int nsteps = mtd->writesize / ecc->size;
	int oobchunk = mtd->oobsize / nsteps;

	/* ecc->strength determines ecc_level and OOB's ecc_bytes. */
	const u8 strengths[]  = {4, 8, 16, 24, 32, 40, 48, 56, 60, 64};
	/* first set the desired ecc_level to match strengths[] */
	int index = ARRAY_SIZE(strengths) - 1;
	int need;

	while (index > 0 && !(ecc->options & NAND_ECC_MAXIMIZE) &&
			strengths[index - 1] >= ecc->strength)
		index--;
	do {
		need = DIV_ROUND_UP(15 * strengths[index], 8);
		if (need <= oobchunk - 2)
			break;
	} while (index > 0);
	ecc->strength = strengths[index];
	ecc->bytes = need;

	if (!tn->eccmask)
		tn->eccmask = devm_kzalloc(tn->dev, ecc->bytes, GFP_KERNEL);
	if (!tn->eccmask)
		return -ENOMEM;

	return 0;
}

/* sample the BCH signature of an erased (all 0xff) page,
 * to XOR into all page traffic, so erased pages have no ECC errors
 */
static int cvm_bch_save_empty_eccmask(struct nand_chip *nand)
{
	struct mtd_info *mtd = nand_to_mtd(nand);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	unsigned int eccsize = nand->ecc.size;
	unsigned int eccbytes = nand->ecc.bytes;
	uint8_t erased_ecc[eccbytes];
	dma_addr_t erased_handle;
	unsigned char *erased_page = dma_alloc_coherent(tn->dev, eccsize,
					&erased_handle, GFP_KERNEL);
	int i;
	int rc = 0;

	if (!erased_page)
		return -ENOMEM;

	memset(erased_page, 0xff, eccsize);
	memset(erased_ecc, 0, eccbytes);

	rc = octeon_nand_bch_calculate_ecc_internal(mtd,
				erased_handle, erased_ecc);

	dma_free_coherent(tn->dev, eccsize, erased_page, erased_handle);

	for (i = 0; i < eccbytes; i++)
		tn->eccmask[i] = erased_ecc[i] ^ 0xff;

	return rc;
}
#endif /*CONFIG_CAVIUM_BCH*/

static void cvm_nfc_chip_sizing(struct nand_chip *nand)
{
	struct cvm_nand_chip *chip = to_cvm_nand(nand);
	struct mtd_info *mtd = nand_to_mtd(nand);
	struct nand_ecc_ctrl *ecc = &nand->ecc;

	chip->row_bytes = nand->onfi_params.addr_cycles & 0xf;
	chip->col_bytes = nand->onfi_params.addr_cycles >> 4;

	/*
	 * HW_BCH using Cavium BCH engine, or SOFT_BCH laid out in
	 * HW_BCH-compatible fashion, depending on devtree advice
	 * and kernel config.
	 * BCH/NFC hardware capable of subpage ops, not implemented.
	 */
	mtd_set_ooblayout(mtd, &nand_ooblayout_lp_ops);
	nand->options |= NAND_NO_SUBPAGE_WRITE;

	if (ecc->mode != NAND_ECC_NONE) {
		int nsteps = ecc->steps ?: 1;

		if (ecc->size && ecc->size != mtd->writesize)
			nsteps = mtd->writesize / ecc->size;
		else if (mtd->writesize > def_ecc_size &&
				!(mtd->writesize & (def_ecc_size - 1)))
			nsteps = mtd->writesize / def_ecc_size;
		ecc->steps = nsteps;
		ecc->size = mtd->writesize / nsteps;
		ecc->bytes = mtd->oobsize / nsteps;

		/*
		 * no subpage ops, but set subpage-shift to match ecc->steps
		 * so mtd_nandbiterrs tests appropriate boundaries
		 */
		if (!mtd->subpage_sft && !(ecc->steps & (ecc->steps - 1)))
			mtd->subpage_sft = fls(ecc->steps) - 1;

#if IS_ENABLED(CONFIG_CAVIUM_BCH)
		if (ecc->mode != NAND_ECC_SOFT && bch_vf &&
				!octeon_nand_calc_bch_ecc_strength(nand)) {
			struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
			struct device *dev = tn->dev;

			dev_info(dev, "Using hardware BCH engine support\n");
			ecc->mode = NAND_ECC_HW_SYNDROME;
			ecc->algo = NAND_ECC_BCH;
			ecc->read_page = octeon_nand_hw_bch_read_page;
			ecc->write_page = octeon_nand_hw_bch_write_page;
			ecc->read_page_raw = octeon_nand_read_page_raw;
			ecc->write_page_raw = octeon_nand_write_page_raw;
			ecc->read_oob = octeon_nand_read_oob_std;
			ecc->write_oob = octeon_nand_write_oob_std;

			ecc->calculate = octeon_nand_bch_calculate;
			ecc->correct = octeon_nand_bch_correct;
			ecc->hwctl = octeon_nand_bch_hwctl;

			DEV_DBG(DEBUG_INIT, tn->dev,
				"NAND chip %d using hw_bch\n",
				tn->selected_chip);
			DEV_DBG(DEBUG_INIT, tn->dev,
				" %d bytes ECC per %d byte block\n",
				ecc->bytes, ecc->size);
			DEV_DBG(DEBUG_INIT, tn->dev,
				" for %d bits of correction per block.",
				ecc->strength);

			cvm_bch_save_empty_eccmask(nand);
		}
#endif /*CONFIG_CAVIUM_BCH*/
	}
}

static int cvm_nfc_chip_init(struct cvm_nfc *tn, struct device *dev,
				   struct device_node *np)
{
	struct cvm_nand_chip *chip;
	struct nand_chip *nand;
	struct mtd_info *mtd;
	int ret;

	chip = devm_kzalloc(dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	ret = of_property_read_u32(np, "reg", &chip->cs);
	if (ret) {
		dev_err(dev, "could not retrieve reg property: %d\n", ret);
		return ret;
	}

	if (chip->cs >= NAND_MAX_CHIPS) {
		dev_err(dev, "invalid reg value: %u (max CS = 7)\n", chip->cs);
		return -EINVAL;
	}

	nand = &chip->nand;
	nand->controller = &tn->controller;

	nand_set_flash_node(nand, np);

	nand->select_chip = cvm_nand_select_chip;
	nand->cmdfunc = cvm_nand_cmdfunc;
	nand->waitfunc = cvm_nand_waitfunc;
	nand->read_byte = cvm_nand_read_byte;
	nand->read_buf = cvm_nand_read_buf;
	nand->write_buf = cvm_nand_write_buf;
	nand->onfi_set_features = cvm_nand_set_features;
	nand->onfi_get_features = cvm_nand_get_features;
	nand->setup_data_interface = cvm_nand_setup_data_interface;

	mtd = nand_to_mtd(nand);
	mtd->dev.parent = dev;

	/* TODO: support more then 1 chip */
	ret = nand_scan_ident(mtd, 1, NULL);
	if (ret)
		return ret;

	cvm_nfc_chip_sizing(nand);

	ret = nand_scan_tail(mtd);
	if (ret) {
		dev_err(dev, "nand_scan_tail failed: %d\n", ret);
		return ret;
	}

	ret = mtd_device_register(mtd, NULL, 0);
	if (ret) {
		dev_err(dev, "failed to register mtd device: %d\n", ret);
		nand_release(mtd);
		return ret;
	}

	list_add_tail(&chip->node, &tn->chips);
	return 0;
}

static int cvm_nfc_chips_init(struct cvm_nfc *tn)
{
	struct device *dev = tn->dev;
	struct device_node *np = dev->of_node;
	struct device_node *nand_np;
	int nr_chips = of_get_child_count(np);
	int ret;

	if (nr_chips > NAND_MAX_CHIPS) {
		dev_err(dev, "too many NAND chips: %d\n", nr_chips);
		return -EINVAL;
	}

	if (!nr_chips) {
		dev_err(dev, "no DT NAND chips found\n");
		return -ENODEV;
	}

	pr_info("%s: scanning %d chips DTs\n", __func__, nr_chips);

	for_each_child_of_node(np, nand_np) {
		ret = cvm_nfc_chip_init(tn, dev, nand_np);
		if (ret) {
			of_node_put(nand_np);
			return ret;
		}
	}
	return 0;
}

/* Reset NFC and initialize registers. */
static int cvm_nfc_init(struct cvm_nfc *tn)
{
	const struct nand_sdr_timings *timings;
	u64 ndf_misc;
	int rc;

	/* Initialize values and reset the fifo */
	ndf_misc = readq(tn->base + NDF_MISC);

	ndf_misc &= ~NDF_MISC_EX_DIS;
	ndf_misc |= (NDF_MISC_BT_DIS | NDF_MISC_RST_FF);
	writeq(ndf_misc, tn->base + NDF_MISC);

	/* Bring the fifo out of reset */
	ndf_misc &= ~(NDF_MISC_RST_FF);

	/* Maximum of co-processor cycles for glitch filtering */
	ndf_misc |= FIELD_PREP(NDF_MISC_WAIT_CNT, 0x3f);

	writeq(ndf_misc, tn->base + NDF_MISC);

	/* Set timing parameters to onfi mode 0 for probing */
	timings = onfi_async_timing_mode_to_sdr_timings(0);
	if (IS_ERR(timings))
		return PTR_ERR(timings);
	rc = set_default_timings(tn, timings);
	if (rc)
		return rc;

	return 0;
}

static int cvm_nfc_probe(struct pci_dev *pdev,
			      const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct cvm_nfc *tn;
	int ret;

	tn = devm_kzalloc(dev, sizeof(*tn), GFP_KERNEL);
	if (!tn)
		return -ENOMEM;

	tn->dev = dev;
	spin_lock_init(&tn->controller.lock);
	init_waitqueue_head(&tn->controller.wq);
	INIT_LIST_HEAD(&tn->chips);

	pci_set_drvdata(pdev, tn);
	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;
	ret = pci_request_regions(pdev, KBUILD_MODNAME);
	if (ret)
		return ret;
	tn->base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!tn->base) {
		ret = -EINVAL;
		goto release;
	}

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSIX);
	if (ret < 0)
		goto release;

	tn->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(tn->clk)) {
		ret = PTR_ERR(tn->clk);
		goto release;
	}

	ret = clk_prepare_enable(tn->clk);
	if (ret)
		goto release;

	if (dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)))
		dev_err(dev, "64 bit DMA mask not available\n");

	tn->buf.dmabuflen = NAND_MAX_PAGESIZE + NAND_MAX_OOBSIZE;
	tn->buf.dmabuf = dma_alloc_coherent(dev, tn->buf.dmabuflen,
					     &tn->buf.dmaaddr, GFP_KERNEL);
	if (!tn->buf.dmabuf) {
		ret = -ENOMEM;
		goto unclk;
	}

	/* one hw-bch response, for one outstanding transaction */
	tn->bch_resp = dma_alloc_coherent(dev, sizeof(*tn->bch_resp),
					&tn->bch_rhandle, GFP_KERNEL);

	tn->stat = dma_alloc_coherent(dev, 8, &tn->stat_addr, GFP_KERNEL);
	if (!tn->stat) {
		ret = -ENOMEM;
		goto unclk;
	}

	ret = devm_request_irq(dev, pci_irq_vector(pdev, 0),
			       cvm_nfc_isr, 0, "nand-flash-controller", tn);
	if (ret)
		goto unclk;

#if IS_ENABLED(CONFIG_CAVIUM_BCH)
	bch_vf = cavm_bch_getv();
#endif

	cvm_nfc_init(tn);
	ret = cvm_nfc_chips_init(tn);
	if (ret) {
		dev_err(dev, "failed to init nand chips\n");
		goto unclk;
	}
	dev_info(dev, "probed\n");
	return 0;

unclk:
	clk_disable_unprepare(tn->clk);
release:
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
	return ret;
}

static void cvm_nfc_remove(struct pci_dev *pdev)
{
	struct cvm_nfc *tn = pci_get_drvdata(pdev);
	struct cvm_nand_chip *chip;

	if (!tn)
		return;

	while (!list_empty(&tn->chips)) {
		chip = list_first_entry(&tn->chips, struct cvm_nand_chip,
					node);
		nand_release(&chip->nand.mtd);
		list_del(&chip->node);
	}
	clk_disable_unprepare(tn->clk);
	pci_release_regions(pdev);

#if IS_ENABLED(CONFIG_CAVIUM_BCH)
	if (bch_vf)
		cavm_bch_putv(bch_vf);
#endif

	pci_set_drvdata(pdev, NULL);
}

#ifdef CONFIG_PM_SLEEP
static int cvm_nfc_suspend(struct pci_dev *pdev, pm_message_t unused)
{
	struct cvm_nfc *tn = pci_get_drvdata(pdev);
	struct cvm_nand_chip *chip;

	list_for_each_entry(chip, &tn->chips, node)
		chip->iface_set = false;
	clk_disable_unprepare(tn->clk);

	return 0;
}

static int cvm_nfc_resume(struct pci_dev *pdev)
{
	struct cvm_nfc *tn = pci_get_drvdata(pdev);
	int ret = clk_prepare_enable(tn->clk);

	if (ret) {
		dev_err(tn->dev, "failed to enable clk\n");
		return ret;
	}

	/* can some of this be skipped, or refactored... */
	cvm_nfc_init(tn);
	ret = cvm_nfc_chips_init(tn);
	if (ret) {
		dev_err(tn->dev, "failed to resume nand chips\n");
		return ret;
	}

	return 0;
}
#endif

static const struct pci_device_id cvm_nfc_pci_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xa04f) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, cvm_nfc_pci_id_table);

static struct pci_driver cvm_nfc_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= cvm_nfc_pci_id_table,
	.probe		= cvm_nfc_probe,
	.remove		= cvm_nfc_remove,
#ifdef CONFIG_PM_SLEEP
	.suspend	= cvm_nfc_suspend,
	.resume		= cvm_nfc_resume,
#endif
};

module_pci_driver(cvm_nfc_pci_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jan Glauber <jglauber@cavium.com>");
MODULE_DESCRIPTION("Cavium Inc. cvm NAND driver");
