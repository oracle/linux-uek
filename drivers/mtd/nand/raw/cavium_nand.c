/*
 * Cavium cn8xxx NAND flash controller (NDF) driver.
 *
 * Copyright (C) 2017 Cavium Inc.
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
#include <linux/mtd/nand.h>
#include <linux/mtd/nand_bch.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include <asm/octeon/octeon.h>

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
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64 nop		: 60;
	u64 opcode	: 4;
#else
	u16 opcode	: 4;
	u16 nop		: 12;
#endif
};

struct ndf_wait_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64		: 53;
	u64 wlen	: 3;	/* timing parameter select */
	u64		: 3;
	u64 r_b		: 1;	/* wait for one cycle or PBUS_WAIT deassert */
	u64 opcode	: 4;
#else
	u16 opcode	: 4;
	u16 r_b		: 1;	/* wait for one cycle or PBUS_WAIT deassert */
	u16		: 3;
	u16 wlen	: 3;	/* timing parameter select */
	u16		: 5;
#endif
};

struct ndf_bus_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64		: 56;
	u64 direction	: 4;	/* 1 = acquire, 0 = release */
	u64 opcode	: 4;
#else
	u16 opcode	: 4;
	u16 direction	: 4;	/* 1 = acquire, 0 = release */
	u16		: 8;
#endif
};

struct ndf_chip_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64		: 54;
	u64 bus_width	: 2;	/* 10 = 16 bit, 01 = 8 bit */
	u64 enable	: 1;	/* 1 = enable, 0 = disable */
	u64 chip	: 3;	/* select chip, 0 = disable */
	u64 opcode	: 4;
#else
	u16 opcode	: 4;
	u16 chip	: 3;	/* select chip, 0 = disable */
	u16 enable	: 1;	/* 1 = enable, 0 = disable */
	u16 bus_width	: 2;	/* 10 = 16 bit, 01 = 8 bit */
	u16		: 6;
#endif
};

struct ndf_cle_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64		: 39;
	u64 clen3	: 3;	/* time between WE deassert and CLE */
	u64 clen2	: 3;	/* time WE remains asserted */
	u64 clen1	: 3;	/* time between PBUS CLE and WE asserts */
	u64 cmd_data	: 8;	/* command sent to the PBUS AD pins */
	u64		: 4;
	u64 opcode	: 4;
#else
	u32 opcode	: 4;
	u32		: 4;
	u32 cmd_data	: 8;	/* command sent to the PBUS AD pins */
	u32 clen1	: 3;	/* time between PBUS CLE and WE asserts */
	u32 clen2	: 3;	/* time WE remains asserted */
	u32 clen3	: 3;	/* time between WE deassert and CLE */
	u32		: 7;
#endif
};

/* RD_EDO_CMD uses the same layout as RD_CMD */
struct ndf_rd_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64		: 32;
	u64 rlen4	: 3;
	u64 rlen3	: 3;
	u64 rlen2	: 3;
	u64 rlen1	: 3;
	u64 data	: 16;	/* data bytes */
	u64 opcode	: 4;
#else
	u32 opcode	: 4;
	u32 data	: 16;	/* data bytes */
	u32 rlen1	: 3;
	u32 rlen2	: 3;
	u32 rlen3	: 3;
	u32 rlen4	: 3;
#endif
};

struct ndf_wr_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64		: 34;
	u64 wlen2	: 3;
	u64 wlen1	: 3;
	u64		: 4;
	u64 data	: 16;	/* data bytes */
	u64 opcode	: 4;
#else
	u32 opcode	: 4;
	u32 data	: 16;	/* data bytes */
	u32		: 4;
	u32 wlen1	: 3;
	u32 wlen2	: 3;
	u32		: 3;
#endif
};

struct ndf_set_tm_par_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 64;
	u64 tm_par7	: 8;
	u64 tm_par6	: 8;
	u64 tm_par5	: 8;	/*     using tim_par * (2 ^ tim_mult).		  */
	u64 tm_par4	: 8;	/*     All values are scaled by tim_mult	  */
	u64 tm_par3	: 8;	/*     A value of zero means one cycle.		  */
	u64 tm_par2	: 8;	/*     specify the number of coprocessor cycles.  */
	u64 tm_par1	: 8;	/* --> Following are the 7 timing parameters that */
	u64 tim_mult	: 4;	/* multiplier for the seven paramters */
	u64 opcode	: 4;
#else
	u64 opcode	: 4;
	u64 tim_mult	: 4;	/* multiplier for the seven paramters */
	u64 tm_par1	: 8;	/* --> Following are the 7 timing parameters that */
	u64 tm_par2	: 8;	/*     specify the number of coprocessor cycles.  */
	u64 tm_par3	: 8;	/*     A value of zero means one cycle.		  */
	u64 tm_par4	: 8;	/*     All values are scaled by tim_mult	  */
	u64 tm_par5	: 8;	/*     using tim_par * (2 ^ tim_mult).		  */
	u64 tm_par6	: 8;
	u64 tm_par7	: 8;
#endif
};

struct ndf_ale_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u64		: 32;
	u64 adr_byt8	: 8;
	u64 adr_byt7	: 8;
	u64 adr_byt6	: 8;
	u64 adr_byt5	: 8;
	u64 adr_byt4	: 8;
	u64 adr_byt3	: 8;
	u64 adr_byt2	: 8;
	u64 adr_byt1	: 8;
	u64		: 4;
	u64 alen4	: 3;
	u64 alen3	: 3;
	u64 alen2	: 3;
	u64 alen1	: 3;
	u64		: 4;
	u64 adr_byte_num: 4;	/* number of address bytes to be sent */
	u64		: 4;
	u64 opcode	: 4;
#else
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
#endif
};

struct ndf_wait_status_cmd {
#ifdef __BIG_ENDIAN_BITFIELD
	u32 rlen4	: 3;
	u32 rlen3	: 3;
	u32 rlen2	: 3;
	u32 rlen1	: 3;
	u32 comp_byte	: 8;
	u32 and_mask	: 8;
	u32 nine	: 4;	/* set to 9 */
	u8 adr_byt[4];		/* ALE only */
	u32		: 4;
	u32 alen4	: 3;	/* ALE only */
	u32 alen3	: 3;	/* ALE only */
	u32 alen2	: 3;	/* ALE only */
	u32 alen1	: 3;	/* ALE only */
	u32		: 4;
	u32 adr_byte_num: 4;	/* ALE only: number of address bytes to be sent */
	u32 ale_ind	: 8;	/* set to 5 to select WAIT_STATUS_ALE command */
	u32		: 8;
	u32 clen3	: 3;
	u32 clen2	: 3;
	u32 clen1	: 3;
	u32 data	: 8;	/* data */
	u32		: 4;
	u32 opcode	: 4;
#else
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
#endif
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

#ifdef CONFIG_CAVIUM_OCTEON_SOC
 #define CLE_CLEN1		0
 #define CLE_CLEN2		1
 #define CLE_CLEN3		3

 #define ALE_ALEN1		4
 #define ALE_ALEN2		1
 #define ALE_ALEN3		2
 #define ALE_ALEN4		5

 #define RD_RLEN1		0
 #define RD_RLEN2		6
 #define RD_RLEN3		7
 #define RD_RLEN4		0
#else
 #define CLE_CLEN1		4
 #define CLE_CLEN2		1
 #define CLE_CLEN3		2

 #define ALE_ALEN1		3
 #define ALE_ALEN2		1
 #define ALE_ALEN3		5
 #define ALE_ALEN4		2

 #define RD_RLEN1		7
 #define RD_RLEN2		3
 #define RD_RLEN3		1
 #define RD_RLEN4		7
#endif

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
#define NAND_MAX_PAGESIZE	2048
#define NAND_MAX_OOBSIZE	64

/* NAND chip related information */
struct cvm_nand_chip {
	struct list_head node;
	struct nand_chip nand;
	int cs;					/* chip select 0..7 */
	struct ndf_set_tm_par_cmd timings;	/* timing parameters */
	int selected_page;
	bool oob_access;
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
};

static inline u64 cvm_nfc_readq(const volatile void __iomem *addr)
{
#ifdef CONFIG_CAVIUM_OCTEON_SOC
	return __raw_readq(addr);
#else
	return readq(addr);
#endif
}

static inline void cvm_nfc_writeq(u64 value, volatile void __iomem *addr)
{
#ifdef CONFIG_CAVIUM_OCTEON_SOC
	__raw_writeq(value, addr);
#else
	writeq(value, addr);
#endif
}

static inline struct cvm_nand_chip *to_cvm_nand(struct nand_chip *nand)
{
	return container_of(nand, struct cvm_nand_chip, nand);
}

static inline struct cvm_nfc *to_cvm_nfc(struct nand_hw_control *ctrl)
{
	return container_of(ctrl, struct cvm_nfc, controller);
}

/* default parameters used for probing chips */
static int default_onfi_timing; /* = 0; */
static int default_width = 1; /* 8 bit */
static int default_page_size = 2048;
static struct ndf_set_tm_par_cmd default_timing_parms;

/*
 * Get the number of bits required to encode the column bits. This
 * does not include bits required for the OOB area.
 */
static int ndf_get_column_bits(struct nand_chip *nand)
{
	int page_size;

	if (!nand)
		page_size = default_page_size;
	else
		page_size = le32_to_cpu(nand->onfi_params.byte_per_page);
	return get_bitmask_order(page_size - 1);
}

irqreturn_t cvm_nfc_isr(int irq, void *dev_id)
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

	if (tn->use_status)
		return *tn->stat;

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

static inline int timing_to_cycle(u32 timing, unsigned long clock)
{
	unsigned int ns;
	int margin = 2;

	ns = DIV_ROUND_UP(timing, 1000);

	clock /= 1000000; /* no rounding needed since clock is multiple of 1MHz */
	ns *= clock;
	return DIV_ROUND_UP(ns, 1000) + margin;
}

#ifdef CONFIG_CAVIUM_OCTEON_SOC
static void set_timings(struct ndf_set_tm_par_cmd *tp,
			const struct nand_sdr_timings *timings,
			unsigned long sclk)
{
	u64 clocks_us;
	int margin;
	int pulse_adjust;
	u64 val;

	clocks_us = DIV_ROUND_UP(octeon_get_io_clock_rate(), 1000000);

	pulse_adjust = timings->tWC_min - timings->tWH_min - timings->tWP_min;
	pulse_adjust = (pulse_adjust / 2000 + 1) * 1000;

	margin = 2 * clocks_us;

	tp->tim_mult = 0;
	tp->tm_par1 = DIV_ROUND_UP(timings->tWP_min + margin + pulse_adjust,
				   1000);
	val = max(timings->tWH_min, timings->tWC_min - timings->tWP_min);
	tp->tm_par2 = DIV_ROUND_UP(val + margin + pulse_adjust, 1000);
	tp->tm_par3 = DIV_ROUND_UP(timings->tCLH_min + margin, 1000);
	tp->tm_par4 = DIV_ROUND_UP(timings->tALS_min + margin, 1000);
	tp->tm_par5 = tp->tm_par3;
	tp->tm_par6 = tp->tm_par1;
	tp->tm_par7 = tp->tm_par2;
}
#else
static void set_timings(struct ndf_set_tm_par_cmd *tp,
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

	/* TODO: comment parameter re-use */

	pr_debug("%s: tim_par: mult: %d  p1: %d  p2: %d  p3: %d\n",
		__func__, tp->tim_mult, tp->tm_par1, tp->tm_par2, tp->tm_par3);
	pr_debug("                 p4: %d  p5: %d  p6: %d  p7: %d\n",
		tp->tm_par4, tp->tm_par5, tp->tm_par6, tp->tm_par7);

}
#endif

static int set_default_timings(struct cvm_nfc *tn,
			       const struct nand_sdr_timings *timings)
{
	unsigned long sclk = clk_get_rate(tn->clk);

	set_timings(&default_timing_parms, timings, sclk);
	return 0;
}

static int cvm_nfc_chip_set_timings(struct cvm_nand_chip *chip,
					 const struct nand_sdr_timings *timings)
{
	struct cvm_nfc *tn = to_cvm_nfc(chip->nand.controller);
	unsigned long sclk = clk_get_rate(tn->clk);

	set_timings(&chip->timings, timings, sclk);
	return 0;
}

/* How many bytes are free in the NFD_CMD queue? */
static int ndf_cmd_queue_free(struct cvm_nfc *tn)
{
	u64 ndf_misc;

	ndf_misc = cvm_nfc_readq(tn->base + NDF_MISC);
	return FIELD_GET(NDF_MISC_FR_BYTE, ndf_misc);
}

/* Submit a command to the NAND command queue. */
static int ndf_submit(struct cvm_nfc *tn, union ndf_cmd *cmd)
{
	int opcode;

#ifdef __BIG_ENDIAN_BITFIELD
	opcode = cmd->val[1] & 0xf;
#else
	opcode = cmd->val[0] & 0xf;
#endif

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
#ifdef __BIG_ENDIAN_BITFIELD
		cvm_nfc_writeq(cmd->val[1], tn->base + NDF_CMD);
#else
		cvm_nfc_writeq(cmd->val[0], tn->base + NDF_CMD);
#endif
		break;
	case NDF_OP_ALE_CMD: /* ALE commands take either one or two 64bit words */
		if (cmd->u.ale_cmd.adr_byte_num < 5) {
			if (ndf_cmd_queue_free(tn) < 8)
				goto full;
#ifdef CONFIG_CAVIUM_OCTEON_SOC
			cvm_nfc_writeq(cmd->val[1], tn->base + NDF_CMD);
#else
			cvm_nfc_writeq(cmd->val[0], tn->base + NDF_CMD);
#endif
		} else {
			if (ndf_cmd_queue_free(tn) < 16)
				goto full;
#ifdef CONFIG_CAVIUM_OCTEON_SOC
			cvm_nfc_writeq(cmd->val[1], tn->base + NDF_CMD);
			cvm_nfc_writeq(cmd->val[0], tn->base + NDF_CMD);
#else
			cvm_nfc_writeq(cmd->val[0], tn->base + NDF_CMD);
			cvm_nfc_writeq(cmd->val[1], tn->base + NDF_CMD);
#endif
		}
		break;
	case NDF_OP_WAIT_STATUS: /* Wait status commands take two 64bit words */
		if (ndf_cmd_queue_free(tn) < 16)
			goto full;
#ifdef CONFIG_CAVIUM_OCTEON_SOC
		cvm_nfc_writeq(cmd->val[1], tn->base + NDF_CMD);
		cvm_nfc_writeq(cmd->val[0], tn->base + NDF_CMD);
#else
		cvm_nfc_writeq(cmd->val[0], tn->base + NDF_CMD);
		cvm_nfc_writeq(cmd->val[1], tn->base + NDF_CMD);
#endif
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
static int ndf_wait_for_busy_done(struct cvm_nfc *tn)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wait.opcode = NDF_OP_WAIT;
	cmd.u.wait.r_b = 1;
	cmd.u.wait.wlen = 6;

	if (ndf_submit(tn, &cmd))
		return -ENOMEM;
	return 0;
}

static bool ndf_dma_done(struct cvm_nfc *tn)
{
	u64 dma_cfg, ndf_int;

	/* Check DMA done bit */
	ndf_int = cvm_nfc_readq(tn->base + NDF_INT);
	if (!(ndf_int & NDF_INT_DMA_DONE))
		return false;

	/* Enable bit should be clear after a transfer */
	dma_cfg = cvm_nfc_readq(tn->base + NDF_DMA_CFG);
	if (dma_cfg & NDF_DMA_CFG_EN)
		return false;
	return true;
}

static int ndf_wait(struct cvm_nfc *tn)
{
	long time_left;

#ifdef CONFIG_CAVIUM_OCTEON_SOC
	/* Octeon needs to poll */
	time_left = 1000;
	do {
		if (ndf_dma_done(tn))
			break;
		udelay(1);
		time_left--;
	} while (time_left);
#else
	/* enable all IRQ types */
	writeq(0xff, tn->base + NDF_INT_ENA_W1S);
	time_left = wait_event_timeout(tn->controller.wq,
				       ndf_dma_done(tn), 250);
	writeq(0xff, tn->base + NDF_INT_ENA_W1C);
#endif

	if (!time_left) {
		dev_err(tn->dev, "ndf_wait: timeout error\n");
		return -ETIMEDOUT;
	}
	return 0;
}

static int ndf_wait_idle(struct cvm_nfc *tn)
{
	u64 val;
	long time_left;

#ifdef CONFIG_CAVIUM_OCTEON_SOC
	/* Octeon needs to poll */
	time_left = 1000;
	do {
		val = cvm_nfc_readq(tn->base + NDF_ST_REG);
		if (val & NDF_ST_REG_EXE_IDLE)
			break;
		udelay(1);
		time_left--;
	} while (time_left);

	if (!time_left)
		return -1;
	else
		return 0;
		
#else
	return readq_poll_timeout(tn->base + NDF_ST_REG, val,
				  val & NDF_ST_REG_EXE_IDLE, 100, 100000);
#endif
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

static int ndf_queue_cmd_wait(struct cvm_nfc *tn, int parm)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wait.opcode = NDF_OP_WAIT;
	cmd.u.wait.wlen = parm;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_cle(struct cvm_nfc *tn, int command)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.cle_cmd.opcode = NDF_OP_CLE_CMD;
	cmd.u.cle_cmd.cmd_data = command;
	cmd.u.cle_cmd.clen1 = CLE_CLEN1;
	cmd.u.cle_cmd.clen2 = CLE_CLEN2;
	cmd.u.cle_cmd.clen3 = CLE_CLEN3;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_ale(struct cvm_nfc *tn, int addr_bytes,
			     struct nand_chip *nand, u64 addr, int page_size)
{
	struct cvm_nand_chip *cvm_nand = (nand) ? to_cvm_nand(nand) : NULL;
	int column = addr & (page_size - 1);
	u64 row = addr >> ndf_get_column_bits(nand);
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.ale_cmd.opcode = NDF_OP_ALE_CMD;
	cmd.u.ale_cmd.adr_byte_num = addr_bytes;

	/* set column bit for OOB area, assume OOB follows page */
	if (cvm_nand && cvm_nand->oob_access)
		column |= page_size;

	if (addr_bytes == 1) {
		cmd.u.ale_cmd.adr_byt1 = addr & 0xff;
	} else if (addr_bytes == 2) {
		cmd.u.ale_cmd.adr_byt1 = addr & 0xff;
		cmd.u.ale_cmd.adr_byt2 = (addr >> 8) & 0xff;
	} else if (addr_bytes == 4) {
		cmd.u.ale_cmd.adr_byt1 =  column & 0xff;
		cmd.u.ale_cmd.adr_byt2 = (column >> 8) & 0xff;
		cmd.u.ale_cmd.adr_byt3 = row & 0xff;
		cmd.u.ale_cmd.adr_byt4 = (row >> 8) & 0xff;
	} else if (addr_bytes > 4) {
		cmd.u.ale_cmd.adr_byt1 =  column & 0xff;
		cmd.u.ale_cmd.adr_byt2 = (column >> 8) & 0xff;
		cmd.u.ale_cmd.adr_byt3 = row & 0xff;
		cmd.u.ale_cmd.adr_byt4 = (row >> 8) & 0xff;
		/* row bits above 16 */
		cmd.u.ale_cmd.adr_byt5 = (row >> 16) & 0xff;
		cmd.u.ale_cmd.adr_byt6 = (row >> 24) & 0xff;
		cmd.u.ale_cmd.adr_byt7 = (row >> 32) & 0xff;
		cmd.u.ale_cmd.adr_byt8 = (row >> 40) & 0xff;
	}

	cmd.u.ale_cmd.alen1 = ALE_ALEN1;
	cmd.u.ale_cmd.alen2 = ALE_ALEN2;
	cmd.u.ale_cmd.alen3 = ALE_ALEN3;
	cmd.u.ale_cmd.alen4 = ALE_ALEN4;
	return ndf_submit(tn, &cmd);
}

static int ndf_queue_cmd_write(struct cvm_nfc *tn, int len)
{
	union ndf_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wr_cmd.opcode = NDF_OP_WR_CMD;
	cmd.u.wr_cmd.data = len;
	cmd.u.wr_cmd.wlen1 = 3;
	cmd.u.wr_cmd.wlen2 = 1;
	return ndf_submit(tn, &cmd);
}

static int ndf_build_pre_cmd(struct cvm_nfc *tn, int cmd1,
			     int addr_bytes, u64 addr, int cmd2)
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
		page_size = le32_to_cpu(nand->onfi_params.byte_per_page);
		if (le16_to_cpu(nand->onfi_params.features) &
		    ONFI_FEATURE_16_BIT_BUS)
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

	rc = ndf_queue_cmd_wait(tn, 1);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_cle(tn, cmd1);
	if (rc)
		return rc;

	if (addr_bytes) {
		rc = ndf_queue_cmd_ale(tn, addr_bytes, nand, addr, page_size);
		if (rc)
			return rc;
	}

	/* CLE 2 */
	if (cmd2) {
		rc = ndf_queue_cmd_cle(tn, cmd2);
		if (rc)
			return rc;
	}
	return 0;
}

static int ndf_build_post_cmd(struct cvm_nfc *tn)
{
	int rc;

	/* Deselect chip */
	rc = ndf_queue_cmd_chip(tn, 0, 0, 0);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_wait(tn, 2);
	if (rc)
		return rc;

	/* Release bus */
	rc = ndf_queue_cmd_bus(tn, 0);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_wait(tn, 2);
	if (rc)
		return rc;

	/* Write 1 to clear all interrupt bits before starting DMA */
	cvm_nfc_writeq(0xff, tn->base + NDF_INT);

	/*
	 * Last action is ringing the doorbell with number of bus
	 * acquire-releases cycles (currently 1).
	 */
	cvm_nfc_writeq(1, tn->base + NDF_DRBELL);
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
	cvm_nfc_writeq(bus_addr, tn->base + NDF_DMA_ADR);
	cvm_nfc_writeq(dma_cfg, tn->base + NDF_DMA_CFG);
}

static int cvm_nand_reset(struct cvm_nfc *tn)
{
	int rc;

	rc = ndf_build_pre_cmd(tn, NAND_CMD_RESET, 0, 0, 0);
	if (rc)
		return rc;

	rc = ndf_wait_for_busy_done(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn);
	if (rc)
		return rc;
	return 0;
}

static int cvm_nand_set_features(struct mtd_info *mtd,
				      struct nand_chip *chip, int feature_addr,
				      u8 *subfeature_para)
{
	struct nand_chip *nand = mtd_to_nand(mtd);
	struct cvm_nfc *tn = to_cvm_nfc(nand->controller);
	int rc;

	rc = ndf_build_pre_cmd(tn, NAND_CMD_SET_FEATURES, 1, feature_addr, 0);
	if (rc)
		return rc;

	memcpy(tn->buf.dmabuf, subfeature_para, 4);
	memset(tn->buf.dmabuf + 4, 0, 4);

	rc = ndf_queue_cmd_write(tn, 8);
	if (rc)
		return rc;

	ndf_setup_dma(tn, 0, tn->buf.dmaaddr, 8);

	rc = ndf_wait_for_busy_done(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn);
	if (rc)
		return rc;
	return 0;
}

static int ndf_read(struct cvm_nfc *tn, int cmd1, int addr_bytes, u64 addr,
		    int cmd2, int len)
{
	dma_addr_t bus_addr = (cmd1 != NAND_CMD_STATUS) ?
			      tn->buf.dmaaddr : tn->stat_addr;
	struct nand_chip *nand = tn->controller.active;
	int timing_mode, bytes, rc;
	union ndf_cmd cmd;
	u64 start, end;

	if (!nand)
		timing_mode = default_onfi_timing;
	else
		timing_mode = onfi_get_async_timing_mode(nand);

	/* Build the command and address cycles */
	rc = ndf_build_pre_cmd(tn, cmd1, addr_bytes, addr, cmd2);
	if (rc)
		return rc;

	/* This waits for some time, then waits for busy to be de-asserted. */
	rc = ndf_wait_for_busy_done(tn);
	if (rc)
		return rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.u.wait.opcode = NDF_OP_WAIT;
	cmd.u.wait.wlen = 3;	/* tRR is 15 cycles, this is 16 so its ok */
	rc = ndf_submit(tn, &cmd);
	if (rc)
		return rc;
	rc = ndf_submit(tn, &cmd);
	if (rc)
		return rc;

	memset(&cmd, 0, sizeof(cmd));
#ifdef CONFIG_CAVIUM_OCTEON_SOC
	if (timing_mode & ONFI_TIMING_MODE_4 ||
	    timing_mode & ONFI_TIMING_MODE_5)
#else
	if (timing_mode == ONFI_TIMING_MODE_4 ||
	    timing_mode == ONFI_TIMING_MODE_5)
#endif
		cmd.u.rd_cmd.opcode = NDF_OP_RD_EDO_CMD;
	else
		cmd.u.rd_cmd.opcode = NDF_OP_RD_CMD;
	cmd.u.rd_cmd.data = len;
	cmd.u.rd_cmd.rlen1 = RD_RLEN1;
	cmd.u.rd_cmd.rlen2 = RD_RLEN2;
	cmd.u.rd_cmd.rlen3 = RD_RLEN3;
	cmd.u.rd_cmd.rlen4 = RD_RLEN4;
	rc = ndf_submit(tn, &cmd);
	if (rc)
		return rc;

	start = (u64) bus_addr;
	ndf_setup_dma(tn, 0, bus_addr, len);

	rc = ndf_build_post_cmd(tn);
	if (rc)
		return rc;

	/* Wait for the DMA to complete */
	rc = ndf_wait(tn);
	if (rc)
		return rc;

	end = cvm_nfc_readq(tn->base + NDF_DMA_ADR);
	bytes = end - start;

	/* Make sure NDF is really done */
	rc = ndf_wait_idle(tn);
	if (rc) {
		dev_err(tn->dev, "poll idle failed\n");
		return rc;
	}
	return bytes;
}

/*
 * Read a page from NAND. If the buffer has room, the out of band
 * data will be included.
 */
int ndf_page_read(struct cvm_nfc *tn, u64 addr, int len)
{
	int rc;

	memset(tn->buf.dmabuf, 0xff, len);
	rc = ndf_read(tn, NAND_CMD_READ0, 4, addr, NAND_CMD_READSTART, len);
	if (rc)
		return rc;

	return rc;
}

/* Erase a NAND block */
static int ndf_block_erase(struct cvm_nfc *tn, u64 addr)
{
	struct nand_chip *nand = tn->controller.active;
	int row, rc;

	row = addr >> ndf_get_column_bits(nand);
	rc = ndf_build_pre_cmd(tn, NAND_CMD_ERASE1, 2, row, NAND_CMD_ERASE2);
	if (rc)
		return rc;

	/* Wait for R_B to signal erase is complete  */
	rc = ndf_wait_for_busy_done(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn);
	if (rc)
		return rc;

	/* Wait until the command queue is idle */
	return ndf_wait_idle(tn);
}

/*
 * Write a page (or less) to NAND.
 */
static int ndf_page_write(struct cvm_nfc *tn, u64 addr)
{
	int len, rc;

	len = tn->buf.data_len - tn->buf.data_index;
	WARN_ON_ONCE(len & 0x7);

	ndf_setup_dma(tn, 1, tn->buf.dmaaddr + tn->buf.data_index, len);
	rc = ndf_build_pre_cmd(tn, NAND_CMD_SEQIN, 4, addr, 0);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_write(tn, len);
	if (rc)
		return rc;

	rc = ndf_queue_cmd_cle(tn, NAND_CMD_PAGEPROG);
	if (rc)
		return rc;

	/* Wait for R_B to signal program is complete  */
	rc = ndf_wait_for_busy_done(tn);
	if (rc)
		return rc;

	rc = ndf_build_post_cmd(tn);
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
	cvm_nand->oob_access = false;

	switch (command) {
	case NAND_CMD_READID:
		tn->buf.data_index = 0;
		memset(tn->buf.dmabuf, 0xff, 8);
		rc = ndf_read(tn, command, 1, column, 0, 8);
		if (rc < 0)
			dev_err(tn->dev, "READID failed with %d\n", rc);
		else
			tn->buf.data_len = rc;
		break;

	case NAND_CMD_READOOB:
		cvm_nand->oob_access = true;
		tn->buf.data_index = 0;
		tn->buf.data_len = ndf_page_read(tn,
				(page_addr << nand->page_shift) + 0x800,
				mtd->oobsize);

		if (tn->buf.data_len < mtd->oobsize) {
			dev_err(tn->dev, "READOOB failed with %d\n",
				tn->buf.data_len);
			tn->buf.data_len = 0;
		}
		break;

	case NAND_CMD_READ0:
		tn->buf.data_index = 0;
		tn->buf.data_len = ndf_page_read(tn,
				column + (page_addr << nand->page_shift),
				(1 << nand->page_shift) + mtd->oobsize);
		if (tn->buf.data_len < (1 << nand->page_shift) + mtd->oobsize) {
			dev_err(tn->dev, "READ0 failed with %d\n",
				tn->buf.data_len);
			tn->buf.data_len = 0;
		}
		break;

	case NAND_CMD_STATUS:
		tn->use_status = true;
		memset(tn->stat, 0xff, 8);
		rc = ndf_read(tn, command, 0, 0, 0, 8);
		if (rc < 0)
			dev_err(tn->dev, "STATUS failed with %d\n", rc);
		break;

	case NAND_CMD_RESET:
		tn->buf.data_index = 0;
		tn->buf.data_len = 0;
		memset(tn->buf.dmabuf, 0xff, tn->buf.dmabuflen);
		rc = cvm_nand_reset(tn);
		if (rc < 0)
			dev_err(tn->dev, "RESET failed with %d\n", rc);
		break;

	case NAND_CMD_PARAM:
		tn->buf.data_index = column;
		memset(tn->buf.dmabuf, 0xff, tn->buf.dmabuflen);
		rc = ndf_read(tn, command, 1, 0, 0, 2048);
		if (rc < 0)
			dev_err(tn->dev, "PARAM failed with %d\n", rc);
		else
			tn->buf.data_len = rc;
		break;

	case NAND_CMD_RNDOUT:
		tn->buf.data_index = column;
		break;

	case NAND_CMD_ERASE1:
		if (ndf_block_erase(tn, page_addr << nand->page_shift))
			dev_err(tn->dev, "ERASE1 failed\n");
		break;

	case NAND_CMD_ERASE2:
		/* We do all erase processing in the first command, so ignore
		 * this one.
		 */
		break;

	case NAND_CMD_SEQIN:
		if (column == mtd->writesize)
			cvm_nand->oob_access = true;
		tn->buf.data_index = column;
		tn->buf.data_len = column;
		cvm_nand->selected_page = page_addr;
		break;

	case NAND_CMD_PAGEPROG:
		rc = ndf_page_write(tn,
			cvm_nand->selected_page << nand->page_shift);
		if (rc)
			dev_err(tn->dev, "PAGEPROG failed with %d\n", rc);
		break;

	default:
		WARN_ON_ONCE(1);
		dev_err(tn->dev, "unhandled nand cmd: %x\n", command);
	}
}

static int cvm_nfc_chip_init_timings(struct cvm_nand_chip *chip,
					   struct device_node *np)
{
	const struct nand_sdr_timings *timings;
	int ret, mode;

	mode = onfi_get_async_timing_mode(&chip->nand);
	if (mode == ONFI_TIMING_MODE_UNKNOWN) {
		mode = chip->nand.onfi_timing_mode_default;
	} else {
		u8 feature[ONFI_SUBFEATURE_PARAM_LEN] = {};

		mode = fls(mode) - 1;
		if (mode < 0)
			mode = 0;

		feature[0] = mode;
		ret = chip->nand.onfi_set_features(&chip->nand.mtd, &chip->nand,
						ONFI_FEATURE_ADDR_TIMING_MODE,
						feature);
		if (ret)
			return ret;
	}

	timings = onfi_async_timing_mode_to_sdr_timings(mode);
	if (IS_ERR(timings))
		return PTR_ERR(timings);

	return cvm_nfc_chip_set_timings(chip, timings);
}

static int cvm_nfc_chip_init(struct cvm_nfc *tn, struct device *dev,
				   struct device_node *np)
{
	struct cvm_nand_chip *chip;
	struct nand_chip *nand;
	struct mtd_info *mtd;
	int ret;
#ifdef CONFIG_CAVIUM_OCTEON_SOC
	char *name;
	static int chip_num;
#endif

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
	nand->onfi_set_features = cvm_nand_set_features;
	nand->read_byte = cvm_nand_read_byte;
	nand->read_buf = cvm_nand_read_buf;
	nand->write_buf = cvm_nand_write_buf;

	mtd = nand_to_mtd(nand);
	mtd->dev.parent = dev;

	/* TODO: support more then 1 chip */
	ret = nand_scan_ident(mtd, 1, NULL);
	if (ret)
		return ret;

	ret = cvm_nfc_chip_init_timings(chip, np);
	if (ret) {
		dev_err(dev, "could not configure chip timings: %d\n", ret);
		return ret;
	}

#ifdef CONFIG_CAVIUM_OCTEON_SOC
	/* We need to override the name, as the default names
	 * have spaces in them, and this prevents the passing
	 * of partitioning information on the kernel command line.
	 */
	name = devm_kzalloc(dev, MAX_NAND_NAME_LEN, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	snprintf(name, MAX_NAND_NAME_LEN, "octeon_nand%d", chip_num);
	mtd->name = name;

	nand->ecc.mode = NAND_ECC_SOFT;
	nand->ecc.algo = NAND_ECC_HAMMING;
#endif

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
#ifdef CONFIG_CAVIUM_OCTEON_SOC
	chip_num++;
#endif

	list_add_tail(&chip->node, &tn->chips);
	return 0;
}

static int cvm_nfc_chips_init(struct cvm_nfc *tn, struct device *dev)
{
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
	ndf_misc = cvm_nfc_readq(tn->base + NDF_MISC);

	ndf_misc &= ~NDF_MISC_EX_DIS;
	ndf_misc |= (NDF_MISC_BT_DIS | NDF_MISC_RST_FF);
	cvm_nfc_writeq(ndf_misc, tn->base + NDF_MISC);

	/* Bring the fifo out of reset */
	ndf_misc &= ~(NDF_MISC_RST_FF);

	/* Maximum of co-processor cycles for glitch filtering */
	ndf_misc |= FIELD_PREP(NDF_MISC_WAIT_CNT, 0x3f);

	cvm_nfc_writeq(ndf_misc, tn->base + NDF_MISC);

	/* Set timing parameters to onfi mode 0 for probing */
	timings = onfi_async_timing_mode_to_sdr_timings(0);
	if (IS_ERR(timings))
		return PTR_ERR(timings);
	rc = set_default_timings(tn, timings);
	if (rc)
		return rc;

	return 0;
}

#ifdef CONFIG_CAVIUM_OCTEON_SOC
static int cvm_nfc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cvm_nfc *tn;
	const __be32 *reg;
	u64 addr;
	int ret;

	tn = devm_kzalloc(dev, sizeof(*tn), GFP_KERNEL);
	if (!tn)
		return -ENOMEM;

	tn->dev = dev;
	spin_lock_init(&tn->controller.lock);
	init_waitqueue_head(&tn->controller.wq);
	INIT_LIST_HEAD(&tn->chips);

	memset(tn->buf.dmabuf, 0xff, tn->buf.dmabuflen);

	platform_set_drvdata(pdev, tn);

	reg = of_get_property(pdev->dev.of_node, "reg", NULL);
	addr = of_translate_address(pdev->dev.of_node, reg);
	tn->base = (void __iomem *)(addr | (1ull << 63));

	tn->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(tn->clk))
		return PTR_ERR(tn->clk);

	ret = clk_prepare_enable(tn->clk);
	if (ret)
		return ret;

	if (dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)))
		dev_err(dev, "64 bit DMA mask not available\n");

	tn->buf.dmabuflen = NAND_MAX_PAGESIZE + NAND_MAX_OOBSIZE;
	tn->buf.dmabuf = dmam_alloc_coherent(dev, tn->buf.dmabuflen,
					     &tn->buf.dmaaddr, GFP_KERNEL);
	if (!tn->buf.dmabuf) {
		ret = -ENOMEM;
		goto error;
	}

	tn->stat = dmam_alloc_coherent(dev, 8, &tn->stat_addr, GFP_KERNEL);
	if (!tn->stat) {
		ret = -ENOMEM;
		goto error;
	}

	cvm_nfc_init(tn);
	ret = cvm_nfc_chips_init(tn, dev);
	if (ret) {
		dev_err(dev, "failed to init nand chips\n");
		goto error;
	}

	dev_info(&pdev->dev, "probed\n");
	return 0;

error:
	clk_disable_unprepare(tn->clk);
	return ret;
}

static int cvm_nfc_remove(struct platform_device *pdev)
{
	return 0;
}

#else
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

	memset(tn->buf.dmabuf, 0xff, tn->buf.dmabuflen);

	pci_set_drvdata(pdev, tn);
	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;
	ret = pci_request_regions(pdev, KBUILD_MODNAME);
	if (ret)
		return ret;
	tn->base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!tn->base)
		return -EINVAL;

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSIX);
	if (ret < 0)
		return ret;
	ret = devm_request_irq(dev, pci_irq_vector(pdev, 0),
			       cvm_nfc_isr, 0, "nand-flash-controller", tn);
	if (ret)
		return ret;

	tn->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(tn->clk))
		return PTR_ERR(tn->clk);

	ret = clk_prepare_enable(tn->clk);
	if (ret)
		return ret;

	if (dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)))
		dev_err(dev, "64 bit DMA mask not available\n");

	tn->buf.dmabuflen = NAND_MAX_PAGESIZE + NAND_MAX_OOBSIZE;
	tn->buf.dmabuf = dmam_alloc_coherent(dev, tn->buf.dmabuflen,
					     &tn->buf.dmaaddr, GFP_KERNEL);
	if (!tn->buf.dmabuf) {
		ret = -ENOMEM;
		goto error;
	}

	tn->stat = dmam_alloc_coherent(dev, 8, &tn->stat_addr, GFP_KERNEL);
	if (!tn->stat) {
		ret = -ENOMEM;
		goto error;
	}

	cvm_nfc_init(tn);
	ret = cvm_nfc_chips_init(tn, dev);
	if (ret) {
		dev_err(dev, "failed to init nand chips\n");
		goto error;
	}
	dev_info(&pdev->dev, "probed\n");
	return 0;

error:
	clk_disable_unprepare(tn->clk);
	return ret;
}

static void cvm_nfc_remove(struct pci_dev *pdev)
{
	struct cvm_nfc *tn = pci_get_drvdata(pdev);
	struct cvm_nand_chip *chip;

	while (!list_empty(&tn->chips)) {
		chip = list_first_entry(&tn->chips, struct cvm_nand_chip,
					node);
		nand_release(&chip->nand.mtd);
		list_del(&chip->node);
	}
	clk_disable_unprepare(tn->clk);
}
#endif

#ifdef CONFIG_CAVIUM_OCTEON_SOC
static struct of_device_id cvm_nfc_match[] = {
	{
		.compatible = "cavium,octeon-5230-nand",
	},
	{},
};
MODULE_DEVICE_TABLE(of, cvm_nfc_match);

static struct platform_driver cvm_nfc_driver = {
	.probe		= cvm_nfc_probe,
	.remove		= cvm_nfc_remove,
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= KBUILD_MODNAME,
		.of_match_table = cvm_nfc_match,
	},
};

static int __init cvm_nfc_mod_init(void)
{
	return platform_driver_register(&cvm_nfc_driver);
}
module_init(cvm_nfc_mod_init);

static void __exit cvm_nfc_mod_exit(void)
{
	platform_driver_unregister(&cvm_nfc_driver);
}
module_exit(cvm_nfc_mod_exit);
#else
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
};

module_pci_driver(cvm_nfc_pci_driver);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jan Glauber <jglauber@cavium.com>");
MODULE_DESCRIPTION("Cavium Inc. cvm NAND driver");
