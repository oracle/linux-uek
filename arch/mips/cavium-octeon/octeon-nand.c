/**
 * Driver for the Octeon NAND flash controller introduced in CN52XX pass 2.
 *
 * LICENSE:
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 - 2012 Cavium, Inc.
 */

#include <asm/octeon/cvmx.h>
#include <asm/octeon/cvmx-nand.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-bch.h>
#include <asm/octeon/cvmx-bch-defs.h>
#include <linux/ctype.h>

#include <linux/module.h>
#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/platform_device.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/rawnand.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/mtd/nand_bch.h>
#include <linux/mtd/partitions.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/mm.h>


#define DRIVER_NAME "octeon-nand"

#define DEBUG_INIT		(1<<0)
#define DEBUG_READ		(1<<1)
#define DEBUG_READ_BUFFER	(1<<2)
#define DEBUG_WRITE		(1<<3)
#define DEBUG_WRITE_BUFFER	(1<<4)
#define DEBUG_CONTROL		(1<<5)
#define DEBUG_SELECT		(1<<6)
#define DEBUG_ALL		-1

#define MAX_NAND_NAME_LEN       20

/**
 * Maximum supported OOB size.  This used to be defined in nand.h.
 * According to my contact at Micron, the current maximum OOB area is 2208
 * bytes and the largest page size is 16K.
 */
#ifndef NAND_MAX_OOBSIZE
# define NAND_MAX_OOBSIZE	2208
#endif

/** Maximum supported page size.  This used to be defined in nand.h */
#ifndef NAND_MAX_PAGESIZE
# define NAND_MAX_PAGESIZE	16384
#endif

static const char * const part_probes[] = { "cmdlinepart", NULL };

#define DEV_DBG(_level, _dev, _format, _arg...)	do {			\
	if (unlikely(debug & (_level)))					\
		dev_info((_dev) , "%s " _format , __func__, ## _arg);	\
	} while (0)

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug bit field. -1 will turn on all debugging.");


struct octeon_nand {
	struct nand_chip nand;
	uint8_t status;
	uint8_t use_status;
	uint8_t read_status_repeat;
	int data_len;		/* Number of byte in the data buffer */
	int data_index;		/* Current read index. Equal to data_len when
					all data has been read */
	int selected_chip;	/* Currently selected NAND chip */
	int selected_page;	/* Last page chosen by SEQIN for PROGRAM */
	struct device *dev;	/* Pointer to the device */
	struct nand_ecclayout *ecclayout;
	unsigned char *eccmask;
	/* Temporary location to store read data, must be 64 bit aligned */
	uint8_t data[NAND_MAX_PAGESIZE + NAND_MAX_OOBSIZE];
};

enum nand_extended_section_type {
	NAND_EXTENDED_UNUSED = 0,
	NAND_EXTENDED_SECTION_TYPE = 1,
	NAND_EXTENDED_ECC = 2,
};

struct nand_extended_section_info {
	uint8_t type;
	uint8_t length;
};

struct nand_extended_ecc_info {
	uint8_t ecc_bits;       /** Number of bits ECC correctability */
	uint8_t ecc_size;       /** 1 << ecc_size */
	uint16_t max_lun_bad_blocks;    /** Max bad blocks per LUN */
	uint16_t block_endurance;
	uint16_t reserved;
};

struct nand_extended_param_page_hdr {
	uint16_t crc;
	char sig[4];    /* Should be 'EPPS' */
	uint8_t reserved0[10];
	struct nand_extended_section_info section_types[8];
};


static struct octeon_nand *octeon_nand_open_mtd[8];

static int octeon_nand_bch_correct(struct mtd_info *mtd, u_char *dat,
				   u_char *read_ecc, u_char *isnull);


/*
 * Read a single byte from the temporary buffer. Used after READID
 * to get the NAND information.
 */
static uint8_t octeon_nand_read_byte(struct mtd_info *mtd)
{
	struct octeon_nand *priv = mtd->priv;

	if (priv->use_status) {
		DEV_DBG(DEBUG_READ, priv->dev,
			"returning status: 0x%x\n", priv->status);
		if (priv->read_status_repeat)
			priv->status = cvmx_nand_get_status(priv->status);
		else
			priv->read_status_repeat = 1;
		return priv->status;
	}
	if (priv->data_index < priv->data_len) {
		DEV_DBG(DEBUG_READ, priv->dev, "read of 0x%02x\n",
			0xff & priv->data[priv->data_index]);
		return priv->data[priv->data_index++];
	} else {
		dev_err(priv->dev, "No data to read\n");
		return 0xff;
	}
}

/*
 * Read two bytes from the temporary buffer. Used after READID to
 * get the NAND information on 16 bit devices.
 *
 */
static uint16_t octeon_nand_read_word(struct mtd_info *mtd)
{
	struct octeon_nand *priv = mtd->priv;

	if (priv->use_status)
		return priv->status | (priv->status << 8);

	if (priv->data_index + 1 < priv->data_len) {
		uint16_t result = le16_to_cpup((uint16_t *)(priv->data +
			priv->data_index));
		priv->data_index += 2;
		DEV_DBG(DEBUG_READ, priv->dev, "read of 0x%04x\n",
			0xffff & result);
		return result;
	} else {
		dev_err(priv->dev, "No data to read\n");
		return 0xff;
	}
	return 0;
}

/*
 * Since we have a write page, I don't think this can ever be
 * called.
 */
static void octeon_nand_write_buf(struct mtd_info *mtd, const uint8_t *buf,
				int len)
{
	struct octeon_nand *priv = mtd->priv;

	DEV_DBG(DEBUG_WRITE_BUFFER, priv->dev, "len=%d\n", len);
	if (len <= (sizeof(priv->data) - priv->data_len)) {
		memcpy(priv->data + priv->data_len, buf, len);
		priv->data_len += len;
		memset(priv->data + priv->data_len, 0xff,
			sizeof(priv->data) - priv->data_len);
	} else {
		dev_err(priv->dev, "Not enough data to write %d bytes\n", len);
	}
}

/*
 * Read a number of pending bytes from the temporary buffer. Used
 * to get page and OOB data.
 */
static void octeon_nand_read_buf(struct mtd_info *mtd, uint8_t *buf, int len)
{
	struct octeon_nand *priv = mtd->priv;

	DEV_DBG(DEBUG_READ_BUFFER, priv->dev, "len=%d\n", len);

	if (len <= priv->data_len - priv->data_index) {
		memcpy(buf, priv->data + priv->data_index, len);
		priv->data_index += len;
	} else {
		dev_err(priv->dev,
			"Not enough data for read of %d bytes\n", len);
		priv->data_len = 0;
	}
}

#ifdef	__DEPRECATED_API
/*
 * Verify the supplied buffer matches the data we last read
 */
static int octeon_nand_verify_buf(struct mtd_info *mtd, const uint8_t *buf,
				int len)
{
	struct octeon_nand *priv = mtd->priv;

	if (memcmp(buf, priv->data, len)) {
		dev_err(priv->dev, "Write verify failed\n");
		return -EFAULT;
	} else
		return 0;
}
#endif

/**
 * Changes the timing settings
 *
 * @param	mtd	MTD controller interface
 * @param[in]	conf	Timing configuration
 * @param	chipnr	If chipnr is set to %NAND_DATA_IFACE_CHECK_ONLY this
 *			  means the configuration should not be applied but
 *			  only checked.
 *
 * @return	0 for success
 */
static int octeon_nand_setup_data_interface(struct mtd_info *mtd,
						int chipnr,
					    const struct nand_data_interface *conf)
{
	const struct nand_sdr_timings *sdr;
	struct octeon_nand *priv = mtd->priv;
	int twp, twh, twc, tclh, tals;

	if (conf->type != NAND_SDR_IFACE)
		return -EINVAL;

	if (chipnr == NAND_DATA_IFACE_CHECK_ONLY)
		return 0;

	sdr = &conf->timings.sdr;

	twp = DIV_ROUND_UP(sdr->tWP_min, 1000);
	twh = DIV_ROUND_UP(sdr->tWH_min, 1000);
	twc = DIV_ROUND_UP(sdr->tWC_min, 1000);
	tclh = DIV_ROUND_UP(sdr->tCLH_min, 1000);
	tals = DIV_ROUND_UP(sdr->tALS_min, 1000);
	cvmx_nand_set_onfi_timing(priv->selected_chip,
				  twp, twh, twc, tclh, tals);
	return 0;
}

static int octeon_nand_hw_bch_read_page(struct mtd_info *mtd,
					struct nand_chip *chip, uint8_t *buf,
					int oob_required, int page)
{
	struct octeon_nand *priv = mtd->priv;
	int i, eccsize = chip->ecc.size, ret;
	int eccbytes = chip->ecc.bytes;
	int eccsteps = chip->ecc.steps;
	uint8_t *p;
	uint8_t *ecc_code = chip->buffers->ecccode;
	unsigned int max_bitflips = 0;

	DEV_DBG(DEBUG_READ, priv->dev, "%s(%p, %p, %p, %d, %d)\n", __func__,
		mtd, chip, buf, oob_required, page);

	/* chip->read_buf() insists on sequential order, we do OOB first */
	memcpy(chip->oob_poi, priv->data + mtd->writesize, mtd->oobsize);

	/* Use private->data buffer as input for ECC correction */
	p = priv->data;

	ret = mtd_ooblayout_get_eccbytes(mtd, ecc_code, chip->oob_poi, 0,
					 chip->ecc.total);
	if (ret)
		return ret;

	for (i = 0; eccsteps; eccsteps--, i += eccbytes, p += eccsize) {
		int stat;

		DEV_DBG(DEBUG_READ, priv->dev,
			"Correcting block offset %ld, ecc offset %d\n",
			p - buf, i);
		stat = chip->ecc.correct(mtd, p, &ecc_code[i], NULL);

		if (stat < 0) {
			mtd->ecc_stats.failed++;
			DEV_DBG(DEBUG_ALL, priv->dev,
				"Cannot correct NAND page %d\n", page);
		} else {
			mtd->ecc_stats.corrected += stat;
			max_bitflips = max_t(unsigned int, max_bitflips, stat);
		}
	}

	/* Copy corrected data to caller's buffer now */
	memcpy(buf, priv->data, mtd->writesize);

	return max_bitflips;
}

static int octeon_nand_hw_bch_write_page(struct mtd_info *mtd,
					 struct nand_chip *chip,
					 const uint8_t *buf, int oob_required,
					 int page)
{
	struct octeon_nand *priv = mtd->priv;
	int i, eccsize = chip->ecc.size, ret;
	int eccbytes = chip->ecc.bytes;
	int eccsteps = chip->ecc.steps;
	const uint8_t *p;
	uint8_t *ecc_calc = chip->buffers->ecccalc;

	DEV_DBG(DEBUG_WRITE, priv->dev, "%s(%p, %p, %p, %d)\n", __func__, mtd,
		chip, buf, oob_required);
	for (i = 0; i < chip->ecc.total; i++)
		ecc_calc[i] = 0xFF;

	/* Copy the page data from caller's buffers to private buffer */
	chip->write_buf(mtd, buf, mtd->writesize);
	/* Use private date as source for ECC calculation */
	p = priv->data;

	/* Hardware ECC calculation */
	for (i = 0; eccsteps; eccsteps--, i += eccbytes, p += eccsize) {
		int ret;

		ret = chip->ecc.calculate(mtd, p, &ecc_calc[i]);

		if (ret < 0)
			DEV_DBG(DEBUG_WRITE, priv->dev,
				"calculate(mtd, p, &ecc_calc[i]) returned %d\n",
				ret);

		DEV_DBG(DEBUG_WRITE, priv->dev,
			"block offset %ld, ecc offset %d\n", p - buf, i);
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

/**
 * octeon_nand_read_oob_std - [REPLACEABLE] the most common OOB data read function
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @page: page number to read
 */
static int octeon_nand_read_oob_std(struct mtd_info *mtd,
				    struct nand_chip *chip,
				    int page)

{
	chip->cmdfunc(mtd, NAND_CMD_READOOB, 0, page);
	chip->read_buf(mtd, chip->oob_poi, mtd->oobsize);
	return 0;
}

/*
 * Select which NAND chip we are working on. A chip of -1
 * represents that no chip should be selected.
 */
static void octeon_nand_select_chip(struct mtd_info *mtd, int chip)
{
#if 0
	if (chip >= 0)
		down(&octeon_bootbus_sem);
	else
		up(&octeon_bootbus_sem);
#endif
}

/*
 * Issue a NAND command to the chip. Almost all work is done here.
 */
static void octeon_nand_cmdfunc(struct mtd_info *mtd, unsigned command,
				int column, int page_addr)
{
	struct octeon_nand *priv = mtd->priv;
	struct nand_chip *nand = mtd_to_nand(mtd);
	int status;

	down(&octeon_bootbus_sem);
	priv->use_status = 0;
	priv->read_status_repeat = 0;

	switch (command) {
	case NAND_CMD_READID:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "READID\n");
		priv->data_index = 0;
		/*
		 * Read length must be a multiple of 8, so read a
		 * little more than we require.
		 */
		priv->data_len = cvmx_nand_read_id(priv->selected_chip,
						   (uint64_t)column,
						virt_to_phys(priv->data), 16);
		if (priv->data_len < 16) {
			dev_err(priv->dev, "READID failed with %d\n",
				priv->data_len);
			priv->data_len = 0;
		}
		break;

	case NAND_CMD_READOOB:
		DEV_DBG(DEBUG_READ_BUFFER, priv->dev,
			"READOOB page_addr=0x%x\n", page_addr);
		priv->data_index = 8;
		/*
		 * Read length must be a multiple of 8, so we start
		 * reading 8 bytes from the end of page.
		 */
		priv->data_len = cvmx_nand_page_read(priv->selected_chip,
					((uint64_t)page_addr << nand->page_shift) +
					(1 << nand->page_shift) -
					priv->data_index,
					virt_to_phys(priv->data),
					mtd->oobsize + priv->data_index);
		if (priv->data_len < mtd->oobsize + priv->data_index) {
			dev_err(priv->dev, "READOOB failed with %d\n",
				priv->data_len);
			priv->data_len = 0;
		}
		break;

	case NAND_CMD_READ0:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"READ0 page_addr=0x%x\n", page_addr);
		priv->data_index = 0;
		/* Here mtd->oobsize _must_ already be a multiple of 8 */
		priv->data_len = cvmx_nand_page_read(priv->selected_chip,
					column +
					((uint64_t)page_addr << nand->page_shift),
					virt_to_phys(priv->data),
					(1 << nand->page_shift) +
					mtd->oobsize);
		if (priv->data_len < (1 << nand->page_shift) + mtd->oobsize) {
			dev_err(priv->dev, "READ0 failed with %d\n",
				priv->data_len);
			priv->data_len = 0;
		}
		break;

	case NAND_CMD_ERASE1:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"ERASE1 page_addr=0x%x\n", page_addr);
		if (cvmx_nand_block_erase(priv->selected_chip,
			(uint64_t)page_addr << nand->page_shift)) {
			dev_err(priv->dev, "ERASE1 failed\n");
		}
		break;

	case NAND_CMD_ERASE2:
		/* We do all erase processing in the first command, so ignore
			this one */
		break;

	case NAND_CMD_STATUS:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "STATUS\n");
		priv->status = cvmx_nand_get_status(priv->selected_chip);
		priv->use_status = 1;

		break;

	case NAND_CMD_SEQIN:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"SEQIN column=%d page_addr=0x%x\n", column, page_addr);
		/* If we don't seem to be doing sequential writes then erase
			all data assuming it is old */
		/* FIXME: if (priv->selected_page != page_addr) */
		if (priv->data_index != column)
			memset(priv->data, 0xff, sizeof(priv->data));
		priv->data_index = column;
		priv->data_len = column;
		priv->selected_page = page_addr;
		break;

	case NAND_CMD_PAGEPROG:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "PAGEPROG\n");
		status = cvmx_nand_page_write(priv->selected_chip,
			(uint64_t)priv->selected_page << nand->page_shift,
			virt_to_phys(priv->data));
		if (status)
			dev_err(priv->dev, "PAGEPROG failed with %d\n",	status);
		break;

	case NAND_CMD_RESET:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "RESET\n");
		priv->data_index = 0;
		priv->data_len = 0;
		memset(priv->data, 0xff, sizeof(priv->data));
		status = cvmx_nand_reset(priv->selected_chip);
		if (status)
			dev_err(priv->dev, "RESET failed with %d\n", status);
		break;

	case NAND_CMD_RNDOUT:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "RNDOUT\n");
		priv->data_index = column;
		break;

	case NAND_CMD_PARAM:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "PARAM\n");
		priv->data_len = cvmx_nand_read_param_page(priv->selected_chip,
					virt_to_phys(priv->data), 2048);
		priv->data_index = column;
		break;

	default:
		dev_err(priv->dev, "Unsupported command 0x%x\n", command);
		break;
	}
	up(&octeon_bootbus_sem);
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
static int octeon_nand_bch_calculate_ecc_internal(struct octeon_nand *priv,
						  const uint8_t *buf,
						  uint8_t *code)
{
	struct nand_chip *nand_chip = &priv->nand;
	static cvmx_bch_response_t response;
	int rc;
	int i;
	static uint8_t *ecc_buffer;

	if (!ecc_buffer)
		ecc_buffer = kmalloc(1024, GFP_KERNEL);
	if ((ulong)buf % 8)
		dev_err(priv->dev, "ECC buffer not aligned!");

	memset(ecc_buffer, 0, nand_chip->ecc.bytes);

	response.u16 = 0;
	barrier();

	rc = cvmx_bch_encode((void *)buf, nand_chip->ecc.size,
			     nand_chip->ecc.strength,
			     (void *)ecc_buffer, &response);

	if (rc) {
		dev_err(priv->dev, "octeon_bch_encode failed\n");
		return -1;
	}

	udelay(10);
	barrier();

	if (!response.s.done) {
		dev_err(priv->dev,
			"octeon_bch_encode timed out, response done: %d, "
			 "uncorrectable: %d, num_errors: %d, erased: %d\n",
			response.s.done, response.s.uncorrectable,
			response.s.num_errors, response.s.erased);
		cvmx_bch_shutdown();
		cvmx_bch_initialize();
		return -1;
	}

	memcpy(code, ecc_buffer, nand_chip->ecc.bytes);

	for (i = 0; i < nand_chip->ecc.bytes; i++)
		code[i] ^= priv->eccmask[i];

	return 0;
}

static void octeon_panic_nand_wait(struct mtd_info *mtd, struct nand_chip *chip,
				   unsigned long timeo)
{
	struct octeon_nand *priv = mtd->priv;
	int i;

	for (i = 0; i < timeo; i++) {
		if (chip->dev_ready) {
			if (chip->dev_ready(mtd))
				break;
		} else {
			if (cvmx_nand_get_status(priv->selected_chip) &
			    NAND_STATUS_READY)
				break;
		}
		mdelay(1);
	}
}

static int octeon_nand_wait(struct mtd_info *mtd, struct nand_chip *chip)
{
	struct octeon_nand *priv = mtd->priv;
	unsigned long timeo = 400;
	int status;

	ndelay(100);

	if (in_interrupt() || oops_in_progress) {
		octeon_panic_nand_wait(mtd, mtd_to_nand(mtd), timeo);
	} else {
		timeo = jiffies + msecs_to_jiffies(timeo);
		do {
			if (chip->dev_ready) {
				if (chip->dev_ready(mtd))
					break;
			} else {
				if (cvmx_nand_get_status(priv->selected_chip) &
				    NAND_STATUS_READY)
					break;
			}
			cond_resched();
		} while (time_before(jiffies, timeo));
	}

	status = cvmx_nand_get_status(priv->selected_chip);
	WARN_ON(!(status & NAND_STATUS_READY));
	return status;
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
	int ret;
	struct octeon_nand *priv = mtd->priv;

	ret = octeon_nand_bch_calculate_ecc_internal(
					priv, (void *)dat, (void *)ecc_code);

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
	struct octeon_nand *priv = mtd->priv;
	struct nand_chip *nand_chip = mtd_to_nand(mtd);
	static cvmx_bch_response_t response;
	int rc;
	int i = nand_chip->ecc.size + nand_chip->ecc.bytes;
	static uint8_t *data_buffer;
	static int buffer_size;
	int max_time = 100;

	if (i > buffer_size) {
		kfree(data_buffer);
		data_buffer = kmalloc(i, GFP_KERNEL);
		if (!data_buffer) {
			dev_err(priv->dev,
				"%s: Could not allocate %d bytes for buffer\n",
				__func__, i);
			goto error;
		}
	}

	memcpy(data_buffer, dat, nand_chip->ecc.size);
	memcpy(data_buffer + nand_chip->ecc.size, read_ecc,
							nand_chip->ecc.bytes);

	for (i = 0; i < nand_chip->ecc.bytes; i++)
		data_buffer[nand_chip->ecc.size + i] ^= priv->eccmask[i];

	response.u16 = 0;
	barrier();

	rc = cvmx_bch_decode(data_buffer, nand_chip->ecc.size,
			     nand_chip->ecc.strength, dat, &response);

	if (rc) {
		dev_err(priv->dev, "cvmx_bch_decode failed\n");
		goto error;
	}

	/* Wait for BCH engine to finsish */
	while (!response.s.done && max_time--) {
		udelay(1);
		barrier();
	}

	if (!response.s.done) {
		dev_err(priv->dev, "Error: BCH engine timeout\n");
		cvmx_bch_shutdown();
		cvmx_bch_initialize();
		goto error;
	}

	if (response.s.erased) {
		DEV_DBG(DEBUG_ALL, priv->dev, "Info: BCH block is erased\n");
		return 0;
	}

	if (response.s.uncorrectable) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"Cannot correct NAND block, response: 0x%x\n",
			response.u16);
		goto error;
	}

	return response.s.num_errors;

error:
	DEV_DBG(DEBUG_ALL, priv->dev, "Error performing bch correction\n");
	return -1;
}

void octeon_nand_bch_hwctl(struct mtd_info *mtd, int mode)
{
	/* Do nothing. */
}

/**
 * Calculates the ONFI CRC16 needed for the extended parameter page
 *
 * @param crc	starting CRC value
 * @param p	pointer to data to calculate CRC over
 * @param len	length in bytes
 *
 * @return crc result
 */
static uint16_t octeon_onfi_crc16(uint16_t crc, uint8_t const *p, size_t len)
{
	int i;
	while (len--) {
		crc ^= *p++ << 8;
		for (i = 0; i < 8; i++)
			crc = (crc << 1) ^ ((crc & 0x8000) ? 0x8005 : 0);
	}

	return crc;
}

/**
 * Given an extended parameter page, calculate the size of the data structure.
 * The size is variable and is made up based on whatever data is placed in it.
 *
 * @param hdr	pointer to extended parameter page header
 *
 * @return length of extended parameter block or -1 if error.
 *
 * NOTE: This function does not verify the CRC, only the signature.
 */
static int calc_ext_param_page_size(struct nand_extended_param_page_hdr *hdr)
{
	int i;
	int length = 0;
	int ext_table_offset = 0;
	int ext_table_size = 0;
	struct nand_extended_section_info *ext_table;

	if (hdr->sig[0] != 'E' ||
	    hdr->sig[1] != 'P' ||
	    hdr->sig[2] != 'P' ||
	    hdr->sig[3] != 'S')
		return -1;

	for (i = 0; i < 8; i++) {
		if (hdr->section_types[i].type == NAND_EXTENDED_UNUSED)
			goto done;
		if (hdr->section_types[i].length > 0)
			length += 16 * hdr->section_types[i].length;
		if (hdr->section_types[i].type == NAND_EXTENDED_SECTION_TYPE) {
			ext_table_offset = length + sizeof(*hdr);
			ext_table_size = 8 * hdr->section_types[i].length;
		}
	}
	if (ext_table_offset != 0) {
		ext_table = (struct nand_extended_section_info *)
			((uint8_t *)hdr + ext_table_offset);
		for (i = 0; i < ext_table_size; i++) {
			if (ext_table[i].type == NAND_EXTENDED_UNUSED)
				goto done;
			length += ext_table[i].length;
		}
	}
done:
	return length + sizeof(struct nand_extended_param_page_hdr);
}

/**
 * Given a pointer to a NAND extended parameter page, return a pointer to the
 * next extended parameter page even if the current block is corrupt.
 */
struct nand_extended_param_page_hdr *
calc_next_ext_page(struct nand_extended_param_page_hdr *hdr, int *offset)
{
	uint8_t *ptr = (uint8_t *)(hdr + 1);
	*offset += sizeof(*hdr);
	while (*offset < 1024 - sizeof(*hdr)) {
		hdr = (struct nand_extended_param_page_hdr *)ptr;
		if (hdr->sig[0] == 'E' &&
		    hdr->sig[1] == 'P' &&
		    hdr->sig[2] == 'P' &&
		    hdr->sig[3] == 'S')
			return hdr;
		*offset += 8;
		ptr += 8;
	}
	return NULL;
}

/**
 * Reads the extended parameter page looking for ECC data
 *
 * @param chip - NAND chip data structure
 *
 * @returns 0 for success, -1 if invalid or unavailable extended parameter page
 */
static int octeon_read_extended_parameters(struct octeon_nand *priv)
{
	struct nand_extended_param_page_hdr *hdr;
	struct nand_extended_ecc_info *ecc_info;
	int size;
	int i;
	int offset;

	down(&octeon_bootbus_sem);
	if (cvmx_nand_read_param_page(priv->selected_chip,
			      cvmx_ptr_to_phys(priv->data), 1024) != 1024) {
		dev_err(priv->dev,
			"Could not read extended parameters from NAND chip %d\n",
			priv->selected_chip);
		up(&octeon_bootbus_sem);
		return -1;
	}
	up(&octeon_bootbus_sem);

	offset = 768;
	hdr = (struct nand_extended_param_page_hdr *)&priv->data[offset];

	/* Look for a valid header */
	do {
		size = calc_ext_param_page_size(hdr);
		if (size < 0)
			return -1;
		if (size < sizeof(*hdr))
			continue;

		if (octeon_onfi_crc16(ONFI_CRC_BASE,
			(uint8_t *)hdr->sig, size - 2) == le16_to_cpu(hdr->crc))
			break;
		hdr = calc_next_ext_page(hdr, &offset);
	} while (hdr);

	DEV_DBG(DEBUG_ALL, priv->dev,
		"Found valid extended parameter page at offset %d\n", offset);

	/* Since the types are always in order then section type 2 for
	 * extended ECC information must be within the first two entries.
	 */
	offset = 0;
	for (i = 0; i < 2; i++) {
		if (hdr->section_types[i].type == NAND_EXTENDED_ECC)
			break;
		if (hdr->section_types[i].type == NAND_EXTENDED_UNUSED) {
			dev_err(priv->dev,
				"%s: No ECC section found\n", __func__);
			return 0;
		}

		offset += hdr->section_types[i].length * 16;
	}

	ecc_info = (struct nand_extended_ecc_info *)
					(((uint8_t *)(hdr + 1)) + offset);
	DEV_DBG(DEBUG_INIT, priv->dev, "Num bits ECC correctability: %u\n",
		ecc_info->ecc_bits);
	DEV_DBG(DEBUG_INIT, priv->dev, "Codeword size: %u (%u)\n",
		ecc_info->ecc_size, 1 << ecc_info->ecc_size);
	DEV_DBG(DEBUG_INIT, priv->dev, "Maximum bad blocks per LUN: %u\n",
		le16_to_cpu(ecc_info->max_lun_bad_blocks));
	DEV_DBG(DEBUG_INIT, priv->dev, "Block endurance: %u * 10^%u\n",
		le16_to_cpu(ecc_info->block_endurance) & 0xff,
		le16_to_cpu(ecc_info->block_endurance) >> 8);

	DEV_DBG(DEBUG_ALL, priv->dev,
		"Found extended ecc header at offset %d in header\n", offset);
	priv->nand.ecc.strength = ecc_info->ecc_bits;
	priv->nand.ecc.size = 1 << ecc_info->ecc_size;
	if (priv->nand.ecc.strength < 0 || priv->nand.ecc.size > 2048) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"NAND ecc size of %d or strength %d not supported\n",
			ecc_info->ecc_bits, priv->nand.ecc.size);
		return -1;
	}
	DEV_DBG(DEBUG_ALL, priv->dev, "%s: ecc strength: %d, ecc size: %d\n",
		__func__, priv->nand.ecc.strength, priv->nand.ecc.size);

	return 0;
}

static int octeon_nand_calc_bch_ecc_strength(struct octeon_nand *priv)
{
	struct nand_chip *chip = &priv->nand;

	/*
	 * nand.ecc.strength will be used as ecc_level so
	 * it should be in {4, 8, 16, 24, 32, 40, 48, 56, 60, 64}
	 * needed ecc_bytes for m=15 (hardcoded in NAND controller)
	 */
	const int ecc_lvls[]  = {4, 8, 16, 24, 32, 40, 48, 56, 60, 64};
	/* for our NAND (4k page, 24bits/1024bytes corrected) and
	 * NAND controller (hardcoded with m=15) ecc_totalbytes
	 * per above ecc_lvls {4,8, 16...64} are
	 */
	const int ecc_bytes[] = {8, 15, 30, 45, 60, 75, 90, 105, 113, 120};
	const int ecc_totalbytes[] = {
			32, 60, 120, 180, 240, 300, 360, 420, 452, 480};
	/* first set the desired ecc_level to match ecc_lvls[] */
	int index = /* 0..9 */
		(chip->ecc.strength >= 64) ? 9/*64*/ :
		(priv->nand.ecc.strength > 56 &&
		 priv->nand.ecc.strength <= 60) ? 8/*60*/ :
		(priv->nand.ecc.strength > 48 &&
		 priv->nand.ecc.strength <= 56) ? 7/*56*/ :
		(priv->nand.ecc.strength > 40 &&
		 priv->nand.ecc.strength <= 48) ? 6/*48*/ :
		(priv->nand.ecc.strength > 32 &&
		 priv->nand.ecc.strength <= 40) ? 5/*40*/ :
		(priv->nand.ecc.strength > 48 &&
		 priv->nand.ecc.strength <= 32) ? 4/*32*/ :
		(priv->nand.ecc.strength > 16 &&
		 priv->nand.ecc.strength <= 24) ? 3/*24*/ :
		(priv->nand.ecc.strength >  8 &&
		 priv->nand.ecc.strength <= 16) ? 2/*16*/ :
		(priv->nand.ecc.strength >  4 &&
		 priv->nand.ecc.strength <=  8) ? 1/*8*/ :
		(priv->nand.ecc.strength >  1 &&
		 priv->nand.ecc.strength <=  4) ? 0/*4*/: 0;
	/*
	 * ..then check if there is enough space in OOB to store
	 * ECC bytes and eventualy (if not) change ecc.strenght
	 * the the best possible value
	 */
	if (ecc_totalbytes[index] <=
	    cvmx_nand_get_oob_size(priv->selected_chip) - 2) {
		priv->nand.ecc.strength = ecc_lvls[index];
		priv->nand.ecc.bytes = ecc_bytes[index];
	} else {
		int i = 9;
		while (ecc_totalbytes[i] >
		       cvmx_nand_get_oob_size(priv->selected_chip))
			i--;
		priv->nand.ecc.strength = ecc_lvls[i];
		priv->nand.ecc.bytes = ecc_bytes[i];
	}

	return 0;
}

static int octeon_nand_scan_onfi(struct octeon_nand *priv)
{
	cvmx_nand_onfi_param_page_t *onfi_params;
	static const uint8_t revision_decode[17] = {
		0, 0, 10, 20, 21, 22, 23, 30, 31, 32, 40, 41, 0, 0, 0, 0, 0 };
	struct nand_chip *chip = &priv->nand;
	struct nand_ecc_ctrl *ecc = &chip->ecc;

	down(&octeon_bootbus_sem);
	if (cvmx_nand_read_id(priv->selected_chip, 0x20,
			      cvmx_ptr_to_phys(priv->data), 8) < 8) {
		dev_err(priv->dev, "ONFI detection failed for chip %d\n",
				priv->selected_chip);
		up(&octeon_bootbus_sem);
		return -1;
	}

	if (priv->data[0] != 'O' ||
	    priv->data[1] != 'N' ||
	    priv->data[2] != 'F' ||
	    priv->data[3] != 'I') {
		dev_err(priv->dev, "ONFI not supported for chip %d\n",
			priv->selected_chip);
		dev_err(priv->dev, "Parameter header: %02x %02x %02x %02x\n",
			priv->data[0], priv->data[1], priv->data[2],
			priv->data[3]);
		goto out;
	}
	if (cvmx_nand_read_param_page(priv->selected_chip,
				      cvmx_ptr_to_phys(priv->data),
				      256 * 3) < 256 * 3) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"%s: Error reading ONFI parameter data for chip %d\n",
		       __func__, priv->selected_chip);
		goto out;
	}

	onfi_params =
		cvmx_nand_onfi_process(
			(cvmx_nand_onfi_param_page_t *)priv->data);
	if (!onfi_params) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"%s: Invalid ONFI parameter data for chip %d\n",
			__func__, priv->selected_chip);
		goto out;
	}

	up(&octeon_bootbus_sem);

	memcpy(&chip->onfi_params, onfi_params, sizeof(struct nand_onfi_params));

	chip->onfi_version =
		revision_decode[fls(le16_to_cpu(chip->onfi_params.revision))];
	DEV_DBG(DEBUG_ALL, priv->dev,
		"ONFI revision %d\n", chip->onfi_version);

	chip->page_shift = fls(le32_to_cpu(chip->onfi_params.byte_per_page)) - 1;
	ecc->strength = chip->onfi_params.ecc_bits;

	if (chip->onfi_params.programs_per_page <= 1)
		chip->options |= NAND_NO_SUBPAGE_WRITE;

	if (chip->onfi_params.ecc_bits == 0) {
		ecc->mode = NAND_ECC_NONE;
		ecc->bytes = 0;
		ecc->strength = 0;
	} else if (chip->onfi_params.ecc_bits == 1) {
		ecc->mode = NAND_ECC_SOFT;
		ecc->algo = NAND_ECC_HAMMING;
		ecc->bytes = 3;
		ecc->size = 256;
		ecc->strength = 1;
		DEV_DBG(DEBUG_ALL, priv->dev,
			"NAND chip %d using single bit ECC\n",
		      priv->selected_chip);
	} else if (octeon_has_feature(OCTEON_FEATURE_BCH)) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"Using hardware ECC syndrome support\n");
		ecc->mode = NAND_ECC_HW_SYNDROME;
		ecc->algo = NAND_ECC_BCH;
		ecc->strength = chip->onfi_params.ecc_bits;
		ecc->read_page = octeon_nand_hw_bch_read_page;
		ecc->write_page = octeon_nand_hw_bch_write_page;
		ecc->read_page_raw = octeon_nand_read_page_raw;
		ecc->write_page_raw = octeon_nand_write_page_raw;
		ecc->read_oob = octeon_nand_read_oob_std;
		ecc->write_oob = octeon_nand_write_oob_std;
		DEV_DBG(DEBUG_INIT, priv->dev, "ECC Bits: %u\n",
			chip->onfi_params.ecc_bits);

		if (chip->onfi_params.ecc_bits == 0xff) {
			/* If 0xff then we need to access the extended parameter
			 * page.
			 */
			if (octeon_read_extended_parameters(priv))
				return -1;
		} else {
			if (!ecc->size)
				ecc->size = 512;
		}

		octeon_nand_calc_bch_ecc_strength(priv);

		/*
		 * strength=24 needs total of ecc.bytes=180 for 4k page
		 * strength=32 needs total of ecc.bytes=240 for 4k page
		 * Our NAND has only 224 bytes OOB so we should use max
		 * ecc.strength=24 ,ecc.bytes=45 and ecc_totalbytes=180
		 */

		/* The number of ECC bits required is m * t
		 * where (2^m) - 1 > bits per ecc block and
		 * t is the number of correctible bits.  So if
		 * a block is 512 bytes and 4 bits of ECC are
		 * to be supported then m = 13 since
		 * (2^13) - 1 > (512 * 8).  This requires a
		 * total of 52 bits.  Rounding up this is 7
		 * bytes.
		 *
		 * OCTEON is hard coded for m=15.
		 * OCTEON requires ((15 * t) + 7) / 8
		 */
		if (!ecc->bytes)
			ecc->bytes = ((15 * ecc->strength) + 7) / 8;

		if (!ecc->steps)
			ecc->steps = (1 << chip->page_shift) / ecc->size;
		ecc->calculate = octeon_nand_bch_calculate;
		ecc->correct = octeon_nand_bch_correct;
		ecc->hwctl = octeon_nand_bch_hwctl;

		DEV_DBG(DEBUG_INIT, priv->dev,
			"NAND chip %d using hw_bch ECC for %d bits of "
			"correction per %d byte block.  ECC size is %d bytes\n",
		      priv->selected_chip,
		      ecc->strength,
		      ecc->size,
		      ecc->bytes);
	} else {
		ecc->mode = NAND_ECC_SOFT;
		ecc->algo = NAND_ECC_BCH;
		ecc->strength = chip->onfi_params.ecc_bits;
		if (chip->onfi_params.ecc_bits == 0xff) {
			/* If 0xff then we need to access the extended parameter
			 * page.
			 */
			if (octeon_read_extended_parameters(priv)) {
				DEV_DBG(DEBUG_INIT, priv->dev,
					"%s: Error reading ONFI extended "
					"parameter data for chip %d\n",
				       __func__, priv->selected_chip);
				return -1;
			}
		} else {
			if (!ecc->size)
				ecc->size = 512;
		}

		/* The number of ECC bits required is m * t
		 * where (2^m) - 1 > bits per ecc block and
		 * t is the number of correctible bits.  So if
		 * a block is 512 bytes and 4 bits of ECC are
		 * to be supported then m = 13 since
		 * (2^13) - 1 > (512 * 8).  This requires a
		 * total of 52 bits.  Rounding up this is 7
		 * bytes.
		 */
		if (!ecc->bytes)
			ecc->bytes = (((fls(ecc->size) - 1 + 3 + 1)
					* ecc->strength) + 7) / 8;
		if (!ecc->steps)
			ecc->steps = (1 << chip->page_shift) / ecc->size;
		DEV_DBG(DEBUG_INIT, priv->dev,
			"NAND chip %d using soft_bch ECC for %d bits of "
			"correction per %d byte block.  ECC size is %d bytes\n",
		      priv->selected_chip,
		      ecc->strength,
		      ecc->size,
		      ecc->bytes);
	}
	return 0;
out:
	up(&octeon_bootbus_sem);
	return -1;
}

/**
 * Calculate the ECC OOC layout
 *
 * @param chip	Chip to calculate layout for
 *
 * @return 0 for success, otherwise failure
 *
 * NOTE: layout is no longer calculated here.
 */
static int octeon_nand_calc_ecc_layout(struct octeon_nand *priv)
{
	struct nand_chip *chip = &priv->nand;
	struct nand_ecc_ctrl *ecc = &chip->ecc;
	struct mtd_info *mtd = nand_to_mtd(chip);
	int oobsize;
	unsigned int eccsize = chip->ecc.size;
	unsigned int eccbytes = chip->ecc.bytes;
	unsigned int eccstrength = chip->ecc.strength;

	if (!mtd->ooblayout && mtd->oobsize >= 64) {
		mtd_set_ooblayout(mtd, &nand_ooblayout_lp_ops);
		if (ecc->options & NAND_ECC_MAXIMIZE) {
			int steps, bytes;

			/* Always prefer 1k blocks over 512 byte ones. */
			ecc->size = 1024;
			steps = mtd->writesize / ecc->size;

			/* Reserve 2 bytes for the BBM */
			bytes = (mtd->oobsize - 2) / steps;
			ecc->strength = bytes * 8 / fls(8 * ecc->size);
			ecc->total = bytes * steps;
		}
	} else if (!mtd->ooblayout && mtd->oobsize < 64) {
		WARN(1, "OOB layout is required when using hardware BCH on small pages.  oob size is %d bytes\n", mtd->oobsize);
	}
	if (!ecc->total)
		ecc->total = ecc->steps * ecc->bytes;

	DEV_DBG(DEBUG_INIT, priv->dev,
		"eccsize: %u, eccbytes: %u, ecc strength: %u, writesize: %u, steps: %d, total: %d, layout ecc count: %d\n",
		eccsize, eccbytes, eccstrength, mtd->writesize, chip->ecc.steps,
		chip->ecc.total,
		mtd_ooblayout_count_eccbytes(mtd));
	if (!eccbytes && eccstrength) {
		eccbytes = DIV_ROUND_UP(eccstrength * fls(8 * eccsize), 8);
		chip->ecc.bytes = eccbytes;
	}

	if (!eccsize || !eccbytes) {
		printk(KERN_WARNING "ecc parameters not supplied\n");
		goto fail;
	}

	if (mtd->oobsize) {
		oobsize = mtd->oobsize;
	} else {
		down(&octeon_bootbus_sem);
		oobsize = cvmx_nand_get_oob_size(priv->selected_chip);
		up(&octeon_bootbus_sem);
	}

	if (!chip->ecc.steps)
		chip->ecc.steps = mtd->writesize / chip->ecc.size;
	if (!chip->ecc.total)
		chip->ecc.total = chip->ecc.steps * eccbytes;
	if (mtd_ooblayout_count_eccbytes(mtd) != (chip->ecc.steps * eccbytes)) {
		printk(KERN_WARNING "invalid ecc layout\n");
		goto fail;
	}

	/* Reserve 2 bytes for bad block marker */
	if (chip->ecc.bytes + 2 > oobsize) {
		DEV_DBG(DEBUG_INIT, priv->dev,
		"no suitable oob scheme available for oobsize: %d ecc steps: %u, ecc size %u\n",
		oobsize, chip->ecc.steps, chip->ecc.size);
		goto fail;
	}

	return 0;

fail:

	return -1;
}

static int octeon_nand_hw_bch_init(struct octeon_nand *priv)
{
	struct nand_chip *chip = &priv->nand;
	int i, rc;
	unsigned char *erased_page = NULL;
	unsigned int eccsize = chip->ecc.size;
	unsigned int eccbytes = chip->ecc.bytes;
	uint8_t erased_ecc[eccbytes];

	/* Without HW BCH, the ECC callbacks would have not been installed */
	if (chip->ecc.mode != NAND_ECC_HW_SYNDROME)
		return 0;

	priv->eccmask = NULL;

	if (octeon_nand_calc_ecc_layout(priv)) {
		dev_err(priv->dev, "Error calculating ECC layout\n");
		return -1;
	}

	rc = cvmx_bch_initialize();
	if (rc) {
		dev_err(priv->dev, "Error initializing BCH subsystem\n");
		goto fail;
	}

	priv->eccmask = kmalloc(eccbytes, GFP_KERNEL);
	if (!priv->eccmask) {
		dev_err(priv->dev, "eccmask: Out of memory\n");
		goto fail;
	}

	erased_page = kmalloc(eccsize, GFP_KERNEL);
	if (!erased_page) {
		dev_err(priv->dev, "erased_page: Out of memory\n");
		goto fail;
	}

	memset(erased_page, 0xff, eccsize);
	memset(priv->eccmask, 0, eccbytes);
	memset(erased_ecc, 0, eccbytes);

	if (octeon_nand_bch_calculate_ecc_internal(
		priv, erased_page, erased_ecc))
		goto fail;

	kfree(erased_page);

	for (i = 0; i < eccbytes; i++)
		priv->eccmask[i] = erased_ecc[i] ^ 0xff;

	return 0;

fail:
	kfree(priv->eccmask);
	priv->eccmask = NULL;

	kfree(erased_page);

	if (rc)
		cvmx_bch_shutdown();

	return -1;
}

/**
 * Get the size of oobsize, writesize and erasesize
 *
 * @param mtd	MTD data structure pointer
 * @param chip	NAND chip data structure pointer
 * @param id_data	Not used.
 *
 * @return	0 for success.
 */
static int octeon_nand_init_size(struct mtd_info *mtd, struct nand_chip *chip,
				 u8 *id_data)
{
	struct octeon_nand *priv = mtd->priv;

	down(&octeon_bootbus_sem);
	mtd->oobsize = cvmx_nand_get_oob_size(priv->selected_chip);
	mtd->writesize = cvmx_nand_get_page_size(priv->selected_chip);
	mtd->erasesize = cvmx_nand_get_pages_per_block(priv->selected_chip)
							* mtd->writesize;
	up(&octeon_bootbus_sem);
	pr_info("NAND %d OOB size: %d, write size: %d, erase size: %d\n",
		priv->selected_chip, mtd->oobsize, mtd->writesize,
		mtd->erasesize);
	/* OCTEON only supports 8-bit width */
	return 0;
}

/**
 * octeon_nand_onfi_set_features- set features for ONFI nand
 * @mtd: MTD device structure
 * @chip: nand chip info structure
 * @addr: feature address.
 * @subfeature_param: the subfeature parameters, a four bytes array.
 */
static int octeon_nand_onfi_set_features(struct mtd_info *mtd,
					 struct nand_chip *chip,
					 int addr, uint8_t *subfeature_param)
{
	struct octeon_nand *priv = mtd->priv;

	if (!chip->onfi_version ||
	    !(le16_to_cpu(chip->onfi_params.opt_cmd)
	      & ONFI_OPT_CMD_SET_GET_FEATURES))
		return -EINVAL;
	DEV_DBG(DEBUG_CONTROL, priv->dev,
		"set feature addr: 0x%x, param: 0x%02x 0x%02x 0x%02x 0x%02x\n",
		addr, subfeature_param[0], subfeature_param[1],
		subfeature_param[2], subfeature_param[3]);
	if (cvmx_nand_set_feature(priv->selected_chip, addr, subfeature_param))
		return -EIO;
	return 0;
}

/**
 * octeon_nand_onfi_get_features- get features for ONFI nand
 * @mtd: MTD device structure
 * @chip: nand chip info structure
 * @addr: feature address.
 * @subfeature_param: the subfeature parameters, a four bytes array.
 */
static int octeon_nand_onfi_get_features(struct mtd_info *mtd,
					 struct nand_chip *chip,
					 int addr, uint8_t *subfeature_param)
{
	struct octeon_nand *priv = mtd->priv;

	if (!chip->onfi_version ||
	    !(le16_to_cpu(chip->onfi_params.opt_cmd)
	      & ONFI_OPT_CMD_SET_GET_FEATURES))
		return -EINVAL;

	if (cvmx_nand_get_feature(priv->selected_chip, addr, subfeature_param))
		return -EIO;
	DEV_DBG(DEBUG_CONTROL, priv->dev,
		"get feature addr: 0x%x, param: 0x%02x 0x%02x 0x%02x 0x%02x\n",
		addr, subfeature_param[0], subfeature_param[1],
		subfeature_param[2], subfeature_param[3]);
	return 0;
}

/*
 * Determine what NAND devices are available
 */
static int octeon_nand_probe(struct platform_device *pdev)
{
	struct octeon_nand *priv;
	struct nand_chip *nand;
	struct mtd_info *mtd;
	struct device_node *child_node;
	int rv;
	int chip;
	int active_chips = 0;
	char *name;
	int chip_num = 0; /* Count of detected chips, used for device naming */

	DEV_DBG(DEBUG_INIT, &pdev->dev, "called\n");

	for_each_child_of_node(pdev->dev.of_node, child_node) {
		u32 reg;
		rv = of_property_read_u32(child_node, "reg", &reg);
		if (rv)
			continue;
		active_chips |= (1 << reg);
	}
	if (!active_chips)
		return -ENODEV;

	down(&octeon_bootbus_sem);
	cvmx_nand_initialize(CVMX_NAND_INITIALIZE_FLAGS_DEBUG
			       /*CVMX_NAND_INITIALIZE_FLAGS_DONT_PROBE */,
			     active_chips);
	up(&octeon_bootbus_sem);

	for (chip = 0; chip < 8; chip++) {
		/* Skip chip selects that don't have NAND */
		if ((active_chips & (1 << chip)) == 0)
			continue;

		/*
		 * Allocate and initialize mtd_info, nand_chip and private
		 * structures
		 */
		priv = devm_kzalloc(&pdev->dev,
				    sizeof(struct octeon_nand), GFP_KERNEL);
		if (!priv) {
			dev_err(&pdev->dev, "Unable to allocate structures\n");
			return -ENOMEM;
		}
		name = devm_kzalloc(&pdev->dev, MAX_NAND_NAME_LEN, GFP_KERNEL);
		if (!name) {
			dev_err(&pdev->dev, "Unable to allocate structures\n");
			return -ENOMEM;
		}

		nand = &priv->nand;
		mtd = nand_to_mtd(nand);
		mtd->owner = THIS_MODULE;
		mtd->priv = priv;
		memset(priv->data, 0xff, sizeof(priv->data));
		priv->dev = &pdev->dev;
		priv->selected_chip = chip;

		/* We always identify chips as 8 bit, as the Octeon NAND
		 * layer makes both 8 and 16 bit look the same.
		 * We never set the 16 bit buswidth option.
		 */

		nand->read_byte = octeon_nand_read_byte;
		nand->read_word = octeon_nand_read_word;
		nand->write_buf = octeon_nand_write_buf;
		nand->read_buf  = octeon_nand_read_buf;
#ifdef	__DEPRECATED_API
		nand->verify_buf = octeon_nand_verify_buf;
#endif
		nand->select_chip = octeon_nand_select_chip;
		nand->cmdfunc = octeon_nand_cmdfunc;
		nand->setup_data_interface = octeon_nand_setup_data_interface;
		nand->onfi_set_features = octeon_nand_onfi_set_features;
		nand->onfi_get_features = octeon_nand_onfi_get_features;
		nand->waitfunc = octeon_nand_wait;

		octeon_nand_init_size(mtd, nand, NULL);
		down(&octeon_bootbus_sem);
		if (cvmx_nand_get_oob_size(chip) >= 64)
			mtd_set_ooblayout(mtd, &nand_ooblayout_lp_ops);
		else
			mtd_set_ooblayout(mtd, &nand_ooblayout_sp_ops);
		up(&octeon_bootbus_sem);
		DEV_DBG(DEBUG_INIT, priv->dev,
			"Scanning ONFI (generic) for chip %d\n", chip);
		rv = nand_scan_ident(mtd, 1, NULL);
		if (rv != 0) {
			dev_err(&pdev->dev, "NAND scan failed\n");
			return rv;
		}
		DEV_DBG(DEBUG_INIT, priv->dev, "Scanning ONFI for chip %d\n",
			chip);
		rv = octeon_nand_scan_onfi(priv);
		if (rv) {
			dev_err(&pdev->dev, "Failed to scan NAND device\n");
			return -ENXIO;
		}
		rv = octeon_nand_hw_bch_init(priv);
		if (rv) {
			dev_err(&pdev->dev, "Failed to initialize BCH for NAND\n");
			return -ENXIO;
		}

		/* Disable subpage support, as it is not properly supported
		 * in this octeon-nand driver. Subpage support is assumed by
		 * nand_base.c for all large-page NAND flashes that use soft
		 * ECC.
		 */
		nand->options &= ~NAND_SUBPAGE_READ;

		/* We need to override the name, as the default names
		 * have spaces in them, and this prevents the passing
		 * of partitioning information on the kernel command line.
		 */
		snprintf(name, MAX_NAND_NAME_LEN, "octeon_nand%d", chip_num);
		mtd->name = name;
		mtd->dev.parent = &pdev->dev;

		DEV_DBG(DEBUG_INIT, priv->dev, "ONFI Information:\n");
		DEV_DBG(DEBUG_INIT, priv->dev, "Revision: 0x%x\n",
			le16_to_cpu(nand->onfi_params.revision));
		DEV_DBG(DEBUG_INIT, priv->dev, "Features: 0x%x\n",
			le16_to_cpu(nand->onfi_params.revision));
		DEV_DBG(DEBUG_INIT, priv->dev, "opt cmd: 0x%x\n",
			le16_to_cpu(nand->onfi_params.opt_cmd));
		DEV_DBG(DEBUG_INIT, priv->dev, "ext param page len: 0x%x\n",
			le16_to_cpu(nand->onfi_params.ext_param_page_length));
		DEV_DBG(DEBUG_INIT, priv->dev, "num param pages: 0x%x\n",
			nand->onfi_params.num_of_param_pages);
		DEV_DBG(DEBUG_INIT, priv->dev, "Manufacturer: %12s\n",
			nand->onfi_params.manufacturer);
		DEV_DBG(DEBUG_INIT, priv->dev, "Model: %20s\n",
			nand->onfi_params.model);
		DEV_DBG(DEBUG_INIT, priv->dev, "JEDEC ID: 0x%x\n",
			nand->onfi_params.jedec_id);
		DEV_DBG(DEBUG_INIT, priv->dev, "Date code: 0x%x\n",
			le16_to_cpu(nand->onfi_params.date_code));
		DEV_DBG(DEBUG_INIT, priv->dev, "Bytes per page: %u\n",
			le32_to_cpu(nand->onfi_params.byte_per_page));
		DEV_DBG(DEBUG_INIT, priv->dev, "Spare bytes per page: %u\n",
			le16_to_cpu(nand->onfi_params.spare_bytes_per_page));
		DEV_DBG(DEBUG_INIT, priv->dev, "Data bytes per ppage: %u\n",
			le32_to_cpu(nand->onfi_params.data_bytes_per_ppage));
		DEV_DBG(DEBUG_INIT, priv->dev, "Spare bytes per ppage: %u\n",
			le16_to_cpu(nand->onfi_params.spare_bytes_per_ppage));
		DEV_DBG(DEBUG_INIT, priv->dev, "Pages per block: %u\n",
			le32_to_cpu(nand->onfi_params.pages_per_block));
		DEV_DBG(DEBUG_INIT, priv->dev, "Blocks per LUN: %u\n",
			le32_to_cpu(nand->onfi_params.blocks_per_lun));
		DEV_DBG(DEBUG_INIT, priv->dev, "LUN count: %u\n",
			nand->onfi_params.lun_count);
		DEV_DBG(DEBUG_INIT, priv->dev, "Address cycles: %u\n",
			nand->onfi_params.addr_cycles);
		DEV_DBG(DEBUG_INIT, priv->dev, "Bits per cell: %u\n",
			nand->onfi_params.bits_per_cell);
		DEV_DBG(DEBUG_INIT, priv->dev, "BB per LUN: %u\n",
			le16_to_cpu(nand->onfi_params.bb_per_lun));
		DEV_DBG(DEBUG_INIT, priv->dev, "Block Endurance: 0x%x\n",
			le16_to_cpu(nand->onfi_params.block_endurance));
		DEV_DBG(DEBUG_INIT, priv->dev, "Guaranteed block endurance: 0x%x\n",
			le16_to_cpu(nand->onfi_params.guaranteed_block_endurance));
		DEV_DBG(DEBUG_INIT, priv->dev, "Programs per page: %u\n",
			nand->onfi_params.programs_per_page);
		DEV_DBG(DEBUG_INIT, priv->dev, "PPage Attribute: 0x%x\n",
			nand->onfi_params.ppage_attr);
		DEV_DBG(DEBUG_INIT, priv->dev, "ECC Bits: %u\n",
			nand->onfi_params.ecc_bits);
		DEV_DBG(DEBUG_INIT, priv->dev, "Interleaved bits: %u\n",
			nand->onfi_params.interleaved_bits);
		DEV_DBG(DEBUG_INIT, priv->dev, "Interleaved ops: %u\n",
			nand->onfi_params.interleaved_ops);
		DEV_DBG(DEBUG_INIT, priv->dev, "IO Pin Capacitance Max: %upF\n",
			nand->onfi_params.io_pin_capacitance_max);
		DEV_DBG(DEBUG_INIT, priv->dev, "Async timing mode: 0x%x\n",
			le16_to_cpu(nand->onfi_params.async_timing_mode));
		DEV_DBG(DEBUG_INIT, priv->dev, "Program cache timing mode: 0x%x\n",
			le16_to_cpu(nand->onfi_params.program_cache_timing_mode));
		DEV_DBG(DEBUG_INIT, priv->dev, "Max program time: %u usec\n",
			le16_to_cpu(nand->onfi_params.t_prog));
		DEV_DBG(DEBUG_INIT, priv->dev, "Max block erase time: %u usec\n",
			le16_to_cpu(nand->onfi_params.t_bers));
		DEV_DBG(DEBUG_INIT, priv->dev, "Max page read time: %u usec\n",
			le16_to_cpu(nand->onfi_params.t_r));
		DEV_DBG(DEBUG_INIT, priv->dev, "Max change column setup time: %u usec\n",
			le16_to_cpu(nand->onfi_params.t_ccs));
		DEV_DBG(DEBUG_INIT, priv->dev, "NV-DDR timing mode: 0x%x\n",
			le16_to_cpu(nand->onfi_params.src_sync_timing_mode));
		DEV_DBG(DEBUG_INIT, priv->dev, "NV-DDR features: 0x%x\n",
			nand->onfi_params.src_ssync_features);
		DEV_DBG(DEBUG_INIT, priv->dev, "Clock pin input capacitance (typical) %u.%01upF\n",
			le16_to_cpu(nand->onfi_params.clk_pin_capacitance_typ) % 10,
			le16_to_cpu(nand->onfi_params.clk_pin_capacitance_typ) / 10);
		DEV_DBG(DEBUG_INIT, priv->dev, "I/O pin capacitance (typical) %u.%01upF\n",
			le16_to_cpu(nand->onfi_params.io_pin_capacitance_typ) % 10,
			le16_to_cpu(nand->onfi_params.io_pin_capacitance_typ) / 10);
		DEV_DBG(DEBUG_INIT, priv->dev, "Input pin capacitance (typical) %u.%01upF\n",
			le16_to_cpu(nand->onfi_params.input_pin_capacitance_typ) % 10,
			le16_to_cpu(nand->onfi_params.input_pin_capacitance_typ) / 10);
		DEV_DBG(DEBUG_INIT, priv->dev, "Input pin capacitance (max) %upF\n",
			nand->onfi_params.input_pin_capacitance_max);
		DEV_DBG(DEBUG_INIT, priv->dev, "Driver strength support: 0x%x\n",
			nand->onfi_params.driver_strength_support);
		DEV_DBG(DEBUG_INIT, priv->dev, "Maximum multi-plane page read time: %u usec\n",
			le16_to_cpu(nand->onfi_params.t_int_r));
		DEV_DBG(DEBUG_INIT, priv->dev, "Program page register clear enhancement: %u nsec\n",
			le16_to_cpu(nand->onfi_params.t_adl));
		DEV_DBG(DEBUG_INIT, priv->dev, "Vendor revision: 0x%x\n",
			le16_to_cpu(nand->onfi_params.vendor_revision));

		rv = nand_scan_tail(mtd);
		if (rv) {
			dev_err(priv->dev, "nand_scan_tail failed, ret: %d\n",
				rv);
			return rv;
		}


		mtd_device_parse_register(mtd, part_probes, NULL, NULL, 0);
		octeon_nand_open_mtd[chip] = priv;
		chip_num++;
	}
	return 0;
}

/*
 * Called when the driver is unloaded. It must clean up all
 * created devices.
 */
static int octeon_nand_remove(struct platform_device *pdev)
{
	struct octeon_nand *priv;
	int chip;

	DEV_DBG(DEBUG_INIT, &pdev->dev, "called\n");
	for (chip = 0; chip < 8; chip++) {
		priv = octeon_nand_open_mtd[chip];
		if (priv) {
			mtd_device_unregister(nand_to_mtd(&priv->nand));
			octeon_nand_open_mtd[chip] = NULL;
		}
	}
	return 0;
}

static struct of_device_id octeon_nand_match[] = {
	{
		.compatible = "cavium,octeon-5230-nand",
	},
	{},
};

static struct platform_driver octeon_nand_driver = {
	.probe = octeon_nand_probe,
	.remove = octeon_nand_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = DRIVER_NAME,
		.of_match_table = octeon_nand_match,
	},
};

static int __init octeon_nand_driver_init(void)
{
	return platform_driver_register(&octeon_nand_driver);
}
/*
 * We need to call octeon_nand_driver_init late enough that the MTD
 * core is already registered.  If built into the kernel , use a late
 * initcall.
 */
late_initcall(octeon_nand_driver_init);

static void __exit octeon_nand_driver_exit(void)
{
	platform_driver_unregister(&octeon_nand_driver);
}
module_exit(octeon_nand_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Inc. <support@cavium.com>");
MODULE_DESCRIPTION("Cavium Inc. OCTEON NAND driver.");
