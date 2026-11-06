// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Advanced Micro Devices Inc.
 *
 * Salina QSPI panic dump driver.
 *
 * On panic, collects the kernel message buffer and writes it to the
 * coredump_partition on qspi1 via the CQSPI indirect write path.
 * DAC (direct access) mode is unavailable on Salina -- the AHB window
 * is only 4 KB and the coredump partition sits at ~256 MB into the flash
 * device -- so all writes go through the controller's indirect SRAM FIFO,
 * driven entirely by polled register access (no IRQs, no scheduler).
 *
 * The partition must be erased before a dump can be written.  The driver
 * reads back the whole dump area at probe time; unless every byte is 0xff
 * (erased NOR state) the partition holds a previous crash or a partially
 * completed erase and is left untouched.  Userspace is responsible for
 * reading and erasing /dev/mtdN (coredump_partition), then writing 1 to the
 * device's "armed" sysfs attribute to re-check the partition and re-arm the
 * driver for the next panic.
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/kmsg_dump.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/spi-nor.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/panic_notifier.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include "cap_reboot.h"

#define SAL_CRASH_NAME	"pensando-sal-crash"

/* CQSPI APB register offsets */
#define CQSPI_REG_CONFIG		0x00
#define   CQSPI_REG_CONFIG_ENABLE	BIT(0)
#define   CQSPI_REG_CONFIG_DECODE	BIT(9)
#define   CQSPI_REG_CONFIG_CHIPSELECT	GENMASK(13, 10)
#define   CQSPI_REG_CONFIG_BAUD		GENMASK(22, 19)
#define CQSPI_REG_CONFIG_IDLE		BIT(31)
#define CQSPI_REG_RD_INSTR		0x04
#define CQSPI_REG_WR_INSTR		0x08
#define   CQSPI_REG_WR_INSTR_OPCODE	GENMASK(7, 0)
#define   CQSPI_REG_WR_INSTR_TYPE_ADDR	GENMASK(13, 12)
#define   CQSPI_REG_WR_INSTR_TYPE_DATA	GENMASK(17, 16)
#define CQSPI_REG_DELAY			0x0c
#define CQSPI_REG_READCAPTURE		0x10
#define CQSPI_REG_SIZE			0x14
#define   CQSPI_REG_SIZE_ADDRESS	GENMASK(3, 0)
#define   CQSPI_REG_SIZE_PAGE		GENMASK(15, 4)
#define CQSPI_REG_SRAMPARTITION		0x18
#define CQSPI_REG_INDIRECTTRIGGER	0x1c
#define CQSPI_REG_WR_COMPLETION_CTRL	0x38
#define   CQSPI_REG_WR_DISABLE_AUTO_POLL	BIT(14)
#define   CQSPI_REG_WR_POLL_POLARITY	BIT(13)
#define   CQSPI_REG_WR_POLL_BIT_MASK	GENMASK(10, 8)
#define   CQSPI_REG_WR_POLL_OPCODE_MASK	GENMASK(7, 0)
#define CQSPI_REG_IRQSTATUS		0x40
#define CQSPI_REG_IRQMASK		0x44
#define CQSPI_REG_INDIRECTWR		0x70
#define   CQSPI_REG_INDIRECTWR_START	BIT(0)
#define   CQSPI_REG_INDIRECTWR_CANCEL	BIT(1)
#define   CQSPI_REG_INDIRECTWR_DONE	BIT(5)
#define CQSPI_REG_INDIRECTWRWATERMARK	0x74
#define CQSPI_REG_INDIRECTWRSTARTADDR	0x78
#define CQSPI_REG_INDIRECTWRBYTES	0x7c
#define CQSPI_REG_CMDCTRL		0x90
#define   CQSPI_REG_CMDCTRL_EXECUTE	BIT(0)
#define   CQSPI_REG_CMDCTRL_INPROGRESS	BIT(1)
#define   CQSPI_REG_CMDCTRL_RD_BYTES	GENMASK(22, 20)
#define   CQSPI_REG_CMDCTRL_RD_EN	BIT(23)
#define   CQSPI_REG_CMDCTRL_OPCODE	GENMASK(31, 24)
#define CQSPI_REG_CMDREADDATALOWER	0xa0
#define CQSPI_IRQ_STATUS_MASK		0x1ffff
#define CQSPI_POLL_TIMEOUT_US		500000
/* Consecutive IDLE reads required, as in cqspi_wait_idle(). */
#define SAL_IDLE_SAMPLES		3
/* Worst-case wait for an interrupted block erase to finish. */
#define SAL_FLASH_READY_TIMEOUT_US	(3 * USEC_PER_SEC)
#define SAL_FLASH_READY_POLL_US		10
/* Read size used when verifying the partition is erased. */
#define SAL_CHECK_CHUNK			SZ_4K

/* Panic dump header, same layout as cap_crash for compatibility. */
struct panicbuf_header {
	u32 magic;
	u32 len;
};

#define PANIC_SIGNATURE	0x9D7A7318U

struct sal_crash_st {
	struct platform_device	*pdev;
	struct kmsg_dumper	 dump;
	void __iomem		*apb_base;	/* qspi1 APB registers */
	void __iomem		*ahb_base;	/* qspi1 AHB FIFO window */
	struct device_node	*qspi_np;	/* pensando,qspi controller */
	u32			 flash_offset;	/* coredump partition offset */
	u32			 flash_size;	/* coredump partition size */
	u32			 fifo_depth;	/* cdns,fifo-depth */
	u32			 fifo_width;	/* cdns,fifo-width (bytes) */
	u32			 wr_instr;	/* CQSPI_REG_WR_INSTR for page program */
	u32			 addr_nbytes;	/* flash address bytes */
	u32			 page_size;	/* flash program page size */
	u32			 cfg_bits;	/* CONFIG decode/CS/baud fields */
	u32			 delay;		/* CQSPI_REG_DELAY */
	u32			 readcapture;	/* CQSPI_REG_READCAPTURE */
	void			*panic_buf;
	bool			 partition_ready; /* erased, safe to write */
	bool			 qspi_suspended; /* qspi1 may be powered off */
	struct mutex		 arm_lock;	/* serialises "armed" writes */
};

static struct sal_crash_st *sal_crash;

/*
 * APB/AHB hazard flush required on Salina.  A dummy read-back of CONFIG
 * drains any pending writes through the APB-to-AHB bridge before we
 * start the indirect transfer.
 */
static void sal_apb_ahb_flush(void __iomem *apb)
{
	u32 reg = readl(apb + CQSPI_REG_CONFIG);

	writel(reg, apb + CQSPI_REG_CONFIG);
}

/*
 * Panic-path deadlines.  ktime_get_mono_fast_ns() reads the NMI-safe latched
 * timekeeper, so it cannot spin if the panic interrupted a timekeeping
 * update, and measures real elapsed time including MMIO and nested polls.
 */
static u64 sal_deadline(u32 timeout_us)
{
	return ktime_get_mono_fast_ns() + (u64)timeout_us * NSEC_PER_USEC;
}

static bool sal_expired(u64 deadline)
{
	return ktime_get_mono_fast_ns() > deadline;
}

/*
 * Poll for the CQSPI controller to report idle: before reconfiguring it in
 * the panic path, after each indirect write before starting the next, and
 * after each STIG command.  This says nothing about the flash itself; see
 * sal_wait_flash_ready().
 *
 * Like cqspi_wait_idle(), require several consecutive IDLE samples since
 * the bit can transition low again.
 */
static int sal_wait_idle(void __iomem *apb, u64 deadline)
{
	unsigned int idle = 0;

	for (;;) {
		if (readl(apb + CQSPI_REG_CONFIG) & CQSPI_REG_CONFIG_IDLE) {
			if (++idle >= SAL_IDLE_SAMPLES)
				return 0;
			continue;
		}

		idle = 0;
		if (sal_expired(deadline))
			return -ETIMEDOUT;
		udelay(1);
	}
}

/*
 * Re-enable controller auto-polling of the flash status register after
 * each page program.  The qspi driver's cqspi_write_setup() sets
 * CQSPI_REG_WR_DISABLE_AUTO_POLL on every MTD write and leaves status
 * polling to spi-nor, so without this the controller reports DONE/IDLE
 * as soon as the data is shifted out and back-to-back page programs
 * within a chunk would be issued while the NOR is still busy.  The
 * controller splits each chunk into page programs itself, so software
 * polling between pages is not possible.
 *
 * Poll with RDSR until WIP (bit 0) reads back as 0.
 */
static void sal_enable_wr_poll(void __iomem *apb)
{
	u32 reg = readl(apb + CQSPI_REG_WR_COMPLETION_CTRL);

	reg &= ~(CQSPI_REG_WR_DISABLE_AUTO_POLL | CQSPI_REG_WR_POLL_POLARITY |
		 CQSPI_REG_WR_POLL_BIT_MASK | CQSPI_REG_WR_POLL_OPCODE_MASK);
	reg |= FIELD_PREP(CQSPI_REG_WR_POLL_OPCODE_MASK, SPINOR_OP_RDSR);
	writel(reg, apb + CQSPI_REG_WR_COMPLETION_CTRL);
	sal_apb_ahb_flush(apb);
}

#define SAL_CFG_BITS	(CQSPI_REG_CONFIG_DECODE | CQSPI_REG_CONFIG_CHIPSELECT | \
			 CQSPI_REG_CONFIG_BAUD)

/*
 * Restore the chip-select, baud-rate and delay settings captured at probe
 * and make sure the controller is enabled.  cqspi_configure() disables the
 * controller while it switches these, so a panic in the middle can leave it
 * disabled with a partial update.  Same sequence as cqspi_configure():
 * disable, program, re-enable.  Called with the controller idle.
 */
static void sal_restore_config(struct sal_crash_st *sc)
{
	void __iomem *apb = sc->apb_base;
	u32 reg = readl(apb + CQSPI_REG_CONFIG);

	reg &= ~CQSPI_REG_CONFIG_ENABLE;
	writel(reg, apb + CQSPI_REG_CONFIG);

	reg = (reg & ~SAL_CFG_BITS) | sc->cfg_bits;
	writel(reg, apb + CQSPI_REG_CONFIG);
	writel(sc->delay, apb + CQSPI_REG_DELAY);
	writel(sc->readcapture, apb + CQSPI_REG_READCAPTURE);

	writel(reg | CQSPI_REG_CONFIG_ENABLE, apb + CQSPI_REG_CONFIG);
	sal_apb_ahb_flush(apb);
}

/*
 * Program the page-program instruction, address width and page size
 * captured from spi-nor at probe.  The qspi driver only sets the first two
 * in cqspi_write_setup() for MTD data writes, so before the first such
 * write (the probe and re-arm checks only read) they hold whatever U-Boot,
 * Zephyr or the reset value left behind.  It never sets the page size,
 * since spi-nor splits writes at page boundaries itself; the panic path's
 * multi-page transfers rely on the controller doing that split.  A wrong
 * opcode, bus width, address width or page size would lose the dump or
 * program it at the wrong flash address.
 */
static void sal_setup_write_op(struct sal_crash_st *sc)
{
	void __iomem *apb = sc->apb_base;
	u32 reg;

	writel(sc->wr_instr, apb + CQSPI_REG_WR_INSTR);

	reg = readl(apb + CQSPI_REG_SIZE);
	reg &= ~(CQSPI_REG_SIZE_ADDRESS | CQSPI_REG_SIZE_PAGE);
	reg |= FIELD_PREP(CQSPI_REG_SIZE_ADDRESS, sc->addr_nbytes - 1) |
	       FIELD_PREP(CQSPI_REG_SIZE_PAGE, sc->page_size);
	writel(reg, apb + CQSPI_REG_SIZE);
	sal_apb_ahb_flush(apb);
}

/*
 * Write one contiguous chunk to flash via CQSPI indirect mode.
 *
 * @flash_addr: destination byte offset within the flash device
 * @buf:        source buffer (must be 4-byte aligned)
 * @len:        byte count (will be padded to a word boundary with 0xff)
 *
 * Returns 0 on success, -ETIMEDOUT on controller timeout.
 */
static int sal_indirect_write(struct sal_crash_st *sc, u32 flash_addr,
			      const u8 *buf, u32 len)
{
	void __iomem *apb = sc->apb_base;
	void __iomem *ahb = sc->ahb_base;
	u32 reg, words, tail, tail_word;
	const u32 *src = (const u32 *)buf;

	writel(flash_addr, apb + CQSPI_REG_INDIRECTWRSTARTADDR);
	writel(len, apb + CQSPI_REG_INDIRECTWRBYTES);

	/* Clear all pending IRQs. */
	writel(CQSPI_IRQ_STATUS_MASK, apb + CQSPI_REG_IRQSTATUS);
	/* Salina indirect_wr_poll_war: flush #1 after IRQSTATUS clear. */
	sal_apb_ahb_flush(apb);
	/*
	 * Mask all IRQs -- sal_crash is purely polled.  The upstream driver
	 * enables CQSPI_IRQ_MASK_WR here; we mask all instead since we never
	 * wait on a completion and the interrupt belongs to the qspi1 driver.
	 */
	writel(0, apb + CQSPI_REG_IRQMASK);
	/* Salina indirect_wr_poll_war: flush #2 after IRQMASK write. */
	sal_apb_ahb_flush(apb);

	/* Start the indirect write. */
	writel(CQSPI_REG_INDIRECTWR_START, apb + CQSPI_REG_INDIRECTWR);
	/* Flush the posted START write, then a second dummy read for apb_ahb_hazard. */
	readl(apb + CQSPI_REG_INDIRECTWR);
	readl(apb + CQSPI_REG_INDIRECTWR);

	/* Push word-aligned portion into the SRAM FIFO via the AHB window. */
	words = len / 4;
	if (words)
		iowrite32_rep(ahb, src, words);

	/* Handle any trailing bytes padded with 0xff (NOR erased state). */
	tail = len & 3;
	if (tail) {
		tail_word = 0xffffffff;
		memcpy(&tail_word, buf + words * 4, tail);
		iowrite32(tail_word, ahb);
	}

	/* Poll for indirect write completion. */
	if (readl_poll_timeout_atomic(apb + CQSPI_REG_INDIRECTWR, reg,
				      reg & CQSPI_REG_INDIRECTWR_DONE,
				      1, CQSPI_POLL_TIMEOUT_US)) {
		writel(CQSPI_REG_INDIRECTWR_CANCEL, apb + CQSPI_REG_INDIRECTWR);
		return -ETIMEDOUT;
	}

	/* Clear the done bit and wait for the controller to go idle. */
	writel(CQSPI_REG_INDIRECTWR_DONE, apb + CQSPI_REG_INDIRECTWR);
	return sal_wait_idle(apb, sal_deadline(CQSPI_POLL_TIMEOUT_US));
}

/*
 * Read the flash status register with a STIG command, mirroring
 * cqspi_command_read(): Salina's CQSPI_DISABLE_STIG_MODE only steers small
 * addressed reads away from STIG, and the qspi driver issues RDSR for
 * spi-nor this way.  Polled only, and bounded by the caller's @deadline, so
 * safe from the panic path.
 */
static int sal_read_sr(void __iomem *apb, u8 *sr, u64 deadline)
{
	u32 reg = FIELD_PREP(CQSPI_REG_CMDCTRL_OPCODE, SPINOR_OP_RDSR) |
		  CQSPI_REG_CMDCTRL_RD_EN |
		  FIELD_PREP(CQSPI_REG_CMDCTRL_RD_BYTES, 0);	/* 1 byte */
	int ret = 0;

	/* Single-line instruction and data, no dummy cycles. */
	writel(0, apb + CQSPI_REG_RD_INSTR);
	writel(reg, apb + CQSPI_REG_CMDCTRL);
	writel(reg | CQSPI_REG_CMDCTRL_EXECUTE, apb + CQSPI_REG_CMDCTRL);

	while (readl(apb + CQSPI_REG_CMDCTRL) & CQSPI_REG_CMDCTRL_INPROGRESS) {
		if (sal_expired(deadline)) {
			ret = -ETIMEDOUT;
			break;
		}
		udelay(1);
	}
	if (!ret)
		ret = sal_wait_idle(apb, deadline);
	if (!ret)
		*sr = readl(apb + CQSPI_REG_CMDREADDATALOWER) & 0xff;

	writel(0, apb + CQSPI_REG_CMDCTRL);
	return ret;
}

/*
 * Wait for the NOR itself to be ready.  Controller IDLE only covers the
 * controller: if the panic stopped a CPU while spi-nor (or another qspi1
 * user) was polling an erase or program, the flash is still busy and would
 * ignore the WREN and page program for the first dump page.  Poll WIP and
 * let the caller skip the dump if it does not clear.  One deadline covers
 * the status reads and the command and idle polls nested in them, so the
 * total wait is bounded by SAL_FLASH_READY_TIMEOUT_US.
 */
static int sal_wait_flash_ready(struct sal_crash_st *sc)
{
	u64 deadline = sal_deadline(SAL_FLASH_READY_TIMEOUT_US);
	u8 sr;
	int ret;

	for (;;) {
		ret = sal_read_sr(sc->apb_base, &sr, deadline);
		if (ret)
			return ret;
		if (!(sr & SR_WIP))
			return 0;
		if (sal_expired(deadline))
			return -ETIMEDOUT;
		udelay(SAL_FLASH_READY_POLL_US);
	}
}

static void sal_do_dump(struct kmsg_dumper *dumper,
			struct kmsg_dump_detail *detail)
{
	struct sal_crash_st *sc = sal_crash;
	struct panicbuf_header *hdr = sc->panic_buf;
	struct kmsg_dump_iter iter;
	size_t kmsg_len;
	u32 chunk, offset, remaining;
	/* max bytes per indirect transfer: half the FIFO */
	u32 max_chunk = sc->fifo_depth * sc->fifo_width / 2;
	const u8 *src;
	int ret;

	if (!READ_ONCE(sc->partition_ready))
		return;

	if (READ_ONCE(sc->qspi_suspended)) {
		pr_err(SAL_CRASH_NAME ": qspi1 suspended, dump skipped\n");
		return;
	}

	/* Let any in-flight qspi1 operation drain before reconfiguring. */
	if (sal_wait_idle(sc->apb_base, sal_deadline(CQSPI_POLL_TIMEOUT_US))) {
		pr_err(SAL_CRASH_NAME ": controller busy, dump skipped\n");
		return;
	}
	sal_restore_config(sc);
	sal_setup_write_op(sc);
	sal_enable_wr_poll(sc->apb_base);

	if (sal_wait_flash_ready(sc)) {
		pr_err(SAL_CRASH_NAME ": flash not ready, dump skipped\n");
		return;
	}

	/*
	 * syslog=true prepends a 3-byte "<N>" level prefix to every line.
	 * On a fully-wrapped ring buffer this overhead (~4-5 KB) may cause
	 * the oldest messages to be dropped; the panic context is always
	 * kept since kmsg_dump_get_buffer drops from the oldest end first.
	 */
	kmsg_dump_rewind(&iter);
	kmsg_dump_get_buffer(&iter, true,
			     (char *)(hdr + 1),
			     sc->flash_size - sizeof(*hdr),
			     &kmsg_len);

	hdr->magic = PANIC_SIGNATURE;
	hdr->len   = kmsg_len;

	/*
	 * Write header + dump data in max_chunk-sized indirect transfers.
	 * The total payload is sizeof(*hdr) + kmsg_len bytes.
	 */
	src       = (const u8 *)hdr;
	offset    = sc->flash_offset;
	remaining = sizeof(*hdr) + kmsg_len;

	while (remaining) {
		chunk = min(remaining, max_chunk);
		ret = sal_indirect_write(sc, offset, src, chunk);
		if (ret) {
			pr_err(SAL_CRASH_NAME ": write timeout at offset 0x%x\n",
			       offset);
			break;
		}
		src       += chunk;
		offset    += chunk;
		remaining -= chunk;
	}

	if (!remaining)
		pr_emerg(SAL_CRASH_NAME ": wrote %zu bytes at 0x%x\n",
			 sizeof(*hdr) + kmsg_len, sc->flash_offset);
}

static int sal_panic_callback(struct notifier_block *nb,
			      unsigned long reason, void *arg)
{
	struct timespec64 ts;
	struct tm tm;

	/*
	 * Use the NMI-safe latched timekeeper: ktime_get_real_ts64() spins on
	 * the timekeeper seqcount and can hang if the panic interrupted a
	 * timekeeping update, which would also block the dump that follows.
	 */
	ts = ns_to_timespec64(ktime_get_real_fast_ns());
	time64_to_tm(ts.tv_sec, 0, &tm);
	pr_info("Panic at Boot #%lu %04ld-%02d-%02d %02d:%02d:%02d.%06ld\n",
		cap_boot_count(),
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		ts.tv_nsec / 1000);
	return NOTIFY_DONE;
}

static struct notifier_block sal_panic_notifier = {
	.notifier_call = sal_panic_callback,
};

/*
 * Look up coredump_partition and make sure it is on a spi-nor flash behind
 * the pensando,qspi controller the panic path writes through.
 * get_mtd_device_nm() searches every MTD device, so a same-named partition
 * on another flash must not be used to arm the driver or to capture write
 * settings.  Returns the MTD with a reference held, or an ERR_PTR
 * (-ENODEV if no such partition is registered yet).
 */
static struct mtd_info *sal_get_coredump_mtd(struct sal_crash_st *sc)
{
	struct device *dev = &sc->pdev->dev;
	struct mtd_info *mtd;
	struct device *flash;

	mtd = get_mtd_device_nm("coredump_partition");
	if (IS_ERR(mtd))
		return mtd;

	/* spi-nor device -> spi_controller -> qspi platform device */
	flash = mtd_get_master(mtd)->dev.parent;
	if (!flash || !flash->driver || strcmp(flash->driver->name, "spi-nor") ||
	    !flash->parent || !flash->parent->parent ||
	    flash->parent->parent->of_node != sc->qspi_np) {
		dev_err(dev, "coredump_partition is not on a spi-nor flash behind %pOF\n",
			sc->qspi_np);
		put_mtd_device(mtd);
		return ERR_PTR(-EINVAL);
	}

	return mtd;
}

/*
 * Check whether the coredump partition is erased (every byte a dump can
 * occupy reads 0xff) using the MTD layer.  Checking only the start is not
 * enough: an interrupted erase can leave a later erase block holding old
 * data, and programming over it would corrupt the next dump.  This runs in
 * process context only (probe and the "armed" sysfs attribute) and avoids
 * replicating the QSPI read-instruction setup that the qspi driver owns.
 * The direct register path is reserved for the panic write, where MTD
 * cannot be used.  A private buffer is used rather than panic_buf, which a
 * concurrent panic may be filling.
 *
 * Returns:
 *   1  - partition is erased, ready to accept a dump
 *   0  - partition is not fully erased, driver will be disarmed
 *  -EPROBE_DEFER - MTD partition not yet available; caller should defer probe
 *  other negative - partition location/size mismatch or read error
 */
static int sal_partition_check(struct sal_crash_st *sc)
{
	struct device *dev = &sc->pdev->dev;
	struct mtd_info *mtd;
	size_t retlen, len;
	loff_t off;
	u8 *buf;
	int ret;

	mtd = sal_get_coredump_mtd(sc);
	if (IS_ERR(mtd)) {
		/*
		 * -ENODEV means the qspi driver hasn't created the MTD
		 * partitions yet.  Request a probe retry; the driver core
		 * will call us again after more devices have initialised.
		 */
		if (PTR_ERR(mtd) == -ENODEV)
			return -EPROBE_DEFER;
		dev_warn(dev, "coredump_partition MTD error %ld\n", PTR_ERR(mtd));
		return PTR_ERR(mtd);
	}

	/*
	 * The panic write targets the absolute pensando,flash-offset, so the
	 * partition being checked must live there (e.g. not moved by an
	 * mtdparts= override).
	 */
	if (mtd_get_master_ofs(mtd, 0) != sc->flash_offset) {
		dev_err(dev, "coredump_partition at 0x%llx, expected flash-offset 0x%x\n",
			mtd_get_master_ofs(mtd, 0), sc->flash_offset);
		ret = -EINVAL;
		goto out_put;
	}

	if (mtd->size < sc->flash_size) {
		dev_warn(dev, "coredump_partition size 0x%llx < flash-size 0x%x\n",
			 mtd->size, sc->flash_size);
		ret = -EINVAL;
		goto out_put;
	}

	buf = kmalloc(SAL_CHECK_CHUNK, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_put;
	}

	ret = 1;
	for (off = 0; off < sc->flash_size; off += len) {
		len = min_t(size_t, SAL_CHECK_CHUNK, sc->flash_size - off);
		ret = mtd_read(mtd, off, len, &retlen, buf);
		if (ret < 0 || retlen != len) {
			dev_warn(dev, "coredump_partition read failed at 0x%llx: %d\n",
				 off, ret);
			ret = ret < 0 ? ret : -EIO;
			break;
		}
		if (memchr_inv(buf, 0xff, len)) {
			ret = 0;
			break;
		}
		ret = 1;
	}

	kfree(buf);
out_put:
	put_mtd_device(mtd);
	return ret;
}

static ssize_t armed_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct sal_crash_st *sc = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%d\n", READ_ONCE(sc->partition_ready));
}

/*
 * Writing 1 re-checks the coredump partition from process context (the
 * MTD read is not usable from the panic path) and arms the driver if it
 * has been erased; the driver stays disarmed if the check fails.  Writing
 * 0 disarms it.
 */
static ssize_t armed_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct sal_crash_st *sc = dev_get_drvdata(dev);
	bool arm;
	int ret;

	ret = kstrtobool(buf, &arm);
	if (ret)
		return ret;

	guard(mutex)(&sc->arm_lock);

	/*
	 * Disarm first so a panic during the scan, or a failed scan, never
	 * writes over data the check has not (or could not) confirm erased.
	 */
	WRITE_ONCE(sc->partition_ready, false);
	if (!arm)
		return count;

	ret = sal_partition_check(sc);
	if (ret == -EPROBE_DEFER)
		ret = -ENODEV;
	if (ret < 0)
		return ret;
	if (!ret)
		return -EBUSY;	/* partition not erased */

	WRITE_ONCE(sc->partition_ready, true);
	return count;
}
static DEVICE_ATTR_RW(armed);

static struct attribute *sal_crash_attrs[] = {
	&dev_attr_armed.attr,
	NULL
};
ATTRIBUTE_GROUPS(sal_crash);

static void sal_of_node_put(void *data)
{
	of_node_put(data);
}

static void sal_qspi_release(void *data)
{
	struct device *qspi = data;

	pm_runtime_put(qspi);
	put_device(qspi);
}

/*
 * Keep the qspi1 controller runtime-resumed for as long as the dumper is
 * registered.  spi-cadence-quadspi autosuspends the controller (disabling
 * it and gating its clock) when idle, and a sleeping resume is not
 * possible from the panic path.  The device link makes sure this driver
 * is unbound before qspi1, so the reference is dropped (by devm, after
 * sal_crash_remove() unregisters the dumper) before qspi1 goes away.
 */
static int sal_qspi_hold(struct sal_crash_st *sc)
{
	struct device *dev = &sc->pdev->dev;
	struct platform_device *qspi_pdev;
	struct device *qspi;
	int ret;

	qspi_pdev = of_find_device_by_node(sc->qspi_np);
	if (!qspi_pdev)
		return dev_err_probe(dev, -EPROBE_DEFER, "qspi device not found\n");
	qspi = &qspi_pdev->dev;

	/* Report errors before put_device(), which may free qspi. */
	if (!device_link_add(dev, qspi, DL_FLAG_AUTOREMOVE_CONSUMER)) {
		ret = dev_err_probe(dev, -EINVAL, "failed to link to %s\n",
				    dev_name(qspi));
		put_device(qspi);
		return ret;
	}

	ret = pm_runtime_resume_and_get(qspi);
	if (ret) {
		ret = dev_err_probe(dev, ret, "failed to resume %s\n",
				    dev_name(qspi));
		put_device(qspi);
		return ret;
	}

	return devm_add_action_or_reset(dev, sal_qspi_release, qspi);
}

/*
 * Capture the page-program opcode, address width and bus widths that
 * spi-nor selected for the flash holding coredump_partition, so the panic
 * path issues the same command spi-nor would.
 */
static int sal_get_write_op(struct sal_crash_st *sc)
{
	struct device *dev = &sc->pdev->dev;
	struct mtd_info *mtd, *master;
	enum spi_nor_protocol proto;
	struct spi_nor *nor;
	int ret = 0;

	mtd = sal_get_coredump_mtd(sc);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);

	/* sal_get_coredump_mtd() checked that this is a spi-nor flash. */
	master = mtd_get_master(mtd);
	/*
	 * The captured configuration is only valid while spi-nor is bound:
	 * spi_nor_restore() on unbind may reset the flash or leave 4-byte
	 * address mode.  Link to the flash device so this driver (and its
	 * dumper) is removed before that happens.
	 */
	if (!device_link_add(dev, master->dev.parent,
			     DL_FLAG_AUTOREMOVE_CONSUMER)) {
		ret = dev_err_probe(dev, -EINVAL, "failed to link to %s\n",
				    dev_name(master->dev.parent));
		goto out_put;
	}

	nor = container_of(master, struct spi_nor, mtd);
	proto = nor->write_proto;

	if (spi_nor_protocol_is_dtr(proto) ||
	    spi_nor_get_protocol_inst_nbits(proto) != 1 ||
	    nor->addr_nbytes < 3 || nor->addr_nbytes > 4) {
		ret = dev_err_probe(dev, -EOPNOTSUPP,
				    "unsupported write protocol 0x%x, %u address bytes\n",
				    proto, nor->addr_nbytes);
		goto out_put;
	}

	if (!is_power_of_2(master->writebufsize) ||
	    master->writebufsize > FIELD_MAX(CQSPI_REG_SIZE_PAGE)) {
		ret = dev_err_probe(dev, -EOPNOTSUPP,
				    "unsupported flash page size %u\n",
				    master->writebufsize);
		goto out_put;
	}

	sc->wr_instr = FIELD_PREP(CQSPI_REG_WR_INSTR_OPCODE, nor->program_opcode) |
		FIELD_PREP(CQSPI_REG_WR_INSTR_TYPE_ADDR,
			   ilog2(spi_nor_get_protocol_addr_nbits(proto))) |
		FIELD_PREP(CQSPI_REG_WR_INSTR_TYPE_DATA,
			   ilog2(spi_nor_get_protocol_data_nbits(proto)));
	sc->addr_nbytes = nor->addr_nbytes;
	sc->page_size = master->writebufsize;

out_put:
	put_mtd_device(mtd);
	return ret;
}

/*
 * Snapshot the controller settings cqspi_configure() programs for this flash
 * (chip select, baud rate divisor, delays, read capture).  It only writes
 * them on the first transfer after a runtime resume, so do one MTD read now
 * that sal_qspi_hold() keeps the controller resumed; with a single flash at
 * a fixed speed they do not change afterwards.
 */
static int sal_snapshot_config(struct sal_crash_st *sc)
{
	struct device *dev = &sc->pdev->dev;
	void __iomem *apb = sc->apb_base;
	struct mtd_info *mtd;
	size_t retlen;
	u32 word, reg;
	int ret;

	mtd = sal_get_coredump_mtd(sc);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);
	ret = mtd_read(mtd, 0, sizeof(word), &retlen, (u8 *)&word);
	put_mtd_device(mtd);
	if (ret < 0 || retlen != sizeof(word))
		return dev_err_probe(dev, ret < 0 ? ret : -EIO,
				     "coredump_partition read failed\n");

	reg = readl(apb + CQSPI_REG_CONFIG);
	if (!(reg & CQSPI_REG_CONFIG_ENABLE))
		return dev_err_probe(dev, -EIO, "qspi controller not enabled\n");

	sc->cfg_bits = reg & SAL_CFG_BITS;
	sc->delay = readl(apb + CQSPI_REG_DELAY);
	sc->readcapture = readl(apb + CQSPI_REG_READCAPTURE);
	return 0;
}

static int sal_crash_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sal_crash_st *sc;
	struct resource *res;
	u32 trigger_addr;
	int err;

	sc = devm_kzalloc(dev, sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return -ENOMEM;

	sc->pdev = pdev;
	platform_set_drvdata(pdev, sc);

	err = devm_mutex_init(dev, &sc->arm_lock);
	if (err)
		return err;

	/*
	 * The APB and AHB regions are shared with the qspi1 platform driver.
	 * Use devm_ioremap() (no request_mem_region) so both drivers can map
	 * the same physical ranges without conflicting, regardless of probe
	 * order.
	 */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return dev_err_probe(dev, -ENODEV, "missing APB resource\n");
	sc->apb_base = devm_ioremap(dev, res->start, resource_size(res));
	if (!sc->apb_base)
		return dev_err_probe(dev, -ENOMEM, "failed to map APB registers\n");

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res)
		return dev_err_probe(dev, -ENODEV, "missing AHB resource\n");
	sc->ahb_base = devm_ioremap(dev, res->start, resource_size(res));
	if (!sc->ahb_base)
		return dev_err_probe(dev, -ENOMEM, "failed to map AHB window\n");

	if (of_property_read_u32(dev->of_node, "pensando,flash-offset",
				 &sc->flash_offset))
		return dev_err_probe(dev, -EINVAL, "missing pensando,flash-offset\n");

	if (of_property_read_u32(dev->of_node, "pensando,flash-size",
				 &sc->flash_size))
		return dev_err_probe(dev, -EINVAL, "missing pensando,flash-size\n");

	if (of_property_read_u32(dev->of_node, "cdns,fifo-depth",
				 &sc->fifo_depth))
		return dev_err_probe(dev, -EINVAL, "missing cdns,fifo-depth\n");

	if (of_property_read_u32(dev->of_node, "cdns,fifo-width",
				 &sc->fifo_width))
		return dev_err_probe(dev, -EINVAL, "missing cdns,fifo-width\n");

	if (of_property_read_u32(dev->of_node, "cdns,trigger-address",
				 &trigger_addr))
		return dev_err_probe(dev, -EINVAL, "missing cdns,trigger-address\n");

	sc->qspi_np = of_parse_phandle(dev->of_node, "pensando,qspi", 0);
	if (!sc->qspi_np)
		return dev_err_probe(dev, -EINVAL, "missing pensando,qspi\n");
	err = devm_add_action_or_reset(dev, sal_of_node_put, sc->qspi_np);
	if (err)
		return err;

	err = sal_partition_check(sc);
	if (err < 0)
		return dev_err_probe(dev, err,
				     "coredump partition check failed\n");
	sc->partition_ready = (err == 1);
	if (!sc->partition_ready)
		dev_info(dev, "coredump partition not erased; erase it and write 1 to armed to enable dump\n");

	err = sal_get_write_op(sc);
	if (err)
		return err;

	/* qspi1 is functional once its MTD partition exists. */
	err = sal_qspi_hold(sc);
	if (err)
		return err;

	err = sal_snapshot_config(sc);
	if (err)
		return err;

	/*
	 * Configure SRAM split, watermark, and trigger address before any
	 * transfers.  Done after taking the runtime PM reference so the
	 * controller is clocked; it is not runtime-resumed again while the
	 * reference is held, so these settings persist.
	 */
	writel(sc->fifo_depth / 2, sc->apb_base + CQSPI_REG_SRAMPARTITION);
	writel(sc->fifo_depth * sc->fifo_width / 8,
	       sc->apb_base + CQSPI_REG_INDIRECTWRWATERMARK);
	writel(trigger_addr, sc->apb_base + CQSPI_REG_INDIRECTTRIGGER);

	sc->panic_buf = vmalloc(sc->flash_size);
	if (!sc->panic_buf)
		return -ENOMEM;

	/*
	 * Set the global before registering the dumper so sal_do_dump() never
	 * races with a NULL pointer between registration and assignment.
	 * Clear it again on any subsequent error.
	 */
	sal_crash = sc;

	sc->dump.max_reason = KMSG_DUMP_PANIC;
	sc->dump.dump = sal_do_dump;
	err = kmsg_dump_register(&sc->dump);
	if (err) {
		sal_crash = NULL;
		dev_err(dev, "kmsg_dump_register failed: %d\n", err);
		vfree(sc->panic_buf);
		return err;
	}

	atomic_notifier_chain_register(&panic_notifier_list,
				       &sal_panic_notifier);
	dev_info(dev, "ready (flash offset 0x%08x, size 0x%x, wr_instr 0x%x, %u-byte addr, %u-byte page, %s)\n",
		 sc->flash_offset, sc->flash_size, sc->wr_instr,
		 sc->addr_nbytes, sc->page_size,
		 sc->partition_ready ? "armed" : "disarmed");
	return 0;
}

static void sal_crash_remove(struct platform_device *pdev)
{
	struct sal_crash_st *sc = platform_get_drvdata(pdev);

	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &sal_panic_notifier);
	if (kmsg_dump_unregister(&sc->dump) < 0)
		dev_err(&pdev->dev, "could not unregister kmsg_dumper\n");
	vfree(sc->panic_buf);
}

/*
 * The runtime PM reference does not stop cqspi_suspend() from forcing qspi1
 * and its clock off for system sleep, and touching it then would fault or
 * hang the panic path.  The device links make the PM core suspend this
 * device before qspi1 and resume it after, so these bracket the window in
 * which the controller may be off.
 */
static int sal_crash_suspend(struct device *dev)
{
	struct sal_crash_st *sc = dev_get_drvdata(dev);

	WRITE_ONCE(sc->qspi_suspended, true);
	return 0;
}

static int sal_crash_resume(struct device *dev)
{
	struct sal_crash_st *sc = dev_get_drvdata(dev);

	WRITE_ONCE(sc->qspi_suspended, false);
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(sal_crash_pm_ops, sal_crash_suspend,
				sal_crash_resume);

static const struct of_device_id sal_crash_dt_ids[] = {
	{ .compatible = "pensando,salina-crash" },
	{ }
};
MODULE_DEVICE_TABLE(of, sal_crash_dt_ids);

static struct platform_driver sal_crash_driver = {
	.probe  = sal_crash_probe,
	.remove = sal_crash_remove,
	.driver = {
		.name           = SAL_CRASH_NAME,
		.of_match_table = sal_crash_dt_ids,
		.dev_groups     = sal_crash_groups,
		.pm             = pm_sleep_ptr(&sal_crash_pm_ops),
	},
};
module_platform_driver(sal_crash_driver);

MODULE_DESCRIPTION("Pensando Salina QSPI Panic Dump Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" SAL_CRASH_NAME);
