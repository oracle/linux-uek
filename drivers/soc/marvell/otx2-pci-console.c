// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Supports the PCI Console when OcteonTX2 is running as an Endpoint.
 *
 */

/* Implementation notes:
 *
 * There are four types of devices for which a driver is provided by this
 * module:
 *
 * - PCI console nexus device
 * - PCI console device
 * - Linux console
 * - Linux TTY
 *
 * The primary device to which the driver initially attaches is the
 * 'PCI console nexus', represented in the Device Tree as
 * 'pci-console-nexus@0x7f000000'.
 *
 * The driver entry points are declared in 'pci_console_nexus_driver'.
 *
 * During its initialization, the pci_console_nexus_driver locates its device
 * memory and verifies that it has been configured appropriately
 * (i.e. by U-Boot).
 *
 * Next, it registers a platform driver for the actual console devices;
 * this driver's entry points are declared in 'pci_console_driver'.
 *
 * Finally, it populates the Device Tree with the console devices, which are
 * represented in the Device Tree as 'pci-console@{0-7}' – these are children
 * of the 'PCI console nexus' device.
 *
 * At this point, Linux will probe each new console device, which in turn will
 * register a Linux console.  The entry points for the Linux console are
 * declared as part of the private state structure of the Linux console device
 * (see invocation of 'register_console()' in the function 'pci_console_init()'.
 *
 * The Linux console device will, in turn, register a Linux TTY device.  These
 * device entry points are declared in 'pci_console_dev_tty_ops'.
 *
 * It is the Linux console & TTY devices which actually transfer data between
 * Linux and the OcteonTX device memory; the OcteonTX device memory is accessed
 * by the host remote console application.  This data transfer uses low-level
 * OcteonTX functions.
 *
 * Naming conventions:
 *
 * PCI console nexus device functions are named 'pci_console_nexus_xxx'.
 * PCI console device functions are named 'pci_console_xxx'.
 * Linux console device functions are named 'pci_console_dev_xxx'.
 * Linux TTY device functions are named 'pci_console_dev_tty_xxx'.
 * Low-level OcteonTX routines are named 'octeontx_console_xxx'.
 *
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/uio_driver.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/of_address.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/tty_driver.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include "otx2-pci-console.h"

#define DRV_NAME       "pci-console"
#define NEXUS_DRV_NAME DRV_NAME "-nexus"

/* copied from Octeon pci console driver */
#define TTY_DRV_MAJOR_VER       4
#define TTY_DRV_MINOR_VER_START 96

#ifdef CONFIG_OCTEONTX2_PCI_CONSOLE_DEBUG
#  define dbgmsg(dev, ...) dev_info((dev), __VA_ARGS__)
#else
#  define dbgmsg(dev, ...) (void)(dev)
#endif // CONFIG_OCTEONTX2_PCI_CONSOLE_DEBUG

static u32 max_consoles = 1;
module_param(max_consoles, uint, 0644);
MODULE_PARM_DESC(max_consoles, "Maximum console count to support");

/* pci console driver prototypes */
static void pci_console_dev_write(struct console *cons, const char *buf,
				  unsigned int len);
static struct tty_driver *pci_console_dev_device(struct console *cons,
						 int *index);
static int pci_console_dev_setup(struct console *cons, char *arg);
static struct platform_driver pci_console_driver;

/* pci console TTY driver prototypes */
static int pci_console_dev_tty_open(struct tty_struct *tty, struct file *filp);
static void pci_console_dev_tty_close(struct tty_struct *tty,
				      struct file *filp);
static int pci_console_dev_tty_write(struct tty_struct *tty,
				     const unsigned char *buf, int count);
static int pci_console_dev_tty_write_room(struct tty_struct *tty);
static int pci_console_dev_tty_chars_in_buffer(struct tty_struct *tty);
static void pci_console_dev_tty_send_xchar(struct tty_struct *tty, char ch);

/* TTY driver operations table */
static const struct tty_operations pci_console_dev_tty_ops = {
	.open = pci_console_dev_tty_open,
	.close = pci_console_dev_tty_close,
	.write = pci_console_dev_tty_write,
	.write_room = pci_console_dev_tty_write_room,
	.chars_in_buffer = pci_console_dev_tty_chars_in_buffer,
	.send_xchar = pci_console_dev_tty_send_xchar,
};

static u32 max_cons_mask;

/*
 * Utility function; returns the number of free bytes in the buffer.
 *
 * @param buffer_size	size of buffer
 * @param wr_idx	write index
 * @param rd_idx	read index
 *
 * @return number of bytes free
 */
static int buffer_free_bytes(size_t buffer_size, u32 wr_idx, u32 rd_idx)
{
	if (rd_idx >= buffer_size || wr_idx >= buffer_size)
		return -1;
	return ((buffer_size - 1) - (wr_idx - rd_idx)) % buffer_size;
}

/*
 * Utility function; returns the number of pending bytes (i.e. data) in the
 * buffer.
 *
 * @param buffer_size	size of buffer
 * @param wr_idx	write index
 * @param rd_idx	read index
 *
 * @return number of pending data bytes
 */
static int buffer_pending_bytes(size_t buffer_size, u32 wr_idx, u32 rd_idx)
{
	if (rd_idx >= buffer_size || wr_idx >= buffer_size)
		return -1;
	return buffer_size - 1 -
	       buffer_free_bytes(buffer_size, wr_idx, rd_idx);
}

/* ======================== pci console nexus driver ======================== */

/*
 * Check that the console version is acceptable.
 */
static bool pci_console_nexus_check_ver(u8 major, u8 minor)
{
	if (major > OCTEONTX_PCIE_CONSOLE_MAJOR)
		return true;
	if (major == OCTEONTX_PCIE_CONSOLE_MAJOR &&
	    minor >= OCTEONTX_PCIE_CONSOLE_MINOR)
		return true;
	return false;
}

/*
 * Used to initialize access to nexus memory.
 */
static int pci_console_nexus_init_resources(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console_nexus *pci_cons_nexus = platform_get_drvdata(pdev);
	struct device_node *of_node;
	const __be32 *of_base;
	u64 of_xbase, of_size;
	int ret;

	dbgmsg(dev, "%s: entry\n", __func__);

	WARN_ON(!pci_cons_nexus);

	ret = -ENODEV;

	pci_cons_nexus->of_node = of_node = pdev->dev.of_node;
	if (!of_node) {
		dev_err(dev, "Missing devicetree configuration\n");
		goto exit;
	}

	of_base = of_get_address(of_node, 0, &of_size, 0);
	if (!of_base) {
		dev_err(dev, "Missing configuration base address\n");
		goto exit;
	}

	of_xbase = of_translate_address(of_node, of_base);
	/* TODO: verify we can use WC */
	if (of_xbase != OF_BAD_ADDR)
		pci_cons_nexus->desc =
			ioremap_wc(of_xbase, of_size);

	if (!pci_cons_nexus->desc) {
		dev_err(dev, "Invalid configuration base address\n");
		goto exit;
	}

	dbgmsg(dev, "of_base: %p (%llx), of_size: %llx, nexus:%p\n",
	       of_base, of_xbase, of_size, pci_cons_nexus->desc);

	ret = 0;

exit:
	return ret ? -ENODEV : 0;
}

static int pci_console_nexus_de_init_resources(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console_nexus *pci_cons_nexus = platform_get_drvdata(pdev);

	dbgmsg(dev, "%s: entry\n", __func__);

	if (pci_cons_nexus && pci_cons_nexus->desc) {
		iounmap(pci_cons_nexus->desc);
		pci_cons_nexus->desc = NULL;
	}

	return 0;
}

/*
 * This is used to initialize the console nexus state.
 */
static int pci_console_nexus_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console_nexus *pci_cons_nexus = platform_get_drvdata(pdev);
	struct octeontx_pcie_console_nexus __iomem *nexus;
	struct device_node *child_node;
	uint num_consoles;
	int ret;

	dbgmsg(dev, "%s: entry\n", __func__);

	WARN_ON(!pci_cons_nexus);

	ret = -ENODEV;

	nexus = pci_cons_nexus->desc;
	if (!nexus)
		goto exit;

	/* Verify/use existing configuration (i.e. from U-Boot) */
	if (readq(&nexus->magic) !=
		cpu_to_le64(OCTEONTX_PCIE_CONSOLE_NEXUS_MAGIC)) {
		dev_err(dev, "Invalid nexus signature (0x%llx).\n",
			(long long)readq(&nexus->magic));
		goto exit;
	}

	if (!pci_console_nexus_check_ver(readb(&nexus->major_version),
					 readb(&nexus->minor_version))) {
		dev_err(dev,
			"Unsupported nexus version %u.%u (%u.%u)\n)",
			readb(&nexus->major_version),
			readb(&nexus->minor_version),
			OCTEONTX_PCIE_CONSOLE_MAJOR,
			OCTEONTX_PCIE_CONSOLE_MINOR);
		goto exit;
	}

	if (!readb(&nexus->num_consoles)) {
		dev_err(dev, "No consoles present");
		goto exit;
	}

	/* enumerate 'available' consoles present in device tree */
	num_consoles = 0;
	for_each_available_child_of_node(pci_cons_nexus->of_node,
					 child_node)
		if (of_device_is_compatible(child_node,
					    "marvell,pci-console"))
			num_consoles++;

	if (num_consoles < readb(&nexus->num_consoles)) {
		dev_err(dev,
			"Console count mismatch: DT %d, nexus: %d\n",
			num_consoles, readb(&nexus->num_consoles));
		goto exit;
	}

	dbgmsg(dev,
	       "Console nexus initialized: ver %u.%u, %u consoles available\n",
	       readb(&nexus->major_version), readb(&nexus->minor_version),
	       readb(&nexus->num_consoles));

	ret = 0;

exit:
	return ret ? -ENODEV : 0;
}

/*
 * This is the main probe routine for the console nexus driver.
 */
static int pci_console_nexus_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console_nexus *pci_cons_nexus;
	bool registered;
	int ret;

	BUILD_BUG_ON(offsetof(struct octeontx_pcie_console_nexus, console_addr)
		     != 128);

	dbgmsg(dev, "%s: entry, max_consoles %d\n", __func__, max_consoles);

	max_cons_mask = BIT(max_consoles) - 1;

	pci_cons_nexus = NULL;
	registered = false;

	ret = -ENODEV;

	/* allocate device structure */
	pci_cons_nexus = devm_kzalloc(dev, sizeof(*pci_cons_nexus),
				       GFP_KERNEL);

	if (pci_cons_nexus == NULL) {
		ret = -ENOMEM;
		dev_err(dev, "Unable to allocate drv context.\n");
		goto exit;
	}

	platform_set_drvdata(pdev, pci_cons_nexus);

	ret = pci_console_nexus_init_resources(pdev);
	if (ret)
		goto exit;

	ret = pci_console_nexus_init(pdev);
	if (ret)
		goto exit;

	dev_info(dev, "Registering child console driver...\n");

	ret = platform_driver_register(&pci_console_driver);

	if (ret) {
		dev_err(dev,
			"Error %d registering child console driver\n",
			ret);
		goto exit;
	} else
		registered = true;

	ret = of_platform_populate(pci_cons_nexus->of_node, NULL, NULL,
				   dev);

	if (ret) {
		dev_err(dev, "Error %d populating children of %s\n",
			ret,
			of_node_full_name(pci_cons_nexus->of_node));
		goto exit;
	}

	ret = 0;

exit:
	if (ret) {
		if (registered)
			platform_driver_unregister(&pci_console_driver);

		pci_console_nexus_de_init_resources(pdev);

		if (pci_cons_nexus != NULL)
			devm_kfree(dev, pci_cons_nexus);
	}

	return ret;
}

static void pci_console_nexus_shutdown(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	dbgmsg(dev, "%s: entry\n", __func__);
}

/*
 * Linux driver callback.
 */
static int pci_console_nexus_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console_nexus *pci_cons_nexus = platform_get_drvdata(pdev);

	dbgmsg(dev, "%s: entry\n", __func__);

	WARN_ON(!pci_cons_nexus);

	of_platform_depopulate(dev);

	platform_driver_unregister(&pci_console_driver);

	pci_console_nexus_de_init_resources(pdev);

	devm_kfree(dev, pci_cons_nexus);

	return 0;
}

static const struct of_device_id pci_console_nexus_of_match[] = {
	{ .compatible = "marvell,pci-console-nexus", },
	{},
};
MODULE_DEVICE_TABLE(of, pci_console_nexus_of_match);

static const struct platform_device_id pci_console_nexus_pdev_match[] = {
	{ .name = NEXUS_DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, pci_console_nexus_pdev_match);

static struct platform_driver pci_console_nexus_driver = {
	.driver = {
		.name = NEXUS_DRV_NAME,
		.of_match_table = pci_console_nexus_of_match,
	},
	.probe = pci_console_nexus_probe,
	.remove = pci_console_nexus_remove,
	.shutdown = pci_console_nexus_shutdown,
	.id_table = pci_console_nexus_pdev_match,
};

module_platform_driver(pci_console_nexus_driver);

MODULE_DESCRIPTION("OcteonTX PCI Console Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" NEXUS_DRV_NAME);

/* =========================== pci console driver =========================== */

/*
 * Low-level initialization function for octeontx console state.
 */
static int octeontx_console_init(struct device *dev,
				 struct pci_console *pci_cons, int index,
				 u64 cons_addr, u64 cons_size)
{
	int ret;
	u32 cons_num;
	struct octeontx_pcie_console __iomem *ring_descr;

	/* see notes in structure declaration regarding these elements */
	BUILD_BUG_ON(offsetof(struct octeontx_pcie_console,
			      host_console_connected) & 0x7);
	BUILD_BUG_ON((offsetof(struct octeontx_pcie_console,
			       host_console_connected) + sizeof(u32)) !=
		     offsetof(struct octeontx_pcie_console, output_read_index));

	dbgmsg(dev, "%s: entry\n", __func__);

	ret = -ENODEV;
	cons_num = index;

	if (!cons_addr) {
		dev_err(dev, "Missing console base address\n");
		goto exit;
	}

	/* map the ring descriptor from the nexus */
	/* TODO: verify we can use WC */
	pci_cons->ring_descr = ioremap_wc(cons_addr, cons_size);
	if (!pci_cons->ring_descr) {
		dev_err(dev,
			"Unable to remap console %d base address\n",
			cons_num);
		goto exit;
	}

	ring_descr = pci_cons->ring_descr;

	/* Here, we verify/use existing configuration
	 * (i.e. from U-Boot).
	 *
	 * If this changes and the console is initialized here,
	 * then the pcie_lock must be taken/released around
	 * the init code.
	 */

	if (readq(&ring_descr->magic) !=
	    cpu_to_le64(OCTEONTX_PCIE_CONSOLE_MAGIC)) {
		dev_err(dev, "Invalid console %d signature\n",
			cons_num);
		goto exit;
	}

	/* Implementation note: using 'u32' will catch negative vals */
	if (((u32)le32_to_cpu(readl(&ring_descr->input_read_index)) >=
	     le32_to_cpu(readl(&ring_descr->input_buf_size))) ||
	    ((u32)le32_to_cpu(readl(&ring_descr->input_write_index)) >=
	     le32_to_cpu(readl(&ring_descr->input_buf_size))) ||
	    ((u32)le32_to_cpu(readl(&ring_descr->output_read_index)) >=
	     le32_to_cpu(readl(&ring_descr->output_buf_size))) ||
	    ((u32)le32_to_cpu(readl(&ring_descr->output_write_index)) >=
	     le32_to_cpu(readl(&ring_descr->output_buf_size))) ||
	    !readl(&ring_descr->input_buf_size) ||
	    !readl(&ring_descr->output_buf_size) ||
	    !readq(&ring_descr->input_base_addr) ||
	    !readq(&ring_descr->output_base_addr)) {
		dev_err(dev, "Invalid console %d ring configuration\n",
			cons_num);
		goto exit;
	}

	/* map the input buffer */
	pci_cons->input_ring = ioremap_wc(readq(&ring_descr->input_base_addr),
					  readl(&ring_descr->input_buf_size));

	/* map the output buffer */
	pci_cons->output_ring = ioremap_wc(readq(&ring_descr->output_base_addr),
					   readl(&ring_descr->output_buf_size));

	if (!pci_cons->input_ring || !pci_cons->output_ring) {
		dev_err(dev,
			"Unable to remap console %d memory ring[s]\n",
			cons_num);
		goto exit;
	}

	writel(cpu_to_le32(cons_num), &ring_descr->host.cons_idx);
	spin_lock_init(&pci_cons->excl_lock[cons_num]);

	ret = 0;

exit:
	return ret ? -ENODEV : 0;
}

/*
 * Low-level de-initialization function for octeontx console state.
 */
static int octeontx_console_de_init(struct device *dev,
				    struct pci_console *pci_cons, int index,
				    u64 cons_addr, u64 cons_size)
{
	dbgmsg(dev, "%s: entry\n", __func__);

	if (pci_cons->input_ring) {
		iounmap(pci_cons->input_ring);
		pci_cons->input_ring = NULL;
	}

	if (pci_cons->output_ring) {
		iounmap(pci_cons->output_ring);
		pci_cons->output_ring = NULL;
	}

	if (pci_cons->ring_descr) {
		iounmap(pci_cons->ring_descr);
		pci_cons->ring_descr = NULL;
	}

	return 0;
}

/*
 * Used to acquire or release a low-level octeontx console.
 */
static bool
octeontx_console_acquire(struct octeontx_pcie_console_nexus __iomem *nexus_desc,
			 int index, bool acquire, u64 *old, u64 *new)
{
	bool b_ok;
	u32 wait_usecs;
	u64 old_use_mask, new_use_mask;
	int cons_num;

	b_ok = false;

	if (!nexus_desc)
		return b_ok;

	cons_num = index;
	wait_usecs = 0;

#define CONSOLE_NEXUS_IN_USE_WAIT_USECS    1
#define CONSOLE_NEXUS_IN_USE_TIMEOUT_USECS 100

	do {
		old_use_mask = le32_to_cpu(readl(&nexus_desc->in_use)) |
			       (u64)le32_to_cpu(readl(
						&nexus_desc->exclusive)) << 32;

		/* set (or clear) both 'in-use' and 'exclusive' bits */
		new_use_mask = ((1ULL << cons_num) |
			       ((1ULL << cons_num) << 32));

		if (acquire) {
			/* Check if console has already been acquired */
			if (old_use_mask & (1ULL << cons_num))
				break;
			new_use_mask = old_use_mask | new_use_mask;
		} else {
			new_use_mask = old_use_mask & ~new_use_mask;
		}

		b_ok = (__atomic_compare_exchange_n((u64 *)&nexus_desc->in_use,
						    &old_use_mask, new_use_mask,
						    false, __ATOMIC_SEQ_CST,
						    __ATOMIC_SEQ_CST));
		if (b_ok)
			break;

		udelay(CONSOLE_NEXUS_IN_USE_WAIT_USECS);
		wait_usecs += CONSOLE_NEXUS_IN_USE_WAIT_USECS;

	} while (wait_usecs < CONSOLE_NEXUS_IN_USE_TIMEOUT_USECS);

	if (old)
		*old = old_use_mask;

	if (new)
		*new = new_use_mask;

	return b_ok;
}

/*
 * Clears pending data [bytes] from the low-level octeontx console output
 * buffer if the host console is not connected.
 * If the host console IS connected, an error is returned.
 *
 * @param console		console to clear output from
 * @param bytes_to_clear	Number of bytes to free up
 *
 * @return	0 for success, -1 on error, or a positive value
 *              If the size of pending data is less than 'bytes_to_clear',
 *              the return value equals the count of pending data.
 */
int octeontx_console_output_truncate(struct octeontx_pcie_console *console,
				     size_t bytes_to_clear)
{
	u64 old_val;
	u64 new_val;
	size_t bytes_avail;
	const u32 out_buf_size = le32_to_cpu(readl(&console->output_buf_size));
	u32 out_wr_idx, out_rd_idx;
	int ret;

	if (le32_to_cpu(readl(&console->host_console_connected)))
		return -1;

	out_wr_idx = le32_to_cpu(readl(&console->output_write_index));
	out_rd_idx = le32_to_cpu(readl(&console->output_read_index));

	old_val = cpu_to_le64((u64)out_rd_idx << 32);
	bytes_avail = buffer_pending_bytes(out_buf_size, out_wr_idx,
					   out_rd_idx);
	if (bytes_avail < 0)
		return bytes_avail;
	/* Not enough space */
	if (bytes_to_clear > bytes_avail)
		return bytes_avail;

	out_rd_idx = (out_rd_idx + bytes_to_clear) % out_buf_size;
	new_val = cpu_to_le64((u64)out_rd_idx << 32);

	/*
	 * We need to use an atomic operation here in case the host
	 * console should connect.  This guarantees that if the host
	 * connects that it will always see a consistent state.  Normally
	 * only the host can modify the read pointer.  This assures us
	 * that the read pointer will only be modified if the host
	 * is disconnected.
	 */
	ret = __atomic_compare_exchange_n
			((u64 *)(&console->host_console_connected),
			 &old_val, new_val, 0,
			 __ATOMIC_RELAXED, __ATOMIC_RELAXED);

	return ret ? 0 : -1;
}

/*
 * Low-level octeontx console write function.
 *
 * NOTE: this may NOT sleep, as it is called by the TTY 'write()' API.
 *
 */
static unsigned
octeontx_console_write(struct device *dev, const char *buf, unsigned int len,
		       struct octeontx_pcie_console __iomem *ring_descr,
		       u8 __iomem *output_ring, spinlock_t *excl_lock)
{
	const u8 *src;
	int srclen, avail, wr_len, written;
	unsigned int wait_usecs;
	u32 sz, rd_idx, wr_idx;

	spin_lock(excl_lock);

	sz = le32_to_cpu(readl(&ring_descr->output_buf_size));
	src = buf;
	srclen = len;
	written = 0;
	wait_usecs = 0;

	wr_idx = le32_to_cpu(readl(&ring_descr->output_write_index));

	while (srclen > 0) {
		rd_idx = le32_to_cpu(readl(&ring_descr->output_read_index));
		avail = buffer_free_bytes(sz, wr_idx, rd_idx);

		if (avail > 0) {
			/* reset host wait time */
			wait_usecs = 0;

			wr_len = min(avail, srclen);
			srclen -= wr_len;
			if (wr_idx + wr_len > sz) {
				memcpy_toio(output_ring + wr_idx, src,
					    (sz - wr_idx));
				wr_len -= (sz - wr_idx);
				src += (sz - wr_idx);
				wr_idx = 0;
			}
			if (wr_len)
				memcpy_toio(output_ring + wr_idx, src, wr_len);
			src += wr_len;
			written += wr_len;
			wr_idx = (wr_idx + wr_len) % sz;

			/* The write index is used by another process
			 * (remote PCI) to indicate the presence of [new] data
			 * in the ring buffer.
			 * Use a barrier here to ensure that all such data
			 * has been committed to memory prior to updating
			 * the write index in the descriptor.
			 */
			wmb();
			writel(cpu_to_le32(wr_idx),
			       &ring_descr->output_write_index);
		} else if (!avail) {
			/* Try to free space in output buffer (i.e. truncate) */
			wr_len = octeontx_console_output_truncate(ring_descr,
								  srclen);

			if (wr_len < 0) {
				if (wait_usecs >=
				    PCI_CONS_HOST_WAIT_TIMEOUT_USECS) {
					dev_err_once(dev,
						     "Timeout awaiting host\n");
					break;
				}
				/* We cannot sleep, we have acquired the lock */
				udelay(PCI_CONS_HOST_WAIT_LOOP_USECS);
				wait_usecs += PCI_CONS_HOST_WAIT_LOOP_USECS;
			} else if (wr_len > 0) {
				/* Truncate what we can */
				wr_len = octeontx_console_output_truncate(
						ring_descr, wr_len);
				if (wr_len != 0) {
					dev_err(dev,
						"output buffer truncate error\n");
					break;
				}
			}
		} else {
			dev_err_once(dev, "output buffer error\n");
			break;
		}
	}

	spin_unlock(excl_lock);

	return written;
}

/*
 * Linux console callback.
 */
static void pci_console_dev_write(struct console *cons, const char *buf,
				  unsigned int len)
{
	struct pci_console *pci_cons = cons->data;
	struct device *dev = pci_cons->device;
	struct octeontx_pcie_console __iomem *ring_descr;
	u8 __iomem *output_ring;
	u32 cons_idx;

	ring_descr = pci_cons->ring_descr;
	output_ring = pci_cons->output_ring;

	cons_idx = le32_to_cpu(readl(&ring_descr->host.cons_idx));

	octeontx_console_write(dev, buf, len, ring_descr, output_ring,
			       &pci_cons->excl_lock[cons_idx]);
}

/*
 * Linux console callback.
 */
static struct tty_driver *pci_console_dev_device(struct console *cons,
						 int *index)
{
	struct pci_console *pci_cons = cons->data;
	struct device *dev = pci_cons->device;

	dbgmsg(dev, "%s: entry\n", __func__);

	*index = pci_cons->cons.index;

	dbgmsg(dev, "return index: %d, tty driver: %p\n", *index,
	       pci_cons->tty.drv);

	return pci_cons->tty.drv;
}

/*
 * Linux console initialization callback.
 *
 * Create and register a TTY driver to be used with this console.
 *
 */
int pci_console_dev_setup(struct console *cons, char *arg)
{
	struct pci_console *pci_cons = cons->data;
	struct device *dev = pci_cons->device;
	struct tty_driver *ttydrv;
	int ret;

	dbgmsg(dev, "%s: entry, args '%s'\n", __func__, arg);

	ret = 0;
	ttydrv = NULL;

	/* Create/register our TTY driver */
	if (!pci_cons->tty.drv) {
		ret = -ENODEV;

		ttydrv = tty_alloc_driver(1 /*i.e. a single line */,
					  TTY_DRIVER_REAL_RAW);
		if (!ttydrv) {
			dev_err(dev, "Cannot allocate tty driver\n");
			goto exit;
		}

		ttydrv->driver_name = DRV_NAME;
		ttydrv->name = "ttyPCI";
		ttydrv->type = TTY_DRIVER_TYPE_SERIAL;
		ttydrv->subtype = SERIAL_TYPE_NORMAL;
		ttydrv->major = TTY_DRV_MAJOR_VER;
		ttydrv->minor_start = TTY_DRV_MINOR_VER_START;
		ttydrv->init_termios = tty_std_termios;
		ttydrv->init_termios.c_cflag =
			B9600 | CS8 | CREAD | HUPCL | CLOCAL;
		ttydrv->driver_state = pci_cons;
		tty_set_operations(ttydrv, &pci_console_dev_tty_ops);
		tty_port_init(&pci_cons->tty.port);
		tty_port_link_device(&pci_cons->tty.port, ttydrv,
				     0 /* i.e. the first, and only, port */);
		ret = tty_register_driver(ttydrv);
		if (ret) {
			dev_err(dev, "Error registering TTY %s\n",
				ttydrv->name);
			goto exit;
		}

		pci_cons->tty.drv = ttydrv;

		ret = 0;
	}

exit:
	/* If error initializing tty driver, release it */
	if (ret && ttydrv)
		put_tty_driver(ttydrv);

	return ret ? -ENODEV : 0;
}

/*
 * Main initialization function for pci_console device instance.
 *
 * returns:
 *   0 if no error
 *   -ENODEV if error occurred initializing device
 *   ENODEV if device should not be used (not an error per se)
 */
static int pci_console_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console *pci_cons = platform_get_drvdata(pdev);
	struct device_node *of_node, *of_parent;
	int ret, cons_num, len;
	u64 cons_addr, cons_size, new_use_mask, old_use_mask;
	u64 of_parent_sz, of_parent_xbase;
	u32 cons_index;
	const __be32 *of_base, *of_parent_base;
	struct octeontx_pcie_console_nexus __iomem *nexus_desc;

	dbgmsg(dev, "%s: entry\n", __func__);

	ret = -ENODEV;

	nexus_desc = NULL;

	of_node = pdev->dev.of_node;
	if (!of_node) {
		dev_err(dev, "Missing devicetree configuration\n");
		goto exit;
	}

	/* retrieve our console index */
	cons_num = -1;
	if (!of_property_read_u32(of_node, "reg", &cons_index))
		cons_num = cons_index;
	if ((cons_num < 0) ||
	    (cons_num >= OCTEONTX_PCIE_MAX_CONSOLES)) {
		dev_err(dev, "Invalid configuration console index\n");
		goto exit;
	}

	if (!(max_cons_mask & BIT(cons_num))) {
		dev_info(dev, "Ignoring excluded console %d\n",
			 cons_num);
		ret = ENODEV;
		goto exit;
	}

	/* Retrieve console base address and length from device tree */
	cons_addr = OF_BAD_ADDR;
	of_base = of_get_address(of_node, 0, &cons_size, 0);
	if (of_base)
		cons_addr = of_translate_address(of_node, of_base);
	if (cons_addr == OF_BAD_ADDR) {
		dev_err(dev, "Invalid configuration base address\n");
		goto exit;
	}

	dbgmsg(dev, "Located console %d, address %#llx, size: %#llx\n",
	       cons_num, cons_addr, cons_size);

	/* ======================================================= */
	/* Note: we must [eventually] call 'of_node_put' on parent */
	of_parent = of_get_parent(of_node);
	if (!of_parent) {
		dev_err(dev,
			"Missing devicetree parent configuration\n");
		goto exit;
	}

	/* retrieve (and map) nexus pointer from parent node */
	of_parent_base = of_get_address(of_parent, 0, &of_parent_sz, 0);
	if (of_parent_base) {
		of_parent_xbase = of_translate_address(of_parent,
						       of_parent_base);
		/* TODO: verify we can use WC */
		if (of_parent_xbase != OF_BAD_ADDR) {
			dbgmsg(dev, "of_parent_xbase: %#llx\n",
			       of_parent_xbase);
			pci_cons->nexus_desc = nexus_desc =
				ioremap_wc(of_parent_xbase,
					   of_parent_sz);
		}
	}

	/* Release reference on parent */
	of_node_put(of_parent);
	/* ======================================================= */

	if (!nexus_desc) {
		dev_err(dev,
			"Invalid parent configuration base address\n");
		goto exit;
	}

	/* Verify/use existing configuration (i.e. from U-Boot) */

	if (readq(&nexus_desc->magic) !=
		cpu_to_le64(OCTEONTX_PCIE_CONSOLE_NEXUS_MAGIC)) {
		dev_err(dev, "Invalid nexus signature\n");
		goto exit;
	}

	if (cons_addr !=
	    le64_to_cpu(readq(&nexus_desc->console_addr[cons_num]))) {
		dev_err(dev,
			"Console %d base address mismatch %#llx/%#llx\n"
			, cons_num, cons_addr,
			le64_to_cpu(readq(&nexus_desc->console_addr[cons_num]))
			);
		goto exit;
	}

	if (le32_to_cpu(readl(&nexus_desc->in_use)) & (1 << cons_num)) {
		dev_err(dev, "Console %d already in-use\n", cons_num);
		goto exit;
	}

	if (octeontx_console_init(dev, pci_cons, cons_num, cons_addr,
				  cons_size)) {
		dev_err(dev,
			"Error initializing octeontx pci console\n");
		goto exit;
	}

	dev_info(dev,
		 "Initialized console %d, address %#llx, size: %#llx\n",
		 cons_num, cons_addr, cons_size);

	old_use_mask = new_use_mask = 0;

	if (!octeontx_console_acquire(pci_cons->nexus_desc, cons_num,
				      true, &old_use_mask,
				      &new_use_mask)) {
		dev_err(dev,
			"Console acquisition failed, old: %#llx, new: %#llx\n",
			old_use_mask, new_use_mask);
		goto exit;
	}

	pci_cons->octeontx_console_acquired = true;

	dbgmsg(dev, "Console acquisition - old: %#llx, new: %#llx\n",
	       old_use_mask, new_use_mask);

	/* initialize linux console state */
	len = sizeof(pci_cons->cons.name);
	strncpy(pci_cons->cons.name, "pci", len - 1);
	pci_cons->cons.name[len - 1] = 0;
	pci_cons->device = dev;
	pci_cons->cons.write = pci_console_dev_write;
	pci_cons->cons.device = pci_console_dev_device;
	pci_cons->cons.setup = pci_console_dev_setup;
	pci_cons->cons.data = pci_cons;
	pci_cons->cons.index = cons_num;
	pci_cons->cons.flags = CON_PRINTBUFFER;

	register_console(&pci_cons->cons);

	ret = 0;

exit:
	return ret;
}

/*
 * Main de-initialization function for pci_console device instance.
 */
static int pci_console_de_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console *pci_cons = platform_get_drvdata(pdev);
	u64 new_use_mask, old_use_mask;
	int cons_num;

	dbgmsg(dev, "%s: entry\n", __func__);

	cons_num = pci_cons->cons.index;

	if (pci_cons->tty.drv) {
		tty_unregister_driver(pci_cons->tty.drv);
		put_tty_driver(pci_cons->tty.drv);
	}

	if (pci_cons->cons.flags & CON_ENABLED) {
		if (unregister_console(&pci_cons->cons))
			dev_err(dev,
				"Error unregistering pci console %d\n",
				cons_num);
	}

	octeontx_console_de_init(dev, pci_cons, cons_num, 0, 0);

	if (pci_cons->octeontx_console_acquired) {
		old_use_mask = new_use_mask = 0;
		if (!octeontx_console_acquire(pci_cons->nexus_desc,
				     cons_num, false, &old_use_mask,
				     &new_use_mask))
			dev_err(dev,
				"Console release failed, old: %#llx, new: %#llx\n",
				old_use_mask, new_use_mask);
		else
			dbgmsg(dev,
			       "Console release - old: %#llx, new: %#llx\n",
			       old_use_mask, new_use_mask);

		iounmap(pci_cons->nexus_desc);
		pci_cons->nexus_desc = NULL;
	}

	return 0;
}

static int pci_console_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console *pci_cons;
	int ret;

	dbgmsg(dev, "%s: entry\n", __func__);

	pci_cons = NULL;

	ret = -ENODEV;

	/* allocate device structure */
	pci_cons = devm_kzalloc(dev, sizeof(*pci_cons), GFP_KERNEL);

	if (pci_cons == NULL) {
		ret = -ENOMEM;
		dev_err(dev, "Unable to allocate drv context.\n");
		goto exit;
	}

	platform_set_drvdata(pdev, pci_cons);

	ret = pci_console_init(pdev);

	/* a negative value indicates an error */
	if (ret < 0)
		dev_err(dev, "Error initializing pci console\n");

exit:
	if (ret) {
		pci_console_de_init(pdev);

		if (pci_cons != NULL)
			devm_kfree(dev, pci_cons);
	}

	return ret ? -ENODEV : 0;
}

static int pci_console_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_console *pci_cons = platform_get_drvdata(pdev);

	dbgmsg(dev, "%s: entry\n", __func__);

	pci_console_de_init(pdev);

	devm_kfree(dev, pci_cons);

	return 0;
}

static void pci_console_shutdown(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	dbgmsg(dev, "%s: entry\n", __func__);

	pci_console_remove(pdev);
}

static const struct of_device_id pci_console_of_match[] = {
	{ .compatible = "marvell,pci-console", },
	{},
};
MODULE_DEVICE_TABLE(of, pci_console_of_match);

static const struct platform_device_id pci_console_pdev_match[] = {
	{ .name = DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, pci_console_pdev_match);

static struct platform_driver pci_console_driver = {
	.driver = {
		.name = DRV_NAME,
		.of_match_table = pci_console_of_match,
	},
	.probe = pci_console_probe,
	.remove = pci_console_remove,
	.shutdown = pci_console_shutdown,
	.id_table = pci_console_pdev_match,
};

/* ========================= pci console TTY driver ========================= */

/*
 * Linux TTY driver timer callback (used to poll for data).
 */
void pci_console_dev_tty_poll(unsigned long ctx)
{
#define MAX_BUFFERED_INP_DATA 0x100
	struct tty_struct *tty = (struct tty_struct *)ctx;
	struct pci_console *pci_cons = tty->driver->driver_state;
	struct octeontx_pcie_console __iomem *ring_descr;
	u8 __iomem *input_ring;
	u8 buf[MAX_BUFFERED_INP_DATA];
	int cnt;
	u32 sz, rd_idx, wr_idx, avail;

	BUILD_BUG_ON(PCI_CONS_TTY_POLL_INTERVAL_JIFFIES > HZ);
	if (!(pci_cons->tty.stats.poll_count++ %
	      (HZ / PCI_CONS_TTY_POLL_INTERVAL_JIFFIES))) {
		dbgmsg(pci_cons->device,
		       "timer poll count: %u, dropped: %u, pushed: %u\n",
		       pci_cons->tty.stats.poll_count,
		       pci_cons->tty.stats.dropped_count,
		       pci_cons->tty.stats.pushed_count);
	}

	ring_descr = pci_cons->ring_descr;
	input_ring = pci_cons->input_ring;
	sz = le32_to_cpu(readl(&ring_descr->input_buf_size));
	rd_idx = le32_to_cpu(readl(&ring_descr->input_read_index));
	wr_idx = le32_to_cpu(readl(&ring_descr->input_write_index));
	avail = buffer_pending_bytes(sz, wr_idx, rd_idx);

	while ((s32)avail > 0) {

		if (rd_idx > wr_idx)
			cnt = min(avail, sz - rd_idx);
		else
			cnt = min(avail, wr_idx - rd_idx);

		cnt = min(cnt, MAX_BUFFERED_INP_DATA);
		memcpy_fromio(buf, &input_ring[rd_idx], cnt);
		cnt = tty_insert_flip_string(tty->port, buf, cnt);
		if (!cnt) {
			pci_cons->tty.stats.dropped_count += cnt;
			break;
		}

		rd_idx = (rd_idx + cnt) % sz;
		avail -= cnt;

		pci_cons->tty.stats.pushed_count += cnt;

		tty_flip_buffer_push(tty->port);
	}
	/* The read index is used by another process (remote PCI) to
	 * indicate which data have been consumed from the ring buffer.
	 * Use a barrier here to ensure that all such data
	 * has been copied from the ring buffer prior to updating the
	 * read index in the descriptor.
	 */
	mb();
	writel(cpu_to_le32(rd_idx), &ring_descr->input_read_index);

	mod_timer(&pci_cons->tty.poll_timer,
		  jiffies + PCI_CONS_TTY_POLL_INTERVAL_JIFFIES);
}

/*
 * Linux TTY driver callback.
 */
static int pci_console_dev_tty_open(struct tty_struct *tty, struct file *filp)
{
	struct pci_console *pci_cons = tty->driver->driver_state;
	struct device *dev = pci_cons->device;

	dbgmsg(dev, "%s: entry\n", __func__);

	if (!pci_cons->tty.open_count++) {
		dbgmsg(dev, "Scheduling timer...\n");
		init_timer(&pci_cons->tty.poll_timer);
		pci_cons->tty.poll_timer.data = (unsigned long)tty;
		pci_cons->tty.poll_timer.function = pci_console_dev_tty_poll;
		mod_timer(&pci_cons->tty.poll_timer,
			  jiffies + PCI_CONS_TTY_POLL_INTERVAL_JIFFIES);
	}

	return 0;
}

/*
 * Linux TTY driver callback.
 */
static void pci_console_dev_tty_close(struct tty_struct *tty,
				      struct file *filp)
{
	struct pci_console *pci_cons = tty->driver->driver_state;
	struct device *dev = pci_cons->device;

	dbgmsg(dev, "%s: entry\n", __func__);

	if (--pci_cons->tty.open_count == 0) {
		dbgmsg(dev, "Deleting timer...\n");
		del_timer(&pci_cons->tty.poll_timer);
	}
}

/*
 * Linux TTY driver callback.
 */
static int pci_console_dev_tty_write(struct tty_struct *tty,
				     const unsigned char *buf, int count)
{
	struct pci_console *pci_cons = tty->driver->driver_state;
	struct device *dev = pci_cons->device;
	struct octeontx_pcie_console __iomem *ring_descr;
	u8 __iomem *output_ring;
	u32 cons_idx;

	ring_descr = pci_cons->ring_descr;
	output_ring = pci_cons->output_ring;

	cons_idx = le32_to_cpu(readl(&ring_descr->host.cons_idx));

	return octeontx_console_write(dev, buf, count, ring_descr,
				      output_ring,
				      &pci_cons->excl_lock[cons_idx]);
}

static int pci_console_dev_tty_write_room(struct tty_struct *tty)
{
	struct pci_console *pci_cons = tty->driver->driver_state;

	/* Assume maximum space is available; write function will wait for
	 * available room, if necessary.
	 */
	return pci_cons->ring_descr->output_buf_size - 1;
}

static int pci_console_dev_tty_chars_in_buffer(struct tty_struct *tty)
{
	struct pci_console *pci_cons = tty->driver->driver_state;

	(void)pci_cons;

	/* We do not buffer any data - zero chars in buffer */
	return 0;
}

static void pci_console_dev_tty_send_xchar(struct tty_struct *tty, char ch)
{
	pci_console_dev_tty_write(tty, (const u8 *)&ch, sizeof(ch));
}

