// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019-2022, Pensando Systems Inc.
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmsg_dump.h>
#include <linux/time.h>
#include <linux/platform_device.h>
#include <linux/panic_notifier.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include "cap_reboot.h"

#define PCRASH_NAME	"pensando-crash"

struct pcrash_st {
	struct platform_device	*pdev;
	struct kmsg_dumper	dump;
	void __iomem		*ctrlbase;
	void __iomem		*flashbase;
	resource_size_t		size;
	void *panic_buf;
};

struct panicbuf_header {
	u32 magic;
	u32 len;
};

static struct pcrash_st *pcrash;
static u32 PANIC_SIGNATURE = 0x9d7a7318;

/*
 * Prepare the Cadence Quad SPI Controller for
 * memory mapped crash dump writes.
 */

#define CQSPI_REG_CONFIG                        0x00
#define CQSPI_REG_CONFIG_ENB_DIR_ACC_CTRL       BIT(7)

#define CQSPI_REG_WR_COMPLETION_CTRL            0x38
#define CQSPI_REG_WR_DISABLE_AUTO_POLL          BIT(14)

static void pcrash_prepare_controller(void)
{
	void __iomem *ctrl = pcrash->ctrlbase;
	u32 val;

	/*
	 * Re-enable the Direct Access Controller (memory-mapped access).
	 */
	val = readl(ctrl + CQSPI_REG_CONFIG);
	if (!(val & CQSPI_REG_CONFIG_ENB_DIR_ACC_CTRL)) {
		val |= CQSPI_REG_CONFIG_ENB_DIR_ACC_CTRL;
		writel(val, ctrl + CQSPI_REG_CONFIG);
	}

	/*
	 * Re-enable auto-polling, if it was disabled.
	 * This is required for memory-mapped writes.
	 */
	val = readl(ctrl + CQSPI_REG_WR_COMPLETION_CTRL);
	if (val & CQSPI_REG_WR_DISABLE_AUTO_POLL) {
		val &= ~CQSPI_REG_WR_DISABLE_AUTO_POLL;
		writel(val, ctrl + CQSPI_REG_WR_COMPLETION_CTRL);
	}

	/* readback + barrier */
	(void)readl(ctrl + CQSPI_REG_CONFIG);
	__iowmb();
}

static void pcrash_do_dump(struct kmsg_dumper *dumper,
			   enum kmsg_dump_reason reason)
{
	int idx;
	u32 *src;
	size_t kmsg_dump_len;
	struct kmsg_dump_iter iter;
	u32 __iomem *dst = (u32 *)pcrash->flashbase;
	struct panicbuf_header *hdr = pcrash->flashbase;

	/*
	 * Prepare the flash controller for memory-mapped writes.
	 */
	pcrash_prepare_controller();

	/*
	 * read first 32bits, if all ff then the new panic data
	 * can be written to the panic buf.
	 */
	if (hdr->magic == 0xffffffff) {
		kmsg_dump_rewind(&iter);
		kmsg_dump_get_buffer(&iter, false, pcrash->panic_buf,
				pcrash->size - sizeof(struct panicbuf_header), &kmsg_dump_len);

		/* write the signature to panic buf log */
		hdr->magic = PANIC_SIGNATURE;
		hdr->len = kmsg_dump_len;
		src = (u32 *)pcrash->panic_buf;
		dst = (u32 *)(hdr + 1);
		for (idx = 0; idx < roundup(kmsg_dump_len, 4) / 4; idx++)
			*dst++ = *src++;
	}
}

static int cap_panic_callback(struct notifier_block *nb,
			       unsigned long reason, void *arg)
{
	struct timespec64 ts;
	struct tm tm;

	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec, 0, &tm);
	pr_info("Panic at Boot #%lu %04ld-%02d-%02d %02d:%02d:%02d.%06ld\n",
		cap_boot_count(),
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		ts.tv_nsec / 1000);
	return NOTIFY_DONE;
}

static struct notifier_block cap_panic_notifier = {
	.notifier_call = cap_panic_callback,
};

static int pcrash_get_flash_controller(struct platform_device *pdev,
	struct resource *res)
{
	const struct device_node *np;
	struct device_node *dn;
	int err = -ENODEV;

	np = pdev->dev.of_node;
	if (np) {
		/*
		 * The pensando,crash-ctrl property should be a phandle
		 * to a pensando,elba-qspi controller.
		 * Extract its register space, if found.
		 */
		dn = of_parse_phandle(np, "pensando,crash-ctrl", 0);
		if (of_device_is_compatible(dn, "pensando,elba-qspi"))
			if (!of_address_to_resource(dn, 0, res))
				err = 0;
		of_node_put(dn);
	}
	return err;
}

static int pcrash_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource ctrlres;
	struct resource *res;
	int err = -ENODEV;

	pcrash = devm_kzalloc(dev, sizeof(*pcrash), GFP_KERNEL);
	if (!pcrash)
		return -ENOMEM;

	pcrash->pdev = pdev;
	platform_set_drvdata(pdev, pcrash);

	/* get and map the flash controller */
	if (pcrash_get_flash_controller(pdev, &ctrlres)) {
		dev_err(dev, "%s: Cannot find flash controller.\n", pdev->name);
		return -ENODEV;
	}
	pcrash->ctrlbase = ioremap(ctrlres.start, resource_size(&ctrlres));
	if (!pcrash->ctrlbase) {
		dev_err(dev, "%s: Cannot map flash controller.\n", pdev->name);
		return -ENODEV;
	}

	/* get and map the memory-mapped flash */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "%s: Memory resource not found\n", pdev->name);
		goto bail1;
	}
	pcrash->flashbase = devm_ioremap_resource(dev, res);
	if (IS_ERR(pcrash->flashbase)) {
		dev_err(dev, "%s: Cannot remap flash address.\n", pdev->name);
		err = PTR_ERR(pcrash->flashbase);
		goto bail1;
	}
	pcrash->size = resource_size(res);
	pcrash->panic_buf = vmalloc(pcrash->size);
	if (!pcrash->panic_buf) {
		dev_err(dev, "%s: Failed to allocate buffer workspace\n",
				pdev->name);
		err = -ENOMEM;
		goto bail1;
	}
	memset(pcrash->panic_buf, 0xff, pcrash->size);
	atomic_notifier_chain_register(&panic_notifier_list,
				       &cap_panic_notifier);
	pcrash->dump.max_reason = KMSG_DUMP_PANIC;
	pcrash->dump.dump = pcrash_do_dump;
	err = kmsg_dump_register(&pcrash->dump);
	if (err) {
		dev_err(dev, "%s: registering kmsg dumper failed, error %d\n",
				pdev->name, err);
		goto bail2;
	}
	return 0;
bail2:
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &cap_panic_notifier);
	vfree(pcrash->panic_buf);
bail1:
	iounmap(pcrash->ctrlbase);
	return err;
}

static int pcrash_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	if (kmsg_dump_unregister(&pcrash->dump) < 0)
		dev_err(dev, "could not unregister kmsg_dumper\n");
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &cap_panic_notifier);
	vfree(pcrash->panic_buf);
	iounmap(pcrash->ctrlbase);
	return 0;
}

static const struct of_device_id pcrash_dt_ids[] = {
	{.compatible = "pensando,capri-crash",},
	{ /* end of table */ }
};

MODULE_DEVICE_TABLE(of, pcrash_dt_ids);

static struct platform_driver pcrash_platform_driver = {
	.probe = pcrash_probe,
	.remove = pcrash_remove,
	.driver = {
		.name = PCRASH_NAME,
		.of_match_table = pcrash_dt_ids,
	},
};

module_platform_driver(pcrash_platform_driver);

MODULE_DESCRIPTION("Pensando Panic Crash Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" PCRASH_NAME);
MODULE_AUTHOR("Rahul Shekhar <rahulshekhar@pensando.io>");
