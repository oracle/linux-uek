// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019-2021, Pensando Systems Inc.
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmsg_dump.h>
#include <linux/time.h>
#include <linux/platform_device.h>
#include <linux/of.h>

#define PCRASH_NAME	"pensando-crash"

struct pcrash_st {
	struct platform_device	*pdev;
	struct kmsg_dumper	dump;
	void __iomem		*flashbase;
	resource_size_t		size;
	void *panic_buf;
};

struct panicbuf_header {
	u32 magic;
	u32 len;
};

static struct pcrash_st *pcrash;
static u32 PANIC_SIGNATURE = 0x9D7A7318;

static void pcrash_do_dump(struct kmsg_dumper *dumper,
			   enum kmsg_dump_reason reason)
{
	int idx;
	u32 *src;
	size_t kmsg_dump_len;
	u32 __iomem *dst = (u32 *)pcrash->flashbase;
	struct panicbuf_header *hdr = pcrash->flashbase;

	/*
	 * read first 32bits, if all ff then the new panic data
	 * can be written to the panic buf.
	 */
	if (hdr->magic == 0xffffffff) {
		kmsg_dump_get_buffer(dumper, false, pcrash->panic_buf,
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
	struct tm broken;

	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec, 0, &broken);
	pr_info("Panic on %d/%d/%ld::%d:%d:%d:%03ld\n",
	       broken.tm_mon + 1, broken.tm_mday, broken.tm_year + 1900,
	       broken.tm_hour, broken.tm_min, broken.tm_sec,
	       ts.tv_nsec / 1000);
	return NOTIFY_DONE;
}

static struct notifier_block cap_panic_notifier = {
	.notifier_call = cap_panic_callback,
};

static int pcrash_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	int err;

	pcrash = devm_kzalloc(dev, sizeof(*pcrash), GFP_KERNEL);
	if (!pcrash)
		return -ENOMEM;

	pcrash->pdev = pdev;
	platform_set_drvdata(pdev, pcrash);

	pcrash->dump.max_reason = KMSG_DUMP_PANIC;
	pcrash->dump.dump = pcrash_do_dump;

	/* Obtain and remap flash address. */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pcrash->flashbase = devm_ioremap_resource(dev, res);
	if (IS_ERR(pcrash->flashbase)) {
		dev_err(dev, "Cannot remap flash address.\n");
		return PTR_ERR(pcrash->flashbase);
	}
	pcrash->size = resource_size(res);
	pcrash->panic_buf = vmalloc(pcrash->size);
	if (!pcrash->panic_buf) {
		dev_err(dev, "failed to allocate buffer workspace\n");
		return -ENOMEM;
	}
	memset(pcrash->panic_buf, 0xff, pcrash->size);
	atomic_notifier_chain_register(&panic_notifier_list,
				       &cap_panic_notifier);
	err = kmsg_dump_register(&pcrash->dump);
	if (err) {
		vfree(pcrash->panic_buf);
		dev_err(dev, "%s: registering kmsg dumper failed, error %d\n", __func__, err);
		return err;
	}
	return 0;
}

static int pcrash_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	if (kmsg_dump_unregister(&pcrash->dump) < 0)
		dev_err(dev, "could not unregister kmsg_dumper\n");
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &cap_panic_notifier);
	vfree(pcrash->panic_buf);
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
