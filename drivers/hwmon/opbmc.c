// SPDX-License-Identifier: GPL-2.0
/*
 * Oracle Pilot Board Management Controller (BMC) driver
 *
 * Author: Eric Snowberg <eric.snowberg@oracle.com>
 */
#include <asm/io.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#define MODULE_NAME		"opbmc"
#define OPBMC_MSG_PREFIX	"Oracle ILOM"
#define OPBMC_IO_BAR		0xFD110000
#define OPBMC_PAD_CFG_GPP_A0	0x400
#define OPBMC_PAD_OFFSET	0x0c
#define OPBMC_GPP_PAGE_ADDR	0xFED81500  /* size 0x400 */
#define OPBMC_GPP_ADDR		0xFED81514

static struct platform_device *opbmc_pdev;

static const struct dmi_system_id oracle_pilot_bmc_table[] = {
	{
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Oracle Corporation"),
			DMI_MATCH(DMI_PRODUCT_NAME, "ORACLE SERVER X7"),
		},
	},
	{
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Oracle Corporation"),
			DMI_MATCH(DMI_PRODUCT_NAME, "ORACLE SERVER X8"),
		},
	},
	{
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Oracle Corporation"),
			DMI_MATCH(DMI_PRODUCT_NAME, "ORACLE SERVER X9"),
		},
	},
	{}
};

static const struct dmi_system_id oracle_AST2600_bmc_table[] = {
	{
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Oracle Corporation"),
			DMI_MATCH(DMI_PRODUCT_NAME, "ORACLE SERVER E5"),
		},
	},
	{}
};

static int reset_sp_ast2600(void)
{
	void __iomem *mem;
	u8 resetbyte;
	int rc = 0;

	if (!request_mem_region(OPBMC_GPP_PAGE_ADDR, 0x400, MODULE_NAME)) {
		pr_err(MODULE_NAME ": Cannot reserve memory region.\n");
		rc = -ENXIO;
		goto err_mem;
	}

	mem = ioremap(OPBMC_GPP_PAGE_ADDR, 0x400);
	if (!mem) {
		rc = -ENXIO;
		goto err_mem;
	}

	/* If the reset bit is active, reset it, as well as the status bit. */
	resetbyte = ioread8(mem + 0x16);
	if (resetbyte & 0x40) {
		pr_info_ratelimited(OPBMC_MSG_PREFIX
			" reset bit set already (%02X).\n", resetbyte);
		iowrite8(resetbyte & ~0x41, mem + 0x16);
		resetbyte = ioread8(mem + 0x16);
		/* Shorter or no delay is unreliable. */
		udelay(20);
	}

	/* Set the reset bit and read it back. */
	iowrite8(resetbyte | 0x40, mem + 0x16);
	resetbyte = ioread8(mem + 0x16);

	/* Minimal measured peak length is 18us for a loaded SP.
	 * Using 3x more to be sure.
	 */
	udelay(60);

	/* Reset bit off. */
	iowrite8(resetbyte ^ 0x40, mem + 0x16);
	resetbyte = ioread8(mem + 0x16);
	if (resetbyte & 0x40)
		pr_notice_ratelimited(OPBMC_MSG_PREFIX
			" reset bit left set (%02X).\n", resetbyte);

	iounmap(mem);
	pr_info_ratelimited(OPBMC_MSG_PREFIX " reset.\n");

err_mem:
	release_mem_region(OPBMC_GPP_PAGE_ADDR, 0x400);
	return rc;
}

static int reset_sp_pilot(void)
{
	void __iomem *mem;
	u32 padbar;
	int rc;
	u8 val;

	if (!request_mem_region(OPBMC_IO_BAR, 0x1000, MODULE_NAME)) {
		pr_err(MODULE_NAME ": Invalid region\n");
		rc = -ENXIO;
		return rc;
	}

	mem = ioremap(OPBMC_IO_BAR, 0x1000);

	if (!mem) {
		rc = -ENXIO;
		goto err_mem;
	}

	padbar = ioread32(mem + OPBMC_PAD_OFFSET);

	if (padbar != OPBMC_PAD_CFG_GPP_A0) {
		pr_err(MODULE_NAME
			": PADBAR %08x not as expected: %08x\n",
			padbar, OPBMC_PAD_CFG_GPP_A0);
		rc = -EINVAL;
		goto err;
	}

	val = ioread8(mem + OPBMC_PAD_CFG_GPP_A0);
	iowrite8(val & 0xFE, mem + OPBMC_PAD_CFG_GPP_A0);
	udelay(60);
	val = ioread8(mem + OPBMC_PAD_CFG_GPP_A0);
	iowrite8(val | 1, mem + OPBMC_PAD_CFG_GPP_A0);
	udelay(60);
	val = ioread8(mem + OPBMC_PAD_CFG_GPP_A0);
	iowrite8(val & 0xFE, mem + OPBMC_PAD_CFG_GPP_A0);
	pr_info_ratelimited(OPBMC_MSG_PREFIX " reset.\n");

err:
	iounmap(mem);
err_mem:
	release_mem_region(OPBMC_IO_BAR, 0x1000);
	return 0;
}


static ssize_t reset_bmc(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	int val, err = 0;

	if (kstrtos32(buf, 0, &val))
		return -EINVAL;

	if (val == 1) {
		if (dmi_check_system(oracle_pilot_bmc_table))
			err = reset_sp_pilot();
		else if (dmi_check_system(oracle_AST2600_bmc_table))
			err = reset_sp_ast2600();
		else
			pr_err(MODULE_NAME ": Platform not identified\n");
	}

	if (err)
		return err;

	return count;
}

static struct kobj_attribute opbmc_reset_attribute =
	__ATTR(reset, 0200, 0, reset_bmc);

static struct attribute *opbmc_reset_attrs[] = {
	&opbmc_reset_attribute.attr,
	NULL,
};

static struct attribute_group opbmc_reset_attr_group = {
	.attrs = opbmc_reset_attrs,
};

static int opbmc_plat_probe(struct platform_device *dev)
{
	return sysfs_create_group(&dev->dev.kobj, &opbmc_reset_attr_group);
}

static void opbmc_plat_remove(struct platform_device *dev)
{
	sysfs_remove_group(&dev->dev.kobj, &opbmc_reset_attr_group);
}

static struct platform_driver opbmc_plat_driver = {
	.driver		= {
		.name	= MODULE_NAME,
	},
	.probe		= opbmc_plat_probe,
	.remove_new	= opbmc_plat_remove,
};

static int opbmc_probe(void)
{

	int err;

	if ((dmi_check_system(oracle_pilot_bmc_table) +
	     dmi_check_system(oracle_AST2600_bmc_table)) != 1)
		return -ENODEV;

	opbmc_pdev = platform_device_alloc(MODULE_NAME, -1);

	if (!opbmc_pdev)
		return -ENOMEM;

	err = platform_device_add(opbmc_pdev);

	if (err) {
		platform_device_put(opbmc_pdev);
		opbmc_pdev = NULL;
		return err;
	}

	return err;
}

static void opbmc_remove(void)
{
	if (opbmc_pdev)
		platform_device_unregister(opbmc_pdev);
}

static int __init opbmc_init(void)
{
	int err;

	err = platform_driver_register(&opbmc_plat_driver);

	if (err)
		return err;

	err = opbmc_probe();

	if (err) {
		platform_driver_unregister(&opbmc_plat_driver);
		return err;
	}

	return err;
}

static void __exit opbmc_exit(void)
{
	platform_driver_unregister(&opbmc_plat_driver);
	opbmc_remove();
}

module_init(opbmc_init);
module_exit(opbmc_exit);

MODULE_AUTHOR("Eric Snowberg <eric.snowberg@oracle.com>");
MODULE_DESCRIPTION("Oracle Pilot BMC");
MODULE_VERSION("2.0");
MODULE_LICENSE("GPL");
