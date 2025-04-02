// SPDX-License-Identifier: GPL-2.0-or-later
/* drivers/rtc/rtc-elbacpld.c
 *
 * Driver for AMD ELBA CPLD real-time clock.
 *
 * Copyright (C) 2023 AMD Corporation
 * Author: Mushtaq Khan<Mushtaq.Khan@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Driver reads Clock and Date registers from ELBA CPLD over SPI.
 * Uses SPI regmap created by driver mfd/pensando-elbasr.c.
 *
 */
#include <linux/bcd.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/mfd/pensando-elbasr.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/rtc.h>
#include <linux/slab.h>

#define RTC_BASE_OFFSET  0xA2
/*
 * Date/Time registers
 */
#define DT_100THS       0x00
#define DT_YEARS        0x01
#define DT_MONTHS       0x02
#define DT_DATE         0x03
#define DT_HOURS        0x04
#define DT_MINUTES      0x05
#define DT_SECS         0x06
#define DT_SUBSECS      0x07
#define DT_NUMREGS	(DT_SUBSECS + 1)

struct elba_rtc {
	struct rtc_device   *rtc;
	struct regmap       *regmap;
};

static ssize_t date_reg_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct elba_rtc *rtc = dev_get_drvdata(dev);
	unsigned int reg_val, reg_offset;
	unsigned int count = 0;
	int i, ret;

	for (i = 0; i < DT_NUMREGS; i++) {
		reg_offset = RTC_BASE_OFFSET + i;
		ret = regmap_read(rtc->regmap, reg_offset, &reg_val);
		if (ret) {
			return sprintf(buf, "error %d reading offset %02X\n",
				       ret, reg_offset);
		}
		count += sprintf(buf + count, "offset:%02X BCD:%02X\n",
				 reg_offset, reg_val);
	}

	return count;
}

static DEVICE_ATTR(date_reg, DEVICE_ATTR_RO, date_reg_show, NULL);

static struct attribute *date_attr[] = {
	&dev_attr_date_reg.attr,
	NULL,
};

static struct attribute_group date_group = {
	.attrs = date_attr,
};

static int elba_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct elba_rtc *rtc = dev_get_drvdata(dev);
	unsigned char buf[DT_NUMREGS];
	int len = sizeof(buf);
	int ret;

	/* read the RTC date and time registers all at once */
	ret = regmap_bulk_read(rtc->regmap, (RTC_BASE_OFFSET + DT_100THS),
			       buf, len);
	if (ret)
		return ret;

	tm->tm_year = bcd2bin(buf[DT_YEARS]);
	/* adjust for 1900 base of rtc_time */
	tm->tm_year += 100;

	tm->tm_wday = 0;
	tm->tm_sec = bcd2bin(buf[DT_SECS]);
	tm->tm_min = bcd2bin(buf[DT_MINUTES]);
	tm->tm_hour = bcd2bin(buf[DT_HOURS]);
	tm->tm_mday = bcd2bin(buf[DT_DATE]);
	tm->tm_mon = bcd2bin(buf[DT_MONTHS]) - 1;

	return 0;
}

static const struct rtc_class_ops rtc_ops = {
	.read_time  = elba_rtc_read_time,
	.set_time   = NULL,
};

static int elbasr_rtc_probe(struct platform_device *pdev)
{
	struct elbasr_data *elbasr = dev_get_drvdata(pdev->dev.parent);
	struct elba_rtc *e_rtc;
	int ret;

	e_rtc = devm_kzalloc(&pdev->dev, sizeof(struct elba_rtc),
			GFP_KERNEL);
	if (!e_rtc)
		return -ENOMEM;

	e_rtc->regmap = elbasr->elbasr_regs;
	e_rtc->rtc = devm_rtc_allocate_device(&pdev->dev);
	if (IS_ERR(e_rtc->rtc))
		return PTR_ERR(e_rtc->rtc);

	e_rtc->rtc->ops = &rtc_ops;

	platform_set_drvdata(pdev, e_rtc);

	ret = devm_rtc_register_device(e_rtc->rtc);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register device\n");
		return ret;
	}

	ret = sysfs_create_group(&pdev->dev.kobj, &date_group);
	if (ret) {
		sysfs_remove_group(&pdev->dev.kobj, &date_group);
		dev_err(&pdev->dev, "Failed to create attr group\n");
	}

	return ret;
}

static const struct of_device_id elba_rtc_dt_match[] = {
	{ .compatible = "amd,pensando-elbasr-rtc", },
	{ /* sentinel */ },
};

static struct platform_driver elbasr_rtc_driver = {
	.driver = {
		.name = "pensando_elbasr_rtc",
		.of_match_table = elba_rtc_dt_match,
	},
	.probe  = elbasr_rtc_probe,
};

module_platform_driver(elbasr_rtc_driver);

MODULE_AUTHOR("Mushtaq Khan <Mushtaq.Khan@amd.com>");
MODULE_DESCRIPTION("elba cpld spi RTC driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
