
/*
 * Copyright (c) 2020, Pensando Systems Inc.
 */

#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * pin:	     3		  2	   |	   1		0
 * bit:	 7------6------5------4----|---3------2------1------0
 *	cs1  cs1_ovr  cs0  cs0_ovr |  cs1  cs1_ovr  cs0	 cs0_ovr
 *		   ssi1		   |		 ssi0
 */
#define SPICS_PIN_SHIFT(pin)	(2 * (pin))
#define SPICS_MASK(pin)		(0x3 << SPICS_PIN_SHIFT(pin))
#define SPICS_SET(pin, val)	((((val) << 1) | 0x1) << SPICS_PIN_SHIFT(pin))

struct elba_spics_priv {
	void __iomem *base;
	spinlock_t lock;
	struct gpio_chip chip;
};

static int elba_spics_get_value(struct gpio_chip *chip, unsigned pin)
{
	return -ENXIO;
}

static void elba_spics_set_value(struct gpio_chip *chip,
		unsigned pin, int value)
{
	struct elba_spics_priv *p = gpiochip_get_data(chip);
	unsigned long flags;
	u32 tmp;

	/* select chip select from register */
	spin_lock_irqsave(&p->lock, flags);
	tmp = readl_relaxed(p->base);
	tmp = (tmp & ~SPICS_MASK(pin)) | SPICS_SET(pin, value);
	writel_relaxed(tmp, p->base);
	spin_unlock_irqrestore(&p->lock, flags);
}

static int elba_spics_direction_input(struct gpio_chip *chip, unsigned pin)
{
	return -ENXIO;
}

static int elba_spics_direction_output(struct gpio_chip *chip,
		unsigned pin, int value)
{
	elba_spics_set_value(chip, pin, value);
	return 0;
}

static int elba_spics_probe(struct platform_device *pdev)
{
	struct elba_spics_priv *p;
	struct resource *res;
	int ret;

	p = devm_kzalloc(&pdev->dev, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	p->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(p->base)) {
		dev_err(&pdev->dev, "failed to remap I/O memory\n");
		return PTR_ERR(p->base);
	}
	spin_lock_init(&p->lock);
	platform_set_drvdata(pdev, p);

	p->chip.ngpio = 4;	/* 2 cs pins for spi0, and 2 for spi1 */
	p->chip.base = -1;
	p->chip.direction_input = elba_spics_direction_input;
	p->chip.direction_output = elba_spics_direction_output;
	p->chip.get = elba_spics_get_value;
	p->chip.set = elba_spics_set_value;
	p->chip.label = dev_name(&pdev->dev);
	p->chip.parent = &pdev->dev;
	p->chip.owner = THIS_MODULE;

	ret = devm_gpiochip_add_data(&pdev->dev, &p->chip, p);
	if (ret) {
		dev_err(&pdev->dev, "unable to add gpio chip\n");
		return ret;
	}

	dev_info(&pdev->dev, "elba spics registered\n");
	return 0;
}

static const struct of_device_id ebla_spics_of_match[] = {
	{ .compatible = "pensando,elba-spics" },
	{}
};

static struct platform_driver elba_spics_driver = {
	.probe = elba_spics_probe,
	.driver = {
		.name = "pensando-elba-spics",
		.of_match_table = ebla_spics_of_match,
	},
};
module_platform_driver(elba_spics_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Elba SPI chip-select driver");
