/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012 - 2014 Cavium, Inc.
 */

#include <linux/platform_device.h>
#include <linux/of_mdio.h>
#include <linux/of_gpio.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/phy.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#define PMD_RX_SIGNAL_DETECT		(MII_ADDR_C45 | 0x01000a)
#define LT_TRAIN_CONTROL		(MII_ADDR_C45 | 0x010096)

#define BASER_PCS_STATUS		(MII_ADDR_C45 | 0x030020)

#define AN_CONTROL			(MII_ADDR_C45 | 0x070000)

#define CHANNEL_CONTROL_1		(MII_ADDR_C45 | 0x1e0001)
#define RESET_CONTROL			(MII_ADDR_C45 | 0x1e000e)
#define HS_CH_CONTROL_1			(MII_ADDR_C45 | 0x1e001d)
#define TI_RESERVED_20			(MII_ADDR_C45 | 0x1e8020)

struct tlk10232_nexus_mdiobus {
	struct mii_bus *mii_bus;
	struct mii_bus *parent_mii_bus;
	int reg_offset;
	struct mutex lock;	/* Lock used for global register sequences */
	int phy_irq[PHY_MAX_ADDR];
};

struct tlk10232_phy {
	int tx_disable_gpio;
};

static int tlk10232_probe(struct phy_device *phydev)
{
	enum of_gpio_flags f;
	int ret;
	struct tlk10232_phy *priv;

	priv = devm_kzalloc(&phydev->mdio.dev, sizeof(*priv), GFP_KERNEL);
	if (priv == NULL)
		return -ENOMEM;
	phydev->priv = priv;

	priv->tx_disable_gpio = of_get_named_gpio_flags(phydev->mdio.dev.of_node,
							"tx-disable", 0, &f);
	if (priv->tx_disable_gpio >= 0) {
		ret = gpio_request(priv->tx_disable_gpio, "phy tx-disable");
		if (ret) {
			dev_err(&phydev->mdio.dev,
				"Error: could not request tx-disable gpio.\n");
			return ret;
		}
		gpio_direction_output(priv->tx_disable_gpio, 1);
	}
	return 0;
}

static void tlk10232_remove(struct phy_device *phydev)
{
}

static int tlk10232_config_init(struct phy_device *phydev)
{
	struct tlk10232_phy *priv = phydev->priv;
	int ret, v;

	phydev->supported = SUPPORTED_10000baseR_FEC;
	phydev->advertising = ADVERTISED_10000baseR_FEC;
	phydev->state = PHY_NOLINK;

	if (priv->tx_disable_gpio >= 0)
		gpio_set_value_cansleep(priv->tx_disable_gpio, 0);

	ret =  phy_read(phydev, CHANNEL_CONTROL_1);
	if (ret < 0)
		goto err;
	v = ret | 1; /* REFCLK_1_P/N as clock */
	ret = phy_write(phydev, CHANNEL_CONTROL_1, v);
	if (ret < 0)
		goto err;

	ret =  phy_read(phydev, HS_CH_CONTROL_1);
	if (ret < 0)
		goto err;
	v = ret | 0x1000; /* REFCLK = 312.5MHz */
	ret = phy_write(phydev, HS_CH_CONTROL_1, v);
	if (ret < 0)
		goto err;

	ret =  phy_read(phydev, AN_CONTROL);
	if (ret < 0)
		goto err;
	v  = ret & 0xefff; /* disable autonegotiation */
	ret = phy_write(phydev, AN_CONTROL, v);
	if (ret < 0)
		goto err;

	ret =  phy_read(phydev, LT_TRAIN_CONTROL);
	if (ret < 0)
		goto err;
	v  = ret & 0xfffd; /* turn off LT_TRAINING_ENABLE */
	ret = phy_write(phydev, LT_TRAIN_CONTROL, v);
	if (ret < 0)
		goto err;

	v = 3; /* Magic */
	ret = phy_write(phydev, TI_RESERVED_20, v);
	if (ret < 0)
		goto err;

	ret =  phy_read(phydev, RESET_CONTROL);
	if (ret < 0)
		goto err;
	v  = ret | 8; /* Reset channel */
	ret = phy_write(phydev, RESET_CONTROL, v);
	if (ret < 0)
		goto err;

	return 0;
err:
	return ret;
}

static int tlk10232_config_aneg(struct phy_device *phydev)
{
	return -EINVAL;
}

static int tlk10232_read_status(struct phy_device *phydev)
{
	int rx_signal_detect;
	int pcs_status;

	rx_signal_detect = phy_read(phydev, PMD_RX_SIGNAL_DETECT);
	if (rx_signal_detect < 0)
		return rx_signal_detect;

	if ((rx_signal_detect & 1) == 0)
		goto no_link;

	pcs_status = phy_read(phydev, BASER_PCS_STATUS);
	if (pcs_status < 0)
		return pcs_status;

	if ((pcs_status & 1) == 0)
		goto no_link;

	phydev->speed = 10000;
	phydev->link = 1;
	phydev->duplex = 1;
	return 0;
no_link:
	phydev->link = 0;
	return 0;
}

static struct of_device_id tlk10232_match[] = {
	{
		.compatible = "ti,tlk10232",
	},
	{},
};
MODULE_DEVICE_TABLE(of, tlk10232_match);

static struct phy_driver tlk10232_phy_driver = {
	.phy_id		= 0x40005100,
	.phy_id_mask	= 0xfffffff0,
	.name		= "TI TLK10232",
	.config_init	= tlk10232_config_init,
	.probe		= tlk10232_probe,
	.remove		= tlk10232_remove,
	.config_aneg	= tlk10232_config_aneg,
	.read_status	= tlk10232_read_status,
	.mdiodrv.driver	= {
		 .of_match_table = tlk10232_match,
	},
};

/* Phy nexus support below. */

static int tlk10232_nexus_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct tlk10232_nexus_mdiobus *p = bus->priv;
	return p->parent_mii_bus->read(p->parent_mii_bus,
				       phy_id + p->reg_offset,
				       regnum);
}

static int tlk10232_nexus_write(struct mii_bus *bus, int phy_id,
			       int regnum, u16 val)
{
	struct tlk10232_nexus_mdiobus *p = bus->priv;
	return p->parent_mii_bus->write(p->parent_mii_bus,
					phy_id + p->reg_offset,
					regnum, val);
}

static int tlk10232_nexus_probe(struct platform_device *pdev)
{
	struct tlk10232_nexus_mdiobus *bus;
	const char *bus_id;
	int len;
	enum of_gpio_flags f;
	int ret = 0;
	int reset_gpio;
	struct device_node *child;

	/* Check to see if drivers are installed for our GPIOS, defer
	 * probing if they are not
	 */
	reset_gpio = of_get_named_gpio_flags(pdev->dev.of_node, "reset", 0, &f);
	if (reset_gpio == -EPROBE_DEFER)
		return reset_gpio;

	for_each_available_child_of_node(pdev->dev.of_node, child) {
		ret = of_get_named_gpio_flags(child, "tx-disable", 0, &f);
		if (ret == -EPROBE_DEFER)
			return ret;
	}

	bus = devm_kzalloc(&pdev->dev, sizeof(*bus), GFP_KERNEL);
	if (!bus)
		return -ENOMEM;

	bus->parent_mii_bus = container_of(pdev->dev.parent,
					   struct mii_bus, dev);

	/* The PHY nexux  must have a reg property in the range [0-31] */
	ret = of_property_read_u32(pdev->dev.of_node, "reg", &bus->reg_offset);
	if (ret) {
		dev_err(&pdev->dev, "%s has invalid PHY address\n",
			pdev->dev.of_node->full_name);
		return ret;
	}

	bus->mii_bus = mdiobus_alloc();
	if (!bus->mii_bus)
		return -ENOMEM;

	bus->mii_bus->priv = bus;
	/* bus->mii_bus->irq = bus->phy_irq; */
	bus->mii_bus->name = "tlk10232_nexus";
	bus_id = bus->parent_mii_bus->id;
	len = strlen(bus_id);
	if (len > MII_BUS_ID_SIZE - 4)
		bus_id += len - (MII_BUS_ID_SIZE - 4);
	snprintf(bus->mii_bus->id, MII_BUS_ID_SIZE, "%s:%02x",
		 bus_id, bus->reg_offset);
	bus->mii_bus->parent = &pdev->dev;

	bus->mii_bus->read = tlk10232_nexus_read;
	bus->mii_bus->write = tlk10232_nexus_write;
	mutex_init(&bus->lock);

	dev_set_drvdata(&pdev->dev, bus);

	if (reset_gpio >= 0) {
		unsigned long flags;
		flags = (f & OF_GPIO_SINGLE_ENDED) ? GPIOF_OPEN_DRAIN : 0;
		ret = gpio_request_one(reset_gpio, flags, "phy-reset");
		if (ret) {
			dev_err(&pdev->dev, "Error requesting reset gpio.\n");
			goto fail_register;
		}
		ret = gpio_direction_output(reset_gpio, 1);
		if (ret) {
			dev_err(&pdev->dev,
				"Error setting direciton of reset gpio.\n");
			goto fail_register;
		}
		gpio_set_value_cansleep(reset_gpio, 0);
		udelay(100);
		gpio_set_value_cansleep(reset_gpio, 1);
	}
	ret = of_mdiobus_register(bus->mii_bus, pdev->dev.of_node);
	if (ret) {
		dev_err(&pdev->dev, "Error registering with device tree\n");
		goto fail_register;
	}

	return 0;

fail_register:
	dev_err(&pdev->dev, "Failed to register\n");
	mdiobus_free(bus->mii_bus);
	return ret;
}

static int tlk10232_nexus_remove(struct platform_device *pdev)
{
	return 0;
}

static struct of_device_id tlk10232_nexus_match[] = {
	{
		.compatible = "ti,tlk10232-nexus",
	},
	{},
};
MODULE_DEVICE_TABLE(of, tlk10232_nexus_match);

static struct platform_driver tlk10232_nexus_driver = {
	.driver = {
		.name		= "tlk10232-nexus",
		.owner		= THIS_MODULE,
		.of_match_table = tlk10232_nexus_match,
	},
	.probe		= tlk10232_nexus_probe,
	.remove		= tlk10232_nexus_remove,
};

static int __init tlk10232_mod_init(void)
{
	int rv;

	rv = platform_driver_register(&tlk10232_nexus_driver);
	if (rv)
		return rv;

	rv = phy_driver_register(&tlk10232_phy_driver, THIS_MODULE);

	return rv;
}
module_init(tlk10232_mod_init);

static void __exit tlk10232_mod_exit(void)
{
	phy_driver_unregister(&tlk10232_phy_driver);

	platform_driver_unregister(&tlk10232_nexus_driver);
}
module_exit(tlk10232_mod_exit);

MODULE_DESCRIPTION("Driver for TI TLK10232 PHY");
MODULE_AUTHOR("David Daney and Aaron Williams");
MODULE_LICENSE("GPL");
