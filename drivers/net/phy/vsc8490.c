/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2015 Cavium, Inc.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>

#define PHY_ID_VSC8490			0x0000070400

#define PMA_CTRL1			(MII_ADDR_C45 | 0x01 << 16 | 0x0000)
#define PMA_STATUS			(MII_ADDR_C45 | 0x01 << 16 | 0x000a)

#define PCS_STATUS			(MII_ADDR_C45 | 0x03 << 16 | 0xe10d)

#define PHYXS_STATUS			(MII_ADDR_C45 | 0x04 << 16 | 0x0018)


enum channel_mode {
	INVALID,
	RXAUI,
	XAUI,
	SGMII
};


struct vsc8490_phy_info {
	enum channel_mode	mode;
};

struct vsc8490_nexus_mdiobus {
	struct mii_bus *mii_bus;
	struct mii_bus *parent_mii_bus;
	int reg_offset;
	struct mutex lock;	/* Lock used for global register sequences */
	int phy_irq[PHY_MAX_ADDR];
};

static int vsc8490_probe(struct phy_device *phydev)
{
	struct vsc8490_phy_info	*dev_info;
	const char		*p;
	int			rc;

	dev_info = devm_kzalloc(&phydev->mdio.dev, sizeof(*dev_info), GFP_KERNEL);
	if (dev_info == NULL)
		return -ENOMEM;

	rc = of_property_read_string(phydev->mdio.dev.of_node, "vitesse,phy-mode",
				     &p);
	if (rc) {
		kfree(dev_info);
		return -ENODEV;
	}

	if (!strcmp(p, "sgmii"))
		dev_info->mode = SGMII;
	else  if (!strcmp(p, "rxaui"))
		dev_info->mode = RXAUI;
	else  if (!strcmp(p, "xaui"))
		dev_info->mode = XAUI;
	else
		dev_info->mode = INVALID;

	phydev->priv = dev_info;

	return 0;
}

static void vsc8490_remove(struct phy_device *phydev)
{
	struct vsc8490_phy_info *dev_info = phydev->priv;

	kfree(dev_info);
}

static int vsc8490_config_aneg(struct phy_device *phydev)
{
	return 0;
}

static int vsc8490_read_status(struct phy_device *phydev)
{
	struct vsc8490_phy_info	*dev_info = phydev->priv;
	int			reg;

	phydev->duplex = 1;
	phydev->link = 0;

	if (dev_info->mode == XAUI || dev_info->mode == RXAUI) {
		phydev->speed = 10000;

		reg = phy_read(phydev, PMA_CTRL1);
		if ((reg & 0x207c) == 0x2040) {
			reg = phy_read(phydev, PMA_STATUS);
			if (reg & 1) {
				reg = phy_read(phydev, PHYXS_STATUS);
				if (reg & 0x1000)
					phydev->link = 1;
			}
		}
	} else if (dev_info->mode == SGMII) {
		phydev->speed = 1000;

		reg = phy_read(phydev, PCS_STATUS);
		if ((reg & 0x111) == 0x111)
			phydev->link = 1;
	}

	return 0;
}

static int vsc8490_match_phy_device(struct phy_device *phydev)
{
	return (phydev->c45_ids.device_ids[1] & 0xfffffff0) == PHY_ID_VSC8490;
}

static struct phy_driver vsc8490_driver = {
	.phy_id			= 0,
	.phy_id_mask		= 0,
	.name			= "Vitesse VSC8490",
	.probe			= vsc8490_probe,
	.remove			= vsc8490_remove,
	.config_aneg		= vsc8490_config_aneg,
	.read_status		= vsc8490_read_status,
	.match_phy_device	= vsc8490_match_phy_device,
};

static int vsc8490_nexus_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct vsc8490_nexus_mdiobus *p = bus->priv;
	return p->parent_mii_bus->read(p->parent_mii_bus,
				       phy_id + p->reg_offset,
				       regnum);
}

static int vsc8490_nexus_write(struct mii_bus *bus, int phy_id,
			       int regnum, u16 val)
{
	struct vsc8490_nexus_mdiobus *p = bus->priv;
	return p->parent_mii_bus->write(p->parent_mii_bus,
					phy_id + p->reg_offset,
					regnum, val);
}

static int vsc8490_nexus_probe(struct platform_device *pdev)
{
	struct vsc8490_nexus_mdiobus *bus;
	const char *bus_id;
	int len;
	int err = 0;

	bus = devm_kzalloc(&pdev->dev, sizeof(*bus), GFP_KERNEL);
	if (!bus)
		return -ENOMEM;

	bus->parent_mii_bus = container_of(pdev->dev.parent,
					   struct mii_bus, dev);

	/* The PHY nexux  must have a reg property in the range [0-31] */
	err = of_property_read_u32(pdev->dev.of_node, "reg", &bus->reg_offset);
	if (err) {
		dev_err(&pdev->dev, "%s has invalid PHY address\n",
			pdev->dev.of_node->full_name);
		return err;
	}

	bus->mii_bus = mdiobus_alloc();
	if (!bus->mii_bus)
		return -ENOMEM;

	bus->mii_bus->priv = bus;
	bus->mii_bus->name = "vsc8490_nexus";
	bus_id = bus->parent_mii_bus->id;
	len = strlen(bus_id);
	if (len > MII_BUS_ID_SIZE - 4)
		bus_id += len - (MII_BUS_ID_SIZE - 4);
	snprintf(bus->mii_bus->id, MII_BUS_ID_SIZE, "%s:%02x",
		 bus_id, bus->reg_offset);
	bus->mii_bus->parent = &pdev->dev;

	bus->mii_bus->read = vsc8490_nexus_read;
	bus->mii_bus->write = vsc8490_nexus_write;
	mutex_init(&bus->lock);

	dev_set_drvdata(&pdev->dev, bus);

	err = of_mdiobus_register(bus->mii_bus, pdev->dev.of_node);
	if (err) {
		dev_err(&pdev->dev, "Error registering with device tree\n");
		goto fail_register;
	}

	return 0;

fail_register:
	dev_err(&pdev->dev, "Failed to register\n");
	mdiobus_free(bus->mii_bus);
	return err;
}

static int vsc8490_nexus_remove(struct platform_device *pdev)
{
	return 0;
}

static struct of_device_id vsc8490_nexus_match[] = {
	{
		.compatible = "vitesse,vsc8490-nexus",
	},
	{},
};
MODULE_DEVICE_TABLE(of, vsc8490_nexus_match);

static struct platform_driver vsc8490_nexus_driver = {
	.driver = {
		.name		= "vsc8490-nexus",
		.owner		= THIS_MODULE,
		.of_match_table = vsc8490_nexus_match,
	},
	.probe		= vsc8490_nexus_probe,
	.remove		= vsc8490_nexus_remove,
};

static int __init vsc8490_init(void)
{
	int	rc;

	rc = platform_driver_register(&vsc8490_nexus_driver);
	if (rc)
		return rc;

	rc = phy_driver_register(&vsc8490_driver, THIS_MODULE);

	return rc;
}
module_init(vsc8490_init);

static void __exit vsc8490_exit(void)
{
	phy_driver_unregister(&vsc8490_driver);
}
module_exit(vsc8490_exit);

MODULE_AUTHOR("Carlos Munoz <cmunoz@caviumnetworks.com>");
MODULE_LICENSE("GPL");
