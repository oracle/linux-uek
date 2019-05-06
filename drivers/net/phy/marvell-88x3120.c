/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2015 Cavium, Inc.
 */

#include <linux/module.h>
#include <linux/phy.h>
#include <linux/of.h>

#define PHY_ID_MARVELL_88X3120 0x01405896

#define MARVELL_PMA_STATUS1 (MII_ADDR_C45 | 0x10001)
#define MARVELL_LASI_CONTROL (MII_ADDR_C45 | 0x19002)
#define MARVELL_LASI_STATUS (MII_ADDR_C45 | 0x19005)

static int m88x3120_config_init(struct phy_device *phydev)
{
	phydev->supported = SUPPORTED_10000baseR_FEC;
	phydev->advertising = ADVERTISED_10000baseR_FEC;
	phydev->state = PHY_NOLINK;
	phydev->autoneg = AUTONEG_DISABLE;

	return 0;
}

static int m88x3120_config_aneg(struct phy_device *phydev)
{
	return -EINVAL;
}

static int m88x3120_read_status(struct phy_device *phydev)
{
	int status;

	status = phy_read(phydev, MARVELL_PMA_STATUS1);

	/* Check the receive-linux-status bit */
	if ((status & 0x4) == 0)
		goto no_link;
	phydev->speed = 10000;
	phydev->link = 1;
	phydev->duplex = 1;
	return 0;

no_link:
	phydev->link = 0;
	return 0;
}

static int m88x3120_config_intr(struct phy_device *phydev)
{
	int reg, err;

	reg = phy_read(phydev, MARVELL_LASI_CONTROL);

	if (reg < 0)
		return reg;

	/* Clear RX_ALARM, TX_ALARM, and LS_ALARM ... */
	reg &= ~7;

	/* ... then set LS_ALARM if requested. */
	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		reg |= 1;

	err = phy_write(phydev, MARVELL_LASI_CONTROL, reg);
	return err;
}

static int m88x3120_did_interrupt(struct phy_device *phydev)
{
	int reg;

	reg = phy_read(phydev, MARVELL_LASI_STATUS);

	if (reg < 0) {
		dev_err(&phydev->mdio.dev,
			"Error: Read of MARVELL_LASI_STATUS failed: %d\n", reg);
		return 0;
	}
	return (reg & 1) != 0;
}

static int  m88x3120_ack_interrupt(struct phy_device *phydev)
{
	/* Reading the LASI status clears it. */
	m88x3120_did_interrupt(phydev);
	return 0;
}

static int m88x3120_match_phy_device(struct phy_device *phydev)
{
	return phydev->c45_ids.device_ids[1] == PHY_ID_MARVELL_88X3120;
}

static struct phy_driver m88x3120_driver[] = {
{
	.phy_id		= 0,
	.phy_id_mask	= 0,
	.name		= "Marvell 88X3120",
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= m88x3120_config_init,
	.config_aneg	= m88x3120_config_aneg,
	.read_status	= m88x3120_read_status,
	.ack_interrupt	= m88x3120_ack_interrupt,
	.config_intr	= m88x3120_config_intr,
	.did_interrupt	= m88x3120_did_interrupt,
	.match_phy_device = m88x3120_match_phy_device,
} };

static int __init m88x3120_init(void)
{
	return phy_drivers_register(m88x3120_driver,
				    ARRAY_SIZE(m88x3120_driver),
				    THIS_MODULE);
}
module_init(m88x3120_init);

static void __exit m88x3120_exit(void)
{
	phy_drivers_unregister(m88x3120_driver,
		ARRAY_SIZE(m88x3120_driver));
}
module_exit(m88x3120_exit);

MODULE_LICENSE("GPL");
