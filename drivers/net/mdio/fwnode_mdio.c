// SPDX-License-Identifier: GPL-2.0-only
/*
 * fwnode helpers for the MDIO (Ethernet PHY) API
 *
 * This file provides helper functions for extracting PHY device information
 * out of the fwnode and using it to populate an mii_bus.
 */

#include <linux/acpi.h>
#include <linux/fwnode_mdio.h>
#include <linux/of.h>
#include <linux/phy.h>

MODULE_AUTHOR("Calvin Johnson <calvin.johnson@oss.nxp.com>");
MODULE_LICENSE("GPL");

static struct mii_timestamper *
fwnode_find_mii_timestamper(struct fwnode_handle *fwnode)
{
	struct of_phandle_args arg;
	int err;

	if (is_acpi_node(fwnode))
		return NULL;

	err = of_parse_phandle_with_fixed_args(to_of_node(fwnode),
					       "timestamper", 1, 0, &arg);
	if (err == -ENOENT)
		return NULL;
	else if (err)
		return ERR_PTR(err);

	if (arg.args_count != 1)
		return ERR_PTR(-EINVAL);

	return register_mii_timestamper(arg.np, arg.args[0]);
}

int fwnode_mdiobus_phy_device_register(struct mii_bus *mdio,
				       struct phy_device *phy,
				       struct fwnode_handle *child, u32 addr)
{
	int rc;

	rc = fwnode_irq_get(child, 0);
	/* Don't wait forever if the IRQ provider doesn't become available,
	 * just fall back to poll mode
	 */
	if (rc == -EPROBE_DEFER)
		rc = driver_deferred_probe_check_state(&phy->mdio.dev);
	if (rc == -EPROBE_DEFER)
		return rc;

	if (rc > 0) {
		phy->irq = rc;
		mdio->irq[addr] = rc;
	} else {
		phy->irq = mdio->irq[addr];
	}

	if (fwnode_property_read_bool(child, "broken-turn-around"))
		mdio->phy_ignore_ta_mask |= 1 << addr;

	fwnode_property_read_u32(child, "reset-assert-us",
				 &phy->mdio.reset_assert_delay);
	fwnode_property_read_u32(child, "reset-deassert-us",
				 &phy->mdio.reset_deassert_delay);

	/* Associate the fwnode with the device structure so it
	 * can be looked up later
	 */
	fwnode_handle_get(child);
	device_set_node(&phy->mdio.dev, child);

	/* All data is now stored in the phy struct;
	 * register it
	 */
	rc = phy_device_register(phy);
	if (rc) {
		device_set_node(&phy->mdio.dev, NULL);
		fwnode_handle_put(child);
		return rc;
	}

	dev_dbg(&mdio->dev, "registered phy %p fwnode at address %i\n",
		child, addr);
	return 0;
}
EXPORT_SYMBOL(fwnode_mdiobus_phy_device_register);

int fwnode_mdiobus_register_phy(struct mii_bus *bus,
				struct fwnode_handle *child, u32 addr)
{
	struct mii_timestamper *mii_ts = NULL;
	struct phy_device *phy;
	bool is_c45 = false;
	u32 phy_id;
	int rc;

	mii_ts = fwnode_find_mii_timestamper(child);
	if (IS_ERR(mii_ts))
		return PTR_ERR(mii_ts);

	rc = fwnode_property_match_string(child, "compatible",
					  "ethernet-phy-ieee802.3-c45");
	if (rc >= 0)
		is_c45 = true;

	if (is_c45 || fwnode_get_phy_id(child, &phy_id))
		phy = get_phy_device(bus, addr, is_c45);
	else
		phy = phy_device_create(bus, addr, phy_id, 0, NULL);
	if (IS_ERR(phy)) {
		struct phy_c45_device_ids c45_ids = {0};
		phy = phy_device_create(bus, addr, 0, is_c45, &c45_ids);
		if (IS_ERR(phy)) {
			dev_err(&bus->dev, "cannot create PHY at address %i\n",
				addr);
			rc = PTR_ERR(phy);
			goto clean_mii_ts;
		}
	}

	if (is_acpi_node(child)) {
		phy->irq = bus->irq[addr];

		/* Associate the fwnode with the device structure so it
		 * can be looked up later.
		 */
		phy->mdio.dev.fwnode = fwnode_handle_get(child);

		/* All data is now stored in the phy struct, so register it */
		rc = phy_device_register(phy);
		if (rc) {
			phy->mdio.dev.fwnode = NULL;
			fwnode_handle_put(child);
			goto clean_phy;
		}
	} else if (is_of_node(child)) {
		rc = fwnode_mdiobus_phy_device_register(bus, phy, child, addr);
		if (rc)
			goto clean_phy;
	}

	/* phy->mii_ts may already be defined by the PHY driver. A
	 * mii_timestamper probed via the device tree will still have
	 * precedence.
	 */
	if (mii_ts)
		phy->mii_ts = mii_ts;
	return 0;

clean_phy:
	phy_device_free(phy);
clean_mii_ts:
	unregister_mii_timestamper(mii_ts);

	return rc;
}
EXPORT_SYMBOL(fwnode_mdiobus_register_phy);
