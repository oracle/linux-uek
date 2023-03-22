// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009-2016 Cavium, Inc.
 */

#include <linux/of_address.h>
#include <linux/of_mdio.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/phy.h>
#include <linux/io.h>
#include <linux/acpi.h>
#include <linux/pci.h>

#include "mdio-cavium.h"

struct thunder_mdiobus_nexus {
	void __iomem *bar0;
	struct cavium_mdiobus *buses[4];
};

#define _calc_clk_freq(_phase) (100000000U / (2 * (_phase)))
#define _calc_sample(_phase) (2 * (_phase) - 3)

#define PHASE_MIN 3
#define PHASE_DFLT 16
#define DFLT_CLK_FREQ _calc_clk_freq(PHASE_DFLT)
#define MAX_CLK_FREQ _calc_clk_freq(PHASE_MIN)

static inline u32 _config_clk(u32 req_freq, u32 *phase, u32 *sample)
{
	unsigned int p;
	u32 freq = 0, freq_prev;

	for (p = PHASE_MIN; p < PHASE_DFLT; p++) {
		freq_prev = freq;
		freq = _calc_clk_freq(p);

		if (req_freq >= freq)
			break;
	}

	if (p == PHASE_DFLT)
		freq = DFLT_CLK_FREQ;

	if (p == PHASE_MIN || p == PHASE_DFLT)
		goto out;

	/* Check which clock value from the identified range
	 * is closer to the requested value
	 */
	if ((freq_prev - req_freq) < (req_freq - freq)) {
		p = p - 1;
		freq = freq_prev;
	}
out:
	*phase = p;
	*sample = _calc_sample(p);
	return freq;
}

static int thunder_mdiobus_pci_probe(struct pci_dev *pdev,
				     const struct pci_device_id *ent)
{
	struct device_node *node;
	struct fwnode_handle *fwn;
	struct thunder_mdiobus_nexus *nexus;
	int err;
	int i;

	nexus = devm_kzalloc(&pdev->dev, sizeof(*nexus), GFP_KERNEL);
	if (!nexus)
		return -ENOMEM;

	pci_set_drvdata(pdev, nexus);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, KBUILD_MODNAME);
	if (err) {
		dev_err(&pdev->dev, "pci_request_regions failed\n");
		goto err_disable_device;
	}

	nexus->bar0 = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!nexus->bar0) {
		err = -ENOMEM;
		goto err_release_regions;
	}

	i = 0;
	device_for_each_child_node(&pdev->dev, fwn) {
		struct resource r;
		struct mii_bus *mii_bus;
		struct cavium_mdiobus *bus;
		union cvmx_smix_en smi_en;
		union cvmx_smix_clk smi_clk;
		u32 req_clk_freq;

		/* If it is not an OF node we cannot handle it yet, so
		 * exit the loop.
		 */
		node = to_of_node(fwn);
		if (!node)
			break;

		err = of_address_to_resource(node, 0, &r);
		if (err) {
			dev_err(&pdev->dev,
				"Couldn't translate address for \"%pOFn\"\n",
				node);
			break;
		}

		mii_bus = devm_mdiobus_alloc_size(&pdev->dev, sizeof(*bus));
		if (!mii_bus)
			break;
		bus = mii_bus->priv;
		bus->mii_bus = mii_bus;

		nexus->buses[i] = bus;
		i++;

		bus->register_base = (u64)nexus->bar0 +
			r.start - pci_resource_start(pdev, 0);

		smi_clk.u64 = oct_mdio_readq(bus->register_base + SMI_CLK);
		smi_clk.s.clk_idle = 1;

		if (!of_property_read_u32(node, "clock-freq", &req_clk_freq)) {
			u32 phase, sample;

			dev_info(&pdev->dev, "requested bus clock frequency=%d\n",
				 req_clk_freq);

			bus->clk_freq = _config_clk(req_clk_freq,
						    &phase, &sample);

			smi_clk.s.phase = phase;
			smi_clk.s.sample_hi = (sample >> 4) & 0x1f;
			smi_clk.s.sample = sample & 0xf;
		} else {
			bus->clk_freq = DFLT_CLK_FREQ;
		}

		oct_mdio_writeq(smi_clk.u64, bus->register_base + SMI_CLK);
		dev_info(&pdev->dev, "bus clock frequency set to %d\n",
			 bus->clk_freq);

		smi_en.u64 = 0;
		smi_en.s.en = 1;
		oct_mdio_writeq(smi_en.u64, bus->register_base + SMI_EN);

		bus->mii_bus->name = KBUILD_MODNAME;
		snprintf(bus->mii_bus->id, MII_BUS_ID_SIZE, "%llx", r.start);
		bus->mii_bus->parent = &pdev->dev;
		bus->mii_bus->read = cavium_mdiobus_read;
		bus->mii_bus->write = cavium_mdiobus_write;

		err = of_mdiobus_register(bus->mii_bus, node);
		if (err)
			dev_err(&pdev->dev, "of_mdiobus_register failed\n");

		dev_info(&pdev->dev, "Added bus at %llx\n", r.start);
		if (i >= ARRAY_SIZE(nexus->buses))
			break;
	}
	fwnode_handle_put(fwn);
	return 0;

err_release_regions:
	pci_release_regions(pdev);

err_disable_device:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void thunder_mdiobus_pci_remove(struct pci_dev *pdev)
{
	int i;
	struct thunder_mdiobus_nexus *nexus = pci_get_drvdata(pdev);

	for (i = 0; i < ARRAY_SIZE(nexus->buses); i++) {
		struct cavium_mdiobus *bus = nexus->buses[i];

		if (!bus)
			continue;

		mdiobus_unregister(bus->mii_bus);
		oct_mdio_writeq(0, bus->register_base + SMI_EN);
	}
	pci_set_drvdata(pdev, NULL);
}

static const struct pci_device_id thunder_mdiobus_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xa02b) },
	{ 0, } /* End of table. */
};
MODULE_DEVICE_TABLE(pci, thunder_mdiobus_id_table);

static struct pci_driver thunder_mdiobus_driver = {
	.name = KBUILD_MODNAME,
	.id_table = thunder_mdiobus_id_table,
	.probe = thunder_mdiobus_pci_probe,
	.remove = thunder_mdiobus_pci_remove,
};

module_pci_driver(thunder_mdiobus_driver);

MODULE_DESCRIPTION("Cavium ThunderX MDIO bus driver");
MODULE_LICENSE("GPL v2");
