/*
 * Capri stub EMMC PHY
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#define EM_CFG_CORE	0x38
#define EM_CFG_PHY0	0x20
#define EM_CFG_PHY1	0x24
#define EM_CFG_PHY2	0x28
#define EM_STA_PHY0	0x30
#define EM_STA_PHY1	0x34

#define EM_ENDLL_COUNT 2

struct pensando_capri_emmc_phy {
	void __iomem	*phy_base;
	int		power_off_called;
	uint32_t	flags;
};
#define CAP_EMMC_OTAP_CTRL	0x1

static int pensando_capri_emmc_phy_init(struct phy *phy)
{
	printk(KERN_INFO "capri_emmc_phy: PHY init \n");
	return 0;
}

static int pensando_capri_emmc_phy_exit(struct phy *phy)
{
	printk(KERN_INFO "capri_emmc_phy: Phy exit\n");
	return 0;
}

static int pensando_capri_emmc_phy_power_off(struct phy *phy)
{
	struct pensando_capri_emmc_phy *cap_phy = phy_get_drvdata(phy);

	printk(KERN_INFO "capri_emmc_phy: Power off\n");
	cap_phy->power_off_called = 1;
	return 0;
}

static int pensando_capri_emmc_phy_power_on(struct phy *phy)
{
	struct pensando_capri_emmc_phy *cap_phy = phy_get_drvdata(phy);
	unsigned int val;
	unsigned int cnt;
	int i;

	// Begin Calibration
	// set tuning count - setting tuning count to 4 -check Arasan
	writel(0x8, cap_phy->phy_base + EM_CFG_CORE);

	// turn off PDB
	val = readl(cap_phy->phy_base + EM_CFG_PHY0);
	val = val & 0xfffffffe;
	writel(val, cap_phy->phy_base + EM_CFG_PHY0);

	// Turn on retenb and off renb
	val = val | 0x8000;
	val = val & 0xffffbfff;
	writel(val, cap_phy->phy_base + EM_CFG_PHY0);

	// Turn retrim
	val = val | 0x20;
	writel(val, cap_phy->phy_base + EM_CFG_PHY0);

	// Turn on PDB
	val = val | 0x1;
	writel(val, cap_phy->phy_base + EM_CFG_PHY0);

	// Enable retrim
	val = val | 0x10;
	writel(val, cap_phy->phy_base + EM_CFG_PHY0);

	// check calibration done
	cnt = 0;
	while (((readl(cap_phy->phy_base + EM_STA_PHY1) & 0x80) == 0) &&
			++cnt < 10000000) {
		/* spin */
	}
	if (cnt >= 10000000)
		printk(KERN_INFO "EMMC calibration failed...%d\n", cnt);
	else
		printk(KERN_INFO "EMMC calibration done...%d\n", cnt);

	// Begin DLL enable
	// set select clocks to select DLL outputs
	val = readl(cap_phy->phy_base + EM_CFG_PHY2);
	val = val & ~0x1800;
	writel(val, cap_phy->phy_base + EM_CFG_PHY2);

	for (i = 0; i < EM_ENDLL_COUNT; i++) {
		// enable DLL
		val = readl(cap_phy->phy_base + EM_CFG_PHY0);
		val = val & ~0x400;
		writel(val, cap_phy->phy_base + EM_CFG_PHY0);

		val = readl(cap_phy->phy_base + EM_CFG_PHY0);
		val = val | 0x400;
		writel(val, cap_phy->phy_base + EM_CFG_PHY0);

		// Wait for DLL ready
		cnt = 0;
		while (((readl(cap_phy->phy_base + EM_STA_PHY1) & 0x4) == 0) && (++cnt) < 10000000) {
			/* spin */
		}
		if (cnt >= 10000000)
			printk(KERN_INFO "EMMC:EMMC DLL is not ready ... %d\n", cnt);
		else
			printk(KERN_INFO "EMMC DLL is ready ... %d\n", cnt);
	}

	if (cap_phy->power_off_called &&
			(cap_phy->flags & CAP_EMMC_OTAP_CTRL)) {
		// FIXME return 1?
		// End Calibration

		// Toggle OTAP DLY ENA - to latch tap values
		val = readl(cap_phy->phy_base + EM_CFG_PHY2);
		if ((val & 0x04000000) == 0x0) {
			printk(KERN_INFO
				"EMMC turning on PHY2 OTAP...0x%x\n", val);
			val = val | 0x8;
			writel(val, cap_phy->phy_base + EM_CFG_PHY2);
		}

		val = readl(cap_phy->phy_base + EM_CFG_PHY2);
		if (val & 0x08000000) {
			printk(KERN_INFO
				"EMMC turning off PHY2 OTAP...0x%x\n", val);
			val = val ^ 0x8;
			writel(val, cap_phy->phy_base + EM_CFG_PHY2);
		}
	} else {
		printk(KERN_INFO "EMMC skipping PHY2 OTAP...\n");
	}

	// FIXME return 1?
	// END DLL enable
	printk(KERN_INFO "EMMC: ... 0x%x 0x%0x\n",
			readl(cap_phy->phy_base + EM_STA_PHY0),
			readl(cap_phy->phy_base + EM_STA_PHY1));

	return 0;
}

static const struct phy_ops ops = {
	.init		= pensando_capri_emmc_phy_init,
	.exit		= pensando_capri_emmc_phy_exit,
	.power_on	= pensando_capri_emmc_phy_power_on,
	.power_off	= pensando_capri_emmc_phy_power_off,
	.owner		= THIS_MODULE,
};

static int pensando_capri_emmc_phy_probe(struct platform_device *pdev)
{
	struct pensando_capri_emmc_phy *cap_phy;
	struct phy_provider *phy_provider;
	struct device *dev = &pdev->dev;
	struct phy *generic_phy;
	struct resource *res;
	int err;

	if (!dev->parent || !dev->parent->of_node)
		return -ENODEV;

	cap_phy = devm_kzalloc(dev, sizeof(*cap_phy), GFP_KERNEL);
	if (!cap_phy)
		return -ENOMEM;

	generic_phy = devm_phy_create(dev, dev->of_node, &ops);
	if (IS_ERR(generic_phy)) {
		dev_err(dev, "failed to create PHY\n");
		return PTR_ERR(generic_phy);
	}

	err = of_property_read_u32(pdev->dev.of_node,
			"pensando,flags", &cap_phy->flags);
	if (!err) {
		printk(KERN_INFO
			"capri_emmc_phy: flags=0x%x\n", cap_phy->flags);
	}
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	cap_phy->phy_base = devm_ioremap_resource(dev, res);
	if (IS_ERR(cap_phy->phy_base)) {
		dev_err(dev, "Cannot remap address.\n");
		return PTR_ERR(cap_phy->phy_base);
	}
	phy_set_drvdata(generic_phy, cap_phy);
	phy_provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);
	printk(KERN_INFO "capri_emmc_phy: phy_provider=%p\n", phy_provider);

	return PTR_ERR_OR_ZERO(phy_provider);
}

static const struct of_device_id pensando_capri_emmc_phy_dt_ids[] = {
	{ .compatible = "pensando,capri-emmc-phy" },
	{}
};

MODULE_DEVICE_TABLE(of, pensando_capri_emmc_phy_dt_ids);

static struct platform_driver pensando_capri_emmc_driver = {
	.probe		= pensando_capri_emmc_phy_probe,
	.driver		= {
		.name	= "pensando_capri-emmc-phy",
		.of_match_table = pensando_capri_emmc_phy_dt_ids,
	},
};

module_platform_driver(pensando_capri_emmc_driver);

MODULE_DESCRIPTION("Pensando Capri EMMC PHY driver");
MODULE_LICENSE("GPL v2");
