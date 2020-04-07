/*
 * Copyright (c) 2019, Pensando Systems Inc.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include "cap_reboot.h"

#define DRV_NAME	"cap_pcie"
#define PFX		DRV_NAME ": "

/* device resource indexes */
#define MS_CFG_WDT_IDX  0
#define WDT_IDX         1
#define PCIEMAC_INT_IDX 2
#define PORTMAC_IDX	3

struct pciedev_info {
	u32 __iomem *ms_cfg_wdt;
	u32 __iomem *wdt;
	u32 __iomem *pciemac_int;
	u32 __iomem *portmac;
	u64 pciemac_mask;
	u64 portmac_crs_en;
	u64 portmac_ltssm_en;
	long (*saved_panic_blink)(int state);
};

static struct pciedev_info pciedev_info;

#define CAP_MS_CSR_CFG_WDT_RST_EN_LSB 0

#define WDT_CR          0x00
#define WDT_TORR        0x01
#define WDT_CRR         0x03

#define WDT_CR_ENABLE   0x1
#define WDT_CR_PCLK_256 (0x7 << 2)

#define WDT_KICK_VAL    0x76

static void pcieport_set_crs(const int on)
{
	struct pciedev_info *pi = &pciedev_info;
	u32 val;

	val = ioread32(pi->portmac);
	if (on)
		val |= pi->portmac_crs_en;
	else
		val &= ~pi->portmac_crs_en;
	iowrite32(val, pi->portmac);
}

static int pcieport_get_ltssm_en(void)
{
	struct pciedev_info *pi = &pciedev_info;
	u32 val = ioread32(pi->portmac);

	return (val & pi->portmac_ltssm_en) != 0;
}

/*
 * Detect if the host is rebooting by watching the pcie mac
 * for an interrupt indicating the link went into reset.
 */
static int pcie_poll_for_hostdn(void)
{
	struct pciedev_info *pi = &pciedev_info;
	u32 int_mac = ioread32(pi->pciemac_int);

	return (int_mac & pi->pciemac_mask) != 0;
}

/*
 * Reset Capri using the WDT0 configured to reset immediately.
 * Note that we do NOT touch the WDT config until here *after*
 * we are in the panic handling.  The WDT might be used by the
 * watchdog driver while the system is up, but here after a panic
 * we take ownership of the WDT to reset the system.
 *
 * Note also this function never returns.
 */
static void reset(void)
{
	struct pciedev_info *pi = &pciedev_info;
	u32 val;

	printk(PFX "reset!\n");

	// Enable WDT0 to reset the system
	val = ioread32(pi->ms_cfg_wdt);
	val |= (1 << CAP_MS_CSR_CFG_WDT_RST_EN_LSB);
	iowrite32(val, pi->ms_cfg_wdt);

	// Configure WDT to immediately reset
	iowrite32(0, pi->wdt + WDT_TORR);
	iowrite32(WDT_KICK_VAL, pi->wdt + WDT_CRR);
	iowrite32(WDT_CR_PCLK_256, pi->wdt + WDT_CR);
	iowrite32(WDT_CR_PCLK_256 | WDT_CR_ENABLE, pi->wdt + WDT_CR);
	for (;;) {
		asm volatile("wfi");
	}
	/* NOTREACHED */
}

/*
 * This function is called by the spin loop at the end of a
 * system panic.  We'll watch for the host to reset and
 * reset ourselves at the same time.
 *
 * If we haven't yet initialized the link (ltssm_en=0) then the
 * host side hasn't come up yet.  In that case just reset immediately.
 */
static long pcie_panic_blink(int state)
{
	/* Check sysfs for immediate reboot */
	if (cap_panic_reboot())
		reset();

	if (pcieport_get_ltssm_en()) {
		pcieport_set_crs(0);
		while (!pcie_poll_for_hostdn())
			continue;
	}
	reset();

	/* NOTREACHED */
	return 0;
}

static int map_resources(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;
	struct device_node *dn = pd->dev.of_node;

	pi->ms_cfg_wdt = of_iomap(dn, MS_CFG_WDT_IDX);
	pi->wdt = of_iomap(dn, WDT_IDX);
	pi->pciemac_int = of_iomap(dn, PCIEMAC_INT_IDX);
	pi->portmac = of_iomap(dn, PORTMAC_IDX);

	if (IS_ERR(pi->ms_cfg_wdt) ||
		IS_ERR(pi->wdt) ||
		IS_ERR(pi->pciemac_int) ||
		IS_ERR(pi->portmac)) {
		pr_err(PFX "iomap resources failed\n");
		goto errout;
	}
	return 0;

 errout:
	if (pi->ms_cfg_wdt != NULL)
		iounmap(pi->ms_cfg_wdt);
	if (pi->wdt != NULL)
		iounmap(pi->wdt);
	if (pi->pciemac_int != NULL)
		iounmap(pi->pciemac_int);
	if (pi->portmac != NULL)
		iounmap(pi->portmac);
	return -ENOMEM;
}

static void unmap_resources(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;

	if (pi->ms_cfg_wdt != NULL)
		iounmap(pi->ms_cfg_wdt);
	if (pi->wdt != NULL)
		iounmap(pi->wdt);
	if (pi->pciemac_int != NULL)
		iounmap(pi->pciemac_int);
	if (pi->portmac != NULL)
		iounmap(pi->portmac);
}

static int pcie_probe(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;
	struct device_node *dn = pd->dev.of_node;
	int err;

	err = map_resources(pd);
	if (err)
		goto errout;

	err = of_property_read_u64(dn, "pciemac_mask", &pi->pciemac_mask);
	if (err) {
		pr_err(PFX "can't find pciemac_mask: %d\n", err);
		goto errout_unmap;
	}
	err = of_property_read_u64(dn, "portmac_crs_en", &pi->portmac_crs_en);
	if (err) {
		pr_err(PFX "can't find portmac_crs_en: %d\n", err);
		goto errout_unmap;
	}
	err = of_property_read_u64(dn, "portmac_ltssm_en",
                                   &pi->portmac_ltssm_en);
	if (err) {
		pr_err(PFX "can't find portmac_ltssm_en: %d\n", err);
		goto errout_unmap;
	}

	/*
	 * Hook the panic_blink handler so we run after
	 * all the panic notifiers and after all the
	 * console msgs have been flushed.
	 */
	pi->saved_panic_blink = panic_blink;
	panic_blink = pcie_panic_blink;
	return 0;

 errout_unmap:
	unmap_resources(pd);
 errout:
	return err;
}

static int pcie_remove(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;

	panic_blink = pi->saved_panic_blink;
	unmap_resources(pd);
	return 0;
}

static struct of_device_id pcie_of_match[] = {
	{ .compatible = "pensando,pcie" },
	{ /* end of table */ }
};

static struct platform_driver pcie_driver = {
	.probe = pcie_probe,
	.remove = pcie_remove,
	.driver = {
		.name = "pensando-pcie",
		.owner = THIS_MODULE,
		.of_match_table = pcie_of_match,
	},
};
module_platform_driver(pcie_driver);
