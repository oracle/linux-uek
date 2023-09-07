// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>

#include "uio_pengic.h"

#define DRIVER_NAME_PCIEMAC	"uio_pciemac0"

#ifdef CONFIG_OF
static const struct of_device_id pengic_match[] = {
	{ .compatible = "pensando,uio_pciemac" },
	{ /* Mark the end of the list */ },
};
#endif

static struct platform_driver uio_pciemac = {
	.probe = pengic_probe_enable,
	.remove = pengic_remove,
	.driver = {
		.name = DRIVER_NAME_PCIEMAC,
		.pm = &pengic_pm_ops,
		.of_match_table = of_match_ptr(pengic_match),
	}
};

module_platform_driver(uio_pciemac);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Support PCIe MAC status reporting");
MODULE_AUTHOR("David VomLehn");
