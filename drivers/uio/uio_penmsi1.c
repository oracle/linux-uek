// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2021, Pensando Systems Inc.
 */

#include <linux/module.h>
#include "uio_penmsi.h"

#define DRIVER_NAME_MSIX1	"uio_penmsi1"

#ifdef CONFIG_OF
static const struct of_device_id penmsi_match[] = {
	{ .compatible = "pensando,uio_penmsi1" },
	{ /* Mark the end of the list */ },
};
#endif

static struct platform_driver penmsi1 = {
	.probe = penmsi_probe,
	.remove = penmsi_remove,
	.driver = {
		.name = DRIVER_NAME_MSIX1,
		.pm = &penmsi_pm_ops,
		.of_match_table = of_match_ptr(penmsi_match),
	}
};

module_platform_driver(penmsi1);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Support userspace I/O for Pensando MSI interrupts");
MODULE_AUTHOR("David VomLehn");
