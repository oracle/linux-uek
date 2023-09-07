/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020-2021, Pensando Systems Inc.
 */

#ifndef _UIO_PENMSI_H_
#define _UIO_PENMSI_H_

#include <linux/of.h>
#include <linux/platform_device.h>

extern const struct dev_pm_ops penmsi_pm_ops;

int penmsi_probe(struct platform_device *pdev);
int penmsi_remove(struct platform_device *pdev);

#endif /* _UIO_PENMSI_H_ */
