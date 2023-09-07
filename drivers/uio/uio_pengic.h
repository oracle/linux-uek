/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020-2021, Pensando Systems Inc.
 */

#ifndef _UIO_PENGIC_H_
#define _UIO_PENGIC_H_

#include <linux/of.h>
#include <linux/platform_device.h>

extern const struct dev_pm_ops pengic_pm_ops;

int pengic_probe(struct platform_device *pdev);
int pengic_probe_enable(struct platform_device *pdev);
int pengic_remove(struct platform_device *pdev);

#endif /* _UIO_PENGIC_H_ */
