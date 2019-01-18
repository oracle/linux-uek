/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_PASSTHROUGH_H
#define __CPT9X_PASSTHROUGH_H

int run_passthrough_test(struct pci_dev *pdev, const char *buf, int size);

#endif /* __CPT9X_PASSTHROUGH_H */
