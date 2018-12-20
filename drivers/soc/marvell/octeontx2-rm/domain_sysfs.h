// SPDX-License-Identifier: GPL-2.0
/* OcteonTX2 RVU Resource Manager driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef DOMAIN_SYSFS_H_
#define DOMAIN_SYSFS_H_

#include "otx2_rm.h"

int domain_sysfs_create(struct rm_dev *rm);
void domain_sysfs_destroy(struct rm_dev *rm);

#endif /* DOMAIN_SYSFS_H_ */
