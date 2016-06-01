/*
 * Copyright (c) 2013, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_elog.h: Misc device for capturing log from the EPSC
 */

#ifndef _SIF_ELOG_H
#define _SIF_ELOG_H

struct sif_dev;

int sif_elog_init(struct sif_dev *sdev, enum psif_mbox_type eps_num);
void sif_elog_deinit(struct sif_dev *sdev, enum psif_mbox_type eps_num);

void sif_elog_intr(struct sif_dev *sdev, enum psif_mbox_type eps_num);

#endif
