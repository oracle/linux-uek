/*
 * Copyright (c) 2016, Oracle and/or its affiliates. All rights reserved.
 *    Author: Francisco Triviño <francisco.trivino@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_hwmon.h: SIF Hardware Monitoring
 */

#ifndef _SIF_HWMON_H
#define _SIF_HWMON_H

void sif_register_hwmon_dev(struct sif_dev *sdev);
void sif_unregister_hwmon_dev(struct sif_dev *sdev);

#endif
