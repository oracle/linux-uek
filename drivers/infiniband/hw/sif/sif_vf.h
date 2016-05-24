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
 * sif_vf.h: SR/IOV support functions
 */
#ifndef __SIF_VF_H
#define __SIF_VF_H

int sif_vf_enable(struct pci_dev *dev, int num_vfs);
void sif_vf_disable(struct sif_dev *sdev);

#endif
