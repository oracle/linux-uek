/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_hwi.h: Hardware init for SIF
 */

#ifndef _SIF_HWI_H
#define _SIF_HWI_H
#include <rdma/ib_verbs.h>
#include "sif_cq.h"
#include "sif_r3.h"

struct sif_dev;
struct sif_pqp;
struct sif_qp;
struct sif_compl;
struct sif_cqe;
struct psif_wr;
struct psif_cq_entry;
enum psif_wr_type;

/* Main calls for hardware specific initialization/deinitialization */

int force_pcie_link_retrain(struct sif_dev *sdev);
int sif_hw_init(struct sif_dev *sdev);
void sif_hw_deinit(struct sif_dev *sdev);

#endif
