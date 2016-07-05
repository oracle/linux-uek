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
 * sif_mw.h: Interface to internal IB memory window logic for SIF
 */

#ifndef __SIF_MW_H
#define __SIF_MW_H

struct ib_mw *sif_alloc_mw(struct ib_pd *ibpd);
int sif_dealloc_mw(struct ib_mw *ibmw);

#endif
