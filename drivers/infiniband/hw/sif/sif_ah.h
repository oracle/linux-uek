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
 * sif_ah.h: Interface to internal IB address handle logic for SIF
 */

#ifndef __SIF_AH_H
#define __SIF_AH_H

struct sif_ah {
	volatile struct psif_ah d;
	struct ib_ah ibah;
	int index;
};

static inline struct sif_ah *to_sah(struct ib_ah *ibah)
{
	return container_of(ibah, struct sif_ah, ibah);
}

struct ib_ah *sif_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr,
			struct ib_udata *udata);
int sif_destroy_ah(struct ib_ah *ibah);
int sif_modify_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr);
int sif_query_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr);

struct seq_file;
struct sif_dev;

/* Line printer for debugfs file */
void sif_dfs_print_ah(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

#endif
